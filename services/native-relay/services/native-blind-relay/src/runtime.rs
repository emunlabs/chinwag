use serde::Deserialize;
use worker::{
    durable_object, event, Context, DurableObject, Env, Method, Request, Response, Result,
    ScheduledTime, SqlStorageValue, State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

use crate::protocol::{
    self, ClientFrame, EndpointId, Failure, ALLOWED_ENDPOINTS, AUTH_CONFIRMED, AUTH_DENIED,
    PROTOCOL,
};
use crate::session::{
    Session, MAX_ADMISSIONS_PER_MINUTE, MAX_CONNECTIONS, MAX_PENDING, PING_INTERVAL_MS,
    PONG_TIMEOUT_MS,
};

const BINDING: &str = "NATIVE_RELAY";
// Both pinned endpoints must always land in the same coordination atom.
const INSTANCE: &str = "native-blind-relay-v1";

fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

fn upgrade_request(req: &Request) -> bool {
    req.method() == Method::Get
        && req.path() == "/relay"
        && req.url().is_ok_and(|url| url.query().is_none())
        && req.inner().body().is_none()
        && req
            .headers()
            .get("upgrade")
            .ok()
            .flatten()
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && req
            .headers()
            .get("sec-websocket-protocol")
            .ok()
            .flatten()
            .is_some_and(|value| protocol::accepts_protocol(&value))
}

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.method() == Method::Get && req.path() == "/health" {
        return Response::ok("native-blind-relay-v1");
    }
    if let Some(probe) = crate::http_probe::response(
        req.method() == Method::Get,
        &req.path(),
        req.headers().get("X-Iroh-Challenge")?.as_deref(),
    ) {
        let mut response = Response::empty()?.with_status(probe.status);
        if probe.allow_origin {
            response
                .headers_mut()
                .set("Access-Control-Allow-Origin", "*")?;
        }
        if let Some(value) = probe.challenge_response {
            response.headers_mut().set("X-Iroh-Response", &value)?;
        }
        return Ok(response);
    }
    if !upgrade_request(&req) {
        return Response::error("relay upgrade required", 400);
    }
    env.durable_object(BINDING)?
        .get_by_name(INSTANCE)?
        .fetch_with_request(req)
        .await
}

#[durable_object]
pub struct NativeBlindRelay {
    state: State,
    schema_ready: bool,
}

impl DurableObject for NativeBlindRelay {
    fn new(state: State, _env: Env) -> Self {
        let schema_ready = state.storage().sql().exec(
            "CREATE TABLE IF NOT EXISTS admission (id INTEGER PRIMARY KEY CHECK(id=1), window_ms INTEGER NOT NULL, count INTEGER NOT NULL)",
            None::<Vec<SqlStorageValue>>,
        ).is_ok();
        Self {
            state,
            schema_ready,
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if !self.schema_ready {
            return Response::error("unavailable", 503);
        }
        if !upgrade_request(&req) {
            return Response::error("relay upgrade required", 400);
        }
        let now = now_ms();
        self.prune(now);
        let sessions = self.sessions();
        let pending = sessions
            .iter()
            .filter(|(_, s)| !s.closed && s.endpoint.is_none())
            .count();
        let total = sessions.iter().filter(|(_, s)| !s.closed).count();
        if total >= MAX_CONNECTIONS || pending >= MAX_PENDING || !self.admit(now)? {
            return Response::error("connection budget", 429);
        }
        let mut challenge = [0_u8; 16];
        getrandom::getrandom(&mut challenge)
            .map_err(|_| worker::Error::RustError("random unavailable".into()))?;
        let pair = WebSocketPair::new()?;
        pair.server
            .serialize_attachment(Session::pending(challenge, now))?;
        self.state.accept_web_socket(&pair.server);
        if pair
            .server
            .send_with_bytes(protocol::challenge_frame(&challenge))
            .is_err()
        {
            self.retire(&pair.server, 1011, "send failed");
            return Response::error("unavailable", 503);
        }
        // The socket is admitted before the first await, so simultaneous fetches cannot
        // reserve the same capacity. An alarm failure must fail closed.
        if self.schedule_alarm(false).await.is_err() {
            self.retire(&pair.server, 1011, "timer unavailable");
            return Response::error("unavailable", 503);
        }
        let mut response = Response::from_websocket(pair.client)?;
        response
            .headers_mut()
            .set("Sec-WebSocket-Protocol", PROTOCOL)?;
        Ok(response)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let result = if self.schema_ready {
            match message {
                WebSocketIncomingMessage::Binary(bytes) => self.message(&ws, &bytes, now_ms()),
                WebSocketIncomingMessage::String(_) => Err(Failure::Malformed),
            }
        } else {
            Err(Failure::State)
        };
        if let Err(failure) = result {
            if self.session(&ws).is_some_and(|s| s.challenge.is_some()) {
                let _ = ws.send_with_bytes(AUTH_DENIED);
            }
            let (code, reason) = match failure {
                Failure::Oversized => (1009, "frame size"),
                Failure::Expired => (1008, "session expired"),
                Failure::Budget => {
                    let _ = ws.send_with_bytes([13, 2]);
                    (1008, "traffic budget")
                }
                Failure::State => (1011, "session unavailable"),
                Failure::Unauthorized | Failure::Malformed => (1008, "invalid frame"),
            };
            self.retire(&ws, code, reason);
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        self.retire(&ws, 1000, "closed");
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: worker::Error) -> Result<()> {
        self.retire(&ws, 1011, "socket error");
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        let now = now_ms();
        self.prune(now);
        for (ws, mut session) in self.sessions() {
            if session.closed
                || session.endpoint.is_none()
                || session.pending_ping.is_some()
                || now.saturating_sub(session.last_ping_ms) < PING_INTERVAL_MS
            {
                continue;
            }
            let mut ping = [0_u8; 8];
            if getrandom::getrandom(&mut ping).is_err() {
                self.retire(&ws, 1011, "random unavailable");
                continue;
            }
            session.last_ping_ms = now;
            session.pending_ping = Some(ping);
            session.pong_deadline_ms = now.saturating_add(PONG_TIMEOUT_MS);
            if ws.serialize_attachment(session).is_err()
                || ws
                    .send_with_bytes(protocol::control_frame(9, &ping))
                    .is_err()
            {
                self.retire(&ws, 1011, "send failed");
            }
        }
        self.schedule_alarm(true).await?;
        Response::empty()
    }
}

impl NativeBlindRelay {
    fn session(&self, ws: &WebSocket) -> Option<Session> {
        ws.deserialize_attachment::<Session>().ok().flatten()
    }

    fn sessions(&self) -> Vec<(WebSocket, Session)> {
        self.state
            .get_websockets()
            .into_iter()
            .filter_map(|ws| {
                if let Some(session) = self.session(&ws) {
                    Some((ws, session))
                } else {
                    let _ = ws.close(Some(1011), Some("session unavailable"));
                    None
                }
            })
            .collect()
    }

    /// One tiny durable counter also bounds unauthenticated connection churn across eviction.
    /// SQL operations contain no await, so this read/update cannot interleave with another event.
    fn admit(&self, now: u64) -> Result<bool> {
        #[derive(Deserialize)]
        struct Admission {
            window_ms: u64,
            count: u32,
        }
        let sql = self.state.storage().sql();
        let old = sql
            .exec(
                "SELECT window_ms, count FROM admission WHERE id=1",
                None::<Vec<SqlStorageValue>>,
            )?
            .to_array::<Admission>()?
            .into_iter()
            .next();
        let (window, count) = match old {
            Some(old) if now < old.window_ms => return Ok(false),
            Some(old) if now - old.window_ms < 60_000 => (old.window_ms, old.count),
            _ => (now, 0),
        };
        if count >= MAX_ADMISSIONS_PER_MINUTE {
            return Ok(false);
        }
        sql.exec(
            "INSERT INTO admission(id, window_ms, count) VALUES(1, ?, ?) ON CONFLICT(id) DO UPDATE SET window_ms=excluded.window_ms, count=excluded.count",
            Some(vec![SqlStorageValue::Integer(window as i64), SqlStorageValue::Integer(i64::from(count + 1))]),
        )?;
        Ok(true)
    }

    fn message(&self, ws: &WebSocket, bytes: &[u8], now: u64) -> std::result::Result<(), Failure> {
        let mut session = self.session(ws).ok_or(Failure::State)?;
        session.check_live(now)?;
        if let Some(challenge) = session.challenge {
            let endpoint = protocol::verify_auth(bytes, &challenge, &ALLOWED_ENDPOINTS)?;
            session.authenticate(endpoint, now)?;
            ws.serialize_attachment(&session)
                .map_err(|_| Failure::State)?;
            // Only a proved owner can replace its own existing socket. Mark the old socket
            // closed before it can process any more datagrams or report the new socket gone.
            for (old, other) in self.sessions() {
                if old != *ws && !other.closed && other.endpoint == Some(endpoint) {
                    let _ = old.send_with_bytes([13, 1]);
                    self.retire(&old, 1000, "replaced");
                }
            }
            ws.send_with_bytes(AUTH_CONFIRMED)
                .map_err(|_| Failure::State)?;
            return Ok(());
        }
        let source = session.endpoint.ok_or(Failure::Unauthorized)?;
        let frame = protocol::client_frame(bytes, &source, &ALLOWED_ENDPOINTS)?;
        session.charge(bytes.len(), now)?;
        // Persist accounting before forwarding or acknowledging the frame.
        if let ClientFrame::Pong(data) = frame {
            session.pong(data)?;
        }
        ws.serialize_attachment(session)
            .map_err(|_| Failure::State)?;
        match frame {
            ClientFrame::Ping(data) => ws
                .send_with_bytes(protocol::control_frame(10, &data))
                .map_err(|_| Failure::State)?,
            ClientFrame::Pong(_) => {}
            ClientFrame::Datagram {
                destination,
                batch,
                body,
            } => {
                if let Some(peer) = self.peer(&destination, now) {
                    if peer
                        .send_with_bytes(protocol::relay_frame(&source, batch, body))
                        .is_err()
                    {
                        self.retire(&peer, 1011, "send failed");
                    }
                } else {
                    // No offline queue. Iroh will retry at the QUIC layer.
                    ws.send_with_bytes(protocol::control_frame(8, &destination))
                        .map_err(|_| Failure::State)?;
                }
            }
        }
        Ok(())
    }

    fn peer(&self, endpoint: &EndpointId, now: u64) -> Option<WebSocket> {
        self.sessions().into_iter().find_map(|(ws, session)| {
            (session.endpoint == Some(*endpoint) && session.check_live(now).is_ok()).then_some(ws)
        })
    }

    fn retire(&self, ws: &WebSocket, code: u16, reason: &str) {
        let Some(mut session) = self.session(ws) else {
            let _ = ws.close(Some(code), Some(reason));
            return;
        };
        if session.closed {
            return;
        }
        session.closed = true;
        session.challenge = None;
        let _ = ws.serialize_attachment(&session);
        let _ = ws.close(Some(code), Some(reason));
        if let Some(endpoint) = session.endpoint {
            // A late close/error from a replaced socket must not invalidate its successor.
            if self.peer(&endpoint, now_ms()).is_none() {
                for (other, state) in self.sessions() {
                    if !state.closed && state.endpoint.is_some() && state.endpoint != Some(endpoint)
                    {
                        let _ = other.send_with_bytes(protocol::control_frame(8, &endpoint));
                    }
                }
            }
        }
    }

    fn prune(&self, now: u64) {
        for (ws, session) in self.sessions() {
            if !session.closed
                && (session.check_live(now).is_err()
                    || session
                        .endpoint
                        .is_some_and(|id| !ALLOWED_ENDPOINTS.contains(&id)))
            {
                self.retire(&ws, 1008, "session expired");
            }
        }
    }

    async fn schedule_alarm(&self, force: bool) -> Result<()> {
        let now = now_ms();
        let deadline = self
            .sessions()
            .into_iter()
            .filter(|(_, s)| !s.closed)
            .map(|(_, s)| s.next_deadline())
            .min();
        if let Some(deadline) = deadline {
            let storage = self.state.storage();
            let desired = deadline.max(now.saturating_add(1));
            // Never let another incoming connection extend an existing authentication deadline.
            if force
                || storage
                    .get_alarm()
                    .await?
                    .is_none_or(|old| old as u64 > desired)
            {
                storage
                    .set_alarm(ScheduledTime::new(js_sys::Date::new(
                        &wasm_bindgen::JsValue::from_f64(desired as f64),
                    )))
                    .await?;
            }
        }
        Ok(())
    }
}
