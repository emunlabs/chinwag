//! Actual upstream client, not a mock codec. The loopback transport adapter calls the
//! production protocol core. It does not establish Cloudflare runtime acceptance.
use futures_util::{SinkExt, StreamExt};
use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{Client, ClientBuilder},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    tls::CaTlsConfig,
};
use native_blind_relay::protocol::{self, ClientFrame};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_websockets::{Message, ServerBuilder};

async fn connect(origin: RelayUrl, key: SecretKey) -> Client {
    let tls = CaTlsConfig::default()
        .client_config(Arc::new(rustls::crypto::ring::default_provider()))
        .unwrap();
    ClientBuilder::new(origin, key, DnsResolver::new())
        .tls_client_config(tls)
        .connect()
        .await
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn actual_iroh_clients_authenticate_route_both_directions_batch_and_ping() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let keys = [SecretKey::from_bytes(&[11;32]), SecretKey::from_bytes(&[12;32])];
        let ids = keys.each_ref().map(|key| *key.public().as_bytes());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin: RelayUrl = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
        let (tx0, rx0) = mpsc::channel::<Vec<u8>>(8);
        let (tx1, rx1) = mpsc::channel::<Vec<u8>>(8);
        let server = tokio::spawn(async move {
            let mut receivers = [Some(rx0), Some(rx1)];
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let (request, mut socket) = ServerBuilder::new().add_header("sec-websocket-protocol".parse().unwrap(), protocol::PROTOCOL.parse().unwrap()).unwrap().accept(tcp).await.unwrap();
                assert_eq!(request.uri().path(), "/relay");
                assert!(protocol::accepts_protocol(request.headers()["sec-websocket-protocol"].to_str().unwrap()));
                socket.send(Message::binary(protocol::challenge_frame(&[7;16]))).await.unwrap();
                let auth = socket.next().await.unwrap().unwrap();
                let endpoint = protocol::verify_auth(auth.as_payload(), &[7;16], &ids).unwrap();
                let index = ids.iter().position(|id| id == &endpoint).unwrap();
                let mut incoming = receivers[index].take().unwrap();
                let outgoing = if index == 0 { tx1.clone() } else { tx0.clone() };
                socket.send(Message::binary(protocol::AUTH_CONFIRMED.to_vec())).await.unwrap();
                tasks.push(tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            message = socket.next() => {
                                let Some(Ok(message)) = message else { break; };
                                if !message.is_binary() { break; }
                                match protocol::client_frame(message.as_payload(), &endpoint, &ids).unwrap() {
                                    ClientFrame::Datagram { batch, body, .. } => outgoing.send(protocol::relay_frame(&endpoint, batch, body)).await.unwrap(),
                                    ClientFrame::Ping(data) => socket.send(Message::binary(protocol::control_frame(10, &data))).await.unwrap(),
                                    ClientFrame::Pong(_) => {},
                                }
                            }
                            frame = incoming.recv() => {
                                let Some(frame) = frame else { break; };
                                socket.send(Message::binary(frame)).await.unwrap();
                            }
                        }
                    }
                }));
            }
            for task in tasks { task.await.unwrap(); }
        });
        let mut a = connect(origin.clone(), keys[0].clone()).await;
        let mut b = connect(origin, keys[1].clone()).await;
        a.send(ClientToRelayMsg::Datagrams { dst_endpoint_id: keys[1].public(), datagrams: Datagrams::from([0,255,17]) }).await.unwrap();
        let RelayToClientMsg::Datagrams { remote_endpoint_id, datagrams } = b.next().await.unwrap().unwrap() else { panic!("expected datagram") };
        assert_eq!(remote_endpoint_id, keys[0].public()); assert_eq!(datagrams.contents.as_ref(), [0,255,17]);
        b.send(ClientToRelayMsg::Datagrams { dst_endpoint_id: keys[0].public(), datagrams: Datagrams { ecn: None, segment_size: std::num::NonZeroU16::new(2), contents: bytes::Bytes::from_static(&[3,4,5,6]) } }).await.unwrap();
        let RelayToClientMsg::Datagrams { remote_endpoint_id, datagrams } = a.next().await.unwrap().unwrap() else { panic!("expected batch") };
        assert_eq!(remote_endpoint_id, keys[1].public()); assert_eq!(datagrams.segment_size.unwrap().get(), 2); assert_eq!(datagrams.contents.as_ref(), [3,4,5,6]);
        a.send(ClientToRelayMsg::Ping([9;8])).await.unwrap();
        assert!(matches!(a.next().await.unwrap().unwrap(), RelayToClientMsg::Pong([9,9,9,9,9,9,9,9])));
        drop(a); drop(b); server.abort();
    }).await.expect("actual native client round trip timed out");
}
