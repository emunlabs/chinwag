# Native blind relay candidate

This is a separate Rust Cloudflare Worker and SQLite Durable Object. `/relay`
negotiates `iroh-relay-v2`, challenges each new socket, verifies the domain-separated
BLAKE3/Ed25519 signature, and authorizes exactly the two public EndpointIDs in
`protocol.rs`. The server always uses the explicit challenge fallback, including
when a client sends a TLS exporter header. No private key or other credential is
needed by this service. No existing coordinator or runtime profile is modified.

One named DO instance coordinates this one endpoint pair. Hibernation attachments
retain the one-time authentication state, identity, deadlines and traffic counters.
SQLite retains a 30-per-minute global admission budget across object eviction.
There are at most six live sockets, four unauthenticated; one proved socket per
identity supersedes its predecessor. Authentication expires after five seconds.
Authenticated sockets have a 30-minute lease, 256-frame/1-MiB-per-second receive
limits and a 64-MiB lifetime receive budget, after which clients must reconnect.
Server pings every 15 seconds require the matching pong within 10 seconds.
Logical deadlines are checked on every message even if an alarm is late.

The relay accepts client tags 4/5/9/10, rewrites only direction and authenticated
source on datagrams, and sends 6/7/8/9/10/13. Packet bodies are at most 64 KiB,
including destination and metadata but excluding the tag. Bad tags, text, invalid
metadata, unauthorized destinations, self-routing, auth replay, expired sessions,
and budget excess close the connection. Datagrams are never logged or stored and
there is no offline or application send queue. Cloudflare's WebSocket API owns its
transport buffers; the service has no transport-level backpressure API. Session
and rate budgets bound accepted traffic but do not guarantee a per-socket platform
buffer size. Connection reset/reconnect is expected during eviction/deployment.

This implements relay data forwarding, not control-plane coordination, QUIC
termination, QAD/STUN, metrics, a public relay, or a signed application receipt.
Author tests are evidence of source behavior; live Cloudflare and authorized
two-host signed round-trip acceptance are separate gates.

Run from the repository root with Rust 1.97.1:

```sh
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo check --locked --target wasm32-unknown-unknown --lib
cd services/native-blind-relay
worker-build --release --locked
```

After independent review, the deployment owner can run `wrangler deploy` from
this service directory using the existing approved account. This creates only
`chinwag-native-blind-relay` and its `NativeBlindRelay` binding; it does not add a
DNS/custom route or edit another service. The default endpoint is the returned
HTTPS workers.dev origin. Before switching product profiles, test actual upstream
client negotiation with a newly generated, unauthorized ephemeral key:

```sh
cargo run --locked -p native-blind-relay --example readiness -- https://WORKER.SUBDOMAIN.workers.dev
```

PASS means native iroh 1.4.1 completed negotiation and received the exact expected
authentication denial; it does not mean either allowed host has connected. Root
and GEM must separately use the existing protected endpoint operators for paired
configuration activation and a unique signed application round trip. This service
contains no fallback relay or tunnel configuration.
