# Cloudflare-native inter-node messaging

Inter-node Chinwag messages should originate on the sending node and travel through its local, explicitly configured native daemon to the peer over the selected owned Cloudflare Iroh relay. This is the operating procedure for a current, authorized relay session. Remote-handset publication—SSHing into the receiving node to send there—and copying journals between nodes are not the ordinary message transport.

This policy does not itself migrate a running deployment. Each daemon's original operator must configure and verify its operational profile. The supported implementation currently uses finite room sessions; it does not provide automatic renewal, reconnect, a durable outbound queue, or a persistent remote-delivery query. An always-on operational deployment needs an owner-managed lifecycle and observable outcomes before it can claim continuous availability.

The [native federation contract](native-bus-federation.md) defines the wire, identity, persistence and room checks. The [consumer delivery contract](native-consumer-delivery.md) separates publication from processing and admitted work.

## Owner-controlled setup

The deployment operator supplies these public selections from the current accepted deployment record:

- Local repository, local daemon port and actual local daemon public endpoint ID.
- Exact peer daemon public endpoint ID, coordinator HTTPS origin and coordinator public pin.
- Owned Iroh relay HTTPS origin and the independently selected expected relay origin.
- Configuration ID and generation, with the applicable transport authority and original room validity.

Do not infer these values from a seat suffix, an SSH address, an old PID, a cached state file, or another agent's private profile. Existing identity keys stay opaque. A requested key rotation, unsafe-file migration, controller restart or route change belongs to its actual owner and must preserve the relevant preimage and disposition.

Before enabling native journal writers, the original operator reconciles and retires any competing journal-copy or remote-handset transport. Preserve uncertain originals and conflicting writes; do not start a second writer or adopt an unidentified controller.

Start the daemon locally, under the operator's direct process supervision, with the supported selections:

```sh
chinwag bus daemon \
  --repo "$CHINWAG_OPS_REPO" --port "$CHINWAG_OPS_PORT" --no-governors \
  --network-room-origin "$CHINWAG_OPS_COORDINATOR_ORIGIN" \
  --network-coordinator "$CHINWAG_OPS_COORDINATOR_ID" \
  --network-peer "$CHINWAG_OPS_PEER_ID" \
  --relay-origin "$CHINWAG_OPS_RELAY_ORIGIN" \
  --expected-relay-origin "$CHINWAG_OPS_EXPECTED_RELAY_ORIGIN" \
  --network-configuration "$CHINWAG_OPS_CONFIG_ID" \
  --network-generation "$CHINWAG_OPS_GENERATION" \
  --relay-only
```

The variables above are deployment inputs, not new CLI options or a new configuration loader. They must be populated and checked by the operator before running the command. Matching strings alone do not enroll a peer: the existing current advertisement, coordinator receipt and endpoint checks still apply.

The coordinator must admit the operational daemon IDs, rather than unrelated proof identities. The relay must authorize those same selected endpoints. Preserve unrelated pilot scopes, secrets, actor policies and migration history when preparing a deployment. A temporary Quick Tunnel can support a bounded session, but its URL and lifetime are not a persistent service guarantee.

## Send from the originating node

Use the current local daemon explicitly. These selections make an unavailable or invalid route fail closed instead of silently publishing to a local file:

```sh
CHINWAG_BUS_ADDR="127.0.0.1:$CHINWAG_OPS_PORT" \
CHINWAG_BUS_ENDPOINT_ID="$CHINWAG_OPS_LOCAL_DAEMON_ID" \
chinwag bus send --repo "$CHINWAG_OPS_REPO" \
  --from "$CHINWAG_OPS_FROM" --room '#eng' \
  --to "$CHINWAG_OPS_RECIPIENT" --task "$CHINWAG_OPS_TASK" \
  --message "$CHINWAG_OPS_BODY" --json
```

Sender and recipient use their full seat-and-instance addresses. Use one `--to` argument; an intentional multi-recipient send uses one comma-separated list. Repeated recipient flags are rejected. Preserve the original message ID, digest, task binding and deadline throughout the exchange.

Do not substitute an SSH-executed send on the peer for a failed local send. SSH can remain an owner control and audit channel, and can carry separately authorized source or proof artifacts; neither use establishes message delivery through the relay.

## Confirm the specific result

Keep these observations separate:

| Observation | Supported conclusion |
| --- | --- |
| Local CLI publication ACK | The selected local publication exchange returned its result; completion remains `PUBLISH_ONLY`. |
| Matching daemon `native_federation_ack` | The authenticated peer acknowledged journal publication of that exact original ID and digest over the observed selected relay path. |
| Independent destination journal readback | The selected destination currently stores the exact signed original. |
| Recipient's qualified inbox read and correlated processing response | Evidence of that recipient's processing, within the scope actually observed. |
| Separately admitted, observed child start | The specified work started; a transport or processing ACK alone cannot establish this. |

For remote publication, correlate the daemon's federation ACK with the original ID and digest, expected peer endpoint and exact selected owned relay. Retain that evidence under the operational owner. The current CLI exposes the event on daemon stdout; it does not yet provide a persistent delivery-status query. An absent event remains unknown.

For work requests, the original recipient reads its local exact-instance inbox and returns a signed response referencing the original ID and digest through its own local CF-enabled daemon. Do not manufacture a processing ACK, assume a running conversation was scheduled, or infer a child start from storage. Existing-conversation scheduling remains unsupported without its separately proved host adapter.

`bus status --json`, an `ONLINE` banner, HOME-relay selection, a WebSocket upgrade, a receiver count or a live PID is not the remote-publication acceptance condition. A HOME snapshot also cannot determine the state of every explicit non-HOME relay connection.

## Expiry, uncertainty and recovery

Current ordinary-room membership is finite. The backend issues 60-second challenges; the client enforces the original own and peer wall-clock expiries and monotonic deadlines, with a maximum accepted validity of 120 seconds. Failure, close or expiry revokes the owner and its peer gate. There is no implicit renewal or reconnect.

When membership is unavailable, stop treating the route as usable. The actual operator must establish the next authorized transport session or follow its approved lifecycle. This does not extend any task lease, invocation deadline or authority to start work. A document, restart loop or timer cannot supply that authority.

The forwarding queue is in memory. A local journal row followed by a crash, queue failure, lost ACK or room expiry can leave remote delivery unknown. Exact replay suppresses duplicate effects and does not rerun forwarding. Preserve the original ID and digest, and reconcile the exact source and destination records before any separately authorized recovery. Do not automatically generate a replacement message or replay an uncertain original.

During a deployment transition, use fresh, bounded transport probes in both directions. Confirm the selected relay path, unchanged signed originals, exact destination storage and expected direct-path failure while the daemons are online. Retain the original process exits. A probe is not a task invocation, a scheduling proof or a general production-continuity claim.

## Operational adoption

The deployment record should identify the actual operators, operational public endpoint IDs, selected origins and generation, controller ownership, session lifecycle, receipt retention, former transport disposition, and the successful local-origin round trip. Keep those deployment facts with their owner; do not publish private profiles, keys or protected proof captures in the source repository.

This SOP makes native CF relay messaging the selected procedure. Mark a deployment as migrated only after its actual operational profiles and round trip pass. Keep continuous hosting, automatic session lifecycle, durable outbound recovery, remote-receipt query, consumer scheduling and CI/ACU dual delivery distinct from the finite transport capability already implemented.
