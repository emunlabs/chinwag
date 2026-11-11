use ed25519_dalek::{Signer, SigningKey};
use native_blind_relay::{protocol::*, session::*};
use serde::Serialize;

#[derive(Serialize)]
struct Auth {
    public_key: EndpointId,
    #[serde(with = "serde_bytes")]
    signature: [u8; 64],
}

fn keys() -> [SigningKey; 2] {
    [
        SigningKey::from_bytes(&[11; 32]),
        SigningKey::from_bytes(&[12; 32]),
    ]
}
fn allowed() -> [EndpointId; 2] {
    keys().map(|key| key.verifying_key().to_bytes())
}
fn auth(challenge: &[u8; 16]) -> Vec<u8> {
    let key = &keys()[0];
    let auth = Auth {
        public_key: key.verifying_key().to_bytes(),
        signature: key.sign(&challenge_message(challenge)).to_bytes(),
    };
    let mut bytes = vec![1];
    bytes.extend(postcard::to_allocvec(&auth).unwrap());
    bytes
}

#[test]
fn challenge_auth_exact_format_and_no_cross_connection_replay() {
    let bytes = auth(&[9; 16]);
    assert_eq!(bytes.len(), 98);
    assert_eq!(bytes[33], 64);
    assert_eq!(verify_auth(&bytes, &[9; 16], &allowed()), Ok(allowed()[0]));
    assert_eq!(
        verify_auth(&bytes, &[8; 16], &allowed()),
        Err(Failure::Unauthorized)
    );
    assert_eq!(
        verify_auth(&bytes, &[9; 16], &ALLOWED_ENDPOINTS),
        Err(Failure::Unauthorized)
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        verify_auth(&trailing, &[9; 16], &allowed()),
        Err(Failure::Malformed)
    );
    for len in 0..bytes.len() {
        assert!(verify_auth(&bytes[..len], &[9; 16], &allowed()).is_err());
    }
    let mut corrupt = bytes;
    corrupt[40] ^= 1;
    assert_eq!(
        verify_auth(&corrupt, &[9; 16], &allowed()),
        Err(Failure::Unauthorized)
    );
    assert_eq!(
        verify_auth(&[1; 129], &[9; 16], &allowed()),
        Err(Failure::Oversized)
    );
}

#[test]
fn authenticated_frame_directions_and_opaque_batch_are_preserved() {
    let ids = allowed();
    for (tag, suffix) in [(4, vec![3, 0, 255, 17]), (5, vec![2, 0, 2, 0, 255, 17])] {
        let mut bytes = vec![tag];
        bytes.extend(ids[1]);
        bytes.extend(&suffix);
        let frame = client_frame(&bytes, &ids[0], &ids).unwrap();
        let ClientFrame::Datagram {
            destination,
            batch,
            body,
        } = frame
        else {
            panic!("datagram required")
        };
        assert_eq!(destination, ids[1]);
        let forwarded = relay_frame(&ids[0], batch, body);
        assert_eq!(forwarded[0], tag + 2);
        assert_eq!(&forwarded[1..33], &ids[0]);
        assert_eq!(&forwarded[33..], suffix);
    }
}

#[test]
fn malformed_and_unauthorized_routing_is_rejected() {
    let ids = allowed();
    for tag in [0, 1, 2, 3, 6, 7, 8, 11, 12, 13, 63] {
        assert!(client_frame(&[tag], &ids[0], &ids).is_err());
    }
    for len in 0..34 {
        assert!(client_frame(&vec![4; len], &ids[0], &ids).is_err());
    }
    let mut single = vec![4];
    single.extend(ids[1]);
    single.push(4);
    assert_eq!(
        client_frame(&single, &ids[0], &ids),
        Err(Failure::Malformed)
    );
    single[33] = 0;
    assert!(client_frame(&single, &ids[0], &ids).is_ok());
    assert_eq!(
        client_frame(&single, &ids[1], &ids),
        Err(Failure::Unauthorized)
    );
    single[1..33].fill(0);
    assert_eq!(
        client_frame(&single, &ids[0], &ids),
        Err(Failure::Unauthorized)
    );
    assert_eq!(
        client_frame(&vec![4; MAX_MESSAGE_SIZE + 1], &ids[0], &ids),
        Err(Failure::Oversized)
    );
    let mut batch = vec![5];
    batch.extend(ids[1]);
    batch.extend([0, 0, 0]);
    assert_eq!(client_frame(&batch, &ids[0], &ids), Err(Failure::Malformed));
    for len in [0, 7, 9] {
        assert!(client_frame(&control_frame(9, &vec![0; len]), &ids[0], &ids).is_err());
    }
    assert_eq!(
        client_frame(&[0x40, 9, 1, 2, 3, 4, 5, 6, 7, 8], &ids[0], &ids),
        Ok(ClientFrame::Ping([1, 2, 3, 4, 5, 6, 7, 8]))
    );
}

#[test]
fn authentication_deadlines_single_use_and_hibernated_budgets() {
    let mut expired = Session::pending([1; 16], 100);
    assert_eq!(
        expired.authenticate(allowed()[0], 100 + AUTH_TIMEOUT_MS),
        Err(Failure::Expired)
    );
    let mut live = Session::pending([1; 16], 100);
    live.authenticate(allowed()[0], 101).unwrap();
    assert_eq!(live.authenticate(allowed()[0], 102), Err(Failure::State));
    for _ in 0..MAX_FRAMES_PER_SECOND {
        live.charge(1, 102).unwrap();
    }
    assert_eq!(live.charge(1, 102), Err(Failure::Budget));
    // An attachment roundtrip cannot reset accounting, one-time auth or ping state.
    let bytes = postcard::to_allocvec(&live).unwrap();
    let mut restored: Session = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(restored.charge(1, 102), Err(Failure::Budget));
    assert!(restored.charge(1, 1101).is_ok());
    restored.pending_ping = Some([5; 8]);
    restored.pong_deadline_ms = 1200;
    assert_eq!(restored.pong([6; 8]), Err(Failure::Malformed));
    restored.pong([5; 8]).unwrap();
    restored.total_bytes = MAX_SESSION_BYTES;
    assert_eq!(restored.charge(1, 1102), Err(Failure::Budget));
    assert_eq!(restored.check_live(99), Err(Failure::State));
    assert_eq!(
        restored.check_live(restored.expires_ms),
        Err(Failure::Expired)
    );
}

#[test]
fn protocol_negotiation_requires_exact_token() {
    assert!(accepts_protocol("iroh-relay-v1, iroh-relay-v2"));
    for value in ["", "iroh-relay-v1", "IROH-RELAY-V2", "iroh-relay-v2evil"] {
        assert!(!accepts_protocol(value));
    }
    assert!(!accepts_protocol(&"x".repeat(257)));
}
