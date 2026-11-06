//! Evidence for publication and existing-consumer processing is kept separate.
//!
//! A legacy bus ACK authenticates a publication response. It supplies neither
//! durable-storage proof nor a supported existing-conversation host receipt.

use crate::agent_instance::parse_recipients;
use serde::Serialize;

pub struct PublicationAck<'a> {
    pub message_id: &'a str,
    pub ok: bool,
    pub signature_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct RecipientFacts {
    pub recipient: String,
    pub consumer_binding: &'static str,
    pub scheduling: &'static str,
    pub processing_ack: &'static str,
    pub work_started: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct PublicationReport {
    pub schema: &'static str,
    pub completion_scope: &'static str,
    pub original_message_id: String,
    pub original_message_digest_sha256: String,
    pub publication_acknowledged: bool,
    pub persistence: &'static str,
    pub recipients: Vec<RecipientFacts>,
}

/// Report only facts supplied by the legacy publication API. Receiver counts
/// deliberately do not enter this interface. A future supported host adapter
/// must supply separate, authenticated evidence before processing can advance.
pub fn legacy_publication_report(
    message_id: &str,
    digest: &str,
    recipients: Option<&str>,
    ack: PublicationAck<'_>,
) -> PublicationReport {
    let recipients = recipients
        .and_then(|raw| parse_recipients(raw).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|recipient| RecipientFacts {
            recipient: recipient.to_string(),
            consumer_binding: "UNKNOWN",
            scheduling: "UNSUPPORTED",
            processing_ack: "UNKNOWN",
            work_started: "UNKNOWN",
            reason: "UNSUPPORTED_EXISTING_CONVERSATION_CONTROL",
        })
        .collect();
    PublicationReport {
        schema: "chinwag.delivery-report.v1",
        completion_scope: "PUBLISH_ONLY",
        original_message_id: message_id.to_owned(),
        original_message_digest_sha256: digest.to_owned(),
        publication_acknowledged: !message_id.is_empty()
            && ack.ok
            && ack.signature_verified
            && ack.message_id == message_id,
        persistence: "UNKNOWN",
        recipients,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer01_t01_ghost_receiver_is_not_processing_or_durable_storage() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(4);
        assert_eq!(tx.send("original").unwrap(), 1);
        let report = legacy_publication_report(
            "original", "digest", Some("GEMINI-PM#one,DELIVERY#two"),
            PublicationAck { message_id: "original", ok: true, signature_verified: true },
        );
        assert!(report.publication_acknowledged);
        assert_eq!(report.completion_scope, "PUBLISH_ONLY");
        assert_eq!(report.persistence, "UNKNOWN");
        assert_eq!(report.recipients.len(), 2);
        for target in report.recipients {
            assert_eq!(target.scheduling, "UNSUPPORTED");
            assert_eq!(target.processing_ack, "UNKNOWN");
            assert_eq!(target.work_started, "UNKNOWN");
        }
        assert_eq!(rx.try_recv().unwrap(), "original");
    }

    #[test]
    fn consumer01_uncorrelated_ack_is_not_publication_evidence() {
        let report = legacy_publication_report(
            "original", "digest", Some("WORKHORSE#CaseSensitive"),
            PublicationAck { message_id: "other", ok: true, signature_verified: true },
        );
        assert!(!report.publication_acknowledged);
        assert_eq!(report.recipients[0].recipient, "WORKHORSE#CaseSensitive");
        assert_eq!(report.recipients[0].consumer_binding, "UNKNOWN");
    }
}
