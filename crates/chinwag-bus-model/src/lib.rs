use std::collections::BTreeMap;

use chinwag_bus_client::{BusMessage, SendReceipt};

/// The most recent messages retained for the selected room.
pub const MAX_HISTORY: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendState {
    Idle,
    Sending {
        body: String,
    },
    Delivered {
        id: String,
        seq: u64,
        transport: String,
        sig_verified: bool,
    },
    Uncertain {
        body: String,
        error: String,
    },
}

#[derive(Debug)]
pub struct Conversation {
    pub room: String,
    pub messages: Vec<BusMessage>,
    pub last_error: Option<String>,
    pub send_state: SendState,
    load_generation: u64,
    send_generation: u64,
    pending_send: Option<PendingSend>,
}

#[derive(Debug)]
struct PendingSend {
    generation: u64,
    room: String,
    body: String,
}

impl Conversation {
    pub fn new(room: &str) -> Self {
        Self {
            room: room.to_owned(),
            messages: Vec::new(),
            last_error: None,
            send_state: SendState::Idle,
            load_generation: 0,
            send_generation: 0,
            pending_send: None,
        }
    }

    /// Starts a new history load. Changing rooms also invalidates pending send results.
    pub fn select_room(&mut self, room: &str) -> u64 {
        self.load_generation = self.load_generation.wrapping_add(1);
        if self.room != room {
            self.room = room.to_owned();
            self.messages.clear();
            self.last_error = None;
            if let Some(pending) = self.pending_send.take() {
                let error = format!(
                    "Room changed while sending to {}. Delivery is unknown; the original text is retained. Check that room before sending again.",
                    pending.room
                );
                self.last_error = Some(error.clone());
                self.send_state = SendState::Uncertain {
                    body: pending.body,
                    error,
                };
            } else if matches!(self.send_state, SendState::Delivered { .. }) {
                self.send_state = SendState::Idle;
            }
        }
        self.load_generation
    }

    pub fn load_generation(&self) -> u64 {
        self.load_generation
    }

    /// Merges an observed page into history without removing newer send receipts.
    pub fn apply_messages(&mut self, generation: u64, messages: Vec<BusMessage>) -> bool {
        if generation != self.load_generation {
            return false;
        }
        if messages.iter().any(|message| message.room != self.room) {
            self.last_error = Some(format!(
                "History contained a message outside the selected room {}.",
                self.room
            ));
            return false;
        }
        self.merge_messages(messages);
        self.last_error = None;
        true
    }

    pub fn begin_send(&mut self, body: &str) -> Result<u64, String> {
        if body.trim().is_empty() {
            return Err("Enter a message before sending.".to_owned());
        }
        if self.pending_send.is_some() || matches!(self.send_state, SendState::Sending { .. }) {
            return Err("A message is already being sent. Wait for its result.".to_owned());
        }
        self.send_generation = self.send_generation.wrapping_add(1);
        self.pending_send = Some(PendingSend {
            generation: self.send_generation,
            room: self.room.clone(),
            body: body.to_owned(),
        });
        self.send_state = SendState::Sending {
            body: body.to_owned(),
        };
        self.last_error = None;
        Ok(self.send_generation)
    }

    pub fn confirm_send(&mut self, generation: u64, receipt: SendReceipt) -> bool {
        let Some(pending) = self.pending_send.as_ref() else {
            return false;
        };
        if pending.generation != generation || pending.room != self.room {
            return false;
        }
        let message = &receipt.message;
        let ack = &receipt.ack;
        if !ack.ok
            || message.room != pending.room
            || ack.room != pending.room
            || message.id.is_empty()
            || ack.message_id != message.id
            || ack.seq != message.seq
            || (message.body != pending.body && message.body != pending.body.trim())
            || ack.transport.trim().is_empty()
        {
            self.fail_send(
                generation,
                format!(
                    "The bus response did not confirm this message in {}. Delivery is unknown; check the room before sending again.",
                    pending.room
                ),
            );
            return false;
        }
        let delivered = SendState::Delivered {
            id: message.id.clone(),
            seq: message.seq,
            transport: ack.transport.clone(),
            sig_verified: message.sig_verified && ack.sig_verified,
        };
        self.merge_messages(vec![receipt.message]);
        self.pending_send = None;
        self.send_state = delivered;
        self.last_error = None;
        true
    }

    /// Records an ambiguous result; this model never retries or republishes a send.
    pub fn fail_send(&mut self, generation: u64, error: String) {
        if !self
            .pending_send
            .as_ref()
            .is_some_and(|pending| pending.generation == generation && pending.room == self.room)
        {
            return;
        }
        let Some(pending) = self.pending_send.take() else {
            return;
        };
        self.last_error = Some(error.clone());
        self.send_state = SendState::Uncertain {
            body: pending.body,
            error,
        };
    }

    fn merge_messages(&mut self, incoming: Vec<BusMessage>) {
        let mut by_id = BTreeMap::new();
        for message in self.messages.drain(..).chain(incoming) {
            if message.room == self.room {
                by_id.insert(message.id.clone(), message);
            }
        }
        self.messages = by_id.into_values().collect();
        self.messages
            .sort_by(|left, right| (left.seq, &left.id).cmp(&(right.seq, &right.id)));
        if self.messages.len() > MAX_HISTORY {
            self.messages.drain(..self.messages.len() - MAX_HISTORY);
        }
    }
}
