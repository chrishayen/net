use x25519_dalek::PublicKey;

use crate::{
    initiator_msg::InitiatorMessage,
    message::{KeyPair, rand_le_bytes},
};

pub struct Handshake {
    static_keys: KeyPair,
    ephemeral_keys: KeyPair,
    peer_public: PublicKey,
    hash: Vec<u8>,
    chain: Vec<u8>,
    sender_index: [u8; 4],
}

impl Handshake {
    pub fn new(static_keys: KeyPair, peer_public: PublicKey) -> Self {
        let ephemeral_keys = KeyPair::new();
        let sender_index = Self::make_sender_index();

        Self {
            static_keys,
            ephemeral_keys,
            peer_public,
            hash: vec![],
            chain: vec![],
            sender_index,
        }
    }

    pub fn make_initiate_msg(&mut self) -> InitiatorMessage {
        let msg = InitiatorMessage::new(
            &self.sender_index,
            &self.static_keys,
            &self.ephemeral_keys,
            &self.peer_public,
        );

        self.hash = msg.hash.clone();
        self.chain = msg.chain.clone();

        msg
    }

    pub fn verify_initiator_message(
        &mut self,
        initiator_message: Vec<u8>,
    ) -> bool {
        let rs = InitiatorMessage::verify(
            initiator_message,
            self.static_keys.clone(),
            self.peer_public,
        );

        if rs.is_some() {
            (self.hash, self.chain) = rs.unwrap();
            return true;
        }

        false
    }

    fn make_sender_index() -> [u8; 4] {
        let mut array = [0u8; 4];
        rand_le_bytes(4).copy_from_slice(&mut array);
        array
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake() {
        let left_keys = KeyPair::new();
        let right_keys = KeyPair::new();

        let mut left = Handshake::new(left_keys.clone(), right_keys.public);
        let mut right = Handshake::new(right_keys.clone(), left_keys.public);

        let initiate_msg = left.make_initiate_msg();
        let verified = right.verify_initiator_message(initiate_msg.to_bytes());

        assert!(verified);
    }
}
