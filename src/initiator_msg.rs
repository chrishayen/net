use crate::message::{
    KeyPair, LABEL_MAC1, PublicKey, RESERVED, aead, hmac,
    initialize_chaining_key, initialize_hash, mac, make_hash, tai64n,
};

const MESSAGE_TYPE: [u8; 1] = [1];

pub struct InitiatorMessage {
    pub message_type: [u8; 1],
    pub reserved_zero: [u8; 3],
    pub sender_index: [u8; 4],
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl InitiatorMessage {
    pub fn new(
        sender_index: [u8; 4],
        static_keys: KeyPair,
        ephemeral_keys: KeyPair,
        responder_public: PublicKey,
    ) -> Self {
        let chain = initialize_chaining_key();
        let hash = initialize_hash(&chain, &responder_public.to_bytes());
        let ephemeral_public = ephemeral_keys.public_bytes();
        let initiator_public = static_keys.public_vec();

        //
        // encrypted static
        //

        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        let hash = make_hash([hash, ephemeral_keys.public_vec()].concat());

        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        let temp = hmac(&chain, &ephemeral_keys.public_bytes());
        let chaining_key = hmac(&temp, &[0x1]);

        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        let secret = ephemeral_keys.dh(&responder_public);
        let temp = hmac(&chaining_key, &secret);

        // initiator.chaining_key = HMAC(temp, 0x1)
        let chaining_key = hmac(&temp, &[0x1]);

        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let part = [&chaining_key[..], &[0x2]].concat();
        let key = hmac(&temp, &part);

        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        let encrypted_static = aead(&key, 0, initiator_public, &hash).unwrap();

        //
        // encrypted timestamp
        //

        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        let hash =
            make_hash([hash.to_vec(), encrypted_static.to_vec()].concat());

        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        let temp = hmac(&chaining_key, &static_keys.dh(&responder_public));

        // initiator.chaining_key = HMAC(temp, 0x1)
        let chaining_key = hmac(&temp, &[0x1]);

        // key = HMAC(temp, initiator.chaining_key || 0x2)
        let key = hmac(&temp, &[chaining_key[..].as_ref(), &[0x2]].concat());

        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        let timestamp = tai64n();
        let encrypted_timestamp = aead(&key, 0, timestamp, &hash).unwrap();

        //
        // mac 1 & mac 2
        //

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        let key =
            make_hash([LABEL_MAC1, &responder_public.to_bytes()].concat());

        let mut msg: Vec<u8> = vec![];
        msg.extend(MESSAGE_TYPE);
        msg.extend(RESERVED);
        msg.extend(sender_index);
        msg.extend(ephemeral_public);
        msg.extend(&encrypted_static);
        msg.extend(&encrypted_timestamp);

        let mac1 = mac(&key, &msg[..msg.len()]);
        let mac2: [u8; 16] = [0; 16];

        //
        // return
        //

        let encrypted_static: [u8; 48] = encrypted_static.try_into().unwrap();
        let timestamp: [u8; 28] = encrypted_timestamp.try_into().unwrap();
        let mac1: [u8; 16] = mac1.try_into().unwrap();

        InitiatorMessage {
            message_type: MESSAGE_TYPE,
            reserved_zero: RESERVED,
            sender_index: sender_index,
            unencrypted_ephemeral: ephemeral_public,
            encrypted_static: encrypted_static,
            encrypted_timestamp: timestamp,
            mac1: mac1,
            mac2: mac2,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.message_type);
        bytes.extend(self.reserved_zero);
        bytes.extend(self.sender_index);
        bytes.extend(self.unencrypted_ephemeral);
        bytes.extend(self.encrypted_static);
        bytes.extend(self.encrypted_timestamp);
        bytes.extend(self.mac1);
        bytes.extend(self.mac2);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_bytes() {
        let responder_public = PublicKey::from([0; 32]);

        let initiator_message = InitiatorMessage::new(
            [0; 4],
            KeyPair::new(),
            KeyPair::new(),
            responder_public,
        );

        let bytes = initiator_message.to_bytes();
        assert_eq!(bytes.len(), 148);
    }
}
