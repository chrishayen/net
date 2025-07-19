use crate::message::{
    KeyPair, LABEL_MAC1, MAC2_ZERO, PublicKey, RESERVED, aead, aead_decrypt,
    hmac, initialize_chaining_key, initialize_hash, mac, make_hash, tai64n,
};

const MESSAGE_TYPE: [u8; 1] = [1];

pub struct InitiatorMessage {
    // message fields
    pub message_type: [u8; 1],
    pub reserved_zero: [u8; 3],
    pub sender_index: [u8; 4],
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],

    // utility fields
    pub hash: Vec<u8>,
    pub chain: Vec<u8>,
    pub static_key: Vec<u8>,
    pub timestamp_key: Vec<u8>,
}

impl InitiatorMessage {
    pub fn new(
        sender_index: &[u8; 4],
        static_keys: &KeyPair,
        ephemeral_keys: &KeyPair,
        responder_public: &PublicKey,
    ) -> Self {
        let chain = initialize_chaining_key();
        let hash = initialize_hash(&chain, &responder_public.to_bytes());
        let ephemeral_public = ephemeral_keys.public_bytes();
        let initiator_public = static_keys.public_vec();

        /*
         * Encrypted static
         *
         * initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
         * temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
         * temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
         * initiator.chaining_key = HMAC(temp, 0x1)
         * key = HMAC(temp, initiator.chaining_key || 0x2)
         * msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
         *
         */

        let hash =
            make_hash([hash.to_vec(), ephemeral_keys.public_vec()].concat());
        let temp = hmac(&chain, &ephemeral_keys.public_bytes());
        let chain = hmac(&temp, &[0x1]);
        let secret = ephemeral_keys.dh(&responder_public);
        let temp = hmac(&chain, &secret);
        let chain = hmac(&temp, &[0x1]);
        let key = hmac(&temp, &[&chain[..], &[0x2]].concat());
        let encrypted_static = aead(&key, 0, initiator_public, &hash).unwrap();
        let static_key = key;

        /*
         *
         * Encrypted timestamp
         *
         * initiator.hash = HASH(initiator.hash || msg.encrypted_static)
         * temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
         * initiator.chaining_key = HMAC(temp, 0x1)
         * key = HMAC(temp, initiator.chaining_key || 0x2)
         * msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
         *
         */

        let h = make_hash([hash.to_vec(), encrypted_static.to_vec()].concat());
        let hash = make_hash(h);
        let temp = hmac(&chain, &static_keys.dh(&responder_public));
        let chain = hmac(&temp, &[0x1]);
        let key = hmac(&temp, &[chain[..].as_ref(), &[0x2]].concat());
        let timestamp = tai64n();
        let encrypted_timestamp = aead(&key, 0, timestamp, &hash).unwrap();
        let timestamp_key = key;

        /*
         *
         * MAC 1 and MAC 2
         *
         * msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
         * msg.mac2 = [zeros]
         *
         */

        let k = [LABEL_MAC1, &responder_public.to_bytes()].concat();
        let key = make_hash(k);

        let mut msg: Vec<u8> = vec![];
        msg.extend(MESSAGE_TYPE);
        msg.extend(RESERVED);
        msg.extend(sender_index);
        msg.extend(ephemeral_public);
        msg.extend(&encrypted_static);
        msg.extend(&encrypted_timestamp);

        let mac1 = mac(&key, &msg);

        /*
         *
         * u8 message_type
         * u8 reserved_zero[3]
         * u32 sender_index
         * u8 unencrypted_ephemeral[32]
         * u8 encrypted_static[AEAD_LEN(48)]
         * u8 encrypted_timestamp[AEAD_LEN(28)]
         * u8 mac1[16]
         * u8 mac2[16]
         *
         */

        let encrypted_static: [u8; 48] = encrypted_static.try_into().unwrap();
        let timestamp: [u8; 28] = encrypted_timestamp.try_into().unwrap();
        let mac1: [u8; 16] = mac1.try_into().unwrap();

        InitiatorMessage {
            message_type: MESSAGE_TYPE,
            reserved_zero: RESERVED,
            sender_index: *sender_index,
            unencrypted_ephemeral: ephemeral_public,
            encrypted_static: encrypted_static,
            encrypted_timestamp: timestamp,
            mac1: mac1,
            mac2: MAC2_ZERO,
            hash: hash,
            chain: chain,
            static_key: static_key,
            timestamp_key: timestamp_key,
        }
    }

    pub fn verify_encrypted_static(
        msg: Vec<u8>,
        static_key: Vec<u8>,
        responder_public: PublicKey,
    ) -> Option<PublicKey> {
        let encrypted_static = msg[40..88].to_vec();
        let decrypted_static = aead_decrypt(
            &static_key,
            0,
            encrypted_static,
            &responder_public.to_bytes(),
        );

        if decrypted_static.is_err() {
            return None;
        }

        let decrypted_static = decrypted_static.unwrap();
        let mut array = [0u8; 32];
        array.copy_from_slice(&decrypted_static);

        Some(PublicKey::from(array))
    }

    pub fn verify_encrypted_timestamp(
        msg: Vec<u8>,
        timestamp_key: Vec<u8>,
        responder_public: PublicKey,
    ) -> Option<tai64::Tai64N> {
        let encrypted_timestamp = msg[88..116].to_vec();
        let decrypted_timestamp = aead_decrypt(
            &timestamp_key,
            0,
            encrypted_timestamp,
            &responder_public.to_bytes(),
        );

        if decrypted_timestamp.is_err() {
            return None;
        }

        let decrypted_timestamp = decrypted_timestamp.unwrap();
        let timestamp = tai64::Tai64N::from_slice(&decrypted_timestamp);

        if timestamp.is_err() {
            return None;
        }

        Some(timestamp.unwrap())
    }

    /// Verify the initiator message
    ///
    /// Returns the hash and chaining key if the message is valid
    ///
    pub fn verify(
        msg: Vec<u8>,
        responder_static_keys: KeyPair,
        initiator_static_public: PublicKey,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let responder_public = responder_static_keys.public.to_bytes();
        let chain = initialize_chaining_key();
        let hash = initialize_hash(&chain, &responder_public);

        // verify the message type
        if msg[0] != 1 {
            return None;
        }

        // verify the reserved bytes
        if msg[1..4] != [0, 0, 0] {
            return None;
        }

        // update hash
        let ephemeral_public = msg[8..40].to_vec();
        let h = [hash, Vec::from(ephemeral_public.clone())].concat();
        let hash = make_hash(h);

        // update chaining key
        let temp = hmac(&chain, &ephemeral_public);
        let chain = hmac(&temp, &[0x1]);

        // get the ephemeral public key from the message
        let mut array = [0u8; 32];
        array.copy_from_slice(&ephemeral_public);
        let p = PublicKey::from(array);

        // make the payload aead key
        let secret = responder_static_keys.private.diffie_hellman(&p);
        let temp = hmac(&chain, secret.as_bytes());
        let chain = hmac(&temp, &[0x1]);
        let part = [&chain[..], &[0x2]].concat();
        let key = hmac(&temp, &part);

        // get the encrypted static public key from the message
        let initiator_encrypted_static = msg[40..88].to_vec();

        // decrypt the static public key
        let initiator_decrypted_static =
            aead_decrypt(&key, 0, initiator_encrypted_static, &hash).unwrap();

        if initiator_decrypted_static
            != initiator_static_public.as_bytes().to_vec()
        {
            return None;
        }

        Some((hash, chain))
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
        let initiator_keys = KeyPair::new();
        let responder_keys = KeyPair::new();
        let ephemeral_keys = KeyPair::new();

        let initiator_message = InitiatorMessage::new(
            &[0; 4],
            &initiator_keys,
            &ephemeral_keys,
            &responder_keys.public,
        );

        let bytes = initiator_message.to_bytes();
        assert_eq!(bytes.len(), 148);

        let rs = InitiatorMessage::verify(
            bytes,
            responder_keys,
            initiator_keys.public,
        );
        assert!(rs.is_some());
    }
}
