use x25519_dalek::PublicKey;

use crate::message::{
    KeyPair, LABEL_MAC1, MAC2_ZERO, RESERVED, aead, hmac, mac, make_hash,
};

const MESSAGE_TYPE: [u8; 1] = [2];

pub struct ResponderMessage {
    pub message_type: [u8; 1],
    pub reserved_zero: [u8; 3],
    pub sender_index: [u8; 4],
    pub receiver_index: [u8; 4],
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_nothing: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl ResponderMessage {
    pub fn new(
        responder_ephemeral_keys: KeyPair,
        initiator_static_public: PublicKey,
        initiator_ephemeral_public: PublicKey,
        initiator_sender_index: [u8; 4],
        responder_sender_index: [u8; 4],
        hash: Vec<u8>,
        chain: Vec<u8>,
        preshared_key: Vec<u8>,
    ) -> Self {
        /*
         *
         * Encrypted Nothing
         *
         * responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
         *
         * temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
         * responder.chaining_key = HMAC(temp, 0x1)
         *
         * temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
         * responder.chaining_key = HMAC(temp, 0x1)
         *
         * temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
         * responder.chaining_key = HMAC(temp, 0x1)
         *
         * temp = HMAC(responder.chaining_key, preshared_key)
         * responder.chaining_key = HMAC(temp, 0x1)
         * temp2 = HMAC(temp, responder.chaining_key || 0x2)
         * key = HMAC(temp, temp2 || 0x3)
         * responder.hash = HASH(responder.hash || temp2)
         *
         * msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
         *
         */

        let b = responder_ephemeral_keys.public.as_bytes().to_vec();
        let hash = make_hash([hash, b.clone()].concat());
        let temp = hmac(&chain, &b);
        let chain = hmac(&temp, &[0x1]);

        let p = initiator_ephemeral_public;
        let secret = responder_ephemeral_keys.private.diffie_hellman(&p);
        let temp = hmac(&chain, secret.as_bytes());
        let chain = hmac(&temp, &[0x1]);

        let p = initiator_static_public;
        let secret = responder_ephemeral_keys.private.diffie_hellman(&p);
        let temp = [chain, secret.as_bytes().to_vec()].concat();
        let chain = hmac(&temp, &[0x1]);

        let temp = hmac(&chain, preshared_key.as_slice());
        let chain = hmac(&temp, &[0x1]);
        let temp2 = hmac(&temp, &[chain, [0x2].to_vec()].concat());
        let key = hmac(&temp, &[temp2.clone(), [0x3].to_vec()].concat());
        let hash = make_hash([hash, temp2].concat());

        let encrypted_nothing = aead(&key, 0, vec![], &hash).unwrap();

        /*
         *
         * MAC1 and MAC2
         *
         * msg.mac1 = MAC(HASH(LABEL_MAC1 || initiator.static_public), msg[0:offsetof(msg.mac1)])
         * msg.mac2 = [zeros]
         *
         */

        let mut msg: Vec<u8> = vec![];
        msg.extend(MESSAGE_TYPE);
        msg.extend(RESERVED);
        msg.extend(responder_sender_index);
        msg.extend(initiator_sender_index);
        msg.extend(responder_ephemeral_keys.public.as_bytes());
        msg.extend(&encrypted_nothing);

        let part = [LABEL_MAC1, initiator_static_public.as_bytes()].concat();
        let part = make_hash(part);
        let mac1 = mac(&part, &msg);

        let unencrypted_ephemeral =
            responder_ephemeral_keys.public.as_bytes().to_vec();

        /*
         *
         * u8 message_type
         * u8 reserved_zero[3]
         * u32 sender_index
         * u32 receiver_index
         * u8 unencrypted_ephemeral[32]
         * u8 encrypted_nothing[AEAD_LEN(0)]
         * u8 mac1[16]
         * u8 mac2[16]
         *
         */

        ResponderMessage {
            message_type: MESSAGE_TYPE,
            reserved_zero: RESERVED,
            sender_index: responder_sender_index,
            receiver_index: initiator_sender_index,
            unencrypted_ephemeral: unencrypted_ephemeral.try_into().unwrap(),
            encrypted_nothing: encrypted_nothing.try_into().unwrap(),
            mac1: mac1.try_into().unwrap(),
            mac2: MAC2_ZERO,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut msg = vec![];
        msg.extend(self.message_type);
        msg.extend(self.reserved_zero);
        msg.extend(self.sender_index);
        msg.extend(self.receiver_index);
        msg.extend(self.unencrypted_ephemeral);
        msg.extend(self.encrypted_nothing);
        msg.extend(self.mac1);
        msg.extend(self.mac2);

        msg
    }
}
