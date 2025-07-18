use crate::message::{
    KeyPair, LABEL_MAC1, MAC2_ZERO, PublicKey, RESERVED, aead, aead_decrypt,
    hmac, initialize_chaining_key, initialize_hash, mac, make_hash, tai64n,
};

const INITIATION_MESSAGE_TYPE: [u8; 1] = [1];
const RESPONSE_MESSAGE_TYPE: [u8; 1] = [2];

pub struct WireGuardHandshake {
    pub static_keys: KeyPair,
    pub ephemeral_keys: Option<KeyPair>,
    pub peer_static_public: Option<PublicKey>,
    pub chaining_key: Vec<u8>,
    pub hash: Vec<u8>,
    pub sender_index: [u8; 4],
    pub receiver_index: Option<[u8; 4]>,
}

pub struct InitiationMessage {
    pub message_type: [u8; 1],
    pub reserved: [u8; 3],
    pub sender_index: [u8; 4],
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

pub struct ResponseMessage {
    pub message_type: [u8; 1],
    pub reserved: [u8; 3],
    pub sender_index: [u8; 4],
    pub receiver_index: [u8; 4],
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_empty: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl WireGuardHandshake {
    pub fn new(static_keys: KeyPair, sender_index: [u8; 4]) -> Self {
        Self {
            static_keys,
            ephemeral_keys: None,
            peer_static_public: None,
            chaining_key: vec![],
            hash: vec![],
            sender_index,
            receiver_index: None,
        }
    }

    pub fn create_initiation_message(
        &mut self,
        peer_static_public: PublicKey,
    ) -> InitiationMessage {
        self.peer_static_public = Some(peer_static_public.clone());
        self.ephemeral_keys = Some(KeyPair::new());

        let ephemeral_keys = self.ephemeral_keys.as_ref().unwrap();

        // Initialize protocol state
        self.chaining_key = initialize_chaining_key();
        self.hash =
            initialize_hash(&self.chaining_key, &peer_static_public.to_bytes());

        // Update hash with ephemeral public key
        self.hash = make_hash(
            [self.hash.clone(), ephemeral_keys.public_vec()].concat(),
        );

        // First DH: ephemeral_private * peer_static_public
        let temp = hmac(&self.chaining_key, &ephemeral_keys.public_bytes());
        self.chaining_key = hmac(&temp, &[0x1]);
        let secret = ephemeral_keys.dh(&peer_static_public);
        let temp = hmac(&self.chaining_key, &secret);
        self.chaining_key = hmac(&temp, &[0x1]);
        let key = hmac(&temp, &[&self.chaining_key[..], &[0x2]].concat());

        // Encrypt static public key
        let encrypted_static =
            aead(&key, 0, self.static_keys.public_vec(), &self.hash).unwrap();

        // Update hash with encrypted static
        self.hash =
            make_hash([self.hash.clone(), encrypted_static.clone()].concat());

        // Second DH: static_private * peer_static_public
        let temp = hmac(
            &self.chaining_key,
            &self.static_keys.dh(&peer_static_public),
        );
        self.chaining_key = hmac(&temp, &[0x1]);
        let key = hmac(&temp, &[&self.chaining_key[..], &[0x2]].concat());

        // Encrypt timestamp
        let timestamp = tai64n();
        let encrypted_timestamp = aead(&key, 0, timestamp, &self.hash).unwrap();

        // Calculate MAC1
        let k = [LABEL_MAC1, &peer_static_public.to_bytes()].concat();
        let mac_key = make_hash(k);

        let mut msg_bytes = vec![];
        msg_bytes.extend(INITIATION_MESSAGE_TYPE);
        msg_bytes.extend(RESERVED);
        msg_bytes.extend(&self.sender_index);
        msg_bytes.extend(&ephemeral_keys.public_bytes());
        msg_bytes.extend(&encrypted_static);
        msg_bytes.extend(&encrypted_timestamp);

        let mac1 = mac(&mac_key, &msg_bytes);

        InitiationMessage {
            message_type: INITIATION_MESSAGE_TYPE,
            reserved: RESERVED,
            sender_index: self.sender_index,
            unencrypted_ephemeral: ephemeral_keys.public_bytes(),
            encrypted_static: encrypted_static.try_into().unwrap(),
            encrypted_timestamp: encrypted_timestamp.try_into().unwrap(),
            mac1: mac1.try_into().unwrap(),
            mac2: MAC2_ZERO,
        }
    }

    pub fn consume_initiation_message(
        &mut self,
        msg: &InitiationMessage,
        peer_static_public: PublicKey,
    ) -> bool {
        // Verify message type
        if msg.message_type != INITIATION_MESSAGE_TYPE {
            return false;
        }

        // Verify reserved bytes
        if msg.reserved != RESERVED {
            return false;
        }

        self.peer_static_public = Some(peer_static_public.clone());
        self.receiver_index = Some(msg.sender_index);

        // Initialize protocol state
        self.chaining_key = initialize_chaining_key();
        self.hash = initialize_hash(
            &self.chaining_key,
            &self.static_keys.public.to_bytes(),
        );

        // Get peer ephemeral public key
        let peer_ephemeral_public = PublicKey::from(msg.unencrypted_ephemeral);

        // Update hash with peer ephemeral public key
        self.hash = make_hash(
            [self.hash.clone(), peer_ephemeral_public.as_bytes().to_vec()]
                .concat(),
        );

        // First DH: static_private * peer_ephemeral_public
        let temp = hmac(&self.chaining_key, &msg.unencrypted_ephemeral);
        self.chaining_key = hmac(&temp, &[0x1]);
        let secret = self.static_keys.dh(&peer_ephemeral_public);
        let temp = hmac(&self.chaining_key, &secret);
        self.chaining_key = hmac(&temp, &[0x1]);
        let key = hmac(&temp, &[&self.chaining_key[..], &[0x2]].concat());

        // Decrypt and verify static public key
        let decrypted_static = match aead_decrypt(
            &key,
            0,
            msg.encrypted_static.to_vec(),
            &self.hash,
        ) {
            Ok(data) => data,
            Err(_) => return false,
        };

        if decrypted_static != peer_static_public.as_bytes() {
            return false;
        }

        // Update hash with encrypted static
        self.hash = make_hash(
            [self.hash.clone(), msg.encrypted_static.to_vec()].concat(),
        );

        // Second DH: static_private * peer_static_public
        let temp = hmac(
            &self.chaining_key,
            &self.static_keys.dh(&peer_static_public),
        );
        self.chaining_key = hmac(&temp, &[0x1]);
        let key = hmac(&temp, &[&self.chaining_key[..], &[0x2]].concat());

        // Decrypt and verify timestamp
        let _timestamp = match aead_decrypt(
            &key,
            0,
            msg.encrypted_timestamp.to_vec(),
            &self.hash,
        ) {
            Ok(data) => data,
            Err(_) => return false,
        };

        true
    }

    pub fn create_response_message(&mut self) -> ResponseMessage {
        self.ephemeral_keys = Some(KeyPair::new());
        let ephemeral_keys = self.ephemeral_keys.as_ref().unwrap();
        let peer_static_public = self.peer_static_public.as_ref().unwrap();

        // Update hash with ephemeral public key
        self.hash = make_hash(
            [self.hash.clone(), ephemeral_keys.public_vec()].concat(),
        );

        // First DH: ephemeral_private * peer_ephemeral_public (from initiation message)
        let temp = hmac(&self.chaining_key, &ephemeral_keys.public_bytes());
        self.chaining_key = hmac(&temp, &[0x1]);

        // Second DH: ephemeral_private * peer_static_public
        let secret = ephemeral_keys.dh(peer_static_public);
        let temp = hmac(&self.chaining_key, &secret);
        self.chaining_key = hmac(&temp, &[0x1]);
        let key = hmac(&temp, &[&self.chaining_key[..], &[0x2]].concat());

        // Encrypt empty payload
        let encrypted_empty = aead(&key, 0, vec![], &self.hash).unwrap();

        // Calculate MAC1
        let k = [LABEL_MAC1, &peer_static_public.to_bytes()].concat();
        let mac_key = make_hash(k);

        let mut msg_bytes = vec![];
        msg_bytes.extend(RESPONSE_MESSAGE_TYPE);
        msg_bytes.extend(RESERVED);
        msg_bytes.extend(&self.sender_index);
        msg_bytes.extend(&self.receiver_index.unwrap());
        msg_bytes.extend(&ephemeral_keys.public_bytes());
        msg_bytes.extend(&encrypted_empty);

        let mac1 = mac(&mac_key, &msg_bytes);

        ResponseMessage {
            message_type: RESPONSE_MESSAGE_TYPE,
            reserved: RESERVED,
            sender_index: self.sender_index,
            receiver_index: self.receiver_index.unwrap(),
            unencrypted_ephemeral: ephemeral_keys.public_bytes(),
            encrypted_empty: encrypted_empty.try_into().unwrap(),
            mac1: mac1.try_into().unwrap(),
            mac2: MAC2_ZERO,
        }
    }

    pub fn consume_response_message(&mut self, msg: &ResponseMessage) -> bool {
        // Verify message type
        if msg.message_type != RESPONSE_MESSAGE_TYPE {
            return false;
        }

        // Verify reserved bytes
        if msg.reserved != RESERVED {
            return false;
        }

        // Verify receiver index matches our sender index
        if msg.receiver_index != self.sender_index {
            return false;
        }

        self.receiver_index = Some(msg.sender_index);

        // Get peer ephemeral public key
        let peer_ephemeral_public = PublicKey::from(msg.unencrypted_ephemeral);

        // Update hash with peer ephemeral public key
        self.hash = make_hash(
            [self.hash.clone(), peer_ephemeral_public.as_bytes().to_vec()]
                .concat(),
        );

        // First DH: ephemeral_private * peer_ephemeral_public
        let temp = hmac(&self.chaining_key, &msg.unencrypted_ephemeral);
        self.chaining_key = hmac(&temp, &[0x1]);

        // Second DH: static_private * peer_ephemeral_public
        let secret = self.static_keys.dh(&peer_ephemeral_public);
        let temp = hmac(&self.chaining_key, &secret);
        self.chaining_key = hmac(&temp, &[0x1]);
        let key = hmac(&temp, &[&self.chaining_key[..], &[0x2]].concat());

        // Decrypt and verify empty payload
        let decrypted_empty = match aead_decrypt(
            &key,
            0,
            msg.encrypted_empty.to_vec(),
            &self.hash,
        ) {
            Ok(data) => data,
            Err(_) => return false,
        };

        if !decrypted_empty.is_empty() {
            return false;
        }

        true
    }

    pub fn derive_keys(&self) -> (Vec<u8>, Vec<u8>) {
        let temp = hmac(&self.chaining_key, &[]);
        let key1 = hmac(&temp, &[&self.chaining_key[..], &[0x1]].concat());
        let key2 = hmac(&temp, &[&key1[..], &[0x2]].concat());
        (key1, key2)
    }
}

impl InitiationMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.message_type);
        bytes.extend(self.reserved);
        bytes.extend(self.sender_index);
        bytes.extend(self.unencrypted_ephemeral);
        bytes.extend(self.encrypted_static);
        bytes.extend(self.encrypted_timestamp);
        bytes.extend(self.mac1);
        bytes.extend(self.mac2);
        bytes
    }
}

impl ResponseMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.message_type);
        bytes.extend(self.reserved);
        bytes.extend(self.sender_index);
        bytes.extend(self.receiver_index);
        bytes.extend(self.unencrypted_ephemeral);
        bytes.extend(self.encrypted_empty);
        bytes.extend(self.mac1);
        bytes.extend(self.mac2);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_handshake() {
        let initiator_keys = KeyPair::new();
        let responder_keys = KeyPair::new();

        let mut initiator =
            WireGuardHandshake::new(initiator_keys.clone(), [1, 0, 0, 0]);
        let mut responder =
            WireGuardHandshake::new(responder_keys.clone(), [2, 0, 0, 0]);

        // Initiator creates initiation message
        let initiation =
            initiator.create_initiation_message(responder_keys.public.clone());

        // Responder consumes initiation message
        assert!(responder.consume_initiation_message(
            &initiation,
            initiator_keys.public.clone()
        ));

        // Responder creates response message
        let response = responder.create_response_message();

        // Initiator consumes response message
        assert!(initiator.consume_response_message(&response));

        // Both parties should now be able to derive the same keys
        let (initiator_key1, initiator_key2) = initiator.derive_keys();
        let (responder_key1, responder_key2) = responder.derive_keys();

        assert_eq!(initiator_key1, responder_key1);
        assert_eq!(initiator_key2, responder_key2);
    }

    #[test]
    fn test_message_serialization() {
        let keys = KeyPair::new();
        let peer_keys = KeyPair::new();
        let mut handshake = WireGuardHandshake::new(keys, [0; 4]);

        let initiation = handshake.create_initiation_message(peer_keys.public);
        let bytes = initiation.to_bytes();
        assert_eq!(bytes.len(), 148); // WireGuard initiation message length

        // Need to set receiver_index before creating response message
        handshake.receiver_index = Some([1, 0, 0, 0]);
        let response = handshake.create_response_message();
        let bytes = response.to_bytes();
        assert_eq!(bytes.len(), 92); // WireGuard response message length
    }
}
