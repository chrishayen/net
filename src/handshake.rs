use crate::{
    node::{EphemeralKeyPair, PublicKey, StaticKeyPair},
    types::HandshakeInitiationResponse,
};
use blake2::Blake2s256;
use blake2s_const::Params;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use hmac::{Mac, SimpleHmac};

const INITIATE_MSG_TYPE: [u8; 1] = [1];
const INITIATE_RESPONSE_MSG_TYPE: [u8; 1] = [2];
const INITIATE_RESERVED: [u8; 3] = [0, 0, 0];
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

// const LABEL_COOKIE: &[u8] = b"cookie--";
// const EMPTY_HASH: [u8; 32] = [0; 32];

pub fn make_initiate_msg(
    initiator_sender_index: [u8; 4],
    initiator_static_keys: StaticKeyPair,
    initiator_ephemeral_keys: EphemeralKeyPair,
    responder_static_public: PublicKey,
) -> Vec<u8> {
    // set up all the things
    let chaining_key = make_initial_chaining_key();
    let unencrypted_ephemeral = initiator_ephemeral_keys.public.as_bytes();
    let p = initiator_static_keys.public.as_bytes();
    let initiator_static_public = p.to_vec();
    let b = responder_static_public.as_bytes();
    let hash = make_initial_hash(&chaining_key, &b);

    // set up the easy stuff
    let mut msg: Vec<u8> = vec![];
    msg.extend(make_initiation_message_type());
    msg.extend(make_reserved());
    msg.extend(initiator_sender_index);
    msg.extend(unencrypted_ephemeral);

    // make the payload aead key
    let (key, hash, chaining_key) = make_payload_aead_key(
        initiator_ephemeral_keys,
        responder_static_public,
        &chaining_key,
        &hash,
    );

    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    let pt = initiator_static_public;
    let encrypted_static = aead(&key, 0, pt, &hash).unwrap();
    msg.extend_from_slice(&encrypted_static);

    // make the timestamp aead key
    let (key, hash) = make_timestamp_aead_key(
        initiator_static_keys,
        responder_static_public,
        &encrypted_static,
        &chaining_key,
        &hash,
    );

    // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    let timestamp = tai64n();
    let encrypted_timestamp = aead(&key, 0, timestamp, &hash).unwrap();
    msg.extend_from_slice(&encrypted_timestamp);

    // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
    msg.extend_from_slice(&make_mac1(responder_static_public, &msg));

    // used for future cookie handling
    // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
    // let part = [hash, encrypted_timestamp].concat();
    // let hash = hash(&part);

    // if (initiator.last_received_cookie is empty or expired)
    //     msg.mac2 = [zeros]
    msg.extend_from_slice(&[0; 16]);

    // future cookie handling
    // else
    //     msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])

    msg
}

/// Does the same operations as make_initiate_msg so that its final state variables are
/// identical, replacing the operands of the DH function to produce equivalent values.
/// verifies that the initiator's static public key matches the one in the message
pub fn verify_initiate_msg(
    msg: Vec<u8>,
    initiator_sender_index: [u8; 4],
    responder_sender_index: [u8; 4],
    responder_static_keys: StaticKeyPair,
    responder_ephemeral_keys: EphemeralKeyPair,
    initiator_static_public: PublicKey,
    preshared_key: Vec<u8>,
) -> Option<HandshakeInitiationResponse> {
    // verify the message type
    if msg[0] != 1 {
        return None;
    }

    // verify the reserved bytes
    if msg[1..4] != [0, 0, 0] {
        return None;
    }

    // set up the easy stuff
    let chaining_key = make_initial_chaining_key();
    let responder_static_public = responder_static_keys.public;
    let p = responder_static_public.as_bytes();
    let hash = make_initial_hash(&chaining_key, &p);

    // update hash
    let ephemeral_public = msg[8..40].to_vec();
    let h = [hash, Vec::from(ephemeral_public.clone())].concat();
    let hash = make_hash(&h);

    // update chaining key
    let temp = hmac(&chaining_key, &ephemeral_public);
    let chaining_key = hmac(&temp, &[0x1]);

    // get the ephemeral public key from the message
    let mut array = [0u8; 32];
    array.copy_from_slice(&ephemeral_public);
    let p = PublicKey::from(array);

    // make the payload aead key
    let secret = responder_static_keys.secret.diffie_hellman(&p);
    let temp = hmac(&chaining_key, secret.as_bytes());
    let chaining_key = hmac(&temp, &[0x1]);
    let part = [&chaining_key[..], &[0x2]].concat();
    let key = hmac(&temp, &part);

    // get the encrypted static public key from the message
    let initiator_encrypted_static = msg[40..88].to_vec();

    // decrypt the static public key
    let initiator_decrypted_static =
        aead_decrypt(&key, 0, initiator_encrypted_static, &hash).unwrap();

    // verify
    if initiator_decrypted_static != initiator_static_public.as_bytes().to_vec()
    {
        return None;
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&ephemeral_public);
    let initiator_ephemeral_public = PublicKey::from(array);

    Some(make_initiation_response_msg(
        responder_ephemeral_keys,
        initiator_static_public,
        initiator_ephemeral_public,
        initiator_sender_index,
        hash,
        chaining_key,
        preshared_key,
    ))
}

pub fn make_initiation_response_msg(
    responder_ephemeral_keys: EphemeralKeyPair,
    initiator_static_public: PublicKey,
    initiator_ephemeral_public: PublicKey,
    initiator_sender_index: [u8; 4],
    hash: Vec<u8>,
    chaining_key: Vec<u8>,
    preshared_key: Vec<u8>,
) -> HandshakeInitiationResponse {
    let mut msg: Vec<u8> = vec![];

    // msg.message_type = 2
    msg.extend(make_initiation_response_message_type());
    // msg.reserved_zero = { 0, 0, 0 }
    msg.extend(make_reserved());
    // msg.sender_index = little_endian(responder.sender_index)
    msg.extend(make_sender_index());
    // msg.receiver_index = little_endian(initiator.sender_index)
    msg.extend(initiator_sender_index);

    // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
    let b = responder_ephemeral_keys.public.as_bytes();
    msg.extend(b);

    // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
    let hash = make_hash(&[hash, b.to_vec()].concat());

    // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
    let temp = hmac(&chaining_key, b);

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac(&temp, &[0x1]);

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
    let p = initiator_ephemeral_public;
    let secret = responder_ephemeral_keys.secret.diffie_hellman(&p);
    let temp = hmac(&chaining_key, secret.as_bytes());

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac(&temp, &[0x1]);

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
    let p = initiator_static_public;
    let secret = responder_ephemeral_keys.secret.diffie_hellman(&p);
    let temp = [chaining_key, secret.as_bytes().to_vec()].concat();

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac(&temp, &[0x1]);

    // temp = HMAC(responder.chaining_key, preshared_key)
    let temp = hmac(&chaining_key, preshared_key.as_slice());
    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac(&temp, &[0x1]);

    // temp2 = HMAC(temp, responder.chaining_key || 0x2)
    let temp2 = hmac(&temp, &[chaining_key, [0x2].to_vec()].concat());

    // key = HMAC(temp, temp2 || 0x3)
    let key = hmac(&temp, &[temp2.clone(), [0x3].to_vec()].concat());

    // responder.hash = HASH(responder.hash || temp2)
    let hash = make_hash(&[hash, temp2].concat());

    // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
    let encrypted_nothing = aead(&key, 0, vec![], &hash).unwrap();

    // responder.hash = HASH(responder.hash || msg.encrypted_nothing)
    let hash = make_hash(&[hash, encrypted_nothing.clone()].concat());

    // msg.mac1 = MAC(HASH(LABEL_MAC1 || initiator.static_public), msg[0:offsetof(msg.mac1)])

    // if (responder.last_received_cookie is empty or expired)
    //     msg.mac2 = [zeros]
    // else
    //     msg.mac2 = MAC(responder.last_received_cookie, msg[0:offsetof(msg.mac2)])

    HandshakeInitiationResponse {
        message_type: 2,
        reserved_zero: [0, 0, 0],
        sender_index: 0,
        receiver_index: 0,
        unencrypted_ephemeral: [0; 32],
        encrypted_nothing: [0; 16],
        mac1: [0; 16],
        mac2: [0; 16],
    }
}

/// initiator.chaining_key = HASH(CONSTRUCTION)
fn make_initial_chaining_key() -> Vec<u8> {
    make_hash(CONSTRUCTION)
}

/// initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
fn make_initial_hash(
    chaining_key: &Vec<u8>,
    static_public_key: &[u8; 32],
) -> Vec<u8> {
    let part = [&chaining_key, IDENTIFIER].concat();
    let part = make_hash(&part);
    let part = [part.as_slice(), static_public_key].concat();
    make_hash(&part)
}

/// msg.message_type = 1
fn make_initiation_message_type() -> [u8; 1] {
    INITIATE_MSG_TYPE
}

/// msg.message_type = 2
fn make_initiation_response_message_type() -> [u8; 1] {
    INITIATE_RESPONSE_MSG_TYPE
}

/// msg.reserved_zero = { 0, 0, 0 }
fn make_reserved() -> [u8; 3] {
    INITIATE_RESERVED
}

/// msg.sender_index = little_endian(initiator.sender_index)
fn make_sender_index() -> [u8; 4] {
    let mut array = [0u8; 4];
    rand_le_bytes(4).copy_from_slice(&mut array);
    array
}

fn make_payload_aead_key(
    ephemeral_keys: EphemeralKeyPair,
    their_static_public: PublicKey,
    chaining_key: &[u8],
    hash: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    let b = ephemeral_keys.public.as_bytes();
    let hash = make_hash(&[hash, b].concat());

    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    let b = ephemeral_keys.public.as_bytes();
    let temp = hmac(&chaining_key, b);
    let chaining_key = hmac(&temp, &[0x1]);

    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let secret = ephemeral_keys.secret.diffie_hellman(&their_static_public);
    let temp = hmac(&chaining_key, secret.as_bytes());

    // initiator.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac(&temp, &[0x1]);

    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let part = [&chaining_key[..], &[0x2]].concat();
    let key = hmac(&temp, &part);
    (key, hash, chaining_key)
}

fn make_timestamp_aead_key(
    initiator_static_keys: StaticKeyPair,
    responder_static_public: PublicKey,
    encrypted_static: &[u8],
    chaining_key: &[u8],
    hash: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
    let part = [hash, encrypted_static].concat();
    let hash = make_hash(&part);

    // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    let part = initiator_static_keys
        .secret
        .diffie_hellman(&responder_static_public);
    let temp = hmac(&chaining_key, part.as_bytes());

    // initiator.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac(&temp, &[0x1]);

    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let part = [chaining_key[..].as_ref(), &[0x2]].concat();
    let key = hmac(&temp, &part);
    (key, hash)
}

fn make_mac1(responder_static_public: PublicKey, msg: &[u8]) -> Vec<u8> {
    let part = [LABEL_MAC1, responder_static_public.as_bytes()].concat();
    let part = make_hash(&part);
    mac(&part, &msg[..msg.len()])
}

/// RAND(len)
///
/// return len random bytes of output
fn rand_le_bytes(len: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut buf = vec![0; len];

    while buf.len() < len {
        buf.extend_from_slice(&rng.next_u32().to_le_bytes());
    }

    buf.truncate(len);
    buf
}

/// AEAD(key, counter, plain text, auth text)
///
/// ChaCha20Poly1305 AEAD, as specified in RFC7539,
/// with its nonce being composed of 32 bits of zeros
/// followed by the 64-bit little-endian value of counter
fn aead(
    key: &[u8],
    counter: u64,
    plain_text: Vec<u8>,
    auth_text: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    // with its nonce being composed of 32 bits of zeros
    let mut nonce = [0u8; 12];
    // followed by the 64-bit little-endian value of counter
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce);

    let cipher = <ChaCha20Poly1305 as KeyInit>::new(key.into());

    let payload = chacha20poly1305::aead::Payload {
        msg: &plain_text,
        aad: auth_text,
    };
    cipher.encrypt(&nonce, payload)
}

fn aead_decrypt(
    key: &[u8],
    counter: u64,
    msg: Vec<u8>,
    auth_text: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    // with its nonce being composed of 32 bits of zeros
    let mut nonce = [0u8; 12];
    // followed by the 64-bit little-endian value of counter
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce);

    let cipher = <ChaCha20Poly1305 as KeyInit>::new(key.into());

    let payload = chacha20poly1305::aead::Payload {
        msg: &msg,
        aad: auth_text,
    };
    cipher.decrypt(&nonce, payload)
}

// XAEAD(key, nonce, plain text, auth text): XChaCha20Poly1305 AEAD, with a random 24-byte nonce
// fn xaead(
//     key: SharedSecret,
//     // nonce: u64,
//     plain_text: Vec<u8>,
//     auth_text: &[u8],
// ) -> Result<Vec<u8>, Error> {
//     let r = rand_le_bytes(24);
//     let nonce = Nonce::from_slice(&r);
//     let cipher = ChaCha20Poly1305::new(key.as_bytes().into());

//     let payload = chacha20poly1305::aead::Payload {
//         msg: &plain_text,
//         aad: auth_text,
//     };

//     let ciphertext = cipher.encrypt(&nonce, payload).unwrap();
//     Ok(ciphertext)
// }

/// HASH(input): Blake2s(input, 32), returning 32 bytes of output
fn make_hash(input: &[u8]) -> Vec<u8> {
    let hash = Params::new()
        .hash_length(32)
        .to_state()
        .update(input)
        .finalize();

    hash.as_bytes().to_vec()
}

/// HMAC(key, input): HMAC-Blake2s(key, input, 32), returning 32 bytes of output
fn hmac(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut mac = <SimpleHmac<Blake2s256> as KeyInit>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(input);
    mac.finalize().into_bytes().to_vec()
}

/// MAC(key, input): Keyed-Blake2s(key, input, 16), returning 16 bytes of output
fn mac(key: &[u8], input: &[u8]) -> Vec<u8> {
    Params::new()
        .hash_length(16)
        .key(key)
        .to_state()
        .update(input)
        .finalize()
        .as_bytes()
        .to_vec()
}

/// TAI64N(): TAI64N timestamp of current time which is 12 bytes
fn tai64n() -> Vec<u8> {
    tai64::Tai64N::now().to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use crate::node;

    use super::*;

    #[test]
    fn test_handshake() {
        let left_sender_index = [0, 0, 0, 1];
        let right_sender_index = [0, 0, 0, 2];
        let left = node::make_static_keys();
        let left_ephemeral = node::make_ephemeral_keys();
        let right_ephemeral = node::make_ephemeral_keys();
        let right = node::make_static_keys();

        let left_public = left.public;
        let preshared_key = b"balls".to_vec();

        let initiator_msg = make_initiate_msg(
            left_sender_index,
            left,
            left_ephemeral,
            right.public,
        );

        if let Some(responder_msg) = verify_initiate_msg(
            initiator_msg,
            left_sender_index,
            right_sender_index,
            right,
            right_ephemeral,
            left_public,
            preshared_key,
        ) {
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_concat() {
        let construction_len = CONSTRUCTION.len();
        let identifier_len = IDENTIFIER.len();
        let concat_len = construction_len + identifier_len;
        let combined = [CONSTRUCTION, IDENTIFIER].concat();
        assert_eq!(combined.len(), concat_len);
        assert_eq!(combined[0..construction_len], *CONSTRUCTION);
        assert_eq!(combined[construction_len..], *IDENTIFIER);
    }

    #[test]
    fn test_hash_output_length() {
        let input = b"hello";
        let hash = make_hash(input);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_256_output() {
        let hash = make_hash(b"abc");
        let expected =
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
        assert_eq!(base16ct::lower::encode_string(&hash), expected);
    }

    #[test]
    fn test_mac_output_length() {
        let key = b"my secret and secure key";
        let input = b"input message";
        let mac = mac(key, input);
        assert_eq!(16, mac.len());
    }

    #[test]
    fn test_hmac_output_length() {
        let key = b"my secret and secure key";
        let input = b"input message";
        let mac = hmac(key, input);
        assert_eq!(32, mac.len());
    }

    #[test]
    fn test_tai64n() {
        let tai64n = tai64n();
        assert_eq!(12, tai64n.len());
    }
}
