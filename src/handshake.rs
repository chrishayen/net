use crate::node::{
    self, EphemeralSecret, PublicKey, SharedSecret, StaticKeyPair, StaticSecret,
};
use blake2::Blake2s256;
use blake2s_const::Params;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use hmac::{Mac, SimpleHmac};
use std::fmt::Error;

const INITIATE_MSG_TYPE: [u8; 1] = [1];
const INITIATE_RESERVED: [u8; 3] = [0, 0, 0];
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";
const EMPTY_HASH: [u8; 32] = [0; 32];

pub fn make_initiate_msg(
    initiator_keys: StaticKeyPair,
    responder_static_public: PublicKey,
) -> Vec<u8> {
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let initiator_chaining_key = hash(CONSTRUCTION);

    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let part = [&initiator_chaining_key, IDENTIFIER].concat();
    let part = hash(&part);
    let part = [part, Vec::from(responder_static_public.as_bytes())].concat();
    let initiator_hash = hash(&part);

    // initiator.ephemeral_private = DH_GENERATE()
    let ephemeral = node::make_ephemeral_keys();
    let initiator_ephemeral_private = ephemeral.secret;

    let mut msg = Vec::new();

    // msg.message_type = 1
    msg.extend_from_slice(&INITIATE_MSG_TYPE);

    // msg.reserved_zero = { 0, 0, 0 }
    msg.extend_from_slice(&INITIATE_RESERVED);

    // msg.sender_index = little_endian(initiator.sender_index)
    let sender_index = rand_le_bytes(4);
    msg.extend_from_slice(&sender_index);

    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let unencrypted_ephemeral = ephemeral.public.as_bytes();
    msg.extend_from_slice(unencrypted_ephemeral);

    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    let part =
        [initiator_hash, Vec::from(ephemeral.public.as_bytes())].concat();
    let initiator_hash = hash(&part);

    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    let temp = hmac(&initiator_chaining_key, unencrypted_ephemeral);
    // initiator.chaining_key = HMAC(temp, 0x1)
    let initiator_chaining_key = hmac(&temp, &[0x1]);

    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let secret =
        initiator_ephemeral_private.diffie_hellman(&responder_static_public);
    let temp = hmac(&initiator_chaining_key, secret.as_bytes());

    // initiator.chaining_key = HMAC(temp, 0x1)
    let initiator_chaining_key = hmac(&temp, &[0x1]);

    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let part = [&initiator_chaining_key[..], &[0x2]].concat();
    let key = hmac(&temp, &part);

    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    let initiator_static_public = Vec::from(initiator_keys.public.as_bytes());
    let encrypted_static =
        aead(&key, 0, initiator_static_public, &initiator_hash).unwrap();
    msg.extend_from_slice(&encrypted_static);

    // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
    let part = [initiator_hash, encrypted_static].concat();
    let initiator_hash = hash(&part);

    // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    let part = initiator_keys
        .secret
        .diffie_hellman(&responder_static_public);
    let temp = hmac(&initiator_chaining_key, part.as_bytes());

    // initiator.chaining_key = HMAC(temp, 0x1)
    let initiator_chaining_key = hmac(&temp, &[0x1]);

    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let part = [initiator_chaining_key, vec![0x2]].concat();
    let key = hmac(&temp, &part);

    // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    let timestamp = tai64n();
    let encrypted_timestamp =
        aead(&key, 0, timestamp, &initiator_hash).unwrap();
    msg.extend_from_slice(&encrypted_timestamp);

    // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
    let part = [initiator_hash, encrypted_timestamp].concat();
    let initiator_hash = hash(&part);

    // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
    let part = [LABEL_MAC1, responder_static_public.as_bytes()].concat();
    let part = hash(&part);
    let mac1 = mac(&part, &msg[..msg.len()]);
    msg.extend_from_slice(&mac1);

    // if (initiator.last_received_cookie is empty or expired)
    //     msg.mac2 = [zeros]
    msg.extend_from_slice(&[0; 16]);
    // else
    //     msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])

    msg
}

/// DH(private key, public key)
///
/// Curve25519 point multiplication of private key and public key,
/// returning 32 bytes of output
fn dh(private_key: StaticSecret, public_key: PublicKey) -> SharedSecret {
    private_key.diffie_hellman(&public_key)
}

/// DH_GENERATE()
///
/// generate a random Curve25519 private key
/// returning 32 bytes of output
fn dh_generate() -> EphemeralSecret {
    EphemeralSecret::random_from_rng(OsRng)
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

/// DH_PUBKEY(private key)
///
/// calculate a Curve25519 public key from private key,
/// returning 32 bytes of output
fn dh_pubkey(private_key: EphemeralSecret) -> PublicKey {
    PublicKey::from(&private_key)
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
    let nonce = Nonce::from_slice(&nonce);
    let payload = chacha20poly1305::aead::Payload {
        msg: &plain_text,
        aad: auth_text,
    };
    cipher.encrypt(&nonce, payload)
}

/// XAEAD(key, nonce, plain text, auth text): XChaCha20Poly1305 AEAD, with a random 24-byte nonce
fn xaead(
    key: SharedSecret,
    // nonce: u64,
    plain_text: Vec<u8>,
    auth_text: &[u8],
) -> Result<Vec<u8>, Error> {
    let r = rand_le_bytes(24);
    let nonce = Nonce::from_slice(&r);
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());

    let payload = chacha20poly1305::aead::Payload {
        msg: &plain_text,
        aad: auth_text,
    };

    let ciphertext = cipher.encrypt(&nonce, payload).unwrap();
    Ok(ciphertext)
}

/// AEAD_LEN(plain len): plain len + 16
fn aead_len(plain_text: Vec<u8>) -> usize {
    plain_text.len() + 16
}

/// HASH(input): Blake2s(input, 32), returning 32 bytes of output
fn hash(input: &[u8]) -> Vec<u8> {
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
    fn test_handshake() {
        let left_keys = node::make_static_keys();
        let right_keys = node::make_static_keys();
        let left_ephemeral_keys = node::make_ephemeral_keys();

        let initiator_msg = make_initiate_msg(left_keys, right_keys.public);

        println!("{:?}", initiator_msg);
    }

    #[test]
    fn test_hash_output_length() {
        let input = b"hello";
        let hash = hash(input);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_256_output() {
        let hash = hash(b"abc");
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
    fn test_aead_len() {
        let plain_text = b"hello";
        let len = aead_len(plain_text.to_vec());
        assert_eq!(5 + 16, len);
    }

    #[test]
    fn test_tai64n() {
        let tai64n = tai64n();
        assert_eq!(12, tai64n.len());
    }
}
