use crate::node::{
    self, EphemeralKeyPair, EphemeralSecret, PublicKey, SharedSecret,
    StaticKeyPair, StaticSecret,
};
use blake2::{Blake2s, Blake2s256};
use blake2s_const::{Hash, Params};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use hkdf::{Hkdf, SimpleHkdf};
use hmac::{Mac, SimpleHmac};
use sha2::Sha256;
use std::fmt::Error;

const INITIATE_MSG_TYPE: [u8; 1] = [1];
const INITIATE_RESERVED: [u8; 3] = [0, 0, 0];
const PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";
const EMPTY_HASH: [u8; 32] = [0; 32];

pub fn make_initiate_msg(
    initiator_keys: StaticKeyPair,
    responder_public_key: PublicKey,
) -> Vec<u8> {
    let chaining_key = hash(PROTOCOL_NAME);
    let msg_hash = hash(b"");
    let ephemeral = node::make_ephemeral_keys();
    let psk = [0u8, 4];
    let h: Vec<u8> = msg_hash
        .as_bytes()
        .iter()
        .chain(ephemeral.public.as_bytes())
        .copied()
        .collect();
    let msg_hash = hash(&h);

    let dh = initiator_keys.secret.diffie_hellman(&responder_public_key);
    let hkdf: Hkdf<Sha256> = Hkdf::new(None, chaining_key.as_bytes());
    let mut okm = [0u8; 64];

    // Info string can be empty for WireGuard's usage, as per Noise protocol
    let info = b"";

    // Perform HKDF expand to derive 64 bytes (two 32-byte keys)
    hkdf.expand(info, &mut okm).expect("HKDF expand failed");

    let mut new_chaining_key = [0u8; 32];
    let mut aead_key = [0u8; 32];
    new_chaining_key.copy_from_slice(&okm[0..32]);
    aead_key.copy_from_slice(&okm[32..64]);

    Vec::new()
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
fn rand(len: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut buf = vec![0; len];
    rng.fill_bytes(&mut buf);
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
    let r = rand(24);
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
fn hash(input: &[u8]) -> Hash {
    Params::new()
        .hash_length(32)
        .to_state()
        .update(input)
        .finalize()
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

// fn kdf(key: &[u8], input: &[u8]) -> Vec<u8> {}

/// TAI64N(): TAI64N timestamp of current time which is 12 bytes
fn tai64n() -> Vec<u8> {
    tai64::Tai64N::now().to_bytes().to_vec()
}
// CONSTRUCTION: the UTF-8 value Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, 37 bytes
// IDENTIFIER: the UTF-8 value WireGuard v1 zx2c4 Jason@zx2c4.com, 34 bytes
// LABEL_MAC1: the UTF-8 value mac1----, 8 bytes
// LABEL_COOKIE: the UTF-8 value cookie--, 8 bytes

#[cfg(test)]
mod tests {
    use crate::node;

    use super::*;

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
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_hash_256_output() {
        let hash = hash(b"abc");
        let expected =
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
        assert_eq!(base16ct::lower::encode_string(hash.as_bytes()), expected);
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
