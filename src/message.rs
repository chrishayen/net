use blake2::Blake2s256;
use blake2s_const::Params as Blake2s;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use hmac::{Mac, SimpleHmac};
pub use x25519_dalek::{PublicKey, StaticSecret};

pub const RESERVED: [u8; 3] = [0, 0, 0];
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const MAC2_ZERO: [u8; 16] = [0; 16];

#[derive(Clone)]
pub struct KeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn new() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);

        KeyPair { private, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn public_vec(&self) -> Vec<u8> {
        self.public.to_bytes().to_vec()
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        self.private.to_bytes()
    }

    pub fn private_vec(&self) -> Vec<u8> {
        self.private.to_bytes().to_vec()
    }

    pub fn dh(&self, other: &PublicKey) -> [u8; 32] {
        let secret = self.private.diffie_hellman(&other);
        return secret.to_bytes();
    }
}

/// initiator.chaining_key = HASH(CONSTRUCTION)
pub fn initialize_chaining_key() -> Vec<u8> {
    make_hash(CONSTRUCTION.to_vec())
}

/// initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
pub fn initialize_hash(
    chaining_key: &Vec<u8>,
    static_public_key: &[u8; 32],
) -> Vec<u8> {
    let part = [&chaining_key, IDENTIFIER].concat();
    let part = make_hash(part);
    let part = [part.as_slice(), static_public_key].concat();
    make_hash(part)
}

/// HASH(input): Blake2s(input, 32), returning 32 bytes of output
pub fn make_hash(input: Vec<u8>) -> Vec<u8> {
    let hash = Blake2s::new()
        .hash_length(32)
        .to_state()
        .update(input.as_slice())
        .finalize();

    hash.as_bytes().to_vec()
}

/// HMAC(key, input): HMAC-Blake2s(key, input, 32), returning 32 bytes of output
pub fn hmac(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut mac = <SimpleHmac<Blake2s256> as KeyInit>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(input);
    mac.finalize().into_bytes().to_vec()
}

/// AEAD(key, counter, plain text, auth text)
///
/// ChaCha20Poly1305 AEAD, as specified in RFC7539,
/// with its nonce being composed of 32 bits of zeros
/// followed by the 64-bit little-endian value of counter
pub fn aead(
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

/// TAI64N(): TAI64N timestamp of current time which is 12 bytes
pub fn tai64n() -> Vec<u8> {
    tai64::Tai64N::now().to_bytes().to_vec()
}

/// MAC(key, input): Keyed-Blake2s(key, input, 16), returning 16 bytes of output
pub fn mac(key: &[u8], input: &[u8]) -> Vec<u8> {
    Blake2s::new()
        .hash_length(16)
        .key(key)
        .to_state()
        .update(input)
        .finalize()
        .as_bytes()
        .to_vec()
}

pub fn aead_decrypt(
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
