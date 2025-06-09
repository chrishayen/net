use chacha20poly1305::aead::OsRng;
pub use x25519_dalek::{
    EphemeralSecret, PublicKey, SharedSecret, StaticSecret,
};

pub struct StaticKeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

pub struct EphemeralKeyPair {
    pub secret: EphemeralSecret,
    pub public: PublicKey,
}

pub fn make_static_keys() -> StaticKeyPair {
    let static_secret = StaticSecret::random_from_rng(OsRng);
    let static_public_key = PublicKey::from(&static_secret);
    StaticKeyPair {
        secret: static_secret,
        public: static_public_key,
    }
}

pub fn make_ephemeral_keys() -> EphemeralKeyPair {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret);
    EphemeralKeyPair {
        secret: ephemeral_secret,
        public: ephemeral_public_key,
    }
}
