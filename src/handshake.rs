use chacha20poly1305::aead::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub fn generate_key_pair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_generates_key_pair() {
        // Generate two key pairs to verify they're different
        let (secret1, public1) = generate_key_pair();
        let (secret2, public2) = generate_key_pair();

        // Verify the public key is correctly derived from the secret
        let derived_public1 = PublicKey::from(&secret1);
        assert_eq!(public1, derived_public1);

        // Verify the keys are different each time
        assert_ne!(public1, public2);

        // Verify the public key
        let derived_public1 = PublicKey::from(&secret1);
        let derived_public2 = PublicKey::from(&secret2);
        assert_eq!(public1, derived_public1);
        assert_eq!(public2, derived_public2);
        assert_ne!(derived_public1, derived_public2);

        // verify the shared secret is the same for both parties
        let shared_1 = secret1.diffie_hellman(&public2);
        let shared_2 = secret2.diffie_hellman(&public1);
        assert_eq!(shared_1.as_bytes(), shared_2.as_bytes());
    }
}
