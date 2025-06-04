use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use hex_literal::hex;
use hkdf::Hkdf;

use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub fn poly_proof() -> Result<(), Box<dyn std::error::Error>> {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = cipher
        .encrypt(&nonce, b"plaintext message".as_ref())
        .map_err(|e| e.to_string())?;

    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| e.to_string())?;

    assert_eq!(&plaintext, b"plaintext message");

    Ok(())
}

pub fn kjdf_proof() -> Result<(), Box<dyn std::error::Error>> {
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm)
        .expect("42 is a valid length for Sha256 to output");

    let expected = hex!(
        "
    3cb25f25faacd57a90434f64d0362f2a
    2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    34007208d5b887185865
"
    );
    assert_eq!(okm, expected);

    Ok(())
}

pub fn x25519_proof() -> Result<(), Box<dyn std::error::Error>> {
    let alice_secret = EphemeralSecret::random_from_rng(OsRng);
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = EphemeralSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_secret);

    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
    assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());

    Ok(())
}
