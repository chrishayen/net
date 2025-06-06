use std::{fmt::Error, io::Read};

use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit, Nonce,
    aead::{AeadMut, OsRng, rand_core::RngCore},
};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

//
// Each party maintains the following variables:
//
// s, e:
// The local party’s static and ephemeral key pairs (which may be empty).
//
// rs re:
// The remote party’s static and ephemeral public keys (which maybe empty)
//
// h:
// A handshake hash value that hashes all the handshake data that’s been sent and received
//
// ck:
// A chaining key that hashes all previous DH outputs. Once the
// handshake completes, the chaining key will be used to derive the encryption/keys for transport messages
//
// k, n:
// An encryption key k (which may be empty) and a counter-based
// nonce n. Whenever a new DH output causes a new ck to be calculated,
// a new k is also calculated. The key k and nonce n are used to encrypt
// static public keys and handshake payloads. Encryption with k uses some
// AEAD cipher mode (in the sense of Rogaway [1]) and uses the current h
// value as associated data which is covered by the AEAD authentication.
// Encryption of static public keys and payloads provides some confidentiality
// and key confirmation during the handshake phase.

//
// **************************************************************
//

// A handshake message consists of some DH public keys followed by a payload.
// The payload may contain certificates or other data chosen by the application.
// To send a handshake message, the sender specifies the payload and sequentially
// processes each token from a message pattern. The possible tokens are:
//

// "e":
// The sender generates a new ephemeral key pair and stores it in the
// e variable, writes the ephemeral public key as cleartext into the message
// buffer, and hashes the public key along with the old h to derive a new h.
//
// "s":
// The sender writes its static public key from the s variable into the
// message buffer, encrypting it if k is non-empty, and hashes the output
// along with the old h to derive a new h.
//
// "ee", "se", "es", "ss":
// A DH is performed between the initiator’s key
// pair (whether static or ephemeral is determined by the first letter) and the
// responder’s key pair (whether static or ephemeral is determined by the
// second letter). The result is hashed along with the old ck to derive a new
// ck and k, and n is set to zero.
//
// After processing the final token in a handshake message, the sender then writes
// the payload into the message buffer, encrypting it if k is non-empty, and hashes
// the output along with the old h to derive a new h.

//
// **************************************************************
//

// DH Functions:

// GENERATE_KEYPAIR():
// Generates a new Diffie-Hellman key pair. A DH key
// pair consists of public_key and private_key elements. A public_key
// represents an encoding of a DH public key into a byte sequence of length
// DHLEN. The public_key encoding details are specific to each set of DH
// functions.

// DH(key_pair, public_key):
// Performs a Diffie-Hellman calculation between the private key in key_pair and the public_key and returns an
// output sequence of bytes of length DHLEN. For security, the Gap-DH problem
// based on this function must be unsolvable by any practical cryptanalytic
// adversary [2].
// The public_key either encodes some value which is a generator in a large
// prime-order group (which value may have multiple equivalent encodings),
// or is an invalid value. Implementations must handle invalid public keys
// either by returning some output which is purely a function of the public
// key and does not depend on the private key, or by signaling an error to
// the caller. The DH function may define more specific rules for handling
// invalid values.

// DHLEN = A constant specifying the size in bytes of public keys and DH
// outputs. For security reasons, DHLEN must be 32 or greater.

//
// **************************************************************
//

// Cipher Functions

// ENCRYPT(k, n, ad, plaintext):
// Encrypts plaintext using the cipher
// key k of 32 bytes and an 8-byte unsigned integer nonce n which must be
// unique for the key k. Returns the ciphertext. Encryption must be done
// with an “AEAD” encryption mode with the associated data ad (using the
// terminology from [1]) and returns a ciphertext that is the same size as the
// plaintext plus 16 bytes for authentication data. The entire ciphertext must
// be indistinguishable from random if the key is secret (note that this is an
// additional requirement that isn’t necessarily met by all AEAD schemes).

// DECRYPT(k, n, ad, ciphertext):
// Decrypts ciphertext using a cipher
// key k of 32 bytes, an 8-byte unsigned integer nonce n, and associated data
// ad. Returns the plaintext, unless authentication fails, in which case an
// error is signaled to the caller.

// REKEY(k):
// Returns a new 32-byte cipher key as a pseudorandom function
// of k. If this function is not specifically defined for some set of cipher
// functions, then it defaults to returning the first 32 bytes from ENCRYPT(k,
// maxnonce, zerolen, zeros), where maxnonce equals 264-1, zerolen is
// a zero-length byte sequence, and zeros is a sequence of 32 bytes filled with
// zeros.

//
// **************************************************************
//

// Hash Functions

// HASH(data):
// Hashes some arbitrary-length data with a collision-resistant
// cryptographic hash function and returns an output of HASHLEN bytes

// HASHLEN = A constant specifying the size in bytes of the hash output.
// Must be 32 or 64.

// BLOCKLEN = A constant specifying the size in bytes that the hash function
// uses internally to divide its input for iterative processing. This is needed
// to use the hash function with HMAC (BLOCKLEN is B in [3]).

//
// **************************************************************
//

// Noise defines additional functions based on the above HASH() function:
//

// HMAC-HASH(key, data):
// Applies HMAC from [3] using the HASH() function.
// This function is only called as part of HKDF(), below.

// HKDF(chaining_key, input_key_material, num_outputs):
// Takes a chaining_key byte sequence of length HASHLEN, and an input_key_material
// byte sequence with length either zero bytes, 32 bytes, or DHLEN bytes.
// Returns a pair or triple of byte sequences each of length HASHLEN,
// depending on whether num_outputs is two or three:
// – Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
// – Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
// – Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
// – If num_outputs == 2 then returns the pair (output1, output2).
// – Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
// – Returns the triple (output1, output2, output3).

// Note that temp_key, output1, output2, and output3 are all HASHLEN bytes in
// length. Also note that the HKDF() function is simply HKDF from [4] with the
// chaining_key as HKDF salt, and zero-length HKDF info.

//
// **************************************************************
//

// Processing Rules

// To precisely define the processing rules we adopt an object-oriented terminology,
// and present three “objects” which encapsulate state variables and contain functions which implement processing logic. These three objects are presented as a
// hierarchy: each higher-layer object includes one instance of the object beneath
// it. From lowest-layer to highest, the objects are:

// A CipherState object contains k and n variables, which it uses to encrypt
// and decrypt ciphertexts. During the handshake phase each party has a
// single CipherState, but during the transport phase each party has two
// CipherState objects: one for sending, and one for receiving.

// A SymmetricState object contains a CipherState plus ck and h variables.
// It is so-named because it encapsulates all the “symmetric crypto”
// used by Noise. During the handshake phase each party has a single
// SymmetricState, which can be deleted once the handshake is finished.

// A HandshakeState object contains a SymmetricState plus DH variables
// (s, e, rs, re) and a variable representing the handshake pattern.
// During the handshake phase each party has a single HandshakeState, which
// can be deleted once the handshake is finished.

// To execute a Noise protocol you Initialize() a HandshakeState. During
// initialization you specify the handshake pattern, any local key pairs, and any
// public keys for the remote party you have knowledge of. After Initialize() you
// call WriteMessage() and ReadMessage() on the HandshakeState to process
// each handshake message. If any error is signaled by the DECRYPT() or DH()
// functions then the handshake has failed and the HandshakeState is deleted.

// Processing the final handshake message returns two CipherState objects, the
// first for encrypting transport messages from initiator to responder, and the second
// for messages in the other direction. At that point the HandshakeState should
// be deleted except for the hash value h, which may be used for post-handshake
// channel binding (see Section 11.2).

// Transport messages are then encrypted and decrypted by calling EncryptWithAd()
// and DecryptWithAd() on the relevant CipherState with zero-length associated
// data. If DecryptWithAd() signals an error due to DECRYPT() failure, then
// the input message is discarded. The application may choose to delete the
// CipherState and terminate the session on such an error, or may continue to
// attempt communications. If EncryptWithAd() or DecryptWithAd() signal an
// error due to nonce exhaustion, then the application must delete the CipherState
// and terminate the session

//
// **************************************************************
//

// The CipherState object

// A CipherState can encrypt and decrypt data based on its k and n variables:
// • k:
// A cipher key of 32 bytes (which may be empty). Empty is a special value
// which indicates k has not yet been initialized.
// • n:
// An 8-byte (64-bit) unsigned integer nonce.
// A CipherState responds to the following functions. The ++ post-increment
// operator applied to n means “use the current n value, then increment it”. The
// maximum n value (264-1) is reserved for other use. If incrementing n results in
// 2^64 - 1, then any further EncryptWithAd() or DecryptWithAd() calls will signal
// an error to the caller.
// • InitializeKey(key):
// Sets k = key. Sets n = 0.
//
// • HasKey():
// Returns true if k is non-empty, false otherwise.
//
// • SetNonce(nonce):
// Sets n = nonce. This function is used for handling
// out-of-order transport messages, as described in Section 11.4.
//
// • EncryptWithAd(ad, plaintext):
// If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.
//
// • DecryptWithAd(ad, ciphertext):
// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext).
// Otherwise returns ciphertext. If an authentication failure occurs in DECRYPT()
// then n is not incremented and an error is signaled to the caller.
//
// • Rekey():
// Sets k = REKEY(k).

//
// **************************************************************
//

// The SymmetricState object
//
// A SymmetricState object contains a CipherState plus the following variables:
//
// • ck: A chaining key of HASHLEN bytes.
// • h: A hash output of HASHLEN bytes.
//
// A SymmetricState responds to the following functions:
//
// • InitializeSymmetric(protocol_name):
// Takes an arbitrary-length protocol_name byte sequence (see Section 8). Executes the following steps:
//
// – If protocol_name is less than or equal to HASHLEN bytes in length,
// sets h equal to protocol_name with zero bytes appended to make
// HASHLEN bytes. Otherwise sets h = HASH(protocol_name).
// – Sets ck = h.
// – Calls InitializeKey(empty).

// • MixKey(input_key_material): Executes the following steps:
// – Sets ck, temp_k = HKDF(ck, input_key_material, 2).
// – If HASHLEN is 64, then truncates temp_k to 32 bytes.
// – Calls InitializeKey(temp_k).
//
// MixHash(data):
// Sets h = HASH(h || data).
//
// • MixKeyAndHash(input_key_material):
// This function is used for handling pre-shared symmetric keys, as described in Section 9.
// It executes the following steps:
// – Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
// – Calls MixHash(temp_h).
// – If HASHLEN is 64, then truncates temp_k to 32 bytes.
// – Calls InitializeKey(temp_k).
//
// • GetHandshakeHash():
// Returns h. This function should only be called at
// the end of a handshake, i.e. after the Split() function has been called.
// This function is used for channel binding, as described in Section 11.2
//
// • EncryptAndHash(plaintext):
// Sets ciphertext = EncryptWithAd(h, plaintext),
// calls MixHash(ciphertext),
// and returns ciphertext. Note that if k is empty,
// the EncryptWithAd() call will set ciphertext equal to plaintext.

// • DecryptAndHash(ciphertext): Sets plaintext = DecryptWithAd(h,
//     ciphertext), calls MixHash(ciphertext), and returns plaintext. Note
//     that if k is empty, the DecryptWithAd() call will set plaintext equal to
//     ciphertext.

// • Split(): Returns a pair of CipherState objects for encrypting transport
// messages. Executes the following steps, where zerolen is a zero-length
// byte sequence:
// – Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
// – If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
// – Creates two new CipherState objects c1 and c2.
// – Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
// – Returns the pair (c1, c2).

//
// **************************************************************
//

// The HandshakeState object

// A HandshakeState object contains a SymmetricState plus the following variables,
// any of which may be empty. Empty is a special value which indicates the variable has not yet been initialized.
// • s: The local static key pair
// • e: The local ephemeral key pair
// • rs: The remote party’s static public key
// • re: The remote party’s ephemeral public key

// A HandshakeState also has variables to track its role, and the remaining portion
// of the handshake pattern:
// • initiator: A boolean indicating the initiator or responder role.
// • message_patterns: A sequence of message patterns. Each message pattern is a sequence of tokens from the set ("e", "s", "ee", "es", "se",
// "ss"). (An additional "psk" token is introduced in Section 9, but we defer
// its explanation until then.)

// A HandshakeState responds to the following functions:

// • Initialize(handshake_pattern, initiator, prologue, s, e, rs,
//     re): Takes a valid handshake_pattern (see Section 7) and an initiator
//     boolean specifying this party’s role as either initiator or responder.
//     Takes a prologue byte sequence which may be zero-length, or which may
//     contain context information that both parties want to confirm is identical
//     (see Section 6).
//     Takes a set of DH key pairs (s, e) and public keys (rs, re) for initializing
//     local variables, any of which may be empty. Public keys are only passed
//     in if the handshake_pattern uses pre-messages (see Section 7). The
//     ephemeral values (e, re) are typically left empty, since they are created
//     and exchanged during the handshake; but there are exceptions (see Section
//     10).
//     Performs the following steps:
//     – Derives a protocol_name byte sequence by combining the names for
//     the handshake pattern and crypto functions, as specified in Section 8.
//     Calls InitializeSymmetric(protocol_name).
//     – Calls MixHash(prologue).
//     – Sets the initiator, s, e, rs, and re variables to the corresponding
//     arguments.
//     – Calls MixHash() once for each public key listed in the pre-messages
//     from handshake_pattern, with the specified public key as input (see
//     Section 7 for an explanation of pre-messages). If both initiator and
// responder have pre-messages, the initiator’s public keys are hashed
// first. If multiple public keys are listed in either party’s pre-message,
// the public keys are hashed in the order that they are listed.
// – Sets message_patterns to the message patterns from handshake_pattern.

// • WriteMessage(payload, message_buffer): Takes a payload byte sequence which may be zero-length, and a message_buffer to write the output into. Performs the following steps, aborting if any EncryptAndHash()
// call returns an error:
// – Fetches and deletes the next message pattern from message_patterns,
// then sequentially processes each token from the message pattern:
// ∗ For "e": Sets e (which must be empty) to GENERATE_KEYPAIR().
// Appends e.public_key to the buffer. Calls MixHash(e.public_key).
// ∗ For "s": Appends EncryptAndHash(s.public_key) to the
// buffer.
// ∗ For "ee": Calls MixKey(DH(e, re)).
// ∗ For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s,
// re)) if responder.
// ∗ For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e,
// rs)) if responder.
// ∗ For "ss": Calls MixKey(DH(s, rs)).
// – Appends EncryptAndHash(payload) to the buffer.
// – If there are no more message patterns returns two new CipherState
// objects by calling Split().

// • ReadMessage(message, payload_buffer): Takes a byte sequence containing a Noise handshake message, and a payload_buffer to write the
// message’s plaintext payload into. Performs the following steps, aborting if
// any DecryptAndHash() call returns an error:
// – Fetches and deletes the next message pattern from message_patterns,
// then sequentially processes each token from the message pattern:
// ∗ For "e": Sets re (which must be empty) to the next DHLEN bytes
// from the message. Calls MixHash(re.public_key).
// ∗ For "s": Sets temp to the next DHLEN + 16 bytes of the message
// if HasKey() == True, or to the next DHLEN bytes otherwise. Sets
// rs (which must be empty) to DecryptAndHash(temp).
// ∗ For "ee": Calls MixKey(DH(e, re)).
// ∗ For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s,
// re)) if responder.
// ∗ For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e,
// rs)) if responder.
// ∗ For "ss": Calls MixKey(DH(s, rs)).
// – Calls DecryptAndHash() on the remaining bytes of the message and
// stores the output into payload_buffer.
// – If there are no more message patterns returns two new CipherState
// objects by calling Split().

// In the following handshake pattern both the initiator and responder possess
// static key pairs, and the handshake pattern comprises three message patterns:
// XX:
// -> e
// <- e, ee, s, es
// -> s, se

// The following handshake pattern describes a handshake where the initiator has
// pre-knowledge of the responder’s static public key and uses it for “zero-RTT”
// encryption:
// NK:
// <- s
// ...
// -> e, es
// <- e, ee
// In the following handshake pattern both parties have pre-knowledge of the other’s
// static public key. The initiator’s pre-message is listed first:
// KK:
// -> s
// <- s
// ...
// -> e, es, ss
// <- e, ee, se

//
// **************************************************************
//

// Protocol names and modifiers

//
// **************************************************************
//

// To produce a Noise protocol name for Initialize() you concatenate the
// ASCII string "Noise_" with four underscore-separated name sections which
// sequentially name the handshake pattern, the DH functions, the cipher functions,
// and then the hash functions. The resulting name must be 255 bytes or less.
// Examples:
// • Noise_XX_25519_AESGCM_SHA256
// • Noise_N_25519_ChaChaPoly_BLAKE2s
// • Noise_IK_448_ChaChaPoly_BLAKE2b
// Each name section must consist only of alphanumeric characters (i.e. characters
// in one of the ranges "A". . . "Z", "a". . . "z", and "0". . . "9"), and the two special
// characters "+" and "/".

//
// **************************************************************
//

// 9. Pre-shared symmetric keys

// Noise provides a pre-shared symmetric key or PSK mode to support protocols where
// both parties have a 32-byte shared secret key.

/// DH(private key, public key)
/// Curve25519 point multiplication of private key and public key,
/// returning 32 bytes of output
fn dh(private_key: StaticSecret, public_key: PublicKey) -> SharedSecret {
    private_key.diffie_hellman(&public_key)
}

/// DH_GENERATE()
/// generate a random Curve25519 private key
/// returning 32 bytes of output
fn dh_generate() -> EphemeralSecret {
    EphemeralSecret::random_from_rng(OsRng)
}

/// RAND(len)
/// return len random bytes of output
fn rand(len: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut buf = vec![0; len];
    rng.fill_bytes(&mut buf);
    buf
}

/// DH_PUBKEY(private key)
/// calculate a Curve25519 public key from private key,
/// returning 32 bytes of output
fn dh_pubkey(private_key: StaticSecret) -> PublicKey {
    PublicKey::from(&private_key)
}

/// AEAD(key, counter, plain text, auth text)
/// ChaCha20Poly1305 AEAD, as specified in RFC7539,
/// with its nonce being composed of 32 bits of zeros
/// followed by the 64-bit little-endian value of counter
/// a.k.a.
/// ENCRYPT(k, n, ad, plaintext):
/// Encrypts plaintext using the cipher
/// key k of 32 bytes and an 8-byte unsigned integer nonce n which must be
/// unique for the key k. Returns the ciphertext. Encryption must be done
/// with an “AEAD” encryption mode with the associated data ad (using the
/// terminology from [1]) and returns a ciphertext that is the same size as the
/// plaintext plus 16 bytes for authentication data. The entire ciphertext must
/// be indistinguishable from random if the key is secret (note that this is an
/// additional requirement that isn’t necessarily met by all AEAD schemes).
fn aead(
    key: SharedSecret,
    counter: Nonce,
    plain_text: Vec<u8>,
    auth_text: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = key.as_bytes();
    let mut cipher = ChaCha20Poly1305::new(key.into());
    // let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &counter,
            chacha20poly1305::aead::Payload {
                msg: &plain_text,
                aad: auth_text,
            },
        )
        .unwrap();
    Ok(ciphertext)
}

// XAEAD(key, nonce, plain text, auth text): XChaCha20Poly1305 AEAD, with a random 24-byte nonce
// AEAD_LEN(plain len): plain len + 16
// HMAC(key, input): HMAC-Blake2s(key, input, 32), returning 32 bytes of output
// MAC(key, input): Keyed-Blake2s(key, input, 16), returning 16 bytes of output
// HASH(input): Blake2s(input, 32), returning 32 bytes of output
// TAI64N(): TAI64N timestamp of current time which is 12 bytes
// CONSTRUCTION: the UTF-8 value Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, 37 bytes
// IDENTIFIER: the UTF-8 value WireGuard v1 zx2c4 Jason@zx2c4.com, 34 bytes
// LABEL_MAC1: the UTF-8 value mac1----, 8 bytes
// LABEL_COOKIE: the UTF-8 value cookie--, 8 bytes
