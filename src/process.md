Assumptions: Initiator knows responder's static public key; uses Curve25519, ChaCha20-Poly1305, BLAKE2s, and HKDF

Step 1: Initialize constants and keys

CONST PROTOCOL_NAME = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" CONST EMPTY_HASH = BLAKE2s("") # Empty hash as starting point CONST INITIAL_CHAINING_KEY = BLAKE2s(PROTOCOL_NAME) # Initial chaining key hash = EMPTY_HASH chaining_key = INITIAL_CHAINING_KEY

Step 2: Generate initiator's ephemeral keypair

initiator_ephemeral_private = GenerateRandomPrivateKey(Curve25519) # Random private key initiator_ephemeral_public = Curve25519_PublicKey(initiator_ephemeral_private) # Derive public key

Step 3: Load pre-shared keys

initiator_static_private = LoadInitiatorStaticPrivateKey() # Pre-configured private key initiator_static_public = Curve25519_PublicKey(initiator_static_private) # Initiator's static public key (32 bytes) responder_static_public = LoadResponderStaticPublicKey() # Known responder's public key (32 bytes) preshared_key = LoadPresharedKey() # Optional pre-shared key (32 bytes, can be all zeros if not used)

Step 4: Mix initiator's ephemeral public key into hash

hash = BLAKE2s(hash || initiator_ephemeral_public) # Append ephemeral public key and update hash

Step 5: Perform Diffie-Hellman (initiator ephemeral private + responder static public)

dh_result = Curve25519_DH(initiator_ephemeral_private, responder_static_public) # Compute shared secret

Step 6: Derive AEAD encryption key using HKDF

HKDF takes chaining_key and dh_result to produce new chaining_key and AEAD key

(chaining_key, aead_key) = HKDF(chaining_key, dh_result, output_length=2) # Two 32-byte outputs: new chaining_key, aead_key

Step 7: Prepare AEAD plaintext (static public key + timestamp)

plaintext = initiator_static_public || GetCurrentTimestamp(TAI64N) # Concatenate static key (32 bytes) + timestamp (12 bytes, TAI64N format)

Step 8: Encrypt with AEAD (ChaCha20-Poly1305)

nonce = 0 # Initial nonce (96-bit, typically 0 for first message) associated_data = hash # Current hash as associated data for AEAD encrypted_payload = ChaCha20Poly1305_Encrypt(aead_key, nonce, plaintext, associated_data) # Encrypt static key + timestamp

Step 9: Compute authentication MACs

mac_key = BLAKE2s(responder_static_public) # Derive MAC key from responder's public key message_so_far = [type, sender_index, initiator_ephemeral_public, encrypted_payload] # Unencrypted fields + encrypted payload mac1 = BLAKE2s(mac_key, message_so_far) # Authenticate message mac2 = ComputeCookieIfUnderLoad() # Optional anti-DoS cookie (empty if not under load)

Step 10: Construct Handshake Initiation message

message = { type: "Handshake Initiation", sender_index: GenerateUniqueSenderIndex(), # Random 4-byte identifier ephemeral_public: initiator_ephemeral_public, # Unencrypted ephemeral key (32 bytes) encrypted_static_and_timestamp: encrypted_payload, # AEAD-encrypted static key + timestamp mac1: mac1, # Authentication MAC (16 bytes) mac2: mac2 # Anti-DoS cookie (16 bytes, empty if not used) }

Step 11: Send message to responder

SendUDP(message, responder_endpoint)

Note: The responder uses its static private key to compute the same DH result, derive aead_key,

and decrypt encrypted_payload to verify the initiator's static public key and timestamp.