struct HandshakeInitiation {
    message_type: u8,
    reserved_zero: [u8; 3],
    sender_index: u32,
    unencrypted_ephemeral: [u8; 32],
    encrypted_static: [u8; 32],
    encrypted_timestamp: [u8; 12],
    mac1: [u8; 16],
    mac2: [u8; 16],
}
