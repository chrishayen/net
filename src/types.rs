pub struct HandshakeInitiationResponse {
    pub message_type: u8,
    pub reserved_zero: [u8; 3],
    pub sender_index: u32,
    pub receiver_index: u32,
    pub unencrypted_ephemeral: [u8; 32],
    pub encrypted_nothing: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}
