// msg = handshake_response {
//     u8 message_type
//     u8 reserved_zero[3]
//     u32 sender_index
//     u32 receiver_index
//     u8 unencrypted_ephemeral[32]
//     u8 encrypted_nothing[AEAD_LEN(0)]
//     u8 mac1[16]
//     u8 mac2[16]
// }
