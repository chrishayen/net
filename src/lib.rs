mod handshake;
mod node;

mod error;

pub fn make_initiate_msg() {
    let left_keys = node::make_static_keys();
    let right_keys = node::make_static_keys();
    let left_ephemeral_keys = node::make_ephemeral_keys();

    let initiator_msg = handshake::make_initiate_msg(
        left_keys,
        left_ephemeral_keys,
        right_keys.static_public_key,
    );
}
