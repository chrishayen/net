use crate::handshake::verify_initiate_msg;

mod error;
mod handshake;
mod node;

pub fn do_it() -> bool {
    let left_keys = node::make_static_keys();
    let right_keys = node::make_static_keys();
    let left_public = left_keys.public;
    let initiator_msg =
        handshake::make_initiate_msg(left_keys, right_keys.public);

    verify_initiate_msg(initiator_msg, right_keys, left_public)
}
