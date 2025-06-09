mod handshake;
mod node;

mod error;

pub fn make_initiate_msg() {
    let left_keys = node::make_static_keys();
    let right_keys = node::make_static_keys();

    let initiator_msg =
        handshake::make_initiate_msg(left_keys, right_keys.public);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_initiate_msg() {
        make_initiate_msg();
    }
}
