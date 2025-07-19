use thiserror::Error;

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("something something")]
    Disconnect(#[from] std::io::Error),
}
