use std::env::VarError;
use std::fmt;
use std::io::Error;

//todo:
#[derive(Debug)]
pub enum TlsHandlerError {
    ProtocolNotSupported([u8; 2]),
    CipherNotSupported([u8; 2]),
    InvalidRecord(u8),
    InvalidHandshake(u8),
    IoError(Error),
}

impl fmt::Display for TlsHandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsHandlerError::ProtocolNotSupported(protocol) => {
                write!(f, "Protocol is not supported: {}", protocol)
            }
            TlsHandlerError::CipherNotSupported(cipher) => {
                write!(f, "Cipher is not supported: {}", cipher)
            }
            TlsHandlerError::InvalidRecord(record) => {
                write!(f, "Invalid record: {}", record)
            }
            TlsHandlerError::InvalidHandshake(header) => {
                write!(f, "Invalid handshake header: {}", header)
            }
            TlsHandlerError::IoError(err) => write!(f, "IO error: {}", err),
        }
    }
}
impl From<Error> for TlsHandlerError {
    fn from(err: Error) -> Self {
        TlsHandlerError::IoError(err)
    }
}
impl From<VarError> for TlsHandlerError {
    fn from(err: Error) -> Self {
        TlsHandlerError::IoError(err)
    }
}
impl std::error::Error for TlsHandlerError {}
