use crate::tls::tls_record::{ClientHelloRecord, HandshakeFinishedRecord};
use std::fmt;

const TLS_PROTOCOL_VERSION: [u8; 2] = [0x03, 0x03];
const TLS_RSA_AES_128_CBC_SHA_256: [u8; 2] = [0x00, 0x3C];
const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_SERVER_HELLO: u8 = 0x02;
const TLS_SERVER_CERTIFICATE: u8 = 0x0B;
const TLS_SERVER_CERTIFICATE_VERIFY: u8 = 0x0f;
const TLS_HANDSHAKE_FINISHED: u8 = 0x14;

#[derive(Debug)]
pub enum TlsHandlerError {
    ProtocolNotSupported([u8; 2]),
    CipherNotSupported([u8; 2]),
    HandshakeHeaderNotRecognized(u8),
    RequestNotRecognized(u8),
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
            TlsHandlerError::HandshakeHeaderNotRecognized(header_type) => {
                write!(f, "Handshake header not recognized. {}", header_type)
            }
            TlsHandlerError::RequestNotRecognized(request_type) => {
                write!(f, "Request not recognized. {}", request_type)
            }
        }
    }
}
impl std::error::Error for TlsHandlerError {}

pub fn handle_tls_requests(size: usize, data: &[u8]) -> Result<(), TlsHandlerError> {
    let request_type = &data[0];

    match request_type {
        TLS_HANDSHAKE_RECORD => { //0x16

            // parse client hello
            let client_hello_record: ClientHelloRecord = convert_bytes_to_client_hello_record(size, data); // <- conversion should handle length validation

            // validate handshake message type
            if client_hello_record.get_header_type() != TLS_CLIENT_HELLO {
                Err(TlsHandlerError::HandshakeHeaderNotRecognized(handshake_header))
            }

            // return server hello

            // kickoff server handshake keys calc - derive session keys
            // return server certificate
            // return server certificate verify
            // return server finished

        }

        TLS_HANDSHAKE_FINISHED => { //0x14

            // parse client handshake finished
            let client_handshake_finished_record: HandshakeFinishedRecord = convert_bytes_to_client_handshake_finished_record(size, data);

            // validate handshake message type
            if client_handshake_finished_record.get_header_type() != TLS_HANDSHAKE_FINISHED {
                Err(TlsHandlerError::HandshakeHeaderNotRecognized(handshake_header))
            }
        }

        _ => Err(TlsHandlerError::RequestNotRecognized(request_type)),
    }
}