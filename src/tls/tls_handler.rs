use crate::tls::tls_record::{
    CertificateRecord, CertificateVerifyRecord, HandshakeFinishedRecord, HandshakeHeader,
    HelloRecord, NewSessionTicketRecord, RecordHeader,
};
use crate::tls::tls_utils::{
    convert_usize_to_3_bytes, generate_random_32_bytes, generate_server_random, read_file_to_bytes,
};
use std::env::VarError;
use std::io::Error;
use std::{env, fmt};

const TLS_PROTOCOL_VERSION: [u8; 2] = [0x03, 0x03];
const TLS_RSA_AES_128_CBC_SHA_256: [u8; 2] = [0x00, 0x3C];
const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_SERVER_HELLO: u8 = 0x02;
const TLS_SERVER_CERTIFICATE: u8 = 0x0B;
const TLS_SERVER_CERTIFICATE_VERIFY: u8 = 0x0f;
const TLS_HANDSHAKE_FINISHED: u8 = 0x14;
const TLS_SERVER_NEW_SESSION_TICKET: u8 = 0x04;
const TLS_SERVER_NEW_SESSION_TICKET_LIFETIME: [u8; 4] = [0x00, 0x00, 0x1c, 0x20];
const TLS_SERVER_SESSION_AGE_ADD: [u8; 4] = [0u8; 4];
const TLS_SERVER_NEW_SESSION_TICKET_NONCE: [u8; 9] = [0u8; 9];

#[derive(Debug)]
pub enum TlsHandlerError {
    ProtocolNotSupported([u8; 2]),
    CipherNotSupported([u8; 2]),
    InvalidRecordType(u8),
    InvalidHandshakeType(u8),
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
            TlsHandlerError::InvalidRecordType(record_type) => {
                write!(f, "Invalid record type: {}", record_type)
            }
            TlsHandlerError::InvalidHandshakeType(header_type) => {
                write!(f, "Invalid handshake header type: {}", header_type)
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

pub fn handle(size: usize, data: &[u8]) -> Result<(), TlsHandlerError> {
    let request_type: &u8 = &data[0];

    match request_type {
        TLS_HANDSHAKE_RECORD => {
            let client_hello_record: HelloRecord = get_client_hello_record(size, data)?;
            // store client hello into session context

            let server_hello_record: HelloRecord = get_server_hello_record()?;
            // store server hello into session context

            // kickoff server handshake keys calc - derive session keys
            let server_certificate_record: CertificateRecord = get_server_certificate_record()?;

            // calculate verify data
            let server_certificate_verify_record: CertificateVerifyRecord =
                get_server_certificate_verify_record()?;

            let server_handshake_finished_record: HandshakeFinishedRecord =
                get_server_handshake_finished_record()?;

            Ok(())
        }
        TLS_HANDSHAKE_FINISHED => Ok(()),
        _ => {
            // an encrypted message
            Ok(())
        }
    }
}

fn get_client_hello_record(size: usize, data: &[u8]) -> Result<HelloRecord, TlsHandlerError> {
    let record_type: u8 = data[0];
    if record_type != TLS_HANDSHAKE_RECORD {
        return Err(TlsHandlerError::InvalidRecordType(record_type));
    }

    let mut protocol_version = [0u8; 2];
    protocol_version.copy_from_slice(&data[1..3]);
    if protocol_version != TLS_PROTOCOL_VERSION {
        return Err(TlsHandlerError::ProtocolNotSupported(TLS_PROTOCOL_VERSION));
    }

    let handshake_message_length = data[3..5];

    let handshake_type: u8 = data[5].clone();
    if handshake_type != TLS_CLIENT_HELLO {
        return Err(TlsHandlerError::InvalidHandshakeType(handshake_type));
    }

    let data_message_length: [u8; 3] = data[6..9].clone();

    // data
    let version: [u8; 2] = data[9..11].clone();
    let random: [u8; 32] = data[11..44].clone();
    let session_id: [u8; 32] = data[44..77].clone();

    let cipher_suite: [u8; 2] = data[77..79].clone();
    if cipher_suite != TLS_RSA_AES_128_CBC_SHA_256 {
        return Err(TlsHandlerError::CipherNotSupported(cipher_suite));
    }

    Ok(HelloRecord {
        record_header: RecordHeader {
            record_type,
            protocol_version,
            handshake_message_length,
        },
        handshake_header: HandshakeHeader {
            handshake_type,
            data_message_length,
        },
        version,
        random,
        session_id,
        cipher_suites,
    })
}

fn get_client_finished_record(
    size: usize,
    data: &[u8],
) -> Result<HandshakeFinishedRecord, TlsHandlerError> {
    let handshake_type: u8 = data[0].clone();
    let length: [u8; 3] = data[1..4].clone();
    let verify_data: Vec<u8> = data[4..].to_vec();

    Ok(HandshakeFinishedRecord {
        handshake_header: HandshakeHeader {
            handshake_type,
            data_message_length: length,
        },
        verify_data,
    })
}

fn get_server_hello_record() -> Result<HelloRecord, TlsHandlerError> {
    Ok(HelloRecord {
        record_header: RecordHeader {
            record_type: TLS_HANDSHAKE_RECORD,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: [0x00, 0x04],
        },
        handshake_header: HandshakeHeader {
            handshake_type: TLS_SERVER_HELLO,
            data_message_length: [0x00, 0x00, 0x44],
        },
        version: TLS_PROTOCOL_VERSION,
        random: generate_server_random(),
        session_id: generate_random_32_bytes(),
        cipher_suites: TLS_RSA_AES_128_CBC_SHA_256.to_vec(),
    })
}

fn get_server_certificate_record() -> Result<CertificateRecord, TlsHandlerError> {
    let path = env::var("PATH_SERVER_CERT_DIR")?;

    let certificate = read_file_to_bytes(&path)?;
    let certificate_length = certificate.len();

    Ok(CertificateRecord {
        handshake_header: HandshakeHeader {
            handshake_type: TLS_SERVER_CERTIFICATE,
            data_message_length: convert_usize_to_3_bytes(certificate_length + 7),
        },
        request_context: 0x00,
        certificates_length: convert_usize_to_3_bytes(certificate_length),
        certificate_length: convert_usize_to_3_bytes(certificate_length),
        certificate,
    })
}

fn get_server_certificate_verify_record() -> Result<CertificateVerifyRecord, TlsHandlerError> {
    Ok(CertificateVerifyRecord {
        handshake_header: HandshakeHeader {
            handshake_type: TLS_SERVER_CERTIFICATE_VERIFY,
            data_message_length: [],
        },
        signature: vec![],
    })
}

fn get_server_handshake_finished_record() -> Result<HandshakeFinishedRecord, TlsHandlerError> {
    Ok(HandshakeFinishedRecord {
        handshake_header: HandshakeHeader {
            handshake_type: TLS_HANDSHAKE_FINISHED,
            data_message_length: [],
        },
        verify_data: vec![],
    })
}

fn get_server_new_session_ticket_record() -> Result<NewSessionTicketRecord, TlsHandlerError> {
    Ok(NewSessionTicketRecord {
        handshake_header: HandshakeHeader {
            handshake_type: TLS_SERVER_NEW_SESSION_TICKET,
            data_message_length: [],
        },
        ticket_lifetime: TLS_SERVER_NEW_SESSION_TICKET_LIFETIME,
        ticket_age_add: TLS_SERVER_SESSION_AGE_ADD,
        ticket_nonce: TLS_SERVER_NEW_SESSION_TICKET_NONCE,
        session_ticket: vec![],
    })
}
