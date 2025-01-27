use crate::tls::tls_record::{
    ApplicationDataRecord, ChangeCipherSpecRecord, HandshakeHeader, HelloRecord, KeyExchangeRecord,
    RecordHeader, ServerCertificateRecord, ServerHelloDoneRecord,
};
use crate::tls::tls_record_parser::{
    parse_application_data_record, parse_change_cipher_spec_record, parse_hello_record,
    parse_key_exchange_record, parse_record_header,
};
use crate::tls::tls_session::SessionContext;
use crate::tls::tls_utils::{
    convert_usize_to_3_bytes, generate_random_32_bytes, generate_server_random, read_file_to_bytes,
};
use std::env::VarError;
use std::io::Error;
use std::{env, fmt};

const TLS_PROTOCOL_VERSION: [u8; 2] = [0x03, 0x03]; // TLS 1.2
const TLS_RSA_AES_128_CBC_SHA_256: [u8; 2] = [0x00, 0x3C];
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
const TLS_RECORD_ALERT: u8 = 0x15;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const TLS_HANDSHAKE_SERVER_CERTIFICATE: u8 = 0x0B;
const TLS_HANDSHAKE_SERVER_KEY_EXCHANGE: u8 = 0x0c;
const TLS_HANDSHAKE_SERVER_HELLO_DONE: u8 = 0x0e;
const TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE: u8 = 0x10;
const TLS_HANDSHAKE_FINISHED: u8 = 0x14;

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

pub fn handle(session_context: &mut SessionContext, data: &[u8]) -> Result<(), TlsHandlerError> {
    let record_header: RecordHeader = parse_record_header(data).unwrap()?;
    match record_header.record_type {
        TLS_RECORD_HANDSHAKE => {
            match handshake_type {
                TLS_HANDSHAKE_CLIENT_HELLO => {
                    let client_hello_record: HelloRecord = parse_hello_record(data).unwrap()?;
                    session_context.client_hello_record = Some(client_hello_record.clone());
                    // client hello
                    //server hello
                    // server certificate
                    // server key exchange generation
                    // server key exchange
                    // server hello done
                    // save all record bytes to session context
                    Ok(())
                }
                TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE => {
                    let client_key_exchange_record: KeyExchangeRecord =
                        parse_key_exchange_record(data).unwrap()?;

                    Ok(())
                }
                _ => {
                    // Client Handshake Finished
                    // server change cipher spec
                    // server handshake finished
                    Ok(())
                }
            }
        }
        TLS_RECORD_CHANGE_CIPHER_SPEC => {
            let client_change_cipher_spec_record: ChangeCipherSpecRecord =
                parse_change_cipher_spec_record(data).unwrap()?;
            Ok(())
        }
        TLS_RECORD_APPLICATION_DATA => {
            let client_application_data_record: ApplicationDataRecord =
                parse_application_data_record(data).unwrap()?;
            Ok(())
        }
        TLS_RECORD_ALERT => {
            let client_close_notify_record: ApplicationDataRecord =
                parse_application_data_record(data).unwrap()?;
            Ok(())
        }
        _ => Err(TlsHandlerError::InvalidRecord(record_header.record_type)),
    }
}

// fn is_valid_client_hello_record(hello_record: HelloRecord) -> bool {
//     if record_type != crate::tls::tls_handler::TLS_RECORD_HANDSHAKE {
//         return Err(TlsHandlerError::InvalidRecord(record_type));
//     }
//
//     if protocol_version != crate::tls::tls_handler::TLS_PROTOCOL_VERSION {
//         return Err(TlsHandlerError::ProtocolNotSupported(crate::tls::tls_handler::TLS_PROTOCOL_VERSION));
//     }
//
//     if handshake_type != crate::tls::tls_handler::TLS_HANDSHAKE_CLIENT_HELLO {
//         return Err(TlsHandlerError::InvalidHandshake(handshake_type));
//     }
//
//     if cipher_suite != crate::tls::tls_handler::TLS_RSA_AES_128_CBC_SHA_256 {
//         return Err(TlsHandlerError::CipherNotSupported(cipher_suite));
//     }
//
//     true
// }

//fn is_valid_client_key_exchange_record() -> bool {}

fn get_server_hello_record() -> Result<HelloRecord, TlsHandlerError> {
    Ok(HelloRecord {
        record_header: RecordHeader {
            record_type: TLS_RECORD_HANDSHAKE,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: [0x00, 0x04],
        },
        handshake_header: HandshakeHeader {
            handshake_type: TLS_HANDSHAKE_SERVER_HELLO,
            data_message_length: [0x00, 0x00, 0x44],
        },
        version: TLS_PROTOCOL_VERSION,
        random: generate_server_random(),
        session_id: generate_random_32_bytes(),
        cipher_suites_length: [0x00, 0x02],
        cipher_suites: vec![TLS_RSA_AES_128_CBC_SHA_256],
    })
}

fn get_server_certificate_record() -> Result<ServerCertificateRecord, TlsHandlerError> {
    let path = env::var("PATH_SERVER_CERT_DIR")?;

    let certificate = read_file_to_bytes(&path)?;
    let certificate_length = certificate.len();

    Ok(ServerCertificateRecord {
        handshake_header: HandshakeHeader {
            handshake_type: TLS_HANDSHAKE_SERVER_CERTIFICATE,
            data_message_length: convert_usize_to_3_bytes(certificate_length + 7),
        },
        request_context: 0x00,
        certificates_length: convert_usize_to_3_bytes(certificate_length),
        certificate_length: convert_usize_to_3_bytes(certificate_length),
        certificate,
    })
}

fn get_server_key_exchange_record() -> Result<KeyExchangeRecord, TlsHandlerError> {
    Ok(())
}

fn get_server_hello_done_record() -> Result<ServerHelloDoneRecord, TlsHandlerError> {
    Ok(())
}

fn get_server_change_cipher_spec_record() -> Result<ChangeCipherSpecRecord, TlsHandlerError> {
    Ok(())
}

fn get_server_handshake_finished_record() -> Result<ApplicationDataRecord, TlsHandlerError> {
    Ok(ApplicationDataRecord {
        record_header: RecordHeader {
            record_type: TLS_RECORD_HANDSHAKE,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: [],
        },
        encryption_iv: [],
        encrypted_data: vec![],
    })
}

fn get_server_application_data_record() -> Result<ApplicationDataRecord, TlsHandlerError> {
    Ok(())
}
