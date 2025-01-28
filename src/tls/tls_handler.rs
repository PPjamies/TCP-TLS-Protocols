use crate::tls::tls_record::{
    ApplicationDataRecord, ChangeCipherSpecRecord, HandshakeHeader, HelloRecord, KeyExchangeRecord,
    RecordHeader, ServerCertificateRecord, ServerHelloDoneRecord,
};
use crate::tls::tls_record_parser::{
    parse_application_data_record, parse_change_cipher_spec_record, parse_handshake_type,
    parse_hello_record, parse_key_exchange_record, parse_record_type,
};
use crate::tls::tls_session::SessionContext;
use crate::tls::tls_utils::{
    convert_usize_to_3_bytes, convert_usize_to_bytes, generate_random_32_bytes,
    generate_server_random, read_file_to_bytes,
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
    let record_type = parse_record_type(data).unwrap()?;
    match record_type {
        TLS_RECORD_HANDSHAKE => {
            let handshake_type = parse_handshake_type(data)?;
            match handshake_type {
                TLS_HANDSHAKE_CLIENT_HELLO => {
                    let client_hello_record: HelloRecord = parse_hello_record(data).unwrap()?;
                    let server_hello_record: HelloRecord = get_server_hello_record()?;
                    let server_certificate_record: ServerCertificateRecord =
                        get_server_certificate_record()?;
                    let server_hello_done_record: ServerHelloDoneRecord =
                        get_server_hello_done_record()?;

                    // set session context
                    session_context.client_hello_record = Some(client_hello_record.clone());
                    session_context.server_hello_record = Some(server_hello_record.clone());
                    session_context.server_certificate_record =
                        Some(server_certificate_record.clone());
                    session_context.server_hello_done_record =
                        Some(server_hello_done_record.clone());

                    Ok(())
                }
                TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE => {
                    let client_key_exchange_record: KeyExchangeRecord =
                        parse_key_exchange_record(data).unwrap()?;
                    session_context.client_key_exchange_record = Some(client_key_exchange_record);

                    // todo: server generates session keys = premaster secret, server/client random, cipher suite
                    // todo: create session state

                    Ok(())
                }
                _ => {
                    let client_handshake_finished_record: ApplicationDataRecord =
                        parse_application_data_record(data).unwrap()?;
                    let server_change_cipher_spec_record: ChangeCipherSpecRecord =
                        get_server_change_cipher_spec_record()?;

                    // todo: update
                    let encryption_length = 0usize;
                    let encryption_iv = [0u8; 16];
                    let encrypted_data = vec![0u8; 20];

                    let server_handshake_finished_record: ApplicationDataRecord =
                        get_server_application_data_record(
                            encryption_length,
                            &encryption_iv,
                            &encrypted_data,
                        )?;

                    // set session context
                    session_context.client_handshake_finished_record =
                        Some(client_handshake_finished_record.clone());
                    session_context.server_change_cipher_spec_record =
                        Some(server_change_cipher_spec_record.clone());
                    session_context.server_handshake_finished_record =
                        Some(server_handshake_finished_record.clone());

                    Ok(())
                }
            }
        }
        TLS_RECORD_CHANGE_CIPHER_SPEC => {
            let client_change_cipher_spec_record: ChangeCipherSpecRecord =
                parse_change_cipher_spec_record(data).unwrap()?;
            session_context.client_change_cipher_spec_record =
                Some(client_change_cipher_spec_record.clone());

            Ok(())
        }
        TLS_RECORD_ALERT => {
            let client_close_notify_record: ApplicationDataRecord =
                parse_application_data_record(data).unwrap()?;

            // todo: decrypt data
            // todo: close connection if "Close Notify"

            Ok(())
        }
        TLS_RECORD_APPLICATION_DATA => {
            let client_application_data_record: ApplicationDataRecord =
                parse_application_data_record(data).unwrap()?;

            // todo: decrypt data
            // todo: print decrypted data

            Ok(())
        }
        _ => Err(TlsHandlerError::InvalidRecord(record_type)),
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

fn get_server_hello_done_record() -> Result<ServerHelloDoneRecord, TlsHandlerError> {
    Ok((ServerHelloDoneRecord {
        record_header: RecordHeader {
            record_type: TLS_RECORD_HANDSHAKE,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: [0x00, 0x04],
        },
        handshake_header: HandshakeHeader {
            handshake_type: TLS_HANDSHAKE_SERVER_HELLO_DONE,
            data_message_length: [0x00, 0x00, 0x00],
        },
    }))
}

fn get_server_change_cipher_spec_record() -> Result<ChangeCipherSpecRecord, TlsHandlerError> {
    Ok((ChangeCipherSpecRecord {
        record_type: TLS_RECORD_CHANGE_CIPHER_SPEC,
        protocol_version: TLS_PROTOCOL_VERSION,
        change_cipher_specs_length: [0x00, 0x01],
        change_cipher_specs: 0x01,
    }))
}

// used for handshake finished records
fn get_server_application_data_record(
    encryption_length: usize,
    encryption_iv: &[u8; 16],
    encrypted_data: &Vec<u8>,
) -> Result<ApplicationDataRecord, TlsHandlerError> {
    Ok((ApplicationDataRecord {
        record_header: RecordHeader {
            record_type: TLS_RECORD_HANDSHAKE,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: convert_usize_to_bytes(encryption_length)
                .try_into()
                .unwrap(),
        },
        encryption_iv: encryption_iv.clone(),
        encrypted_data: encrypted_data.clone(),
    }))
}
