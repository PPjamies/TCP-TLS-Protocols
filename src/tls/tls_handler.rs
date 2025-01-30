use crate::tls::tls_record::*;
use crate::tls::tls_record_decoder::*;
use crate::tls::tls_record_encoder::*;
use crate::tls::tls_server_responses::*;
use crate::tls::tls_session::*;
use socket2::Socket;
use std::env::VarError;
use std::fmt;
use std::io::{Error, Write};

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

pub fn handle(
    mut socket: &Socket,
    state: &mut SessionState,
    context: &mut SessionContext,
    data: &[u8],
) -> Result<(), TlsHandlerError> {
    let record_type = decode_record_type(data).unwrap()?;
    match record_type {
        TLS_RECORD_HANDSHAKE => {
            let handshake_type = decode_handshake_type(data)?;
            match handshake_type {
                TLS_HANDSHAKE_CLIENT_HELLO => {
                    let client_hello_record: HelloRecord = decode_hello_record(data).unwrap()?;
                    let server_hello_record: HelloRecord = get_server_hello_record();
                    let server_certificate_record: ServerCertificateRecord = get_server_certificate_record()?;
                    let server_hello_done_record: ServerHelloDoneRecord = get_server_hello_done_record();

                    // set session context
                    context.client_hello_record = Some(client_hello_record.clone());
                    context.server_hello_record = Some(server_hello_record.clone());
                    context.server_certificate_record = Some(server_certificate_record.clone());
                    context.server_hello_done_record = Some(server_hello_done_record.clone());

                    // encode
                    socket.write_all(&*encode_hello_record(&server_hello_record))?;
                    socket.write_all(&*encode_server_certificate_record(&server_certificate_record))?;
                    socket.write_all(&*encode_server_hello_done_record(&server_hello_done_record))?;

                    Ok(())
                }
                TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE => {
                    let client_key_exchange_record: KeyExchangeRecord = decode_key_exchange_record(data).unwrap()?;

                    // derive session keys
                    let session_keys: SessionKeys = get_session_keys(
                        &client_key_exchange_record.premaster_secret,
                        &*context.get_client_random(),
                        &*context.get_server_random(),
                    )?;

                    // store session state
                    state.session_id = Some(context.get_server_session_id());
                    state.session_keys = Some(session_keys);

                    // store session context
                    context.client_key_exchange_record = Some(client_key_exchange_record.clone());

                    Ok(())
                }
                _ => {
                    let client_handshake_finished_record: ApplicationDataRecord = decode_application_data_record(data).unwrap()?;
                    let server_change_cipher_spec_record: ChangeCipherSpecRecord = get_server_change_cipher_spec_record();

                    // todo: update
                    let encryption_iv = [0u8; 16];
                    let encrypted_data = vec![0u8; 20];

                    let session_keys: &SessionKeys = &state.session_keys.unwrap()

                    let server_handshake_finished_record: ApplicationDataRecord = get_server_application_data_record(
                            session_keys.encryption_length,
                            &encryption_iv,
                            &encrypted_data,
                        )?;

                    // set session context
                    context.client_handshake_finished_record =
                        Some(client_handshake_finished_record.clone());
                    context.server_change_cipher_spec_record =
                        Some(server_change_cipher_spec_record.clone());
                    context.server_handshake_finished_record =
                        Some(server_handshake_finished_record.clone());

                    Ok(())
                }
            }
        }
        TLS_RECORD_CHANGE_CIPHER_SPEC => {
            let client_change_cipher_spec_record: ChangeCipherSpecRecord =
                decode_change_cipher_spec_record(data).unwrap()?;
            context.client_change_cipher_spec_record =
                Some(client_change_cipher_spec_record.clone());

            Ok(())
        }
        TLS_RECORD_ALERT => {
            let client_close_notify_record: ApplicationDataRecord =
                decode_application_data_record(data).unwrap()?;

            // todo: decrypt data
            // todo: close connection if "Close Notify"

            Ok(())
        }
        TLS_RECORD_APPLICATION_DATA => {
            let client_application_data_record: ApplicationDataRecord =
                decode_application_data_record(data).unwrap()?;

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
