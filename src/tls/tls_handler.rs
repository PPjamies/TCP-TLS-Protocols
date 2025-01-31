use crate::tls::tls_constants::*;
use crate::tls::tls_record::{HandshakeFinishedRecord, HandshakeHeader};
use crate::tls::tls_record_decoder::*;
use crate::tls::tls_record_encoder::*;
use crate::tls::tls_session::*;
use socket2::Socket;
use std::io::Write;
use std::net::Shutdown;
use crate::tls::tls_error::TlsHandlerError;

pub fn handle(
    mut socket: &Socket,
    state: &mut SessionState,
    context: &mut SessionContext,
    data: &[u8],
) -> Result<(), TlsHandlerError> {
    let record_type = get_record_type(&data);
    match record_type {
        TLS_RECORD_HANDSHAKE => {
            let handshake_type = get_handshake_type(&data);
            match handshake_type {
                TLS_HANDSHAKE_CLIENT_HELLO => {
                    // store handshake bytes to context for handshake finished
                    context.client_hello_record = data.clone().to_vec();
                    let _ = get_client_hello_record(&data);

                    let server_hello_record_bytes: Vec<u8> = get_server_hello_record_bytes();
                    context.server_hello_record = server_hello_record_bytes.clone();
                    socket.write_all(&server_hello_record_bytes)?;

                    let server_certificate_record_bytes: Vec<u8> = get_server_certificate_record_bytes();
                    context.server_certificate_record = server_certificate_record_bytes.clone();
                    socket.write_all(&server_certificate_record_bytes)?;

                    let server_hello_done_record_bytes: Vec<u8> = get_server_hello_record_bytes();
                    context.server_hello_done_record = server_hello_done_record_bytes.clone();
                    socket.write_all(&server_hello_done_record_bytes)?;

                    Ok(())
                }
                TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE => {
                    // store handshake bytes to context for handshake finished
                    context.client_key_exchange_record = data.clone().to_vec();
                    let client_key_exchange_record = get_client_key_exchange_record(&data);

                    // decrypt premaster secret and derive session keys
                    let premaster_secret = decrypt_premaster_secret(&client_key_exchange_record.premaster_secret);
                    let session_keys = decrypt_session_keys(
                        &premaster_secret,
                        &context.get_client_random(),
                        &context.get_client_random(),
                    )?;

                    // store session state
                    state.session_id = Some(context.get_server_session_id());
                    state.premaster_secret = Some(premaster_secret);
                    state.session_keys = Some(session_keys);

                    Ok(())
                }
                _ => {
                    let client_handshake_finished_record = get_client_application_data_record(&data);

                    // decrypt the client data
                    let data_bytes = decrypt_data(
                        &state.session_keys.as_ref().unwrap(),
                        &client_handshake_finished_record.encryption_iv,
                        &client_handshake_finished_record.encrypted_data,
                    );

                    // cast the data bytes to get verify data and verify hash
                    let client_handshake_finished_record_with_verify_data = get_client_handshake_finished_record(&data_bytes);
                    verify_finished_message(
                        &client_handshake_finished_record_with_verify_data.verify_data,
                        &context,
                        &state,
                    );

                    let server_change_cipher_spec_record_bytes: Vec<u8> = get_server_change_cipher_spec_record_bytes();
                    socket.write_all(&server_change_cipher_spec_record_bytes)?;

                    // todo: create handshake finished record with verify data
                    let server_handshake_finished_record = HandshakeFinishedRecord {
                        handshake_header: HandshakeHeader {
                            handshake_type: TLS_HANDSHAKE_FINISHED,
                            data_message_length: [],
                        },
                        verify_data: vec![],
                    };

                    // todo: encrypt the payload
                    // todo: create an application payload with server encryption iv, and the encrypted data (verify data payload)
                    // todo: encode the everything

                    let server_handshake_finished_record_bytes: Vec<u8> = get_server_handshake_finished_record_bytes(
                        encrypted_length,
                        &encryption_iv,
                        &encrypted_data,
                    )?;
                    socket.write_all(&server_handshake_finished_record_bytes)?;

                    Ok(())
                }
            }
        }
        TLS_RECORD_CHANGE_CIPHER_SPEC => {
            context.client_change_cipher_spec_record = data.clone().to_vec();
            let _ = get_client_change_cipher_spec_record(&data);
            Ok(())
        }
        TLS_RECORD_ALERT | TLS_RECORD_APPLICATION_DATA => {
            let client_alert_record = get_client_alert_record(&data);

            let data_bytes = decrypt_data(
                &state.session_keys.as_ref().unwrap(),
                &client_alert_record.encryption_iv,
                &client_alert_record.encrypted_data,
            );

            let data_message = String::from_utf8_lossy(&data_bytes);
            if data_message == "Close Notify" {
                socket.shutdown(Shutdown::Both)?;
            } else {
                println!("Decrypted Message: {}", data_message);
            }

            Ok(())
        }
        _ => Err(TlsHandlerError::InvalidRecord(record_type)),
    }
}
