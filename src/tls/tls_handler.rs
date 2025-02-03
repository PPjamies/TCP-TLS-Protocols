use crate::tls::tls_constants::*;
use crate::tls::tls_record_decoder::*;
use crate::tls::tls_record_encoder::*;
use crate::tls::tls_session::*;
use socket2::Socket;
use std::io::Write;
use std::net::Shutdown;

pub fn handle(
    mut socket: &Socket,
    state: &mut SessionState,
    context: &mut SessionContext,
    data: &[u8],
) {
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
                    socket
                        .write_all(&server_hello_record_bytes)
                        .expect("Unable to write server_hello record"); //todo: handle errors better

                    //todo: handle errors gracefully - too much unwrapping
                    let server_certificate_record_bytes: Vec<u8> =
                        get_server_certificate_record_bytes().unwrap();
                    context.server_certificate_record = server_certificate_record_bytes.clone();
                    socket
                        .write_all(&server_certificate_record_bytes)
                        .expect("Unable to write server_certificate record");

                    let server_hello_done_record_bytes: Vec<u8> = get_server_hello_record_bytes();
                    context.server_hello_done_record = server_hello_done_record_bytes.clone();
                    socket
                        .write_all(&server_hello_done_record_bytes)
                        .expect("Unable to write server_hello record");
                }
                TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE => {
                    context.client_key_exchange_record = data.clone().to_vec();
                    let client_key_exchange_record = get_client_key_exchange_record(&data);

                    // server decrypts premaster secret and derive session keys
                    let premaster_secret = decrypt_premaster_secret(
                        &client_key_exchange_record.unwrap().premaster_secret,
                    );
                    let session_keys = generate_session_keys(
                        &premaster_secret.as_ref().unwrap(),
                        &context.get_client_random().unwrap(),
                        &context.get_client_random().unwrap(),
                    )
                    .unwrap();

                    // store session state
                    state.session_id = Some(context.get_server_session_id().unwrap());
                    state.premaster_secret = Some(premaster_secret.unwrap());
                    state.session_keys = Some(session_keys);
                }
                _ => {
                    // client handshake finished
                    let client_application_data_record = get_client_application_data_record(&data);
                    let data_bytes = decrypt_data(
                        &state.session_keys.as_ref().unwrap(),
                        &client_application_data_record
                            .as_ref()
                            .unwrap()
                            .encryption_iv,
                        &client_application_data_record
                            .as_ref()
                            .unwrap()
                            .encrypted_data,
                    );

                    let client_handshake_finished_record =
                        get_client_handshake_finished_record(&data_bytes.unwrap());
                    let _ = validate_verify_data(
                        &state,
                        &context,
                        &client_handshake_finished_record.unwrap().verify_data,
                    );

                    let server_change_cipher_spec_record_bytes: Vec<u8> =
                        get_server_change_cipher_spec_record_bytes();
                    socket
                        .write_all(&server_change_cipher_spec_record_bytes)
                        .expect("Unable to write server_change_cipher_spec record");

                    // create handshake finished record with verify data
                    let server_handshake_finished_record_bytes =
                        get_server_handshake_finished_record_bytes(&context, &state);

                    // encrypt payload
                    let encryption_iv = &state.session_keys.as_ref().unwrap().iv;
                    let encrypted_data = encrypt_data(
                        &state.session_keys.as_ref().unwrap(),
                        &encryption_iv,
                        &server_handshake_finished_record_bytes.unwrap(),
                    );
                    let encryption_len =
                        encrypted_data.as_ref().unwrap().len() + encryption_iv.len();

                    // wrap up and encode
                    let server_application_data_record_bytes: Vec<u8> =
                        get_server_application_data_record_bytes(
                            encryption_len,
                            &encryption_iv,
                            &encrypted_data.unwrap(),
                        );
                    socket
                        .write_all(&server_application_data_record_bytes)
                        .expect("Unable to write server_application_data record");
                }
            }
        }
        TLS_RECORD_CHANGE_CIPHER_SPEC => {
            context.client_change_cipher_spec_record = data.clone().to_vec();
            let _ = get_client_change_cipher_spec_record(&data);
        }
        TLS_RECORD_ALERT | TLS_RECORD_APPLICATION_DATA => {
            let client_alert_record = get_client_alert_record(&data);
            let data_bytes = decrypt_data(
                &state.session_keys.as_ref().unwrap(),
                &client_alert_record.as_ref().unwrap().encryption_iv,
                &client_alert_record.as_ref().unwrap().encrypted_data,
            );

            let data_message = String::from_utf8_lossy(&data_bytes.unwrap());
            if data_message == "Close Notify" {
                socket
                    .shutdown(Shutdown::Both)
                    .expect("Unable to shutdown socket");
            } else {
                println!("Decrypted Message: {}", data_message);
            }
        }
        _ => {
            eprint!("Unable to handle request") //todo: ew
        }
    }
}
