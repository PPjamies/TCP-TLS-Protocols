use crate::tls::tls_record::{
    ApplicationDataRecord, ChangeCipherSpecRecord, HandshakeHeader, HelloRecord, RecordHeader,
    ServerCertificateRecord, ServerHelloDoneRecord,
};
use crate::tls::tls_utils::{
    convert_usize_to_3_bytes, convert_usize_to_bytes, generate_random_32_bytes,
    generate_server_random, read_file_to_bytes,
};
use std::env;
use TlsHandlerError;

pub static TLS_PROTOCOL_VERSION: [u8; 2] = [0x03, 0x03]; // TLS 1.2
pub static TLS_RSA_AES_128_CBC_SHA_256: [u8; 2] = [0x00, 0x3C];
pub static TLS_HANDSHAKE_MESSAGE_LENGTH: [u8; 2] = [0x00, 0x04];
pub static TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub static TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub static TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
pub static TLS_RECORD_ALERT: u8 = 0x15;
pub static TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub static TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
pub static TLS_HANDSHAKE_SERVER_CERTIFICATE: u8 = 0x0B;
pub static TLS_HANDSHAKE_SERVER_HELLO_DONE: u8 = 0x0e;
pub static TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE: u8 = 0x10;
pub static TLS_HANDSHAKE_FINISHED: u8 = 0x14;

pub fn get_server_hello_record() -> HelloRecord {
    HelloRecord {
        record_header: RecordHeader {
            record_type: TLS_RECORD_HANDSHAKE,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: TLS_HANDSHAKE_MESSAGE_LENGTH,
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
    }
}

pub fn get_server_certificate_record() -> Result<ServerCertificateRecord, TlsHandlerError> {
    let path = env::var("PATH_SERVER_CERT_DIR")?;

    let certificate = read_file_to_bytes(&path)?;
    let certificate_length = certificate.len();

    Ok(ServerCertificateRecord {
        record_header: RecordHeader {
            record_type: TLS_RECORD_HANDSHAKE,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: TLS_HANDSHAKE_MESSAGE_LENGTH,
        },
        handshake_header: HandshakeHeader {
            handshake_type: TLS_HANDSHAKE_SERVER_CERTIFICATE,
            data_message_length: convert_usize_to_3_bytes(certificate_length + 7),
        },
        certificates_length: convert_usize_to_3_bytes(certificate_length),
        certificate_length: convert_usize_to_3_bytes(certificate_length),
        certificate,
    })
}

pub fn get_server_hello_done_record() -> ServerHelloDoneRecord {
    ServerHelloDoneRecord {
        record_header: RecordHeader {
            record_type: TLS_RECORD_HANDSHAKE,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: TLS_HANDSHAKE_MESSAGE_LENGTH,
        },
        handshake_header: HandshakeHeader {
            handshake_type: TLS_HANDSHAKE_SERVER_HELLO_DONE,
            data_message_length: [0x00, 0x00, 0x00],
        },
    }
}

pub fn get_server_change_cipher_spec_record() -> ChangeCipherSpecRecord {
    ChangeCipherSpecRecord {
        record_type: TLS_RECORD_CHANGE_CIPHER_SPEC,
        protocol_version: TLS_PROTOCOL_VERSION,
        change_cipher_specs_length: [0x00, 0x01],
        change_cipher_specs: 0x01,
    }
}

// used for handshake finished records
pub fn get_server_application_data_record(
    encryption_length: usize,
    encryption_iv: &[u8; 16],
    encrypted_data: &Vec<u8>,
) -> Result<ApplicationDataRecord, TlsHandlerError> {
    Ok(ApplicationDataRecord {
        record_header: RecordHeader {
            record_type: TLS_RECORD_HANDSHAKE,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: convert_usize_to_bytes(encryption_length).try_into().unwrap(),
        },
        encryption_iv: encryption_iv.clone(),
        encrypted_data: encrypted_data.clone(),
    })
}
