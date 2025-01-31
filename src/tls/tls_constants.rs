use crate::tls::tls_record::{
    ChangeCipherSpecRecord, HandshakeHeader, HelloRecord, RecordHeader, ServerHelloDoneRecord,
};
use crate::tls::tls_utils::{generate_random_32_bytes, generate_server_random};

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
pub static TLS_SERVER_HELLO: HelloRecord = HelloRecord {
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
};

pub static TLS_SERVER_HELLO_DONE: ServerHelloDoneRecord = ServerHelloDoneRecord {
    record_header: RecordHeader {
        record_type: TLS_RECORD_HANDSHAKE,
        protocol_version: TLS_PROTOCOL_VERSION,
        handshake_message_length: TLS_HANDSHAKE_MESSAGE_LENGTH,
    },
    handshake_header: HandshakeHeader {
        handshake_type: TLS_HANDSHAKE_SERVER_HELLO_DONE,
        data_message_length: [0x00, 0x00, 0x00],
    },
};

pub static TLS_SERVER_CHANGE_CIPHER_SPEC: ChangeCipherSpecRecord = ChangeCipherSpecRecord {
    record_type: TLS_RECORD_CHANGE_CIPHER_SPEC,
    protocol_version: TLS_PROTOCOL_VERSION,
    change_cipher_specs_length: [0x00, 0x01],
    change_cipher_specs: 0x01,
};
