use crate::tls::tls_record::{
    ApplicationDataRecord, ChangeCipherSpecRecord, HandshakeHeader, HelloRecord, RecordHeader,
    ServerHelloDoneRecord,
};

pub fn encode_record_header(record_header: &RecordHeader) -> [u8; 5] {
    let mut data_bytes: [u8; 5] = [0u8; 5];
    data_bytes[0] = record_header.record_type;
    data_bytes[1..3].copy_from_slice(&record_header.protocol_version);
    data_bytes[3..5].copy_from_slice(&record_header.handshake_message_length);
    data_bytes
}

pub fn encode_handshake_header(handshake_header: &HandshakeHeader) -> [u8; 4] {
    let mut data_bytes: [u8; 4] = [0u8; 4];
    data_bytes[0] = handshake_header.handshake_type;
    data_bytes[1..4].copy_from_slice(&handshake_header.data_message_length);
    data_bytes
}

pub fn encode_hello_record(hello_record: &HelloRecord) -> Vec<u8> {
    let record_header = encode_record_header(&hello_record.record_header);
    let handshake_header = encode_handshake_header(&hello_record.handshake_header);

    let mut data_bytes: Vec<u8> = Vec::new();
    data_bytes.extend_from_slice(&record_header);
    data_bytes.extend_from_slice(&handshake_header);
    data_bytes.extend_from_slice(&hello_record.version);
    data_bytes.extend_from_slice(&hello_record.random);
    data_bytes.extend_from_slice(&hello_record.session_id);
    data_bytes.extend_from_slice(&hello_record.cipher_suites_length);
    for cipher_suite in &hello_record.cipher_suites {
        data_bytes.extend_from_slice(cipher_suite);
    }
    data_bytes
}

pub fn encode_server_hello_done_record(server_hello_done_record: ServerHelloDoneRecord) -> [u8; 9] {
    let record_header = encode_record_header(&server_hello_done_record.record_header);
    let handshake_header = encode_handshake_header(&server_hello_done_record.handshake_header);

    let mut data_bytes: [u8; 9] = [0u8; 9];
    data_bytes[0..6].copy_from_slice(&record_header);
    data_bytes[6..10].copy_from_slice(&handshake_header);
    data_bytes
}

pub fn encode_change_cipher_spec_record(
    change_cipher_spec_record: &ChangeCipherSpecRecord,
) -> Vec<u8> {
    let mut data_bytes: Vec<u8> = Vec::new();
    data_bytes.push(change_cipher_spec_record.record_type);
    data_bytes.extend_from_slice(&change_cipher_spec_record.protocol_version);
    data_bytes.extend_from_slice(&change_cipher_spec_record.change_cipher_specs_length);
    data_bytes.push(change_cipher_spec_record.change_cipher_specs);
    data_bytes
}

pub fn encode_application_data_record(application_data_record: &ApplicationDataRecord) -> Vec<u8> {
    let record_header = encode_record_header(&application_data_record.record_header);

    let mut data_bytes: Vec<u8> = Vec::new();
    data_bytes.extend_from_slice(&record_header);
    data_bytes.extend_from_slice(&application_data_record.encryption_iv);
    data_bytes.extend_from_slice(&application_data_record.encrypted_data);
    data_bytes
}
