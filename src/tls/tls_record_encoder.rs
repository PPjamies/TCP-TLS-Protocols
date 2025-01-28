use crate::tls::tls_record::{
    ApplicationDataRecord, ChangeCipherSpecRecord, HandshakeHeader, HelloRecord, RecordHeader,
    ServerHelloDoneRecord,
};

pub fn encode_record_header(record_header: &RecordHeader) -> Vec<u8> {

}

pub fn encode_handshake_header(handshake_header: &HandshakeHeader) -> Vec<u8> {}

pub fn encode_hello_record(hello_record: &HelloRecord) -> Vec<u8> {}

pub fn encode_server_hello_done_record(server_hello_done_record: ServerHelloDoneRecord) -> Vec<u8> {
}

pub fn encode_change_cipher_spec_record(
    change_cipher_spec_record: &ChangeCipherSpecRecord,
) -> Vec<u8> {
}

pub fn encode_application_data_record(application_data_record: &ApplicationDataRecord) -> Vec<u8> {}
