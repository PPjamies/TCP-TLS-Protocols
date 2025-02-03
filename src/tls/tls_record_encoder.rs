use crate::tls::tls_constants::{
    TLS_HANDSHAKE_FINISHED, TLS_HANDSHAKE_MESSAGE_LENGTH, TLS_HANDSHAKE_SERVER_CERTIFICATE,
    TLS_PROTOCOL_VERSION, TLS_RECORD_HANDSHAKE, TLS_SERVER_CHANGE_CIPHER_SPEC, TLS_SERVER_HELLO,
    TLS_SERVER_HELLO_DONE,
};
use crate::tls::tls_record::{
    ApplicationDataRecord, ChangeCipherSpecRecord, HandshakeFinishedRecord, HandshakeHeader,
    HelloRecord, RecordHeader, ServerCertificateRecord, ServerHelloDoneRecord,
};
use crate::tls::tls_session::{get_verify_data, HandshakeError};
use crate::tls::tls_utils::{
    convert_usize_to_2_bytes, convert_usize_to_3_bytes, read_file_to_bytes,
};
use crate::tls::{SessionContext, SessionState};
use std::env;

#[derive(Debug)]
pub enum EncoderError {
    CertificateEnvVarReadError,
    CertificateReadError,
}
impl std::fmt::Display for EncoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EncoderError::CertificateEnvVarReadError => {
                write!(f, "Unable to read environment variable")
            }
            EncoderError::CertificateReadError => {
                write!(f, "Unable to read certificate")
            }
        }
    }
}
impl std::error::Error for EncoderError {}

fn encode_record_header(record_header: &RecordHeader) -> [u8; 5] {
    let mut data_bytes: [u8; 5] = [0u8; 5];
    data_bytes[0] = record_header.record_type;
    data_bytes[1..3].copy_from_slice(&record_header.protocol_version);
    data_bytes[3..5].copy_from_slice(&record_header.handshake_message_length);
    data_bytes
}

fn encode_handshake_header(handshake_header: &HandshakeHeader) -> [u8; 4] {
    let mut data_bytes: [u8; 4] = [0u8; 4];
    data_bytes[0] = handshake_header.handshake_type;
    data_bytes[1..4].copy_from_slice(&handshake_header.data_message_length);
    data_bytes
}

fn encode_hello_record(hello_record: &HelloRecord) -> Vec<u8> {
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

fn encode_server_certificate_record(
    server_certificate_record: &ServerCertificateRecord,
) -> Vec<u8> {
    let record_header = encode_record_header(&server_certificate_record.record_header);
    let handshake_header = encode_handshake_header(&server_certificate_record.handshake_header);

    let mut data_bytes: Vec<u8> = Vec::new();
    data_bytes.extend_from_slice(&record_header);
    data_bytes.extend_from_slice(&handshake_header);
    data_bytes.extend_from_slice(&server_certificate_record.certificates_length);
    data_bytes.extend_from_slice(&server_certificate_record.certificate_length);
    data_bytes.extend_from_slice(&server_certificate_record.certificate);
    data_bytes
}

fn encode_server_hello_done_record(server_hello_done_record: &ServerHelloDoneRecord) -> [u8; 9] {
    let record_header = encode_record_header(&server_hello_done_record.record_header);
    let handshake_header = encode_handshake_header(&server_hello_done_record.handshake_header);

    let mut data_bytes: [u8; 9] = [0u8; 9];
    data_bytes[0..6].copy_from_slice(&record_header);
    data_bytes[6..10].copy_from_slice(&handshake_header);
    data_bytes
}

fn encode_change_cipher_spec_record(change_cipher_spec_record: &ChangeCipherSpecRecord) -> Vec<u8> {
    let mut data_bytes: Vec<u8> = Vec::new();
    data_bytes.push(change_cipher_spec_record.record_type);
    data_bytes.extend_from_slice(&change_cipher_spec_record.protocol_version);
    data_bytes.extend_from_slice(&change_cipher_spec_record.change_cipher_specs_length);
    data_bytes.push(change_cipher_spec_record.change_cipher_specs);
    data_bytes
}

fn encode_handshake_finished_record(
    handshake_finished_record: &HandshakeFinishedRecord,
) -> Vec<u8> {
    let handshake_header = encode_handshake_header(&handshake_finished_record.handshake_header);

    let mut data_bytes: Vec<u8> = Vec::new();
    data_bytes.extend_from_slice(&handshake_header);
    data_bytes.extend_from_slice(&handshake_finished_record.verify_data);
    data_bytes
}

fn encode_application_data_record(application_data_record: &ApplicationDataRecord) -> Vec<u8> {
    let record_header = encode_record_header(&application_data_record.record_header);

    let mut data_bytes: Vec<u8> = Vec::new();
    data_bytes.extend_from_slice(&record_header);
    data_bytes.extend_from_slice(&application_data_record.encryption_iv);
    data_bytes.extend_from_slice(&application_data_record.encrypted_data);
    data_bytes
}

pub fn get_server_hello_record_bytes() -> Vec<u8> {
    encode_hello_record(&TLS_SERVER_HELLO)
}

pub fn get_server_certificate_record_bytes() -> Result<Vec<u8>, EncoderError> {
    let path =
        env::var("PATH_SERVER_CERT_DIR").map_err(|_| EncoderError::CertificateEnvVarReadError)?;

    let certificate = read_file_to_bytes(&path).map_err(|_| EncoderError::CertificateReadError)?;
    let certificate_length = certificate.len();

    let record = ServerCertificateRecord {
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
    };

    Ok(encode_server_certificate_record(&record))
}

pub fn get_server_hello_done_record_bytes() -> [u8; 9] {
    encode_server_hello_done_record(&TLS_SERVER_HELLO_DONE)
}

pub fn get_server_change_cipher_spec_record_bytes() -> Vec<u8> {
    encode_change_cipher_spec_record(&TLS_SERVER_CHANGE_CIPHER_SPEC)
}

pub fn get_server_handshake_finished_record_bytes(
    context: &SessionContext,
    state: &SessionState,
) -> Result<Vec<u8>, HandshakeError> {
    let verify_data = get_verify_data(&state, &context)?;
    let verify_data_len = verify_data.len();

    let record = HandshakeFinishedRecord {
        handshake_header: HandshakeHeader {
            handshake_type: TLS_HANDSHAKE_FINISHED,
            data_message_length: convert_usize_to_3_bytes(verify_data_len),
        },
        verify_data,
    };
    Ok(encode_handshake_finished_record(&record))
}

pub fn get_server_application_data_record_bytes(
    encryption_length: usize,
    encryption_iv: &Vec<u8>,
    encrypted_data: &Vec<u8>,
) -> Vec<u8> {
    let record = ApplicationDataRecord {
        record_header: RecordHeader {
            record_type: TLS_RECORD_HANDSHAKE,
            protocol_version: TLS_PROTOCOL_VERSION,
            handshake_message_length: convert_usize_to_2_bytes(encryption_length),
        },
        encryption_iv: encryption_iv.clone(),
        encrypted_data: encrypted_data.clone(),
    };
    encode_application_data_record(&record)
}
