#[derive(Debug)]
pub struct RecordHeader {
    pub record_type: u8,
    pub protocol_version: [u8; 2],
    pub handshake_message_length: [u8; 2],
}

#[derive(Debug)]
pub struct HandshakeHeader {
    pub handshake_type: u8,
    pub data_message_length: [u8; 3],
}

#[derive(Debug)]
pub struct HelloRecord {
    pub record_header: RecordHeader,
    pub handshake_header: HandshakeHeader,
    pub version: [u8; 2],
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub cipher_suites: Vec<u8>,
}

#[derive(Debug)]
pub struct CertificateRecord {
    pub handshake_header: HandshakeHeader,
    pub request_context: u8,
    pub certificates_length: [u8; 3],
    pub certificate_length: [u8; 3],
    pub certificate: Vec<u8>,
}

#[derive(Debug)]
pub struct Signature {
    pub signature_type: [u8; 2],
    pub length: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct CertificateVerifyRecord {
    pub handshake_header: HandshakeHeader,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct HandshakeFinishedRecord {
    pub handshake_header: HandshakeHeader,
    pub verify_data: Vec<u8>,
}

#[derive(Debug)]
pub struct NewSessionTicketRecord {
    pub handshake_header: HandshakeHeader,
    pub ticket_lifetime: [u8; 4],
    pub ticket_age_add: [u8; 4],
    pub ticket_nonce: [u8; 9],
    pub session_ticket: Vec<u8>,
}

#[derive(Debug)]
pub struct ApplicationData {
    pub payload: Vec<u8>,
}
