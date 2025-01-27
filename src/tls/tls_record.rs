#[derive(Debug, Clone)]
pub struct RecordHeader {
    pub record_type: u8,
    pub protocol_version: [u8; 2],
    pub handshake_message_length: [u8; 2],
}

#[derive(Debug, Clone)]
pub struct HandshakeHeader {
    pub handshake_type: u8,
    pub data_message_length: [u8; 3],
}

#[derive(Debug, Clone)]
pub struct HelloRecord {
    pub record_header: RecordHeader,
    pub handshake_header: HandshakeHeader,
    pub version: [u8; 2],
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub cipher_suites_length: [u8; 2],
    pub cipher_suites: Vec<[u8; 2]>,
}

#[derive(Debug)]
pub struct ServerCertificateRecord {
    pub handshake_header: HandshakeHeader,
    pub request_context: u8,
    pub certificates_length: [u8; 3],
    pub certificate_length: [u8; 3],
    pub certificate: Vec<u8>,
}

#[derive(Debug)]
pub struct KeyExchangeRecord {
    pub record_header: RecordHeader,
    pub handshake_header: HandshakeHeader,
    pub public_key: [u8; 32],
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ServerHelloDoneRecord {
    pub record_header: RecordHeader,
    pub handshake_header: HandshakeHeader,
}

#[derive(Debug)]
pub struct ChangeCipherSpecRecord {
    pub record_header: RecordHeader,
}

#[derive(Debug)]
pub struct ApplicationDataRecord {
    // used for handshake finished records as well
    pub record_header: RecordHeader,
    pub encryption_iv: [u8; 16],
    pub encrypted_data: Vec<u8>,
}
