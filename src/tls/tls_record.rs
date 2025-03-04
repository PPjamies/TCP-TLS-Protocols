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

#[derive(Debug, Clone)]
pub struct ServerCertificateRecord {
    pub record_header: RecordHeader,
    pub handshake_header: HandshakeHeader,
    pub certificates_length: [u8; 3],
    pub certificate_length: [u8; 3],
    pub certificate: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ServerHelloDoneRecord {
    pub record_header: RecordHeader,
    pub handshake_header: HandshakeHeader,
}

#[derive(Debug, Clone)]
pub struct KeyExchangeRecord {
    pub record_header: RecordHeader,
    pub handshake_header: HandshakeHeader,
    pub premaster_secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ChangeCipherSpecRecord {
    pub record_type: u8,
    pub protocol_version: [u8; 2],
    pub change_cipher_specs_length: [u8; 2],
    pub change_cipher_specs: u8,
}

#[derive(Debug, Clone)]
pub struct HandshakeFinishedRecord {
    pub handshake_header: HandshakeHeader,
    pub verify_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ApplicationDataRecord {
    // used for handshake finished records as well
    pub record_header: RecordHeader,
    pub encryption_iv: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}
