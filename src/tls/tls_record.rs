use crate::tls::tls_certificate::load_certificates;
use crate::tls::tls_utils::{
    add_to_3_byte_u8_array, generate_random_32_bytes, generate_server_random,
};

#[derive(Debug)]
pub struct RecordHeader {
    record_type: u8,
    protocol_version: [u8; 2],
    length: [u8; 2],
}

#[derive(Debug)]
pub struct HandshakeHeader {
    handshake_type: u8,
    length: [u8; 3],
}

#[derive(Debug)]
pub struct HelloRecord {
    version: [u8; 2],
    random: [u8; 32],
    session_id: [u8; 32],
    cipher_suite: [u8; 2],
    compression_method: [u8; 2],
}

#[derive(Debug)]
pub struct ClientHelloRecord {
    record_header: RecordHeader,
    handshake_header: HandshakeHeader,
    hello_record: HelloRecord,
}

impl ClientHelloRecord {
    fn new(
        record_header: RecordHeader,
        handshake_header: HandshakeHeader,
        hello_record: HelloRecord,
    ) -> Self {
        Self {
            record_header,
            handshake_header,
            hello_record,
        }
    }
}

#[derive(Debug)]
pub struct ServerHelloRecord {
    record_header: RecordHeader,
    handshake_header: HandshakeHeader,
    hello_record: HelloRecord,
}

impl ServerHelloRecord {
    fn new() -> Self {
        Self {
            record_header: RecordHeader {
                record_type: 0x16,              // HANDSHAKE
                protocol_version: [0x03, 0x03], //TLS 1.2
                length: [0x00, 0x03],           // BYTES OF HANDSHAKE HEADER
            },
            handshake_header: HandshakeHeader {
                handshake_type: 0x02,       // CLIENT HELLO
                length: [0x00, 0x00, 0x46], // BYTES OF CLIENT HELLO DATA
            },
            hello_record: HelloRecord {
                version: [0x03, 0x03],
                random: generate_server_random(),
                session_id: generate_random_32_bytes(),
                cipher_suite: [0x00, 0x3C], // TLS RSA with AES 128 CBC SHA
                compression_method: [0x01, 0x00],
            },
        }
    }
}

#[derive(Debug)]
pub struct ServerCertificate {
    pub length: [u8; 3],
    pub certificate: Vec<u8>,
}

#[derive(Debug)]
pub struct ServerCertificateRecord {
    handshake_header: HandshakeHeader,
    request_context: u8,
    certificates_length: [u8; 3],
    certificates: Vec<ServerCertificate>,
}

impl ServerCertificateRecord {
    fn new() -> Self {
        let (certificates_length, certificates) =
            load_certificates().expect("unable to load certificates");

        let length = add_to_3_byte_u8_array(&certificates_length, 4);

        ServerCertificateRecord {
            handshake_header: HandshakeHeader {
                handshake_type: 0x0B,
                length,
            },
            request_context: 0x00,
            certificates_length,
            certificates,
        }
    }
}

#[derive(Debug)]
pub struct ClientKeyExchangeRecord {}

#[derive(Debug)]
pub struct ServerFinishedRecord {
    message_type: u8,
    length: [u8; 12],
    hash: Vec<u8>,
}

impl ServerFinishedRecord {
    fn new() -> Self {
        let length: [u8; 12] = get_hash_length();
        let hash: Vec<u8> = get_server_hash();

        ServerFinishedRecord {
            message_type: 0x14, // FINISHED,
            length,
            hash,
        }
    }
}
