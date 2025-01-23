use crate::tls::tls_certificate::load_certificates;
use crate::tls::tls_utils::{generate_random_32_bytes, generate_server_random};
use std::env;

pub struct ServerHelloRecord {
    message_type: u8,
    protocol_version: [u8; 2],
    random: [u8; 32],
    session_id: [u8; 32],
    cipher_suite: [u8; 2],
    compression_method: u8,
}

impl ServerHelloRecord {
    fn new() -> Self {
        ServerHelloRecord {
            message_type: 0x02,             //HELLO
            protocol_version: [0x03, 0x03], // TLS 1.2
            random: generate_server_random(),
            session_id: generate_random_32_bytes(),
            cipher_suite: [0x00, 0x3C], // TLS RSA with AES 128 CBC SHA
            compression_method: 0x00,   // No compression
        }
    }
}

pub struct ServerCertificateRecord {
    message_type: u8,
    certificate_type: u8,
    length: [u8; 3],
    certificates: Vec<Vec<u8>>,
}

impl ServerCertificateRecord {
    fn new() -> Self {
        let cert_path = env::var("PATH_SERVER_CERT_DIR").expect("Server cert directory not found");
        let cert_paths = vec![cert_path];

        let (length, certificates) =
            load_certificates(cert_paths).expect("unable to load certificates");

        ServerCertificateRecord {
            message_type: 0x0B,     // CERTIFICATE
            certificate_type: 0x00, //X509
            length,
            certificates,
        }
    }
}

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
