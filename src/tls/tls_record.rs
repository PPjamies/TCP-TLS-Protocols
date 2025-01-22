use crate::tls::tls_utils::{generate_random_32_bytes, generate_server_random};

/* server hello message:
* protocol version (2 bytes)
* server random (32 bytes)
* session id (32 bytes)
* cipher suite (2 bytes)
* compression method (1 byte) */
struct TlsServerHelloRecord {
    message_type: u8,
    protocol_version: [u8; 2],
    random: [u8; 32],
    session_id: [u8; 32],
    cipher_suite: [u8; 2],
    compression_method: u8,
}

impl TlsServerHelloRecord {
    fn new() -> Self {
        //TODO: place in server config
        let message_type = 0x02; //HELLO
        let protocol_version = [0x03, 0x03]; // TLS 1.2
        let random = generate_server_random();
        let session_id = generate_random_32_bytes();
        let cipher_suite = [0x00, 0x3C]; // TLS_RSA_WITH_AES_128_CBC_SHA
        let compression_method = 0x00; // No compression

        TlsServerHelloRecord {
            message_type,
            protocol_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
        }
    }
}

/* server certificate message:
* certificate type (1 byte)
* length (3 bytes) -  total size of certificates list
* certificates (variable bytes) - list of all tls certificates */
/* a certificate = (3 bytes - length) + (bytes - data) */
struct TlsServerCertificateRecord {
    message_type: u8,
    certificate_type: u8,
    length: [u8; 3],
    certificates: Vec<u8>,
}

impl TlsServerCertificateRecord {
    fn new() -> Self {
        //TODO: place in server config
        let message_type = 0x0B; // CERTIFICATE
        let certificate_type = 0x00; //X509
        let certificate_length: [u8; 3] = get_server_certificates_length();
        let certificates: Vec<u8> = get_server_certificates();

        TlsServerCertificateRecord {
            message_type,
            certificate_type,
            length: certificate_length,
            certificates,
        }
    }
}

/* server finished message:
* message_type (1 byte)
* length (12 bytes - SHA 256) - length of the hash
* finished hash (variable bytes) - the hash of the entire handshake signed by the server's private key */
struct TlsServerFinishedRecord {
    message_type: u8,
    length: [u8; 12],
    hash: Vec<u8>,
}

impl TlsServerFinishedRecord {
    fn new() -> Self {
        //TODO: put in config
        let message_type: u8 = 0x14; // FINISHED
        let length: [u8; 12] = get_hash_length();
        let hash: Vec<u8> = get_server_hash();

        TlsServerFinishedRecord {
            message_type,
            length,
            hash,
        }
    }
}
