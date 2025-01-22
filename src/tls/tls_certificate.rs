use openssl::x509::X509;
use std::fs::File;
use std::io::{Read, Result};

// (total size, bytes of the certificate)
fn load_certificate(path: String) -> Result<([u8; 3], Vec<u8>)> {
    let mut file = File::open(&path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(X509::from_pem(&data)?)
}

// (total size of all certificates, all certificates)
pub fn load_certificates() -> Result<([u8; 3], Vec<u8>)> {
    // todo: list all certificate paths in config
    let paths = Vec::new();

    let mut certificates: Vec<u8> = Vec::new();
    for path in paths {
        let (size, certificate_bytes) = load_certificate(path)?;

        let certificate: Vec<u8> = size + certificate_bytes;
        certificates.push(certificate);
    }

    let total_size: [u8; 3] = certificates.len();

    Ok((total_size, certificates))
}