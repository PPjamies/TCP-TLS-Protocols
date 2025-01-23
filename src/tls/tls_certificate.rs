use crate::tls::tls_record::ServerCertificate;
use crate::tls::tls_utils::{read_file_to_bytes, convert_usize_to_3_bytes};
use std::env;
use std::io::Error;

#[derive(Debug)]
pub enum CertificateError {
    SizeExceedsLimit(usize),
    IoError(Error),
}

impl From<Error> for CertificateError {
    fn from(err: Error) -> Self {
        CertificateError::IoError(err)
    }
}

type Result<T> = std::result::Result<T, CertificateError>;

fn validate_certificate_size(size: usize) -> Result<()> {
    if size > 0xFFFFFF {
        return Err(CertificateError::SizeExceedsLimit(size));
    }
    Ok(())
}

pub fn load_certificates() -> Result<([u8; 3], Vec<ServerCertificate>)> {
    //todo: handle this gracefully
    let cert_path = env::var("PATH_SERVER_CERT_DIR").expect("Server cert directory not found");
    let paths = vec![cert_path];

    let mut certs: Vec<ServerCertificate> = Vec::new();

    for path in paths {
        let cert_bytes = read_file_to_bytes(&path)?;
        let cert_length = cert_bytes.len();

        validate_certificate_size(cert_length)?;

        let server_certificate = ServerCertificate {
            length: convert_usize_to_3_bytes(cert_length),
            certificate: cert_bytes,
        };

        certs.push(server_certificate);
    }

    validate_certificate_size(certs.len())?;
    let certs_length = convert_usize_to_3_bytes(certs.len());

    Ok((certs_length, certs))
}
