use crate::tls::tls_utils::{read_file_to_bytes, usize_to_3_bytes};
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

pub fn load_certificates(paths: Vec<String>) -> Result<([u8; 3], Vec<Vec<u8>>)> {
    let mut certs = Vec::new();
    let mut certs_length: usize = 0;

    for path in paths {
        let cert_bytes = read_file_to_bytes(&path)?;
        let cert_length = cert_bytes.len();

        validate_certificate_size(cert_length)?;
        validate_certificate_size(certs_length + cert_length)?;

        let mut data = Vec::new();
        data.extend_from_slice(&usize_to_3_bytes(cert_length));
        data.extend_from_slice(&cert_bytes);

        certs.push(data);
        certs_length += cert_length;
    }

    Ok((usize_to_3_bytes(certs_length), certs))
}
