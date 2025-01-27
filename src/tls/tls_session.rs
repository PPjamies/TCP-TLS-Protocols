use crate::tls::tls_record::{
    ApplicationDataRecord, ChangeCipherSpecRecord, HelloRecord, KeyExchangeRecord,
    ServerCertificateRecord, ServerHelloDoneRecord,
};
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use std::fs::File;
use std::io::{Read, Result};

#[derive(Debug)]
pub struct SessionContext {
    pub client_hello_record: Option<HelloRecord>,
    pub server_hello_record: Option<HelloRecord>,
    pub server_certificate_record: Option<ServerCertificateRecord>,
    pub server_key_exchange_record: Option<KeyExchangeRecord>,
    pub server_hello_done_record: Option<ServerHelloDoneRecord>,
    pub client_key_exchange_record: Option<KeyExchangeRecord>,
    pub client_change_cipher_spec_record: Option<ChangeCipherSpecRecord>,
    pub client_handshake_finished_record: Option<ApplicationDataRecord>,
    pub server_change_cipher_spec_record: Option<ChangeCipherSpecRecord>,
    pub server_handshake_finished_record: Option<ApplicationDataRecord>,
}

impl SessionContext {
    pub fn new() -> SessionContext {
        Self {
            client_hello_record: None,
            server_hello_record: None,
            server_certificate_record: None,
            server_key_exchange_record: None,
            server_hello_done_record: None,
            client_key_exchange_record: None,
            client_change_cipher_spec_record: None,
            client_handshake_finished_record: None,
            server_change_cipher_spec_record: None,
            server_handshake_finished_record: None,
        }
    }
}

#[derive(Debug)]
pub struct SessionState {
    pub session_id: [u8; 32],
    pub cipher_suite: Vec<u8>,
    pub pre_master_secret: Vec<u8>,
    pub session_keys: SessionKeys,
}

#[derive(Debug)]
pub struct SessionKeys {
    pub encryption_key: Vec<u8>,
    pub mac_key: Vec<u8>,
    pub iv: Vec<u8>,
}

fn load_private_key() -> Result<PKey<Private>> {
    let mut file = File::open("../certs/server_private.pem")?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let rsa = Rsa::private_key_from_pem(&data)?;
    Ok(PKey::from_rsa(rsa)?)
}

fn decrypt_pre_master_secret(
    private_key: &PKey<Private>,
    pre_master_secret: &[u8],
) -> Result<Vec<u8>> {
    let rsa = private_key.rsa()?;
    let mut decrypt = vec![0; rsa.size() as usize]; // buffer to store decrypted pre master secret
    let decrypted_len = rsa.private_decrypt(
        pre_master_secret,
        &mut decrypt,
        openssl::rsa::Padding::PKCS1, // padding scheme
    )?;
    decrypt.truncate(decrypted_len);
    Ok(decrypt)
}

// salt = [client_random + server_random].concat
// info = b"tls1.2";
// output_len = 64 bytes
fn derive_session_keys(
    pre_master_secret: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<SessionKeys> {
    // HKDF

    // Extract - HMAC(salt, pre-master secret) -> PRK
    let mut hmac = Hasher::new(MessageDigest::sha256())?;
    hmac.update(&salt)?;
    hmac.update(&pre_master_secret)?;
    let prk = hmac.finish()?;

    // Expand  - HMAC(prk, info+prev_block)
    let mut blocks = Vec::new(); // block = [encryption key, mac key, IV (maybe), other keys]
    let mut prev_block = vec![0; output_len];

    while blocks.len() < output_len {
        let mut hmac = Hasher::new(MessageDigest::sha256())?;

        let mut info_and_prev_block = Vec::new();
        info_and_prev_block.extend_from_slice(&info);
        info_and_prev_block.extend_from_slice(&prev_block);

        hmac.update(&prk)?;
        hmac.update(&info_and_prev_block)?;

        let result = hmac.finish()?;
        prev_block = result.to_vec();

        blocks.extend_from_slice(&result);
    }

    blocks.truncate(output_len);

    // for HMAC-SHA256 encryption key = 16 bytes, mac key = 32 bytes, iv = 16 bytes
    let encryption_key = blocks[0..16].to_vec();
    let mac_key = blocks[16..48].to_vec();
    let iv = blocks[48..64].to_vec();

    Ok(SessionKeys {
        encryption_key,
        mac_key,
        iv,
    })
}
