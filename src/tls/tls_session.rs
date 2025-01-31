use crate::tls::tls_utils::read_file_to_bytes;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::symm::{decrypt, encrypt, Cipher};
use std::env;
use std::result::Result;

#[derive(Debug)]
pub enum HandshakeError {
    EncryptionFailed,
    DecryptionFailed,
    PremasterSecretDecryptionFailed,
    SessionKeysGenerationFailed,
    HMACGenerationFailed,
    HMACSaltUpdateFailed,
    HMACPremasterSecretUpdateFailed,
    HMACPRKUpdateFailed,
    HMACBlockUpdateFailed,
    HMACFinishedFailed,
    KeyLoadingFailed,
    RSAKeyGenerationFailed,
    HMACPKeyGenerationFailed,
    InvalidVerifyData,
    SignerGenerationFailed,
    SignerUpdateFailed,
    SignerSignFailed,
    IOError(std::io::Error),
    EnvVarError(env::VarError),
    OpenSSLError(openssl::error::ErrorStack),
}
impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HandshakeError::EncryptionFailed => write!(f, "Encryption failed"),
            HandshakeError::DecryptionFailed => write!(f, "Decryption failed"),
            HandshakeError::PremasterSecretDecryptionFailed => {
                write!(f, "Premaster secret decryption failed")
            }
            HandshakeError::SessionKeysGenerationFailed => {
                write!(f, "Session keys generation failed")
            }
            HandshakeError::HMACGenerationFailed => {
                write!(f, "HMAC generation failed")
            }
            HandshakeError::HMACSaltUpdateFailed => {
                write!(f, "HMAC update failed")
            }
            HandshakeError::HMACPremasterSecretUpdateFailed => {
                write!(f, "HMAC premaster secret update failed")
            }
            HandshakeError::HMACPRKUpdateFailed => {
                write!(f, "HMAC PRK update failed")
            }
            HandshakeError::HMACBlockUpdateFailed => {
                write!(f, "HMAC block update failed")
            }
            HandshakeError::HMACFinishedFailed => {
                write!(f, "HMAC finished failed")
            }
            HandshakeError::KeyLoadingFailed => {
                write!(f, "Key loading failed")
            }
            HandshakeError::RSAKeyGenerationFailed => {
                write!(f, "RSA Key generation failed")
            }
            HandshakeError::HMACPKeyGenerationFailed => {
                write!(f, "HMAC PKey generation failed")
            }
            HandshakeError::InvalidVerifyData => {
                write!(f, "Invalid verify data")
            }
            HandshakeError::SignerGenerationFailed => {
                write!(f, "Signer generation failed")
            }
            HandshakeError::SignerUpdateFailed => {
                write!(f, "Signer update failed")
            }
            HandshakeError::SignerSignFailed => {
                write!(f, "Signer signing failed")
            }
            HandshakeError::IOError(e) => {
                write!(f, "IO error: {}", e)
            }
            HandshakeError::EnvVarError(e) => {
                write!(f, "Environment variable error: {}", e)
            }
            HandshakeError::OpenSSLError(e) => {
                write!(f, "OpenSSL error: {}", e)
            }
        }
    }
}
impl std::error::Error for HandshakeError {}

#[derive(Debug)]
pub struct SessionContext {
    pub client_hello_record: Vec<u8>,
    pub server_hello_record: Vec<u8>,
    pub server_certificate_record: Vec<u8>,
    pub server_hello_done_record: Vec<u8>,
    pub client_key_exchange_record: Vec<u8>,
    pub client_change_cipher_spec_record: Vec<u8>,
}

impl SessionContext {
    pub fn new() -> SessionContext {
        Self {
            client_hello_record: Vec::new(),
            server_hello_record: Vec::new(),
            server_certificate_record: Vec::new(),
            server_hello_done_record: Vec::new(),
            client_key_exchange_record: Vec::new(),
            client_change_cipher_spec_record: Vec::new(),
        }
    }

    pub fn get_client_random(&self) -> [u8; 32] {

    }

    pub fn get_server_random(&self) -> [u8; 32] {

    }

    pub fn get_server_session_id(&self) -> [u8; 32] {

    }
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_id: Option<[u8; 32]>,
    pub premaster_secret: Option<Vec<u8>>,
    pub session_keys: Option<SessionKeys>,
}

impl SessionState {
    pub fn new() -> SessionState {
        Self {
            session_id: None,
            premaster_secret: None,
            session_keys: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub encryption_key: Vec<u8>,
    pub mac_key: Vec<u8>,
    pub iv: Vec<u8>,
}

pub fn encrypt_data(
    session_keys: &SessionKeys,
    encryption_iv: &Vec<u8>,
    data: &Vec<u8>,
) -> Result<Vec<u8>, HandshakeError> {
    let key = session_keys.encryption_key.clone();
    encrypt(Cipher::aes_128_cbc(), &key, Some(&encryption_iv), data)
        .map_err(|_| HandshakeError::EncryptionFailed)
}

pub fn decrypt_data(
    session_keys: &SessionKeys,
    encryption_iv: &Vec<u8>,
    data: &Vec<u8>,
) -> Result<Vec<u8>, HandshakeError> {
    let key = session_keys.encryption_key.clone();
    decrypt(Cipher::aes_128_cbc(), &key, Some(&encryption_iv), data)
        .map_err(|_| HandshakeError::DecryptionFailed)
}

pub fn decrypt_premaster_secret(premaster_secret: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let private_key = load_private_key()?;
    let rsa = private_key
        .rsa()
        .map_err(|_| HandshakeError::RSAKeyGenerationFailed)?;

    let mut decrypted_premaster_secret = vec![0; rsa.size() as usize];
    let decrypted_len = rsa
        .private_decrypt(
            premaster_secret,
            &mut decrypted_premaster_secret,
            Padding::PKCS1,
        )
        .map_err(|_| HandshakeError::PremasterSecretDecryptionFailed)?;
    decrypted_premaster_secret.truncate(decrypted_len);

    Ok(decrypted_premaster_secret)
}

fn load_private_key() -> Result<PKey<Private>, HandshakeError> {
    let path = env::var("PATH_SERVER_KEY_DIR").map_err(|_| HandshakeError::KeyLoadingFailed)?;
    let pem_bytes: Vec<u8> =
        read_file_to_bytes(&path).map_err(|_| HandshakeError::KeyLoadingFailed)?;
    let rsa =
        Rsa::private_key_from_pem(&pem_bytes).map_err(|_| HandshakeError::KeyLoadingFailed)?;
    let pkey = PKey::from_rsa(rsa).map_err(|_| HandshakeError::RSAKeyGenerationFailed)?;

    Ok(pkey)
}

// Key Derivation Function  - HKDF
fn hkdf(
    premaster_secret: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<SessionKeys, HandshakeError> {
    // Extract - HMAC(salt, premaster_secret) -> PRK
    let mut hmac =
        Hasher::new(MessageDigest::sha256()).map_err(|_| HandshakeError::HMACGenerationFailed)?;

    hmac.update(&salt)
        .map_err(|_| HandshakeError::HMACSaltUpdateFailed)?;
    hmac.update(&premaster_secret)
        .map_err(|_| HandshakeError::HMACPremasterSecretUpdateFailed)?;

    let prk = hmac
        .finish()
        .map_err(|_| HandshakeError::HMACFinishedFailed)?;

    // Expand - HMAC(prk, info + prev_block)
    let mut blocks = Vec::new(); // block = [encryption key, mac key, IV (maybe), other keys]
    let mut prev_block = vec![0; output_len];

    while blocks.len() < output_len {
        let mut hmac = Hasher::new(MessageDigest::sha256())
            .map_err(|_| HandshakeError::HMACGenerationFailed)?;

        let mut info_and_prev_block = Vec::new();
        info_and_prev_block.extend_from_slice(&info);
        info_and_prev_block.extend_from_slice(&prev_block);

        hmac.update(&prk)
            .map_err(|_| HandshakeError::HMACPRKUpdateFailed)?;
        hmac.update(&info_and_prev_block)
            .map_err(|_| HandshakeError::HMACBlockUpdateFailed)?;

        let result = hmac
            .finish()
            .map_err(|_| HandshakeError::HMACFinishedFailed)?;
        prev_block = result.to_vec();

        blocks.extend_from_slice(&result);
    }

    blocks.truncate(output_len);

    // (HMAC-SHA256)
    // encryption key = 16 bytes
    // mac key = 32 bytes
    // iv = 16 bytes
    let encryption_key = blocks[0..16].to_vec();
    let mac_key = blocks[16..48].to_vec();
    let iv = blocks[48..64].to_vec();

    Ok(SessionKeys {
        encryption_key,
        mac_key,
        iv,
    })
}

pub fn generate_session_keys(
    premaster_secret: &[u8],
    server_random: &[u8],
    client_random: &[u8],
) -> Result<SessionKeys, HandshakeError> {
    let mut salt = [0u8; 64];
    salt.copy_from_slice(server_random);
    salt.copy_from_slice(client_random);

    let info = b"tls1.2";
    let output_len = 64usize;

    let session_keys: SessionKeys = hkdf(&premaster_secret, &salt, &info, output_len)?;
    Ok(session_keys)
}

pub fn validate_verify_data(
    state: &SessionState,
    context: &SessionContext,
    verify_data: &Vec<u8>,
) -> Result<(), HandshakeError> {
    let computed_verify_data = get_verify_data(&state, &context);

    if *verify_data != computed_verify_data {
        return Err(HandshakeError::InvalidVerifyData);
    }

    Ok(())
}

pub fn get_verify_data(state: &SessionState, context: &SessionContext) -> Vec<u8> {
    let mac_key = &state.session_keys.as_ref().unwrap().mac_key;

    let client_random = &context.get_client_random();
    let server_random = &context.get_server_random();

    let mut handshake_messages_bytes = Vec::new();
    handshake_messages_bytes.extend_from_slice(&context.client_hello_record);
    handshake_messages_bytes.extend_from_slice(&context.server_hello_record);
    handshake_messages_bytes.extend_from_slice(&context.server_certificate_record);
    handshake_messages_bytes.extend_from_slice(&context.server_hello_done_record);
    handshake_messages_bytes.extend_from_slice(&context.client_key_exchange_record);
    handshake_messages_bytes.extend_from_slice(&context.client_change_cipher_spec_record);

    compute_verify_data(
        &mac_key,
        &client_random,
        &server_random,
        &handshake_messages_bytes,
    )
}

fn compute_verify_data(
    mac_key: &Vec<u8>,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    handshake_messages_bytes: &Vec<u8>,
) -> Vec<u8> {
    let pkey = PKey::hmac(&mac_key).map_err(HandshakeError::HMACPKeyGenerationFailed);

    let mut signer =
        Signer::new(MessageDigest::sha256(), &pkey).map_err(HandshakeError::SignerGenerationFailed);

    let mut info = Vec::new();
    info.extend_from_slice(client_random);
    info.extend_from_slice(server_random);

    signer
        .update(&info)
        .map_err(HandshakeError::SignerUpdateFailed);
    signer
        .update(&handshake_messages_bytes)
        .map_error(HandshakeError::SignerUpdateFailed);

    let computed_verify_data = signer
        .sign_to_vec()
        .map_error(HandshakeError::SignerSignFailed);

    computed_verify_data
}
