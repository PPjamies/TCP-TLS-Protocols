use crate::tls::tls_utils::read_file_to_bytes;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::symm::{decrypt, Cipher};
use std::env;
use std::io::Result;

#[derive(Debug)]
pub struct SessionContext {
    pub client_hello_record: Vec<u8>,
    pub server_hello_record: Vec<u8>,
    pub server_certificate_record: Vec<u8>,
    pub server_hello_done_record: Vec<u8>,
    pub client_key_exchange_record: Vec<u8>,
    pub client_change_cipher_spec_record: Vec<u8>
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

    pub fn get_client_random(&self) -> [u8; 32] {}

    pub fn get_server_random(&self) -> [u8; 32] {}

    pub fn get_server_session_id(&self) -> [u8; 32] {}
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

fn load_private_key() -> Result<PKey<Private>> {
    let path = env::var("PATH_SERVER_KEY_DIR").unwrap();
    let data: Vec<u8> = read_file_to_bytes(&path)?;
    let rsa = Rsa::private_key_from_pem(&data)?;
    Ok(PKey::from_rsa(rsa)?)
}

pub fn decrypt_premaster_secret(premaster_secret: &[u8]) -> Vec<u8> {
    let private_key = load_private_key().expect("failed to load private key");
    let rsa = private_key.rsa().expect("failed to get private key");
    let mut decrypt = vec![0; rsa.size() as usize]; // buffer to store decrypted pre master secret
    let decrypted_len = rsa
        .private_decrypt(
            premaster_secret,
            &mut decrypt,
            openssl::rsa::Padding::PKCS1, // padding scheme
        )
        .expect("failed to decrypt premaster secret");
    decrypt.truncate(decrypted_len);
    decrypt
}

fn hkdf(
    premaster_secret: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<SessionKeys> {
    // Extract - HMAC(salt, premaster_secret) -> PRK
    let mut hmac = Hasher::new(MessageDigest::sha256())?;
    hmac.update(&salt)?;
    hmac.update(&premaster_secret)?;
    let prk = hmac.finish()?;

    // Expand - HMAC(prk, info + prev_block)
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

pub fn decrypt_session_keys(
    premaster_secret: &[u8],
    server_random: &[u8],
    client_random: &[u8],
) -> Result<SessionKeys> {
    let mut salt = [0u8; 64];
    salt.copy_from_slice(server_random);
    salt.copy_from_slice(client_random);

    let info = b"tls1.2";
    let output_len = 64usize;

    let session_keys: SessionKeys = hkdf(&premaster_secret, &salt, &info, output_len)?;
    Ok(session_keys)
}

pub fn decrypt_data(
    session_keys: &SessionKeys,
    encryption_iv: &[u8; 16],
    data: &Vec<u8>,
) -> Vec<u8> {
    let key = session_keys.encryption_key.clone();
    decrypt(Cipher::aes_128_cbc(), &key, Some(&encryption_iv), data).expect("Decryption failed")
}

pub fn verify_finished_message(
    verify_data: &Vec<u8>,
    context: &SessionContext,
    state: &SessionState,
) {
    let mut handshake_messages = Vec::new();
    handshake_messages.extend_from_slice(&context.client_hello_record);
    handshake_messages.extend_from_slice(&context.server_hello_record);
    handshake_messages.extend_from_slice(&context.server_certificate_record);
    handshake_messages.extend_from_slice(&context.server_hello_done_record);
    handshake_messages.extend_from_slice(&context.client_key_exchange_record);
    handshake_messages.extend_from_slice(&context.client_change_cipher_spec_record);

    let mac_key = state.session_keys.as_ref().unwrap().mac_key.to_vec();
    let pkey = PKey::hmac(&mac_key).expect("failed to create pkey");

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("failed to create signer");

    let mut info = Vec::new();
    info.extend_from_slice(&context.get_client_random());
    info.extend_from_slice(&context.get_server_random());

    signer.update(&info).expect("failed to update session info");
    signer
        .update(&handshake_messages)
        .expect("failed to update handshake messages");

    let verify_data_calculated = signer
        .sign_to_vec()
        .expect("failed to sign handshake messages");
    if verify_data_calculated == *verify_data {
        println!("Verify data matches. Handshake is complete.");
    } else {
        println!("Verify data does not match. Handshake failed.");
    }
}
