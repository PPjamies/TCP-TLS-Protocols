use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use ring::rand::{SecureRandom, SystemRandom};
use std::fs::File;
use std::io::{Read, Result};
use std::time::SystemTime;

fn main() {}

fn generate_unix_timestamp_4_bytes() -> [u8; 4] {
    let now: u32 = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as u32;

    now.to_be_bytes()
}

fn generate_random_bytes(number_of_bytes: usize) -> Vec<u8> {
    let ring = SystemRandom::new();
    let mut random_bytes: Vec<u8> = vec![0u8; number_of_bytes];
    ring.fill(&mut random_bytes)
        .expect("Failed to generate random bytes");

    random_bytes
}

fn generate_server_random() -> [u8; 32] {
    let unix_timestamp_4_bytes: [u8; 4] = generate_unix_timestamp_4_bytes();
    let random_bytes = generate_random_bytes(28);

    let mut server_random = [0u8; 32];
    server_random[..4].copy_from_slice(&unix_timestamp_4_bytes);
    server_random[4..].copy_from_slice(&random_bytes);

    server_random
}

fn load_private_key() -> Result<PKey<Private>> {
    let mut file = File::open("server_private.pem")?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let rsa = Rsa::private_key_from_pem(&data)?;
    Ok(PKey::from_rsa(rsa)?)
}

fn load_certificate() -> Result<X509> {
    let mut file = File::open("server_cert.pem")?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(X509::from_pem(&data)?)
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

struct SessionKeys {
    encryption_key: Vec<u8>,
    mac_key: Vec<u8>,
    iv: Vec<u8>,
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
