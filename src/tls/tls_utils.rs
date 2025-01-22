use ring::rand::{SecureRandom, SystemRandom};
use std::fs::File;
use std::io::{BufReader, Read, Result};
use std::time::SystemTime;

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

pub fn generate_random_32_bytes() -> [u8; 32] {
    let random = generate_random_bytes(32);

    let mut random_32_bytes = [0u8; 32];
    random_32_bytes.copy_from_slice(&random);

    random_32_bytes
}

pub fn generate_server_random() -> [u8; 32] {
    let unix_timestamp_4_bytes: [u8; 4] = generate_unix_timestamp_4_bytes();
    let random_bytes = generate_random_bytes(28);

    let mut server_random = [0u8; 32];
    server_random[..4].copy_from_slice(&unix_timestamp_4_bytes);
    server_random[4..].copy_from_slice(&random_bytes);

    server_random
}

pub fn usize_to_3_bytes(from: usize) -> [u8; 3] {
    let mut to = [0u8; 3];
    to[0] = ((from >> 16) & 0xFF) as u8;
    to[1] = ((from >> 8) & 0xFF) as u8;
    to[2] = (from & 0xFF) as u8;
    to
}

pub fn read_file_to_bytes(path: &String) -> Result<Vec<u8>> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    Ok(data)
}
