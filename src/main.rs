mod tls;

use ring::rand::SecureRandom;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Error, Read, Result, Write};
use std::net::SocketAddr;
use std::thread::spawn;

fn main() -> Result<()> {
    let socket: Socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    let addr: SocketAddr = "127.0.0.1:8080"
        .parse()
        .map_err(|e| Error::new(std::io::ErrorKind::InvalidInput, e))?;

    socket.bind(&addr.into())?;
    socket.listen(128)?;

    loop {
        let (mut client_socket, client_addr) = socket.accept()?;

        spawn(move || {
            let mut buf = [0u8; 1024];
            let size = client_socket.read(&mut buf)?;
            let data_bytes: [u8] = buf[..size];

            message_handler(size, &data_bytes)?;

            Ok(())
        });
    }
}

pub fn message_handler(size: usize, data: &[u8]) -> Result<()> {
    const TLS_PROTOCOL_VERSION: [u8; 2] = [0x03, 0x03];
    const TLS_HANDSHAKE: u8 = 0x17;
    const TLS_CLIENT_HELLO: u8 = 0x01;
    const TLS_SERVER_HELLO: u8 = 0x02;
    const TLS_CLIENT_KEY_EXCHANGE: u8 = 0x10;
    const TLS_SERVER_CERTIFICATE: u8 = 0x0B;
    const TLS_SERVER_FINISHED: u8 = 0x14;

    // header
    let handshake_type = &data[0];

    match handshake_type {
        TLS_CLIENT_HELLO => {
            let protocol_version = data[1..3];
            if protocol_version != TLS_PROTOCOL_VERSION {} //throw error: not supported protocol

            let handshake_size = data[3..5];
            //validate length

        }
        TLS_SERVER_HELLO => {}
        TLS_CLIENT_KEY_EXCHANGE => {}
        TLS_SERVER_CERTIFICATE => {}
        TLS_SERVER_FINISHED => {}
        _ => {}
    }

    // if protocol_version != TLS_PROTOCOL_VERSION {} // throw error: does not support
    // if length_message != (size - 5) {} // throw error: invalid message length
    //
    // // body
    // let message_type = &data[5];
    // let length_body = &data[6..9];
    // let body = &[9..size];
    //
    // if length_body != body.len() {} //throw error: invalid body length



    Ok(())
}


// record_header: RecordHeader {
//     record_type: 0x16,              // HANDSHAKE
//     protocol_version: [0x03, 0x03], //TLS 1.2
//     length: [0x00, 0x03],           // BYTES OF HANDSHAKE HEADER
// },
// handshake_header: HandshakeHeader {
//     handshake_type: 0x01, // CLIENT HELLO
//     length: [0x00, 0x46], // BYTES OF CLIENT HELLO DATA
// },
// hello_record: HelloRecord {
//     version: [0x03, 0x03],
//     random: generate_server_random(),
//     session_id: generate_random_32_bytes(),
//     cipher_suite: [0x00, 0x3C], // TLS RSA with AES 128 CBC SHA
//     compression_method: [0x01, 0x00],
// },