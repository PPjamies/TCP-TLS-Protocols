mod tls;

use crate::tls::{handle, SessionContext};
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
        let (mut client_socket, _) = socket.accept()?;
        let mut session_context: SessionContext = SessionContext::new();

        spawn(move || {
            let mut buf = [0u8; 1024];
            let size = client_socket.read(&mut buf)?;
            let data_bytes: [u8] = buf[..size];

            handle(&mut session_context, &data_bytes)?;

            Ok(())
        });
    }
}
