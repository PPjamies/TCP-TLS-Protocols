use crate::tls::tls_record::{ServerFinishedRecord, ServerHelloRecord};

pub struct SessionContext {
    // used to keep track of the handshake process
    client_hello: String,
    server_hello: Option<ServerHelloRecord>,
    certificates: Option<Vec<Vec<u8>>>,
    client_key_exchange: String,
    server_finished: Option<ServerFinishedRecord>,
}

pub struct SessionState {
    // persist state once handshake is complete and session is established
    session_id: Vec<u8>,
    cipher_suite: String,
    master_secret: Vec<u8>,
    session_keys: String,
    is_resumable: bool,
}

pub struct SessionKeys {
    encryption_key: Vec<u8>,
    mac_key: Vec<u8>,
    iv: Vec<u8>,
}
