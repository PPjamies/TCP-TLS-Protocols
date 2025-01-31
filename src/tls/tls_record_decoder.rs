use crate::tls::tls_record::{ApplicationDataRecord, ChangeCipherSpecRecord, HandshakeFinishedRecord, HandshakeHeader, HelloRecord, KeyExchangeRecord, RecordHeader};

use nom::multi::count;
use nom::{bytes::complete::take, IResult};

fn decode_record_type(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, record_type) = take(1usize)(input)?;
    Ok((input, record_type[0]))
}

fn decode_handshake_type(input: &[u8]) -> IResult<&[u8], u8> {
    decode_record_header(input)?;
    let (input, handshake_type) = take(1usize)(input)?;
    Ok((input, handshake_type[0]))
}

fn decode_record_header(input: &[u8]) -> IResult<&[u8], RecordHeader> {
    (take(1usize), take(2usize), take(2usize))
        .map(
            |(record_type, protocol_version, handshake_message_length)| RecordHeader {
                record_type: record_type[0],
                protocol_version: [protocol_version[0], protocol_version[1]],
                handshake_message_length: [
                    handshake_message_length[0],
                    handshake_message_length[1],
                ],
            },
        )
        .decode(input)
}

fn decode_handshake_header(input: &[u8]) -> IResult<&[u8], HandshakeHeader> {
    (take(1usize), take(3usize))
        .map(|(handshake_type, data_message_length)| HandshakeHeader {
            handshake_type: handshake_type[0],
            data_message_length: [
                data_message_length[0],
                data_message_length[1],
                data_message_length[2],
            ],
        })
        .decode(input)
}

fn decode_hello_record(input: &[u8]) -> IResult<&[u8], HelloRecord> {
    let (input, record_header) = decode_record_header(input)?;
    let (input, handshake_header) = decode_handshake_header(input)?;
    let (input, version) = take(2usize)(input)?;
    let (input, random) = take(32usize)(input)?;
    let (input, session_id) = take(32usize)(input)?;
    let (input, cipher_suites_length) = take(2usize)(input)?;

    let length = u16::from_be_bytes([cipher_suites_length[0], cipher_suites_length[1]]) as usize;
    let (input, cipher_suites) = count(take(2usize), length).decode(input)?;
    let cipher_suites = cipher_suites
        .into_iter()
        .map(|bytes| [bytes[0], bytes[1]])
        .collect();

    Ok((
        input,
        HelloRecord {
            record_header,
            handshake_header,
            version: [version[0], version[1]],
            random: random.try_into().unwrap(),
            session_id: session_id.try_into().unwrap(),
            cipher_suites_length: [cipher_suites_length[0], cipher_suites_length[1]],
            cipher_suites,
        },
    ))
}

fn decode_key_exchange_record(input: &[u8]) -> IResult<&[u8], KeyExchangeRecord> {
    let (input, record_header) = decode_record_header(input)?;
    let (input, handshake_header) = decode_handshake_header(input)?;
    let (input, premaster_secret) = input.iter().collect();

    Ok((
        input,
        KeyExchangeRecord {
            record_header,
            handshake_header,
            premaster_secret,
        },
    ))
}

fn decode_change_cipher_spec_record(input: &[u8]) -> IResult<&[u8], ChangeCipherSpecRecord> {
    let (input, record_type) = take(1usize)(input)?;
    let (input, protocol_version) = take(2usize)(input)?;
    let (input, change_cipher_specs_length) = take(2usize)(input)?;
    let (input, change_cipher_specs) = take(1usize)(input)?;

    Ok((
        input,
        ChangeCipherSpecRecord {
            record_type: record_type[0],
            protocol_version: [protocol_version[0], protocol_version[1]],
            change_cipher_specs_length: [
                change_cipher_specs_length[0],
                change_cipher_specs_length[1],
            ],
            change_cipher_specs: change_cipher_specs[0],
        },
    ))
}

fn decode_application_data_record(input: &[u8]) -> IResult<&[u8], ApplicationDataRecord> {
    let (input, record_header) = decode_record_header(input)?;
    let (input, encryption_iv) = take(16usize)(input)?;
    let (input, encrypted_data) = input.iter().collect();

    Ok((
        input,
        ApplicationDataRecord {
            record_header,
            encryption_iv: encryption_iv.try_into().unwrap(),
            encrypted_data,
        },
    ))
}

fn decode_handshake_finished_record(input: &[u8]) -> IResult<&[u8], HandshakeFinishedRecord> {
    let (input, handshake_header) = decode_handshake_header(input)?;
    let (input, verify_data) = input.iter().collect();

    Ok((input, HandshakeFinishedRecord { handshake_header, verify_data }))
}

//todo:
pub fn get_record_type(input: &[u8]) -> IResult<&[u8], u8> {
    decode_record_type(input)
}

pub fn get_handshake_type(input: &[u8]) -> IResult<&[u8], u8> {
    decode_handshake_type(input)
}

//TODO:
pub fn get_client_hello_record(input: &[u8]) -> HelloRecord {
    let record = decode_hello_record(input)?;

    // validate record
}

pub fn get_client_key_exchange_record(input: &[u8]) -> KeyExchangeRecord {
    let record = decode_key_exchange_record(input)?;
}

pub fn get_client_change_cipher_spec_record(input: &[u8]) -> ChangeCipherSpecRecord {
    let record = decode_change_cipher_spec_record(input)?;
}

pub fn get_client_handshake_finished_record(input: &[u8]) -> HandshakeFinishedRecord {
    let record = decode_handshake_finished_record(input)?;
}

pub fn get_client_alert_record(input: &[u8]) -> ApplicationDataRecord {
    let record = decode_application_data_record(input)?;
}

pub fn get_client_application_data_record(input: &[u8]) -> ApplicationDataRecord {
    let record = decode_application_data_record(input)?;
}


// fn is_valid_client_hello_record(hello_record: HelloRecord) -> bool {
//     if record_type != crate::tls::tls_handler::TLS_RECORD_HANDSHAKE {
//         return Err(TlsHandlerError::InvalidRecord(record_type));
//     }
//
//     if protocol_version != crate::tls::tls_handler::TLS_PROTOCOL_VERSION {
//         return Err(TlsHandlerError::ProtocolNotSupported(crate::tls::tls_handler::TLS_PROTOCOL_VERSION));
//     }
//
//     if handshake_type != crate::tls::tls_handler::TLS_HANDSHAKE_CLIENT_HELLO {
//         return Err(TlsHandlerError::InvalidHandshake(handshake_type));
//     }
//
//     if cipher_suite != crate::tls::tls_handler::TLS_RSA_AES_128_CBC_SHA_256 {
//         return Err(TlsHandlerError::CipherNotSupported(cipher_suite));
//     }
//
//     true
// }
