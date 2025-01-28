use crate::tls::tls_record::{ApplicationDataRecord, ChangeCipherSpecRecord, HandshakeHeader, HelloRecord, KeyExchangeRecord, RecordHeader};

use nom::multi::count;
use nom::{bytes::complete::take, IResult, Parser};
use nom::combinator::opt;

pub fn parse_record_type(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, record_type) = take(1usize)(input)?;
    Ok((input, record_type[0]))
}

pub fn parse_handshake_type(input: &[u8]) -> IResult<&[u8], u8> {
    parse_record_header(input)?;
    let (input, handshake_type) = take(1usize)(input)?;
    Ok((input, handshake_type[0]))
}

pub fn parse_record_header(input: &[u8]) -> IResult<&[u8], RecordHeader> {
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
        .parse(input)
}

pub fn parse_handshake_header(input: &[u8]) -> IResult<&[u8], HandshakeHeader> {
    (take(1usize), take(3usize))
        .map(|(handshake_type, data_message_length)| HandshakeHeader {
            handshake_type: handshake_type[0],
            data_message_length: [
                data_message_length[0],
                data_message_length[1],
                data_message_length[2],
            ],
        })
        .parse(input)
}

pub fn parse_hello_record(input: &[u8]) -> IResult<&[u8], HelloRecord> {
    let (input, record_header) = parse_record_header(input)?;
    let (input, handshake_header) = parse_handshake_header(input)?;
    let (input, version) = take(2usize)(input)?;
    let (input, random) = take(32usize)(input)?;
    let (input, session_id) = take(32usize)(input)?;
    let (input, cipher_suites_length) = take(2usize)(input)?;

    let length = u16::from_be_bytes([cipher_suites_length[0], cipher_suites_length[1]]) as usize;
    let (input, cipher_suites) = count(take(2usize), length).parse(input)?;
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

pub fn parse_key_exchange_record(input: &[u8]) -> IResult<&[u8], KeyExchangeRecord> {
    let (input, record_header) = parse_record_header(input)?;
    let (input, handshake_header) = parse_handshake_header(input)?;
    let (input, public_key) = take(32usize)(input)?;
    let (input, signature) = opt(take(32usize)(input))?;

    Ok((
        input,
        KeyExchangeRecord {
            record_header,
            handshake_header,
            public_key: public_key.try_into().unwrap(),
            signature,
        },
    ))
}

pub fn parse_change_cipher_spec_record(input: &[u8]) -> IResult<&[u8], ChangeCipherSpecRecord> {
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

pub fn parse_application_data_record(input: &[u8]) -> IResult<&[u8], ApplicationDataRecord> {
    let (input, record_header) = parse_record_header(input)?;
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
