use crate::tls::tls_record::{
    ApplicationDataRecord, ChangeCipherSpecRecord, HandshakeFinishedRecord, HandshakeHeader,
    HelloRecord, KeyExchangeRecord, RecordHeader,
};

use crate::tls::tls_constants::{
    TLS_HANDSHAKE_CLIENT_HELLO, TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE, TLS_HANDSHAKE_FINISHED,
    TLS_HANDSHAKE_MESSAGE_LENGTH, TLS_PROTOCOL_VERSION, TLS_RECORD_ALERT,
    TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
    TLS_RSA_AES_128_CBC_SHA_256,
};
use nom::multi::count;
use nom::{bytes::complete::take, IResult};
use std::result::Result;

#[derive(Debug)]
pub enum DecoderError {
    NomError(nom::Err<nom::error::Error<Vec<u8>>>),
    RecordTypeNotFound,
    HandshakeTypeNotFound,
    InvalidClientHelloRecord,
    InvalidHelloRecord,
    InvalidClientKeyExchangeRecord,
    InvalidClientChangeCipherSpecRecord,
    InvalidClientHandshakeFinishedRecord,
    InvalidClientAlertRecord,
    InvalidClientApplicationDataRecord,
    InvalidRecordType,
    UnsupportedProtocolVersion,
    InvalidHandshakeMessageLength,
    InvalidHandshakeType,
    UnsupportedCipherSuite,
}
impl std::fmt::Display for DecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DecoderError::NomError(err) => write!(f, "Parsing error: {:?}", err),
            DecoderError::RecordTypeNotFound => write!(f, "Record type not found"),
            DecoderError::HandshakeTypeNotFound => write!(f, "Handshake type not found"),
            DecoderError::InvalidClientHelloRecord => write!(f, "Invalid Client Hello Record"),
            DecoderError::InvalidHelloRecord => write!(f, "Invalid Hello Record"),
            DecoderError::InvalidClientKeyExchangeRecord => {
                write!(f, "Invalid Client Key Exchange Record")
            }
            DecoderError::InvalidClientChangeCipherSpecRecord => {
                write!(f, "Invalid Client Change Cipher Spec Record")
            }
            DecoderError::InvalidClientHandshakeFinishedRecord => {
                write!(f, "Invalid Client Handshake Finished Record")
            }
            DecoderError::InvalidClientAlertRecord => write!(f, "Invalid Client Alert Record"),
            DecoderError::InvalidClientApplicationDataRecord => {
                write!(f, "Invalid Client Application Data Record")
            }
            DecoderError::InvalidRecordType => {
                write!(f, "Invalid Record Type")
            }
            DecoderError::UnsupportedProtocolVersion => write!(f, "Unsupported Protocol Version"),
            DecoderError::InvalidHandshakeMessageLength => {
                write!(f, "Invalid Handshake Message Length")
            }
            DecoderError::InvalidHandshakeType => {
                write!(f, "Invalid Handshake Type")
            }
            DecoderError::UnsupportedCipherSuite => write!(f, "Unsupported Cipher Suite"),
        }
    }
}
impl std::error::Error for DecoderError {}

fn validate_record_header(
    record_header: &RecordHeader,
    expected_record_type: &u8,
) -> Result<(), DecoderError> {
    if &record_header.record_type != expected_record_type {
        return Err(DecoderError::InvalidRecordType);
    }
    if &record_header.protocol_version != &TLS_PROTOCOL_VERSION {
        return Err(DecoderError::UnsupportedProtocolVersion);
    }
    if &record_header.handshake_message_length != &TLS_HANDSHAKE_MESSAGE_LENGTH {
        return Err(DecoderError::InvalidHandshakeMessageLength);
    }
    Ok(())
}

fn validate_handshake_header(
    handshake_header: &HandshakeHeader,
    expected_handshake_type: &u8,
) -> Result<(), DecoderError> {
    if &handshake_header.handshake_type != expected_handshake_type {
        return Err(DecoderError::InvalidHandshakeType);
    }
    Ok(())
}

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

    Ok((
        input,
        HandshakeFinishedRecord {
            handshake_header,
            verify_data,
        },
    ))
}

pub fn get_record_type(input: &[u8]) -> Result<u8, DecoderError> {
    decode_record_type(input)
        .map(|(_, record)| record)
        .map_err(DecoderError::RecordTypeNotFound)
}

pub fn get_handshake_type(input: &[u8]) -> Result<u8, DecoderError> {
    decode_handshake_type(input)
        .map(|(_, record)| record)
        .map_err(DecoderError::HandshakeTypeNotFound)
}

pub fn get_client_hello_record(input: &[u8]) -> Result<HelloRecord, DecoderError> {
    let record = decode_hello_record(input)
        .map(|(_, record)| record)
        .map_err(DecoderError::InvalidClientHelloRecord)?;

    validate_record_header(&record.record_header, &TLS_RECORD_HANDSHAKE)?;
    validate_handshake_header(&record.handshake_header, &TLS_HANDSHAKE_CLIENT_HELLO)?;

    let contains_supported_cipher_suite = &record
        .cipher_suites
        .iter()
        .any(|cipher_suite| cipher_suite == &TLS_RSA_AES_128_CBC_SHA_256);

    if !contains_supported_cipher_suite {
        return Err(DecoderError::UnsupportedCipherSuite);
    }
    Ok(record)
}

pub fn get_hello_record(
    input: &[u8],
    handshake_header_type: &u8,
) -> Result<HelloRecord, DecoderError> {
    let record = decode_hello_record(input)
        .map(|(_, record)| record)
        .map_err(DecoderError::InvalidHelloRecord)?;

    validate_record_header(&record.record_header, &TLS_RECORD_HANDSHAKE)?;
    validate_handshake_header(&record.handshake_header, &handshake_header_type)?;

    let contains_supported_cipher_suite = &record
        .cipher_suites
        .iter()
        .any(|cipher_suite| cipher_suite == &TLS_RSA_AES_128_CBC_SHA_256);

    if !contains_supported_cipher_suite {
        return Err(DecoderError::UnsupportedCipherSuite);
    }
    Ok(record)
}

pub fn get_client_key_exchange_record(input: &[u8]) -> Result<KeyExchangeRecord, DecoderError> {
    let record = decode_key_exchange_record(input)
        .map(|(_, record)| record)
        .map_err(DecoderError::InvalidClientKeyExchangeRecord)?;

    validate_record_header(&record.record_header, &TLS_RECORD_HANDSHAKE)?;
    validate_handshake_header(&record.handshake_header, &TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE)?;
    Ok(record)
}

pub fn get_client_change_cipher_spec_record(
    input: &[u8],
) -> Result<ChangeCipherSpecRecord, DecoderError> {
    let record = decode_change_cipher_spec_record(input)
        .map(|(_, record)| record)
        .map_err(DecoderError::InvalidClientChangeCipherSpecRecord)?;

    if &record.record_type != &TLS_RECORD_CHANGE_CIPHER_SPEC {
        return Err(DecoderError::InvalidRecordType);
    }
    if &record.protocol_version != &TLS_PROTOCOL_VERSION {
        return Err(DecoderError::UnsupportedProtocolVersion);
    }
    Ok(record)
}

pub fn get_client_handshake_finished_record(
    input: &[u8],
) -> Result<HandshakeFinishedRecord, DecoderError> {
    let record = decode_handshake_finished_record(input)
        .map(|(_, record)| record)
        .map_err(DecoderError::InvalidClientHandshakeFinishedRecord)?;

    validate_handshake_header(&record.handshake_header, &TLS_HANDSHAKE_FINISHED)?;
    Ok(record)
}

pub fn get_client_alert_record(input: &[u8]) -> Result<ApplicationDataRecord, DecoderError> {
    let record = decode_application_data_record(input)
        .map(|(_, record)| record)
        .map_err(DecoderError::InvalidClientAlertRecord)?;

    validate_record_header(&record.record_header, &TLS_RECORD_ALERT)?;
    Ok(record)
}

pub fn get_client_application_data_record(
    input: &[u8],
) -> Result<ApplicationDataRecord, DecoderError> {
    let record = decode_application_data_record(input)
        .map(|(_, record)| record)
        .map_err(DecoderError::InvalidClientApplicationDataRecord)?;

    validate_record_header(&record.record_header, &TLS_RECORD_APPLICATION_DATA)?;
    Ok(record)
}
