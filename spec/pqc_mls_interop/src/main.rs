use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use openmls::{
    framing::{MlsMessageBodyIn, MlsMessageIn},
    prelude::{tls_codec::*, *},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;
use serde_json::{json, Value};

const PLAINTEXT_FROM_TYPESCRIPT: &[u8] = b"TypeScript to OpenMLS hybrid MLS interop";
const PLAINTEXT_FROM_OPENMLS: &[u8] = b"OpenMLS to TypeScript hybrid MLS interop";

fn read_message(reader: &mut BufReader<TcpStream>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read protocol message");
    assert!(!line.is_empty(), "interop client disconnected early");
    serde_json::from_str(&line).expect("protocol message must be JSON")
}

fn write_message(reader: &mut BufReader<TcpStream>, value: Value) {
    let stream = reader.get_mut();
    serde_json::to_writer(&mut *stream, &value).expect("write protocol JSON");
    stream.write_all(b"\n").expect("terminate protocol message");
    stream.flush().expect("flush protocol message");
}

fn run_session(mut stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let start = read_message(&mut reader);
    assert_eq!(start["phase"], "start");

    let provider = OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44;
    let encoded_key_package = BASE64
        .decode(start["key_package"].as_str().expect("base64 KeyPackage"))
        .expect("decode TypeScript KeyPackage");
    let mls_message = MlsMessageIn::tls_deserialize_exact(encoded_key_package)
        .expect("deserialize TypeScript MLS KeyPackage message");
    let key_package_in = match mls_message.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        other => panic!("expected KeyPackage message, got {other:?}"),
    };
    let key_package = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .expect("validate TypeScript KeyPackage signature and capabilities");
    assert_eq!(key_package.ciphersuite(), ciphersuite);

    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("generate ML-DSA-44 OpenMLS signing key");
    signature_keys.store(provider.storage()).expect("store signer");
    let credential = BasicCredential::new(b"openmls-peer".to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.public().into(),
    };
    let mut group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build(&provider, &signature_keys, credential_with_key)
        .expect("create OpenMLS group");

    let (commit, welcome, _group_info) = group
        .add_members(&provider, &signature_keys, std::slice::from_ref(&key_package))
        .expect("add TypeScript client to OpenMLS group");
    let welcome_bytes = welcome
        .tls_serialize_detached()
        .expect("serialize OpenMLS Welcome");
    commit
        .tls_serialize_detached()
        .expect("serialize OpenMLS commit");
    group
        .merge_pending_commit(&provider)
        .expect("merge OpenMLS add-member commit");
    write_message(
        &mut reader,
        json!({ "phase": "welcome", "welcome": BASE64.encode(welcome_bytes) }),
    );

    let app = read_message(&mut reader);
    assert_eq!(app["phase"], "application");
    let app_bytes = BASE64
        .decode(app["message"].as_str().expect("base64 application message"))
        .expect("decode TypeScript application message");
    let incoming = MlsMessageIn::tls_deserialize_exact(app_bytes)
        .expect("deserialize TypeScript application message");
    let protocol_message = incoming
        .try_into_protocol_message()
        .expect("convert TypeScript message to MLS protocol message");
    let processed = group
        .process_message(&provider, protocol_message)
        .expect("authenticate and decrypt TypeScript application message");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            assert_eq!(message.into_bytes(), PLAINTEXT_FROM_TYPESCRIPT);
        }
        other => panic!("expected application message, got {other:?}"),
    }
    write_message(&mut reader, json!({ "phase": "received", "ok": true }));

    let outgoing = group
        .create_message(&provider, &signature_keys, PLAINTEXT_FROM_OPENMLS)
        .expect("encrypt OpenMLS application message");
    let outgoing_bytes = outgoing
        .tls_serialize_detached()
        .expect("serialize OpenMLS application message");
    write_message(
        &mut reader,
        json!({ "phase": "application", "message": BASE64.encode(outgoing_bytes) }),
    );
    let done = read_message(&mut reader);
    assert_eq!(done["phase"], "done");
    stream.flush().expect("flush session");
}

fn main() {
    let address = std::env::var("PQC_OPENMLS_BIND").unwrap_or_else(|_| "0.0.0.0:45554".into());
    let listener = TcpListener::bind(&address).expect("bind local OpenMLS interop listener");
    eprintln!("OpenMLS interop listener ready at {address}");
    let (stream, _) = listener.accept().expect("accept interop client");
    run_session(stream);
}
