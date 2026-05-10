#![allow(dead_code)]
use hmac::{Hmac, Mac};
use log::{debug, error, info, warn};
use rand::rngs::OsRng;
use std::collections::VecDeque;
use std::io::{self, Read as SocketRead, Write as SocketWrite};
use std::net::TcpStream;
use std::time::Duration;
use tls13tutorial::alert::Alert;
use tls13tutorial::display::to_hex;
use tls13tutorial::extensions::{
    ByteSerializable, Extension, ExtensionData, ExtensionOrigin, ExtensionType,
    KeyShareClientHello, KeyShareEntry, NameType, NamedGroup, NamedGroupList, ServerName,
    ServerNameList, SignatureScheme, SupportedSignatureAlgorithms, SupportedVersions, VersionKind,
};
use tls13tutorial::handshake::{
    cipher_suites, ClientHello, Handshake, HandshakeMessage, HandshakeType, Random,
    TLS_VERSION_1_3, TLS_VERSION_COMPATIBILITY,
};
use tls13tutorial::tls_record::{ContentType, TLSRecord};

// Cryptographic libraries
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use tls13tutorial::parser::ByteParser;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

const DEBUGGING_EPHEMERAL_SECRET: [u8; 32] = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// Key calculation and resulting keys, includes initial random values for `ClientHello`
/// Check section about [KeySchedule](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
struct HandshakeKeys {
    random_seed: Random,
    session_id: Random,
    // WARNING: we should use single-use `EphemeralSecret` for security in real systems
    dh_client_ephemeral_secret: StaticSecret,
    dh_client_public: PublicKey,
    dh_server_public: PublicKey,
    dh_shared_secret: Option<SharedSecret>, // Instanced later
    client_hs_key: Vec<u8>,
    client_hs_iv: Vec<u8>,
    client_hs_finished_key: Vec<u8>,
    client_seq_num: u64,
    server_hs_key: Vec<u8>,
    server_hs_iv: Vec<u8>,
    server_hs_finished_key: Vec<u8>,
    server_seq_num: u64,
}
impl HandshakeKeys {
    #[must_use]
    fn new() -> Self {
        // Generate 32 bytes of random data as key length is 32 bytes in SHA-256
        // let seed_random = rand::random::<[u8; 32]>();
        // FIXME use random data instead of hardcoded seed
        // Hardcoded value has been used for debugging purposes
        let random_seed = DEBUGGING_EPHEMERAL_SECRET;
        // let random_session_id = rand::random::<[u8; 32]>();
        let session_id = random_seed;
        // Generate a new Elliptic Curve Diffie-Hellman public-private key pair (X25519)
        let (dh_client_ephemeral_secret, dh_client_public);
        #[cfg(not(debug_assertions))]
        {
            dh_client_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
            dh_client_public = PublicKey::from(&dh_client_ephemeral_secret);
        }
        #[cfg(debug_assertions)]
        {
            dh_client_ephemeral_secret = StaticSecret::from(DEBUGGING_EPHEMERAL_SECRET);
            dh_client_public = PublicKey::from(&dh_client_ephemeral_secret);
        }

        Self {
            random_seed,
            session_id,
            dh_client_ephemeral_secret,
            dh_client_public,
            dh_server_public: PublicKey::from([0u8; 32]),
            dh_shared_secret: None,
            client_hs_key: vec![0u8; 32],
            client_hs_iv: vec![0u8; 12],
            client_hs_finished_key: vec![0u8; 32],
            client_seq_num: 0,
            server_hs_key: vec![0u8; 32],
            server_hs_iv: vec![0u8; 12],
            server_hs_finished_key: vec![0u8; 32],
            server_seq_num: 0,
        }
    }
    /// Update the keys based on handshake messages
    /// Specific for SHA256 hash function
    /// See especially Section 7. in the standard
    /// This function works correctly for the initial key calculation, to finish the handshake
    /// you need to also other keys later on following the same idea.
    fn key_schedule(&mut self, transcript_hash: &[u8]) {
        // Calculate the shared secret
        self.dh_shared_secret = Some(
            self.dh_client_ephemeral_secret
                .diffie_hellman(&self.dh_server_public),
        );
        // Early secret - we don't implement PSK, so need to use empty arrays
        let (early_secret, _hk) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &[0u8; 32]);
        let sha256_empty = Sha256::digest([]);
        let derived_secret = Self::derive_secret(&early_secret, b"derived", &sha256_empty, 32);
        // Handshake secrets with Key & IV pairs
        let (handshake_secret, _hk) = Hkdf::<Sha256>::extract(
            Some(&derived_secret),
            self.dh_shared_secret.as_ref().unwrap().as_bytes(),
        );
        let client_hs_traffic_secret =
            Self::derive_secret(&handshake_secret, b"c hs traffic", transcript_hash, 32);
        self.client_hs_key = Self::derive_secret(&client_hs_traffic_secret, b"key", &[], 32);
        self.client_hs_iv = Self::derive_secret(&client_hs_traffic_secret, b"iv", &[], 12);
        self.client_hs_finished_key =
            Self::derive_secret(&client_hs_traffic_secret, b"finished", &[], 32);
        let server_hs_traffic_secret =
            Self::derive_secret(&handshake_secret, b"s hs traffic", transcript_hash, 32);
        self.server_hs_key = Self::derive_secret(&server_hs_traffic_secret, b"key", &[], 32);
        self.server_hs_iv = Self::derive_secret(&server_hs_traffic_secret, b"iv", &[], 12);
        self.server_hs_finished_key =
            Self::derive_secret(&server_hs_traffic_secret, b"finished", &[], 32);
        // Print all the keys as hex strings
        debug!(
            "Shared secret: {}",
            to_hex(self.dh_shared_secret.as_ref().unwrap().as_bytes())
        );
        debug!("Early secret: {}", to_hex(&early_secret));
        debug!("Derived secret: {}", to_hex(&derived_secret));
        debug!("Handshake secret: {}", to_hex(&handshake_secret));
        debug!(
            "Client handshake traffic secret: {}",
            to_hex(&client_hs_traffic_secret)
        );
        debug!("Client handshake key: {}", to_hex(&self.client_hs_key));
        debug!("Client handshake IV: {}", to_hex(&self.client_hs_iv));
        debug!(
            "Client handshake finished key: {}",
            to_hex(&self.client_hs_finished_key)
        );
        debug!(
            "Server handshake traffic secret: {}",
            to_hex(&server_hs_traffic_secret)
        );
        debug!("Server handshake key: {}", to_hex(&self.server_hs_key));
        debug!("Server handshake IV: {}", to_hex(&self.server_hs_iv));
        debug!(
            "Server handshake finished key: {}",
            to_hex(&self.server_hs_finished_key)
        );
    }
    /// Expand the secret with the label and transcript hash (hash bytes of the combination of messages)
    /// Label format is described in the RFC 8446 section 7.1
    /// FIXME will panic on invalid lengths. Maybe someone notices this with a bit of fuzzing..
    #[must_use]
    fn derive_secret(
        secret: &[u8],
        label: &[u8],
        transcript_hash: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
        // All the labels are ASCII strings, prepend with "tls13 "
        let mut combined_label = b"tls13 ".to_vec();
        combined_label.extend_from_slice(label);
        hkdf_label.extend_from_slice(&u8::try_from(combined_label.len()).unwrap().to_be_bytes());
        hkdf_label.extend_from_slice(&combined_label);
        hkdf_label.extend_from_slice(&u8::try_from(transcript_hash.len()).unwrap().to_be_bytes());
        hkdf_label.extend_from_slice(transcript_hash);
        let hk = Hkdf::<Sha256>::from_prk(secret).expect("Failed to create HKDF from PRK");
        let mut okm = vec![0u8; length];
        hk.expand(&hkdf_label, &mut okm)
            .expect("Failed to expand the secret");
        okm
    }
}

/// Process the data from TCP stream in the chunks of 4096 bytes and
/// read the response data into a buffer in a form of Queue for easier parsing.
fn process_tcp_stream(mut stream: &mut TcpStream) -> io::Result<VecDeque<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(2000)))?;
    let mut reader = io::BufReader::new(&mut stream);
    let mut buffer: VecDeque<u8> = VecDeque::new();
    let mut chunk = [0; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                debug!("Received {n} bytes of data.");
                buffer.extend(&chunk[..n]);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                warn!("TCP read blocking...force return.");
                return Ok(buffer);
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                warn!("TCP read timed out...force return.");
                return Ok(buffer);
            }
            Err(e) => {
                error!("Error when reading from the TCP stream: {}", e);
                return Err(e);
            }
        }
    }
    Ok(buffer)
}

/// Main event loop for the TLS 1.3 client implementation
#[allow(clippy::too_many_lines)]
fn main() {
    // Get address as command-line argument, e.g. cargo run cloudflare.com:443
    let args = std::env::args().collect::<Vec<String>>();
    let address = if args.len() > 1 {
        args[1].as_str()
    } else {
        eprintln!("Usage: {} <address:port>", args[0]);
        std::process::exit(1);
    };
    // Creating logger.
    // You can change the level with RUST_LOG environment variable, e.g. RUST_LOG=debug
    env_logger::builder().format_timestamp(None).init();
    // Note: unsafe, not  everything-covering validation for the address
    let Some((hostname, _port)) = address.split_once(':') else {
        error!("Invalid address:port format");
        std::process::exit(1);
    };
    // Create initial random values and keys for the handshake
    let mut handshake_keys = HandshakeKeys::new();

    match TcpStream::connect(address) {
        Ok(mut stream) => {
            info!("Successfully connected to the server '{address}'.");

            // Generate the ClientHello message with the help of the data structures
            // Selects the cipher suite and properties
            let client_hello = ClientHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: handshake_keys.random_seed,
                legacy_session_id: handshake_keys.session_id.into(),
                cipher_suites: vec![cipher_suites::TLS_CHACHA20_POLY1305_SHA256],
                legacy_compression_methods: vec![0],
                extensions: vec![
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::SupportedVersions,
                        extension_data: ExtensionData::SupportedVersions(SupportedVersions {
                            version: VersionKind::Suggested(vec![TLS_VERSION_1_3]),
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::ServerName,
                        extension_data: ExtensionData::ServerName(ServerNameList {
                            server_name_list: vec![ServerName {
                                name_type: NameType::HostName,
                                host_name: hostname.to_string().as_bytes().to_vec(),
                            }],
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::SupportedGroups,
                        extension_data: ExtensionData::SupportedGroups(NamedGroupList {
                            named_group_list: vec![NamedGroup::X25519],
                        }),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::SignatureAlgorithms,
                        extension_data: ExtensionData::SignatureAlgorithms(
                            SupportedSignatureAlgorithms {
                                supported_signature_algorithms: vec![
                                    SignatureScheme::Ed25519,
                                    SignatureScheme::RsaPssRsaeSha256,
                                    SignatureScheme::RsaPssRsaeSha384,
                                    SignatureScheme::RsaPssRsaeSha512,
                                    SignatureScheme::EcdsaSecp256r1Sha256,
                                    SignatureScheme::EcdsaSecp384r1Sha384,
                                ],
                            },
                        ),
                    },
                    Extension {
                        origin: ExtensionOrigin::Client,
                        extension_type: ExtensionType::KeyShare,
                        extension_data: ExtensionData::KeyShareClientHello(KeyShareClientHello {
                            client_shares: vec![KeyShareEntry {
                                group: NamedGroup::X25519,
                                key_exchange: handshake_keys.dh_client_public.to_bytes().to_vec(),
                            }],
                        }),
                    },
                ],
            };
            info!("Sending ClientHello as follows...\n");
            println!("{client_hello}");
            // Alternative styles
            // dbg!(&client_hello);
            // println!("{client_hello:#?}");
            let handshake = Handshake {
                msg_type: HandshakeType::ClientHello,
                length: u32::try_from(
                    client_hello
                        .as_bytes()
                        .expect("Failed to serialize ClientHello message into bytes")
                        .len(),
                )
                .expect("ClientHello message too long"),
                message: HandshakeMessage::ClientHello(client_hello.clone()),
            };
            let client_handshake_bytes = handshake
                .as_bytes()
                .expect("Failed to serialize Handshake message into bytes");

            let request_record = TLSRecord {
                record_type: ContentType::Handshake,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: u16::try_from(client_handshake_bytes.len())
                    .expect("Handshake message too long"),
                fragment: client_handshake_bytes.clone(),
            };
            // Send the constructed request to the server
            match stream.write_all(
                &request_record
                    .as_bytes()
                    .expect("Failed to serialize TLS Record into bytes"),
            ) {
                Ok(()) => {
                    info!("The handshake request has been sent...");
                }
                Err(e) => {
                    error!("Failed to send the request: {e}");
                }
            }
            // Read all the response data into a `VecDeque` buffer
            let buffer = process_tcp_stream(&mut stream).unwrap_or_else(|e| {
                error!("Failed to read the TCP response: {e}");
                std::process::exit(1)
            });
            let response_records = tls13tutorial::get_records(buffer).unwrap_or_else(|e| {
                error!("Failed to process the records: {e}");
                std::process::exit(1)
            });
            let mut raw_server_hello_bytes: Vec<u8> = Vec::new();
            for record in response_records {
                match record.record_type {
                    ContentType::Alert => match Alert::from_bytes(&mut record.fragment.into()) {
                        Ok(alert) => {
                            warn!("Alert received: {alert}");
                        }
                        Err(e) => {
                            error!("Failed to parse the alert: {e}");
                        }
                    },
                    ContentType::Handshake => {
                        debug!("Raw handshake data: {:?}", record.fragment);
                        raw_server_hello_bytes = record.fragment.clone();
                        let handshake = *Handshake::from_bytes(&mut record.fragment.into())
                            .expect("Failed to parse Handshake message");
                        debug!("Handshake message: {:?}", &handshake);

                        if let HandshakeMessage::ServerHello(server_hello) = handshake.message {
                            info!("ServerHello message: {:?}", server_hello);

                            let server_pub_key_bytes = server_hello
                                .extensions
                                .iter()
                                .find_map(|ext| {
                                    if let ExtensionData::KeyShareServerHello(ref ks) =
                                        ext.extension_data
                                    {
                                        Some(ks.server_share.key_exchange.clone())
                                    } else {
                                        None
                                    }
                                })
                                .expect("No KeyShare extension found in ServerHello");

                            let server_pub_array: [u8; 32] = server_pub_key_bytes
                                .try_into()
                                .expect("Server public key must be 32 bytes long");
                            handshake_keys.dh_server_public = PublicKey::from(server_pub_array);

                            let mut transcript = Sha256::new();
                            transcript.update(&client_handshake_bytes);
                            transcript.update(&raw_server_hello_bytes);
                            let transcript_hash = transcript.finalize();

                            handshake_keys.key_schedule(&transcript_hash);
                            info!("Handshake keys derived successfully");
                        }
                    }
                    ContentType::ApplicationData => {
                        info!("Application data received, size of : {:?}", record.length);

                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes.copy_from_slice(&handshake_keys.server_hs_iv);
                        let seq_bytes = handshake_keys.server_seq_num.to_be_bytes();
                        for i in 0..8 {
                            nonce_bytes[4 + i] ^= seq_bytes[i];
                        }
                        handshake_keys.server_seq_num += 1;

                        let aad = {
                            let len = record.length.to_be_bytes();
                            vec![0x17u8, 0x03, 0x03, len[0], len[1]]
                        };

                        let key = Key::from_slice(&handshake_keys.server_hs_key);
                        let cipher = ChaCha20Poly1305::new(key);
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        match cipher.decrypt(
                            nonce,
                            Payload {
                                msg: &record.fragment,
                                aad: &aad,
                            },
                        ) {
                            Ok(inner_bytes) => {
                                let content_type_idx = inner_bytes
                                    .iter()
                                    .rposition(|&b| b != 0)
                                    .expect("Decrypted TLSInnerPlaintext has no content type");
                                let content_type = inner_bytes[content_type_idx];
                                let content = &inner_bytes[..content_type_idx];

                                info!("Decrypted record, inner type: {:?}", content_type);

                                match content_type {
                                    22 => {
                                        let mut content_parser = ByteParser::from(content);
                                        while !content_parser.is_empty() {
                                            let remaining_before = content_parser.len();
                                            match tls13tutorial::handshake::Handshake::from_bytes(
                                                &mut content_parser,
                                            ) {
                                                Ok(hs) => {
                                                    info!("Inner handshake: {:?}, consumed {} bytes, {} remaining",
                    hs.msg_type,
                    remaining_before - content_parser.len(),
                    content_parser.len()
                );
                                                }
                                                Err(e) => {
                                                    error!("Could not parse inner handshake: {e}, {} bytes remaining", content_parser.len());
                                                    break;
                                                }
                                            }
                                        }
                                        let mut finished_transcript = Sha256::new();
                                        finished_transcript.update(&client_handshake_bytes);
                                        finished_transcript.update(&raw_server_hello_bytes);
                                        finished_transcript.update(content);
                                        let finished_hash = finished_transcript.finalize();

                                        let finished_key = &handshake_keys.client_hs_finished_key;
                                        let mut mac =
                                            <Hmac<Sha256> as Mac>::new_from_slice(finished_key)
                                                .unwrap();
                                        mac.update(&finished_hash);
                                        let verify_data = mac.finalize().into_bytes().to_vec();

                                        let finished_msg =
                                            tls13tutorial::handshake::Finished { verify_data };
                                        let finished_hs = Handshake {
                                            msg_type: HandshakeType::Finished,
                                            length: finished_msg.verify_data.len() as u32,
                                            message: HandshakeMessage::Finished(finished_msg),
                                        };
                                        let finished_bytes = finished_hs.as_bytes().unwrap();

                                        let mut plaintext = finished_bytes.clone();
                                        plaintext.push(0x16);

                                        let mut nonce_bytes = [0u8; 12];
                                        nonce_bytes.copy_from_slice(&handshake_keys.client_hs_iv);
                                        let seq_bytes = handshake_keys.client_seq_num.to_be_bytes();
                                        for i in 0..8 {
                                            nonce_bytes[4 + i] ^= seq_bytes[i];
                                        }
                                        handshake_keys.client_seq_num += 1;

                                        let ct_len = (plaintext.len() + 16) as u16;
                                        let aad = vec![
                                            0x17u8,
                                            0x03,
                                            0x03,
                                            (ct_len >> 8) as u8,
                                            ct_len as u8,
                                        ];
                                        let key = Key::from_slice(&handshake_keys.client_hs_key);
                                        let cipher = ChaCha20Poly1305::new(key);
                                        let nonce = Nonce::from_slice(&nonce_bytes);
                                        let ciphertext = cipher
                                            .encrypt(
                                                nonce,
                                                Payload {
                                                    msg: &plaintext,
                                                    aad: &aad,
                                                },
                                            )
                                            .unwrap();

                                        let finished_record = TLSRecord {
                                            record_type: ContentType::ApplicationData,
                                            legacy_record_version: TLS_VERSION_COMPATIBILITY,
                                            length: ciphertext.len() as u16,
                                            fragment: ciphertext,
                                        };
                                        stream
                                            .write_all(&finished_record.as_bytes().unwrap())
                                            .unwrap();
                                        info!("ClientFinished sent!");
                                        // Derive application traffic keys
                                        // Read the server's response to ClientFinished
                                        let post_hs_buffer =
                                            process_tcp_stream(&mut stream).unwrap_or_default();
                                        info!(
                                            "Post-handshake data received: {} bytes",
                                            post_hs_buffer.len()
                                        );

                                        // Derive application traffic keys
                                        // These follow from the handshake secret via another round of the key schedule
                                        let sha256_empty = Sha256::digest([]);
                                        let (early_secret, _) = hkdf::Hkdf::<Sha256>::extract(
                                            Some(&[0u8; 32]),
                                            &[0u8; 32],
                                        );
                                        let derived_secret_hs = HandshakeKeys::derive_secret(
                                            &{
                                                // Re-derive handshake secret — need it for master secret derivation
                                                // Easier: store it in HandshakeKeys. For now recompute from stored shared secret
                                                let sha256_empty2 = Sha256::digest([]);
                                                let (es, _) = hkdf::Hkdf::<Sha256>::extract(
                                                    Some(&[0u8; 32]),
                                                    &[0u8; 32],
                                                );
                                                let ds = HandshakeKeys::derive_secret(
                                                    &es,
                                                    b"derived",
                                                    &sha256_empty2,
                                                    32,
                                                );
                                                let (hs, _) = hkdf::Hkdf::<Sha256>::extract(
                                                    Some(&ds),
                                                    handshake_keys
                                                        .dh_shared_secret
                                                        .as_ref()
                                                        .unwrap()
                                                        .as_bytes(),
                                                );
                                                hs
                                            },
                                            b"derived",
                                            &sha256_empty,
                                            32,
                                        );
                                        let (master_secret, _) = hkdf::Hkdf::<Sha256>::extract(
                                            Some(&derived_secret_hs),
                                            &[0u8; 32],
                                        );

                                        // Full transcript hash for application keys
                                        let mut app_transcript = Sha256::new();
                                        app_transcript.update(&client_handshake_bytes);
                                        app_transcript.update(&raw_server_hello_bytes);
                                        app_transcript.update(content);
                                        let app_transcript_hash = app_transcript.finalize();

                                        let client_app_traffic_secret =
                                            HandshakeKeys::derive_secret(
                                                &master_secret,
                                                b"c ap traffic",
                                                &app_transcript_hash,
                                                32,
                                            );
                                        let server_app_traffic_secret =
                                            HandshakeKeys::derive_secret(
                                                &master_secret,
                                                b"s ap traffic",
                                                &app_transcript_hash,
                                                32,
                                            );
                                        let client_app_key = HandshakeKeys::derive_secret(
                                            &client_app_traffic_secret,
                                            b"key",
                                            &[],
                                            32,
                                        );
                                        let client_app_iv = HandshakeKeys::derive_secret(
                                            &client_app_traffic_secret,
                                            b"iv",
                                            &[],
                                            12,
                                        );
                                        let server_app_key = HandshakeKeys::derive_secret(
                                            &server_app_traffic_secret,
                                            b"key",
                                            &[],
                                            32,
                                        );
                                        let server_app_iv = HandshakeKeys::derive_secret(
                                            &server_app_traffic_secret,
                                            b"iv",
                                            &[],
                                            12,
                                        );
                                        info!("Application traffic keys derived");

                                        // Send HTTP GET request encrypted with application keys
                                        let http_request = b"GET /robots.txt HTTP/1.1\r\nHost: www.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
                                        let mut app_plaintext = http_request.to_vec();
                                        app_plaintext.push(0x17); // inner content type = ApplicationData

                                        let mut app_nonce = [0u8; 12];
                                        app_nonce.copy_from_slice(&client_app_iv);
                                        // seq num is 0 for first app record, XOR with 0 is no-op

                                        let app_ct_len = (app_plaintext.len() + 16) as u16;
                                        let app_aad = vec![
                                            0x17u8,
                                            0x03,
                                            0x03,
                                            (app_ct_len >> 8) as u8,
                                            app_ct_len as u8,
                                        ];
                                        let app_key = Key::from_slice(&client_app_key);
                                        let app_cipher = ChaCha20Poly1305::new(app_key);
                                        let app_nonce_obj = Nonce::from_slice(&app_nonce);
                                        let app_ciphertext = app_cipher
                                            .encrypt(
                                                app_nonce_obj,
                                                Payload {
                                                    msg: &app_plaintext,
                                                    aad: &app_aad,
                                                },
                                            )
                                            .unwrap();

                                        let app_record = TLSRecord {
                                            record_type: ContentType::ApplicationData,
                                            legacy_record_version: TLS_VERSION_COMPATIBILITY,
                                            length: app_ciphertext.len() as u16,
                                            fragment: app_ciphertext,
                                        };
                                        stream.write_all(&app_record.as_bytes().unwrap()).unwrap();
                                        info!("HTTP GET request sent!");

                                        // Read and decrypt server's response
                                        let response_buffer =
                                            process_tcp_stream(&mut stream).unwrap_or_default();
                                        info!("Response received: {} bytes", response_buffer.len());
                                        let response_records =
                                            tls13tutorial::get_records(response_buffer)
                                                .unwrap_or_default();
                                        let mut server_app_seq: u64 = 0;
                                        for resp_record in response_records {
                                            if let ContentType::ApplicationData =
                                                resp_record.record_type
                                            {
                                                let mut resp_nonce = [0u8; 12];
                                                resp_nonce.copy_from_slice(&server_app_iv);
                                                let seq_b = server_app_seq.to_be_bytes();
                                                for i in 0..8 {
                                                    resp_nonce[4 + i] ^= seq_b[i];
                                                }
                                                server_app_seq += 1;
                                                let resp_len = resp_record.length.to_be_bytes();
                                                let resp_aad = vec![
                                                    0x17u8,
                                                    0x03,
                                                    0x03,
                                                    resp_len[0],
                                                    resp_len[1],
                                                ];
                                                let resp_key = Key::from_slice(&server_app_key);
                                                let resp_cipher = ChaCha20Poly1305::new(resp_key);
                                                let resp_nonce_obj = Nonce::from_slice(&resp_nonce);
                                                match resp_cipher.decrypt(
                                                    resp_nonce_obj,
                                                    Payload {
                                                        msg: &resp_record.fragment,
                                                        aad: &resp_aad,
                                                    },
                                                ) {
                                                    Ok(plaintext) => {
                                                        // Strip trailing content type byte
                                                        if let Some(pos) =
                                                            plaintext.iter().rposition(|&b| b != 0)
                                                        {
                                                            let content = &plaintext[..pos];
                                                            info!(
                                                                "Decrypted response ({} bytes):",
                                                                content.len()
                                                            );
                                                            println!(
                                                                "{}",
                                                                String::from_utf8_lossy(content)
                                                            );
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!("Response decryption failed: {e}");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    21 => {
                                        info!("Encrypted alert received: {:?}", content);
                                    }
                                    _ => {
                                        warn!("Unknown inner content type: {}", content_type);
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Decryption failed (seq: {}): {e}",
                                    handshake_keys.server_seq_num - 1
                                );
                            }
                        }
                    }
                    ContentType::ChangeCipherSpec => {
                        debug!("ChangeCipherSpec received, ignoring (TLS 1.3 compatibility)");
                    }
                    _ => {
                        error!("Unexpected response type: {:?}", record.record_type);
                        // debug!("Remaining bytes: {:?}", parser.deque);
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to connect: {e}");
        }
    }
}
