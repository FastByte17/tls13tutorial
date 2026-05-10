#![no_main]
use libfuzzer_sys::fuzz_target;
use tls13tutorial::extensions::ByteSerializable;
use tls13tutorial::handshake::Certificate;
use tls13tutorial::parser::ByteParser;

fuzz_target!(|data: &[u8]| {
    let mut parser = ByteParser::from(data);
    if let Ok(decoded) = Certificate::from_bytes(&mut parser) {
        let _ = decoded.as_bytes();
    }
});
