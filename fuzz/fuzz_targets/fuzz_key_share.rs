#![no_main]
use libfuzzer_sys::fuzz_target;
use tls13tutorial::extensions::{ByteSerializable, KeyShareEntry};
use tls13tutorial::parser::ByteParser;

fuzz_target!(|data: &[u8]| {
    let mut parser = ByteParser::from(data);
    if let Ok(decoded) = KeyShareEntry::from_bytes(&mut parser) {
        // If decoding succeeds, re-encoding must not panic.....
        let _ = decoded.as_bytes();
    }
});
