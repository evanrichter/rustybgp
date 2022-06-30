#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    rustybgpd::fuzz::rpki_decode_stream(bytes);
});
