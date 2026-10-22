#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| pcp_fuzz::f4_statement(data));
