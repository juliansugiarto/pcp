#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| pcp_fuzz::f3_buyer(data));
