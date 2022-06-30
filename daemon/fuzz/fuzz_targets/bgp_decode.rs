#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (u32, u32, bool, bool, &[u8])| {
    let (local_asn, local_addr, keep_aspath, keep_nexthop, bytes) = data;
    rustybgpd::fuzz::bgp_decode_stream(local_asn, local_addr, keep_aspath, keep_nexthop, bytes);
});
