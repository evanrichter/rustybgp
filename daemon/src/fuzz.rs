// Copyright (C) 2019-2021 The RustyBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bytes::BytesMut;
use tokio_util::codec::Decoder;

pub fn bgp_decode_stream(
    local_asn: u32,
    local_addr: u32,
    keep_aspath: bool,
    keep_nexthop: bool,
    bytes: &[u8],
) {
    use crate::packet::bgp::CodecBuilder;

    let mut codec = CodecBuilder::new()
        .local_asn(local_asn)
        .local_addr(std::net::IpAddr::V4(local_addr.into()))
        .keep_aspath(keep_aspath)
        .keep_nexthop(keep_nexthop)
        .build();

    let mut bytes = BytesMut::from(bytes);

    loop {
        let prev_len = bytes.len();

        // decode message
        let _ = codec.decode(&mut bytes);

        if prev_len == bytes.len() {
            // break fuzzing if no bytes were consumed
            break;
        }
    }
}

pub fn rpki_decode_stream(bytes: &[u8]) {
    let mut codec = crate::packet::rpki::RtrCodec::new();
    let mut bytes = BytesMut::from(bytes);

    loop {
        let prev_len = bytes.len();

        // decode message
        let _ = codec.decode(&mut bytes);

        if prev_len == bytes.len() {
            // break fuzzing if no bytes were consumed
            break;
        }
    }
}
