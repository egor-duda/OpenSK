// Copyright 2019-2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub const ATTESTATION_PRIVATE_KEY_LENGTH: usize = 32;
pub const AAGUID_LENGTH: usize = 16;
pub const UPGRADE_PUBLIC_KEY_LENGTH: usize = 77;

pub const AAGUID: &[u8; AAGUID_LENGTH] =
    include_bytes!(concat!(env!("OUT_DIR"), "/opensk_aaguid.bin"));
pub const UPGRADE_PUBLIC_KEY: &[u8; UPGRADE_PUBLIC_KEY_LENGTH] =
    include_bytes!(concat!(env!("OUT_DIR"), "/opensk_upgrade_pubkey_cbor.bin"));
