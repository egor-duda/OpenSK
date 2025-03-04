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

use super::super::clock::CtapInstant;
use super::apdu::{Apdu, ApduStatusCode};
use super::crypto_wrapper::{decrypt_credential_source, encrypt_key_handle, PrivateKey};
use super::CtapState;
use crate::ctap::storage;
use crate::env::Env;
use alloc::vec::Vec;
use arrayref::array_ref;
use core::convert::{Into, TryFrom};

// For now, they're the same thing with apdu.rs containing the authoritative definition
pub type Ctap1StatusCode = ApduStatusCode;

// The specification referenced in this file is at:
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.pdf

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ctap1Flags {
    CheckOnly = 0x07,
    EnforceUpAndSign = 0x03,
    DontEnforceUpAndSign = 0x08,
}

impl TryFrom<u8> for Ctap1Flags {
    type Error = Ctap1StatusCode;

    fn try_from(value: u8) -> Result<Ctap1Flags, Ctap1StatusCode> {
        match value {
            0x07 => Ok(Ctap1Flags::CheckOnly),
            0x03 => Ok(Ctap1Flags::EnforceUpAndSign),
            0x08 => Ok(Ctap1Flags::DontEnforceUpAndSign),
            _ => Err(Ctap1StatusCode::SW_WRONG_DATA),
        }
    }
}

impl Into<u8> for Ctap1Flags {
    fn into(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, PartialEq, Eq)]
enum U2fCommand {
    Register {
        challenge: [u8; 32],
        application: [u8; 32],
    },
    Authenticate {
        challenge: [u8; 32],
        application: [u8; 32],
        key_handle: Vec<u8>,
        flags: Ctap1Flags,
    },
    Version,
    VendorSpecific {
        payload: Vec<u8>,
    },
}

impl TryFrom<&[u8]> for U2fCommand {
    type Error = Ctap1StatusCode;

    fn try_from(message: &[u8]) -> Result<Self, Ctap1StatusCode> {
        let apdu: Apdu = match Apdu::try_from(message) {
            Ok(apdu) => apdu,
            Err(apdu_status_code) => {
                return Err(Ctap1StatusCode::try_from(apdu_status_code).unwrap())
            }
        };

        let lc = apdu.lc as usize;

        // ISO7816 APDU Header format. Each cell is 1 byte. Note that the CTAP flavor always
        // encodes the length on 3 bytes and doesn't use the field "Le" (Length Expected).
        // We keep the 2 byte of "Le" for the packet length in mind, but always ignore its value.
        // Lc is using big-endian encoding
        // +-----+-----+----+----+-----+-----+-----+
        // | CLA | INS | P1 | P2 | Lc1 | Lc2 | Lc3 |
        // +-----+-----+----+----+-----+-----+-----+
        if apdu.header.cla != Ctap1Command::CTAP1_CLA {
            return Err(Ctap1StatusCode::SW_CLA_INVALID);
        }

        // Since there is always request data, the expected length is either omitted or
        // encoded in 2 bytes.
        if lc != apdu.data.len() && lc + 2 != apdu.data.len() {
            return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
        }

        match apdu.header.ins {
            // U2F raw message format specification, Section 4.1
            // +-----------------+-------------------+
            // + Challenge (32B) | Application (32B) |
            // +-----------------+-------------------+
            Ctap1Command::U2F_REGISTER => {
                if lc != 64 {
                    return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
                }
                Ok(Self::Register {
                    challenge: *array_ref!(apdu.data, 0, 32),
                    application: *array_ref!(apdu.data, 32, 32),
                })
            }

            // U2F raw message format specification, Section 5.1
            // +-----------------+-------------------+---------------------+------------+
            // + Challenge (32B) | Application (32B) | key handle len (1B) | key handle |
            // +-----------------+-------------------+---------------------+------------+
            Ctap1Command::U2F_AUTHENTICATE => {
                if lc < 65 {
                    return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
                }
                let handle_length = apdu.data[64] as usize;
                if lc != 65 + handle_length {
                    return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
                }
                let flag = Ctap1Flags::try_from(apdu.header.p1)?;
                Ok(Self::Authenticate {
                    challenge: *array_ref!(apdu.data, 0, 32),
                    application: *array_ref!(apdu.data, 32, 32),
                    key_handle: apdu.data[65..].to_vec(),
                    flags: flag,
                })
            }

            // U2F raw message format specification, Section 6.1
            Ctap1Command::U2F_VERSION => {
                if lc != 0 {
                    return Err(Ctap1StatusCode::SW_WRONG_LENGTH);
                }
                Ok(Self::Version)
            }

            // For Vendor specific command.
            Ctap1Command::VENDOR_SPECIFIC_FIRST..=Ctap1Command::VENDOR_SPECIFIC_LAST => {
                Ok(Self::VendorSpecific {
                    payload: apdu.data.to_vec(),
                })
            }

            _ => Err(Ctap1StatusCode::SW_INS_INVALID),
        }
    }
}

pub struct Ctap1Command {}

impl Ctap1Command {
    const CTAP1_CLA: u8 = 0;
    // This byte is used in Register, but only serves backwards compatibility.
    const LEGACY_BYTE: u8 = 0x05;
    // This byte is hardcoded into the specification of Authenticate.
    const USER_PRESENCE_INDICATOR_BYTE: u8 = 0x01;

    // CTAP1/U2F commands
    // U2F raw message format specification 1.2 (version 20170411)
    const U2F_REGISTER: u8 = 0x01;
    const U2F_AUTHENTICATE: u8 = 0x02;
    const U2F_VERSION: u8 = 0x03;
    const VENDOR_SPECIFIC_FIRST: u8 = 0x40;
    const VENDOR_SPECIFIC_LAST: u8 = 0xBF;

    pub fn process_command(
        env: &mut impl Env,
        message: &[u8],
        ctap_state: &mut CtapState,
        clock_value: CtapInstant,
    ) -> Result<Vec<u8>, Ctap1StatusCode> {
        if !ctap_state
            .allows_ctap1(env)
            .map_err(|_| Ctap1StatusCode::SW_INTERNAL_EXCEPTION)?
        {
            return Err(Ctap1StatusCode::SW_COMMAND_NOT_ALLOWED);
        }
        let command = U2fCommand::try_from(message)?;
        match command {
            U2fCommand::Register {
                challenge,
                application,
            } => {
                if !ctap_state.u2f_up_state.consume_up(clock_value) {
                    return Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED);
                }
                Ctap1Command::process_register(env, challenge, application)
            }

            U2fCommand::Authenticate {
                challenge,
                application,
                key_handle,
                flags,
            } => {
                // The order is important due to side effects of checking user presence.
                if flags == Ctap1Flags::EnforceUpAndSign
                    && !ctap_state.u2f_up_state.consume_up(clock_value)
                {
                    return Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED);
                }
                Ctap1Command::process_authenticate(
                    env,
                    challenge,
                    application,
                    key_handle,
                    flags,
                    ctap_state,
                )
            }

            // U2F raw message format specification (version 20170411) section 6.3
            U2fCommand::Version => Ok(Vec::<u8>::from(super::U2F_VERSION_STRING)),

            // TODO: should we return an error instead such as SW_INS_NOT_SUPPORTED?
            U2fCommand::VendorSpecific { .. } => Err(Ctap1StatusCode::SW_SUCCESS),
        }
    }

    // U2F raw message format specification (version 20170411) section 4.3
    // In case of success we need to send back the following reply
    // (excluding ISO7816 success code)
    // +------+--------------------+---------------------+------------+------------+------+
    // + 0x05 | User pub key (65B) | key handle len (1B) | key handle | X.509 Cert | Sign |
    // +------+--------------------+---------------------+------------+------------+------+
    //
    // Where Sign is an ECDSA signature over the following structure:
    // +------+-------------------+-----------------+------------+--------------------+
    // + 0x00 | application (32B) | challenge (32B) | key handle | User pub key (65B) |
    // +------+-------------------+-----------------+------------+--------------------+
    fn process_register(
        env: &mut impl Env,
        challenge: [u8; 32],
        application: [u8; 32],
    ) -> Result<Vec<u8>, Ctap1StatusCode> {
        let sk = crypto::ecdsa::SecKey::gensk(env.rng());
        let pk = sk.genpk();
        let key_handle = encrypt_key_handle(env, &PrivateKey::from(sk), &application)
            .map_err(|_| Ctap1StatusCode::SW_INTERNAL_EXCEPTION)?;
        if key_handle.len() > 0xFF {
            // This is just being defensive with unreachable code.
            return Err(Ctap1StatusCode::SW_INTERNAL_EXCEPTION);
        }

        let certificate = storage::attestation_certificate(env)
            .map_err(|_| Ctap1StatusCode::SW_MEMERR)?
            .ok_or(Ctap1StatusCode::SW_INTERNAL_EXCEPTION)?;
        let private_key = storage::attestation_private_key(env)
            .map_err(|_| Ctap1StatusCode::SW_INTERNAL_EXCEPTION)?
            .ok_or(Ctap1StatusCode::SW_INTERNAL_EXCEPTION)?;

        let mut response = Vec::with_capacity(105 + key_handle.len() + certificate.len());
        response.push(Ctap1Command::LEGACY_BYTE);
        let user_pk = pk.to_uncompressed();
        response.extend_from_slice(&user_pk);
        response.push(key_handle.len() as u8);
        response.extend(key_handle.clone());
        response.extend_from_slice(&certificate);

        // The first byte is reserved.
        let mut signature_data = Vec::with_capacity(66 + key_handle.len());
        signature_data.push(0x00);
        signature_data.extend(&application);
        signature_data.extend(&challenge);
        signature_data.extend(key_handle);
        signature_data.extend_from_slice(&user_pk);

        let attestation_key = crypto::ecdsa::SecKey::from_bytes(&private_key).unwrap();
        let signature = attestation_key.sign_rfc6979::<crypto::sha256::Sha256>(&signature_data);

        response.extend(signature.to_asn1_der());
        Ok(response)
    }

    // U2F raw message format specification (version 20170411) section 5.4
    // In case of success we need to send back the following reply
    // (excluding ISO7816 success code)
    // +---------+--------------+-----------+
    // + UP (1B) | Counter (4B) | Signature |
    // +---------+--------------+-----------+
    // UP only has 2 defined values:
    //  - 0x00: user presence was not verified
    //  - 0x01: user presence was verified
    //
    // Where Signature is an ECDSA signature over the following structure:
    // +-------------------+---------+--------------+-----------------+
    // + application (32B) | UP (1B) | Counter (4B) | challenge (32B) |
    // +-------------------+---------+--------------+-----------------+
    fn process_authenticate(
        env: &mut impl Env,
        challenge: [u8; 32],
        application: [u8; 32],
        key_handle: Vec<u8>,
        flags: Ctap1Flags,
        ctap_state: &mut CtapState,
    ) -> Result<Vec<u8>, Ctap1StatusCode> {
        let credential_source = decrypt_credential_source(env, key_handle, &application)
            .map_err(|_| Ctap1StatusCode::SW_WRONG_DATA)?;
        if let Some(credential_source) = credential_source {
            // CTAP1 only supports ECDSA, the default case applies if CTAP2 adds more algorithms.
            #[allow(unreachable_patterns)]
            let ecdsa_key = match credential_source.private_key {
                PrivateKey::Ecdsa(k) => k,
                _ => return Err(Ctap1StatusCode::SW_WRONG_DATA),
            };
            if flags == Ctap1Flags::CheckOnly {
                return Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED);
            }
            ctap_state
                .increment_global_signature_counter(env)
                .map_err(|_| Ctap1StatusCode::SW_WRONG_DATA)?;
            let mut signature_data = ctap_state
                .generate_auth_data(
                    env,
                    &application,
                    Ctap1Command::USER_PRESENCE_INDICATOR_BYTE,
                )
                .map_err(|_| Ctap1StatusCode::SW_WRONG_DATA)?;
            signature_data.extend(&challenge);
            let signature = ecdsa_key.sign_rfc6979::<crypto::sha256::Sha256>(&signature_data);

            let mut response = signature_data[application.len()..application.len() + 5].to_vec();
            response.extend(signature.to_asn1_der());
            Ok(response)
        } else {
            Err(Ctap1StatusCode::SW_WRONG_DATA)
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::crypto_wrapper::ECDSA_CREDENTIAL_ID_SIZE;
    use super::super::data_formats::SignatureAlgorithm;
    use super::super::key_material;
    use super::*;
    use crate::api::customization::Customization;
    use crate::clock::TEST_CLOCK_FREQUENCY_HZ;
    use crate::env::test::TestEnv;
    use crypto::Hash256;

    fn create_register_message(application: &[u8; 32]) -> Vec<u8> {
        let mut message = vec![
            Ctap1Command::CTAP1_CLA,
            Ctap1Command::U2F_REGISTER,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
        ];
        let challenge = [0x0C; 32];
        message.extend(&challenge);
        message.extend(application);
        message
    }

    fn create_authenticate_message(
        application: &[u8; 32],
        flags: Ctap1Flags,
        key_handle: &Vec<u8>,
    ) -> Vec<u8> {
        let mut message = vec![
            Ctap1Command::CTAP1_CLA,
            Ctap1Command::U2F_AUTHENTICATE,
            flags.into(),
            0x00,
            0x00,
            0x00,
            65 + ECDSA_CREDENTIAL_ID_SIZE as u8,
        ];
        let challenge = [0x0C; 32];
        message.extend(&challenge);
        message.extend(application);
        message.push(ECDSA_CREDENTIAL_ID_SIZE as u8);
        message.extend(key_handle);
        message
    }

    #[test]
    fn test_process_allowed() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));
        storage::toggle_always_uv(&mut env).unwrap();

        let application = [0x0A; 32];
        let message = create_register_message(&application);
        ctap_state.u2f_up_state.consume_up(CtapInstant::new(0));
        ctap_state.u2f_up_state.grant_up(CtapInstant::new(0));
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert_eq!(response, Err(Ctap1StatusCode::SW_COMMAND_NOT_ALLOWED));
    }

    #[test]
    fn test_process_register() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let application = [0x0A; 32];
        let message = create_register_message(&application);
        ctap_state.u2f_up_state.consume_up(CtapInstant::new(0));
        ctap_state.u2f_up_state.grant_up(CtapInstant::new(0));
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        // Certificate and private key are missing
        assert_eq!(response, Err(Ctap1StatusCode::SW_INTERNAL_EXCEPTION));

        let fake_key = [0x41u8; key_material::ATTESTATION_PRIVATE_KEY_LENGTH];
        assert!(storage::set_attestation_private_key(&mut env, &fake_key).is_ok());
        ctap_state.u2f_up_state.consume_up(CtapInstant::new(0));
        ctap_state.u2f_up_state.grant_up(CtapInstant::new(0));
        let response = Ctap1Command::process_command(
            &mut env,
            &message,
            &mut ctap_state,
            CtapInstant::new(0_u64),
        );
        // Certificate is still missing
        assert_eq!(response, Err(Ctap1StatusCode::SW_INTERNAL_EXCEPTION));

        let fake_cert = [0x99u8; 100]; // Arbitrary length
        assert!(storage::set_attestation_certificate(&mut env, &fake_cert[..]).is_ok());
        ctap_state.u2f_up_state.consume_up(CtapInstant::new(0));
        ctap_state.u2f_up_state.grant_up(CtapInstant::new(0));
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0))
                .unwrap();
        assert_eq!(response[0], Ctap1Command::LEGACY_BYTE);
        assert_eq!(response[66], ECDSA_CREDENTIAL_ID_SIZE as u8);
        assert!(decrypt_credential_source(
            &mut env,
            response[67..67 + ECDSA_CREDENTIAL_ID_SIZE].to_vec(),
            &application
        )
        .unwrap()
        .is_some());
        const CERT_START: usize = 67 + ECDSA_CREDENTIAL_ID_SIZE;
        assert_eq!(
            &response[CERT_START..CERT_START + fake_cert.len()],
            &fake_cert[..]
        );
    }

    #[test]
    fn test_process_register_bad_message() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let application = [0x0A; 32];
        let message = create_register_message(&application);
        let response = Ctap1Command::process_command(
            &mut env,
            &message[..message.len() - 1],
            &mut ctap_state,
            CtapInstant::new(0),
        );

        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_LENGTH));
    }

    #[test]
    fn test_process_register_without_up() {
        let application = [0x0A; 32];
        let message = create_register_message(&application);

        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        ctap_state.u2f_up_state.consume_up(CtapInstant::new(0));
        ctap_state.u2f_up_state.grant_up(CtapInstant::new(0));
        let timeout_clock_value: CtapInstant =
            CtapInstant::new((30001 * TEST_CLOCK_FREQUENCY_HZ as u64) / 1000);
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, timeout_clock_value);
        assert_eq!(response, Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED));
    }

    #[test]
    fn test_process_authenticate_check_only() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let sk = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = encrypt_key_handle(&mut env, &sk, &application).unwrap();
        let message = create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);

        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert_eq!(response, Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_rp() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let sk = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = encrypt_key_handle(&mut env, &sk, &application).unwrap();
        let application = [0x55; 32];
        let message = create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);

        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_DATA));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_length() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let sk = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = encrypt_key_handle(&mut env, &sk, &application).unwrap();
        let mut message = create_authenticate_message(
            &application,
            Ctap1Flags::DontEnforceUpAndSign,
            &key_handle,
        );

        message.push(0x00);
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert!(response.is_ok());

        message.push(0x00);
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert!(response.is_ok());

        message.push(0x00);
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert!(response.is_ok());

        message.push(0x00);
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_LENGTH));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_cla() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let sk = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = encrypt_key_handle(&mut env, &sk, &application).unwrap();
        let mut message =
            create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);
        message[0] = 0xEE;

        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert_eq!(response, Err(Ctap1StatusCode::SW_CLA_INVALID));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_ins() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let sk = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = encrypt_key_handle(&mut env, &sk, &application).unwrap();
        let mut message =
            create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);
        message[1] = 0xEE;

        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert_eq!(response, Err(Ctap1StatusCode::SW_INS_INVALID));
    }

    #[test]
    fn test_process_authenticate_check_only_wrong_flags() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let sk = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = encrypt_key_handle(&mut env, &sk, &application).unwrap();
        let mut message =
            create_authenticate_message(&application, Ctap1Flags::CheckOnly, &key_handle);
        message[2] = 0xEE;

        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_DATA));
    }

    fn check_signature_counter(env: &mut impl Env, response: &[u8; 4], signature_counter: u32) {
        if env.customization().use_signature_counter() {
            assert_eq!(u32::from_be_bytes(*response), signature_counter);
        } else {
            assert_eq!(response, &[0x00, 0x00, 0x00, 0x00]);
        }
    }

    #[test]
    fn test_process_authenticate_enforce() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let sk = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = encrypt_key_handle(&mut env, &sk, &application).unwrap();
        let message =
            create_authenticate_message(&application, Ctap1Flags::EnforceUpAndSign, &key_handle);

        ctap_state.u2f_up_state.consume_up(CtapInstant::new(0));
        ctap_state.u2f_up_state.grant_up(CtapInstant::new(0));
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0))
                .unwrap();
        assert_eq!(response[0], 0x01);
        let global_signature_counter = storage::global_signature_counter(&mut env).unwrap();
        check_signature_counter(
            &mut env,
            array_ref!(response, 1, 4),
            global_signature_counter,
        );
    }

    #[test]
    fn test_process_authenticate_dont_enforce() {
        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let sk = PrivateKey::new(env.rng(), SignatureAlgorithm::ES256);
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        let rp_id = "example.com";
        let application = crypto::sha256::Sha256::hash(rp_id.as_bytes());
        let key_handle = encrypt_key_handle(&mut env, &sk, &application).unwrap();
        let message = create_authenticate_message(
            &application,
            Ctap1Flags::DontEnforceUpAndSign,
            &key_handle,
        );

        let response = Ctap1Command::process_command(
            &mut env,
            &message,
            &mut ctap_state,
            CtapInstant::new((30001 * TEST_CLOCK_FREQUENCY_HZ as u64) / 1000),
        )
        .unwrap();
        assert_eq!(response[0], 0x01);
        let global_signature_counter = storage::global_signature_counter(&mut env).unwrap();
        check_signature_counter(
            &mut env,
            array_ref!(response, 1, 4),
            global_signature_counter,
        );
    }

    #[test]
    fn test_process_authenticate_bad_key_handle() {
        let application = [0x0A; 32];
        let key_handle = vec![0x00; ECDSA_CREDENTIAL_ID_SIZE];
        let message =
            create_authenticate_message(&application, Ctap1Flags::EnforceUpAndSign, &key_handle);

        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        ctap_state.u2f_up_state.consume_up(CtapInstant::new(0));
        ctap_state.u2f_up_state.grant_up(CtapInstant::new(0));
        let response =
            Ctap1Command::process_command(&mut env, &message, &mut ctap_state, CtapInstant::new(0));
        assert_eq!(response, Err(Ctap1StatusCode::SW_WRONG_DATA));
    }

    #[test]
    fn test_process_authenticate_without_up() {
        let application = [0x0A; 32];
        let key_handle = vec![0x00; ECDSA_CREDENTIAL_ID_SIZE];
        let message =
            create_authenticate_message(&application, Ctap1Flags::EnforceUpAndSign, &key_handle);

        let mut env = TestEnv::new();
        env.user_presence()
            .set(|_| panic!("Unexpected user presence check in CTAP1"));
        let mut ctap_state = CtapState::new(&mut env, CtapInstant::new(0));

        ctap_state.u2f_up_state.consume_up(CtapInstant::new(0));
        ctap_state.u2f_up_state.grant_up(CtapInstant::new(0));
        let response = Ctap1Command::process_command(
            &mut env,
            &message,
            &mut ctap_state,
            CtapInstant::new((30001 * TEST_CLOCK_FREQUENCY_HZ as u64) / 1000),
        );
        assert_eq!(response, Err(Ctap1StatusCode::SW_COND_USE_NOT_SATISFIED));
    }
}
