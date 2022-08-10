// Copyright 2022 Google LLC
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

// FIXME: Add descriptions.

use crate::api::attestation_store::AttestationStore;
use crate::api::connection::{HidConnection, SendOrRecvError, SendOrRecvResult, SendOrRecvStatus};
use crate::api::customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION};
use crate::api::firmware_protection::FirmwareProtection;
use crate::api::upgrade_storage::UpgradeStorage;
use crate::api::user_presence::{UserPresence, UserPresenceError, UserPresenceResult};
use crate::api::{attestation_store, key_store};
use crate::clock::ClockInt;
use crate::ctap::Transport;
use crate::env::Env;
use embedded_time::duration::Milliseconds;
use embedded_time::fixed_point::FixedPoint;
use persistent_store::{FileOptions, FileStorage, StorageError, StorageResult, Store};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rng256::Rng256;
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

pub struct HostEnv {
    rng: HostRng256,
    user_presence: HostUserPresence,
    store: Store<FileStorage>,
    hid_connection: HostHidConnection,
}

pub struct HostHidConnection {
    stream: UnixStream,
}

impl HostHidConnection {
    fn set_read_timeout(&mut self, timeout: Milliseconds<ClockInt>) -> io::Result<()> {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(timeout.integer())))
    }

    fn set_write_timeout(&mut self, timeout: Milliseconds<ClockInt>) -> io::Result<()> {
        self.stream
            .set_write_timeout(Some(Duration::from_millis(timeout.integer())))
    }

    fn read_buf(&mut self, buf: &mut [u8; 64], timeout: Milliseconds<ClockInt>) -> io::Result<()> {
        self.set_read_timeout(timeout)?;
        self.stream.read_exact(buf)
    }

    fn write_buf(&mut self, buf: &mut [u8; 64], timeout: Milliseconds<ClockInt>) -> io::Result<()> {
        self.set_write_timeout(timeout)?;
        self.stream.write_all(buf)?;
        self.stream.flush()
    }

    pub fn recv_with_timeout(
        &mut self,
        buf: &mut [u8; 64],
        timeout: Milliseconds<ClockInt>,
    ) -> SendOrRecvResult {
        match self.read_buf(buf, timeout) {
            Ok(_) => Ok(SendOrRecvStatus::Received(Transport::MainHid)),
            Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(SendOrRecvStatus::Timeout),
            Err(_) => Err(SendOrRecvError),
        }
    }
}

impl HidConnection for HostHidConnection {
    fn send_and_maybe_recv(
        &mut self,
        buf: &mut [u8; 64],
        timeout: Milliseconds<ClockInt>,
    ) -> SendOrRecvResult {
        match self.write_buf(buf, timeout) {
            Ok(_) => Ok(SendOrRecvStatus::Sent),
            Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(SendOrRecvStatus::Timeout),
            Err(_) => Err(SendOrRecvError),
        }
    }
}

pub struct HostRng256 {
    rng: StdRng,
}

impl Rng256 for HostRng256 {
    fn gen_uniform_u8x32(&mut self) -> [u8; 32] {
        let mut result = [Default::default(); 32];
        self.rng.fill(&mut result);
        result
    }
}

pub struct HostUserPresence {
    rx: Receiver<String>,
}

impl HostUserPresence {
    fn new() -> Self {
        let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();
        thread::spawn(move || {
            // FIXME: handle stdin errors
            loop {
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                tx.send(input).unwrap();
            }
        });
        HostUserPresence { rx }
    }
}

impl UserPresence for HostUserPresence {
    fn check_init(&mut self) {
        print!("Press <Enter> to confirm user presence");
        io::stdout().flush().unwrap();
    }
    fn wait_with_timeout(&mut self, timeout: Milliseconds<ClockInt>) -> UserPresenceResult {
        match self
            .rx
            .recv_timeout(Duration::from_millis(timeout.integer()))
        {
            Ok(_) => Ok(()),
            // FIXME: handle disconnect
            Err(_) => Err(UserPresenceError::Timeout),
        }
    }
    fn check_complete(&mut self, result: &UserPresenceResult) {
        match result {
            Ok(_) => {
                println!("Confirmed.");
            }
            Err(UserPresenceError::Canceled) => {
                println!("\nCanceled.");
            }
            Err(UserPresenceError::Declined) => {
                println!("\nDeclined.");
            }
            Err(UserPresenceError::Timeout) => {
                println!("\nTimed out.");
            }
        }
    }
}

pub struct TestWrite;

impl core::fmt::Write for TestWrite {
    fn write_str(&mut self, _: &str) -> core::fmt::Result {
        Ok(())
    }
}

fn new_storage(path: &Path, options: FileOptions) -> StorageResult<FileStorage> {
    FileStorage::new(path, options)
}

impl HostEnv {
    pub fn new(storage_path: &Path, socket_path: &Path) -> Self {
        let rng = HostRng256 {
            rng: StdRng::from_entropy(),
        };
        // TODO: Implement real user presence check, instead of automatic "yes".
        let user_presence = HostUserPresence::new();
        // FIXME: Move to parameters.
        let options = FileOptions {
            word_size: 4,
            page_size: 0x1000,
            num_pages: 20,
        };
        let storage = new_storage(storage_path, options).unwrap();
        let stream = UnixStream::connect(socket_path).unwrap();
        let store = Store::new(storage).ok().unwrap();
        // FIXME: Move to parameters.
        let hid_connection = HostHidConnection { stream };
        HostEnv {
            rng,
            user_presence,
            store,
            hid_connection,
        }
    }

    pub fn rng(&mut self) -> &mut HostRng256 {
        &mut self.rng
    }
}

impl UpgradeStorage for HostEnv {
    fn read_partition(&self, _offset: usize, _length: usize) -> StorageResult<&[u8]> {
        Err(StorageError::CustomError)
    }

    fn write_partition(&mut self, _offset: usize, _data: &[u8]) -> StorageResult<()> {
        Err(StorageError::CustomError)
    }

    fn partition_address(&self) -> usize {
        0
    }

    fn partition_length(&self) -> usize {
        0
    }

    fn read_metadata(&self) -> StorageResult<&[u8]> {
        Err(StorageError::CustomError)
    }

    fn write_metadata(&mut self, _data: &[u8]) -> StorageResult<()> {
        Err(StorageError::CustomError)
    }
}

impl FirmwareProtection for HostEnv {
    fn lock(&mut self) -> bool {
        true
    }
}

impl key_store::Helper for HostEnv {}

impl AttestationStore for HostEnv {
    fn get(
        &mut self,
        _id: &attestation_store::Id,
    ) -> Result<Option<attestation_store::Attestation>, attestation_store::Error> {
        attestation_store::helper_get(self)
    }

    fn set(
        &mut self,
        _id: &attestation_store::Id,
        attestation: Option<&attestation_store::Attestation>,
    ) -> Result<(), attestation_store::Error> {
        attestation_store::helper_set(self, attestation)
    }
}

impl Env for HostEnv {
    type Rng = HostRng256;
    type UserPresence = HostUserPresence;
    type Storage = FileStorage;
    type KeyStore = Self;
    type AttestationStore = Self;
    type FirmwareProtection = Self;
    type UpgradeStorage = Self;
    type Write = TestWrite;
    type Customization = CustomizationImpl;
    type HidConnection = HostHidConnection;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }

    fn store(&mut self) -> &mut Store<Self::Storage> {
        &mut self.store
    }

    fn key_store(&mut self) -> &mut Self {
        self
    }

    fn attestation_store(&mut self) -> &mut Self {
        self
    }

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection {
        self
    }

    fn upgrade_storage(&mut self) -> Option<&mut Self::UpgradeStorage> {
        None
    }

    fn write(&mut self) -> Self::Write {
        TestWrite
    }

    fn customization(&self) -> &Self::Customization {
        &DEFAULT_CUSTOMIZATION
    }

    fn main_hid_connection(&mut self) -> &mut Self::HidConnection {
        &mut self.hid_connection
    }

    #[cfg(feature = "vendor_hid")]
    fn vendor_hid_connection(&mut self) -> &mut Self::HidConnection {
        &mut self.hid_connection
    }
}
