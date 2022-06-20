use self::upgrade_storage::BufferUpgradeStorage;
use crate::api::channel::{CtapHidChannel, SendOrRecvError, SendOrRecvResult};
use crate::api::customization::DEFAULT_CUSTOMIZATION;
use crate::api::firmware_protection::FirmwareProtection;
use crate::api::user_presence::{UserPresence, UserPresenceResult, UserPresenceStatus};
use crate::clock::CtapDuration;
use crate::ctap::Channel;
use crate::env::Env;
use customization::TestCustomization;
use persistent_store::{BufferOptions, BufferStorage, Store};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rng256::Rng256;

pub mod customization;
mod upgrade_storage;

pub struct TestEnv {
    rng: TestRng256,
    user_presence: TestUserPresence,
    store: Store<BufferStorage>,
    upgrade_storage: Option<BufferUpgradeStorage>,
    customization: TestCustomization,
}

pub struct TestRng256 {
    rng: StdRng,
}

impl TestRng256 {
    pub fn seed_from_u64(&mut self, state: u64) {
        self.rng = StdRng::seed_from_u64(state);
    }
}

impl Rng256 for TestRng256 {
    fn gen_uniform_u8x32(&mut self) -> [u8; 32] {
        let mut result = [Default::default(); 32];
        self.rng.fill(&mut result);
        result
    }
}

pub struct TestUserPresence {
    check: Box<dyn Fn(Channel) -> UserPresenceResult>,
}

pub struct TestWrite;

impl core::fmt::Write for TestWrite {
    fn write_str(&mut self, _: &str) -> core::fmt::Result {
        Ok(())
    }
}

fn new_storage() -> BufferStorage {
    // Use the Nordic configuration.
    const PAGE_SIZE: usize = 0x1000;
    const NUM_PAGES: usize = 20;
    let store = vec![0xff; NUM_PAGES * PAGE_SIZE].into_boxed_slice();
    let options = BufferOptions {
        word_size: 4,
        page_size: PAGE_SIZE,
        max_word_writes: 2,
        max_page_erases: 10000,
        strict_mode: true,
    };
    BufferStorage::new(store, options)
}

impl CtapHidChannel for TestEnv {
    fn send_or_recv_with_timeout(
        &mut self,
        _buf: &mut [u8; 64],
        _timeout: CtapDuration,
    ) -> SendOrRecvResult {
        // TODO: Implement I/O from canned requests/responses for integration testing.
        Err(SendOrRecvError)
    }
}

impl TestEnv {
    pub fn new() -> Self {
        let rng = TestRng256 {
            rng: StdRng::seed_from_u64(0),
        };
        let user_presence = TestUserPresence {
            check: Box::new(|_| Ok(UserPresenceStatus::Confirmed)),
        };
        let storage = new_storage();
        let store = Store::new(storage).ok().unwrap();
        let upgrade_storage = Some(BufferUpgradeStorage::new().unwrap());
        let customization = DEFAULT_CUSTOMIZATION.into();
        TestEnv {
            rng,
            user_presence,
            store,
            upgrade_storage,
            customization,
        }
    }

    pub fn disable_upgrade_storage(&mut self) {
        self.upgrade_storage = None;
    }

    pub fn customization_mut(&mut self) -> &mut TestCustomization {
        &mut self.customization
    }

    pub fn rng(&mut self) -> &mut TestRng256 {
        &mut self.rng
    }
}

impl TestUserPresence {
    pub fn set(&mut self, check: impl Fn(Channel) -> UserPresenceResult + 'static) {
        self.check = Box::new(check);
    }
}

impl UserPresence for TestUserPresence {
    fn check_init(&mut self, _channel: Channel) {}
    fn wait_with_timeout(
        &mut self,
        channel: Channel,
        _timeout: CtapDuration,
    ) -> UserPresenceResult {
        (self.check)(channel)
    }
    fn check_complete(&mut self, _result: &UserPresenceResult) {}
}

impl FirmwareProtection for TestEnv {
    fn lock(&mut self) -> bool {
        true
    }
}

impl Env for TestEnv {
    type Rng = TestRng256;
    type UserPresence = TestUserPresence;
    type Storage = BufferStorage;
    type UpgradeStorage = BufferUpgradeStorage;
    type FirmwareProtection = Self;
    type Write = TestWrite;
    type Customization = TestCustomization;
    type CtapHidChannel = Self;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }

    fn store(&mut self) -> &mut Store<Self::Storage> {
        &mut self.store
    }

    fn upgrade_storage(&mut self) -> Option<&mut Self::UpgradeStorage> {
        self.upgrade_storage.as_mut()
    }

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection {
        self
    }

    fn write(&mut self) -> Self::Write {
        TestWrite
    }

    fn customization(&self) -> &Self::Customization {
        &self.customization
    }

    fn main_hid_channel(&mut self) -> &mut Self::CtapHidChannel {
        self
    }

    #[cfg(feature = "vendor_hid")]
    fn vendor_hid_channel(&mut self) -> &mut Self::CtapHidChannel {
        self
    }
}
