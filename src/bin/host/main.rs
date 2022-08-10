#[cfg(feature = "std")]
// Copyright 2019 Google LLC
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
extern crate alloc;
extern crate arrayref;
extern crate byteorder;
extern crate core;
extern crate lang_items;

#[cfg(feature = "with_ctap1")]
use core::cell::Cell;
#[cfg(feature = "debug_ctap")]
use core::convert::TryFrom;
use core::convert::TryInto;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use ctap2::api::connection::{HidConnection, SendOrRecvStatus};
#[cfg(feature = "debug_ctap")]
use ctap2::clock::CtapClock;
use ctap2::clock::{new_clock, Clock, ClockInt, KEEPALIVE_DELAY};
use ctap2::env::host::HostEnv;
#[cfg(feature = "with_ctap1")]
use ctap2::env::tock::blink_leds;
use ctap2::env::tock::{switch_off_leds, wink_leds};
use ctap2::env::Env;
#[cfg(feature = "debug_ctap")]
use embedded_time::duration::Microseconds;
use embedded_time::duration::Milliseconds;
#[cfg(feature = "with_ctap1")]
use libtock_drivers::buttons::{self, ButtonState};
#[cfg(feature = "debug_ctap")]
use libtock_drivers::console::Console;
#[cfg(any(not(feature = "std"), feature = "with_ctap1"))]
use libtock_drivers::result::FlexUnwrap;
use std::path::Path;

libtock_core::stack_size! {0x4000}

const SEND_TIMEOUT: Milliseconds<ClockInt> = Milliseconds(1000);

fn main() {
    let clock = new_clock();

    let boot_time = clock.try_now().unwrap();

    // FIXME: Get path for storage from command line
    let env = HostEnv::new(
        Path::new("opensk-storage.bin"),
        Path::new("/home/deo/tmp/fido2.sock"),
    );

    let mut ctap = ctap2::Ctap::new(env, boot_time);

    let mut led_counter = 0;
    let mut last_led_increment = boot_time;

    // Main loop. If CTAP1 is used, we register button presses for U2F while receiving and waiting.
    // The way TockOS and apps currently interact, callbacks need a yield syscall to execute,
    // making consistent blinking patterns and sending keepalives harder.
    loop {
        // Create the button callback, used for CTAP1.
        #[cfg(feature = "with_ctap1")]
        let button_touched = Cell::new(false);
        #[cfg(feature = "with_ctap1")]
        let mut buttons_callback = buttons::with_callback(|_button_num, state| {
            match state {
                ButtonState::Pressed => button_touched.set(true),
                ButtonState::Released => (),
            };
        });
        #[cfg(feature = "with_ctap1")]
        let mut buttons = buttons_callback.init().flex_unwrap();
        // At the moment, all buttons are accepted. You can customize your setup here.
        #[cfg(feature = "with_ctap1")]
        for mut button in &mut buttons {
            button.enable().flex_unwrap();
        }

        let mut pkt_request = [0; 64];
        let transport = match ctap
            .env()
            .main_hid_connection()
            .recv_with_timeout(&mut pkt_request, KEEPALIVE_DELAY)
        {
            Ok(SendOrRecvStatus::Received(transport)) => Some(transport),
            Ok(SendOrRecvStatus::Timeout) => None,
            _ => panic!("Error receiving packet"),
        };

        let now = clock.try_now().unwrap();
        #[cfg(feature = "with_ctap1")]
        {
            if button_touched.get() {
                ctap.state().u2f_grant_user_presence(now);
            }
            // Cleanup button callbacks. We miss button presses while processing though.
            // Heavy computation mostly follows a registered touch luckily. Unregistering
            // callbacks is important to not clash with those from check_user_presence.
            for mut button in &mut buttons {
                button.disable().flex_unwrap();
            }
            drop(buttons);
            drop(buttons_callback);
        }

        // These calls are making sure that even for long inactivity, wrapping clock values
        // don't cause problems with timers.
        ctap.update_timeouts(now);

        if let Some(transport) = transport {
            let reply = ctap.process_hid_packet(&pkt_request, transport, now);
            // This block handles sending packets.
            for mut pkt_reply in reply {
                let hid_connection = transport.hid_connection(ctap.env());
                match hid_connection.send_and_maybe_recv(&mut pkt_reply, SEND_TIMEOUT) {
                    Ok(SendOrRecvStatus::Timeout) => {
                        #[cfg(feature = "debug_ctap")]
                        print_packet_notice("Sending packet timed out", &clock);
                        // TODO: reset the ctap_hid state.
                        // Since sending the packet timed out, we cancel this reply.
                        break;
                    }
                    Ok(SendOrRecvStatus::Sent) => {
                        #[cfg(feature = "debug_ctap")]
                        print_packet_notice("Sent packet", &clock);
                    }
                    Ok(SendOrRecvStatus::Received(_)) => {
                        #[cfg(feature = "debug_ctap")]
                        print_packet_notice("Received an UNEXPECTED packet", &clock);
                        // TODO: handle this unexpected packet.
                    }
                    Err(_) => panic!("Error sending packet"),
                }
            }
        }

        let now = clock.try_now().unwrap();
        if let Some(wait_duration) = now.checked_duration_since(&last_led_increment) {
            let wait_duration: Milliseconds<ClockInt> = wait_duration.try_into().unwrap();
            if wait_duration > KEEPALIVE_DELAY {
                // Loops quickly when waiting for U2F user presence, so the next LED blink
                // state is only set if enough time has elapsed.
                led_counter += 1;
                last_led_increment = now;
            }
        } else {
            // This branch means the clock frequency changed. This should never happen.
            led_counter += 1;
            last_led_increment = now;
        }

        if ctap.hid().should_wink(now) {
            wink_leds(led_counter);
        } else {
            #[cfg(not(feature = "with_ctap1"))]
            switch_off_leds();
            #[cfg(feature = "with_ctap1")]
            if ctap.state().u2f_needs_user_presence(now) {
                // Flash the LEDs with an almost regular pattern. The inaccuracy comes from
                // delay caused by processing and sending of packets.
                blink_leds(led_counter);
            } else {
                switch_off_leds();
            }
        }
    }
}

#[cfg(feature = "debug_ctap")]
fn print_packet_notice(notice_text: &str, clock: &CtapClock) {
    let now = clock.try_now().unwrap();
    let now_us = Microseconds::<u64>::try_from(now.duration_since_epoch())
        .unwrap()
        .0;
    writeln!(
        Console::new(),
        "{} at {}.{:06} s",
        notice_text,
        now_us / 1_000_000,
        now_us % 1_000_000
    )
    .unwrap();
}
