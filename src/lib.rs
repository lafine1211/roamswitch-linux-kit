//! Read-only async client for [RoamSwitch](https://lafine.net)'s local Linux
//! network security diagnostics.
//!
//! See the [crate README](https://github.com/lafine1211/roamswitch-linux-kit)
//! for design principles and usage examples.

mod client;
pub mod models;

pub use client::{RoamSwitchClient, RoamSwitchClientError};
pub use models::*;
