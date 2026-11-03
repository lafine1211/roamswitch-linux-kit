//! Async client for [RoamSwitch](https://lafine.net)'s local Linux network
//! security diagnostics. It has no API that changes a RoamSwitch setting.
//!
//! [`RoamSwitchClient`] starts RoamSwitch's `roamswitch-mcp` binary for each
//! call and decodes the answer into the types of [`models`], which are also
//! re-exported at the crate root. It covers all 45 tools of `roamswitch-mcp`:
//! one method for most tools, two for `audit_secrets` (text or path),
//! `audit_agent_setup` and `get_detection_coverage` (JSON, or SARIF /
//! ATT&CK Navigator), `get_privilege_escalation_paths` (one account, or the
//! `agent_users`), and `verify_fim` (the critical-path report, or everything
//! the tool returns). `security_report` and `server_security_report` are two
//! methods for one tool.
//!
//! Where a tool answers with the output of a separate format or product, the
//! method returns a [`serde_json::Value`] for that part and says why in its
//! documentation.
//!
//! See the [crate README](https://github.com/lafine1211/roamswitch-linux-kit)
//! for design principles and usage examples.

mod client;
pub mod models;

pub use client::{RoamSwitchClient, RoamSwitchClientError};
pub use models::*;
