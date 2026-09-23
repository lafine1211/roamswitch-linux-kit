# AGENTS.md

Reference for AI coding assistants integrating `roamswitch-linux-kit` into a Rust/Linux project. This file states the exact API surface — do not guess at method names, field names, or error cases beyond what's listed here.

## What this crate is

A read-only async Rust client for RoamSwitch (a Linux network-security tool, https://lafine.net/linux.html). It queries live diagnostics (security posture score, exposed network ports, guard on/off state, URL safety, secret leaks, security logs, quarantine/canary status) from an already-installed RoamSwitch. It cannot change any RoamSwitch setting — there is no write/mutation API in this crate, and none should be invented when generating code against it.

## Requirements

- A recent stable Rust toolchain (2021 edition), `tokio` runtime
- RoamSwitch for Linux must be installed on the machine the code runs on, with `roamswitch-mcp` reachable (sibling of your binary, `/usr/bin/roamswitch-mcp`, or `/usr/local/bin/roamswitch-mcp`). If it isn't, every call returns `Err(RoamSwitchClientError::AppNotInstalled)` — this is an expected, normal condition, not a bug. Code that calls this crate should match on that variant and degrade gracefully (skip the feature / show a message), never `.unwrap()` or treat it as fatal.

## Installation

```toml
[dependencies]
roamswitch-linux-kit = { git = "https://github.com/lafine1211/roamswitch-linux-kit", tag = "v0.1.0" }
tokio = { version = "1", features = ["full"] }
```

## Full API surface

```rust
use roamswitch_linux_kit::RoamSwitchClient;

impl RoamSwitchClient {
    pub fn new(executable_path: Option<PathBuf>, timeout: Option<Duration>) -> Result<Self, RoamSwitchClientError>;

    pub async fn security_report(&self) -> Result<SecurityReport, RoamSwitchClientError>;
    pub async fn server_security_report(&self) -> Result<SecurityReport, RoamSwitchClientError>;
    pub async fn exposed_ports(&self, include_local_only: bool) -> Result<ExposedPorts, RoamSwitchClientError>;
    pub async fn run_active_vuln_scan(&self) -> Result<ActiveVulnScanResult, RoamSwitchClientError>;
    pub async fn guard_status(&self) -> Result<GuardStatus, RoamSwitchClientError>;
    pub async fn audit_url_safety(&self, url: &str) -> Result<LinkAuditReport, RoamSwitchClientError>;
    pub async fn audit_secrets(&self, text: &str) -> Result<SecretAuditResult, RoamSwitchClientError>;
    pub async fn audit_security_logs(&self, hours: u32) -> Result<SecurityLogSummary, RoamSwitchClientError>;
    pub async fn get_app_help(&self, query: Option<&str>, topic: Option<&str>) -> Result<KnowledgeSearchResult, RoamSwitchClientError>;
    pub async fn quarantine_status(&self) -> Result<QuarantineStatus, RoamSwitchClientError>;
    pub async fn canary_status(&self) -> Result<CanaryStatus, RoamSwitchClientError>;
    pub async fn package_cve_scan(&self) -> Result<PackageCveScanResult, RoamSwitchClientError>;
    pub async fn package_cve_scan_languages(&self, watched_folders: &[PathBuf]) -> Result<PackageCveScanLanguagesResult, RoamSwitchClientError>;
    pub async fn verify_fim(&self) -> Result<FimReport, RoamSwitchClientError>;
    pub async fn get_port_anomaly_incidents(&self) -> Result<PortAnomalyIncidentsSummary, RoamSwitchClientError>;
    pub async fn get_ebpf_incidents(&self) -> Result<EbpfIncidentsSummary, RoamSwitchClientError>;  // Server Edition only
    pub async fn vulnerability_scan_history(&self) -> Result<Vec<ProbeStatus>, RoamSwitchClientError>;
    pub async fn get_resource_guard_incidents(&self) -> Result<ResourceGuardIncidentsSummary, RoamSwitchClientError>;  // Server Edition only
    pub async fn get_file_scan_guard_status(&self) -> Result<FileScanGuardStatus, RoamSwitchClientError>;  // Server Edition only
    pub async fn notification_history(&self) -> Result<Vec<NotificationHistoryEntry>, RoamSwitchClientError>;
    pub async fn get_incident_timeline(&self) -> Result<Vec<TimelineEvent>, RoamSwitchClientError>;  // EXPERIMENTAL
    pub async fn audit_secrets_path(&self, path: &Path) -> Result<SecretPathAuditResult, RoamSwitchClientError>;
    pub async fn vpn_status(&self) -> Result<VpnStatusSummary, RoamSwitchClientError>;  // Client Edition only
    pub async fn link_guard_status(&self) -> Result<LinkGuardStatusSummary, RoamSwitchClientError>;  // Client Edition only
    pub async fn air_gap_status(&self) -> Result<AirGapStatusSummary, RoamSwitchClientError>;  // Client Edition only
    pub async fn sharing_services_status(&self) -> Result<SharingServicesStatusSummary, RoamSwitchClientError>;  // Client Edition only
    pub async fn bluetooth_guard_status(&self) -> Result<BluetoothGuardStatusSummary, RoamSwitchClientError>;  // Client Edition only
    pub async fn usb_guard_status(&self) -> Result<UsbGuardStatusSummary, RoamSwitchClientError>;  // Client Edition only
}
```

`new(None, None)` uses defaults: auto-discover `roamswitch-mcp`, 30s timeout. If it doesn't answer in time, the subprocess is dropped and the call returns `Err(RoamSwitchClientError::TimedOut)`.

This is the entire public API. There are no other types, methods, or properties to call. In particular:

- No method to change security level, toggle a guard, isolate/unblock a port, quarantine/restore a file, freeze a process, or manage USB device approvals — these don't exist by design, and are handled by RoamSwitch's own privileged daemon/CLI, not by this crate.
- No persistent connection, callback, or streaming API — every call is a single request/response over a fresh subprocess.
- No way to force RoamSwitch to install or launch itself.

### `SecurityReport`

```rust
pub struct SecurityReport {
    pub score: i32,              // 0-100
    pub grade: String,
    pub total_checks: i32,
    pub passed_checks: i32,
    pub items: Vec<SecurityAuditItem>,
    pub caveats: Vec<String>,
}

pub struct SecurityAuditItem {
    pub category: String,
    pub title: String,
    pub is_passed: bool,
    pub status_text: String,
    pub detail: String,
    pub recommendation: String,
    pub settings_url: Option<String>,
    pub is_applicable: bool,
    pub fix_action: Option<String>,   // token for a one-click remediation, when one exists
}
```

### `ExposedPorts`

```rust
pub struct ExposedPorts {
    pub is_firewall_shielded: bool,
    pub ports: Vec<ExposedPort>,
}

pub struct ExposedPort {
    pub process_name: String,
    pub pid: i32,
    pub port: i32,
    pub is_globally_exposed: bool,
    pub executable_path: Option<String>,
    pub audit_performed: bool,
    pub overall_risk: Option<String>,   // "low" | "medium" | "high" | "critical"; None unless audit_performed
    pub findings: Vec<PortFinding>,
    pub http_headers: Option<std::collections::HashMap<String, String>>,
    pub is_dev_server: bool,
    pub is_isolated: bool,
}

pub struct PortFinding {
    pub title: String,
    pub risk_level: String,
    pub description: String,
    pub recommendation: String,
}
```

### `GuardStatus`

```rust
pub struct GuardStatus {
    pub active_security_level: String,        // e.g. "open" | "balanced" | "lockdown"
    pub active_security_level_label: String,  // localized display name
    pub is_current_network_trusted: bool,
    pub guards: Vec<GuardEntry>,
    pub caveats: Vec<String>,
}

pub struct GuardEntry {
    pub key: String,   // portAnomalyGuard, arpSpoofAutoContainment, usbStorageGuard, webMailDownloadGuard, dnsThreatGuard, ransomwareCanaryGuard, devServerIsolator, bluetoothGuard
    pub enabled_in_settings: bool,
}
```

### `LinkAuditReport`

```rust
pub struct LinkAuditReport {
    pub original_url: String,
    pub final_url: String,
    pub redirect_chain: Vec<String>,
    pub domain: String,
    pub score: i32,             // 0-100 (100 = safe, <50 = dangerous)
    pub risk_level: String,     // "safe" | "caution" | "dangerous"
    pub is_https: bool,
    pub risk_factors: Vec<LinkRiskFactor>,
    pub verdict: Verdict,       // Allow | Warn | Block — the actual enforcement decision
}

pub struct LinkRiskFactor {
    pub title: String,
    pub detail: String,
    pub is_severe: bool,
}

pub enum Verdict { Allow, Warn, Block }
```

### `SecretAuditResult`, `SecurityLogSummary`, `KnowledgeSearchResult`, `QuarantineStatus`, `CanaryStatus`, `ActiveVulnScanResult`, `PackageCveScanResult`, `PackageCveScanLanguagesResult`, `FimReport`, `ProbeStatus`, `NotificationHistoryEntry`

See [`src/models.rs`](src/models.rs) for the complete field list of these eleven bonus response types (beyond the four macOS RoamSwitchKit also has) — field names follow the same `snake_case`-Rust / `camelCase`-wire convention as everything above, **except `FimReport`/`FimViolation`, which are plain snake_case on the wire too** (no `camelCase` rename — that's the actual JSON `verify_fim` sends, not an inconsistency to "fix").

### `PortAnomalyIncidentsSummary` / `EbpfIncidentsSummary`

```rust
// Plain snake_case on the wire (same exception as FimReport above): mirrors
// an existing on-disk daemon state file, not a shape we're free to rename.
pub struct PortAnomalyIncidentsSummary {
    pub incidents: Vec<PortAnomalyIncident>,
    pub auto_isolated_ports: Vec<u16>,
    pub user_isolated_ports: Vec<u16>,
    pub baseline_captured: bool,
}

pub struct PortAnomalyIncident {
    pub timestamp: String,
    pub identity: String,      // the executable identity string that was flagged
    pub proc_name: String,
    pub pid: i32,
    pub port: u16,
}

// Server Edition only.
pub struct EbpfIncidentsSummary {
    pub current_status: ServerQuarantineStatus,
    pub incidents: Vec<EbpfIncidentRecord>,
}

pub struct ServerQuarantineStatus {
    pub is_isolated: bool,
    pub isolation_mode: String,        // "none" | "process" | "host_with_maintenance_ssh" | "host_all"
    pub isolated_pids: Vec<i32>,
    pub isolated_cgroups: Vec<String>,
    pub active_maintenance_ports: Vec<u16>,
    pub whitelist_ips: Vec<String>,
    pub last_action_time: Option<String>,
}

pub struct EbpfIncidentRecord {
    pub event: EbpfAlertEvent,
    pub action_taken: String,          // e.g. "Process Frozen (SIGSTOP) + Network Blocked"
}

pub struct EbpfAlertEvent {
    pub timestamp: String,
    pub priority: String,              // "Debug" | "Informational" | "Notice" | "Warning" | "Error" | "Critical" | "Alert" | "Emergency"
    pub rule: String,
    pub proc_name: Option<String>,
    pub proc_pid: Option<i32>,
    pub proc_cmdline: Option<String>,
    pub container_id: Option<String>,
    pub user_name: Option<String>,
    pub fd_sip: Option<String>,
    pub fd_sport: Option<u16>,
    pub fd_dip: Option<String>,
    pub fd_dport: Option<u16>,
}
```

### `ResourceGuardIncidentsSummary` (Server Edition only)

```rust
pub struct ResourceGuardIncidentsSummary {
    pub incidents: Vec<ResourceGuardIncidentRecord>,
}

pub struct ResourceGuardIncidentRecord {
    pub event: ResourceGuardEvent,
    pub action_taken: String,
}

// Plain snake_case on the wire (mirrors the daemon's persisted
// resource_guard_incidents.json, same exception as PortAnomalyIncidentsSummary).
pub struct ResourceGuardEvent {
    pub timestamp: String,
    pub kind: String,          // "memory_leak_trend" | "crash_loop"
    pub proc_name: Option<String>,
    pub pid: Option<i32>,
    pub unit_or_container: Option<String>,
    pub confidence: String,    // "possible" | "correlated"
    pub matched_signals: Vec<String>,
    pub detail: String,
}
```

### `FileScanGuardStatus` (Server Edition only)

```rust
pub struct FileScanGuardStatus {
    pub clamav_enabled: bool,
    pub scan_dirs: Vec<String>,
    pub scan_interval_secs: u64,
    pub freshclam_interval_secs: u64,
    pub quarantine: QuarantineStatus,
}
```

### `TimelineEvent` (EXPERIMENTAL — `get_incident_timeline`)

```rust
// Plain snake_case on the wire. `source` / `resolution` are kept as strings
// so a future source kind never fails deserialization.
pub struct TimelineEvent {
    pub id: String,
    pub timestamp: String,     // RFC 3339
    pub source: String,        // "link_guard" | "canary" | "ebpf_guard" | "resource_guard"
    pub severity: String,
    pub summary: String,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub process_ancestry: Vec<ProcessAncestor>,  // #[serde(default)]
    pub attack_technique: Option<AttackTechnique>,
    pub action_taken: Option<String>,
    pub containment_latency_ms: Option<u64>,
    pub resolved_at: Option<String>,
    pub resolution: Option<String>,  // "released" | "auto_timeout" | "allowlisted", or None while open
}

pub struct ProcessAncestor {
    pub pid: u32,
    pub name: Option<String>,
}

pub struct AttackTechnique {
    pub id: String,    // MITRE ATT&CK technique id, e.g. "T1486"
    pub name: String,
}
```

### `SecretPathAuditResult` (`audit_secrets_path`)

```rust
// `Directory` is tried first — only it carries `filesScanned`. A single
// file returns the same shape as a text audit (`SecretAuditResult`, already
// documented above).
#[serde(untagged)]
pub enum SecretPathAuditResult {
    Directory(SecretDirectoryAuditResult),
    File(SecretAuditResult),
}

pub struct SecretDirectoryAuditResult {
    pub files_scanned: usize,
    pub has_leaks: bool,
    pub finding_count: usize,
    pub flagged_files: Vec<SecretFileFindings>,
    pub summary: String,
}

pub struct SecretFileFindings {
    pub path: String,
    pub findings: Vec<SecretFinding>,  // same type SecretAuditResult uses
}
```

### Client Edition runtime status (`vpn_status`, `link_guard_status`, `air_gap_status`, `sharing_services_status`, `bluetooth_guard_status`, `usb_guard_status`)

Every one of these six carries a localized `summary` and `caveats`, plus `daemon_running` — when `false`, what's reported is the last saved state / configured value and may not actually be enforced.

```rust
pub struct VpnStatusSummary {
    pub daemon_running: bool,
    pub vpn_on_untrusted_enabled: bool,
    pub backend: String,       // "wireguard" | "tailscale"
    pub active_level: Option<String>,
    pub tunnel_expected_now: bool,  // the daemon only brings the tunnel up at the "lockdown" level
    pub tunnel_up: bool,
    pub kill_switch_armed: bool,
    pub kill_switch_verified: Option<bool>,  // the nftables table is actually loaded; root only
    pub wireguard: WireGuardRuntime,
    pub tailscale: TailscaleRuntime,
    pub summary: String,
    pub caveats: Vec<String>,
}

pub struct WireGuardRuntime {
    pub tools_present: bool,
    pub config_imported: Option<bool>,  // None when /etc/wireguard isn't readable by the caller
    pub interface_up: bool,
    pub armed: bool,
    pub config_name: Option<String>,
    pub endpoint: Option<String>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub last_handshake_age_secs: Option<u64>,  // root only
}

pub struct TailscaleRuntime {
    pub tools_present: bool,
    pub running: bool,
    pub logged_in: bool,
    pub tailnet_name: Option<String>,
    pub active_exit_node: Option<String>,
    pub configured_exit_node: String,
    pub exit_node_candidate_count: usize,
    pub armed: bool,
}

pub struct LinkGuardStatusSummary {
    pub daemon_running: bool,
    pub enabled: bool,
    pub mode: String,               // configured: "off" | "warn" | "block"
    pub effective_mode: String,     // "off" whenever enabled is false, otherwise mode
    pub allowlist: Vec<String>,
    pub blocklist_extra: Vec<String>,
    pub use_threat_dns: bool,
    pub xdp_boot_gate_enabled: bool,
    pub pending_decisions: Vec<PendingApproval>,
    pub recent_events: Vec<LinkGuardEvent>,  // last 7 days, newest first, max 50
    pub summary: String,
    pub caveats: Vec<String>,
}

// An entry of the daemon's user-approval queue (held Link Guard connection,
// unapproved USB device, ...) — shared with UsbGuardStatusSummary below.
pub struct PendingApproval {
    pub id: String,
    pub kind: String,          // "link_warn", "link_block", "usb_keyboard", "usb_storage", ...
    pub title: String,
    pub body: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub created_at_ms: u64,
}

pub struct LinkGuardEvent {
    pub timestamp: String,
    pub kind: String,          // "blocked" | "held" | "warned" | "dnsWarned"
    pub kind_label: String,
    pub title: String,
    pub body: String,
}

pub struct AirGapStatusSummary {
    pub daemon_running: bool,
    pub active: bool,
    pub engaged_at_unix: Option<u64>,
    pub active_for_secs: Option<u64>,
    pub auto_release_after_secs: u64,
    pub trigger_reason: Option<String>,  // e.g. "arp_spoof" | "canary_tamper"
    pub trigger: Option<serde_json::Value>,  // the raw trigger record the daemon saved when Air-Gap engaged
    pub auto_rfkill_enabled: bool,
    pub frozen_processes: Vec<FrozenProcessView>,
    pub summary: String,
    pub caveats: Vec<String>,
}

pub struct FrozenProcessView {
    pub pid: u32,
    pub name: String,
    pub reason: String,   // "ransomware_burst" | "canary_tamper" | "kernel_exploit" | "ebpf_guard" | "manual"
    pub reason_label: String,
    pub frozen_at: String,
}

pub struct SharingServicesStatusSummary {
    pub daemon_running: bool,
    pub control_enabled: bool,
    pub active_level: Option<String>,
    pub stops_services_on_current_level: Option<bool>,
    pub stopped_by_roamswitch: Option<Vec<String>>,  // None when the daemon's record isn't readable by the caller
    pub services: Vec<SharingServiceUnit>,
    pub summary: String,
    pub caveats: Vec<String>,
}

pub struct SharingServiceUnit {
    pub unit: String,
    pub active_state: String,  // systemd ActiveState
    pub is_active: bool,
    pub stopped_by_roamswitch: bool,
}

pub struct BluetoothGuardStatusSummary {
    pub daemon_running: bool,
    pub guard_enabled: bool,
    pub active_level: Option<String>,
    pub network_trusted: Option<bool>,
    pub shield_active_now: bool,
    pub controller: BluetoothStatus,
    pub summary: String,
    pub caveats: Vec<String>,
}

pub struct BluetoothStatus {
    pub is_available: bool,
    pub is_powered: bool,
    pub is_discoverable: bool,
    pub connected_devices_count: usize,
    pub connected_devices: Vec<String>,
    pub is_shielded_on_untrusted: bool,  // mirrors the Bluetooth Guard setting
}

pub struct UsbGuardStatusSummary {
    pub daemon_running: bool,
    pub storage_guard_enabled: bool,
    pub keyboard_guard_enabled: bool,  // BadUSB guard — suppresses input via evdev EVIOCGRAB, never kernel de-authorization
    pub usb_zero_trust_enabled: bool,
    pub usb_zero_trust_active: Option<bool>,
    pub connected_devices: Vec<UsbDeviceInfo>,
    pub allowed_devices: Vec<AllowedUsbDevice>,
    pub pending_approvals: Vec<PendingApproval>,
    pub summary: String,
    pub caveats: Vec<String>,
}

pub struct UsbDeviceInfo {
    pub device_identifier: String,
    pub display_name: String,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub serial_number: Option<String>,
    pub is_storage: bool,
    pub is_keyboard: bool,
    pub is_pointer: bool,   // #[serde(default)]
    pub is_hub: bool,       // #[serde(default)]
    pub is_authorized: bool,
}

pub struct AllowedUsbDevice {
    pub device_identifier: String,
    pub display_name: String,
    pub date_added: String,
}
```

### `RoamSwitchClientError`

```rust
pub enum RoamSwitchClientError {
    AppNotInstalled,
    ServerBinaryNotFound(String),
    ProcessLaunchFailed(String),
    NoResponse,
    TimedOut,
    InvalidResponse(String),
    ToolError(String),
}
```

`AppNotInstalled` is the case to handle explicitly — it's the expected outcome whenever the user doesn't have RoamSwitch. The rest are edge cases (corrupt install, unexpected server behavior) worth logging but rarely worth distinct UI.

## Correct usage pattern

```rust
match RoamSwitchClient::new(None, None) {
    Ok(client) => match client.security_report().await {
        Ok(report) => { /* use report */ }
        Err(roamswitch_linux_kit::RoamSwitchClientError::AppNotInstalled) => {
            // expected when RoamSwitch isn't installed — hide/disable the feature, don't alert as an error
        }
        Err(e) => { /* genuinely unexpected — log it */ }
    },
    Err(_) => { /* same as AppNotInstalled for construction-time failures */ }
}
```

## Performance notes for generated code

Each call spawns a subprocess and exits it — there is no way to keep a connection warm, and none is needed for occasional queries. Do not call these methods in a tight loop or a per-request hot path. `exposed_ports()` is the slowest of these (each externally-exposed port is individually probed) and can take a few seconds if several ports are open — always `.await` it from an async context, never block on it synchronously.

`RoamSwitchClient` holds no interior mutability beyond its own config (executable path, timeout) and no persistent connection, so a single instance can be shared across concurrent tasks (e.g. behind an `Arc`) or a fresh one created per call — both are cheap and safe.
