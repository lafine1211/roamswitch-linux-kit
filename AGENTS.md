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

### `SecretAuditResult`, `SecurityLogSummary`, `KnowledgeSearchResult`, `QuarantineStatus`, `CanaryStatus`, `ActiveVulnScanResult`, `PackageCveScanResult`, `PackageCveScanLanguagesResult`, `FimReport`

See [`src/models.rs`](src/models.rs) for the complete field list of these nine bonus response types (beyond the four macOS RoamSwitchKit also has) — field names follow the same `snake_case`-Rust / `camelCase`-wire convention as everything above, **except `FimReport`/`FimViolation`, which are plain snake_case on the wire too** (no `camelCase` rename — that's the actual JSON `verify_fim` sends, not an inconsistency to "fix").

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
