# roamswitch-linux-kit

A read-only async Rust client for [RoamSwitch](https://lafine.net)'s local Linux network security diagnostics.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://lafine.net/linux.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

This is the Linux counterpart to [RoamSwitchKit](https://github.com/lafine1211/RoamSwitchKit) (macOS/Swift) — same read-only design, same zero-telemetry guarantee, wrapped for Rust instead of Swift.

## What is RoamSwitch?

[**RoamSwitch**](https://lafine.net/linux.html) is a Linux network security tool that automatically defends your machine's network boundary — tightening `nft` rules on untrusted networks, watching for ARP spoofing, and flagging dev servers or databases you forgot are listening on `0.0.0.0`. It ships as a free Community Edition, with a paid Business tier for fleet management.

Concretely, RoamSwitch continuously computes:

- **Network trust** — is the current network one you've marked trusted, and what security level is currently active
- **ARP spoofing** — gateway MAC fingerprint changes that indicate a man-in-the-middle attempt
- **Exposed ports** — every TCP port listening beyond `localhost`, cross-referenced against a database of commonly-misconfigured services (Redis, MongoDB, Docker, Memcached, dev servers, local AI inference servers like Ollama/LM Studio) and probed for risky HTTP responses
- **A local security posture score** — disk encryption, AppArmor, firewall (`nft`) state, Wi-Fi encryption, ARP status, exposed ports, kernel hardening, and guard configuration
- **Offline URL/phishing analysis**, **secret-leak scanning**, **security log auditing**, **ransomware canary status**, and **quarantine vault status**

RoamSwitch already exposes this same data to AI assistants (Claude Desktop, Claude Code, and other [MCP](https://modelcontextprotocol.io)-compatible clients) via a bundled read-only MCP server binary, `roamswitch-mcp` — see [lafine.net/mcp-setup](https://lafine.net/mcp-setup.html). **This crate is the same interface, wrapped for Rust code instead of an AI client**: it lets your own Linux app or script ask "is this machine's network safe right now?" and get back the exact data RoamSwitch itself computed, without reimplementing ARP inspection, port scanning, or log auditing yourself.

Typical uses: a sync app pausing background transfers on an untrusted network, a CI runner failing a job when it detects an unexpectedly exposed dev server, a fleet-monitoring script collecting security scores across machines, or an automation workflow that reacts to network trust changes.

## Design principles

- **Read-only, always.** This crate can query RoamSwitch's current diagnostics. It has no API to change RoamSwitch's security level, toggle a guard, isolate a port, quarantine a file, or freeze a process — that surface simply doesn't exist here. Any app linking this crate has no way to alter another user's protection state; only RoamSwitch's own CLI, driven by the user, can do that. This is a deliberate scope limit, not a v1 gap.
- **Fully local, zero telemetry.** Every call launches RoamSwitch's bundled `roamswitch-mcp` binary as a subprocess and talks to it over stdio. There is no network I/O anywhere in this crate's code — nothing is sent anywhere, by this crate or by RoamSwitch itself. (`run_active_vuln_scan` is the one exception worth knowing about: it makes real TCP connections, but only ever to `127.0.0.1`, and only when explicitly opted in via RoamSwitch's own config — see below.)
- **No new attack surface.** This crate doesn't open a socket, register a service, or listen for anything. It spawns a process, writes a request to its stdin, reads one response from its stdout, and lets the process exit.
- **Not the same thing as `roamswitch-daemon`'s control socket.** RoamSwitch on Linux also runs a privileged daemon listening on a local Unix socket for CLI commands — that socket is a general control plane (it can enable Air-Gap isolation, freeze a process, manage USB device approvals, etc.) and is intentionally out of scope for a public, read-only SDK. This crate only ever talks to the diagnostics-only `roamswitch-mcp` binary, which is architecturally incapable of mutating anything: it never opens the daemon socket and needs no elevated privileges.

## Requirements

- Rust 1.75+ (async, `tokio` runtime)
- [RoamSwitch for Linux](https://lafine.net/linux.html) installed on the machine your code runs on, with `roamswitch-mcp` on `PATH` (typically `/usr/bin/roamswitch-mcp` from the official `.deb`/`.rpm` package)

## Installation

Not yet published to crates.io — add it as a git dependency in your `Cargo.toml`:

```toml
[dependencies]
roamswitch-linux-kit = { git = "https://github.com/lafine1211/roamswitch-linux-kit", tag = "v0.1.0" }
```

## Usage

```rust
use roamswitch_linux_kit::RoamSwitchClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RoamSwitchClient::new(None, None)?;

    // Full security audit (disk encryption, AppArmor, firewall, Wi-Fi
    // encryption, ARP spoofing, exposed ports — scored 0-100 with per-item
    // recommendations for anything failing).
    let report = client.security_report().await?;
    println!("{} ({})", report.score, report.grade);

    // Every port listening beyond localhost, audited for known-dangerous
    // services and risky HTTP responses.
    let ports = client.exposed_ports(false).await?;
    for port in ports.ports.iter().filter(|p| p.overall_risk.as_deref() == Some("high")) {
        println!("{} on port {}", port.process_name, port.port);
    }

    // Whether RoamSwitch's optional auto-response guards are turned on, and
    // whether the current network is in the user's trusted list.
    let status = client.guard_status().await?;
    println!("{} {}", status.active_security_level_label, status.is_current_network_trusted);

    // Inspect email links, shortened URLs, or suspicious web domains for
    // phishing, Unicode homograph spoofing, and brand imitation (Zero Telemetry).
    let url_report = client.audit_url_safety("https://apple.com.login-verify.xyz").await?;
    println!("{} {}", url_report.score, url_report.risk_level); // e.g. 20, "dangerous"

    Ok(())
}
```

All calls are `async` and return `Result<_, RoamSwitchClientError>` — most commonly `.AppNotInstalled` if RoamSwitch isn't present. Handle that case gracefully (e.g. hide the feature, or point the user to lafine.net) rather than treating it as fatal.

## How it works

`RoamSwitchClient` doesn't talk to a running RoamSwitch process directly. Each call:

1. Resolves `roamswitch-mcp`'s location — a binary sitting next to your own executable, or `/usr/bin/roamswitch-mcp` / `/usr/local/bin/roamswitch-mcp` from the official package — unless you pass an explicit path to `RoamSwitchClient::new`.
2. Launches that binary as a fresh subprocess.
3. Sends a `tools/call` request as newline-delimited JSON-RPC 2.0 over the subprocess's stdin — the same protocol RoamSwitch speaks to Claude Desktop/Code and other MCP clients.
4. Reads the matching response line from stdout, deserializes its JSON payload into a typed Rust struct, and lets the subprocess exit.

This is stateless by design: no persistent connection, no daemon, nothing left running between calls. Each method call has its own subprocess lifetime, which also means calls have process-launch overhead (tens of milliseconds) plus whatever the diagnostic itself takes — `exposed_ports()` in particular can take a couple of seconds if there are several externally-exposed ports to audit, since each is probed individually.

`RoamSwitchClient` holds no interior mutability beyond its own config, so a single instance can be shared (e.g. behind an `Arc`) and called concurrently from multiple tasks — each call spawns its own independent subprocess.

## API reference

### `RoamSwitchClient`

```rust
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
}
```

- `new(executable_path, timeout)` — `executable_path: None` searches standard install locations; `timeout` defaults to 30s. On expiry the subprocess is killed (dropped) and the call returns `.TimedOut`.
- `security_report()` / `server_security_report()` — full local audit; the latter runs the Server Edition's 28-check profile (kernel hardening, container isolation, kernel CVE exposure, eBPF LSM) instead of the desktop client's 24 checks.
- `exposed_ports(include_local_only)` — lists listening TCP ports. Ports exposed beyond localhost are always fully audited; pass `true` to also include localhost-only ports (returned without the slower per-port audit).
- `run_active_vuln_scan()` — opt-in, non-destructive reachability verification against `127.0.0.1` only. Returns `enabled: false` and no findings unless the user has set `active_vuln_scan_enabled: true` in RoamSwitch's own config.
- `guard_status()` — current active security level, trusted-network status, and each optional guard's on/off state.
- `audit_url_safety(url)` — analyzes a URL for phishing, Unicode homograph spoofing, brand subdomain deception, and high-risk TLDs (Zero Telemetry, no network fetch of the URL itself).
- `audit_secrets(text)` — scans text for exposed API keys/secrets.
- `audit_security_logs(hours)` — summarizes sudo/SSH/firewall/AppArmor/ClamAV log activity over the trailing window.
- `get_app_help(query, topic)` — full-text search over RoamSwitch's offline knowledge base.
- `quarantine_status()` / `canary_status()` — malware quarantine vault state / Ransomware Canary Guard state.

### `SecurityReport`

| Field | Type | Description |
|---|---|---|
| `score` | `i32` | 0–100 overall score |
| `grade` | `String` | Letter grade derived from `score` |
| `total_checks` | `i32` | Number of audit items |
| `passed_checks` | `i32` | Number of items that passed |
| `items` | `Vec<SecurityAuditItem>` | One entry per check |
| `caveats` | `Vec<String>` | Notes on anything this tool couldn't fully verify |

`SecurityAuditItem`: `category`, `title`, `is_passed: bool`, `status_text`, `detail`, `recommendation`, `settings_url: Option<String>`, `is_applicable: bool`, `fix_action: Option<String>` (a token identifying a one-click remediation, when one exists).

### `ExposedPorts`

`ExposedPorts { is_firewall_shielded: bool, ports: Vec<ExposedPort> }`.

`ExposedPort`: `process_name`, `pid: i32`, `port: i32`, `is_globally_exposed: bool`, `executable_path: Option<String>`, `audit_performed: bool`, `overall_risk: Option<String>` (`"low"`/`"medium"`/`"high"`/`"critical"`, present only when audited), `findings: Vec<PortFinding>`, `http_headers: Option<HashMap<String, String>>`, `is_dev_server: bool`, `is_isolated: bool`.

`PortFinding`: `title`, `risk_level: String`, `description`, `recommendation`.

### `GuardStatus`

`GuardStatus { active_security_level, active_security_level_label, is_current_network_trusted: bool, guards: Vec<GuardEntry>, caveats: Vec<String> }`.

`GuardEntry`: `key: String`, `enabled_in_settings: bool`. Known keys: `portAnomalyGuard`, `arpSpoofAutoContainment`, `usbStorageGuard`, `webMailDownloadGuard`, `dnsThreatGuard`, `ransomwareCanaryGuard`, `devServerIsolator`, `bluetoothGuard`.

### `LinkAuditReport`

`LinkAuditReport { original_url, final_url, redirect_chain: Vec<String>, domain, score: i32, risk_level, is_https: bool, risk_factors: Vec<LinkRiskFactor>, verdict: Verdict }`.

`LinkRiskFactor`: `title`, `detail`, `is_severe: bool`. `Verdict` is `Allow` / `Warn` / `Block` — the actual enforcement decision RoamSwitch's inline link filter would make (`risk_level` above is for display).

### `RoamSwitchClientError`

| Variant | Meaning |
|---|---|
| `AppNotInstalled` | No `roamswitch-mcp` binary found in any standard location |
| `ServerBinaryNotFound(path)` | An explicit path was given but nothing exists there |
| `ProcessLaunchFailed(msg)` | The subprocess itself failed to launch, or its stdio pipes failed |
| `NoResponse` | The subprocess's stdout closed before a response arrived |
| `TimedOut` | The subprocess didn't respond within the timeout |
| `InvalidResponse(msg)` | A response was received but wasn't valid/expected JSON |
| `ToolError(msg)` | The server returned a JSON-RPC error |

## Compatibility note

The JSON returned by RoamSwitch's diagnostic tools is the actual contract between this crate and the app. [`src/models.rs`](src/models.rs) mirrors that shape independently — this crate is a separate, public repository from the private `roamswitch-linux` repo, so it can't share Rust types directly. If a future RoamSwitch release changes a response shape, these models are updated to match in lockstep; pin a version if that matters to you.

## License

MIT — see [LICENSE](LICENSE).
