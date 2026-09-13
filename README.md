# roamswitch-linux-kit

**English** | [日本語](README.ja.md)

A read-only async Rust client for [RoamSwitch](https://lafine.net)'s local Linux network security diagnostics.

[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://lafine.net/linux.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

This is the Linux counterpart to [RoamSwitchKit](https://github.com/lafine1211/RoamSwitchKit) (macOS/Swift) — same read-only design, same zero-telemetry guarantee, wrapped for Rust instead of Swift.

## What is RoamSwitch?

[**RoamSwitch**](https://lafine.net/linux.html) is a Linux network security tool that automatically defends your machine's network boundary — tightening `nft` rules on untrusted networks, watching for ARP spoofing, and flagging dev servers or databases you forgot are listening on `0.0.0.0`. It ships today as a free Community Edition.

Concretely, RoamSwitch continuously computes:

- **Network trust** — is the current network one you've marked trusted, and what security level is currently active
- **ARP spoofing** — gateway MAC fingerprint changes that indicate a man-in-the-middle attempt
- **Exposed ports** — every TCP port listening beyond `localhost`, cross-referenced against a database of commonly-misconfigured services (Redis, MongoDB, Docker, Memcached, dev servers, local AI inference servers like Ollama/LM Studio) and probed for risky HTTP responses
- **A local security posture score** (24 checks) — LUKS/dm-crypt disk encryption, AppArmor/SELinux, UEFI Secure Boot, sudo/SSH configuration, kernel `sysctl` hardening, Wi-Fi encryption, ARP spoofing, exposed ports, and malware/download guard configuration
- **Offline URL/phishing analysis**, **secret-leak scanning**, **security log auditing**, **ransomware canary status**, and **quarantine vault status**
- **Guard runtime state** — VPN tunnel + kill-switch, passive Link Guard block/warn history, Air-Gap and frozen processes, sharing services, Bluetooth and USB guards

RoamSwitch already exposes this same data to AI assistants (Claude Desktop, Claude Code, and other [MCP](https://modelcontextprotocol.io)-compatible clients) via a bundled read-only MCP server binary, `roamswitch-mcp` — see [lafine.net/mcp-setup](https://lafine.net/mcp-setup.html). **This crate is the same interface, wrapped for Rust code instead of an AI client**: it lets your own Linux app or script ask "is this machine's network safe right now?" and get back the exact data RoamSwitch itself computed, without reimplementing ARP inspection, port scanning, or log auditing yourself.

Typical uses: a sync app pausing background transfers on an untrusted network, a CI runner failing a job when it detects an unexpectedly exposed dev server, a fleet-monitoring script collecting security scores across machines, or an automation workflow that reacts to network trust changes.

## Design principles

- **Read-only, always.** This crate can query RoamSwitch's current diagnostics. It has no API to change RoamSwitch's security level, toggle a guard, isolate a port, quarantine a file, or freeze a process — that surface simply doesn't exist here. Any app linking this crate has no way to alter another user's protection state; only RoamSwitch's own CLI, driven by the user, can do that. This is a deliberate scope limit, not a v1 gap.
- **Fully local, zero telemetry.** Every call launches RoamSwitch's bundled `roamswitch-mcp` binary as a subprocess and talks to it over stdio. There is no network I/O anywhere in this crate's code — nothing is sent anywhere, by this crate or by RoamSwitch itself. (`run_active_vuln_scan` is the one exception worth knowing about: it makes real TCP connections, but only ever to `127.0.0.1`, and only when explicitly opted in via RoamSwitch's own config — see below.)
- **No new attack surface.** This crate doesn't open a socket, register a service, or listen for anything. It spawns a process, writes a request to its stdin, reads one response from its stdout, and lets the process exit.
- **Not the same thing as `roamswitch-daemon`'s control socket.** RoamSwitch on Linux also runs a privileged daemon listening on a local Unix socket for CLI commands — that socket is a general control plane (it can enable Air-Gap isolation, freeze a process, manage USB device approvals, etc.) and is intentionally out of scope for a public, read-only SDK. This crate only ever talks to the diagnostics-only `roamswitch-mcp` binary, which is architecturally incapable of mutating anything: it never opens the daemon socket and needs no elevated privileges.

## Requirements

- A recent stable Rust toolchain (2021 edition; built and tested against 1.98) with the `tokio` async runtime
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

    // Installed OS packages checked against a local, network-free CVE map.
    let pkg_cve = client.package_cve_scan().await?;
    for finding in &pkg_cve.findings {
        println!("{} {}: {} (CVSS {})", finding.package, finding.installed_version, finding.cve_id, finding.cvss_score);
    }

    // Critical Path FIM: re-hashes ~150 critical system files/binaries and
    // compares against the persisted baseline (errors if no baseline has
    // ever been captured on this host via `sudo roamswitch fim update`).
    if let Ok(fim) = client.verify_fim().await {
        println!("FIM: {} monitored, healthy={}", fim.total_monitored, fim.is_healthy);
    }

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
    pub async fn package_cve_scan(&self) -> Result<PackageCveScanResult, RoamSwitchClientError>;
    pub async fn package_cve_scan_languages(&self, watched_folders: &[PathBuf]) -> Result<PackageCveScanLanguagesResult, RoamSwitchClientError>;
    pub async fn verify_fim(&self) -> Result<FimReport, RoamSwitchClientError>;
    pub async fn get_port_anomaly_incidents(&self) -> Result<PortAnomalyIncidentsSummary, RoamSwitchClientError>;
    pub async fn get_ebpf_incidents(&self) -> Result<EbpfIncidentsSummary, RoamSwitchClientError>;
    pub async fn get_resource_guard_incidents(&self) -> Result<ResourceGuardIncidentsSummary, RoamSwitchClientError>;
    pub async fn get_file_scan_guard_status(&self) -> Result<FileScanGuardStatus, RoamSwitchClientError>;
    pub async fn notification_history(&self) -> Result<Vec<NotificationHistoryEntry>, RoamSwitchClientError>;
    pub async fn get_incident_timeline(&self) -> Result<Vec<TimelineEvent>, RoamSwitchClientError>;
    pub async fn audit_secrets_path(&self, path: &Path) -> Result<SecretPathAuditResult, RoamSwitchClientError>;
    pub async fn vpn_status(&self) -> Result<VpnStatusSummary, RoamSwitchClientError>;
    pub async fn link_guard_status(&self) -> Result<LinkGuardStatusSummary, RoamSwitchClientError>;
    pub async fn air_gap_status(&self) -> Result<AirGapStatusSummary, RoamSwitchClientError>;
    pub async fn sharing_services_status(&self) -> Result<SharingServicesStatusSummary, RoamSwitchClientError>;
    pub async fn bluetooth_guard_status(&self) -> Result<BluetoothGuardStatusSummary, RoamSwitchClientError>;
    pub async fn usb_guard_status(&self) -> Result<UsbGuardStatusSummary, RoamSwitchClientError>;
}
```

Every one of `roamswitch-mcp`'s 25 read-only tools is covered (`audit_secrets` twice: `audit_secrets` for text, `audit_secrets_path` for a file or directory). Human-readable text in the responses — titles, details, recommendations, summaries, caveats — follows the language the user selected in RoamSwitch (10 languages; the OS locale when unset). Machine-readable fields (`risk_level`, `verdict`, `kind`, `mode`, ...) never change with the language.

- `new(executable_path, timeout)` — `executable_path: None` searches standard install locations; `timeout` defaults to 30s. On expiry the subprocess is killed (dropped) and the call returns `.TimedOut`.
- `security_report()` / `server_security_report()` — full local audit; the latter runs the Server Edition's 30-check profile (kernel hardening, container isolation, kernel CVE exposure, eBPF LSM) instead of the desktop client's 24 checks.
- `exposed_ports(include_local_only)` — lists listening TCP ports. Ports exposed beyond localhost are always fully audited; pass `true` to also include localhost-only ports (returned without the slower per-port audit).
- `run_active_vuln_scan()` — opt-in, non-destructive reachability verification against `127.0.0.1` only. Returns `enabled: false` and no findings unless the user has set `active_vuln_scan_enabled: true` in RoamSwitch's own config.
- `guard_status()` — current active security level, trusted-network status, and each optional guard's on/off state.
- `audit_url_safety(url)` — analyzes a URL for phishing, Unicode homograph spoofing, brand subdomain deception, and high-risk TLDs (Zero Telemetry, no network fetch of the URL itself).
- `audit_secrets(text)` — scans text for exposed API keys/secrets.
- `audit_security_logs(hours)` — summarizes sudo/SSH/firewall/AppArmor/ClamAV log activity over the trailing window.
- `get_app_help(query, topic)` — full-text search over RoamSwitch's offline knowledge base.
- `quarantine_status()` / `canary_status()` — malware quarantine vault state / Ransomware Canary Guard state.
- `package_cve_scan()` — audits installed OS packages (dpkg/pacman/rpm, auto-detected) against RoamSwitch's local, network-free CVE map.
- `package_cve_scan_languages(watched_folders)` — audits language-ecosystem lockfiles (npm/PyPI/crates.io/etc.) under the given folders against the same local CVE map.
- `verify_fim()` — read-only Critical Path FIM verification (~150 critical system files re-hashed and compared against the persisted baseline). Does not update or initialize the baseline — that requires root and is intentionally not exposed here. Errors if no baseline has ever been captured on this host.
- `get_port_anomaly_incidents()` — Port Anomaly Guard's incident log: newly-appearing, externally-exposed listening executables (backdoors, C2 listeners, accidentally-`0.0.0.0` dev servers) that were auto-blocked, with timestamp/process/PID/port for each.
- `get_ebpf_incidents()` — Server Edition only. eBPF Runtime Guard's containment history: each alert that actually triggered process isolation, a freeze, or a full host Air-Gap lockdown, plus the current containment status. This is the primary trigger reason behind an Air-Gap lockdown, which no other tool exposes — useful for offline triage right after one fires, since this crate never touches the network either.
- `get_resource_guard_incidents()` — Server Edition only. Resource Exhaustion / Process Anomaly Guard's incident log: network-exposed services flagged for sustained, non-recovering RSS growth or crash-looping, each with a confidence tier (`"possible"` vs `"correlated"`). A `"possible"` entry is not necessarily an attack.
- `get_file_scan_guard_status()` — Server Edition only. File Scan Guard's configuration (ClamAV enabled, scanned directories, scan / freshclam intervals) and the quarantine vault it feeds into.
- `notification_history()` — notifications RoamSwitch sent over the past 7 days (timestamp, title, body), most recent first.
- `get_incident_timeline()` — EXPERIMENTAL. One chronological timeline correlating Link Guard, the Ransomware Canary, the eBPF Runtime Guard and the Resource Guard (most recent 50), with process ancestry, MITRE ATT&CK tags where confidently mappable, containment latency where measured, and resolution status.
- `audit_secrets_path(path)` — scans a file, or a directory recursively (skipping `.git` / `node_modules` / `target` / `vendor` / `dist` / `build` / `__pycache__` / `venv`, and files over 2MB or that look binary). The path is read by `roamswitch-mcp` with your own privileges.
- `vpn_status()` — Client Edition. "VPN on untrusted networks": enabled, backend (WireGuard / Tailscale), whether the tunnel should be up at the current level (RoamSwitch only brings it up at `lockdown`), whether it is up, and whether the leak-blocking kill-switch is armed.
- `link_guard_status()` — Client Edition. Passive Link Guard mode (`off` / `warn` / `block`), allow-list and extra block-list, connections waiting for the user's decision, and block / warn events from the last 7 days.
- `air_gap_status()` — Client Edition. Whether emergency Air-Gap isolation is active, since when, what triggered it, and every process RoamSwitch currently holds frozen with SIGSTOP. It never lifts Air-Gap or resumes a process.
- `sharing_services_status()` — Client Edition. Automatic SSH / Samba / remote-desktop control: setting, units RoamSwitch has stopped and will restore, and each installed unit's systemd state.
- `bluetooth_guard_status()` — Client Edition. Bluetooth Guard setting and the controller's live state (powered, discoverable, connected devices).
- `usb_guard_status()` — Client Edition. USB storage / BadUSB keyboard guard settings, connected USB devices, the allow-list, and devices waiting for approval.

The six Client Edition status methods are built from files the RoamSwitch daemon already makes world-readable (plus sysfs / procfs and read-only CLI queries) — `roamswitch-mcp` still never opens the daemon's control socket. Each returns `daemon_running`; when it's `false` the values are the last saved state or the configured setting and may not actually be enforced. The two facts that need root (the nftables kill-switch table actually being loaded, and the WireGuard handshake age) are `None` unless the caller is root.

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

`GuardStatus { active_security_level, active_security_level_label, is_current_network_trusted: bool, guards: Vec<GuardEntry>, caveats: Vec<String>, settings: Option<GuardSettings> }`.

`GuardEntry`: `key: String`, `enabled_in_settings: bool`. Known keys: `portAnomalyGuard`, `arpSpoofAutoContainment`, `usbStorageGuard`, `usbKeyboardGuard`, `usbZeroTrust`, `webMailDownloadGuard`, `clamavScan`, `dnsThreatGuard`, `ransomwareCanaryGuard`, `devServerIsolator`, `bluetoothGuard`, `linkGuard`, `vpnOnUntrusted`, `gatewayArpLock`, `yamaMemoryProtect`, `systemWideFanotify`, `preExecBlocking`, `entropyFreeze`, `mountHardening`, `sharingServiceControl`, `clickfixClipboardGuard`, `activeVulnScan`. Treat unknown keys as forward-compatible additions.

`GuardSettings { link_guard_mode, vpn_backend, dns_scope, dns_provider }` — `None` from older `roamswitch-mcp` builds.

### `QuarantineStatus`

`QuarantineStatus { item_count: usize, items: Vec<QuarantineItem>, quarantine_directory, exclusion_paths: Vec<String>, clamav: Option<ClamAvDatabaseInfo> }`. `ClamAvDatabaseInfo` (plain snake_case on the wire): `is_installed: bool`, `engine_version`, `database_version`, `last_updated`, `is_up_to_date: bool`.

### `LinkAuditReport`

`LinkAuditReport { original_url, final_url, redirect_chain: Vec<String>, domain, score: i32, risk_level, is_https: bool, risk_factors: Vec<LinkRiskFactor>, verdict: Verdict }`.

`LinkRiskFactor`: `title`, `detail`, `is_severe: bool`. `Verdict` is `Allow` / `Warn` / `Block` — the actual enforcement decision RoamSwitch's inline link filter would make (`risk_level` above is for display).

### `PackageCveScanResult` / `PackageCveScanLanguagesResult`

`PackageCveScanResult { map_installed: bool, map_version: String, findings: Vec<PackageCveFinding> }` — `map_installed: false` means "no local CVE data yet", distinct from "ran, found nothing".

`PackageCveScanLanguagesResult { scanned_folder_count: usize, findings: Vec<PackageCveFinding> }`.

### `PortAnomalyIncidentsSummary`

`PortAnomalyIncidentsSummary { incidents: Vec<PortAnomalyIncident>, auto_isolated_ports: Vec<u16>, user_isolated_ports: Vec<u16>, baseline_captured: bool }`. Field names here are plain snake_case (not camelCase like most other types here), matching `FimReport`/`FimViolation` — this mirrors the wire format of an existing on-disk state file the daemon already writes, not a shape we're free to name however we like.

`PortAnomalyIncident`: `timestamp`, `identity` (the executable identity string that was flagged), `proc_name`, `pid: i32`, `port: u16`.

### `EbpfIncidentsSummary`

Server Edition only. `EbpfIncidentsSummary { current_status: ServerQuarantineStatus, incidents: Vec<EbpfIncidentRecord> }`.

`ServerQuarantineStatus`: `is_isolated: bool`, `isolation_mode` (`"none"` / `"process"` / `"host_with_maintenance_ssh"` / `"host_all"`), `isolated_pids: Vec<i32>`, `isolated_cgroups: Vec<String>`, `active_maintenance_ports: Vec<u16>`, `whitelist_ips: Vec<String>`, `last_action_time: Option<String>`.

`EbpfIncidentRecord`: `event: EbpfAlertEvent`, `action_taken` (e.g. `"Process Frozen (SIGSTOP) + Network Blocked"`, `"Pinpoint Process Isolated"`).

`EbpfAlertEvent`: `timestamp`, `priority` (`"Debug"` / `"Informational"` / `"Notice"` / `"Warning"` / `"Error"` / `"Critical"` / `"Alert"` / `"Emergency"`), `rule`, `proc_name: Option<String>`, `proc_pid: Option<i32>`, `proc_cmdline: Option<String>`, `container_id: Option<String>`, `user_name: Option<String>`, `fd_sip: Option<String>`, `fd_sport: Option<u16>`, `fd_dip: Option<String>`, `fd_dport: Option<u16>`.

`PackageCveFinding`: `ecosystem` (e.g. `"npm"`, `"PyPI"`, `"crates.io"`, or the OS package manager name), `package`, `installed_version`, `cve_id`, `cvss_score: f64`, `fixed_version`, `summary`.

### `FimReport`

`FimReport { total_monitored: usize, passed_count: usize, violations: Vec<FimViolation>, last_checked_at: String, is_healthy: bool, skipped_unreadable: usize }` — `skipped_unreadable` counts baseline entries that couldn't be read due to insufficient privileges (e.g. `/etc/shadow` without root); this is not tampering and doesn't affect `is_healthy`. Field names here are plain snake_case, not camelCase like the other types on this page — that's the actual wire format `roamswitch-mcp` sends for this tool.

`FimViolation`: `path`, `violation_type` (`"modified"` / `"deleted"` / `"permission_changed"` / `"new_file"`), `expected_sha256: Option<String>`, `actual_sha256: Option<String>`, `detected_at`.

### `SecretPathAuditResult`

`enum SecretPathAuditResult { Directory(SecretDirectoryAuditResult), File(SecretAuditResult) }`. `SecretDirectoryAuditResult { files_scanned: usize, has_leaks: bool, finding_count: usize, flagged_files: Vec<SecretFileFindings>, summary }`; `SecretFileFindings { path, findings: Vec<SecretFinding> }`.

### `NotificationHistoryEntry` / `TimelineEvent` / `ResourceGuardIncidentsSummary` / `FileScanGuardStatus`

`NotificationHistoryEntry { timestamp, title, body }` (RFC 3339 timestamp).

`TimelineEvent` (plain snake_case on the wire): `id`, `timestamp`, `source` (`"link_guard"` / `"canary"` / `"ebpf_guard"` / `"resource_guard"`), `severity`, `summary`, `process_name: Option<String>`, `process_pid: Option<u32>`, `process_ancestry: Vec<ProcessAncestor { pid, name }>`, `attack_technique: Option<AttackTechnique { id, name }>`, `action_taken: Option<String>`, `containment_latency_ms: Option<u64>`, `resolved_at: Option<String>`, `resolution: Option<String>` (`"released"` / `"auto_timeout"` / `"allowlisted"`).

`ResourceGuardIncidentsSummary { incidents: Vec<ResourceGuardIncidentRecord { event: ResourceGuardEvent, action_taken }> }` (plain snake_case). `ResourceGuardEvent`: `timestamp`, `kind` (`"memory_leak_trend"` / `"crash_loop"`), `proc_name: Option<String>`, `pid: Option<i32>`, `unit_or_container: Option<String>`, `confidence` (`"possible"` / `"correlated"`), `matched_signals: Vec<String>`, `detail`.

`FileScanGuardStatus { clamav_enabled: bool, scan_dirs: Vec<String>, scan_interval_secs: u64, freshclam_interval_secs: u64, quarantine: QuarantineStatus }`.

### Client Edition runtime status

All six carry `daemon_running: bool`, a localized `summary`, and localized `caveats: Vec<String>`.

- `VpnStatusSummary { vpn_on_untrusted_enabled, backend, active_level: Option<String>, tunnel_expected_now, tunnel_up, kill_switch_armed, kill_switch_verified: Option<bool>, wireguard: WireGuardRuntime, tailscale: TailscaleRuntime, .. }`. `WireGuardRuntime { tools_present, config_imported: Option<bool>, interface_up, armed, config_name, endpoint, rx_bytes, tx_bytes, last_handshake_age_secs }`; `TailscaleRuntime { tools_present, running, logged_in, tailnet_name, active_exit_node, configured_exit_node, exit_node_candidate_count, armed }`.
- `LinkGuardStatusSummary { enabled, mode, effective_mode, allowlist, blocklist_extra, use_threat_dns, xdp_boot_gate_enabled, pending_decisions: Vec<PendingApproval>, recent_events: Vec<LinkGuardEvent>, .. }`. `LinkGuardEvent { timestamp, kind ("blocked" / "held" / "warned" / "dnsWarned"), kind_label, title, body }`.
- `AirGapStatusSummary { active, engaged_at_unix: Option<u64>, active_for_secs: Option<u64>, auto_release_after_secs, trigger_reason: Option<String>, trigger: Option<serde_json::Value>, auto_rfkill_enabled, frozen_processes: Vec<FrozenProcessView { pid, name, reason, reason_label, frozen_at }>, .. }`.
- `SharingServicesStatusSummary { control_enabled, active_level, stops_services_on_current_level: Option<bool>, stopped_by_roamswitch: Option<Vec<String>>, services: Vec<SharingServiceUnit { unit, active_state, is_active, stopped_by_roamswitch }>, .. }`.
- `BluetoothGuardStatusSummary { guard_enabled, active_level, network_trusted: Option<bool>, shield_active_now, controller: BluetoothStatus { is_available, is_powered, is_discoverable, connected_devices_count, connected_devices, is_shielded_on_untrusted }, .. }`.
- `UsbGuardStatusSummary { storage_guard_enabled, keyboard_guard_enabled, usb_zero_trust_enabled, usb_zero_trust_active: Option<bool>, connected_devices: Vec<UsbDeviceInfo>, allowed_devices: Vec<AllowedUsbDevice>, pending_approvals: Vec<PendingApproval>, .. }`.

`PendingApproval { id, kind ("link_warn" / "link_block" / "usb_keyboard" / "usb_storage" / ...), title, body, device_id, device_name, created_at_ms }`. `UsbDeviceInfo { device_identifier, display_name, vendor_id, product_id, serial_number, is_storage, is_keyboard, is_pointer, is_hub, is_authorized }`. `AllowedUsbDevice { device_identifier, display_name, date_added }`.

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
