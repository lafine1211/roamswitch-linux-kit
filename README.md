# roamswitch-linux-kit

**English** | [日本語](README.ja.md)

An async Rust client for [RoamSwitch](https://lafine.net)'s local Linux network security diagnostics. It has no API that changes a RoamSwitch setting.

[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://lafine.net/linux.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

This is the Linux counterpart to [RoamSwitchKit](https://github.com/lafine1211/RoamSwitchKit) (macOS/Swift) — same design: it reads RoamSwitch's state and cannot change its settings, and it sends no telemetry. It is wrapped for Rust instead of Swift.

## What is RoamSwitch?

[**RoamSwitch**](https://lafine.net/linux.html) is a Linux network security tool that automatically defends your machine's network boundary — tightening `nft` rules on untrusted networks, watching for ARP spoofing, and flagging dev servers or databases you forgot are listening on `0.0.0.0`. It ships today as a free Community Edition.

Concretely, RoamSwitch continuously computes:

- **Network trust** — is the current network one you've marked trusted, and what security level is currently active
- **ARP spoofing** — gateway MAC fingerprint changes that indicate a man-in-the-middle attempt
- **Exposed ports** — every TCP port listening beyond `localhost`, cross-referenced against a database of commonly-misconfigured services (Redis, MongoDB, Docker, Memcached, dev servers, local AI inference servers like Ollama/LM Studio) and probed for risky HTTP responses
- **A local security posture score** (31 checks on the Client Edition, 42 on the Server Edition) — LUKS/dm-crypt disk encryption, AppArmor/SELinux, UEFI Secure Boot, sudo/SSH configuration, kernel `sysctl` hardening, Wi-Fi encryption, ARP spoofing, exposed ports, and malware/download guard configuration
- **Offline URL/phishing analysis**, **secret-leak scanning**, **security log auditing**, **ransomware canary status**, and **quarantine vault status**
- **Guard runtime state** — VPN tunnel + kill-switch, passive Link Guard block/warn history, Air-Gap and frozen processes, sharing services, Bluetooth and USB guards

RoamSwitch already exposes this same data to AI assistants (Claude Desktop, Claude Code, and other [MCP](https://modelcontextprotocol.io)-compatible clients) via a bundled MCP server binary, `roamswitch-mcp` (45 tools) — see [lafine.net/mcp-setup](https://lafine.net/mcp-setup.html). **This crate is the same interface, wrapped for Rust code instead of an AI client**: it lets your own Linux app or script ask "is this machine's network safe right now?" and get back the exact data RoamSwitch itself computed, without reimplementing ARP inspection, port scanning, or log auditing yourself.

Typical uses: a sync app pausing background transfers on an untrusted network, a CI runner failing a job when it detects an unexpectedly exposed dev server, a fleet-monitoring script collecting security scores across machines, or an automation workflow that reacts to network trust changes.

## Design principles

- **No API that changes RoamSwitch.** This crate can read RoamSwitch's current diagnostics. It has no call to change RoamSwitch's security level, toggle a guard, isolate a port, quarantine a file, or freeze a process. Only RoamSwitch's own CLI or app, driven by the user, can do that. This is a deliberate scope limit, not a gap.
- **What `roamswitch-mcp` declares.** Of its 45 tools, `roamswitch-mcp` marks 42 as read-only and 3 as not (`readOnlyHint: false`): `run_active_vuln_scan` appends to RoamSwitch's scan history, `audit_security_logs` updates RoamSwitch's log-template baseline, and `run_npm_audit_signatures` lets npm write its log and cache under `~/.npm`. Two calls marked read-only also write a little: `canary_status()` creates RoamSwitch's decoy files when they are missing, and the lockfile part of `verify_fim_full()` adds lockfiles of newly watched project folders to its baseline and drops those of folders no longer watched. It never replaces the recorded hash of a lockfile that is already in the baseline.
- **No telemetry.** This crate opens no network connection and no socket. Every call starts `roamswitch-mcp` as a subprocess. `roamswitch-mcp` sends nothing over the network, with these exceptions:
  - `run_npm_audit_signatures` runs `npm audit signatures`, which asks the npm registry. It is off unless the user sets `npm_audit_signatures_enabled` to true in RoamSwitch's config. It is the only tool marked `openWorldHint`.
  - `run_active_vuln_scan` makes TCP connections to `127.0.0.1` only, and only when the user opted in.
  - On the Server Edition, the `server_domain_check` item of `security_report` and `verify_security_findings` looks up DNS and RDAP for the domains the operator listed in `domain_check_domains`. The list is empty by default, so nothing is sent by default.
- **No new attack surface.** This crate doesn't open a socket, register a service, or listen for anything. It spawns a process, writes a request to its stdin, reads one response from its stdout, and lets the process exit.
- **No control of the daemon.** RoamSwitch on Linux also runs a privileged daemon on a local Unix socket for CLI commands. That socket can enable Air-Gap isolation, freeze a process, manage USB device approvals and more, and this crate never uses it for that. `roamswitch-mcp` has no tool that changes a setting or the protection state. Three of its tools use a local Unix socket for one read request each: `get_sensor_audit_results` asks the RoamSwitch daemon to list the Sensor audit results, and `get_lan_sensor_overview` and `get_lan_network_threats` read from the socket of a RoamSwitch Sensor on the same host. Two more start separately installed programs as the calling user with fixed arguments: `get_privilege_escalation_paths` starts PathScope and `get_access_log_report` starts AccessScope.
- **Runs as the calling user.** Several answers are partial without root (the exec log, the SSH ban list, some FIM files, PathScope and AccessScope results). The answer then says so in a field (`error`, `complete`, `skipped_unreadable`, ...), and a zero count in such an answer is not a clean result. Check these fields.

## Requirements

- A recent stable Rust toolchain (2021 edition; built and tested against 1.98) with the `tokio` async runtime
- [RoamSwitch for Linux](https://lafine.net/linux.html) installed on the machine your code runs on, with `roamswitch-mcp` on `PATH` (typically `/usr/bin/roamswitch-mcp` from the official `.deb`/`.rpm` package)

## Installation

Not yet published to crates.io — add it as a git dependency in your `Cargo.toml`:

```toml
[dependencies]
roamswitch-linux-kit = { git = "https://github.com/lafine1211/roamswitch-linux-kit", tag = "v0.2.0" }
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

    // After fixing something, re-check just those findings. The verdict is
    // stillPresent, resolved or inconclusive; "inconclusive" means this process
    // could not observe the state (no root, no daemon, ...), not that it is fine.
    let after = client.verify_security_findings(Some(&["luks_encryption"]), None).await?;
    for r in &after.results {
        println!("{} {:?} ({})", r.check_id, r.verdict, r.reason);
    }

    // Tools that depend on a separate product answer `available: false`
    // when it is not installed. That is an answer, not an error.
    let paths = client.get_privilege_escalation_paths(None).await?;
    if paths.analyzed && !paths.analysis.complete {
        println!("part of the machine was not looked at: {:?}", paths.analysis.mcp_caution);
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
    pub async fn verify_fim_full(&self) -> Result<FimVerification, RoamSwitchClientError>;
    pub async fn get_port_anomaly_incidents(&self) -> Result<PortAnomalyIncidentsSummary, RoamSwitchClientError>;
    pub async fn get_ebpf_incidents(&self) -> Result<EbpfIncidentsSummary, RoamSwitchClientError>;
    pub async fn vulnerability_scan_history(&self) -> Result<Vec<ProbeStatus>, RoamSwitchClientError>;
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

    // Added in 0.2.0
    pub async fn verify_security_findings(&self, check_ids: Option<&[&str]>, is_server: Option<bool>) -> Result<FindingVerificationReport, RoamSwitchClientError>;
    pub async fn get_port_scan_incidents(&self) -> Result<PortScanIncidentsSummary, RoamSwitchClientError>;
    pub async fn get_ssh_guard_incidents(&self) -> Result<SshGuardIncidentsSummary, RoamSwitchClientError>;
    pub async fn get_fleet_status(&self) -> Result<FleetStatusSummary, RoamSwitchClientError>;
    pub async fn search_exec_events(&self, query: &ExecEventQuery) -> Result<ExecEventSearch, RoamSwitchClientError>;
    pub async fn get_process_tree(&self, pid: u32) -> Result<ProcessTree, RoamSwitchClientError>;
    pub async fn run_package_lifecycle_script_scan(&self, watched_folders: &[PathBuf]) -> Result<PackageLifecycleScriptScanResult, RoamSwitchClientError>;
    pub async fn run_typosquat_scan(&self, watched_folders: &[PathBuf]) -> Result<TyposquatScanResult, RoamSwitchClientError>;
    pub async fn run_npm_audit_signatures(&self, directory: &Path) -> Result<NpmAuditSignaturesResult, RoamSwitchClientError>;
    pub async fn audit_mcp_configs(&self) -> Result<McpConfigAuditPayload, RoamSwitchClientError>;
    pub async fn audit_agent_setup(&self) -> Result<AgentSetupAuditPayload, RoamSwitchClientError>;
    pub async fn audit_agent_setup_sarif(&self) -> Result<serde_json::Value, RoamSwitchClientError>;
    pub async fn detection_coverage(&self, is_server: Option<bool>) -> Result<CoverageReport, RoamSwitchClientError>;
    pub async fn detection_coverage_navigator(&self, is_server: Option<bool>) -> Result<serde_json::Value, RoamSwitchClientError>;
    pub async fn get_sensor_audit_results(&self) -> Result<Vec<SensorAuditResult>, RoamSwitchClientError>;
    pub async fn get_honeytoken_status(&self, is_server: Option<bool>) -> Result<HoneytokenStatus, RoamSwitchClientError>;
    pub async fn get_ransomware_entropy_guard_status(&self, is_server: Option<bool>) -> Result<EntropyGuardStatus, RoamSwitchClientError>;
    pub async fn get_lan_sensor_overview(&self) -> Result<SensorReply<LanOverview>, RoamSwitchClientError>;
    pub async fn get_lan_network_threats(&self, limit: Option<u32>, min_severity: Option<&str>) -> Result<SensorReply<LanThreats>, RoamSwitchClientError>;
    pub async fn get_privilege_escalation_paths(&self, start: Option<&str>) -> Result<PrivilegeEscalationPaths, RoamSwitchClientError>;
    pub async fn get_privilege_escalation_paths_for_agent_users(&self) -> Result<PrivilegeEscalationPaths, RoamSwitchClientError>;
    pub async fn get_access_log_report(&self, since: Option<&str>) -> Result<AccessLogReport, RoamSwitchClientError>;
}
```

All 45 tools of `roamswitch-mcp` are covered. Some tools have more than one method: `get_security_report` (`security_report`, `server_security_report`), `audit_secrets` (`audit_secrets` for text, `audit_secrets_path` for a file or directory), `verify_fim` (`verify_fim`, `verify_fim_full`), `audit_agent_setup` and `get_detection_coverage` (the typed report, or the SARIF / ATT&CK Navigator form) and `get_privilege_escalation_paths` (one account, or the `agent_users`). The names of the methods added in 0.2.0 are the tool names. Human-readable text in the responses — titles, details, recommendations, summaries, caveats — follows the language the user selected in RoamSwitch (10 languages; the OS locale when unset). Machine-readable fields (`risk_level`, `verdict`, `kind`, `mode`, ...) never change with the language.

- `new(executable_path, timeout)` — `executable_path: None` searches standard install locations; `timeout` defaults to 30s. On expiry the subprocess is killed (dropped) and the call returns `.TimedOut`.
- `security_report()` / `server_security_report()` — full local audit. The Client Edition audit has 31 checks (one more, where the decoy credential files were placed, is added while the Client daemon has recorded it). `server_security_report()` asks for the Server Edition's 42-check profile (kernel hardening, container isolation, kernel CVE exposure, eBPF LSM). `security_report()` sends no edition and gets the audit of the installed one.
- `exposed_ports(include_local_only)` — lists listening TCP ports. Ports exposed beyond localhost are always fully audited; pass `true` to also include localhost-only ports (returned without the slower per-port audit).
- `run_active_vuln_scan()` — opt-in, non-destructive reachability verification against `127.0.0.1` only. Returns `enabled: false` and no findings unless the user has set `active_vuln_scan_enabled: true` in RoamSwitch's own config. `ActiveVulnScanResult` also carries `confirmed_safe` (checks that completed and found nothing) and `inconclusive` (checks that couldn't even complete — unreachable/timeout) as `Vec<ScanCheckOutcome>`, kept separate so an empty `findings` list can't be mistaken for "everything was actually checked."
- `guard_status()` — current active security level, trusted-network status, and each optional guard's on/off state.
- `audit_url_safety(url)` — analyzes a URL for phishing, Unicode homograph spoofing, brand subdomain deception, and high-risk TLDs (Zero Telemetry, no network fetch of the URL itself).
- `audit_secrets(text)` — scans text for exposed API keys/secrets.
- `audit_security_logs(hours)` — summarizes sudo/SSH/firewall/AppArmor/ClamAV log activity over the trailing window.
- `get_app_help(query, topic)` — full-text search over RoamSwitch's offline knowledge base.
- `quarantine_status()` / `canary_status()` — malware quarantine vault state / Ransomware Canary Guard state. `canary_status()` also creates RoamSwitch's decoy files in the watched folders when they are missing.
- `package_cve_scan()` — audits installed OS packages (dpkg/pacman/rpm, auto-detected) against RoamSwitch's local, network-free CVE map.
- `package_cve_scan_languages(watched_folders)` — audits language-ecosystem lockfiles (npm/PyPI/crates.io/etc.) under the given folders against the same local CVE map.
- `verify_fim()` — Critical Path FIM verification (~150 critical system files re-hashed and compared against the persisted baseline). Does not update or initialize that baseline — that requires root and is intentionally not exposed here. Returns `RoamSwitchClientError::ToolError` if no baseline has ever been captured on this host.
- `verify_fim_full()` — the same call with everything the tool returns: the critical-path report (`critical_path_fim`), the lockfile FIM report for the watched project folders (`lockfile_fim`, `None` when no folders are set or Lockfile FIM is off) and who made recent changes (`recent_intrusion_context`, root only). It also accepts the bare report an older `roamswitch-mcp` sends.
- `get_port_anomaly_incidents()` — Port Anomaly Guard's incident log: newly-appearing, externally-exposed listening executables (backdoors, C2 listeners, accidentally-`0.0.0.0` dev servers) that were auto-blocked, with timestamp/process/PID/port for each.
- `get_ebpf_incidents()` — Server Edition only. eBPF Runtime Guard's containment history: each alert that actually triggered process isolation, a freeze, or a full host Air-Gap lockdown, plus the current containment status. This is the primary trigger reason behind an Air-Gap lockdown, which no other tool exposes — useful for offline triage right after one fires, since this crate never touches the network either.
- `vulnerability_scan_history()` — the last recorded result and days elapsed (`pass_age_days`) for every probe `run_active_vuln_scan()` has ever recorded, derived from its on-disk heartbeat log rather than a scheduled runner (there is none yet) — reflects only however often the scan has actually been run.
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

Added in 0.2.0:

- `verify_security_findings(check_ids, is_server)` — re-checks earlier `security_report` findings, for use after a fix. Per check it returns a verdict (`FindingVerdict::StillPresent` / `Resolved` / `Inconclusive`), a language-independent `reason` code and `verification_status`. A check that needs root, the daemon, Docker or a missing tool is `Inconclusive`, never guessed. Where the Linux daemons have recorded earlier audits, `change` says what changed since (`fixed`, `already_resolved` is not a fix, `still_present`, `newly_present`, `no_earlier_check`). `check_ids: None` verifies every item, at most 64 distinct ids are verified, and `is_server: None` uses the installed edition. It writes nothing.
- `get_port_scan_incidents()` — incoming port scans the Server Edition's daemon detected: source address, distinct ports reached, a sample of the ports, and whether the source was auto-blocked and for how long. Empty on the Client Edition or when nothing was detected.
- `get_ssh_guard_incidents()` — the SSH brute-force guard's state (`block`, `detect_only` or `disabled`, and why), the sources banned now, and up to 200 recent incidents (a ban, a source over the threshold that was not banned, or a login that succeeded after failures from the same source). The ban list is root-only: another user gets the count in `active_bans` and an empty `bans`. Tried user names are not stored, only how many. There is no call to lift a ban.
- `get_fleet_status()` — Fleet (organization management) status of this device: enrolled or not, applied policy version, last check-in, last error, removal reason. No codes, tokens, keys or license data. Fleet has no remote command channel, and a device that is not enrolled sends nothing.
- `search_exec_events(query)` — searches the exec/process recorder log (path, sanitised argv, ancestry, uid, working directory, container id, SHA-256), newest first, with `ExecEventQuery { since_minutes, pid, exe, user, parent, text, limit }` (limit default 100, at most 1000). The result carries `chain_status`, the hash-chain check of the log (tamper-evident, not tamper-proof). The log is root-only: as another user `events` is empty and `error` says why.
- `get_process_tree(pid)` — the recorded ancestry (up to 8 levels) and recorded descendants of a process id. A pid with no record, or an unreadable log, is a `ToolError`.
- `run_package_lifecycle_script_scan(watched_folders)` — inventory of `preinstall` / `install` / `postinstall` / `prepare` scripts under each folder's `node_modules`, with a heuristic `is_danger_pattern` flag (many legitimate scripts match), settings that allow dependency confusion, and `drift`: install-time code added since a person last recorded the accepted state. The tool never records that state. Reads local files only, runs nothing, sends no network requests. It is an inventory, not a verdict.
- `run_typosquat_scan(watched_folders)` — `package.json` dependency names within edit distance 1 or 2 of a well-known npm package. Reads local files only and contacts no registry. Some findings are false positives.
- `run_npm_audit_signatures(directory)` — runs `npm audit signatures` in an npm project directory. **It contacts the npm registry**, it is off unless `npm_audit_signatures_enabled` is true in RoamSwitch's config (otherwise `enabled: false` and `message`), and npm writes its log and cache under `~/.npm`. `raw_output` is npm's own text. npm can take longer than the 30 s default timeout, so create the client with a longer one.
- `audit_mcp_configs()` — static audit of the MCP client configuration files (Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline, Gemini CLI, Codex, OpenCode, and the registered project folders): auto-approved tools, plaintext `http://` servers, shell one-liner launchers, unpinned package launchers and more. Reads files only. No env or header values, arguments or secrets are returned. Files that exist but could not be parsed are listed in `unreadable_files` and were not audited.
- `audit_agent_setup()` / `audit_agent_setup_sarif()` — static audit of the files that steer AI coding agents (CLAUDE.md, AGENTS.md, commands, subagents, skills, Cursor rules, agent memory, editor tasks, CI workflows, agent settings): hidden characters, override wording, fetch-and-run, credential references and more. Reads files only; the text of the files is not copied into the answer. Each finding has OWASP LLM and, where unambiguous, ATT&CK ids. The SARIF form is SARIF 2.1.0 and is returned as `serde_json::Value`, because SARIF is an external format.
- `detection_coverage(is_server)` / `detection_coverage_navigator(is_server)` — a self-check of what RoamSwitch can and cannot see: for ATT&CK techniques used to impair defenses, hide or persist, the coverage (`Detects` / `Partial` / `Nothing`), the guards that would notice, the blind spot, and whether those guards run now. A technique that is not listed was not assessed. Reads local state only. The Navigator form is a MITRE ATT&CK Navigator layer (4.5) returned as `serde_json::Value`.
- `get_sensor_audit_results()` — results of active audits this device asked a paired RoamSwitch Sensor to run against it (at most 2 are kept). Reads results already retrieved; it cannot request an audit or pair. `findings` is the Sensor's own report and stays `serde_json::Value`.
- `get_honeytoken_status(is_server)` — whether the Credential Honeytoken Guard is enabled, where the decoy credential files were planted, how their watcher is doing, and the 50 most recent accesses to a decoy. If `events_readable` is `false`, an empty `recent_events` means nothing. Other users' home paths are shown only to root and administrators. No network.
- `get_ransomware_entropy_guard_status(is_server)` — whether the entropy-based ransomware detection is on, with which settings (`settings`, untyped because the keys differ by edition), and the 50 most recent bursts. If `incidents_readable` is `false`, an empty list means nothing.
- `get_lan_sensor_overview()` / `get_lan_network_threats(limit, min_severity)` — what a RoamSwitch Sensor on this same host sees on its LAN segment: devices, VLANs, capture state, threats. They read from the Sensor's local socket (one request) and send no network requests. With no Sensor on the host the answer is `available: false` with a `reason`. It is not an error. `limit` is 1 to 500, `min_severity` is `info`, `medium`, `high` or `critical`; anything else is a `ToolError`. If `coverage_gaps` is not empty, the Sensor cannot see part of the LAN and zero threats does not mean nothing is wrong. Strings in `data` come from devices on the network and are untrusted.
- `get_privilege_escalation_paths(start)` / `get_privilege_escalation_paths_for_agent_users()` — how a local account could reach root, from the separately installed PathScope, run as the calling user with fixed arguments. Suggested fix commands are not returned and nothing is applied. `start` is the account to analyse; another account needs root or an administrator, and the `agent_users` form needs root. If `analysis.complete` is `false`, part of the machine was not looked at and zero paths does not mean the account is safe. With no PathScope the answer is `available: false`.
- `get_access_log_report(since)` — a summary of attacks in the host's web server, SSH and auth logs, from the separately installed AccessScope, run as the calling user with fixed arguments. `since` is 1 to 90 days written like `"24h"` or `"7d"`; anything else is a `ToolError`. Only logs the calling user can read are analysed. If `complete` is `false`, part of the logs was not examined and zero findings does not mean the host is safe. With no AccessScope the answer is `available: false`. Every string in `report` comes from logs attackers can write and is untrusted.

Which parts are `serde_json::Value`: the SARIF log and the ATT&CK Navigator layer (external formats), the Sensor's own audit report in `SensorAuditResult::findings` and each threat's `detail` (the Sensor defines them, and `detail` differs per kind), `EntropyGuardStatus::settings` (different keys per edition), the sigma rule rejections in the exec recorder status, the process and login facts in `FimViolation::intrusion` and `FimVerification::recent_intrusion_context` (still changing), and AccessScope's detailed counters under `report.coverage`. Everything else in the new answers is typed.

The six Client Edition status methods are built from files the RoamSwitch daemon already makes world-readable (plus sysfs / procfs and read-only CLI queries). These six tools do not open the daemon's socket. Each returns `daemon_running`; when it's `false` the values are the last saved state or the configured setting and may not actually be enforced. The two facts that need root (the nftables kill-switch table actually being loaded, and the WireGuard handshake age) are `None` unless the caller is root.

### `SecurityReport`

| Field | Type | Description |
|---|---|---|
| `score` | `i32` | 0–100 overall score |
| `grade` | `String` | Letter grade derived from `score` |
| `total_checks` | `i32` | Number of audit items |
| `passed_checks` | `i32` | Number of items that passed |
| `items` | `Vec<SecurityAuditItem>` | One entry per check |
| `caveats` | `Vec<String>` | Notes on anything this tool couldn't fully verify |

`SecurityAuditItem`: `category`, `title`, `check_id: String` (stable machine identifier, e.g. `"luks_encryption"`; empty on older releases), `is_passed: bool`, `status_text`, `detail`, `recommendation`, `settings_url: Option<String>`, `is_applicable: bool`, `is_inconclusive: bool` (true only alongside `is_passed: true` — couldn't confirm safe, not a hard failure), `fix_action: Option<String>` (a token identifying a one-click remediation, when one exists), `cis_control: Option<String>` (a CIS Controls v8 safeguard number when confidently mappable; `None` also just means "no confident mapping"), `nist_csf: Vec<String>` (NIST CSF 2.0 subcategory codes, e.g. `["PR.DS-01"]`; same "confident or omit" policy).

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

### `ProbeStatus` / `NotificationHistoryEntry` / `TimelineEvent` / `ResourceGuardIncidentsSummary` / `FileScanGuardStatus`

`ProbeStatus { probe_name, port: Option<u16>, last_outcome, last_finished_at, pass_age_days: Option<u64> }`. `last_outcome` is `"vulnerable"` / `"safe"` / `"inconclusive"` (same three-state vocabulary as `ActiveVulnScanResult`'s findings). `pass_age_days` is whole days since `last_finished_at`; `None` only if the server couldn't parse its own timestamp.

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

### Types added in 0.2.0

Field names follow the same rule as above: `snake_case` in Rust, `camelCase` on the wire, except where noted. Types marked "plain snake_case" mirror a file a daemon writes, so their keys are snake_case on the wire too.

- `FindingVerificationReport { results: Vec<FindingVerification>, caveats, timestamp }`. `FindingVerification { check_id, title, verdict: FindingVerdict, reason, status_text, detail, verification_status, rationale, counter_evidence: Option<String>, severity_changes_if: Option<String>, change: Option<String>, previous_verdict: Option<FindingVerdict>, previous_checked_at: Option<String> }`. `FindingVerdict` is `StillPresent` / `Resolved` / `Inconclusive` / `Unknown` (a verdict this crate does not know).
- `PortScanIncidentsSummary { incidents: Vec<PortScanIncidentRecord { timestamp, source_ip, distinct_port_count, sample_ports: Vec<u16>, blocked, block_duration_secs: Option<u64> }> }` (plain snake_case).
- `SshGuardIncidentsSummary { running, status: Option<SshGuardStatus>, reason_text: Option<String>, active_bans, bans: Vec<SshBanEntry>, incidents: Vec<SshGuardIncidentRecord> }`. `SshGuardStatus`, `SshBanEntry` (unix seconds) and `SshGuardIncidentRecord { timestamp, kind ("ban" / "detect_only" / "exempt" / "success_after_failures"), source, failures, window_secs, distinct_users, banned, ban_secs, repeat, yielded_to, exempt_reason, login_user, login_method }` are plain snake_case.
- `FleetStatusSummary { fleet: FleetPublicStatus, remote_command_channel: bool }`. `FleetPublicStatus` is plain snake_case (`enrolled`, `org_id`, `device_id`, `policy_version_applied`, `policy_active`, `last_ok_at`, `last_error`, `removed_reason`, ...).
- `ExecEventSearch { events: Vec<ExecRecord>, chain_status: Option<ExecChainStatus>, chain: Option<String> (deprecated debug text; use chain_status), status: Option<ExecRecorderStatus>, error: Option<String> }`. `ExecRecord` is plain snake_case (`kind`, `ts`, `pid`, `ppid`, `uid`, `user`, `exe`, `argv`, `cwd`, `container_id`, `sha256`, `ancestry: Vec<ExecAncestor>`, `loginuid`, `ld_env`, ...). `ExecChainStatus { status ("ok" / "not_chained" / "broken"), segments, unchecked_records, seq, reason, reason_text, previous_seq }`. `ProcessTree { ancestry: Vec<ExecAncestor>, tree: ProcessTreeNode { pid, exe, argv, ts, children } }`.
- `PackageLifecycleScriptScanResult { scanned_folder_count, findings: Vec<LifecycleScriptFinding>, dependency_confusion: Vec<DependencyConfusionFinding>, baseline_accepted_at, drift: Vec<PackageInstallDrift>, uncovered_folders }`. `TyposquatScanResult { scanned_folder_count, findings: Vec<TyposquatFinding { dependency_name, suspected_target, distance, project_dir }> }`.
- `NpmAuditSignaturesResult { enabled, directory, raw_output, exit_code, has_issues, message }`. One struct for three answers: disabled (`enabled: false`, `message`), npm not found (`message`), npm ran (`raw_output`, `exit_code`, `has_issues`).
- `McpConfigAuditPayload { scanned_file_count, scanned_files, server_count, unreadable_files, findings: Vec<McpConfigFinding { id, severity, file, server, detail, message }> }`. `AgentSetupAuditPayload { scanned_file_count, scanned_files, skill_count, open_claw_config_found, unreadable_files, findings: Vec<AgentSetupFinding { id, severity, area, file, detail, message, owasp_llm, attack_id }>, baseline_accepted_at }`.
- `CoverageReport { platform, edition, summary: CoverageSummary, techniques: Vec<TechniqueCoverage { id, name, platform, coverage: CoverageLevel, covered_by, blind_spot, live_state }>, guards: Vec<CoverageGuardState>, inactive: Vec<InactiveInfo>, caveats }`. `CoverageLevel` is `Detects` / `Partial` / `Nothing` (`"none"` on the wire) / `Unknown`.
- `SensorAuditResult { request_id, sensor_addr, requested_at, status ("pending" / "completed" / "failed"), completed_at, attempts, findings: Option<serde_json::Value>, failure_reason }` (plain snake_case).
- `HoneytokenStatus { edition, enabled: Option<bool>, setting, setting_source, config_readable, placement: Option<HoneytokenPlacement>, inactive, events_readable, recent_events: Vec<HoneytokenEvent>, hidden_events_count, notes, timeline_problem }`. `EntropyGuardStatus { edition, enabled: Option<bool>, setting_source, config_readable, settings: Option<serde_json::Value>, freezes_on_detection, inactive, incidents_file, incidents_readable, recent_incidents: Vec<EntropyIncident>, hidden_incidents_count, notes }`. `enabled` is `None` when `server.conf` is not readable by the caller.
- `SensorReply<T> { available, reason, mcp_note, sensor_error, schema_supported, schema, supported_schema, coverage_gaps, mcp_caution, data: Option<T> }`, with `T` = `LanOverview` (gateway, device counts, VLANs, capture state, paired endpoints, behavior baselines, unmanaged-device audit counts, threat counts) or `LanThreats { schema, generated_at, site, sensor_public_key, threats: Vec<LanThreat { id, time, category, kind, severity, subject, summary, detail }>, coverage_notes }`. The inner types are plain snake_case.
- `PrivilegeEscalationPaths { available, analyzed, reason, mcp_note, pathscope_error, mode, requested_user, schema, accounts, users: Vec<EscalationAgentUser>, skipped, analysis: PrivilegeEscalationAnalysis }`. `analysis` is flattened into the same JSON object: `start`, `goal`, `os`, `privileged`, `paths` (a count), `paths_shown` (the first 20, each as its steps), `urgent_total`, `urgent: Vec<UrgentEscalationFix>`, `uncollected_by_kind`, `notes`, `complete`, `mcp_caution`.
- `AccessLogReport { available, analyzed, reason, mcp_note, accessscope_error, schema_supported, schema, since, risk_level, risk_score, findings_total, findings_shown, coverage_partial, unread_sources, complete, mcp_caution, report: Option<AccessScopeBrief> }`. `AccessScopeBrief` is AccessScope's `accessscope-brief/1` report: `risk`, `coverage`, `sources`, and `findings: Vec<AccessScopeFinding { n, kind, title, severity, confidence, count, first, last, attack_id, subject, ips, notes, evidence }>` (at most 40 findings, at most 3 masked evidence lines each).
- `InactiveInfo { guard, name, state ("off" / "partial"), code, message, next_step }`: a guard that is switched on and known for certain not to (fully) work. Used by `GuardStatus`, `CoverageReport`, `HoneytokenStatus` and `EntropyGuardStatus`.
- `FimVerification { critical_path_fim: FimReport, lockfile_fim: Option<LockfileFimResult>, recent_intrusion_context: Vec<serde_json::Value> }`. `LockfileFimResult` is a `FimReport` or `{ error }`.

### Changes to older types in 0.2.0

`roamswitch-mcp` had added fields and changed one answer since the types of 0.1.0. A response from the current `roamswitch-mcp` was compared with each of the 26 older tools.

- `verify_fim()` read the bare report; the current tool wraps it in `criticalPathFim` next to `lockfileFim` and `recentIntrusionContext`. In 0.1.0 `verify_fim()` could not decode a current response. It now returns the critical-path report again, and `verify_fim_full()` returns all three parts.
- Fields added (all `#[serde(default)]` or `Option`, so older `roamswitch-mcp` builds still decode):
  - `ExposedPort`: `is_network_reachable`, `ai_runtimes`.
  - `GuardStatus`: `collectors`, `inactive`. `GuardEntry`: `effective_state`, `inactive_reason`.
  - `SecurityLogSummary`: `journal_read_complete` (when `false`, every count is zero because nothing was read), `journal_error`, `journal_line_limit`, `coverage_note`, `recent_package_management_activity`, `all_anomalies_are_baseline_warmup_noise`, `crash_signals`. `TemplateAnomalySummary`: `own_history_observations`, `own_history_mature`.
  - `PackageCveScanResult`: `complete` (when `false`, `findings` does not say the system is clean), `incomplete_reason`, `ecosystem`, `release`, `acceptance`. `PackageCveScanLanguagesResult`: `acceptance`. `PackageCveFinding`: `lockfile`, `release`, `binary`, `pro_only`, `epss`, `epss_date`, `kev`, `unfixed`, `accepted`, `acceptance_expired_at`.
  - `ActiveScanFinding`: `evidence_kind`, `previously_safe_at`, `probe_name`. `ActiveVulnScanResult`: `probes_run`. `ProbeStatus`: `side_effects`.
  - `FimViolation`: `pid`, `intrusion`.
  - `CanaryStatus`: `hidden_directories_count`, `hidden_incidents_count`. `QuarantineItem`: `owner_uid`.
  - `PortAnomalyIncidentsSummary`: `current_port_state_note`, `incidents_note`.
  - `EbpfIncidentRecord`: `detect_to_receive_ms`, `receive_to_action_ms`, `detect_to_action_ms`. `EbpfIncidentsSummary`: `heartbeat`.
  - `FileScanGuardStatus`: `last_run`.
  - `LinkGuardStatusSummary`: `table_installed`. `UsbGuardStatusSummary`: `storage_guard_effective`, `keyboard_guard_effective`.
  - `TimelineEvent`: `parent_event_id`, `root_event_id`, `evidence_refs`.
- `get_app_help(query, topic)` no longer sends `null` for an argument that is `None`; the tool's input schema types both as a string.
- A tool answer flagged `isError` (a refused argument, an unknown tool, a failed FIM verification) is now a `RoamSwitchClientError::ToolError` with the tool's own sentence. In 0.1.0 it was an `InvalidResponse`.

Not covered, although `roamswitch-mcp` supports it: the `include_build_output` argument of `audit_secrets` and its `buildOutput` result, and the `format: "sarif"` argument of `run_active_vuln_scan`. `get_incident_timeline()` returns the events only, not the `incidents` grouping the tool also sends.

### `RoamSwitchClientError`

| Variant | Meaning |
|---|---|
| `AppNotInstalled` | No `roamswitch-mcp` binary found in any standard location |
| `ServerBinaryNotFound(path)` | An explicit path was given but nothing exists there |
| `ProcessLaunchFailed(msg)` | The subprocess itself failed to launch, or its stdio pipes failed |
| `NoResponse` | The subprocess's stdout closed before a response arrived |
| `TimedOut` | The subprocess didn't respond within the timeout |
| `InvalidResponse(msg)` | A response was received but wasn't valid/expected JSON |
| `ToolError(msg)` | The server returned a JSON-RPC error, or a tool refused the request (its result is flagged `isError`), or `get_process_tree` found no record |

## Compatibility note

The JSON returned by RoamSwitch's diagnostic tools is the actual contract between this crate and the app. [`src/models.rs`](src/models.rs) mirrors that shape independently — this crate is a separate, public repository from the private `roamswitch-linux` repo, so it can't share Rust types directly. If a future RoamSwitch release changes a response shape, these models are updated to match in lockstep; pin a version if that matters to you.

The tests check this against recorded responses of the real `roamswitch-mcp` in [`tests/fixtures`](tests/fixtures) (see the README there for how they were taken). For every tool, the type must keep every field of the recorded response, and every request must fit the tool's published input schema. Types ignore fields they do not know, so a newer RoamSwitch does not break decoding.

## License

MIT — see [LICENSE](LICENSE).
