use crate::models::*;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

/// `{"isServer": b}` for `Some(b)`, `{}` for `None` (the server then uses the
/// installed edition).
fn server_arg(is_server: Option<bool>) -> serde_json::Value {
    match is_server {
        Some(b) => serde_json::json!({ "isServer": b }),
        None => serde_json::json!({}),
    }
}

#[derive(Debug, Error)]
pub enum RoamSwitchClientError {
    #[error("RoamSwitch is not installed on this system")]
    AppNotInstalled,
    #[error("roamswitch-mcp binary not found at specified path: {0}")]
    ServerBinaryNotFound(String),
    #[error("process launch failed: {0}")]
    ProcessLaunchFailed(String),
    #[error("no response received from RoamSwitch")]
    NoResponse,
    #[error("request timed out")]
    TimedOut,
    #[error("invalid JSON response: {0}")]
    InvalidResponse(String),
    #[error("tool execution error: {0}")]
    ToolError(String),
}

/// A client for RoamSwitch's local Linux security diagnostics.
///
/// Every call spawns RoamSwitch's bundled `roamswitch-mcp` binary as a fresh
/// subprocess and talks to it over stdio using newline-delimited JSON-RPC 2.0
/// — the same protocol RoamSwitch speaks to Claude Desktop/Code and other
/// MCP clients. This crate keeps no persistent connection and opens no socket
/// or network connection of its own.
///
/// `RoamSwitchClient` has no API to change RoamSwitch's settings, toggle a
/// guard, isolate a port, or quarantine a file — that surface doesn't exist
/// here. Linking this crate gives no way to alter another user's protection
/// state; only RoamSwitch's own CLI/daemon, driven by the user, can do that.
///
/// Most methods only read. Three do more, because the `roamswitch-mcp` tool
/// behind them does: [`run_active_vuln_scan`](Self::run_active_vuln_scan)
/// appends to RoamSwitch's scan history,
/// [`audit_security_logs`](Self::audit_security_logs) updates the log-template
/// baseline, and [`run_npm_audit_signatures`](Self::run_npm_audit_signatures)
/// lets npm write its log and cache under `~/.npm`. Only the last one makes
/// `roamswitch-mcp` contact a remote server (the npm registry), and it is off
/// unless the user turned it on in RoamSwitch's own config.
pub struct RoamSwitchClient {
    executable_path: PathBuf,
    timeout_duration: Duration,
}

impl RoamSwitchClient {
    /// Creates a new client. Searches standard install locations for
    /// `roamswitch-mcp` if `executable_path` is `None`.
    pub fn new(
        executable_path: Option<PathBuf>,
        timeout_duration: Option<Duration>,
    ) -> Result<Self, RoamSwitchClientError> {
        let path = if let Some(p) = executable_path {
            if !p.exists() {
                return Err(RoamSwitchClientError::ServerBinaryNotFound(
                    p.to_string_lossy().to_string(),
                ));
            }
            p
        } else {
            Self::find_default_binary()?
        };

        Ok(Self {
            executable_path: path,
            timeout_duration: timeout_duration.unwrap_or(Duration::from_secs(30)),
        })
    }

    fn find_default_binary() -> Result<PathBuf, RoamSwitchClientError> {
        // First, check for a sibling binary next to the current executable.
        if let Ok(mut current) = std::env::current_exe() {
            current.pop();
            let sibling = current.join("roamswitch-mcp");
            if sibling.exists() {
                return Ok(sibling);
            }
        }

        let candidates = ["/usr/bin/roamswitch-mcp", "/usr/local/bin/roamswitch-mcp"];

        for c in &candidates {
            let p = Path::new(c);
            if p.exists() {
                return Ok(p.to_path_buf());
            }
        }

        Err(RoamSwitchClientError::AppNotInstalled)
    }

    /// Runs RoamSwitch's full local Linux security audit for the installed
    /// edition. The Client Edition audit has 31 checks (disk encryption,
    /// AppArmor/SELinux, firewall, Wi-Fi encryption, ARP spoofing, exposed
    /// ports, guard configuration, ...); one more, where the decoy credential
    /// files were placed, is added while the Client daemon has recorded it.
    pub async fn security_report(&self) -> Result<SecurityReport, RoamSwitchClientError> {
        self.call_tool("get_security_report", serde_json::json!({}))
            .await
    }

    /// Runs the Server Edition audit (42 checks: kernel hardening, Docker
    /// and container runtime isolation, kernel CVE exposure, eBPF LSM, etc.)
    /// instead of the Client Edition's 31-check audit, whichever edition is
    /// installed.
    pub async fn server_security_report(&self) -> Result<SecurityReport, RoamSwitchClientError> {
        self.call_tool(
            "get_security_report",
            serde_json::json!({ "isServer": true }),
        )
        .await
    }

    /// Lists every TCP port listening beyond localhost, audited for known-
    /// dangerous services and risky HTTP responses. Pass `include_local_only:
    /// true` to also include localhost-only ports (returned without the
    /// slower per-port audit).
    pub async fn exposed_ports(
        &self,
        include_local_only: bool,
    ) -> Result<ExposedPorts, RoamSwitchClientError> {
        self.call_tool(
            "get_exposed_ports",
            serde_json::json!({ "includeLocalOnly": include_local_only }),
        )
        .await
    }

    /// Runs opt-in, non-destructive reachability verification against
    /// `127.0.0.1` only (real TCP probes, never a mutating command).
    /// Returns `enabled: false` and no findings unless
    /// `active_vuln_scan_enabled: true` is set in the user's `config.json`.
    pub async fn run_active_vuln_scan(
        &self,
    ) -> Result<ActiveVulnScanResult, RoamSwitchClientError> {
        self.call_tool("run_active_vuln_scan", serde_json::json!({}))
            .await
    }

    /// Current status of every probe `run_active_vuln_scan` has ever
    /// recorded a result for (most-stale first) — the `pass_age`
    /// staleness surfacing for its heartbeat log. No scheduled runner
    /// exists, so this reflects only however irregularly the scan has
    /// actually been run.
    pub async fn vulnerability_scan_history(
        &self,
    ) -> Result<Vec<crate::models::ProbeStatus>, RoamSwitchClientError> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            probes: Vec<crate::models::ProbeStatus>,
        }
        let res: Wrapper = self
            .call_tool("get_vulnerability_scan_history", serde_json::json!({}))
            .await?;
        Ok(res.probes)
    }

    /// Current active security level, trusted-network status, and each
    /// optional guard's on/off state.
    pub async fn guard_status(&self) -> Result<GuardStatus, RoamSwitchClientError> {
        self.call_tool("get_guard_status", serde_json::json!({}))
            .await
    }

    /// Analyzes a URL for phishing, Unicode homograph spoofing, brand
    /// subdomain deception, and high-risk TLDs — fully offline, zero
    /// telemetry. No network fetch of the URL itself is performed.
    pub async fn audit_url_safety(
        &self,
        url: &str,
    ) -> Result<LinkAuditReport, RoamSwitchClientError> {
        self.call_tool("audit_url_safety", serde_json::json!({ "url": url }))
            .await
    }

    /// Scans input text for exposed API keys and other secrets.
    pub async fn audit_secrets(
        &self,
        text: &str,
    ) -> Result<SecretAuditResult, RoamSwitchClientError> {
        self.call_tool("audit_secrets", serde_json::json!({ "text": text }))
            .await
    }

    /// Summarizes recent system security log activity (sudo, SSH, firewall,
    /// AppArmor, ClamAV) over the trailing `hours`.
    pub async fn audit_security_logs(
        &self,
        hours: u32,
    ) -> Result<SecurityLogSummary, RoamSwitchClientError> {
        self.call_tool("audit_security_logs", serde_json::json!({ "hours": hours }))
            .await
    }

    /// Full-text search over RoamSwitch's bundled offline knowledge base.
    pub async fn get_app_help(
        &self,
        query: Option<&str>,
        topic: Option<&str>,
    ) -> Result<KnowledgeSearchResult, RoamSwitchClientError> {
        // `None` is left out: the input schema types both as string, not null.
        let mut args = serde_json::Map::new();
        if let Some(q) = query {
            args.insert("query".into(), serde_json::json!(q));
        }
        if let Some(t) = topic {
            args.insert("topic".into(), serde_json::json!(t));
        }
        self.call_tool("get_app_help", serde_json::Value::Object(args))
            .await
    }

    /// Current malware quarantine vault status.
    pub async fn quarantine_status(&self) -> Result<QuarantineStatus, RoamSwitchClientError> {
        self.call_tool("get_quarantine_status", serde_json::json!({}))
            .await
    }

    /// Ransomware Canary Guard status: monitored decoy files and any recent
    /// tamper incidents.
    pub async fn canary_status(&self) -> Result<CanaryStatus, RoamSwitchClientError> {
        self.call_tool("get_canary_status", serde_json::json!({}))
            .await
    }

    /// Audits installed OS packages (dpkg/pacman/rpm, auto-detected) against
    /// RoamSwitch's local, network-free CVE map.
    pub async fn package_cve_scan(&self) -> Result<PackageCveScanResult, RoamSwitchClientError> {
        self.call_tool("run_package_cve_scan", serde_json::json!({}))
            .await
    }

    /// Audits language-ecosystem lockfiles (npm/PyPI/crates.io/etc.) under
    /// the given folders against the same local CVE map. Sends no network
    /// requests.
    pub async fn package_cve_scan_languages(
        &self,
        watched_folders: &[PathBuf],
    ) -> Result<PackageCveScanLanguagesResult, RoamSwitchClientError> {
        let folders: Vec<String> = watched_folders
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        self.call_tool(
            "run_package_cve_scan_languages",
            serde_json::json!({ "watchedFolders": folders }),
        )
        .await
    }

    /// Verifies the integrity of ~150 critical system binaries/configs
    /// against RoamSwitch's persisted baseline and returns that
    /// critical-path report. It does not update or initialize that baseline
    /// (that requires root and 'roamswitch fim update'/'init', a mutating
    /// operation intentionally not exposed here). Returns a `ToolError` if no
    /// baseline has ever been captured on this host.
    ///
    /// Current `roamswitch-mcp` builds also verify the dependency lockfiles
    /// of the watched project folders and list who made recent changes; use
    /// [`verify_fim_full`](Self::verify_fim_full) for those parts. The same
    /// tool call adds lockfiles of newly watched folders to the lockfile
    /// baseline and drops those of folders no longer watched (never replacing
    /// the recorded hash of a lockfile already in it), when the caller may
    /// write that file.
    pub async fn verify_fim(&self) -> Result<FimReport, RoamSwitchClientError> {
        Ok(self.verify_fim_full().await?.critical_path_fim)
    }

    /// [`verify_fim`](Self::verify_fim) with everything the tool returns: the
    /// critical-path report, the lockfile FIM report (`None` when no project
    /// folders are configured or Lockfile FIM is off) and the recent changes
    /// with the process and login behind them (root only). A `roamswitch-mcp`
    /// that still sends the bare critical-path report is accepted too.
    pub async fn verify_fim_full(&self) -> Result<FimVerification, RoamSwitchClientError> {
        let value: serde_json::Value = self.call_tool("verify_fim", serde_json::json!({})).await?;
        if value.get("criticalPathFim").is_some() {
            serde_json::from_value(value)
        } else {
            serde_json::from_value::<FimReport>(value).map(|r| FimVerification {
                critical_path_fim: r,
                lockfile_fim: None,
                recent_intrusion_context: Vec::new(),
            })
        }
        .map_err(|e| {
            RoamSwitchClientError::InvalidResponse(format!("failed to parse payload: {e}"))
        })
    }

    /// Port Anomaly Guard's incident log: newly-appearing, externally-exposed
    /// listening executables that were auto-blocked (timestamp, process,
    /// PID, port), plus the current auto-/user-isolated port sets.
    pub async fn get_port_anomaly_incidents(
        &self,
    ) -> Result<PortAnomalyIncidentsSummary, RoamSwitchClientError> {
        self.call_tool("get_port_anomaly_incidents", serde_json::json!({}))
            .await
    }

    /// Server Edition only. eBPF Runtime Guard's containment history — each
    /// alert that actually triggered process isolation, a freeze, or a full
    /// host Air-Gap lockdown — plus the current containment status. This is
    /// the primary trigger reason behind an Air-Gap lockdown.
    pub async fn get_ebpf_incidents(&self) -> Result<EbpfIncidentsSummary, RoamSwitchClientError> {
        self.call_tool("get_ebpf_incidents", serde_json::json!({}))
            .await
    }

    /// Server Edition only. Resource Exhaustion / Process Anomaly Guard's
    /// incident log: network-exposed services flagged for sustained RSS
    /// growth or crash-looping, each with a confidence tier (`"possible"` vs
    /// `"correlated"`). A `"possible"` entry is not necessarily an attack.
    pub async fn get_resource_guard_incidents(
        &self,
    ) -> Result<ResourceGuardIncidentsSummary, RoamSwitchClientError> {
        self.call_tool("get_resource_guard_incidents", serde_json::json!({}))
            .await
    }

    /// Server Edition only. File Scan Guard's configuration (ClamAV enabled,
    /// scanned directories, scan / freshclam intervals) and the quarantine
    /// vault it feeds into.
    pub async fn get_file_scan_guard_status(
        &self,
    ) -> Result<FileScanGuardStatus, RoamSwitchClientError> {
        self.call_tool("get_file_scan_guard_status", serde_json::json!({}))
            .await
    }

    /// Notifications RoamSwitch sent over the past 7 days, most recent first.
    pub async fn notification_history(
        &self,
    ) -> Result<Vec<NotificationHistoryEntry>, RoamSwitchClientError> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            notifications: Vec<NotificationHistoryEntry>,
        }
        let res: Wrapper = self
            .call_tool("get_notification_history", serde_json::json!({}))
            .await?;
        Ok(res.notifications)
    }

    /// EXPERIMENTAL. Unified chronological incident timeline across Link
    /// Guard, the Ransomware Canary, the eBPF Runtime Guard and the Resource
    /// Guard (most recent 50), with process ancestry and MITRE ATT&CK tags.
    pub async fn get_incident_timeline(&self) -> Result<Vec<TimelineEvent>, RoamSwitchClientError> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            events: Vec<TimelineEvent>,
        }
        let res: Wrapper = self
            .call_tool("get_incident_timeline", serde_json::json!({}))
            .await?;
        Ok(res.events)
    }

    /// Scans a file, or a directory recursively (skipping `.git`,
    /// `node_modules`, `target`, `vendor`, `dist`, `build`, `__pycache__`,
    /// `venv`, and files over 2MB or that look binary), for exposed API keys
    /// and secrets. The path is read by `roamswitch-mcp` with your privileges.
    pub async fn audit_secrets_path(
        &self,
        path: &Path,
    ) -> Result<SecretPathAuditResult, RoamSwitchClientError> {
        self.call_tool(
            "audit_secrets",
            serde_json::json!({ "path": path.to_string_lossy() }),
        )
        .await
    }

    /// Client Edition. "VPN on untrusted networks" state: enabled, backend
    /// (WireGuard / Tailscale), whether the tunnel should be / is up, and
    /// whether the kill-switch is armed.
    pub async fn vpn_status(&self) -> Result<VpnStatusSummary, RoamSwitchClientError> {
        self.call_tool("get_vpn_status", serde_json::json!({}))
            .await
    }

    /// Client Edition. Passive Link Guard mode, allow / block lists,
    /// connections awaiting a decision, and block / warn events from the
    /// last 7 days.
    pub async fn link_guard_status(&self) -> Result<LinkGuardStatusSummary, RoamSwitchClientError> {
        self.call_tool("get_link_guard_status", serde_json::json!({}))
            .await
    }

    /// Client Edition. Whether emergency Air-Gap isolation is active (and
    /// what triggered it), plus processes currently frozen with SIGSTOP.
    pub async fn air_gap_status(&self) -> Result<AirGapStatusSummary, RoamSwitchClientError> {
        self.call_tool("get_air_gap_status", serde_json::json!({}))
            .await
    }

    /// Client Edition. Automatic sharing-service (SSH / Samba / RDP / VNC)
    /// control: setting, units RoamSwitch stopped, and each unit's state.
    pub async fn sharing_services_status(
        &self,
    ) -> Result<SharingServicesStatusSummary, RoamSwitchClientError> {
        self.call_tool("get_sharing_services_status", serde_json::json!({}))
            .await
    }

    /// Client Edition. Bluetooth Guard setting and live controller state.
    pub async fn bluetooth_guard_status(
        &self,
    ) -> Result<BluetoothGuardStatusSummary, RoamSwitchClientError> {
        self.call_tool("get_bluetooth_guard_status", serde_json::json!({}))
            .await
    }

    /// Client Edition. USB storage / BadUSB keyboard guard settings,
    /// connected USB devices, allow-list and pending approvals.
    pub async fn usb_guard_status(&self) -> Result<UsbGuardStatusSummary, RoamSwitchClientError> {
        self.call_tool("get_usb_guard_status", serde_json::json!({}))
            .await
    }

    /// Re-checks earlier `security_report` findings read-only, for use after a
    /// fix was applied (or to confirm none was needed). Returns, per check, a
    /// verdict (`stillPresent` / `resolved` / `inconclusive`), a
    /// language-independent reason code and, when the Linux daemons have
    /// recorded earlier audits, what changed since. Pass the `check_id`
    /// values from the report (at most 64 distinct ids are verified); an empty
    /// slice verifies every item. `is_server: None` uses the installed
    /// edition, exactly as `security_report` does. Nothing is written and
    /// nothing is sent to the network.
    pub async fn verify_security_findings(
        &self,
        check_ids: Option<&[&str]>,
        is_server: Option<bool>,
    ) -> Result<FindingVerificationReport, RoamSwitchClientError> {
        let mut args = serde_json::Map::new();
        if let Some(ids) = check_ids {
            args.insert("checkIds".into(), serde_json::json!(ids));
        }
        if let Some(s) = is_server {
            args.insert("isServer".into(), serde_json::json!(s));
        }
        self.call_tool("verify_security_findings", serde_json::Value::Object(args))
            .await
    }

    /// Incoming port-scan (reconnaissance) detections: each confirmed scan
    /// source with the distinct-port count, a sample of the ports touched and
    /// whether it was auto-blocked. Server Edition only: its daemon writes the
    /// log (`port_scan_detect_enabled`, on by default). On the Client Edition,
    /// or when nothing was detected, the list is empty.
    pub async fn get_port_scan_incidents(
        &self,
    ) -> Result<PortScanIncidentsSummary, RoamSwitchClientError> {
        self.call_tool("get_port_scan_incidents", serde_json::json!({}))
            .await
    }

    /// The SSH brute-force guard's state and history: whether it bans or only
    /// detects, the sources banned right now (the ban list is root-only, so a
    /// non-root caller sees only the count) and up to the 200 most recent
    /// incidents. Server Edition, and the Linux client while sshd is running.
    /// There is no call here to lift a ban.
    pub async fn get_ssh_guard_incidents(
        &self,
    ) -> Result<SshGuardIncidentsSummary, RoamSwitchClientError> {
        self.call_tool("get_ssh_guard_incidents", serde_json::json!({}))
            .await
    }

    /// Fleet (organization management) status of this device: enrollment,
    /// applied policy, check-in state and removal reason. Secret-free: no
    /// enrollment codes, tokens, keys or license data. Fleet has no remote
    /// command channel, and a device that is not enrolled sends nothing.
    pub async fn get_fleet_status(&self) -> Result<FleetStatusSummary, RoamSwitchClientError> {
        self.call_tool("get_fleet_status", serde_json::json!({}))
            .await
    }

    /// Searches the local exec/process recorder log (executions with path,
    /// sanitised argv, ancestry, uid, working directory, container id and
    /// SHA-256), newest first, and reports the log's hash-chain check. The log
    /// is root-only: as another user the result has no events and `error`
    /// explains it.
    pub async fn search_exec_events(
        &self,
        query: &ExecEventQuery,
    ) -> Result<ExecEventSearch, RoamSwitchClientError> {
        let args = serde_json::to_value(query)
            .map_err(|e| RoamSwitchClientError::InvalidResponse(e.to_string()))?;
        self.call_tool("search_exec_events", args).await
    }

    /// The recorded ancestry (up to 8 levels) and recorded descendants of a
    /// process id, built from its latest exec record. A pid with no record,
    /// or a log that cannot be read (it is root-only), is a
    /// [`RoamSwitchClientError::ToolError`] carrying the tool's own sentence.
    pub async fn get_process_tree(&self, pid: u32) -> Result<ProcessTree, RoamSwitchClientError> {
        let v: serde_json::Value = self
            .call_tool("get_process_tree", serde_json::json!({ "pid": pid }))
            .await?;
        if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
            return Err(RoamSwitchClientError::ToolError(e.to_string()));
        }
        serde_json::from_value(v).map_err(|e| {
            RoamSwitchClientError::InvalidResponse(format!("failed to parse payload: {e}"))
        })
    }

    /// Inventory of `package.json` lifecycle scripts (`preinstall`, `install`,
    /// `postinstall`, `prepare`) under the given project folders'
    /// `node_modules`, plus dependency-confusion settings and install-code
    /// drift. Reads local files only, executes nothing and sends no network
    /// requests. It is a plain inventory, not a threat verdict.
    pub async fn run_package_lifecycle_script_scan(
        &self,
        watched_folders: &[PathBuf],
    ) -> Result<PackageLifecycleScriptScanResult, RoamSwitchClientError> {
        let folders: Vec<String> = watched_folders
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        self.call_tool(
            "run_package_lifecycle_script_scan",
            serde_json::json!({ "watchedFolders": folders }),
        )
        .await
    }

    /// Checks each project folder's `package.json` dependency names for
    /// names suspiciously close (edit distance 1 or 2) to a well-known npm
    /// package. Reads local files only and contacts no registry. A
    /// reference-only heuristic; some findings are false positives.
    pub async fn run_typosquat_scan(
        &self,
        watched_folders: &[PathBuf],
    ) -> Result<TyposquatScanResult, RoamSwitchClientError> {
        let folders: Vec<String> = watched_folders
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        self.call_tool(
            "run_typosquat_scan",
            serde_json::json!({ "watchedFolders": folders }),
        )
        .await
    }

    /// Runs `npm audit signatures` in `directory` (an npm project with
    /// `node_modules`) to verify installed packages' registry signatures.
    ///
    /// Unlike every other method of this client, this one sends requests to
    /// the npm registry (registry.npmjs.org), and it is not read-only: npm
    /// writes its own run log and cache under `~/.npm`. It is off by default
    /// and refuses to run (`enabled: false`) unless
    /// `npm_audit_signatures_enabled` is true in the user's `config.json`. The
    /// default timeout of this client is 30 seconds, which npm can exceed:
    /// create the client with a longer one.
    pub async fn run_npm_audit_signatures(
        &self,
        directory: &Path,
    ) -> Result<NpmAuditSignaturesResult, RoamSwitchClientError> {
        self.call_tool(
            "run_npm_audit_signatures",
            serde_json::json!({ "directory": directory.to_string_lossy() }),
        )
        .await
    }

    /// Static audit of the MCP client configuration files (Claude Desktop,
    /// Claude Code, Cursor, Windsurf, VS Code, Cline, Gemini CLI, Codex,
    /// OpenCode, plus the registered project folders): auto-approved tools,
    /// plaintext remote servers, shell one-liner launchers, unpinned package
    /// launchers, and so on. Reads files only and sends no network requests.
    /// Never returns env or header values, arguments or secrets.
    pub async fn audit_mcp_configs(&self) -> Result<McpConfigAuditPayload, RoamSwitchClientError> {
        self.call_tool("audit_mcp_configs", serde_json::json!({}))
            .await
    }

    /// Static audit of the files that steer AI coding agents (CLAUDE.md,
    /// AGENTS.md, commands, subagents, skills, Cursor rules, agent memory,
    /// editor tasks, CI workflows, agent settings): hidden characters,
    /// instruction-override wording, fetch-and-run, credential references and
    /// so on. Reads files only and sends no network requests; the text of the
    /// files is not copied into the answer.
    pub async fn audit_agent_setup(&self) -> Result<AgentSetupAuditPayload, RoamSwitchClientError> {
        self.call_tool("audit_agent_setup", serde_json::json!({}))
            .await
    }

    /// [`audit_agent_setup`](Self::audit_agent_setup) as a SARIF 2.1.0 log.
    /// Returned as a [`serde_json::Value`] because SARIF is an external,
    /// versioned format with its own schema, not a RoamSwitch type.
    pub async fn audit_agent_setup_sarif(
        &self,
    ) -> Result<serde_json::Value, RoamSwitchClientError> {
        self.call_tool(
            "audit_agent_setup",
            serde_json::json!({ "format": "sarif" }),
        )
        .await
    }

    /// Self-check of what RoamSwitch can and cannot see for ATT&CK techniques
    /// an intruder uses to impair defenses, hide or persist on a Linux host:
    /// per technique the coverage (`detects` / `partial` / `none`), the
    /// guards that would notice, the blind spot and whether those guards are
    /// running now. Reads local state only and executes nothing.
    /// `is_server: None` uses the installed edition.
    pub async fn detection_coverage(
        &self,
        is_server: Option<bool>,
    ) -> Result<CoverageReport, RoamSwitchClientError> {
        self.call_tool("get_detection_coverage", server_arg(is_server))
            .await
    }

    /// [`detection_coverage`](Self::detection_coverage) as a MITRE ATT&CK
    /// Navigator layer (layer format 4.5, enterprise). Returned as a
    /// [`serde_json::Value`] because the layer is MITRE's external format.
    pub async fn detection_coverage_navigator(
        &self,
        is_server: Option<bool>,
    ) -> Result<serde_json::Value, RoamSwitchClientError> {
        let mut args = server_arg(is_server);
        args["format"] = serde_json::json!("navigator");
        self.call_tool("get_detection_coverage", args).await
    }

    /// Active-audit results this device asked a paired RoamSwitch Sensor to
    /// run against it (newest first, at most 2 are kept). Reads results that
    /// were already retrieved; requesting an audit or pairing is not possible
    /// from here. An empty list when the daemon cannot be reached.
    pub async fn get_sensor_audit_results(
        &self,
    ) -> Result<Vec<SensorAuditResult>, RoamSwitchClientError> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            #[serde(rename = "auditResults")]
            audit_results: Vec<SensorAuditResult>,
        }
        let res: Wrapper = self
            .call_tool("get_sensor_audit_results", serde_json::json!({}))
            .await?;
        Ok(res.audit_results)
    }

    /// Credential Honeytoken Guard: whether it is enabled, where the decoy
    /// credential files were planted, how their watcher is doing and the 50
    /// most recent accesses to a decoy (a real access is a strong signal of
    /// credential harvesting). Reads local files and process state only;
    /// opens no daemon socket. `is_server: None` uses the installed edition.
    pub async fn get_honeytoken_status(
        &self,
        is_server: Option<bool>,
    ) -> Result<HoneytokenStatus, RoamSwitchClientError> {
        self.call_tool("get_honeytoken_status", server_arg(is_server))
            .await
    }

    /// Entropy-based ransomware detection: whether it is on, with which
    /// settings, and the 50 most recent bursts (20 files that look encrypted
    /// within 5 seconds, written by one process). Reads local files and
    /// process state only; opens no daemon socket. `is_server: None` uses the
    /// installed edition.
    pub async fn get_ransomware_entropy_guard_status(
        &self,
        is_server: Option<bool>,
    ) -> Result<EntropyGuardStatus, RoamSwitchClientError> {
        self.call_tool("get_ransomware_entropy_guard_status", server_arg(is_server))
            .await
    }

    /// The RoamSwitch Sensor's picture of its LAN segment: gateway, device
    /// counts, packet capture state and coverage gaps, paired endpoints, IoT
    /// baselines, weak unmanaged devices and threat counts. Talks only to the
    /// local Unix socket of a Sensor running on this same host (one read-only
    /// request) and sends no network requests. With no Sensor on the host the
    /// answer has `available: false` and a `reason`; it is not an error.
    pub async fn get_lan_sensor_overview(
        &self,
    ) -> Result<SensorReply<LanOverview>, RoamSwitchClientError> {
        self.call_tool("get_lan_sensor_overview", serde_json::json!({}))
            .await
    }

    /// The LAN threats a local RoamSwitch Sensor knows, newest first (rogue
    /// DHCP server, ARP spoofing, DNS tunneling, weak unmanaged devices, ...).
    /// `limit` is 1 to 500 (default 200); `min_severity` is one of `"info"`
    /// (default), `"medium"`, `"high"`, `"critical"`; a value outside that
    /// range is a tool error. Same socket-only behavior as
    /// [`get_lan_sensor_overview`](Self::get_lan_sensor_overview). The list is not a
    /// complete log, and with `coverage_gaps` not empty an empty list does not
    /// mean nothing is wrong.
    pub async fn get_lan_network_threats(
        &self,
        limit: Option<u32>,
        min_severity: Option<&str>,
    ) -> Result<SensorReply<LanThreats>, RoamSwitchClientError> {
        let mut args = serde_json::Map::new();
        if let Some(l) = limit {
            args.insert("limit".into(), serde_json::json!(l));
        }
        if let Some(s) = min_severity {
            args.insert("minSeverity".into(), serde_json::json!(s));
        }
        self.call_tool("get_lan_network_threats", serde_json::Value::Object(args))
            .await
    }

    /// How a local account could reach root, from the separately installed
    /// PathScope (run as the calling user with fixed arguments; no shell, no
    /// network, nothing is applied). `start` is the account to analyse
    /// (default: the calling user; another account needs root or an
    /// administrator). With no PathScope installed the answer has
    /// `available: false`; it is not an error. When `analysis.complete` is
    /// `false`, zero paths does not mean the account is safe.
    pub async fn get_privilege_escalation_paths(
        &self,
        start: Option<&str>,
    ) -> Result<PrivilegeEscalationPaths, RoamSwitchClientError> {
        let args = match start {
            Some(user) => serde_json::json!({ "start": user }),
            None => serde_json::json!({}),
        };
        self.call_tool("get_privilege_escalation_paths", args).await
    }

    /// [`get_privilege_escalation_paths`](Self::get_privilege_escalation_paths)
    /// for every account in the Server Edition's `agent_users`
    /// (`checkAgentUsers: true`). Needs root, reads `/etc/roamswitch/server.conf`
    /// and cannot be combined with `start`; as another user the answer has
    /// `reason: "not_permitted"`.
    pub async fn get_privilege_escalation_paths_for_agent_users(
        &self,
    ) -> Result<PrivilegeEscalationPaths, RoamSwitchClientError> {
        self.call_tool(
            "get_privilege_escalation_paths",
            serde_json::json!({ "checkAgentUsers": true }),
        )
        .await
    }

    /// Summary of attacks found in this host's web server, SSH and auth logs,
    /// from the separately installed AccessScope (run as the calling user with
    /// fixed arguments; no shell, no network, no LLM; privilege is never
    /// raised). `since` is the window, 1 to 90 days written like `"24h"`
    /// (default) or `"7d"`; anything else is a tool error. With no AccessScope
    /// installed the answer has `available: false`; it is not an error. When
    /// `complete` is `false`, zero findings does not mean the host is safe.
    pub async fn get_access_log_report(
        &self,
        since: Option<&str>,
    ) -> Result<AccessLogReport, RoamSwitchClientError> {
        let mut args = serde_json::Map::new();
        if let Some(s) = since {
            args.insert("since".into(), serde_json::json!(s));
        }
        self.call_tool("get_access_log_report", serde_json::Value::Object(args))
            .await
    }

    async fn call_tool<T: serde::de::DeserializeOwned>(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> Result<T, RoamSwitchClientError> {
        let mut child = Command::new(&self.executable_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| RoamSwitchClientError::ProcessLaunchFailed(e.to_string()))?;

        let mut stdin = child.stdin.take().ok_or_else(|| {
            RoamSwitchClientError::ProcessLaunchFailed("failed to open stdin".to_string())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            RoamSwitchClientError::ProcessLaunchFailed("failed to open stdout".to_string())
        })?;
        let mut reader = BufReader::new(stdout).lines();

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        });

        let mut req_str = serde_json::to_string(&request)
            .map_err(|e| RoamSwitchClientError::InvalidResponse(e.to_string()))?;
        req_str.push('\n');

        let exchange = async {
            stdin
                .write_all(req_str.as_bytes())
                .await
                .map_err(|e| RoamSwitchClientError::ProcessLaunchFailed(e.to_string()))?;
            stdin
                .flush()
                .await
                .map_err(|e| RoamSwitchClientError::ProcessLaunchFailed(e.to_string()))?;

            let line = reader
                .next_line()
                .await
                .map_err(|e| RoamSwitchClientError::ProcessLaunchFailed(e.to_string()))?
                .ok_or(RoamSwitchClientError::NoResponse)?;

            Ok::<String, RoamSwitchClientError>(line)
        };

        let response_line = timeout(self.timeout_duration, exchange)
            .await
            .map_err(|_| RoamSwitchClientError::TimedOut)??;

        let resp_json: serde_json::Value = serde_json::from_str(&response_line).map_err(|e| {
            RoamSwitchClientError::InvalidResponse(format!("{}: {}", e, response_line))
        })?;

        if let Some(err) = resp_json.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(RoamSwitchClientError::ToolError(msg.to_string()));
        }

        // A tool that refuses a request (a bad argument, an unknown tool) answers
        // with a normal result flagged `isError`. Its text is `{"error": "..."}` or
        // plain text; it is not the payload of the tool.
        if resp_json
            .get("result")
            .and_then(|r| r.get("isError"))
            .and_then(|e| e.as_bool())
            == Some(true)
        {
            let text = resp_json
                .get("result")
                .and_then(|r| r.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|item| item.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("unknown error");
            let msg = serde_json::from_str::<serde_json::Value>(text)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
                .unwrap_or_else(|| text.to_string());
            return Err(RoamSwitchClientError::ToolError(msg));
        }

        let content_text = resp_json
            .get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|item| item.get("text"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| {
                RoamSwitchClientError::InvalidResponse("missing text content in result".to_string())
            })?;

        serde_json::from_str(content_text).map_err(|e| {
            RoamSwitchClientError::InvalidResponse(format!(
                "failed to parse payload: {} (raw: {})",
                e, content_text
            ))
        })
    }
}
