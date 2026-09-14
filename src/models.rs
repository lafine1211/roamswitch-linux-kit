//! Response types returned by `roamswitch-mcp`'s diagnostic tools.
//!
//! These mirror the JSON shape RoamSwitch itself produces byte-for-byte
//! (field names, `serde` renames, and all). This crate is a separate, public
//! repository from the private RoamSwitch app repo, so it can't share Rust
//! types directly — if a future RoamSwitch release changes a response
//! shape, these models are updated to match in lockstep. Pin a version if
//! that matters to you.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityReport {
    pub score: i32,
    pub grade: String,
    #[serde(rename = "totalChecks")]
    pub total_checks: i32,
    #[serde(rename = "passedChecks")]
    pub passed_checks: i32,
    pub items: Vec<SecurityAuditItem>,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityAuditItem {
    pub category: String,
    pub title: String,
    #[serde(rename = "isPassed")]
    pub is_passed: bool,
    #[serde(rename = "statusText")]
    pub status_text: String,
    pub detail: String,
    pub recommendation: String,
    #[serde(rename = "settingsURL")]
    pub settings_url: Option<String>,
    #[serde(rename = "isApplicable")]
    pub is_applicable: bool,
    /// Token identifying a one-click remediation the GUI can offer for a
    /// failed item. `None` when the fix is manual.
    #[serde(default, rename = "fixAction")]
    pub fix_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExposedPorts {
    #[serde(rename = "isFirewallShielded")]
    pub is_firewall_shielded: bool,
    pub ports: Vec<ExposedPort>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExposedPort {
    #[serde(rename = "processName")]
    pub process_name: String,
    pub pid: i32,
    pub port: i32,
    #[serde(rename = "isGloballyExposed")]
    pub is_globally_exposed: bool,
    #[serde(rename = "executablePath")]
    pub executable_path: Option<String>,
    #[serde(rename = "auditPerformed")]
    pub audit_performed: bool,
    #[serde(rename = "overallRisk")]
    pub overall_risk: Option<String>,
    pub findings: Vec<PortFinding>,
    #[serde(rename = "httpHeaders")]
    pub http_headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub is_dev_server: bool,
    #[serde(default)]
    pub is_isolated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortFinding {
    pub title: String,
    #[serde(rename = "riskLevel")]
    pub risk_level: String,
    pub description: String,
    pub recommendation: String,
}

/// One probe that did NOT produce an [`ActiveScanFinding`] — either the
/// target was actually confirmed safe, or the probe itself couldn't
/// complete (connection refused, timeout, DNS/socket error). Reported
/// separately in [`ActiveVulnScanResult`] so a caller can't mistake
/// "checked, and it's fine" for "never actually got to check" — both used
/// to collapse into the same empty `findings` list (see
/// <https://dev.to/raknaos/my-wait-for-it-wrapper-reported-success-for-a-port-that-never-opened-ga3>).
/// `check` is the same title an [`ActiveScanFinding`] for this exact probe
/// would carry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanCheckOutcome {
    pub port: u16,
    pub process_name: String,
    pub check: String,
}

/// Wire format for `run_active_vuln_scan` (Phase 2 of the active-vulnerability
/// -verification roadmap): non-destructive, opt-in reachability verification
/// against `127.0.0.1` only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActiveVulnScanResult {
    pub enabled: bool,
    pub scanned_target_count: usize,
    pub findings: Vec<ActiveScanFinding>,
    /// Checks that ran to completion and found no issue. Older servers that
    /// predate this field simply omit it — defaults to empty.
    #[serde(default)]
    pub confirmed_safe: Vec<ScanCheckOutcome>,
    /// Checks that could not complete (unreachable/timeout) — never
    /// evidence of safety. Older servers that predate this field simply
    /// omit it — defaults to empty.
    #[serde(default)]
    pub inconclusive: Vec<ScanCheckOutcome>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActiveScanFinding {
    pub port: u16,
    pub process_name: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    /// `true` if the probe positively confirmed unauthenticated reachability
    /// (not merely "the port is open").
    pub confirmed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardStatus {
    #[serde(rename = "activeSecurityLevel")]
    pub active_security_level: String,
    #[serde(rename = "activeSecurityLevelLabel")]
    pub active_security_level_label: String,
    #[serde(rename = "isCurrentNetworkTrusted")]
    pub is_current_network_trusted: bool,
    pub guards: Vec<GuardEntry>,
    pub caveats: Vec<String>,
    /// Non-boolean qualifiers for some of the guards above. `None` from
    /// `roamswitch-mcp` builds older than this field.
    #[serde(default)]
    pub settings: Option<GuardSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GuardSettings {
    /// Effective Link Guard mode: `"off"` / `"warn"` / `"block"`.
    pub link_guard_mode: String,
    /// `"wireguard"` / `"tailscale"`.
    pub vpn_backend: String,
    /// `"untrusted_only"` / `"always_on"`.
    pub dns_scope: String,
    /// e.g. `"quad9"` / `"cloudflare"`.
    pub dns_provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardEntry {
    pub key: String,
    #[serde(rename = "enabledInSettings")]
    pub enabled_in_settings: bool,
}

/// What the interception layer would do with a connection to this URL's
/// domain. Display purposes should use `LinkAuditReport::risk_level`
/// instead — this is the actual enforcement decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    #[default]
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkAuditReport {
    #[serde(rename = "originalURL")]
    pub original_url: String,
    #[serde(rename = "finalURL")]
    pub final_url: String,
    #[serde(rename = "redirectChain")]
    pub redirect_chain: Vec<String>,
    pub domain: String,
    pub score: i32,
    #[serde(rename = "riskLevel")]
    pub risk_level: String,
    #[serde(rename = "isHTTPS")]
    pub is_https: bool,
    #[serde(rename = "riskFactors")]
    pub risk_factors: Vec<LinkRiskFactor>,
    #[serde(default)]
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkRiskFactor {
    pub title: String,
    pub detail: String,
    #[serde(rename = "isSevere")]
    pub is_severe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretFinding {
    #[serde(rename = "secretType")]
    pub secret_type: String,
    pub provider: String,
    pub masked: String,
    #[serde(rename = "lineNumber")]
    pub line_number: usize,
    pub entropy: f64,
    pub recommendation: String,
    #[serde(rename = "isSevere")]
    pub is_severe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretAuditResult {
    #[serde(rename = "hasLeaks")]
    pub has_leaks: bool,
    #[serde(rename = "findingCount")]
    pub finding_count: usize,
    pub findings: Vec<SecretFinding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityLogEvent {
    pub time: String,
    pub category: String,
    #[serde(rename = "categoryLabel")]
    pub category_label: String,
    pub title: String,
    pub detail: String,
    pub severity: String,
}

/// A log template flagged as anomalous — either never seen before relative
/// to the persisted baseline, or a statistical frequency outlier within the
/// current audit run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemplateAnomalySummary {
    pub template: String,
    pub example: String,
    pub count: usize,
    #[serde(rename = "zScore")]
    pub z_score: f64,
    #[serde(rename = "isNew")]
    pub is_new: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityLogSummary {
    pub hours: u32,
    #[serde(rename = "sudoFailures")]
    pub sudo_failures: u32,
    #[serde(rename = "sshAttempts")]
    pub ssh_attempts: u32,
    #[serde(rename = "firewallBlocks")]
    pub firewall_blocks: u32,
    #[serde(rename = "apparmorBlocks")]
    pub apparmor_blocks: u32,
    #[serde(rename = "clamavDetections")]
    pub clamav_detections: u32,
    #[serde(rename = "usbInsertions")]
    pub usb_insertions: u32,
    pub events: Vec<SecurityLogEvent>,
    /// Older `roamswitch-mcp` builds don't send this field at all — default
    /// to empty rather than fail the whole response.
    #[serde(default, rename = "templateAnomalies")]
    pub template_anomalies: Vec<TemplateAnomalySummary>,
    #[serde(rename = "aiPrompt")]
    pub ai_prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeItem {
    pub id: String,
    pub topic: String,
    pub title: String,
    pub summary: String,
    pub details: String,
    pub recommendation: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeSearchResult {
    pub query: Option<String>,
    pub topic: Option<String>,
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    pub items: Vec<KnowledgeItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineItem {
    pub id: String,
    #[serde(rename = "originalPath")]
    pub original_path: String,
    #[serde(rename = "fileName")]
    pub file_name: String,
    #[serde(rename = "quarantinedPath")]
    pub quarantined_path: String,
    #[serde(rename = "quarantineDate")]
    pub quarantine_date: String,
    #[serde(rename = "threatName")]
    pub threat_name: String,
    #[serde(rename = "fileSizeBytes")]
    pub file_size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineStatus {
    #[serde(rename = "itemCount")]
    pub item_count: usize,
    pub items: Vec<QuarantineItem>,
    #[serde(rename = "quarantineDirectory")]
    pub quarantine_directory: String,
    #[serde(rename = "exclusionPaths")]
    pub exclusion_paths: Vec<String>,
    /// ClamAV engine / signature database state (localized placeholders).
    /// `None` from older `roamswitch-mcp` builds, and inside
    /// `FileScanGuardStatus::quarantine`.
    #[serde(default)]
    pub clamav: Option<ClamAvDatabaseInfo>,
}

/// Plain snake_case on the wire, matching `roamswitch-core`'s `ClamAVDatabaseInfo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClamAvDatabaseInfo {
    pub is_installed: bool,
    pub engine_version: String,
    pub database_version: String,
    pub last_updated: String,
    pub is_up_to_date: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryIncident {
    pub id: String,
    pub timestamp: String,
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "detectedAction")]
    pub detected_action: String,
    #[serde(rename = "suspectedProcess")]
    pub suspected_process: Option<String>,
    #[serde(rename = "suspectedPid")]
    pub suspected_pid: Option<u32>,
    #[serde(rename = "isContained")]
    pub is_contained: bool,
    /// Other files in the watched folders modified around the incident (the
    /// "blast radius"). Empty for incidents recorded before this field existed.
    #[serde(default, rename = "affectedFilePaths")]
    pub affected_file_paths: Vec<String>,
}

/// Wire format for `run_package_cve_scan` (OS packages — dpkg/pacman/rpm)
/// and `run_package_cve_scan_languages` (npm/PyPI/crates.io/etc. lockfiles),
/// both matched against a local, network-free CVE map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PackageCveScanResult {
    pub map_installed: bool,
    pub map_version: String,
    pub findings: Vec<PackageCveFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PackageCveScanLanguagesResult {
    pub scanned_folder_count: usize,
    pub findings: Vec<PackageCveFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PackageCveFinding {
    pub ecosystem: String,
    pub package: String,
    pub installed_version: String,
    pub cve_id: String,
    pub cvss_score: f64,
    pub fixed_version: String,
    pub summary: String,
}

/// Wire format for `verify_fim` — read-only Critical Path FIM verification
/// (~150 critical system files/binaries re-hashed and compared against the
/// persisted baseline). Does NOT update or initialize the baseline — that
/// requires root and is a mutating operation intentionally not exposed via
/// MCP. Field names are plain snake_case (not camelCase like most other
/// types here), matching `roamswitch-core`'s `FimReport`/`FimViolation`
/// exactly, which carry no `#[serde(rename_all)]` of their own.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FimReport {
    pub total_monitored: usize,
    pub passed_count: usize,
    pub violations: Vec<FimViolation>,
    pub last_checked_at: String,
    pub is_healthy: bool,
    /// Baseline entries that couldn't be read due to insufficient privileges
    /// (e.g. `/etc/shadow` when running as a non-root user) — not tampering,
    /// and doesn't affect `is_healthy`.
    #[serde(default)]
    pub skipped_unreadable: usize,
}

/// Wire format for `get_port_anomaly_incidents`. Plain snake_case (not
/// camelCase like most other types here), matching `FimReport`/
/// `FimViolation`: this mirrors an existing on-disk state file
/// (`/var/lib/roamswitch/port_guard.json`) the daemon already writes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortAnomalyIncident {
    pub timestamp: String,
    pub identity: String,
    pub proc_name: String,
    pub pid: i32,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PortAnomalyIncidentsSummary {
    pub incidents: Vec<PortAnomalyIncident>,
    pub auto_isolated_ports: Vec<u16>,
    pub user_isolated_ports: Vec<u16>,
    pub baseline_captured: bool,
}

/// Server Edition only. Wire format for `get_ebpf_incidents`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EbpfAlertEvent {
    pub timestamp: String,
    pub priority: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EbpfIncidentRecord {
    pub event: EbpfAlertEvent,
    pub action_taken: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerQuarantineStatus {
    pub is_isolated: bool,
    pub isolation_mode: String,
    pub isolated_pids: Vec<i32>,
    pub isolated_cgroups: Vec<String>,
    pub active_maintenance_ports: Vec<u16>,
    pub whitelist_ips: Vec<String>,
    pub last_action_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EbpfIncidentsSummary {
    pub current_status: ServerQuarantineStatus,
    pub incidents: Vec<EbpfIncidentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FimViolation {
    pub path: String,
    pub violation_type: String,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanaryStatus {
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
    #[serde(rename = "monitoredFilesCount")]
    pub monitored_files_count: usize,
    #[serde(rename = "watchedDirectories")]
    pub watched_directories: Vec<String>,
    #[serde(rename = "recentIncidents")]
    pub recent_incidents: Vec<CanaryIncident>,
    #[serde(rename = "lastInspectionDate")]
    pub last_inspection_date: Option<String>,
}

// ---------------------------------------------------------------------------
// audit_secrets with `path`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretFileFindings {
    pub path: String,
    pub findings: Vec<SecretFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretDirectoryAuditResult {
    #[serde(rename = "filesScanned")]
    pub files_scanned: usize,
    #[serde(rename = "hasLeaks")]
    pub has_leaks: bool,
    #[serde(rename = "findingCount")]
    pub finding_count: usize,
    #[serde(rename = "flaggedFiles")]
    pub flagged_files: Vec<SecretFileFindings>,
    pub summary: String,
}

/// `audit_secrets_path`: a directory is scanned recursively; a single file
/// returns the same shape as a text audit. `Directory` is tried first — only
/// it carries `filesScanned`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum SecretPathAuditResult {
    Directory(SecretDirectoryAuditResult),
    File(SecretAuditResult),
}

// ---------------------------------------------------------------------------
// get_notification_history / get_resource_guard_incidents / get_incident_timeline
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationHistoryEntry {
    /// RFC 3339.
    pub timestamp: String,
    pub title: String,
    pub body: String,
}

/// Server Edition only. Plain snake_case on the wire (mirrors the daemon's
/// persisted `resource_guard_incidents.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceGuardEvent {
    pub timestamp: String,
    /// `"memory_leak_trend"` / `"crash_loop"`.
    pub kind: String,
    pub proc_name: Option<String>,
    pub pid: Option<i32>,
    pub unit_or_container: Option<String>,
    /// `"possible"` / `"correlated"`.
    pub confidence: String,
    pub matched_signals: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceGuardIncidentRecord {
    pub event: ResourceGuardEvent,
    pub action_taken: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourceGuardIncidentsSummary {
    pub incidents: Vec<ResourceGuardIncidentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessAncestor {
    pub pid: u32,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackTechnique {
    /// MITRE ATT&CK technique id, e.g. `"T1486"`.
    pub id: String,
    pub name: String,
}

/// EXPERIMENTAL. One entry of `get_incident_timeline`. Plain snake_case on
/// the wire. `source` / `resolution` are kept as strings so a future source
/// kind never fails deserialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineEvent {
    pub id: String,
    /// RFC 3339.
    pub timestamp: String,
    /// `"link_guard"` / `"canary"` / `"ebpf_guard"` / `"resource_guard"`.
    pub source: String,
    pub severity: String,
    pub summary: String,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    #[serde(default)]
    pub process_ancestry: Vec<ProcessAncestor>,
    pub attack_technique: Option<AttackTechnique>,
    pub action_taken: Option<String>,
    pub containment_latency_ms: Option<u64>,
    pub resolved_at: Option<String>,
    /// `"released"` / `"auto_timeout"` / `"allowlisted"`, or `None` while open.
    pub resolution: Option<String>,
}

/// Server Edition only. Wire format for `get_file_scan_guard_status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileScanGuardStatus {
    pub clamav_enabled: bool,
    pub scan_dirs: Vec<String>,
    pub scan_interval_secs: u64,
    pub freshclam_interval_secs: u64,
    pub quarantine: QuarantineStatus,
}

// ---------------------------------------------------------------------------
// Client Edition runtime status (get_vpn_status, get_link_guard_status,
// get_air_gap_status, get_sharing_services_status, get_bluetooth_guard_status,
// get_usb_guard_status). Every one carries a localized `summary` and
// `caveats`, plus `daemon_running` — when false, what's reported is the last
// saved state / configured value and may not actually be enforced.
// ---------------------------------------------------------------------------

/// An entry of the daemon's user-approval queue (held Link Guard connection,
/// unapproved USB device, ...).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PendingApproval {
    pub id: String,
    /// `"link_warn"`, `"link_block"`, `"usb_keyboard"`, `"usb_storage"`, ...
    pub kind: String,
    pub title: String,
    pub body: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardRuntime {
    pub tools_present: bool,
    /// `None` when `/etc/wireguard` isn't readable by the caller.
    pub config_imported: Option<bool>,
    pub interface_up: bool,
    pub armed: bool,
    pub config_name: Option<String>,
    pub endpoint: Option<String>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    /// Root only.
    pub last_handshake_age_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VpnStatusSummary {
    pub daemon_running: bool,
    pub vpn_on_untrusted_enabled: bool,
    /// `"wireguard"` / `"tailscale"`.
    pub backend: String,
    pub active_level: Option<String>,
    /// The daemon only brings the tunnel up at the `lockdown` level.
    pub tunnel_expected_now: bool,
    pub tunnel_up: bool,
    pub kill_switch_armed: bool,
    /// The nftables kill-switch table is actually loaded. Root only.
    pub kill_switch_verified: Option<bool>,
    pub wireguard: WireGuardRuntime,
    pub tailscale: TailscaleRuntime,
    pub summary: String,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinkGuardEvent {
    pub timestamp: String,
    /// `"blocked"` / `"held"` / `"warned"` / `"dnsWarned"`.
    pub kind: String,
    pub kind_label: String,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinkGuardStatusSummary {
    pub daemon_running: bool,
    pub enabled: bool,
    /// Configured mode: `"off"` / `"warn"` / `"block"`.
    pub mode: String,
    /// `"off"` whenever `enabled` is false, otherwise `mode`.
    pub effective_mode: String,
    pub allowlist: Vec<String>,
    pub blocklist_extra: Vec<String>,
    pub use_threat_dns: bool,
    pub xdp_boot_gate_enabled: bool,
    pub pending_decisions: Vec<PendingApproval>,
    /// Last 7 days, newest first, max 50.
    pub recent_events: Vec<LinkGuardEvent>,
    pub summary: String,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FrozenProcessView {
    pub pid: u32,
    pub name: String,
    /// `"ransomware_burst"` / `"canary_tamper"` / `"kernel_exploit"` / `"ebpf_guard"` / `"manual"`.
    pub reason: String,
    pub reason_label: String,
    pub frozen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AirGapStatusSummary {
    pub daemon_running: bool,
    pub active: bool,
    pub engaged_at_unix: Option<u64>,
    pub active_for_secs: Option<u64>,
    pub auto_release_after_secs: u64,
    /// e.g. `"arp_spoof"` / `"canary_tamper"`.
    pub trigger_reason: Option<String>,
    /// The raw trigger record the daemon saved when Air-Gap engaged.
    pub trigger: Option<serde_json::Value>,
    pub auto_rfkill_enabled: bool,
    pub frozen_processes: Vec<FrozenProcessView>,
    pub summary: String,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharingServiceUnit {
    pub unit: String,
    /// systemd `ActiveState`.
    pub active_state: String,
    pub is_active: bool,
    pub stopped_by_roamswitch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SharingServicesStatusSummary {
    pub daemon_running: bool,
    pub control_enabled: bool,
    pub active_level: Option<String>,
    pub stops_services_on_current_level: Option<bool>,
    /// `None` when the daemon's record isn't readable by the caller.
    pub stopped_by_roamswitch: Option<Vec<String>>,
    pub services: Vec<SharingServiceUnit>,
    pub summary: String,
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BluetoothStatus {
    #[serde(rename = "isAvailable")]
    pub is_available: bool,
    #[serde(rename = "isPowered")]
    pub is_powered: bool,
    #[serde(rename = "isDiscoverable")]
    pub is_discoverable: bool,
    #[serde(rename = "connectedDevicesCount")]
    pub connected_devices_count: usize,
    #[serde(rename = "connectedDevices")]
    pub connected_devices: Vec<String>,
    /// Mirrors the Bluetooth Guard setting.
    #[serde(rename = "isShieldedOnUntrusted")]
    pub is_shielded_on_untrusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsbDeviceInfo {
    #[serde(rename = "deviceIdentifier")]
    pub device_identifier: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "vendorId")]
    pub vendor_id: Option<String>,
    #[serde(rename = "productId")]
    pub product_id: Option<String>,
    #[serde(rename = "serialNumber")]
    pub serial_number: Option<String>,
    #[serde(rename = "isStorage")]
    pub is_storage: bool,
    #[serde(rename = "isKeyboard")]
    pub is_keyboard: bool,
    #[serde(rename = "isPointer", default)]
    pub is_pointer: bool,
    #[serde(rename = "isHub", default)]
    pub is_hub: bool,
    #[serde(rename = "isAuthorized")]
    pub is_authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowedUsbDevice {
    #[serde(rename = "deviceIdentifier")]
    pub device_identifier: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UsbGuardStatusSummary {
    pub daemon_running: bool,
    pub storage_guard_enabled: bool,
    /// BadUSB guard — suppresses input via evdev `EVIOCGRAB`, never by kernel de-authorization.
    pub keyboard_guard_enabled: bool,
    pub usb_zero_trust_enabled: bool,
    pub usb_zero_trust_active: Option<bool>,
    pub connected_devices: Vec<UsbDeviceInfo>,
    pub allowed_devices: Vec<AllowedUsbDevice>,
    pub pending_approvals: Vec<PendingApproval>,
    pub summary: String,
    pub caveats: Vec<String>,
}
