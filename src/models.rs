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

/// Wire format for `run_active_vuln_scan` (Phase 2 of the active-vulnerability
/// -verification roadmap): non-destructive, opt-in reachability verification
/// against `127.0.0.1` only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActiveVulnScanResult {
    pub enabled: bool,
    pub scanned_target_count: usize,
    pub findings: Vec<ActiveScanFinding>,
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
