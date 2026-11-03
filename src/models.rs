//! Response types returned by `roamswitch-mcp`'s diagnostic tools.
//!
//! These mirror the JSON shape RoamSwitch itself produces byte-for-byte
//! (field names, `serde` renames, and all). This crate is a separate, public
//! repository from the private RoamSwitch app repo, so it can't share Rust
//! types directly — if a future RoamSwitch release changes a response
//! shape, these models are updated to match in lockstep. Pin a version if
//! that matters to you.
//!
//! Rules the types follow:
//!
//! - Unknown fields are ignored (no `deny_unknown_fields`), so a field added by a
//!   newer RoamSwitch never breaks decoding.
//! - A field that RoamSwitch added to an answer after the rest is
//!   `#[serde(default)]`, so an older `roamswitch-mcp` still decodes.
//! - Values that can grow new members (kinds, sources, states) are `String`s,
//!   documented with the values known today. The enums [`FindingVerdict`] and
//!   [`CoverageLevel`] have an `Unknown` variant for a value this crate does not know.
//! - A part of an answer that belongs to another format or product, or whose
//!   shape differs per case, is a `serde_json::Value`; its documentation says why.

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
    /// Stable machine identifier for this specific check (e.g.
    /// `"luks_encryption"`), independent of the localized `title` — key on
    /// this instead of parsing a display string. `#[serde(default)]` so a
    /// response from an older RoamSwitch release (before this field
    /// existed) still decodes — an empty string means "no stable
    /// identifier available".
    #[serde(default, rename = "checkId")]
    pub check_id: String,
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
    /// `true` only alongside `is_passed: true`: the check couldn't confirm
    /// this item is actually safe, but the evidence isn't strong enough to
    /// call it a hard failure either. Never combined with `is_passed:
    /// false`. `#[serde(default)]` for the same older-release reason as
    /// `check_id`.
    #[serde(default, rename = "isInconclusive")]
    pub is_inconclusive: bool,
    /// Token identifying a one-click remediation the GUI can offer for a
    /// failed item. `None` when the fix is manual.
    #[serde(default, rename = "fixAction")]
    pub fix_action: Option<String>,
    /// A CIS Controls v8 safeguard number this check corresponds to (e.g.
    /// `"3.11"`), when confident. `None` means "not confidently mappable to
    /// a single control number", not "not compliance-relevant".
    #[serde(default, rename = "cisControl")]
    pub cis_control: Option<String>,
    /// NIST CSF 2.0 subcategory codes (e.g. `["PR.DS-01"]`) this check
    /// relates to. A check can map to more than one subcategory, so this is
    /// a `Vec`, unlike `cis_control`.
    #[serde(default, rename = "nistCsf")]
    pub nist_csf: Vec<String>,
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
    /// Reachable from the network: a wildcard bind or a bind to any concrete
    /// non-loopback address. `#[serde(default)]` for `roamswitch-mcp` builds
    /// older than this field.
    #[serde(default, rename = "isNetworkReachable")]
    pub is_network_reachable: bool,
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
    /// Local AI runtimes (Ollama, vLLM, Gradio, ...) this listener may be.
    /// Absent when none was recognized.
    #[serde(
        default,
        rename = "aiRuntimes",
        skip_serializing_if = "Option::is_none"
    )]
    pub ai_runtimes: Option<Vec<AiRuntime>>,
}

/// A local AI runtime a listening port may be (`get_exposed_ports`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiRuntime {
    pub product: String,
    /// `"confirmed"` (the process carries the product's own name, or Ollama's
    /// dedicated port) or `"likely"` (a port or response-header hint only; it
    /// never raises the risk level).
    pub confidence: String,
    /// What pointed at the product: `"port"`, `"header"`, `"process-name"`.
    pub basis: Vec<String>,
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
    /// The probes this run attempted, with what each leaves on the probed
    /// service. Absent when nothing was run.
    #[serde(default, rename = "probesRun", skip_serializing_if = "Vec::is_empty")]
    pub probes_run: Vec<ProbeDeclaration>,
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
    /// How the finding is known: `"confirmed"` (the probe saw it),
    /// `"versionRangeMatch"` (a reported version lies in a CVE's range) or
    /// `"externalToolReport"` (an nmap script's own finding). Rows from older
    /// servers read as `"confirmed"`.
    #[serde(default = "default_evidence_kind", rename = "evidenceKind")]
    pub evidence_kind: String,
    /// RFC 3339 time this probe on this port last reached a `safe` verdict
    /// before this run. It is what the local scan log holds, not proof that a
    /// fix was undone.
    #[serde(
        default,
        rename = "previouslySafeAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub previously_safe_at: Option<String>,
    /// The check that produced the finding (a signature id, `webvuln-*` or
    /// `nmap-nse`); it is the SARIF rule id and never changes once published.
    #[serde(default, rename = "probeName", skip_serializing_if = "Option::is_none")]
    pub probe_name: Option<String>,
}

fn default_evidence_kind() -> String {
    "confirmed".to_string()
}

/// What one probe of `run_active_vuln_scan` is: its stable name, what it
/// leaves on the probed service and how a positive result is known.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeDeclaration {
    pub probe_name: String,
    /// `"connectionInLogs"`, `"iocInLogs"`, `"readsServiceData"`,
    /// `"loginAttempt"`, `"mailTransactionNoMessage"`.
    pub side_effects: Vec<String>,
    /// Same vocabulary as `ActiveScanFinding::evidence_kind`.
    pub evidence_kind: String,
}

/// Wire format for `get_vulnerability_scan_history` — the current status of
/// one probe, derived from the most recent row `run_active_vuln_scan`
/// wrote to its on-disk heartbeat log. There is no scheduled runner, so
/// `pass_age_days` reflects only however irregularly the scan has actually
/// been run — a probe never run has no status at all, not a stale one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeStatus {
    pub probe_name: String,
    pub port: Option<u16>,
    /// `"vulnerable"` | `"safe"` | `"inconclusive"` — same three-state
    /// vocabulary as `ActiveScanFinding`/`ScanCheckOutcome`.
    pub last_outcome: String,
    pub last_finished_at: String,
    /// Whole days since `last_finished_at`. `None` only if the server
    /// couldn't parse its own timestamp (should not happen in practice).
    pub pass_age_days: Option<u64>,
    /// What this probe leaves on the probed service (same vocabulary as
    /// `ProbeDeclaration::side_effects`). Empty for an unknown probe name.
    #[serde(default)]
    pub side_effects: Vec<String>,
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
    /// What the daemon's guards could not read, per input source. Only fresh
    /// entries; absent when none is published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collectors: Option<std::collections::BTreeMap<String, CollectorHealth>>,
    /// Every guard that is switched on and known for certain not to (fully)
    /// work, with the reason. Absent when nothing is known to be wrong.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inactive: Vec<InactiveInfo>,
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
    /// `"off"` / `"partial"`, only when the guard is switched on and known
    /// not to (fully) work. Absent means nothing is known to be wrong, not
    /// that it was verified.
    #[serde(
        default,
        rename = "effectiveState",
        skip_serializing_if = "Option::is_none"
    )]
    pub effective_state: Option<String>,
    /// Why, with a stable `code`, a localized message and the next step.
    #[serde(
        default,
        rename = "inactiveReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub inactive_reason: Option<InactiveInfo>,
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
    /// How many runs (including this one) this template has been seen in.
    #[serde(default, rename = "ownHistoryObservations")]
    pub own_history_observations: usize,
    /// Whether that is enough to trust the template's own historical baseline.
    #[serde(default, rename = "ownHistoryMature")]
    pub own_history_mature: bool,
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
    /// Whether a package-manager log was modified within the scanned window:
    /// anomalies may then be routine upgrade noise.
    #[serde(default, rename = "recentPackageManagementActivity")]
    pub recent_package_management_activity: bool,
    /// Every anomaly is a new template (no frequency spike) and the baseline is
    /// still in its first week or a package manager ran: nothing worth paging.
    #[serde(default, rename = "allAnomaliesAreBaselineWarmupNoise")]
    pub all_anomalies_are_baseline_warmup_noise: bool,
    /// systemd's own crash/restart lines found in the window.
    #[serde(default, rename = "crashSignals")]
    pub crash_signals: Vec<SystemdCrashSignal>,
    /// `false` when the journal could not be read: every count above is then
    /// zero because nothing was read, NOT because nothing happened.
    #[serde(default = "default_true", rename = "journalReadComplete")]
    pub journal_read_complete: bool,
    /// Why the journal could not be read.
    #[serde(
        default,
        rename = "journalError",
        skip_serializing_if = "Option::is_none"
    )]
    pub journal_error: Option<String>,
    /// Set (to the number of entries read) when the window held more entries
    /// than the audit reads, so the oldest ones were not examined.
    #[serde(
        default,
        rename = "journalLineLimit",
        skip_serializing_if = "Option::is_none"
    )]
    pub journal_line_limit: Option<u32>,
    /// One sentence saying what this result does not cover.
    #[serde(
        default,
        rename = "coverageNote",
        skip_serializing_if = "Option::is_none"
    )]
    pub coverage_note: Option<String>,
}

fn default_true() -> bool {
    true
}

/// A crash or restart line systemd wrote itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemdCrashSignal {
    pub unit: String,
    pub timestamp: String,
    /// `"main_process_exited"`, `"failed_result"`, `"scheduled_restart"` or `"start_limit_hit"`.
    pub kind: String,
    pub detail: Option<String>,
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
    /// uid of the user who owned the file when it was quarantined; 0 (root
    /// only) for older records and Server Edition records.
    #[serde(default, rename = "ownerUid")]
    pub owner_uid: u32,
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
    /// `false` when the scan did not finish (the package manager could not be
    /// determined, or the installed-package list could not be read): `findings`
    /// is then NOT a statement that the system is clean. Absent in older
    /// output, which means `true`.
    #[serde(default = "default_true")]
    pub complete: bool,
    /// Why the scan did not finish; absent when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<String>,
    /// Which CVE map was used (`"Debian"`, `"Ubuntu"`, `"Arch"`, ...). Absent
    /// when no package manager was found.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ecosystem: String,
    /// Ubuntu only: the release the host was matched as (`"24.04"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// How many findings need action and how many a person has accepted until
    /// a date. The tool never carries the reason or the account of an acceptance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<AcceptanceSummary>,
}

/// Counts of the findings of one package CVE scan.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AcceptanceSummary {
    /// Findings that need action: not accepted, or accepted until a date that has passed.
    pub open: usize,
    /// Findings under an acceptance in force.
    pub accepted: usize,
    /// Of `accepted`, those whose acceptance ends within a few days.
    pub expiring_soon: usize,
    /// Findings whose earlier acceptance has run out (counted in `open` as well).
    pub expired: usize,
}

/// A person's risk acceptance for a finding, as the tools carry it (without
/// the reason and the account).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedRisk {
    /// RFC 3339, UTC.
    pub accepted_at: String,
    /// RFC 3339, UTC. The finding is open again from this moment.
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PackageCveScanLanguagesResult {
    pub scanned_folder_count: usize,
    pub findings: Vec<PackageCveFinding>,
    /// See [`PackageCveScanResult::acceptance`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<AcceptanceSummary>,
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
    /// Language ecosystems only: absolute path of the lockfile the package was
    /// found in.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lockfile: String,
    /// Ubuntu only: the release the host was matched as.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub release: String,
    /// Ubuntu only: the installed binary packages built from `package`, comma separated.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub binary: String,
    /// Ubuntu only: the fix exists only in Ubuntu Pro (ESM).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pro_only: bool,
    /// FIRST's EPSS (0 to 1) on `epss_date`. A hint for ordering, not a
    /// confirmation that the CVE is exploited. Absent when the map has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    /// The day (`YYYY-MM-DD`) `epss` was taken.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub epss_date: String,
    /// CISA lists the CVE in its Known Exploited Vulnerabilities catalog.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub kev: bool,
    /// No fixed version has been published, so updating the package does not close this.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unfixed: bool,
    /// Set while a person's risk acceptance for this finding is in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<AcceptedRisk>,
    /// When an earlier acceptance ran out (RFC 3339); the finding counts as open again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance_expired_at: Option<String>,
}

/// The Critical Path FIM report inside the `verify_fim` answer (`criticalPathFim`;
/// the lockfile FIM report under `lockfileFim` has the same shape): ~150
/// critical system files/binaries re-hashed and compared against the persisted
/// baseline. The tool does NOT update or initialize the critical-path baseline —
/// that requires root and is a mutating operation intentionally not exposed via
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
    /// Reminder that the two isolated-port lists are a live snapshot, not a
    /// timeline. Absent from older `roamswitch-mcp` builds.
    #[serde(default)]
    pub current_port_state_note: String,
    /// Reminder that `incidents` is the only timeline. Absent from older builds.
    #[serde(default)]
    pub incidents_note: String,
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
    /// Milliseconds from the sensor's detection to this daemon reading the
    /// alert. Absent when the sensor gave no parsable time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect_to_receive_ms: Option<u64>,
    /// Milliseconds from reading the alert to the response being in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_to_action_ms: Option<u64>,
    /// The sum: how long an attacker had between detection and response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect_to_action_ms: Option<u64>,
}

/// State of the Falco heartbeat: whether a rule the daemon trips itself comes
/// back through Falco's output path.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct EbpfHeartbeatStatus {
    /// `"ok"`, `"silent"`, `"starting"`, `"idle"`, `"disabled"` or `"unsupported"`.
    pub state: String,
    /// Unix seconds of the last probe that came back, 0 if none yet.
    pub last_ok_at: i64,
    /// Round trip of that probe in milliseconds.
    pub last_rtt_ms: Option<u64>,
    /// Probes in a row that did not come back.
    pub consecutive_misses: u32,
    /// Unix seconds this status was written.
    pub updated_at: i64,
    /// Seconds between probes.
    pub interval_secs: u64,
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
    /// The Falco alert-path heartbeat, when the daemon has written one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<EbpfHeartbeatStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FimViolation {
    pub path: String,
    pub violation_type: String,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub detected_at: String,
    /// The writer's PID (event-driven watch only).
    #[serde(default)]
    pub pid: Option<i32>,
    /// Who made the change and through which login (event-driven watch only).
    /// Its inner shape (process facts, SSH/not-SSH origin) is still changing,
    /// so it stays untyped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intrusion: Option<serde_json::Value>,
}

/// The lockfile FIM part of `verify_fim`: the same report shape as the
/// critical-path part, or `{"error": "..."}` when its verification failed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum LockfileFimResult {
    Report(FimReport),
    Failed { error: String },
}

/// Wire format for `verify_fim` as `roamswitch-mcp` sends it today: the
/// Critical Path FIM report, the dependency-lockfile FIM report and who made
/// recent changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FimVerification {
    #[serde(rename = "criticalPathFim")]
    pub critical_path_fim: FimReport,
    /// Lockfile FIM of the Package CVE Scan watched project folders (a
    /// different baseline from the critical-path one). `None` when no folders
    /// are configured or Lockfile FIM is disabled.
    #[serde(default, rename = "lockfileFim")]
    pub lockfile_fim: Option<LockfileFimResult>,
    /// The latest changes the event-driven watch saw, each with the process
    /// that made it and the login it belongs to. Empty when the caller is not
    /// root. The records carry process and login facts whose shape is still
    /// changing, so they stay untyped.
    #[serde(default, rename = "recentIntrusionContext")]
    pub recent_intrusion_context: Vec<serde_json::Value>,
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
    /// Watched directories left out of `watchedDirectories` because the caller
    /// is neither an administrator nor the owner (a count, no paths).
    #[serde(default, rename = "hiddenDirectoriesCount")]
    pub hidden_directories_count: usize,
    /// Incidents left out of `recentIncidents` for the same reason.
    #[serde(default, rename = "hiddenIncidentsCount")]
    pub hidden_incidents_count: usize,
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
    /// `"link_guard"`, `"canary"`, `"ebpf_guard"`, `"resource_guard"`,
    /// `"exec_recorder"`, `"fleet"`, `"incident_capture"`, `"honeytoken"`,
    /// `"persistence"`, `"fim"`, `"vuln_acceptance"`, ... (new sources are
    /// added over time).
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
    /// The event that caused this one, when a writer knew its id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    /// The first event of the chain this one belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_event_id: Option<String>,
    /// Evidence saved for this event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<EvidenceRef>,
}

/// Points from a timeline row to saved evidence: the bundle folder name (never
/// a path), optionally one file in it and that file's SHA-256.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRef {
    pub bundle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
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
    /// The last pass; `None` before the first one.
    #[serde(default)]
    pub last_run: Option<FileScanRunStatus>,
}

/// What the last File Scan Guard pass did, with the text of the errors it hit.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FileScanRunStatus {
    /// Unix seconds when the pass ended.
    pub at: i64,
    pub files_scanned: usize,
    pub hits: usize,
    pub quarantined: usize,
    pub error_count: usize,
    /// The first few error texts.
    pub errors: Vec<String>,
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
    /// Whether the guard's firewall table is actually installed. Absent when
    /// not known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_installed: Option<bool>,
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
    /// The storage guard is on and actually working. Absent from older builds.
    #[serde(default)]
    pub storage_guard_effective: Option<bool>,
    /// The BadUSB guard is on and actually working. Absent from older builds.
    #[serde(default)]
    pub keyboard_guard_effective: Option<bool>,
    pub connected_devices: Vec<UsbDeviceInfo>,
    pub allowed_devices: Vec<AllowedUsbDevice>,
    pub pending_approvals: Vec<PendingApproval>,
    pub summary: String,
    pub caveats: Vec<String>,
}

// ---------------------------------------------------------------------------
// Shared: why a guard that is switched on does not (fully) work
// ---------------------------------------------------------------------------

/// A guard that is switched on in the settings but known for certain not to
/// (fully) work, with the reason. Carried by `get_guard_status`,
/// `get_detection_coverage`, `get_honeytoken_status` and
/// `get_ransomware_entropy_guard_status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InactiveInfo {
    pub guard: String,
    /// Localized display name of the guard.
    pub name: String,
    /// `"off"` / `"partial"`.
    pub state: String,
    /// Stable machine code of the reason.
    pub code: String,
    /// Localized explanation.
    pub message: String,
    /// Localized one-line next step.
    pub next_step: String,
}

/// What a daemon guard could not read from one input source (a log, the
/// journal, ...). Part of `get_guard_status`'s `collectors` object.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct CollectorHealth {
    pub restarts: u64,
    pub rotation_events: u64,
    pub unreadable: u64,
    pub lines_dropped_oversize: u64,
    pub lossy_utf8_lines: u64,
    /// Unix seconds of the last gap; `None` when none was recorded.
    pub last_gap_time: Option<i64>,
    pub last_gap_kind: Option<String>,
    /// Whether the source could be read at the last attempt; `None` when not tried yet.
    pub readable: Option<bool>,
    pub unreadable_since: Option<i64>,
    /// Unix seconds this snapshot was taken.
    pub updated_at: i64,
}

// ---------------------------------------------------------------------------
// verify_security_findings
// ---------------------------------------------------------------------------

/// Verdict of one re-checked finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingVerdict {
    /// The check applies and still fails.
    StillPresent,
    /// The check passes, or by design does not apply on this host.
    Resolved,
    /// This process could not observe the state reliably (see `reason`).
    Inconclusive,
    /// A verdict newer than this crate knows.
    #[serde(other)]
    Unknown,
}

/// One re-verified finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingVerification {
    pub check_id: String,
    pub title: String,
    pub verdict: FindingVerdict,
    /// Language-independent code: `failing`, `passing`, `not_applicable`,
    /// `not_root`, `daemon_unknown`, `tool_missing`, `tool_timeout`,
    /// `docker_unreachable`, `not_verifiable`, `unconfirmed`, `unknown_check_id`.
    pub reason: String,
    /// Localized status text of the underlying check.
    pub status_text: String,
    /// Localized detail of the underlying check.
    pub detail: String,
    /// `"verified"` / `"false_positive"` (the check does not apply here by
    /// design) / `"unverified"`.
    pub verification_status: String,
    /// One English sentence saying whether the finding still reproduces.
    pub rationale: String,
    /// Only on `stillPresent` results of a known check: the strongest reason
    /// the failure could be benign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_evidence: Option<String>,
    /// Only on `stillPresent` results of a known check: what would make the
    /// severity higher or lower.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity_changes_if: Option<String>,
    /// What changed since the check was last measured conclusively: `"fixed"`,
    /// `"already_resolved"` (not a fix), `"still_present"`, `"newly_present"`
    /// or `"no_earlier_check"`. Absent on `inconclusive` results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<String>,
    /// The earlier conclusive verdict `change` compares with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_verdict: Option<FindingVerdict>,
    /// ISO 8601 (UTC) time of that earlier measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingVerificationReport {
    pub results: Vec<FindingVerification>,
    pub caveats: Vec<String>,
    /// ISO 8601 (UTC).
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// get_port_scan_incidents / get_ssh_guard_incidents
// ---------------------------------------------------------------------------

/// One confirmed incoming port scan. Plain snake_case on the wire (mirrors the
/// daemon's `port_scan_incidents.json`). Server Edition's guard writes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortScanIncidentRecord {
    /// RFC 3339.
    pub timestamp: String,
    pub source_ip: String,
    pub distinct_port_count: usize,
    /// A sample of the ports touched, ascending.
    pub sample_ports: Vec<u16>,
    /// Whether the source was also auto-blocked.
    pub blocked: bool,
    pub block_duration_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PortScanIncidentsSummary {
    pub incidents: Vec<PortScanIncidentRecord>,
}

/// One SSH brute-force guard event worth recording. Plain snake_case on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct SshGuardIncidentRecord {
    /// RFC 3339.
    pub timestamp: String,
    /// `"ban"`, `"detect_only"`, `"exempt"` or `"success_after_failures"` (a
    /// login that followed a run of failures from the same source: a
    /// credential may have been guessed).
    pub kind: String,
    /// The address, or the /64 for IPv6.
    pub source: String,
    pub failures: u32,
    pub window_secs: u64,
    /// How many different user names were tried (the names are not kept).
    pub distinct_users: usize,
    pub banned: bool,
    pub ban_secs: Option<u64>,
    /// Earlier bans of the same source.
    pub repeat: u32,
    /// `"fail2ban"` / `"crowdsec"` when the ban was left to it.
    pub yielded_to: Option<String>,
    pub exempt_reason: Option<String>,
    /// For `success_after_failures`: the account logged into and how.
    pub login_user: Option<String>,
    pub login_method: Option<String>,
}

/// The running SSH guard's own status file. Plain snake_case on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct SshGuardStatus {
    /// `"block"`, `"detect_only"` or `"disabled"`.
    pub mode: String,
    pub reason: String,
    /// `"fail2ban"` / `"crowdsec"` when the ban is left to it.
    pub yielded_to: Option<String>,
    pub ports: Vec<u16>,
    /// `"journal"` or the log file being followed.
    pub source: String,
    pub daemon_pid: u32,
    pub updated_at: i64,
    pub active_bans: usize,
}

/// A source banned right now. Plain snake_case on the wire; unix seconds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SshBanEntry {
    /// `1.2.3.4`, `2001:db8::1` or `2001:db8:0:1::/64`.
    pub target: String,
    pub banned_at: i64,
    /// When the ban ends.
    pub until: i64,
    pub failures: u32,
    /// Earlier bans of the same source.
    pub strikes: u32,
    /// `false` in detect-only mode: recorded, never loaded into the firewall.
    pub enforced: bool,
}

impl Default for SshBanEntry {
    fn default() -> Self {
        Self {
            target: String::new(),
            banned_at: 0,
            until: 0,
            failures: 0,
            strikes: 0,
            enforced: true,
        }
    }
}

/// Wire format for `get_ssh_guard_incidents`: Server Edition, and the Linux
/// client while sshd runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SshGuardIncidentsSummary {
    /// Whether a daemon refreshed the status file lately.
    pub running: bool,
    /// `None` when no daemon is running.
    pub status: Option<SshGuardStatus>,
    /// Localized explanation of `status.reason`; `None` without a status.
    pub reason_text: Option<String>,
    pub active_bans: usize,
    /// Banned sources with the time left. The ban list is root-only, so a
    /// non-root caller gets an empty list here and only the count above.
    pub bans: Vec<SshBanEntry>,
    /// Up to the most recent 200.
    pub incidents: Vec<SshGuardIncidentRecord>,
}

// ---------------------------------------------------------------------------
// get_fleet_status
// ---------------------------------------------------------------------------

/// Secret-free Fleet (organization management) status of this device. Plain
/// snake_case on the wire; times are unix seconds, 0 when never.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct FleetPublicStatus {
    pub enrolled: bool,
    pub org_id: Option<String>,
    pub device_id: Option<String>,
    pub device_label: Option<String>,
    /// Short fingerprint prefix of the pinned organization key.
    pub org_key_fp_prefix: Option<String>,
    pub org_key_epoch: u64,
    pub policy_version_applied: u64,
    pub policy_active: bool,
    pub policy_not_after: Option<u64>,
    /// Policy keys this edition only records.
    pub policy_unmapped_keys: Vec<String>,
    /// A daemon restart is needed before the policy takes effect.
    pub policy_restart_required: bool,
    pub policy_forwarding_destination: Option<String>,
    /// `"applied"`, `"fwd_not_allowlisted"`, `"fwd_plaintext"`.
    pub policy_forwarding_status: Option<String>,
    pub last_rejected_version: Option<u64>,
    pub last_rejected_code: Option<String>,
    pub checkin_interval_s: u64,
    pub last_attempt_at: u64,
    pub last_ok_at: u64,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    /// Why the device was removed from the fleet, if it was.
    pub removed_reason: Option<String>,
    pub removed_at: Option<u64>,
    /// `None` (no revocation notice ever seen), `"ignored:<reason>"` or `"applied"`.
    pub revocation_last: Option<String>,
    pub revocation_last_at: Option<u64>,
    pub fleet_service_key_configured: bool,
    pub base_host: Option<String>,
    pub updated_at: u64,
}

/// Wire format for `get_fleet_status`. Fleet has no remote command channel
/// and a device that is not enrolled sends nothing; the tool never returns
/// enrollment codes, tokens, keys or license data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetStatusSummary {
    pub fleet: FleetPublicStatus,
    /// Always `false`.
    pub remote_command_channel: bool,
}

// ---------------------------------------------------------------------------
// search_exec_events / get_process_tree
// ---------------------------------------------------------------------------

/// Filters of `search_exec_events`. Every field is optional; `None` is not
/// sent. `Default` searches the newest 100 records.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecEventQuery {
    /// Only records from the last N minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_minutes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Substring of the executable path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// User name or uid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Parent pid or name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Substring of executable, argv or working directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Default 100, at most 1000.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One entry of a recorded process ancestry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecAncestor {
    pub pid: u32,
    pub exe: Option<String>,
    pub comm: Option<String>,
}

/// `LD_PRELOAD`, `LD_AUDIT` and `LD_LIBRARY_PATH` of a process, kept only
/// when set in a way worth a look (`LD_PRELOAD`/`LD_AUDIT` at all, or
/// `LD_LIBRARY_PATH` pointing at a writable place).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecLdEnv {
    pub preload: Option<String>,
    pub audit: Option<String>,
    pub library_path: Option<String>,
}

/// One record of the exec/process recorder log. Plain snake_case on the wire.
/// `argv`, `cwd` and `exe` come from the process and are untrusted text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct ExecRecord {
    /// `"exec"` or `"uid"` (a uid change).
    pub kind: String,
    /// RFC 3339.
    pub ts: String,
    pub ts_ms: i64,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub euid: Option<u32>,
    pub prev_euid: Option<u32>,
    pub gid: Option<u32>,
    pub user: Option<String>,
    pub exe: Option<String>,
    pub comm: Option<String>,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub cgroup: Option<String>,
    pub container_id: Option<String>,
    pub exe_deleted: bool,
    pub exe_memfd: bool,
    pub exe_setuid: bool,
    pub exe_mtime: Option<i64>,
    pub sha256: Option<String>,
    pub ancestry: Vec<ExecAncestor>,
    /// Enrichment raced with process exit.
    pub partial: bool,
    /// `"netlink"` or `"procscan"`.
    pub src: String,
    /// Audit login uid: the account that logged in, kept across `sudo`/`su`.
    pub loginuid: Option<u32>,
    /// Audit session id.
    pub sessionid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ld_env: Option<ExecLdEnv>,
}

/// Result of the exec log's hash-chain check (tamper-evident, not
/// tamper-proof). `status` is `"ok"` (`segments`, and `unchecked_records` when
/// the log has checkpoints), `"not_chained"` (nothing was verified) or
/// `"broken"` (`seq`, `reason`, `reason_text`, and `previous_seq` for a
/// `segment_gap`). `reason` is one of `unreadable`, `missing_header`,
/// `checkpoint_mismatch`, `segment_gap`, `next_hash_mismatch`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecChainStatus {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<usize>,
    /// Records after the newest checkpoint, which an `ok` does not cover yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unchecked_records: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_seq: Option<u64>,
}

/// The exec recorder's own status file. Plain snake_case on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct ExecRecorderStatus {
    /// `"netlink"`, `"procscan"` or `"disabled"`.
    pub mode: String,
    pub note: String,
    pub updated: String,
    pub recorded: u64,
    pub dropped_events: u64,
    pub alerts: u64,
    pub chain_ok: Option<bool>,
    pub sigma_rules: u64,
    /// Sigma rules that were not loaded, each `{file, title, reason, detail?}`.
    pub sigma_rejected: Vec<serde_json::Value>,
    /// Unix seconds of the last write; 0 from an older version.
    pub updated_unix: i64,
    pub pid: u32,
}

/// Wire format for `search_exec_events`. When the log cannot be read,
/// `events` is empty and `error` says why (no log, or root-only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct ExecEventSearch {
    /// Newest first.
    pub events: Vec<ExecRecord>,
    #[serde(rename = "chainStatus", skip_serializing_if = "Option::is_none")]
    pub chain_status: Option<ExecChainStatus>,
    /// Deprecated: a Rust debug text of the same check (`Ok { segments: 3 }`).
    /// Read `chain_status`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ExecRecorderStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A process and its recorded descendants (up to 8 levels).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessTreeNode {
    pub pid: u32,
    pub exe: Option<String>,
    pub argv: Vec<String>,
    /// RFC 3339.
    pub ts: String,
    pub children: Vec<ProcessTreeNode>,
}

/// Wire format for `get_process_tree`. The tool answers an unknown pid or an
/// unreadable log with `{"error": "..."}` instead of this shape; the client
/// turns that into a [`RoamSwitchClientError::ToolError`](crate::RoamSwitchClientError).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessTree {
    /// Parents of the process, nearest first.
    pub ancestry: Vec<ExecAncestor>,
    pub tree: ProcessTreeNode,
}

// ---------------------------------------------------------------------------
// run_package_lifecycle_script_scan / run_typosquat_scan / run_npm_audit_signatures
// ---------------------------------------------------------------------------

/// A `package.json` lifecycle script (`preinstall`, `install`, `postinstall`,
/// `prepare`) under `node_modules`. A plain inventory, never a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleScriptFinding {
    pub package_name: String,
    pub package_version: String,
    pub script_name: String,
    pub script_command: String,
    /// Path of the package's `package.json`.
    pub relative_path: String,
    /// A lightweight heuristic match against risky shell patterns. Many
    /// legitimate scripts also match.
    pub is_danger_pattern: bool,
    /// Which pattern matched (for example `"curl | sh"`).
    pub danger_pattern_label: Option<String>,
}

/// A setting that makes dependency confusion possible, or a lockfile whose
/// package manager has no release-age gate. Read from files only; no registry
/// is asked, so each entry is a setting to look at, not a confirmed exposure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DependencyConfusionFinding {
    /// `"pip_extra_index"`, `"uv_unsafe_index"`, `"npm_unpinned_scope"`,
    /// `"npm_private_unscoped"` or `"release_age_gate_missing"`.
    pub kind: String,
    /// The file that carries the setting (or the lockfile).
    pub file: String,
    /// Index or registry host. Absent for `release_age_gate_missing`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// npm only: the scope, `@scope`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    /// npm only: how many packages come from that registry.
    pub package_count: usize,
    /// A few package names.
    pub packages: Vec<String>,
    /// `release_age_gate_missing` only: `"npm"`, `"pnpm"`, `"yarn"`, `"bun"` or `"uv"`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub manager: String,
    /// `release_age_gate_missing` only: a setting exists and is switched off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub explicitly_disabled: bool,
}

/// A package that gained install-time code since a person last recorded the
/// accepted state (`roamswitch scan-scripts --accept`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageInstallDrift {
    pub package_name: String,
    pub old_version: Option<String>,
    pub new_version: String,
    /// `"script_added"`, `"script_changed"`, `"native_added"` or
    /// `"new_package_with_install_code"`.
    pub kind: String,
    /// The lifecycle script concerned (script kinds only).
    pub script_name: Option<String>,
    /// `"high"` or `"medium"`.
    pub severity: String,
    pub danger_pattern_label: Option<String>,
}

/// Wire format for `run_package_lifecycle_script_scan`. Reads local files
/// only and runs nothing. The tool never records the accepted state, so an
/// agent cannot accept its own change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PackageLifecycleScriptScanResult {
    pub scanned_folder_count: usize,
    pub findings: Vec<LifecycleScriptFinding>,
    #[serde(default)]
    pub dependency_confusion: Vec<DependencyConfusionFinding>,
    /// When the state `drift` compares with was accepted (ISO 8601); `None`
    /// if none was, in which case `drift` is empty.
    #[serde(default)]
    pub baseline_accepted_at: Option<String>,
    #[serde(default)]
    pub drift: Vec<PackageInstallDrift>,
    /// `node_modules` folders found now that the accepted state does not
    /// cover; an empty `drift` says nothing about them.
    #[serde(default)]
    pub uncovered_folders: Vec<String>,
}

/// A dependency name suspiciously close to a well-known npm package. A
/// reference-only heuristic, not a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TyposquatFinding {
    /// The name as declared in `package.json`.
    pub dependency_name: String,
    /// The popular package it is close to.
    pub suspected_target: String,
    /// Edit distance (1 or 2).
    pub distance: usize,
    /// The project folder whose `package.json` declares the name.
    #[serde(default)]
    pub project_dir: String,
}

/// Wire format for `run_typosquat_scan`. Reads local files only and contacts
/// no registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TyposquatScanResult {
    pub scanned_folder_count: usize,
    pub findings: Vec<TyposquatFinding>,
}

/// Wire format for `run_npm_audit_signatures`. THIS TOOL CONTACTS THE NPM
/// REGISTRY (`npm audit signatures`) and is off by default. One struct covers
/// the three shapes the tool returns:
///
/// - disabled (`npm_audit_signatures_enabled` is not true in `config.json`):
///   `enabled: false` and `message`;
/// - npm was not found: `enabled: true`, `directory` and `message`;
/// - npm ran: `enabled: true`, `directory`, `raw_output`, `exit_code` and
///   `has_issues`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NpmAuditSignaturesResult {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    /// npm's own stdout and stderr, verbatim. It is not parsed because npm's
    /// wording is not a contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// A heuristic: non-zero exit code, or "invalid" / "missing registry
    /// signature" in the output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_issues: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// audit_mcp_configs / audit_agent_setup
// ---------------------------------------------------------------------------

/// One finding of `audit_mcp_configs`. Never carries an env or header value,
/// an argument or a secret. `server` and `file` come from the config files
/// and are untrusted text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpConfigFinding {
    /// Stable id: `code_loading_env`, `traffic_interception_env`,
    /// `auto_approve`, `remote_plain_http`, `shell_wrapper`, `hexstrike`,
    /// `world_writable_config`, `auto_trust_project_servers`,
    /// `unpinned_package_launcher`, `container_host_access`,
    /// `injection_exposure`.
    pub id: String,
    /// `"high"` or `"medium"`.
    pub severity: String,
    pub file: String,
    pub server: Option<String>,
    /// Short technical fact, never a secret.
    pub detail: String,
    /// Localized explanation and what to do about it.
    pub message: String,
}

/// Wire format for `audit_mcp_configs`. Reads the MCP client configuration
/// files only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpConfigAuditPayload {
    pub scanned_file_count: usize,
    pub scanned_files: Vec<String>,
    pub server_count: usize,
    /// Files that exist but could not be read or parsed. They were NOT
    /// audited, so no finding for them is not a clean result.
    pub unreadable_files: Vec<String>,
    pub findings: Vec<McpConfigFinding>,
}

/// One finding of `audit_agent_setup`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSetupFinding {
    /// Stable rule id, for example `override_instruction`,
    /// `remote_script_exec`, `hidden_tag_characters`.
    pub id: String,
    /// `"high"` or `"medium"`.
    pub severity: String,
    /// `"instructions"`, `"openclaw"`, `"mcp"`, `"project"` or `"settings"`.
    pub area: String,
    pub file: String,
    /// Short English technical fact (rule, line number, URL host), never a secret.
    pub detail: String,
    /// Localized explanation and what to do about it.
    pub message: String,
    /// OWASP Top 10 for LLM Applications ids.
    #[serde(default, rename = "owaspLlm")]
    pub owasp_llm: Vec<String>,
    /// MITRE ATT&CK ids, only where unambiguous.
    #[serde(default, rename = "attackId")]
    pub attack_id: Vec<String>,
}

/// Wire format for `audit_agent_setup` (JSON format). Reads the files that
/// steer AI coding agents; the text of those files is not copied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentSetupAuditPayload {
    pub scanned_file_count: usize,
    pub scanned_files: Vec<String>,
    pub skill_count: usize,
    pub open_claw_config_found: bool,
    /// Files that exist but could not be read. They were NOT audited.
    pub unreadable_files: Vec<String>,
    pub findings: Vec<AgentSetupFinding>,
    /// When the accepted state the drift findings compare with was recorded
    /// (ISO 8601); `None` if none was.
    pub baseline_accepted_at: Option<String>,
}

// ---------------------------------------------------------------------------
// get_detection_coverage
// ---------------------------------------------------------------------------

/// How well RoamSwitch notices one ATT&CK technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageLevel {
    /// The technique itself is recognized.
    Detects,
    /// A named part of it is.
    Partial,
    /// Nothing looks for it.
    #[serde(rename = "none")]
    Nothing,
    /// A level newer than this crate knows.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TechniqueCoverage {
    /// MITRE ATT&CK technique id.
    pub id: String,
    pub name: String,
    /// `"linux"`.
    pub platform: String,
    pub coverage: CoverageLevel,
    /// The guards or features that would notice.
    pub covered_by: Vec<String>,
    /// One localized sentence on what is not seen.
    pub blind_spot: String,
    /// `"on"`, `"off"`, `"partial"`, `"unknown"` or `"not_applicable"`.
    pub live_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageGuardState {
    pub id: String,
    /// `"on"`, `"off"`, `"partial"` or `"unknown"`.
    pub state: String,
    /// Why a guard that is switched on does not (fully) work, when certain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<InactiveInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageSummary {
    pub total: usize,
    pub detects: usize,
    pub partial: usize,
    pub none: usize,
    /// Covered techniques whose covering guards are all off or not running.
    pub covered_but_off: usize,
}

/// Wire format for `get_detection_coverage` (JSON format): a hand-written
/// self-check of what RoamSwitch can and cannot see, for one edition. It states
/// what the product watches, not how well; a technique that is not listed was
/// not assessed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageReport {
    /// `"linux"`.
    pub platform: String,
    /// `"client"` or `"server"`.
    pub edition: String,
    pub summary: CoverageSummary,
    pub techniques: Vec<TechniqueCoverage>,
    /// The state of every guard some technique relies on.
    pub guards: Vec<CoverageGuardState>,
    /// Every guard that is switched on and not (fully) working.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inactive: Vec<InactiveInfo>,
    pub caveats: Vec<String>,
}

// ---------------------------------------------------------------------------
// get_sensor_audit_results
// ---------------------------------------------------------------------------

/// An active audit this device asked a paired RoamSwitch Sensor to run
/// against it. Plain snake_case on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SensorAuditResult {
    pub request_id: String,
    pub sensor_addr: String,
    /// RFC 3339.
    pub requested_at: String,
    /// `"pending"`, `"completed"` or `"failed"`.
    pub status: String,
    /// RFC 3339, set once `status` leaves `pending`.
    #[serde(default)]
    pub completed_at: Option<String>,
    /// How many times the result was pulled so far.
    #[serde(default)]
    pub attempts: u32,
    /// The Sensor's own report, passed on as it is. Its shape belongs to the
    /// separate Sensor product and may change, so it stays untyped. `None`
    /// until `status` is `completed`.
    #[serde(default)]
    pub findings: Option<serde_json::Value>,
    /// Set only when the Sensor refused the pull (currently `"not_paired"`).
    #[serde(default)]
    pub failure_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// get_honeytoken_status / get_ransomware_entropy_guard_status
// ---------------------------------------------------------------------------

/// Where the Client Edition planted the decoy credential files and how their
/// watcher is doing, as the caller may see it. The Server Edition only
/// reports `home`, `home_visible` and `home_source` (`"server_conf"`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HoneytokenPlacement {
    /// `None` when the caller may not see it (another user's home).
    pub home: Option<String>,
    pub home_visible: bool,
    /// Why that home: `"sudo_user"`, `"config"`, `"session"`, `"first_home"`,
    /// `"fallback"` or `"server_conf"`.
    pub home_source: String,
    #[serde(default)]
    pub deploy_ok: Option<bool>,
    #[serde(default)]
    pub deploy_error: String,
    #[serde(default)]
    pub watcher_pid: u32,
    /// How many times the watcher was started again after it ended.
    #[serde(default)]
    pub restarts: u64,
    #[serde(default)]
    pub last_exit: String,
    /// Other homes that got no decoys.
    #[serde(default)]
    pub other_homes: usize,
    /// Unix seconds.
    #[serde(default)]
    pub updated_at: i64,
}

/// One access to a decoy credential file (or one cascade deployment of more
/// decoys). A real access is a strong signal of credential harvesting
/// (MITRE T1552). `accessed_by` and the process fields are untrusted text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HoneytokenEvent {
    pub timestamp: String,
    /// `"access"` or `"cascade_deploy"`.
    pub event_type: String,
    /// Decoy kind: `aws_credentials`, `ssh_private_key`, `docker_config`, ...
    pub kind: Option<String>,
    /// The decoy that was opened.
    pub path: Option<String>,
    pub severity: String,
    pub suspected_process: Option<String>,
    pub suspected_pid: Option<u32>,
    pub accessed_by: Option<String>,
    /// Names of the parents of the process, nearest first.
    pub process_ancestry: Vec<String>,
    /// MITRE ATT&CK technique id.
    pub attack_technique: Option<String>,
}

/// Wire format for `get_honeytoken_status`. The guard only records and
/// notifies; it never cuts the network. Check `events_readable` before reading
/// an empty `recent_events` as "no access", and `enabled` / `inactive` before
/// reading it as "the guard ran the whole time".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HoneytokenStatus {
    /// `"client"` or `"server"`.
    pub edition: String,
    /// `None` when `server.conf` is not readable by this user.
    pub enabled: Option<bool>,
    /// `"honeytokens_enabled"`.
    pub setting: String,
    /// `"config.json"` or `"server.conf"`.
    pub setting_source: String,
    pub config_readable: bool,
    pub placement: Option<HoneytokenPlacement>,
    /// Why the guard is on but not working, when certain.
    pub inactive: Option<InactiveInfo>,
    /// `false` when the incident timeline could not be read.
    pub events_readable: bool,
    /// Up to the 50 most recent.
    pub recent_events: Vec<HoneytokenEvent>,
    /// Accesses left out because the decoy is in another user's home.
    pub hidden_events_count: usize,
    pub notes: Vec<String>,
    /// Why the timeline could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline_problem: Option<String>,
}

/// One burst of the entropy-based ransomware detection (20 files that look
/// encrypted within 5 seconds, written by one process).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EntropyIncident {
    pub id: String,
    /// RFC 3339, UTC.
    pub timestamp: String,
    pub pid: u32,
    /// Empty when the process had already gone before it could be named.
    pub process_name: String,
    /// At most 50 files the caller may see.
    pub affected_files: Vec<String>,
    /// How many files the burst counted.
    pub affected_files_total: usize,
    pub avg_entropy: f64,
    /// The writer was stopped (SIGSTOP).
    pub frozen: bool,
    /// Files of the burst this caller may not see, or that were not kept.
    #[serde(default)]
    pub hidden_files: usize,
}

/// Wire format for `get_ransomware_entropy_guard_status`. Check
/// `incidents_readable` before reading an empty `recent_incidents` as "no
/// burst": it is `false` when the file exists but could not be read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EntropyGuardStatus {
    /// `"client"` or `"server"`.
    pub edition: String,
    /// `None` when `server.conf` is not readable by this user.
    pub enabled: Option<bool>,
    /// `"config.json"` or `"server.conf"`.
    pub setting_source: String,
    pub config_readable: bool,
    /// The settings that decide the guard, by their real names. They differ by
    /// edition (`system_wide_fanotify_enabled`, ... on the client;
    /// `entropy_watch_enabled`, `entropy_watch_dirs`, ... on the server, where
    /// `entropy_watch_dirs` is a `{configured, hiddenFromThisUser}` object for
    /// a non-administrator), so they stay untyped. `None` when unreadable.
    pub settings: Option<serde_json::Value>,
    /// Client Edition: always `true`. Server Edition: `entropy_watch_freeze`.
    pub freezes_on_detection: Option<bool>,
    pub inactive: Option<InactiveInfo>,
    pub incidents_file: String,
    pub incidents_readable: bool,
    /// Up to 50, newest first.
    pub recent_incidents: Vec<EntropyIncident>,
    pub hidden_incidents_count: usize,
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// get_lan_sensor_overview / get_lan_network_threats
// ---------------------------------------------------------------------------

/// Answer of the two Sensor tools. The tool talks only to the local Unix
/// socket of a RoamSwitch Sensor on this host. No Sensor on the host is a
/// normal answer: `available: false` with a `reason` (`not_installed`,
/// `not_running`, `permission_denied`, `timeout`, `sensor_error`, ...), not an
/// error. Strings inside `data` come from devices on the network and are
/// untrusted. When `coverage_gaps` is not empty the Sensor cannot see part of
/// the LAN right now: zero threats then does NOT mean nothing is wrong, and
/// `mcp_caution` says so.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    rename_all = "camelCase",
    bound(
        deserialize = "T: serde::Deserialize<'de>",
        serialize = "T: serde::Serialize"
    )
)]
pub struct SensorReply<T> {
    pub available: bool,
    /// Why `available` is `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_note: Option<String>,
    /// The Sensor's own error text (`reason` is `sensor_error`). Untrusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor_error: Option<String>,
    /// `Some(false)` when the Sensor answered with a schema this server does
    /// not understand; then `data` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_supported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_schema: Option<u64>,
    /// Coverage-gap codes (`capture_stalled`, `capture_open_failed`, ...).
    #[serde(default)]
    pub coverage_gaps: Vec<String>,
    #[serde(default)]
    pub mcp_caution: Option<String>,
    /// The Sensor's reply (schema 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanSensorInfo {
    pub public_key: String,
    pub version: String,
    pub site: String,
    /// The Sensor is in lockdown.
    pub lockdown: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanNetworkInfo {
    pub gateway_ip: Option<String>,
    pub gateway_mac: Option<String>,
    pub sensor_addr: Option<String>,
    pub devices_total: usize,
    pub devices_online: usize,
    /// Devices with no operator note yet.
    pub devices_unregistered: usize,
    pub devices_ipv6_only: usize,
    pub vlans: Vec<u16>,
    /// RFC 3339; `None` before the first refresh.
    pub last_updated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanCaptureInfo {
    /// `"listening"`, `"open_failed"` or `"off"`.
    pub state: String,
    pub interface: String,
    pub frames: u64,
    pub kernel_drops: u64,
    /// Coverage-gap codes.
    pub coverage_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanBehaviorInfo {
    /// IoT devices whose behavior baseline was learned.
    pub learned_devices: usize,
    pub anomalies_active: usize,
}

/// Counts of unmanaged devices with each kind of weak spot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanUnmanagedAudits {
    pub devices_audited: usize,
    pub kev_confirmed: usize,
    pub kev_product: usize,
    pub noauth_open: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanThreatCounts {
    pub total: usize,
    /// Keys `critical`, `high`, `medium`, `info`.
    pub by_severity: std::collections::BTreeMap<String, usize>,
    /// Keyed by threat category.
    pub by_category: std::collections::BTreeMap<String, usize>,
}

/// `data` of `get_lan_sensor_overview` (Sensor schema 1; plain snake_case;
/// fields are only ever added).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanOverview {
    pub schema: u64,
    pub generated_at: String,
    pub sensor: LanSensorInfo,
    pub network: LanNetworkInfo,
    pub capture: LanCaptureInfo,
    pub paired_endpoints: usize,
    pub behavior: LanBehaviorInfo,
    pub unmanaged_audits: LanUnmanagedAudits,
    pub threats: LanThreatCounts,
}

/// One LAN threat the Sensor knows. Text fields are untrusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanThreat {
    /// The Sensor's notifier event id; 0 for a finding built from a stored
    /// light audit of an unmanaged device.
    pub id: u64,
    /// RFC 3339.
    pub time: String,
    /// `rogue_dhcp`, `rogue_ipv6_router`, `ndp_spoof`, `ipv6_only_device`,
    /// `arp_spoof`, `arp_scan`, `new_device`, `dns_tunnel`, `outbound_flood`,
    /// `malicious_destination`, `iot_behavior`, `behavior_anomaly`,
    /// `unmanaged_weak_device`.
    pub category: String,
    pub kind: String,
    /// `"critical"`, `"high"`, `"medium"` or `"info"`.
    pub severity: String,
    /// A MAC, an IP or a device name.
    pub subject: String,
    pub summary: String,
    /// The finding's own fields. They differ per `kind`, so they stay untyped.
    pub detail: serde_json::Value,
}

/// `data` of `get_lan_network_threats` (Sensor schema 1; plain snake_case).
/// The list comes from the Sensor's in-memory notification history (the last
/// 500 events, lost when the Sensor restarts) and its stored light audits, so
/// it is not a complete log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanThreats {
    pub schema: u64,
    pub generated_at: String,
    pub site: String,
    pub sensor_public_key: String,
    /// Newest first.
    pub threats: Vec<LanThreat>,
    /// What the Sensor cannot see right now.
    pub coverage_notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// get_privilege_escalation_paths
// ---------------------------------------------------------------------------

/// One step of a path to root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscalationEdge {
    pub from: Option<String>,
    pub to: Option<String>,
    /// The first reason, for example `docker_group` or `suid_gtfobins`.
    pub kind: Option<String>,
    pub reason: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EscalationAttack {
    pub technique_id: Option<String>,
    pub technique_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscalationPriority {
    /// `"critical"`, `"high"`, `"medium"` or `"low"`. Only critical and high
    /// are listed as urgent.
    pub level: Option<String>,
    /// 0 to 100.
    pub score: Option<u8>,
}

/// An urgent fix (priority critical or high). The fix commands PathScope
/// suggests are never returned and never run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UrgentEscalationFix {
    pub edge: Option<EscalationEdge>,
    /// How many paths pass through this step.
    pub impact: Option<u64>,
    pub priority: EscalationPriority,
    pub attack: Option<EscalationAttack>,
    pub remediation_summary: Option<String>,
}

/// What PathScope found for one account.
///
/// `complete` is `false` when part of the machine was not looked at (PathScope
/// ran without root, or `uncollected_by_kind` is not empty): zero paths then
/// does NOT mean the account is safe, and `mcp_caution` says so. It also
/// defaults to `false` when nothing was analysed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct PrivilegeEscalationAnalysis {
    pub start: Option<String>,
    pub goal: Option<String>,
    pub os: Option<String>,
    pub privileged: Option<bool>,
    /// How many paths to root there are.
    pub paths: u64,
    /// The first 20 paths, each as its steps.
    pub paths_shown: Vec<Vec<EscalationEdge>>,
    pub urgent_total: u64,
    /// The first 20 urgent fixes.
    pub urgent: Vec<UrgentEscalationFix>,
    /// What PathScope could not collect, by kind.
    pub uncollected_by_kind: std::collections::BTreeMap<String, u64>,
    pub uncollected_fixable_with_privilege: std::collections::BTreeMap<String, u64>,
    pub notes: Vec<String>,
    pub complete: bool,
    pub mcp_caution: Option<String>,
}

/// One account of the `checkAgentUsers` mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscalationAgentUser {
    pub user: Option<String>,
    pub uid: Option<u32>,
    pub entry: Option<String>,
    pub analysis: Option<PrivilegeEscalationAnalysis>,
}

/// An `agent_users` entry that was not analysed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscalationSkippedEntry {
    pub entry: Option<String>,
    pub reason: Option<String>,
}

/// Wire format for `get_privilege_escalation_paths`: how a local account
/// could reach root, from the separately installed PathScope (run as the
/// calling user, nothing is applied). Names, paths and file names come from
/// the system and are untrusted.
///
/// - Analysed one account (`mode` `"single"`): `analyzed` is `true` and the
///   result is in `analysis` (flattened into the same object on the wire).
/// - Analysed every `agent_users` account (`mode` `"agent_users"`): `users`
///   and `skipped`; `analysis.complete` and `analysis.mcp_caution` are the
///   overall answer.
/// - Not analysed: `analyzed` is `false`, `reason` is a code (`not_installed`,
///   `not_trusted`, `timeout`, `not_permitted`, `unknown_schema`, `exit_2`,
///   ...) and `mcp_note` says why. `available` is `false` when PathScope is
///   not installed or not trusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegeEscalationPaths {
    pub available: bool,
    pub analyzed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_note: Option<String>,
    /// PathScope's own first words of error text. Untrusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pathscope_error: Option<String>,
    /// `"single"` or `"agent_users"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_user: Option<String>,
    /// `agent_users` mode: `"pathscope.agent-users/v1"`. With `reason`
    /// `unknown_schema`: the schema that was not understood.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<usize>,
    #[serde(default)]
    pub users: Vec<EscalationAgentUser>,
    #[serde(default)]
    pub skipped: Vec<EscalationSkippedEntry>,
    #[serde(flatten)]
    pub analysis: PrivilegeEscalationAnalysis,
}

// ---------------------------------------------------------------------------
// get_access_log_report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessScopeTool {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessScopeRisk {
    /// 0 to 100.
    pub score: u8,
    /// `"none"`, `"low"`, `"mid"` or `"high"`.
    pub level: String,
}

/// AccessScope's coverage object. `partial` is `true` when some part of the
/// logs could not be examined. Only `partial`, `notes` and `files_not_read` are
/// fixed by the `accessscope-brief/1` schema; the detailed counters
/// (`lines`, `sources`, `time`) are AccessScope's own and stay untyped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessScopeCoverage {
    pub partial: bool,
    /// Note codes, for example `late_start`.
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub files_not_read: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessScopeUnreadSource {
    pub path: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessScopeSources {
    /// How many log sources were read.
    pub read: usize,
    /// Log sources that could not be read.
    pub unread: Vec<AccessScopeUnreadSource>,
}

/// One masked evidence line. The text is attacker-controlled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessScopeEvidence {
    /// Index into the source list.
    pub source: u32,
    pub line: u64,
    pub text: String,
}

/// One finding of the access-log report. Every string comes from logs that
/// attackers can write and is untrusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessScopeFinding {
    /// 1-based position.
    pub n: u32,
    pub kind: String,
    pub title: String,
    /// `"high"`, `"medium"` or `"low"`.
    pub severity: String,
    /// `"confirmed"`, `"likely"` or `"hypothesis"`.
    pub confidence: String,
    pub count: u64,
    /// Unix seconds.
    #[serde(default)]
    pub first: Option<i64>,
    #[serde(default)]
    pub last: Option<i64>,
    #[serde(default)]
    pub attack_id: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
    /// At most 3 masked lines.
    pub evidence: Vec<AccessScopeEvidence>,
}

/// AccessScope's `accessscope-brief/1` report, passed on as the tool received
/// it (strings cut to a bounded length).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessScopeBrief {
    pub schema: String,
    pub tool: AccessScopeTool,
    /// Unix seconds.
    pub generated_at: i64,
    pub risk: AccessScopeRisk,
    pub coverage: AccessScopeCoverage,
    pub sources: AccessScopeSources,
    pub findings_total: usize,
    /// At most 40.
    pub findings_shown: usize,
    pub findings: Vec<AccessScopeFinding>,
}

/// Wire format for `get_access_log_report`: attacks found in this host's web
/// server, SSH and auth logs by the separately installed AccessScope, run as
/// the calling user (privilege is never raised). Every string in `report`
/// comes from logs attackers can write and is untrusted.
///
/// When `complete` is `false` (the analysis is partial, or `report.sources.unread`
/// is not empty) part of the logs was not examined: zero findings does NOT mean
/// the host is safe, and `mcp_caution` says so.
///
/// Not analysed: `analyzed` is `false` and `reason` is `not_installed`,
/// `not_trusted`, `nothing_read` (no readable log), `timeout`, `unknown_schema`,
/// ... with `mcp_note`. `available` is `false` when AccessScope is not
/// installed or not trusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogReport {
    pub available: bool,
    pub analyzed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_note: Option<String>,
    /// AccessScope's own first words of error text. Untrusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessscope_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_supported: Option<bool>,
    /// `"accessscope-brief/1"`. With `reason` `unknown_schema`: the schema
    /// that was not understood.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// The window that was asked for, like `24h` or `7d`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings_shown: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_partial: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread_sources: Option<u64>,
    /// `false` when part of the logs was not examined, and also when nothing
    /// was analysed.
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub mcp_caution: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<AccessScopeBrief>,
}
