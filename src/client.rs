use crate::models::*;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

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

/// A read-only client for RoamSwitch's local Linux security diagnostics.
///
/// Every call spawns RoamSwitch's bundled `roamswitch-mcp` binary as a fresh
/// subprocess and talks to it over stdio using newline-delimited JSON-RPC 2.0
/// — the same protocol RoamSwitch speaks to Claude Desktop/Code and other
/// MCP clients. There is no persistent connection, no daemon socket, and no
/// network I/O anywhere in this crate: nothing is sent anywhere.
///
/// `RoamSwitchClient` has no API to change RoamSwitch's settings, toggle a
/// guard, isolate a port, or quarantine a file — that surface doesn't exist
/// here. Linking this crate gives no way to alter another user's protection
/// state; only RoamSwitch's own CLI/daemon, driven by the user, can do that.
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

    /// Runs RoamSwitch's full local Linux security audit (Community/Pro:
    /// 24 checks — FileVault-equivalent disk encryption, AppArmor, firewall,
    /// Wi-Fi encryption, ARP spoofing, exposed ports, guard configuration).
    pub async fn security_report(&self) -> Result<SecurityReport, RoamSwitchClientError> {
        self.call_tool("get_security_report", serde_json::json!({})).await
    }

    /// Runs the Server Edition audit (27 checks: kernel hardening, Docker
    /// and container runtime isolation, kernel CVE exposure, eBPF LSM, etc.)
    /// instead of the desktop client's 24-check audit.
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
    pub async fn run_active_vuln_scan(&self) -> Result<ActiveVulnScanResult, RoamSwitchClientError> {
        self.call_tool("run_active_vuln_scan", serde_json::json!({})).await
    }

    /// Current active security level, trusted-network status, and each
    /// optional guard's on/off state.
    pub async fn guard_status(&self) -> Result<GuardStatus, RoamSwitchClientError> {
        self.call_tool("get_guard_status", serde_json::json!({})).await
    }

    /// Analyzes a URL for phishing, Unicode homograph spoofing, brand
    /// subdomain deception, and high-risk TLDs — fully offline, zero
    /// telemetry. No network fetch of the URL itself is performed.
    pub async fn audit_url_safety(&self, url: &str) -> Result<LinkAuditReport, RoamSwitchClientError> {
        self.call_tool("audit_url_safety", serde_json::json!({ "url": url }))
            .await
    }

    /// Scans input text for exposed API keys and other secrets.
    pub async fn audit_secrets(&self, text: &str) -> Result<SecretAuditResult, RoamSwitchClientError> {
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
        self.call_tool(
            "get_app_help",
            serde_json::json!({ "query": query, "topic": topic }),
        )
        .await
    }

    /// Current malware quarantine vault status.
    pub async fn quarantine_status(&self) -> Result<QuarantineStatus, RoamSwitchClientError> {
        self.call_tool("get_quarantine_status", serde_json::json!({})).await
    }

    /// Ransomware Canary Guard status: monitored decoy files and any recent
    /// tamper incidents.
    pub async fn canary_status(&self) -> Result<CanaryStatus, RoamSwitchClientError> {
        self.call_tool("get_canary_status", serde_json::json!({})).await
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

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| RoamSwitchClientError::ProcessLaunchFailed("failed to open stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RoamSwitchClientError::ProcessLaunchFailed("failed to open stdout".to_string()))?;
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

        let resp_json: serde_json::Value = serde_json::from_str(&response_line)
            .map_err(|e| RoamSwitchClientError::InvalidResponse(format!("{}: {}", e, response_line)))?;

        if let Some(err) = resp_json.get("error") {
            let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error");
            return Err(RoamSwitchClientError::ToolError(msg.to_string()));
        }

        let content_text = resp_json
            .get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|item| item.get("text"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| RoamSwitchClientError::InvalidResponse("missing text content in result".to_string()))?;

        serde_json::from_str(content_text)
            .map_err(|e| RoamSwitchClientError::InvalidResponse(format!("failed to parse payload: {} (raw: {})", e, content_text)))
    }
}
