//! Offline wire-format tests: each sample below is the JSON shape
//! `roamswitch-mcp` sends for a tool, so these run (and must pass) without
//! RoamSwitch installed — unlike `client_tests.rs`, which skips in that case.

use roamswitch_linux_kit::*;

#[test]
fn guard_status_accepts_old_and_new_payloads() {
    let old = r#"{"activeSecurityLevel":"balanced","activeSecurityLevelLabel":"Balanced","isCurrentNetworkTrusted":false,
        "guards":[{"key":"portAnomalyGuard","enabledInSettings":true}],"caveats":[]}"#;
    let st: GuardStatus = serde_json::from_str(old).expect("old payload");
    assert!(st.settings.is_none());

    let new = r#"{"activeSecurityLevel":"lockdown","activeSecurityLevelLabel":"Travel","isCurrentNetworkTrusted":false,
        "guards":[{"key":"linkGuard","enabledInSettings":true},{"key":"vpnOnUntrusted","enabledInSettings":false}],"caveats":[],
        "settings":{"linkGuardMode":"block","vpnBackend":"tailscale","dnsScope":"untrusted_only","dnsProvider":"quad9"}}"#;
    let st: GuardStatus = serde_json::from_str(new).expect("new payload");
    assert_eq!(st.settings.unwrap().vpn_backend, "tailscale");
}

#[test]
fn quarantine_status_with_and_without_clamav() {
    let raw = r#"{"itemCount":0,"items":[],"quarantineDirectory":"/home/u/.local/share/roamswitch/quarantine","exclusionPaths":["/tmp"],
        "clamav":{"is_installed":false,"engine_version":"Not installed","database_version":"--","last_updated":"--","is_up_to_date":false}}"#;
    let st: QuarantineStatus = serde_json::from_str(raw).expect("with clamav");
    assert!(!st.clamav.unwrap().is_installed);

    let raw = r#"{"itemCount":0,"items":[],"quarantineDirectory":"/q","exclusionPaths":[]}"#;
    assert!(serde_json::from_str::<QuarantineStatus>(raw).expect("without clamav").clamav.is_none());
}

#[test]
fn secret_path_result_distinguishes_directory_from_file() {
    let dir = r#"{"filesScanned":2,"hasLeaks":true,"findingCount":1,"summary":"1 leak",
        "flaggedFiles":[{"path":"/p/.env","findings":[{"secretType":"AWS Access Key ID","provider":"AWS","masked":"AKIAAB...MNOP",
        "lineNumber":1,"entropy":3.9,"recommendation":"Deactivate the access key in the AWS IAM console.","isSevere":true}]}]}"#;
    match serde_json::from_str::<SecretPathAuditResult>(dir).expect("dir") {
        SecretPathAuditResult::Directory(d) => assert_eq!(d.flagged_files[0].findings.len(), 1),
        other => panic!("expected Directory, got {other:?}"),
    }
    let file = r#"{"hasLeaks":false,"findingCount":0,"findings":[],"summary":"safe"}"#;
    assert!(matches!(serde_json::from_str::<SecretPathAuditResult>(file).expect("file"), SecretPathAuditResult::File(_)));
}

#[test]
fn timeline_resource_guard_and_file_scan_guard_payloads() {
    let ev = r#"{"id":"1","timestamp":"2026-09-14T00:00:00+00:00","source":"canary","severity":"Critical","summary":"Canary tampered",
        "process_name":"enc","process_pid":42,"process_ancestry":[{"pid":1,"name":"systemd"}],
        "attack_technique":{"id":"T1486","name":"Data Encrypted for Impact"},"action_taken":"contained",
        "containment_latency_ms":null,"resolved_at":null,"resolution":null}"#;
    let e: TimelineEvent = serde_json::from_str(ev).expect("timeline event");
    assert_eq!(e.attack_technique.unwrap().id, "T1486");

    let rg = r#"{"incidents":[{"event":{"timestamp":"t","kind":"crash_loop","proc_name":"app","pid":7,"unit_or_container":"app.service",
        "confidence":"possible","matched_signals":[],"detail":"restarted 5x"},"action_taken":"logged"}]}"#;
    let s: ResourceGuardIncidentsSummary = serde_json::from_str(rg).expect("resource guard");
    assert_eq!(s.incidents[0].event.kind, "crash_loop");

    let fsg = r#"{"clamavEnabled":true,"scanDirs":["/srv"],"scanIntervalSecs":3600,"freshclamIntervalSecs":86400,
        "quarantine":{"itemCount":0,"items":[],"quarantineDirectory":"/var/lib/roamswitch/quarantine","exclusionPaths":[]}}"#;
    let st: FileScanGuardStatus = serde_json::from_str(fsg).expect("file scan guard");
    assert_eq!(st.scan_interval_secs, 3600);
}

#[test]
fn runtime_status_payloads() {
    let vpn = r#"{"daemonRunning":true,"vpnOnUntrustedEnabled":true,"backend":"wireguard","activeLevel":"lockdown",
        "tunnelExpectedNow":true,"tunnelUp":true,"killSwitchArmed":true,"killSwitchVerified":null,
        "wireguard":{"toolsPresent":true,"configImported":null,"interfaceUp":true,"armed":true,"configName":"home",
          "endpoint":"203.0.113.5:51820","rxBytes":10,"txBytes":20,"lastHandshakeAgeSecs":null},
        "tailscale":{"toolsPresent":false,"running":false,"loggedIn":false,"tailnetName":null,"activeExitNode":null,
          "configuredExitNode":"","exitNodeCandidateCount":0,"armed":false},
        "summary":"The VPN tunnel is up and the kill-switch is armed (WireGuard)","caveats":[]}"#;
    let v: VpnStatusSummary = serde_json::from_str(vpn).expect("vpn");
    assert!(v.kill_switch_armed && v.kill_switch_verified.is_none());

    let lg = r#"{"daemonRunning":true,"enabled":true,"mode":"warn","effectiveMode":"warn","allowlist":["example.com"],
        "blocklistExtra":[],"useThreatDns":false,"xdpBootGateEnabled":false,
        "pendingDecisions":[{"id":"link_warn:evil.test","kind":"link_warn","title":"t","body":"b","deviceId":"evil.test","deviceName":"evil.test","createdAtMs":1}],
        "recentEvents":[{"timestamp":"2026-09-14T00:00:00+09:00","kind":"blocked","kindLabel":"Blocked","title":"🚫","body":"evil.test"}],
        "summary":"Link Guard: warn only (last 7 days: 1 blocked / 0 warned)","caveats":["..."]}"#;
    let l: LinkGuardStatusSummary = serde_json::from_str(lg).expect("link guard");
    assert_eq!(l.pending_decisions[0].kind, "link_warn");

    let ag = r#"{"daemonRunning":true,"active":true,"engagedAtUnix":1757800000,"activeForSecs":12,"autoReleaseAfterSecs":600,
        "triggerReason":"arp_spoof","trigger":{"reason":"arp_spoof"},"autoRfkillEnabled":true,
        "frozenProcesses":[{"pid":4242,"name":"enc","reason":"ransomware_burst","reasonLabel":"Ransomware encryption burst","frozenAt":"t"}],
        "summary":"Emergency Air-Gap is ACTIVE","caveats":[]}"#;
    let a: AirGapStatusSummary = serde_json::from_str(ag).expect("air gap");
    assert_eq!(a.frozen_processes[0].pid, 4242);

    let sh = r#"{"daemonRunning":false,"controlEnabled":true,"activeLevel":null,"stopsServicesOnCurrentLevel":null,
        "stoppedByRoamswitch":null,"services":[{"unit":"ssh.service","activeState":"active","isActive":true,"stoppedByRoamswitch":false}],
        "summary":"s","caveats":["daemon not running"]}"#;
    let s: SharingServicesStatusSummary = serde_json::from_str(sh).expect("sharing");
    assert!(s.stopped_by_roamswitch.is_none());

    let bt = r#"{"daemonRunning":true,"guardEnabled":true,"activeLevel":"balanced","networkTrusted":false,"shieldActiveNow":true,
        "controller":{"isAvailable":true,"isPowered":true,"isDiscoverable":false,"connectedDevicesCount":0,"connectedDevices":[],"isShieldedOnUntrusted":true},
        "summary":"s","caveats":[]}"#;
    let b: BluetoothGuardStatusSummary = serde_json::from_str(bt).expect("bluetooth");
    assert!(b.shield_active_now);

    let usb = r#"{"daemonRunning":true,"storageGuardEnabled":true,"keyboardGuardEnabled":false,"usbZeroTrustEnabled":false,"usbZeroTrustActive":false,
        "connectedDevices":[{"deviceIdentifier":"046d:c52b","displayName":"Unifying Receiver","vendorId":"046d","productId":"c52b",
          "serialNumber":null,"isStorage":false,"isKeyboard":true,"isPointer":true,"isAuthorized":true}],
        "allowedDevices":[{"deviceIdentifier":"046d:c52b","displayName":"Unifying Receiver","dateAdded":"2026-09-14 10:00"}],
        "pendingApprovals":[],"summary":"s","caveats":[]}"#;
    let u: UsbGuardStatusSummary = serde_json::from_str(usb).expect("usb");
    assert!(u.connected_devices[0].is_pointer && !u.connected_devices[0].is_hub);
}
