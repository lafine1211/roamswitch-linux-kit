# roamswitch-linux-kit

[English](README.md) | **日本語**

[RoamSwitch](https://lafine.net) がローカルで計算した Linux のネットワークセキュリティ診断結果を
取得するための、非同期の Rust クライアントです。RoamSwitch の設定を変更する API はありません。

[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://lafine.net/linux.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[RoamSwitchKit](https://github.com/lafine1211/RoamSwitchKit)（macOS / Swift）の Linux 版に
あたります。設計は同じで、RoamSwitch の状態を読めますが設定は変更できず、テレメトリも送りません。
Swift ではなく Rust 向けにラップしたものです。

## RoamSwitch とは

[**RoamSwitch**](https://lafine.net/linux.html) は、マシンのネットワーク境界を自動で防衛する
Linux 向けセキュリティツールです。未信頼ネットワークでは `nft` ルールを締め、ARP スプーフィングを
監視し、`0.0.0.0` で待ち受けたままの開発サーバーやデータベースを検出して警告します。
現在は無償の Community Edition として提供されています。

具体的に、RoamSwitch は次を常時計算しています。

- **ネットワーク信頼度** — 現在のネットワークが信頼登録済みか、また現在どの保護レベルが
  適用されているか
- **ARP スプーフィング** — 中間者攻撃の兆候となるゲートウェイ MAC フィンガープリントの変化
- **外部公開ポート** — `localhost` を超えて待ち受けている全 TCP ポート。設定ミスが多い既知
  サービス（Redis、MongoDB、Docker、Memcached、各種開発サーバー、Ollama / LM Studio などの
  ローカル AI 推論サーバー）と突き合わせ、危険な HTTP レスポンスも確認します
- **ローカルセキュリティ診断スコア（Client Edition は 31 項目）** — LUKS / dm-crypt ディスク暗号化、
  AppArmor / SELinux、UEFI Secure Boot、sudo / SSH 設定、カーネル `sysctl` 強化、Wi-Fi 暗号化、
  ARP スプーフィング、外部公開ポート、マルウェア・ダウンロード保護の設定
  （Server Edition では 42 項目のサーバー向けプロファイル）
- **オフライン URL / フィッシング解析**、**シークレット漏洩検査**、**セキュリティログ監査**、
  **ランサムウェア・カナリア状態**、**隔離 Vault の状態**
- **ガードの稼働状態** — VPN トンネルとキルスイッチ、受動リンクガードの遮断 / 警告履歴、
  Air-Gap と凍結中プロセス、共有サービス、Bluetooth / USB ガード

RoamSwitch はこれと同じデータを、同梱の MCP サーバーバイナリ `roamswitch-mcp`（45 ツール）
経由で AI アシスタント（Claude Desktop、Claude Code、その他
[MCP](https://modelcontextprotocol.io) 対応クライアント）にも提供しています
（設定方法は [lafine.net/mcp-setup](https://lafine.net/mcp-setup.html)）。
**本クレートは、その同じインターフェースを AI クライアントではなく Rust コードから使える
ようにしたもの**です。ARP 解析やポートスキャン、ログ監査を自前で再実装することなく、
「今このマシンのネットワークは安全か？」を RoamSwitch が算出したそのままのデータで取得できます。

想定用途: 未信頼ネットワークでバックグラウンド転送を止める同期アプリ、想定外に公開された
開発サーバーを検出したらジョブを失敗させる CI ランナー、複数マシンのセキュリティスコアを
集める監視スクリプト、ネットワーク信頼度の変化に反応する自動化ワークフローなど。

## 設計方針

- **RoamSwitch を変更する API はありません。** 本クレートは現在の診断結果を取得できるだけです。
  保護レベルの変更、ガードの切り替え、ポート隔離、ファイルの隔離、プロセスの凍結を行う呼び出しは
  ありません。それができるのは、ユーザー自身が操作する RoamSwitch の CLI やアプリだけです。
  これは未実装ではなく、意図したスコープの制限です。
- **`roamswitch-mcp` が宣言している内容。** `roamswitch-mcp` は 45 ツールのうち 42 を読み取り専用、
  3 つをそうでない（`readOnlyHint: false`）と宣言しています。`run_active_vuln_scan` は RoamSwitch の
  スキャン履歴に追記し、`audit_security_logs` は RoamSwitch のログテンプレートの基準ファイルを更新し、
  `run_npm_audit_signatures` は npm に自分のログとキャッシュを `~/.npm` へ書かせます。読み取り専用と
  宣言されている呼び出しのうち 2 つも、少しだけ書き込みます。`canary_status()` は、RoamSwitch の
  おとりファイルが監視フォルダーに無いとき作ります。`verify_fim_full()` のロックファイル部分は、新たに
  監視対象になったプロジェクトフォルダーのロックファイルを基準に加え、監視対象でなくなったものを外します。
  基準にすでにあるロックファイルの記録済みハッシュは置き換えません。
- **テレメトリはありません。** 本クレートはネットワーク接続もソケットも開きません。各呼び出しは
  `roamswitch-mcp` をサブプロセスとして起動します。`roamswitch-mcp` はネットワークへ何も送りません。
  例外は次のとおりです。
  - `run_npm_audit_signatures` は `npm audit signatures` を実行し、npm レジストリに問い合わせます。
    RoamSwitch の設定で `npm_audit_signatures_enabled` を true にしない限り動きません。
    `openWorldHint` が付くのはこのツールだけです。
  - `run_active_vuln_scan` は `127.0.0.1` にだけ TCP 接続します。ユーザーがオプトインしたときだけ動きます。
  - Server Edition では、`security_report` と `verify_security_findings` の `server_domain_check` 項目が、
    運用者が `domain_check_domains` に書いたドメインの DNS と RDAP を引きます。既定では空なので、
    既定では何も送りません。
- **新たな攻撃面を作らない。** 本クレートはソケットを開かず、サービスを登録せず、何も
  待ち受けません。プロセスを起動し、stdin にリクエストを書き、stdout から 1 件のレスポンスを
  読み、プロセスを終了させるだけです。
- **デーモンを操作しません。** Linux 版 RoamSwitch は CLI コマンドを受け付ける特権
  デーモンをローカル Unix ソケットで動かしています。そのソケットは Air-Gap 隔離の発動、プロセス凍結、
  USB デバイス承認の管理などもでき、本クレートがそのために使うことはありません。`roamswitch-mcp` には、設定や保護状態を
  変更するツールがありません。3 つのツールは、ローカル Unix ソケットへ読み取りの要求を 1 回ずつ送ります。
  `get_sensor_audit_results` は RoamSwitch デーモンに Sensor 監査結果の一覧を求め、
  `get_lan_sensor_overview` と `get_lan_network_threats` は同じホストの RoamSwitch Sensor のソケットから
  読みます。ほかの 2 つは、別にインストールされたプログラムを、呼び出したユーザーの権限と固定の引数で
  起動します。`get_privilege_escalation_paths` は PathScope を、`get_access_log_report` は AccessScope を
  起動します。
- **呼び出したユーザーの権限で動きます。** root でないと一部しか得られない答えがあります（exec ログ、
  SSH の遮断リスト、一部の FIM ファイル、PathScope と AccessScope の結果）。その場合、答えの
  フィールド（`error`、`complete`、`skipped_unreadable` など）がそう伝えます。そうした答えの 0 件は、
  問題がなかったという意味ではありません。これらのフィールドを確認してください。

## 動作要件

- 比較的新しい stable Rust ツールチェーン（2021 edition、1.98 でビルド・テスト）と `tokio`
  非同期ランタイム
- コードを実行するマシンに [RoamSwitch for Linux](https://lafine.net/linux.html) が
  インストール済みで、`roamswitch-mcp` が `PATH` にあること（公式 `.deb` / `.rpm` パッケージ
  では通常 `/usr/bin/roamswitch-mcp`）

## インストール

crates.io には未公開です。`Cargo.toml` に git 依存として追加してください。

```toml
[dependencies]
roamswitch-linux-kit = { git = "https://github.com/lafine1211/roamswitch-linux-kit", tag = "v0.2.0" }
```

## 使い方

```rust
use roamswitch_linux_kit::RoamSwitchClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = RoamSwitchClient::new(None, None)?;

    // 総合セキュリティ診断（ディスク暗号化、AppArmor、ファイアウォール、
    // Wi-Fi 暗号化、ARP スプーフィング、外部公開ポート — 0〜100 でスコア化し、
    // 不合格項目には改善アドバイスが付きます）。
    let report = client.security_report().await?;
    println!("{} ({})", report.score, report.grade);

    // localhost を超えて待ち受けている全ポート。既知の危険サービスや
    // 危険な HTTP レスポンスの観点で監査済みです。
    let ports = client.exposed_ports(false).await?;
    for port in ports.ports.iter().filter(|p| p.overall_risk.as_deref() == Some("high")) {
        println!("{} on port {}", port.process_name, port.port);
    }

    // RoamSwitch の自動対応ガードが有効かどうか、および現在の
    // ネットワークがユーザーの信頼リストに含まれるかどうか。
    let status = client.guard_status().await?;
    println!("{} {}", status.active_security_level_label, status.is_current_network_trusted);

    // メール中のリンク、短縮 URL、不審なドメインをフィッシング・Unicode
    // ホモグラフ偽装・ブランド偽装の観点で診断します（Zero Telemetry）。
    let url_report = client.audit_url_safety("https://apple.com.login-verify.xyz").await?;
    println!("{} {}", url_report.score, url_report.risk_level); // 例: 20, "dangerous"

    // インストール済み OS パッケージを、ネットワーク非依存のローカル
    // CVE マップと照合します。
    let pkg_cve = client.package_cve_scan().await?;
    for finding in &pkg_cve.findings {
        println!("{} {}: {} (CVSS {})", finding.package, finding.installed_version, finding.cve_id, finding.cvss_score);
    }

    // クリティカルパス FIM: 約 150 箇所の最重要システムファイル／バイナリを
    // 再ハッシュし、保存済みベースラインと比較します（このホストで一度も
    // `sudo roamswitch fim update` を実行していない場合はエラーになります）。
    if let Ok(fim) = client.verify_fim().await {
        println!("FIM: {} monitored, healthy={}", fim.total_monitored, fim.is_healthy);
    }

    // 何かを直したあとは、その指摘だけを再検証します。判定は stillPresent / resolved /
    // inconclusive のいずれかです。inconclusive は、このプロセスから状態を観測できなかった
    // （root やデーモンが無いなど）という意味で、問題がないという意味ではありません。
    let after = client.verify_security_findings(Some(&["luks_encryption"]), None).await?;
    for r in &after.results {
        println!("{} {:?} ({})", r.check_id, r.verdict, r.reason);
    }

    // 別製品に頼るツールは、それが無いとき `available: false` を返します。
    // これはエラーではなく、答えです。
    let paths = client.get_privilege_escalation_paths(None).await?;
    if paths.analyzed && !paths.analysis.complete {
        println!("マシンの一部は調べられていません: {:?}", paths.analysis.mcp_caution);
    }

    Ok(())
}
```

すべての呼び出しは `async` で `Result<_, RoamSwitchClientError>` を返します。最も多いのは
RoamSwitch が未インストールの場合の `.AppNotInstalled` です。致命的エラーとして扱うのではなく、
機能を隠す・lafine.net を案内するなど、穏当に処理してください。

## 動作の仕組み

`RoamSwitchClient` は稼働中の RoamSwitch プロセスと直接通信するわけではありません。
各呼び出しは次の流れで動きます。

1. `roamswitch-mcp` の場所を解決します（自分の実行ファイルの隣、または公式パッケージの
   `/usr/bin/roamswitch-mcp` / `/usr/local/bin/roamswitch-mcp`）。`RoamSwitchClient::new` に
   明示的なパスを渡した場合はそれを使います。
2. そのバイナリを新規サブプロセスとして起動します。
3. `tools/call` リクエストを、改行区切りの JSON-RPC 2.0 としてサブプロセスの stdin へ
   書き込みます。これは RoamSwitch が Claude Desktop / Code などの MCP クライアントと
   話すのと同じプロトコルです。
4. stdout から対応するレスポンス行を読み、JSON ペイロードを型付き Rust 構造体へデシリアライズし、
   サブプロセスを終了させます。

これは意図的にステートレスな設計です。永続接続もデーモンも無く、呼び出し間に何も残りません。
そのため各呼び出しにはプロセス起動のオーバーヘッド（数十ミリ秒）と診断自体の所要時間が
かかります。特に `exposed_ports()` は、外部公開ポートが複数ある場合それぞれを個別にプローブ
するため数秒かかることがあります。

`RoamSwitchClient` は自身の設定以外に内部可変状態を持たないため、1 インスタンスを
（`Arc` などで）共有して複数タスクから同時に呼び出せます。各呼び出しは独立したサブプロセスを
起動します。

## API リファレンス

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

    // 0.2.0 で追加
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

`roamswitch-mcp` の 45 ツールすべてに対応しています。複数のメソッドを持つツールがあります。
`get_security_report`（`security_report` と `server_security_report`）、`audit_secrets`（テキスト用の
`audit_secrets` と、ファイル／ディレクトリ用の `audit_secrets_path`）、`verify_fim`（`verify_fim` と
`verify_fim_full`）、`audit_agent_setup` と `get_detection_coverage`（型付きのレポートと、SARIF /
ATT&CK Navigator 形式）、`get_privilege_escalation_paths`（1 アカウント、または `agent_users`）です。
0.2.0 で追加したメソッドの名前は、ツール名と同じです。レスポンス中の
人が読むテキスト（タイトル・詳細・推奨対策・サマリー・注意事項）は、RoamSwitch で選択した言語
（10 言語、未設定時は OS ロケール）に従います。`risk_level`・`verdict`・`kind`・`mode` などの
機械可読フィールドは言語によって変わりません。

- `new(executable_path, timeout)` — `executable_path: None` なら標準のインストール場所を検索
  します。`timeout` の既定は 30 秒で、超過するとサブプロセスを kill（drop）して `.TimedOut` を
  返します。
- `security_report()` / `server_security_report()` — ローカル総合診断。Client Edition の診断は 31 項目です
  （Client デーモンがおとりの認証情報ファイルの置き場所を記録しているあいだは、もう 1 項目が加わります）。
  `server_security_report()` は Server Edition の 42 項目プロファイル（カーネル強化、コンテナ隔離、
  カーネル CVE 露出、eBPF LSM）を指定します。`security_report()` はエディションを送らず、
  インストールされているエディションの診断を受け取ります。
- `exposed_ports(include_local_only)` — 待ち受け中の TCP ポートを列挙します。localhost を
  超えて公開されているものは常に完全監査されます。`true` を渡すと localhost 限定ポートも
  含めます（こちらは時間のかかる個別監査なしで返ります）。
- `run_active_vuln_scan()` — オプトインの非破壊到達性検証で、対象は `127.0.0.1` のみです。
  RoamSwitch 自身の設定で `active_vuln_scan_enabled: true` にしていない限り、
  `enabled: false` と空の結果を返します。`ActiveVulnScanResult` には
  `confirmed_safe`（確認できて問題なしだった項目）と `inconclusive`
  （接続できず確認自体ができなかった項目）も `Vec<ScanCheckOutcome>` として
  含まれます。`findings` が空でも「全部確認して安全だった」のか「一部は
  確認自体できなかった」のかを区別できるよう、別枠で返す設計です。
- `guard_status()` — 現在の保護レベル、信頼ネットワーク判定、各オプションガードの ON/OFF。
- `audit_url_safety(url)` — URL をフィッシング、Unicode ホモグラフ偽装、ブランド偽装
  サブドメイン、高リスク TLD の観点で解析します（Zero Telemetry。URL 自体の取得も行いません）。
- `audit_secrets(text)` — テキスト中に露出した API キー・シークレットを検査します。
- `audit_security_logs(hours)` — 直近 N 時間の sudo / SSH / ファイアウォール / AppArmor /
  ClamAV のログ活動を集計します。
- `get_app_help(query, topic)` — RoamSwitch のオフラインナレッジベースを全文検索します。
- `quarantine_status()` / `canary_status()` — マルウェア隔離 Vault の状態 /
  ランサムウェア・カナリアガードの状態。`canary_status()` は、RoamSwitch のおとりファイルが監視フォルダーに
  無いとき、それも作ります。
- `package_cve_scan()` — インストール済み OS パッケージ（dpkg / pacman / rpm を自動判定）を
  RoamSwitch のネットワーク非依存ローカル CVE マップと照合します。
- `package_cve_scan_languages(watched_folders)` — 指定フォルダ配下の言語エコシステムの
  ロックファイル（npm / PyPI / crates.io など）を、同じローカル CVE マップと照合します。
- `verify_fim()` — クリティカルパス FIM 検証（約 150 箇所の最重要システムファイルを再ハッシュし、
  保存済みベースラインと比較）。そのベースラインの更新・初期化は行いません（root が必要なため意図的に
  非公開）。このホストで一度もベースラインを取得していない場合は `RoamSwitchClientError::ToolError` に
  なります。
- `verify_fim_full()` — 同じ呼び出しで、ツールが返すものをすべて受け取ります。クリティカルパスの
  レポート（`critical_path_fim`）、監視中のプロジェクトフォルダーのロックファイル FIM レポート
  （`lockfile_fim`。フォルダー未設定、またはロックファイル FIM が無効なら `None`）、最近の変更を
  誰が行ったか（`recent_intrusion_context`。root のみ）です。古い `roamswitch-mcp` が送る、
  包まれていないレポートも受け付けます。
- `get_port_anomaly_incidents()` — ポート異常ガードのインシデントログ。新たに外部公開ポートで
  待ち受け始めて自動遮断された実行ファイル（バックドア、C2 リスナー、うっかり `0.0.0.0` に
  バインドした開発サーバー）を、日時 / プロセス / PID / ポートとともに返します。
- `get_ebpf_incidents()` — Server Edition 専用。eBPF ランタイムガードの封じ込め履歴（実際に
  プロセス隔離・凍結・ホスト全体の Air-Gap ロックダウンを引き起こしたアラート）と、現在の
  封じ込め状態。Air-Gap ロックダウンの発動理由を得られる唯一のツールであり、本クレート自体も
  ネットワークに触れないため、発動直後のオフライン・トリアージに有用です。
- `get_resource_guard_incidents()` — Server Edition 専用。リソース枯渇・プロセス異常ガードの
  インシデントログ。ネットワーク公開サービスの回復しない RSS 増大やクラッシュループを、確度ティア
  （`"possible"` / `"correlated"`）付きで返します。`"possible"` は攻撃とは限りません。
- `get_file_scan_guard_status()` — Server Edition 専用。ファイルスキャンガードの設定（ClamAV の
  有効状態、スキャン対象ディレクトリ、スキャン / freshclam 間隔）と、隔離先 Vault の状態。
- `notification_history()` — RoamSwitch が直近 7 日間に送信した通知（日時・タイトル・本文）を
  新しい順に返します。
- `get_incident_timeline()` — 実験的機能。リンクガード / ランサムウェア・カナリア / eBPF
  ランタイムガード / リソースガードのインシデントを単一の時系列（直近 50 件）に統合し、プロセス系譜、
  確実に対応付けられる場合のみの MITRE ATT&CK タグ、計測済みの封じ込め遅延、解決状態を付けて返します。
- `audit_secrets_path(path)` — ファイル、またはディレクトリを再帰的に検査します（`.git` /
  `node_modules` / `target` / `vendor` / `dist` / `build` / `__pycache__` / `venv` と、2MB 超
  またはバイナリと思われるファイルはスキップ）。パスは呼び出し元自身の権限で `roamswitch-mcp` が
  読み取ります。
- `vpn_status()` — Client Edition。「未信頼ネットワークで VPN」の状態。有効かどうか、バックエンド
  （WireGuard / Tailscale）、現在の保護レベルでトンネルが確立されるべきか（RoamSwitch は
  `lockdown` 時のみ確立）、実際に確立済みか、通信漏れを防ぐキルスイッチが有効か。
- `link_guard_status()` — Client Edition。受動リンクガードのモード（`off` / `warn` / `block`）、
  許可リストと追加遮断リスト、ユーザーの判断待ちの接続、直近 7 日間の遮断 / 警告イベント。
- `air_gap_status()` — Client Edition。Air-Gap 緊急遮断が発動中か、いつから・何が発動させたか、
  および RoamSwitch が SIGSTOP で凍結中のすべてのプロセス。Air-Gap の解除やプロセスの再開は
  行いません。
- `sharing_services_status()` — Client Edition。SSH / Samba / リモートデスクトップの自動制御の
  設定、RoamSwitch が停止して復元予定のユニット、インストール済み各ユニットの systemd 状態。
- `bluetooth_guard_status()` — Client Edition。Bluetooth ガードの設定と、コントローラーの
  現在の状態（電源・検出可能・接続中デバイス）。
- `usb_guard_status()` — Client Edition。USB ストレージ / BadUSB キーボードガードの設定、
  接続中の USB デバイス、許可リスト、承認待ちのデバイス。

0.2.0 で追加したメソッド:

- `verify_security_findings(check_ids, is_server)` — 先に出した `security_report` の指摘を、修正後に
  再検証します。項目ごとに、判定（`FindingVerdict::StillPresent` / `Resolved` / `Inconclusive`）、
  言語に依存しない `reason` コード、`verification_status` を返します。root・デーモン・Docker・不足している
  ツールが必要な項目は、推測せず `Inconclusive` です。Linux のデーモンが過去の診断を記録していれば、
  `change` が前回からの変化を伝えます（`fixed`、`already_resolved`＝直したのではない、`still_present`、
  `newly_present`、`no_earlier_check`）。`check_ids: None` は全項目を検証します。検証される ID は重複を除いて
  最大 64 個で、`is_server: None` はインストール済みのエディションを使います。何も書き込みません。
- `get_port_scan_incidents()` — Server Edition のデーモンが検知した、外部からのポートスキャン。
  発信元アドレス、到達した異なるポートの数、ポートの例、自動遮断したか・何秒か。Client Edition や、
  何も検知していないときは空です。
- `get_ssh_guard_incidents()` — SSH 総当たりガードの状態（`block`・`detect_only`・`disabled` と、その理由）、
  いま遮断中の接続元、直近の最大 200 件の記録（遮断、閾値を超えたが遮断しなかった接続元、同じ接続元からの
  失敗が続いたあとに成功したログイン）。遮断リストは root だけが読めるため、ほかのユーザーには
  `active_bans` の件数だけが返り、`bans` は空です。試されたユーザー名は保存せず、種類の数だけです。
  遮断を解除する呼び出しはありません。
- `get_fleet_status()` — この端末の Fleet（組織管理）の状態。登録済みか、適用中のポリシー版、
  最後のチェックイン、最後のエラー、削除の理由。コード・トークン・鍵・ライセンス情報は返しません。
  Fleet に遠隔コマンドの仕組みはなく、未登録の端末は何も送りません。
- `search_exec_events(query)` — 実行/プロセスレコーダーのログ（パス、無害化した引数、親子関係、uid、
  作業ディレクトリ、コンテナ ID、SHA-256）を新しい順に検索します。`ExecEventQuery { since_minutes, pid,
  exe, user, parent, text, limit }` で絞ります（`limit` の既定は 100、最大 1000）。結果にはログの
  ハッシュチェーン検査 `chain_status` が付きます（改ざんの検知はできますが、防止はできません）。
  ログは root 専用です。ほかのユーザーでは `events` が空になり、`error` が理由を伝えます。
- `get_process_tree(pid)` — プロセス ID について、記録された親（最大 8 階層）と記録された子孫。
  記録の無い pid や読めないログは `ToolError` です。
- `run_package_lifecycle_script_scan(watched_folders)` — 各フォルダーの `node_modules` にある
  `preinstall` / `install` / `postinstall` / `prepare` スクリプトの一覧です。ヒューリスティックな
  `is_danger_pattern` の印（正当なスクリプトにも多く当てはまります）、依存関係の取り違えを許す設定、
  人が最後に確認済みの状態を記録してから増えたインストール時のコード（`drift`）を返します。この
  ツールがその状態を記録することはありません。ローカルのファイルを読むだけで、何も実行せず、
  ネットワーク通信もしません。判定ではなく棚卸しです。
- `run_typosquat_scan(watched_folders)` — `package.json` の依存名のうち、有名な npm パッケージと
  編集距離 1〜2 のもの。ローカルのファイルを読むだけで、レジストリには問い合わせません。
  誤検知もあります。
- `run_npm_audit_signatures(directory)` — npm プロジェクトのディレクトリで `npm audit signatures` を
  実行します。**npm レジストリに通信します。** RoamSwitch の設定で `npm_audit_signatures_enabled` を
  true にしない限り動かず（`enabled: false` と `message` を返します）、npm は自分のログとキャッシュを
  `~/.npm` に書きます。`raw_output` は npm 自身の出力です。npm は既定の 30 秒より長くかかることが
  あるので、もっと長いタイムアウトでクライアントを作ってください。
- `audit_mcp_configs()` — MCP クライアントの設定ファイル（Claude Desktop・Claude Code・Cursor・
  Windsurf・VS Code・Cline・Gemini CLI・Codex・OpenCode と、登録したプロジェクトフォルダー）の
  静的な点検。自動承認されたツール、平文の `http://` サーバー、シェル 1 行での起動、バージョン未固定の
  パッケージ起動などを見つけます。ファイルを読むだけです。環境変数やヘッダーの値、引数、秘密情報は
  返しません。存在するのに解析できなかったファイルは `unreadable_files` に載り、点検されていません。
- `audit_agent_setup()` / `audit_agent_setup_sarif()` — AI コーディングエージェントに読ませるファイル
  （CLAUDE.md、AGENTS.md、コマンド、サブエージェント、スキル、Cursor ルール、エージェントのメモリ、
  エディターのタスク、CI ワークフロー、エージェントの設定）の静的な点検。隠し文字、指示を上書きする
  文、取得してそのまま実行する記述、認証情報の参照などを見つけます。ファイルを読むだけで、
  ファイルの本文は答えにコピーしません。各指摘に OWASP LLM の ID が付き、当てはまる手法が 1 つに
  決まるものだけ ATT&CK の ID が付きます。SARIF 形式は SARIF 2.1.0 で、外部の形式なので
  `serde_json::Value` で返します。
- `detection_coverage(is_server)` / `detection_coverage_navigator(is_server)` — RoamSwitch に見えるものと
  見えないものの自己点検です。防御を弱める・隠れる・居座るときに使われる ATT&CK の手法ごとに、検知の
  範囲（`Detects` / `Partial` / `Nothing`）、気づくガード、見えない部分、そのガードがいま動いているかを
  返します。一覧に無い手法は、評価していません。ローカルの状態を読むだけです。Navigator 形式は
  MITRE ATT&CK Navigator のレイヤー（4.5）で、`serde_json::Value` で返します。
- `get_sensor_audit_results()` — この端末がペアリング済みの RoamSwitch Sensor に依頼した、この端末への
  能動監査の結果（保持されるのは最大 2 件）。取得済みの結果を読むだけで、監査の依頼やペアリングはできません。
  `findings` は Sensor 自身のレポートなので、`serde_json::Value` のままです。
- `get_honeytoken_status(is_server)` — 認証情報おとりガードが有効か、おとりの認証情報ファイルをどこに
  置いたか、監視プロセスの状態、おとりへのアクセスの直近 50 件。`events_readable` が `false` のとき、
  空の `recent_events` は何も意味しません。ほかのユーザーのホームのパスは、root と管理者にだけ見せます。
  ネットワーク通信はありません。
- `get_ransomware_entropy_guard_status(is_server)` — エントロピーによるランサムウェア検知が有効か、
  どの設定か（`settings`。エディションでキーが違うため型を付けていません）、直近 50 件のバースト。
  `incidents_readable` が `false` のとき、空の一覧は何も意味しません。
- `get_lan_sensor_overview()` / `get_lan_network_threats(limit, min_severity)` — 同じホストの RoamSwitch
  Sensor が LAN セグメントで見ているもの（機器、VLAN、キャプチャの状態、脅威）。Sensor のローカル
  ソケットから 1 回の要求で読み、ネットワーク通信はしません。ホストに Sensor が無いときの答えは、
  `available: false` と `reason` で、エラーではありません。`limit` は 1〜500、`min_severity` は
  `info`・`medium`・`high`・`critical` で、それ以外は `ToolError` です。`coverage_gaps` が空でないとき、
  Sensor は LAN の一部を見られておらず、脅威 0 件は「何もない」という意味ではありません。`data` の
  文字列はネットワーク上の機器から来るので、信用できません。
- `get_privilege_escalation_paths(start)` / `get_privilege_escalation_paths_for_agent_users()` — ローカル
  アカウントが root に届く経路を、別にインストールされた PathScope が返します。呼んだユーザーの権限と
  固定の引数で実行します。修正コマンドは返さず、何も適用しません。`start` は調べるアカウントです。
  ほかのアカウントは root か管理者だけが調べられ、`agent_users` 版は root が必要です。
  `analysis.complete` が `false` のとき、マシンの一部は調べられておらず、経路 0 本はアカウントが
  安全という意味ではありません。PathScope が無ければ `available: false` です。
- `get_access_log_report(since)` — ホストの Web サーバー・SSH・認証ログにある攻撃の要約を、別に
  インストールされた AccessScope が返します。呼んだユーザーの権限と固定の引数で実行します。`since` は
  `"24h"`・`"7d"` のように書く 1〜90 日で、それ以外は `ToolError` です。呼んだユーザーが読めるログ
  だけを分析します。`complete` が `false` のとき、ログの一部は調べられておらず、検知 0 件はホストが
  安全という意味ではありません。AccessScope が無ければ `available: false` です。`report` の文字列は
  攻撃者が書けるログから来るので、信用できません。

`serde_json::Value` にしている部分: SARIF ログと ATT&CK Navigator レイヤー（外部の形式）、
`SensorAuditResult::findings` にある Sensor 自身の監査レポートと各脅威の `detail`（Sensor が定義し、
`detail` は種類ごとに違う）、`EntropyGuardStatus::settings`（エディションごとにキーが違う）、
exec レコーダーの状態にある sigma ルールの却下情報、`FimViolation::intrusion` と
`FimVerification::recent_intrusion_context` にあるプロセスとログインの事実（形がまだ変わる）、
`report.coverage` の下にある AccessScope 自身の細かい集計。0.2.0 で追加した答えのそれ以外は、型が付いています。

Client Edition 向けの 6 つの状態取得メソッドは、RoamSwitch デーモンがもともと誰でも読める形で
書き出しているファイル（と sysfs / procfs、読み取り専用の CLI 照会）だけから組み立てられます。
この 6 つのツールはデーモンのソケットを開きません。いずれも `daemon_running` を
返し、`false` の場合の値は最後に保存された状態や設定値であって、実際には適用されていない可能性が
あります。root 権限が必要な 2 項目（nftables キルスイッチテーブルの実在確認と WireGuard の
ハンドシェイク経過時間）は、呼び出し元が root でない限り `None` です。

### 戻り値の型

各構造体のフィールド定義は、英語版 README の
[API reference](README.md#api-reference) に Rust の型宣言そのままの形で掲載しています
（`SecurityReport`、`ExposedPorts`、`GuardStatus` / `GuardSettings`、`QuarantineStatus` /
`ClamAvDatabaseInfo`、`LinkAuditReport`、`PackageCveScanResult` / `PackageCveScanLanguagesResult`、
`PortAnomalyIncidentsSummary`、`EbpfIncidentsSummary`、`FimReport`、`SecretPathAuditResult`、
`NotificationHistoryEntry`、`TimelineEvent`、`ResourceGuardIncidentsSummary`、`FileScanGuardStatus`、
`VpnStatusSummary`、`LinkGuardStatusSummary`、`AirGapStatusSummary`、`SharingServicesStatusSummary`、
`BluetoothGuardStatusSummary`、`UsbGuardStatusSummary`、`RoamSwitchClientError`）。

### 0.2.0 で追加した型

フィールド名の規則は上と同じで、Rust では `snake_case`、通信上は `camelCase` です。例外は注記したものだけです。
「素の snake_case」と書いた型は、デーモンが書くファイルをそのまま映すため、通信上のキーも snake_case です。

- `FindingVerificationReport { results: Vec<FindingVerification>, caveats, timestamp }`。
  `FindingVerification { check_id, title, verdict: FindingVerdict, reason, status_text, detail, verification_status,
  rationale, counter_evidence: Option<String>, severity_changes_if: Option<String>, change: Option<String>,
  previous_verdict: Option<FindingVerdict>, previous_checked_at: Option<String> }`。`FindingVerdict` は
  `StillPresent` / `Resolved` / `Inconclusive` / `Unknown`（このクレートが知らない判定）です。
- `PortScanIncidentsSummary { incidents: Vec<PortScanIncidentRecord { timestamp, source_ip, distinct_port_count,
  sample_ports: Vec<u16>, blocked, block_duration_secs: Option<u64> }> }`（素の snake_case）。
- `SshGuardIncidentsSummary { running, status: Option<SshGuardStatus>, reason_text: Option<String>, active_bans,
  bans: Vec<SshBanEntry>, incidents: Vec<SshGuardIncidentRecord> }`。`SshGuardStatus`、`SshBanEntry`
  （unix 秒）、`SshGuardIncidentRecord { timestamp, kind ("ban" / "detect_only" / "exempt" /
  "success_after_failures"), source, failures, window_secs, distinct_users, banned, ban_secs, repeat,
  yielded_to, exempt_reason, login_user, login_method }` は素の snake_case です。
- `FleetStatusSummary { fleet: FleetPublicStatus, remote_command_channel: bool }`。`FleetPublicStatus` は
  素の snake_case です（`enrolled`、`org_id`、`device_id`、`policy_version_applied`、`policy_active`、
  `last_ok_at`、`last_error`、`removed_reason` など）。
- `ExecEventSearch { events: Vec<ExecRecord>, chain_status: Option<ExecChainStatus>, chain: Option<String>
  （非推奨のデバッグ文字列。chain_status を使ってください）, status: Option<ExecRecorderStatus>,
  error: Option<String> }`。`ExecRecord` は素の snake_case です（`kind`、`ts`、`pid`、`ppid`、`uid`、`user`、
  `exe`、`argv`、`cwd`、`container_id`、`sha256`、`ancestry: Vec<ExecAncestor>`、`loginuid`、`ld_env` など）。
  `ExecChainStatus { status ("ok" / "not_chained" / "broken"), segments, unchecked_records, seq, reason,
  reason_text, previous_seq }`。`ProcessTree { ancestry: Vec<ExecAncestor>, tree: ProcessTreeNode { pid,
  exe, argv, ts, children } }`。
- `PackageLifecycleScriptScanResult { scanned_folder_count, findings: Vec<LifecycleScriptFinding>,
  dependency_confusion: Vec<DependencyConfusionFinding>, baseline_accepted_at, drift:
  Vec<PackageInstallDrift>, uncovered_folders }`。`TyposquatScanResult { scanned_folder_count, findings:
  Vec<TyposquatFinding { dependency_name, suspected_target, distance, project_dir }> }`。
- `NpmAuditSignaturesResult { enabled, directory, raw_output, exit_code, has_issues, message }`。1 つの構造体で
  3 つの答えを表します。無効（`enabled: false` と `message`）、npm が無い（`message`）、npm を実行した
  （`raw_output`、`exit_code`、`has_issues`）です。
- `McpConfigAuditPayload { scanned_file_count, scanned_files, server_count, unreadable_files, findings:
  Vec<McpConfigFinding { id, severity, file, server, detail, message }> }`。`AgentSetupAuditPayload {
  scanned_file_count, scanned_files, skill_count, open_claw_config_found, unreadable_files, findings:
  Vec<AgentSetupFinding { id, severity, area, file, detail, message, owasp_llm, attack_id }>,
  baseline_accepted_at }`。
- `CoverageReport { platform, edition, summary: CoverageSummary, techniques: Vec<TechniqueCoverage { id, name,
  platform, coverage: CoverageLevel, covered_by, blind_spot, live_state }>, guards: Vec<CoverageGuardState>,
  inactive: Vec<InactiveInfo>, caveats }`。`CoverageLevel` は `Detects` / `Partial` / `Nothing`（通信上は
  `"none"`）/ `Unknown` です。
- `SensorAuditResult { request_id, sensor_addr, requested_at, status ("pending" / "completed" / "failed"),
  completed_at, attempts, findings: Option<serde_json::Value>, failure_reason }`（素の snake_case）。
- `HoneytokenStatus { edition, enabled: Option<bool>, setting, setting_source, config_readable, placement:
  Option<HoneytokenPlacement>, inactive, events_readable, recent_events: Vec<HoneytokenEvent>,
  hidden_events_count, notes, timeline_problem }`。`EntropyGuardStatus { edition, enabled: Option<bool>,
  setting_source, config_readable, settings: Option<serde_json::Value>, freezes_on_detection, inactive,
  incidents_file, incidents_readable, recent_incidents: Vec<EntropyIncident>, hidden_incidents_count, notes }`。
  `server.conf` を呼び出し元が読めないとき、`enabled` は `None` です。
- `SensorReply<T> { available, reason, mcp_note, sensor_error, schema_supported, schema, supported_schema,
  coverage_gaps, mcp_caution, data: Option<T> }`。`T` は `LanOverview`（ゲートウェイ、機器数、VLAN、キャプチャの
  状態、ペアリング済みエンドポイント、挙動の基準、未管理機器の監査の件数、脅威の件数）または `LanThreats {
  schema, generated_at, site, sensor_public_key, threats: Vec<LanThreat { id, time, category, kind, severity,
  subject, summary, detail }>, coverage_notes }` です。内側の型は素の snake_case です。
- `PrivilegeEscalationPaths { available, analyzed, reason, mcp_note, pathscope_error, mode, requested_user,
  schema, accounts, users: Vec<EscalationAgentUser>, skipped, analysis: PrivilegeEscalationAnalysis }`。
  `analysis` は同じ JSON オブジェクトに展開されます。`start`、`goal`、`os`、`privileged`、`paths`（件数）、
  `paths_shown`（先頭 20 本。各経路は手順の並び）、`urgent_total`、`urgent: Vec<UrgentEscalationFix>`、
  `uncollected_by_kind`、`notes`、`complete`、`mcp_caution` です。
- `AccessLogReport { available, analyzed, reason, mcp_note, accessscope_error, schema_supported, schema, since,
  risk_level, risk_score, findings_total, findings_shown, coverage_partial, unread_sources, complete,
  mcp_caution, report: Option<AccessScopeBrief> }`。`AccessScopeBrief` は AccessScope の
  `accessscope-brief/1` レポートで、`risk`、`coverage`、`sources`、`findings: Vec<AccessScopeFinding { n, kind,
  title, severity, confidence, count, first, last, attack_id, subject, ips, notes, evidence }>`（検知は最大 40 件、
  マスク済みの根拠行は各 3 行まで）を持ちます。
- `InactiveInfo { guard, name, state ("off" / "partial"), code, message, next_step }`: 設定では有効なのに、
  (完全には)動いていないと確実に分かっているガード。`GuardStatus`、`CoverageReport`、`HoneytokenStatus`、
  `EntropyGuardStatus` が使います。
- `FimVerification { critical_path_fim: FimReport, lockfile_fim: Option<LockfileFimResult>,
  recent_intrusion_context: Vec<serde_json::Value> }`。`LockfileFimResult` は `FimReport` か `{ error }` です。

### 0.2.0 での古い型の変更

0.1.0 の型を作ってから、`roamswitch-mcp` はフィールドを足し、答えの形を 1 つ変えました。現在の
`roamswitch-mcp` の応答を、古い 26 のツールそれぞれと突き合わせました。

- `verify_fim()` は包まれていないレポートを読んでいましたが、現在のツールは `criticalPathFim` に包み、
  `lockfileFim` と `recentIntrusionContext` を並べて返します。0.1.0 の `verify_fim()` は、現在の応答を
  読めませんでした。いまはクリティカルパスのレポートを再び返し、`verify_fim_full()` が 3 つすべてを返します。
- 足したフィールド（すべて `#[serde(default)]` か `Option` なので、古い `roamswitch-mcp` も読めます）:
  - `ExposedPort`: `is_network_reachable`、`ai_runtimes`。
  - `GuardStatus`: `collectors`、`inactive`。`GuardEntry`: `effective_state`、`inactive_reason`。
  - `SecurityLogSummary`: `journal_read_complete`（`false` のとき、何も読めていないため件数がすべて 0 です）、
    `journal_error`、`journal_line_limit`、`coverage_note`、`recent_package_management_activity`、
    `all_anomalies_are_baseline_warmup_noise`、`crash_signals`。`TemplateAnomalySummary`:
    `own_history_observations`、`own_history_mature`。
  - `PackageCveScanResult`: `complete`（`false` のとき、`findings` が空でもシステムが問題なしという意味ではありません）、
    `incomplete_reason`、`ecosystem`、`release`、`acceptance`。`PackageCveScanLanguagesResult`: `acceptance`。
    `PackageCveFinding`: `lockfile`、`release`、`binary`、`pro_only`、`epss`、`epss_date`、`kev`、`unfixed`、
    `accepted`、`acceptance_expired_at`。
  - `ActiveScanFinding`: `evidence_kind`、`previously_safe_at`、`probe_name`。`ActiveVulnScanResult`: `probes_run`。
    `ProbeStatus`: `side_effects`。
  - `FimViolation`: `pid`、`intrusion`。
  - `CanaryStatus`: `hidden_directories_count`、`hidden_incidents_count`。`QuarantineItem`: `owner_uid`。
  - `PortAnomalyIncidentsSummary`: `current_port_state_note`、`incidents_note`。
  - `EbpfIncidentRecord`: `detect_to_receive_ms`、`receive_to_action_ms`、`detect_to_action_ms`。
    `EbpfIncidentsSummary`: `heartbeat`。
  - `FileScanGuardStatus`: `last_run`。
  - `LinkGuardStatusSummary`: `table_installed`。`UsbGuardStatusSummary`: `storage_guard_effective`、
    `keyboard_guard_effective`。
  - `TimelineEvent`: `parent_event_id`、`root_event_id`、`evidence_refs`。
- `get_app_help(query, topic)` は、`None` の引数を `null` で送らなくなりました。ツールの入力スキーマは
  どちらも文字列と定めています。
- `isError` が付いたツールの答え（拒否された引数、未知のツール、失敗した FIM 検証）は、ツール自身の
  文を持つ `RoamSwitchClientError::ToolError` になりました。0.1.0 では `InvalidResponse` でした。

`roamswitch-mcp` が対応していても、このクレートが扱わないもの: `audit_secrets` の `include_build_output`
引数とその結果の `buildOutput`、`run_active_vuln_scan` の `format: "sarif"` 引数。`get_incident_timeline()` は
イベントだけを返し、ツールが一緒に送る `incidents` の分類は返しません。

### `RoamSwitchClientError`

| バリアント | 意味 |
|---|---|
| `AppNotInstalled` | 標準のいずれの場所にも `roamswitch-mcp` バイナリが見つからない |
| `ServerBinaryNotFound(path)` | 明示パスを指定したが、そこに何も存在しない |
| `ProcessLaunchFailed(msg)` | サブプロセスの起動、または stdio パイプの作成に失敗した |
| `NoResponse` | レスポンスが届く前にサブプロセスの stdout が閉じた |
| `TimedOut` | タイムアウト内に応答が無かった |
| `InvalidResponse(msg)` | 応答はあったが、正しい／想定どおりの JSON ではなかった |
| `ToolError(msg)` | サーバーが JSON-RPC エラーを返した、またはツールがリクエストを拒否した（結果に `isError` が付く）、または `get_process_tree` が記録を見つけられなかった |

## 互換性について

RoamSwitch の診断ツールが返す JSON が、本クレートとアプリ本体の実質的な契約です。
[`src/models.rs`](src/models.rs) はその形を独立してミラーしています。本クレートは非公開の
`roamswitch-linux` リポジトリとは別の公開リポジトリであり、Rust の型を直接共有できないためです。
将来の RoamSwitch リリースでレスポンス形状が変わる場合、これらのモデルも同時に更新されます。
厳密に固定したい場合はバージョンをピンしてください。

テストは、本物の `roamswitch-mcp` の応答を記録した [`tests/fixtures`](tests/fixtures)（記録の取り方は
そこの README にあります）と照らして、この形を確かめています。どのツールでも、型は記録された応答の
すべてのフィールドを保たなければならず、すべてのリクエストはツールが公開している入力スキーマに合わなければ
なりません。型は知らないフィールドを無視するので、新しい RoamSwitch でもデコードは壊れません。

## ライセンス

MIT — [LICENSE](LICENSE) を参照してください。
