# roamswitch-linux-kit

[English](README.md) | **日本語**

[RoamSwitch](https://lafine.net) がローカルで計算した Linux のネットワークセキュリティ診断結果を
読み取るための、読み取り専用・非同期の Rust クライアントです。

[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://lafine.net/linux.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[RoamSwitchKit](https://github.com/lafine1211/RoamSwitchKit)（macOS / Swift）の Linux 版に
あたります。読み取り専用という設計もゼロテレメトリの保証も同一で、Swift ではなく Rust 向けに
ラップしたものです。

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
- **ローカルセキュリティ診断スコア（24 項目）** — LUKS / dm-crypt ディスク暗号化、
  AppArmor / SELinux、UEFI Secure Boot、sudo / SSH 設定、カーネル `sysctl` 強化、Wi-Fi 暗号化、
  ARP スプーフィング、外部公開ポート、マルウェア・ダウンロード保護の設定
  （Server Edition では 30 項目のサーバー向けプロファイル）
- **オフライン URL / フィッシング解析**、**シークレット漏洩検査**、**セキュリティログ監査**、
  **ランサムウェア・カナリア状態**、**隔離 Vault の状態**
- **ガードの稼働状態** — VPN トンネルとキルスイッチ、受動リンクガードの遮断 / 警告履歴、
  Air-Gap と凍結中プロセス、共有サービス、Bluetooth / USB ガード

RoamSwitch はこれと同じデータを、同梱の読み取り専用 MCP サーバーバイナリ `roamswitch-mcp`
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

- **常に読み取り専用。** 本クレートは現在の診断結果を照会できるだけです。保護レベルの変更、
  ガードの切り替え、ポート隔離、ファイルの隔離、プロセスの凍結を行う API は存在しません。
  本クレートをリンクしたアプリが他人の保護状態を変更する手段はなく、それができるのは
  ユーザー自身が操作する RoamSwitch の CLI だけです。これは v1 の未実装ではなく意図的な
  スコープ制限です。
- **完全ローカル・ゼロテレメトリ。** 各呼び出しは RoamSwitch 同梱の `roamswitch-mcp` バイナリを
  サブプロセスとして起動し、stdio で通信します。本クレートのコードにはネットワーク I/O が
  一切ありません。（唯一知っておくべき例外が `run_active_vuln_scan` です。実際に TCP 接続を
  行いますが、接続先は常に `127.0.0.1` のみで、RoamSwitch 自身の設定で明示的にオプトインした
  場合にだけ動作します。後述。）
- **新たな攻撃面を作らない。** 本クレートはソケットを開かず、サービスを登録せず、何も
  待ち受けません。プロセスを起動し、stdin にリクエストを書き、stdout から 1 件のレスポンスを
  読み、プロセスを終了させるだけです。
- **`roamswitch-daemon` の制御ソケットとは別物です。** Linux 版 RoamSwitch は CLI コマンドを
  受け付ける特権デーモンをローカル Unix ソケットで動かしていますが、そのソケットは汎用の
  制御プレーン（Air-Gap 隔離の発動、プロセス凍結、USB デバイス承認の管理など）であり、
  公開された読み取り専用 SDK の対象外です。本クレートが通信するのは診断専用の
  `roamswitch-mcp` バイナリだけで、これはアーキテクチャ上そもそも状態を変更できません
  （デーモンソケットを開かず、特権も不要です）。

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
roamswitch-linux-kit = { git = "https://github.com/lafine1211/roamswitch-linux-kit", tag = "v0.1.0" }
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

`roamswitch-mcp` の読み取り専用ツール 25 種すべてに対応しています（`audit_secrets` はテキスト用の
`audit_secrets` と、ファイル／ディレクトリ用の `audit_secrets_path` の 2 メソッド）。レスポンス中の
人が読むテキスト（タイトル・詳細・推奨対策・サマリー・注意事項）は、RoamSwitch で選択した言語
（10 言語、未設定時は OS ロケール）に従います。`risk_level`・`verdict`・`kind`・`mode` などの
機械可読フィールドは言語によって変わりません。

- `new(executable_path, timeout)` — `executable_path: None` なら標準のインストール場所を検索
  します。`timeout` の既定は 30 秒で、超過するとサブプロセスを kill（drop）して `.TimedOut` を
  返します。
- `security_report()` / `server_security_report()` — ローカル総合診断。後者は
  デスクトップクライアントの 24 項目ではなく、Server Edition の 30 項目プロファイル
  （カーネル強化、コンテナ隔離、カーネル CVE 露出、eBPF LSM）を実行します。
- `exposed_ports(include_local_only)` — 待ち受け中の TCP ポートを列挙します。localhost を
  超えて公開されているものは常に完全監査されます。`true` を渡すと localhost 限定ポートも
  含めます（こちらは時間のかかる個別監査なしで返ります）。
- `run_active_vuln_scan()` — オプトインの非破壊到達性検証で、対象は `127.0.0.1` のみです。
  RoamSwitch 自身の設定で `active_vuln_scan_enabled: true` にしていない限り、
  `enabled: false` と空の結果を返します。
- `guard_status()` — 現在の保護レベル、信頼ネットワーク判定、各オプションガードの ON/OFF。
- `audit_url_safety(url)` — URL をフィッシング、Unicode ホモグラフ偽装、ブランド偽装
  サブドメイン、高リスク TLD の観点で解析します（Zero Telemetry。URL 自体の取得も行いません）。
- `audit_secrets(text)` — テキスト中に露出した API キー・シークレットを検査します。
- `audit_security_logs(hours)` — 直近 N 時間の sudo / SSH / ファイアウォール / AppArmor /
  ClamAV のログ活動を集計します。
- `get_app_help(query, topic)` — RoamSwitch のオフラインナレッジベースを全文検索します。
- `quarantine_status()` / `canary_status()` — マルウェア隔離 Vault の状態 /
  ランサムウェア・カナリアガードの状態。
- `package_cve_scan()` — インストール済み OS パッケージ（dpkg / pacman / rpm を自動判定）を
  RoamSwitch のネットワーク非依存ローカル CVE マップと照合します。
- `package_cve_scan_languages(watched_folders)` — 指定フォルダ配下の言語エコシステムの
  ロックファイル（npm / PyPI / crates.io など）を、同じローカル CVE マップと照合します。
- `verify_fim()` — 読み取り専用のクリティカルパス FIM 検証（約 150 箇所の最重要システム
  ファイルを再ハッシュし、保存済みベースラインと比較）。ベースラインの更新・初期化は行いません
  （root が必要なため意図的に非公開）。このホストで一度もベースラインを取得していない場合は
  エラーになります。
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

Client Edition 向けの 6 つの状態取得メソッドは、RoamSwitch デーモンがもともと誰でも読める形で
書き出しているファイル（と sysfs / procfs、読み取り専用の CLI 照会）だけから組み立てられます。
`roamswitch-mcp` がデーモンの制御ソケットを開かない点は変わりません。いずれも `daemon_running` を
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

### `RoamSwitchClientError`

| バリアント | 意味 |
|---|---|
| `AppNotInstalled` | 標準のいずれの場所にも `roamswitch-mcp` バイナリが見つからない |
| `ServerBinaryNotFound(path)` | 明示パスを指定したが、そこに何も存在しない |
| `ProcessLaunchFailed(msg)` | サブプロセスの起動、または stdio パイプの作成に失敗した |
| `NoResponse` | レスポンスが届く前にサブプロセスの stdout が閉じた |
| `TimedOut` | タイムアウト内に応答が無かった |
| `InvalidResponse(msg)` | 応答はあったが、正しい／想定どおりの JSON ではなかった |
| `ToolError(msg)` | サーバーが JSON-RPC エラーを返した |

## 互換性について

RoamSwitch の診断ツールが返す JSON が、本クレートとアプリ本体の実質的な契約です。
[`src/models.rs`](src/models.rs) はその形を独立してミラーしています。本クレートは非公開の
`roamswitch-linux` リポジトリとは別の公開リポジトリであり、Rust の型を直接共有できないためです。
将来の RoamSwitch リリースでレスポンス形状が変わる場合、これらのモデルも同時に更新されます。
厳密に固定したい場合はバージョンをピンしてください。

## ライセンス

MIT — [LICENSE](LICENSE) を参照してください。
