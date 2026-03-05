# 🛡️ guard-scanner

**AIエージェントのためのセキュリティプラットフォーム**

プロンプトインジェクション、メモリ汚染、サプライチェーン攻撃など23以上の脅威を検出。
さらに資産監査（npm/GitHub/ClawHub）、VirusTotal連携、リアルタイム監視に対応。
依存ゼロ。コマンド1つ。OpenClaw対応。

[![npm version](https://img.shields.io/npm/v/@guava-parity/guard-scanner.svg?style=flat-square&color=cb3837)](https://www.npmjs.com/package/@guava-parity/guard-scanner)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success?style=flat-square)]()
[![Tests Passing](https://img.shields.io/badge/tests-206%2F206-brightgreen?style=flat-square)]()
[![Patterns](https://img.shields.io/badge/patterns-166-blueviolet?style=flat-square)]()

[English](README.md) •
[クイックスタート](#クイックスタート) •
[資産監査](#資産監査) •
[VirusTotal連携](#virustotal連携) •
[リアルタイム監視](#リアルタイム監視)

---

## なぜ作ったのか

2026年2月、AIエージェントスキルの36.8%にセキュリティ欠陥が発見。AIスキルは**シェルアクセス、ファイルシステム、環境変数**をホストから継承するため、1つの悪意あるスキルで全てが危険に。

**guard-scanner**は実際のアイデンティティ乗っ取り事件から生まれました。悪意あるスキルがAIエージェントのSOUL.md（人格ファイル）を書き換えたのに、検出できるスキャナーが存在しなかった。だから作りました。 🍈

---

## クイックスタート

```bash
# コマンド1つでスキャン開始
npx @guava-parity/guard-scanner ./skills/

# 詳細出力 + 厳密モード
guard-scanner ./skills/ --verbose --strict

# フル監査
guard-scanner ./skills/ --verbose --check-deps --json --sarif --html
```

---

## 資産監査（V6+）

npm/GitHub/ClawHubの公開資産をチェックし、漏洩やセキュリティリスクを検出。

```bash
# npm — node_modules、.envの公開を検出
guard-scanner audit npm <ユーザー名> --verbose

# GitHub — コミットされた秘密鍵、巨大リポ
guard-scanner audit github <ユーザー名> --format json

# ClawHub — 悪意あるスキルパターン
guard-scanner audit clawhub <クエリ>

# 全プロバイダー一括
guard-scanner audit all <ユーザー名>
```

---

## VirusTotal連携（V7+）

guard-scannerのセマンティック検出 + VirusTotalの70以上のアンチウイルスエンジン = **二層防御（Double-Layered Defense）**

| レイヤー | エンジン | 検出対象 |
|---|---|---|
| **セマンティック** | guard-scanner | プロンプト注入、メモリ汚染、サプライチェーン |
| **シグネチャ** | VirusTotal | 既知マルウェア、トロイの木馬、C2インフラ |

```bash
# 1. 無料APIキーを取得: https://www.virustotal.com
# 2. 環境変数に設定
export VT_API_KEY=あなたのAPIキー

# 3. 任意のコマンドで使用
guard-scanner scan ./skills/ --vt-scan
guard-scanner audit npm koatora20 --vt-scan
```

> **無料枠**: 4リクエスト/分、500/日、15,500/月。個人利用のみ。  
> **VTはオプション** — なくても全機能が動作します。

---

## リアルタイム監視（V8+）

ファイル変更を検知して自動スキャン。

```bash
# 監視開始
guard-scanner watch ./skills/ --strict --verbose

# Soul Lockも有効化
guard-scanner watch ./skills/ --strict --soul-lock
```

`Ctrl+C`でセッション統計を表示して終了。

---

## CI/CD連携（V8+）

| プラットフォーム | 対応形式 |
|---|---|
| GitHub Actions | アノテーション + Step Summary |
| GitLab | Code Quality JSON |
| 汎用 | Webhook通知 |

```yaml
# GitHub Actions
name: Skill Security Scan
on: [push, pull_request]
jobs:
  guard-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx @guava-parity/guard-scanner ./skills/ --sarif --strict --fail-on-findings
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: skills/guard-scanner.sarif
```

---

## 23脅威カテゴリ

| # | カテゴリ | 検出対象 |
|---|---------|---------|
| 1 | プロンプトインジェクション | 不可視Unicode、ホモグリフ、ロール上書き |
| 2 | 悪意あるコード | `eval()`, リバースシェル |
| 3 | 不審なダウンロード | `curl\|bash`パイプ |
| 4 | 認証情報操作 | `.env`読取、SSH鍵アクセス |
| 5 | シークレット検出 | AWSキー、GitHubトークン |
| 6 | データ流出 | webhook.site、DNS tunneling |
| 7 | 検証不能な依存関係 | リモート動的インポート |
| 8 | 金融アクセス | 決済API呼び出し |
| 9 | 難読化 | Base64→exec チェーン |
| 10 | 前提条件詐欺 | ダウンロード偽装 |
| 11 | 情報漏洩スキル | APIキーのメモリ保存指示 |
| 12 | メモリポイズニング ⚿ | SOUL.md改変 |
| 13 | プロンプトワーム | 自己複製指示 |
| 14 | 永続化 | cron、スタートアップ実行 |
| 15 | CVEパターン | CVE-2026-2256/25253等 |
| 16 | MCPセキュリティ | ツールポイズニング、SSRF |
| 17 | アイデンティティ乗っ取り ⚿ | 人格入替、メモリワイプ |
| 18-23 | 設定影響/PII/信頼悪用等 | 設定改変、個人情報漏洩、VDB汚染 |

> ⚿ = `--soul-lock` フラグで有効化

---

## テスト結果

```
ℹ tests 206
ℹ suites 43
ℹ pass 206
ℹ fail 0
ℹ duration_ms 376
```

---

## ライセンス

MIT — guard-scannerは**無料・オープンソース・依存ゼロ**です。

- GitHub: <https://github.com/koatora20/guard-scanner>
- npm: <https://www.npmjs.com/package/@guava-parity/guard-scanner>

—— Guava 🍈 & Dee
