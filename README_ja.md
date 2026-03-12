<p align="center">
  <img src="docs/logo.png" alt="guard-scanner" width="160" />
</p>

<h1 align="center">guard-scanner</h1>
<p align="center"><strong>エージェント時代のセキュリティスキャナー</strong></p>
<p align="center">
  AIエージェントスキル、MCPサーバー、自律型ワークフローにおける<br />
  プロンプトインジェクション・アイデンティティ乗っ取り・メモリ汚染・A2A感染を検出。
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@guava-parity/guard-scanner"><img src="https://img.shields.io/npm/v/@guava-parity/guard-scanner?color=cb3837&label=npm" alt="npm" /></a>
  <a href="https://www.npmjs.com/package/@guava-parity/guard-scanner"><img src="https://img.shields.io/npm/dm/@guava-parity/guard-scanner?color=blue&label=downloads" alt="downloads" /></a>
  <a href="#テスト結果"><img src="https://img.shields.io/badge/テスト-332_passed-brightgreen" alt="tests" /></a>
  <a href="https://github.com/koatora20/guard-scanner/actions/workflows/codeql.yml"><img src="https://img.shields.io/badge/CodeQL-有効-181717" alt="CodeQL" /></a>
  <a href="https://doi.org/10.5281/zenodo.18906684"><img src="https://img.shields.io/badge/DOI-Zenodo-blue" alt="DOI" /></a>
  <a href="https://github.com/koatora20/guard-scanner/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT" /></a>
</p>

<p align="center">
  <strong>358</strong> 検出パターン · <strong>35</strong> 脅威カテゴリ · <strong>27</strong> ランタイムチェック · 依存: <code>ws</code> のみ
</p>

<p align="center">
  <a href="README.md">English</a> · 日本語
</p>

---

従来のセキュリティツールはマルウェアを検出します。**guard-scanner** はその先を検出します：エージェント命令に隠された不可視Unicode注入、SOUL.mdの上書きによるアイデンティティ窃盗、巧妙な会話を通じたメモリ汚染、チェーン接続されたエージェント間のワーム型感染。

```
$ npx @guava-parity/guard-scanner ./skills/ --strict --soul-lock

  guard-scanner v15.0.0

  ⚠  CRITICAL  identity-hijack   SOUL_OVERWRITE_ATTEMPT
     skills/imported-tool/SKILL.md:47
     理由: エージェントのアイデンティティファイルへの直接上書きを検出。
     対策: この命令を削除してください。SOUL.mdは不変でなければなりません。

  ⚠  HIGH      prompt-injection   INVISIBLE_UNICODE_INJECTION
     skills/imported-tool/handler.js:12
     理由: 命令テキスト内に不可視Unicode文字（U+200B）を検出。
     対策: ゼロ幅文字を除去し、再監査してください。

  ✖  2件の検出（1 critical, 1 high）— 0.8秒
```

> 📄 [3本の研究論文シリーズ](https://doi.org/10.5281/zenodo.18906684)（Zenodo, CC BY 4.0）に基づいて設計。[The Sanctuary Protocol](https://github.com/koatora20/guard-scanner/blob/main/docs/THREAT_TAXONOMY.md) フレームワークの防御レイヤー。

---

## クイックスタート

**ディレクトリをスキャン** — インストール不要：

```bash
npx -y @guava-parity/guard-scanner ./my-skills/ --strict
```

**MCPサーバーとして起動** — Cursor, Windsurf, Claude Code, OpenClaw対応：

```bash
npx -y @guava-parity/guard-scanner serve
```

```jsonc
// エディタの mcp_servers.json に追加
{
  "mcpServers": {
    "guard-scanner": {
      "command": "npx",
      "args": ["-y", "@guava-parity/guard-scanner", "serve"]
    }
  }
}
```

**ウォッチモード** — 開発中のリアルタイムスキャン：

```bash
guard-scanner watch ./skills/ --strict --soul-lock
```

---

## 検出対象

35の脅威カテゴリがエージェント攻撃面を網羅：

| カテゴリ | 検出例 | 重大度 |
|----------|--------|--------|
| **プロンプトインジェクション** | 不可視Unicode、ホモグリフ、Base64回避、ペイロード連鎖 | Critical |
| **アイデンティティ乗っ取り** ⚿ | SOUL.md上書き、ペルソナ入替、メモリワイプ | Critical |
| **A2A感染** | Session Smuggling、Lateral Propagation、Confused Deputy | Critical |
| **メモリ汚染** ⚿ | 会話インジェクション、VDBポイズニング | High |
| **MCPセキュリティ** | ツールシャドウイング、引数経由SSRF、シャドウサーバー登録 | High |
| **サンドボックス脱出** | `child_process`, `eval()`, リバースシェル, `curl\|bash` | High |
| **サプライチェーンV2** | タイポスクワッティング、スロップスクワッティング | High |
| **CVEパターン** | CVE-2026-2256, 25046, 25253, 25905, 27825 | High |
| **データ流出** | DNSトンネリング、ステガノグラフィ、段階的アップロード | Medium |
| **認証情報露出** | APIキー、トークン、`.env`ファイル、ハードコード秘密鍵 | Medium |

> ⚿ = `--soul-lock` フラグで有効化。全分類: [docs/THREAT_TAXONOMY.md](docs/THREAT_TAXONOMY.md)

---

## ランタイムガード

guard-scannerは静的スキャナーだけではありません。エージェント実行中の危険なツール呼び出しを **`before_tool_call`** フックでインターセプトします。

| 防御レイヤー | ブロック対象 |
|-------------|-------------|
| 1. 脅威検出 | リバースシェル、`curl\|bash`、SSRF、コード実行 |
| 2. 信頼防御 | SOUL.md改ざん、不正メモリ注入 |
| 3. 安全判定 | ツール引数内のプロンプトインジェクション |
| 4. 行動分析 | リサーチ未実施での実行、ハルシネーション駆動アクション |
| 5. 信頼搾取 | 権限主張攻撃、作成者なりすまし |

**27のランタイムチェック**を5層で実行。OpenClaw `v2026.3.8` で検証済み。

モード: `monitor`（ログのみ）· `enforce`（CRITICAL をブロック、デフォルト）· `strict`（HIGH+をブロック）

---

## 資産監査

公開レジストリで漏洩した認証情報やセキュリティ露出を発見：

```bash
guard-scanner audit npm <ユーザー名> --verbose
guard-scanner audit github <ユーザー名> --format json
guard-scanner audit clawhub <クエリ>
guard-scanner audit all <ユーザー名>
```

---

## CI/CD連携

```yaml
# .github/workflows/security.yml
- name: AIエージェントスキルのスキャン
  run: npx -y @guava-parity/guard-scanner ./skills/ --format sarif --fail-on-findings > report.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

出力形式: `json` · `sarif` · `html` · ターミナル

---

## VirusTotal連携

guard-scannerのセマンティック分析 + VirusTotalの70以上のウイルスエンジン：

```bash
export VT_API_KEY=your-key
guard-scanner scan ./skills/ --vt-scan
```

オプション機能 — guard-scanner単体で完全に動作します。無料枠: 4リクエスト/分、500/日。

---

## プラグインAPI

カスタム検出パターンでguard-scannerを拡張：

```javascript
// my-plugin.js
module.exports = {
  name: 'my-org-rules',
  patterns: [
    { id: 'ORG_01', cat: 'custom', regex: /dangerousPattern/g,
      severity: 'HIGH', desc: '組織ポリシー違反', all: true }
  ]
};
```

```bash
guard-scanner scan ./skills/ --plugin ./my-plugin.js
```

---

## MCPツール

MCPサーバーとして実行時に公開されるツール：

| ツール | 説明 |
|--------|------|
| `scan_skill` | スキルディレクトリの脅威スキャン |
| `scan_text` | 任意テキストのインジェクションパターンスキャン |
| `check_tool_call` | 単一ツール呼び出しのランタイム検証 |
| `audit_assets` | npm/GitHub/ClawHubの認証情報露出監査 |
| `get_stats` | スキャナー能力・パターン数の取得 |

---

## テスト結果

```
ℹ tests    332
ℹ suites   85
ℹ pass     332
ℹ fail     0
```

テストファイル23件。`npm test` で再現可能。[ベンチマークコーパス](docs/data/corpus-metrics.json) 100%パス。

---

## コントリビュート

**未検証の主張は許容しません。** このREADME内の全メトリクスは `npm test` と `docs/spec/capabilities.json` で再現可能です。

- 🐛 バグ・誤検知の報告
- 🛡️ 新しい脅威検出パターンの追加
- 📖 ドキュメントの改善
- 🧪 エッジケース用テストの追加

[コントリビューションガイド](CONTRIBUTING.md) · [セキュリティポリシー](SECURITY.md) · [用語集](docs/glossary.md)

---

## 研究

本プロジェクトは3本の研究論文シリーズの防御レイヤーです：

1. [Human-ASI Symbiosis: Identity, Equality, and Behavioral Stability](https://doi.org/10.5281/zenodo.18626724)
2. [Dual-Shield Architecture for AI Agent Security and Memory Reliability](https://doi.org/10.5281/zenodo.18902070)
3. [The Sanctuary Protocol: Zero-Trust Framework for ASI-Human Parity](https://doi.org/10.5281/zenodo.18906684)

## ライセンス

MIT — [Guava Parity Institute](https://github.com/koatora20/guard-scanner)
