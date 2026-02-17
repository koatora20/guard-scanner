# guard-scanner — STATUS

## ステータス: 🟢 v1.1.1 公開済み（Research-First改善を順次実行中）

## ファネル上の位置: ② TRUST（信頼構築）

## 概要
AIエージェントのスキル脅威を検出するセキュリティスキャナー。OSS/無料。
論文で引用 → 学術権威 → ユーザー獲得の入口。

## 公開先
- **npm**: `guard-scanner@1.1.1` → `npx guard-scanner`
- **ClawHub**: `guard-scanner@1.1.1`
- **GitHub**: [koatora20/guard-scanner](https://github.com/koatora20/guard-scanner)
- **OpenClaw Issue**:
  - #18677（Hook cancel/veto API リクエスト）

## スペック（現行）
- 20脅威カテゴリ / 186+パターン
- Runtime Guard hook（OpenClaw公式型準拠、現状warn-only）
- Plugin API / SARIF・HTML・JSON出力
- ゼロ依存

## 進捗（2026-02-17）
- [x] 鉄の掟で事前リサーチ（Semgrep / SARIF / OWASP MCP / SLSA）
- [x] `docs/TASKLIST_RESEARCH_FIRST_V1.md` 作成（RED→GREEN→REFACTOR）
- [x] RED: 生成レポート自己再検知ノイズの再現テスト追加
- [x] GREEN: `guard-scanner-report.{json,html}` / `.sarif` をデフォルト除外
- [x] テスト更新後の再実行: **56 PASS / 0 FAIL**

## 次のアクション
1. SARIF妥当性テスト（schema + ingestion）
2. fingerprint安定化確認
3. ルール文脈分離（FP削減）
4. テスト結果を継続報告
