# guard-scanner Research-First Tasklist (t-wada + 鉄の掟)

Updated: 2026-02-17

## 0) Research Baseline (完了)
- [x] Semgrep rule testing practices（ruleid/okでFN/FPを分離管理）
- [x] GitHub SARIF要件（重複防止fingerprint・SARIF 2.1.0 subset）
- [x] OWASP MCP Top 10（context/protocol attack surface）
- [x] SLSA levels（provenance配布・build track段階化）

## 1) RED — テスト仕様を先に固定
- [ ] T1: False Positive回帰テストを追加（safe skill 20ケース）
- [ ] T2: False Negative回帰テストを追加（malicious corpus 20ケース）
- [x] T3: node_modules/生成レポート由来ノイズの再現テスト
- [ ] T4: SARIF妥当性テスト（schema + GitHub ingestion向け）
- [ ] T5: 性能テスト（N=10/50/100 skillsで時間とメモリ）

## 2) GREEN — 最小実装
- [x] G1: デフォルト除外ルール（node_modules / guard-scanner-report.*）
- [ ] G2: trust-boundaryの文脈制約（docs/コメント誤検知を抑制）
- [ ] G3: entropy検知の閾値と例外改善（既知データ定数除外）
- [ ] G4: SARIF fingerprint一貫性の強化

## 3) REFACTOR — 構造改善
- [ ] R1: 検知ルールを「攻撃シグナル」と「文脈ルール」に分離
- [ ] R2: ルール単位で precision/recall メトリクス出力
- [ ] R3: release gate（テスト全通過 + SLSA provenance確認）

## 4) Delivery & GTM
- [ ] D1: note無料記事（使い方 + 失敗例 + 回避）
- [ ] D2: X告知（SEO/LLMOワード最適化2パターンAB）
- [ ] D3: Moltbook技術投稿（検知改善ログ + フィードバック募集）

## Exit Criteria
- FP率: 現状比 30%以上削減
- FN率: 悪性固定コーパスで95%以上検知
- 55既存テスト + 新規テスト全PASS
- SARIFをGitHub Code Scanningで取り込み確認
