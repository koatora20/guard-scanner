# guard-scanner ROADMAP

## 方針
guard-scannerはファネル②（Trust）の中核。OSSで実力を証明し、論文で引用する。
旧guava-guard-v5のTier 1/2、privacy-guardのPII検出を吸収。

## v1.0.0 ✅
- 静的スキャン 17カテゴリ/170+パターン
- Runtime Guard hook 12パターン/3モード
- Plugin API / SARIF・HTML・JSON出力
- npm + ClawHub + GitHub公開

## v1.1.0（現在 ✅）— sandbox検証 + 複雑度 + 設定インパクト
吸収元: Issue #18677フィードバック + OpenClawエコシステム調査
- [x] SKILL.md manifest validation（sandbox-validation）
  - 危険バイナリ要求検出（sudo/rm/curl等23種）
  - 広すぎるfileスコープ検出（**/*）
  - 機密env要求検出（SECRET/PASSWORD/PRIVATE_KEY等）
- [x] Code complexity metrics
  - 1000行超ファイル / 5段ネスト / eval密度2%超
- [x] Config impact analysis
  - openclaw.json直接書き込み検出
  - exec.approvals無効化 / exec.hostゲートウェイ化
  - hooks.internal変更 / network.allowedDomainsワイルドカード
- [x] config-impactパターン6種追加
- [x] calculateRisk倍率 + レコメンデーション追加
- カテゴリ数: 17→20 / パターン数: 170+→186

## v1.2 — PII検出カテゴリ
吸収元: `privacy-guard`
- [ ] PII検出をスキャンカテゴリ化（クレカ、住所、電話番号等）
- [ ] Credential-in-context検出
- [ ] Memory poisoning vector検出

## v2.0 — AST解析
吸収元: `guava-guard-v4` Tier 1
- [ ] JavaScript/TypeScript AST解析（ゼロ依存）
- [ ] データフロー追跡（変数→require/import→exec/fetch）
- [ ] Taint analysis
