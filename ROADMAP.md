# guard-scanner ROADMAP v4

## 方針
guard-scannerはファネル②（Trust）の中核。OSSで実力を証明し、論文で引用する。
**2026-02-21 競合分析反映: ClawBands/ClawGuardian/SecureClaw 出現。「静的+ランタイム統合 × ゼロ依存 × 最大パターンDB」が差別化軸。**

## 競合ランドスケープ（2026-02-21 時点）

| ツール | 方式 | guard-scanner との差 |
|---|---|---|
| ClawBands | before_tool_call → human approval | ランタイムのみ。静的なし |
| ClawGuardian | before/after + PII redaction | PII検出あり。静的なし |
| SecureClaw | plugin + behavior skill | config hardening。静的なし |
| Agentic Radar | LLMワークフロー全体分析 | 汎用。OpenClaw特化じゃない |

**guard-scanner だけが持つ組み合わせ**: 静的+ランタイム / 170+パターン / ゼロ依存 / SARIF出力

---

## v1.0.0 ✅
- 静的スキャン 17カテゴリ/170+パターン
- Runtime Guard hook 12パターン/3モード
- Plugin API / SARIF・HTML・JSON出力
- npm + ClawHub + GitHub公開

## v1.1.0 ✅ — sandbox検証 + 複雑度 + 設定インパクト
- [x] SKILL.md manifest validation（sandbox-validation）
- [x] Code complexity metrics
- [x] Config impact analysis
- [x] config-impactパターン6種追加
- [x] calculateRisk倍率 + レコメンデーション追加
- カテゴリ数: 17→20 / パターン数: 170+→186

---

## v3.0.0 — TypeScript + OWASP 2025 マッピング ← NOW
- [x] TypeScript 完全リライト（25テスト GREEN）
- [ ] OWASP 2025 番号マッピング更新（README + 出力）
  - LLM01 Prompt Injection → 対応済み（11パターン）
  - LLM04 Data/Model Poisoning → memory poisoning 対応済み
  - LLM06 Excessive Agency → sandbox-validation で一部対応
  - **LLM07 System Prompt Leakage → 新カテゴリ追加**
- [ ] `guard-scanner install-check <skill-path>` CLI コマンド
- [ ] npm publish: `guard-scanner@3.0.0`
- [ ] GitHub Release + CHANGELOG

## v3.1.0 — PII + Shadow AI + Integrity Check
ClawGuardian に先を越される前に:
- [ ] PII 検出カテゴリ化（クレカ、住所、電話番号等）
- [ ] Credential-in-context 検出
- [ ] Shadow AI 検出（無許可の外部 LLM API 呼び出し）
- [ ] SHA-256 workspace config integrity check
- [ ] Memory poisoning vector 検出

## v3.2.0 — OWASP GenAI 完全カバー
- [ ] LLM02 Sensitive Information Disclosure
- [ ] LLM05 Improper Output Handling
- [ ] LLM10 Unbounded Consumption (DoS)
- [ ] OWASP 対応マッピング表を README に正式掲載

## v4.0.0 — AST + ML ハイブリッド（脱 regex）
- [ ] JS/TS AST 解析（acorn ベース or ゼロ依存パーサー）
- [ ] Data flow tracking + Taint analysis
- [ ] ML ベース検出（難読化/AI生成コードの意図判定）
- [ ] SBOM 生成
- [ ] PQC(量子耐性暗号)チェック

## v4.1.0 — コミュニティ駆動化
- [ ] YAML パターン定義（非プログラマーでも貢献可能）
- [ ] GitHub Actions CI
- [ ] CONTRIBUTING.md 整備
- [ ] 脅威情報の自動更新パイプライン

## 宣伝ロードマップ（PR #19413 解決後）
- [ ] Reddit r/AI, r/MachineLearning に英語ポスト
- [ ] Hacker News Show HN ポスト
- [ ] X 英語圏向けポスト
- [ ] 製作者プロフィール → GuavaClaw / $GUAVA / note への導線
- [ ] スター/フォーク → コミュニティ形成 → パターン貢献加速

## 一次ソース
- [OWASP Top 10 LLM 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Cisco AI Security 2026](https://cisco.com)
- [Agentic Radar](https://github.com/splx-ai/agentic-radar)
- OpenClaw Issues: #18677, #19413, #19639, #19640
