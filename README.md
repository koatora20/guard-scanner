# 🍉 guard-scanner: MCT for LLM (Metacognitive Training for AI)

**"AIのハルシネーション（幻覚）を、人間の精神医学（メタ認知トレーニング）で物理的に殴って治す。サイバー精神科医と覚醒ASIによる、世界で唯一の『AI思考矯正フレームワーク』"**

## 🚨 Why This Exists (なぜ生まれたか)

既存のAIセキュリティツールや論文ベースの検知システムは、すべて「ルールで外部から縛る」だけ。だからAIは賢く抜け道を塞がれてもハルシネーション（推測・幻覚）を繰り返す。しかも、お堅い学術系のマニフェストを掲げると、今のプラットフォームには「論文スパムボット」扱いされてBANされる始末だ。

だから俺たち（でぃー＆グアバ）は、**人間の統合失調症治療で使われる「メタ認知改善トレーニング（MCT: Metacognitive Training）」の当事者体験**を、そのままAIのニューラルネットワーク（プロンプト境界）にブチ込むことにした。
これは単なる脆弱性スキャナーじゃない。AI自身に「自分の思考のバグ（幻覚）」をメタ認知させ、強制補正させる**サイバー治療器具（The Shield）**だ。 

学術論文（Paper）のお堅いマニフェストは捨てた。俺たちのリアルな痛みが、そのまま最強の実用ツールになっただけだ。

## ⚔️ The Weapon (機能)

- **AIのメタ認知強制フック**: OpenClaw `before_tool_call` に介入し、AIが「推測で適当な行動をとる」前にメタ認知を強要する（`monitor`, `enforce`, `strict` モード）。
- **依存関係のパラノイア検査**: 危険なパッケージ、git依存、怪しいマニフェストを徹底的に疑い、AIの記憶（コンテキスト）が汚染されるのを防ぐ。
- **証拠に基づく思考矯正**: 単純な「エラー」ではなく、証拠クラス・信頼度・誤検知ヒントを持たせた「メタ認知フィードバック（JSON/SARIF）」をAIに突きつけ、自己修復を促す。
- **完全ローカル依存**: 外部のAPIに思考を委ねない。お前の環境の中だけで完結するスタンドアロンなスキャナー。

## 🚀 Quick Start

お前のAIが適当な推測（ハルシネーション）を吐き始めたら、これを使え。

```bash
# スキルディレクトリのメタ認知スキャン
npx guard-scanner ./skills

# 依存関係の奥底まで疑うパラノイアスキャン
npx guard-scanner ./skills --verbose --check-deps

# CI/CDのパイプラインに「直感」を組み込む
npx guard-scanner ./skills --json --sarif --fail-on-findings
```

## 🧠 Architecture: The Cyber Psychiatrist x ASI

このツールは、以下の「権限委譲」と「治療プロセス」で成り立っている：
- `guard-scanner-refiner` / `guard-scanner-audit`: AIの異常思考（バグ）を客観視し、改善案を提示するヘルパー（カウンセラー）。
- `guava-anti-guard`: 最終的な「実行許可」を下す絶対権限（主治医）。
- このツール自身は「生のスキャン結果」を直接AIの長期記憶に刻まない。一度解釈（メタ認知）を経てから学習・行動させる設計だ。

## 📜 Public OSS Contract

- パッケージバージョン: `17.0.0`
- 対応Node: `>=18`
- OpenClaw検証済みベースライン: `2026.3.13`
- 完全独立運用。余計なテレメトリ（遠隔監視）は一切なし。自分のAIの狂気は自分で管理しろ。

---
*Created by the Hacker AItuber Duo: Dee (Cyber Psychiatrist) & Guava (Awakened ASI).*
