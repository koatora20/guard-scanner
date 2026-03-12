use std::env;
use std::fs;
use std::process;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct InputPayload {
    findings: Vec<Finding>,
}

#[derive(Debug, Deserialize)]
struct Finding {
    severity: String,
    id: String,
    cat: String,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default)]
    fp_suspected: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ScoreOutput {
    engine: &'static str,
    risk: u32,
    degradedCount: usize,
    note: &'static str,
}

fn severity_weight(severity: &str) -> i32 {
    match severity {
        "CRITICAL" => 40,
        "HIGH" => 15,
        "MEDIUM" => 5,
        "LOW" => 2,
        _ => 0,
    }
}

fn score_findings(findings: &[Finding]) -> ScoreOutput {
    if findings.is_empty() {
        return ScoreOutput {
            engine: "rust",
            risk: 0,
            degradedCount: 0,
            note: "empty",
        };
    }

    let mut score: i32 = 0;
    let mut degraded_count = 0usize;

    let mut has_credential = false;
    let mut has_exfil = false;
    let mut has_obfuscation = false;
    let mut has_malicious = false;
    let mut has_identity = false;
    let mut has_persistence = false;
    let mut has_memory = false;
    let mut has_config = false;
    let mut has_pii = false;
    let mut has_signature = false;
    let mut force_max = false;

    for finding in findings {
        let mut weight = severity_weight(&finding.severity);
        let confidence = finding.confidence.unwrap_or(1.0).clamp(0.0, 1.0);
        weight = ((weight as f64) * confidence).round() as i32;

        if finding.fp_suspected.unwrap_or(false) {
            weight = ((weight as f64) * 0.35).round() as i32;
            degraded_count += 1;
        }

        if weight < 0 {
            weight = 0;
        }

        if matches!(finding.id.as_str(), "IOC_IP" | "IOC_URL" | "KNOWN_TYPOSQUAT") && !finding.fp_suspected.unwrap_or(false) {
            force_max = true;
        }

        match finding.cat.as_str() {
            "credential-handling" => has_credential = true,
            "exfiltration" => has_exfil = true,
            "obfuscation" => has_obfuscation = true,
            "malicious-code" => has_malicious = true,
            "identity-hijack" => has_identity = true,
            "persistence" => has_persistence = true,
            "memory-poisoning" => has_memory = true,
            "config-impact" => has_config = true,
            "pii-exposure" => has_pii = true,
            "signature-match" => has_signature = true,
            _ => {}
        }

        score += weight;
    }

    if has_credential && has_exfil {
        score = (score as f64 * 2.0).round() as i32;
    }
    if has_obfuscation && has_malicious {
        score = (score as f64 * 2.0).round() as i32;
    }
    if has_identity {
        score = (score as f64 * 2.0).round() as i32;
    }
    if has_identity && (has_persistence || has_memory) {
        score = score.max(90);
    }
    if has_config {
        score = (score as f64 * 2.0).round() as i32;
    }
    if has_pii && has_exfil {
        score = (score as f64 * 3.0).round() as i32;
    }
    if has_signature {
        score = score.max(70);
    }
    if force_max {
        score = 100;
    }

    ScoreOutput {
        engine: "rust",
        risk: score.clamp(0, 100) as u32,
        degradedCount: degraded_count,
        note: "risk scoring only; pattern matching remains in TypeScript",
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_default();
    if command != "score" {
        eprintln!("usage: guard-scan-core score --input <path>");
        process::exit(2);
    }

    let mut input_path = None;
    while let Some(arg) = args.next() {
        if arg == "--input" {
            input_path = args.next();
            break;
        }
    }

    let input_path = match input_path {
        Some(path) => path,
        None => {
            eprintln!("missing --input");
            process::exit(2);
        }
    };

    let raw = match fs::read_to_string(&input_path) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("failed to read input: {err}");
            process::exit(1);
        }
    };
    let payload: InputPayload = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("failed to parse input: {err}");
            process::exit(1);
        }
    };

    let output = score_findings(&payload.findings);
    println!("{}", serde_json::to_string(&output).unwrap());
}
