//! `signupctl` — move a user base into a mid-sovereign-signup service.
//!
//! ```text
//! signupctl supabase-sql
//!     → the query that exports a Supabase project's auth.users as JSONL
//!
//! signupctl import --url <server> --tenant <id> --file <users.jsonl>
//!     [--from native|supabase]          input shape (default supabase)
//!     [--username-key <key>]            supabase: metadata key of the username (default username)
//!     [--include-unverified]            carry rows whose address was never confirmed
//!     [--keep-ids <file>]               …or only these (UUIDs or did:mata:<uuid>, one per line)
//!     [--username-conflict drop|refuse] a taken/malformed username (default drop: import without it)
//!     [--batch <n>]                     users per request (default 500, max 1000)
//!     [--report <file>]                 the JSON report (ids and counts, never an address)
//!     [--ids-out <file>]                every id sent, for `verify`
//!     [--dry-run]                       parse, filter and report; send nothing
//!
//! signupctl verify --url <server> --tenant <id> --expect-ids <file> [--missing-out <file>]
//!     → exit 0 only if every id in the file has a user
//! ```
//!
//! The import token is read from `SIGNUP_IMPORT_TOKEN` — never an argument,
//! so it stays out of shell history. Imports keep ids and are safe to re-run:
//! users already present answer `already_present`.

use std::collections::BTreeSet;
use std::process::ExitCode;

use mid_sovereign_signup::migrate::{
    parse_line, read_ids, Filter, LineError, Report, Source, SUPABASE_EXPORT_SQL,
};
use serde_json::{json, Value};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn required(args: &[String], name: &str) -> Result<String, String> {
    arg(args, name).ok_or_else(|| format!("missing {name}"))
}

fn token() -> Result<String, String> {
    std::env::var("SIGNUP_IMPORT_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .map(|t| t.trim().to_string())
        .ok_or_else(|| "SIGNUP_IMPORT_TOKEN is not set".to_string())
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("supabase-sql") => {
            println!("{SUPABASE_EXPORT_SQL}");
            Ok(true)
        }
        Some("import") => import(&args).await,
        Some("verify") => verify(&args).await,
        _ => Err(
            "usage: signupctl supabase-sql | import … | verify … (see the source header)".into(),
        ),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("signupctl: {e}");
            ExitCode::from(2)
        }
    }
}

async fn import(args: &[String]) -> Result<bool, String> {
    let url = required(args, "--url")?;
    let tenant = required(args, "--tenant")?;
    let file = required(args, "--file")?;
    let source = match arg(args, "--from").as_deref().unwrap_or("supabase") {
        "native" => Source::Native,
        "supabase" => Source::Supabase {
            username_key: arg(args, "--username-key").unwrap_or_else(|| "username".into()),
        },
        other => return Err(format!("--from must be native or supabase, not {other:?}")),
    };
    let conflict = arg(args, "--username-conflict").unwrap_or_else(|| "drop".into());
    if conflict != "drop" && conflict != "refuse" {
        return Err("--username-conflict must be drop or refuse".into());
    }
    let batch: usize = arg(args, "--batch")
        .map(|b| {
            b.parse()
                .map_err(|_| "--batch must be a number".to_string())
        })
        .transpose()?
        .unwrap_or(500);
    if !(1..=1_000).contains(&batch) {
        return Err("--batch must be 1..=1000".into());
    }
    let keep_ids: BTreeSet<String> = match arg(args, "--keep-ids") {
        Some(p) => read_ids(&read(&p)?).0.into_iter().collect(),
        None => BTreeSet::new(),
    };
    let filter = Filter {
        include_unverified: flag(args, "--include-unverified"),
        keep_ids,
    };
    let dry = flag(args, "--dry-run");

    let mut report = Report::default();
    let mut send = Vec::new();
    for (i, line) in read(&file)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        report.source_rows += 1;
        match parse_line(&source, line) {
            Ok(r) if filter.wants(&r) => send.push(r),
            Ok(_) => report.skipped_unverified += 1,
            Err(e) => report.parse_errors.push(LineError {
                line: i + 1,
                error: e,
            }),
        }
    }
    report.sent = send.len();
    report.sent_ids = send.iter().map(|r| r.id.to_lowercase()).collect();

    if !dry {
        let token = token()?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| e.to_string())?;
        let endpoint = format!("{}/v1/import", url.trim_end_matches('/'));
        for (n, chunk) in send.chunks(batch).enumerate() {
            let body = json!({ "tenant": tenant, "users": chunk, "username_conflict": conflict });
            let resp = http
                .post(&endpoint)
                .bearer_auth(&token)
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("batch {}: {e} (re-running is safe)", n + 1))?;
            let status = resp.status();
            let v: Value = resp.json().await.unwrap_or(Value::Null);
            if !status.is_success() {
                write_report(args, &report)?;
                return Err(format!(
                    "batch {}: HTTP {status} {} (re-running is safe)",
                    n + 1,
                    v["error"].as_str().unwrap_or("")
                ));
            }
            for r in v["results"].as_array().into_iter().flatten() {
                report.absorb(r);
            }
            eprintln!("batch {}: {} users", n + 1, chunk.len());
        }
    }
    write_report(args, &report)?;
    if let Some(p) = arg(args, "--ids-out") {
        std::fs::write(&p, report.sent_ids.join("\n") + "\n").map_err(|e| format!("{p}: {e}"))?;
    }
    println!(
        "rows {} · parse errors {} · skipped unverified {} · sent {} · imported {} · already present {} · usernames dropped {} · refused {}{}",
        report.source_rows,
        report.parse_errors.len(),
        report.skipped_unverified,
        report.sent,
        report.imported,
        report.already_present,
        report.username_dropped.len(),
        report.refused.len(),
        if dry { " (dry run: nothing sent)" } else { "" }
    );
    Ok(if dry {
        report.parse_errors.is_empty()
    } else {
        report.is_clean()
    })
}

fn write_report(args: &[String], report: &Report) -> Result<(), String> {
    if let Some(p) = arg(args, "--report") {
        let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
        std::fs::write(&p, json).map_err(|e| format!("{p}: {e}"))?;
    }
    Ok(())
}

async fn verify(args: &[String]) -> Result<bool, String> {
    let url = required(args, "--url")?;
    let tenant = required(args, "--tenant")?;
    let (ids, not_accounts) = read_ids(&read(&required(args, "--expect-ids")?)?);
    let token = token()?;
    let http = reqwest::Client::new();
    let endpoint = format!("{}/v1/import/check", url.trim_end_matches('/'));
    let mut missing: Vec<String> = Vec::new();
    for chunk in ids.chunks(5_000) {
        let resp = http
            .post(&endpoint)
            .bearer_auth(&token)
            .json(&json!({ "tenant": tenant, "ids": chunk }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(format!(
                "HTTP {status} {}",
                v["error"].as_str().unwrap_or("")
            ));
        }
        missing.extend(
            v["missing"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|m| m.as_str().map(str::to_string)),
        );
    }
    if let Some(p) = arg(args, "--missing-out") {
        std::fs::write(&p, missing.join("\n") + "\n").map_err(|e| format!("{p}: {e}"))?;
    }
    println!(
        "expected {} · present {} · missing {} · non-account lines ignored {}",
        ids.len(),
        ids.len() - missing.len(),
        missing.len(),
        not_accounts
    );
    Ok(missing.is_empty())
}
