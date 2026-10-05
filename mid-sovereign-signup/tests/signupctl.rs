//! `signupctl` end to end: the shipped binary, in its own process, moving a
//! Supabase-shaped export into a live server on a bound socket — then
//! re-running, and proving every id landed.

use std::sync::Arc;

use mid_sovereign_signup::server::{
    serve, Clock, KeyDidResolver, Server, ServerConfig, ServiceIdentity, SystemClock, VolumeOnly,
};
use mid_sovereign_signup::store::MemEngine;
use mid_sovereign_signup::{OsEntropy, Pepper, SignupStore, StubMailer, Tenant, TenantId, UserId};
use serde_json::{json, Value};

const TOKEN: &str = "migration-token-0123456789abcdef0123456789";
const A: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const B: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const C: &str = "cccccccc-0000-4000-8000-000000000003";
const D: &str = "dddddddd-0000-4000-8000-000000000004";
const E: &str = "eeeeeeee-0000-4000-8000-000000000005";
const H: &str = "ffffffff-0000-4000-8000-000000000008";

fn row(id: &str, email: Option<&str>, confirmed: Option<&str>, username: Option<&str>) -> String {
    json!({
        "id": id,
        "email": email,
        "email_confirmed_at": confirmed,
        "created_at": "2025-06-01T10:00:00.000000+00:00",
        "last_sign_in_at": "2025-07-01 10:00:00+00",
        "raw_user_meta_data": {
            "username": username, "referral_code": "FRIEND", "webauthn_credential_id": format!("cred-{id}"),
            "email_verified": true, "sub": id
        }
    })
    .to_string()
}

async fn server() -> (String, Arc<Server<MemEngine>>) {
    let store = SignupStore::in_memory(Pepper::from_bytes([5; 32])).unwrap();
    let t = Tenant::new(
        TenantId::parse("mata").unwrap(),
        "MATA",
        vec![],
        SystemClock.now_secs(),
        &mut OsEntropy,
    )
    .unwrap();
    store.create_tenant(&t).unwrap();
    let server = Arc::new(Server::new(
        Arc::new(store),
        Arc::new(StubMailer::new()),
        Arc::new(ServiceIdentity::from_secret([9; 32]).unwrap()),
        Arc::new(KeyDidResolver),
        Arc::new(VolumeOnly),
        Arc::new(SystemClock),
        ServerConfig {
            import_token: Some(TOKEN.into()),
            ..ServerConfig::default()
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(server.clone(), listener, std::future::pending()));
    (url, server)
}

async fn ctl(args: &[&str]) -> (i32, String, String) {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_signupctl"))
        .args(args)
        .env("SIGNUP_IMPORT_TOKEN", TOKEN)
        .output()
        .await
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn signupctl_moves_a_supabase_export_in_and_proves_it() {
    let (url, server) = server().await;
    let dir = tempfile::tempdir().unwrap();
    let p = |n: &str| dir.path().join(n).to_string_lossy().to_string();
    let lines = [
        row(
            A,
            Some("Alice@Example.com"),
            Some("2025-06-01T10:05:00+00:00"),
            Some("Alice"),
        ),
        row(
            B,
            Some("bob@example.com"),
            Some("2025-06-02T10:05:00+00:00"),
            Some("alice"),
        ), // taken
        row(
            C,
            Some("carol@example.com"),
            Some("2025-06-03T10:05:00+00:00"),
            Some("a b"),
        ), // malformed
        row(D, Some("dave@example.com"), None, Some("dave")), // abandoned
        row(E, Some("erin@example.com"), None, Some("erin")), // unverified, but kept
        "this is not json".to_string(),
        row(
            "99999999-0000-4000-8000-000000000009",
            None,
            Some("2025-06-01T00:00:00Z"),
            None,
        ), // phone-only
        row(
            H,
            Some("alice@example.com"),
            Some("2025-06-04T10:05:00+00:00"),
            None,
        ), // another id, same address
    ];
    std::fs::write(p("auth_users.jsonl"), lines.join("\n") + "\n").unwrap();
    std::fs::write(
        p("keep.txt"),
        format!("# ids the registry knows\ndid:mata:{E}\n"),
    )
    .unwrap();

    // The export query is printable for any Supabase project.
    let (code, sql, _) = ctl(&["supabase-sql"]).await;
    assert_eq!(code, 0);
    assert!(sql.contains("from auth.users") && sql.contains("deleted_at is null"));

    // Dry run: parses and filters, sends nothing.
    let base = [
        "import",
        "--url",
        &url,
        "--tenant",
        "mata",
        "--file",
        &p("auth_users.jsonl"),
        "--keep-ids",
        &p("keep.txt"),
    ];
    let mut dry = base.to_vec();
    dry.push("--dry-run");
    let (_, out, _) = ctl(&dry).await;
    assert!(out.contains("sent 5") && out.contains("dry run"), "{out}");
    assert_eq!(
        server
            .store()
            .count_users(&TenantId::parse("mata").unwrap())
            .unwrap(),
        0
    );

    // The import.
    let mut real = base.to_vec();
    let (report_path, sent_path) = (p("report.json"), p("sent.txt"));
    real.extend([
        "--report",
        &report_path,
        "--ids-out",
        &sent_path,
        "--batch",
        "2",
    ]);
    let (code, out, err) = ctl(&real).await;
    assert_eq!(
        code, 1,
        "not clean: a parse error and a refusal\n{out}\n{err}"
    );
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(p("report.json")).unwrap()).unwrap();
    assert_eq!(report["source_rows"], 8);
    assert_eq!(report["parse_errors"].as_array().unwrap().len(), 2);
    assert_eq!(report["skipped_unverified"], 1);
    assert_eq!(
        (report["sent"].as_u64(), report["imported"].as_u64()),
        (Some(5), Some(4))
    );
    let dropped: Vec<(String, String)> = report["username_dropped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["id"].as_str().unwrap().into(),
                d["reason"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        dropped,
        vec![
            (B.into(), "username_taken".into()),
            (C.into(), "invalid_username".into())
        ]
    );
    assert_eq!(
        report["refused"],
        json!([{ "id": H, "reason": "email_taken" }])
    );
    assert!(
        !std::fs::read_to_string(p("report.json"))
            .unwrap()
            .contains('@'),
        "the report never names an address"
    );

    // What landed is what was meant: same ids, verified dates, metadata.
    let mata = TenantId::parse("mata").unwrap();
    let alice = server
        .store()
        .user(&mata, &UserId::parse(A).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (alice.email.as_str(), alice.username.as_deref()),
        ("alice@example.com", Some("alice"))
    );
    assert_eq!(alice.email_verified_at, Some(1_748_772_300));
    assert_eq!(alice.metadata["referral_code"], "FRIEND");
    assert!(!alice.metadata.contains_key("sub") && !alice.metadata.contains_key("email_verified"));
    let erin = server
        .store()
        .user(&mata, &UserId::parse(E).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        erin.email_verified_at, None,
        "kept, but not pretended verified"
    );
    assert!(server
        .store()
        .user(&mata, &UserId::parse(D).unwrap())
        .unwrap()
        .is_none());
    assert!(server.store().check_integrity().unwrap().is_clean());

    // Re-run: nothing new, nothing broken.
    let (_, out, _) = ctl(&real).await;
    assert!(
        out.contains("imported 0") && out.contains("already present 4"),
        "{out}"
    );

    // Verify: the sent list includes the refused id, so it is missing.
    let (code, out, _) = ctl(&[
        "verify",
        "--url",
        &url,
        "--tenant",
        "mata",
        "--expect-ids",
        &p("sent.txt"),
        "--missing-out",
        &p("missing.txt"),
    ])
    .await;
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("expected 5") && out.contains("missing 1"),
        "{out}"
    );
    assert_eq!(std::fs::read_to_string(p("missing.txt")).unwrap().trim(), H);
    // …and the registry's view (account DIDs + a key-derived DID) is complete.
    std::fs::write(
        p("registry.txt"),
        format!(
            "did:mata:{A}\ndid:mata:{E}\ndid:mata:xPoFoPWHEJWJFQXHLCXhTgyx6nvCKeEiXpGyprbqUYjw\n"
        ),
    )
    .unwrap();
    let (code, out, _) = ctl(&[
        "verify",
        "--url",
        &url,
        "--tenant",
        "mata",
        "--expect-ids",
        &p("registry.txt"),
    ])
    .await;
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("missing 0") && out.contains("non-account lines ignored 1"),
        "{out}"
    );

    // Without the token the door is refused; with the wrong token, too.
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_signupctl"))
        .args([
            "verify",
            "--url",
            &url,
            "--tenant",
            "mata",
            "--expect-ids",
            &p("registry.txt"),
        ])
        .env(
            "SIGNUP_IMPORT_TOKEN",
            "wrong-token-wrong-token-wrong-token!!xx",
        )
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("401"));
}
