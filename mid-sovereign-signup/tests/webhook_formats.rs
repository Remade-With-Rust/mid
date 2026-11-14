//! Webhook formats and the `signup.code_sent` event: what a Slack channel and a
//! signed-event receiver each get queued, and the endpoints a deployment
//! declares in `SIGNUP_BOOTSTRAP_WEBHOOKS`.

use mid_sovereign_signup::flow::{StartRequest, VerifyRequest};
use mid_sovereign_signup::server::env::{
    bootstrap_webhooks, parse_bootstrap_webhooks, CONFIG_WEBHOOK_PREFIX,
};
use mid_sovereign_signup::store::MemEngine;
use mid_sovereign_signup::{
    OsEntropy, Pepper, SignupStore, Tenant, TenantId, WebhookFormat,
};
use serde_json::Value;

const NOW: u64 = 1_759_190_400;

fn acme() -> TenantId {
    TenantId::parse("acme").unwrap()
}

fn store() -> SignupStore<MemEngine> {
    let s = SignupStore::in_memory(Pepper::from_bytes([9u8; 32])).unwrap();
    s.create_tenant(
        &Tenant::new(acme(), "Acme", vec!["https://app.acme.com".into()], NOW, &mut OsEntropy)
            .unwrap(),
    )
    .unwrap();
    s
}

fn ev(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn start(s: &SignupStore<MemEngine>, email: &str, now: u64) -> String {
    let t = acme();
    s.start(
        &StartRequest { tenant: &t, email, create_user: true, now },
        None,
        &mut OsEntropy,
    )
    .unwrap()
    .code
    .as_str()
    .to_string()
}

fn verify(s: &SignupStore<MemEngine>, email: &str, code: &str, now: u64) {
    let t = acme();
    s.verify(&VerifyRequest { tenant: &t, email, code, now }, &mut OsEntropy)
        .unwrap();
}

/// Every queued delivery as (endpoint id, event type, body), oldest first.
fn drain(s: &SignupStore<MemEngine>, now: u64) -> Vec<(String, String, Value)> {
    let due = s.due_deliveries(now, 100).unwrap();
    let out = due
        .iter()
        .map(|d| {
            (
                d.endpoint.id.clone(),
                d.item.event_type.clone(),
                serde_json::from_str(&d.item.payload).unwrap(),
            )
        })
        .collect();
    for d in due {
        s.delivery_succeeded(&d.item.id, now).unwrap();
    }
    out
}

#[test]
fn slack_gets_the_two_lines_and_event_receivers_get_signed_json() {
    let s = store();
    let otp = "https://hooks.slack.example/T/B/otp";
    let welcome = "https://hooks.slack.example/T/B/welcome";
    assert!(s
        .ensure_webhook(&acme(), "wh_cfg_otp", otp, ev(&["signup.code_sent"]), WebhookFormat::Slack, NOW, &mut OsEntropy)
        .unwrap());
    // Declaring the same endpoint again changes nothing.
    assert!(!s
        .ensure_webhook(&acme(), "wh_cfg_otp", otp, ev(&["signup.code_sent"]), WebhookFormat::Slack, NOW, &mut OsEntropy)
        .unwrap());
    s.ensure_webhook(&acme(), "wh_cfg_new", welcome, ev(&["user.created"]), WebhookFormat::Slack, NOW, &mut OsEntropy)
        .unwrap();
    let api = s
        .add_webhook(&acme(), "https://crm.acme.com/hooks", ev(&["signup.code_sent", "user.created"]), NOW, &mut OsEntropy)
        .unwrap();
    assert_eq!(api.format, WebhookFormat::Event);

    // A new address asks for a code.
    let code = start(&s, "New.Person@Example.COM", NOW);
    let q = drain(&s, NOW);
    assert_eq!(q.len(), 2, "{q:?}");
    let slack = q.iter().find(|(id, ..)| id == "wh_cfg_otp").unwrap();
    assert_eq!(slack.2, serde_json::json!({ "text": "New OTP Request for new.person@example.com" }));
    let json = q.iter().find(|(id, ..)| *id == api.id).unwrap();
    assert_eq!(json.1, "signup.code_sent");
    assert_eq!(json.2["type"], "signup.code_sent");
    assert_eq!(json.2["data"]["email"], "new.person@example.com");
    assert_eq!(json.2["data"]["existing_user"], false);

    // They verify: the welcome line, and nothing for the events Slack did not ask for.
    verify(&s, "new.person@example.com", &code, NOW + 10);
    let q = drain(&s, NOW + 10);
    let slack: Vec<_> = q.iter().filter(|(id, ..)| id.starts_with(CONFIG_WEBHOOK_PREFIX)).collect();
    assert_eq!(slack.len(), 1, "{q:?}");
    assert_eq!(slack[0].0, "wh_cfg_new");
    assert_eq!(slack[0].2, serde_json::json!({ "text": "Welcome new user - new.person@example.com" }));
    assert!(q.iter().any(|(id, t, _)| *id == api.id && t == "user.created"));

    // Signing in later: a code line again (existing user), no welcome.
    let code = start(&s, "new.person@example.com", NOW + 100);
    let q = drain(&s, NOW + 100);
    assert_eq!(q.iter().find(|(id, ..)| *id == api.id).unwrap().2["data"]["existing_user"], true);
    verify(&s, "new.person@example.com", &code, NOW + 110);
    let q = drain(&s, NOW + 110);
    assert!(q.iter().all(|(id, ..)| *id == api.id), "no Slack line on sign-in: {q:?}");
}

#[test]
fn slack_text_cannot_carry_a_link_or_mention() {
    let t = WebhookFormat::slack_text("signup.code_sent", "<!channel>&<https://evil|x>");
    assert!(!t.contains('<') && !t.contains('>'), "{t}");
    assert!(t.starts_with("New OTP Request for &lt;!channel&gt;&amp;"));
}

#[test]
fn declared_endpoints_sync_and_never_echo_their_url() {
    let raw = "acme|slack|signup.code_sent|https://hooks.slack.example/T/B/secret-one;\
               acme|slack|user.created|https://hooks.slack.example/T/B/secret-two";
    let hooks = parse_bootstrap_webhooks(raw).unwrap();
    assert_eq!(hooks.len(), 2);
    assert!(!format!("{hooks:?}").contains("secret"), "Debug hides the URL path");

    // A bad entry is reported by position, never by content.
    let err = parse_bootstrap_webhooks("acme|smoke|user.created|https://hooks.slack.example/T/B/secret").unwrap_err();
    assert!(!err.contains("secret") && err.contains("entry 1"), "{err}");
    assert!(parse_bootstrap_webhooks("acme|slack|user.nope|https://h.example/x").is_err());
    assert!(parse_bootstrap_webhooks("acme|slack|user.created|http://h.example/x").is_err());

    let s = store();
    let api = s
        .add_webhook(&acme(), "https://crm.acme.com/hooks", ev(&["user.created"]), NOW, &mut OsEntropy)
        .unwrap();
    bootstrap_webhooks(&s, &hooks, NOW).unwrap();
    let ids: Vec<String> = s.tenant(&acme()).unwrap().unwrap().webhooks.iter().map(|w| w.id.clone()).collect();
    assert_eq!(ids.len(), 3);

    // A rotated URL updates the same endpoint in place.
    let rotated = parse_bootstrap_webhooks(
        "acme|slack|signup.code_sent|https://hooks.slack.example/T/B/rotated;\
         acme|slack|user.created|https://hooks.slack.example/T/B/secret-two",
    )
    .unwrap();
    assert_eq!(rotated[0].id(), hooks[0].id());
    bootstrap_webhooks(&s, &rotated, NOW).unwrap();
    let t = s.tenant(&acme()).unwrap().unwrap();
    assert_eq!(t.webhooks.len(), 3);
    assert!(t.webhooks.iter().any(|w| w.url.ends_with("/rotated")));

    // Dropping a declaration removes its endpoint; API-created ones stay.
    bootstrap_webhooks(&s, &rotated[1..], NOW).unwrap();
    let ids: Vec<String> = s.tenant(&acme()).unwrap().unwrap().webhooks.iter().map(|w| w.id.clone()).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&api.id) && ids.contains(&rotated[1].id()));
    bootstrap_webhooks(&s, &[], NOW).unwrap();
    let ids: Vec<String> = s.tenant(&acme()).unwrap().unwrap().webhooks.iter().map(|w| w.id.clone()).collect();
    assert_eq!(ids, vec![api.id]);
}
