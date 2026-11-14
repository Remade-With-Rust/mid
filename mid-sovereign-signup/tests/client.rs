//! The headless client against a real server on a bound socket.

use std::sync::Arc;

use mid_sovereign_signup::attest::{verify_attestation, AttestationPolicy};
use mid_sovereign_signup::client::{
    ClientError, SealedFileSessionStore, SessionStore, SignupClient, UserPatch,
};
use mid_sovereign_signup::server::{
    serve, Clock, KeyDidResolver, Server, ServerConfig, ServiceIdentity, SystemClock, VolumeOnly,
};
use mid_sovereign_signup::{Limits, OsEntropy, Pepper, SignupStore, StubMailer, Tenant, TenantId};

async fn boot() -> (
    SignupClient,
    Arc<StubMailer>,
    Arc<Server<mid_sovereign_signup::store::MemEngine>>,
) {
    let store = SignupStore::in_memory(Pepper::from_bytes([6; 32]))
        .unwrap()
        .with_limits(Limits::NONE);
    let t = Tenant::new(
        TenantId::parse("acme").unwrap(),
        "Acme",
        vec![],
        SystemClock.now_secs(),
        &mut OsEntropy,
    )
    .unwrap();
    store.create_tenant(&t).unwrap();
    let mail = Arc::new(StubMailer::new());
    let server = Arc::new(Server::new(
        Arc::new(store),
        mail.clone(),
        Arc::new(ServiceIdentity::from_secret([8; 32]).unwrap()),
        Arc::new(KeyDidResolver),
        Arc::new(VolumeOnly),
        Arc::new(SystemClock),
        ServerConfig::default(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "http://{}/v1/p/{}",
        listener.local_addr().unwrap(),
        t.public_id
    );
    tokio::spawn(serve(server.clone(), listener, std::future::pending()));
    (SignupClient::new(base), mail, server)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_drives_the_whole_lifecycle() {
    let (c, mail, server) = boot().await;
    assert_eq!(c.start("Client@Example.com", true).await.unwrap(), 60);
    let code = mail.take().pop().unwrap().code.as_str().to_string();

    let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
    let e = c.verify("client@example.com", &wrong).await.unwrap_err();
    assert!(
        matches!(
            e,
            ClientError::Api {
                attempts_left: Some(4),
                ..
            }
        ),
        "{e:?}"
    );

    let v = c.verify("client@example.com", &code).await.unwrap();
    assert!(v.user_created && v.first_verification);
    assert_eq!(v.user.email, "client@example.com");
    let acme = TenantId::parse("acme").unwrap();
    verify_attestation(
        &v.attestation,
        &AttestationPolicy {
            expected_issuer: Some(&v.attestation_issuer),
            expected_tenant: Some(&acme),
            now_unix_secs: server.now(),
            max_iat_skew_secs: 60,
        },
    )
    .unwrap();

    // Sessions at rest: sealed, reloadable, useless under another key.
    let dir = tempfile::tempdir().unwrap();
    let store = SealedFileSessionStore::new(dir.path().join("session"), [3; 32]);
    store.save(&v.session).unwrap();
    let loaded = store.load().unwrap().unwrap();

    assert!(c.username_available("clienty").await.unwrap());
    let mut md = std::collections::BTreeMap::new();
    md.insert("referral_code".to_string(), serde_json::json!("ABC"));
    let me = c
        .update_me(
            &loaded.token,
            &UserPatch {
                metadata: Some(md),
                username: Some(Some("Clienty".into())),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        (
            me.username.as_deref(),
            me.metadata["referral_code"].as_str()
        ),
        (Some("clienty"), Some("ABC"))
    );
    assert!(!c.username_available("clienty").await.unwrap());

    let fresh = c.attestation(&loaded.token).await.unwrap();
    assert_eq!(fresh.attestation_issuer, v.attestation_issuer);

    let rotated = c.refresh(&loaded.refresh).await.unwrap();
    assert!(
        c.me(&loaded.token).await.unwrap_err().is_unauthorized(),
        "the old access token died"
    );
    assert_eq!(c.me(&rotated.token).await.unwrap().id, v.user.id);
    assert!(
        c.refresh(&loaded.refresh)
            .await
            .unwrap_err()
            .is_unauthorized(),
        "replay refused"
    );
    assert!(
        c.me(&rotated.token).await.unwrap_err().is_unauthorized(),
        "and the replay revoked the family"
    );

    // Sign in again, then sign out everywhere.
    c.start("client@example.com", false).await.unwrap();
    let code = mail.take().pop().unwrap().code.as_str().to_string();
    let again = c.verify("client@example.com", &code).await.unwrap();
    assert!(!again.user_created);
    assert_eq!(again.user.id, v.user.id);
    assert_eq!(c.logout_all(&again.session.token).await.unwrap(), 1);
    assert!(c
        .me(&again.session.token)
        .await
        .unwrap_err()
        .is_unauthorized());

    // A network failure is typed as one.
    let dead = SignupClient::new("http://127.0.0.1:9/v1/p/pub_x");
    assert_eq!(
        dead.start("x@y.co", true).await.unwrap_err().code(),
        "network"
    );
}
