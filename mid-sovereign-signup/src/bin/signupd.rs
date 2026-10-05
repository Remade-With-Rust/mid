//! `signupd` — the open sign-up service, runnable by anyone.
//!
//! Volume-only durability, key-derived DIDs for backend callers (no
//! registry), and mail through SES when built with `mail-ses` and
//! `SES_FROM_ADDRESS` is set — otherwise codes are LOGGED (`[Email STUB]`),
//! which is for local use only. Configuration: see `server::env`.
//!
//! Refuses to start (exit 2, with a sentence) without a pepper, on an
//! unusable key file, or on a store it cannot open (e.g. already held).

use std::sync::Arc;

use mid_sovereign_signup::server::env::{bootstrap, bootstrap_webhooks, DaemonEnv};
use mid_sovereign_signup::server::{
    serve, Clock, KeyDidResolver, LogMailer, Server, ServiceIdentity, SystemClock, VolumeOnly,
};
use mid_sovereign_signup::{Mailer, Pepper, SignupStore};

fn die(msg: impl std::fmt::Display) -> ! {
    tracing::error!("{msg}");
    eprintln!("signupd: {msg}");
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let env = DaemonEnv::from_env().unwrap_or_else(|e| die(e));
    let store =
        SignupStore::open_dir(&env.db, Pepper::from_bytes(env.pepper)).unwrap_or_else(|e| {
            die(format!(
                "cannot open the store at {}: {e}",
                env.db.display()
            ))
        });
    let store = Arc::new(store);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    bootstrap(&store, &env.bootstrap, clock.now_secs())
        .unwrap_or_else(|e| die(format!("bootstrap: {e}")));
    bootstrap_webhooks(&store, &env.bootstrap_webhooks, clock.now_secs())
        .unwrap_or_else(|e| die(format!("bootstrap webhooks: {e}")));
    let identity = ServiceIdentity::from_secret(env.identity_secret).unwrap_or_else(|e| die(e));
    if env.cfg.import_token.is_some() {
        tracing::warn!(
            "SIGNUP_IMPORT_TOKEN is set — the migration door is OPEN. Unset it after the import."
        );
    }

    let mailer: Arc<dyn Mailer + Send + Sync> = mailer().await;
    tracing::info!(
        did = identity.did(),
        mail = mailer.kind(),
        durability = "volume-only",
        operators = env.cfg.operators.len(),
        "signupd ready"
    );
    let server = Arc::new(Server::new(
        store,
        mailer,
        Arc::new(identity),
        Arc::new(KeyDidResolver),
        Arc::new(VolumeOnly),
        clock,
        env.cfg,
    ));
    let listener = tokio::net::TcpListener::bind(&env.bind)
        .await
        .unwrap_or_else(|e| die(format!("bind {}: {e}", env.bind)));
    tracing::info!(bind = %env.bind, "listening");
    if let Err(e) = serve(server, listener, shutdown()).await {
        die(format!("server: {e}"));
    }
}

async fn mailer() -> Arc<dyn Mailer + Send + Sync> {
    #[cfg(feature = "mail-ses")]
    if let Some(m) = mid_sovereign_signup::mail_ses::SesMailer::from_env().await {
        return Arc::new(m);
    }
    tracing::warn!(
        "no mail provider configured — codes will be LOGGED ([Email STUB]); local use only"
    );
    Arc::new(LogMailer)
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    tracing::info!("shutdown signal received");
}
