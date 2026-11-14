//! Background loops: webhook delivery, snapshot landing, housekeeping.

use std::sync::Arc;
use std::time::Duration;

use super::{blocking, Server};
use crate::store::StoreEngine;
use crate::webhook::{self, EVENT_ID_HEADER, EVENT_TYPE_HEADER, SIGNATURE_HEADER};

impl<E: StoreEngine + 'static> Server<E> {
    /// Attempt every webhook delivery due now, once. Returns how many were
    /// acknowledged. The delivery loop calls this; tests can too.
    pub async fn deliver_due(self: &Arc<Self>) -> usize {
        let store = self.store.clone();
        let now = self.now();
        let due = match blocking(move || store.due_deliveries(now, 50)).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "cannot read the webhook outbox");
                return 0;
            }
        };
        let mut ok = 0;
        for d in due {
            let ts = self.now();
            let signature = webhook::sign(&d.endpoint.secret, ts, d.item.payload.as_bytes());
            let sent = self
                .http
                .post(&d.endpoint.url)
                .header("content-type", "application/json")
                .header(SIGNATURE_HEADER, signature)
                .header(EVENT_ID_HEADER, &d.item.event_id)
                .header(EVENT_TYPE_HEADER, &d.item.event_type)
                .body(d.item.payload.clone())
                .send()
                .await;
            let failure = match sent {
                Ok(r) if r.status().is_success() => None,
                Ok(r) => Some(format!("HTTP {}", r.status())),
                Err(e) => Some(e.to_string()),
            };
            let store = self.store.clone();
            let id = d.item.id.clone();
            let now = self.now();
            match failure {
                None => {
                    ok += 1;
                    if let Err(e) = blocking(move || store.delivery_succeeded(&id, now)).await {
                        tracing::error!(error = %e, "could not dequeue a delivered webhook (it will repeat; receivers dedupe on the event id)");
                    }
                }
                Some(err) => {
                    tracing::warn!(webhook = %d.endpoint.id, event = %d.item.event_id, error = %err, "webhook delivery failed");
                    match blocking(move || store.delivery_failed(&id, now, &err)).await {
                        Ok(true) => {
                            tracing::error!(webhook = %d.endpoint.id, event = %d.item.event_id, "webhook delivery abandoned after its last retry")
                        }
                        Ok(false) => {}
                        Err(e) => tracing::error!(error = %e, "could not record a webhook failure"),
                    }
                }
            }
        }
        ok
    }
}

pub(super) fn spawn<E: StoreEngine + 'static>(
    s: Arc<Server<E>>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let deliver = {
        let s = s.clone();
        tokio::spawn(async move {
            loop {
                s.deliver_due().await;
                tokio::select! {
                    _ = s.wake.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        })
    };
    let snapshot = {
        let s = s.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                s.land_snapshot().await;
            }
        })
    };
    let housekeeping = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(600)).await;
            let store = s.store.clone();
            let now = s.now();
            let r = blocking(move || {
                let c = store.purge_challenges(now, 86_400)?;
                let k = store.purge_sessions(now)?;
                Ok::<_, crate::StoreError>((c, k))
            })
            .await;
            match r {
                Ok((c, k)) if c + k > 0 => {
                    tracing::info!(challenges = c, sessions = k, "housekeeping purged")
                }
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "housekeeping failed"),
            }
        }
    });
    vec![deliver, snapshot, housekeeping]
}
