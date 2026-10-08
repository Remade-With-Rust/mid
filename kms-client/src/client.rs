//! The HTTP round-trip helper.
//!
//! Talks to a remote verifier's `/v1/nonce` endpoint, then signs the
//! returned [`NonceEnvelope`] using the provided [`DeviceSigner`].

use kms_types::{NonceEnvelope, SignedAssertion, VerifyError};
use serde::Serialize;
use thiserror::Error;

use crate::{sign_assertion, DeviceSigner};

/// Errors that can occur during the HTTP round-trip.
///
/// Per [envelope_spec.md §"Error taxonomy"](../../../docs/kms/envelope_spec.md),
/// the server returns the granular variants as a single opaque
/// `"invalid assertion"` 4xx — clients shouldn't try to differentiate the
/// failure modes. We surface `HttpStatus` opaquely for that reason. Local
/// errors (no network, bad JSON, envelope-shape failures) are differentiated
/// so the wallet can show a meaningful retry path.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Transport failure — no response, TLS error, DNS, etc.
    #[error("network error: {0}")]
    Network(String),

    /// Server returned a non-2xx response.
    #[error("server returned HTTP {status}: {body}")]
    HttpStatus {
        /// Status code.
        status: u16,
        /// Response body (typically opaque).
        body: String,
    },

    /// Response body couldn't be parsed as JSON.
    #[error("malformed response body: {0}")]
    BadResponseBody(String),

    /// Response decoded as a [`NonceEnvelope`] but failed shape validation
    /// (e.g., server returned an envelope with TTL > 300s, wrong version,
    /// etc.). Defensive — a misbehaving server cannot trick the client into
    /// signing something out-of-spec.
    #[error("server returned invalid envelope: {0}")]
    InvalidEnvelope(VerifyError),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Network(e.to_string())
    }
}

/// HTTP client for a remote KMS verifier's nonce-issuance endpoint.
///
/// Configured with a base URL (e.g., `https://banking.mata.network`). The
/// nonce endpoint is `<base_url>/v1/nonce`.
///
/// Build one per service: a wallet talking to both banking and OIDC would
/// hold two `KmsClient` instances with different base URLs.
pub struct KmsClient {
    base_url: String,
    http: reqwest::Client,
}

impl KmsClient {
    /// Construct a client with the default `reqwest::Client`. The base URL
    /// should NOT include a trailing slash; `/v1/nonce` is appended.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Construct a client with a caller-supplied [`reqwest::Client`]. Use
    /// this when the wallet has already configured a client with custom
    /// timeouts, headers, or middleware.
    pub fn with_http_client(base_url: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    /// Request a fresh nonce envelope from the server.
    ///
    /// POSTs `{ did, purpose }` to `<base_url>/v1/nonce`. The server is
    /// expected to return a [`NonceEnvelope`] JSON body on 2xx.
    pub async fn request_nonce(
        &self,
        did: &str,
        purpose: &str,
    ) -> Result<NonceEnvelope, ClientError> {
        #[derive(Serialize)]
        struct Body<'a> {
            did: &'a str,
            purpose: &'a str,
        }

        let url = format!("{}/v1/nonce", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&Body { did, purpose })
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        let envelope: NonceEnvelope = resp
            .json()
            .await
            .map_err(|e| ClientError::BadResponseBody(e.to_string()))?;

        envelope.validate().map_err(ClientError::InvalidEnvelope)?;

        Ok(envelope)
    }

    /// Full round-trip: request a nonce, sign it, return the assertion ready
    /// to send to the protected endpoint.
    pub async fn request_and_sign(
        &self,
        signer: &dyn DeviceSigner,
        did: &str,
        purpose: &str,
    ) -> Result<SignedAssertion, ClientError> {
        let envelope = self.request_nonce(did, purpose).await?;
        sign_assertion(signer, envelope).map_err(ClientError::InvalidEnvelope)
    }
}
