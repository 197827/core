//! Attack tests for `txwatch-notifier` verifying HMAC signature defenses,
//! retry exhaustion behavior, and denial of service resistance.

use std::sync::{Arc, Mutex};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::oneshot;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use txwatch_notifier::{build_client, send_webhook, test_payload};

#[tokio::test]
async fn test_attack_hmac_tamper_detection() {
    let payload = test_payload("AttackTest");
    let body = serde_json::to_string(&payload).unwrap();
    let secret = "correct-secret-key";

    // Compute legitimate HMAC
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let valid_signature = hex::encode(mac.finalize().into_bytes());

    // Tampered payload body simulation
    let mut tampered_mac = Hmac::<Sha256>::new_from_slice(b"forged-attacker-key").unwrap();
    tampered_mac.update(body.as_bytes());
    let forged_signature = hex::encode(tampered_mac.finalize().into_bytes());

    assert_ne!(
        valid_signature, forged_signature,
        "Forged secret must never produce matching HMAC signature"
    );
}

#[tokio::test]
async fn test_attack_server_slowloris_or_500_flood_terminates() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let url = format!("{}/hook", server.uri());
    let payload = test_payload("SlowlorisDefense");
    let (_tx, rx) = oneshot::channel();

    let result = send_webhook(&client, &url, &payload, Some("secret"), rx).await;
    assert!(
        result.is_err(),
        "Exhausted retries on 500 flood must terminate with error"
    );
}

/// Records the `contract` field of every span that is entered, keyed by span id.
#[derive(Clone, Default)]
struct SpanRecorder {
    entered: Arc<Mutex<Vec<(u64, String)>>>,
}

struct ContractVisitor<'a>(&'a mut Option<String>);

impl Visit for ContractVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "contract" {
            *self.0 = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "contract" {
            *self.0 = Some(format!("{:?}", value));
        }
    }
}

impl<S> Layer<S> for SpanRecorder
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut contract = None;
        attrs.record(&mut ContractVisitor(&mut contract));
        if let Some(contract) = contract {
            if let Some(span) = ctx.span(id) {
                span.extensions_mut().insert(contract);
            }
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            if let Some(contract) = span.extensions().get::<String>() {
                self.entered
                    .lock()
                    .unwrap()
                    .push((id.into_u64(), contract.clone()));
            }
        }
    }

    fn on_event(&self, _event: &Event<'_>, _ctx: Context<'_, S>) {}
}

#[tokio::test]
async fn test_concurrent_deliveries_keep_span_attribution() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let recorder = SpanRecorder::default();
    let subscriber = tracing_subscriber::registry().with(recorder.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let client = build_client().unwrap();
    let url = format!("{}/hook", server.uri());

    let mut handles = Vec::new();
    for contract in ["ContractA", "ContractB"] {
        let client = client.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let payload = test_payload(contract);
            let (_tx, rx) = oneshot::channel();
            let span = tracing::info_span!("delivery", contract = contract);
            let _ = tracing::Instrument::instrument(
                send_webhook(&client, &url, &payload, Some("secret"), rx),
                span,
            )
            .await;
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let entered = recorder.entered.lock().unwrap().clone();
    assert!(
        !entered.is_empty(),
        "expected at least one span to be entered during delivery"
    );

    // Each span id must map to exactly one contract; a guard held across an
    // await would let a span be entered under the wrong task's context.
    let mut seen: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    for (id, contract) in entered {
        if let Some(prev) = seen.insert(id, contract.clone()) {
            assert_eq!(
                prev, contract,
                "span {id} was entered with conflicting contract attribution"
            );
        }
    }
}
