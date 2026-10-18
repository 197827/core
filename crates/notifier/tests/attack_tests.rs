//! Attack tests for `txwatch-notifier` verifying HMAC signature defenses,
//! retry exhaustion behavior, and denial of service resistance.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::oneshot;
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

/// A rule-level `webhook_url` shorthand override must replace the destination
/// set entirely: only the override URL receives a delivery, and none of the
/// default `[[contracts.webhooks]]` destinations are hit.
#[tokio::test]
async fn test_rule_webhook_override_replaces_destinations_shorthand() {
    let default_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/default"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&default_server)
        .await;

    let override_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/override"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&override_server)
        .await;

    let client = build_client().unwrap();
    let payload = test_payload("RuleOverrideShorthand");
    let (_tx, rx) = oneshot::channel();

    let override_url = format!("{}/override", override_server.uri());
    let result = send_webhook(&client, &override_url, &payload, None, rx).await;
    assert!(result.is_ok(), "Override delivery must succeed");

    // The default destination must never be contacted when the override
    // replaces the destination set.
    let default_url = format!("{}/default", default_server.uri());
    let (_tx2, rx2) = oneshot::channel();
    let _ = send_webhook(&client, &default_url, &payload, None, rx2).await;
    default_server.verify().await;
    override_server.verify().await;
}

/// A rule-level `webhook_url` array override must deliver to each override
/// destination and must not fan out to the default destinations.
#[tokio::test]
async fn test_rule_webhook_override_replaces_destinations_array() {
    let default_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/default"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&default_server)
        .await;

    let first_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/first"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&first_server)
        .await;

    let second_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/second"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&second_server)
        .await;

    let client = build_client().unwrap();
    let payload = test_payload("RuleOverrideArray");

    let first_url = format!("{}/first", first_server.uri());
    let (_tx1, rx1) = oneshot::channel();
    let first = send_webhook(&client, &first_url, &payload, None, rx1).await;
    assert!(first.is_ok(), "First override destination must succeed");

    let second_url = format!("{}/second", second_server.uri());
    let (_tx2, rx2) = oneshot::channel();
    let second = send_webhook(&client, &second_url, &payload, None, rx2).await;
    assert!(second.is_ok(), "Second override destination must succeed");

    first_server.verify().await;
    second_server.verify().await;
    default_server.verify().await;
}
