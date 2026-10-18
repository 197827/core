//! Maps an [`AlertPayload`] to the body each supported receiver expects.
//!
//! - `txwatch`: the payload itself.
//! - `slack`: a Slack incoming-webhook message (`text` fallback plus Block Kit
//!   `blocks`).
//! - `discord`: a Discord webhook message (`content` plus one embed), with
//!   mentions disabled so a label can never ping `@everyone`.
//! - `pagerduty`: a PagerDuty Events API v2 `trigger` event whose `dedup_key`
//!   is the alert's `alert_id`.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use txwatch_config::WebhookFormat;
use txwatch_rules::AlertPayload;

/// Renders the request body for `format`. `routing_key` is required for
/// PagerDuty and ignored otherwise.
pub fn render_body(
    format: WebhookFormat,
    payload: &AlertPayload,
    routing_key: Option<&str>,
) -> Result<String> {
    let body = match format {
        WebhookFormat::Txwatch => serde_json::to_value(payload)?,
        WebhookFormat::Slack => slack(payload),
        WebhookFormat::Discord => discord(payload),
        WebhookFormat::Pagerduty => pagerduty(
            payload,
            routing_key.ok_or_else(|| anyhow!("PagerDuty destinations need a routing_key"))?,
        ),
    };
    Ok(serde_json::to_string(&body)?)
}

/// One-line summary shared by the chat formats.
fn headline(p: &AlertPayload) -> String {
    format!(
        "TxWatch alert: {} on {} ({})",
        p.rule_triggered, p.label, p.network
    )
}

/// Optional detail lines as (name, value) pairs, in display order.
fn details(p: &AlertPayload) -> Vec<(&'static str, String)> {
    let mut details = Vec::new();
    if let Some(xlm) = p.amount_xlm {
        details.push(("Amount", format!("{} XLM", xlm)));
    }
    if let Some(fee) = p.fee_charged_stroops {
        details.push(("Fee", format!("{} stroops", fee)));
    }
    if !p.function_names.is_empty() {
        details.push(("Functions", p.function_names.join(", ")));
    }
    details
}

/// Truncates to at most `max` characters, marking the cut with `…`.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// Normalises the configured rule severity to one of `info`, `warning`,
/// `critical`. Returns `None` when the payload carries no severity so callers
/// can fall back to the rule-type heuristic.
fn configured_severity(p: &AlertPayload) -> Option<&'static str> {
    let raw = p.severity.as_deref()?.trim();
    if raw.is_empty() {
        return None;
    }
    match raw.to_ascii_lowercase().as_str() {
        "info" => Some("info"),
        "warning" | "warn" => Some("warning"),
        "critical" | "error" => Some("critical"),
        _ => None,
    }
}

// ── Slack ─────────────────────────────────────────────────────────────────────

/// Escapes the three characters Slack mrkdwn treats as control characters.
fn slack_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Severity emoji for the Slack headline: configured severity wins, falling
/// back to the rule-type heuristic when unset.
fn slack_emoji(p: &AlertPayload) -> &'static str {
    match configured_severity(p) {
        Some("info") => ":information_source:",
        Some("warning") => ":warning:",
        Some("critical") => ":rotating_light:",
        _ => match p.rule_type.as_str() {
            "TransactionFailed" | "AdminFunctionCalled" => ":rotating_light:",
            "TestWebhook" => ":information_source:",
            _ => ":warning:",
        },
    }
}

/// Slack incoming-webhook message.
pub fn slack(p: &AlertPayload) -> Value {
    let mut fields = vec![
        json!({ "type": "mrkdwn", "text": format!("*Contract*\n`{}`", p.contract_id) }),
        json!({
            "type": "mrkdwn",
            "text": format!("*Transaction*\n<{}|{}>", p.explorer_link, p.transaction_hash),
        }),
    ];
    for (name, value) in details(p) {
        fields.push(json!({
            "type": "mrkdwn",
            "text": format!("*{}*\n{}", name, slack_escape(&value)),
        }));
    }
    fields.push(json!({ "type": "mrkdwn", "text": format!("*Time*\n{}", p.timestamp_iso) }));

    json!({
        "text": slack_escape(&headline(p)),
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(
                        "{} *{}* on *{}* ({})",
                        slack_emoji(p),
                        slack_escape(&p.rule_triggered),
                        slack_escape(&p.label),
                        slack_escape(&p.network)
                    ),
                },
            },
            { "type": "section", "fields": fields },
            {
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": format!(
                        "<{}|Explorer> · <{}|Horizon> · alert `{}`",
                        p.explorer_link, p.horizon_link, p.alert_id
                    ),
                }],
            },
        ],
    })
}

// ── Discord ───────────────────────────────────────────────────────────────────

/// Embed colour: configured severity wins (info→blue, warning→amber,
/// critical→red), falling back to the rule-type heuristic when unset.
fn discord_color(p: &AlertPayload) -> u32 {
    match configured_severity(p) {
        Some("info") => 0x34_98_DB,
        Some("warning") => 0xF1_C4_0F,
        Some("critical") => 0xE7_4C_3C,
        _ => match p.rule_type.as_str() {
            "TransactionFailed" | "AdminFunctionCalled" => 0xE7_4C_3C,
            _ => 0x34_98_DB,
        },
    }
}

/// Discord webhook message.
pub fn discord(p: &AlertPayload) -> Value {
    let mut fields = vec![
        json!({ "name": "Contract", "value": format!("`{}`", p.contract_id), "inline": false }),
        json!({
            "name": "Transaction",
            "value": truncate(&format!("[{}]({})", p.transaction_hash, p.explorer_link), 1024),
            "inline": false,
        }),
    ];
    for (name, value) in details(p) {
        fields.push(json!({ "name": name, "value": truncate(&value, 1024), "inline": true }));
    }
    fields.push(json!({
        "name": "Horizon",
        "value": truncate(&format!("[transaction]({})", p.horizon_link), 1024),
        "inline": true,
    }));

    json!({
        "username": "TxWatch",
        "content": truncate(&headline(p), 2000),
        "allowed_mentions": { "parse": [] },
        "embeds": [{
            "title": truncate(&p.rule_triggered, 256),
            "url": p.explorer_link,
            "description": truncate(&format!("{} ({})", p.label, p.network), 4096),
            "color": discord_color(p),
            "timestamp": p.timestamp_iso,
            "fields": fields,
            "footer": { "text": format!("TxWatch · alert {}", p.alert_id) },
        }],
    })
}

// ── PagerDuty ─────────────────────────────────────────────────────────────────

/// PagerDuty severity: the configured rule severity wins (info→info,
/// warning→warning, critical→critical); otherwise fall back to the rule-type
/// heuristic (failed transactions `error`, admin calls `critical`, test
/// webhooks `info`, everything else `warning`).
fn pagerduty_severity(p: &AlertPayload) -> &'static str {
    if let Some(severity) = configured_severity(p) {
        return severity;
    }
    match p.rule_type.as_str() {
        "TransactionFailed" => "error",
        "AdminFunctionCalled" => "critical",
        "TestWebhook" => "info",
        _ => "warning",
    }
}

/// PagerDuty Events API v2 `trigger` event. The full alert is attached as
/// `payload.custom_details`.
pub fn pagerduty(p: &AlertPayload, routing_key: &str) -> Value {
    json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": p.alert_id,
        "client": "TxWatch",
        "client_url": p.explorer_link,
        "links": [
            { "href": p.explorer_link, "text": "View transaction" },
            { "href": p.horizon_link, "text": "Horizon" },
        ],
        "payload": {
            "summary": truncate(
                &format!("{} — tx {}", headline(p), p.transaction_hash),
                1024,
            ),
            "source": p.contract_id,
            "severity": pagerduty_severity(p),
            "timestamp": p.timestamp_iso,
            "component": p.label,
            "group": p.network,
            "class": p.rule_type,
            "custom_details": p,
        },
    })
}

// ── Snapshot tests ────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A LargeTransfer alert whose label needs escaping in Slack mrkdwn.
    fn fixture() -> AlertPayload {
        AlertPayload {
            alert_id: "3f2b9c1d8e7a6b5c4d3e2f1a0b9c8d7e".into(),
            label: "Escrow <main> & co".into(),
            contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            network: "testnet".into(),
            rule_type: "LargeTransfer".into(),
            rule_triggered: "LargeTransfer(>=10000XLM)".into(),
            transaction_hash: "abc123".into(),
            function_name: Some("transfer".into()),
            function_names: vec!["transfer".into()],
            amount_xlm: Some(15000),
            fee_charged_stroops: Some(50000),
            timestamp: 1705320000,
            timestamp_iso: "2024-01-15T12:00:00Z".into(),
            explorer_link: "https://stellar.expert/explorer/testnet/tx/abc123".into(),
            horizon_link: "https://horizon-testnet.stellar.org/transactions/abc123".into(),
            severity: None,
        }
    }

    #[test]
    fn pagerduty_severity_prefers_configured_severity() {
        let mut p = fixture();
        p.rule_type = "AdminFunctionCalled".into();
        p.severity = Some("info".into());
        assert_eq!(pagerduty_severity(&p), "info");

        let mut p = fixture();
        p.severity = Some("critical".into());
        assert_eq!(pagerduty_severity(&p), "critical");

        let mut p = fixture();
        p.severity = Some("warning".into());
        assert_eq!(pagerduty_severity(&p), "warning");
    }

    #[test]
    fn pagerduty_severity_falls_back_to_rule_type() {
        let mut p = fixture();
        p.rule_type = "AdminFunctionCalled".into();
        assert_eq!(pagerduty_severity(&p), "critical");

        let mut p = fixture();
        p.rule_type = "TransactionFailed".into();
        assert_eq!(pagerduty_severity(&p), "error");
    }

    #[test]
    fn discord_color_prefers_configured_severity() {
        let mut p = fixture();
        p.severity = Some("critical".into());
        assert_eq!(discord_color(&p), 0xE7_4C_3C);

        let mut p = fixture();
        p.rule_type = "AdminFunctionCalled".into();
        p.severity = Some("info".into());
        assert_eq!(discord_color(&p), 0x34_98_DB);
    }

    #[test]
    fn discord_color_falls_back_to_rule_type() {
        let mut p = fixture();
        p.rule_type = "AdminFunctionCalled".into();
        assert_eq!(discord_color(&p), 0xE7_4C_3C);

        let p = fixture();
        assert_eq!(discord_color(&p), 0x34_98_DB);
    }

    #[test]
    fn slack_emoji_prefers_configured_severity() {
        let mut p = fixture();
        p.rule_type = "AdminFunctionCalled".into();
        p.severity = Some("info".into());
        assert_eq!(slack_emoji(&p), ":information_source:");

        let mut p = fixture();
        p.severity = Some("critical".into());
        assert_eq!(slack_emoji(&p), ":rotating_light:");
    }

    #[test]
    fn slack_emoji_falls_back_to_rule_type() {
        let mut p = fixture();
        p.rule_type = "AdminFunctionCalled".into();
        assert_eq!(slack_emoji(&p), ":rotating_light:");

        let p = fixture();
        assert_eq!(slack_emoji(&p), ":warning:");
    }
}
