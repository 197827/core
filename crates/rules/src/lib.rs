#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

//! txwatch-rules evaluates `AlertRule` conditions against enriched Stellar transactions
//! and constructs structured `AlertPayload` webhook bodies.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use txwatch_config::{AlertRule, FunctionMatchMode, RuleConfig, EVENT_TOPIC_WILDCARD};

pub mod yield_calculator;
pub use yield_calculator::{PoolYield, YieldCalculator};

// ── Constants ──────────────────────────────────────────────────────────────────

/// Maximum XLM supply in stroops: 50 billion XLM × 10^7 stroops/XLM
/// = 5 × 10^17 (500 quadrillion) stroops, well below u64::MAX (~1.8 × 10^19).
/// Parsed amounts and fees above this value cannot exist on the network, so
/// [`EnrichedTransaction::from_horizon`] discards them as malformed.
pub const MAX_XLM_SUPPLY_STROOPS: u64 = 500_000_000_000_000_000;

/// Returns `value` if it is a possible on-chain stroop amount, logging and
/// discarding anything above [`MAX_XLM_SUPPLY_STROOPS`].
fn sanitize_stroops(value: Option<u64>, field: &str, tx_hash: &str) -> Option<u64> {
    match value {
        Some(v) if v > MAX_XLM_SUPPLY_STROOPS => {
            tracing::warn!(
                tx = %tx_hash,
                field,
                value = v,
                max = MAX_XLM_SUPPLY_STROOPS,
                "parsed amount exceeds the total XLM supply — ignoring it"
            );
            None
        }
        other => other,
    }
}

// ── Horizon transaction shape ─────────────────────────────────────────────────

/// Raw Horizon transaction record as returned by the REST API.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HorizonTransaction {
    /// Transaction hash.
    pub hash: String,
    /// Ledger close time as an RFC 3339 string.
    pub created_at: String, // RFC 3339
    /// Whether the transaction succeeded.
    pub successful: bool,
    /// Horizon paging token for this record.
    pub paging_token: String,
    /// Fee charged in stroops (Horizon returns this as a string).
    pub fee_charged: Option<String>,
    /// The Stellar account that submitted (signed) the transaction.
    /// For fee-bump transactions, this is the fee-bump source account.
    pub source_account: Option<String>,
    /// For fee-bump transactions, the inner source account.
    pub fee_account: Option<String>,
    /// Base64-encoded XDR transaction envelope.
    pub envelope_xdr: Option<String>,
    /// Base64-encoded XDR transaction result.
    pub result_xdr: Option<String>,
    // ── Issue #56: additional Horizon fields ──────────────────────────────────
    /// Ledger sequence number in which this transaction was included.
    pub ledger: Option<u32>,
    /// Memo content as a string (may be absent for `MemoNone`).
    pub memo: Option<String>,
    /// Memo type: `"none"`, `"text"`, `"id"`, `"hash"`, `"return"`.
    pub memo_type: Option<String>,
    /// Total number of operations in the transaction.
    pub operation_count: Option<u32>,
}

// ── Contract events ───────────────────────────────────────────────────────────

/// A Soroban contract event emitted by a transaction, as returned by Soroban
/// RPC `getEvents` with `xdrFormat: "json"`. Topics and data are `ScVal`s in
/// their JSON form, e.g. `{"symbol": "transfer"}` or `{"address": "G…"}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractEvent {
    /// Contract that emitted the event.
    pub contract_id: String,
    /// Event topics as JSON-encoded `ScVal`s; topic 0 is conventionally the
    /// event name symbol.
    pub topics: Vec<Value>,
    /// Event body as a JSON-encoded `ScVal`.
    pub data: Value,
}

impl ContractEvent {
    /// The first topic as a symbol, if it is one.
    fn first_symbol(&self) -> Option<&str> {
        self.topics.first()?.get("symbol")?.as_str()
    }

    /// Does this event match an `EventEmitted { topic, topics }` rule?
    /// `topic` must equal topic 0 as a symbol exactly; each entry of `topics`
    /// is compared positionally against topics 1.. (`"*"` matches anything).
    pub fn matches(&self, topic: &str, topics: &[String]) -> bool {
        if self.first_symbol() != Some(topic) {
            return false;
        }
        topics.iter().enumerate().all(|(i, pattern)| {
            pattern == EVENT_TOPIC_WILDCARD
                || self
                    .topics
                    .get(i + 1)
                    .is_some_and(|value| topic_value_matches(value, pattern))
        })
    }
}

/// Compare a topic's compact JSON rendering against `pattern`. A topic is
/// compared once per event, so the allocation is not worth avoiding.
#[allow(clippy::cmp_owned)]
fn cmp_rendered(value: &Value, pattern: &str) -> bool {
    value.to_string() == pattern
}

// Compare one `ScVal` topic against a config pattern. Single-key scalar
/// values (`{"symbol": "x"}`, `{"address": "G…"}`, `{"u32": 5}`, `{"i128": "-1"}`)
/// match the inner value's text; anything else matches its compact JSON.
fn topic_value_matches(value: &Value, pattern: &str) -> bool {
    let scalar = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    };
    let inner = match value {
        Value::Object(map) if map.len() == 1 => map.values().next().and_then(scalar),
        other => scalar(other),
    };
    match inner {
        Some(text) => text == pattern,
        // A non-scalar topic matches its own compact JSON rendering.
        None => cmp_rendered(value, pattern),
    }
}

// ── Enriched transaction ──────────────────────────────────────────────────────

/// A transaction enriched with Soroban-specific fields extracted from the
/// Horizon `operations` sub-resource JSON (returned inline via `join=operations`
/// or fetched separately). We keep this as a plain struct so rule evaluation
/// stays pure and testable without network calls.
#[derive(Debug, Clone)]
pub struct EnrichedTransaction {
    /// Transaction hash.
    pub hash: String,
    /// Ledger close time of the transaction.
    pub timestamp: DateTime<Utc>,
    /// Whether the transaction succeeded.
    pub successful: bool,
    /// Horizon paging token for this record.
    pub paging_token: String,
    /// All Soroban contract functions invoked in this transaction (may be multiple).
    pub function_names: Vec<String>,
    /// Transfer amount in stroops (1 XLM = 10_000_000 stroops), if detected.
    /// Uses u64 because the total XLM supply is ~50 billion XLM = 5 × 10^17
    /// (500 quadrillion) stroops ([`MAX_XLM_SUPPLY_STROOPS`]), well within
    /// u64::MAX (~1.8 × 10^19).
    pub amount_stroops: Option<u64>,
    /// Fee charged for this transaction in stroops.
    pub fee_charged_stroops: Option<u64>,
    /// The Stellar account that submitted the transaction (G-address).
    pub source_account: Option<String>,
    /// For fee-bump transactions, the inner source account.
    pub fee_account: Option<String>,
    // ── Issue #56: additional metadata fields ─────────────────────────────────
    /// Ledger sequence number in which this transaction was included.
    pub ledger: Option<u32>,
    /// Memo content (absent for `MemoNone`).
    pub memo: Option<String>,
    /// Memo type: `"none"`, `"text"`, `"id"`, `"hash"`, `"return"`.
    pub memo_type: Option<String>,
    /// Total number of operations in the transaction.
    pub operation_count: Option<u32>,
    /// Contract events emitted by this transaction. Only populated when the
    /// contract has an `EventEmitted` rule (fetched from Soroban RPC).
    pub events: Vec<ContractEvent>,
}

impl EnrichedTransaction {
    /// Build from a raw Horizon record plus optional Soroban operation details.
    pub fn from_horizon(
        tx: HorizonTransaction,
        function_names: Vec<String>,
        amount_stroops: Option<u64>,
        fee_charged_stroops: Option<u64>,
    ) -> Result<Self> {
        let timestamp = tx.created_at.parse::<DateTime<Utc>>().with_context(|| {
            format!(
                "cannot parse timestamp '{}' for tx {}",
                tx.created_at, tx.hash
            )
        })?;

        let fee_charged_stroops = fee_charged_stroops.or_else(|| {
            tx.fee_charged
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
        });

        Ok(Self {
            amount_stroops: sanitize_stroops(amount_stroops, "amount_stroops", &tx.hash),
            fee_charged_stroops: sanitize_stroops(
                fee_charged_stroops,
                "fee_charged_stroops",
                &tx.hash,
            ),
            hash: tx.hash,
            timestamp,
            successful: tx.successful,
            paging_token: tx.paging_token,
            function_names,
            // The sanitized values set above are authoritative; the raw ones
            // are deliberately not repeated here.
            source_account: tx.source_account,
            fee_account: tx.fee_account,
            ledger: tx.ledger,
            memo: tx.memo,
            memo_type: tx.memo_type,
            operation_count: tx.operation_count,
            events: Vec::new(),
        })
    }

    /// Attach the contract events emitted by this transaction.
    pub fn with_events(mut self, events: Vec<ContractEvent>) -> Self {
        self.events = events;
        self
    }
}

// ── AlertPayload ──────────────────────────────────────────────────────────────

/// The JSON body POSTed to the webhook URL when a rule fires.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertPayload {
    /// Schema version for this payload shape (issue #58).
    /// Receivers should use this to detect breaking changes.
    /// Additive changes (new optional fields) keep the same version;
    /// breaking changes (field removals or renames) bump it.
    pub schema_version: u32,
    /// Stable, deterministic alert identifier derived from
    /// (network, contract_id, tx hash, rule_type, rule params) via SHA-256
    /// (issue #57). Receivers should deduplicate on this value.
    /// Used as the PagerDuty `dedup_key`.
    #[serde(default)]
    pub alert_id: String,
    /// Human-readable label of the watched contract.
    pub label: String,
    /// Contract ID the alert is about.
    pub contract_id: String,
    /// Network the contract lives on (`"mainnet"`, `"testnet"`, …).
    pub network: String,
    /// Stable machine-readable rule variant (e.g. `"LargeTransfer"`).
    pub rule_type: String,
    /// Human-readable description of the rule that fired.
    pub rule_triggered: String,
    /// Transaction hash, or `null` for synthetic alerts (e.g. `NoActivity`).
    pub transaction_hash: String,
    /// First invoked function name (backward-compat singular field).
    pub function_name: Option<String>,
    /// All invoked function names in this transaction.
    pub function_names: Vec<String>,
    /// Amount in whole XLM (truncated, stroops / 10_000_000), present for
    /// LargeTransfer. Kept for backward compatibility — use `amount_xlm_decimal`
    /// for precise accounting (e.g. 9,999.99 XLM appears here as `9999`).
    #[serde(rename = "amount_xlm")]
    pub amount_xlm: Option<u64>,
    /// Transfer amount in stroops (1 XLM = 10_000_000 stroops).
    pub amount_stroops: Option<u64>,
    /// Transfer amount as a decimal string with 7 fractional digits
    /// (e.g. `"9999.9900000"`), or `null` when no amount is present.
    pub amount_xlm_decimal: Option<String>,
    /// Fee charged in stroops.
    pub fee_charged_stroops: Option<u64>,
    /// The Stellar account that submitted the transaction (G-address).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_account: Option<String>,
    /// Optional severity level from the rule definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Unix timestamp (seconds).
    pub timestamp: i64,
    /// ISO 8601 timestamp string.
    pub timestamp_iso: String,
    /// Horizon link to the transaction (or account for synthetic alerts).
    pub horizon_link: String,
    /// Stellar Expert explorer link for the transaction.
    pub explorer_link: String,
    /// Effective webhook URL for this alert (may be rule-level override).
    #[serde(skip)]
    pub effective_webhook_url: Option<String>,
    /// Effective webhook secret for this alert (may be rule-level override).
    #[serde(skip)]
    pub effective_webhook_secret: Option<String>,
    // ── Issue #56: additional metadata fields ─────────────────────────────────
    /// Ledger sequence number in which this transaction was included.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,
    /// Memo content (absent for `MemoNone`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// Memo type: `"none"`, `"text"`, `"id"`, `"hash"`, `"return"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo_type: Option<String>,
    /// Total number of operations in the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_count: Option<u32>,
    /// `true` for a recovery alert (e.g. activity resumed after `NoActivity`).
    /// `false` (the default) for an incident alert.
    #[serde(default)]
    pub resolved: bool,
    /// Contract events that matched an `EventEmitted` rule (topics and data);
    /// empty for every other rule type.
    #[serde(default)]
    pub matched_events: Vec<ContractEvent>,
    /// Number of matches of this rule that were suppressed by its
    /// `cooldown_seconds` since the previous alert was sent. 0 when the rule
    /// has no cooldown or nothing was suppressed.
    #[serde(default)]
    pub suppressed_count: u64,
    /// `true` only for synthetic payloads sent by `txwatch test-webhook`;
    /// omitted from the JSON otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub test: bool,
}

/// Deterministic alert ID: the first 32 hex characters (128 bits) of
/// SHA-256 over `contract_id`, `transaction_hash` and `rule_triggered`.
pub fn alert_id(contract_id: &str, transaction_hash: &str, rule_triggered: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in [contract_id, transaction_hash, rule_triggered] {
        hasher.update(part.as_bytes());
        // Separator so ("ab", "c") and ("a", "bc") differ.
        hasher.update([0u8]);
    }
    let mut id = hex::encode(hasher.finalize());
    id.truncate(32);
    id
}

// ── Rule evaluation ───────────────────────────────────────────────────────────

/// Context passed to [`evaluate`] to identify the contract being evaluated
/// and provide the link base URLs needed to build webhook payloads.
///
/// Using a struct instead of five positional `&str` parameters prevents
/// argument-order bugs (e.g. swapping `horizon_base` and `explorer_base`).
///
/// # Example
/// ```
/// use txwatch_rules::EvalContext;
/// use txwatch_config::{AlertRule, Network, RuleConfig, WatchedContract};
///
/// let contract = WatchedContract {
///     label: "My Oracle".into(),
///     contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".into(),
///     network: Network::Testnet,
///     rules: vec![RuleConfig {
///         rule: AlertRule::AnyTransaction,
///         cooldown_seconds: None,
///     }],
///     webhook_url: Some("https://hooks.example.com/hook".into()),
///     webhook_secret: None,
///     webhook_format: Default::default(),
///     webhook_headers: Default::default(),
///     webhook_routing_key: None,
///     webhooks: Vec::new(),
///     poll_interval_seconds: None,
///     enabled: true,
///     soroban_rpc_url: None,
///     batch_alerts: false,
///     horizon_base_url_override: None,
/// };
/// let ctx = EvalContext::from_contract(&contract);
/// assert_eq!(ctx.network, "testnet");
/// ```
#[derive(Debug, Clone)]
pub struct EvalContext<'a> {
    /// Human-readable label of the watched contract.
    pub label: &'a str,
    /// Contract ID being evaluated.
    pub contract_id: &'a str,
    /// Network the contract lives on (`"mainnet"`, `"testnet"`, …).
    pub network: &'a str,
    /// Horizon base URL used to build transaction links.
    pub horizon_base: &'a str,
    /// Explorer base URL for the network; `None` for custom networks that
    /// have no configured explorer (links will fall back to `horizon_link`).
    pub explorer_base: Option<&'a str>,
}

impl<'a> EvalContext<'a> {
    /// Convenience constructor: derive all fields from a [`WatchedContract`].
    /// Callers that need to override the Horizon base URL (e.g. tests using a
    /// mock server) should fill in the fields manually instead.
    pub fn from_contract(contract: &'a txwatch_config::WatchedContract) -> Self {
        let horizon_base = contract
            .horizon_base_url_override
            .as_deref()
            .unwrap_or_else(|| contract.network.horizon_base_url());
        Self {
            label: &contract.label,
            contract_id: &contract.contract_id,
            network: contract.network.as_str(),
            horizon_base,
            explorer_base: contract.network.explorer_base_url(),
        }
    }
}

/// Shared, thread-safe counter map used to rate-limit repeated evaluation
/// warnings. Keyed by `"<contract_id>:<rule_label>"`.
#[derive(Debug, Default, Clone)]
pub struct WarningSuppressor(Arc<Mutex<HashMap<String, u64>>>);

impl WarningSuppressor {
    /// Returns `true` if the warning for this key should be emitted (i.e. the
    /// first occurrence or every 100th recurrence).
    pub fn should_warn(&self, key: &str) -> bool {
        if let Ok(mut map) = self.0.lock() {
            let count = map.entry(key.to_owned()).or_insert(0);
            *count += 1;
            *count == 1 || *count % 100 == 0
        } else {
            true // lock poisoned — always warn rather than silently drop
        }
    }

    /// Returns how many times a warning has been suppressed for the given key.
    #[cfg(test)]
    pub fn suppressed_count(&self, key: &str) -> u64 {
        self.0
            .lock()
            .ok()
            .and_then(|m| m.get(key).copied())
            .unwrap_or(0)
    }
}

/// Evaluate all per-transaction rules for one contract against one transaction.
/// Returns one `AlertPayload` per matching rule.
/// Never panics — errors in individual rule evaluation are logged and skipped.
/// Repeated errors for the same rule are suppressed after the first occurrence
/// (see [`WarningSuppressor`]).
///
/// Pass `suppressor` as `None` to use a one-shot suppressor (appropriate for
/// replay and tests). The poller keeps a per-contract suppressor to
/// deduplicate repeated warnings across poll cycles.
pub fn evaluate<R: AsRef<AlertRule> + RuleOverrides>(
    ctx: &EvalContext<'_>,
    rules: &[R],
    tx: &EnrichedTransaction,
    suppressor: Option<&WarningSuppressor>,
) -> Vec<AlertPayload> {
    let label = ctx.label;
    let contract_id = ctx.contract_id;
    let network = ctx.network;
    // #45: Trim trailing slashes so callers that pass "https://host/" do not
    // produce double slashes in the generated links.
    let horizon_base = ctx.horizon_base.trim_end_matches('/');
    let horizon_link = format!("{}/transactions/{}", horizon_base, tx.hash);
    let explorer_link = match ctx.explorer_base {
        Some(base) => format!("{}/tx/{}", base.trim_end_matches('/'), tx.hash),
        None => horizon_link.clone(),
    };
    let timestamp = tx.timestamp.timestamp();
    let timestamp_iso = tx.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let _local_suppressor;
    let suppressor = match suppressor {
        Some(s) => s,
        None => {
            _local_suppressor = WarningSuppressor::default();
            &_local_suppressor
        }
    };

    // #46: Compute both forms of the amount once per transaction.
    let amount_xlm = tx.amount_stroops.map(|s| s / 10_000_000);
    let amount_xlm_decimal = tx.amount_stroops.map(|s| {
        let whole = s / 10_000_000;
        let frac = s % 10_000_000;
        format!("{}.{:07}", whole, frac)
    });

    rules
        .iter()
        .filter(|entry| entry.enabled())
        .filter_map(|entry| {
            let rule: &AlertRule = entry.as_ref();
            match eval_rule(rule, tx) {
                Ok(true) => Some(AlertPayload {
                    schema_version: 1,
                    alert_id: alert_id(contract_id, &tx.hash, &rule.label()),
                    label: label.to_string(),
                    contract_id: contract_id.to_string(),
                    network: network.to_string(),
                    // #44: Use the single canonical implementations from txwatch-config.
                    rule_type: rule.rule_type().to_string(),
                    rule_triggered: rule.label(),
                    transaction_hash: tx.hash.clone(),
                    function_name: tx.function_names.first().cloned(),
                    function_names: tx.function_names.clone(),
                    amount_xlm,
                    amount_stroops: tx.amount_stroops,
                    amount_xlm_decimal: amount_xlm_decimal.clone(),
                    fee_charged_stroops: tx.fee_charged_stroops,
                    source_account: tx.source_account.clone(),
                    // Per-rule delivery overrides, absent unless the rule sets them.
                    severity: entry.severity().map(|s| s.to_string()),
                    effective_webhook_url: entry.webhook_url().map(str::to_owned),
                    effective_webhook_secret: entry.webhook_secret().map(str::to_owned),
                    timestamp,
                    timestamp_iso: timestamp_iso.clone(),
                    horizon_link: horizon_link.clone(),
                    explorer_link: explorer_link.clone(),
                    ledger: tx.ledger,
                    memo: tx.memo.clone(),
                    memo_type: tx.memo_type.clone(),
                    operation_count: tx.operation_count,
                    resolved: false,
                    matched_events: matched_events(rule, tx),
                    suppressed_count: 0,
                    test: false,
                }),
                Ok(false) => None,
                Err(e) => {
                    // A broken rule would otherwise warn on every poll cycle.
                    let key = format!("{}:{}", ctx.contract_id, rule.label());
                    if suppressor.should_warn(&key) {
                        tracing::warn!(
                            tx = %tx.hash,
                            rule = %rule.label(),
                            error = %e,
                            "rule evaluation error — skipping"
                        );
                    }
                    None
                }
            }
        })
        .collect()
}

/// Per-rule delivery settings that ride alongside the rule itself. A bare
/// [`AlertRule`] and a `RuleConfig` have none; a `RuleEntry` (used for the
/// nested rules of a composite) carries the enable flag, the webhook overrides
/// and the severity.
pub trait RuleOverrides {
    /// `false` skips the rule entirely.
    fn enabled(&self) -> bool {
        true
    }
    /// Webhook URL this rule overrides the contract's with.
    fn webhook_url(&self) -> Option<&str> {
        None
    }
    /// Webhook secret this rule overrides the contract's with.
    fn webhook_secret(&self) -> Option<&str> {
        None
    }
    /// Severity carried on the alert payload.
    fn severity(&self) -> Option<&txwatch_config::Severity> {
        None
    }
}

impl<T: RuleOverrides + ?Sized> RuleOverrides for &T {
    fn enabled(&self) -> bool {
        (**self).enabled()
    }
    fn webhook_url(&self) -> Option<&str> {
        (**self).webhook_url()
    }
    fn webhook_secret(&self) -> Option<&str> {
        (**self).webhook_secret()
    }
    fn severity(&self) -> Option<&txwatch_config::Severity> {
        (**self).severity()
    }
}

impl RuleOverrides for AlertRule {}
impl RuleOverrides for txwatch_config::RuleConfig {}

impl RuleOverrides for txwatch_config::RuleEntry {
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn webhook_url(&self) -> Option<&str> {
        self.webhook_url.as_deref()
    }
    fn webhook_secret(&self) -> Option<&str> {
        self.webhook_secret.as_deref()
    }
    fn severity(&self) -> Option<&txwatch_config::Severity> {
        self.severity.as_ref()
    }
}

// NOTE: When adding a new AlertRule variant, update both `eval_rule()` in this
// file and `AlertRule::label()` / `AlertRule::rule_type()` in txwatch-config together.
// Rust's exhaustive matching catches missing arms in eval_rule automatically.
fn eval_rule(rule: &AlertRule, tx: &EnrichedTransaction) -> Result<bool> {
    Ok(match rule {
        AlertRule::AnyTransaction => true,

        AlertRule::TransactionFailed => !tx.successful,

        // #43: threshold_stroops is pre-computed once during validation; no
        // per-evaluation multiplication or overflow path needed.
        AlertRule::LargeTransfer {
            threshold_stroops, ..
        } => tx
            .amount_stroops
            .map(|s| s >= *threshold_stroops)
            .unwrap_or(false),

        AlertRule::FunctionCalled {
            function_name,
            match_mode,
        } => tx.function_names.iter().any(|f| match match_mode {
            FunctionMatchMode::Exact => f == function_name.as_str(),
            FunctionMatchMode::Prefix => f.starts_with(function_name.as_str()),
            FunctionMatchMode::Glob => glob_match(function_name, f),
        }),

        AlertRule::AdminFunctionCalled { function_names } => tx.function_names.iter().any(|f| {
            let f_lower = f.to_lowercase();
            function_names.iter().any(|n| n.to_lowercase() == f_lower)
        }),

        AlertRule::HighFee {
            threshold_stroops, ..
        } => tx
            .fee_charged_stroops
            .map(|f| f >= *threshold_stroops)
            .unwrap_or(false),

        AlertRule::SourceAccount { allow, deny } => {
            match tx.source_account.as_deref() {
                None => false,
                Some(src) => {
                    let in_allow = allow.iter().any(|a| a == src);
                    let in_deny = deny.iter().any(|d| d == src);
                    if !allow.is_empty() {
                        // `allow` gates the rule; an address on the `deny`
                        // fire-list still fires, so it can carve out exceptions.
                        in_allow || in_deny
                    } else if !deny.is_empty() {
                        // With no gate, `deny` alone decides.
                        in_deny
                    } else {
                        true
                    }
                }
            }
        }

        AlertRule::All { rules } => {
            for entry in rules {
                if !entry.enabled {
                    continue;
                }
                if !eval_rule(&entry.rule, tx)? {
                    return Ok(false);
                }
            }
            true
        }

        AlertRule::Any { rules } => {
            for entry in rules {
                if !entry.enabled {
                    continue;
                }
                if eval_rule(&entry.rule, tx)? {
                    return Ok(true);
                }
            }
            false
        }

        AlertRule::Not { rule: inner } => !eval_rule(&inner.rule, tx)?,
        // NoActivity is a poll-cycle-level rule evaluated by `check_no_activity`,
        // not a per-transaction rule.  It never fires here.
        AlertRule::NoActivity { .. } => false,
        AlertRule::EventEmitted { topic, topics } => {
            tx.events.iter().any(|e| e.matches(topic, topics))
        }
    })
}

/// The events an `EventEmitted` rule matched; empty for other rules.
fn matched_events(rule: &AlertRule, tx: &EnrichedTransaction) -> Vec<ContractEvent> {
    match rule {
        AlertRule::EventEmitted { topic, topics } => tx
            .events
            .iter()
            .filter(|e| e.matches(topic, topics))
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

// NOTE: When adding a new AlertRule variant, update both `eval_rule()` and
// `rule_label()` together. Rust's exhaustive matching catches missing arms,
// but this convention should be preserved for new rule variants.
fn rule_label(rule: &AlertRule) -> String {
    match rule {
        AlertRule::AnyTransaction => "AnyTransaction".into(),
        AlertRule::TransactionFailed => "TransactionFailed".into(),
        AlertRule::LargeTransfer { threshold_xlm, .. } => {
            format!("LargeTransfer(>={}XLM)", threshold_xlm)
        }
        AlertRule::FunctionCalled {
            function_name,
            match_mode,
        } => match match_mode {
            FunctionMatchMode::Exact => format!("FunctionCalled({})", function_name),
            FunctionMatchMode::Prefix => format!("FunctionCalled(prefix:{})", function_name),
            FunctionMatchMode::Glob => format!("FunctionCalled(glob:{})", function_name),
        },
        AlertRule::AdminFunctionCalled { function_names } => {
            format!("AdminFunctionCalled([{}])", function_names.join(", "))
        }
        AlertRule::HighFee {
            threshold_stroops,
            threshold_xlm,
        } => {
            if let Some(xlm) = threshold_xlm {
                format!("HighFee(>={} XLM)", xlm)
            } else {
                format!("HighFee(>={} stroops)", threshold_stroops)
            }
        }
        AlertRule::SourceAccount { allow, deny } => {
            let mut parts = Vec::new();
            if !allow.is_empty() {
                parts.push(format!("allow=[{}]", allow.join(", ")));
            }
            if !deny.is_empty() {
                parts.push(format!("deny=[{}]", deny.join(", ")));
            }
            format!("SourceAccount({})", parts.join(", "))
        }
        AlertRule::All { rules } => {
            let inner: Vec<String> = rules.iter().map(|e| rule_label(&e.rule)).collect();
            format!("All({})", inner.join(", "))
        }
        AlertRule::Any { rules } => {
            let inner: Vec<String> = rules.iter().map(|e| rule_label(&e.rule)).collect();
            format!("Any({})", inner.join(", "))
        }
        AlertRule::Not { rule: inner } => format!("Not({})", rule_label(&inner.rule)),
        AlertRule::NoActivity { minutes } => format!("NoActivity({}min)", minutes),
        AlertRule::EventEmitted { topic, topics } => {
            txwatch_config::event_emitted_label(topic, topics)
        }
    }
}

// ── NoActivity poll-cycle evaluation ─────────────────────────────────────────

/// State machine for a single `NoActivity` rule instance on one contract.
///
/// The poller keeps one `NoActivityState` per `(contract_id, rule_index)` pair
/// and calls [`check_no_activity`] once per poll cycle — even when there are no
/// new transactions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NoActivityState {
    /// The contract is active (or we haven't yet exceeded the threshold).
    #[default]
    Active,
    /// The threshold was exceeded and an alert was fired.  We're in the quiet
    /// window; we will fire a recovery alert the next time a transaction arrives.
    Alerting,
}

/// Check the `NoActivity` rule for a single contract after one poll cycle.
///
/// * `rule`              — must be `AlertRule::NoActivity { minutes }`.
/// * `last_seen`         — the timestamp of the most recent transaction seen,
///   or `None` if we have never seen any transaction.
/// * `now`               — current time (injectable for testing).
/// * `state`             — mutable state carried across poll cycles.
/// * `ctx`               — context used to build the `AlertPayload`.
///
/// Returns `Some(payload)` when the rule fires (either an incident or a
/// recovery); returns `None` when nothing changed.
///
/// Behaviour:
/// - First breach → returns an incident payload and transitions to `Alerting`.
/// - Still quiet (consecutive breaches) → returns `None` (already alerting).
/// - Activity resumes after breach → returns a recovery payload
///   (`resolved = true`) and transitions back to `Active`.
/// - Activity present and never breached → returns `None`.
pub fn check_no_activity(
    rule: &AlertRule,
    last_seen: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    state: &mut NoActivityState,
    ctx: &EvalContext<'_>,
) -> Option<AlertPayload> {
    let AlertRule::NoActivity { minutes } = rule else {
        return None;
    };

    let horizon_base = ctx.horizon_base.trim_end_matches('/');
    let explorer_base = ctx.explorer_base.map(|b| b.trim_end_matches('/'));

    let threshold = chrono::Duration::minutes(*minutes as i64);
    let quiet_since = last_seen
        .map(|t| now - t)
        .unwrap_or_else(|| chrono::Duration::MAX);
    let is_quiet = quiet_since >= threshold;

    let ts = now.timestamp();
    let ts_iso = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Synthetic payloads have no transaction — use empty hash and link to Horizon