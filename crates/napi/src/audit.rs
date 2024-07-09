//! Audit trail at the N-API capability boundary.
//!
//! Every capability exported by this crate is recorded through [`run`], so the
//! CLI and the GUI cannot bypass attribution. The schema, sanitising, rotation
//! and query implementation come from the shared `wae-audit` contract
//! (`wae.audit/v0`). This module only supplies Open Cleaner's domain fields.

use std::sync::{Arc, PoisonError, RwLock};

use open_cleaner_core::{Error as CoreError, Result as CoreResult, capability_code};
use serde_json::Value;
use wae::audit::{Actor, Auditor, Entry, Mode, Outcome, Query};

/// Application name written into every record.
const APP: &str = "open-cleaner";

static AUDITOR: RwLock<Option<Arc<Auditor>>> = RwLock::new(None);

/// Target count and human-readable summary attached to a record.
#[derive(Debug, Clone)]
pub struct Summary {
    pub count: u64,
    pub summary: String,
}

impl Summary {
    pub fn new(count: u64, summary: impl Into<String>) -> Self {
        Self { count, summary: summary.into() }
    }
}

/// Process-wide auditor; built from environment defaults on first use.
fn auditor() -> Arc<Auditor> {
    if let Some(existing) = AUDITOR.read().unwrap_or_else(PoisonError::into_inner).as_ref() {
        return Arc::clone(existing);
    }
    let built = Arc::new(Auditor::from_env(APP, env!("CARGO_PKG_VERSION")));
    let mut guard = AUDITOR.write().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(guard.get_or_insert(built))
}

/// Replace the process-wide auditor after an explicit actor/session override.
pub fn configure(actor: Actor, session: Option<String>, host: Option<String>) {
    let mut builder = Auditor::builder(APP, env!("CARGO_PKG_VERSION")).actor(actor);
    if let Some(session) = session {
        builder = builder.session(session);
    }
    if let Some(host) = host {
        builder = builder.host(host);
    }
    let configured = Arc::new(builder.build());
    audit_configured(&configured);
    *AUDITOR.write().unwrap_or_else(PoisonError::into_inner) = Some(configured);
}

fn audit_configured(auditor: &Auditor) {
    let actor = auditor.actor();
    let params = serde_json::json!({
        "actorKind": actor.kind,
        "actorId": actor.id,
        "actorSource": actor.source,
        "session": auditor.session(),
        "host": auditor.host(),
    });
    let _ = run_with(auditor, "audit-configure", Mode::DryRun, params, || Ok(((), Summary::new(0, "audit configuration updated"))));
}

/// Record one capability call and return its result unchanged.
///
/// Read-only capabilities use [`Mode::DryRun`]; capabilities that mutate host
/// state use [`Mode::Execute`]. Platform refusals are stored as `rejected`, all
/// other failures as `failure`.
pub fn run<T>(capability: &str, mode: Mode, params: Value, body: impl FnOnce() -> CoreResult<(T, Summary)>) -> CoreResult<T> {
    let auditor = auditor();
    run_with(&auditor, capability, mode, params, body)
}

/// [`run`] against an explicit auditor, used by tests.
pub fn run_with<T>(
    auditor: &Auditor,
    capability: &str,
    mode: Mode,
    params: Value,
    body: impl FnOnce() -> CoreResult<(T, Summary)>,
) -> CoreResult<T> {
    let call = auditor.call(capability, mode).params(params);
    match body() {
        Ok((value, summary)) => {
            let _ = call.targets(summary.count, summary.summary).succeed();
            Ok(value)
        }
        Err(error) => {
            let code = error_code(&error);
            match error_outcome(&error) {
                Outcome::Rejected => {
                    let _ = call.reject(code);
                }
                _ => {
                    let _ = call.fail(code);
                }
            }
            Err(error)
        }
    }
}

/// Query the shared history.
pub fn query(filter: &Query) -> Result<Vec<Entry>, wae::audit::AuditError> {
    auditor().query(filter)
}

/// Stable error code recorded for a failed capability call.
fn error_code(error: &CoreError) -> String {
    if let Some(code) = capability_code(error) {
        return code.to_string();
    }
    match error {
        CoreError::Io { .. } => "io-error".to_string(),
        CoreError::Message(_) => "message".to_string(),
        CoreError::Capability { .. } => "capability".to_string(),
    }
}

fn error_outcome(error: &CoreError) -> Outcome {
    match error {
        CoreError::Capability { .. } => Outcome::Rejected,
        _ => Outcome::Failure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use open_cleaner_core::CapabilityState;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use wae::audit::ActorKind;

    fn test_auditor() -> (Auditor, PathBuf) {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("open-cleaner-audit-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
        let actor = Actor { kind: ActorKind::Agent, id: "agent-1".into(), source: "test".into() };
        let auditor = Auditor::builder(APP, "0.0.0").actor(actor).session("session-1").host("host-1").dir(&dir).build();
        (auditor, dir)
    }

    #[test]
    fn success_is_recorded_with_targets() {
        let (auditor, dir) = test_auditor();
        run_with(&auditor, "scan", Mode::DryRun, serde_json::json!({ "root": "C:/tmp" }), || Ok((42, Summary::new(3, "three entries"))))
            .unwrap();
        let entries = auditor.query(&Query::default()).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.capability, "scan");
        assert_eq!(entry.mode, Mode::DryRun);
        assert_eq!(entry.outcome, Outcome::Success);
        assert_eq!(entry.targets.count, 3);
        assert_eq!(entry.actor.id, "agent-1");
        assert!(entry.error_code.is_none());
        let text = std::fs::read_to_string(dir.join("open-cleaner.jsonl")).unwrap();
        assert!(text.contains("\"schema\":\"wae.audit/v0\""));
    }

    #[test]
    fn failures_and_rejections_use_distinct_codes() {
        let (auditor, _) = test_auditor();
        let failure: CoreResult<()> = run_with(&auditor, "scan", Mode::DryRun, Value::Null, || Err(CoreError::Message("boom".into())));
        assert!(failure.is_err());

        let rejected: CoreResult<()> = run_with(&auditor, "registry-scan", Mode::DryRun, Value::Null, || {
            Err(CoreError::Capability {
                capability: "registry-scan",
                state: CapabilityState::UnsupportedPlatform,
                detail: "not available".into(),
            })
        });
        assert!(rejected.is_err());

        let entries = auditor.query(&Query::default()).unwrap();
        assert_eq!(entries.len(), 2);
        let scan = entries.iter().find(|e| e.capability == "scan").unwrap();
        assert_eq!(scan.outcome, Outcome::Failure);
        assert_eq!(scan.error_code.as_deref(), Some("message"));
        let registry = entries.iter().find(|e| e.capability == "registry-scan").unwrap();
        assert_eq!(registry.outcome, Outcome::Rejected);
        assert_eq!(registry.error_code.as_deref(), Some("unsupported_platform"));
    }

    #[test]
    fn execution_mode_is_recorded_for_mutating_capabilities() {
        let (auditor, _) = test_auditor();
        run_with(&auditor, "gui-open", Mode::Execute, Value::Null, || Ok(((), Summary::new(1, "window opened")))).unwrap();
        let entries = auditor.query(&Query::default()).unwrap();
        assert_eq!(entries[0].mode, Mode::Execute);
    }

    #[test]
    fn abandoned_calls_are_not_silently_lost() {
        let (auditor, _) = test_auditor();
        drop(auditor.call("scan", Mode::DryRun));
        let entries = auditor.query(&Query::default()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, Outcome::Failure);
        assert_eq!(entries[0].error_code.as_deref(), Some("wae.audit::abandoned"));
    }

    #[test]
    fn credentials_in_params_are_redacted_before_write() {
        let (auditor, dir) = test_auditor();
        run_with(&auditor, "scan", Mode::DryRun, serde_json::json!({ "token": "SECRET", "root": "C:/tmp" }), || {
            Ok(((), Summary::new(0, "none")))
        })
        .unwrap();
        let text = std::fs::read_to_string(dir.join("open-cleaner.jsonl")).unwrap();
        assert!(!text.contains("SECRET"));
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn query_filters_by_actor_and_capability() {
        let (auditor, _) = test_auditor();
        run_with(&auditor, "scan", Mode::DryRun, Value::Null, || Ok(((), Summary::new(0, "none")))).unwrap();
        run_with(&auditor, "registry-scan", Mode::DryRun, Value::Null, || Ok(((), Summary::new(0, "none")))).unwrap();

        let by_capability = Query { capability: Some("scan".into()), ..Query::default() };
        assert_eq!(auditor.query(&by_capability).unwrap().len(), 1);
        let by_actor = Query { actor_id: Some("agent-1".into()), ..Query::default() };
        assert_eq!(auditor.query(&by_actor).unwrap().len(), 2);
        let unknown_actor = Query { actor_id: Some("someone-else".into()), ..Query::default() };
        assert!(auditor.query(&unknown_actor).unwrap().is_empty());
    }
}
