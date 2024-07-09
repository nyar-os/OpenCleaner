//! Node-API surface for `@wae/open-cleaner` via the WAE facade.
//!
//! This crate is platform-agnostic: the GUI host, window and event pump all
//! forward to `wae::webview`, which selects a backend per compile target and
//! reports missing capabilities as structured [`wae::webview::WebViewError`]
//! values. There is no `cfg` branch here and no platform-specific message.
//!
//! Every exported capability is recorded through [`audit::run`], including the
//! GUI IPC path.

mod audit;

use std::{cell::RefCell, path::PathBuf};

use open_cleaner_core::{CapabilityState, Error as CoreError, RegistryOptions, ScanOptions, capabilities, registry_scan, scan};
use serde_json::{Value, json};
use wae::{
    CallContext, Env, Error, JsValue, Result,
    audit::{Actor, ActorKind, Mode, Query},
    function, optional_string_prop, register_module, sys,
    webview::{IpcHandler, IpcOutcome, OpenOptions, WebViewHost},
};

thread_local! {
    static GUI: RefCell<Option<GuiState>> = const { RefCell::new(None) };
}

struct GuiState {
    host: WebViewHost,
}

struct ScanIpcHandler;

impl IpcHandler for ScanIpcHandler {
    fn on_ipc(&mut self, message: &str) -> IpcOutcome {
        let Ok(value) = serde_json::from_str::<Value>(message)
        else {
            return IpcOutcome::Ignored;
        };
        let ty = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match ty {
            "close" => IpcOutcome::CloseWindow,
            "scan" => {
                let id = value.get("id").cloned().unwrap_or(Value::Null);
                let root = value.get("root").and_then(|v| v.as_str()).map(|s| s.to_string());
                match audited_scan(ScanOptions { root, limit: Some(100) }) {
                    Ok(report) => {
                        let reply = json!({
                            "type": "scanResult",
                            "id": id,
                            "report": report,
                        });
                        IpcOutcome::ReplyToPage(reply.to_string())
                    }
                    Err(err) => {
                        let reply = json!({
                            "type": "scanError",
                            "id": id,
                            "message": err.to_string(),
                        });
                        IpcOutcome::ReplyToPage(reply.to_string())
                    }
                }
            }
            "audit" => {
                let id = value.get("id").cloned().unwrap_or(Value::Null);
                let filter = query_from_value(Some(&value));
                match audit::query(&filter) {
                    Ok(entries) => {
                        let reply = json!({ "type": "auditResult", "id": id, "entries": entries });
                        IpcOutcome::ReplyToPage(reply.to_string())
                    }
                    Err(err) => {
                        let reply = json!({ "type": "auditError", "id": id, "message": err.to_string() });
                        IpcOutcome::ReplyToPage(reply.to_string())
                    }
                }
            }
            _ => IpcOutcome::Ignored,
        }
    }
}

fn core_error(error: CoreError) -> Error {
    Error::new(error.to_string())
}

fn webview_error(error: wae::webview::WebViewError) -> CoreError {
    if matches!(error, wae::webview::WebViewError::Unsupported { .. }) {
        return CoreError::Capability { capability: "gui", state: CapabilityState::UnsupportedPlatform, detail: error.to_string() };
    }
    CoreError::Message(error.to_string())
}

fn audited_scan(options: ScanOptions) -> Result<open_cleaner_core::ScanReport> {
    let params = json!({ "root": options.root, "limit": options.limit });
    let report = audit::run("scan", Mode::DryRun, params, || {
        let report = scan(options)?;
        let count = report.entries.len() as u64;
        let summary = format!("root {}, {} entries, {} bytes", report.root, report.entries.len(), report.total_bytes);
        Ok((report, audit::Summary::new(count, summary)))
    })
    .map_err(core_error)?;
    Ok(report)
}

fn scan_options_from_js(arg: Option<JsValue>) -> Result<ScanOptions> {
    let Some(obj) = arg
    else {
        return Ok(ScanOptions { root: None, limit: Some(50) });
    };
    if obj.is_undefined()? {
        return Ok(ScanOptions { root: None, limit: Some(50) });
    }
    let root = optional_string_prop(obj, "root")?;
    let limit = match obj.get_named("limit") {
        Ok(v) if !v.is_undefined()? && v.type_of()? == sys::napi_number => Some(v.as_i64()?.max(1) as usize),
        _ => Some(50),
    };
    Ok(ScanOptions { root, limit })
}

fn report_to_js(env: Env, report: &open_cleaner_core::ScanReport) -> Result<JsValue> {
    let obj = env.object()?;
    obj.set_named("root", env.string(&report.root)?)?;
    obj.set_named("totalBytes", env.int64(report.total_bytes as i64)?)?;
    obj.set_named("scannedAtUnixMs", env.int64(report.scanned_at_unix_ms as i64)?)?;

    let arr = env.array_with_length(report.entries.len())?;
    for (i, entry) in report.entries.iter().enumerate() {
        let item = env.object()?;
        item.set_named("path", env.string(&entry.path)?)?;
        item.set_named("bytes", env.int64(entry.bytes as i64)?)?;
        item.set_named("kind", env.string(&entry.kind)?)?;
        arr.set_element(i as u32, item)?;
    }
    obj.set_named("entries", arr)?;
    Ok(obj)
}

#[function(js_name = "scan")]
fn scan_js(ctx: CallContext) -> Result<JsValue> {
    let options = scan_options_from_js(ctx.args().first().copied())?;
    let report = audited_scan(options)?;
    report_to_js(ctx.env(), &report)
}

#[function]
fn version(ctx: CallContext) -> Result<JsValue> {
    let version = env!("CARGO_PKG_VERSION");
    audit::run("version", Mode::DryRun, Value::Null, || Ok(((), audit::Summary::new(0, format!("version {version}"))))).map_err(core_error)?;
    ctx.env().string(version)
}

#[function(js_name = "capabilities")]
fn capabilities_js(ctx: CallContext) -> Result<JsValue> {
    let caps = audit::run("capabilities", Mode::DryRun, Value::Null, || {
        let caps = capabilities();
        let summary = format!("platform {} {}", caps.platform, caps.arch);
        Ok((caps, audit::Summary::new(0, summary)))
    })
    .map_err(core_error)?;

    let env = ctx.env();
    let obj = env.object()?;
    obj.set_named("platform", env.string(&caps.platform)?)?;
    obj.set_named("arch", env.string(&caps.arch)?)?;
    obj.set_named("fileScan", env.boolean(caps.file_scan)?)?;
    obj.set_named("registryScan", env.boolean(caps.registry_scan)?)?;
    obj.set_named("registryClean", env.boolean(caps.registry_clean)?)?;
    // The GUI host is provided by the `wae` facade, which compiles for every
    // target this crate supports. Availability is still confirmed per call by
    // the structured `Unsupported` error returned from `openGui`.
    obj.set_named("gui", env.boolean(true)?)?;

    let notes = env.array_with_length(caps.notes.len())?;
    for (i, note) in caps.notes.iter().enumerate() {
        notes.set_element(i as u32, env.string(note)?)?;
    }
    obj.set_named("notes", notes)?;
    Ok(obj)
}

fn registry_options_from_js(arg: Option<JsValue>) -> Result<RegistryOptions> {
    let Some(obj) = arg
    else {
        return Ok(RegistryOptions { limit: Some(100) });
    };
    if obj.is_undefined()? {
        return Ok(RegistryOptions { limit: Some(100) });
    }
    let limit = match obj.get_named("limit") {
        Ok(v) if !v.is_undefined()? && v.type_of()? == sys::napi_number => Some(v.as_i64()?.max(1) as usize),
        _ => Some(100),
    };
    Ok(RegistryOptions { limit })
}

fn registry_report_to_js(env: Env, report: &open_cleaner_core::RegistryReport) -> Result<JsValue> {
    let obj = env.object()?;
    obj.set_named("platform", env.string(&report.platform)?)?;
    obj.set_named("scannedKeys", env.int64(report.scanned_keys as i64)?)?;
    obj.set_named("scannedAtUnixMs", env.int64(report.scanned_at_unix_ms as i64)?)?;

    let arr = env.array_with_length(report.entries.len())?;
    for (i, entry) in report.entries.iter().enumerate() {
        let item = env.object()?;
        item.set_named("key", env.string(&entry.key)?)?;
        if let Some(value) = &entry.display_name {
            item.set_named("displayName", env.string(value)?)?;
        }
        if let Some(value) = &entry.install_location {
            item.set_named("installLocation", env.string(value)?)?;
        }
        if let Some(value) = &entry.version {
            item.set_named("version", env.string(value)?)?;
        }
        item.set_named("reason", env.string(&entry.reason)?)?;
        arr.set_element(i as u32, item)?;
    }
    obj.set_named("entries", arr)?;
    Ok(obj)
}

#[function(js_name = "registryScan")]
fn registry_scan_js(ctx: CallContext) -> Result<JsValue> {
    let options = registry_options_from_js(ctx.args().first().copied())?;
    let limit = options.limit;
    let report = audit::run("registry-scan", Mode::DryRun, json!({ "limit": limit }), || {
        let report = registry_scan(options)?;
        let count = report.entries.len() as u64;
        let summary = format!("platform {}, {} stale entries out of {} keys", report.platform, report.entries.len(), report.scanned_keys);
        Ok((report, audit::Summary::new(count, summary)))
    })
    .map_err(core_error)?;
    registry_report_to_js(ctx.env(), &report)
}

#[function(js_name = "openGui")]
fn open_gui(ctx: CallContext) -> Result<JsValue> {
    let mut title = "Open Cleaner".to_string();
    let mut content_dir: Option<String> = None;
    let mut entry_url: Option<String> = None;

    if let Ok(arg) = ctx.arg(0)
        && !arg.is_undefined()?
    {
        if let Some(t) = optional_string_prop(arg, "title")? {
            title = t;
        }
        content_dir = optional_string_prop(arg, "contentDir")?;
        entry_url = optional_string_prop(arg, "entryUrl")?;
    }

    let params = json!({ "title": title, "contentDir": content_dir, "entryUrl": entry_url });
    let host = audit::run("gui-open", Mode::Execute, params, || {
        let options = if let Some(dir) = content_dir.clone() {
            OpenOptions::from_content_dir(dir, title.clone())
        }
        else if let Some(url) = entry_url.clone() {
            OpenOptions::from_url(url, title.clone())
        }
        else {
            let dir = resolve_gui_dir().map_err(|error| CoreError::Message(error.to_string()))?;
            OpenOptions::from_content_dir(dir.display().to_string(), title.clone())
        };
        let host = WebViewHost::open(options, Box::new(ScanIpcHandler)).map_err(webview_error)?;
        let summary = format!("window opened with {} backend", host.backend_name());
        Ok((host, audit::Summary::new(1, summary)))
    })
    .map_err(core_error)?;

    GUI.with(|slot| {
        *slot.borrow_mut() = Some(GuiState { host });
    });
    ctx.env().undefined()
}

#[function(js_name = "pumpEvents")]
fn pump_events(ctx: CallContext) -> Result<JsValue> {
    let alive = audit::run("gui-pump", Mode::Execute, Value::Null, || {
        let alive = GUI.with(|slot| {
            let mut guard = slot.borrow_mut();
            match guard.as_mut() {
                Some(state) => {
                    let ok = state.host.pump();
                    if !ok {
                        *guard = None;
                    }
                    ok
                }
                None => false,
            }
        });
        Ok((alive, audit::Summary::new(1, if alive { "window alive" } else { "window closed" })))
    })
    .map_err(core_error)?;
    ctx.env().boolean(alive)
}

#[function(js_name = "closeGui")]
fn close_gui(ctx: CallContext) -> Result<JsValue> {
    audit::run("gui-close", Mode::Execute, Value::Null, || {
        let closed = GUI.with(|slot| {
            let mut guard = slot.borrow_mut();
            if let Some(mut state) = guard.take() {
                let _ = state.host.close();
                true
            }
            else {
                false
            }
        });
        Ok(((), audit::Summary::new(1, if closed { "window closed" } else { "no window" })))
    })
    .map_err(core_error)?;
    ctx.env().undefined()
}

#[function(js_name = "isGuiOpen")]
fn is_gui_open(ctx: CallContext) -> Result<JsValue> {
    let open = audit::run("gui-status", Mode::DryRun, Value::Null, || {
        let open = GUI.with(|slot| slot.borrow().as_ref().map(|s| s.host.is_alive()).unwrap_or(false));
        Ok((open, audit::Summary::new(1, if open { "open" } else { "closed" })))
    })
    .map_err(core_error)?;
    ctx.env().boolean(open)
}

#[function(js_name = "configureAudit")]
fn configure_audit_js(ctx: CallContext) -> Result<JsValue> {
    let arg = ctx.arg(0).ok();
    let actor = actor_from_js(arg)?;
    let session = optional_string_prop_of(arg, "session")?;
    let host = optional_string_prop_of(arg, "host")?;
    audit::configure(actor, session, host);
    ctx.env().undefined()
}

#[function(js_name = "auditQuery")]
fn audit_query_js(ctx: CallContext) -> Result<JsValue> {
    let filter = query_from_js(ctx.arg(0).ok())?;
    let params = query_params(&filter);
    let entries = audit::run("audit-query", Mode::DryRun, params, || {
        let entries = audit::query(&filter).map_err(|error| CoreError::Message(error.to_string()))?;
        Ok((entries, audit::Summary::new(0, "audit history queried")))
    })
    .map_err(core_error)?;
    json_to_js(ctx.env(), &serde_json::to_value(&entries).unwrap_or(Value::Null))
}

fn query_params(filter: &Query) -> Value {
    let actor_kind = filter.actor_kind.map(|kind| if kind == ActorKind::Agent { "agent" } else { "user" });
    json!({
        "actorKind": actor_kind,
        "actorId": filter.actor_id.as_deref(),
        "fromMs": filter.from_ms,
        "toMs": filter.to_ms,
        "capability": filter.capability.as_deref(),
        "limit": filter.limit,
    })
}

fn optional_string_prop_of(arg: Option<JsValue>, name: &str) -> Result<Option<String>> {
    match arg {
        Some(value) if !value.is_undefined()? => optional_string_prop(value, name),
        _ => Ok(None),
    }
}

fn optional_number_prop_of(arg: Option<JsValue>, name: &str) -> Result<Option<u64>> {
    let Some(value) = arg
    else {
        return Ok(None);
    };
    if value.is_undefined()? {
        return Ok(None);
    }
    match value.get_named(name) {
        Ok(v) if !v.is_undefined()? && v.type_of()? == sys::napi_number => Ok(Some(v.as_i64()?.max(0) as u64)),
        _ => Ok(None),
    }
}

fn actor_from_js(arg: Option<JsValue>) -> Result<Actor> {
    let mut actor = Actor::from_env();
    let Some(value) = arg
    else {
        return Ok(actor);
    };
    if value.is_undefined()? {
        return Ok(actor);
    }
    if let Some(kind) = optional_string_prop(value, "actorKind")? {
        actor.kind = if kind.eq_ignore_ascii_case("agent") { ActorKind::Agent } else { ActorKind::User };
    }
    if let Some(id) = optional_string_prop(value, "actorId")?
        && !id.trim().is_empty()
    {
        actor.id = id;
    }
    if let Some(source) = optional_string_prop(value, "actorSource")?
        && !source.trim().is_empty()
    {
        actor.source = source;
    }
    Ok(actor)
}

fn query_from_js(arg: Option<JsValue>) -> Result<Query> {
    Ok(Query {
        actor_kind: optional_string_prop_of(arg, "actorKind")?
            .map(|kind| if kind.eq_ignore_ascii_case("agent") { ActorKind::Agent } else { ActorKind::User }),
        actor_id: optional_string_prop_of(arg, "actorId")?,
        from_ms: optional_number_prop_of(arg, "fromMs")?,
        to_ms: optional_number_prop_of(arg, "toMs")?,
        capability: optional_string_prop_of(arg, "capability")?,
        limit: optional_number_prop_of(arg, "limit")?.map(|limit| limit as usize),
    })
}

fn query_from_value(value: Option<&Value>) -> Query {
    let Some(value) = value
    else {
        return Query::default();
    };
    Query {
        actor_kind: value
            .get("actorKind")
            .and_then(Value::as_str)
            .map(|kind| if kind.eq_ignore_ascii_case("agent") { ActorKind::Agent } else { ActorKind::User }),
        actor_id: value.get("actorId").and_then(Value::as_str).map(|id| id.to_string()),
        from_ms: value.get("fromMs").and_then(Value::as_u64),
        to_ms: value.get("toMs").and_then(Value::as_u64),
        capability: value.get("capability").and_then(Value::as_str).map(|capability| capability.to_string()),
        limit: value.get("limit").and_then(Value::as_u64).map(|limit| limit as usize),
    }
}

fn json_to_js(env: Env, value: &Value) -> Result<JsValue> {
    match value {
        Value::Null => env.null(),
        Value::Bool(flag) => env.boolean(*flag),
        Value::Number(number) => match number.as_i64() {
            Some(int) => env.int64(int),
            None => env.double(number.as_f64().unwrap_or(0.0)),
        },
        Value::String(text) => env.string(text),
        Value::Array(items) => {
            let array = env.array_with_length(items.len())?;
            for (index, item) in items.iter().enumerate() {
                array.set_element(index as u32, json_to_js(env, item)?)?;
            }
            Ok(array)
        }
        Value::Object(map) => {
            let object = env.object()?;
            for (key, item) in map {
                object.set_named(key, json_to_js(env, item)?)?;
            }
            Ok(object)
        }
    }
}

fn resolve_gui_dir() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("OPEN_CLEANER_GUI") {
        let path = PathBuf::from(p);
        if path.is_dir() {
            return Ok(path);
        }
        if path.is_file()
            && let Some(parent) = path.parent()
        {
            return Ok(parent.to_path_buf());
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        let candidates = [cwd.join("packages").join("open-cleaner").join("dist").join("gui"), cwd.join("dist").join("gui"), cwd.join("gui")];
        for c in candidates {
            if c.join("index.html").is_file() {
                return Ok(c);
            }
        }
    }

    Err(Error::new("dist/gui folder not found, pass contentDir to openGui()"))
}

register_module![
    scan_js,
    version,
    capabilities_js,
    registry_scan_js,
    open_gui,
    pump_events,
    close_gui,
    is_gui_open,
    configure_audit_js,
    audit_query_js
];
