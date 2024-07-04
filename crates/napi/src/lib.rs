//! Node-API surface for `@wae/open-cleaner` via the WAE facade.

#[cfg(windows)]
use std::{cell::RefCell, path::PathBuf};

use open_cleaner_core::{RegistryOptions, ScanOptions, capabilities, registry_scan, scan};
use wae::{CallContext, Env, Error, JsValue, Result, function, optional_string_prop, register_module, sys};

#[cfg(windows)]
use wae::webview::{IpcHandler, IpcOutcome, OpenOptions, WebViewHost};

#[cfg(windows)]
thread_local! {
    static GUI: RefCell<Option<GuiState>> = const { RefCell::new(None) };
}

#[cfg(windows)]
struct GuiState {
    host: WebViewHost,
}

#[cfg(windows)]
struct ScanIpcHandler;

#[cfg(windows)]
impl IpcHandler for ScanIpcHandler {
    fn on_ipc(&mut self, message: &str) -> IpcOutcome {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(message)
        else {
            return IpcOutcome::Ignored;
        };
        let ty = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match ty {
            "close" => IpcOutcome::CloseWindow,
            "scan" => {
                let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
                let root = value.get("root").and_then(|v| v.as_str()).map(|s| s.to_string());
                match scan(ScanOptions { root, limit: Some(100) }) {
                    Ok(report) => {
                        let reply = serde_json::json!({
                            "type": "scanResult",
                            "id": id,
                            "report": report,
                        });
                        IpcOutcome::ReplyToPage(reply.to_string())
                    }
                    Err(err) => {
                        let reply = serde_json::json!({
                            "type": "scanError",
                            "id": id,
                            "message": err.to_string(),
                        });
                        IpcOutcome::ReplyToPage(reply.to_string())
                    }
                }
            }
            _ => IpcOutcome::Ignored,
        }
    }
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
    let report = scan(options).map_err(|e| Error::new(e.to_string()))?;
    report_to_js(ctx.env(), &report)
}

#[function]
fn version(ctx: CallContext) -> Result<JsValue> {
    ctx.env().string(env!("CARGO_PKG_VERSION"))
}

#[function(js_name = "capabilities")]
fn capabilities_js(ctx: CallContext) -> Result<JsValue> {
    let caps = capabilities();
    let env = ctx.env();
    let obj = env.object()?;
    obj.set_named("platform", env.string(&caps.platform)?)?;
    obj.set_named("arch", env.string(&caps.arch)?)?;
    obj.set_named("fileScan", env.boolean(caps.file_scan)?)?;
    obj.set_named("registryScan", env.boolean(caps.registry_scan)?)?;
    obj.set_named("registryClean", env.boolean(caps.registry_clean)?)?;
    obj.set_named("gui", env.boolean(caps.gui)?)?;

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
    let report = registry_scan(options).map_err(|e| Error::new(e.to_string()))?;
    registry_report_to_js(ctx.env(), &report)
}

#[function(js_name = "openGui")]
fn open_gui(ctx: CallContext) -> Result<JsValue> {
    #[cfg(not(windows))]
    {
        let _ = ctx;
        Err(Error::new("openGui is only supported on Windows"))
    }
    #[cfg(windows)]
    {
        open_gui_impl(ctx)
    }
}

#[cfg(windows)]
fn open_gui_impl(ctx: CallContext) -> Result<JsValue> {
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

    let options = if let Some(dir) = content_dir {
        OpenOptions::from_content_dir(dir, title)
    }
    else if let Some(url) = entry_url {
        OpenOptions::from_url(url, title)
    }
    else {
        let dir = resolve_gui_dir()?;
        OpenOptions::from_content_dir(dir.display().to_string(), title)
    };

    let host = WebViewHost::open(options, Box::new(ScanIpcHandler)).map_err(|e| Error::new(e.to_string()))?;

    GUI.with(|slot| {
        *slot.borrow_mut() = Some(GuiState { host });
    });
    ctx.env().undefined()
}

#[function(js_name = "pumpEvents")]
fn pump_events(ctx: CallContext) -> Result<JsValue> {
    #[cfg(not(windows))]
    {
        ctx.env().boolean(false)
    }
    #[cfg(windows)]
    {
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
        ctx.env().boolean(alive)
    }
}

#[function(js_name = "closeGui")]
fn close_gui(ctx: CallContext) -> Result<JsValue> {
    #[cfg(windows)]
    {
        GUI.with(|slot| {
            let mut guard = slot.borrow_mut();
            if let Some(mut state) = guard.take() {
                let _ = state.host.close();
            }
        });
    }
    ctx.env().undefined()
}

#[function(js_name = "isGuiOpen")]
fn is_gui_open(ctx: CallContext) -> Result<JsValue> {
    #[cfg(not(windows))]
    {
        ctx.env().boolean(false)
    }
    #[cfg(windows)]
    {
        let open = GUI.with(|slot| slot.borrow().as_ref().map(|s| s.host.is_alive()).unwrap_or(false));
        ctx.env().boolean(open)
    }
}

#[cfg(windows)]
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

    Err(Error::new("dist/gui folder not found; pass contentDir to openGui()"))
}

register_module![scan_js, version, capabilities_js, registry_scan_js, open_gui, pump_events, close_gui, is_gui_open];
