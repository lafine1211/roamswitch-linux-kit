//! Test helpers: a stand-in `roamswitch-mcp` that answers with a recorded
//! response, and a check that a typed value kept every field of that response.
//!
//! The fixtures in `tests/fixtures/` are the complete JSON-RPC response lines
//! `roamswitch-mcp` wrote for a `tools/call` (JSON payload block plus the
//! untrusted-data notice block). See `tests/fixtures/README.txt` for how they
//! were taken.

#![allow(dead_code)]

use roamswitch_linux_kit::RoamSwitchClient;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;
use tokio::sync::Mutex;

/// The stand-in reads one request line, saves it to `$RS_TEST_REQ` and prints
/// the file `$RS_TEST_FIXTURE`. The two variables are set under [`LOCK`].
const SCRIPT: &str = "#!/bin/sh\nIFS= read -r line\nprintf '%s\\n' \"$line\" > \"$RS_TEST_REQ\"\ncat \"$RS_TEST_FIXTURE\"\n";

static LOCK: Mutex<()> = Mutex::const_new(());
static SERVER: OnceLock<PathBuf> = OnceLock::new();

pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.json"))
}

/// The recorded response line of `name` as JSON.
pub fn response(name: &str) -> Value {
    let text = std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"));
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("fixture {name} is not JSON: {e}"))
}

/// The first text block of the recorded response, parsed: what the client decodes.
pub fn payload(name: &str) -> Value {
    let r = response(name);
    let text = r["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("fixture {name} has no text block"));
    serde_json::from_str(text).unwrap_or_else(|e| panic!("fixture {name} payload is not JSON: {e}"))
}

fn server_script() -> &'static PathBuf {
    SERVER.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt;
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("fake-roamswitch-mcp-{}", std::process::id()));
        std::fs::write(&path, SCRIPT).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    })
}

/// The `inputSchema` of `tool` in the recorded `tools/list` response.
pub fn input_schema(tool: &str) -> Value {
    let list = response("tools_list");
    list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == tool)
        .unwrap_or_else(|| panic!("{tool} is not in the recorded tools/list"))["inputSchema"]
        .clone()
}

/// Fails if `arguments` has a key the tool's input schema does not list, a
/// required key is missing, or a value has another JSON type than the schema says.
pub fn assert_arguments_fit_schema(tool: &str, arguments: &Value) {
    let schema = input_schema(tool);
    let props = schema["properties"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let args = match arguments {
        Value::Object(m) => m.clone(),
        Value::Null => Default::default(),
        other => panic!("{tool}: arguments are not an object: {other}"),
    };
    for (k, v) in &args {
        let p = props
            .get(k)
            .unwrap_or_else(|| panic!("{tool}: argument {k:?} is not in the input schema"));
        let ok = match p["type"].as_str() {
            Some("string") => v.is_string(),
            Some("boolean") => v.is_boolean(),
            Some("integer") => v.is_i64() || v.is_u64(),
            Some("array") => v.is_array(),
            Some("object") => v.is_object(),
            _ => true,
        };
        assert!(ok, "{tool}: argument {k:?} has the wrong type: {v}");
    }
    for r in schema["required"].as_array().into_iter().flatten() {
        let r = r.as_str().unwrap();
        assert!(
            args.contains_key(r),
            "{tool}: required argument {r:?} is missing"
        );
    }
}

/// What the client sent.
pub struct Sent {
    /// `params.name` of the `tools/call` request.
    pub tool: String,
    /// `params.arguments` of the request, exactly as sent.
    pub arguments: Value,
}

/// Runs `f` with a client whose `roamswitch-mcp` answers with the recorded
/// response `fixture`, and returns what `f` returned together with the request
/// the client wrote.
pub async fn with_fixture<T, F, Fut>(fixture: &str, f: F) -> (T, Sent)
where
    F: FnOnce(RoamSwitchClient) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    with_fixture_file(fixture_path(fixture), f).await
}

/// [`with_fixture`] for a response line in any file.
pub async fn with_fixture_file<T, F, Fut>(fixture: PathBuf, f: F) -> (T, Sent)
where
    F: FnOnce(RoamSwitchClient) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let script = server_script().clone();
    let _guard = LOCK.lock().await;
    let req = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("request-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&req);
    std::env::set_var("RS_TEST_REQ", &req);
    std::env::set_var("RS_TEST_FIXTURE", &fixture);
    let client = RoamSwitchClient::new(Some(script), None).expect("client");
    let out = f(client).await;
    let text = std::fs::read_to_string(&req).expect("the stand-in saved no request");
    let v: Value = serde_json::from_str(text.trim()).expect("request is JSON");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["method"], "tools/call");
    let sent = Sent {
        tool: v["params"]["name"].as_str().unwrap().to_string(),
        arguments: v["params"]["arguments"].clone(),
    };
    // Every request of every test must fit the input schema the real server published.
    assert_arguments_fit_schema(&sent.tool, &sent.arguments);
    (out, sent)
}

/// Fails if `typed` (a decoded value serialized again) lost or changed any
/// field of `original` (what the tool really sent). Fields that only `typed`
/// has are fine. This catches a misspelled `rename`, a field the type does
/// not have, and a value read into the wrong type.
pub fn assert_covers(original: &Value, typed: &Value, path: &str) {
    match (original, typed) {
        (Value::Object(o), Value::Object(t)) => {
            for (k, v) in o {
                match t.get(k) {
                    Some(tv) => assert_covers(v, tv, &format!("{path}.{k}")),
                    None => panic!("field lost at {path}.{k} (original value: {v})"),
                }
            }
        }
        (Value::Array(o), Value::Array(t)) => {
            assert_eq!(o.len(), t.len(), "array length differs at {path}");
            for (i, (a, b)) in o.iter().zip(t).enumerate() {
                assert_covers(a, b, &format!("{path}[{i}]"));
            }
        }
        (a, b) => assert_eq!(a, b, "value differs at {path}"),
    }
}

/// [`assert_covers`] for a typed value against the payload of `fixture`.
pub fn assert_fixture_covered<T: serde::Serialize>(fixture: &str, typed: &T) {
    let original = payload(fixture);
    let typed = serde_json::to_value(typed).unwrap();
    assert_covers(&original, &typed, fixture);
}
