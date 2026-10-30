use crate::{Result, RuntimeError};
use chinwag_bus_client::{BusClient, ClientError};
use rustix::fs::{FlockOperation, OFlags, flock};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{fs::OpenOptionsExt, fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const LOCAL_URL: &str = "http://127.0.0.1:44339";
const LOCAL_MODE: &str = "isolated-local-alpha";
const LOCAL_TRANSPORT: &str = "local-jsonl-alpha (unsigned, isolated)";
const MAX_RECEIPT: u64 = 65_536;
const MAX_DESKTOP: u64 = 1024 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

mod forward;

#[derive(Debug, Clone)]
struct Options {
    state: PathBuf,
    desktop: PathBuf,
    bus_url: Option<String>,
    cursor_onboarding: bool,
    studio_forward: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProcessReceipt {
    runtime: String,
    pid: u32,
    url: String,
    command: Vec<String>,
    started_unix_ms: u64,
}

trait Platform {
    fn current_exe(&self) -> &Path;
    fn status(&mut self, url: &str) -> Result<Option<Value>>;
    fn process_command(&mut self, pid: u32) -> Result<Option<String>>;
    fn spawn_local(&mut self, command: &[String], log: &Path) -> Result<u32>;
    fn poll_local(&mut self, pid: u32) -> Result<Option<i32>>;
    fn open_app(&mut self, arguments: &[String]) -> Result<()>;
    fn pause(&mut self);
    fn forward_identity(&mut self, pid: u32) -> Result<Option<forward::ProcessIdentity>>;
    fn forward_port_free(&mut self) -> Result<bool>;
    fn spawn_forward(&mut self, command: &[String], log: &Path) -> Result<u32>;
    fn poll_forward(&mut self, pid: u32) -> Result<Option<i32>>;
    fn forward_listens(&mut self, pid: u32) -> Result<bool>;
}

struct System {
    executable: PathBuf,
    child: Option<Child>,
    forward_child: Option<Child>,
}

pub fn run(args: &[String]) -> Result<()> {
    let mut system = System {
        executable: std::env::current_exe()?,
        child: None,
        forward_child: None,
    };
    let options = Options::parse(args, system.current_exe())?;
    let receipt = launch(options, &mut system)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt)
            .map_err(|error| RuntimeError::Invalid(error.to_string()))?
    );
    Ok(())
}

impl Options {
    fn parse(args: &[String], executable: &Path) -> Result<Self> {
        let mut state = None;
        let mut desktop = None;
        let mut bus_url = None;
        let mut cursor_onboarding = false;
        let mut studio_forward = false;
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            if flag == "--studio-forward" {
                if studio_forward {
                    return invalid("duplicate launch option");
                }
                studio_forward = true;
                index += 1;
                continue;
            }
            if !matches!(
                flag,
                "--state-dir" | "--desktop" | "--bus-url" | "--onboarding"
            ) {
                return invalid(
                    "launch accepts --state-dir, --desktop, --bus-url, --onboarding cursor and --studio-forward only",
                );
            }
            let value = args
                .get(index + 1)
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| RuntimeError::Invalid(format!("missing value for {flag}")))?;
            let duplicate = match flag {
                "--state-dir" => state.replace(PathBuf::from(value)).is_some(),
                "--desktop" => desktop.replace(PathBuf::from(value)).is_some(),
                "--bus-url" => bus_url.replace(value.clone()).is_some(),
                "--onboarding" => {
                    if value != "cursor" {
                        return invalid("only Cursor onboarding is supported");
                    }
                    std::mem::replace(&mut cursor_onboarding, true)
                }
                _ => unreachable!(),
            };
            if duplicate {
                return invalid("duplicate launch option");
            }
            index += 2;
        }
        if let Some(url) = &bus_url {
            let url = url.clone();
            let normalized = thread::spawn(move || {
                BusClient::new(&url)
                    .map(|client| {
                        client
                            .normalized_endpoint()
                            .trim_end_matches('/')
                            .to_owned()
                    })
                    .map_err(|error| RuntimeError::Invalid(error.to_string()))
            })
            .join()
            .map_err(|_| RuntimeError::Unavailable("endpoint validation worker failed".into()))??;
            bus_url = Some(normalized);
        }
        if (cursor_onboarding || studio_forward) && bus_url.is_none() {
            return invalid(
                "Cursor onboarding and Studio forwarding require an explicit --bus-url",
            );
        }
        if studio_forward && bus_url.as_deref() != Some(forward::URL) {
            return invalid(
                "--studio-forward supports only the saved Studio loopback route http://127.0.0.1:44345",
            );
        }
        let state = match state {
            Some(state) => state,
            None => PathBuf::from(
                std::env::var_os("HOME")
                    .ok_or_else(|| RuntimeError::Invalid("HOME is unavailable".into()))?,
            )
            .join("Documents/Codex/2026-10-30/chinwag-gpui-bus-integration-v1"),
        };
        let desktop = desktop.unwrap_or_else(|| {
            executable
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("chinwag-desktop-alpha")
        });
        Ok(Self {
            state: std::path::absolute(state)?,
            desktop: std::path::absolute(desktop)?,
            bus_url,
            cursor_onboarding,
            studio_forward,
        })
    }
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(RuntimeError::Invalid(message.into()))
}

fn unavailable<T>(message: &str) -> Result<T> {
    Err(RuntimeError::Unavailable(message.into()))
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| RuntimeError::Invalid("alpha paths must be valid UTF-8".into()))
}

fn lock_launcher(executable: &Path) -> Result<File> {
    let directory = executable
        .parent()
        .ok_or_else(|| RuntimeError::Invalid("runtime executable has no parent".into()))?;
    let guard = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(directory.join("alpha-launcher.lock"))?;
    flock(&guard, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
        RuntimeError::Unavailable("another alpha launcher is active; no duplicate attempted".into())
    })?;
    Ok(guard)
}

fn launch(mut options: Options, platform: &mut impl Platform) -> Result<Value> {
    let _guard = lock_launcher(platform.current_exe())?;
    fs::create_dir_all(&options.state)?;
    options.state = fs::canonicalize(&options.state)?;
    let source = open_regular(&options.desktop, MAX_DESKTOP)?;
    drop(source);
    let url = options.bus_url.as_deref().unwrap_or(LOCAL_URL);
    let mode = if options.bus_url.is_some() {
        "existing-bus-http"
    } else {
        LOCAL_MODE
    };
    let bus = if options.bus_url.is_none() {
        Some(ensure_local_bus(&options.state, platform)?)
    } else {
        None
    };
    let studio_forward = if options.studio_forward {
        Some(forward::ensure(&options.state, platform)?)
    } else {
        None
    };
    let endpoint_preflight = if options.bus_url.is_some() {
        let status = platform.status(url).map_err(|error| RuntimeError::Unavailable(format!(
            "Configured bus connection is unavailable; the app was not opened. No Cursor setup was attempted. {error}"
        )))?.ok_or_else(|| RuntimeError::Unavailable(
            "Configured bus connection is unavailable; the app was not opened. Check the preview connection before trying again. No Cursor setup was attempted.".into()
        ))?;
        Some(validate_external_status(&status, options.studio_forward)?)
    } else {
        None
    };
    if options.studio_forward {
        forward::verify_after_preflight(&options.state, platform)?;
    }
    let (app, executable, bundle_id) =
        package_app(&options.state, &options.desktop, options.cursor_onboarding)?;
    let drafts = options.state.join("human-drafts.json");
    let mut arguments = vec![
        "--env".into(),
        format!("CHINWAG_BUS_URL={url}"),
        "--env".into(),
        format!("CHINWAG_ALPHA_DRAFTS_PATH={}", path_text(&drafts)?),
    ];
    if options.cursor_onboarding {
        arguments.extend(["--env".into(), "CHINWAG_ALPHA_ONBOARDING=cursor".into()]);
    }
    if options.studio_forward {
        arguments.extend(["--env".into(), "CHINWAG_ALPHA_TARGET_HOST=Studio".into()]);
    }
    arguments.push(path_text(&app)?);
    platform.open_app(&arguments)?;
    let receipt = json!({
        "runtime": "rust",
        "at_unix_ms": now_ms()?,
        "app": path_text(&app)?,
        "bundle_id": bundle_id,
        "binary": path_text(&executable)?,
        "source_binary": path_text(&options.desktop)?,
        "endpoint": url,
        "endpoint_is_requested_setting": true,
        "existing_app_environment_replaced": false,
        "mode": mode,
        "bus": bus,
        "studio_forward": studio_forward,
        "endpoint_preflight": endpoint_preflight,
        "onboarding": if options.cursor_onboarding {Some("cursor")} else {None},
        "drafts_path": path_text(&drafts)?,
        "launch_action": "open-or-activate",
        "connection_verified": false,
        "fleet_delivery_verified": false,
        "registered_fleet_workers_invoked": false,
    });
    atomic_json(&options.state.join("latest-launch.json"), &receipt)?;
    Ok(receipt)
}

fn validate_external_status(status: &Value, studio: bool) -> Result<Value> {
    let mode = status.get("mode").and_then(Value::as_str);
    if status.get("ok").and_then(Value::as_bool) != Some(true)
        || status.get("storage_healthy").and_then(Value::as_bool) != Some(true)
        || !matches!(
            mode,
            Some(LOCAL_MODE | "fleet-ledger-read-only" | "fleet-signed-ui")
        )
        || (studio
            && (mode != Some("fleet-ledger-read-only")
                || status.get("read_only").and_then(Value::as_bool) != Some(true)
                || status.get("send_allowed").and_then(Value::as_bool) != Some(false)
                || status.get("agent_wake").and_then(Value::as_bool) != Some(false)
                || status.get("transport").and_then(Value::as_str)
                    != Some("local-ledger-read-only")))
    {
        return unavailable(
            "Configured endpoint did not confirm a healthy expected Chinwag bus; the app was not opened. No Cursor setup was attempted.",
        );
    }
    Ok(
        json!({"http_status_checked":true,"mode":mode,"storage_healthy":true,
        "client_connected":false,"recipient_delivery_verified":false}),
    )
}

fn bus_command(state: &Path, executable: &Path) -> Result<Vec<String>> {
    Ok(vec![
        path_text(executable)?,
        "serve-local".into(),
        "--data-dir".into(),
        path_text(&state.join("local-bus"))?,
        "--port".into(),
        "44339".into(),
    ])
}

fn verify_process(pid: u32, expected: &[String], platform: &mut impl Platform) -> Result<bool> {
    match platform.process_command(pid)? {
        None => Ok(false),
        Some(command) if command.trim() == expected.join(" ") => Ok(true),
        Some(_) => {
            unavailable("original alpha PID/command proof does not match; no replacement attempted")
        }
    }
}

fn recorded_process(state: &Path, platform: &mut impl Platform) -> Result<Option<u32>> {
    let path = state.join("local-bus-process.json");
    let mut input = match open_regular(&path, MAX_RECEIPT) {
        Ok(input) => input,
        Err(RuntimeError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut raw = Vec::new();
    input.read_to_end(&mut raw)?;
    let receipt: ProcessReceipt = serde_json::from_slice(&raw).map_err(|_| {
        RuntimeError::Unavailable(
            "original process receipt is not a validated Rust receipt; root owns migration".into(),
        )
    })?;
    let expected = bus_command(state, platform.current_exe())?;
    if receipt.runtime != "rust"
        || receipt.pid == 0
        || receipt.url != LOCAL_URL
        || receipt.command != expected
    {
        return unavailable(
            "original process receipt does not match this Rust runtime; no duplicate attempted",
        );
    }
    if verify_process(receipt.pid, &expected, platform)? {
        Ok(Some(receipt.pid))
    } else {
        Ok(None)
    }
}

fn validate_status(
    status: &Value,
    state: &Path,
    expected_pid: Option<u32>,
    platform: &mut impl Platform,
) -> Result<u32> {
    if status.get("mode").and_then(Value::as_str) != Some(LOCAL_MODE)
        || status.get("ok").and_then(Value::as_bool) != Some(true)
        || status.get("live_fleet").and_then(Value::as_bool) != Some(false)
        || status.get("signed").and_then(Value::as_bool) != Some(false)
        || status.get("agent_wake").and_then(Value::as_bool) != Some(false)
        || status.get("transport").and_then(Value::as_str) != Some(LOCAL_TRANSPORT)
        || status.get("storage_healthy").and_then(Value::as_bool) != Some(true)
        || status.get("data_dir").and_then(Value::as_str)
            != Some(path_text(&state.join("local-bus"))?.as_str())
    {
        return unavailable(
            "listener does not confirm this healthy isolated unsigned data directory; retained",
        );
    }
    let pid = status
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| RuntimeError::Unavailable("listener process identity is invalid".into()))?;
    if expected_pid.is_some_and(|expected| pid != expected) {
        return unavailable("listener PID is not the original child; original retained");
    }
    let expected = bus_command(state, platform.current_exe())?;
    if !verify_process(pid, &expected, platform)? {
        return unavailable("listener PID is no longer present; no replacement attempted");
    }
    Ok(pid)
}

fn ensure_local_bus(state: &Path, platform: &mut impl Platform) -> Result<Value> {
    if let Some(status) = platform.status(LOCAL_URL)? {
        let pid = validate_status(&status, state, None, platform)?;
        return Ok(
            json!({"action":"reused","pid":pid,"data_dir":state.join("local-bus"),
            "identity_proof":"healthy-status-and-exact-rust-pid-command"}),
        );
    }
    if let Some(pid) = recorded_process(state, platform)? {
        return unavailable(&format!(
            "original alpha PID {pid} is running but not ready; retained without duplicate"
        ));
    }
    let command = bus_command(state, platform.current_exe())?;
    let started_unix_ms = now_ms()?;
    let pid = platform.spawn_local(&command, &state.join("local-bus.log"))?;
    let receipt = ProcessReceipt {
        runtime: "rust".into(),
        pid,
        url: LOCAL_URL.into(),
        command,
        started_unix_ms,
    };
    atomic_json(&state.join("local-bus-process.json"), &receipt).map_err(|error| {
        RuntimeError::Unavailable(format!(
            "started original PID {pid}; receipt write failed; retain it and do not retry: {error}"
        ))
    })?;
    for _ in 0..30 {
        if let Some(code) = platform.poll_local(pid)? {
            return unavailable(&format!(
                "owned alpha PID {pid} exited {code}; inspect local-bus.log; no retry"
            ));
        }
        match platform.status(LOCAL_URL) {
            Ok(Some(status)) => {
                validate_status(&status, state, Some(pid), platform)?;
                return Ok(
                    json!({"action":"started","pid":pid,"data_dir":state.join("local-bus"),
                    "identity_proof":"healthy-status-and-exact-rust-pid-command"}),
                );
            }
            Ok(None) => platform.pause(),
            Err(error) => {
                return unavailable(&format!(
                    "original alpha PID {pid} has uncertain readiness; retained: {error}"
                ));
            }
        }
    }
    unavailable(&format!(
        "original alpha PID {pid} did not become ready; retained for inspection"
    ))
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| RuntimeError::Invalid("system time is outside the receipt range".into()))
}

fn open_regular(path: &Path, maximum: u64) -> Result<File> {
    let input = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return invalid("expected a bounded regular non-symlink alpha artifact");
    }
    Ok(input)
}

fn temporary(path: &Path) -> Result<(PathBuf, File)> {
    let parent = path
        .parent()
        .ok_or_else(|| RuntimeError::Invalid("artifact has no parent".into()))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| RuntimeError::Invalid("artifact name is not UTF-8".into()))?;
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(&temporary)?;
    Ok((temporary, file))
}

fn atomic_file(path: &Path, mode: u32, write: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    let (temporary, mut output) = temporary(path)?;
    let result = (|| {
        write(&mut output)?;
        output.set_permissions(fs::Permissions::from_mode(mode))?;
        output.sync_all()?;
        drop(output);
        fs::rename(&temporary, path)?;
        File::open(
            path.parent()
                .ok_or_else(|| RuntimeError::Invalid("artifact has no parent".into()))?,
        )?
        .sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| RuntimeError::Invalid(error.to_string()))?;
    encoded.push(b'\n');
    atomic_file(path, 0o600, |output| {
        output.write_all(&encoded)?;
        Ok(())
    })
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn package_app(
    state: &Path,
    desktop: &Path,
    cursor_onboarding: bool,
) -> Result<(PathBuf, PathBuf, String)> {
    let display_name = if cursor_onboarding {
        "Chinwag Cursor Setup"
    } else {
        "Chinwag Alpha"
    };
    let app = state.join(format!("{display_name}.app"));
    let contents = app.join("Contents");
    let executable = contents.join("MacOS/ChinwagAlpha");
    fs::create_dir_all(
        executable
            .parent()
            .ok_or_else(|| RuntimeError::Invalid("app has no executable directory".into()))?,
    )?;
    let mut hasher = Sha256::new();
    hasher.update(state.as_os_str().as_encoded_bytes());
    if cursor_onboarding {
        hasher.update(b"\0cursor-onboarding");
    }
    let digest = format!("{:x}", hasher.finalize());
    let bundle_id = format!("com.emunlabs.chinwag.alpha.a{}", &digest[..16]);
    let source = open_regular(desktop, MAX_DESKTOP)?;
    atomic_file(&executable, 0o755, |output| {
        if std::io::copy(&mut source.take(MAX_DESKTOP + 1), output)? > MAX_DESKTOP {
            return invalid("desktop executable exceeds its copy bound");
        }
        Ok(())
    })?;
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\
         <key>CFBundleName</key><string>{display_name}</string>\
         <key>CFBundleDisplayName</key><string>{display_name}</string>\
         <key>CFBundleIdentifier</key><string>{}</string>\
         <key>CFBundleExecutable</key><string>ChinwagAlpha</string>\
         <key>CFBundlePackageType</key><string>APPL</string>\
         <key>CFBundleShortVersionString</key><string>0.1.0</string>\
         <key>NSHighResolutionCapable</key><true/>\
         </dict></plist>\n",
        xml_escape(&bundle_id)
    );
    atomic_file(&contents.join("Info.plist"), 0o644, |output| {
        output.write_all(plist.as_bytes())?;
        Ok(())
    })?;
    Ok((app, executable, bundle_id))
}

impl Platform for System {
    fn current_exe(&self) -> &Path {
        &self.executable
    }

    fn status(&mut self, url: &str) -> Result<Option<Value>> {
        let url = url.to_owned();
        thread::spawn(move || {
            let client =
                BusClient::new(&url).map_err(|error| RuntimeError::Invalid(error.to_string()))?;
            match client.status() {
                Ok(value) => {
                    if serde_json::to_vec(&value).map_or(true, |raw| raw.len() as u64 > MAX_RECEIPT)
                    {
                        return unavailable("status exceeds the launcher read bound");
                    }
                    Ok(Some(value))
                }
                Err(ClientError::Transport(error)) if connection_refused(&error) => Ok(None),
                Err(error) => unavailable(&format!(
                    "listener is uncertain; no replacement attempted: {error}"
                )),
            }
        })
        .join()
        .map_err(|_| {
            RuntimeError::Unavailable("status worker failed; no replacement attempted".into())
        })?
    }

    fn process_command(&mut self, pid: u32) -> Result<Option<String>> {
        let mut command = Command::new("/bin/ps");
        command.args(["-p", &pid.to_string(), "-o", "command="]);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn()?;
        let status = wait_helper(&mut child, Duration::from_secs(2))?;
        let mut raw = Vec::new();
        child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("PID proof has no output".into()))?
            .take(MAX_RECEIPT + 1)
            .read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_RECEIPT {
            return unavailable("PID command proof exceeds its read bound");
        }
        let output = String::from_utf8(raw)
            .map_err(|_| RuntimeError::Unavailable("PID command is not UTF-8".into()))?;
        if status == Some(1) && output.trim().is_empty() {
            return Ok(None);
        }
        if status != Some(0) {
            return unavailable("PID command outcome is uncertain");
        }
        Ok(Some(output))
    }

    fn spawn_local(&mut self, command: &[String], log: &Path) -> Result<u32> {
        if self.child.is_some()
            || command.first().map(String::as_str) != self.executable.to_str()
            || command.get(1).map(String::as_str) != Some("serve-local")
        {
            return invalid("launcher may start only its own isolated Rust server once");
        }
        let log = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(log)?;
        let mut child = Command::new(&self.executable);
        child
            .args(&command[1..])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .process_group(0);
        let child = child.spawn()?;
        let pid = child.id();
        self.child = Some(child);
        Ok(pid)
    }

    fn poll_local(&mut self, pid: u32) -> Result<Option<i32>> {
        let child = self
            .child
            .as_mut()
            .filter(|child| child.id() == pid)
            .ok_or_else(|| RuntimeError::Invalid("cannot poll another process".into()))?;
        Ok(child.try_wait()?.map(|status| status.code().unwrap_or(-1)))
    }

    fn open_app(&mut self, arguments: &[String]) -> Result<()> {
        let mut child = Command::new("/usr/bin/open")
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        if wait_helper(&mut child, Duration::from_secs(10))? != Some(0) {
            return unavailable("application activation failed; connection outcome is unverified");
        }
        Ok(())
    }

    fn pause(&mut self) {
        thread::sleep(Duration::from_millis(100));
    }

    fn forward_identity(&mut self, pid: u32) -> Result<Option<forward::ProcessIdentity>> {
        let mut child = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "lstart=", "-o", "command="])
            .env("LC_ALL", "C")
            .env("TZ", "UTC0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let status = wait_helper(&mut child, Duration::from_secs(2))?;
        let mut raw = Vec::new();
        child
            .stdout
            .take()
            .ok_or_else(|| {
                RuntimeError::Unavailable("owned forward process proof has no output".into())
            })?
            .take(MAX_RECEIPT + 1)
            .read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_RECEIPT {
            return unavailable("owned forward process proof exceeds its bound");
        }
        let output = String::from_utf8(raw).map_err(|_| {
            RuntimeError::Unavailable("owned forward process proof is not UTF-8".into())
        })?;
        if status == Some(1) && output.trim().is_empty() {
            return Ok(None);
        }
        if status != Some(0) || output.trim().lines().count() != 1 {
            return unavailable("owned forward process proof is uncertain");
        }
        let fields: Vec<_> = output.split_whitespace().collect();
        if fields.len() < 6 {
            return unavailable("owned forward process start-time proof is incomplete");
        }
        Ok(Some(forward::ProcessIdentity {
            started: fields[..5].join(" "),
            command: fields[5..].join(" "),
        }))
    }

    fn forward_port_free(&mut self) -> Result<bool> {
        match std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 44345)) {
            Ok(listener) => {
                drop(listener);
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn spawn_forward(&mut self, command: &[String], log: &Path) -> Result<u32> {
        if self.forward_child.is_some() || command != forward::command().as_slice() {
            return invalid("launcher may start only one fixed saved Studio forward");
        }
        let log = forward::log(log)?;
        let child = Command::new(&command[0])
            .args(&command[1..])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .process_group(0)
            .spawn()?;
        let pid = child.id();
        // std::process::Child does not kill on Drop. Null stdin, a separate
        // process group and owned log let this child survive the launcher exit.
        self.forward_child = Some(child);
        Ok(pid)
    }

    fn poll_forward(&mut self, pid: u32) -> Result<Option<i32>> {
        let child = self
            .forward_child
            .as_mut()
            .filter(|child| child.id() == pid)
            .ok_or_else(|| {
                RuntimeError::Invalid("cannot poll an unrelated forward process".into())
            })?;
        Ok(child.try_wait()?.map(|status| status.code().unwrap_or(-1)))
    }

    fn forward_listens(&mut self, pid: u32) -> Result<bool> {
        let mut child = Command::new("/usr/sbin/lsof")
            .args([
                "-nP",
                "-a",
                "-p",
                &pid.to_string(),
                "-iTCP@127.0.0.1:44345",
                "-sTCP:LISTEN",
                "-Fpn",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let status = wait_helper(&mut child, Duration::from_secs(2))?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Unavailable("owned listener proof has no output".into()))?
            .take(4097)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return unavailable("owned listener proof exceeds its bound");
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| RuntimeError::Unavailable("owned listener proof is not UTF-8".into()))?;
        if status == Some(1) && text.trim().is_empty() {
            return Ok(false);
        }
        if status != Some(0) {
            return unavailable("owned listener proof is uncertain");
        }
        forward::parse_listener_proof(&text, pid)
    }
}

fn connection_refused(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::ConnectionRefused)
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn wait_helper(child: &mut Child, timeout: Duration) -> Result<Option<i32>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.code());
        }
        if started.elapsed() >= timeout {
            // Only our short-lived ps/open helper is stopped; never an app or bus.
            child.kill()?;
            child.wait()?;
            return unavailable(
                "launcher helper timed out; application/bus outcome remains unverified",
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
#[path = "launcher_tests.rs"]
mod tests;
