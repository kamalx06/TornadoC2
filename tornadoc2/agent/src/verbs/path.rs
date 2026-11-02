//! `which`, `readlink`, `realpath`, `du`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::core::helpers::encode_output;
use crate::protocol::{Task, TaskResult};

pub async fn which(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "which requires <cmd>");
    }
    match look_path_no_exec(&task.args[0]) {
        Ok(p) => {
            let mut out = p.to_string_lossy().into_owned();
            out.push('\n');
            ok(task, out.as_bytes())
        }
        Err(e) => err(task, &e),
    }
}

/// Find `cmd` on PATH without executing it.
///
/// Mirrors `lookPathNoExec`:
/// - A name containing `/` or `\` is checked as a direct path.
/// - Otherwise PATH is searched; on Windows `PATHEXT` is tried
///   (default `.EXE;.CMD;.BAT;.COM`).
/// - On Unix, the POSIX default PATH is used when `PATH` is
///   unset.
pub fn look_path_no_exec(cmd: &str) -> Result<PathBuf, String> {
    if cmd.contains('/') || cmd.contains('\\') {
        let info = fs::metadata(cmd);
        match info {
            Ok(m) if !m.is_dir() => return Ok(PathBuf::from(cmd)),
            _ => return Err(format!("not found: {cmd}")),
        }
    }

    let path_env = std::env::var("PATH").unwrap_or_default();
    let (sep, path_env) = if cfg!(windows) {
        (
            ';',
            if path_env.is_empty() {
                String::new()
            } else {
                path_env
            },
        )
    } else {
        (
            ':',
            if path_env.is_empty() {
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                    .to_string()
            } else {
                path_env
            },
        )
    };

    let exts: Vec<String> = if cfg!(windows) {
        match std::env::var("PATHEXT") {
            Ok(pe) if !pe.is_empty() => {
                pe.split(';').map(|s| s.to_string()).collect()
            }
            _ => vec![
                ".EXE".to_string(),
                ".CMD".to_string(),
                ".BAT".to_string(),
                ".COM".to_string(),
            ],
        }
    } else {
        vec![String::new()]
    };

    for dir in path_env.split(sep) {
        if dir.is_empty() {
            continue;
        }
        for ext in &exts {
            let candidate = Path::new(dir).join(format!("{cmd}{ext}"));
            if let Ok(m) = fs::metadata(&candidate) {
                if !m.is_dir() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(format!("not found in PATH: {cmd}"))
}

pub async fn readlink(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "readlink requires <path>");
    }
    match fs::read_link(&task.args[0]) {
        Ok(p) => {
            let mut out = p.to_string_lossy().into_owned();
            out.push('\n');
            ok(task, out.as_bytes())
        }
        Err(e) => err(task, &e.to_string()),
    }
}

pub async fn realpath(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "realpath requires <path>");
    }
    let abs = match fs::canonicalize(&task.args[0]) {
        Ok(p) => p,
        Err(_) => {
            // Fallback: absolute but unresolved.
            match std::env::current_dir()
                .map(|d| d.join(&task.args[0]))
            {
                Ok(p) => p,
                Err(e) => return err(task, &e.to_string()),
            }
        }
    };
    let mut out = abs.to_string_lossy().into_owned();
    out.push('\n');
    ok(task, out.as_bytes())
}

pub async fn du(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "du requires <path>");
    }
    let mut total: u64 = 0;
    for entry in walkdir::WalkDir::new(&task.args[0])
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if let Ok(m) = entry.metadata() {
            if m.is_file() {
                total += m.len();
            }
        }
    }
    ok(task, format!("{total}\n").as_bytes())
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