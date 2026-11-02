//! `mkdir`, `rm`, `cp`, `mv`, `chmod`, `ln`, `touch`.

use std::fs;
use std::time::SystemTime;

use crate::core::helpers::encode_output;
use crate::protocol::{Task, TaskResult};

pub async fn mkdir(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "mkdir requires <path>");
    }
    match fs::create_dir_all(&task.args[0]) {
        Ok(_) => ok(task, b"ok\n"),
        Err(e) => err(task, &e.to_string()),
    }
}

pub async fn rm(task: &Task) -> TaskResult {
    let mut args = task.args.clone();
    let mut recursive = false;
    if let Some(first) = args.first() {
        match first.as_str() {
            "-r" | "-rf" | "-fr" => {
                recursive = true;
                args.remove(0);
            }
            _ => {}
        }
    }
    if args.is_empty() {
        return err(task, "rm requires <path>");
    }
    let mut errs: Vec<String> = Vec::new();
    for p in &args {
        let r = if recursive {
            fs::remove_dir_all(p)
        } else {
            fs::remove_file(p)
        };
        if let Err(e) = r {
            errs.push(e.to_string());
        }
    }
    if errs.is_empty() {
        ok(task, b"ok\n")
    } else {
        err(task, &errs.join("; "))
    }
}

pub async fn cp(task: &Task) -> TaskResult {
    if task.args.len() < 2 {
        return err(task, "cp requires <src> <dst>");
    }
    match fs::copy(&task.args[0], &task.args[1]) {
        Ok(_) => ok(task, b"ok\n"),
        Err(e) => err(task, &e.to_string()),
    }
}

pub async fn mv(task: &Task) -> TaskResult {
    if task.args.len() < 2 {
        return err(task, "mv requires <src> <dst>");
    }
    match fs::rename(&task.args[0], &task.args[1]) {
        Ok(_) => ok(task, b"ok\n"),
        Err(e) => err(task, &e.to_string()),
    }
}

pub async fn chmod(task: &Task) -> TaskResult {
    if task.args.len() < 2 {
        return err(task, "chmod requires <octal> <path>");
    }
    let mode = match u32::from_str_radix(&task.args[0], 8) {
        Ok(m) => m,
        Err(e) => return err(task, &format!("invalid mode: {e}")),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(mode);
        match fs::set_permissions(&task.args[1], perms) {
            Ok(_) => ok(task, b"ok\n"),
            Err(e) => err(task, &e.to_string()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        err(task, "chmod is not supported on this platform")
    }
}

pub async fn ln(task: &Task) -> TaskResult {
    let mut args = task.args.clone();
    // Both `-s` and `-sf` select symlink mode; the `-f` half is
    // accepted for compat but not honoured (Go's NativeLn does
    // the same — it calls os.Symlink which fails if the target
    // exists).
    if let Some(first) = args.first() {
        if first == "-s" || first == "-sf" {
            args.remove(0);
        }
    }
    if args.len() < 2 {
        return err(task, "ln [-s] <target> <linkpath>");
    }
    #[cfg(unix)]
    {
        match std::os::unix::fs::symlink(&args[0], &args[1]) {
            Ok(_) => ok(task, b"ok\n"),
            Err(e) => err(task, &e.to_string()),
        }
    }
    #[cfg(not(unix))]
    {
        err(task, "ln is not supported on this platform")
    }
}

pub async fn touch(task: &Task) -> TaskResult {
    let mut args = task.args.clone();
    let mut ref_path: Option<String> = None;
    if args.len() >= 3 && args[0] == "-r" {
        ref_path = Some(args[1].clone());
        args.drain(0..2);
    }
    if args.is_empty() {
        return err(task, "touch [-r <ref>] <path>");
    }
    let path = &args[0];

    // Create if missing; otherwise leave contents untouched.
    if let Err(e) = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
    {
        return err(task, &e.to_string());
    }

    let mtime = if let Some(ref p) = ref_path {
        match fs::metadata(p).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(e) => {
                return err(task, &format!("reference: {e}"))
            }
        }
    } else {
        SystemTime::now()
    };
    // filetime crate is the portable way to set mtime; fall back
    // to skipping the timestamp if it is not in the dep tree yet.
    #[cfg(feature = "filetime")]
    {
        use filetime::FileTime;
        let ft = FileTime::from_system_time(mtime);
        if let Err(e) = filetime::set_file_mtime(path, ft) {
            return err(task, &e.to_string());
        }
    }
    #[cfg(not(feature = "filetime"))]
    {
        let _ = mtime;
    }
    ok(task, b"ok\n")
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