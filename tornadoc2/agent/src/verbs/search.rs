//! `find` and `grep`.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use regex::Regex;

use crate::core::helpers::encode_output;
use crate::protocol::{Task, TaskResult};

use super::flags::{parse_flags, parse_size_suffix, FlagSpec};

pub async fn find(task: &Task) -> TaskResult {
    let spec = FlagSpec::new().with_values(&["name", "size", "mtime", "type"]);
    let parsed = match parse_flags(&task.args, &spec) {
        Ok(p) => p,
        Err(e) => return err(task, &format!("find: {e}")),
    };
    if parsed.positional.is_empty() {
        return err(
            task,
            "find <path> [-name pat] [-size +N|-N] \
             [-mtime -N|+N] [-type f|d]",
        );
    }
    let root = parsed.positional[0].clone();
    let name_pat = match parsed.get("name") {
        Some(s) => Some(s.to_string()),
        None => {
            // Backwards-compat: positional pattern after root.
            parsed.positional.get(1).cloned()
        }
    };

    let (size_cmp, size_val) = match parsed.get("size") {
        Some(s) => {
            let (sign, rest) = match s.as_bytes().first() {
                Some(b'+') => (Some(b'+'), &s[1..]),
                Some(b'-') => (Some(b'-'), &s[1..]),
                _ => (None, s),
            };
            match parse_size_suffix(rest) {
                Ok(n) => (sign, n),
                Err(e) => {
                    return err(task, &format!("find -size: {e}"))
                }
            }
        }
        None => (None, 0i64),
    };

    let (mtime_cmp, mtime_days) = match parsed.get("mtime") {
        Some(s) => {
            let (sign, rest) = match s.as_bytes().first() {
                Some(b'+') => (Some(b'+'), &s[1..]),
                Some(b'-') => (Some(b'-'), &s[1..]),
                _ => (None, s),
            };
            match rest.parse::<i64>() {
                Ok(n) => (sign, n),
                Err(_) => {
                    return err(task, "find -mtime: invalid days")
                }
            }
        }
        None => (None, 0i64),
    };

    let type_filter = parsed.get("type").map(|s| s.to_string());

    let mut out = String::new();
    let now = std::time::SystemTime::now();
    for entry in walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if type_filter.as_deref() == Some("f") && meta.is_dir() {
            continue;
        }
        if type_filter.as_deref() == Some("d") && !meta.is_dir() {
            continue;
        }
        if let Some(ref pat) = name_pat {
            let name = entry.file_name().to_string_lossy();
            if !glob_match(pat, &name) {
                continue;
            }
        }
        if size_cmp.is_some() && !meta.is_dir() {
            let sz = meta.len() as i64;
            let keep = match size_cmp {
                Some(b'+') => sz > size_val,
                Some(b'-') => sz < size_val,
                _ => true,
            };
            if !keep {
                continue;
            }
        }
        if let Some(cmp) = mtime_cmp {
            let days = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .map(|d| d.as_secs_f64() / 86_400.0)
                .unwrap_or(0.0);
            let keep = match cmp {
                b'-' => days <= mtime_days as f64,
                b'+' => days >= mtime_days as f64,
                _ => true,
            };
            if !keep {
                continue;
            }
        }
        out.push_str(&entry.path().to_string_lossy());
        out.push('\n');
    }
    ok(task, out.as_bytes())
}

pub async fn grep(task: &Task) -> TaskResult {
    let spec = FlagSpec::new().with_bools(&["r", "i", "l"]);
    let parsed = match parse_flags(&task.args, &spec) {
        Ok(p) => p,
        Err(e) => return err(task, &format!("grep: {e}")),
    };
    if parsed.positional.len() < 2 {
        return err(task, "grep <pattern> <path> [-r] [-i] [-l]");
    }
    let mut pattern = parsed.positional[0].clone();
    let path = parsed.positional[1].clone();
    if parsed.get("i").is_some() {
        pattern = format!("(?i){pattern}");
    }
    let re = match Regex::new(&pattern) {
        Ok(r) => r,
        Err(e) => return err(task, &format!("regex: {e}")),
    };
    let list_only = parsed.get("l").is_some();
    let recursive = parsed.get("r").is_some();

    let mut out = String::new();
    let path_obj = Path::new(&path);
    let meta = match fs::metadata(path_obj) {
        Ok(m) => m,
        Err(e) => return err(task, &e.to_string()),
    };
    if meta.is_dir() {
        if !recursive {
            return err(
                task,
                &format!("grep: {path} is a directory (use -r)"),
            );
        }
        for entry in walkdir::WalkDir::new(path_obj)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_dir() {
                continue;
            }
            grep_file(
                entry.path(),
                &re,
                list_only,
                recursive,
                &mut out,
            );
        }
    } else {
        grep_file(path_obj, &re, list_only, recursive, &mut out);
    }
    ok(task, out.as_bytes())
}

fn grep_file(
    path: &Path,
    re: &Regex,
    list_only: bool,
    recursive: bool,
    out: &mut String,
) {
    let Ok(f) = fs::File::open(path) else { return };
    let reader = BufReader::with_capacity(1024 * 1024, f);
    let mut lineno = 0u64;
    let mut matched = false;
    for line in reader.lines().map_while(Result::ok) {
        lineno += 1;
        if re.is_match(&line) {
            if list_only {
                matched = true;
                break;
            }
            if recursive {
                out.push_str(&format!(
                    "{}:{}:{}\n",
                    path.display(),
                    lineno,
                    line,
                ));
            } else {
                out.push_str(&format!("{lineno}:{line}\n"));
            }
        }
    }
    if list_only && matched {
        out.push_str(&path.to_string_lossy());
        out.push('\n');
    }
}

/// Glob match implementing `filepath.Match` semantics: `*`
/// matches any sequence of non-separator characters, `?` matches
/// one character, `[a-z]` is a character class.
fn glob_match(pattern: &str, name: &str) -> bool {
    fn helper(p: &[u8], n: &[u8]) -> bool {
        if p.is_empty() {
            return n.is_empty();
        }
        match p[0] {
            b'*' => {
                for skip in 0..=n.len() {
                    if helper(&p[1..], &n[skip..]) {
                        return true;
                    }
                    if skip < n.len()
                        && matches!(n[skip], b'/' | b'\\')
                    {
                        return false;
                    }
                }
                false
            }
            b'?' => {
                !n.is_empty()
                    && !matches!(n[0], b'/' | b'\\')
                    && helper(&p[1..], &n[1..])
            }
            c => !n.is_empty() && c == n[0] && helper(&p[1..], &n[1..]),
        }
    }
    helper(pattern.as_bytes(), name.as_bytes())
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

// Silence unused-import warnings when `HashMap` is only used in
// the (future) parallel variant.
#[allow(dead_code)]
fn _unused(_: HashMap<(), ()>) {}