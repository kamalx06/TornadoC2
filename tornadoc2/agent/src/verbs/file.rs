//! File inspection verbs: head, tail, stat, strings, hexdump.

use std::io::{Read, Seek, SeekFrom};
use std::fs::File;

use crate::core::helpers::encode_output;
use crate::protocol::{Task, TaskResult};

use super::flags::{parse_flags, FlagSpec};

pub async fn head(task: &Task) -> TaskResult {
    let spec = FlagSpec::new().with_value("n");
    let parsed = match parse_flags(&task.args, &spec) {
        Ok(p) => p,
        Err(e) => return err(task, &format!("head: {e}")),
    };
    if parsed.positional.is_empty() {
        return err(task, "head <file> [-n N]");
    }
    let path = parsed.positional[0].clone();
    let n: usize = match parsed.get("n") {
        Some(s) => match s.parse::<usize>() {
            Ok(v) => v,
            Err(_) => return err(task, "head -n: invalid count"),
        },
        None => {
            // Backwards-compat: a second positional is N.
            parsed
                .positional
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(20)
        }
    };

    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut out = String::new();
    for (i, line) in data.lines().enumerate() {
        if i >= n {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    ok(task, out.as_bytes())
}

pub async fn tail(task: &Task) -> TaskResult {
    let spec = FlagSpec::new().with_value("n");
    let parsed = match parse_flags(&task.args, &spec) {
        Ok(p) => p,
        Err(e) => return err(task, &format!("tail: {e}")),
    };
    if parsed.positional.is_empty() {
        return err(task, "tail <file> [-n N]");
    }
    let path = parsed.positional[0].clone();
    let n: usize = match parsed.get("n") {
        Some(s) => match s.parse::<usize>() {
            Ok(v) => v,
            Err(_) => return err(task, "tail -n: invalid count"),
        },
        None => 20,
    };
    if n == 0 {
        return ok(task, b"");
    }

    // Backward read: mirror the Go implementation's block loop so
    // large files do not require a full read.
    let mut f = match File::open(&path) {
        Ok(f) => f,
        Err(e) => return err(task, &e.to_string()),
    };
    let size = match f.metadata() {
        Ok(m) => m.len(),
        Err(e) => return err(task, &e.to_string()),
    };
    if size == 0 {
        return ok(task, b"");
    }

    const CHUNK: u64 = 8192;
    let mut buf: Vec<u8> = Vec::new();
    let mut offset = size;
    let mut newlines = 0usize;
    while offset > 0 && newlines <= n {
        let read_size = CHUNK.min(offset);
        offset -= read_size;
        if let Err(e) = f.seek(SeekFrom::Start(offset)) {
            return err(task, &e.to_string());
        }
        let mut block = vec![0u8; read_size as usize];
        if let Err(e) = f.read_exact(&mut block) {
            return err(task, &e.to_string());
        }
        let mut combined = block;
        combined.extend_from_slice(&buf);
        buf = combined;
        newlines = buf.iter().filter(|b| **b == b'\n').count();
    }

    // Trim to the last n lines.
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    let text = String::from_utf8_lossy(&buf);
    let lines: Vec<&str> = text.split('\n').collect();
    let start = lines.len().saturating_sub(n);
    let mut out = lines[start..].join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    ok(task, out.as_bytes())
}

pub async fn stat(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "stat requires <path>");
    }
    let path = &task.args[0];
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut out = String::new();
    out.push_str(&format!("Path:    {path}\n"));
    out.push_str(&format!("Size:    {}\n", meta.len()));
    out.push_str(&format!("Mode:    {}\n", mode_string(&meta)));
    out.push_str(&format!(
        "ModTime: {}\n",
        meta.modified()
            .ok()
            .map(|m| chrono::DateTime::<chrono::Utc>::from(m)
                .to_rfc3339())
            .unwrap_or_default(),
    ));
    out.push_str(&format!("IsDir:   {}\n", meta.is_dir()));
    // Platform-specific extension (native.NativeStatExtra in Go).
    // The Rust port keeps this a no-op until `native::*` exposes
    // it; the field will be added when the platform files land.
    ok(task, out.as_bytes())
}

fn mode_string(meta: &std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        let kind = if meta.is_dir() {
            'd'
        } else if meta.file_type().is_symlink() {
            'l'
        } else {
            '-'
        };
        let mut s = String::with_capacity(10);
        s.push(kind);
        for shift in [6, 3, 0] {
            let bits = (mode >> shift) & 0o7;
            s.push(if bits & 4 != 0 { 'r' } else { '-' });
            s.push(if bits & 2 != 0 { 'w' } else { '-' });
            s.push(if bits & 1 != 0 { 'x' } else { '-' });
        }
        s
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        String::new()
    }
}

pub async fn strings(task: &Task) -> TaskResult {
    let spec = FlagSpec::new().with_value("n");
    let parsed = match parse_flags(&task.args, &spec) {
        Ok(p) => p,
        Err(e) => return err(task, &format!("strings: {e}")),
    };
    if parsed.positional.is_empty() {
        return err(task, "strings <file> [-n N]");
    }
    let path = parsed.positional[0].clone();
    let min_len: usize = match parsed.get("n") {
        Some(s) => match s.parse::<usize>() {
            Ok(v) if v >= 1 => v,
            _ => {
                return err(task, "strings -n: invalid min length")
            }
        },
        None => 4,
    };

    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => return err(task, &e.to_string()),
    };
    if !meta.is_file() {
        return err(task, "strings: not a regular file");
    }

    let mut f = match File::open(&path) {
        Ok(f) => f,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut out = String::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return err(task, &e.to_string()),
        };
        for &b in &buf[..n] {
            if (0x20..0x7f).contains(&b) {
                cur.push(b);
            } else if !cur.is_empty() {
                if cur.len() >= min_len {
                    out.push_str(
                        &String::from_utf8_lossy(&cur),
                    );
                    out.push('\n');
                }
                cur.clear();
            }
        }
    }
    if cur.len() >= min_len {
        out.push_str(&String::from_utf8_lossy(&cur));
        out.push('\n');
    }
    ok(task, out.as_bytes())
}

pub async fn hexdump(task: &Task) -> TaskResult {
    let spec = FlagSpec::new().with_values(&["n", "o"]);
    let parsed = match parse_flags(&task.args, &spec) {
        Ok(p) => p,
        Err(e) => return err(task, &format!("hexdump: {e}")),
    };
    if parsed.positional.is_empty() {
        return err(task, "hexdump <file> [-n N] [-o offset]");
    }
    let path = parsed.positional[0].clone();
    let max_bytes: i64 = match parsed.get("n") {
        Some(s) => match s.parse() {
            Ok(v) if v >= 0 => v,
            _ => {
                return err(task, "hexdump -n: invalid count")
            }
        },
        None => 64 * 1024,
    };
    let start_offset: i64 = match parsed.get("o") {
        Some(s) => match s.parse() {
            Ok(v) if v >= 0 => v,
            _ => {
                return err(task, "hexdump -o: invalid offset")
            }
        },
        None => 0,
    };

    let mut f = match File::open(&path) {
        Ok(f) => f,
        Err(e) => return err(task, &e.to_string()),
    };
    if start_offset > 0 {
        if let Err(e) =
            f.seek(SeekFrom::Start(start_offset as u64))
        {
            return err(task, &e.to_string());
        }
    }

    let mut buf = vec![0u8; (max_bytes + 1) as usize];
    let n = match f.read(&mut buf) {
        Ok(n) => n,
        Err(e) => return err(task, &e.to_string()),
    };
    buf.truncate(n);
    let truncated = buf.len() as i64 > max_bytes;
    if truncated {
        buf.truncate(max_bytes as usize);
    }

    let mut out = String::new();
    for (i, chunk) in buf.chunks(16).enumerate() {
        let addr = start_offset as usize + i * 16;
        out.push_str(&format!("{addr:08x}  "));
        for b in chunk {
            out.push_str(&format!("{b:02x} "));
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        out.push_str(" |");
        for &b in chunk {
            out.push(if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    if truncated {
        out.push_str(&format!(
            "... truncated at {max_bytes} bytes\n"
        ));
    }
    ok(task, out.as_bytes())
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