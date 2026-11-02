//! `base64`, `gzip`, `gunzip`.

use std::fs::File;
use std::io::{Read, Write};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::core::helpers::encode_output;
use crate::protocol::{Task, TaskResult};

pub async fn base64(task: &Task) -> TaskResult {
    let mut encode = true;
    let mut string_mode = false;
    let mut i = 0;
    while i < task.args.len() && task.args[i].starts_with('-') {
        match task.args[i].as_str() {
            "-e" | "--encode" => encode = true,
            "-d" | "--decode" => encode = false,
            "-s" | "--string" => string_mode = true,
            other => {
                return err(
                    task,
                    &format!("unknown flag: {other}"),
                )
            }
        }
        i += 1;
    }
    if i >= task.args.len() {
        return err(task, "base64 [-e|-d] [-s] <file|string>");
    }
    let arg = &task.args[i];

    let data: Vec<u8> = if string_mode {
        arg.as_bytes().to_vec()
    } else {
        match std::fs::read(arg) {
            Ok(d) => d,
            Err(e) => return err(task, &e.to_string()),
        }
    };

    if encode {
        let out = STANDARD.encode(&data);
        let mut s = out;
        s.push('\n');
        return ok(task, s.as_bytes());
    }
    let trimmed = String::from_utf8_lossy(&data).trim().to_string();
    match STANDARD.decode(trimmed.as_bytes()) {
        Ok(d) => ok(task, &d),
        Err(e) => err(task, &e.to_string()),
    }
}

pub async fn gzip(task: &Task, encode: bool) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "gzip/gunzip requires <file>");
    }
    let src = &task.args[0];
    let dst = if encode {
        format!("{src}.gz")
    } else {
        let stripped = src.strip_suffix(".gz").unwrap_or(src);
        if stripped == src {
            format!("{src}.out")
        } else {
            stripped.to_string()
        }
    };

    let mut input = match File::open(src) {
        Ok(f) => f,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut output = match File::create(&dst) {
        Ok(f) => f,
        Err(e) => return err(task, &e.to_string()),
    };

    if encode {
        let mut enc = GzEncoder::new(&mut output, Compression::default());
        if let Err(e) = std::io::copy(&mut input, &mut enc) {
            return err(task, &e.to_string());
        }
        if let Err(e) = enc.finish() {
            return err(task, &e.to_string());
        }
    } else {
        let mut dec = GzDecoder::new(&mut input);
        if let Err(e) = std::io::copy(&mut dec, &mut output) {
            return err(task, &e.to_string());
        }
    }
    let mut out = dst;
    out.push('\n');
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

// Silence unused `Write` when only `Read` is used by gzip decode.
#[allow(dead_code)]
fn _unused(_: &mut dyn Write, _: &mut dyn Read) {}