//! `sha1`, `sha256`, `md5`, `cksum`.

use std::fs::File;
use std::io::Read;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::core::helpers::encode_output;
use crate::protocol::{Task, TaskResult};

#[derive(Clone, Copy)]
pub enum Algo {
    Sha1,
    Sha256,
    Md5,
}

pub async fn hash(task: &Task, algo: Algo) -> TaskResult {
    let name = match algo {
        Algo::Sha1 => "sha1",
        Algo::Sha256 => "sha256",
        Algo::Md5 => "md5",
    };
    if task.args.is_empty() {
        return err(task, &format!("{name} requires <file>"));
    }
    let mut f = match File::open(&task.args[0]) {
        Ok(f) => f,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut buf = [0u8; 65536];
    let hex = match algo {
        Algo::Sha1 => {
            let mut h = Sha1::new();
            loop {
                match f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => h.update(&buf[..n]),
                    Err(e) => return err(task, &e.to_string()),
                }
            }
            hex::encode(h.finalize())
        }
        Algo::Sha256 => {
            let mut h = Sha256::new();
            loop {
                match f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => h.update(&buf[..n]),
                    Err(e) => return err(task, &e.to_string()),
                }
            }
            hex::encode(h.finalize())
        }
        Algo::Md5 => {
            let mut h = Md5::new();
            loop {
                match f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => h.update(&buf[..n]),
                    Err(e) => return err(task, &e.to_string()),
                }
            }
            hex::encode(h.finalize())
        }
    };
    ok(task, hex.as_bytes())
}

pub async fn cksum(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "cksum requires <file>");
    }
    let mut f = match File::open(&task.args[0]) {
        Ok(f) => f,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut hasher = crc32fast::Hasher::new();
    let mut total: u64 = 0;
    let mut buf = [0u8; 65536];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                total += n as u64;
            }
            Err(e) => return err(task, &e.to_string()),
        }
    }
    let out = format!("{} {} {}\n", hasher.finalize(), total, task.args[0]);
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