//! `wc`, `nl`, `rev`, `sort`, `uniq`, `tr`.

use std::fs;

use crate::core::helpers::encode_output;
use crate::protocol::{Task, TaskResult};

pub async fn wc(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "wc requires <file>");
    }
    let data = match fs::read(&task.args[0]) {
        Ok(d) => d,
        Err(e) => return err(task, &e.to_string()),
    };
    let text = String::from_utf8_lossy(&data);
    let mut lines = 0u64;
    let mut words = 0u64;
    let mut bytes = 0u64;
    for line in text.split_inclusive('\n') {
        lines += 1;
        bytes += line.len() as u64;
        words += line.split_whitespace().count() as u64;
    }
    // Handle a trailing chunk with no newline that split_inclusive
    // may have already counted.
    if !data.is_empty() && data.last() != Some(&b'\n') && lines == 0 {
        lines = 1;
    }
    let out = format!(
        "{lines} {words} {bytes} {}\n",
        task.args[0],
    );
    ok(task, out.as_bytes())
}

pub async fn nl(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "nl requires <file>");
    }
    let data = match fs::read_to_string(&task.args[0]) {
        Ok(d) => d,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut out = String::new();
    let mut n = 0;
    for line in data.lines() {
        if line.is_empty() {
            out.push('\n');
            continue;
        }
        n += 1;
        out.push_str(&format!("{n:>6}\t{line}\n"));
    }
    ok(task, out.as_bytes())
}

pub async fn rev(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "rev requires <file>");
    }
    let data = match fs::read_to_string(&task.args[0]) {
        Ok(d) => d,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut out = String::new();
    for line in data.lines() {
        let reversed: String = line.chars().rev().collect();
        out.push_str(&reversed);
        out.push('\n');
    }
    ok(task, out.as_bytes())
}

pub async fn sort(task: &Task) -> TaskResult {
    let mut numeric = false;
    let mut reverse = false;
    let mut i = 0;
    while i < task.args.len() && task.args[i].starts_with('-') {
        match task.args[i].as_str() {
            "-n" => numeric = true,
            "-r" => reverse = true,
            "-nr" | "-rn" => {
                numeric = true;
                reverse = true;
            }
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
        return err(task, "sort [-n] [-r] <file>");
    }
    let path = &task.args[i];
    let data = match fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) => return err(task, &e.to_string()),
    };
    let trimmed = data.trim_end_matches('\n');
    let mut lines: Vec<&str> = if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split('\n').collect()
    };

    if numeric {
        let parse_first = |s: &str| -> Option<f64> {
            s.split_whitespace().next()?.parse::<f64>().ok()
        };
        lines.sort_by(|a, b| match (parse_first(a), parse_first(b)) {
            (Some(na), Some(nb)) => na
                .partial_cmp(&nb)
                .unwrap_or(std::cmp::Ordering::Equal),
            _ => a.cmp(b),
        });
    } else {
        lines.sort();
    }
    if reverse {
        lines.reverse();
    }
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    ok(task, out.as_bytes())
}

pub async fn uniq(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "uniq requires <file>");
    }
    let data = match fs::read_to_string(&task.args[0]) {
        Ok(d) => d,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut out = String::new();
    let mut prev: Option<&str> = None;
    let mut first = true;
    for line in data.lines() {
        if first || Some(line) != prev {
            out.push_str(line);
            out.push('\n');
            prev = Some(line);
            first = false;
        }
    }
    ok(task, out.as_bytes())
}

pub async fn tr(task: &Task) -> TaskResult {
    let mut args = task.args.clone();
    let delete = if let Some(first) = args.first() {
        if first == "-d" || first == "--delete" {
            args.remove(0);
            true
        } else {
            false
        }
    } else {
        false
    };
    let (set1, set2, path) = if delete {
        if args.len() < 2 {
            return err(task, "tr -d <set> <file>");
        }
        (args[0].clone(), String::new(), args[1].clone())
    } else {
        if args.len() < 3 {
            return err(task, "tr <set1> <set2> <file>");
        }
        (args[0].clone(), args[1].clone(), args[2].clone())
    };
    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => return err(task, &e.to_string()),
    };

    let mut out = Vec::with_capacity(data.len());
    if delete {
        let set: std::collections::HashSet<u8> =
            set1.as_bytes().iter().copied().collect();
        for &b in &data {
            if !set.contains(&b) {
                out.push(b);
            }
        }
    } else {
        if set2.is_empty() {
            return err(task, "tr: set2 must be non-empty");
        }
        let s1 = set1.as_bytes();
        let s2 = set2.as_bytes();
        let mut table = std::collections::HashMap::new();
        for (i, &from) in s1.iter().enumerate() {
            let to = if i < s2.len() {
                s2[i]
            } else {
                s2[s2.len() - 1]
            };
            table.insert(from, to);
        }
        for &b in &data {
            out.push(*table.get(&b).unwrap_or(&b));
        }
    }
    ok(task, &out)
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