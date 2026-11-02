//! Argument parsing helpers.
//!
//! Port of `flagSpec`, `parseFlags`, `consumeArg`, and
//! `parseSizeSuffix` from `native_extra.go`.

use std::collections::HashMap;

/// Describes which flags a verb accepts.
///
/// `bools` and `values` are the two categories Go's `flagSpec`
/// carried. A bool flag has no argument; a value flag consumes the
/// next argument.
#[derive(Default)]
pub struct FlagSpec {
    pub bools: HashMap<&'static str, bool>,
    pub values: HashMap<&'static str, bool>,
}

impl FlagSpec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_bool(mut self, name: &'static str) -> Self {
        self.bools.insert(name, true);
        self
    }

    pub fn with_bools(mut self, names: &[&'static str]) -> Self {
        for n in names {
            self.bools.insert(n, true);
        }
        self
    }

    pub fn with_value(mut self, name: &'static str) -> Self {
        self.values.insert(name, true);
        self
    }

    pub fn with_values(mut self, names: &[&'static str]) -> Self {
        for n in names {
            self.values.insert(n, true);
        }
        self
    }
}

/// Result of `parse_flags`: recognised flags plus leftover
/// positional arguments.
pub struct Parsed {
    pub flags: HashMap<String, String>,
    pub positional: Vec<String>,
}

impl Parsed {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(|s| s.as_str())
    }
    pub fn has(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }
}

/// Parse `args` against `spec`.
///
/// Mirrors the Go `parseFlags`:
/// - `--` terminates flag parsing; everything after is
///   positional.
/// - An arg of the form `-name` or `--name` (any run of leading
///   dashes) is a flag. `strings.TrimLeft(arg, "-")` in Go means
///   `---name` also resolves.
/// - A bool flag stores `"true"` as its value.
/// - A value flag consumes the next argument.
/// - An unknown flag is an error.
pub fn parse_flags(
    args: &[String],
    spec: &FlagSpec,
) -> Result<Parsed, String> {
    let mut flags = HashMap::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            positional.extend_from_slice(&args[i + 1..]);
            return Ok(Parsed { flags, positional });
        }
        if arg.len() < 2 || !arg.starts_with('-') {
            positional.push(arg.clone());
            i += 1;
            continue;
        }
        let name = arg.trim_start_matches('-');
        if spec.bools.contains_key(name) {
            flags.insert(name.to_string(), "true".to_string());
            i += 1;
            continue;
        }
        if spec.values.contains_key(name) {
            if i + 1 >= args.len() {
                return Err(format!("flag -{name} requires a value"));
            }
            flags.insert(name.to_string(), args[i + 1].clone());
            i += 2;
            continue;
        }
        return Err(format!("unknown flag: {arg}"));
    }
    Ok(Parsed { flags, positional })
}

/// Pop a flag value from `args` at `start`, honouring shell-style
/// quoting.
///
/// Matches the Go `consumeArg`:
/// - Unquoted first token: returned as-is.
/// - Token starting with `"` or `'`: accumulate subsequent tokens
///   (joined with a space) until the token ends with the same
///   quote. Strip the quotes.
/// - Returns the new index (one past the last token consumed).
pub fn consume_arg(args: &[String], start: usize) -> (String, usize) {
    if start >= args.len() {
        return (String::new(), start);
    }
    let first = &args[start];
    if first.is_empty() {
        return (first.clone(), start + 1);
    }
    let q = first.as_bytes()[0] as char;
    if q != '"' && q != '\'' {
        return (first.clone(), start + 1);
    }
    if first.len() >= 2 && first.ends_with(q) {
        return (
            first[1..first.len() - 1].to_string(),
            start + 1,
        );
    }
    let mut parts = vec![first.clone()];
    let mut i = start + 1;
    while i < args.len() {
        parts.push(args[i].clone());
        if args[i].ends_with(q) {
            i += 1;
            break;
        }
        i += 1;
    }
    let joined = parts.join(" ");
    let trimmed = if joined.len() >= 2
        && joined.starts_with(q)
        && joined.ends_with(q)
    {
        joined[1..joined.len() - 1].to_string()
    } else {
        joined
    };
    (trimmed, i)
}

/// Parse a size suffix. Accepts an optional trailing `c` (bytes),
/// `k`/`K` (KiB), `M` (MiB), or `G` (GiB).
///
/// No suffix is bytes. Matches the Go `parseSizeSuffix`, including
/// its exact multiplier values.
pub fn parse_size_suffix(s: &str) -> Result<i64, String> {
    if s.is_empty() {
        return Err("empty size".to_string());
    }
    let bytes = s.as_bytes();
    let (num_str, mult) = match bytes[bytes.len() - 1] {
        b'c' => (&s[..s.len() - 1], 1i64),
        b'k' | b'K' => (&s[..s.len() - 1], 1024),
        b'M' => (&s[..s.len() - 1], 1024 * 1024),
        b'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    let n: i64 = num_str
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    Ok(n * mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_default_bytes() {
        assert_eq!(parse_size_suffix("42").unwrap(), 42);
    }

    #[test]
    fn parse_size_char_suffix() {
        assert_eq!(parse_size_suffix("42c").unwrap(), 42);
    }

    #[test]
    fn parse_size_k_suffixes() {
        assert_eq!(parse_size_suffix("1k").unwrap(), 1024);
        assert_eq!(parse_size_suffix("1K").unwrap(), 1024);
    }

    #[test]
    fn parse_size_m_g() {
        assert_eq!(parse_size_suffix("2M").unwrap(), 2 * 1024 * 1024);
        assert_eq!(
            parse_size_suffix("3G").unwrap(),
            3 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn parse_size_invalid() {
        assert!(parse_size_suffix("").is_err());
        assert!(parse_size_suffix("abc").is_err());
    }

    #[test]
    fn consume_unquoted() {
        let args = vec!["hello".to_string(), "next".to_string()];
        assert_eq!(consume_arg(&args, 0), ("hello".to_string(), 1));
    }

    #[test]
    fn consume_double_quoted() {
        let args = vec!["\"hello world\"".to_string(), "next".to_string()];
        assert_eq!(
            consume_arg(&args, 0),
            ("hello world".to_string(), 1)
        );
    }

    #[test]
    fn consume_quoted_multi_token() {
        let args = vec![
            "\"hello".to_string(),
            "world\"".to_string(),
            "next".to_string(),
        ];
        assert_eq!(
            consume_arg(&args, 0),
            ("hello world".to_string(), 2)
        );
    }

    #[test]
    fn parse_flags_bool_and_value() {
        let spec = FlagSpec::new()
            .with_bool("i")
            .with_value("n");
        let args = vec![
            "-i".to_string(),
            "-n".to_string(),
            "10".to_string(),
            "file".to_string(),
        ];
        let p = parse_flags(&args, &spec).unwrap();
        assert_eq!(p.get("i"), Some("true"));
        assert_eq!(p.get("n"), Some("10"));
        assert_eq!(p.positional, vec!["file"]);
    }

    #[test]
    fn parse_flags_terminator() {
        let spec = FlagSpec::new().with_bool("i");
        let args = vec![
            "--".to_string(),
            "-i".to_string(),
        ];
        let p = parse_flags(&args, &spec).unwrap();
        assert!(!p.has("i"));
        assert_eq!(p.positional, vec!["-i"]);
    }

    #[test]
    fn parse_flags_unknown_errors() {
        let spec = FlagSpec::new().with_bool("i");
        let args = vec!["-x".to_string()];
        assert!(parse_flags(&args, &spec).is_err());
    }
}