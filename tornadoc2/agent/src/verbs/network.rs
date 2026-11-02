//! `curl`, `resolve`, `nc`, `ifconfig`.

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::TokioAsyncResolver;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::redirect::Policy;

use crate::core::helpers::encode_output;
use crate::protocol::{Task, TaskResult};

use super::flags::consume_arg;

// ---- curl -----------------------------------------------------------

pub async fn curl(task: &Task) -> TaskResult {
    let args = &task.args;
    let mut method: Option<String> = None;
    let mut headers: Vec<String> = Vec::new();
    let mut body: Option<String> = None;
    let mut user_agent: Option<String> = None;
    let mut insecure = false;
    let mut include_headers = false;
    let mut follow_redirects = false;
    let mut out_path: Option<String> = None;
    let mut timeout_secs: u64 = 30;
    let mut max_size: u64 = 1024 * 1024;
    let mut url: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-X" => {
                let (v, ni) = consume_arg(args, i + 1);
                if ni == i + 1 {
                    return err(task, "-X requires an argument");
                }
                method = Some(v);
                i = ni;
            }
            "-H" => {
                let (v, ni) = consume_arg(args, i + 1);
                if ni == i + 1 {
                    return err(task, "-H requires an argument");
                }
                headers.push(v);
                i = ni;
            }
            "-d" => {
                let (v, ni) = consume_arg(args, i + 1);
                if ni == i + 1 {
                    return err(task, "-d requires an argument");
                }
                body = Some(v);
                i = ni;
            }
            "-A" => {
                let (v, ni) = consume_arg(args, i + 1);
                if ni == i + 1 {
                    return err(task, "-A requires an argument");
                }
                user_agent = Some(v);
                i = ni;
            }
            "-k" | "--insecure" => {
                insecure = true;
                i += 1;
            }
            "-i" | "--include" => {
                include_headers = true;
                i += 1;
            }
            "-L" | "--location" => {
                follow_redirects = true;
                i += 1;
            }
            "-o" => {
                let (v, ni) = consume_arg(args, i + 1);
                if ni == i + 1 {
                    return err(task, "-o requires a path");
                }
                out_path = Some(v);
                i = ni;
            }
            "-m" => {
                let (v, ni) = consume_arg(args, i + 1);
                if ni == i + 1 {
                    return err(task, "-m requires seconds");
                }
                timeout_secs = match v.parse::<u64>() {
                    Ok(n) if n > 0 => n,
                    _ => return err(task, "-m: invalid seconds"),
                };
                i = ni;
            }
            "--max-size" => {
                let (v, ni) = consume_arg(args, i + 1);
                if ni == i + 1 {
                    return err(task, "--max-size requires bytes");
                }
                max_size = match v.parse::<u64>() {
                    Ok(n) if n > 0 => n,
                    _ => return err(task, "--max-size: invalid bytes"),
                };
                i = ni;
            }
            other if other.starts_with('-') => {
                return err(task, &format!("unknown flag: {other}"));
            }
            other => {
                if url.is_some() {
                    return err(
                        task,
                        "only one URL may be supplied",
                    );
                }
                url = Some(other.to_string());
                i += 1;
            }
        }
    }
    let url = match url {
        Some(u) => u,
        None => return err(task, "curl requires a URL"),
    };

    let method = match method {
        Some(m) => m,
        None => {
            if body.is_some() {
                "POST".to_string()
            } else {
                "GET".to_string()
            }
        }
    };

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(insecure);
    builder = if follow_redirects {
        builder.redirect(Policy::limited(10))
    } else {
        builder.redirect(Policy::none())
    };
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => return err(task, &e.to_string()),
    };

    let mut req = client.request(
        reqwest::Method::from_bytes(method.as_bytes())
            .unwrap_or(reqwest::Method::GET),
        &url,
    );
    if let Some(b) = &body {
        req = req.body(b.clone());
    }
    req = req.header(
        reqwest::header::USER_AGENT,
        user_agent.as_deref().unwrap_or("curl/8.5.0"),
    );
    for h in &headers {
        if let Some((name, value)) = h.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                req = req.header(n, v);
            } else {
                return err(
                    task,
                    &format!("invalid header: {h}"),
                );
            }
        } else {
            return err(
                task,
                &format!(
                    "invalid header (expected 'Name: Value'): {h}"
                ),
            );
        }
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return err(task, &e.to_string()),
    };
    let status = resp.status();
    let headers_snapshot: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return err(task, &e.to_string()),
    };
    let mut data = bytes.to_vec();
    let truncated = data.len() as u64 > max_size;
    if truncated {
        data.truncate(max_size as usize);
    }

    let mut out = String::new();
    if include_headers {
        out.push_str(&format!(
            "HTTP/{} {}\n",
            if resp.version() == reqwest::Version::HTTP_2 {
                "2.0"
            } else if resp.version() == reqwest::Version::HTTP_11
            {
                "1.1"
            } else {
                "1.0"
            },
            status.as_u16(),
        ));
        let mut keys: Vec<&String> =
            headers_snapshot.iter().map(|(k, _)| k).collect();
        keys.sort();
        for k in keys {
            for (_, v) in
                headers_snapshot.iter().filter(|(hk, _)| hk == k)
            {
                out.push_str(&format!("{k}: {v}\n"));
            }
        }
        out.push('\n');
    }

    if let Some(p) = &out_path {
        if let Err(e) = std::fs::write(p, &data) {
            return err(task, &e.to_string());
        }
        out.push_str(&format!(
            "HTTP {}  {} bytes written to {}",
            status.as_u16(),
            data.len(),
            p,
        ));
        if truncated {
            out.push_str(&format!(" (truncated at {max_size})"));
        }
        out.push('\n');
    } else {
        if !include_headers {
            out.push_str(&format!(
                "HTTP {}\n",
                status.as_u16()
            ));
        }
        out.push_str(&String::from_utf8_lossy(&data));
        if truncated {
            out.push('\n');
            out.push_str(&format!(
                "... truncated at {max_size} bytes\n"
            ));
        } else if !data.is_empty() && data.last() != Some(&b'\n') {
            out.push('\n');
        }
    }
    ok(task, out.as_bytes())
}

// ---- resolve --------------------------------------------------------

pub async fn resolve(task: &Task) -> TaskResult {
    if task.args.is_empty() {
        return err(task, "resolve requires <host> [type]");
    }
    let host = task.args[0].clone();
    let rtype = task
        .args
        .get(1)
        .map(|s| s.to_ascii_uppercase())
        .unwrap_or_else(|| "A".to_string());

    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(_) => TokioAsyncResolver::tokio(
            hickory_resolver::config::ResolverConfig::cloudflare(),
            hickory_resolver::config::ResolverOpts::default(),
        ),
    };

    let mut out = String::new();
    let res: Result<(), String> = match rtype.as_str() {
        "A" | "AAAA" => {
            let ips = resolver
                .lookup_ip(&host)
                .await
                .map_err(|e| e.to_string())?;
            for ip in ips.iter() {
                let is_v4 = matches!(ip, IpAddr::V4(_));
                if (rtype == "A" && is_v4)
                    || (rtype == "AAAA" && !is_v4)
                {
                    out.push_str(&format!("{ip}\n"));
                }
            }
            Ok(())
        }
        "CNAME" => {
            let c = resolver
                .lookup(host.as_str(), hickory_resolver::proto::rr::RecordType::CNAME)
                .await
                .map_err(|e| e.to_string())?;
            for r in c.iter() {
                out.push_str(&format!("{r}\n"));
            }
            Ok(())
        }
        "MX" => {
            let c = resolver
                .lookup(host.as_str(), hickory_resolver::proto::rr::RecordType::MX)
                .await
                .map_err(|e| e.to_string())?;
            for r in c.iter() {
                out.push_str(&format!("{r}\n"));
            }
            Ok(())
        }
        "NS" => {
            let c = resolver
                .lookup(host.as_str(), hickory_resolver::proto::rr::RecordType::NS)
                .await
                .map_err(|e| e.to_string())?;
            for r in c.iter() {
                out.push_str(&format!("{r}\n"));
            }
            Ok(())
        }
        "TXT" => {
            let c = resolver
                .lookup(host.as_str(), hickory_resolver::proto::rr::RecordType::TXT)
                .await
                .map_err(|e| e.to_string())?;
            for r in c.iter() {
                out.push_str(&format!("{r}\n"));
            }
            Ok(())
        }
        "PTR" => {
            let addr: IpAddr = match host.parse() {
                Ok(a) => a,
                Err(e) => {
                    return err(task, &format!("bad PTR arg: {e}"))
                }
            };
            let c = resolver
                .reverse_lookup(addr)
                .await
                .map_err(|e| e.to_string())?;
            for r in c.iter() {
                out.push_str(&format!("{r}\n"));
            }
            Ok(())
        }
        other => {
            return err(
                task,
                &format!(
                    "unknown type: {other} (use A, AAAA, \
                     CNAME, MX, NS, TXT, or PTR)"
                ),
            );
        }
    };
    match res {
        Ok(()) => {
            if out.is_empty() {
                out.push_str("(no records)\n");
            }
            ok(task, out.as_bytes())
        }
        Err(e) => err(task, &e),
    }
}

// ---- nc -------------------------------------------------------------

pub async fn nc(task: &Task) -> TaskResult {
    let args = &task.args;
    let mut zero_io = false;
    let mut send_data: Option<String> = None;
    let mut timeout = Duration::from_secs(5);
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-z" => {
                zero_io = true;
                i += 1;
            }
            "-w" => {
                let (v, ni) = consume_arg(args, i + 1);
                if ni == i + 1 {
                    return err(task, "-w requires seconds");
                }
                let n = match v.parse::<u64>() {
                    Ok(n) if n > 0 => n,
                    _ => return err(task, "-w: invalid seconds"),
                };
                timeout = Duration::from_secs(n);
                i = ni;
            }
            "--send" => {
                let (v, ni) = consume_arg(args, i + 1);
                if ni == i + 1 {
                    return err(task, "--send requires data");
                }
                send_data = Some(v);
                i = ni;
            }
            other if other.starts_with('-') => {
                return err(task, &format!("unknown flag: {other}"));
            }
            other => {
                if host.is_none() {
                    host = Some(other.to_string());
                    i += 1;
                } else if port.is_none() {
                    port = match other.parse::<u16>() {
                        Ok(p) if p >= 1 => Some(p),
                        _ => {
                            return err(
                                task,
                                &format!("invalid port: {other}"),
                            )
                        }
                    };
                    i += 1;
                    break;
                } else {
                    return err(task, "nc: unexpected argument");
                }
            }
        }
    }

    let (host, port) = match (host, port) {
        (Some(h), Some(p)) => (h, p),
        _ => return err(task, "nc requires <host> <port>"),
    };
    nc_dial(task, &host, port, zero_io, send_data.as_deref(), timeout)
        .await
}

async fn nc_dial(
    task: &Task,
    host: &str,
    port: u16,
    zero_io: bool,
    send_data: Option<&str>,
    timeout_dur: Duration,
) -> TaskResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr_str = format!("{host}:{port}");
    let target = match tokio::net::lookup_host(&addr_str).await {
        Ok(mut iter) => match iter.next() {
            Some(a) => a,
            None => {
                return err(
                    task,
                    &format!("no address for {host}:{port}"),
                )
            }
        },
        Err(e) => {
            return err(
                task,
                &format!("connect failed: {e}"),
            )
        }
    };
    let stream = tokio::time::timeout(
        timeout_dur,
        tokio::net::TcpStream::connect(target),
    )
    .await;
    let mut stream = match stream {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return err(task, &format!("connect failed: {e}"))
        }
        Err(_) => return err(task, "connect timed out"),
    };

    if zero_io {
        return ok(
            task,
            format!("open: {addr_str}\n").as_bytes(),
        );
    }

    if let Some(data) = send_data {
        if let Err(e) = tokio::time::timeout(
            timeout_dur,
            stream.write_all(data.as_bytes()),
        )
        .await
        .unwrap_or_else(|_| Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "write timed out",
        )))
        {
            return err(task, &format!("write failed: {e}"));
        }
    }

    let mut buf = vec![0u8; 64 * 1024];
    let mut received = Vec::new();
    loop {
        let n = match tokio::time::timeout(
            timeout_dur,
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break,
            Err(_) => break,
        };
        received.extend_from_slice(&buf[..n]);
        if received.len() >= 64 * 1024 {
            break;
        }
    }

    if received.is_empty() {
        return ok(
            task,
            format!("open: {addr_str} (no data)\n").as_bytes(),
        );
    }
    ok(task, &received)
}

// ---- ifconfig -------------------------------------------------------

pub async fn ifconfig(task: &Task) -> TaskResult {
    #[cfg(target_os = "linux")]
    {
        // Read /proc/net/dev — this is what the Go tree's
        // NativeIfconfig approached via net.Interfaces().
        match tokio::fs::read_to_string("/proc/net/dev").await {
            Ok(s) => ok(task, s.as_bytes()),
            Err(e) => err(task, &e.to_string()),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let out = tokio::process::Command::new("/sbin/ifconfig")
            .output()
            .await;
        match out {
            Ok(o) => ok(task, &o.stdout),
            Err(e) => err(task, &e.to_string()),
        }
    }
    #[cfg(target_os = "windows")]
    {
        let out = tokio::process::Command::new("ipconfig")
            .output()
            .await;
        match out {
            Ok(o) => ok(task, &o.stdout),
            Err(e) => err(task, &e.to_string()),
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        err(task, "ifconfig is not supported on this platform")
    }
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