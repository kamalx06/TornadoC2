// build.rs — reads every TC2_* environment variable the builder emits
// and writes config_generated.rs into OUT_DIR.
//
// src/config.rs does:
//     include!(concat!(env!("OUT_DIR"), "/config_generated.rs"));
//
// so every TC2_* const is available as a module-level identifier.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut out_src = String::new();

    let vars: &[(&str, &str)] = &[
        ("TC2_URL",                      ""),
        ("TC2_SLEEP",                    "60"),
        ("TC2_JITTER",                   "0.3"),
        ("TC2_KILL_DAYS",                "30"),
        ("TC2_WORK_START",               "08:00"),
        ("TC2_WORK_END",                 "19:00"),
        ("TC2_C2_PROFILE",               ""),
        ("TC2_TLS_PROFILE",              "rustls"),
        ("TC2_TRANSPORT",                "http"),
        ("TC2_TRANSPORT_FAILOVER_AFTER", "3"),
        ("TC2_AGENT_SIGNING_KEY",        ""),
        ("TC2_AGENT_PUBKEY",             ""),
        ("TC2_SERVER_ECDH_PUBKEY",       ""),
        ("TC2_IDENTITY_ROLE",            ""),
        ("TC2_MTLS_CERT",                ""),
        ("TC2_MTLS_KEY",                 ""),
        ("TC2_MTLS_CA",                  ""),
        ("TC2_DNS_DOMAIN",               ""),
        ("TC2_DOH_RESOLVER",             ""),
        ("TC2_ICMP_HOST",                ""),
        ("TC2_WG_SERVER_PUBKEY",         ""),
        ("TC2_WG_SERVER_ADDR",           ""),
        ("TC2_WG_AGENT_PRIVKEY",         ""),
        ("TC2_WG_TUNNEL_IP",             ""),
        ("TC2_WG_SERVER_TUNNEL_IP",      "10.99.0.1"),
        ("TC2_WG_INNER_PORT",            "8881"),
        ("TC2_PIVOT_KEY",                ""),
        ("TC2_SMB_PIPE",                 ""),
        ("TC2_SMB_RELAY_PIPE",           ""),
        ("TC2_TCP_BIND_ADDR",            ""),
        ("TC2_TCP_BIND_TOKEN",           ""),
        ("TC2_TCP_RELAY_TARGET",         ""),
        ("TC2_TCP_RELAY_TOKEN",          ""),
        ("TC2_TCP_REV_LISTEN",           ""),
        ("TC2_TCP_REV_TARGET",           ""),
        ("TC2_TCP_REV_TOKEN",            ""),
        ("TC2_SLEEP_MASK",               "none"),
        ("TC2_SYSCALL_METHOD",           "default"),
        ("TC2_VERBOSE",                  "0"),
    ];

    for (name, default) in vars {
        println!("cargo:rerun-if-env-changed={name}");
        let v = env::var(name).unwrap_or_else(|_| (*default).to_string());
        let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
        out_src.push_str(&format!("pub const {name}: &str = \"{escaped}\";\n"));
    }

    fs::write(out.join("config_generated.rs"), out_src).unwrap();
}
