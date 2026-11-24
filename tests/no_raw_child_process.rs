//! Every child process the proxy starts is built by `src/plugins/child_process.rs`, which
//! clears the inherited environment and passes an explicit allowlist. A bare `Command::new`
//! would hand the child the proxy's whole environment, including the vault master password.
//!
//! The scan covers all of `src/` (test modules included: a blocking test helper that spawns
//! raw is the same hole). The helper file is the only exception. A new spawn site must call
//! `tokio_command` or `std_command` with a `ChildEnv` profile.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_raw_command_outside_the_child_process_helper() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let helper = src.join("plugins").join("child_process.rs");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(
        files.len() > 20 && helper.is_file(),
        "the scan is broken: {} files",
        files.len()
    );
    let mut offenders = Vec::new();
    let mut helper_users = 0;
    for f in files {
        if f == helper {
            continue;
        }
        let text = fs::read_to_string(&f).unwrap();
        for (i, l) in text.lines().enumerate() {
            let t = l.trim_start();
            if t.starts_with("//") {
                continue;
            }
            if l.contains("Command::new")
                || l.contains("process::Command")
                || l.contains("CommandExt")
            {
                offenders.push(format!("{}:{}: {}", f.display(), i + 1, t));
            }
            if l.contains("tokio_command(") || l.contains("std_command(") {
                helper_users += 1;
            }
        }
    }
    assert!(
        helper_users >= 10,
        "found only {helper_users} helper call sites: the scan is broken"
    );
    assert!(
        offenders.is_empty(),
        "raw child-process construction outside src/plugins/child_process.rs (use tokio_command / std_command):\n{}",
        offenders.join("\n")
    );
}
