//! Build provenance for the posture endpoint (`GET /api/v1/posture`): the exact rustc that
//! compiled this binary and the git commit it was built from. Nothing here affects the code
//! that is compiled. `VULTRINO_BUILD_SHA` overrides the git lookup (a build from a source
//! archive has no repository); with neither, the SHA is "unknown" and the deploy gate refuses it.
use std::process::Command;

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let rustc_version = run(&rustc, &["--version"]).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=VULTRINO_RUSTC_VERSION={rustc_version}");

    let sha = std::env::var("VULTRINO_BUILD_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| run("git", &["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    let dirty = match run("git", &["status", "--porcelain", "--untracked-files=no"]) {
        Some(s) => !s.is_empty(),
        None => false,
    };
    println!("cargo:rustc-env=VULTRINO_BUILD_SHA={sha}");
    println!("cargo:rustc-env=VULTRINO_BUILD_DIRTY={dirty}");
    println!("cargo:rerun-if-env-changed=VULTRINO_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=RUSTC");
    if let Some(head) = run("git", &["rev-parse", "--git-path", "HEAD"]) {
        if std::path::Path::new(&head).exists() {
            println!("cargo:rerun-if-changed={head}");
        }
    }
}
