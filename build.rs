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
    // Re-run when the commit or the tree changes, not only when HEAD's file does: on a branch
    // checkout HEAD holds `ref: refs/heads/x` and never changes on commit or pull, so also watch
    // the ref it points at, packed-refs and the index, and the sources (the dirty flag).
    let mut watch: Vec<String> = ["HEAD", "packed-refs", "index"]
        .iter()
        .filter_map(|n| run("git", &["rev-parse", "--git-path", n]))
        .collect();
    if let Some(r) = run("git", &["symbolic-ref", "-q", "HEAD"]) {
        if let Some(p) = run("git", &["rev-parse", "--git-path", &r]) {
            watch.push(p);
        }
    }
    for p in watch {
        if std::path::Path::new(&p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    for p in ["src", "Cargo.toml", "Cargo.lock", "build.rs"] {
        println!("cargo:rerun-if-changed={p}");
    }
}
