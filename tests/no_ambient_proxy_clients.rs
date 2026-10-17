//! VUL-29: every outbound HTTP client in the product source that can carry a secret ignores
//! the ambient HTTP_PROXY, HTTPS_PROXY and ALL_PROXY variables. reqwest honours them by
//! default, and has no automatic loopback exclusion, so a client built without `.no_proxy()`
//! would hand its Authorization header or tenant assertion to whatever proxy the environment
//! names.
//!
//! The scan covers every `Client::builder()` in non-test source. A new client must either call
//! `.no_proxy()` within its builder chain or be built by `build_guarded_client`.

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
fn every_product_client_builder_calls_no_proxy() {
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut seen = 0;
    let mut missing = Vec::new();
    for f in files {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        if name.ends_with("tests.rs") || name.ends_with("_test.rs") {
            continue;
        }
        let text = fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Everything from the first `#[cfg(test)] mod` on is test code.
        let end = (0..lines.len())
            .find(|&i| {
                lines[i].trim_start().starts_with("#[cfg(test)]")
                    && lines.get(i + 1).is_some_and(|n| n.contains("mod "))
            })
            .unwrap_or(lines.len());
        for (i, l) in lines[..end].iter().enumerate() {
            if l.contains("Client::builder()") && !l.trim_start().starts_with("//") {
                seen += 1;
                let chain_end = (i + 14).min(end);
                let chain = lines[i..chain_end].join("\n");
                // The builder chain ends at the first `.build()`.
                let chain = chain.split(".build()").next().unwrap_or(&chain).to_string();
                if !chain.contains(".no_proxy()") {
                    missing.push(format!("{}:{}", f.display(), i + 1));
                }
            }
        }
    }
    assert!(
        seen >= 6,
        "the scan found only {seen} builders: the scan is broken"
    );
    assert!(
        missing.is_empty(),
        "client builders without .no_proxy(): {missing:?}"
    );
}
