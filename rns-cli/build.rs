use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");
    println!("cargo:rerun-if-changed=../rns-hooks/examples/stats_scraper/src/lib.rs");
    println!("cargo:rerun-if-changed=../rns-hooks/examples/stats_scraper/Cargo.toml");
    println!("cargo:rerun-if-changed=../rns-hooks/sdk/rns-hooks-sdk/src");
    println!("cargo:rerun-if-changed=../rns-hooks/sdk/rns-hooks-abi/src");

    let pkg_version = env!("CARGO_PKG_VERSION");
    let parts: Vec<&str> = pkg_version.split('.').collect();
    let major = parts.first().unwrap_or(&"0");
    let minor = parts.get(1).unwrap_or(&"0");

    let commit_count = Command::new("git")
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "0".to_string());

    let commit_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let version = format!("{}.{}.{}-{}", major, minor, commit_count, commit_hash);
    println!("cargo:rustc-env=FULL_VERSION={}", version);

    embed_stats_hook().expect("failed to build embedded stats hook");
}

fn embed_stats_hook() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let hook_manifest = manifest_dir.join("../rns-hooks/examples/stats_scraper/Cargo.toml");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let profile = if env::var("PROFILE").unwrap_or_else(|_| "debug".to_string()) == "release" {
        "release"
    } else {
        "debug"
    };

    let mut cmd = Command::new(cargo);
    let target_root = PathBuf::from(env::var("OUT_DIR")?).join("embedded-hook-target");
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(&hook_manifest)
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--target-dir")
        .arg(&target_root);
    if profile == "release" {
        cmd.arg("--release");
    }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("stats hook build failed with status {}", status);
    }

    let wasm_path = target_root
        .join("wasm32-unknown-unknown")
        .join(profile)
        .join("stats_scraper.wasm");
    if !Path::new(&wasm_path).exists() {
        anyhow::bail!("expected embedded hook at {}", wasm_path.display());
    }

    println!(
        "cargo:rustc-env=RNS_STATSD_HOOK_WASM={}",
        wasm_path.display()
    );
    Ok(())
}
