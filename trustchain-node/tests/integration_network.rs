//! Multi-node network integration test.
//!
//! Spawns 3 actual trustchain-node processes with consistent port layout,
//! makes HTTP calls to the REST API, and verifies bilateral chains form.
//!
//! Port convention: QUIC=base, gRPC=base+1, HTTP=base+2, proxy=base+3.
//!
//! NOTE: On Windows, `tokio::signal::ctrl_c()` inside child processes spawned
//! by `cargo test` can fire spuriously (console handler inheritance). This test
//! is marked `#[ignore]` and should be run in isolation:
//!
//!   cargo test -p trustchain-node --test integration_network -- --ignored --nocapture
//!
//! For CI, prefer the Python integration test: `python tests/test_integration_network.py`

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn find_port_base() -> u16 {
    for _ in 0..100 {
        let base = free_port();
        if (1..=3).all(|o| TcpListener::bind(format!("127.0.0.1:{}", base + o)).is_ok()) {
            return base;
        }
    }
    panic!("Could not find 4 consecutive free ports");
}

struct NodeHandle {
    child: std::process::Child,
    name: String,
    http_port: u16,
    _data_dir: tempfile::TempDir,
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn find_binary() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();
    for profile in ["release", "debug"] {
        for name in ["trustchain-node.exe", "trustchain-node"] {
            let p = workspace_root.join("target").join(profile).join(name);
            if p.exists() { return p; }
        }
    }
    panic!("binary not found");
}

fn spawn_node(name: &str) -> NodeHandle {
    let binary = find_binary();
    let data_dir = tempfile::tempdir().unwrap();
    let base = find_port_base();
    let (quic_port, grpc_port, http_port, proxy_port) = (base, base+1, base+2, base+3);

    let cfg = data_dir.path().join("node.toml");
    std::fs::write(&cfg, format!(
        "quic_addr = \"127.0.0.1:{quic_port}\"\n\
         grpc_addr = \"127.0.0.1:{grpc_port}\"\n\
         http_addr = \"127.0.0.1:{http_port}\"\n\
         proxy_addr = \"127.0.0.1:{proxy_port}\"\n\
         key_path = \"{kp}\"\n\
         db_path = \"{dp}\"\n\
         stun_server = \"\"\n\
         checkpoint_interval_secs = 300\n",
        kp = data_dir.path().join("identity.key").to_string_lossy().replace('\\', "/"),
        dp = data_dir.path().join("trustchain.db").to_string_lossy().replace('\\', "/"),
    )).unwrap();

    let child = Command::new(&binary)
        .arg("run").arg("--config").arg(&cfg)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {binary:?}: {e}"));

    NodeHandle { child, name: name.into(), http_port, _data_dir: data_dir }
}

fn wait_ready(h: &mut NodeHandle, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    let c = reqwest::blocking::Client::builder().timeout(Duration::from_secs(2)).build().unwrap();
    while start.elapsed() < timeout {
        if let Some(st) = h.child.try_wait().ok().flatten() {
            eprintln!("Node {} exited: {st}", h.name);
            return false;
        }
        if c.get(format!("http://127.0.0.1:{}/status", h.http_port)).send().map(|r| r.status().is_success()).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn json_get(port: u16, path: &str) -> serde_json::Value {
    reqwest::blocking::Client::new()
        .get(format!("http://127.0.0.1:{port}{path}"))
        .send().unwrap().json().unwrap()
}

fn json_post(port: u16, path: &str, body: serde_json::Value) -> serde_json::Value {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15)).build().unwrap()
        .post(format!("http://127.0.0.1:{port}{path}"))
        .json(&body).send().unwrap().json().unwrap()
}

#[test]
#[ignore]
fn test_three_node_bilateral_chains() {
    let mut a = spawn_node("alpha");
    let mut b = spawn_node("beta");
    let mut c = spawn_node("gamma");

    let t = Duration::from_secs(15);
    assert!(wait_ready(&mut a, t), "A failed");
    assert!(wait_ready(&mut b, t), "B failed");
    assert!(wait_ready(&mut c, t), "C failed");
    eprintln!("3 nodes up");

    let pk_a = json_get(a.http_port, "/status")["public_key"].as_str().unwrap().to_string();
    let pk_b = json_get(b.http_port, "/status")["public_key"].as_str().unwrap().to_string();
    let pk_c = json_get(c.http_port, "/status")["public_key"].as_str().unwrap().to_string();
    assert_ne!(pk_a, pk_b); assert_ne!(pk_b, pk_c);

    // Register peers bidirectionally.
    for (port, pk, addr) in [
        (a.http_port, &pk_b, format!("http://127.0.0.1:{}", b.http_port)),
        (a.http_port, &pk_c, format!("http://127.0.0.1:{}", c.http_port)),
        (b.http_port, &pk_a, format!("http://127.0.0.1:{}", a.http_port)),
        (b.http_port, &pk_c, format!("http://127.0.0.1:{}", c.http_port)),
        (c.http_port, &pk_a, format!("http://127.0.0.1:{}", a.http_port)),
        (c.http_port, &pk_b, format!("http://127.0.0.1:{}", b.http_port)),
    ] {
        json_post(port, "/peers", serde_json::json!({"pubkey": pk, "address": addr}));
    }

    // A→B, B→C, A→C proposals.
    let r1 = json_post(a.http_port, "/propose", serde_json::json!({"counterparty_pubkey": pk_b, "transaction": {"service": "compute"}}));
    eprintln!("A→B completed={}", r1["completed"]);
    std::thread::sleep(Duration::from_millis(500));

    let r2 = json_post(b.http_port, "/propose", serde_json::json!({"counterparty_pubkey": pk_c, "transaction": {"service": "storage"}}));
    eprintln!("B→C completed={}", r2["completed"]);
    std::thread::sleep(Duration::from_millis(500));

    let r3 = json_post(a.http_port, "/propose", serde_json::json!({"counterparty_pubkey": pk_c, "transaction": {"service": "relay"}}));
    eprintln!("A→C completed={}", r3["completed"]);
    std::thread::sleep(Duration::from_millis(500));

    // Verify chains.
    let ca = json_get(a.http_port, &format!("/chain/{pk_a}"))["blocks"].as_array().unwrap().len();
    let cb = json_get(b.http_port, &format!("/chain/{pk_b}"))["blocks"].as_array().unwrap().len();
    let cc = json_get(c.http_port, &format!("/chain/{pk_c}"))["blocks"].as_array().unwrap().len();
    eprintln!("Chains: A={ca}, B={cb}, C={cc}");
    assert!(ca >= 2); assert!(cb >= 2); assert!(cc >= 2);

    // Trust scores.
    let tab = json_get(a.http_port, &format!("/trust/{pk_b}"))["trust_score"].as_f64().unwrap();
    eprintln!("Trust A→B: {tab:.3}");
    assert!(tab >= 0.0);

    eprintln!("=== PASSED ===");
}
