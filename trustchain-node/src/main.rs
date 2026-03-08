//! TrustChain Node — standalone binary for running a TrustChain node.

mod config;
mod node;

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use trustchain_core::Identity;

use crate::config::NodeConfig;
use crate::node::Node;

#[derive(Parser)]
#[command(name = "trustchain-node")]
#[command(about = "TrustChain — decentralized trust substrate for the AI agent economy")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 identity keypair.
    Keygen {
        /// Output path for the private key file.
        #[arg(short, long, default_value = "identity.key")]
        output: String,
    },

    /// Start the TrustChain node.
    Run {
        /// Path to TOML configuration file.
        #[arg(short, long, default_value = "node.toml")]
        config: String,
    },

    /// Run MCP server over stdio for local LLM hosts (Claude Desktop, Cursor, etc.).
    #[cfg(feature = "mcp")]
    McpStdio {
        /// Agent name (used for data directory: ~/.trustchain/<name>/).
        #[arg(long, default_value = "trustchain")]
        name: String,

        /// Data directory override. Defaults to ~/.trustchain/<name>/.
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Run as a sidecar next to an agent — one command to join the trust network.
    ///
    /// Generates identity, starts all services (QUIC, gRPC, HTTP, proxy),
    /// and prints the HTTP_PROXY env var for the agent to use.
    Sidecar {
        /// Agent name (used for data directory: ~/.trustchain/<name>/).
        #[arg(long)]
        name: String,

        /// The agent's own HTTP endpoint (e.g. http://localhost:8080).
        #[arg(long)]
        endpoint: String,

        /// Base port for services. QUIC=base, gRPC=base+1, HTTP=base+2, proxy=base+3.
        #[arg(long, default_value = "8200")]
        port_base: u16,

        /// Bootstrap peer addresses (comma-separated HTTP addresses).
        #[arg(long, value_delimiter = ',')]
        bootstrap: Vec<String>,

        /// Public HTTP address to advertise to other nodes.
        /// Required on public servers: e.g. http://203.0.113.5:8202
        /// If omitted, STUN discovery is attempted automatically.
        #[arg(long)]
        advertise: Option<String>,

        /// Data directory. Defaults to ~/.trustchain/<name>/.
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Log level.
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Audit recording level: minimal, standard (default), comprehensive.
        #[arg(long, default_value = "standard")]
        audit_mode: String,

        /// Disable networking (QUIC, gossip, STUN). Pure audit-only sidecar.
        #[arg(long)]
        no_networking: bool,
    },

    /// Launch an app with a TrustChain sidecar (Dapr-style).
    ///
    /// Starts the sidecar, waits for /healthz, sets HTTP_PROXY, then launches
    /// the given command. On app exit the sidecar shuts down automatically.
    ///
    /// Example: trustchain-node launch --name my-agent -- python my_agent.py
    Launch {
        /// Agent name (used for data directory: ~/.trustchain/<name>/).
        #[arg(long)]
        name: String,

        /// The agent's own HTTP endpoint (e.g. http://localhost:8080).
        #[arg(long, default_value = "http://localhost:8080")]
        endpoint: String,

        /// Base port for services. QUIC=base, gRPC=base+1, HTTP=base+2, proxy=base+3.
        #[arg(long, default_value = "8200")]
        port_base: u16,

        /// Bootstrap peer addresses (comma-separated HTTP addresses).
        #[arg(long, value_delimiter = ',')]
        bootstrap: Vec<String>,

        /// Public HTTP address to advertise to other nodes.
        #[arg(long)]
        advertise: Option<String>,

        /// Data directory. Defaults to ~/.trustchain/<name>/.
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Log level.
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Audit recording level: minimal, standard (default), comprehensive.
        #[arg(long, default_value = "standard")]
        audit_mode: String,

        /// Disable networking (QUIC, gossip, STUN). Pure audit-only sidecar.
        #[arg(long)]
        no_networking: bool,

        /// The command and arguments to launch (after --).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Query a running node's status.
    Status {
        /// HTTP address of the peer to query.
        #[arg(short, long, default_value = "http://127.0.0.1:8202")]
        peer: String,
    },

    /// Send a proposal to a peer.
    Propose {
        /// Public key of the counterparty.
        #[arg(long)]
        peer: String,

        /// Transaction payload as JSON.
        #[arg(long)]
        tx: String,

        /// HTTP address of our own node.
        #[arg(long, default_value = "http://127.0.0.1:8202")]
        node: String,
    },

    /// Print default configuration.
    InitConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => {
            let identity = Identity::generate();
            identity.save(&output)?;
            println!("Generated Ed25519 identity:");
            println!("  Public key: {}", identity.pubkey_hex());
            println!("  Saved to:   {output}");
        }

        Commands::Run {
            config: config_path,
        } => {
            let config = if std::path::Path::new(&config_path).exists() {
                NodeConfig::load(&config_path)?
            } else {
                tracing::info!("No config file found, using defaults");
                NodeConfig::default()
            };

            // Set up tracing/logging.
            let filter = tracing_subscriber::EnvFilter::try_new(&config.log_level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            tracing_subscriber::fmt().with_env_filter(filter).init();

            // Load or generate identity.
            let identity = if config.key_path.exists() {
                let id = Identity::load(&config.key_path)?;
                tracing::info!(pubkey = %id.pubkey_hex(), "loaded identity");
                id
            } else {
                let id = Identity::generate();
                id.save(&config.key_path)?;
                tracing::info!(pubkey = %id.pubkey_hex(), "generated new identity");
                id
            };

            let node = Node::new(identity, config);
            node.run().await?;
        }

        #[cfg(feature = "mcp")]
        Commands::McpStdio { name, data_dir } => {
            let dir = data_dir.unwrap_or_else(|| {
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".trustchain").join(&name)
            });
            std::fs::create_dir_all(&dir).ok();

            let key_path = dir.join("identity.key");
            let identity = if key_path.exists() {
                Identity::load(&key_path)?
            } else {
                let id = Identity::generate();
                id.save(&key_path)?;
                eprintln!("Generated identity: {}", id.pubkey_hex());
                id
            };

            let db_path = dir.join("trustchain.db");
            let store = trustchain_core::SqliteBlockStore::open(&db_path)
                .map_err(|e| anyhow::anyhow!("Failed to open database: {e}"))?;
            let protocol = trustchain_core::TrustChainProtocol::new(identity.clone(), store);
            let discovery = trustchain_transport::PeerDiscovery::new(identity.pubkey_hex(), vec![]);

            trustchain_transport::mcp::run_mcp_stdio(
                std::sync::Arc::new(tokio::sync::Mutex::new(protocol)),
                std::sync::Arc::new(discovery),
                vec![], // stdio mode: no seed nodes configured (user passes via config)
            )
            .await?;
        }

        Commands::Sidecar {
            name,
            endpoint,
            port_base,
            bootstrap,
            advertise,
            data_dir,
            log_level,
            audit_mode,
            no_networking,
        } => {
            // Resolve data directory: --data-dir or ~/.trustchain/<name>/
            let data_dir = data_dir.unwrap_or_else(|| {
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".trustchain").join(&name)
            });

            // Create data directory.
            std::fs::create_dir_all(&data_dir)?;

            // Set up tracing/logging.
            let filter = tracing_subscriber::EnvFilter::try_new(&log_level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            tracing_subscriber::fmt().with_env_filter(filter).init();

            // Load or generate identity.
            let key_path = data_dir.join("identity.key");
            let identity = if key_path.exists() {
                let id = Identity::load(&key_path)?;
                tracing::info!(pubkey = %id.pubkey_hex(), "loaded identity");
                id
            } else {
                let id = Identity::generate();
                id.save(&key_path)?;
                tracing::info!(pubkey = %id.pubkey_hex(), "generated new identity");
                id
            };

            // Build config from CLI args.
            let config = NodeConfig {
                quic_addr: format!("0.0.0.0:{}", port_base),
                grpc_addr: format!("0.0.0.0:{}", port_base + 1),
                http_addr: format!("0.0.0.0:{}", port_base + 2),
                proxy_addr: format!("127.0.0.1:{}", port_base + 3),
                key_path,
                db_path: data_dir.join("trustchain.db"),
                bootstrap_nodes: bootstrap,
                agent_name: Some(name.clone()),
                agent_endpoint: Some(endpoint.clone()),
                advertise_addr: advertise,
                audit_level: Some(audit_mode.clone()),
                no_networking,
                ..NodeConfig::default()
            };

            // Print banner.
            let pubkey = identity.pubkey_hex();
            let mode_label = if no_networking {
                format!("{audit_mode} (offline)")
            } else {
                audit_mode
            };
            println!();
            println!("  TrustChain Sidecar");
            println!("  ──────────────────────────────────────────");
            println!("  Agent:     {name}");
            println!("  Endpoint:  {endpoint}");
            println!("  Audit:     {mode_label}");
            println!("  Public key: {pubkey}");
            println!("  Data dir:  {}", data_dir.display());
            println!();
            println!("  QUIC:   0.0.0.0:{}", port_base);
            println!("  gRPC:   0.0.0.0:{}", port_base + 1);
            println!("  HTTP:   0.0.0.0:{}", port_base + 2);
            println!("  Proxy:  127.0.0.1:{}", port_base + 3);
            println!();
            println!("  Set this in your agent's environment:");
            println!("    export HTTP_PROXY=http://127.0.0.1:{}", port_base + 3);
            println!("  ──────────────────────────────────────────");
            println!();

            let node = Node::new(identity, config);
            if no_networking {
                node.run_audit_only().await?;
            } else {
                node.run().await?;
            }
        }

        Commands::Launch {
            name,
            endpoint,
            port_base,
            bootstrap,
            advertise,
            data_dir,
            log_level,
            audit_mode,
            no_networking,
            command,
        } => {
            // Resolve data directory.
            let data_dir = data_dir.unwrap_or_else(|| {
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".trustchain").join(&name)
            });
            std::fs::create_dir_all(&data_dir)?;

            // Set up tracing/logging.
            let filter = tracing_subscriber::EnvFilter::try_new(&log_level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            tracing_subscriber::fmt().with_env_filter(filter).init();

            // Load or generate identity.
            let key_path = data_dir.join("identity.key");
            let identity = if key_path.exists() {
                let id = Identity::load(&key_path)?;
                tracing::info!(pubkey = %id.pubkey_hex(), "loaded identity");
                id
            } else {
                let id = Identity::generate();
                id.save(&key_path)?;
                tracing::info!(pubkey = %id.pubkey_hex(), "generated new identity");
                id
            };

            let proxy_addr = format!("127.0.0.1:{}", port_base + 3);
            let http_addr = format!("127.0.0.1:{}", port_base + 2);

            let config = NodeConfig {
                quic_addr: format!("0.0.0.0:{}", port_base),
                grpc_addr: format!("0.0.0.0:{}", port_base + 1),
                http_addr: format!("0.0.0.0:{}", port_base + 2),
                proxy_addr: proxy_addr.clone(),
                key_path,
                db_path: data_dir.join("trustchain.db"),
                bootstrap_nodes: bootstrap,
                agent_name: Some(name.clone()),
                agent_endpoint: Some(endpoint.clone()),
                advertise_addr: advertise,
                audit_level: Some(audit_mode.clone()),
                no_networking,
                ..NodeConfig::default()
            };

            let pubkey = identity.pubkey_hex();
            let mode_label = if no_networking {
                format!("{audit_mode} (offline)")
            } else {
                audit_mode
            };
            println!();
            println!("  TrustChain Launch");
            println!("  ──────────────────────────────────────────");
            println!("  Agent:      {name}");
            println!("  Endpoint:   {endpoint}");
            println!("  Audit:      {mode_label}");
            println!("  Public key: {pubkey}");
            println!("  Command:    {}", command.join(" "));
            println!("  ──────────────────────────────────────────");
            println!();

            // Start sidecar in background.
            let node = Node::new(identity, config);
            let run_no_net = no_networking;
            let node_handle = tokio::spawn(async move {
                let result = if run_no_net {
                    node.run_audit_only().await
                } else {
                    node.run().await
                };
                if let Err(e) = result {
                    tracing::error!("Sidecar error: {e}");
                }
            });

            // Wait for /healthz (poll up to 30 seconds).
            let healthz_url = format!("http://{http_addr}/healthz");
            let client = reqwest::Client::new();
            let mut ready = false;
            for _ in 0..60 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if let Ok(resp) = client.get(&healthz_url).send().await {
                    if resp.status().is_success() {
                        ready = true;
                        break;
                    }
                }
            }
            if !ready {
                anyhow::bail!("Sidecar did not become ready within 30 seconds");
            }
            tracing::info!("Sidecar ready — launching app");

            // Launch the user's application with HTTP_PROXY set.
            let mut child = std::process::Command::new(&command[0])
                .args(&command[1..])
                .env("HTTP_PROXY", format!("http://{proxy_addr}"))
                .env("TRUSTCHAIN_PUBKEY", &pubkey)
                .env("TRUSTCHAIN_HTTP", format!("http://{http_addr}"))
                .spawn()?;

            let status = child.wait()?;
            tracing::info!(code = ?status.code(), "App exited");

            // App finished — stop sidecar.
            node_handle.abort();

            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        }

        Commands::Status { peer } => {
            let url = format!("{peer}/status");
            let resp = reqwest::get(&url)
                .await?
                .json::<serde_json::Value>()
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::Propose { peer, tx, node } => {
            let transaction: serde_json::Value = serde_json::from_str(&tx)?;
            let body = serde_json::json!({
                "counterparty_pubkey": peer,
                "transaction": transaction,
            });

            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{node}/propose"))
                .json(&body)
                .send()
                .await?
                .json::<serde_json::Value>()
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::InitConfig => {
            println!("{}", NodeConfig::default_toml());
        }
    }

    Ok(())
}
