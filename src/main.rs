mod url;

use std::io::Write;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use url::AgentUrl;

static NEXT_ID: AtomicI64 = AtomicI64::new(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const RPC_TIMEOUT: Duration = Duration::from_secs(120);

fn next_id() -> i64 {
    NEXT_ID.fetch_add(1, Ordering::SeqCst)
}

// ── CLI ──

#[derive(Parser)]
#[command(name = "agc", about = "Agent protocol client — curl for agent://")]
struct Cli {
    /// agent:// URL (e.g. agent://id.relay.example.com/claude)
    url: String,

    /// Message to send (use -- before message if it starts with -)
    message: Option<String>,

    /// Auth token (prefer AGC_TOKEN env var or --token-file for security)
    #[arg(short, long)]
    token: Option<String>,

    /// Read auth token from file
    #[arg(long)]
    token_file: Option<String>,

    /// Relay secret token (prefer AGC_RELAY_SECRET env var)
    #[arg(long)]
    relay_secret: Option<String>,

    /// Working directory for the session
    #[arg(short, long)]
    cwd: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

// ── Connection ──

enum Connection {
    Tls {
        reader: BufReader<ReadHalf<TlsStream<TcpStream>>>,
        writer: WriteHalf<TlsStream<TcpStream>>,
    },
    Tcp {
        reader: BufReader<ReadHalf<TcpStream>>,
        writer: WriteHalf<TcpStream>,
    },
}

impl Connection {
    async fn connect(parsed: &AgentUrl) -> anyhow::Result<Self> {
        let stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((parsed.relay_host.as_str(), parsed.port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout to {}:{}", parsed.relay_host, parsed.port))??;

        let mut conn = if parsed.use_tls {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_store)
            .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let domain = rustls_pki_types::ServerName::try_from(parsed.tls_domain.clone())
                .map_err(|e| anyhow::anyhow!("Invalid TLS domain: {}", e))?;
            let tls_stream = connector.connect(domain, stream).await?;
            let (r, w) = tokio::io::split(tls_stream);
            Connection::Tls {
                reader: BufReader::new(r),
                writer: w,
            }
        } else {
            let (r, w) = tokio::io::split(stream);
            Connection::Tcp {
                reader: BufReader::new(r),
                writer: w,
            }
        };

        // Relay handshake
        if let Some(ref target) = parsed.relay_target {
            let mut connect_msg = json!({
                "type": "connect",
                "target": target
            });
            if let Some(ref token) = parsed.relay_token {
                connect_msg["token"] = json!(token);
            }
            conn.send(connect_msg).await?;
            let resp = conn.recv().await?;
            match resp.get("type").and_then(|v| v.as_str()) {
                Some("connected") => {}
                Some("error") => {
                    let msg = resp["message"].as_str().unwrap_or("Unknown relay error");
                    anyhow::bail!("Relay error: {}", msg);
                }
                other => anyhow::bail!("Unexpected relay response: {:?}", other),
            }
        }

        Ok(conn)
    }

    /// Send initialize handshake (with optional auth token)
    async fn initialize(&mut self, token: Option<&str>) -> anyhow::Result<Value> {
        let id = next_id();

        let mut params = json!({
            "protocolVersion": "0.1.0",
            "clientInfo": {"name": "agc", "version": "0.2.0"}
        });

        if let Some(token) = token {
            params["_meta"] = json!({"authToken": token});
        }

        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": params
        }))
        .await?;

        let resp = tokio::time::timeout(RPC_TIMEOUT, self.recv())
            .await
            .map_err(|_| anyhow::anyhow!("Timeout waiting for initialize response"))??;

        if let Some(error) = resp.get("error") {
            if !error.is_null() {
                let msg = error["message"].as_str().unwrap_or("Unknown error");
                anyhow::bail!("Initialize error: {}", msg);
            }
        }

        Ok(resp)
    }

    async fn send(&mut self, msg: Value) -> anyhow::Result<()> {
        let mut data = serde_json::to_string(&msg)?;
        data.push('\n');
        match self {
            Connection::Tls { writer, .. } => {
                writer.write_all(data.as_bytes()).await?;
                writer.flush().await?;
            }
            Connection::Tcp { writer, .. } => {
                writer.write_all(data.as_bytes()).await?;
                writer.flush().await?;
            }
        }
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<Value> {
        loop {
            let line = match self {
                Connection::Tls { reader, .. } => read_line(reader).await?,
                Connection::Tcp { reader, .. } => read_line(reader).await?,
            };
            let line = match line {
                Some(l) => l,
                None => anyhow::bail!("Connection closed"),
            };
            if line.is_empty() {
                continue;
            }
            // Skip ping/pong heartbeats
            if let Ok(val) = serde_json::from_str::<Value>(&line) {
                match val.get("type").and_then(|v| v.as_str()) {
                    Some("ping") | Some("pong") => continue,
                    _ => return Ok(val),
                }
            } else {
                continue;
            }
        }
    }

    /// Send a prompt and collect streaming response
    async fn prompt(&mut self, agent: Option<&str>, message: &str, cwd: Option<&str>) -> anyhow::Result<Value> {
        let id = next_id();

        let mut params = json!({
            "message": message
        });

        if let Some(agent) = agent {
            params["agent"] = json!(agent);
        }
        if let Some(cwd) = cwd {
            params["cwd"] = json!(cwd);
        }

        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "prompt",
            "params": params
        }))
        .await?;

        let mut text_parts: Vec<String> = Vec::new();

        loop {
            let resp = tokio::time::timeout(RPC_TIMEOUT, self.recv())
                .await
                .map_err(|_| anyhow::anyhow!("Timeout waiting for response"))??;

            // Error response
            if let Some(error) = resp.get("error") {
                if !error.is_null() {
                    let msg = error["message"].as_str().unwrap_or("Unknown error");
                    let code = error["code"].as_i64().unwrap_or(0);
                    anyhow::bail!("Error ({}): {}", code, msg);
                }
            }

            // Final response: has result with stopReason, or has matching id
            let is_final = resp.get("result")
                .and_then(|r| r.get("stopReason"))
                .is_some()
                || resp.get("id").and_then(|v| v.as_i64()) == Some(id);

            if is_final {
                let result = resp.get("result").cloned().unwrap_or(json!({}));
                return Ok(json!({
                    "stopReason": result.get("stopReason").unwrap_or(&json!("endTurn")),
                    "text": text_parts.join(""),
                    "sessionId": result.get("sessionId").unwrap_or(&json!(null))
                }));
            }

            // Collect chunk notifications (only for our session)
            if resp.get("method").and_then(|v| v.as_str()) == Some("sessionUpdate") {
                if let Some(text) = resp.pointer("/params/update/content/text").and_then(|v| v.as_str()) {
                    text_parts.push(text.to_string());
                    print!("{}", text);
                    std::io::stdout().flush()?;
                }
            } else if resp.get("method").and_then(|v| v.as_str()) == Some("chunk") {
                // Legacy chunk format — notifications carry no id; accept those
                // (single-prompt CLI) or ones explicitly tagged with our id.
                let tagged = resp.get("id").and_then(|v| v.as_i64());
                if tagged.is_none() || tagged == Some(id) {
                    if let Some(text) = resp.pointer("/params/text").and_then(|v| v.as_str()) {
                        text_parts.push(text.to_string());
                        print!("{}", text);
                        std::io::stdout().flush()?;
                    }
                }
            }
        }
    }
}

const MAX_LINE_SIZE: usize = 1024 * 1024; // 1MB

async fn read_line<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> anyhow::Result<Option<String>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    if line.len() > MAX_LINE_SIZE {
        anyhow::bail!("Line too long ({} bytes, max {})", line.len(), MAX_LINE_SIZE);
    }
    Ok(Some(line.trim().to_string()))
}

// ── Main ──

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut parsed = AgentUrl::parse(&cli.url)?;

    // Resolve relay secret: AGC_RELAY_SECRET env > --relay-secret
    if std::env::var("AGC_RELAY_SECRET").map(|s| !s.is_empty()).unwrap_or(false) {
        parsed.relay_token = Some(std::env::var("AGC_RELAY_SECRET").unwrap());
    } else if let Some(ref secret) = cli.relay_secret {
        parsed.relay_token = Some(secret.clone());
    }

    // Resolve token: --token-file > AGC_TOKEN env > --token (least secure, visible in ps)
    let token = if let Some(ref path) = cli.token_file {
        Some(std::fs::read_to_string(path)?.trim().to_string())
    } else if let Ok(t) = std::env::var("AGC_TOKEN") {
        if !t.is_empty() { Some(t) } else { None }
    } else {
        cli.token.clone()
    };

    // Warn if sending token over plaintext connection
    if token.is_some() && !parsed.use_tls {
        eprintln!("[agc] Warning: sending auth token over unencrypted connection");
    }

    if cli.verbose {
        eprintln!("[agc] Connecting to {}", parsed);
    }

    let mut conn = Connection::connect(&parsed).await?;

    // Initialize with optional auth token
    if cli.verbose {
        eprintln!("[agc] Initializing...");
    }
    conn.initialize(token.as_deref()).await?;

    // Get message
    let message = match cli.message {
        Some(msg) => msg,
        None => {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    if message.is_empty() {
        anyhow::bail!("No message provided");
    }

    if cli.verbose {
        eprintln!("[agc] Sending prompt...");
    }

    let result = conn
        .prompt(
            parsed.agent.as_deref(),
            &message,
            cli.cwd.as_deref(),
        )
        .await?;

    // Trailing newline
    if let Some(text) = result.get("text").and_then(|v| v.as_str()) {
        if !text.ends_with('\n') {
            println!();
        }
    } else {
        println!();
    }

    Ok(())
}
