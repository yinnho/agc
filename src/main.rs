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
// 借用轮 ticket/materials/files 都走单行 JSON，1MB 远不够。
const MAX_LINE_SIZE: usize = 128 * 1024 * 1024; // 128MB

fn next_id() -> i64 {
    NEXT_ID.fetch_add(1, Ordering::SeqCst)
}

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64_TABLE[(n >> 18) as usize & 63] as char);
        out.push(B64_TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64_TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64_TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    fn val(c: u8) -> anyhow::Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => anyhow::bail!("invalid base64 byte {c:#x}"),
        }
    }
    let clean: Vec<u8> = s.bytes().filter(|b| !b" \n\r\t".contains(b)).collect();
    let clean = match clean.iter().position(|&b| b == b'=') {
        Some(i) => clean[..i].to_vec(),
        None => clean,
    };
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        if chunk.len() < 2 {
            anyhow::bail!("truncated base64");
        }
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
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

    /// 借用轮：session ticket JSON 文件路径（进/出；配合 --save-ticket 实现跨轮连续）
    #[arg(long)]
    ticket: Option<String>,

    /// 借用轮：把响应里更新的 ticket 写到该文件（下一轮 --ticket 回喂）
    #[arg(long)]
    save_ticket: Option<String>,

    /// 借用轮素材，格式 name=path（可多次）；内容 base64 后随 prompt 上行
    #[arg(long = "material")]
    materials: Vec<String>,

    /// 借用轮回传产物落盘目录（agent 产出的 files 写到这里）
    #[arg(long)]
    files_dir: Option<String>,

    /// 借用轮显式 flow 名
    #[arg(long)]
    flow: Option<String>,

    /// 借用者身份（网关无鉴权时采信此值做 friends 名单门；也可用 AGC_BORROWER env）
    #[arg(long)]
    borrower: Option<String>,

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
        // Dial the bare relay host (tls_domain), not the id-prefixed
        // `<id>.relay.<domain>` name: the relay routes by the `connect`
        // message's target id, so the subdomain never needs DNS resolution.
        // In direct mode tls_domain == relay_host, so this is unchanged there.
        let stream = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((parsed.tls_domain.as_str(), parsed.port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout to {}:{}", parsed.tls_domain, parsed.port))??;

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
    async fn prompt(
        &mut self,
        agent: Option<&str>,
        message: &str,
        cwd: Option<&str>,
        ticket: Option<serde_json::Value>,
        materials: serde_json::Value,
        flow: Option<String>,
        borrower: Option<String>,
    ) -> anyhow::Result<Value> {
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
        if let Some(t) = ticket {
            params["sessionTicket"] = t;
        }
        if materials.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
            params["materials"] = materials;
        }
        if let Some(f) = flow {
            params["activeFlow"] = json!(f);
        }
        if let Some(b) = borrower {
            params["borrower"] = json!(b);
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
                let mut out = json!({
                    "stopReason": result.get("stopReason").unwrap_or(&json!("endTurn")),
                    "text": text_parts.join(""),
                    "sessionId": result.get("sessionId").unwrap_or(&json!(null))
                });
                // 借用轮：更新后的票据与回传产物随最终响应带回。
                if let Some(t) = result.get("sessionTicket") {
                    out["sessionTicket"] = t.clone();
                }
                if let Some(f) = result.get("files") {
                    out["files"] = f.clone();
                }
                return Ok(out);
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

    // 借用轮参数装配：ticket 文件读入、素材 name=path 读文件并 base64。
    let ticket_val = match &cli.ticket {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("Failed to read ticket file {path}: {e}"))?;
            Some(serde_json::from_str::<Value>(&raw)
                .map_err(|e| anyhow::anyhow!("Ticket file {path} is not valid JSON: {e}"))?)
        }
        None => None,
    };
    let mut mats = Vec::new();
    use std::io::Read as _;
    for spec in &cli.materials {
        let (name, path) = spec.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("--material expects name=path, got: {spec}")
        })?;
        let mut content = Vec::new();
        std::fs::File::open(path)
            .and_then(|mut f| f.read_to_end(&mut content))
            .map_err(|e| anyhow::anyhow!("Failed to read material {path}: {e}"))?;
        mats.push(json!({
            "name": name,
            "contentBase64": base64_encode(&content),
        }));
    }

    if cli.verbose {
        eprintln!("[agc] Sending prompt...");
    }

    let borrower = cli
        .borrower
        .clone()
        .or_else(|| std::env::var("AGC_BORROWER").ok().filter(|v| !v.is_empty()));
    let result = conn
        .prompt(
            parsed.agent.as_deref(),
            &message,
            cli.cwd.as_deref(),
            ticket_val,
            json!(mats),
            cli.flow.clone(),
            borrower,
        )
        .await?;

    // 借用轮回执：保存更新后的票据、落盘回传产物。
    if let (Some(path), Some(t)) = (&cli.save_ticket, result.get("sessionTicket")) {
        std::fs::write(path, serde_json::to_string_pretty(t)?)
            .map_err(|e| anyhow::anyhow!("Failed to save ticket to {path}: {e}"))?;
        if cli.verbose {
            eprintln!("[agc] Ticket saved to {path}");
        }
    }
    if let Some(dir) = &cli.files_dir {
        if let Some(files) = result.get("files").and_then(|f| f.as_array()) {
            std::fs::create_dir_all(dir)?;
            for f in files {
                let Some(name) = f.get("name").and_then(|n| n.as_str()) else { continue };
                let Some(b64) = f.get("contentBase64").and_then(|c| c.as_str()) else { continue };
                // Sanitize: no separators/parent refs in returned names.
                if name.contains("..") || name.starts_with('/') || name.contains('\\') {
                    eprintln!("[agc] Skipping file with unsafe name: {name}");
                    continue;
                }
                let dest = std::path::Path::new(dir).join(name);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                match base64_decode(b64) {
                    Ok(bytes) => {
                        std::fs::write(&dest, &bytes)?;
                        eprintln!("[agc] File saved: {}", dest.display());
                    }
                    Err(e) => eprintln!("[agc] Failed to decode {name}: {e}"),
                }
            }
        }
    }

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
