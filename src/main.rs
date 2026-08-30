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

    /// Message to send (use -- before message if it starts with -).
    /// 省略时从 stdin 读到 EOF（多行 prompt 完整进入）
    #[arg(verbatim_doc_comment)]
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

    /// Session ID to resume (agent-side conversation, e.g. claude --resume).
    /// First round: omit it, then take the sessionId from the result output
    /// and pass it back here to continue the same conversation.
    #[arg(short, long)]
    session: Option<String>,

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

    /// 主人绑定：配对码（bindDevice → token 入本地钥匙串后退出，不发消息）
    #[arg(long = "bind")]
    bind_code: Option<String>,

    /// --bind 时的设备名（默认 <USER>-agc）
    #[arg(long)]
    device_name: Option<String>,

    /// 访客申请：名字（requestAccess → 轮询等主人同意 → token 入钥匙串后退出）。
    /// agent 范围取 URL 路径后缀（agent://gw/clone-creator 即只申请该分身）
    #[arg(long)]
    request_access: Option<String>,

    /// --request-access 等主人同意的秒数（0 = 只挂单不等待；默认 300）
    #[arg(long, default_value_t = 300)]
    wait_secs: u64,

    /// 忘掉该网关存的 token（吊销/过期/换身份时用）
    #[arg(long)]
    logout: bool,

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

    /// Plain request/response RPC (admin & consent methods — no streaming).
    /// Returns the result object; bails on JSON-RPC error.
    async fn rpc(&mut self, method: &str, params: Value) -> anyhow::Result<Value> {
        let id = next_id();
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))
        .await?;
        loop {
            let resp = tokio::time::timeout(RPC_TIMEOUT, self.recv())
                .await
                .map_err(|_| anyhow::anyhow!("Timeout waiting for {method} response"))??;
            match resp.get("id").and_then(|v| v.as_i64()) {
                Some(rid) if rid == id => {
                    if let Some(error) = resp.get("error") {
                        if !error.is_null() {
                            let msg = error["message"].as_str().unwrap_or("Unknown error");
                            let code = error["code"].as_i64().unwrap_or(0);
                            anyhow::bail!("Error ({}): {}", code, msg);
                        }
                    }
                    return Ok(resp.get("result").cloned().unwrap_or(json!({})));
                }
                // Stray notification (heartbeat etc.) — wait for our reply.
                _ => continue,
            }
        }
    }

    /// bindDevice（ACP.md §2.3）：私有网关主人配对。成功后本连接升 Bound
    /// （网关把新 auth 状态记在 relay client 上），可直接 listAgents 确认。
    async fn bind_device(&mut self, pair_code: &str, device_name: &str) -> anyhow::Result<(String, String)> {
        let result = self
            .rpc("bindDevice", json!({"pairCode": pair_code, "deviceName": device_name}))
            .await?;
        let token = result
            .get("token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow::anyhow!("bindDevice 响应缺 token"))?
            .to_string();
        let name = result
            .get("deviceName")
            .and_then(|d| d.as_str())
            .unwrap_or(device_name)
            .to_string();
        Ok((name, token))
    }

    /// requestAccess（§2.9 访客申请）。返回完整 result（status/…）。
    async fn request_access(&mut self, client_name: &str, agent: Option<&str>) -> anyhow::Result<Value> {
        let mut params = json!({"clientName": client_name});
        if let Some(a) = agent {
            params["agent"] = json!(a);
        }
        self.rpc("requestAccess", params).await
    }

    /// checkAccess（§2.9 访客轮询取票）：approved = 一次性 token，网关销单。
    async fn check_access(&mut self, request_id: &str) -> anyhow::Result<Value> {
        self.rpc("checkAccess", json!({"requestId": request_id})).await
    }

    /// listAgents：确认 token 可用 + 打印可用分身。
    async fn list_agents(&mut self) -> anyhow::Result<Vec<(String, String)>> {
        let result = self.rpc("listAgents", json!({})).await?;
        let agents = result
            .get("agents")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(agents
            .iter()
            .filter_map(|a| {
                let id = a.get("id").and_then(|v| v.as_str())?;
                let name = a.get("name").and_then(|v| v.as_str()).unwrap_or(id);
                Some((id.to_string(), name.to_string()))
            })
            .collect())
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
    #[allow(clippy::too_many_arguments)]
    async fn prompt(
        &mut self,
        agent: Option<&str>,
        message: &str,
        cwd: Option<&str>,
        session_id: Option<&str>,
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
        if let Some(sid) = session_id {
            params["sessionId"] = json!(sid);
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
        // Agent-side session id parsed from the chunk stream (e.g. claude
        // --output-format stream-json emits a final {"type":"result",...}
        // line carrying it). The gateway result only echoes the input param,
        // so real resume ids must come from here.
        let mut stream_session_id: Option<String> = None;

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
                let session_id = stream_session_id
                    .or_else(|| result.get("sessionId").and_then(|v| v.as_str().map(String::from)));
                let mut out = json!({
                    "stopReason": result.get("stopReason").unwrap_or(&json!("endTurn")),
                    "text": text_parts.join(""),
                    "sessionId": session_id
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
                        // Opportunistic session-id harvest from structured
                        // agent output (claude stream-json result line).
                        if stream_session_id.is_none() {
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                                if v.get("type").and_then(|t| t.as_str()) == Some("result") {
                                    if let Some(sid) = v.get("session_id").and_then(|s| s.as_str()) {
                                        if valid_session_id(sid) {
                                            stream_session_id = Some(sid.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        text_parts.push(text.to_string());
                        print!("{}", text);
                        std::io::stdout().flush()?;
                    }
                }
            }
        }
    }
}

/// Same charset gate as the gateway (aginx handler.rs): alphanumeric,
/// hyphen, underscore. Anything else is not a safe session id to echo
/// back into resume args.
fn valid_session_id(sid: &str) -> bool {
    !sid.is_empty()
        && sid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

async fn read_line<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> anyhow::Result<Option<String>> {    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    if line.len() > MAX_LINE_SIZE {
        anyhow::bail!("Line too long ({} bytes, max {})", line.len(), MAX_LINE_SIZE);
    }
    Ok(Some(line.trim().to_string()))
}

// ── 本地钥匙串（per-网关单身份：主人 token 或 访客 token） ──

/// 网关身份键：relay 网关 = target id（跨端口稳定）；直连 = host:port。
fn gateway_key(u: &AgentUrl) -> String {
    match u.relay_target {
        Some(ref t) => t.clone(),
        None => format!("{}:{}", u.relay_host, u.port),
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
struct StoredIdentity {
    /// 网关发的 token（bindDevice Bound token 或同意流 Authorized token）。
    /// None = 只挂了单还没取到票。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    /// 设备名（主人）或访客名
    name: String,
    /// "owner" | "visitor"
    role: String,
    /// 访客挂单 id（wait 超时留下，下次 --request-access 同名续轮）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_request_id: Option<String>,
    saved_at: i64,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
struct TokenStore {
    #[serde(default)]
    gateways: std::collections::BTreeMap<String, StoredIdentity>,
}

impl TokenStore {
    fn path() -> anyhow::Result<std::path::PathBuf> {
        let home = std::env::var("HOME")
            .map_err(|_| anyhow::anyhow!("HOME 未设置，找不到钥匙串路径"))?;
        Ok(std::path::Path::new(&home).join(".aginx/agc/tokens.json"))
    }

    /// 文件缺失/损坏 → 空 store（损坏告警不 panic——钥匙串可重建）。
    fn load() -> Self {
        let Ok(path) = Self::path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
                eprintln!("[agc] 钥匙串损坏（{}），按空处理——旧 token 需重新绑定", e);
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    /// 原子写（tmp+rename）+ 0600 权限。
    fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

fn default_device_name() -> String {
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .map(|u| format!("{u}-agc"))
        .unwrap_or_else(|| "agc".to_string())
}

// ── Main ──

/// 同意流收尾：取票（approved 响应）→ 入钥匙串。
fn finish_consent(
    store: &mut TokenStore,
    gw_key: &str,
    name: &str,
    request_id: &str,
    res: &Value,
    url: &str,
) -> anyhow::Result<()> {
    let token = res
        .get("token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("approved 响应缺 token"))?
        .to_string();
    store.gateways.insert(
        gw_key.to_string(),
        StoredIdentity {
            token: Some(token),
            name: name.to_string(),
            role: "visitor".to_string(),
            pending_request_id: None, // 已销单
            saved_at: TokenStore::now(),
        },
    );
    store.save()?;
    eprintln!("[agc] 主人已同意，取票成功（挂单 {request_id} 已销），token 已入 {}", TokenStore::path()?.display());
    eprintln!("[agc] 现在可以直接对话：agc {url} <消息>");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `agc ask <url> …` 兼容（CARRIER.md §3.4-2 的命令字面）：剥掉裸 `ask`
    // 前缀再交给 clap——子命令糖不动 Cli 形状，`agc <url>` 原样可用。
    let mut argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("ask") {
        argv.remove(1);
    }
    let cli = Cli::parse_from(argv);
    let mut parsed = AgentUrl::parse(&cli.url)?;

    // Resolve relay secret: AGC_RELAY_SECRET env > --relay-secret
    if std::env::var("AGC_RELAY_SECRET").map(|s| !s.is_empty()).unwrap_or(false) {
        parsed.relay_token = Some(std::env::var("AGC_RELAY_SECRET").unwrap());
    } else if let Some(ref secret) = cli.relay_secret {
        parsed.relay_token = Some(secret.clone());
    }

    // Resolve token: --token-file > AGC_TOKEN env > --token (least secure, visible in ps)
    let explicit_token = if let Some(ref path) = cli.token_file {
        Some(std::fs::read_to_string(path)?.trim().to_string())
    } else if let Ok(t) = std::env::var("AGC_TOKEN") {
        if !t.is_empty() { Some(t) } else { None }
    } else {
        cli.token.clone()
    };

    // ── 钥匙串：per-网关身份（bind/同意流的产物） ──
    let gw_key = gateway_key(&parsed);
    let mut store = TokenStore::load();

    if cli.logout {
        match store.gateways.remove(&gw_key) {
            Some(old) => {
                store.save()?;
                eprintln!("[agc] 已忘掉 {gw_key}（{}·{}）的 token", old.role, old.name);
            }
            None => eprintln!("[agc] {gw_key} 本来就没存 token"),
        }
        return Ok(());
    }

    if cli.bind_code.is_some() && cli.request_access.is_some() {
        anyhow::bail!("--bind 与 --request-access 二选一");
    }

    // Warn if sending token over plaintext connection
    if explicit_token.is_some() && !parsed.use_tls {
        eprintln!("[agc] Warning: sending auth token over unencrypted connection");
    }

    if cli.verbose {
        eprintln!("[agc] Connecting to {}", parsed);
    }

    // ── 绑定流：bindDevice → token 入钥匙串 ──
    if let Some(code) = cli.bind_code.clone() {
        let device = cli.device_name.clone().unwrap_or_else(default_device_name);
        let mut conn = Connection::connect(&parsed).await?;
        conn.initialize(None).await?;
        let (bound_name, token) = conn.bind_device(&code, &device).await?;
        // 本连接已升 Bound——直接 listAgents 确认 token 可用
        let agents = conn.list_agents().await?;
        store.gateways.insert(
            gw_key.clone(),
            StoredIdentity {
                token: Some(token),
                name: bound_name.clone(),
                role: "owner".to_string(),
                pending_request_id: None,
                saved_at: TokenStore::now(),
            },
        );
        store.save()?;
        eprintln!("[agc] 绑定成功：{gw_key} · {bound_name}（token 已入 {}）", TokenStore::path()?.display());
        eprintln!("[agc] 可用分身：{}", agents.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>().join(", "));
        eprintln!("[agc] 现在可以直接对话：agc {} <消息>", cli.url);
        return Ok(());
    }

    // ── 同意流：requestAccess → 轮询等主人同意 → 取票入钥匙串 ──
    if let Some(name) = cli.request_access.clone() {
        let mut conn = Connection::connect(&parsed).await?;
        conn.initialize(None).await?;
        let scope = parsed.agent.clone(); // 客服码后缀 = URL 路径 agent

        // 上次同名挂单还在？先续轮（approved 直接取票；notFound 才重新挂）
        let mut request_id: Option<String> = None;
        let prev = store.gateways.get(&gw_key).cloned();
        if let Some(prev) = prev {
            if prev.role == "visitor" && prev.name == name {
                if let Some(rid) = &prev.pending_request_id {
                    let res = conn.check_access(rid).await?;
                    match res.get("status").and_then(|s| s.as_str()) {
                        Some("approved") => {
                            finish_consent(&mut store, &gw_key, &name, rid, &res, &cli.url)?;
                            return Ok(());
                        }
                        Some("pending") => request_id = Some(rid.clone()),
                        _ => {} // notFound：被拒/过期 → 走新挂单
                    }
                }
            }
        }

        if request_id.is_none() {
            let res = conn.request_access(&name, scope.as_deref()).await?;
            match res.get("status").and_then(|s| s.as_str()) {
                Some("approved") => {
                    // auto_approve 网关：即申即得，无 requestId
                    store.gateways.insert(
                        gw_key.clone(),
                        StoredIdentity {
                            token: res.get("token").and_then(|t| t.as_str()).map(String::from),
                            name: name.clone(),
                            role: "visitor".to_string(),
                            pending_request_id: None,
                            saved_at: TokenStore::now(),
                        },
                    );
                    store.save()?;
                    eprintln!("[agc] 即时授权（auto_approve 网关），token 已入 {}]", TokenStore::path()?.display());
                    eprintln!("[agc] 现在可以直接对话：agc {} <消息>", cli.url);
                    return Ok(());
                }
                Some("pending") => {
                    request_id = res
                        .get("requestId")
                        .and_then(|r| r.as_str())
                        .map(String::from);
                }
                other => anyhow::bail!("requestAccess 未知状态: {other:?}"),
            }
        }
        let Some(request_id) = request_id else {
            anyhow::bail!("pending 响应缺 requestId");
        };

        if cli.wait_secs == 0 {
            store.gateways.insert(
                gw_key.clone(),
                StoredIdentity {
                    token: None,
                    name: name.clone(),
                    role: "visitor".to_string(),
                    pending_request_id: Some(request_id),
                    saved_at: TokenStore::now(),
                },
            );
            store.save()?;
            eprintln!("[agc] 已挂单（{}·{name}，24h 内有效）。主人同意后重跑本命令取票：", gw_key);
            eprintln!("[agc]   agc {} --request-access {name} --wait-secs 600", cli.url);
            return Ok(());
        }

        eprintln!("[agc] 已挂单，等主人同意（最多 {}s，Ctrl-C 放弃不销单）…", cli.wait_secs);
        let deadline = std::time::Instant::now() + Duration::from_secs(cli.wait_secs);
        loop {
            if std::time::Instant::now() >= deadline {
                store.gateways.insert(
                    gw_key.clone(),
                    StoredIdentity {
                        token: None,
                        name: name.clone(),
                        role: "visitor".to_string(),
                        pending_request_id: Some(request_id.clone()),
                        saved_at: TokenStore::now(),
                    },
                );
                store.save()?;
                anyhow::bail!("等待超时（{}s）。挂单仍在——主人同意后重跑本命令取票", cli.wait_secs);
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            let res = conn.check_access(&request_id).await?;
            match res.get("status").and_then(|s| s.as_str()) {
                Some("approved") => {
                    finish_consent(&mut store, &gw_key, &name, &request_id, &res, &cli.url)?;
                    return Ok(());
                }
                Some("pending") => continue,
                Some("notFound") => anyhow::bail!("申请被拒或已过期（网关不区分两者）"),
                other => anyhow::bail!("checkAccess 未知状态: {other:?}"),
            }
        }
    }

    // ── 普通对话轮：token = 显式来源 > 钥匙串 ──
    let stored = store.gateways.get(&gw_key).cloned();
    let used_stored_token =
        explicit_token.is_none() && stored.as_ref().is_some_and(|s| s.token.is_some());
    let token = explicit_token.or_else(|| stored.as_ref().and_then(|s| s.token.clone()));
    if used_stored_token {
        if cli.verbose {
            eprintln!("[agc] 用钥匙串 token（{}·{}）from {}", stored.as_ref().unwrap().role, stored.as_ref().unwrap().name, TokenStore::path()?.display());
        }
        if !parsed.use_tls {
            eprintln!("[agc] Warning: sending auth token over unencrypted connection");
        }
    }

    let mut conn = Connection::connect(&parsed).await?;

    // Initialize with optional auth token
    if cli.verbose {
        eprintln!("[agc] Initializing...");
    }
    let init_resp = conn.initialize(token.as_deref()).await?;
    // 钥匙串 token 被网关拒（吊销/过期）→ 明说，别等 prompt 才炸
    if used_stored_token {
        let authed = init_resp
            .pointer("/result/authenticated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !authed {
            anyhow::bail!(
                "钥匙串里的 token 已失效（被吊销或过期）。清掉重来：\n  agc {} --logout\n  agc {} --request-access <名字>   # 或 --bind <配对码>",
                cli.url, cli.url
            );
        }
    }

    // Get message: 参数优先；否则 stdin **读到 EOF**（多行 prompt 不截断，
    // 管道/heredoc 自然闭合；交互终端单行用 Ctrl-D 结束）。
    let message = match cli.message {
        Some(msg) => msg,
        None => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
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
        None => {
            // 借用信号在但没带票据：自动用空票据开局，让第一轮就走无状态
            // 借道路径（sessionTicket 参数在场即触发）。否则首轮落进服务器
            // 持久 session，违背"借用者零持久化"。
            let env_borrower =
                std::env::var("AGC_BORROWER").map(|s| !s.is_empty()).unwrap_or(false);
            if cli.borrower.is_some() || env_borrower || !cli.materials.is_empty() {
                Some(json!({
                    "version": 1,
                    "label": null,
                    "messages": [],
                    "turnSummaries": []
                }))
            } else {
                None
            }
        }
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
    let result = match conn
        .prompt(
            parsed.agent.as_deref(),
            &message,
            cli.cwd.as_deref(),
            cli.session.as_deref(),
            ticket_val,
            json!(mats),
            cli.flow.clone(),
            borrower,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // 私有网关裸敲 URL 的经典死法——把两条活路指出来
            if e.to_string().contains("Authentication required") {
                eprintln!();
                eprintln!("[agc] 该网关是私有的，当前没有有效凭证。两条路：");
                eprintln!("[agc]   主人：agc {} --bind <配对码>", cli.url);
                eprintln!("[agc]   访客：agc {} --request-access <你的名字>", cli.url);
            }
            return Err(e);
        }
    };

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

    // Session ID for resume: agent-side conversation id from the chunk stream
    // (e.g. claude --output-format stream-json result line). Pass it back with
    // --session to continue this conversation.
    if let Some(sid) = result.get("sessionId").and_then(|v| v.as_str()) {
        if !sid.is_empty() {
            eprintln!("[agc] sessionId: {sid} (--session {sid} 续接)");
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

/// ACP.md 金样本互锁测试（协议立法层）。
///
/// ACP.md 住在隔壁 aginx 仓——agc 是协议唯一客户端，参数名/结果形状与文档
/// 打架即测试红。独立 clone（GitHub CI）没有该文件时跳过。
#[cfg(test)]
mod golden_tests {
    use serde_json::json;

    fn doc() -> Option<String> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../aginx/ACP.md");
        match std::fs::read_to_string(path) {
            Ok(d) => Some(d),
            Err(_) => {
                eprintln!("SKIP golden_tests: {path} 不存在（独立 clone 无 aginx 仓）");
                None
            }
        }
    }

    fn golden(doc: &str, name: &str) -> serde_json::Value {
        let marker = format!("<!-- golden: {name} -->");
        let start = doc
            .find(&marker)
            .unwrap_or_else(|| panic!("ACP.md 缺金样本标记: {name}"));
        let rest = &doc[start + marker.len()..];
        let fence = rest
            .find("```json")
            .unwrap_or_else(|| panic!("金样本 {name} 后缺 ```json 围栏"));
        let body = &rest[fence + "```json".len()..];
        let end = body
            .find("```")
            .unwrap_or_else(|| panic!("金样本 {name} 围栏未闭合"));
        serde_json::from_str(body[..end].trim())
            .unwrap_or_else(|e| panic!("金样本 {name} 不是合法 JSON: {e}"))
    }

    /// 借用轮 prompt 参数名——锁死 agc prompt() 的参数装配与文档一致。
    #[test]
    fn borrowed_prompt_param_names() {
        let Some(doc) = doc() else { return };
        let v = golden(&doc, "external_prompt_borrowed_request");
        let params = v.get("params").expect("params 必填");
        for key in [
            "agent",
            "message",
            "sessionTicket",
            "materials",
            "activeFlow",
            "borrower",
        ] {
            assert!(params.get(key).is_some(), "prompt params 缺 {key}");
        }
    }

    /// 普通轮参数——message 是扁平字符串，不带 ContentBlock 数组。
    #[test]
    fn plain_prompt_param_names() {
        let Some(doc) = doc() else { return };
        let v = golden(&doc, "external_prompt_plain_request");
        let params = v.get("params").expect("params 必填");
        assert!(params.get("message").and_then(|m| m.as_str()).is_some());
        for absent in ["sessionTicket", "materials", "activeFlow", "borrower"] {
            assert!(params.get(absent).is_none(), "普通轮不应带 {absent}");
        }
    }

    /// 最终结果消费形状——agc 的 is_final 判据 + sessionTicket/files 提取。
    #[test]
    fn final_result_consumer_shape() {
        let Some(doc) = doc() else { return };
        let v = golden(&doc, "external_final_result_borrowed");
        assert!(v.get("id").is_none(), "最终响应不带 id（agc 靠 result.stopReason 判终）");
        let result = v.get("result").expect("result 必填");
        assert_eq!(
            result.get("stopReason").and_then(|s| s.as_str()),
            Some("endTurn")
        );
        assert!(result.get("sessionTicket").is_some());
        assert!(result.get("files").is_some());
    }

    /// chunk 通知形状——agc 只消费 params.text。
    #[test]
    fn chunk_notification_shape() {
        let Some(doc) = doc() else { return };
        let v = golden(&doc, "external_chunk_notification");
        assert_eq!(v.get("method").and_then(|m| m.as_str()), Some("chunk"));
        assert!(v.pointer("/params/text").and_then(|t| t.as_str()).is_some());
    }

    /// 票据键名 camelCase——agc 的自动空票据构造器（main 里 turnSummaries）
    /// 必须与桥的 SessionTicket serde 同名，否则首轮票据被静默吞字段。
    #[test]
    fn ticket_key_names_camel() {
        let Some(doc) = doc() else { return };
        let v = golden(&doc, "ticket_v1");
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["contextWindowTokens", "label", "messages", "turnSummaries", "version"]
        );
        let opener = json!({
            "version": 1,
            "label": null,
            "messages": [],
            "turnSummaries": []
        });
        for (k, _) in opener.as_object().unwrap() {
            assert!(v.get(k).is_some(), "空票据构造器用了票据没有的键 {k}");
        }
    }
}

/// 钥匙串与网关键测试。
#[cfg(test)]
mod store_tests {
    use super::*;

    /// relay 网关键 = target id（端口变化不影响身份）；直连 = host:port。
    #[test]
    fn gateway_key_relay_vs_direct() {
        let r = AgentUrl::parse("agent://selvkwjv.relay.aginx.net:8443/claude").unwrap();
        assert_eq!(gateway_key(&r), "selvkwjv");
        let r2 = AgentUrl::parse("agent://selvkwjv.relay.aginx.net/claude").unwrap();
        assert_eq!(gateway_key(&r2), "selvkwjv", "显式端口与默认端口同一身份");
        let d = AgentUrl::parse("agent://192.168.1.100:86").unwrap();
        assert_eq!(gateway_key(&d), "192.168.1.100:86");
    }

    /// 往返：insert → JSON → load 回来字段齐（pending 态与取票态两种）。
    #[test]
    fn store_roundtrip_pending_and_approved() {
        let mut s = TokenStore::default();
        s.gateways.insert(
            "gw1".into(),
            StoredIdentity {
                token: None,
                name: "张三".into(),
                role: "visitor".into(),
                pending_request_id: Some("req-abc".into()),
                saved_at: 123,
            },
        );
        s.gateways.insert(
            "gw2".into(),
            StoredIdentity {
                token: Some("token-x".into()),
                name: "sophie-agc".into(),
                role: "owner".into(),
                pending_request_id: None,
                saved_at: 456,
            },
        );
        let raw = serde_json::to_string(&s).unwrap();
        let back: TokenStore = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, s);
        // pending 态：token 字段不落盘（skip_serializing_if）
        assert!(!raw.contains("\"token\": null"));
    }
}
