//! agent:// URL parser
//!
//! Formats:
//!   agent://<id>.relay.yinnho.cn           → TLS relay (port 8443)
//!   agent://<id>.relay.yinnho.cn:8443      → TLS relay with explicit port
//!   agent://<id>.relay.yinnho.cn/<agent>   → TLS relay targeting specific agent
//!   agent://<host>:<port>                  → Direct TCP (no TLS)
//!   agent://<host>:<port>/<agent>          → Direct TCP targeting specific agent

use std::fmt;

#[derive(Debug)]
pub struct AgentUrl {
    /// The relay target ID (e.g. "qi7o6bj5"), if connecting via relay
    pub relay_target: Option<String>,
    /// Host to connect to (relay host or direct host)
    pub relay_host: String,
    /// Port
    pub port: u16,
    /// TLS domain for SNI (if TLS)
    pub tls_domain: String,
    /// Whether to use TLS
    pub use_tls: bool,
    /// Agent name from path (e.g. "claude")
    pub agent: Option<String>,
    /// Relay secret token (from AGC_RELAY_SECRET env or --relay-secret)
    pub relay_token: Option<String>,
}

impl AgentUrl {
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let url = url.trim();

        // Strip agent://
        let rest = url
            .strip_prefix("agent://")
            .ok_or_else(|| anyhow::anyhow!("URL must start with agent://"))?;

        // Split host and path
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };

        let agent = path.and_then(|p| {
            let p = p.trim_end_matches('/');
            if p.is_empty() { None } else { Some(p.to_string()) }
        });

        // Parse host:port (supports IPv6 [::1]:port)
        let (host, explicit_port) = if host_port.starts_with('[') {
            // IPv6: [host]:port or [host]
            let close = host_port.find(']')
                .ok_or_else(|| anyhow::anyhow!("Invalid IPv6 address in URL"))?;
            let h = host_port[1..close].to_string();
            let rest = &host_port[close + 1..];
            let port = if let Some(p) = rest.strip_prefix(':') {
                Some(p.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("Invalid port in URL"))?)
            } else if rest.is_empty() {
                None
            } else {
                return Err(anyhow::anyhow!("Invalid URL after IPv6 address"));
            };
            (h, port)
        } else if let Some(colon) = host_port.rfind(':') {
            let h = &host_port[..colon];
            let p: u16 = host_port[colon + 1..]
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port in URL"))?;
            (h.to_string(), Some(p))
        } else {
            (host_port.to_string(), None)
        };

        // Detect relay mode: host contains ".relay." or known relay domains
        let is_relay = host.contains(".relay.");

        let (relay_target, relay_host, use_tls, tls_domain) = if is_relay {
            // host is like "qi7o6bj5.relay.yinnho.cn"
            // target = subdomain before ".relay."
            // tls_domain = the relay host itself (e.g. "relay.yinnho.cn") —
            // SNI must match the relay's leaf/wildcard cert, NOT the parent
            // domain suffix. (Comment previously said *.yinnho.cn wildcard,
            // but the issued cert is a leaf for relay.yinnho.cn.)
            let parts: Vec<&str> = host.split(".relay.").collect();
            let target = parts[0].to_string();
            let tls_domain = format!("relay.{}", parts[1..].join("."));
            (Some(target), host.clone(), true, tls_domain)
        } else {
            (None, host.clone(), false, host.clone())
        };

        // Default port: relay=8443 (TLS), direct=86
        let port = explicit_port.unwrap_or(if is_relay { 8443 } else { 86 });

        Ok(AgentUrl {
            relay_target,
            relay_host,
            port,
            use_tls,
            tls_domain,
            agent,
            relay_token: None,
        })
    }
}

impl fmt::Display for AgentUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "agent://{}:{}", self.relay_host, self.port)?;
        if let Some(ref agent) = self.agent {
            write!(f, "/{}", agent)?;
        }
        if self.use_tls {
            write!(f, " [TLS")?;
            if let Some(ref target) = self.relay_target {
                write!(f, ", relay={}", target)?;
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_url() {
        let url = AgentUrl::parse("agent://qi7o6bj5.relay.yinnho.cn").unwrap();
        assert_eq!(url.relay_target, Some("qi7o6bj5".to_string()));
        assert_eq!(url.relay_host, "qi7o6bj5.relay.yinnho.cn");
        assert_eq!(url.port, 8443);
        assert!(url.use_tls);
        assert!(url.agent.is_none());
    }

    #[test]
    fn test_relay_url_with_agent() {
        let url = AgentUrl::parse("agent://qi7o6bj5.relay.yinnho.cn/claude").unwrap();
        assert_eq!(url.relay_target, Some("qi7o6bj5".to_string()));
        assert_eq!(url.agent, Some("claude".to_string()));
    }

    #[test]
    fn test_relay_url_with_port() {
        let url = AgentUrl::parse("agent://qi7o6bj5.relay.yinnho.cn:8443/copilot").unwrap();
        assert_eq!(url.port, 8443);
        assert_eq!(url.agent, Some("copilot".to_string()));
    }

    #[test]
    fn test_direct_url() {
        let url = AgentUrl::parse("agent://192.168.1.100:86/claude").unwrap();
        assert!(url.relay_target.is_none());
        assert_eq!(url.relay_host, "192.168.1.100");
        assert_eq!(url.port, 86);
        assert!(!url.use_tls);
        assert_eq!(url.agent, Some("claude".to_string()));
    }

    #[test]
    fn test_no_scheme() {
        assert!(AgentUrl::parse("http://example.com").is_err());
    }

    #[test]
    fn test_ipv6_url() {
        let url = AgentUrl::parse("agent://[::1]:86/claude").unwrap();
        assert!(url.relay_target.is_none());
        assert_eq!(url.relay_host, "::1");
        assert_eq!(url.port, 86);
        assert!(!url.use_tls);
        assert_eq!(url.agent, Some("claude".to_string()));
    }

    #[test]
    fn test_ipv6_no_port() {
        let url = AgentUrl::parse("agent://[::1]").unwrap();
        assert_eq!(url.relay_host, "::1");
        assert_eq!(url.port, 86); // default direct port
    }
}
