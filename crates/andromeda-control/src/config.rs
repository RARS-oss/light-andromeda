//! Declarative fabric configuration (TOML).
//!
//! A node's view of the overlay — its own underlay address, the VNI it serves, the
//! virtual gateway MAC, an optional NAT/gateway, and the endpoint table — loaded
//! from a single human-readable file. Example:
//!
//! ```toml
//! local_node          = "192.168.1.1"
//! peer_node           = "192.168.1.2"   # optional default route
//! vni                 = 100
//! virtual_gateway_mac = "02:00:00:00:00:ff"
//! # nat_ip            = "203.0.113.7"   # optional SNAT egress
//!
//! [[endpoint]]
//! inner_ip  = "10.0.0.10"
//! inner_mac = "aa:bb:cc:00:00:10"
//! node_ip   = "192.168.1.1"
//! local     = true
//!
//! [[endpoint]]
//! inner_ip  = "10.0.0.20"
//! inner_mac = "aa:bb:cc:00:00:20"
//! node_ip   = "192.168.1.2"
//! ```

use crate::{Endpoint, Fabric, Vpc};
use andromeda_core::ethernet::MacAddr;
use serde::Deserialize;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::Path;

/// The raw TOML shape (all addresses as strings; validated in [`NodeConfig::parse`]).
#[derive(Debug, Deserialize)]
struct RawConfig {
    local_node: String,
    peer_node: Option<String>,
    vni: u32,
    virtual_gateway_mac: Option<String>,
    nat_ip: Option<String>,
    vpc_cidr: Option<String>,
    #[serde(default, rename = "endpoint")]
    endpoints: Vec<RawEndpoint>,
}

#[derive(Debug, Deserialize)]
struct RawEndpoint {
    inner_ip: String,
    inner_mac: String,
    node_ip: String,
    #[serde(default)]
    local: bool,
}

/// A validated node configuration.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub local_node: Ipv4Addr,
    pub peer_node: Option<Ipv4Addr>,
    pub vni: u32,
    pub virtual_gateway_mac: MacAddr,
    pub nat_ip: Option<Ipv4Addr>,
    pub vpc_cidr: (Ipv4Addr, u8),
    pub endpoints: Vec<Endpoint>,
}

impl NodeConfig {
    /// Parse and validate a TOML document.
    pub fn parse(toml_str: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(toml_str).map_err(|e| ConfigError(e.to_string()))?;

        let local_node = parse_ip(&raw.local_node, "local_node")?;
        let peer_node = raw
            .peer_node
            .as_deref()
            .map(|s| parse_ip(s, "peer_node"))
            .transpose()?;
        let nat_ip = raw
            .nat_ip
            .as_deref()
            .map(|s| parse_ip(s, "nat_ip"))
            .transpose()?;
        let virtual_gateway_mac = match raw.virtual_gateway_mac.as_deref() {
            Some(s) => s
                .parse()
                .map_err(|_| ConfigError(format!("bad virtual_gateway_mac: {s}")))?,
            None => MacAddr([0x02, 0, 0, 0, 0, 0xff]),
        };
        let vpc_cidr = match raw.vpc_cidr.as_deref() {
            Some(s) => parse_cidr(s)?,
            None => (Ipv4Addr::UNSPECIFIED, 0),
        };

        let mut endpoints = Vec::with_capacity(raw.endpoints.len());
        for e in &raw.endpoints {
            endpoints.push(Endpoint {
                vni: raw.vni,
                inner_ip: parse_ip(&e.inner_ip, "endpoint.inner_ip")?,
                inner_mac: e
                    .inner_mac
                    .parse()
                    .map_err(|_| ConfigError(format!("bad endpoint.inner_mac: {}", e.inner_mac)))?,
                node_ip: parse_ip(&e.node_ip, "endpoint.node_ip")?,
                local: e.local,
            });
        }

        Ok(Self {
            local_node,
            peer_node,
            vni: raw.vni,
            virtual_gateway_mac,
            nat_ip,
            vpc_cidr,
            endpoints,
        })
    }

    /// Load and parse a config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// Build the runtime [`Fabric`] this config describes.
    #[must_use]
    pub fn build_fabric(&self) -> Fabric {
        let mut fabric = Fabric::new(self.local_node);
        fabric.add_vpc(Vpc {
            vni: self.vni,
            name: format!("vpc-{}", self.vni),
            cidr: self.vpc_cidr,
        });
        for ep in &self.endpoints {
            fabric.add_endpoint(*ep);
        }
        fabric
    }
}

fn parse_ip(s: &str, field: &str) -> Result<Ipv4Addr, ConfigError> {
    s.parse()
        .map_err(|_| ConfigError(format!("bad {field}: {s}")))
}

fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8), ConfigError> {
    let (net, len) = s
        .split_once('/')
        .ok_or_else(|| ConfigError(format!("bad cidr: {s}")))?;
    let ip = parse_ip(net, "vpc_cidr")?;
    let prefix: u8 = len
        .parse()
        .map_err(|_| ConfigError(format!("bad cidr prefix: {s}")))?;
    if prefix > 32 {
        return Err(ConfigError(format!("cidr prefix out of range: {s}")));
    }
    Ok((ip, prefix))
}

/// Configuration error (bad TOML or an invalid field value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "config error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        local_node          = "192.168.1.1"
        peer_node           = "192.168.1.2"
        vni                 = 100
        virtual_gateway_mac = "02:00:00:00:00:ff"
        nat_ip              = "203.0.113.7"
        vpc_cidr            = "10.0.0.0/24"

        [[endpoint]]
        inner_ip  = "10.0.0.10"
        inner_mac = "aa:bb:cc:00:00:10"
        node_ip   = "192.168.1.1"
        local     = true

        [[endpoint]]
        inner_ip  = "10.0.0.20"
        inner_mac = "aa:bb:cc:00:00:20"
        node_ip   = "192.168.1.2"
    "#;

    #[test]
    fn parses_full_config() {
        let c = NodeConfig::parse(SAMPLE).unwrap();
        assert_eq!(c.local_node, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(c.peer_node, Some("192.168.1.2".parse().unwrap()));
        assert_eq!(c.vni, 100);
        assert_eq!(c.virtual_gateway_mac, MacAddr([0x02, 0, 0, 0, 0, 0xff]));
        assert_eq!(c.nat_ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(c.endpoints.len(), 2);

        let fab = c.build_fabric();
        let nh = fab.resolve(100, "10.0.0.20".parse().unwrap()).unwrap();
        assert_eq!(nh.node_ip, "192.168.1.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            nh.inner_mac,
            "aa:bb:cc:00:00:20".parse::<MacAddr>().unwrap()
        );
    }

    #[test]
    fn minimal_config_defaults() {
        let c = NodeConfig::parse("local_node = \"192.168.1.1\"\nvni = 7\n").unwrap();
        assert_eq!(c.vni, 7);
        assert_eq!(c.virtual_gateway_mac, MacAddr([0x02, 0, 0, 0, 0, 0xff]));
        assert!(c.peer_node.is_none());
        assert!(c.endpoints.is_empty());
        assert_eq!(c.vpc_cidr.1, 0);
    }

    #[test]
    fn rejects_bad_ip() {
        let err = NodeConfig::parse("local_node = \"nope\"\nvni = 1\n").unwrap_err();
        assert!(err.to_string().contains("local_node"));
    }
}
