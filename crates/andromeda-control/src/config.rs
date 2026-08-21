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
///
/// Two forms are accepted. A **flat** single-VPC document (`vni = …` plus top-level
/// `[[endpoint]]`), and a **multi-VPC** document with one or more `[[vpc]]` blocks,
/// each with its own `vni`, `cidr`, and `[[vpc.endpoint]]` list — so one switch's
/// fabric can serve several tenants that reuse the same private addresses, kept apart
/// by their VNI.
#[derive(Debug, Deserialize)]
struct RawConfig {
    local_node: String,
    peer_node: Option<String>,
    vni: Option<u32>,
    virtual_gateway_mac: Option<String>,
    nat_ip: Option<String>,
    vpc_cidr: Option<String>,
    #[serde(default, rename = "endpoint")]
    endpoints: Vec<RawEndpoint>,
    #[serde(default, rename = "vpc")]
    vpcs: Vec<RawVpc>,
}

#[derive(Debug, Deserialize)]
struct RawVpc {
    vni: u32,
    cidr: Option<String>,
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

/// One virtual network within a node's fabric.
#[derive(Debug, Clone)]
pub struct VpcSpec {
    pub vni: u32,
    pub cidr: (Ipv4Addr, u8),
    pub endpoints: Vec<Endpoint>,
}

/// A validated node configuration.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub local_node: Ipv4Addr,
    pub peer_node: Option<Ipv4Addr>,
    /// Primary VNI (the first VPC) — used by the single-VPC switch path.
    pub vni: u32,
    pub virtual_gateway_mac: MacAddr,
    pub nat_ip: Option<Ipv4Addr>,
    pub vpc_cidr: (Ipv4Addr, u8),
    /// All endpoints across all VPCs (the fabric is keyed by (VNI, inner-IP)).
    pub endpoints: Vec<Endpoint>,
    /// Every VPC this node serves.
    pub vpcs: Vec<VpcSpec>,
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
        // Build the VPC list from either the multi-VPC `[[vpc]]` form or the flat form.
        let mut vpcs: Vec<VpcSpec> = Vec::new();
        if !raw.vpcs.is_empty() {
            for v in &raw.vpcs {
                let cidr = v
                    .cidr
                    .as_deref()
                    .map(parse_cidr)
                    .transpose()?
                    .unwrap_or((Ipv4Addr::UNSPECIFIED, 0));
                vpcs.push(VpcSpec {
                    vni: v.vni,
                    cidr,
                    endpoints: parse_endpoints(&v.endpoints, v.vni)?,
                });
            }
        } else {
            let vni = raw.vni.ok_or_else(|| {
                ConfigError("config needs a `vni` or at least one `[[vpc]]`".into())
            })?;
            let cidr = raw
                .vpc_cidr
                .as_deref()
                .map(parse_cidr)
                .transpose()?
                .unwrap_or((Ipv4Addr::UNSPECIFIED, 0));
            vpcs.push(VpcSpec {
                vni,
                cidr,
                endpoints: parse_endpoints(&raw.endpoints, vni)?,
            });
        }

        let primary_vni = vpcs[0].vni;
        let vpc_cidr = vpcs[0].cidr;
        let endpoints: Vec<Endpoint> = vpcs
            .iter()
            .flat_map(|v| v.endpoints.iter().copied())
            .collect();

        Ok(Self {
            local_node,
            peer_node,
            vni: primary_vni,
            virtual_gateway_mac,
            nat_ip,
            vpc_cidr,
            endpoints,
            vpcs,
        })
    }

    /// The set of VNIs this node serves.
    #[must_use]
    pub fn served_vnis(&self) -> Vec<u32> {
        self.vpcs.iter().map(|v| v.vni).collect()
    }

    /// Load and parse a config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// Build the runtime [`Fabric`] this config describes — every VPC and every
    /// endpoint. The fabric is keyed by (VNI, inner-IP), so tenants that reuse the
    /// same private addresses in different VPCs never collide.
    #[must_use]
    pub fn build_fabric(&self) -> Fabric {
        let mut fabric = Fabric::new(self.local_node);
        for v in &self.vpcs {
            fabric.add_vpc(Vpc {
                vni: v.vni,
                name: format!("vpc-{}", v.vni),
                cidr: v.cidr,
            });
            for ep in &v.endpoints {
                fabric.add_endpoint(*ep);
            }
        }
        fabric
    }
}

fn parse_endpoints(raw: &[RawEndpoint], vni: u32) -> Result<Vec<Endpoint>, ConfigError> {
    raw.iter()
        .map(|e| {
            Ok(Endpoint {
                vni,
                inner_ip: parse_ip(&e.inner_ip, "endpoint.inner_ip")?,
                inner_mac: e
                    .inner_mac
                    .parse()
                    .map_err(|_| ConfigError(format!("bad endpoint.inner_mac: {}", e.inner_mac)))?,
                node_ip: parse_ip(&e.node_ip, "endpoint.node_ip")?,
                local: e.local,
            })
        })
        .collect()
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
        // Flat form is one VPC.
        assert_eq!(c.served_vnis(), vec![100]);
    }

    #[test]
    fn multi_vpc_parses_and_isolates_overlapping_ips() {
        // Two tenants that BOTH use 10.0.0.5 — kept apart only by their VNI.
        let toml = r#"
            local_node          = "192.168.1.1"
            virtual_gateway_mac = "02:00:00:00:00:ff"

            [[vpc]]
            vni  = 100
            cidr = "10.0.0.0/24"
            [[vpc.endpoint]]
            inner_ip  = "10.0.0.5"
            inner_mac = "aa:bb:cc:00:01:05"
            node_ip   = "192.168.1.2"

            [[vpc]]
            vni  = 200
            cidr = "10.0.0.0/24"
            [[vpc.endpoint]]
            inner_ip  = "10.0.0.5"
            inner_mac = "aa:bb:cc:00:02:05"
            node_ip   = "192.168.1.3"
        "#;
        let c = NodeConfig::parse(toml).unwrap();
        assert_eq!(c.served_vnis(), vec![100, 200]);
        assert_eq!(c.endpoints.len(), 2);
        assert_eq!(c.vni, 100); // primary

        let fab = c.build_fabric();
        // Same inner IP, different VNI → different physical node. Tenant isolation.
        let a = fab.resolve(100, "10.0.0.5".parse().unwrap()).unwrap();
        let b = fab.resolve(200, "10.0.0.5".parse().unwrap()).unwrap();
        assert_eq!(a.node_ip, "192.168.1.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(b.node_ip, "192.168.1.3".parse::<Ipv4Addr>().unwrap());
        assert_ne!(a.node_ip, b.node_ip);
        assert_ne!(a.inner_mac, b.inner_mac);
    }

    #[test]
    fn config_without_vni_or_vpc_is_rejected() {
        let err = NodeConfig::parse("local_node = \"192.168.1.1\"\n").unwrap_err();
        assert!(err.to_string().contains("vni") || err.to_string().contains("vpc"));
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
