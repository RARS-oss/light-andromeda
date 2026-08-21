//! # andromeda-control
//!
//! The control plane's in-memory model of the virtual fabric. It answers the one
//! question the dataplane asks on every packet it forwards:
//!
//! > "Inside VPC `vni`, for inner destination IP `X`, which underlay node do I
//! > encapsulate toward, and what inner destination MAC do I use?"
//!
//! This is the software-defined-networking (SDN) half of the design: a logically
//! centralized map of endpoints → physical location, distributed to every switch.
//! Here we keep it as a simple authoritative table; a production system would sync
//! it via a control protocol (BGP-EVPN, a custom gRPC bus, etc.).

use andromeda_core::ethernet::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// A tenant virtual network, identified by its 24-bit VNI.
#[derive(Clone, Debug)]
pub struct Vpc {
    pub vni: u32,
    pub name: String,
    /// The tenant's address space, e.g. 10.0.0.0/24. Stored as (network, prefix_len).
    pub cidr: (Ipv4Addr, u8),
}

impl Vpc {
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let (net, len) = self.cidr;
        if len == 0 {
            return true;
        }
        let mask = u32::MAX.checked_shl(32 - len as u32).unwrap_or(0);
        (u32::from(ip) & mask) == (u32::from(net) & mask)
    }
}

/// A tenant endpoint (a VM/container NIC) and where it physically lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub vni: u32,
    pub inner_ip: Ipv4Addr,
    pub inner_mac: MacAddr,
    /// Underlay address of the node hosting this endpoint.
    pub node_ip: Ipv4Addr,
    /// True if this endpoint is attached to the *local* switch (deliver on decap
    /// instead of re-encapsulating).
    pub local: bool,
}

/// The result of a forwarding lookup: where and how to send an encapsulated packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NextHop {
    pub node_ip: Ipv4Addr,
    pub inner_mac: MacAddr,
    pub local: bool,
}

/// The fabric map held by one switch instance.
pub struct Fabric {
    /// This switch's own underlay address.
    pub local_node_ip: Ipv4Addr,
    vpcs: HashMap<u32, Vpc>,
    /// (vni, inner_ip) -> endpoint.
    endpoints: HashMap<(u32, Ipv4Addr), Endpoint>,
}

impl Fabric {
    #[must_use]
    pub fn new(local_node_ip: Ipv4Addr) -> Self {
        Self { local_node_ip, vpcs: HashMap::new(), endpoints: HashMap::new() }
    }

    pub fn add_vpc(&mut self, vpc: Vpc) {
        self.vpcs.insert(vpc.vni, vpc);
    }

    pub fn add_endpoint(&mut self, ep: Endpoint) {
        self.endpoints.insert((ep.vni, ep.inner_ip), ep);
    }

    #[must_use]
    pub fn vpc(&self, vni: u32) -> Option<&Vpc> {
        self.vpcs.get(&vni)
    }

    /// Resolve an inner destination within a VPC to a next hop. `None` means the
    /// destination is unknown (dataplane should drop or flood per policy).
    #[must_use]
    pub fn resolve(&self, vni: u32, inner_dst: Ipv4Addr) -> Option<NextHop> {
        let ep = self.endpoints.get(&(vni, inner_dst))?;
        Some(NextHop { node_ip: ep.node_ip, inner_mac: ep.inner_mac, local: ep.local })
    }

    /// All endpoints local to this switch (used to program the tap/veth side).
    pub fn local_endpoints(&self) -> impl Iterator<Item = &Endpoint> {
        self.endpoints.values().filter(|e| e.local)
    }

    #[must_use]
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr([0x02, 0, 0, 0, 0, n])
    }

    #[test]
    fn cidr_membership() {
        let vpc = Vpc { vni: 100, name: "web".into(), cidr: ("10.0.0.0".parse().unwrap(), 24) };
        assert!(vpc.contains("10.0.0.42".parse().unwrap()));
        assert!(!vpc.contains("10.0.1.1".parse().unwrap()));
    }

    #[test]
    fn resolve_across_nodes() {
        let mut fab = Fabric::new("192.168.1.1".parse().unwrap());
        fab.add_vpc(Vpc { vni: 100, name: "web".into(), cidr: ("10.0.0.0".parse().unwrap(), 24) });
        // Local endpoint on this node.
        fab.add_endpoint(Endpoint {
            vni: 100,
            inner_ip: "10.0.0.10".parse().unwrap(),
            inner_mac: mac(0x10),
            node_ip: "192.168.1.1".parse().unwrap(),
            local: true,
        });
        // Remote endpoint on another node.
        fab.add_endpoint(Endpoint {
            vni: 100,
            inner_ip: "10.0.0.20".parse().unwrap(),
            inner_mac: mac(0x20),
            node_ip: "192.168.1.2".parse().unwrap(),
            local: false,
        });

        let nh = fab.resolve(100, "10.0.0.20".parse().unwrap()).unwrap();
        assert_eq!(nh.node_ip, "192.168.1.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(nh.inner_mac, mac(0x20));
        assert!(!nh.local);

        let local = fab.resolve(100, "10.0.0.10".parse().unwrap()).unwrap();
        assert!(local.local);

        // Unknown inner IP and wrong VNI both miss.
        assert!(fab.resolve(100, "10.0.0.99".parse().unwrap()).is_none());
        assert!(fab.resolve(200, "10.0.0.20".parse().unwrap()).is_none());
        assert_eq!(fab.local_endpoints().count(), 1);
    }
}
