# Architecture & packet walk

This document traces a packet through Light-Andromeda and describes how the pure
forwarding pipeline drops onto the AF_XDP ring loop.

## Components

```
              ┌──────────────────────────────────────────────────────────┐
              │                    andromeda switch                       │
              │                                                           │
  tenant  ───▶│  RX ring ─▶ [ pipeline ] ─▶ TX ring  ───▶ underlay        │
  veth        │              │      ▲                                     │
              │              ▼      │                                     │
              │        ┌───────────────────┐   ┌────────────────────┐     │
              │        │ control: Fabric   │   │ nat: NatEngine     │     │
              │        │ (VNI, IP)→node/MAC│   │ SNAT/DNAT+conntrack│     │
              │        └───────────────────┘   └────────────────────┘     │
              └──────────────────────────────────────────────────────────┘
```

* **`andromeda-core`** — the wire. Views over bytes; no allocation, no unsafe.
* **`andromeda-control`** — the map. Authoritative `(VNI, inner-IP) → (node, MAC)`.
* **`andromeda-nat`** — the translations. Pure decision + in-place `apply`.
* **`andromeda-dataplane`** — the loop. Owns the pipeline; AF_XDP feeds it frames.

## Egress: tenant → underlay (`on_tenant_frame`)

1. Parse the inner Ethernet frame; require IPv4 inside.
2. Look up the inner destination IP in the fabric for this VNI.
   * **Hit** → next hop = the endpoint's underlay node; rewrite the inner
     destination MAC to the endpoint's MAC (overlay L2 adjacency).
   * **Miss** → if a default gateway node is configured, send there and mark the
     flow for SNAT; otherwise **drop** (`no-route`).
3. If leaving the VPC, run the NAT engine (`Outbound`) and `apply` the rewrite,
   fixing L3 + L4 checksums incrementally.
4. Compute the flow hash over the (post-NAT) 5-tuple.
5. `encap`: prepend outer Ethernet + IPv4 + UDP + Andromeda header; the outer UDP
   source port carries the flow hash so the underlay can ECMP; set the outer UDP
   checksum over the whole payload.
6. Hand the encapsulated bytes to the TX ring.

## Ingress: underlay → tenant (`on_underlay_frame`)

1. `decap`: verify outer ethertype/proto and that the UDP destination port is the
   Andromeda port; parse the Andromeda header. Non-Andromeda frames → **Pass**.
2. Check the VNI matches this switch. Copy the inner frame to the output buffer.
3. If NAT is active, run the engine (`Inbound`) — this reverses an earlier SNAT
   (rewrite destination back to the private endpoint) or applies DNAT for a
   forwarded port — and `apply` it.
4. Deliver the inner frame to the tenant port.

## AF_XDP integration plan

The pipeline is deliberately socket-agnostic: it consumes `&[u8]` and writes
`&mut [u8]`, returning a `Decision`. The AF_XDP layer will:

1. Allocate a **UMEM** (a contiguous mmap'd region) carved into fixed frames.
2. Bind an **`AF_XDP` socket (XSK)** to a queue on the target interface; a small
   XDP program redirects matching RX frames into the socket's `XSKMAP`.
3. On the RX ring, for each descriptor, form a `&mut [u8]` view into its UMEM frame
   and call the pipeline. On `Forward(n)`, enqueue the frame on the TX ring; on
   `Drop`/`Pass`, recycle the frame to the FILL ring.
4. Use `sendto`/busy-poll to kick TX and keep the rings drained.

Because the pipeline never copies out of the frame it was handed (except the one
reused scratch buffer during encap), the RX→process→TX path stays close to
zero-copy — the property that makes kernel bypass worth doing.

## Testing strategy

* **Unit** — every parser/checksum/NAT/overlay invariant is asserted against
  known-good vectors and against full-recompute baselines.
* **Pipeline** — end-to-end encap/decap and NAT are exercised over in-memory
  buffers, so the logic is validated before any privileged AF_XDP setup.
* **Integration (next)** — a veth/netns topology carries real `ping`/`iperf`
  traffic across two switch instances; benchmarks compare overlay latency to the
  kernel path.
