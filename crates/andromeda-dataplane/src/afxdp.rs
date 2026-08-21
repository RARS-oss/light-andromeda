//! AF_XDP socket wrapper and forwarding loop (Linux, `feature = "afxdp"`).
//!
//! This is where "OS bypass" becomes concrete. `XskSocket::open` binds an AF_XDP
//! socket to an interface queue via the C shim; libxdp's built-in redirect program
//! steers RX frames into our socket's ring, past the kernel's networking stack. We
//! then read each frame directly out of the shared UMEM, run it through the
//! [`Pipeline`], and (in encap mode) transmit the result — all in user space.
//!
//! Frame accounting lives here in Rust: a free list of UMEM frame addresses is
//! split between the FILL ring (for RX) and TX; completed TX frames return to the
//! free list. This is the ring-buffer bookkeeping AF_XDP pushes onto the app.

use crate::pipeline::{Decision, Pipeline};
use andromeda_core::{ethernet::EthFrame, five_tuple_of};
use std::ffi::CString;
use std::io;
use std::os::raw::{c_char, c_int, c_uint};
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[repr(C)]
struct AndroXsk {
    _private: [u8; 0],
}

extern "C" {
    fn andro_xsk_open(
        ifname: *const c_char,
        queue_id: c_uint,
        n_frames: c_uint,
        frame_size: c_uint,
        fill_size: c_uint,
        comp_size: c_uint,
        rx_size: c_uint,
        tx_size: c_uint,
        xdp_mode: c_int,
        out_err: *mut c_int,
    ) -> *mut AndroXsk;
    fn andro_xsk_close(x: *mut AndroXsk);
    fn andro_umem_area(x: *mut AndroXsk) -> *mut u8;
    fn andro_xsk_fd(x: *mut AndroXsk) -> c_int;
    fn andro_fq_push(x: *mut AndroXsk, addrs: *const u64, n: c_uint) -> c_uint;
    fn andro_rx_peek(x: *mut AndroXsk, addrs: *mut u64, lens: *mut c_uint, max: c_uint) -> c_uint;
    fn andro_tx_push(x: *mut AndroXsk, addrs: *const u64, lens: *const c_uint, n: c_uint)
        -> c_uint;
    fn andro_cq_collect(x: *mut AndroXsk, addrs: *mut u64, max: c_uint) -> c_uint;
    fn andro_tx_needs_wakeup(x: *mut AndroXsk) -> c_int;
    fn andro_kick_tx(x: *mut AndroXsk) -> c_int;
    fn andro_poll_rx(x: *mut AndroXsk, timeout_ms: c_int) -> c_int;
}

/// XDP attach mode.
#[derive(Clone, Copy, Debug)]
pub enum XdpMode {
    /// Let libxdp choose (native, falling back to generic).
    Auto = 0,
    /// Force generic/SKB mode (works on any interface, incl. quirky veth setups).
    Skb = 1,
    /// Force native/driver mode.
    Drv = 2,
}

/// UMEM + ring sizing.
#[derive(Clone, Copy, Debug)]
pub struct XskConfig {
    pub n_frames: u32,
    pub frame_size: u32,
    pub fill_size: u32,
    pub comp_size: u32,
    pub rx_size: u32,
    pub tx_size: u32,
    pub xdp_mode: XdpMode,
}

impl Default for XskConfig {
    fn default() -> Self {
        Self {
            n_frames: 4096,
            frame_size: 2048,
            fill_size: 2048,
            comp_size: 2048,
            rx_size: 2048,
            tx_size: 2048,
            xdp_mode: XdpMode::Auto,
        }
    }
}

/// A bound AF_XDP socket with a UMEM and a free-frame pool.
pub struct XskSocket {
    ptr: *mut AndroXsk,
    area: *mut u8,
    frame_size: u32,
    fd: i32,
    /// Frame addresses currently owned by user space (available for TX or refill).
    free: Vec<u64>,
}

impl XskSocket {
    /// Bind to `(ifname, queue)`. Requires CAP_NET_ADMIN (run as root).
    pub fn open(ifname: &str, queue: u32, cfg: &XskConfig) -> io::Result<Self> {
        let cif = CString::new(ifname)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name has NUL"))?;
        let mut err: c_int = 0;
        let ptr = unsafe {
            andro_xsk_open(
                cif.as_ptr(),
                queue,
                cfg.n_frames,
                cfg.frame_size,
                cfg.fill_size,
                cfg.comp_size,
                cfg.rx_size,
                cfg.tx_size,
                cfg.xdp_mode as c_int,
                &mut err,
            )
        };
        if ptr.is_null() {
            return Err(io::Error::from_raw_os_error(err));
        }
        let area = unsafe { andro_umem_area(ptr) };
        let fd = unsafe { andro_xsk_fd(ptr) };
        // All frames start free; RX frames get moved into the FILL ring below.
        let free: Vec<u64> = (0..cfg.n_frames as u64)
            .map(|i| i * cfg.frame_size as u64)
            .collect();
        let mut s = Self {
            ptr,
            area,
            frame_size: cfg.frame_size,
            fd,
            free,
        };
        s.refill(cfg.fill_size);
        Ok(s)
    }

    #[must_use]
    pub fn fd(&self) -> i32 {
        self.fd
    }

    #[must_use]
    pub fn free_frames(&self) -> usize {
        self.free.len()
    }

    /// Move up to `want` free frames into the FILL ring for the kernel to fill.
    pub fn refill(&mut self, want: u32) -> u32 {
        if want == 0 || self.free.is_empty() {
            return 0;
        }
        let take = (want as usize).min(self.free.len());
        let start = self.free.len() - take;
        let pushed = unsafe { andro_fq_push(self.ptr, self.free[start..].as_ptr(), take as c_uint) }
            as usize;
        self.free.truncate(self.free.len() - pushed);
        pushed as u32
    }

    /// Block until readable or `ms` elapse. Returns the raw poll() result.
    pub fn poll_rx(&self, ms: i32) -> i32 {
        unsafe { andro_poll_rx(self.ptr, ms) }
    }

    /// Fetch a burst of received frames as (addr, len) pairs.
    ///
    /// The C shim already bounds each descriptor to the UMEM; we clamp `len` to the
    /// frame size again here so a length never exceeds the frame slot even if the FFI
    /// contract were violated — the raw-slice views in the forwarding loop rely on it.
    pub fn rx_burst(&mut self, addrs: &mut [u64], lens: &mut [u32]) -> usize {
        let max = addrs.len().min(lens.len()) as c_uint;
        let n =
            unsafe { andro_rx_peek(self.ptr, addrs.as_mut_ptr(), lens.as_mut_ptr(), max) as usize };
        for l in &mut lens[..n] {
            if *l > self.frame_size {
                *l = self.frame_size;
            }
        }
        n
    }

    /// Immutable view of a frame's bytes.
    ///
    /// # Safety contract (upheld by the loop): `addr` is a valid frame offset and
    /// the frame is not concurrently handed to the kernel.
    #[inline]
    #[must_use]
    pub fn frame(&self, addr: u64, len: u32) -> &[u8] {
        unsafe { slice::from_raw_parts(self.area.add(addr as usize), len as usize) }
    }

    /// Mutable, full-size view of a frame's bytes (for building a TX packet).
    ///
    /// Takes `&self` on purpose: the forwarding loop needs an immutable [`frame`]
    /// view of the RX frame and a mutable view of a *different* TX frame at the same
    /// time. The caller guarantees `addr` differs from any live `frame` view, so the
    /// two slices never alias — hence the `mut_from_ref` allow.
    #[inline]
    #[must_use]
    #[allow(clippy::mut_from_ref)]
    pub fn frame_mut(&self, addr: u64) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.area.add(addr as usize), self.frame_size as usize) }
    }

    /// Take a free frame to build a TX packet in.
    pub fn alloc_tx(&mut self) -> Option<u64> {
        self.free.pop()
    }

    /// Return a frame to the free pool (dropped packet, or reclaimed RX frame).
    pub fn recycle(&mut self, addr: u64) {
        self.free.push(addr);
    }

    /// Enqueue one (addr, len) on the TX ring. Returns true if queued.
    pub fn tx_one(&mut self, addr: u64, len: u32) -> bool {
        let a = [addr];
        let l = [len];
        unsafe { andro_tx_push(self.ptr, a.as_ptr(), l.as_ptr(), 1) == 1 }
    }

    /// Kick the kernel to service TX if the ring asked for a wakeup.
    pub fn kick_tx_if_needed(&self) {
        if unsafe { andro_tx_needs_wakeup(self.ptr) } != 0 {
            unsafe {
                let _ = andro_kick_tx(self.ptr);
            }
        }
    }

    /// Reclaim up to `max` completed TX frames back to the free pool. Returns count.
    pub fn complete_tx(&mut self, max: u32) -> usize {
        if max == 0 {
            return 0;
        }
        let mut buf = vec![0u64; max as usize];
        let n = unsafe { andro_cq_collect(self.ptr, buf.as_mut_ptr(), max) } as usize;
        self.free.extend_from_slice(&buf[..n]);
        n
    }
}

impl Drop for XskSocket {
    fn drop(&mut self) {
        unsafe { andro_xsk_close(self.ptr) };
    }
}

/// What the forwarder does with each received frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Parse and print each frame — proves frames reach user space via AF_XDP.
    Dump,
    /// Treat each frame as a tenant inner frame; encapsulate and transmit it.
    Encap,
    /// Treat each frame as overlay traffic; decapsulate and report the inner packet.
    Decap,
}

/// Loop controls.
#[derive(Clone, Copy, Debug)]
pub struct RunOpts {
    pub mode: Mode,
    pub max_packets: Option<u64>,
    pub max_secs: Option<u64>,
    pub batch: u32,
}

/// Counters returned when the loop exits.
#[derive(Clone, Copy, Debug, Default)]
pub struct RunStats {
    pub rx: u64,
    pub tx: u64,
    pub dropped: u64,
    pub decapped: u64,
    pub bytes_in: u64,
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_sig: c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Install a SIGINT handler so Ctrl-C stops the loop cleanly.
pub fn install_sigint_handler() {
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
}

/// Evict NAT bindings idle longer than this (ms). Conntrack-style idle timeout;
/// without periodic eviction the SNAT port pool and conntrack tables never reclaim.
const NAT_IDLE_TIMEOUT_MS: u64 = 120_000;
/// How often the forwarding loops run NAT garbage collection.
const NAT_GC_INTERVAL: Duration = Duration::from_secs(1);

/// Run the forwarding loop until Ctrl-C, packet cap, or time cap.
pub fn run(sock: &mut XskSocket, pipeline: &mut Pipeline, opts: RunOpts) -> io::Result<RunStats> {
    let batch = opts.batch.max(1);
    let mut addrs = vec![0u64; batch as usize];
    let mut lens = vec![0u32; batch as usize];
    let mut stats = RunStats::default();
    let start = Instant::now();
    let mut gc_at = Instant::now();

    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        if let Some(m) = opts.max_packets {
            if stats.rx >= m {
                break;
            }
        }
        if let Some(s) = opts.max_secs {
            if start.elapsed().as_secs() >= s {
                break;
            }
        }

        // Periodically reclaim idle NAT bindings (port pool + conntrack).
        if gc_at.elapsed() >= NAT_GC_INTERVAL {
            pipeline.gc(start.elapsed().as_millis() as u64, NAT_IDLE_TIMEOUT_MS);
            gc_at = Instant::now();
        }

        let pr = sock.poll_rx(200);
        if pr <= 0 {
            // Timeout or interrupted: keep the rings healthy and loop.
            sock.complete_tx(batch);
            sock.refill(batch);
            continue;
        }

        let n = sock.rx_burst(&mut addrs, &mut lens);
        let now_ms = start.elapsed().as_millis() as u64;

        for i in 0..n {
            let (addr, len) = (addrs[i], lens[i]);
            stats.rx += 1;
            stats.bytes_in += len as u64;

            match opts.mode {
                Mode::Dump => {
                    if stats.rx <= 20 {
                        print_frame(sock.frame(addr, len), stats.rx);
                    }
                    sock.recycle(addr);
                }
                Mode::Encap => {
                    if let Some(tx_addr) = sock.alloc_tx() {
                        let decision = {
                            let inner = sock.frame(addr, len);
                            let out = sock.frame_mut(tx_addr);
                            pipeline.on_tenant_frame(inner, out, now_ms)
                        };
                        match decision {
                            // Forward (encapsulated) and Reply (ARP) both TX on this
                            // single socket.
                            Decision::Forward(m) | Decision::Reply(m)
                                if sock.tx_one(tx_addr, m as u32) =>
                            {
                                stats.tx += 1;
                            }
                            _ => {
                                sock.recycle(tx_addr);
                                stats.dropped += 1;
                            }
                        }
                    } else {
                        stats.dropped += 1;
                    }
                    sock.recycle(addr);
                }
                Mode::Decap => {
                    if let Some(tx_addr) = sock.alloc_tx() {
                        let decision = {
                            let frame = sock.frame(addr, len);
                            let out = sock.frame_mut(tx_addr);
                            pipeline.on_underlay_frame(frame, out, now_ms)
                        };
                        if let Decision::Forward(m) = decision {
                            stats.decapped += 1;
                            if stats.decapped <= 20 {
                                print_frame(sock.frame(tx_addr, m as u32), stats.decapped);
                            }
                        }
                        sock.recycle(tx_addr);
                    }
                    sock.recycle(addr);
                }
            }
        }

        sock.kick_tx_if_needed();
        sock.complete_tx(batch);
        sock.refill(batch);
    }

    Ok(stats)
}

/// Run a full two-interface switch: encapsulate frames arriving on the tenant
/// port and transmit them on the underlay port; decapsulate frames arriving on the
/// underlay port and deliver them on the tenant port. This is the real datapath a
/// node runs — a bidirectional overlay bridge in user space.
///
/// Because the two ports have independent UMEMs, forwarding copies the built packet
/// into a destination-port frame (a shared-UMEM zero-copy path is a later
/// optimization). Both directions run every iteration; a single `poll` waits on
/// both sockets.
pub fn run_switch(
    tenant: &mut XskSocket,
    underlay: &mut XskSocket,
    pipeline: &mut Pipeline,
    opts: RunOpts,
) -> io::Result<RunStats> {
    let batch = opts.batch.max(1);
    let mut addrs = vec![0u64; batch as usize];
    let mut lens = vec![0u32; batch as usize];
    let mut stats = RunStats::default();
    let start = Instant::now();
    let mut report_at = Instant::now();
    let (mut last_rx, mut last_tx) = (0u64, 0u64);

    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        if let Some(m) = opts.max_packets {
            if stats.rx >= m {
                break;
            }
        }
        if let Some(s) = opts.max_secs {
            if start.elapsed().as_secs() >= s {
                break;
            }
        }

        // Live stats line, once a second — interesting to watch under load.
        let since = report_at.elapsed();
        if since >= Duration::from_secs(1) {
            // Reclaim idle NAT bindings (port pool + conntrack) on the same tick.
            pipeline.gc(start.elapsed().as_millis() as u64, NAT_IDLE_TIMEOUT_MS);
            let dt = since.as_secs_f64();
            let ps = pipeline.stats();
            println!(
                "[+{:>3}s] rx {:>9} ({:>8.0} pps)  tx {:>9} ({:>8.0} pps)  encap {} decap {} arp {} drop {}",
                start.elapsed().as_secs(),
                stats.rx,
                (stats.rx - last_rx) as f64 / dt,
                stats.tx,
                (stats.tx - last_tx) as f64 / dt,
                ps.encapped,
                ps.decapped,
                ps.arp_replied,
                stats.dropped,
            );
            last_rx = stats.rx;
            last_tx = stats.tx;
            report_at = Instant::now();
        }

        // Wait on both sockets at once.
        let mut pfds = [
            libc::pollfd {
                fd: tenant.fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: underlay.fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let pr = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 200) };
        let now_ms = start.elapsed().as_millis() as u64;

        // Tenant -> underlay (encapsulate).
        if pr > 0 && (pfds[0].revents & libc::POLLIN) != 0 {
            let n = tenant.rx_burst(&mut addrs, &mut lens);
            for i in 0..n {
                let (addr, len) = (addrs[i], lens[i]);
                stats.rx += 1;
                stats.bytes_in += len as u64;
                if let Some(tx_addr) = underlay.alloc_tx() {
                    let decision = {
                        let inner = tenant.frame(addr, len);
                        let out = underlay.frame_mut(tx_addr);
                        pipeline.on_tenant_frame(inner, out, now_ms)
                    };
                    match decision {
                        // Encapsulated frame → out the underlay port.
                        Decision::Forward(m) if underlay.tx_one(tx_addr, m as u32) => stats.tx += 1,
                        // ARP reply → back out the tenant port. The bytes were built
                        // into an underlay frame, so copy them into a tenant frame.
                        Decision::Reply(m) => {
                            let reply = underlay.frame(tx_addr, m as u32).to_vec();
                            underlay.recycle(tx_addr);
                            if let Some(t_addr) = tenant.alloc_tx() {
                                tenant.frame_mut(t_addr)[..m].copy_from_slice(&reply);
                                if tenant.tx_one(t_addr, m as u32) {
                                    stats.tx += 1;
                                } else {
                                    tenant.recycle(t_addr);
                                    stats.dropped += 1;
                                }
                            } else {
                                stats.dropped += 1;
                            }
                        }
                        _ => {
                            underlay.recycle(tx_addr);
                            stats.dropped += 1;
                        }
                    }
                } else {
                    stats.dropped += 1;
                }
                tenant.recycle(addr);
            }
        }

        // Underlay -> tenant (decapsulate + deliver).
        if pr > 0 && (pfds[1].revents & libc::POLLIN) != 0 {
            let n = underlay.rx_burst(&mut addrs, &mut lens);
            for i in 0..n {
                let (addr, len) = (addrs[i], lens[i]);
                stats.rx += 1;
                stats.bytes_in += len as u64;
                if let Some(tx_addr) = tenant.alloc_tx() {
                    let decision = {
                        let frame = underlay.frame(addr, len);
                        let out = tenant.frame_mut(tx_addr);
                        pipeline.on_underlay_frame(frame, out, now_ms)
                    };
                    match decision {
                        Decision::Forward(m) if tenant.tx_one(tx_addr, m as u32) => {
                            stats.tx += 1;
                            stats.decapped += 1;
                        }
                        _ => {
                            tenant.recycle(tx_addr);
                            stats.dropped += 1;
                        }
                    }
                } else {
                    stats.dropped += 1;
                }
                underlay.recycle(addr);
            }
        }

        underlay.kick_tx_if_needed();
        tenant.kick_tx_if_needed();
        underlay.complete_tx(batch);
        tenant.complete_tx(batch);
        underlay.refill(batch);
        tenant.refill(batch);
    }

    Ok(stats)
}

/// Print a one-line summary of a frame (used by dump/decap modes).
fn print_frame(frame: &[u8], seq: u64) {
    match EthFrame::parse(frame) {
        Ok(eth) => {
            let ft = five_tuple_of(eth.payload());
            match ft {
                Some(t) => println!(
                    "#{seq:<4} {} bytes  {} -> {}  {}",
                    frame.len(),
                    eth.src(),
                    eth.dst(),
                    t
                ),
                None => println!(
                    "#{seq:<4} {} bytes  {} -> {}  ethertype=0x{:04x}",
                    frame.len(),
                    eth.src(),
                    eth.dst(),
                    eth.ethertype()
                ),
            }
        }
        Err(_) => println!("#{seq:<4} {} bytes  <unparsable>", frame.len()),
    }
}
