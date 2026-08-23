// Thin C shim over the system libxdp AF_XDP API.
//
// libxdp exposes the four rings (FILL / COMPLETION / RX / TX) mainly through
// `static inline` helpers in <xdp/xsk.h>, which cannot be linked from Rust. This
// shim wraps them as ordinary exported functions, and bundles the umem+socket
// creation, so the Rust side sees a small, safe-to-call C surface and drives all
// the frame accounting itself.
//
// Design: one UMEM (a page-aligned buffer of `n_frames` × `frame_size`), one XSK
// bound to (ifname, queue). RX/TX descriptors carry a byte offset (`addr`) into
// that buffer and a length. libxdp's xsk_socket__create loads its built-in XDP
// redirect program and inserts us into the xsks_map, so packets on the queue land
// in our RX ring — bypassing the kernel network stack. That is the "OS bypass".

#include <xdp/xsk.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>

struct andro_xsk {
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    void *area;
    uint32_t frame_size;
    uint32_t n_frames;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    int fd;
    int zc_bound; // 1 if the socket bound in zero-copy mode, 0 if copy mode.
};

// Open an AF_XDP socket on (ifname, queue_id) with a fresh UMEM.
// `xdp_mode`: 0 = let libxdp choose (native, fall back to skb), 1 = force SKB
// (generic) mode, 2 = force native (driver) mode.
// `zerocopy`: 1 = request true zero-copy UMEM (needs a driver that supports it,
// e.g. mlx5/ice/i40e/ixgbe); falls back to copy mode if the driver refuses.
// 0 = copy mode (works everywhere, incl. veth). Query the result with
// andro_xsk_zerocopy().
// On failure returns NULL and sets *out_err to a positive errno.
struct andro_xsk *andro_xsk_open(const char *ifname, uint32_t queue_id,
                                 uint32_t n_frames, uint32_t frame_size,
                                 uint32_t fill_size, uint32_t comp_size,
                                 uint32_t rx_size, uint32_t tx_size,
                                 int xdp_mode, int zerocopy, int *out_err) {
    struct andro_xsk *x = calloc(1, sizeof(*x));
    if (!x) { if (out_err) *out_err = ENOMEM; return NULL; }
    // frame_size is used as a divisor in andro_rx_peek; reject 0 up front (SIGFPE guard).
    if (frame_size == 0) { if (out_err) *out_err = EINVAL; free(x); return NULL; }
    x->frame_size = frame_size;
    x->n_frames = n_frames;

    uint64_t area_sz = (uint64_t)n_frames * frame_size;
    // posix_memalign returns the error code directly and does NOT set errno.
    int rc = posix_memalign(&x->area, getpagesize(), area_sz);
    if (rc) {
        if (out_err) *out_err = rc; free(x); return NULL;
    }
    memset(x->area, 0, area_sz);

    struct xsk_umem_config ucfg;
    memset(&ucfg, 0, sizeof(ucfg));
    ucfg.fill_size = fill_size;
    ucfg.comp_size = comp_size;
    ucfg.frame_size = frame_size;
    ucfg.frame_headroom = 0;
    ucfg.flags = 0;

    int err = xsk_umem__create(&x->umem, x->area, area_sz, &x->fill, &x->comp, &ucfg);
    if (err) { if (out_err) *out_err = -err; free(x->area); free(x); return NULL; }

    struct xsk_socket_config scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.rx_size = rx_size;
    scfg.tx_size = tx_size;
    scfg.libxdp_flags = 0;
    if (xdp_mode == 1)      scfg.xdp_flags = XDP_FLAGS_SKB_MODE;
    else if (xdp_mode == 2) scfg.xdp_flags = XDP_FLAGS_DRV_MODE;
    // Zero-copy requires the native driver path; prefer it when none is forced.
    else                    scfg.xdp_flags = zerocopy ? XDP_FLAGS_DRV_MODE : 0;

    // First attempt: zero-copy if requested, else copy. Zero-copy binds only on a
    // driver that supports it (mlx5/ice/i40e/ixgbe); on anything else (veth, virtio,
    // generic mode) the create fails and we transparently fall back to copy mode.
    scfg.bind_flags = XDP_USE_NEED_WAKEUP | (zerocopy ? XDP_ZEROCOPY : XDP_COPY);
    err = xsk_socket__create(&x->xsk, ifname, queue_id, x->umem, &x->rx, &x->tx, &scfg);
    if (err && zerocopy) {
        // Drop the forced native flag too, so libxdp can degrade to SKB/generic on an
        // interface with no native XDP — not only to copy mode on a native driver.
        scfg.xdp_flags = 0;
        scfg.bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY;
        err = xsk_socket__create(&x->xsk, ifname, queue_id, x->umem, &x->rx, &x->tx, &scfg);
        x->zc_bound = 0;
    } else {
        x->zc_bound = (!err && zerocopy) ? 1 : 0;
    }
    if (err) {
        if (out_err) *out_err = -err;
        xsk_umem__delete(x->umem); free(x->area); free(x); return NULL;
    }

    x->fd = xsk_socket__fd(x->xsk);
    if (out_err) *out_err = 0;
    return x;
}

void andro_xsk_close(struct andro_xsk *x) {
    if (!x) return;
    if (x->xsk) xsk_socket__delete(x->xsk);
    if (x->umem) xsk_umem__delete(x->umem);
    if (x->area) free(x->area);
    free(x);
}

void *andro_umem_area(struct andro_xsk *x) { return x->area; }
uint32_t andro_frame_size(struct andro_xsk *x) { return x->frame_size; }
uint32_t andro_n_frames(struct andro_xsk *x) { return x->n_frames; }
int andro_xsk_fd(struct andro_xsk *x) { return x->fd; }

// 1 if the socket bound in true zero-copy mode, 0 if it is in (or fell back to) copy mode.
int andro_xsk_zerocopy(struct andro_xsk *x) { return x ? x->zc_bound : 0; }

// Hand `n` frame addresses to the FILL ring so the kernel can deliver RX into
// them. Returns how many were actually enqueued (bounded by ring space).
uint32_t andro_fq_push(struct andro_xsk *x, const uint64_t *addrs, uint32_t n) {
    uint32_t idx = 0;
    uint32_t got = xsk_ring_prod__reserve(&x->fill, n, &idx);
    for (uint32_t i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&x->fill, idx + i) = addrs[i];
    if (got) xsk_ring_prod__submit(&x->fill, got);
    return got;
}

// Peek up to `max` received frames, copy their (addr,len) out, and release the
// RX ring slots. The frame buffers themselves remain owned by the caller until
// recycled to FILL or handed to TX. Returns the number of frames returned.
uint32_t andro_rx_peek(struct andro_xsk *x, uint64_t *addrs, uint32_t *lens, uint32_t max) {
    uint32_t idx = 0;
    uint32_t got = xsk_ring_cons__peek(&x->rx, max, &idx);
    uint64_t area_sz = (uint64_t)x->n_frames * x->frame_size;
    for (uint32_t i = 0; i < got; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&x->rx, idx + i);
        uint64_t a = d->addr;
        uint32_t l = d->len;
        // Defense-in-depth: never let a descriptor address/length escape its frame
        // slot. Under XDP_COPY the kernel already bounds these, but a native/multi-
        // buffer driver could deliver a larger len or an unaligned addr; clamping to
        // the room left in THIS slot keeps the Rust slice inside one frame (no OOB
        // read, no crossing into the next slot, no aliasing with a TX frame). Since
        // frame_size divides area_sz, a slot never crosses the UMEM boundary either.
        if (a >= area_sz) { a = 0; l = 0; }
        // Snap the address to its frame-slot base: an unaligned descriptor address (a
        // buggy/native-mode driver) must never be recycled into the frame pool as an
        // unaligned offset and later sliced as a full frame past the UMEM end. Aligned
        // mode (flags=0) already delivers slot-aligned addresses, so this is a no-op there.
        a -= a % x->frame_size;
        if (l > x->frame_size) l = x->frame_size;
        addrs[i] = a;
        lens[i] = l;
    }
    if (got) xsk_ring_cons__release(&x->rx, got);
    return got;
}

// Enqueue `n` (addr,len) descriptors on the TX ring. Returns how many were queued.
uint32_t andro_tx_push(struct andro_xsk *x, const uint64_t *addrs, const uint32_t *lens, uint32_t n) {
    uint32_t idx = 0;
    uint32_t got = xsk_ring_prod__reserve(&x->tx, n, &idx);
    for (uint32_t i = 0; i < got; i++) {
        struct xdp_desc *d = xsk_ring_prod__tx_desc(&x->tx, idx + i);
        d->addr = addrs[i];
        d->len = lens[i];
        d->options = 0;
    }
    if (got) xsk_ring_prod__submit(&x->tx, got);
    return got;
}

// Reclaim completed TX frame addresses from the COMPLETION ring.
uint32_t andro_cq_collect(struct andro_xsk *x, uint64_t *addrs, uint32_t max) {
    uint32_t idx = 0;
    uint32_t got = xsk_ring_cons__peek(&x->comp, max, &idx);
    for (uint32_t i = 0; i < got; i++)
        addrs[i] = *xsk_ring_cons__comp_addr(&x->comp, idx + i);
    if (got) xsk_ring_cons__release(&x->comp, got);
    return got;
}

int andro_tx_needs_wakeup(struct andro_xsk *x) { return xsk_ring_prod__needs_wakeup(&x->tx); }
int andro_fq_needs_wakeup(struct andro_xsk *x) { return xsk_ring_prod__needs_wakeup(&x->fill); }

// Kick the kernel to process the TX ring (needed in need-wakeup mode).
int andro_kick_tx(struct andro_xsk *x) {
    int r = sendto(x->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    return (r < 0) ? -errno : 0;
}

// Block until the socket is readable or `timeout_ms` elapses. Returns poll()'s value.
int andro_poll_rx(struct andro_xsk *x, int timeout_ms) {
    struct pollfd pfd = { .fd = x->fd, .events = POLLIN, .revents = 0 };
    return poll(&pfd, 1, timeout_ms);
}
