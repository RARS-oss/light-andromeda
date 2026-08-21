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
};

// Open an AF_XDP socket on (ifname, queue_id) with a fresh UMEM.
// `xdp_mode`: 0 = let libxdp choose (native, fall back to skb), 1 = force SKB
// (generic) mode, 2 = force native (driver) mode.
// On failure returns NULL and sets *out_err to a positive errno.
struct andro_xsk *andro_xsk_open(const char *ifname, uint32_t queue_id,
                                 uint32_t n_frames, uint32_t frame_size,
                                 uint32_t fill_size, uint32_t comp_size,
                                 uint32_t rx_size, uint32_t tx_size,
                                 int xdp_mode, int *out_err) {
    struct andro_xsk *x = calloc(1, sizeof(*x));
    if (!x) { if (out_err) *out_err = ENOMEM; return NULL; }
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
    else                    scfg.xdp_flags = 0;
    // veth cannot do zero-copy; force copy mode and use need-wakeup semantics.
    scfg.bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY;

    err = xsk_socket__create(&x->xsk, ifname, queue_id, x->umem, &x->rx, &x->tx, &scfg);
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
        uint32_t slot_room = x->frame_size - (uint32_t)(a % x->frame_size);
        if (l > slot_room) l = slot_room;
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
