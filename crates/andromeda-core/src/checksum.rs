//! Internet checksum (RFC 1071) and incremental checksum update (RFC 1624).
//!
//! The incremental update is the part that matters for a NAT/overlay dataplane:
//! when we rewrite an IP address or a port in-place we must NOT recompute the
//! whole L4 checksum over the payload on every packet — that would trash the
//! latency budget. Instead we adjust the existing checksum by the 16-bit delta
//! of only the fields we touched. This is exactly what the Linux kernel and every
//! serious software router does.

/// Compute the one's-complement 16-bit Internet checksum over `data`.
///
/// Returns the value in host byte order, ready to be written big-endian into a
/// header field. The result is the bitwise-NOT of the folded one's-complement sum.
#[must_use]
pub fn checksum(data: &[u8]) -> u16 {
    !fold(sum_be16(data))
}

/// Sum a byte slice as a sequence of big-endian 16-bit words into a 32-bit accumulator.
/// A trailing odd byte is treated as the high byte of a final word (low byte = 0).
#[must_use]
pub fn sum_be16(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([c[0], c[1]]) as u32);
    }
    if let [last] = chunks.remainder() {
        sum = sum.wrapping_add((u16::from_be_bytes([*last, 0])) as u32);
    }
    sum
}

/// Fold a 32-bit accumulator down to 16 bits by adding the carries back in.
#[must_use]
pub fn fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Continue an existing folded-sum accumulator with more data. Useful to build a
/// checksum across several non-contiguous regions (e.g. a pseudo-header + payload)
/// without allocating a scratch buffer.
#[must_use]
pub fn accumulate(acc: u32, data: &[u8]) -> u32 {
    acc.wrapping_add(sum_be16(data))
}

/// Finalize an accumulator produced by [`accumulate`]/[`sum_be16`] into a checksum field value.
#[must_use]
pub fn finalize(acc: u32) -> u16 {
    !fold(acc)
}

/// Incrementally update a 16-bit checksum after a field changed, per RFC 1624:
///
/// ```text
/// HC' = ~(~HC + ~m + m')
/// ```
///
/// where `HC` is the old checksum, `m` is the old 16-bit word, `m'` the new one.
/// Call once per changed 16-bit word. `old_check` and the return value are in
/// host order.
#[must_use]
pub fn update_word(old_check: u16, old: u16, new: u16) -> u16 {
    // Work in one's-complement arithmetic on the 32-bit accumulator, then fold.
    let mut sum = (!old_check as u32) & 0xffff;
    sum = sum.wrapping_add((!old as u32) & 0xffff);
    sum = sum.wrapping_add(new as u32);
    !fold(sum)
}

/// Incrementally update a checksum after a 32-bit field (e.g. an IPv4 address)
/// changed. Splits the change into its two 16-bit halves.
#[must_use]
pub fn update_dword(old_check: u16, old: u32, new: u32) -> u16 {
    let c = update_word(old_check, (old >> 16) as u16, (new >> 16) as u16);
    update_word(c, (old & 0xffff) as u16, (new & 0xffff) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_known_vector() {
        // Classic worked example from the checksum literature. Summing these
        // 16-bit words and taking the one's complement yields 0x220d.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_verifies_to_zero() {
        // A valid checksum, when included in the summed data, makes the running
        // sum fold to 0xffff (i.e. checksum-of-the-whole == 0).
        let mut data = vec![0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
                            0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
                            0xac, 0x10, 0x0a, 0x0c];
        let c = checksum(&data);
        data[10] = (c >> 8) as u8;
        data[11] = (c & 0xff) as u8;
        assert_eq!(checksum(&data), 0, "recomputing over data incl. checksum must be 0");
    }

    #[test]
    fn odd_length_uses_high_byte() {
        // A trailing odd byte is the high byte of the final word.
        assert_eq!(sum_be16(&[0x12, 0x34, 0x56]), 0x1234 + 0x5600);
    }

    #[test]
    fn incremental_matches_full_recompute() {
        // Build an IPv4-ish header, checksum it, mutate a 32-bit field, and show
        // the incremental update equals a from-scratch recompute.
        let mut hdr = [0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
                       0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
                       0xac, 0x10, 0x0a, 0x0c];
        let c0 = checksum(&hdr);
        hdr[10] = (c0 >> 8) as u8;
        hdr[11] = (c0 & 0xff) as u8;

        // Change source address 172.16.10.99 -> 10.0.0.7 (SNAT-style rewrite).
        let old_src = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
        let new_src = u32::from_be_bytes([10, 0, 0, 7]);
        hdr[12..16].copy_from_slice(&new_src.to_be_bytes());

        let incremental = update_dword(c0, old_src, new_src);

        // Full recompute for comparison (zero the field first).
        hdr[10] = 0;
        hdr[11] = 0;
        let full = checksum(&hdr);
        assert_eq!(incremental, full, "incremental update must equal full recompute");
    }
}
