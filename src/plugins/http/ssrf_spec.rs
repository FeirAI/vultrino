//! Independent specification of the SSRF address classifier, used only by the
//! Kani proofs and the table-consistency tests. It is compiled out of production
//! builds. It deliberately does NOT import `IPV4_BLOCKED` / `IPV6_BLOCKED` or the
//! helpers in the parent module: the tables below are a separate transcription of
//! the IANA Special-Purpose Address Registry snapshots committed under
//! `formal/vectors/`, written as octets / 16-bit groups instead of packed integers,
//! and the prefix test uses a different formulation (xor and shift, not mask).
//!
//! Blocked iff the address is in a range the registry marks "Globally Reachable:
//! False" (REGISTRY tables), or in a documented extra-policy range (POLICY
//! tables), or, for IPv6, it carries an IPv4 address in a decoded form (IPv4-mapped,
//! NAT64, 6to4) and that IPv4 address is blocked.

/// `a` is inside `net`/`len`. xor-and-shift formulation.
const fn in4(a: u32, o: [u8; 4], len: u8) -> bool {
    let net = u32::from_be_bytes(o);
    len == 0 || ((a ^ net) >> (32 - len as u32)) == 0
}

const fn in6(a: u128, g: [u16; 8], len: u8) -> bool {
    let mut net: u128 = 0;
    let mut i = 0;
    while i < 8 {
        net = (net << 16) | g[i] as u128;
        i += 1;
    }
    len == 0 || ((a ^ net) >> (128 - len as u32)) == 0
}

/// IPv4 rows the registry marks not globally reachable, reduced to the maximal
/// rows (sub-rows such as 192.0.0.0/29 or 255.255.255.255/32 are contained in
/// these). Carve-outs the registry marks reachable (192.0.0.9/32, 192.0.0.10/32)
/// are NOT carved out here: the guard blocks them on purpose.
#[cfg(any(test, kani))]
const REGISTRY_V4: [([u8; 4], u8); 13] = [
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([240, 0, 0, 0], 4),
];

/// Extra IPv4 policy: all of multicast (not in the registry) and the deprecated
/// 6to4 relay anycast block (its registry row has no Globally Reachable value).
#[cfg(any(test, kani))]
const POLICY_V4: [([u8; 4], u8); 2] = [([224, 0, 0, 0], 4), ([192, 88, 99, 0], 24)];

/// IPv6 rows marked not globally reachable, maximal rows only, excluding the
/// IPv4-mapped row (::ffff:0:0/96), which is decoded instead of blocked outright.
/// 2001::/23 contains Teredo 2001::/32 and the benchmarking row 2001:2::/48.
#[cfg(any(test, kani))]
const REGISTRY_V6: [([u16; 8], u8); 11] = [
    ([0, 0, 0, 0, 0, 0, 0, 1], 128),
    ([0, 0, 0, 0, 0, 0, 0, 0], 128),
    ([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
    ([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
    ([0x100, 0, 0, 1, 0, 0, 0, 0], 64),
    ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
    ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
    ([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16),
    ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
];

/// Extra IPv6 policy: IPv4-compatible ::/96 (deprecated), site-local fec0::/10
/// (deprecated) and all of multicast ff00::/8.
#[cfg(any(test, kani))]
const POLICY_V6: [([u16; 8], u8); 3] = [
    ([0, 0, 0, 0, 0, 0, 0, 0], 96),
    ([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
];

/// IPv4 spec: blocked iff in a registry row or a policy row.
#[cfg(any(test, kani))]
fn spec_v4(a: u32) -> bool {
    let mut i = 0;
    while i < REGISTRY_V4.len() {
        if in4(a, REGISTRY_V4[i].0, REGISTRY_V4[i].1) {
            return true;
        }
        i += 1;
    }
    let mut j = 0;
    while j < POLICY_V4.len() {
        if in4(a, POLICY_V4[j].0, POLICY_V4[j].1) {
            return true;
        }
        j += 1;
    }
    false
}

/// IPv6 spec. Decode rules: IPv4-mapped (::ffff:0:0/96), NAT64 (64:ff9b::/32, a
/// conservative superset of the /96 well-known prefix: the shipped decode does not
/// check the middle 64 bits, which only over-blocks) and 6to4 (2002::/16) classify
/// the embedded IPv4 address with `spec_v4`. Teredo (2001::/32) and 64:ff9b:1::/48
/// are blocked outright by the registry table.
#[cfg(any(test, kani))]
fn spec_v6(a: u128) -> bool {
    let mut i = 0;
    while i < REGISTRY_V6.len() {
        if in6(a, REGISTRY_V6[i].0, REGISTRY_V6[i].1) {
            return true;
        }
        i += 1;
    }
    let mut j = 0;
    while j < POLICY_V6.len() {
        if in6(a, POLICY_V6[j].0, POLICY_V6[j].1) {
            return true;
        }
        j += 1;
    }
    if in6(a, [0, 0, 0, 0, 0, 0xffff, 0, 0], 96) {
        return spec_v4(a as u32);
    }
    if in6(a, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 32) {
        return spec_v4(a as u32);
    }
    if in6(a, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16) {
        return spec_v4((a >> 80) as u32);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const V4_CSV: &str = include_str!("../../../formal/vectors/iana-ipv4-special-registry-1.csv");
    const V6_CSV: &str = include_str!("../../../formal/vectors/iana-ipv6-special-registry-1.csv");

    /// Minimal RFC 4180 reader: quoted cells may hold commas and newlines.
    fn parse_csv(text: &str) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        let mut row: Vec<String> = Vec::new();
        let mut cell = String::new();
        let mut quoted = false;
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            match (quoted, c) {
                (true, '"') if chars.peek() == Some(&'"') => {
                    cell.push('"');
                    chars.next();
                }
                (true, '"') => quoted = false,
                (true, _) => cell.push(c),
                (false, '"') => quoted = true,
                (false, ',') => row.push(std::mem::take(&mut cell)),
                (false, '\n') => {
                    row.push(std::mem::take(&mut cell));
                    rows.push(std::mem::take(&mut row));
                }
                (false, '\r') => {}
                (false, _) => cell.push(c),
            }
        }
        if !cell.is_empty() || !row.is_empty() {
            row.push(cell);
            rows.push(row);
        }
        rows
    }

    /// Strip a trailing footnote marker such as " [2]".
    fn strip_note(s: &str) -> &str {
        s.split(" [").next().unwrap().trim()
    }

    /// (network, len) rows whose "Globally Reachable" cell is `False` (footnote
    /// markers ignored). `N/A` and empty cells are not matched.
    fn false_rows(csv: &str) -> Vec<(String, u8)> {
        let rows = parse_csv(csv);
        let gr = rows[0]
            .iter()
            .position(|h| h == "Globally Reachable")
            .expect("Globally Reachable column");
        let mut out = Vec::new();
        for r in &rows[1..] {
            if strip_note(&r[gr]) != "False" {
                continue;
            }
            for block in r[0].split(',') {
                let (net, len) = strip_note(block).split_once('/').expect("prefix");
                out.push((net.to_string(), len.parse().expect("len")));
            }
        }
        out
    }

    fn contains4(outer: (u32, u8), inner: (u32, u8)) -> bool {
        outer.1 <= inner.1 && (outer.1 == 0 || (outer.0 ^ inner.0) >> (32 - outer.1 as u32) == 0)
    }

    fn contains6(outer: (u128, u8), inner: (u128, u8)) -> bool {
        outer.1 <= inner.1 && (outer.1 == 0 || (outer.0 ^ inner.0) >> (128 - outer.1 as u32) == 0)
    }

    fn maximal<T: Copy + Ord>(
        rows: &[(T, u8)],
        contains: fn((T, u8), (T, u8)) -> bool,
    ) -> BTreeSet<(T, u8)> {
        rows.iter()
            .copied()
            .filter(|r| !rows.iter().any(|o| o != r && contains(*o, *r)))
            .collect()
    }

    fn v4_csv_rows() -> Vec<(u32, u8)> {
        false_rows(V4_CSV)
            .into_iter()
            .map(|(n, l)| (u32::from(n.parse::<Ipv4Addr>().unwrap()), l))
            .collect()
    }

    #[test]
    fn spec_v4_registry_table_equals_committed_csv_false_rows() {
        let csv = v4_csv_rows();
        assert!(csv.len() >= 13, "csv parse lost rows: {}", csv.len());
        let spec: BTreeSet<(u32, u8)> = REGISTRY_V4
            .iter()
            .map(|(o, l)| (u32::from_be_bytes(*o), *l))
            .collect();
        // 192.88.99.2/32 (6a44 relay) is a False row inside the policy block
        // 192.88.99.0/24, so the policy row subsumes it.
        let policy: Vec<(u32, u8)> = POLICY_V4
            .iter()
            .map(|(o, l)| (u32::from_be_bytes(*o), *l))
            .collect();
        let uncovered: Vec<(u32, u8)> = csv
            .into_iter()
            .filter(|r| !policy.iter().any(|p| contains4(*p, *r)))
            .collect();
        assert_eq!(spec, maximal(&uncovered, contains4));
    }

    #[test]
    fn spec_v6_registry_table_equals_committed_csv_false_rows() {
        let csv: Vec<(u128, u8)> = false_rows(V6_CSV)
            .into_iter()
            .map(|(n, l)| (u128::from(n.parse::<Ipv6Addr>().unwrap()), l))
            .collect();
        assert!(csv.len() >= 10, "csv parse lost rows: {}", csv.len());
        // The IPv4-mapped row is decoded, not blocked outright: it is the one row
        // moved out of the outright table, and it must be present in the CSV.
        let mapped = (u128::from("::ffff:0:0".parse::<Ipv6Addr>().unwrap()), 96u8);
        assert!(csv.contains(&mapped), "IPv4-mapped row missing from CSV");
        let outright: Vec<(u128, u8)> = csv.into_iter().filter(|r| *r != mapped).collect();
        let to_u128 = |g: &[u16; 8]| g.iter().fold(0u128, |acc, s| (acc << 16) | *s as u128);
        let spec: BTreeSet<(u128, u8)> =
            REGISTRY_V6.iter().map(|(g, l)| (to_u128(g), *l)).collect();
        assert_eq!(spec, maximal(&outright, contains6));
    }

    #[test]
    fn spec_policy_rows_are_the_documented_additions() {
        // Documented extra policy: multicast and the deprecated 6to4 relay block
        // (IPv4); IPv4-compatible, site-local and multicast (IPv6). None of the
        // IPv4 policy rows is already a registry False row.
        assert_eq!(POLICY_V4.len(), 2);
        assert_eq!(POLICY_V6.len(), 3);
        let v4 = v4_csv_rows();
        for (o, l) in POLICY_V4 {
            let row = (u32::from_be_bytes(o), l);
            assert!(
                !v4.contains(&row),
                "policy row {row:?} is already a registry row"
            );
        }
        // Rows the registry marks reachable or N/A that the policy blocks anyway
        // must exist in the snapshot, so a registry change that moves them shows.
        for needle in ["192.0.0.9/32", "192.0.0.10/32", "192.88.99.0/24"] {
            assert!(
                V4_CSV.contains(needle),
                "{needle} missing from the IPv4 snapshot"
            );
        }
        for needle in ["2001::/32", "2002::/16", "64:ff9b::/96", "64:ff9b:1::/48"] {
            assert!(
                V6_CSV.contains(needle),
                "{needle} missing from the IPv6 snapshot"
            );
        }
    }

    #[test]
    fn spec_matches_shipped_classifier_on_probe_addresses() {
        // Cheap runtime cross-check of the spec against the shipped function; the
        // exhaustive comparison is the Kani harnesses.
        use super::super::HttpPlugin;
        use std::net::IpAddr;
        for a in [
            0u32,
            0x0a00_0001,
            0x0808_0808,
            0xe000_0001,
            0xc000_0009,
            0xc058_6301,
            0xffff_ffff,
        ] {
            assert_eq!(
                HttpPlugin::is_private_ip(&IpAddr::V4(Ipv4Addr::from(a))),
                spec_v4(a),
                "{a:#x}"
            );
        }
        for s in [
            "::1",
            "::ffff:10.0.0.1",
            "::ffff:8.8.8.8",
            "64:ff9b::a00:1",
            "64:ff9b::808:808",
            "2002:a00:1::1",
            "2002:808:808::1",
            "2001::1",
            "2606:4700::1",
            "fec0::1",
            "ff02::1",
        ] {
            let ip: Ipv6Addr = s.parse().unwrap();
            assert_eq!(
                HttpPlugin::is_private_ip(&IpAddr::V6(ip)),
                spec_v6(u128::from(ip)),
                "{s}"
            );
        }
    }
}

#[cfg(kani)]
mod kani_ssrf_proofs {
    use super::super::HttpPlugin;
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// For every IPv4 address, the shipped classifier equals the independent spec.
    #[kani::proof]
    #[kani::unwind(20)]
    fn ipv4_classifier_equals_spec_over_all_u32() {
        let a: u32 = kani::any();
        let got = HttpPlugin::is_private_ip(&IpAddr::V4(Ipv4Addr::from(a)));
        kani::cover!(got, "some IPv4 address is blocked");
        kani::cover!(!got, "some IPv4 address is allowed");
        kani::cover!(in4(a, [224, 0, 0, 0], 4) && got, "multicast blocked");
        kani::cover!(
            in4(a, [192, 0, 0, 9], 32) && got,
            "registry-reachable carve-out blocked by policy"
        );
        assert_eq!(got, spec_v4(a));
    }

    /// For every IPv6 address, the shipped classifier equals the independent spec.
    /// A single harness over the whole 2^128 domain: `a` is fully symbolic, so no
    /// split by prefix class is used and none needs justifying.
    #[kani::proof]
    #[kani::unwind(20)]
    fn ipv6_classifier_equals_spec_over_all_u128() {
        let a: u128 = kani::any();
        let got = HttpPlugin::is_private_ip(&IpAddr::V6(Ipv6Addr::from(a)));
        let mapped = in6(a, [0, 0, 0, 0, 0, 0xffff, 0, 0], 96);
        let nat64_local = in6(a, [0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48);
        let nat64 = in6(a, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 32) && !nat64_local;
        let six4 = in6(a, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16);
        kani::cover!(mapped && got, "IPv4-mapped decode: embedded blocked");
        kani::cover!(mapped && !got, "IPv4-mapped decode: embedded allowed");
        kani::cover!(nat64 && got, "NAT64 decode: embedded blocked");
        kani::cover!(nat64 && !got, "NAT64 decode: embedded allowed");
        kani::cover!(six4 && got, "6to4 decode: embedded blocked");
        kani::cover!(six4 && !got, "6to4 decode: embedded allowed");
        kani::cover!(
            in6(a, [0x2001, 0, 0, 0, 0, 0, 0, 0], 32) && got,
            "Teredo blocked outright"
        );
        kani::cover!(nat64_local && got, "NAT64 local-use blocked outright");
        kani::cover!(
            !got && !mapped && !nat64 && !six4,
            "ordinary global address allowed"
        );
        assert_eq!(got, spec_v6(a));
    }
}
