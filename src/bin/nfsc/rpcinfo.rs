//! `rpcinfo -p` style output: table formatting and RPC service names.

use std::collections::HashMap;

use nfsc::portmap::Mapping;
use nfsc::rpc::Proto;

const HEADER: &str = "   program vers proto   port  service\n";

/// Well-known program names, used when /etc/rpc does not list a number.
const BUILTIN: &[(u32, &str)] = &[
    (100000, "portmapper"),
    (100001, "rstatd"),
    (100002, "rusersd"),
    (100003, "nfs"),
    (100004, "ypserv"),
    (100005, "mountd"),
    (100007, "ypbind"),
    (100008, "walld"),
    (100009, "yppasswdd"),
    (100010, "etherstatd"),
    (100011, "rquotad"),
    (100012, "sprayd"),
    (100013, "3270_mapper"),
    (100014, "rje_mapper"),
    (100015, "selection_svc"),
    (100016, "database_svc"),
    (100017, "rexd"),
    (100018, "alis"),
    (100019, "sched"),
    (100020, "llockmgr"),
    (100021, "nlockmgr"),
    (100022, "x25.inr"),
    (100023, "statmon"),
    (100024, "status"),
    (100026, "bootparam"),
    (100028, "ypupdated"),
    (100029, "keyserv"),
    (100033, "sunlink_mapper"),
    (100227, "nfs_acl"),
    (150001, "pcnfs"),
];

/// Program number to service name.
#[derive(Debug, Default, Clone)]
pub struct ServiceNames {
    map: HashMap<u32, String>,
}

impl ServiceNames {
    /// Names from /etc/rpc when present, then the built-in table for anything missing.
    pub fn load() -> Self {
        let mut names = std::fs::read_to_string("/etc/rpc")
            .map(|text| Self::parse_rpc(&text))
            .unwrap_or_default();
        names.add_builtin();
        names
    }

    /// Parses /etc/rpc: `name number [aliases...]`, `#` starts a comment.
    /// The first entry for a number wins, as with getrpcbynumber(3).
    pub fn parse_rpc(text: &str) -> Self {
        let mut map = HashMap::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut fields = line.split_whitespace();
            let (Some(name), Some(num)) = (fields.next(), fields.next()) else {
                continue;
            };
            if let Ok(num) = num.parse::<u32>() {
                map.entry(num).or_insert_with(|| name.to_string());
            }
        }
        Self { map }
    }

    fn add_builtin(&mut self) {
        for &(num, name) in BUILTIN {
            self.map.entry(num).or_insert_with(|| name.to_string());
        }
    }

    pub fn name(&self, prog: u32) -> Option<&str> {
        self.map.get(&prog).map(String::as_str)
    }
}

/// Renders mappings with the same layout as `rpcinfo -p`, in the order given.
pub fn format_table(mappings: &[Mapping], names: &ServiceNames) -> String {
    let mut out = String::from(HEADER);
    for m in mappings {
        let proto = match Proto::from_ipproto(m.prot) {
            Some(p) => p.name().to_string(),
            None => m.prot.to_string(),
        };
        out.push_str(&format!(
            "{:>10}{:>5}   {:<5}{:>5}",
            m.prog, m.vers, proto, m.port
        ));
        // rpcinfo prints the name column only for known programs.
        if let Some(service) = names.name(m.prog) {
            out.push_str("  ");
            out.push_str(service);
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(prog: u32, vers: u32, prot: u32, port: u32) -> Mapping {
        Mapping {
            prog,
            vers,
            prot,
            port,
        }
    }

    #[test]
    fn golden_table() {
        let names = ServiceNames::parse_rpc("portmapper 100000 portmap\nnfs 100003 nfsprog\n");
        let mappings = vec![
            m(100000, 2, 6, 111),
            m(100000, 2, 17, 111),
            m(100005, 1, 17, 56107),
            m(100003, 3, 6, 2049),
            m(100227, 3, 6, 2049),
            m(100021, 4, 17, 60623),
            m(999999, 1, 6, 12345),
        ];
        // Unknown program names: rpcinfo omits the service column entirely.
        let expected = [
            "   program vers proto   port  service",
            "    100000    2   tcp    111  portmapper",
            "    100000    2   udp    111  portmapper",
            "    100005    1   udp  56107",
            "    100003    3   tcp   2049  nfs",
            "    100227    3   tcp   2049",
            "    100021    4   udp  60623",
            "    999999    1   tcp  12345",
            "",
        ]
        .join("\n");
        assert_eq!(format_table(&mappings, &names), expected);
    }

    #[test]
    fn header_only_when_empty() {
        assert_eq!(format_table(&[], &ServiceNames::default()), HEADER);
    }

    #[test]
    fn parse_rpc_ignores_comments_and_bad_lines() {
        let text = "\
#ident \"@(#)rpc 1.11\"
# comment
portmapper\t100000\tportmap sunrpc rpcbind
rstatd\t\t100001\trstat rup perfmeter rstat_svc
bogus
dup\t100000
debug_svc \t100066  dbsrv
badnum\tnotanumber
nfs_acl\t\t100227
  nfs 100003 nfsprog # trailing comment
";
        let names = ServiceNames::parse_rpc(text);
        assert_eq!(names.name(100000), Some("portmapper"));
        assert_eq!(names.name(100001), Some("rstatd"));
        assert_eq!(names.name(100066), Some("debug_svc"));
        assert_eq!(names.name(100227), Some("nfs_acl"));
        assert_eq!(names.name(100003), Some("nfs"));
        assert_eq!(names.name(42), None);
    }

    #[test]
    fn builtin_fills_gaps() {
        let mut names = ServiceNames::parse_rpc("mountd 100005\n");
        names.add_builtin();
        assert_eq!(names.name(100005), Some("mountd"));
        assert_eq!(names.name(100024), Some("status"));
        assert_eq!(names.name(100021), Some("nlockmgr"));
    }

    #[test]
    fn unknown_protocol_number_is_printed_raw() {
        let t = format_table(&[m(100000, 2, 1, 111)], &ServiceNames::default());
        assert!(t.ends_with("    100000    2   1      111\n"), "{t:?}");
    }
}
