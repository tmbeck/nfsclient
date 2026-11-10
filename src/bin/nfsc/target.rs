//! Target syntax for `nfsc shell`.
//!
//! - `nfs://host[:port]/path` (IPv6 literals in brackets: `nfs://[::1]:2049/export/x`)
//! - `host:/path` (IPv6 literals in brackets: `[::1]:/export`)
//!
//! The path is a full server path. Which export it lives in is decided by
//! `fs::connect`, not by the parser, so `nfs://nas/srv/data/x` works whatever
//! the export names are.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host name or IP literal, without brackets.
    pub host: String,
    /// Port from an `nfs://host:port/...` target.
    pub port: Option<u16>,
    /// Absolute server path, normalized (no empty, `.` or `..` segments). `/` when none was given.
    pub path: String,
}

pub fn parse_target(s: &str) -> Result<Target, String> {
    if let Some(rest) = s.strip_prefix("nfs://") {
        let (authority, path_part) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let (host, port) = split_host_port(authority, s)?;
        let path = normalize_path(path_part, s)?;
        return Ok(Target { host, port, path });
    }
    if let Some(i) = s.find(":/") {
        let (host_part, rest) = (&s[..i], &s[i + 1..]);
        let (host, port) = split_host_port(host_part, s)?;
        if port.is_some() {
            return Err(format!("'{s}': use nfs://host:port/path to give a port"));
        }
        let path = normalize_path(rest, s)?;
        return Ok(Target {
            host,
            port: None,
            path,
        });
    }
    Err(format!(
        "'{s}': expected nfs://host[:port]/path or host:/path"
    ))
}

/// Parses `host`, `host:port`, `[v6]`, or `[v6]:port`.
fn split_host_port(authority: &str, whole: &str) -> Result<(String, Option<u16>), String> {
    if let Some(inner) = authority.strip_prefix('[') {
        let (host, after) = inner
            .split_once(']')
            .ok_or_else(|| format!("'{whole}': unterminated '[' in host"))?;
        if host.is_empty() {
            return Err(format!("'{whole}': empty host"));
        }
        let port = match after {
            "" => None,
            p if p.starts_with(':') => Some(parse_port(&p[1..], whole)?),
            _ => return Err(format!("'{whole}': unexpected text after ']'")),
        };
        return Ok((host.to_string(), port));
    }
    let (host, port) = match authority.matches(':').count() {
        0 => (authority, None),
        1 => {
            let (h, p) = authority.split_once(':').expect("one colon");
            (h, Some(parse_port(p, whole)?))
        }
        _ => {
            return Err(format!(
                "'{whole}': IPv6 host addresses must be in [brackets]"
            ));
        }
    };
    if host.is_empty() {
        return Err(format!("'{whole}': empty host"));
    }
    Ok((host.to_string(), port))
}

fn parse_port(p: &str, whole: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("'{whole}': invalid port '{p}'")),
        Ok(n) => Ok(n),
    }
}

/// `/a//b/` becomes `/a/b`; an empty path becomes `/`.
fn normalize_path(path_part: &str, whole: &str) -> Result<String, String> {
    let segs: Vec<&str> = path_part.split('/').filter(|s| !s.is_empty()).collect();
    if let Some(bad) = segs.iter().find(|s| **s == "." || **s == "..") {
        return Err(format!(
            "'{whole}': '{bad}' is not allowed in a target path"
        ));
    }
    if segs.is_empty() {
        return Ok("/".to_string());
    }
    Ok(format!("/{}", segs.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, port: Option<u16>, path: &str) -> Target {
        Target {
            host: host.into(),
            port,
            path: path.into(),
        }
    }

    #[test]
    fn nfs_url_forms() {
        assert_eq!(
            parse_target("nfs://nas/export").unwrap(),
            t("nas", None, "/export")
        );
        assert_eq!(
            parse_target("nfs://nas:2049/export/a/b").unwrap(),
            t("nas", Some(2049), "/export/a/b")
        );
        assert_eq!(
            parse_target("nfs://nas/export/").unwrap(),
            t("nas", None, "/export")
        );
        assert_eq!(
            parse_target("nfs://nas//export//a/").unwrap(),
            t("nas", None, "/export/a")
        );
        assert_eq!(parse_target("nfs://nas").unwrap(), t("nas", None, "/"));
        assert_eq!(parse_target("nfs://nas/").unwrap(), t("nas", None, "/"));
    }

    #[test]
    fn full_path_is_kept_without_guessing_an_export() {
        // The first segment is not special: a multi-segment export is just a path.
        assert_eq!(
            parse_target("nfs://nas/srv/data/x").unwrap(),
            t("nas", None, "/srv/data/x")
        );
        assert_eq!(
            parse_target("nas:/srv/data").unwrap(),
            t("nas", None, "/srv/data")
        );
    }

    #[test]
    fn nfs_url_ipv6() {
        assert_eq!(
            parse_target("nfs://[fd00::5]/export").unwrap(),
            t("fd00::5", None, "/export")
        );
        assert_eq!(
            parse_target("nfs://[::1]:2049/export/x").unwrap(),
            t("::1", Some(2049), "/export/x")
        );
    }

    #[test]
    fn host_colon_slash_forms() {
        assert_eq!(
            parse_target("nas:/export").unwrap(),
            t("nas", None, "/export")
        );
        assert_eq!(
            parse_target("nas:/export/dir/sub").unwrap(),
            t("nas", None, "/export/dir/sub")
        );
        assert_eq!(
            parse_target("[fd00::5]:/export").unwrap(),
            t("fd00::5", None, "/export")
        );
        assert_eq!(parse_target("nas:/").unwrap(), t("nas", None, "/"));
    }

    #[test]
    fn rejects_bad_targets() {
        for bad in [
            "",
            "nas",
            "nas:export",
            "nfs://",
            "nfs:///export",
            "nfs://nas:0/export",
            "nfs://nas:99999/export",
            "nfs://nas:abc/export",
            "nfs://[::1/export",
            "nfs://[]/export",
            "nfs://[::1]x/export",
            "nfs://fd00::5/export",
            "fd00::5:/export",
            "nfs://nas/export/../etc",
            "nas:/export/./x",
            "nas:[::1]:/export",
            "nfs://nas:2049:1/export",
        ] {
            assert!(parse_target(bad).is_err(), "expected error for {bad:?}");
        }
    }

    #[test]
    fn host_colon_slash_rejects_port() {
        assert!(parse_target("nas:2049:/export").is_err());
    }
}
