//! Export target syntax.
//!
//! - `nfs://host[:port]/export[/path]` (IPv6 literals in brackets: `nfs://[::1]:2049/export`)
//! - `host:/export[/path]` (IPv6 literals in brackets: `[::1]:/export`)
//!
//! The export is the first path segment after the host. Exports whose names span
//! several segments (`/srv/data`) are resolved against the server's export list
//! once MOUNT EXPORT exists (milestone 2); until then the first segment is used.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host name or IP literal, without brackets.
    pub host: String,
    pub port: Option<u16>,
    /// Absolute export name, e.g. `/export`.
    pub export: String,
    /// Absolute path inside the export; `/` when none was given.
    pub path: String,
}

pub fn parse_target(s: &str) -> Result<Target, String> {
    if let Some(rest) = s.strip_prefix("nfs://") {
        let (authority, path_part) = rest
            .find('/')
            .map(|i| rest.split_at(i))
            .ok_or_else(|| format!("'{s}': missing /export after host"))?;
        let (host, port) = split_host_port(authority, s)?;
        let (export, path) = split_export(path_part, s)?;
        return Ok(Target {
            host,
            port,
            export,
            path,
        });
    }
    if let Some(i) = s.find(":/") {
        let (host_part, rest) = (&s[..i], &s[i + 1..]);
        let (host, port) = split_host_port(host_part, s)?;
        if port.is_some() {
            return Err(format!("'{s}': use nfs://host:port/export to give a port"));
        }
        let (export, path) = split_export(rest, s)?;
        return Ok(Target {
            host,
            port: None,
            export,
            path,
        });
    }
    Err(format!(
        "'{s}': expected nfs://host[:port]/export[/path] or host:/export[/path]"
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
            let (h, p) = authority.split_once(':').unwrap();
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

/// Splits `/export/sub/dir` into (`/export`, `/sub/dir`). Empty segments are ignored.
fn split_export(path_part: &str, whole: &str) -> Result<(String, String), String> {
    let segs: Vec<&str> = path_part.split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        return Err(format!("'{whole}': missing export name"));
    }
    if let Some(bad) = segs.iter().find(|s| **s == "." || **s == "..") {
        return Err(format!(
            "'{whole}': '{bad}' is not allowed in a target path"
        ));
    }
    let export = format!("/{}", segs[0]);
    let path = if segs.len() == 1 {
        "/".to_string()
    } else {
        format!("/{}", segs[1..].join("/"))
    };
    Ok((export, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, port: Option<u16>, export: &str, path: &str) -> Target {
        Target {
            host: host.into(),
            port,
            export: export.into(),
            path: path.into(),
        }
    }

    #[test]
    fn nfs_url_forms() {
        assert_eq!(
            parse_target("nfs://nas/export").unwrap(),
            t("nas", None, "/export", "/")
        );
        assert_eq!(
            parse_target("nfs://nas:2049/export/a/b").unwrap(),
            t("nas", Some(2049), "/export", "/a/b")
        );
        assert_eq!(
            parse_target("nfs://nas/export/").unwrap(),
            t("nas", None, "/export", "/")
        );
        assert_eq!(
            parse_target("nfs://nas//export//a/").unwrap(),
            t("nas", None, "/export", "/a")
        );
    }

    #[test]
    fn nfs_url_ipv6() {
        assert_eq!(
            parse_target("nfs://[fd00::5]/export").unwrap(),
            t("fd00::5", None, "/export", "/")
        );
        assert_eq!(
            parse_target("nfs://[::1]:2049/export/x").unwrap(),
            t("::1", Some(2049), "/export", "/x")
        );
    }

    #[test]
    fn host_colon_slash_forms() {
        assert_eq!(
            parse_target("nas:/export").unwrap(),
            t("nas", None, "/export", "/")
        );
        assert_eq!(
            parse_target("nas:/export/dir/sub").unwrap(),
            t("nas", None, "/export", "/dir/sub")
        );
        assert_eq!(
            parse_target("[fd00::5]:/export").unwrap(),
            t("fd00::5", None, "/export", "/")
        );
    }

    #[test]
    fn rejects_bad_targets() {
        for bad in [
            "",
            "nas",
            "nas:export",
            "nfs://",
            "nfs://nas",
            "nfs://nas/",
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
