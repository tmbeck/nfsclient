//! Output formatting for ls, stat and df. Times are rendered in UTC; no
//! timezone database is consulted.

use std::fmt::Write;

use nfsc::fs::{Attr, FileType, Time};

use crate::text::display_name;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Half a Gregorian year in seconds: ls shows the time of day for files newer
/// than this, and the year for older ones.
const HALF_YEAR: i64 = 15_778_476;

pub fn type_char(t: FileType) -> char {
    match t {
        FileType::Regular => '-',
        FileType::Directory => 'd',
        FileType::Symlink => 'l',
        FileType::BlockDevice => 'b',
        FileType::CharDevice => 'c',
        FileType::Socket => 's',
        FileType::Fifo => 'p',
        FileType::Other(_) => '?',
    }
}

pub fn type_name(t: FileType) -> &'static str {
    match t {
        FileType::Regular => "regular file",
        FileType::Directory => "directory",
        FileType::Symlink => "symbolic link",
        FileType::BlockDevice => "block special file",
        FileType::CharDevice => "character special file",
        FileType::Socket => "socket",
        FileType::Fifo => "fifo",
        FileType::Other(_) => "unknown",
    }
}

/// The ten-character `ls -l` mode string, including setuid/setgid/sticky.
pub fn mode_string(t: FileType, mode: u32) -> String {
    let mut out = [type_char(t), '-', '-', '-', '-', '-', '-', '-', '-', '-'];
    for (i, bit) in [0o400, 0o200, 0o100, 0o40, 0o20, 0o10, 0o4, 0o2, 0o1]
        .into_iter()
        .enumerate()
    {
        if mode & bit != 0 {
            out[i + 1] = ['r', 'w', 'x'][i % 3];
        }
    }
    // Special bits replace the execute letter: lower case when x is also set.
    for (idx, bit, on_exec, off_exec) in [
        (3, 0o4000, 's', 'S'),
        (6, 0o2000, 's', 'S'),
        (9, 0o1000, 't', 'T'),
    ] {
        if mode & bit != 0 {
            out[idx] = if out[idx] == 'x' { on_exec } else { off_exec };
        }
    }
    out.iter().collect()
}

/// Shows a name with `\xNN` escapes; see [`crate::text::display_name`].
pub fn name(raw: &[u8]) -> String {
    display_name(raw)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

/// Converts unix seconds to a UTC calendar date (proleptic Gregorian).
fn civil(secs: i64) -> Civil {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    Civil {
        year,
        month,
        day,
        hour: (rem / 3600) as u32,
        minute: ((rem % 3600) / 60) as u32,
        second: (rem % 60) as u32,
    }
}

/// `ls -l` time: `Mon dd HH:MM` for recent files, `Mon dd  YYYY` otherwise.
pub fn ls_time(mtime: i64, now: i64) -> String {
    let c = civil(mtime);
    let month = MONTHS[(c.month - 1) as usize];
    if (now - mtime).abs() < HALF_YEAR {
        format!("{month} {:>2} {:02}:{:02}", c.day, c.hour, c.minute)
    } else {
        format!("{month} {:>2}  {:>4}", c.day, c.year)
    }
}

/// `YYYY-MM-DD HH:MM:SS.nnnnnnnnn +0000`, as coreutils `stat` prints times.
pub fn full_time(t: Time) -> String {
    let c = civil(t.seconds);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:09} +0000",
        c.year, c.month, c.day, c.hour, c.minute, c.second, t.nseconds
    )
}

/// Owner as shown by ls and stat: the v4 owner string, else the numeric uid.
pub fn owner_of(attr: &Attr) -> String {
    attr.owner.clone().unwrap_or_else(|| attr.uid.to_string())
}

/// Group as shown by ls and stat: the v4 group string, else the numeric gid.
pub fn group_of(attr: &Attr) -> String {
    attr.group.clone().unwrap_or_else(|| attr.gid.to_string())
}

/// Sizes in the style of `df -h`: one decimal below 10, rounded up.
pub fn human(bytes: u64) -> String {
    const UNITS: [char; 6] = ['B', 'K', 'M', 'G', 'T', 'P'];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        return format!("{bytes}B");
    }
    if value < 10.0 {
        format!("{:.1}{}", (value * 10.0).ceil() / 10.0, UNITS[unit])
    } else {
        format!("{:.0}{}", value.ceil(), UNITS[unit])
    }
}

/// Names in ls column order (sorted down, then across) for a terminal `width`.
pub fn columns(names: &[String], width: usize) -> String {
    if names.is_empty() {
        return String::new();
    }
    let colw = names.iter().map(|n| n.chars().count()).max().unwrap_or(0) + 2;
    let cols = (width / colw).max(1);
    let rows = names.len().div_ceil(cols);
    let mut out = String::new();
    for r in 0..rows {
        let mut c = 0;
        while let Some(cell) = names.get(c * rows + r) {
            out.push_str(cell);
            let next = names.get((c + 1) * rows + r);
            if next.is_some() {
                let pad = colw - cell.chars().count();
                out.extend(std::iter::repeat_n(' ', pad));
            }
            c += 1;
        }
        out.push('\n');
    }
    out
}

/// One `ls -l` row, already resolved to display strings.
pub struct LongEntry {
    pub mode: String,
    pub nlink: u32,
    pub owner: String,
    pub group: String,
    pub size: u64,
    pub date: String,
    pub name: String,
}

/// Renders rows with columns aligned to the widest entry.
pub fn long_listing(entries: &[LongEntry]) -> String {
    let nlink_w = entries
        .iter()
        .map(|e| e.nlink.to_string().len())
        .max()
        .unwrap_or(1);
    let owner_w = entries
        .iter()
        .map(|e| e.owner.chars().count())
        .max()
        .unwrap_or(0);
    let group_w = entries
        .iter()
        .map(|e| e.group.chars().count())
        .max()
        .unwrap_or(0);
    let size_w = entries
        .iter()
        .map(|e| e.size.to_string().len())
        .max()
        .unwrap_or(1);
    let mut out = String::new();
    for e in entries {
        let _ = writeln!(
            out,
            "{} {:>nlink_w$} {:<owner_w$} {:<group_w$} {:>size_w$} {} {}",
            e.mode, e.nlink, e.owner, e.group, e.size, e.date, e.name
        );
    }
    out
}

/// The multi-line `stat` report. `link` is the target when the object is a symlink.
pub fn stat_text(name: &str, attr: &Attr, link: Option<&str>, io_size: u32) -> String {
    let mut out = String::new();
    let label = match link {
        Some(target) => format!("{name} -> {target}"),
        None => name.to_string(),
    };
    let _ = writeln!(out, "  File: {label}");
    let _ = writeln!(
        out,
        "  Size: {:<15} Blocks: {:<10} IO Block: {:<6} {}",
        attr.size,
        attr.used.div_ceil(512),
        io_size,
        type_name(attr.ftype)
    );
    let _ = writeln!(
        out,
        "Device: {:x}h/{}d  Inode: {:<11} Links: {}",
        attr.fsid, attr.fsid, attr.fileid, attr.nlink
    );
    let _ = writeln!(
        out,
        "Access: ({:04o}/{})  Uid: ({:>5}/{:>8})   Gid: ({:>5}/{:>8})",
        attr.mode & 0o7777,
        mode_string(attr.ftype, attr.mode),
        attr.uid,
        owner_of(attr),
        attr.gid,
        group_of(attr)
    );
    let _ = writeln!(out, "Access: {}", full_time(attr.atime));
    let _ = writeln!(out, "Modify: {}", full_time(attr.mtime));
    let _ = writeln!(out, "Change: {}", full_time(attr.ctime));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_strings_include_type_and_special_bits() {
        assert_eq!(mode_string(FileType::Regular, 0o644), "-rw-r--r--");
        assert_eq!(mode_string(FileType::Directory, 0o755), "drwxr-xr-x");
        assert_eq!(mode_string(FileType::Symlink, 0o777), "lrwxrwxrwx");
        assert_eq!(mode_string(FileType::Regular, 0o4755), "-rwsr-xr-x");
        assert_eq!(mode_string(FileType::Regular, 0o4644), "-rwSr--r--");
        assert_eq!(mode_string(FileType::Directory, 0o1777), "drwxrwxrwt");
        assert_eq!(mode_string(FileType::Directory, 0o1776), "drwxrwxrwT");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(
            civil(0),
            Civil {
                year: 1970,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0
            }
        );
        // 2026-11-09 19:52:07 UTC (checked with `date -u -d`)
        let c = civil(1_794_253_927);
        assert_eq!(
            (c.year, c.month, c.day, c.hour, c.minute),
            (2026, 11, 9, 19, 52)
        );
        // A leap day and the last second of a year.
        assert_eq!(civil(951_782_400).day, 29); // 2000-02-29
        assert_eq!(civil(1_735_689_599).year, 2024); // 2024-12-31 23:59:59
    }

    #[test]
    fn ls_time_switches_between_clock_and_year() {
        let now = 1_700_000_000; // 2023-11-14 22:13:20 UTC
        let recent = now - 3600;
        assert_eq!(ls_time(recent, now), "Nov 14 21:13");
        let old = now - 2 * HALF_YEAR; // about a year back
        assert_eq!(ls_time(old, now), "Nov 14  2022");
        assert_eq!(ls_time(0, 0), "Jan  1 00:00");
        // Single-digit days are space padded to two columns.
        assert_eq!(
            ls_time(1_704_067_200 + 60, 1_704_067_200 + 120),
            "Jan  1 00:01"
        );
    }

    #[test]
    fn full_time_format() {
        let t = Time {
            seconds: 1_700_000_000,
            nseconds: 5,
        };
        assert_eq!(full_time(t), "2023-11-14 22:13:20.000000005 +0000");
    }

    #[test]
    fn human_sizes_like_df_h() {
        assert_eq!(human(512), "512B");
        assert_eq!(human(1024), "1.0K");
        assert_eq!(human(1536), "1.5K");
        assert_eq!(human(4_500_000_000), "4.2G");
        assert_eq!(human(42 * 1024 * 1024 * 1024), "42G");
    }

    #[test]
    fn columns_fill_down_then_across() {
        let names: Vec<String> = ["a", "bb", "ccc", "d", "e"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // colw = 5, width 12 -> 2 columns, 3 rows
        assert_eq!(columns(&names, 12), "a    d\nbb   e\nccc\n");
        // Narrow terminal: one per line.
        assert_eq!(columns(&names, 4), "a\nbb\nccc\nd\ne\n");
        assert_eq!(columns(&[], 80), "");
    }

    #[test]
    fn long_listing_aligns_columns() {
        let rows = vec![
            LongEntry {
                mode: "-rw-r--r--".into(),
                nlink: 1,
                owner: "root".into(),
                group: "wheel".into(),
                size: 5,
                date: "Nov 14 21:13".into(),
                name: "a".into(),
            },
            LongEntry {
                mode: "drwxr-xr-x".into(),
                nlink: 12,
                owner: "1000".into(),
                group: "100".into(),
                size: 4096,
                date: "Jan  1  2020".into(),
                name: "dir".into(),
            },
        ];
        assert_eq!(
            long_listing(&rows),
            "-rw-r--r--  1 root wheel    5 Nov 14 21:13 a\n\
             drwxr-xr-x 12 1000 100   4096 Jan  1  2020 dir\n"
        );
    }

    #[test]
    fn stat_report_golden() {
        let t = Time {
            seconds: 1_700_000_000,
            nseconds: 0,
        };
        let attr = Attr {
            ftype: FileType::Regular,
            mode: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 100,
            owner: None,
            group: None,
            size: 12,
            used: 4096,
            rdev: (0, 0),
            fsid: 0x2a,
            fileid: 77,
            atime: t,
            mtime: t,
            ctime: t,
        };
        let text = stat_text("notes.txt", &attr, None, 65536);
        assert_eq!(
            text,
            "  File: notes.txt\n\
             \x20 Size: 12              Blocks: 8          IO Block: 65536  regular file\n\
             Device: 2ah/42d  Inode: 77          Links: 1\n\
             Access: (0644/-rw-r--r--)  Uid: ( 1000/    1000)   Gid: (  100/     100)\n\
             Access: 2023-11-14 22:13:20.000000000 +0000\n\
             Modify: 2023-11-14 22:13:20.000000000 +0000\n\
             Change: 2023-11-14 22:13:20.000000000 +0000\n"
        );
        let link = stat_text("ln", &attr, Some("notes.txt"), 4096);
        assert!(link.starts_with("  File: ln -> notes.txt\n"));
    }
}
