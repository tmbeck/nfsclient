//! Transfer progress bars on stderr, drawn with `indicatif`.
//!
//! A single file shows one bar:
//!
//! ```text
//! backup.tar.zst  ██████████▋          52%  620 MiB/1.2 GiB  845 MiB/s  1s
//! ```
//!
//! Recursive transfers (`get -r`, `put -r`) add a totals bar for the whole
//! tree under the current file's bar, sized by a scan before the transfer:
//!
//! ```text
//! total 12/40     ████▎                21%  1.5 GiB/7.0 GiB 845 MiB/s  6s
//! ```
//!
//! Bars are only drawn when stderr is a terminal (`Session::progress`).
//! Text written to stderr during a recursive transfer goes through
//! [`LineWriter`], which pauses the bars for each whole line.

use std::io::{self, Write};
use std::time::Instant;

use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};

/// Single files smaller than this get no bar (inside a tree, the totals bar
/// still moves).
pub(super) const PROGRESS_MIN: u64 = 1 << 20;

fn unicode_locale() -> bool {
    // The first of these that is set and non-empty decides, as in setlocale(3).
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            let v = v.to_ascii_lowercase();
            return v.contains("utf-8") || v.contains("utf8");
        }
    }
    false
}

/// Bar style; `label_width` keeps the file and totals bars aligned.
pub(super) fn style() -> ProgressStyle {
    let template = "{msg:<24!} {wide_bar} {percent:>3}%  {bytes:>10}/{total_bytes:<10} \
                    {bytes_per_sec:>12}  {eta:>3}";
    let chars = if unicode_locale() {
        "█▉▊▋▌▍▎▏ "
    } else {
        "#>-"
    };
    ProgressStyle::with_template(template)
        .expect("valid progress template")
        .progress_chars(chars)
}

fn new_bar(len: u64, start: u64, label: &str) -> ProgressBar {
    let bar = ProgressBar::hidden();
    bar.set_style(style());
    bar.set_length(len);
    bar.set_position(start);
    // Rate and ETA should reflect this run, not bytes already present (-c).
    bar.reset_eta();
    bar.set_message(label.to_string());
    bar
}

/// Totals for a recursive transfer. Lives on the session for the length of
/// one `get -r` / `put -r`; each file's [`Meter`] borrows it.
pub(super) struct TreeProgress {
    multi: MultiProgress,
    /// The totals bar, present when a pre-scan sized the tree.
    total: Option<ProgressBar>,
    /// Files found by the pre-scan.
    files: u64,
    /// Files finished so far.
    pub files_done: u64,
    /// Bytes of finished files, including parts that were already present (`-c`).
    pub bytes_done: u64,
    /// Bytes actually moved over the network in this run.
    pub moved: u64,
    started: Instant,
}

impl TreeProgress {
    /// `totals` is (files, bytes) from the pre-scan, or `None` when progress is
    /// off, in which case nothing is drawn and only the summary is printed.
    pub(super) fn new(totals: Option<(u64, u64)>) -> Self {
        let multi = MultiProgress::with_draw_target(if totals.is_some() {
            ProgressDrawTarget::stderr()
        } else {
            ProgressDrawTarget::hidden()
        });
        let total = totals.map(|(files, bytes)| {
            let bar = multi.add(new_bar(bytes, 0, &format!("total 0/{files}")));
            bar.tick();
            bar
        });
        TreeProgress {
            multi,
            total,
            files: totals.map_or(0, |t| t.0),
            files_done: 0,
            bytes_done: 0,
            moved: 0,
            started: Instant::now(),
        }
    }

    /// A handle for [`LineWriter`].
    pub(super) fn multi(&self) -> MultiProgress {
        self.multi.clone()
    }

    fn show(&self, current: u64) {
        if let Some(bar) = &self.total {
            bar.set_position(self.bytes_done + current);
            bar.set_message(format!(
                "total {}/{}",
                (self.files_done + 1).min(self.files),
                self.files
            ));
        }
    }

    /// "got 12 files (1.5 GiB) in 2.1s (731 MiB/s)"-style summary. Also
    /// removes the totals bar.
    pub(super) fn finish(self, verb: &str) -> String {
        if let Some(bar) = &self.total {
            bar.finish_and_clear();
        }
        let secs = self.started.elapsed().as_secs_f64();
        let rate = if secs > 0.0 {
            self.moved as f64 / secs
        } else {
            0.0
        };
        format!(
            "{verb} {} file{} ({}) in {:.1}s ({}/s)",
            self.files_done,
            if self.files_done == 1 { "" } else { "s" },
            HumanBytes(self.bytes_done),
            secs,
            HumanBytes(rate as u64),
        )
    }
}

/// The progress display for one file transfer.
pub(super) struct Meter<'t> {
    bar: Option<ProgressBar>,
    /// Size of the whole file and the offset the transfer started from.
    total: u64,
    start: u64,
    done: u64,
    tree: Option<&'t mut TreeProgress>,
}

impl<'t> Meter<'t> {
    /// `total` is the full size of the file; `start` is the offset already present.
    pub(super) fn new(
        progress: bool,
        label: &str,
        total: u64,
        start: u64,
        tree: Option<&'t mut TreeProgress>,
    ) -> Self {
        let bar = (progress && total >= PROGRESS_MIN).then(|| {
            let bar = new_bar(total, start, label);
            match tree
                .as_deref()
                .and_then(|t| t.total.as_ref().map(|tb| (t, tb)))
            {
                // Above the totals bar.
                Some((t, totals)) => t.multi.insert_before(totals, bar),
                None => {
                    bar.set_draw_target(ProgressDrawTarget::stderr());
                    bar
                }
            }
        });
        if let Some(t) = tree.as_deref() {
            t.show(start);
        }
        Meter {
            bar,
            total,
            start,
            done: start,
            tree,
        }
    }

    /// `done` is the absolute file offset reached so far.
    pub(super) fn tick(&mut self, done: u64) {
        self.done = done;
        if let Some(bar) = &self.bar {
            bar.set_position(done);
        }
        if let Some(t) = self.tree.as_deref() {
            t.show(done);
        }
    }

    /// Removes the bar and books the file into the tree totals. `completed`
    /// is false when the transfer failed or was interrupted.
    pub(super) fn finish(self, completed: bool) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
            if let Some(t) = self.tree.as_deref() {
                t.multi.remove(bar);
            }
        }
        if let Some(t) = self.tree {
            t.moved += self.done - self.start;
            if completed {
                t.files_done += 1;
                t.bytes_done += self.total;
            }
            t.show(0);
        }
    }
}

/// Writes whole lines to `inner` with the progress bars paused, so messages
/// printed during a recursive transfer don't tear through the bars.
pub(super) struct LineWriter<'a> {
    inner: &'a mut dyn Write,
    multi: MultiProgress,
    buf: Vec<u8>,
}

impl<'a> LineWriter<'a> {
    pub(super) fn new(inner: &'a mut dyn Write, multi: MultiProgress) -> Self {
        LineWriter {
            inner,
            multi,
            buf: Vec::new(),
        }
    }

    fn emit(&mut self, upto: usize) -> io::Result<()> {
        let line: Vec<u8> = self.buf.drain(..upto).collect();
        let inner = &mut *self.inner;
        self.multi.suspend(|| inner.write_all(&line))
    }
}

impl Write for LineWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if let Some(pos) = self.buf.iter().rposition(|&b| b == b'\n') {
            self.emit(pos + 1)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let n = self.buf.len();
        if n > 0 {
            self.emit(n)?;
        }
        self.inner.flush()
    }
}

impl Drop for LineWriter<'_> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn style_template_is_valid() {
        let _ = style();
    }

    #[test]
    fn meters_book_completed_files_into_the_tree() {
        let mut tree = TreeProgress::new(None);
        let mut m = Meter::new(false, "a", 10, 0, Some(&mut tree));
        m.tick(10);
        m.finish(true);
        let mut m = Meter::new(false, "b", 10, 4, Some(&mut tree));
        m.tick(7);
        m.finish(false);
        assert_eq!((tree.files_done, tree.bytes_done, tree.moved), (1, 10, 13));
    }

    #[test]
    fn hidden_progress_writes_nothing_and_summary_wording() {
        let mut tree = TreeProgress::new(None);
        tree.files_done = 1;
        tree.bytes_done = 2048;
        assert!(tree.finish("got").starts_with("got 1 file (2.00 KiB) in "));
        let mut tree = TreeProgress::new(None);
        tree.files_done = 2;
        assert!(tree.finish("put").starts_with("put 2 files (0 B) in "));
    }

    #[test]
    fn line_writer_passes_whole_lines_through() {
        let mut out = Vec::new();
        {
            let mut w = LineWriter::new(
                &mut out,
                MultiProgress::with_draw_target(ProgressDrawTarget::hidden()),
            );
            write!(w, "one ").unwrap();
            writeln!(w, "line").unwrap();
            write!(w, "partial").unwrap();
        }
        assert_eq!(out, b"one line\npartial");
    }
}
