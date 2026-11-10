//! Tab completion for the interactive shell.
//!
//! Command names are completed at the start of a command (after the line start
//! or `;`). Remote path arguments are completed from a listing of the directory
//! part of the word, and local path arguments from the local file system. Names
//! are escaped the way the line parser reads them back, so a name with spaces
//! or quotes can be completed. Any error gives no candidates; completion never
//! prints anything.

use std::path::{Path, PathBuf};

use nfsc::fs::FileType;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

use super::remote::{RemoteCtx, resolve_path};
use super::session::{COMMANDS, last_node, normalize_local};

/// The word under the cursor, unescaped.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Word {
    /// Byte index in the line where the raw word starts (its opening quote, if any).
    start: usize,
    /// The word's text so far, with quotes and backslashes removed.
    value: String,
    /// The quote still open at the cursor, if any.
    quote: Option<char>,
}

/// The line left of the cursor, split into the current command's completed
/// words and the word being typed.
#[derive(Debug, PartialEq, Eq)]
struct Scan {
    /// Completed words of the current command; the first is the command name.
    words: Vec<String>,
    word: Word,
}

/// Splits `line` (the text left of the cursor) into words. Mirrors the rules of
/// `line::parse_script`, but keeps track of where the word under the cursor starts.
fn scan(line: &str) -> Scan {
    fn word_at(cur: &mut Option<Word>, i: usize) -> &mut Word {
        cur.get_or_insert_with(|| Word {
            start: i,
            value: String::new(),
            quote: None,
        })
    }

    let mut words: Vec<String> = Vec::new();
    let mut cur: Option<Word> = None;
    let mut open: Option<char> = None;
    let mut chars = line.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if let Some(q) = open {
            if c == q {
                open = None;
            } else if q == '"' && c == '\\' {
                match chars.peek().copied() {
                    Some((_, n @ ('"' | '\\'))) => {
                        chars.next();
                        word_at(&mut cur, i).value.push(n);
                    }
                    _ => word_at(&mut cur, i).value.push('\\'),
                }
            } else {
                word_at(&mut cur, i).value.push(c);
            }
            continue;
        }
        match c {
            ' ' | '\t' => {
                if let Some(w) = cur.take() {
                    words.push(w.value);
                }
            }
            ';' | '\n' => {
                if let Some(w) = cur.take() {
                    words.push(w.value);
                }
                words.clear();
            }
            '\\' => {
                let next = chars.next().map(|(_, n)| n);
                let w = word_at(&mut cur, i);
                if let Some(n) = next {
                    w.value.push(n);
                }
            }
            '\'' | '"' => {
                word_at(&mut cur, i);
                open = Some(c);
            }
            _ => word_at(&mut cur, i).value.push(c),
        }
    }
    let word = match cur {
        Some(mut w) => {
            w.quote = open;
            w
        }
        None => Word {
            start: line.len(),
            value: String::new(),
            quote: None,
        },
    };
    Scan { words, word }
}

/// What a path argument may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Remote { dirs_only: bool },
    Local { dirs_only: bool },
}

/// The kind of the positional argument at `index` (flags do not count) of `cmd`.
fn arg_kind(cmd: &str, index: usize) -> Option<Kind> {
    use Kind::{Local, Remote};
    Some(match (cmd, index) {
        ("ls" | "dir" | "cat", 0) => Remote { dirs_only: false },
        ("stat" | "rm" | "rmdir", _) => Remote { dirs_only: false },
        ("cd" | "df", 0) => Remote { dirs_only: true },
        ("mv" | "ln", 0 | 1) => Remote { dirs_only: false },
        ("chmod" | "chown", i) if i >= 1 => Remote { dirs_only: false },
        ("get", 0) | ("put", 1) => Remote { dirs_only: false },
        ("get", 1) | ("put", 0) => Local { dirs_only: false },
        ("lcd", 0) => Local { dirs_only: true },
        _ => return None,
    })
}

/// Options a command accepts, offered when the word starts with '-'.
fn flags_for(cmd: &str) -> &'static [&'static str] {
    match cmd {
        "ls" | "dir" => &["-l"],
        "get" | "put" => &["-c", "-r"],
        "ln" => &["-s"],
        _ => &[],
    }
}

/// Whether a directory entry name is offered for `prefix`. Dotfiles appear only
/// when the prefix starts with a dot, as with the shell's globbing.
fn matches_prefix(name: &str, prefix: &str) -> bool {
    name.starts_with(prefix) && (!name.starts_with('.') || prefix.starts_with('.'))
}

/// Splits a path word into its directory part (with the trailing '/') and the
/// name prefix being typed.
fn split_dir(value: &str) -> (&str, &str) {
    match value.rfind('/') {
        Some(i) => (&value[..=i], &value[i + 1..]),
        None => ("", value),
    }
}

/// A candidate name: the entry name and whether it is a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    name: String,
    is_dir: bool,
}

/// Whether a name can be typed back in and read by the line parser.
fn usable(name: &str, quote: Option<char>) -> bool {
    !name.contains(['*', '?'])
        && !name.chars().any(char::is_control)
        && !(quote == Some('\'') && name.contains('\''))
}

/// Escapes `text` for the word's quoting context.
fn escape(quote: Option<char>, text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match quote {
            Some('"') => {
                if c == '"' || c == '\\' {
                    out.push('\\');
                }
                out.push(c);
            }
            // Single quotes take everything literally; `usable` drops names with a quote.
            Some(_) => out.push(c),
            None => {
                if matches!(c, ' ' | '\t' | '\n' | ';' | '\\' | '\'' | '"') {
                    out.push('\\');
                }
                out.push(c);
            }
        }
    }
    out
}

/// Builds the pairs that replace `word`. `dir_part` is the directory text
/// typed before the candidate names (empty for command names and flags).
fn make_pairs(word: &Word, dir_part: &str, mut items: Vec<Item>) -> Vec<Pair> {
    items.retain(|i| usable(&i.name, word.quote));
    items.sort_by(|a, b| a.name.cmp(&b.name));
    let unique = items.len() == 1;
    let open: String = word.quote.map(String::from).unwrap_or_default();
    items
        .into_iter()
        .map(|item| {
            let suffix = if item.is_dir { "/" } else { "" };
            let text = format!("{dir_part}{}{suffix}", item.name);
            let mut replacement = format!("{open}{}", escape(word.quote, &text));
            // A unique file completes fully: close any quote and add a space.
            // A unique directory leaves the cursor after '/' to continue the path.
            if unique && !item.is_dir {
                if let Some(q) = word.quote {
                    replacement.push(q);
                }
                replacement.push(' ');
            }
            Pair {
                display: format!("{}{suffix}", item.name),
                replacement,
            }
        })
        .collect()
}

/// Completion source and line editor helper. The shell refreshes the remote
/// context before each prompt, so completion always sees the current directory.
#[derive(Default)]
pub struct ShellHelper {
    remote: Option<RemoteCtx>,
    local_cwd: PathBuf,
}

impl ShellHelper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the remote context and local working directory.
    pub fn sync(&mut self, remote: RemoteCtx, local_cwd: PathBuf) {
        self.remote = Some(remote);
        self.local_cwd = local_cwd;
    }

    /// Candidates for the word at the end of `line` (the text left of the cursor).
    /// Returns the byte index where the replacement starts, and the pairs.
    pub fn candidates(&self, line: &str) -> (usize, Vec<Pair>) {
        let scan = scan(line);
        let start = scan.word.start;
        match self.plan(&scan) {
            Some(pairs) => (start, pairs),
            None => (line.len(), Vec::new()),
        }
    }

    fn plan(&self, scan: &Scan) -> Option<Vec<Pair>> {
        let word = &scan.word;
        let Some(cmd) = scan.words.first() else {
            let items = COMMANDS
                .iter()
                .filter(|c| c.starts_with(word.value.as_str()))
                .map(|c| Item {
                    name: (*c).to_string(),
                    is_dir: false,
                })
                .collect();
            return Some(make_pairs(word, "", items));
        };
        if word.value.starts_with('-') {
            let items = flags_for(cmd)
                .iter()
                .filter(|f| f.starts_with(word.value.as_str()))
                .map(|f| Item {
                    name: (*f).to_string(),
                    is_dir: false,
                })
                .collect();
            return Some(make_pairs(word, "", items));
        }
        let index = scan.words[1..]
            .iter()
            .filter(|a| !a.starts_with('-'))
            .count();
        let kind = arg_kind(cmd, index)?;
        let (dir_part, prefix) = split_dir(&word.value);
        let items = match kind {
            Kind::Remote { dirs_only } => self.remote_items(dir_part, prefix, dirs_only)?,
            Kind::Local { dirs_only } => local_items(&self.local_cwd, dir_part, prefix, dirs_only)?,
        };
        Some(make_pairs(word, dir_part, items))
    }

    /// Entries of the remote directory `dir_part`, filtered by `prefix`.
    fn remote_items(&self, dir_part: &str, prefix: &str, dirs_only: bool) -> Option<Vec<Item>> {
        let ctx = self.remote.as_ref()?;
        let mut fs = ctx.fs.clone();
        let path = if dir_part.is_empty() { "." } else { dir_part };
        let stack = resolve_path(&mut fs, &ctx.root, &ctx.export, &ctx.cwd, path, true).ok()?;
        let node = last_node(&stack);
        if node.attr.ftype != FileType::Directory {
            return None;
        }
        let listing = ctx.cache.borrow_mut().listing(&mut fs, &node.fh).ok()?;
        Some(
            listing
                .into_iter()
                .filter_map(|e| {
                    let name = String::from_utf8(e.name).ok()?;
                    Some(Item {
                        name,
                        is_dir: e.is_dir,
                    })
                })
                .filter(|i| matches_prefix(&i.name, prefix) && (!dirs_only || i.is_dir))
                .collect(),
        )
    }
}

/// Entries of the local directory `dir_part` (relative to `local_cwd`).
fn local_items(
    local_cwd: &Path,
    dir_part: &str,
    prefix: &str,
    dirs_only: bool,
) -> Option<Vec<Item>> {
    let dir = if dir_part.is_empty() {
        local_cwd.to_path_buf()
    } else {
        normalize_local(&local_cwd.join(dir_part))
    };
    let mut items = Vec::new();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let is_dir = entry.path().is_dir();
        if matches_prefix(&name, prefix) && (!dirs_only || is_dir) {
            items.push(Item { name, is_dir });
        }
    }
    Some(items)
}

impl Completer for ShellHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let left = line.get(..pos).unwrap_or(line);
        Ok(self.candidates(left))
    }
}

impl Hinter for ShellHelper {
    type Hint = String;
}

impl Highlighter for ShellHelper {}

impl Validator for ShellHelper {}

impl Helper for ShellHelper {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_tracks_the_word_under_the_cursor() {
        let s = scan("get 'my fi");
        assert_eq!(s.words, vec!["get"]);
        assert_eq!(
            s.word,
            Word {
                start: 4,
                value: "my fi".into(),
                quote: Some('\'')
            }
        );
        let s = scan(r"mv a\ b c");
        assert_eq!(s.words, vec!["mv", "a b"]);
        assert_eq!(s.word.value, "c");
        let s = scan("ls x; cd ");
        assert_eq!(s.words, vec!["cd"], "a new command starts after ';'");
        assert_eq!(
            s.word.start, 9,
            "the empty word after the space sits at the cursor"
        );
    }

    #[test]
    fn scan_handles_double_quote_escapes() {
        let s = scan(r#"put "a\"b"#);
        assert_eq!(s.word.value, "a\"b");
        assert_eq!(s.word.quote, Some('"'));
    }

    #[test]
    fn arg_kinds_follow_the_command() {
        assert_eq!(arg_kind("get", 0), Some(Kind::Remote { dirs_only: false }));
        assert_eq!(arg_kind("get", 1), Some(Kind::Local { dirs_only: false }));
        assert_eq!(arg_kind("put", 0), Some(Kind::Local { dirs_only: false }));
        assert_eq!(arg_kind("put", 1), Some(Kind::Remote { dirs_only: false }));
        assert_eq!(arg_kind("chmod", 0), None, "the mode is not a path");
        assert_eq!(
            arg_kind("chmod", 1),
            Some(Kind::Remote { dirs_only: false })
        );
        assert_eq!(arg_kind("lcd", 0), Some(Kind::Local { dirs_only: true }));
        assert_eq!(arg_kind("mkdir", 0), None);
        assert_eq!(arg_kind("cd", 1), None);
    }

    #[test]
    fn escaping_matches_the_line_parser() {
        use super::super::line::parse_script;
        for name in ["a b", "x;y", "q'uote", "d\"q", "back\\slash", "plain"] {
            let line = format!("cat {}", escape(None, name));
            let cmds = parse_script(&line).unwrap();
            assert_eq!(cmds[0][1], name, "{line}");
            let line = format!("cat \"{}\"", escape(Some('"'), name));
            let cmds = parse_script(&line).unwrap();
            assert_eq!(cmds[0][1], name, "{line}");
        }
    }

    #[test]
    fn unusable_names_are_dropped() {
        assert!(!usable("a*b", None));
        assert!(!usable("what?", None));
        assert!(!usable("it's", Some('\'')));
        assert!(usable("it's", None), "unquoted names escape their quotes");
        assert!(!usable("tab\there", None));
    }

    #[test]
    fn unique_files_close_quotes_and_add_a_space() {
        let word = Word {
            start: 0,
            value: String::new(),
            quote: Some('"'),
        };
        let pairs = make_pairs(
            &word,
            "dir/",
            vec![Item {
                name: "my file".into(),
                is_dir: false,
            }],
        );
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].display, "my file");
        assert_eq!(pairs[0].replacement, "\"dir/my file\" ");
    }

    #[test]
    fn directories_get_a_slash_and_no_space() {
        let word = Word {
            start: 0,
            value: "a".into(),
            quote: None,
        };
        let pairs = make_pairs(
            &word,
            "",
            vec![Item {
                name: "a b".into(),
                is_dir: true,
            }],
        );
        assert_eq!(pairs[0].display, "a b/");
        assert_eq!(pairs[0].replacement, "a\\ b/");
    }
}
