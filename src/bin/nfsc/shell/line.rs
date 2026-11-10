//! Command-line tokenizing, option letters and the `*` / `?` matcher.

/// Splits `input` into commands (separated by unquoted `;` or newlines), each
/// split into words. Supports "double" quotes (with `\"` and `\\` escapes),
/// 'single' quotes (literal) and backslash escapes outside quotes. Commands
/// with no words are dropped.
pub fn parse_script(input: &str) -> Result<Vec<Vec<String>>, String> {
    let mut commands = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => end_word(&mut words, &mut word),
            ';' | '\n' => {
                end_word(&mut words, &mut word);
                if !words.is_empty() {
                    commands.push(std::mem::take(&mut words));
                }
            }
            '\\' => {
                let next = chars.next().unwrap_or('\\');
                word.get_or_insert_with(String::new).push(next);
            }
            '\'' => {
                let buf = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => buf.push(ch),
                        None => return Err("unterminated single quote".into()),
                    }
                }
            }
            '"' => {
                let buf = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.peek().copied() {
                            Some(n @ ('"' | '\\')) => {
                                buf.push(n);
                                chars.next();
                            }
                            _ => buf.push('\\'),
                        },
                        Some(ch) => buf.push(ch),
                        None => return Err("unterminated double quote".into()),
                    }
                }
            }
            _ => word.get_or_insert_with(String::new).push(c),
        }
    }
    end_word(&mut words, &mut word);
    if !words.is_empty() {
        commands.push(words);
    }
    Ok(commands)
}

fn end_word(words: &mut Vec<String>, word: &mut Option<String>) {
    if let Some(w) = word.take() {
        words.push(w);
    }
}

/// Arguments of one command after option parsing.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Args {
    flags: String,
    pub positional: Vec<String>,
}

impl Args {
    pub fn has(&self, flag: char) -> bool {
        self.flags.contains(flag)
    }
}

/// Parses `-abc` option clusters, where each letter must be in `allowed`.
/// `--` ends options; a lone `-` is a positional argument.
pub fn parse_args(words: &[String], allowed: &str) -> Result<Args, String> {
    let mut args = Args::default();
    let mut options_done = false;
    for w in words {
        if options_done || w == "-" || !w.starts_with('-') {
            args.positional.push(w.clone());
        } else if w == "--" {
            options_done = true;
        } else {
            for ch in w[1..].chars() {
                if !allowed.contains(ch) {
                    return Err(format!("invalid option -- '{ch}'"));
                }
                args.flags.push(ch);
            }
        }
    }
    Ok(args)
}

/// True when a path component contains glob characters.
pub fn is_pattern(s: &str) -> bool {
    s.contains(['*', '?'])
}

/// Shell-style matching of `*` (any run) and `?` (one character). A leading
/// dot in a name must be matched by a leading dot in the pattern.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    if n.first() == Some(&'.') && p.first() != Some(&'.') {
        return false;
    }
    let (mut pi, mut ni) = (0, 0);
    // Position of the last '*' seen, and the name index it currently absorbs up to.
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            star = Some((sp, sn + 1));
            ni = sn + 1;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(cmds: &[Vec<String>]) -> Vec<Vec<&str>> {
        cmds.iter()
            .map(|c| c.iter().map(String::as_str).collect())
            .collect()
    }

    #[test]
    fn splits_words_and_commands() {
        let cmds = parse_script("ls  -l ;pwd\n  get a b ; ; ").unwrap();
        assert_eq!(
            words(&cmds),
            vec![vec!["ls", "-l"], vec!["pwd"], vec!["get", "a", "b"]]
        );
        assert!(parse_script("   ;; \n").unwrap().is_empty());
    }

    #[test]
    fn double_quotes_keep_spaces_and_semicolons() {
        let cmds = parse_script(r#"put "my file.txt" "dir; x""#).unwrap();
        assert_eq!(words(&cmds), vec![vec!["put", "my file.txt", "dir; x"]]);
    }

    #[test]
    fn double_quotes_honor_only_quote_and_backslash_escapes() {
        let cmds = parse_script(r#"echo "a\"b" "c\\d" "e\nf""#).unwrap();
        assert_eq!(words(&cmds), vec![vec!["echo", "a\"b", "c\\d", "e\\nf"]]);
    }

    #[test]
    fn single_quotes_are_literal() {
        let cmds = parse_script(r"cat 'a\b' 'x y;z'").unwrap();
        assert_eq!(words(&cmds), vec![vec!["cat", r"a\b", "x y;z"]]);
    }

    #[test]
    fn backslash_escapes_outside_quotes() {
        let cmds = parse_script(r"mv a\ b c\;d").unwrap();
        assert_eq!(words(&cmds), vec![vec!["mv", "a b", "c;d"]]);
    }

    #[test]
    fn empty_quotes_make_an_empty_argument() {
        let cmds = parse_script(r#"ln -s "" x"#).unwrap();
        assert_eq!(words(&cmds), vec![vec!["ln", "-s", "", "x"]]);
    }

    #[test]
    fn unterminated_quotes_are_errors() {
        assert!(parse_script("ls 'abc").is_err());
        assert!(parse_script("ls \"abc").is_err());
    }

    #[test]
    fn option_clusters_and_positionals() {
        let w: Vec<String> = ["-lr", "--", "-odd", "-"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = parse_args(&w, "lr").unwrap();
        assert!(a.has('l') && a.has('r') && !a.has('x'));
        assert_eq!(a.positional, vec!["-odd", "-"]);
        let bad: Vec<String> = vec!["-x".into()];
        assert_eq!(parse_args(&bad, "lr").unwrap_err(), "invalid option -- 'x'");
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*.txt", "a.txt"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("*a*b*", "xxaYYbzz"));
        assert!(!glob_match("*.txt", "a.txt.bak"));
        assert!(glob_match("file*", "file"));
        assert!(!glob_match("*", ".hidden"), "dotfiles need an explicit dot");
        assert!(glob_match(".*", ".hidden"));
        assert!(glob_match("*é", "café"));
    }
}
