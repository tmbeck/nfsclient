//! Shell behaviour against an in-memory export (`nfsc::memfs::MemFs`).
//! Session paths are shown as `/export/...`, matching the export name given to `Session::new`.

use std::fs;
use std::path::{Path, PathBuf};

use nfsc::fs::{CreateMode, Filesystem, SetAttr};
use nfsc::memfs::MemFs;

use super::line::parse_script;
use super::session::{Flow, Session};
use super::{CmdError, run_script_to};

const NOW: i64 = 1_700_000_000; // 2023-11-14 22:13:20 UTC

/// b.txt ("hello"), a/inner.txt, and ln -> b.txt. Timestamps are NOW.
fn fixture() -> MemFs {
    let mut fs = MemFs::new();
    fs.clock = NOW;
    fs.add_file("b.txt", b"hello").unwrap();
    fs.add_dir("a").unwrap();
    fs.add_file("a/inner.txt", b"inner data").unwrap();
    fs.add_symlink("ln", "b.txt").unwrap();
    fs
}

fn session(fs: MemFs) -> Session {
    let mut s = Session::new(Box::new(fs), "nas".into(), b"/export".to_vec(), &[]).unwrap();
    s.clock = NOW;
    s.term_width = 80;
    s
}

struct Run {
    out: String,
    err: String,
    failure: Option<String>,
}

/// Runs a line of commands, stopping at the first failure like the shell's `-c` mode.
fn run(s: &mut Session, line: &str) -> Run {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut failure = None;
    for words in parse_script(line).expect("test script parses") {
        match s.execute(&words, &mut out, &mut err) {
            Ok(Flow::Continue) => {}
            Ok(Flow::Exit) => break,
            Err(f) => {
                failure = Some(f.to_string());
                break;
            }
        }
    }
    Run {
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
        failure,
    }
}

fn ok(s: &mut Session, line: &str) -> String {
    let r = run(s, line);
    assert!(r.failure.is_none(), "`{line}` failed: {:?}", r.failure);
    r.out
}

fn fails(s: &mut Session, line: &str) -> String {
    let r = run(s, line);
    r.failure
        .unwrap_or_else(|| panic!("`{line}` should fail, printed {:?}", r.out))
}

/// A fresh, empty directory under the system temp dir.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nfsc-shell-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn lcd(s: &mut Session, dir: &Path) {
    ok(s, &format!("lcd \"{}\"", dir.display()));
}

#[test]
fn ls_short_form_sorts_and_fills_columns() {
    let mut s = session(fixture());
    assert_eq!(ok(&mut s, "ls"), "a      b.txt  ln\n");
    s.term_width = 10;
    assert_eq!(ok(&mut s, "dir"), "a\nb.txt\nln\n");
}

#[test]
fn ls_long_form_golden() {
    let mut s = session(fixture());
    assert_eq!(
        ok(&mut s, "ls -l"),
        "drwxr-xr-x 2 0 0 4096 Nov 14 22:13 a\n\
         -rw-r--r-- 1 0 0    5 Nov 14 22:13 b.txt\n\
         lrwxrwxrwx 1 0 0    5 Nov 14 22:13 ln -> b.txt\n"
    );
}

#[test]
fn ls_of_a_file_or_link_shows_one_entry() {
    let mut s = session(fixture());
    assert_eq!(ok(&mut s, "ls b.txt"), "b.txt\n");
    assert_eq!(
        ok(&mut s, "ls -l ln"),
        "lrwxrwxrwx 1 0 0 5 Nov 14 22:13 ln -> b.txt\n"
    );
    assert_eq!(
        fails(&mut s, "ls nope"),
        "nfsc: ls: nope: no such file or directory"
    );
}

#[test]
fn ls_lists_a_symlink_to_a_directory_as_its_contents() {
    let mut fs = fixture();
    fs.add_symlink("adir", "a").unwrap();
    let mut s = session(fs);
    assert_eq!(ok(&mut s, "ls adir"), "inner.txt\n");
}

#[test]
fn ls_shows_non_utf8_names_escaped() {
    let mut fs = fixture();
    let root = fs.root();
    fs.create(
        &root,
        b"bad\xffname",
        CreateMode::Unchecked,
        &SetAttr::default(),
    )
    .unwrap();
    let mut s = session(fs);
    assert!(ok(&mut s, "ls").contains("bad\\xffname"));
}

#[test]
fn cd_pwd_and_dotdot_never_leave_the_export() {
    let mut s = session(fixture());
    assert_eq!(ok(&mut s, "pwd"), "/export\n");
    ok(&mut s, "cd a");
    assert_eq!(ok(&mut s, "pwd"), "/export/a\n");
    ok(&mut s, "cd ..");
    assert_eq!(ok(&mut s, "pwd"), "/export\n");
    ok(&mut s, "cd ../../../..");
    assert_eq!(ok(&mut s, "pwd"), "/export\n", ".. at the root stays there");
    ok(&mut s, "cd /a");
    assert_eq!(ok(&mut s, "pwd"), "/export/a\n", "/ is the export root");
    ok(&mut s, "cd");
    assert_eq!(
        ok(&mut s, "pwd"),
        "/export\n",
        "cd alone goes to the export root"
    );
}

#[test]
fn cd_errors_name_the_path() {
    let mut s = session(fixture());
    assert_eq!(
        fails(&mut s, "cd nope"),
        "nfsc: cd: nope: no such file or directory"
    );
    assert_eq!(
        fails(&mut s, "cd b.txt"),
        "nfsc: cd: b.txt: not a directory"
    );
    assert_eq!(fails(&mut s, "cd ln"), "nfsc: cd: ln: not a directory");
}

#[test]
fn relative_and_absolute_symlinks_resolve_inside_the_export() {
    let mut fs = fixture();
    fs.add_symlink("abs", "/export/a").unwrap();
    fs.add_symlink("rel", "a").unwrap();
    fs.add_symlink("a/up", "../b.txt").unwrap();
    let mut s = session(fs);
    ok(&mut s, "cd abs");
    assert_eq!(ok(&mut s, "pwd"), "/export/a\n");
    ok(&mut s, "cd /");
    ok(&mut s, "cd rel");
    assert_eq!(ok(&mut s, "pwd"), "/export/a\n");
    ok(&mut s, "cd /");
    assert_eq!(
        ok(&mut s, "cat a/up"),
        "hello",
        "../ climbs from the link's directory"
    );
}

#[test]
fn symlinks_pointing_outside_the_export_are_refused() {
    let mut fs = fixture();
    fs.add_symlink("out", "/etc/passwd").unwrap();
    let mut s = session(fs);
    assert_eq!(
        fails(&mut s, "cd out"),
        "nfsc: cd: out: symbolic link target '/etc/passwd' is outside the export"
    );
    // A dangling or outside link is still listed and stat'ed as itself.
    assert_eq!(
        ok(&mut s, "ls -l out"),
        "lrwxrwxrwx 1 0 0 11 Nov 14 22:13 out -> /etc/passwd\n"
    );
}

#[test]
fn symlink_loops_are_bounded() {
    let mut fs = fixture();
    fs.add_symlink("loop1", "loop2").unwrap();
    fs.add_symlink("loop2", "loop1").unwrap();
    let mut s = session(fs);
    assert_eq!(
        fails(&mut s, "cd loop1"),
        "nfsc: cd: loop1: too many levels of symbolic links"
    );
}

#[test]
fn stat_shows_link_targets_without_following() {
    let mut s = session(fixture());
    let text = ok(&mut s, "stat ln b.txt");
    assert!(text.starts_with("  File: ln -> b.txt\n"), "{text}");
    assert!(
        text.contains("  Size: 5 "),
        "link size is the target length: {text}"
    );
    assert!(text.contains("Access: (0777/lrwxrwxrwx)"), "{text}");
    assert!(text.contains("  File: b.txt\n  Size: 5 "), "{text}");
    assert!(
        text.contains("symbolic link") && text.contains("regular file"),
        "{text}"
    );
    assert_eq!(fails(&mut s, "stat"), "nfsc: stat: usage: stat path...");
}

#[test]
fn cat_streams_contents_and_refuses_directories() {
    let mut s = session(fixture());
    assert_eq!(ok(&mut s, "cat b.txt"), "hello");
    assert_eq!(ok(&mut s, "cat ln"), "hello", "cat follows symlinks");
    assert_eq!(fails(&mut s, "cat a"), "nfsc: cat: a: is a directory");
    assert_eq!(fails(&mut s, "cat"), "nfsc: cat: usage: cat path");
}

#[test]
fn mkdir_quotes_and_errors() {
    let mut s = session(fixture());
    ok(&mut s, "mkdir newdir \"with space\"");
    assert!(ok(&mut s, "ls").contains("with space"));
    assert_eq!(fails(&mut s, "mkdir a"), "nfsc: mkdir: a: file exists");
    assert_eq!(
        fails(&mut s, "mkdir x/y"),
        "nfsc: mkdir: x/y: no such file or directory"
    );
}

#[test]
fn rm_rmdir_and_their_errors() {
    let mut s = session(fixture());
    ok(&mut s, "rm b.txt");
    assert!(!ok(&mut s, "ls").contains("b.txt"));
    assert_eq!(
        fails(&mut s, "rm nope"),
        "nfsc: rm: nope: no such file or directory"
    );
    assert_eq!(fails(&mut s, "rm a"), "nfsc: rm: a: is a directory");
    assert_eq!(
        fails(&mut s, "rmdir a"),
        "nfsc: rmdir: a: directory not empty"
    );
    ok(&mut s, "rm a/inner.txt; rmdir a");
    assert_eq!(ok(&mut s, "ls"), "ln\n");
    // rm removes the link itself, not its target.
    ok(&mut s, "rm ln");
    assert_eq!(ok(&mut s, "ls"), "");
}

#[test]
fn mv_renames_and_moves_into_directories() {
    let mut s = session(fixture());
    ok(&mut s, "mv b.txt moved.txt");
    assert_eq!(ok(&mut s, "cat moved.txt"), "hello");
    assert_eq!(
        fails(&mut s, "cat b.txt"),
        "nfsc: cat: b.txt: no such file or directory"
    );
    ok(&mut s, "mv moved.txt a");
    assert_eq!(ok(&mut s, "cat a/moved.txt"), "hello");
    ok(&mut s, "mv a/inner.txt a/renamed.txt");
    assert_eq!(ok(&mut s, "cat a/renamed.txt"), "inner data");
    assert_eq!(
        fails(&mut s, "mv nope x"),
        "nfsc: mv: nope: no such file or directory"
    );
    assert_eq!(fails(&mut s, "mv a x y"), "nfsc: mv: usage: mv src dst");
}

#[test]
fn ln_hard_and_symbolic_links() {
    let mut s = session(fixture());
    ok(&mut s, "ln -s b.txt sym2");
    assert_eq!(
        ok(&mut s, "stat sym2").lines().next(),
        Some("  File: sym2 -> b.txt")
    );
    ok(&mut s, "ln b.txt hard");
    assert!(
        ok(&mut s, "stat hard").contains("Links: 2"),
        "hard link count"
    );
    ok(&mut s, "ln -s /export/b.txt a");
    assert_eq!(
        ok(&mut s, "cat a/b.txt"),
        "hello",
        "a directory destination takes the base name"
    );
    assert_eq!(
        fails(&mut s, "ln b.txt hard"),
        "nfsc: ln: hard: file exists"
    );
}

#[test]
fn chmod_and_chown() {
    let mut s = session(fixture());
    ok(&mut s, "chmod 600 b.txt");
    assert!(ok(&mut s, "stat b.txt").contains("Access: (0600/-rw-------)"));
    assert_eq!(
        fails(&mut s, "chmod 999 b.txt"),
        "nfsc: chmod: invalid mode '999'"
    );
    ok(&mut s, "chown 1000:100 b.txt");
    let st = ok(&mut s, "stat b.txt");
    assert!(
        st.contains("Uid: ( 1000/    1000)") && st.contains("Gid: (  100/     100)"),
        "{st}"
    );
    ok(&mut s, "chown :7 b.txt");
    assert!(ok(&mut s, "stat b.txt").contains("Gid: (    7/       7)"));
    assert_eq!(
        fails(&mut s, "chown bob b.txt"),
        "nfsc: chown: invalid owner 'bob' (use uid, uid:gid or :gid)"
    );
}

#[test]
fn df_reports_space_in_human_units() {
    let mut s = session(fixture());
    let text = ok(&mut s, "df");
    let mut lines = text.lines();
    assert!(lines.next().unwrap().starts_with("Filesystem"));
    let data = lines.next().unwrap();
    assert!(data.starts_with("nas:/export"), "{data}");
    assert!(
        data.contains("1.0G") && data.contains("512M") && data.ends_with("50%"),
        "{data}"
    );
}

#[test]
fn help_lists_the_commands_and_exit_ends_the_script() {
    let mut s = session(fixture());
    let help = ok(&mut s, "help");
    assert!(help.contains("ls [-l] [path]") && help.contains("chown uid[:gid] path..."));
    let r = run(&mut s, "pwd; exit; cd a");
    assert!(r.failure.is_none());
    assert_eq!(r.out, "/export\n", "commands after exit do not run");
}

#[test]
fn unknown_commands_and_bad_options_are_reported() {
    let mut s = session(fixture());
    assert_eq!(
        fails(&mut s, "frob"),
        "nfsc: frob: unknown command (try help)"
    );
    assert_eq!(fails(&mut s, "ls -z"), "nfsc: ls: invalid option -- 'z'");
    assert_eq!(
        fails(&mut s, "get"),
        "nfsc: get: usage: get [-r] remote [local]"
    );
}

#[test]
fn globs_expand_the_final_component_and_skip_dotfiles() {
    let mut fs = fixture();
    fs.add_file("x.tmp", b"x").unwrap();
    fs.add_file("y.tmp", b"y").unwrap();
    fs.add_file(".dot.tmp", b"d").unwrap();
    let mut s = session(fs);
    assert_eq!(ok(&mut s, "ls *.tmp"), "x.tmp\ny.tmp\n");
    assert_eq!(ok(&mut s, "ls .*.tmp"), ".dot.tmp\n");
    assert_eq!(ok(&mut s, "ls a/*.txt"), "a/inner.txt\n");
    assert_eq!(ok(&mut s, "ls ?.txt"), "b.txt\n");
    assert_eq!(fails(&mut s, "ls *.none"), "nfsc: ls: *.none: no match");
    assert_eq!(
        fails(&mut s, "ls *x/*.txt"),
        "nfsc: ls: *x/*.txt: wildcards are only supported in the last path component"
    );
    assert!(ok(&mut s, "stat *.tmp").matches("  File: ").count() == 2);
    ok(&mut s, "rm *.tmp");
    // Plain ls shows dotfiles too; only the glob hid them.
    assert_eq!(
        ok(&mut s, "ls"),
        format!("{:<10}{:<10}{:<10}ln\n", ".dot.tmp", "a", "b.txt"),
        "rm * removed only the matches"
    );
}

#[test]
fn glob_skips_names_that_are_not_utf8() {
    let mut fs = fixture();
    let root = fs.root();
    fs.create(
        &root,
        b"bad\xff",
        CreateMode::Unchecked,
        &SetAttr::default(),
    )
    .unwrap();
    let mut s = session(fs);
    assert_eq!(fails(&mut s, "ls bad*"), "nfsc: ls: bad*: no match");
}

#[test]
fn quoting_reaches_the_command() {
    let mut s = session(fixture());
    ok(&mut s, "mv 'b.txt' \"new name.txt\"");
    assert_eq!(ok(&mut s, "cat 'new name.txt'"), "hello");
}

#[test]
fn lcd_changes_the_local_directory_and_reports_errors() {
    let dir = scratch("lcd");
    let mut s = session(fixture());
    lcd(&mut s, &dir);
    assert_eq!(s.local_cwd, dir);
    let err = fails(&mut s, "lcd /definitely/not/here");
    assert_eq!(
        err,
        "nfsc: lcd: /definitely/not/here: No such file or directory"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_and_put_round_trip_a_tree_with_modes() {
    let root = scratch("tree");
    let src = root.join("src");
    fs::create_dir_all(src.join("tree/sub")).unwrap();
    fs::write(src.join("tree/f1.bin"), b"0123456789").unwrap();
    fs::set_permissions(
        src.join("tree/f1.bin"),
        std::os::unix::fs::PermissionsExt::from_mode(0o640),
    )
    .unwrap();
    fs::write(src.join("tree/sub/f2.txt"), b"nested").unwrap();
    let dst = root.join("dst");
    fs::create_dir_all(&dst).unwrap();

    let mut s = session(fixture());
    lcd(&mut s, &src);
    let put = run(&mut s, "put -r tree");
    assert!(put.failure.is_none(), "{:?}", put.failure);
    assert!(put.err.contains("putting file"), "{}", put.err);
    assert_eq!(ok(&mut s, "cat tree/sub/f2.txt"), "nested");
    assert!(
        ok(&mut s, "stat tree/f1.bin").contains("(0640/-rw-r-----)"),
        "put keeps mode bits"
    );

    lcd(&mut s, &dst);
    let get = run(&mut s, "get -r tree");
    assert!(get.failure.is_none(), "{:?}", get.failure);
    assert!(
        get.err.contains("getting file f1.bin of size 10 as "),
        "{}",
        get.err
    );
    assert_eq!(fs::read(dst.join("tree/f1.bin")).unwrap(), b"0123456789");
    assert_eq!(fs::read(dst.join("tree/sub/f2.txt")).unwrap(), b"nested");
    let mode = fs::metadata(dst.join("tree/f1.bin")).unwrap().permissions();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
        0o640
    );

    assert_eq!(
        fails(&mut s, "get tree"),
        "nfsc: get: tree: is a directory (use -r)"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn get_file_variants_overwrite_and_stream() {
    let dir = scratch("get_variants");
    let mut s = session(fixture());
    lcd(&mut s, &dir);

    ok(&mut s, "get b.txt");
    assert_eq!(fs::read(dir.join("b.txt")).unwrap(), b"hello");

    ok(&mut s, "get b.txt renamed.txt");
    assert_eq!(fs::read(dir.join("renamed.txt")).unwrap(), b"hello");

    fs::create_dir_all(dir.join("into")).unwrap();
    ok(&mut s, "get b.txt into");
    assert_eq!(
        fs::read(dir.join("into/b.txt")).unwrap(),
        b"hello",
        "existing dir takes the name"
    );

    ok(&mut s, "get ln viaLink");
    assert_eq!(
        fs::read(dir.join("viaLink")).unwrap(),
        b"hello",
        "get follows symlinks"
    );

    let to_stdout = run(&mut s, "get b.txt -");
    assert!(to_stdout.failure.is_none());
    assert_eq!(to_stdout.out, "hello");
    assert!(
        to_stdout
            .err
            .contains("getting file b.txt of size 5 as - ("),
        "{}",
        to_stdout.err
    );

    fs::write(dir.join("b.txt"), b"a much longer old copy").unwrap();
    ok(&mut s, "get b.txt");
    assert_eq!(
        fs::read(dir.join("b.txt")).unwrap(),
        b"hello",
        "get overwrites"
    );

    assert_eq!(
        fails(&mut s, "get nope"),
        "nfsc: get: nope: no such file or directory"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_with_globs_takes_several_files_into_a_directory() {
    let dir = scratch("get_glob");
    let mut fs_ = fixture();
    fs_.add_file("x.tmp", b"x").unwrap();
    fs_.add_file("y.tmp", b"y").unwrap();
    let mut s = session(fs_);
    lcd(&mut s, &dir);

    assert_eq!(
        fails(&mut s, "get *.tmp nowhere"),
        "nfsc: get: *.tmp: several files need a local directory as destination"
    );
    let r = run(&mut s, "get *.tmp");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert_eq!(fs::read(dir.join("x.tmp")).unwrap(), b"x");
    assert_eq!(fs::read(dir.join("y.tmp")).unwrap(), b"y");

    // Directories in a glob are skipped without -r rather than failing the batch.
    let r = run(&mut s, "get a* ");
    assert!(r.err.contains("skipping directory a (use -r)"), "{}", r.err);
    assert!(r.failure.is_none());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_tree_skips_symlinks_with_a_note() {
    let mut fs_ = fixture();
    fs_.add_dir("t").unwrap();
    fs_.add_symlink("t/loop", "..").unwrap();
    fs_.add_file("t/real", b"r").unwrap();
    let mut s = session(fs_);
    let dir = scratch("get_tree_links");
    lcd(&mut s, &dir);
    let r = run(&mut s, "get -r t");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("skipping symbolic link loop"), "{}", r.err);
    assert!(dir.join("t/real").exists());
    assert!(!dir.join("t/loop").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_overwrites_and_places_into_directories() {
    let dir = scratch("put_variants");
    fs::write(dir.join("hi.txt"), b"hi").unwrap();
    let mut s = session(fixture());
    lcd(&mut s, &dir);

    ok(&mut s, "put hi.txt b.txt");
    assert_eq!(
        ok(&mut s, "cat b.txt"),
        "hi",
        "put truncates the old, longer file"
    );

    ok(&mut s, "put hi.txt a");
    assert_eq!(
        ok(&mut s, "cat a/hi.txt"),
        "hi",
        "existing directory takes the base name"
    );

    assert_eq!(
        fails(&mut s, "put missing.txt"),
        "nfsc: put: missing.txt: No such file or directory"
    );
    fs::create_dir_all(dir.join("ldir")).unwrap();
    assert_eq!(
        fails(&mut s, "put ldir"),
        "nfsc: put: ldir: is a directory (use -r)"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_progress_and_summary_go_to_stderr() {
    let dir = scratch("put_summary");
    fs::write(dir.join("p.txt"), b"abc").unwrap();
    let mut s = session(fixture());
    lcd(&mut s, &dir);
    let r = run(&mut s, "put p.txt");
    assert!(r.out.is_empty(), "stdout stays clean: {:?}", r.out);
    assert!(r.err.starts_with("putting file "), "{}", r.err);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_copes_with_short_writes_from_the_server() {
    let dir = scratch("short_writes");
    fs::write(dir.join("long.txt"), b"0123456789abcdef").unwrap();
    let mut backend = fixture();
    backend.write_call_limit = Some(3); // every WRITE accepts at most 3 bytes
    let mut s = session(backend);
    lcd(&mut s, &dir);
    ok(&mut s, "put long.txt");
    assert_eq!(ok(&mut s, "cat long.txt"), "0123456789abcdef");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_fails_instead_of_looping_when_no_bytes_are_accepted() {
    let dir = scratch("zero_writes");
    fs::write(dir.join("z.txt"), b"data").unwrap();
    let mut backend = fixture();
    backend.write_call_limit = Some(0);
    let mut s = session(backend);
    lcd(&mut s, &dir);
    let msg = fails(&mut s, "put z.txt");
    assert!(msg.contains("server accepted no data"), "{msg}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_skips_special_entries_in_trees() {
    let dir = scratch("put_tree_links");
    fs::create_dir_all(dir.join("tree")).unwrap();
    fs::write(dir.join("tree/keep.txt"), b"k").unwrap();
    std::os::unix::fs::symlink("keep.txt", dir.join("tree/link")).unwrap();
    let mut s = session(fixture());
    lcd(&mut s, &dir);
    let r = run(&mut s, "put -r tree");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("skipping"), "{}", r.err);
    assert_eq!(ok(&mut s, "cat tree/keep.txt"), "k");
    assert!(fails(&mut s, "cat tree/link").contains("no such file"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn commands_in_a_script_stop_at_the_first_failure() {
    let mut s = session(fixture());
    let cmds = parse_script("cd a; pwd; cd nope; pwd").unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = run_script_to(&mut s, &cmds, &mut out, &mut err);
    assert!(matches!(result, Err(CmdError::Reported(1))), "{result:?}");
    assert_eq!(String::from_utf8(out).unwrap(), "/export/a\n");
    assert_eq!(
        String::from_utf8(err).unwrap(),
        "nfsc: cd: nope: no such file or directory\n"
    );
}

#[test]
fn exit_in_a_script_succeeds_early() {
    let mut s = session(fixture());
    let cmds = parse_script("pwd; exit; cd nope").unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = run_script_to(&mut s, &cmds, &mut out, &mut err);
    assert!(matches!(result, Ok(Flow::Exit)), "{result:?}");
    assert_eq!(String::from_utf8(out).unwrap(), "/export\n");
    assert!(err.is_empty());
}

#[test]
fn a_clean_script_succeeds() {
    let mut s = session(fixture());
    let cmds = parse_script("ls; pwd").unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = run_script_to(&mut s, &cmds, &mut out, &mut err);
    assert!(matches!(result, Ok(Flow::Continue)));
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "a      b.txt  ln\n/export\n"
    );
}

#[test]
fn session_starts_at_the_resolved_remainder() {
    let fs = fixture();
    let s = Session::new(
        Box::new(fs),
        "nas".into(),
        b"/export".to_vec(),
        &[b"a".to_vec()],
    )
    .unwrap();
    assert_eq!(s.cwd_path(), "/export/a");
    assert_eq!(s.prompt(), "nfs nas:/export/a> ");
    assert_eq!(s.banner(), "Connected to nas:/export (NFSv3)");

    let missing = Session::new(
        Box::new(fixture()),
        "nas".into(),
        b"/export".to_vec(),
        &[b"nope".to_vec()],
    );
    assert!(missing.is_err());
    let not_dir = Session::new(
        Box::new(fixture()),
        "nas".into(),
        b"/export".to_vec(),
        &[b"b.txt".to_vec()],
    );
    assert!(not_dir.is_err());
}

#[test]
fn session_prompt_follows_cd() {
    let mut s = session(fixture());
    ok(&mut s, "cd a");
    assert_eq!(s.prompt(), "nfs nas:/export/a> ");
}
