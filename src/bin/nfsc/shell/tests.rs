//! Shell behaviour against an in-memory export (`nfsc::memfs::MemFs`).
//! Session paths are shown as `/export/...`, matching the export name given to `Session::new`.

use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use nfsc::fs::{Attr, CreateMode, DirEntry, FileHandle, Filesystem, FsStat, NfsVersion, SetAttr};
use nfsc::memfs::MemFs;

use super::complete::ShellHelper;
use super::line::parse_script;
use super::session::{COMMANDS, Flow, Session};
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
        "nfsc: get: usage: get [-r] [-c] remote [local]"
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
    // The bulk default in the Filesystem trait reports this as a protocol error.
    let msg = fails(&mut s, "put z.txt");
    assert!(msg.contains("0-byte write"), "{msg}");
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

/// Sessions that share a test-owned flag, so Ctrl-C can be simulated.
fn session_with(fs: Box<dyn Filesystem>, flag: Arc<AtomicBool>) -> Session {
    let mut s = Session::new(fs, "nas".into(), b"/export".to_vec(), &[]).unwrap();
    s.clock = NOW;
    s.term_width = 80;
    s.interrupt = flag;
    s
}

/// A backend shared with the test. It raises `flag` on the `trip_after`-th
/// read or write call, as if Ctrl-C had been pressed at that moment.
struct Tripwire {
    fs: Rc<RefCell<MemFs>>,
    flag: Arc<AtomicBool>,
    calls: usize,
    trip_after: usize,
}

impl Tripwire {
    fn new(fs: Rc<RefCell<MemFs>>, flag: Arc<AtomicBool>, trip_after: usize) -> Self {
        Tripwire {
            fs,
            flag,
            calls: 0,
            trip_after,
        }
    }

    fn tick(&mut self) {
        self.calls += 1;
        if self.calls == self.trip_after {
            self.flag.store(true, Ordering::SeqCst);
        }
    }
}

impl Filesystem for Tripwire {
    fn version(&self) -> NfsVersion {
        self.fs.borrow().version()
    }
    fn root(&self) -> FileHandle {
        self.fs.borrow().root()
    }
    fn max_read(&self) -> u32 {
        self.fs.borrow().max_read()
    }
    fn max_write(&self) -> u32 {
        self.fs.borrow().max_write()
    }
    fn getattr(&mut self, fh: &FileHandle) -> nfsc::Result<Attr> {
        self.fs.borrow_mut().getattr(fh)
    }
    fn setattr(&mut self, fh: &FileHandle, attrs: &SetAttr) -> nfsc::Result<Attr> {
        self.fs.borrow_mut().setattr(fh, attrs)
    }
    fn lookup(&mut self, dir: &FileHandle, name: &[u8]) -> nfsc::Result<(FileHandle, Attr)> {
        self.fs.borrow_mut().lookup(dir, name)
    }
    fn readdir(&mut self, dir: &FileHandle) -> nfsc::Result<Vec<DirEntry>> {
        self.fs.borrow_mut().readdir(dir)
    }
    fn readlink(&mut self, fh: &FileHandle) -> nfsc::Result<Vec<u8>> {
        self.fs.borrow_mut().readlink(fh)
    }
    fn read(&mut self, fh: &FileHandle, offset: u64, count: u32) -> nfsc::Result<(Vec<u8>, bool)> {
        self.tick();
        self.fs.borrow_mut().read(fh, offset, count)
    }
    fn write(&mut self, fh: &FileHandle, offset: u64, data: &[u8]) -> nfsc::Result<u32> {
        self.tick();
        self.fs.borrow_mut().write(fh, offset, data)
    }
    fn create(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        mode: CreateMode,
        attrs: &SetAttr,
    ) -> nfsc::Result<(FileHandle, Attr)> {
        self.fs.borrow_mut().create(dir, name, mode, attrs)
    }
    fn mkdir(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        attrs: &SetAttr,
    ) -> nfsc::Result<(FileHandle, Attr)> {
        self.fs.borrow_mut().mkdir(dir, name, attrs)
    }
    fn symlink(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        target: &[u8],
        attrs: &SetAttr,
    ) -> nfsc::Result<(FileHandle, Attr)> {
        self.fs.borrow_mut().symlink(dir, name, target, attrs)
    }
    fn link(&mut self, target: &FileHandle, dir: &FileHandle, name: &[u8]) -> nfsc::Result<()> {
        self.fs.borrow_mut().link(target, dir, name)
    }
    fn remove(&mut self, dir: &FileHandle, name: &[u8]) -> nfsc::Result<()> {
        self.fs.borrow_mut().remove(dir, name)
    }
    fn rmdir(&mut self, dir: &FileHandle, name: &[u8]) -> nfsc::Result<()> {
        self.fs.borrow_mut().rmdir(dir, name)
    }
    fn rename(
        &mut self,
        from_dir: &FileHandle,
        from_name: &[u8],
        to_dir: &FileHandle,
        to_name: &[u8],
    ) -> nfsc::Result<()> {
        self.fs
            .borrow_mut()
            .rename(from_dir, from_name, to_dir, to_name)
    }
    fn fsstat(&mut self, fh: &FileHandle) -> nfsc::Result<FsStat> {
        self.fs.borrow_mut().fsstat(fh)
    }
    fn disconnect(&mut self) -> nfsc::Result<()> {
        self.fs.borrow_mut().disconnect()
    }
}

/// `len` bytes of a repeating ASCII pattern, so contents are easy to compare.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| b'a' + (i % 26) as u8).collect()
}

/// Completion candidates for `line` as (display, replacement) pairs.
fn complete(s: &Session, line: &str) -> Vec<(String, String)> {
    let mut helper = ShellHelper::new();
    s.sync_completer(&mut helper);
    let (_, pairs) = helper.candidates(line);
    pairs
        .into_iter()
        .map(|p| (p.display, p.replacement))
        .collect()
}

fn pair(display: &str, replacement: &str) -> (String, String) {
    (display.to_string(), replacement.to_string())
}

#[test]
fn completes_command_names_at_the_start_of_each_command() {
    let s = session(fixture());
    assert_eq!(complete(&s, "ca"), vec![pair("cat", "cat ")]);
    assert_eq!(complete(&s, "ls; st"), vec![pair("stat", "stat ")]);
    assert_eq!(complete(&s, "").len(), COMMANDS.len());
    assert!(
        complete(&s, "ls -l ca").is_empty(),
        "after a command, words are paths, not commands"
    );
}

#[test]
fn completes_remote_paths_and_marks_directories() {
    let s = session(fixture());
    assert_eq!(complete(&s, "cat b"), vec![pair("b.txt", "b.txt ")]);
    assert_eq!(
        complete(&s, "ls a/i"),
        vec![pair("inner.txt", "a/inner.txt ")]
    );
    assert_eq!(
        complete(&s, "cd "),
        vec![pair("a/", "a/")],
        "cd lists directories only"
    );
    assert_eq!(complete(&s, "stat ln"), vec![pair("ln", "ln ")]);
    assert!(
        complete(&s, "cd nosuch/").is_empty(),
        "errors give no candidates"
    );
}

#[test]
fn hidden_names_need_a_leading_dot() {
    let mut fs = fixture();
    fs.add_file(".hidden", b"x").unwrap();
    let s = session(fs);
    let plain: Vec<String> = complete(&s, "cat ").into_iter().map(|p| p.0).collect();
    assert!(!plain.contains(&".hidden".to_string()), "{plain:?}");
    assert_eq!(complete(&s, "cat .h"), vec![pair(".hidden", ".hidden ")]);
}

#[test]
fn names_with_spaces_and_quotes_complete_to_readable_words() {
    let mut fs = MemFs::new();
    fs.add_file("my file.txt", b"x").unwrap();
    fs.add_dir("my dir").unwrap();
    fs.add_file("my dir/inner file", b"y").unwrap();
    let s = session(fs);
    assert_eq!(
        complete(&s, "cat my\\ f"),
        vec![pair("my file.txt", "my\\ file.txt ")]
    );
    assert_eq!(
        complete(&s, "cat \"my f"),
        vec![pair("my file.txt", "\"my file.txt\" ")]
    );
    assert_eq!(
        complete(&s, "cat 'my f"),
        vec![pair("my file.txt", "'my file.txt' ")]
    );
    assert_eq!(
        complete(&s, "cd \"my d"),
        vec![pair("my dir/", "\"my dir/")]
    );
    assert_eq!(
        complete(&s, "cat \"my dir/i"),
        vec![pair("inner file", "\"my dir/inner file\" ")]
    );
    // Replacements read back, through the line parser, as the names they stand for.
    let word = complete(&s, "cat \"my dir/i")[0].1.clone();
    let cmds = parse_script(&format!("cat {word}")).unwrap();
    assert_eq!(cmds[0][1], "my dir/inner file");
    let word = complete(&s, "cat my\\ f")[0].1.clone();
    let cmds = parse_script(&format!("cat {word}")).unwrap();
    assert_eq!(cmds[0][1], "my file.txt");
}

#[test]
fn names_the_line_parser_cannot_express_are_not_offered() {
    let mut fs = MemFs::new();
    fs.add_file("a*b", b"x").unwrap();
    fs.add_file("plain", b"y").unwrap();
    let s = session(fs);
    assert_eq!(complete(&s, "cat "), vec![pair("plain", "plain ")]);
}

#[test]
fn completion_listings_refresh_after_a_modifying_command() {
    let mut s = session(fixture());
    assert!(complete(&s, "cat ne").is_empty());
    ok(&mut s, "mkdir nested");
    assert_eq!(complete(&s, "cat ne"), vec![pair("nested/", "nested/")]);
}

#[test]
fn flags_complete_after_a_dash() {
    let s = session(fixture());
    assert_eq!(complete(&s, "ls -"), vec![pair("-l", "-l ")]);
    assert_eq!(
        complete(&s, "get -"),
        vec![pair("-c", "-c"), pair("-r", "-r")]
    );
    assert_eq!(complete(&s, "ln -"), vec![pair("-s", "-s ")]);
}

#[test]
fn local_paths_complete_from_the_local_directory() {
    let dir = scratch("complete_local");
    fs::write(dir.join("upload.bin"), b"x").unwrap();
    fs::create_dir_all(dir.join("sub dir")).unwrap();
    let mut s = session(fixture());
    lcd(&mut s, &dir);
    assert_eq!(
        complete(&s, "put up"),
        vec![pair("upload.bin", "upload.bin ")]
    );
    assert_eq!(complete(&s, "lcd su"), vec![pair("sub dir/", "sub\\ dir/")]);
    assert_eq!(complete(&s, "lcd "), vec![pair("sub dir/", "sub\\ dir/")]);
    assert_eq!(
        complete(&s, "get b.txt up"),
        vec![pair("upload.bin", "upload.bin ")],
        "the second argument of get is local"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ctrl_c_with_no_transfer_running_stops_a_script_with_status_130() {
    let mut s = session(fixture());
    s.interrupt.store(true, Ordering::SeqCst);
    let cmds = parse_script("pwd; pwd").unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = run_script_to(&mut s, &cmds, &mut out, &mut err);
    assert!(matches!(r, Err(CmdError::Reported(130))));
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "/export\n",
        "only the first command ran"
    );
    assert_eq!(String::from_utf8(err).unwrap(), "nfsc: interrupted\n");
}

#[test]
fn ctrl_c_during_get_removes_the_partial_file() {
    let dir = scratch("ctrl_c_get");
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.max_read = 512;
    inner.add_file("big.bin", &pattern(8192)).unwrap();
    let flag = Arc::new(AtomicBool::new(false));
    let backend = Rc::new(RefCell::new(inner));
    let mut s = session_with(
        Box::new(Tripwire::new(backend, flag.clone(), 2)),
        flag.clone(),
    );
    lcd(&mut s, &dir);
    assert_eq!(
        fails(&mut s, "get big.bin"),
        "nfsc: get: big.bin: interrupted"
    );
    assert!(
        !dir.join("big.bin").exists(),
        "the partial download is removed"
    );
    // The prompt works again once the flag is cleared.
    flag.store(false, Ordering::SeqCst);
    assert_eq!(ok(&mut s, "pwd"), "/export\n");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ctrl_c_during_put_leaves_a_partial_remote_file_that_put_c_completes() {
    let dir = scratch("ctrl_c_put");
    let data = pattern(8192);
    fs::write(dir.join("up.bin"), &data).unwrap();
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.max_write = 512;
    let backend = Rc::new(RefCell::new(inner));
    let flag = Arc::new(AtomicBool::new(false));
    let mut s = session_with(
        Box::new(Tripwire::new(backend.clone(), flag.clone(), 2)),
        flag.clone(),
    );
    lcd(&mut s, &dir);
    let r = run(&mut s, "put up.bin");
    assert_eq!(r.failure.as_deref(), Some("nfsc: put: up.bin: interrupted"));
    assert!(
        r.err
            .contains("partial (1024 of 8192 bytes); put -c continues it"),
        "{}",
        r.err
    );
    assert_eq!(backend.borrow().attr_at("up.bin").unwrap().size, 1024);

    flag.store(false, Ordering::SeqCst);
    let r = run(&mut s, "put -c up.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at 1024"), "{}", r.err);
    assert_eq!(backend.borrow().read_file("up.bin"), Some(data));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_c_continues_a_partial_local_file() {
    let dir = scratch("get_resume");
    let data = pattern(8192);
    let mut backend = MemFs::new();
    backend.clock = NOW;
    backend.add_file("big.bin", &data).unwrap();
    let mut s = session(backend);
    lcd(&mut s, &dir);
    fs::write(dir.join("big.bin"), &data[..3000]).unwrap();

    let r = run(&mut s, "get -c big.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at 3000"), "{}", r.err);
    assert_eq!(fs::read(dir.join("big.bin")).unwrap(), data);

    let r = run(&mut s, "get -c big.bin");
    assert!(r.err.contains("already complete"), "{}", r.err);

    fs::write(dir.join("big.bin"), vec![0u8; 9000]).unwrap();
    let msg = fails(&mut s, "get -c big.bin");
    assert!(msg.contains("larger than the remote file"), "{msg}");
    assert_eq!(
        fs::metadata(dir.join("big.bin")).unwrap().len(),
        9000,
        "never truncated"
    );

    ok(&mut s, "get big.bin");
    assert_eq!(
        fs::read(dir.join("big.bin")).unwrap(),
        data,
        "without -c it is overwritten"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_c_continues_a_partial_remote_file() {
    let dir = scratch("put_resume");
    let data = pattern(8192);
    fs::write(dir.join("up.bin"), &data).unwrap();
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.add_file("up.bin", &data[..3000]).unwrap();
    let backend = Rc::new(RefCell::new(inner));
    let flag = Arc::new(AtomicBool::new(false));
    let mut s = session_with(
        Box::new(Tripwire::new(backend.clone(), flag.clone(), usize::MAX)),
        flag,
    );
    lcd(&mut s, &dir);
    let r = run(&mut s, "put -c up.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at 3000"), "{}", r.err);
    assert_eq!(backend.borrow().read_file("up.bin"), Some(data));
    let r = run(&mut s, "put -c up.bin");
    assert!(r.err.contains("already complete"), "{}", r.err);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_sets_the_local_mtime_to_the_remote_mtime() {
    let dir = scratch("mtime");
    let mut s = session(fixture());
    lcd(&mut s, &dir);
    ok(&mut s, "get b.txt");
    let mtime = fs::metadata(dir.join("b.txt")).unwrap().modified().unwrap();
    assert_eq!(mtime, UNIX_EPOCH + Duration::from_secs(NOW as u64));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_c_past_four_gib_fetches_only_the_tail() {
    const FOUR_GIB: u64 = 1 << 32;
    let dir = scratch("sparse_get");
    let local = dir.join("huge.bin");
    File::create(&local).unwrap().set_len(FOUR_GIB).unwrap();
    let mut backend = MemFs::new();
    backend.clock = NOW;
    backend
        .add_sparse_file("huge.bin", FOUR_GIB + 4096, 0xAB)
        .unwrap();
    let mut s = session(backend);
    lcd(&mut s, &dir);
    let r = run(&mut s, "get -c huge.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at 4294967296"), "{}", r.err);
    let mut f = File::open(&local).unwrap();
    assert_eq!(f.metadata().unwrap().len(), FOUR_GIB + 4096);
    f.seek(SeekFrom::Start(FOUR_GIB)).unwrap();
    let mut tail = vec![0u8; 4096];
    f.read_exact(&mut tail).unwrap();
    assert!(tail.iter().all(|&b| b == 0xAB));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_c_past_four_gib_uploads_only_the_tail() {
    const FOUR_GIB: u64 = 1 << 32;
    let dir = scratch("sparse_put");
    let local = dir.join("huge.bin");
    {
        let mut f = File::create(&local).unwrap();
        f.set_len(FOUR_GIB + 4096).unwrap();
        f.seek(SeekFrom::Start(FOUR_GIB)).unwrap();
        f.write_all(&[0x5A; 4096]).unwrap();
    }
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.add_sparse_file("huge.bin", FOUR_GIB, 0).unwrap();
    let backend = Rc::new(RefCell::new(inner));
    let flag = Arc::new(AtomicBool::new(false));
    let mut s = session_with(
        Box::new(Tripwire::new(backend.clone(), flag.clone(), usize::MAX)),
        flag,
    );
    lcd(&mut s, &dir);
    let r = run(&mut s, "put -c huge.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at 4294967296"), "{}", r.err);
    let b = backend.borrow();
    assert_eq!(b.attr_at("huge.bin").unwrap().size, FOUR_GIB + 4096);
    assert_eq!(
        b.read_at("huge.bin", FOUR_GIB, 4096).unwrap(),
        vec![0x5A; 4096]
    );
    drop(b);
    let _ = fs::remove_dir_all(&dir);
}

// ---- Hostile server replies (review of v1.0.0) -----------------------------

/// `t` holds a real file and several names a hostile server could send. The
/// names are injected with `add_raw_child`, so MemFs does not reject them.
fn hostile_fixture(abs: &str) -> MemFs {
    let mut fs_ = fixture();
    fs_.add_dir("t").unwrap();
    fs_.add_dir("t/sub").unwrap();
    fs_.add_file("t/src.txt", b"payload").unwrap();
    fs_.add_file("t/real.txt", b"real").unwrap();
    fs_.add_raw_child("t", b"../../escaped.txt", "t/src.txt")
        .unwrap();
    fs_.add_raw_child("t", abs.as_bytes(), "t/src.txt").unwrap();
    fs_.add_raw_child("t", b"sub/../../escaped2.txt", "t/src.txt")
        .unwrap();
    fs_.add_raw_child("t", b"nul\0name", "t/src.txt").unwrap();
    fs_.add_raw_child("t", b"dot/.", "t/src.txt").unwrap();
    fs_
}

#[test]
fn get_r_never_writes_outside_the_destination_for_server_names() {
    let root = scratch("hostile_names");
    let dl = root.join("dl");
    fs::create_dir_all(&dl).unwrap();
    let abs = format!("/tmp/nfsc-review-{}-abs.txt", std::process::id());
    let mut s = session(hostile_fixture(&abs));
    lcd(&mut s, &dl);
    let r = run(&mut s, "get -r t");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(!root.join("escaped.txt").exists(), "wrote outside dl");
    assert!(!root.join("escaped2.txt").exists(), "wrote outside dl");
    assert!(
        !Path::new(&abs).exists(),
        "wrote to an absolute server name"
    );
    assert_eq!(fs::read(dl.join("t/real.txt")).unwrap(), b"real");
    assert!(r.err.contains("unsafe name"), "{}", r.err);
    let _ = fs::remove_file(&abs);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn get_r_stops_at_a_directory_linked_into_its_own_tree() {
    let mut fs_ = hostile_fixture("/tmp/nfsc-review-unused-abs");
    fs_.add_raw_child("t/sub", b"again", "t").unwrap();
    let mut s = session(fs_);
    let dir = scratch("get_r_loop");
    lcd(&mut s, &dir);
    let r = run(&mut s, "get -r t");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("directory loop"), "{}", r.err);
    assert!(dir.join("t/real.txt").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_r_limits_directory_depth() {
    let mut fs_ = fixture();
    let mut p = String::from("deep");
    fs_.add_dir(&p).unwrap();
    for _ in 0..300 {
        p.push_str("/d");
        fs_.add_dir(&p).unwrap();
    }
    fs_.add_file("deep/top.txt", b"top").unwrap();
    let mut s = session(fs_);
    let dir = scratch("get_r_depth");
    lcd(&mut s, &dir);
    let r = run(&mut s, "get -r deep");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("too deep"), "{}", r.err);
    assert!(dir.join("deep/top.txt").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_strips_setuid_setgid_and_sticky_from_server_modes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("get_modes");
    let mut fs_ = fixture();
    let root = fs_.root();
    let (fh, _) = fs_.lookup(&root, b"b.txt").unwrap();
    fs_.setattr(
        &fh,
        &SetAttr {
            mode: Some(0o7777),
            ..SetAttr::default()
        },
    )
    .unwrap();
    let mut s = session(fs_);
    lcd(&mut s, &dir);
    ok(&mut s, "get b.txt");
    let mode = fs::metadata(dir.join("b.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o7000,
        0,
        "special bits from the server reached the local file"
    );
    assert_eq!(mode & 0o777, 0o777);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn server_names_with_control_bytes_are_shown_escaped() {
    let dir = scratch("get_escape");
    let mut fs_ = fixture();
    fs_.add_file("ev\u{1b}[2Jil.txt", b"x").unwrap();
    let mut s = session(fs_);
    lcd(&mut s, &dir);
    let r = run(&mut s, "get ev*");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(!r.err.contains('\u{1b}'), "raw escape in {:?}", r.err);
    assert!(r.err.contains("ev\\x1b[2Jil.txt"), "{}", r.err);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn stat_shows_escaped_symlink_targets() {
    let mut fs_ = fixture();
    fs_.add_symlink("evlink", "tgt\u{1b}[31m").unwrap();
    let mut s = session(fs_);
    let out = ok(&mut s, "stat evlink");
    assert!(!out.contains('\u{1b}'), "raw escape in {out:?}");
}

#[test]
fn get_r_does_not_write_through_a_local_symlink() {
    let root = scratch("get_r_symlink");
    let dl = root.join("dl");
    fs::create_dir_all(dl.join("t")).unwrap();
    let victim = root.join("victim.txt");
    fs::write(&victim, b"keep").unwrap();
    std::os::unix::fs::symlink(&victim, dl.join("t/real.txt")).unwrap();
    let mut s = session(hostile_fixture("/tmp/nfsc-review-unused-2"));
    lcd(&mut s, &dl);
    let r = run(&mut s, "get -r t");
    assert!(
        r.failure.as_deref().is_some_and(|f| f.contains("symbolic link")),
        "{:?}",
        r.failure
    );
    assert_eq!(fs::read(&victim).unwrap(), b"keep", "download wrote through a symlink");
    let _ = fs::remove_dir_all(&root);
}
