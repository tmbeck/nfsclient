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
    assert!(help.contains("ls [-l] [path]") && help.contains("chown uid[:gid] path.."));
    assert!(help.contains("help <cmd>"), "{help}");
    let get = ok(&mut s, "help get");
    assert!(
        get.starts_with("get [-rcknpV] remote... [local]\n")
            && get.contains("-c  resume")
            && get.contains("-V  verify"),
        "{get}"
    );
    assert_eq!(ok(&mut s, "help quit"), ok(&mut s, "help exit"));
    assert!(run(&mut s, "help frob").failure.is_some());
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
        "nfsc: get: usage: get [-rcknpV] remote... [local]"
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
        "nfsc: get: nowhere: several files need a local directory as destination"
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
    /// Reads of this file at or past this offset fail with an I/O error, as
    /// if the server or the network broke down mid-transfer.
    fail_reads: Option<(FileHandle, u64)>,
    /// The byte at this offset of this file comes back flipped in the next
    /// `n` reads that cover it, as if data were damaged on the way.
    corrupt_reads: Option<(FileHandle, u64, usize)>,
    /// Writes (to any file) at or past this offset fail with an I/O error.
    fail_writes: Option<u64>,
    /// The byte at this offset is flipped in the next `n` writes covering it.
    corrupt_writes: Option<(u64, usize)>,
}

impl Tripwire {
    fn new(fs: Rc<RefCell<MemFs>>, flag: Arc<AtomicBool>, trip_after: usize) -> Self {
        Tripwire {
            fs,
            flag,
            calls: 0,
            trip_after,
            fail_reads: None,
            corrupt_reads: None,
            fail_writes: None,
            corrupt_writes: None,
        }
    }

    /// A backend that damages the byte at `offset` of `path` in the next
    /// `times` reads covering it.
    fn corrupting(fs: Rc<RefCell<MemFs>>, path: &str, offset: u64, times: usize) -> Self {
        let fh = {
            let mut inner = fs.borrow_mut();
            let root = inner.root();
            inner.lookup(&root, path.as_bytes()).unwrap().0
        };
        Tripwire {
            corrupt_reads: Some((fh, offset, times)),
            ..Self::new(fs, Arc::new(AtomicBool::new(false)), usize::MAX)
        }
    }

    /// A backend whose reads of `path` fail from `offset` on.
    fn failing(fs: Rc<RefCell<MemFs>>, flag: Arc<AtomicBool>, path: &str, offset: u64) -> Self {
        let fh = {
            let mut inner = fs.borrow_mut();
            let mut fh = inner.root();
            for part in path.split('/') {
                fh = inner.lookup(&fh, part.as_bytes()).unwrap().0;
            }
            fh
        };
        Tripwire {
            fail_reads: Some((fh, offset)),
            ..Self::new(fs, flag, usize::MAX)
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
        if let Some((bad, from)) = &self.fail_reads
            && bad == fh
            && offset >= *from
        {
            return Err(nfsc::Error::Nfs(nfsc::fs::Status::Io));
        }
        let (mut data, eof) = self.fs.borrow_mut().read(fh, offset, count)?;
        if let Some((bad, at, left)) = &mut self.corrupt_reads
            && bad == fh
            && *left > 0
            && *at >= offset
            && *at < offset + data.len() as u64
        {
            data[(*at - offset) as usize] ^= 0xFF;
            *left -= 1;
        }
        Ok((data, eof))
    }
    fn write(&mut self, fh: &FileHandle, offset: u64, data: &[u8]) -> nfsc::Result<u32> {
        self.tick();
        if self
            .fail_writes
            .is_some_and(|from| offset + data.len() as u64 > from)
        {
            return Err(nfsc::Error::Nfs(nfsc::fs::Status::Io));
        }
        if let Some((at, left)) = &mut self.corrupt_writes
            && *left > 0
            && *at >= offset
            && *at < offset + data.len() as u64
        {
            let mut bad = data.to_vec();
            bad[(*at - offset) as usize] ^= 0xFF;
            *left -= 1;
            return self.fs.borrow_mut().write(fh, offset, &bad);
        }
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
        vec![
            pair("-V", "-V"),
            pair("-c", "-c"),
            pair("-k", "-k"),
            pair("-n", "-n"),
            pair("-p", "-p"),
            pair("-r", "-r")
        ]
    );
    assert_eq!(complete(&s, "rm -"), vec![pair("-r", "-r ")]);
    assert_eq!(
        complete(&s, "du -"),
        vec![pair("-h", "-h"), pair("-s", "-s")]
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
fn ctrl_c_during_put_removes_the_remote_part_and_put_c_keeps_it() {
    let dir = scratch("cli3-ctrl_c_put");
    let data = pattern(8192);
    fs::write(dir.join("up.bin"), &data).unwrap();
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.max_write = 512;
    inner.add_file("up.bin", b"old good copy").unwrap();
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
            .contains("removed partial remote file up.bin.nfsc-part"),
        "{}",
        r.err
    );
    assert!(backend.borrow().attr_at("up.bin.nfsc-part").is_none());
    assert_eq!(
        backend.borrow().read_file("up.bin").unwrap(),
        b"old good copy",
        "an interrupted put leaves the existing remote file alone"
    );

    // With -c the part stays for the next put -c.
    flag.store(false, Ordering::SeqCst);
    let mut s = session_with(
        Box::new(Tripwire::new(backend.clone(), flag.clone(), 2)),
        flag.clone(),
    );
    lcd(&mut s, &dir);
    let r = run(&mut s, "put -c up.bin new.bin");
    assert_eq!(r.failure.as_deref(), Some("nfsc: put: up.bin: interrupted"));
    assert!(
        r.err
            .contains("partial remote file new.bin.nfsc-part kept (up to 1024 of 8192 bytes sent); put -c checks it and continues"),
        "{}",
        r.err
    );
    let kept = backend.borrow().attr_at("new.bin.nfsc-part").unwrap().size;
    assert_eq!(kept, 1024);
    assert!(backend.borrow().attr_at("new.bin").is_none());

    flag.store(false, Ordering::SeqCst);
    let r = run(&mut s, "put -c up.bin new.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at 1024"), "{}", r.err);
    assert_eq!(backend.borrow().read_file("new.bin"), Some(data));
    assert!(backend.borrow().attr_at("new.bin.nfsc-part").is_none());
    let _ = fs::remove_dir_all(&dir);
}

/// A session whose WRITEs fail from `offset` on, over `inner`.
fn failing_put(inner: MemFs, offset: u64) -> (Session, Rc<RefCell<MemFs>>) {
    let backend = Rc::new(RefCell::new(inner));
    let flag = Arc::new(AtomicBool::new(false));
    let mut wire = Tripwire::new(backend.clone(), flag.clone(), usize::MAX);
    wire.fail_writes = Some(offset);
    (session_with(Box::new(wire), flag), backend)
}

#[test]
fn a_failed_put_leaves_no_final_file_and_keeps_an_existing_one() {
    let dir = scratch("cli3-put_fail");
    let data = pattern(8192);
    fs::write(dir.join("big.bin"), &data).unwrap();
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.max_write = 512;
    inner.add_file("old.bin", b"good remote copy").unwrap();
    let (mut s, backend) = failing_put(inner, 4096);
    lcd(&mut s, &dir);

    let msg = fails(&mut s, "put big.bin");
    assert!(msg.starts_with("nfsc: put: big.bin: "), "{msg}");
    assert!(
        backend.borrow().attr_at("big.bin").is_none(),
        "no final name"
    );
    assert!(backend.borrow().attr_at("big.bin.nfsc-part").is_none());

    let r = run(&mut s, "put big.bin old.bin");
    assert!(r.failure.is_some());
    assert!(
        r.err
            .contains("removed partial remote file old.bin.nfsc-part"),
        "{}",
        r.err
    );
    assert_eq!(
        backend.borrow().read_file("old.bin").unwrap(),
        b"good remote copy",
        "never truncated or replaced"
    );

    // With -c the part is kept, and the existing file is still untouched.
    let r = run(&mut s, "put -c big.bin fresh.bin");
    assert!(r.failure.is_some());
    assert!(
        r.err.contains("put -c checks it and continues"),
        "{}",
        r.err
    );
    assert!(backend.borrow().attr_at("fresh.bin").is_none());
    assert_eq!(
        backend
            .borrow()
            .attr_at("fresh.bin.nfsc-part")
            .unwrap()
            .size,
        4096
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_replaces_through_a_rename_and_keeps_the_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("cli3-put_rename");
    fs::write(dir.join("ro.txt"), b"read only").unwrap();
    fs::set_permissions(dir.join("ro.txt"), fs::Permissions::from_mode(0o444)).unwrap();
    let backend = Rc::new(RefCell::new(fixture()));
    let flag = Arc::new(AtomicBool::new(false));
    let mut s = session_with(
        Box::new(Tripwire::new(backend.clone(), flag.clone(), usize::MAX)),
        flag,
    );
    lcd(&mut s, &dir);
    ok(&mut s, "put ro.txt b.txt");
    let b = backend.borrow();
    assert_eq!(b.read_file("b.txt").unwrap(), b"read only");
    assert_eq!(b.attr_at("b.txt").unwrap().mode & 0o7777, 0o444);
    assert!(b.attr_at("b.txt.nfsc-part").is_none());
    drop(b);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_c_resumes_from_the_remote_part() {
    let dir = scratch("cli3-put_resume_part");
    let data = pattern(8192);
    fs::write(dir.join("up.bin"), &data).unwrap();
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.add_file("up.bin", b"previous version").unwrap();
    inner.add_file("up.bin.nfsc-part", &data[..3000]).unwrap();
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
    assert!(backend.borrow().attr_at("up.bin.nfsc-part").is_none());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_c_refuses_a_part_that_differs_from_the_local_file() {
    let dir = scratch("cli3-put_resume_tail");
    let data = pattern(8192);
    fs::write(dir.join("up.bin"), &data).unwrap();
    let mut tail_differs = data[..3000].to_vec();
    tail_differs[2990] ^= 1;
    // A failed pipelined upload: a later chunk landed, an earlier one did not.
    let mut gap = data[..6000].to_vec();
    gap[1024..1536].fill(0);
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.add_file("up.bin.nfsc-part", &tail_differs).unwrap();
    inner.add_file("gap.bin.nfsc-part", &gap).unwrap();
    let backend = Rc::new(RefCell::new(inner));
    let flag = Arc::new(AtomicBool::new(false));
    let mut s = session_with(
        Box::new(Tripwire::new(backend.clone(), flag.clone(), usize::MAX)),
        flag,
    );
    lcd(&mut s, &dir);

    let msg = fails(&mut s, "put -c up.bin");
    assert!(
        msg.contains("remote file up.bin.nfsc-part differs from") && msg.contains("at offset 2990"),
        "{msg}"
    );
    assert!(msg.contains("put without -c"), "{msg}");
    assert_eq!(
        backend.borrow().read_file("up.bin.nfsc-part").unwrap(),
        tail_differs,
        "the part is left as it was"
    );
    assert!(backend.borrow().attr_at("up.bin").is_none());

    let msg = fails(&mut s, "put -c up.bin gap.bin");
    assert!(msg.contains("at offset 1024"), "the gap is found: {msg}");
    assert!(backend.borrow().attr_at("gap.bin").is_none());

    // Without -c the upload starts over and succeeds.
    ok(&mut s, "put up.bin");
    assert_eq!(backend.borrow().read_file("up.bin"), Some(data));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_verify_detects_data_damaged_on_the_way() {
    let dir = scratch("cli3-put_verify");
    let data = pattern(8192);
    fs::write(dir.join("big.bin"), &data).unwrap();
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.max_write = 512;
    inner.add_file("big.bin", b"good remote copy").unwrap();
    let backend = Rc::new(RefCell::new(inner));
    let mk = |times| {
        let flag = Arc::new(AtomicBool::new(false));
        let mut wire = Tripwire::new(backend.clone(), flag.clone(), usize::MAX);
        wire.corrupt_writes = Some((5000, times));
        session_with(Box::new(wire), flag)
    };

    let mut s = mk(1);
    lcd(&mut s, &dir);
    let r = run(&mut s, "put --verify big.bin");
    let msg = r.failure.expect("the mismatch fails the put");
    assert!(msg.contains("verification failed"), "{msg}");
    assert!(
        r.err.contains("removed big.bin.nfsc-part from the server"),
        "{}",
        r.err
    );
    assert!(backend.borrow().attr_at("big.bin.nfsc-part").is_none());
    assert_eq!(
        backend.borrow().read_file("big.bin").unwrap(),
        b"good remote copy",
        "damaged data never replaces the remote file"
    );

    // Undamaged: verified and in place.
    let mut s = mk(0);
    lcd(&mut s, &dir);
    let r = run(&mut s, "put -V big.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(
        r.err
            .contains(&format!("verified sha256 {}", sha256_hex(&data))),
        "{}",
        r.err
    );
    assert_eq!(backend.borrow().read_file("big.bin"), Some(data.clone()));

    // Without -V the same damage goes unnoticed.
    let mut s = mk(1);
    lcd(&mut s, &dir);
    ok(&mut s, "put big.bin");
    assert_ne!(backend.borrow().read_file("big.bin"), Some(data));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_applies_the_umask_unless_p() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("cli3-umask");
    let mut fs_ = fixture();
    let root = fs_.root();
    for (name, mode) in [(&b"b.txt"[..], 0o666), (&b"a"[..], 0o777)] {
        let (fh, _) = fs_.lookup(&root, name).unwrap();
        fs_.setattr(
            &fh,
            &SetAttr {
                mode: Some(mode),
                ..SetAttr::default()
            },
        )
        .unwrap();
    }
    let mut s = session(fs_);
    s.umask = 0o027;
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;

    lcd(&mut s, &dir);
    ok(&mut s, "get b.txt");
    assert_eq!(mode(&dir.join("b.txt")), 0o640);
    ok(&mut s, "get -r a");
    assert_eq!(mode(&dir.join("a")), 0o750);

    let keep = dir.join("keep");
    fs::create_dir(&keep).unwrap();
    lcd(&mut s, &keep);
    ok(&mut s, "get -p b.txt");
    assert_eq!(mode(&keep.join("b.txt")), 0o666);
    ok(&mut s, "get --preserve -r a");
    assert_eq!(mode(&keep.join("a")), 0o777);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_c_does_not_resume_an_older_local_file_in_place() {
    let dir = scratch("cli3-get_old_inplace");
    let data = pattern(8192);
    let mut backend = MemFs::new();
    backend.clock = NOW;
    backend.add_file("big.bin", &data).unwrap();
    let mut s = session(backend);
    lcd(&mut s, &dir);
    // An older complete copy whose start matches: the tail check passes,
    // but the file predates the remote one.
    let local = dir.join("big.bin");
    fs::write(&local, &data[..3000]).unwrap();
    File::options()
        .write(true)
        .open(&local)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(NOW as u64 - 3600))
        .unwrap();
    let msg = fails(&mut s, "get -c big.bin");
    assert!(msg.contains("older than the remote file"), "{msg}");
    assert_eq!(fs::read(&local).unwrap(), &data[..3000], "left alone");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_c_refuses_when_only_zeros_could_be_compared() {
    const MIB: u64 = 1 << 20;
    let dir = scratch("cli3-get_zero_tail");
    let mut backend = MemFs::new();
    backend.clock = NOW;
    backend.add_sparse_file("disk.img", 80 * MIB, 0).unwrap();
    backend.add_sparse_file("small.img", 3 * MIB, 0).unwrap();
    let mut s = session(backend);
    lcd(&mut s, &dir);
    File::create(dir.join("disk.img.nfsc-part"))
        .unwrap()
        .set_len(70 * MIB)
        .unwrap();
    let msg = fails(&mut s, "get -c disk.img");
    assert!(msg.contains("are all zeros"), "{msg}");
    assert!(msg.contains("get -cV"), "{msg}");
    assert_eq!(
        fs::metadata(dir.join("disk.img.nfsc-part")).unwrap().len(),
        70 * MIB
    );
    // -V checks the whole file afterwards, so it may resume.
    let r = run(&mut s, "get -cV disk.img");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at"), "{}", r.err);
    assert_eq!(fs::metadata(dir.join("disk.img")).unwrap().len(), 80 * MIB);

    // A zero prefix short enough to compare in full is proof enough.
    File::create(dir.join("small.img.nfsc-part"))
        .unwrap()
        .set_len(2 * MIB)
        .unwrap();
    let r = run(&mut s, "get -c small.img");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at 2097152"), "{}", r.err);
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
    {
        // Sparse up to 4 GiB; the last MiB matches the server, so the resume
        // check passes.
        let mut f = File::create(&local).unwrap();
        f.set_len(FOUR_GIB).unwrap();
        f.seek(SeekFrom::Start(FOUR_GIB - (1 << 20))).unwrap();
        f.write_all(&vec![0xAB; 1 << 20]).unwrap();
    }
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
    s.umask = 0o022;
    lcd(&mut s, &dir);
    ok(&mut s, "get -p b.txt");
    let mode = fs::metadata(dir.join("b.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o7000,
        0,
        "special bits from the server reached the local file"
    );
    assert_eq!(mode & 0o777, 0o777, "-p keeps the server's bits");
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
        r.failure
            .as_deref()
            .is_some_and(|f| f.contains("symbolic link")),
        "{:?}",
        r.failure
    );
    assert_eq!(
        fs::read(&victim).unwrap(),
        b"keep",
        "download wrote through a symlink"
    );
    let _ = fs::remove_dir_all(&root);
}

/// big.bin (8192 bytes, read in 512-byte chunks) behind a backend whose reads
/// of it fail from offset 2048, plus the shared inner filesystem.
fn failing_big_file() -> (Session, Rc<RefCell<MemFs>>, Vec<u8>) {
    let data = pattern(8192);
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.max_read = 512;
    inner.add_file("big.bin", &data).unwrap();
    let backend = Rc::new(RefCell::new(inner));
    let flag = Arc::new(AtomicBool::new(false));
    let s = session_with(
        Box::new(Tripwire::failing(
            backend.clone(),
            flag.clone(),
            "big.bin",
            2048,
        )),
        flag,
    );
    (s, backend, data)
}

#[test]
fn a_failed_get_leaves_no_partial_file_and_keeps_an_existing_one() {
    let dir = scratch("atomic_get");
    let (mut s, _, _) = failing_big_file();
    lcd(&mut s, &dir);
    let r = run(&mut s, "get big.bin");
    assert!(r.failure.is_some(), "the read error fails the get");
    assert!(r.err.contains("removed partial file"), "{}", r.err);
    assert!(!dir.join("big.bin").exists(), "no truncated final file");
    assert!(!dir.join("big.bin.nfsc-part").exists(), "part file removed");

    fs::write(dir.join("big.bin"), b"good old copy").unwrap();
    let r = run(&mut s, "get big.bin");
    assert!(r.failure.is_some());
    assert_eq!(
        fs::read(dir.join("big.bin")).unwrap(),
        b"good old copy",
        "a failed get must not damage the existing file"
    );
    assert!(!dir.join("big.bin.nfsc-part").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_c_keeps_the_part_file_on_failure_and_resumes_from_it() {
    let dir = scratch("resume_part");
    let (mut s, backend, data) = failing_big_file();
    lcd(&mut s, &dir);
    let r = run(&mut s, "get -c big.bin");
    assert!(r.failure.is_some());
    assert!(r.err.contains("partial file kept as"), "{}", r.err);
    assert!(
        !dir.join("big.bin").exists(),
        "nothing under the final name"
    );
    assert_eq!(
        fs::metadata(dir.join("big.bin.nfsc-part")).unwrap().len(),
        2048
    );

    // The server recovers.
    let flag = Arc::new(AtomicBool::new(false));
    let mut s = session_with(
        Box::new(Tripwire::new(backend, flag.clone(), usize::MAX)),
        flag,
    );
    lcd(&mut s, &dir);
    let r = run(&mut s, "get -c big.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at 2048"), "{}", r.err);
    assert_eq!(fs::read(dir.join("big.bin")).unwrap(), data);
    assert!(
        !dir.join("big.bin.nfsc-part").exists(),
        "renamed into place"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// t/{a.bin, b.bin, c.bin, sub/d.txt}; reads of t/b.bin fail.
fn failing_tree() -> Session {
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.add_dir("t").unwrap();
    inner.add_file("t/a.bin", b"aaaa").unwrap();
    inner.add_file("t/b.bin", b"bbbb").unwrap();
    inner.add_file("t/c.bin", b"cccc").unwrap();
    inner.add_dir("t/sub").unwrap();
    inner.add_file("t/sub/d.txt", b"dddd").unwrap();
    let backend = Rc::new(RefCell::new(inner));
    let flag = Arc::new(AtomicBool::new(false));
    session_with(
        Box::new(Tripwire::failing(backend, flag.clone(), "t/b.bin", 0)),
        flag,
    )
}

#[test]
fn get_r_stops_at_the_first_error_without_keep_going() {
    let dir = scratch("tree_stop");
    let mut s = failing_tree();
    lcd(&mut s, &dir);
    let r = run(&mut s, "get -r t");
    let msg = r.failure.expect("the tree fails");
    assert!(
        msg.starts_with("nfsc: get: t: ") && msg.contains("t/b.bin: "),
        "the failure names the file: {msg}"
    );
    assert!(dir.join("t/a.bin").exists());
    assert!(!dir.join("t/b.bin").exists());
    assert!(!dir.join("t/c.bin").exists(), "stopped at b.bin");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_r_keep_going_fetches_the_rest_and_fails_with_a_summary() {
    let dir = scratch("tree_keep_going");
    let mut s = failing_tree();
    lcd(&mut s, &dir);
    // A local directory where a file should go is a second, local failure.
    fs::create_dir_all(dir.join("t/c.bin")).unwrap();
    let r = run(&mut s, "get -r -k t");
    assert_eq!(
        r.failure.as_deref(),
        Some("nfsc: get: 2 items failed (listed above)")
    );
    assert_eq!(fs::read(dir.join("t/a.bin")).unwrap(), b"aaaa");
    assert_eq!(fs::read(dir.join("t/sub/d.txt")).unwrap(), b"dddd");
    assert!(!dir.join("t/b.bin").exists());
    assert!(!dir.join("t/b.bin.nfsc-part").exists());
    let summary = r.err.split("nfsc: get: failed:\n").nth(1).unwrap_or("");
    let listed: Vec<&str> = summary.lines().collect();
    assert_eq!(listed.len(), 2, "{}", r.err);
    assert!(listed[0].contains("t/b.bin: "), "{}", r.err);
    assert!(listed[1].contains("is not a regular file"), "{}", r.err);

    // In a script the failure stops the run with status 1.
    let _ = fs::remove_dir_all(dir.join("t"));
    let cmds = parse_script("get --keep-going -r t; pwd").unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = run_script_to(&mut s, &cmds, &mut out, &mut err);
    assert!(matches!(result, Err(CmdError::Reported(1))), "{result:?}");
    assert!(out.is_empty(), "pwd did not run");
    assert_eq!(fs::read(dir.join("t/c.bin")).unwrap(), b"cccc");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_n_skips_existing_local_files() {
    let dir = scratch("no_clobber");
    let mut s = session(fixture());
    lcd(&mut s, &dir);
    fs::write(dir.join("b.txt"), b"mine").unwrap();
    let r = run(&mut s, "get -n b.txt");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("skipping"), "{}", r.err);
    assert_eq!(fs::read(dir.join("b.txt")).unwrap(), b"mine");

    fs::create_dir_all(dir.join("a")).unwrap();
    fs::write(dir.join("a/inner.txt"), b"local").unwrap();
    ok(&mut s, "get -rn a");
    assert_eq!(fs::read(dir.join("a/inner.txt")).unwrap(), b"local");

    ok(&mut s, "get -n b.txt fresh.txt");
    assert_eq!(fs::read(dir.join("fresh.txt")).unwrap(), b"hello");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_r_restores_directory_modes_and_mtimes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("dir_attrs");
    let mut fs_ = fixture();
    let root = fs_.root();
    let (a, _) = fs_.lookup(&root, b"a").unwrap();
    fs_.setattr(
        &a,
        &SetAttr {
            mode: Some(0o3555),
            ..SetAttr::default()
        },
    )
    .unwrap();
    let mut s = session(fs_);
    lcd(&mut s, &dir);
    ok(&mut s, "get -r a");
    let meta = fs::metadata(dir.join("a")).unwrap();
    assert_eq!(
        meta.modified().unwrap(),
        UNIX_EPOCH + Duration::from_secs(NOW as u64)
    );
    assert_eq!(
        meta.permissions().mode() & 0o7777,
        0o555,
        "mode restored without setgid/sticky"
    );
    assert_eq!(fs::read(dir.join("a/inner.txt")).unwrap(), b"inner data");
    // A second run can still write into the read-only directory.
    ok(&mut s, "get -r a");
    assert_eq!(
        fs::metadata(dir.join("a")).unwrap().permissions().mode() & 0o777,
        0o555
    );
    fs::set_permissions(dir.join("a"), fs::Permissions::from_mode(0o755)).unwrap();
    let _ = fs::remove_dir_all(&dir);
}

/// A stdout whose reader has gone away.
struct ClosedPipe;

impl Write for ClosedPipe {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn a_closed_stdout_pipe_ends_cat_and_get_quietly() {
    for line in ["cat b.txt; pwd", "get b.txt -; pwd"] {
        let mut s = session(fixture());
        let cmds = parse_script(line).unwrap();
        let mut err = Vec::new();
        let result = run_script_to(&mut s, &cmds, &mut ClosedPipe, &mut err);
        assert!(
            matches!(result, Err(CmdError::Reported(141))),
            "{line}: {result:?}"
        );
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "",
            "{line}: nothing printed"
        );
    }
}

// ---- Integrity, multi-argument transfers, rm -r, du -------------------------

/// SHA-256 of `data` as hex.
fn sha256_hex(data: &[u8]) -> String {
    let mut h = super::checksum::Algo::Sha256.hasher();
    h.update(data);
    h.hex()
}

#[test]
fn sum_prints_sha256sum_lines() {
    let mut s = session(fixture());
    assert_eq!(
        ok(&mut s, "sum b.txt"),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  b.txt\n"
    );
    let out = ok(&mut s, "sum -a sha512 b.txt a/*.txt");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert!(
        lines[0].starts_with("9b71d224bd62f3785d96d46ad3ea3d73") && lines[0].ends_with("  b.txt"),
        "{out}"
    );
    assert!(lines[1].ends_with("  a/inner.txt"), "{out}");
    assert_eq!(
        fails(&mut s, "sum -a md4 b.txt"),
        "nfsc: sum: unknown algorithm 'md4' (use sha256, sha512)"
    );
    // A bad path is reported; the others are still summed and the command fails.
    let r = run(&mut s, "sum a nothere b.txt");
    assert!(r.out.ends_with("  b.txt\n"), "{}", r.out);
    assert!(r.err.contains("nfsc: sum: a: "), "{}", r.err);
    assert!(r.failure.unwrap().contains("2 items failed"));
}

#[test]
fn get_verify_passes_and_reports_the_digest() {
    let dir = scratch("get_verify");
    let data = pattern(8192);
    let mut backend = MemFs::new();
    backend.clock = NOW;
    backend.max_read = 512;
    backend.add_file("big.bin", &data).unwrap();
    let mut s = session(backend);
    lcd(&mut s, &dir);
    let r = run(&mut s, "get --verify big.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(
        r.err
            .contains(&format!("verified sha256 {}", sha256_hex(&data))),
        "{}",
        r.err
    );
    assert_eq!(fs::read(dir.join("big.bin")).unwrap(), data);

    // A resume hashes the kept prefix too.
    fs::write(dir.join("big.bin.nfsc-part"), &data[..3000]).unwrap();
    fs::remove_file(dir.join("big.bin")).unwrap();
    let r = run(&mut s, "get -cV big.bin");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(r.err.contains("resumed at 3000"), "{}", r.err);
    assert!(r.err.contains("verified sha256"), "{}", r.err);
    assert_eq!(fs::read(dir.join("big.bin")).unwrap(), data);

    assert!(fails(&mut s, "get -V big.bin -").contains("-V needs a local file"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_verify_detects_data_damaged_in_transit() {
    let dir = scratch("get_verify_bad");
    let data = pattern(8192);
    let mut inner = MemFs::new();
    inner.clock = NOW;
    inner.max_read = 512;
    inner.add_file("big.bin", &data).unwrap();
    let backend = Rc::new(RefCell::new(inner));
    let mut s = session_with(
        Box::new(Tripwire::corrupting(backend.clone(), "big.bin", 5000, 1)),
        Arc::new(AtomicBool::new(false)),
    );
    lcd(&mut s, &dir);
    fs::write(dir.join("big.bin"), b"good old copy").unwrap();
    let r = run(&mut s, "get -V big.bin");
    let msg = r.failure.expect("the mismatch fails the get");
    assert!(msg.contains("verification failed"), "{msg}");
    assert!(r.err.contains("removed"), "{}", r.err);
    assert!(
        !dir.join("big.bin.nfsc-part").exists(),
        "damaged data removed"
    );
    assert_eq!(
        fs::read(dir.join("big.bin")).unwrap(),
        b"good old copy",
        "the existing file is not replaced by damaged data"
    );

    // Without -V the same damage goes unnoticed, which is why -V exists.
    let mut s = session_with(
        Box::new(Tripwire::corrupting(backend, "big.bin", 5000, 1)),
        Arc::new(AtomicBool::new(false)),
    );
    lcd(&mut s, &dir);
    ok(&mut s, "get big.bin");
    assert_ne!(fs::read(dir.join("big.bin")).unwrap(), data);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_c_refuses_when_the_local_tail_differs_from_the_server() {
    let dir = scratch("resume_tail");
    let data = pattern(8192);
    let mut backend = MemFs::new();
    backend.clock = NOW;
    backend.add_file("big.bin", &data).unwrap();
    let mut s = session(backend);
    lcd(&mut s, &dir);
    let mut part = data[..3000].to_vec();
    part[2990] ^= 1;
    fs::write(dir.join("big.bin.nfsc-part"), &part).unwrap();
    let msg = fails(&mut s, "get -c big.bin");
    assert!(
        msg.contains("does not match the remote file in the 3000 bytes before offset 3000"),
        "{msg}"
    );
    assert!(msg.contains("without -c"), "{msg}");
    assert_eq!(
        fs::read(dir.join("big.bin.nfsc-part")).unwrap(),
        part,
        "the part file is left as it was"
    );
    assert!(!dir.join("big.bin").exists());

    // An in-place partial file is checked the same way.
    fs::remove_file(dir.join("big.bin.nfsc-part")).unwrap();
    fs::write(dir.join("big.bin"), b"something else entirely").unwrap();
    assert!(fails(&mut s, "get -c big.bin").contains("does not match"));
    ok(&mut s, "get big.bin");
    assert_eq!(fs::read(dir.join("big.bin")).unwrap(), data);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn get_takes_several_remote_arguments_into_a_local_directory() {
    let dir = scratch("get_multi");
    let mut fs_ = fixture();
    fs_.add_file("x.tmp", b"x").unwrap();
    fs_.add_file("y.tmp", b"y").unwrap();
    let mut s = session(fs_);
    lcd(&mut s, &dir);
    fs::create_dir(dir.join("dl")).unwrap();
    let r = run(&mut s, "get b.txt a/inner.txt *.tmp dl");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    for (name, body) in [
        ("b.txt", &b"hello"[..]),
        ("inner.txt", b"inner data"),
        ("x.tmp", b"x"),
        ("y.tmp", b"y"),
    ] {
        assert_eq!(fs::read(dir.join("dl").join(name)).unwrap(), body, "{name}");
    }
    assert_eq!(
        fails(&mut s, "get b.txt a/inner.txt nowhere"),
        "nfsc: get: nowhere: several files need a local directory as destination"
    );
    assert_eq!(
        fails(&mut s, "get b.txt missing/"),
        "nfsc: get: missing/: no such local directory"
    );
    // Two arguments keep their meaning: remote, then local name.
    ok(&mut s, "get b.txt renamed.txt");
    assert_eq!(fs::read(dir.join("renamed.txt")).unwrap(), b"hello");
    ok(&mut s, "get b.txt dl/");
    // -k carries on past a missing remote.
    let r = run(&mut s, "get -k nothere b.txt dl");
    assert!(r.failure.unwrap().contains("1 item failed"));
    assert!(r.err.contains("nothere"), "{}", r.err);
    assert!(fails(&mut s, "get b.txt x.tmp -").contains("only one file"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn put_expands_local_globs_and_honors_n_and_k() {
    let dir = scratch("put_glob");
    fs::write(dir.join("x.iso"), b"x-local").unwrap();
    fs::write(dir.join("y.iso"), b"y-local").unwrap();
    fs::write(dir.join("z.txt"), b"z-local").unwrap();
    fs::create_dir(dir.join("sub")).unwrap();
    fs::write(dir.join("sub/w.tar"), b"w-local").unwrap();
    let backend = Rc::new(RefCell::new(fixture()));
    let flag = Arc::new(AtomicBool::new(false));
    let mut s = session_with(
        Box::new(Tripwire::new(backend.clone(), flag.clone(), usize::MAX)),
        flag,
    );
    lcd(&mut s, &dir);

    ok(&mut s, "put *.iso");
    assert_eq!(backend.borrow().read_file("x.iso").unwrap(), b"x-local");
    assert_eq!(backend.borrow().read_file("y.iso").unwrap(), b"y-local");
    assert!(backend.borrow().read_file("z.txt").is_none());

    ok(&mut s, "put sub/*.tar z.txt a");
    assert_eq!(backend.borrow().read_file("a/w.tar").unwrap(), b"w-local");
    assert_eq!(backend.borrow().read_file("a/z.txt").unwrap(), b"z-local");
    assert!(
        fails(&mut s, "put x.iso y.iso nowhere").contains("several files need a remote directory")
    );
    assert!(fails(&mut s, "put *.nope").contains("no match"));

    // -n leaves existing remote files alone.
    fs::write(dir.join("x.iso"), b"x-changed").unwrap();
    let r = run(&mut s, "put -n *.iso");
    assert!(r.failure.is_none(), "{:?}", r.failure);
    assert!(
        r.err.contains("skipping x.iso: it exists on the server"),
        "{}",
        r.err
    );
    assert_eq!(backend.borrow().read_file("x.iso").unwrap(), b"x-local");
    ok(&mut s, "put --no-clobber -r sub");
    assert_eq!(backend.borrow().read_file("sub/w.tar").unwrap(), b"w-local");

    // -k: the missing file is reported, the rest still go up, the command fails.
    let r = run(&mut s, "put -k missing.bin x.iso z.txt a");
    let msg = r.failure.expect("put -k still fails");
    assert!(msg.contains("1 item failed"), "{msg}");
    assert!(r.err.contains("missing.bin"), "{}", r.err);
    assert_eq!(backend.borrow().read_file("a/x.iso").unwrap(), b"x-changed");
    // Without -k the first failure stops the put.
    assert!(run(&mut s, "put missing.bin y.iso a").failure.is_some());
    assert!(backend.borrow().read_file("a/y.iso").is_none());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rm_r_removes_a_tree_without_following_links() {
    let mut fs_ = fixture();
    fs_.add_dir("t/sub/deeper").unwrap();
    fs_.add_file("t/f.txt", b"f").unwrap();
    fs_.add_file("t/sub/g.txt", b"g").unwrap();
    fs_.add_file("t/sub/deeper/h.txt", b"h").unwrap();
    fs_.add_symlink("t/to_a", "../a").unwrap();
    let mut s = session(fs_);
    assert!(
        run(&mut s, "rm t").failure.is_some(),
        "rm without -r keeps trees"
    );
    ok(&mut s, "rm -r t");
    assert!(fails(&mut s, "stat t").contains("t"));
    assert_eq!(
        ok(&mut s, "cat a/inner.txt"),
        "inner data",
        "link target kept"
    );
    // A plain file works with -r too.
    ok(&mut s, "rm -r b.txt");
    assert!(run(&mut s, "stat b.txt").failure.is_some());
    // The working directory cannot be removed from under the session.
    ok(&mut s, "cd a");
    assert!(fails(&mut s, "rm -r /a").contains("refusing to remove the current directory"));
    assert!(fails(&mut s, "rm -r ..").contains("invalid name"));
}

#[test]
fn rm_r_does_not_loop_through_a_directory_linked_into_its_tree() {
    let mut fs_ = hostile_fixture("/tmp/nfsc-review-unused-abs");
    fs_.add_raw_child("t/sub", b"again", "t").unwrap();
    let mut s = session(fs_);
    let r = run(&mut s, "rm -r t");
    assert!(
        r.err.contains("skipping directory loop t/sub/again"),
        "{}",
        r.err
    );
    assert!(
        r.failure.is_some(),
        "the loop keeps t/sub from being emptied"
    );
}

#[test]
fn du_sums_file_sizes_per_directory() {
    let mut fs_ = fixture();
    fs_.add_file("a/sub/more.bin", &pattern(3000)).unwrap();
    let mut s = session(fs_);
    assert_eq!(ok(&mut s, "du"), "3000\t./a/sub\n3010\t./a\n3015\t.\n");
    assert_eq!(ok(&mut s, "du -s a/"), "3010\ta\n");
    assert_eq!(ok(&mut s, "du -sh"), "3.0K\t.\n");
    assert_eq!(ok(&mut s, "du b.txt"), "5\tb.txt\n");
    assert!(run(&mut s, "du nothere").failure.is_some());
}
