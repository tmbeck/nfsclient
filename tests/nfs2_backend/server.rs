//! In-process NFSv2 server over an in-memory tree, for backend tests.
//!
//! Serves program 100003 version 2 on 127.0.0.1 over both TCP (record marking)
//! and UDP (one datagram per message) on the same port number. It only speaks
//! NFSv2; portmap and MOUNT are not served (the backend is connected with a
//! known root handle and an explicit port).

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use nfsc::fs::FileHandle;
use nfsc::nfs2::proto::*;
use nfsc::xdr::{Decoder, Encoder, Opaque, Unpack, from_bytes, to_bytes};

const PROG: u32 = 100003;
const VERS: u32 = 2;
const ROOT: u32 = 1;

// Stat values used by the fake.
const ST_PERM: u32 = 1;
const ST_NOENT: u32 = 2;
const ST_INVAL: u32 = 22;
const ST_ISDIR: u32 = 21;
const ST_NOTDIR: u32 = 20;
const ST_EXIST: u32 = 17;
const ST_NOTEMPTY: u32 = 66;
const ST_STALE: u32 = 70;

// Accept status values.
const ACCEPT_SUCCESS: u32 = 0;
const ACCEPT_PROG_UNAVAIL: u32 = 1;
const ACCEPT_PROG_MISMATCH: u32 = 2;
const ACCEPT_PROC_UNAVAIL: u32 = 3;
const ACCEPT_GARBAGE_ARGS: u32 = 4;

const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// Fixed server clock so attribute assertions are deterministic.
const NOW: TimeVal = TimeVal {
    seconds: 1_650_000_000,
    useconds: 123_000,
};
const BLOCKSIZE: u32 = 1024;

/// Counters and fault knobs shared with the test.
#[derive(Default)]
pub struct Stats {
    pub readdir_calls: AtomicUsize,
    /// UDP requests to silently drop before answering again.
    pub udp_drop: AtomicUsize,
}

#[derive(Clone)]
enum Body {
    Dir(BTreeMap<Vec<u8>, u32>),
    File(Vec<u8>),
    Link(Vec<u8>),
}

#[derive(Clone)]
struct Node {
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    atime: TimeVal,
    mtime: TimeVal,
    ctime: TimeVal,
    parent: u32,
    body: Body,
}

pub struct MemFs {
    nodes: HashMap<u32, Node>,
    next_id: u32,
}

type St<T> = Result<T, u32>;

fn new_node(mode: u32, parent: u32, body: Body) -> Node {
    Node {
        mode,
        uid: 0,
        gid: 0,
        nlink: 1,
        atime: NOW,
        mtime: NOW,
        ctime: NOW,
        parent,
        body,
    }
}

impl MemFs {
    fn new() -> Self {
        let mut root = new_node(0o755, ROOT, Body::Dir(BTreeMap::new()));
        root.nlink = 2;
        let mut nodes = HashMap::new();
        nodes.insert(ROOT, root);
        MemFs { nodes, next_id: 2 }
    }

    fn handle(id: u32) -> WireFh {
        let mut b = [0u8; FHSIZE];
        b[..4].copy_from_slice(&id.to_be_bytes());
        WireFh(b)
    }

    fn id_of(&self, fh: &WireFh) -> St<u32> {
        let id = u32::from_be_bytes(fh.0[..4].try_into().unwrap());
        if self.nodes.contains_key(&id) && fh.0[4..].iter().all(|&b| b == 0) {
            Ok(id)
        } else {
            Err(ST_STALE)
        }
    }

    fn node(&self, id: u32) -> &Node {
        &self.nodes[&id]
    }

    fn node_mut(&mut self, id: u32) -> &mut Node {
        self.nodes.get_mut(&id).unwrap()
    }

    fn dir_entries(&self, id: u32) -> St<&BTreeMap<Vec<u8>, u32>> {
        match &self.node(id).body {
            Body::Dir(m) => Ok(m),
            _ => Err(ST_NOTDIR),
        }
    }

    fn dir_entries_mut(&mut self, id: u32) -> St<&mut BTreeMap<Vec<u8>, u32>> {
        match &mut self.node_mut(id).body {
            Body::Dir(m) => Ok(m),
            _ => Err(ST_NOTDIR),
        }
    }

    fn is_dir(&self, id: u32) -> bool {
        matches!(self.node(id).body, Body::Dir(_))
    }

    fn fresh_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn attr(&self, id: u32) -> Fattr {
        let n = self.node(id);
        let (ftype, typebits, size, rdev) = match &n.body {
            Body::Dir(_) => (NFDIR, S_IFDIR, BLOCKSIZE, 0),
            Body::File(d) => (NFREG, S_IFREG, d.len() as u32, 0),
            Body::Link(t) => (NFLNK, S_IFLNK, t.len() as u32, 0),
        };
        let nlink = n.nlink;
        Fattr {
            ftype,
            mode: n.mode | typebits,
            nlink,
            uid: n.uid,
            gid: n.gid,
            size,
            blocksize: BLOCKSIZE,
            rdev,
            blocks: size.div_ceil(BLOCKSIZE),
            fsid: 0x1234,
            fileid: id,
            atime: n.atime,
            mtime: n.mtime,
            ctime: n.ctime,
        }
    }

    fn getattr(&self, fh: &WireFh) -> St<Fattr> {
        Ok(self.attr(self.id_of(fh)?))
    }

    fn setattr(&mut self, fh: &WireFh, sa: Sattr) -> St<Fattr> {
        let id = self.id_of(fh)?;
        if sa.size != UNSET {
            match &mut self.node_mut(id).body {
                Body::File(d) => d.resize(sa.size as usize, 0),
                Body::Dir(_) => return Err(ST_ISDIR),
                Body::Link(_) => return Err(ST_INVAL),
            }
        }
        let n = self.node_mut(id);
        if sa.mode != UNSET {
            n.mode = sa.mode & 0o7777;
        }
        if sa.uid != UNSET {
            n.uid = sa.uid;
        }
        if sa.gid != UNSET {
            n.gid = sa.gid;
        }
        if sa.atime != TimeVal::UNSET {
            n.atime = sa.atime;
        }
        if sa.mtime != TimeVal::UNSET {
            n.mtime = sa.mtime;
        }
        Ok(self.attr(id))
    }

    fn lookup(&self, dir: &WireFh, name: &[u8]) -> St<(WireFh, Fattr)> {
        let d = self.id_of(dir)?;
        let entries = self.dir_entries(d)?;
        let child = match name {
            b"." => d,
            b".." => self.node(d).parent,
            _ => *entries.get(name).ok_or(ST_NOENT)?,
        };
        Ok((Self::handle(child), self.attr(child)))
    }

    fn readlink(&self, fh: &WireFh) -> St<Opaque> {
        match &self.node(self.id_of(fh)?).body {
            Body::Link(t) => Ok(Opaque(t.clone())),
            _ => Err(ST_INVAL),
        }
    }

    fn read(&self, fh: &WireFh, offset: u32, count: u32) -> St<(Fattr, Opaque)> {
        let id = self.id_of(fh)?;
        let data = match &self.node(id).body {
            Body::File(d) => d,
            Body::Dir(_) => return Err(ST_ISDIR),
            Body::Link(_) => return Err(ST_INVAL),
        };
        let start = (offset as usize).min(data.len());
        let end = (start + (count.min(MAXDATA)) as usize).min(data.len());
        Ok((self.attr(id), Opaque(data[start..end].to_vec())))
    }

    fn write(&mut self, fh: &WireFh, offset: u32, data: &[u8]) -> St<Fattr> {
        let id = self.id_of(fh)?;
        match &mut self.node_mut(id).body {
            Body::File(d) => {
                let end = offset as usize + data.len();
                if d.len() < end {
                    d.resize(end, 0);
                }
                d[offset as usize..end].copy_from_slice(data);
            }
            Body::Dir(_) => return Err(ST_ISDIR),
            Body::Link(_) => return Err(ST_INVAL),
        }
        self.node_mut(id).mtime = NOW;
        Ok(self.attr(id))
    }

    /// Insert a new child (`body`) under `dir`/`name`, after checking the name is free.
    fn insert_child(
        &mut self,
        dir: &WireFh,
        name: &[u8],
        mode: u32,
        body: Body,
    ) -> St<(u32, Node)> {
        let d = self.id_of(dir)?;
        if !self.is_dir(d) {
            return Err(ST_NOTDIR);
        }
        if self.dir_entries(d)?.contains_key(name) {
            return Err(ST_EXIST);
        }
        let id = self.fresh_id();
        let is_dir = matches!(body, Body::Dir(_));
        let node = new_node(mode, d, body);
        self.dir_entries_mut(d)?.insert(name.to_vec(), id);
        if is_dir {
            self.node_mut(d).nlink += 1;
        }
        self.nodes.insert(id, node.clone());
        Ok((id, node))
    }

    fn create(&mut self, dir: &WireFh, name: &[u8], sa: Sattr) -> St<(WireFh, Fattr)> {
        let d = self.id_of(dir)?;
        if let Some(&existing) = self.dir_entries(d)?.get(name) {
            if self.is_dir(existing) {
                return Err(ST_ISDIR);
            }
            if sa.size != UNSET {
                self.setattr(&Self::handle(existing), sa)?;
            }
            return Ok((Self::handle(existing), self.attr(existing)));
        }
        let mode = if sa.mode == UNSET {
            0o644
        } else {
            sa.mode & 0o7777
        };
        let (id, _) = self.insert_child(dir, name, mode, Body::File(Vec::new()))?;
        if sa.size != UNSET {
            self.setattr(&Self::handle(id), sa)?;
        }
        Ok((Self::handle(id), self.attr(id)))
    }

    fn mkdir(&mut self, dir: &WireFh, name: &[u8], sa: Sattr) -> St<(WireFh, Fattr)> {
        let mode = if sa.mode == UNSET {
            0o755
        } else {
            sa.mode & 0o7777
        };
        let (id, _) = self.insert_child(dir, name, mode, Body::Dir(BTreeMap::new()))?;
        self.node_mut(id).nlink = 2;
        Ok((Self::handle(id), self.attr(id)))
    }

    fn symlink(&mut self, dir: &WireFh, name: &[u8], target: &[u8]) -> St<()> {
        self.insert_child(dir, name, 0o777, Body::Link(target.to_vec()))?;
        Ok(())
    }

    fn link(&mut self, target: &WireFh, dir: &WireFh, name: &[u8]) -> St<()> {
        let t = self.id_of(target)?;
        if self.is_dir(t) {
            return Err(ST_PERM);
        }
        let d = self.id_of(dir)?;
        if !self.is_dir(d) {
            return Err(ST_NOTDIR);
        }
        if self.dir_entries(d)?.contains_key(name) {
            return Err(ST_EXIST);
        }
        self.dir_entries_mut(d)?.insert(name.to_vec(), t);
        self.node_mut(t).nlink += 1;
        Ok(())
    }

    /// Remove a non-directory entry, dropping the node once its last link goes.
    fn remove(&mut self, dir: &WireFh, name: &[u8]) -> St<()> {
        let d = self.id_of(dir)?;
        let child = *self.dir_entries(d)?.get(name).ok_or(ST_NOENT)?;
        if self.is_dir(child) {
            return Err(ST_ISDIR);
        }
        self.dir_entries_mut(d)?.remove(name);
        self.unlink_node(child);
        Ok(())
    }

    fn unlink_node(&mut self, id: u32) {
        let n = self.node_mut(id);
        n.nlink -= 1;
        if n.nlink == 0 {
            self.nodes.remove(&id);
        }
    }

    fn rmdir(&mut self, dir: &WireFh, name: &[u8]) -> St<()> {
        let d = self.id_of(dir)?;
        let child = *self.dir_entries(d)?.get(name).ok_or(ST_NOENT)?;
        match &self.node(child).body {
            Body::Dir(m) if !m.is_empty() => return Err(ST_NOTEMPTY),
            Body::Dir(_) => {}
            _ => return Err(ST_NOTDIR),
        }
        self.dir_entries_mut(d)?.remove(name);
        self.node_mut(d).nlink -= 1;
        self.nodes.remove(&child);
        Ok(())
    }

    fn rename(
        &mut self,
        from_dir: &WireFh,
        from_name: &[u8],
        to_dir: &WireFh,
        to_name: &[u8],
    ) -> St<()> {
        let fd = self.id_of(from_dir)?;
        let td = self.id_of(to_dir)?;
        let src = *self.dir_entries(fd)?.get(from_name).ok_or(ST_NOENT)?;
        if !self.is_dir(td) {
            return Err(ST_NOTDIR);
        }
        if let Some(&dst) = self.dir_entries(td)?.get(to_name) {
            if dst == src {
                return Ok(());
            }
            match (self.is_dir(src), self.is_dir(dst)) {
                (true, false) => return Err(ST_NOTDIR),
                (false, true) => return Err(ST_ISDIR),
                (true, true) => {
                    if !matches!(&self.node(dst).body, Body::Dir(m) if m.is_empty()) {
                        return Err(ST_NOTEMPTY);
                    }
                    self.node_mut(td).nlink -= 1;
                    self.nodes.remove(&dst);
                }
                (false, false) => self.unlink_node(dst),
            }
            self.dir_entries_mut(td)?.remove(to_name);
        }
        self.dir_entries_mut(fd)?.remove(from_name);
        self.dir_entries_mut(td)?.insert(to_name.to_vec(), src);
        if self.is_dir(src) {
            self.node_mut(src).parent = td;
            if fd != td {
                self.node_mut(fd).nlink -= 1;
                self.node_mut(td).nlink += 1;
            }
        }
        Ok(())
    }

    fn readdir(&self, dir: &WireFh, cookie: Cookie, count: u32) -> St<DirList> {
        let d = self.id_of(dir)?;
        let entries = self.dir_entries(d)?;
        let mut listing: Vec<(Vec<u8>, u32)> =
            vec![(b".".to_vec(), d), (b"..".to_vec(), self.node(d).parent)];
        listing.extend(entries.iter().map(|(k, &v)| (k.clone(), v)));

        let mut i = u32::from_be_bytes(cookie.0) as usize;
        // Header overhead: status, the final "no more entries" flag, and eof.
        let budget = (count as usize).saturating_sub(12);
        let mut used = 0usize;
        let mut out = Vec::new();
        while i < listing.len() {
            let (name, fileid) = &listing[i];
            let size = 16 + name.len().div_ceil(4) * 4;
            if used + size > budget && !out.is_empty() {
                break;
            }
            used += size;
            out.push(Entry {
                fileid: *fileid,
                name: Opaque(name.clone()),
                cookie: Cookie(((i + 1) as u32).to_be_bytes()),
            });
            i += 1;
        }
        Ok(DirList {
            entries: out,
            eof: i >= listing.len(),
        })
    }
}

/// Decode arguments; a malformed body is GARBAGE_ARGS.
fn dec<T: Unpack>(args: &[u8]) -> Result<T, u32> {
    from_bytes(args).map_err(|_| ACCEPT_GARBAGE_ARGS)
}

fn res<T>(r: St<T>) -> Res<T> {
    match r {
        Ok(v) => Res::Ok(v),
        Err(s) => Res::Err(s),
    }
}

/// Run one NFSv2 procedure. Returns the result bytes, or an accept_stat.
fn dispatch(fs: &mut MemFs, stats: &Stats, proc_: u32, args: &[u8]) -> Result<Vec<u8>, u32> {
    let out = match proc_ {
        PROC_NULL => Vec::new(),
        PROC_GETATTR => {
            let fh: WireFh = dec(args)?;
            to_bytes(&res(fs.getattr(&fh)))
        }
        PROC_SETATTR => {
            let (fh, sa): (WireFh, Sattr) = dec(args)?;
            to_bytes(&res(fs.setattr(&fh, sa)))
        }
        PROC_LOOKUP => {
            let (dir, name): (WireFh, Opaque) = dec(args)?;
            to_bytes(&res(fs.lookup(&dir, &name.0)))
        }
        PROC_READLINK => {
            let fh: WireFh = dec(args)?;
            to_bytes(&res(fs.readlink(&fh)))
        }
        PROC_READ => {
            let (fh, off, count, _total): (WireFh, u32, u32, u32) = dec(args)?;
            to_bytes(&res(fs.read(&fh, off, count)))
        }
        PROC_WRITE => {
            let w: WriteArgs = dec(args)?;
            to_bytes(&res(fs.write(&w.fh, w.offset, &w.data.0)))
        }
        PROC_CREATE => {
            let ((dir, name), sa): ((WireFh, Opaque), Sattr) = dec(args)?;
            to_bytes(&res(fs.create(&dir, &name.0, sa)))
        }
        PROC_REMOVE => {
            let (dir, name): (WireFh, Opaque) = dec(args)?;
            to_bytes(&res(fs.remove(&dir, &name.0)))
        }
        PROC_RENAME => {
            let ((fd, fname), (td, tname)): ((WireFh, Opaque), (WireFh, Opaque)) = dec(args)?;
            to_bytes(&res(fs.rename(&fd, &fname.0, &td, &tname.0)))
        }
        PROC_LINK => {
            let (target, (dir, name)): (WireFh, (WireFh, Opaque)) = dec(args)?;
            to_bytes(&res(fs.link(&target, &dir, &name.0)))
        }
        PROC_SYMLINK => {
            let ((dir, name), target, _sa): ((WireFh, Opaque), Opaque, Sattr) = dec(args)?;
            to_bytes(&res(fs.symlink(&dir, &name.0, &target.0)))
        }
        PROC_MKDIR => {
            let ((dir, name), sa): ((WireFh, Opaque), Sattr) = dec(args)?;
            to_bytes(&res(fs.mkdir(&dir, &name.0, sa)))
        }
        PROC_RMDIR => {
            let (dir, name): (WireFh, Opaque) = dec(args)?;
            to_bytes(&res(fs.rmdir(&dir, &name.0)))
        }
        PROC_READDIR => {
            stats.readdir_calls.fetch_add(1, Ordering::SeqCst);
            let (dir, cookie, count): (WireFh, Cookie, u32) = dec(args)?;
            to_bytes(&res(fs.readdir(&dir, cookie, count)))
        }
        PROC_STATFS => {
            let _fh: WireFh = dec(args)?;
            to_bytes(&Res::Ok(StatfsOk {
                tsize: MAXDATA,
                bsize: 1024,
                blocks: 1000,
                bfree: 500,
                bavail: 400,
            }))
        }
        _ => return Err(ACCEPT_PROC_UNAVAIL),
    };
    Ok(out)
}

/// Accepted reply header followed by `body`.
fn accepted(xid: u32, accept: u32, body: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.put_u32(xid).put_u32(1).put_u32(0);
    e.put_u32(0).put_opaque(&[]); // verifier AUTH_NONE
    e.put_u32(accept);
    let mut v = e.into_inner();
    v.extend_from_slice(body);
    v
}

/// Parse a CALL and produce the reply bytes. `None` means the datagram is junk.
fn handle_message(fs: &Mutex<MemFs>, stats: &Stats, msg: &[u8]) -> Option<Vec<u8>> {
    let mut d = Decoder::new(msg);
    let xid = d.get_u32().ok()?;
    if d.get_u32().ok()? != 0 || d.get_u32().ok()? != 2 {
        return None; // not a CALL, or wrong RPC version (not exercised)
    }
    let prog = d.get_u32().ok()?;
    let vers = d.get_u32().ok()?;
    let proc_ = d.get_u32().ok()?;
    for _ in 0..2 {
        // credential, then verifier: flavor + opaque body
        d.get_u32().ok()?;
        d.get_opaque().ok()?;
    }
    let args = d.rest();
    if prog != PROG {
        return Some(accepted(xid, ACCEPT_PROG_UNAVAIL, &[]));
    }
    if vers != VERS {
        let mut body = Vec::new();
        body.extend_from_slice(&VERS.to_be_bytes());
        body.extend_from_slice(&VERS.to_be_bytes());
        return Some(accepted(xid, ACCEPT_PROG_MISMATCH, &body));
    }
    let mut fs = fs.lock().unwrap();
    Some(match dispatch(&mut fs, stats, proc_, args) {
        Ok(body) => accepted(xid, ACCEPT_SUCCESS, &body),
        Err(accept) => accepted(xid, accept, &[]),
    })
}

fn read_record(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).ok()?;
        let w = u32::from_be_bytes(hdr);
        let mut frag = vec![0u8; (w & 0x7fff_ffff) as usize];
        s.read_exact(&mut frag).ok()?;
        out.extend_from_slice(&frag);
        if w & 0x8000_0000 != 0 {
            return Some(out);
        }
    }
}

fn write_record(s: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    s.write_all(&(0x8000_0000u32 | data.len() as u32).to_be_bytes())?;
    s.write_all(data)
}

pub struct FakeNfs2 {
    pub port: u16,
    pub stats: Arc<Stats>,
    root: FileHandle,
}

impl FakeNfs2 {
    pub fn root(&self) -> FileHandle {
        self.root.clone()
    }
}

/// Start a server on a fresh 127.0.0.1 port, serving TCP and UDP on that number.
pub fn start() -> FakeNfs2 {
    let (udp, tcp, port) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        // TCP must be on the same number: the backend takes one NFS port.
        if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)) {
            break (udp, tcp, port);
        }
    };
    let fs = Arc::new(Mutex::new(MemFs::new()));
    let stats = Arc::new(Stats::default());

    {
        let fs = Arc::clone(&fs);
        let stats = Arc::clone(&stats);
        thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, peer)) = udp.recv_from(&mut buf) else {
                    continue;
                };
                let remaining = stats.udp_drop.load(Ordering::SeqCst);
                if remaining > 0 {
                    stats.udp_drop.store(remaining - 1, Ordering::SeqCst);
                    continue;
                }
                if let Some(reply) = handle_message(&fs, &stats, &buf[..n]) {
                    let _ = udp.send_to(&reply, peer);
                }
            }
        });
    }
    {
        let fs = Arc::clone(&fs);
        let stats = Arc::clone(&stats);
        thread::spawn(move || {
            for conn in tcp.incoming() {
                let Ok(mut conn) = conn else { continue };
                let _ = conn.set_nodelay(true);
                let fs = Arc::clone(&fs);
                let stats = Arc::clone(&stats);
                thread::spawn(move || {
                    while let Some(msg) = read_record(&mut conn) {
                        let Some(reply) = handle_message(&fs, &stats, &msg) else {
                            break;
                        };
                        if write_record(&mut conn, &reply).is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    FakeNfs2 {
        port,
        stats,
        root: FileHandle(MemFs::handle(ROOT).0.to_vec()),
    }
}
