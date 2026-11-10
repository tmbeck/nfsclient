//! Version-agnostic filesystem facade.
//!
//! PUBLIC API CONTRACT: the NFSv2, v3 and v4 backends implement [`Filesystem`];
//! the shell and other consumers only use this trait. Do not change existing
//! signatures without coordinating; adding new provided methods is fine.

use std::fmt;
use std::net::IpAddr;

use crate::error::Result;
use crate::rpc::RpcOptions;

/// Opaque server file handle (v2: 32 bytes, v3: <=64, v4: <=128).
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct FileHandle(pub Vec<u8>);

impl fmt::Debug for FileHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileHandle(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NfsVersion {
    V2,
    V3,
    /// NFSv4 with the given minor version (0, 1, 2).
    V4(u32),
}

impl fmt::Display for NfsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NfsVersion::V2 => write!(f, "NFSv2"),
            NfsVersion::V3 => write!(f, "NFSv3"),
            NfsVersion::V4(m) => write!(f, "NFSv4.{m}"),
        }
    }
}

/// Which version(s) to try when connecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VersionPref {
    /// Try v4 (highest minor first), then v3, then v2.
    #[default]
    Auto,
    Exact(NfsVersion),
    /// Any v4 minor version (highest supported first).
    AnyV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Socket,
    Fifo,
    /// v4 named-attribute types and anything unknown.
    Other(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Time {
    pub seconds: i64,
    pub nseconds: u32,
}

/// File attributes, normalized across versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    pub ftype: FileType,
    /// Permission bits incl. setuid/setgid/sticky (low 12 bits); no type bits.
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// v4 owner / owner_group strings ("user@domain" or numeric). None for v2/v3.
    pub owner: Option<String>,
    pub group: Option<String>,
    pub size: u64,
    /// Bytes of storage used (v2: blocks * blocksize).
    pub used: u64,
    /// (major, minor) for device files.
    pub rdev: (u32, u32),
    pub fsid: u64,
    pub fileid: u64,
    pub atime: Time,
    pub mtime: Time,
    pub ctime: Time,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Raw name bytes (not necessarily UTF-8). "." and ".." are filtered out.
    pub name: Vec<u8>,
    pub fileid: u64,
    /// Present when the backend got attributes cheaply (READDIRPLUS / v4 READDIR).
    pub attr: Option<Attr>,
    pub handle: Option<FileHandle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsStat {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub avail_bytes: u64,
    pub total_files: u64,
    pub free_files: u64,
    pub avail_files: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTime {
    ServerNow,
    Client(Time),
}

/// Attributes to change; `None` leaves a field untouched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// v4 only: owner / group strings take precedence over uid/gid when set.
    pub owner: Option<String>,
    pub group: Option<String>,
    pub size: Option<u64>,
    pub atime: Option<SetTime>,
    pub mtime: Option<SetTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateMode {
    /// Create or truncate-if-exists semantics are NOT implied; succeeds if the file exists
    /// (v3 UNCHECKED). The `SetAttr` passed to create is applied.
    Unchecked,
    /// Fail with Status::Exist if the name exists (v3 GUARDED).
    Guarded,
    /// Exclusive create (v3 EXCLUSIVE / v4 EXCLUSIVE4_1).
    Exclusive,
}

/// Normalized NFS status codes (numbering follows nfsstat3, which v2 and v4 share
/// for the common values). Version-specific errors go in `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    Perm,         // 1
    NoEnt,        // 2
    Io,           // 5
    Nxio,         // 6
    Access,       // 13
    Exist,        // 17
    XDev,         // 18
    NoDev,        // 19
    NotDir,       // 20
    IsDir,        // 21
    Inval,        // 22
    FBig,         // 27
    NoSpc,        // 28
    Rofs,         // 30
    MLink,        // 31
    NameTooLong,  // 63
    NotEmpty,     // 66
    DQuot,        // 69
    Stale,        // 70
    Remote,       // 71
    BadHandle,    // 10001
    NotSync,      // 10002
    BadCookie,    // 10003
    NotSupp,      // 10004
    TooSmall,     // 10005
    ServerFault,  // 10006
    BadType,      // 10007
    Jukebox,      // 10008 (v4: NFS4ERR_DELAY)
    /// Any other code; the version tells you how to interpret it.
    Other(NfsVersion, u32),
}

impl Status {
    /// Map an nfsstat2/nfsstat3 (or mountstat3) value. 0 (OK) must not be passed.
    pub fn from_v3(code: u32) -> Self {
        Self::common(code).unwrap_or(match code {
            10001 => Status::BadHandle,
            10002 => Status::NotSync,
            10003 => Status::BadCookie,
            10004 => Status::NotSupp,
            10005 => Status::TooSmall,
            10006 => Status::ServerFault,
            10007 => Status::BadType,
            10008 => Status::Jukebox,
            c => Status::Other(NfsVersion::V3, c),
        })
    }

    /// Map an nfsstat4 value. 0 (NFS4_OK) must not be passed.
    pub fn from_v4(code: u32, minor: u32) -> Self {
        Self::common(code).unwrap_or(match code {
            10001 => Status::BadHandle,
            10003 => Status::BadCookie,
            10004 => Status::NotSupp,
            10005 => Status::TooSmall,
            10006 => Status::ServerFault,
            10007 => Status::BadType,
            10008 => Status::Jukebox,
            c => Status::Other(NfsVersion::V4(minor), c),
        })
    }

    fn common(code: u32) -> Option<Self> {
        Some(match code {
            1 => Status::Perm,
            2 => Status::NoEnt,
            5 => Status::Io,
            6 => Status::Nxio,
            13 => Status::Access,
            17 => Status::Exist,
            18 => Status::XDev,
            19 => Status::NoDev,
            20 => Status::NotDir,
            21 => Status::IsDir,
            22 => Status::Inval,
            27 => Status::FBig,
            28 => Status::NoSpc,
            30 => Status::Rofs,
            31 => Status::MLink,
            63 => Status::NameTooLong,
            66 => Status::NotEmpty,
            69 => Status::DQuot,
            70 => Status::Stale,
            71 => Status::Remote,
            _ => return None,
        })
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Status::Perm => "operation not permitted",
            Status::NoEnt => "no such file or directory",
            Status::Io => "I/O error",
            Status::Nxio => "no such device or address",
            Status::Access => "permission denied",
            Status::Exist => "file exists",
            Status::XDev => "cross-device link",
            Status::NoDev => "no such device",
            Status::NotDir => "not a directory",
            Status::IsDir => "is a directory",
            Status::Inval => "invalid argument",
            Status::FBig => "file too large",
            Status::NoSpc => "no space left on device",
            Status::Rofs => "read-only file system",
            Status::MLink => "too many links",
            Status::NameTooLong => "file name too long",
            Status::NotEmpty => "directory not empty",
            Status::DQuot => "disk quota exceeded",
            Status::Stale => "stale file handle",
            Status::Remote => "too many levels of remote in path",
            Status::BadHandle => "illegal file handle",
            Status::NotSync => "update synchronization mismatch",
            Status::BadCookie => "stale READDIR cookie",
            Status::NotSupp => "operation not supported",
            Status::TooSmall => "buffer or request too small",
            Status::ServerFault => "server fault",
            Status::BadType => "type not supported by server",
            Status::Jukebox => "server busy, try again later",
            Status::Other(v, c) => return write!(f, "{v} error {c}"),
        };
        f.write_str(s)
    }
}

/// The operations every NFS version backend provides. Methods take `&mut self`
/// because a backend owns a single RPC connection.
pub trait Filesystem {
    fn version(&self) -> NfsVersion;

    /// Handle of the export root this backend was connected to.
    fn root(&self) -> FileHandle;

    /// Preferred maximum READ / WRITE transfer sizes in bytes.
    fn max_read(&self) -> u32;
    fn max_write(&self) -> u32;

    fn getattr(&mut self, fh: &FileHandle) -> Result<Attr>;
    fn setattr(&mut self, fh: &FileHandle, attrs: &SetAttr) -> Result<Attr>;

    /// Look up one name (never contains '/'). ".." must work (v4: LOOKUPP).
    fn lookup(&mut self, dir: &FileHandle, name: &[u8]) -> Result<(FileHandle, Attr)>;

    /// The complete directory listing, without "." and "..". The backend handles
    /// cookies/verifiers and pagination.
    fn readdir(&mut self, dir: &FileHandle) -> Result<Vec<DirEntry>>;

    fn readlink(&mut self, fh: &FileHandle) -> Result<Vec<u8>>;

    /// Read up to `count` bytes; returns (data, eof).
    fn read(&mut self, fh: &FileHandle, offset: u64, count: u32) -> Result<(Vec<u8>, bool)>;

    /// Write `data` at `offset`; returns bytes written (may be short). Data must
    /// be durable on return (FILE_SYNC, or UNSTABLE followed by `commit`).
    fn write(&mut self, fh: &FileHandle, offset: u64, data: &[u8]) -> Result<u32>;

    fn create(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        mode: CreateMode,
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)>;
    fn mkdir(&mut self, dir: &FileHandle, name: &[u8], attrs: &SetAttr) -> Result<(FileHandle, Attr)>;
    fn symlink(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        target: &[u8],
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)>;
    /// Hard link `target` into `dir` as `name`.
    fn link(&mut self, target: &FileHandle, dir: &FileHandle, name: &[u8]) -> Result<()>;
    fn remove(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()>;
    fn rmdir(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()>;
    fn rename(
        &mut self,
        from_dir: &FileHandle,
        from_name: &[u8],
        to_dir: &FileHandle,
        to_name: &[u8],
    ) -> Result<()>;

    fn fsstat(&mut self, fh: &FileHandle) -> Result<FsStat>;

    /// Release server state (UMNT, CLOSE/DESTROY_SESSION, ...). Best effort.
    fn disconnect(&mut self) -> Result<()>;
}

/// Options for connecting a backend.
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    pub rpc: RpcOptions,
    /// Override the NFS port (skips portmap for NFS; v4 defaults to 2049 without portmap).
    pub nfs_port: Option<u16>,
    /// Override the MOUNT port (v2/v3).
    pub mount_port: Option<u16>,
    pub version: VersionPref,
}

/// Result of connecting: the backend plus where in it the requested path lands.
pub struct Connected {
    pub fs: Box<dyn Filesystem>,
    /// The export (v2/v3) or pseudo-fs path (v4) that `fs.root()` corresponds to.
    pub export: Vec<u8>,
    /// Remaining path components below the export root (already split on '/').
    pub remainder: Vec<Vec<u8>>,
}

/// Connect to `path` on `host` honoring `opts.version`. With `Auto`, tries v4
/// (4.2, 4.1, 4.0), then v3, then v2, returning the first that succeeds; if all
/// fail, returns the error from the highest version attempted unless a lower one
/// failed for a more specific reason than "not supported".
pub fn connect(host: IpAddr, path: &[u8], opts: &ConnectOptions) -> Result<Connected> {
    crate::client::connect(host, path, opts)
}
