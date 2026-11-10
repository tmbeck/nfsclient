//! Compile-only check of the library example in README.md. Nothing here
//! connects to a server; the function is never called.

use std::net::IpAddr;

use nfsc::fs::{self, ConnectOptions};

fn _list_export() -> nfsc::Result<()> {
    let host: IpAddr = "192.0.2.10".parse().expect("literal address");
    let mut conn = fs::connect(host, b"/srv/data", &ConnectOptions::default())?;

    // `conn.remainder` holds the path components below the export root.
    let mut dir = conn.fs.root();
    for part in &conn.remainder {
        dir = conn.fs.lookup(&dir, part)?.0;
    }
    for entry in conn.fs.readdir(&dir)? {
        println!("{}", String::from_utf8_lossy(&entry.name));
    }
    conn.fs.disconnect()
}

#[test]
fn readme_example_compiles() {
    // The example is type-checked above; calling it would need a live server.
    let _: fn() -> nfsc::Result<()> = _list_export;
}
