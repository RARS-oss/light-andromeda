//! A tiny Unix-socket control plane for hot-reloading the fabric map.
//!
//! The forwarding loop keeps running; a client (or an operator via `socat`/`nc -U`)
//! sends a one-line command to the socket and the fabric is swapped atomically
//! underneath the data path via [`arc_swap`] — no packet loss, no restart. Unix-only.
//!
//! ```text
//! $ echo "reload /etc/andromeda/node1.toml" | nc -U /run/andromeda.sock
//! ok reloaded: 2 vpc(s), 5 endpoint(s)
//! ```

use andromeda_control::{Fabric, NodeConfig};
use arc_swap::ArcSwap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// Shared handle to a pipeline's hot-swappable fabric — from
/// [`crate::Pipeline::fabric_handle`]. Cloneable; the control thread and the data path
/// hold clones of the same `ArcSwap`.
pub type FabricHandle = Arc<ArcSwap<Fabric>>;

/// Apply one control command against `fabric`, returning the reply line.
///
/// * `reload <config.toml>` — load and validate the config, then swap in its fabric.
/// * `ping` — liveness check.
///
/// Invalid input never panics; it returns an `err …` line.
#[must_use]
pub fn apply_command(line: &str, fabric: &FabricHandle) -> String {
    let mut parts = line.trim().splitn(2, char::is_whitespace);
    match (parts.next(), parts.next().map(str::trim)) {
        (Some("reload"), Some(path)) if !path.is_empty() => {
            match NodeConfig::load(Path::new(path)) {
                Ok(nc) => {
                    let vnis = nc.served_vnis().len();
                    let eps = nc.endpoints.len();
                    // Atomic swap: in-flight packets finish against the old fabric, the
                    // next reads see the new one.
                    fabric.store(Arc::new(nc.build_fabric()));
                    format!("ok reloaded: {vnis} vpc(s), {eps} endpoint(s)")
                }
                Err(e) => format!("err {e}"),
            }
        }
        (Some("ping"), _) => "ok pong".to_string(),
        _ => "err usage: `reload <config.toml>` | `ping`".to_string(),
    }
}

/// Handle a single control connection: read one command line, act, reply one line.
fn handle_conn(stream: UnixStream, fabric: &FabricHandle) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let reply = apply_command(&line, fabric);
    if let Ok(mut stream) = reader.into_inner().try_clone() {
        let _ = writeln!(stream, "{reply}");
    }
}

/// Bind a Unix socket at `path` and serve control commands on a background thread,
/// mutating the fabric a running pipeline reads. Returns the listener thread handle.
///
/// # Errors
/// Returns the bind error if the socket path cannot be created.
pub fn serve(path: impl AsRef<Path>, fabric: FabricHandle) -> std::io::Result<JoinHandle<()>> {
    let path: PathBuf = path.as_ref().to_path_buf();
    // A stale socket file from a previous run would make bind() fail with EADDRINUSE.
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    // Owner-only (0600), independent of umask: connecting to a filesystem Unix socket
    // requires write access to its inode, so this restricts the fabric-reload channel to
    // the same uid (and root). The `reload` command can redirect every tenant's traffic,
    // so this access control is load-bearing, not cosmetic.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => handle_conn(s, &fabric),
                Err(_) => break,
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::Ipv4Addr;

    fn handle() -> FabricHandle {
        Arc::new(ArcSwap::from_pointee(Fabric::new(
            "192.168.1.1".parse().unwrap(),
        )))
    }

    fn write_temp_config(name: &str, body: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("{}-{}", std::process::id(), name));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn reload_command_swaps_fabric() {
        let h = handle();
        assert!(h
            .load()
            .resolve(100, "10.0.0.20".parse().unwrap())
            .is_none());

        let cfg = write_temp_config(
            "ctl-a.toml",
            "local_node = \"192.168.1.1\"\nvni = 100\nvpc_cidr = \"10.0.0.0/24\"\n\n[[endpoint]]\ninner_ip = \"10.0.0.20\"\ninner_mac = \"02:00:00:00:00:20\"\nnode_ip = \"192.168.1.2\"\n",
        );
        let reply = apply_command(&format!("reload {}", cfg.display()), &h);
        assert!(reply.starts_with("ok"), "reply was: {reply}");

        // The running data path (which holds only the handle) now sees the new endpoint.
        let nh = h.load().resolve(100, "10.0.0.20".parse().unwrap()).unwrap();
        assert_eq!(nh.node_ip, "192.168.1.2".parse::<Ipv4Addr>().unwrap());
        let _ = std::fs::remove_file(&cfg);
    }

    #[test]
    fn bad_command_and_bad_path_report_errors_without_panic() {
        let h = handle();
        assert!(apply_command("wat", &h).starts_with("err"));
        assert!(apply_command("reload", &h).starts_with("err"));
        assert!(apply_command("reload /no/such/file.toml", &h).starts_with("err"));
        assert_eq!(apply_command("ping", &h), "ok pong");
    }

    #[test]
    fn end_to_end_over_the_socket() {
        let h = handle();
        let cfg = write_temp_config("ctl-b.toml", "local_node = \"192.168.1.1\"\nvni = 7\n");
        let mut sock = std::env::temp_dir();
        sock.push(format!("andromeda-ctl-{}.sock", std::process::id()));
        let _guard = serve(&sock, Arc::clone(&h)).unwrap();

        let mut stream = UnixStream::connect(&sock).unwrap();
        writeln!(stream, "reload {}", cfg.display()).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("ok"), "reply was: {reply}");

        let _ = std::fs::remove_file(&cfg);
        let _ = std::fs::remove_file(&sock);
    }
}
