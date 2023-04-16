use std::fmt::Display;
use std::string::ToString;

use color_eyre::{Help, Report};
use itertools::Itertools;
use libproc::libproc::proc_pid;
use netstat2::SocketInfo;

mod applications;
pub use applications::Config;

use crate::config;

fn root() -> bool {
    proc_pid::am_root()
}

#[derive(Debug)]
struct PortUser {
    name: String,
    #[allow(dead_code)]
    /// we use it as we use the Debug impl
    path: String,
}

impl Display for PortUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("- `{}`\n\t\tpath: {}", self.name, self.path))
    }
}

type ErrorString = String;
#[derive(Debug)]
struct Errors {
    resolving_name: Vec<(Pid, ErrorString)>,
    quering_socket: Vec<netstat2::error::Error>,
}

type Pid = i32;

fn port_users(port: u16) -> Result<(Vec<PortUser>, Errors), Report> {
    let (pids, mut errors) = port_pids(port)?;
    let (users, name_errs): (Vec<_>, Vec<_>) = pids
        .into_iter()
        .map(|pid| pid.try_into().unwrap())
        .map(|pid| {
            proc_pid::name(pid).map_err(|e| (pid, e)).and_then(|name| {
                proc_pid::pidpath(pid)
                    .map(|path| PortUser { name, path })
                    .map_err(|e| (pid, e))
            })
        })
        .partition_result();

    errors.resolving_name = name_errs;
    Ok((users, errors))
}

fn port_pids(port: u16) -> Result<(Vec<u32>, Errors), Report> {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

    let tcp_port = |sock: &SocketInfo| {
        let ProtocolSocketInfo::Tcp(ref info) = sock.protocol_socket_info else {
            panic!("should not get Upd info with protocol flags set to TCP only");
        };
        info.local_port
    };

    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP;

    let (socks, errs): (Vec<_>, Vec<_>) =
        netstat2::iterate_sockets_info(af_flags, proto_flags)?.partition_result();

    let pids = socks
        .into_iter()
        .filter(|sock| tcp_port(sock) == port)
        .flat_map(|sock| sock.associated_pids)
        .collect();

    Ok((
        pids,
        Errors {
            resolving_name: Vec::new(),
            quering_socket: errs,
        },
    ))
}

fn insufficent_permission(port: u16) -> bool {
    port <= 1024 && !root()
}

pub(crate) fn cant_bind_port(config: &config::Config, e: hyper::Error) -> Report {
    match build_report(&config.diagnostics, e, config.port) {
        Ok(r) => r,
        Err(r) => r.wrap_err("Could not deduce cause of error"),
    }
}

fn build_report<E>(config: &Config, e: E, port: u16) -> Result<Report, Report>
where
    E: std::error::Error + Sync + Send + 'static,
{
    let mut r = Report::new(e);
    if insufficent_permission(port) {
        r = r.wrap_err("insufficient permission to attach to port");
        r = r.with_suggestion(|| {
            "You normally need sudo to attach to ports below 1025"
        });
        r = r.with_note(|| format!("port: {port}"));
    }

    let (users, errs) = port_users(port)?;
    if !users.is_empty() || !errs.resolving_name.is_empty() {
        r = r.wrap_err("The port is already in use");

        if !users.is_empty() {
            let list = users.iter().map(ToString::to_string).join(",\n\t");
            r = r.with_note(|| format!("The port is being used by:\n\t{list}"));
            r = applications::improve_report(config, port, r, &users);
        }

        if !errs.resolving_name.is_empty() {
            r = r.with_warning(|| {
                format!("Could not resolve name for pids: {:?}", errs.resolving_name)
            });
        }

        if !errs.quering_socket.is_empty() {
            r = r.with_warning(|| {
                format!(
                    "Could not check all sockets: {:?}",
                    errs.quering_socket.is_empty()
                )
            });
        }
    }

    Ok(r)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn find_port_users() {
        let port_binder = TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_port = port_binder.local_addr().unwrap().port();

        let (users, errs) = port_users(bound_port).unwrap();

        assert!(errs.quering_socket.is_empty(), "{:?}", errs.quering_socket);
        assert!(errs.resolving_name.is_empty(), "{:?}", errs.resolving_name);
        assert_eq!(users.len(), 1, "{users:?}");
    }

    #[test]
    fn detect_insufficent_perm() {
        assert!(insufficent_permission(1024));
        assert!(!insufficent_permission(1025));
    }
}
