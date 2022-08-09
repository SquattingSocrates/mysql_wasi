// Copyright (c) 2020 rust-mysql-simple contributors
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use bufstream::BufStream;
use io_enum::*;

use lunatic::net;
use std::{fmt, io, net::SocketAddr, time::Duration};

use crate::error::{
    DriverError::{ConnectTimeout, CouldNotConnect},
    Error::DriverError,
    Result as MyResult,
};

mod tcp;
mod tls;

#[derive(Debug, Read, Write)]
pub enum Stream {
    TcpStream(TcpStreamWrapper),
}

impl Stream {
    pub fn connect_tcp(
        ip_or_hostname: &str,
        port: u16,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_keepalive_time: Option<u32>,
        tcp_connect_timeout: Option<Duration>,
        bind_address: Option<SocketAddr>,
    ) -> MyResult<Stream> {
        let mut builder = tcp::MyTcpBuilder::new(format!("{}:{}", ip_or_hostname, port));
        builder
            .connect_timeout(tcp_connect_timeout)
            .read_timeout(read_timeout)
            .write_timeout(write_timeout)
            .keepalive_time_ms(tcp_keepalive_time)
            // .nodelay(nodelay)
            .bind_address(bind_address);
        builder
            .connect()
            .map(|stream| Stream::TcpStream(TcpStreamWrapper::Insecure(BufStream::new(stream))))
            .map_err(|err| {
                if err.kind() == io::ErrorKind::TimedOut {
                    DriverError(ConnectTimeout)
                } else {
                    let addr = format!("{}:{}", ip_or_hostname, port);
                    let desc = format!("{}", err);
                    DriverError(CouldNotConnect(Some((addr, desc, err.kind()))))
                }
            })
    }

    pub fn is_insecure(&self) -> bool {
        match self {
            Stream::TcpStream(TcpStreamWrapper::Insecure(_)) => true,
            _ => false,
        }
    }

    pub fn is_socket(&self) -> bool {
        false
    }

    #[cfg(all(not(feature = "native-tls"), not(feature = "rustls")))]
    pub fn make_secure(self, _host: url::Host, _ssl_opts: crate::SslOpts) -> MyResult<Stream> {
        panic!(
            "Client had asked for TLS connection but TLS support is disabled. \
            Please enable one of the following features: [\"native-tls\", \"rustls\"]"
        )
    }
}

#[derive(Read, Write)]
pub enum TcpStreamWrapper {
    Insecure(BufStream<net::TcpStream>),
}

impl fmt::Debug for TcpStreamWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TcpStreamWrapper::Insecure(ref s) => write!(f, "Insecure stream {:?}", s),
        }
    }
}
