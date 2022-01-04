use std::fmt::{Display, Formatter};
use std::fs::read_to_string;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use anyhow::Context;
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use clap::{App, Arg};

#[derive(Clone, Debug)]
pub struct Config {
    pub private_key: Arc<X25519SecretKey>,
    pub endpoint_public_key: Arc<X25519PublicKey>,
    pub endpoint_addr: SocketAddr,
    pub source_peer_ip: IpAddr,
    pub keepalive_seconds: Option<u16>,
    pub max_transmission_unit: usize,
    pub ports_to_forward: Vec<u16>,
}

impl Config {
    pub fn from(
        private_key: &str,
        endpoint_public_key: &str,
        endpoint_addr: &str,
        source_peer_ip: &str,
        keepalive_seconds: u16,
        max_transmission_unit: usize,
        ports_to_forward: Vec<u16>,
    ) -> anyhow::Result<Self> {
        let config = Config {
            private_key: Arc::new(parse_private_key(private_key)?),
            endpoint_public_key: Arc::new(parse_public_key(Some(endpoint_public_key))?),
            endpoint_addr: parse_addr(Some(endpoint_addr))?,
            source_peer_ip: parse_ip(Some(source_peer_ip))?,
            keepalive_seconds: Some(keepalive_seconds),
            max_transmission_unit: max_transmission_unit,
            ports_to_forward: ports_to_forward,
        };

        Ok(config)
    }

    pub fn from_args() -> anyhow::Result<Self> {
        let matches = App::new("p2p-port-forward")
            .version(env!("CARGO_PKG_VERSION"))
            .args(&[
                Arg::with_name("private-key")
                    .required_unless("private-key-file")
                    .takes_value(true)
                    .long("private-key")
                    .help("The private key of this peer. The corresponding public key should be registered in the WireGuard endpoint. \
                    You can also use '--private-key-file' to specify a file containing the key instead."),
                Arg::with_name("private-key-file")
                    .takes_value(true)
                    .long("private-key-file")
                    .help("The path to a file containing the private key of this peer. The corresponding public key should be registered in the WireGuard endpoint."),
                Arg::with_name("endpoint-public-key")
                    .required(true)
                    .takes_value(true)
                    .long("endpoint-public-key")
                    .help("The public key of the WireGuard endpoint (remote)."),
                Arg::with_name("endpoint-addr")
                    .required(true)
                    .takes_value(true)
                    .long("endpoint-addr")
                    .help("The address (IP + port) of the WireGuard endpoint (remote). Example: 1.2.3.4:51820"),
                Arg::with_name("source-peer-ip")
                    .required(true)
                    .takes_value(true)
                    .long("source-peer-ip")
                    .help("The source IP to identify this peer as (local). Example: 192.168.4.3"),
                Arg::with_name("keep-alive")
                    .required(false)
                    .takes_value(true)
                    .long("keep-alive")
                    .help("Configures a persistent keep-alive for the WireGuard tunnel, in seconds."),
                Arg::with_name("max-transmission-unit")
                    .required(false)
                    .takes_value(true)
                    .long("max-transmission-unit")
                    .default_value("1420")
                    .help("Configures the max-transmission-unit (MTU) of the WireGuard tunnel."),
                Arg::with_name("ports-to-forward")
                    .required(true)
                    .multiple(true)
                    .takes_value(true)
                    .long("ports-to-forward")
                    .help("Configures the ports to forward. Example: --ports-to-forward 22,80,443"),
            ]).get_matches();

        let private_key = if let Some(private_key_file) = matches.value_of("private-key-file") {
            read_to_string(private_key_file)
                .map(|s| s.trim().to_string())
                .with_context(|| "Failed to read private key file")
        } else {
            matches
                .value_of("private-key")
                .map(String::from)
                .with_context(|| "Missing private key")
        }?;

        Ok(Self {
            private_key: Arc::new(
                parse_private_key(&private_key).with_context(|| "Invalid private key")?,
            ),
            endpoint_public_key: Arc::new(
                parse_public_key(matches.value_of("endpoint-public-key"))
                    .with_context(|| "Invalid endpoint public key")?,
            ),
            endpoint_addr: parse_addr(matches.value_of("endpoint-addr"))
                .with_context(|| "Invalid endpoint address")?,
            source_peer_ip: parse_ip(matches.value_of("source-peer-ip"))
                .with_context(|| "Invalid source peer IP")?,
            keepalive_seconds: parse_keep_alive(matches.value_of("keep-alive"))
                .with_context(|| "Invalid keep-alive value")?,
            max_transmission_unit: parse_mtu(matches.value_of("max-transmission-unit"))
                .with_context(|| "Invalid max-transmission-unit value")?,
            ports_to_forward: matches
                .values_of("ports-to-forward")
                .unwrap()
                .map(|s| s.parse::<u16>().unwrap())
                .collect(),
        })
    }

    }

fn parse_addr(s: Option<&str>) -> anyhow::Result<SocketAddr> {
    s.with_context(|| "Missing address")?
        .to_socket_addrs()
        .with_context(|| "Invalid address")?
        .next()
        .with_context(|| "Could not lookup address")
}

fn parse_ip(s: Option<&str>) -> anyhow::Result<IpAddr> {
    s.with_context(|| "Missing IP")?
        .parse::<IpAddr>()
        .with_context(|| "Invalid IP address")
}

fn parse_private_key(s: &str) -> anyhow::Result<X25519SecretKey> {
    s.parse::<X25519SecretKey>()
        .map_err(|e| anyhow::anyhow!("{}", e))
}

fn parse_public_key(s: Option<&str>) -> anyhow::Result<X25519PublicKey> {
    s.with_context(|| "Missing public key")?
        .parse::<X25519PublicKey>()
        .map_err(|e| anyhow::anyhow!("{}", e))
        .with_context(|| "Invalid public key")
}

fn parse_keep_alive(s: Option<&str>) -> anyhow::Result<Option<u16>> {
    if let Some(s) = s {
        let parsed: u16 = s.parse().with_context(|| {
            format!(
                "Keep-alive must be a number between 0 and {} seconds",
                u16::MAX
            )
        })?;
        Ok(Some(parsed))
    } else {
        Ok(None)
    }
}

fn parse_mtu(s: Option<&str>) -> anyhow::Result<usize> {
    s.with_context(|| "Missing MTU")?
        .parse()
        .with_context(|| "Invalid MTU")
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PortProtocol {
    Tcp,
    Icmp,
}

impl Display for PortProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Tcp => "TCP",
                Self::Icmp => "Icmp",
            }
        )
    }
}
