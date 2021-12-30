use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::Context;
use boringtun::noise::{Tunn, TunnResult};
use log::Level;
use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::config::{Config, PortProtocol};
use crate::virtual_iface::VirtualPort;

/// The capacity of the channel for received IP packets.
pub const DISPATCH_CAPACITY: usize = 1_000;
const MAX_PACKET: usize = 65536;

/// A WireGuard tunnel. Encapsulates and decapsulates IP packets
/// to be sent to and received from a remote UDP endpoint.
/// This tunnel supports at most 1 peer IP at a time, but supports simultaneous ports.
pub struct WireGuardTunnel {
    pub(crate) source_peer_ip: IpAddr,
    /// `boringtun` peer/tunnel implementation, used for crypto & WG protocol.
    peer: Box<Tunn>,
    /// The UDP socket for the public WireGuard endpoint to connect to.
    udp: UdpSocket,
    /// The address of the public WireGuard endpoint (UDP).
    pub(crate) endpoint: SocketAddr,
    /// Maps virtual ports to the corresponding IP packet dispatcher.
    virtual_port_ip_tx: dashmap::DashMap<VirtualPort, tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// IP packet dispatcher for unroutable packets. `None` if not initialized.
    sink_ip_tx: RwLock<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>,
    /// The max transmission unit for WireGuard.
    pub(crate) max_transmission_unit: usize,
}

impl WireGuardTunnel {
    /// Initialize a new WireGuard tunnel.
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        let source_peer_ip = config.source_peer_ip;
        let peer = Self::create_tunnel(config)?;
        let endpoint = config.endpoint_addr;
        let udp = UdpSocket::bind(match endpoint {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        })
        .await
        .with_context(|| "Failed to create UDP socket for WireGuard connection")?;
        let virtual_port_ip_tx = Default::default();

        Ok(Self {
            source_peer_ip,
            peer,
            udp,
            endpoint,
            virtual_port_ip_tx,
            sink_ip_tx: RwLock::new(None),
            max_transmission_unit: config.max_transmission_unit,
        })
    }

    /// Encapsulates and sends an IP packet through to the WireGuard endpoint.
    pub async fn send_ip_packet(&self, packet: &[u8]) -> anyhow::Result<()> {
        trace_ip_packet("Sending IP packet", packet);
        let mut send_buf = [0u8; MAX_PACKET];
        match self.peer.encapsulate(packet, &mut send_buf) {
            TunnResult::WriteToNetwork(packet) => {
                self.udp
                    .send_to(packet, self.endpoint)
                    .await
                    .with_context(|| "Failed to send encrypted IP packet to WireGuard endpoint.")?;
                debug!(
                    "Sent {} bytes to WireGuard endpoint (encrypted IP packet)",
                    packet.len()
                );
            }
            TunnResult::Err(e) => {
                error!("Failed to encapsulate IP packet: {:?}", e);
            }
            TunnResult::Done => {
                // Ignored
            }
            other => {
                error!(
                    "Unexpected WireGuard state during encapsulation: {:?}",
                    other
                );
            }
        };
        Ok(())
    }

    /// Register a virtual interface (using its assigned virtual port) with the given IP packet `Sender`.
    pub fn register_virtual_interface(
        &self,
        virtual_port: VirtualPort,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> anyhow::Result<()> {
        self.virtual_port_ip_tx.insert(virtual_port, sender);
        Ok(())
    }

    /// Register a virtual interface (using its assigned virtual port) with the given IP packet `Sender`.
    pub async fn register_sink_interface(
        &self,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<Vec<u8>>> {
        let (sender, receiver) = tokio::sync::mpsc::channel(DISPATCH_CAPACITY);

        let mut sink_ip_tx = self.sink_ip_tx.write().await;
        *sink_ip_tx = Some(sender);

        Ok(receiver)
    }

    /// Releases the virtual interface from IP dispatch.
    pub fn release_virtual_interface(&self, virtual_port: VirtualPort) {
        self.virtual_port_ip_tx.remove(&virtual_port);
    }

    /// WireGuard Routine task. Handles Handshake, keep-alive, etc.
    pub async fn routine_task(&self) -> anyhow::Result<()> {
        let mut send_buf = [0u8; MAX_PACKET];
        match self.peer.update_timers(&mut send_buf) {
            TunnResult::WriteToNetwork(packet) => {
                debug!(
                    "Sending routine packet of {} bytes to WireGuard endpoint",
                    packet.len()
                );
                self.udp
                    .send_to(packet, self.endpoint)
                    .await
                    .with_context(|| "Failed to send routine packet to WireGuard endpoint.")
                    .and_then(|_| Ok(()))
            }
            TunnResult::Err(e) => {
                // todo: recover from this
                error!(
                    "Failed to prepare routine packet for WireGuard endpoint: {:?}",
                    e
                );
                Err(anyhow::anyhow!(
                    "Failed to prepare routine packet for WireGuard endpoint: {:?}",
                    e
                ))
            }
            TunnResult::Done => {
                // Sleep for a bit
                tokio::time::sleep(Duration::from_millis(1)).await;
                Ok(())
            }
            other => {
                warn!("Unexpected WireGuard routine task state: {:?}", other);
                Ok(())
            }
        }
    }

    /// WireGuard consumption task. Receives encrypted packets from the WireGuard endpoint,
    /// decapsulates them, and dispatches newly received IP packets.
    pub async fn consume_task(&self) -> ! {
        trace!("Starting WireGuard consumption task");

        loop {
            let mut recv_buf = [0u8; MAX_PACKET];
            let mut send_buf = [0u8; MAX_PACKET];

            let size = match self.udp.recv(&mut recv_buf).await {
                Ok(size) => size,
                Err(e) => {
                    error!("Failed to read from WireGuard endpoint: {:?}", e);
                    // Sleep a little bit and try again
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
            };

            let data = &recv_buf[..size];
            match self.peer.decapsulate(None, data, &mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    match self.udp.send_to(packet, self.endpoint).await {
                        Ok(_) => {}
                        Err(e) => {
                            error!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                            continue;
                        }
                    };
                    loop {
                        let mut send_buf = [0u8; MAX_PACKET];
                        match self.peer.decapsulate(None, &[], &mut send_buf) {
                            TunnResult::WriteToNetwork(packet) => {
                                match self.udp.send_to(packet, self.endpoint).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        error!("Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}", e);
                                        break;
                                    }
                                };
                            }
                            _ => {
                                break;
                            }
                        }
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    debug!(
                        "WireGuard endpoint sent IP packet of {} bytes",
                        packet.len()
                    );

                    // For debugging purposes: parse packet
                    trace_ip_packet("Received IP packet", packet);

                    match self.route_ip_packet(packet) {
                        RouteResult::Dispatch(port) => {
                            let sender = self.virtual_port_ip_tx.get(&port);
                            if let Some(sender_guard) = sender {
                                let sender = sender_guard.value();
                                match sender.send(packet.to_vec()).await {
                                    Ok(_) => {
                                        trace!(
                                            "Dispatched received IP packet to virtual port {}",
                                            port
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to dispatch received IP packet to virtual port {}: {}",
                                            port, e
                                        );
                                    }
                                }
                            } else {
                                warn!("[{}] Race condition: failed to get virtual port sender after it was dispatched", port);
                            }
                        }
                        RouteResult::Sink => {
                            trace!("Sending unroutable IP packet received from WireGuard endpoint to sink interface");
                            self.route_ip_sink(packet).await.unwrap_or_else(|e| {
                                error!("Failed to send unroutable IP packet to sink: {:?}", e)
                            });
                        }
                        RouteResult::Drop => {
                            trace!("Dropped unroutable IP packet received from WireGuard endpoint");
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn create_tunnel(config: &Config) -> anyhow::Result<Box<Tunn>> {
        Tunn::new(
            config.private_key.clone(),
            config.endpoint_public_key.clone(),
            None,
            config.keepalive_seconds,
            0,
            None,
        )
        .map_err(|s| anyhow::anyhow!("{}", s))
        .with_context(|| "Failed to initialize boringtun Tunn")
    }

    /// Makes a decision on the handling of an incoming IP packet.
    fn route_ip_packet(&self, packet: &[u8]) -> RouteResult {
        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => {
                Ipv4Packet::new_checked(&packet)
                    .ok()
                    // Only care if the packet is destined for this tunnel
                    .filter(|packet| Ipv4Addr::from(packet.dst_addr()) == self.source_peer_ip)
                    .map(|packet| match packet.protocol() {
                        IpProtocol::Tcp => Some(self.route_tcp_segment(packet.payload())),
                        // Unrecognized protocol, so we cannot determine where to route
                        _ => Some(RouteResult::Drop),
                    })
                    .flatten()
                    .unwrap_or(RouteResult::Drop)
            }
            Ok(IpVersion::Ipv6) => {
                Ipv6Packet::new_checked(&packet)
                    .ok()
                    // Only care if the packet is destined for this tunnel
                    .filter(|packet| Ipv6Addr::from(packet.dst_addr()) == self.source_peer_ip)
                    .map(|packet| match packet.next_header() {
                        IpProtocol::Tcp => Some(self.route_tcp_segment(packet.payload())),
                        // Unrecognized protocol, so we cannot determine where to route
                        _ => Some(RouteResult::Drop),
                    })
                    .flatten()
                    .unwrap_or(RouteResult::Drop)
            }
            _ => RouteResult::Drop,
        }
    }

    /// Makes a decision on the handling of an incoming TCP segment.
    fn route_tcp_segment(&self, segment: &[u8]) -> RouteResult {
        debug!(
            "route_tcp_segment called with segment of {} bytes",
            segment.len()
        );

        TcpPacket::new_checked(segment)
            .ok()
            .map(|tcp| {
                if self
                    .virtual_port_ip_tx
                    .get(&VirtualPort(tcp.dst_port(), PortProtocol::Tcp))
                    .is_some()
                {
                    RouteResult::Dispatch(VirtualPort(tcp.dst_port(), PortProtocol::Tcp))
                } else if tcp.rst() {
                    RouteResult::Drop
                } else {
                    RouteResult::Sink
                }
            })
            .unwrap_or(RouteResult::Drop)
    }

    /// Route a packet to the IP sink interface.
    async fn route_ip_sink(&self, packet: &[u8]) -> anyhow::Result<()> {
        let ip_sink_tx = self.sink_ip_tx.read().await;

        if let Some(ip_sink_tx) = &*ip_sink_tx {
            ip_sink_tx
                .send(packet.to_vec())
                .await
                .with_context(|| "Failed to dispatch IP packet to sink interface")
        } else {
            warn!(
                "Could not dispatch unroutable IP packet to sink because interface is not active."
            );
            Ok(())
        }
    }
}

fn trace_ip_packet(message: &str, packet: &[u8]) {
    if log_enabled!(Level::Trace) {
        use smoltcp::wire::*;

        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
            ),
            Ok(IpVersion::Ipv6) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
            ),
            _ => {}
        }
    }
}

enum RouteResult {
    /// Dispatch the packet to the virtual port.
    Dispatch(VirtualPort),
    /// The packet is not routable, and should be sent to the sink interface.
    Sink,
    /// The packet is not routable, and can be safely ignored.
    Drop,
}
