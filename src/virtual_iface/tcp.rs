use crate::config::{PortProtocol};
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};
use crate::wg::WireGuardTunnel;
use anyhow::Context;
use async_trait::async_trait;
use smoltcp::iface::InterfaceBuilder;
use smoltcp::socket::{TcpSocket, TcpSocketBuffer, TcpState};
use smoltcp::wire::{IpAddress, IpCidr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const MAX_PACKET: usize = 65536;

pub struct TcpVirtualInterface {
    port: u16,
    wg: Arc<WireGuardTunnel>,
    abort: Arc<AtomicBool>,
    sender_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    receiver_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    readiness_notifier: tokio::sync::oneshot::Sender<()>,
}

impl TcpVirtualInterface {
    pub fn new(
        port: u16,
        wg: Arc<WireGuardTunnel>,
        abort: Arc<AtomicBool>,
        sender_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        receiver_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        readiness_notifier: tokio::sync::oneshot::Sender<()>,
    ) -> Self {
        Self {
            port,
            wg,
            abort,
            sender_tx,
            receiver_rx,
            readiness_notifier,
        }
    }
}

#[async_trait]
impl VirtualInterfacePoll for TcpVirtualInterface {
    async fn poll_loop(self) -> anyhow::Result<()> {
        let mut readiness_notifier = Some(self.readiness_notifier);
        let mut receiver_rx = self.receiver_rx;
        let wg = self.wg.clone();

        let device = VirtualIpDevice::new_direct(VirtualPort(self.port, PortProtocol::Tcp), true, self.wg)
            .with_context(|| "Failed to create virtual IP device")?;

        let mut virtual_interface = InterfaceBuilder::new(device, vec![])
            .ip_addrs([
                IpCidr::new(IpAddress::from(wg.source_peer_ip), 32),
            ])
            .finalize();

        let client_socket: anyhow::Result<TcpSocket> = {
            let rx_data = vec![0u8; MAX_PACKET];
            let tx_data = vec![0u8; MAX_PACKET];
            let tcp_rx_buffer = TcpSocketBuffer::new(rx_data);
            let tcp_tx_buffer = TcpSocketBuffer::new(tx_data);
            let mut socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
            socket.listen(self.port)?;
            Ok(socket)
        };

        let client_handle = virtual_interface.add_socket(client_socket?);

        let mut tx_extra = Vec::new();
        let mut has_connected = false;

        loop {
            let loop_start = smoltcp::time::Instant::now();

            let shutdown = self.abort.load(Ordering::Relaxed);

            if shutdown {
                // Shutdown: sends a RST packet.
                trace!("[{}] Shutting down virtual interface", self.port);
                let client_socket = virtual_interface.get_socket::<TcpSocket>(client_handle);
                client_socket.abort();
            }

            match virtual_interface.poll(loop_start) {
                Ok(processed) if processed => {
                    trace!(
                        "[{}] Virtual interface polled some packets to be processed",
                        self.port
                    );
                }
                Err(e) => {
                    error!(
                        "[{}] Virtual interface poll error: {:?}",
                        self.port, e
                    );
                }
                _ => {}
            }


            {
                let (client_socket, _context) =
                    virtual_interface.get_socket_and_context::<TcpSocket>(client_handle);

                if !shutdown && client_socket.state() == TcpState::Closed && has_connected {
                    self.abort.store(true, Ordering::Relaxed);
                    continue;
                }

                if client_socket.state() == TcpState::Established {
                    has_connected = true;

                    if let Some(readiness_notifier) = readiness_notifier.take() {
                        debug!("sending READY");
                        readiness_notifier
                            .send(())
                            .expect("Failed to notify real client that virtual client is ready");
                    }

                }

                if client_socket.can_recv() {
                    match client_socket.recv(|buffer| (buffer.len(), buffer.to_vec())) {
                        Ok(data) => {
                            trace!(
                                "[{}] Virtual client received {} bytes of data",
                                self.port,
                                data.len()
                            );
                            // Send it to the real client
                            if let Err(e) = self.sender_tx.send(data).await {
                                error!("[{}] Failed to dispatch data from virtual client to real client: {:?}", self.port, e);
                            }
                        }
                        Err(e) => {
                            error!(
                                "[{}] Failed to read from virtual client socket: {:?}",
                                self.port, e
                            );
                        }
                    }
                }
                if client_socket.can_send() {
                    let mut to_transfer = None;

                    if tx_extra.is_empty() {
                        // The payload segment from the previous loop is complete,
                        // we can now read the next payload in the queue.
                        if let Ok(data) = receiver_rx.try_recv() {
                            to_transfer = Some(data);
                        } else if client_socket.state() == TcpState::CloseWait {
                            // No data to be sent in this loop. If the client state is CLOSE-WAIT (because of a server FIN),
                            // the interface is shutdown.
                            trace!("[{}] Shutting down virtual interface because client sent no more data, and server sent FIN (CLOSE-WAIT)", self.port);
                            self.abort.store(true, Ordering::Relaxed);
                            continue;
                        }
                    }

                    let to_transfer_slice = to_transfer.as_ref().unwrap_or(&tx_extra).as_slice();
                    if !to_transfer_slice.is_empty() {
                        let total = to_transfer_slice.len();
                        match client_socket.send_slice(to_transfer_slice) {
                            Ok(sent) => {
                                trace!(
                                    "[{}] Sent {}/{} bytes via virtual client socket",
                                    self.port,
                                    sent,
                                    total,
                                );
                                tx_extra = Vec::from(&to_transfer_slice[sent..total]);
                            }
                            Err(e) => {
                                error!(
                                    "[{}] Failed to send slice via virtual client socket: {:?}",
                                    self.port, e
                                );
                            }
                        }
                    }
                }
            }


            if shutdown {
                debug!("/////SHUTDOWN/////");
                break;
            }

            match virtual_interface.poll_delay(loop_start) {
                Some(smoltcp::time::Duration::ZERO) => {
                    continue;
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }

        }
        trace!("[{}] Virtual interface task terminated", self.port);
        self.abort.store(true, Ordering::Relaxed);

        Ok(())
    }
}
