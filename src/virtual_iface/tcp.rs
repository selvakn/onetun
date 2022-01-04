use crate::config::PortProtocol;
use crate::virtual_device::VirtualIpDevice;
use crate::virtual_iface::{VirtualInterfacePoll, VirtualPort};
use crate::wg::WireGuardTunnel;
use anyhow::Context;
use async_trait::async_trait;
use smoltcp::iface::{InterfaceBuilder, SocketHandle};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer, TcpState};
use smoltcp::wire::{IpAddress, IpCidr};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const MAX_PACKET: usize = 65536;

pub struct TcpVirtualInterface {
    port: u16,
    wg: Arc<WireGuardTunnel>,
    sender_tx: tokio::sync::mpsc::Sender<(Uuid, Vec<u8>)>,
    receiver_rx: tokio::sync::mpsc::Receiver<(Uuid, Vec<u8>)>,
    readiness_notifier: tokio::sync::oneshot::Sender<Uuid>,
}

impl TcpVirtualInterface {
    pub fn new(
        port: u16,
        wg: Arc<WireGuardTunnel>,
        sender_tx: tokio::sync::mpsc::Sender<(Uuid, Vec<u8>)>,
        receiver_rx: tokio::sync::mpsc::Receiver<(Uuid, Vec<u8>)>,
        readiness_notifier: tokio::sync::oneshot::Sender<Uuid>,
    ) -> Self {
        Self {
            port,
            wg,
            sender_tx,
            receiver_rx,
            readiness_notifier,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SocketListenerHandle {
    identifier: Uuid,
    socket_handle: SocketHandle,
    connected: bool,
}

impl SocketListenerHandle {
    pub fn mark_as_connected(&mut self) {
        self.connected = true;
    }

    pub fn new(handle: SocketHandle) -> SocketListenerHandle {
        Self {
            identifier: Uuid::new_v4(),
            socket_handle: handle,
            connected: false,
        }
    }
}

pub fn new_listener_socket<'a>(port: u16) -> anyhow::Result<TcpSocket<'a>> {
    let rx_data = vec![0u8; MAX_PACKET];
    let tx_data = vec![0u8; MAX_PACKET];
    let tcp_rx_buffer = TcpSocketBuffer::new(rx_data);
    let tcp_tx_buffer = TcpSocketBuffer::new(tx_data);
    let mut socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
    socket.listen(port)?;
    Ok(socket)
}

#[async_trait]
impl VirtualInterfacePoll for TcpVirtualInterface {
    async fn poll_loop(self) -> anyhow::Result<()> {
        debug!("VirtualInterfacePoll::poll_loop");
        let mut readiness_notifier = Some(self.readiness_notifier);
        let mut receiver_rx = self.receiver_rx;
        let wg = self.wg.clone();

        let device =
            VirtualIpDevice::new_direct(VirtualPort(self.port, PortProtocol::Tcp), true, self.wg)
                .with_context(|| "Failed to create virtual IP device")?;

        let mut virtual_interface = InterfaceBuilder::new(device, vec![])
            .ip_addrs([IpCidr::new(IpAddress::from(wg.source_peer_ip), 32)])
            .finalize();

        let mut socket_listeners = std::collections::HashMap::new();

        let socket = new_listener_socket(self.port)?;
        let client_handle = virtual_interface.add_socket(socket);
        let docket_listener_handle = SocketListenerHandle::new(client_handle);
        socket_listeners.insert(docket_listener_handle.identifier, docket_listener_handle);

        let mut listen_next = false;

        let mut tx_extra_identifier = None;
        let mut tx_extra = Vec::new();
        loop {
            let loop_start = smoltcp::time::Instant::now();

            match virtual_interface.poll(loop_start) {
                Ok(processed) if processed => {
                    trace!(
                        "[{}] Virtual interface polled some packets to be processed",
                        self.port
                    );
                }
                Err(e) => {
                    error!("[{}] Virtual interface poll error: {:?}", self.port, e);
                }
                _ => {}
            }

            
            if listen_next {
                info!("accepting next connection");
                let socket = new_listener_socket(self.port)?;
                let client_handle = virtual_interface.add_socket(socket);
                let docket_listener_handle = SocketListenerHandle::new(client_handle);
                socket_listeners.insert(docket_listener_handle.identifier, docket_listener_handle);
                listen_next = false;
            }

            for socket_identifier in socket_listeners.clone().keys() {
                let socket_listener_handle = socket_listeners.get_mut(socket_identifier).unwrap();
                let client_socket =
                    virtual_interface.get_socket::<TcpSocket>(socket_listener_handle.socket_handle);

                if socket_listener_handle.connected && client_socket.state() == TcpState::Closed {
                    trace!("[{}] Client socket closed TcpState::Closed", self.port);
                    socket_listener_handle.connected = false;
                    client_socket.abort();
                    socket_listeners.remove(socket_identifier);
                    continue;
                }

                if !socket_listener_handle.connected
                    && client_socket.state() == TcpState::Established
                {
                    socket_listener_handle.mark_as_connected();
                    listen_next = true;
                    if let Some(readiness_notifier) = readiness_notifier.take() {
                        debug!("sending READY");
                        readiness_notifier
                            .send(socket_listener_handle.identifier.clone())
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
                            if let Err(e) = self
                                .sender_tx
                                .send((socket_listener_handle.identifier.clone(), data))
                                .await
                            {
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
                if client_socket.state() == TcpState::CloseWait {
                    // No data to be sent in this loop. If the client state is CLOSE-WAIT (because of a server FIN),
                    // the interface is shutdown.
                    trace!(
                        "[{}] client sent no more data, and server sent FIN (CLOSE-WAIT)",
                        self.port
                    );
                    socket_listener_handle.connected = false;
                    client_socket.abort();
                    socket_listeners.remove(socket_identifier);
                    continue;
                }
            }

            let mut to_transfer = None;

            if tx_extra.is_empty() {
                if let Ok((id, data)) = receiver_rx.try_recv() {
                    tx_extra_identifier = Some(id);
                    to_transfer = Some(data);
                }
            }
            let to_transfer_slice = to_transfer.as_ref().unwrap_or(&tx_extra).as_slice();

            if !to_transfer_slice.is_empty() {

                if !socket_listeners.contains_key(&tx_extra_identifier.unwrap()) {
                    tx_extra = Vec::new();
                } else {
                let socket_listener_handle = socket_listeners
                    .get_mut(&tx_extra_identifier.unwrap())
                    .unwrap();
                let client_handle = socket_listener_handle.socket_handle;
                let (client_socket, _context) =
                    virtual_interface.get_socket_and_context::<TcpSocket>(client_handle);

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

            match virtual_interface.poll_delay(loop_start) {
                Some(smoltcp::time::Duration::ZERO) => {
                    continue;
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
    }
}
