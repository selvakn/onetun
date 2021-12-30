#[macro_use]
extern crate log;

use std::sync::Arc;

use anyhow::Context;

use crate::config::Config;
use crate::config::PortProtocol;
use crate::virtual_iface::tcp::TcpVirtualInterface;
use crate::virtual_iface::VirtualInterfacePoll;
use crate::virtual_iface::VirtualPort;
use crate::wg::WireGuardTunnel;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpStream;

pub mod config;
pub mod ip_sink;
pub mod virtual_device;
pub mod virtual_iface;
pub mod wg;

const MAX_PACKET: usize = 65536;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_args().with_context(|| "Failed to read config")?;

    loop {
        start_wireguard(&config)
            .await
            .unwrap_or_else(|e| error!("recovering from: {}", e));
    }
}

async fn start_wireguard(config: &Config) -> anyhow::Result<()> {
    let wg = WireGuardTunnel::new(config)
        .await
        .with_context(|| "Failed to initialize WireGuard tunnel")?;
    let wg = Arc::new(wg);

    for port in config.ports_to_forward.clone() {
        {
            let wg = wg.clone();
            tokio::spawn(async move { forward_port(wg, port).await });
        }    
    }

    {
        let wg = wg.clone();
        tokio::spawn(async move { ip_sink::run_ip_sink_interface(wg).await });
    }

    {
        let wg = wg.clone();
        tokio::spawn(async move { wg.consume_task().await });
    }

    {
        let wg = wg.clone();
        loop {
            wg.routine_task().await?
        }
    }
}

async fn forward_port(wg: Arc<WireGuardTunnel>, port: u16) {
    loop {
        let result = listen_and_forward(port, wg.clone()).await;

        if let Err(e) = result {
            error!("[{}] Connection dropped un-gracefully: {:?}", port, e);
        } else {
            info!("[{}] Connection closed by client", port);
        }

        wg.release_virtual_interface(VirtualPort(port, PortProtocol::Tcp));
    }
}

async fn listen_and_forward(port: u16, wg: Arc<WireGuardTunnel>) -> anyhow::Result<()> {
    let abort = Arc::new(AtomicBool::new(false));
    let (client_rediness_tx, client_rediness_rx) = tokio::sync::oneshot::channel::<()>();

    let (client_socket_tx, data_to_real_client_rx) = tokio::sync::mpsc::channel(1_000);
    let (data_to_virtual_server_tx, listener_socket_rx) = tokio::sync::mpsc::channel(1_000);

    {
        let abort = abort.clone();
        let virtual_interface = TcpVirtualInterface::new(
            port,
            wg,
            abort.clone(),
            client_socket_tx,
            listener_socket_rx,
            client_rediness_tx,
        );

        tokio::spawn(async move {
            virtual_interface.poll_loop().await.unwrap_or_else(|e| {
                error!("Virtual interface poll loop failed unexpectedly: {}", e);
                abort.store(true, Ordering::Relaxed);
            })
        });
    }

    client_rediness_rx
        .await
        .with_context(|| "Virtual client dropped before being ready.")?;
    trace!("[{}] Virtual client is ready to send data", port);

    pipe_to_port(
        port,
        data_to_virtual_server_tx,
        data_to_real_client_rx,
        abort,
    )
    .await?;

    Ok(())
}

async fn pipe_to_port(
    port: u16,
    data_to_virtual_server_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut data_to_real_client_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    abort: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .or_else(|e| {
            error!("[{}] Failed to establish connection: {:?}", port, e);
            abort.store(true, Ordering::Relaxed);
            Err(e)
        })?;

    loop {
        tokio::select! {
            readable_result = ssh_stream.readable() => {
                match readable_result {
                    Ok(_) => {
                        // Buffer for the individual TCP segment.
                        let mut buffer = Vec::with_capacity(MAX_PACKET);
                        match ssh_stream.try_read_buf(&mut buffer) {
                            Ok(size) if size > 0 => {
                                let data = &buffer[..size];
                                debug!(
                                    "[{}] Read {} bytes of TCP data from real client",
                                    port, size
                                );
                                if let Err(e) = data_to_virtual_server_tx.send(data.to_vec()).await {
                                    error!(
                                        "[{}] Failed to dispatch data to virtual interface: {:?}",
                                        port, e
                                    );
                                }
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                continue;
                            }
                            Err(e) => {
                                error!(
                                    "[{}] Failed to read from client TCP socket: {:?}",
                                    port, e
                                );
                                break;
                            }
                            _ => {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("[{}] Failed to check if readable: {:?}", port, e);
                        break;
                    }
                }
            }
            data_recv_result = data_to_real_client_rx.recv() => {
                match data_recv_result {
                    Some(data) => match ssh_stream.try_write(&data) {
                        Ok(size) => {
                            debug!(
                                "[{}] Wrote {} bytes of TCP data to real client",
                                port, size
                            );
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if abort.load(Ordering::Relaxed) {
                                break;
                            } else {
                                continue;
                            }
                        }
                        Err(e) => {
                            error!(
                                "[{}] Failed to write to client TCP socket: {:?}",
                                port, e
                            );
                        }
                    },
                    None => {
                        if abort.load(Ordering::Relaxed) {
                            break;
                        } else {
                            continue;
                        }
                    },
                }
            }
        }
    }

    trace!("[{}] TCP socket handler task terminated", port);
    abort.store(true, Ordering::Relaxed);

    Ok(())
}
