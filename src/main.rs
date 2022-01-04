#[macro_use]
extern crate log;

use std::sync::Arc;

use crate::config::Config;
use crate::config::PortProtocol;
use crate::virtual_iface::tcp::TcpVirtualInterface;
use crate::virtual_iface::VirtualInterfacePoll;
use crate::virtual_iface::VirtualPort;
use crate::wg::WireGuardTunnel;
use anyhow::Context;
use rand::{thread_rng, Rng};
use tokio::net::TcpStream;
use uuid::Uuid;

pub mod config;
pub mod ip_sink;
pub mod virtual_device;
pub mod virtual_iface;
pub mod wg;

const MAX_PACKET: usize = 65536;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = Config::from_args().with_context(|| "Failed to read config")?;

    loop {
        start_wireguard(&config)
            .await
            .unwrap_or_else(|e| error!("recovering from: {}", e));
    }
}

pub async fn start_wireguard(config: &Config) -> anyhow::Result<()> {
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
    let (client_rediness_tx, client_rediness_rx) = tokio::sync::oneshot::channel();

    let (client_socket_tx, data_to_real_client_rx) = tokio::sync::mpsc::channel(1_000);
    let (data_to_virtual_server_tx, listener_socket_rx) = tokio::sync::mpsc::channel(1_000);

    {
        let virtual_interface = TcpVirtualInterface::new(
            port,
            wg,
            client_socket_tx,
            listener_socket_rx,
            client_rediness_tx,
        );

        tokio::spawn(async move {
            virtual_interface.poll_loop().await.unwrap_or_else(|e| {
                error!("Virtual interface poll loop failed unexpectedly: {}", e);
            })
        });
    }

    client_rediness_rx
        .await
        .with_context(|| "Virtual client dropped before being ready.")?;
    trace!("[{}] first client connected", port);

    pipe_to_port(
        port,
        data_to_virtual_server_tx,
        data_to_real_client_rx,
    )
    .await?;

    Ok(())
}

async fn tcp_stream(
    upstreams: &mut std::collections::HashMap<Uuid, Arc<TcpStream>>,
    id: Uuid,
    port: u16,
) -> Arc<TcpStream> {
    let upstream_fd = upstreams.get(&id);
    if upstream_fd.is_none() {
        debug!("[{}] Creating upstream connection", port);
        let s = Arc::new(TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap());
        upstreams.insert(id, s.clone());
        return s;
    }
    upstream_fd.unwrap().clone()
    // let b = unsafe { TcpStream::from_std(std::net::TcpStream::from_raw_fd(upstream_fd.unwrap())) };
    // debug!("[{}] Upstream fd is {} and convertion successfule", port, upstream_fd.unwrap());
    // b.unwrap()
}

async fn pipe_to_port(
    port: u16,
    data_to_virtual_server_tx: tokio::sync::mpsc::Sender<(Uuid, Vec<u8>)>,
    mut data_to_real_client_rx: tokio::sync::mpsc::Receiver<(Uuid, Vec<u8>)>,
) -> anyhow::Result<()> {
    let mut upstreams: std::collections::HashMap<Uuid, Arc<TcpStream>> =
        std::collections::HashMap::new();

    loop {
        tokio::select! {
            _ = async {
                loop {
                    info!("tokio::select lopop");
                    if upstreams.len() == 0 {
                        info!("empty upstreams");
                        return std::future::pending().await;
                    }
                    let ids  = upstreams.clone().into_keys().collect::<Vec<Uuid>>();

                    // let upstreams_clone = upstreams.clone();
                    // let rs: Vec<Box<dyn std::future::Future<Output=std::io::Result<()>>>> = upstreams_clone.iter().map(|(k,v)| -> Box<dyn std::future::Future<Output=std::io::Result<()>>> {
                    //     Box::new(v.readable())
                    // }).collect();

                    // for id in ids 
                    {
                    let id = ids[thread_rng().gen_range(0..ids.len())];
                    debug!("[{}] cheking upstream {}", port, id);

                    let upstream = tcp_stream(&mut upstreams, id, port).await;
                    upstream.readable().await?;

                    let mut buffer = Vec::with_capacity(MAX_PACKET);
                    match upstream.try_read_buf(&mut buffer) {
                        Ok(size) if size > 0 => {
                            let data = &buffer[..size];
                            debug!(
                                "[{}] Read {} bytes of TCP data from real client",
                                port, size
                            );
                            if let Err(e) = data_to_virtual_server_tx.send((id, data.to_vec())).await {
                                error!(
                                    "[{}] Failed to dispatch data to virtual interface: {:?}",
                                    port, e
                                );
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // ignore
                        }
                        Err(e) => {
                            error!(
                                "[{}] Failed to read from client TCP socket: {:?}",
                                port, e
                            );
                            trace!("break1");
                            upstreams.remove(&id);
                        }
                        _ => {
                            trace!("break2");
                            upstreams.remove(&id);
                        }
                    }
                    }
                }

                Ok::<_, anyhow::Error>(())
            } => {}

            data_recv_result = data_to_real_client_rx.recv() => {
                match data_recv_result {
                    Some((id, data)) => {
                        debug!(
                            "[{}] Received {} bytes of TCP data from virtual server",
                            port, data.len()
                        );
                        let upstream =  tcp_stream(&mut upstreams, id, port).await;

                        match upstream.try_write(&data) {
                            Ok(size) => {
                                debug!(
                                    "[{}] Wrote {} bytes of TCP data to real client",
                                    port, size
                                );
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            }
                            Err(e) => {
                                error!(
                                    "[{}] Failed to write to client TCP socket: {:?}",
                                    port, e
                                );
                            }
                        }
                    },
                    None => {
                    },
                }
            }
        }
    }

    trace!("[{}] TCP socket handler task terminated", port);

    Ok(())
}
