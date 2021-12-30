use crate::virtual_device::VirtualIpDevice;
use crate::wg::WireGuardTunnel;
use smoltcp::iface::InterfaceBuilder;
use std::sync::Arc;
use tokio::time::Duration;

pub async fn run_ip_sink_interface(wg: Arc<WireGuardTunnel>) -> ! {
    let device = VirtualIpDevice::new_sink(wg)
        .await
        .expect("Failed to initialize VirtualIpDevice for sink interface");

    let mut virtual_interface = InterfaceBuilder::new(device, vec![])
        .ip_addrs([])
        .finalize();

    loop {
        let loop_start = smoltcp::time::Instant::now();
        match virtual_interface.poll(loop_start) {
            Ok(processed) if processed => {
                trace!("[SINK] Virtual interface polled some packets to be processed",);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            Err(e) => {
                error!("[SINK] Virtual interface poll error: {:?}", e);
            }
            _ => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}
