use anyhow::Result;
use async_io::Async;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripheral;
use esp_idf_svc::hal::prelude::Peripherals;
use esp_idf_svc::sys::EspError;
use esp_idf_svc::wifi::{
    AccessPointConfiguration, BlockingWifi, ClientConfiguration, Configuration, EspWifi,
};
use log::*;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::{env, thread};

use esp_idf_sys::{nvs_flash_init, ESP_OK};

#[allow(dead_code)]
#[cfg(not(feature = "qemu"))]
const SSID: &str = env!("SSID");
#[allow(dead_code)]
#[cfg(not(feature = "qemu"))]
const PASS: &str = env!("PASS");

#[no_mangle]
extern "C" fn rust_main() -> i32 {
    let res = wifi_and_https();
    info!("wifi_and_https: {res:?}");
    1337
}

fn wifi_and_https() -> Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    let flash_result = unsafe { nvs_flash_init() };
    if flash_result != ESP_OK {
        error!("Failed to initialize NVS flash");
    }

    #[allow(unused)]
    let peripherals = Peripherals::take().unwrap();

    #[allow(unused)]
    let sysloop = EspSystemEventLoop::take()?;

    #[allow(clippy::redundant_clone)]
    #[cfg(not(feature = "qemu"))]
    #[allow(unused_mut)]
    let mut _wifi = wifi(peripherals.modem, sysloop.clone())?;

    #[allow(clippy::redundant_clone)]
    #[cfg(feature = "qemu")]
    let eth = {
        let mut eth = Box::new(esp_idf_svc::eth::EspEth::wrap(
            esp_idf_svc::eth::EthDriver::new_openeth(peripherals.mac, sysloop.clone())?,
        )?);
        eth_configure(&sysloop, &mut eth)?;

        eth
    };

    esp_idf_svc::sys::esp!(unsafe {
        esp_idf_svc::sys::esp_vfs_eventfd_register(&esp_idf_svc::sys::esp_vfs_eventfd_config_t {
            max_fds: 5,
            ..Default::default()
        })
    })?;

    test_https_client()?;

    Ok(())
}

fn test_https_client() -> anyhow::Result<()> {
    async fn test() -> anyhow::Result<()> {
        // Implement `esp_idf_svc::tls::PollableSocket` for async-io sockets
        ////////////////////////////////////////////////////////////////////

        pub struct EspTlsSocket(Option<async_io::Async<TcpStream>>);

        impl EspTlsSocket {
            pub const fn new(socket: async_io::Async<TcpStream>) -> Self {
                Self(Some(socket))
            }

            pub fn handle(&self) -> i32 {
                self.0.as_ref().unwrap().as_raw_fd()
            }

            pub fn poll_readable(
                &self,
                ctx: &mut core::task::Context,
            ) -> core::task::Poll<Result<(), esp_idf_svc::sys::EspError>> {
                self.0
                    .as_ref()
                    .unwrap()
                    .poll_readable(ctx)
                    .map_err(|_| EspError::from_infallible::<{ esp_idf_svc::sys::ESP_FAIL }>())
            }

            pub fn poll_writeable(
                &self,
                ctx: &mut core::task::Context,
            ) -> core::task::Poll<Result<(), esp_idf_svc::sys::EspError>> {
                self.0
                    .as_ref()
                    .unwrap()
                    .poll_writable(ctx)
                    .map_err(|_| EspError::from_infallible::<{ esp_idf_svc::sys::ESP_FAIL }>())
            }

            fn release(&mut self) -> Result<(), esp_idf_svc::sys::EspError> {
                let socket = self.0.take().unwrap();
                socket.into_inner().unwrap().into_raw_fd();

                Ok(())
            }
        }

        impl esp_idf_svc::tls::Socket for EspTlsSocket {
            fn handle(&self) -> i32 {
                EspTlsSocket::handle(self)
            }

            fn release(&mut self) -> Result<(), esp_idf_svc::sys::EspError> {
                EspTlsSocket::release(self)
            }
        }

        impl esp_idf_svc::tls::PollableSocket for EspTlsSocket {
            fn poll_readable(
                &self,
                ctx: &mut core::task::Context,
            ) -> core::task::Poll<Result<(), esp_idf_svc::sys::EspError>> {
                EspTlsSocket::poll_readable(self, ctx)
            }

            fn poll_writable(
                &self,
                ctx: &mut core::task::Context,
            ) -> core::task::Poll<Result<(), esp_idf_svc::sys::EspError>> {
                EspTlsSocket::poll_writeable(self, ctx)
            }
        }

        ////////////////////////////////////////////////////////////////////

        let addr = "tilde.cat:443".to_socket_addrs()?.next().unwrap();
        info!("Addr: {addr:?}");
        let socket = Async::<TcpStream>::connect(addr).await?;

        let mut tls = esp_idf_svc::tls::EspAsyncTls::adopt(EspTlsSocket::new(socket))?;
        info!("tls");

        tls.negotiate("tilde.cat", &esp_idf_svc::tls::Config::new())
            .await?;
        info!("negotiate");

        tls.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
        info!("GET");

        let mut body = [0_u8; 2048];

        let read = esp_idf_svc::io::utils::asynch::try_read_full(&mut tls, &mut body)
            .await
            .map_err(|(e, _)| e)?;

        info!(
            "Body (truncated to 2K):\n{:?}",
            String::from_utf8_lossy(&body[..read]).into_owned()
        );

        Ok(())
    }

    let th = thread::Builder::new()
        .stack_size(20000)
        .spawn(move || async_io::block_on(test()))?;

    th.join().unwrap()
}

#[cfg(not(feature = "qemu"))]
#[allow(dead_code)]
fn wifi(
    modem: impl peripheral::Peripheral<P = esp_idf_svc::hal::modem::Modem> + 'static,
    sysloop: EspSystemEventLoop,
) -> Result<Box<EspWifi<'static>>> {
    let mut esp_wifi = EspWifi::new(modem, sysloop.clone(), None)?;

    let mut wifi = BlockingWifi::wrap(&mut esp_wifi, sysloop)?;

    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;

    info!("Starting wifi...");

    wifi.start()?;

    info!("Scanning...");

    let ap_infos = wifi.scan()?;

    let ours = ap_infos.into_iter().find(|a| a.ssid == SSID);

    let channel = if let Some(ours) = ours {
        info!(
            "Found configured access point {} on channel {}",
            SSID, ours.channel
        );
        Some(ours.channel)
    } else {
        info!(
            "Configured access point {} not found during scanning, will go with unknown channel",
            SSID
        );
        None
    };

    wifi.set_configuration(&Configuration::Mixed(
        ClientConfiguration {
            ssid: SSID.try_into().unwrap(),
            password: PASS.try_into().unwrap(),
            channel,
            ..Default::default()
        },
        AccessPointConfiguration {
            ssid: "aptest".try_into().unwrap(),
            channel: channel.unwrap_or(1),
            ..Default::default()
        },
    ))?;

    info!("Connecting wifi...");

    wifi.connect()?;

    info!("Waiting for DHCP lease...");

    wifi.wait_netif_up()?;

    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;

    info!("Wifi DHCP info: {:?}", ip_info);

    Ok(Box::new(esp_wifi))
}

#[cfg(any(feature = "qemu", feature = "w5500", feature = "ip101"))]
fn eth_configure<'d, T>(
    sysloop: &EspSystemEventLoop,
    eth: &mut esp_idf_svc::eth::EspEth<'d, T>,
) -> Result<()> {
    info!("Eth created");

    let mut eth = esp_idf_svc::eth::BlockingEth::wrap(eth, sysloop.clone())?;

    info!("Starting eth...");

    eth.start()?;

    info!("Waiting for DHCP lease...");

    eth.wait_netif_up()?;

    let ip_info = eth.eth().netif().get_ip_info()?;

    info!("Eth DHCP info: {:?}", ip_info);

    ping(ip_info.subnet.gateway)?;

    Ok(())
}
