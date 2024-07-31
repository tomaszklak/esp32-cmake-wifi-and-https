#![no_std]

use core::ffi::CStr;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripheral;
use esp_idf_svc::hal::prelude::Peripherals;
use esp_idf_svc::sys::EspError;
use esp_idf_svc::wifi::{
    AccessPointConfiguration, BlockingWifi, ClientConfiguration, Configuration, EspWifi,
};
use esp_idf_sys::{nvs_flash_init, ESP_FAIL, ESP_OK};
use log::*;

#[allow(dead_code)]
#[cfg(not(feature = "qemu"))]
const SSID: &str = core::env!("SSID");
#[allow(dead_code)]
#[cfg(not(feature = "qemu"))]
const PASS: &str = core::env!("PASS");

#[no_mangle]
extern "C" fn rust_main() -> i32 {
    wifi_and_https();
    1337
}

fn wifi_and_https() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    let flash_result = unsafe { nvs_flash_init() };
    if flash_result != ESP_OK {
        error!("Failed to initialize NVS flash");
    }

    #[allow(unused)]
    let peripherals = Peripherals::take().unwrap();

    #[allow(unused)]
    let sysloop = EspSystemEventLoop::take().unwrap();

    #[allow(clippy::redundant_clone)]
    #[cfg(not(feature = "qemu"))]
    #[allow(unused_mut)]
    let mut _wifi = wifi(peripherals.modem, sysloop.clone()).unwrap();

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
    })
    .unwrap();

    test_https_client2();
}

fn test_https_client2() {
    use esp_idf_sys::{
        esp_crt_bundle_attach, esp_err_to_name, esp_http_client_cleanup, esp_http_client_config_t,
        esp_http_client_event, esp_http_client_event_id_t_HTTP_EVENT_ON_DATA,
        esp_http_client_get_content_length, esp_http_client_get_status_code, esp_http_client_init,
        esp_http_client_is_chunked_response, esp_http_client_perform,
    };

    extern "C" fn http_event_handler(event: *mut esp_http_client_event) -> i32 {
        assert!(!event.is_null());
        let event = if event.is_null() {
            return ESP_FAIL;
        } else {
            unsafe { &*event }
        };

        if event.event_id == esp_http_client_event_id_t_HTTP_EVENT_ON_DATA {
            if !unsafe { esp_http_client_is_chunked_response(event.client) } {
                let data = unsafe {
                    core::slice::from_raw_parts(
                        event.data as *const u8,
                        event.data_len.try_into().unwrap(),
                    )
                };
                match core::str::from_utf8(&data[..]) {
                    Ok(body) => info!("{body}"),
                    Err(e) => error!("error reading body: {e:?}"),
                }
            }
        }
        ESP_OK
    }

    // let url = CStr::from_bytes_with_nul(b"https://tilde.cat\0").unwrap();
    let url = CStr::from_bytes_with_nul(b"https://www.howsmyssl.com\0").unwrap();
    let config = esp_http_client_config_t {
        url: url.as_ptr() as *const i8,
        event_handler: Some(http_event_handler),
        crt_bundle_attach: Some(esp_crt_bundle_attach),
        ..Default::default()
    };

    let client = unsafe { esp_http_client_init(&config) };
    let err = unsafe { esp_http_client_perform(client) };
    if err == ESP_OK {
        info!(
            "HTTPS Status = {}, content_length = {}",
            unsafe { esp_http_client_get_status_code(client) },
            unsafe { esp_http_client_get_content_length(client) },
        );
    } else {
        let name = unsafe { esp_err_to_name(err) };
        let name = unsafe { CStr::from_ptr(name) };
        let name = name.to_str();
        error!("Error perform http request {name:?}");
    }
    unsafe { esp_http_client_cleanup(client) };
}

#[cfg(not(feature = "qemu"))]
#[allow(dead_code)]
fn wifi(
    modem: impl peripheral::Peripheral<P = esp_idf_svc::hal::modem::Modem> + 'static,
    sysloop: EspSystemEventLoop,
) -> Result<EspWifi<'static>, EspError> {
    let mut esp_wifi = EspWifi::new(modem, sysloop.clone(), None).unwrap();

    let mut wifi = BlockingWifi::wrap(&mut esp_wifi, sysloop).unwrap();

    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))
        .unwrap();

    info!("Starting wifi...");

    wifi.start().unwrap();

    info!("Scanning...");

    let ap_infos = wifi.scan().unwrap();

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
    ))
    .unwrap();

    info!("Connecting wifi...");

    wifi.connect().unwrap();

    info!("Waiting for DHCP lease...");

    wifi.wait_netif_up().unwrap();

    let ip_info = wifi.wifi().sta_netif().get_ip_info().unwrap();

    info!("Wifi DHCP info: {:?}", ip_info);

    Ok(esp_wifi)
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
