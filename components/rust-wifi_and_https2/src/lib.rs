#![no_std]

use core::ffi::CStr;
// use esp_idf_svc::eventloop::EspSystemEventLoop;
// use esp_idf_svc::hal::peripheral;
// use esp_idf_svc::hal::prelude::Peripherals;
// use esp_idf_svc::sys::EspError;
// use esp_idf_svc::wifi::{
//     AccessPointConfiguration, BlockingWifi, ClientConfiguration, Configuration, EspWifi,
// };
use esp_idf_sys::{ESP_FAIL, ESP_OK};
use esp_println::println;
// use log::*;

// #[allow(dead_code)]
// #[cfg(not(feature = "qemu"))]
// const SSID: &str = core::env!("SSID");
// #[allow(dead_code)]
// #[cfg(not(feature = "qemu"))]
// const PASS: &str = core::env!("PASS");

#[no_mangle]
extern "C" fn rust_main() -> i32 {
    wifi_and_https();
    1337
}

fn wifi_and_https() {
    esp_idf_sys::link_patches();
    // esp_idf_svc::log::EspLogger::initialize_default();
    // let flash_result = unsafe { nvs_flash_init() };
    // if flash_result != ESP_OK {
    //     error!("Failed to initialize NVS flash");
    // }

    // #[allow(unused)]
    // let peripherals = Peripherals::take().unwrap();

    // #[allow(unused)]
    // let sysloop = EspSystemEventLoop::take().unwrap();

    // #[allow(clippy::redundant_clone)]
    // #[cfg(not(feature = "qemu"))]
    // #[allow(unused_mut)]
    // let mut _wifi = wifi(peripherals.modem, sysloop.clone()).unwrap();

    println!("Will init wifi");
    // wifi_init();

    #[allow(clippy::redundant_clone)]
    #[cfg(feature = "qemu")]
    let eth = {
        let mut eth = Box::new(esp_idf_svc::eth::EspEth::wrap(
            esp_idf_svc::eth::EthDriver::new_openeth(peripherals.mac, sysloop.clone())?,
        )?);
        eth_configure(&sysloop, &mut eth)?;

        eth
    };

    // esp_idf_svc::sys::esp!(unsafe {
    //     esp_idf_svc::sys::esp_vfs_eventfd_register(&esp_idf_svc::sys::esp_vfs_eventfd_config_t {
    //         max_fds: 5,
    //         ..Default::default()
    //     })
    // })
    // .unwrap();

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
                    Ok(body) => println!("{body}"),
                    Err(e) => println!("error reading body: {e:?}"),
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
        println!(
            "HTTPS Status = {}, content_length = {}",
            unsafe { esp_http_client_get_status_code(client) },
            unsafe { esp_http_client_get_content_length(client) },
        );
    } else {
        let name = unsafe { esp_err_to_name(err) };
        let name = unsafe { CStr::from_ptr(name) };
        let name = name.to_str();
        println!("Error perform http request {name:?}");
    }
    unsafe { esp_http_client_cleanup(client) };
}

/*
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
*/

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

/*
use core::mem::MaybeUninit;
// use esp_idf_hal::prelude::*;
use esp_idf_sys::ip_event_t_IP_EVENT_STA_GOT_IP as IP_EVENT_STA_GOT_IP;
use esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_DISCONNECTED as WIFI_EVENT_STA_DISCONNECTED;
use esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_START as WIFI_EVENT_STA_START;
use esp_idf_sys::wifi_sae_pwe_method_t_WPA3_SAE_PWE_BOTH;
use esp_idf_sys::*;

const WIFI_CONNECTED_BIT: u32 = esp_idf_sys::BIT0;
const WIFI_FAIL_BIT: u32 = esp_idf_sys::BIT1;

static mut WIFI_EVENT_GROUP: MaybeUninit<*mut EventGroupDef_t> = MaybeUninit::uninit();
static mut RETRY_NUM: i32 = 0;
const MAXIMUM_RETRY: i32 = 5;

extern "C" fn event_handler(
    arg: *mut core::ffi::c_void,
    event_base: esp_event_base_t,
    event_id: i32,
    event_data: *mut core::ffi::c_void,
) {
    unsafe {
        if event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START as i32 {
            esp_wifi_connect();
        } else if event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED as i32 {
            if RETRY_NUM < MAXIMUM_RETRY {
                esp_wifi_connect();
                RETRY_NUM += 1;
                info!("Retry to connect to the AP");
            } else {
                xEventGroupSetBits(WIFI_EVENT_GROUP.assume_init(), WIFI_FAIL_BIT);
            }
            info!("Failed to connect to the AP");
        } else if event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP as i32 {
            let event = &*(event_data as *const ip_event_got_ip_t);
            let ip = ip4_addr_t {
                addr: event.ip_info.ip.addr,
            };
            let addr = CStr::from_ptr(ip4addr_ntoa(&ip));
            info!("Got IP: {}", addr.to_str().unwrap());
            RETRY_NUM = 0;
            xEventGroupSetBits(WIFI_EVENT_GROUP.assume_init(), WIFI_CONNECTED_BIT);
        }
    }
}


fn wifi_init() {
    info!("XXXXXXX");
    unsafe { WIFI_EVENT_GROUP.write(xEventGroupCreate()) };
    esp!(unsafe { esp_netif_init() }).expect("Failed to initialize network interface");
    esp!(unsafe { esp_event_loop_create_default() }).expect("Failed to create event loop");
    unsafe { esp_netif_create_default_wifi_sta() };

    let nvs_enabled = true;
    let wifi_cfg = wifi_init_config_t {
        #[cfg(esp_idf_version_major = "4")]
        event_handler: Some(esp_event_send_internal),
        osi_funcs: unsafe { core::ptr::addr_of_mut!(g_wifi_osi_funcs) },
        wpa_crypto_funcs: unsafe { g_wifi_default_wpa_crypto_funcs },
        static_rx_buf_num: CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM as _,
        dynamic_rx_buf_num: CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM as _,
        tx_buf_type: CONFIG_ESP32_WIFI_TX_BUFFER_TYPE as _,
        static_tx_buf_num: WIFI_STATIC_TX_BUFFER_NUM as _,
        dynamic_tx_buf_num: WIFI_DYNAMIC_TX_BUFFER_NUM as _,
        cache_tx_buf_num: WIFI_CACHE_TX_BUFFER_NUM as _,
        csi_enable: WIFI_CSI_ENABLED as _,
        ampdu_rx_enable: WIFI_AMPDU_RX_ENABLED as _,
        ampdu_tx_enable: WIFI_AMPDU_TX_ENABLED as _,
        amsdu_tx_enable: WIFI_AMSDU_TX_ENABLED as _,
        nvs_enable: i32::from(nvs_enabled),
        nano_enable: WIFI_NANO_FORMAT_ENABLED as _,
        //tx_ba_win: WIFI_DEFAULT_TX_BA_WIN as _,
        rx_ba_win: WIFI_DEFAULT_RX_BA_WIN as _,
        wifi_task_core_id: WIFI_TASK_CORE_ID as _,
        beacon_max_len: WIFI_SOFTAP_BEACON_MAX_LEN as _,
        mgmt_sbuf_num: WIFI_MGMT_SBUF_NUM as _,
        #[cfg(any(
            esp_idf_version_major = "4",
            all(esp_idf_version_major = "5", esp_idf_version_minor = "0"),
            esp_idf_version_full = "5.1.0",
            esp_idf_version_full = "5.1.1",
            esp_idf_version_full = "5.1.2"
        ))]
        feature_caps: unsafe { g_wifi_feature_caps },
        #[cfg(not(any(
            esp_idf_version_major = "4",
            all(esp_idf_version_major = "5", esp_idf_version_minor = "0"),
            esp_idf_version_full = "5.1.0",
            esp_idf_version_full = "5.1.1",
            esp_idf_version_full = "5.1.2"
        )))]
        feature_caps: WIFI_FEATURE_CAPS as _,
        sta_disconnected_pm: WIFI_STA_DISCONNECTED_PM_ENABLED != 0,
        // Available since ESP IDF V4.4.4+
        #[cfg(any(
            not(esp_idf_version_major = "4"),
            all(
                esp_idf_version_major = "4",
                any(
                    not(esp_idf_version_minor = "4"),
                    all(
                        not(esp_idf_version_patch = "0"),
                        not(esp_idf_version_patch = "1"),
                        not(esp_idf_version_patch = "2"),
                        not(esp_idf_version_patch = "3")
                    )
                )
            )
        ))]
        espnow_max_encrypt_num: CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM as i32,
        magic: WIFI_INIT_CONFIG_MAGIC as _,
        ..Default::default()
    };
    // let wifi_init_config = unsafe { wifi_init_config_t::default() };
    let wifi_init_config = wifi_cfg;
    esp!(unsafe { esp_wifi_init(&wifi_init_config) }).expect("Failed to initialize Wi-Fi");

    info!("YYYYYY");
    esp!(unsafe {
        esp_event_handler_instance_register(
            WIFI_EVENT,
            ESP_EVENT_ANY_ID,
            Some(event_handler),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    })
    .expect("Failed to register Wi-Fi event handler");

    esp!(unsafe {
        esp_event_handler_instance_register(
            IP_EVENT,
            IP_EVENT_STA_GOT_IP as i32,
            Some(event_handler),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    })
    .expect("Failed to register IP event handler");

    // Set Wi-Fi configuration
    let mut wifi_config = wifi_config_t {
        sta: wifi_sta_config_t {
            ssid: *b"PLAY_Swiatlowodowy_C0E1\0\0\0\0\0\0\0\0\0",
            password: *b"MgMcCqHjyk\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            threshold: wifi_scan_threshold_t {
                authmode: wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK,
                rssi:  -127,
            },
            sae_pwe_h2e: wifi_sae_pwe_method_t_WPA3_SAE_PWE_BOTH,
            sae_h2e_identifier: *b"your_identifier12345678901234567",
            ..Default::default()
        },
    };

    esp!(unsafe { esp_wifi_set_mode(esp_idf_sys::wifi_mode_t_WIFI_MODE_STA) })
        .expect("Failed to set Wi-Fi mode");
    esp!(unsafe {
        esp_wifi_set_config(esp_idf_sys::wifi_interface_t_WIFI_IF_STA, &mut wifi_config)
    })
    .expect("Failed to set Wi-Fi configuration");
    esp!(unsafe { esp_wifi_start() }).expect("Failed to start Wi-Fi");

    let bits = unsafe {
        xEventGroupWaitBits(
            WIFI_EVENT_GROUP.assume_init(),
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            0,
            0,
            u32::MAX,
        )
    };

    if bits & WIFI_CONNECTED_BIT != 0 {
        info!("Connected to WIFI");
    } else if bits & WIFI_FAIL_BIT != 0 {
        info!("Failed to connect to WIFI");
    } else {
        error!("Unexpected event");
    }
}*/
