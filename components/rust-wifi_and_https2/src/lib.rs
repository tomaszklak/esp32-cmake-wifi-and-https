#![no_std]

use core::ffi::CStr;
use esp_idf_sys::{ESP_FAIL, ESP_OK};
use esp_println::println;

#[no_mangle]
extern "C" fn rust_main() -> i32 {
    https();
    1337
}

fn https() {
    esp_idf_sys::link_patches();
    test_https_client();
}

fn test_https_client() {
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
