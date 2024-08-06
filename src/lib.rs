#![no_std]

use core::ffi::CStr;

use esp_println::println;

#[no_mangle]
extern "C" fn hello_world(name: *mut i8) -> i32 {
    esp_idf_sys::link_patches();

    let name = unsafe { CStr::from_ptr(name) };
    let name = match name.to_str() {
        Ok(s) => s,
        Err(_) => "Unknown",
    };
    println!("Hello '{name}' from Rust!");
    name.len() as i32
}
