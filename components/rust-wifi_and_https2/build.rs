// use std::env;
// use std::path::PathBuf;

fn main() {
    // let include_paths: Vec<_> = std::env::var("CARGO_CMAKE_BUILD_INCLUDES")
    //     .unwrap()
    //     .split(';')
    //     .map(|s| s.to_owned())
    //     .collect();
    // println!("XXXXXXXXX {include_paths:?}",);
    // // Tell cargo to look for shared libraries in the specified directory
    // // println!("cargo:rustc-link-search=/path/to/lib");

    // // Tell cargo to tell rustc to link the system bzip2
    // // shared library.
    // // println!("cargo:rustc-link-lib=bz2");

    // // The bindgen::Builder is the main entry point
    // // to bindgen, and lets you build up options for
    // // the resulting bindings.
    // let mut bindings_generator = bindgen::Builder::default()
    //     .detect_include_paths(true)
    //     // The input header we would like to generate
    //     // bindings for.
    //     .header("wrapper.h")
    //     // Tell cargo to invalidate the built crate whenever any of the
    //     // included header files changed.
    //     .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    // for path in include_paths {
    //     bindings_generator = bindings_generator.clang_arg(format!("-I{path}"));
    // }
    // // Finish the builder and generate the bindings.
    // let bindings = bindings_generator
    //     .generate()
    //     // Unwrap the Result and panic on failure.
    //     .expect("Unable to generate bindings");

    // // Write the bindings to the $OUT_DIR/bindings.rs file.
    // let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // bindings
    //     .write_to_file(out_path.join("bindings.rs"))
    //     .expect("Couldn't write bindings!");
    embuild::espidf::sysenv::output();
}
