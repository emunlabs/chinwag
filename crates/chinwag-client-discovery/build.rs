fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    let sdk = std::process::Command::new("/usr/bin/xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .expect("client discovery requires the Apple SDK");
    assert!(sdk.status.success(), "xcrun could not locate the Apple SDK");
    let sdk = String::from_utf8(sdk.stdout).expect("Apple SDK path must be UTF-8");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    bindgen::Builder::default()
        .header_contents("client_observation.h", "#include <libproc.h>\n")
        .clang_args(["-isysroot", sdk.trim()])
        .allowlist_type("proc_bsdinfo")
        .allowlist_function("proc_listpids|proc_pidinfo|proc_pidpath")
        .allowlist_var("PROC_UID_ONLY|PROC_PIDTBSDINFO|PROC_PIDPATHINFO_MAXSIZE")
        .layout_tests(false)
        .derive_default(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("could not derive public libproc ABI from the Apple SDK")
        .write_to_file(output.join("libproc.rs"))
        .expect("could not save public libproc bindings");
}
