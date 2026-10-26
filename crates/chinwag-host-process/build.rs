fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    let sdk = std::process::Command::new("/usr/bin/xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .expect("chinwag-host-process requires an installed Apple SDK");
    assert!(sdk.status.success(), "xcrun could not locate the Apple SDK");
    let sdk = String::from_utf8(sdk.stdout).expect("Apple SDK path must be UTF-8");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    bindgen::Builder::default()
        .header_contents(
            "owned_group_layout.h",
            r#"
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <stddef.h>
enum {
 CHINWAG_KINFO_SIZE = sizeof(struct kinfo_proc),
 CHINWAG_PID_OFFSET = offsetof(struct kinfo_proc, kp_proc.p_pid),
 CHINWAG_PGID_OFFSET = offsetof(struct kinfo_proc, kp_eproc.e_pgid),
 CHINWAG_STATUS_OFFSET = offsetof(struct kinfo_proc, kp_proc.p_stat),
 CHINWAG_STATUS_IDLE = SIDL,
 CHINWAG_STATUS_RUN = SRUN,
 CHINWAG_STATUS_SLEEP = SSLEEP,
 CHINWAG_STATUS_STOP = SSTOP,
 CHINWAG_STATUS_ZOMBIE = SZOMB
};
"#,
        )
        .clang_args(["-isysroot", sdk.trim()])
        .allowlist_var("CHINWAG_.*")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("could not derive owned-group scalar layout from the Apple SDK")
        .write_to_file(out.join("layout.rs"))
        .expect("could not save Apple SDK layout constants");
}
