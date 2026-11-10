fn main() {
    println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
    println!("cargo:rustc-link-lib=dylib=duckdb");
    println!("cargo:rerun-if-changed=build.rs");
}
