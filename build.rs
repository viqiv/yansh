fn main() {
    println!("cargo:rerun-if-changed=src/sys.o");
    println!("cargo:rustc-link-arg=src/sys.o");
}
