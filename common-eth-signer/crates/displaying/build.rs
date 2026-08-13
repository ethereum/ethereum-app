fn main() {
    // Only compile the Slint markup when the `slint` feature is enabled.
    #[cfg(feature = "slint")]
    slint_build::compile("ui/confirm.slint").expect("failed to compile Slint UI");
}
