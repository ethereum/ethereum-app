//! Random backend for bare-metal device targets.
//!
//! On the host (Linux/macOS/Windows) `getrandom` uses the OS backend and this
//! module compiles to nothing. On a bare-metal target (`target_os = "none"`,
//! e.g. `thumbv7em-none-eabihf`) `getrandom` has no built-in backend, so we
//! register one backed by the device's hardware TRNG.
//!
//! Adjust the `cfg` below if your device target reports a different `target_os`.

#[cfg(target_os = "none")]
mod embedded {
    use core::ffi::c_int;

    extern "C" {
        /// Provided by the device firmware / HAL: fill `len` bytes at `buf` with
        /// true-random data. Returns 0 on success, non-zero on failure.
        fn device_trng_fill(buf: *mut u8, len: usize) -> c_int;
    }

    fn trng(dest: &mut [u8]) -> Result<(), getrandom::Error> {
        // SAFETY: `dest` is a valid, writable slice of `dest.len()` bytes.
        let rc = unsafe { device_trng_fill(dest.as_mut_ptr(), dest.len()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(getrandom::Error::UNSUPPORTED)
        }
    }

    getrandom::register_custom_getrandom!(trng);
}
