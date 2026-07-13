#[unsafe(no_mangle)]
pub extern "C" fn ffi_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    #[test]
    fn ffi_version_is_non_zero() {
        assert_eq!(super::ffi_version(), 1);
    }
}
