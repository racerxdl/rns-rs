/// ESP32 hardware RNG wrapper implementing `rns_crypto::Rng`.
///
/// This is provided separately from `rns_crypto::OsRng` for cases where:
/// 1. The `std` feature of `rns-crypto` is not enabled
/// 2. Explicit control over RNG usage is desired (e.g., for identity generation)
///
/// When `rns-crypto` is built with both `std` and `espidf` features, its `OsRng`
/// also uses `esp_fill_random` internally. Both implementations are equivalent.
pub struct EspRng;

impl rns_crypto::Rng for EspRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            esp_idf_sys::esp_fill_random(dest.as_mut_ptr() as *mut core::ffi::c_void, dest.len());
        }
    }
}
