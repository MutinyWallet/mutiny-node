pub mod socket;

#[cfg(target_arch = "wasm32")]
pub mod proxy;

#[cfg(target_arch = "wasm32")]
pub mod ws_socket;
