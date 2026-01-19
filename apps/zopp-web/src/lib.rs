#![recursion_limit = "256"]

pub mod app;
pub mod components;
pub mod pages;
pub mod services;
pub mod state;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use app::App;
    console_error_panic_hook::set_once();
    // For client-side only rendering (no SSR), we use mount_to_body
    leptos::mount::mount_to_body(App);
}
