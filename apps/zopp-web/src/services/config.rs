//! Configuration utilities for the web app

/// Get the gRPC-web server URL.
///
/// In development (trunk serve on port 3000), returns `http://localhost:8080`
/// since Envoy runs separately. In production, returns `{origin}/api` assuming
/// a reverse proxy routes /api to the gRPC-web endpoint.
#[cfg(target_arch = "wasm32")]
pub fn get_server_url() -> String {
    use web_sys::window;

    let origin = window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default();

    // In development, trunk serves on port 3000 but Envoy is on 8080
    if origin.contains(":3000") {
        "http://localhost:8080".to_string()
    } else {
        // Production: assume /api routes to gRPC-web proxy
        format!("{}/api", origin)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn get_server_url() -> String {
    "http://localhost:8080".to_string()
}
