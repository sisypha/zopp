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

/// Check if this is a cloud deployment (zopp.dev domain).
///
/// Returns true if the app is running on the official cloud service,
/// false for self-hosted deployments. This is used to show/hide
/// marketing content that isn't relevant for self-hosted users.
#[cfg(target_arch = "wasm32")]
pub fn is_cloud_deployment() -> bool {
    use web_sys::window;

    let host = window()
        .and_then(|w| w.location().host().ok())
        .unwrap_or_default();

    // Check for official cloud domains
    host == "zopp.dev"
        || host.ends_with(".zopp.dev")
        || host == "app.zopp.dev"
        || host == "localhost:3000" // Show cloud UI in development for testing
}

#[cfg(not(target_arch = "wasm32"))]
pub fn is_cloud_deployment() -> bool {
    false
}
