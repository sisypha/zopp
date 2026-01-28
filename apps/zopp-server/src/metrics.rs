//! Prometheus metrics for zopp-server.
//!
//! Exposes server metrics in Prometheus format at the `/metrics` endpoint.

use metrics::{counter, describe_counter, describe_histogram, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Instant;

/// Initialize the Prometheus metrics recorder and return a handle for rendering.
///
/// Must be called once at server startup before any metrics are recorded.
pub fn init_metrics() -> PrometheusHandle {
    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    // Describe metrics for better documentation in /metrics output
    describe_counter!(
        "zopp_grpc_requests_total",
        "Total number of gRPC requests processed"
    );
    describe_histogram!(
        "zopp_grpc_request_duration_seconds",
        "Duration of gRPC requests in seconds"
    );
    describe_counter!(
        "zopp_grpc_errors_total",
        "Total number of gRPC errors by status code"
    );

    handle
}

/// Record a successful gRPC request.
#[allow(dead_code)]
pub fn record_grpc_request(method: &'static str, duration: std::time::Duration) {
    counter!("zopp_grpc_requests_total", "method" => method, "status" => "ok").increment(1);
    histogram!("zopp_grpc_request_duration_seconds", "method" => method)
        .record(duration.as_secs_f64());
}

/// Record a failed gRPC request.
#[allow(dead_code)]
pub fn record_grpc_error(method: &'static str, status_code: &'static str) {
    counter!("zopp_grpc_requests_total", "method" => method, "status" => "error").increment(1);
    counter!("zopp_grpc_errors_total", "method" => method, "code" => status_code).increment(1);
}

/// A helper to time a request and record metrics on completion.
#[allow(dead_code)]
pub struct RequestTimer {
    method: &'static str,
    start: Instant,
}

#[allow(dead_code)]
impl RequestTimer {
    /// Start timing a request.
    pub fn new(method: &'static str) -> Self {
        Self {
            method,
            start: Instant::now(),
        }
    }

    /// Record a successful completion.
    pub fn success(self) {
        record_grpc_request(self.method, self.start.elapsed());
    }

    /// Record a failure with the given gRPC status code.
    pub fn error(self, status_code: &'static str) {
        record_grpc_error(self.method, status_code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_timer() {
        // Just verify the API compiles and doesn't panic
        // Actual metrics testing would require setting up a recorder
        let timer = RequestTimer::new("test_method");
        // Simulate some work
        std::thread::sleep(std::time::Duration::from_millis(1));
        timer.success();
    }
}
