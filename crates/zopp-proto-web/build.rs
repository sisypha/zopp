fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate proto code from the shared proto file
    // Disable transport-specific code generation since we're targeting WASM
    tonic_prost_build::configure()
        // Don't generate the server implementation (we're client-only)
        .build_server(false)
        // Don't generate the connect convenience method (requires transport feature)
        .build_transport(false)
        .compile_protos(
            &["../zopp-proto/proto/zopp.proto"],
            &["../zopp-proto/proto"],
        )?;
    Ok(())
}
