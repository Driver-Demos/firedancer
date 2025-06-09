## Folders
- **[src](rust_compat/src.driver.md)**: The `src` folder in the `firedancer` codebase contains Rust source files that implement and test QUIC connections using different libraries and configurations, including `main.rs` for command-line interface setup, `quiche.rs` for managing connections with Firedancer and quiche, and `quinn.rs` for integrating Quinn with Firedancer's QUIC implementation.

## Files
- **[build.rs](rust_compat/build.rs.driver.md)**: The `build.rs` file in the `firedancer` codebase sets up the build process for the Rust compatibility layer by configuring library paths, linking static libraries, and generating Rust bindings using `bindgen`.
- **[Cargo.toml](rust_compat/Cargo.toml.driver.md)**: The `Cargo.toml` file in the `firedancer` codebase specifies the package configuration and dependencies for the `firedancer-rust-quic-test` project, including libraries like `quiche`, `quinn`, and `tokio` with specific features enabled.
- **[wrapper.h](rust_compat/wrapper.h.driver.md)**: The `wrapper.h` file in the `firedancer` codebase defines several macros and includes headers related to network utilities, QUIC protocol, and UDP socket functionalities.
