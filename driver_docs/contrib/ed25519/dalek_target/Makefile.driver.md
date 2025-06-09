# Purpose
This Makefile is used to automate the build and clean processes for a Rust project. It sets specific `RUSTFLAGS` to enable various sanitizer coverage options and force frame pointers, which are useful for debugging and profiling. The `build` target compiles the project using Cargo with the specified Rust version and target architecture, while the `clean` target removes build artifacts.
