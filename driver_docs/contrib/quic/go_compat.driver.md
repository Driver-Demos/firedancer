
## Files
- **[.gitignore](go_compat/.gitignore.driver.md)**: The `.gitignore` file in the `firedancer/contrib/quic/go_compat` directory specifies that the `go_compat` binary, which is the output of the "go build ." command, should be ignored by Git.
- **[cert.go](go_compat/cert.go.driver.md)**: The `cert.go` file in the `firedancer` codebase provides functionality to generate a Solana-specific TLS certificate using the Ed25519 cryptographic algorithm.
- **[go.mod](go_compat/go.mod.driver.md)**: The `go.mod` file in the `firedancer` codebase specifies the module path, Go version, toolchain, and dependencies for the `firedancer/contrib/quic/go_compat` module, including both direct and indirect dependencies.
- **[go.sum](go_compat/go.sum.driver.md)**: The `go.sum` file in the `firedancer` codebase at `go_compat/go.sum.driver.md` contains checksums for the dependencies used in the Go project, ensuring the integrity and consistency of the modules.
- **[loopback.go](go_compat/loopback.go.driver.md)**: The `loopback.go` file in the `firedancer` codebase implements a loopback packet connection for simulating network communication between two endpoints using Go channels.
- **[main.go](go_compat/main.go.driver.md)**: The `main.go` file in the `firedancer` codebase implements a Go program that tests QUIC protocol compatibility between `fd_quic` and `quic-go` by setting up both client and server tests, handling packet wrapping and unwrapping, and managing QUIC connections and streams.
