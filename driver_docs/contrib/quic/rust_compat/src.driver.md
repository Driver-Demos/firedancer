
## Files
- **[main.rs](src/main.rs.driver.md)**: The `main.rs` file in the `firedancer` codebase sets up a command-line interface for testing QUIC connections using different client-server configurations, including quiche and quinn clients with various cryptographic providers.
- **[quiche.rs](src/quiche.rs.driver.md)**: The `quiche.rs` file in the `firedancer` codebase sets up and manages a QUIC connection using both the Firedancer and quiche libraries, including UDP socket configuration, packet capture, and connection lifecycle management.
- **[quinn.rs](src/quinn.rs.driver.md)**: The `quinn.rs` file in the `firedancer` codebase provides an integration between the Quinn library and Firedancer's QUIC implementation, including setting up UDP sockets, handling server certificate verification, and managing QUIC connections.
