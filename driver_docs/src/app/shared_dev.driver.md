## Folders
- **[boot](shared_dev/boot.driver.md)**: The `boot` folder in the `firedancer` codebase contains files for initializing and executing development commands and configurations for Firedancer devices.
- **[commands](shared_dev/commands.driver.md)**: The `commands` folder in the `firedancer` codebase contains a variety of source files and subfolders dedicated to implementing and managing commands for benchmarking, configuration, packet generation, QUIC tracing, and other network-related functionalities.
- **[rpc_client](shared_dev/rpc_client.driver.md)**: The `rpc_client` folder in the `firedancer` codebase contains implementations and tests for an RPC client that manages network connections and requests to both local and remote servers, with files for client functionality, private data structures, and build configurations.

## Files
- **[Local.mk](shared_dev/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase is a makefile that conditionally compiles and links various shared development components and commands for the `fddev_shared` library, based on the presence of hosted, Linux, and SSE environments.
