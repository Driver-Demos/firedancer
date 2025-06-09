
## Files
- **[.gitignore](rpcserver/.gitignore.driver.md)**: The `.gitignore` file in the `firedancer/src/app/rpcserver` directory specifies that the `venv` directory should be ignored by Git.
- **[Local.mk](rpcserver/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines a makefile rule for building the `fd_rpcserver` binary, conditional on the presence of certain features like `FD_HAS_HOSTED`, `FD_HAS_INT128`, and `FD_HAS_SSE`.
- **[main.c](rpcserver/main.c.driver.md)**: The `main.c` file in the `firedancer` codebase initializes and runs an RPC server, handling both online and offline modes, and manages connections to various services and resources such as blockstores and sham links.
- **[README](rpcserver/README.driver.md)**: The `README` file in the `firedancer/src/app/rpcserver` directory provides instructions and warnings about the RPC implementation specific to the Firedancer validator, emphasizing its incompatibility with Frankendancer and noting that the service is under active development.
- **[requirements.txt](rpcserver/requirements.txt.driver.md)**: The `requirements.txt` file in the `firedancer` codebase specifies the `requests` and `websockets` libraries as dependencies for the `rpcserver` application.
- **[sham_link.h](rpcserver/sham_link.h.driver.md)**: The `sham_link.h` file in the `firedancer` codebase defines a structure and functions for managing a shared memory link, including initialization, starting, and polling operations.
- **[test_rpc_server.py](rpcserver/test_rpc_server.py.driver.md)**: The `test_rpc_server.py` file in the `firedancer` codebase is a unit test and fuzzer script for testing the `rpcserver` by sending various JSON-RPC requests and validating responses, including both valid and invalid method calls.
