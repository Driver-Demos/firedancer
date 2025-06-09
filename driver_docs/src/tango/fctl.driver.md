
## Files
- **[fd_fctl.c](fctl/fd_fctl.c.driver.md)**: The `fd_fctl.c` file in the `firedancer` codebase implements functions for configuring and managing flow control settings, including initialization, adding receiver configurations, and finalizing the configuration with burst and refill parameters.
- **[fd_fctl.h](fctl/fd_fctl.h.driver.md)**: The `fd_fctl.h` file in the `firedancer` codebase provides APIs for implementing ultra-flexible, low-overhead credit-based flow control, designed to be used sparingly in large-scale distributed systems to manage backpressure between transmitters and receivers.
- **[Local.mk](fctl/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, object files, and unit tests for the `fd_fctl` component, including running the `test_fctl` unit test.
- **[test_fctl.c](fctl/test_fctl.c.driver.md)**: The `test_fctl.c` file in the `firedancer` codebase contains a unit test for the `fd_fctl` module, verifying its configuration and functionality through various test cases and assertions.
