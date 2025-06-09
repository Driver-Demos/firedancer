
## Files
- **[fd_wsample.c](wsample/fd_wsample.c.driver.md)**: The `fd_wsample.c` file in the `firedancer` codebase implements a weighted sampling algorithm using a high-radix tree structure, designed for performance optimization and flexibility in future enhancements.
- **[fd_wsample.h](wsample/fd_wsample.h.driver.md)**: The `fd_wsample.h` file in the `firedancer` codebase defines methods for computing weighted random samples, specifically for Solana's leader schedule and Turbine tree, using a ChaCha20-based random number generator.
- **[Local.mk](wsample/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, object files, and unit test configurations for the `fd_wsample` component within the `ballet` module.
- **[test_wsample.c](wsample/test_wsample.c.driver.md)**: The `test_wsample.c` file in the `firedancer` codebase contains a series of tests for the `fd_wsample` module, including tests for probability distribution sampling with and without replacement, chi-squared goodness of fit, and various other functionalities such as sharing, restoration, and handling of empty or poisoned samples.
