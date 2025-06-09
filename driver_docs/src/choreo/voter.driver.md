
## Files
- **[fd_voter.c](voter/fd_voter.c.driver.md)**: The `fd_voter.c` file in the `firedancer` codebase implements a function to retrieve the voter state from a given record in the `fd_funk` system, handling various conditions and logging warnings for invalid states.
- **[fd_voter.h](voter/fd_voter.h.driver.md)**: The `fd_voter.h` file in the `firedancer` codebase defines structures and functions for managing voter states, including serialization formats and querying mechanisms for different versions of voter data.
- **[fd_voter_ctl.c](voter/fd_voter_ctl.c.driver.md)**: The `fd_voter_ctl.c` file in the `firedancer` codebase reads a JSON file to extract and encode a vote account address using base58 encoding.
- **[Local.mk](voter/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies build instructions for the `fd_voter` component, including headers, objects, binaries, and unit tests, conditional on the presence of `FD_HAS_INT128` and `FD_HAS_HOSTED`.
- **[test_voter.c](voter/test_voter.c.driver.md)**: The `test_voter.c` file in the `firedancer` codebase contains test functions for verifying the functionality of voter state decoding and validation using predefined data structures and signatures.
