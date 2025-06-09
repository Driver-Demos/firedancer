
## Files
- **[fd_merlin.c](merlin/fd_merlin.c.driver.md)**: The `fd_merlin.c` file implements the Merlin transcript protocol using Strobe-128 internals for cryptographic operations, including initialization, message appending, and challenge generation.
- **[fd_merlin.h](merlin/fd_merlin.h.driver.md)**: The `fd_merlin.h` file defines structures and functions for managing a cryptographic transcript using the Merlin protocol within the Firedancer project.
- **[Local.mk](merlin/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, object files, and unit tests for the `merlin` component within the `flamenco` runtime program.
- **[test_merlin.c](merlin/test_merlin.c.driver.md)**: The `test_merlin.c` file contains a test for the Merlin transcript protocol, verifying the equivalence of generated challenge bytes against expected values.
