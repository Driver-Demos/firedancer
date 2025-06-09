
## Files
- **[fd_tower.c](tower/fd_tower.c.driver.md)**: The `fd_tower.c` file in the `firedancer` codebase implements functions for managing and manipulating a voting tower structure, including operations for creating, joining, leaving, deleting, and verifying towers, as well as performing various checks and simulations related to voting and lockout mechanisms.
- **[fd_tower.h](tower/fd_tower.h.driver.md)**: The `fd_tower.h` file in the `firedancer` codebase provides an API for implementing Solana's TowerBFT algorithm, which is used to achieve consensus by managing a validator's "vote tower" and ensuring convergence on a single blockchain fork.
- **[Local.mk](tower/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines build configurations and dependencies for the `fd_tower` and its associated unit tests, conditional on the presence of `FD_HAS_INT128`, `FD_HAS_SECP256K1`, and `FD_HAS_HOSTED` flags.
- **[test_tower.c](tower/test_tower.c.driver.md)**: The `test_tower.c` file contains a test suite for the `fd_tower` module, verifying the functionality of voting operations, including vote addition, expiration, and root production within a tower structure.
