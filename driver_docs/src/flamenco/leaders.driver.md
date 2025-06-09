
## Files
- **[fd_leaders.c](leaders/fd_leaders.c.driver.md)**: The `fd_leaders.c` file in the `firedancer` codebase implements functions for managing epoch leaders, including memory alignment, footprint calculation, and leader sampling using ChaCha20 RNG and weighted sampling.
- **[fd_leaders.h](leaders/fd_leaders.h.driver.md)**: The `fd_leaders.h` file in the `firedancer` codebase provides APIs for managing and interacting with the Solana leader schedule, including functions for creating, joining, and deleting leader schedule objects, as well as retrieving leader public keys for specific slots.
- **[Local.mk](leaders/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines build and test instructions for the `fd_leaders` component, conditional on the presence of 128-bit integer support.
- **[test_leaders.c](leaders/test_leaders.c.driver.md)**: The `test_leaders.c` file in the `firedancer` codebase tests the functionality of epoch leader management by verifying the correctness of leader assignments for slots in a specific epoch using imported data from Solana's Mainnet-beta epoch 454.
