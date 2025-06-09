
## Files
- **[.gitignore](consensus/.gitignore.driver.md)**: The `.gitignore` file in the `firedancer/src/discof/consensus` directory specifies that all files with the `.sh` extension should be ignored by Git.
- **[Local.mk](consensus/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase defines unit tests for consensus and gossip echo vote functionalities, conditional on the presence of `FD_HAS_INT128` and `FD_HAS_SECP256K1`.
- **[test_consensus.c](consensus/test_consensus.c.driver.md)**: The `test_consensus.c` file in the `firedancer` codebase is a comprehensive test implementation for consensus mechanisms, involving setup and management of various components like gossip, repair, turbine, and replay threads, along with network communication and data handling functionalities.
- **[test_gossip_echo_vote.c](consensus/test_gossip_echo_vote.c.driver.md)**: The `test_gossip_echo_vote.c` file in the `firedancer` codebase implements a test for gossip-based vote echoing in a consensus protocol, including functions for signing, socket creation, UDP packet sending, and handling gossip messages.
