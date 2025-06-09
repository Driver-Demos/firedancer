## Folders
- **[generated](xdp/generated.driver.md)**: The `generated` folder in the `firedancer` codebase contains a generated header file, `xdp_seccomp.h`, which defines a seccomp filter policy for XDP.

## Files
- **[fd_xdp_tile.c](xdp/fd_xdp_tile.c.driver.md)**: The `fd_xdp_tile.c` file in the `firedancer` codebase implements the functionality for translating traffic between AF_XDP and fd_tango, including setting up XDP and XSK socket configurations, managing network packet transmission and reception, and handling various network-related operations and metrics.
- **[Local.mk](xdp/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies conditional object file additions for `fd_xdp_tile` and `fd_disco` based on the presence of `FD_HAS_SSE` and `FD_HAS_ALLOCA` definitions.
- **[xdp.seccomppolicy](xdp/xdp.seccomppolicy.driver.md)**: The `xdp.seccomppolicy` file in the `firedancer` codebase defines security policies for file descriptors and system calls related to logging and XDP socket operations, including sendto, recvmsg, and getsockopt, for network and loopback devices.
