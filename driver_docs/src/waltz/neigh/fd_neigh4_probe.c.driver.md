# Purpose
The provided C source code file is designed to implement a network probing utility, specifically for probing IPv4 neighbors on a local network. It defines functions to initialize, finalize, and execute probes using UDP sockets. The primary function, [`fd_neigh4_prober_init`](#fd_neigh4_prober_init), sets up a UDP socket with specific options such as a low Time-To-Live (TTL) value and the `SO_DONTROUTE` option, which ensures that packets are only sent to directly connected neighbors. This setup is crucial for network diagnostics and monitoring tasks where understanding the reachability and response of local network devices is necessary.

The code also includes a rate-limiting mechanism using a token bucket algorithm to control the frequency of probe packets, preventing network congestion. The [`fd_neigh4_probe`](#fd_neigh4_probe) function sends a probe packet to a specified IPv4 address and updates the probe entry with a delay to suppress further probes until a specified time. The file is likely part of a larger network management or diagnostic tool, as indicated by its inclusion of headers and reliance on external functions like `fd_tempo_tick_per_ns`. The code is structured to be reusable and modular, with clear separation of initialization, operation, and cleanup tasks, making it suitable for integration into broader network monitoring systems.
# Imports and Dependencies

---
- `fd_neigh4_probe.h`
- `../../tango/tempo/fd_tempo.h`
- `errno.h`
- `sys/socket.h`
- `netinet/in.h`
- `unistd.h`


# Functions

---
### fd\_neigh4\_prober\_init<!-- {{#callable:fd_neigh4_prober_init}} -->
The `fd_neigh4_prober_init` function initializes a network prober for sending probe packets to Ethernet neighbors with specified rate limits and delays.
- **Inputs**:
    - `prober`: A pointer to an `fd_neigh4_prober_t` structure that will be initialized by the function.
    - `max_probes_per_second`: A float specifying the maximum number of probe packets that can be sent per second.
    - `max_probe_burst`: An unsigned long specifying the maximum number of probe packets that can be sent in a burst.
    - `probe_delay_seconds`: A float specifying the delay in seconds between sending probe packets.
- **Control Flow**:
    - Create a UDP socket using `socket(AF_INET, SOCK_DGRAM, 0)` and check for errors.
    - Set the IP Time-To-Live (TTL) option to 1 using `setsockopt` and check for errors.
    - Set the socket option `SO_DONTROUTE` to 1 to ensure packets are only sent to Ethernet neighbors and check for errors.
    - Calculate the number of ticks per nanosecond using `fd_tempo_tick_per_ns`.
    - Initialize the `fd_neigh4_prober_t` structure with the socket file descriptor, calculated probe delay, and rate limiting parameters.
- **Output**: The function initializes the `fd_neigh4_prober_t` structure with a socket file descriptor, probe delay, and rate limiting parameters for sending probe packets.


---
### fd\_neigh4\_prober\_fini<!-- {{#callable:fd_neigh4_prober_fini}} -->
The `fd_neigh4_prober_fini` function closes the socket associated with a network prober and resets its file descriptor to -1.
- **Inputs**:
    - `prober`: A pointer to an `fd_neigh4_prober_t` structure, which contains the socket file descriptor to be closed.
- **Control Flow**:
    - Check if closing the socket file descriptor `prober->sock_fd` returns a non-zero value, indicating an error.
    - If an error occurs during the socket close operation, log an error message with the file descriptor and error details.
    - Set the `sock_fd` field of the `prober` structure to -1 to indicate that the socket is no longer valid.
- **Output**: The function does not return a value; it performs cleanup by closing a socket and updating the prober's state.


---
### fd\_neigh4\_probe<!-- {{#callable:fd_neigh4_probe}} -->
The `fd_neigh4_probe` function sends a probe packet to a specified IPv4 address and updates the entry's probe suppression time.
- **Inputs**:
    - `prober`: A pointer to an `fd_neigh4_prober_t` structure, which contains the socket file descriptor and probe delay information.
    - `entry`: A pointer to an `fd_neigh4_entry_t` structure, which will have its `probe_suppress_until` field updated.
    - `ip4_addr`: An unsigned integer representing the IPv4 address to which the probe packet is sent.
    - `now`: A long integer representing the current time, used to calculate the next allowable probe time.
- **Control Flow**:
    - Initialize a `sockaddr_in` structure `dst` with the IPv4 address, setting the family to `AF_INET` and port to `0xFFFF`.
    - Attempt to send a zero-length UDP packet to the specified IPv4 address using the `sendto` function with the `MSG_DONTWAIT` flag.
    - If the `sendto` call fails, return the error number `errno`.
    - Update the `probe_suppress_until` field of the `entry` structure to the current time plus the probe delay.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or an error number if the `sendto` call fails.


