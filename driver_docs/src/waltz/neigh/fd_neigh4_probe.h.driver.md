# Purpose
The `fd_neigh4_probe.h` file is a C header file that provides functionality for triggering ARP (Address Resolution Protocol) requests in a Linux environment using a method that requires minimal privileges. This file is part of the Firedancer network stack and is specifically designed to handle situations where an IP packet is sent, but no corresponding entry exists in the neighbor table to resolve the destination MAC address. The header defines a mechanism to send empty UDP packets to indirectly prompt the Linux kernel to issue ARP requests, thereby updating the neighbor table with the necessary MAC address information. This approach is chosen because it does not require elevated privileges, unlike other potential solutions that involve direct manipulation of the neighbor table or sending raw packets.

The file defines the `fd_neigh4_prober_t` structure, which encapsulates the state and configuration for the neighbor probing process, including a UDP socket, a delay for successive ARP requests, and a token bucket rate limiter to control the frequency of outgoing probes. The header also declares several functions: [`fd_neigh4_prober_init`](#fd_neigh4_prober_init) for initializing the prober, [`fd_neigh4_prober_fini`](#fd_neigh4_prober_fini) for cleaning up resources, and [`fd_neigh4_probe`](#fd_neigh4_probe) for sending the UDP packets. Additionally, it provides a rate-limited version of the probe function, [`fd_neigh4_probe_rate_limited`](#fd_neigh4_probe_rate_limited), which ensures that probes do not exceed specified rate limits. This file is intended to be included in other C source files that require neighbor probing functionality, and it defines a public API for managing and executing these probes within the constraints of the Firedancer network stack.
# Imports and Dependencies

---
- `fd_neigh4_map.h`
- `../fd_token_bucket.h`


# Data Structures

---
### fd\_neigh4\_prober
- **Type**: `struct`
- **Members**:
    - `sock_fd`: UDP socket with IP_TTL 0.
    - `probe_delay`: Specifies the delay in ticks for successive ARP requests to the same IP address.
    - `rate_limit`: Token bucket rate limiter on any outgoing ARP probes.
    - `local_rate_limited_cnt`: Metric counter for probes suppressed by local rate limit.
    - `global_rate_limited_cnt`: Metric counter for probes suppressed by global rate limit.
- **Description**: The `fd_neigh4_prober` structure is designed to facilitate ARP requests in a Linux environment by sending empty UDP packets to trigger the kernel's ARP mechanism. It includes a UDP socket (`sock_fd`) with a time-to-live of zero, a delay mechanism (`probe_delay`) to control the frequency of ARP requests to the same IP, and a token bucket rate limiter (`rate_limit`) to manage the rate of outgoing ARP probes. Additionally, it maintains counters (`local_rate_limited_cnt` and `global_rate_limited_cnt`) to track the number of probes suppressed due to local and global rate limits, respectively. This structure is part of a solution to perform neighbor probing with minimal privileges.


---
### fd\_neigh4\_prober\_t
- **Type**: `struct`
- **Members**:
    - `sock_fd`: UDP socket with IP_TTL 0.
    - `probe_delay`: Specifies the delay in ticks for successive ARP requests to the same IP address.
    - `rate_limit`: Token bucket rate limiter on any outgoing ARP probes.
    - `local_rate_limited_cnt`: Metric counter for probes suppressed by local rate limit.
    - `global_rate_limited_cnt`: Metric counter for probes suppressed by global rate limit.
- **Description**: The `fd_neigh4_prober_t` structure is designed to facilitate neighbor probing in a network by sending empty UDP/IP packets to trigger ARP requests indirectly. It contains a UDP socket descriptor, a delay parameter for controlling the frequency of ARP requests to the same IP, a token bucket for rate limiting outgoing probes, and counters for tracking the number of probes suppressed by local and global rate limits. This structure is part of a solution that minimizes required privileges by using UDP packets to prompt the kernel to perform ARP requests.


# Functions

---
### fd\_neigh4\_probe\_rate\_limited<!-- {{#callable:fd_neigh4_probe_rate_limited}} -->
The `fd_neigh4_probe_rate_limited` function attempts to send a network probe while adhering to local and global rate limits.
- **Inputs**:
    - `prober`: A pointer to an `fd_neigh4_prober_t` structure, which contains the state and configuration for probing, including rate limits and counters.
    - `entry`: A pointer to an `fd_neigh4_entry_t` structure, which represents an entry in the neighbor table and includes the timestamp for when probing is next allowed.
    - `ip4_addr`: An unsigned integer representing the IPv4 address to probe, in big-endian format.
    - `now`: A long integer representing the current time, typically obtained from `fd_tickcount()`, used to check against rate limits.
- **Control Flow**:
    - Check if the current time `now` is less than `entry->probe_suppress_until`; if true, increment the local rate limit counter and return -1 to indicate rate limiting.
    - Update `entry->probe_suppress_until` to the current time plus the probe delay to set the next allowable probe time.
    - Attempt to consume a token from the global rate limiter using `fd_token_bucket_consume`; if unsuccessful, increment the global rate limit counter and return -1 to indicate rate limiting.
    - If both rate limits are not exceeded, call [`fd_neigh4_probe`](fd_neigh4_probe.c.driver.md#fd_neigh4_probe) to send the probe and return its result.
- **Output**: Returns 0 if the probe is successfully sent, -1 if either local or global rate limits are hit, or a positive errno value if [`fd_neigh4_probe`](fd_neigh4_probe.c.driver.md#fd_neigh4_probe) fails.
- **Functions called**:
    - [`fd_neigh4_probe`](fd_neigh4_probe.c.driver.md#fd_neigh4_probe)


# Function Declarations (Public API)

---
### fd\_neigh4\_prober\_init<!-- {{#callable_declaration:fd_neigh4_prober_init}} -->
Initialize a neighbor prober for sending UDP packets.
- **Description**: This function initializes a `fd_neigh4_prober_t` object, setting up a UDP socket with specific options to facilitate neighbor probing via ARP requests. It configures the prober with rate limiting parameters for outgoing probe packets and a delay between successive probes to the same IP address. This function should be called before using the prober to send any probe packets, ensuring that the prober is properly configured and ready for operation.
- **Inputs**:
    - `prober`: A pointer to a `fd_neigh4_prober_t` structure that will be initialized. Must not be null. The caller retains ownership.
    - `max_probes_per_second`: A float specifying the maximum number of probes that can be sent per second. Must be a non-negative value.
    - `max_probe_burst`: An unsigned long specifying the maximum burst size of probes that can be sent at once. Must be a non-negative value.
    - `probe_delay_seconds`: A float specifying the minimum delay in seconds between successive probes to the same IP address. Must be a non-negative value.
- **Output**: None
- **See also**: [`fd_neigh4_prober_init`](fd_neigh4_probe.c.driver.md#fd_neigh4_prober_init)  (Implementation)


---
### fd\_neigh4\_prober\_fini<!-- {{#callable_declaration:fd_neigh4_prober_fini}} -->
Closes the socket associated with a neighbor prober.
- **Description**: Use this function to properly close and clean up a `fd_neigh4_prober_t` instance when it is no longer needed. This function should be called to release the resources associated with the prober, specifically the UDP socket used for neighbor probing. It is important to ensure that the prober is not used after this function is called, as the socket file descriptor will be set to an invalid state.
- **Inputs**:
    - `prober`: A pointer to a `fd_neigh4_prober_t` instance. This must not be null, and it should point to a valid prober that was previously initialized. The function will close the socket associated with this prober and set its `sock_fd` to -1.
- **Output**: None
- **See also**: [`fd_neigh4_prober_fini`](fd_neigh4_probe.c.driver.md#fd_neigh4_prober_fini)  (Implementation)


---
### fd\_neigh4\_probe<!-- {{#callable_declaration:fd_neigh4_probe}} -->
Sends an empty UDP packet to trigger ARP requests.
- **Description**: This function is used to initiate the neighbor discovery process by sending an empty UDP packet to a specified IP address on a neighboring subnet. It is particularly useful in environments where minimal privileges are available, as it does not require elevated permissions. The function should be called with a valid prober and entry, and the IP address must be in big-endian format. The 'now' parameter should be a recent tick count. The function updates the entry to suppress further probes for a specified delay period.
- **Inputs**:
    - `prober`: A pointer to an initialized fd_neigh4_prober_t structure. Must not be null. The prober should have a valid UDP socket and configured probe delay.
    - `entry`: A pointer to an fd_neigh4_entry_t structure. Must not be null. This entry will be updated to suppress further probes for a delay period.
    - `ip4_addr`: The IP address of the target neighbor in big-endian format. Must be a valid IPv4 address.
    - `now`: A long integer representing the current tick count. Used to calculate the suppression period for further probes.
- **Output**: Returns 0 on success, or an errno value if the send operation fails.
- **See also**: [`fd_neigh4_probe`](fd_neigh4_probe.c.driver.md#fd_neigh4_probe)  (Implementation)


