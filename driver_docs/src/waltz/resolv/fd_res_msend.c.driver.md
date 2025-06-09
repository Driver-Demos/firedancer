# Purpose
This C source code file implements a network communication utility focused on sending and receiving DNS queries over both UDP and TCP protocols. The primary function, [`fd_res_msend_rc`](#fd_res_msend_rc), is designed to handle multiple DNS queries simultaneously, sending them to configured nameservers and processing the responses. The code is structured to handle both IPv4 and IPv6 addresses, with provisions for environments that may lack IPv6 support. It uses non-blocking sockets and the `poll` system call to manage multiple file descriptors efficiently, allowing it to handle multiple queries and responses concurrently.

The file includes several static helper functions, such as [`cleanup`](#cleanup), [`mtime`](#mtime), [`start_tcp`](#start_tcp), and [`step_mh`](#step_mh), which assist in managing socket connections, measuring time, initiating TCP connections, and adjusting message headers, respectively. The code is robust in handling various network conditions, including server failures and truncated responses, by implementing retries and fallback mechanisms. It is designed to be part of a larger system, likely a DNS resolver library, and does not define public APIs or external interfaces directly. Instead, it provides internal functionality that can be integrated into a broader application or library for DNS resolution tasks.
# Imports and Dependencies

---
- `sys/socket.h`
- `netinet/in.h`
- `netinet/tcp.h`
- `netdb.h`
- `arpa/inet.h`
- `stdint.h`
- `string.h`
- `poll.h`
- `time.h`
- `unistd.h`
- `errno.h`
- `pthread.h`
- `syscall.h`
- `fd_lookup.h`


# Functions

---
### cleanup<!-- {{#callable:cleanup}} -->
The `cleanup` function iterates over an array of `pollfd` structures and closes any file descriptors that are open.
- **Inputs**:
    - `pfd`: A pointer to an array of `struct pollfd`, which contains file descriptors and event flags for polling.
- **Control Flow**:
    - The function starts a loop with an index `i` initialized to 0.
    - The loop continues as long as the file descriptor `pfd[i].fd` is greater than or equal to -1.
    - Within the loop, it checks if the file descriptor `pfd[i].fd` is greater than or equal to 0.
    - If the file descriptor is valid (i.e., greater than or equal to 0), it calls the `syscall` function with `SYS_close` to close the file descriptor `pfd[i].fd`.
- **Output**: The function does not return any value; it performs cleanup by closing file descriptors.


---
### mtime<!-- {{#callable:mtime}} -->
The `mtime` function retrieves the current time in milliseconds using either the monotonic or real-time clock.
- **Inputs**: None
- **Control Flow**:
    - Declare a `timespec` structure `ts` to hold the time values.
    - Attempt to get the current time using the `CLOCK_MONOTONIC` clock; if this fails and the error is `ENOSYS`, indicating the system does not support this clock, fall back to using `CLOCK_REALTIME`.
    - Convert the seconds and nanoseconds from the `timespec` structure to milliseconds and return the result as an unsigned long.
- **Output**: The function returns the current time in milliseconds as an unsigned long integer.


---
### start\_tcp<!-- {{#callable:start_tcp}} -->
The `start_tcp` function initiates a non-blocking TCP connection with the option for TCP Fast Open, sending an initial message if possible.
- **Inputs**:
    - `pfd`: A pointer to a `struct pollfd` which will be used to monitor the file descriptor for events.
    - `family`: An integer representing the address family (e.g., AF_INET for IPv4, AF_INET6 for IPv6).
    - `sa`: A pointer to a socket address structure containing the address to connect to.
    - `sl`: A `socklen_t` value representing the size of the socket address structure.
    - `q`: A pointer to a buffer containing the data to be sent immediately after the connection is established.
    - `ql`: An integer representing the length of the data in the buffer `q`.
- **Control Flow**:
    - Initialize a `msghdr` structure to prepare the message to be sent, including the address and data buffers.
    - Create a non-blocking TCP socket with the specified address family and set it in the `pollfd` structure for monitoring output events.
    - Attempt to enable TCP Fast Open on the socket using `setsockopt`.
    - If TCP Fast Open is enabled, send the message using `sendmsg` with the `MSG_FASTOPEN` flag, and adjust the `pollfd` events based on the result.
    - If the message is sent successfully, return the number of bytes sent; if the operation is in progress, return 0.
    - If TCP Fast Open is not enabled or fails, attempt a regular `connect` call to establish the connection.
    - If the connection is successful or in progress, return 0.
    - If the connection fails, close the socket, set the file descriptor in `pollfd` to -1, and return -1.
- **Output**: The function returns the number of bytes sent if successful, 0 if the connection is in progress, or -1 if the connection fails.


---
### step\_mh<!-- {{#callable:step_mh}} -->
The `step_mh` function adjusts the `iovec` structures within a `msghdr` to skip the first `n` bytes of data.
- **Inputs**:
    - `mh`: A pointer to a `msghdr` structure that contains message header information, including an array of `iovec` structures.
    - `n`: A `size_t` value representing the number of bytes to skip in the `iovec` structures.
- **Control Flow**:
    - The function enters a loop that continues as long as there are `iovec` structures remaining (`mh->msg_iovlen` is non-zero) and the number of bytes to skip (`n`) is greater than or equal to the length of the current `iovec` (`mh->msg_iov->iov_len`).
    - Within the loop, it subtracts the length of the current `iovec` from `n`, advances the `msg_iov` pointer to the next `iovec`, and decrements the `msg_iovlen` counter.
    - If there are no more `iovec` structures left (`mh->msg_iovlen` is zero), the function returns immediately.
    - If there are still `iovec` structures left, it adjusts the base pointer of the current `iovec` to skip `n` bytes and reduces the length of the current `iovec` by `n`.
- **Output**: The function does not return a value; it modifies the `msghdr` structure in place to reflect the skipped bytes.


---
### fd\_res\_msend\_rc<!-- {{#callable:fd_res_msend_rc}} -->
The `fd_res_msend_rc` function sends multiple DNS queries to configured nameservers and processes their responses, handling both UDP and TCP protocols.
- **Inputs**:
    - `nqueries`: The number of DNS queries to be sent.
    - `queries`: An array of pointers to the DNS query data.
    - `qlens`: An array of integers representing the lengths of each query.
    - `answers`: An array of pointers where the DNS response data will be stored.
    - `alens`: An array of integers where the lengths of each response will be stored.
    - `asize`: The maximum size of each answer buffer.
    - `conf`: A pointer to a `fd_resolvconf_t` structure containing the resolver configuration, including nameservers and timeout settings.
- **Control Flow**:
    - Initialize socket and address structures for communication with nameservers.
    - Iterate over the configured nameservers to set up their addresses.
    - Open a UDP socket and bind it to a local address, handling IPv6 support if necessary.
    - Enter a loop that continues until all queries have received responses or the timeout is reached.
    - Send queries to all configured nameservers in parallel if the retry interval has elapsed.
    - Use `poll` to wait for responses or until it's time to retry sending queries.
    - Process incoming responses, matching them to the corresponding queries and storing the results.
    - Handle server failures by retrying queries and fall back to TCP if responses are truncated.
    - Close sockets and clean up resources after processing all queries.
- **Output**: Returns 0 on successful processing of all queries, with the lengths of responses stored in `alens`. If a query fails, its corresponding length in `alens` is set to 0.
- **Functions called**:
    - [`mtime`](#mtime)
    - [`start_tcp`](#start_tcp)
    - [`step_mh`](#step_mh)
    - [`cleanup`](#cleanup)


