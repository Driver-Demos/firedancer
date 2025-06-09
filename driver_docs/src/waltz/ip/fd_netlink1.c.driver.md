# Purpose
This C source code file provides functionality for interacting with the Linux kernel's Netlink protocol, specifically for routing-related messages using the NETLINK_ROUTE protocol. The code is designed to create, manage, and read from Netlink sockets, which are used for communication between user-space processes and the kernel. The file includes functions to initialize and finalize Netlink connections, read messages from a Netlink socket, and iterate over received Netlink messages. It also includes utility functions to convert routing message types and attributes to human-readable strings, enhancing the interpretability of Netlink messages.

The code is structured around several key components: socket creation and management, message reading and iteration, and error handling. The [`fd_nl_create_socket`](#fd_nl_create_socket) and [`fd_nl_close_socket`](#fd_nl_close_socket) functions handle the lifecycle of the Netlink socket, while [`fd_netlink_read_socket`](#fd_netlink_read_socket) is responsible for reading messages from the socket, with robust error handling for common issues like buffer overflows. The iteration over messages is managed by functions like [`fd_netlink_iter_init`](#fd_netlink_iter_init), [`fd_netlink_iter_next`](#fd_netlink_iter_next), and [`fd_netlink_iter_bounds_check`](#fd_netlink_iter_bounds_check), which ensure that messages are processed correctly and safely. The file also defines a global counter `fd_netlink_enobufs_cnt` to track buffer overflow occurrences. This code is intended to be part of a larger system, likely a library, given its focus on providing specific Netlink-related functionality without a `main` function or standalone execution capability.
# Imports and Dependencies

---
- `sys/types.h`
- `sys/socket.h`
- `linux/netlink.h`
- `linux/rtnetlink.h`
- `errno.h`
- `unistd.h`
- `fd_netlink1.h`
- `../../util/fd_util.h`


# Global Variables

---
### fd\_netlink\_enobufs\_cnt
- **Type**: `ulong`
- **Description**: The `fd_netlink_enobufs_cnt` is a global variable of type `ulong` that is used to count the number of times a `recvfrom` call on a netlink socket fails due to the `ENOBUFS` error, which indicates that the kernel's buffer is full and cannot accommodate more data.
- **Use**: This variable is incremented each time a `recvfrom` call returns an `ENOBUFS` error, serving as a counter for such occurrences.


# Functions

---
### fd\_nl\_create\_socket<!-- {{#callable:fd_nl_create_socket}} -->
The `fd_nl_create_socket` function creates a Netlink socket for communication with the kernel's routing subsystem and configures it to support extended acknowledgments.
- **Inputs**: None
- **Control Flow**:
    - The function attempts to create a socket using the `socket` function with parameters `AF_NETLINK`, `SOCK_RAW`, and `NETLINK_ROUTE` to establish a raw Netlink socket for routing messages.
    - If the socket creation fails (i.e., `fd < 0`), it logs a warning message with the error details and returns `-1`.
    - If the socket is successfully created, it sets the `NETLINK_EXT_ACK` option on the socket using `setsockopt` to enable extended acknowledgment messages.
    - If setting the socket option fails, it logs a warning, closes the socket, and returns `-1`.
    - If both the socket creation and option setting are successful, it returns the file descriptor of the created socket.
- **Output**: The function returns the file descriptor of the created Netlink socket on success, or `-1` on failure.


---
### fd\_nl\_close\_socket<!-- {{#callable:fd_nl_close_socket}} -->
The `fd_nl_close_socket` function closes a network socket if the file descriptor is valid.
- **Inputs**:
    - `fd`: An integer representing the file descriptor of the socket to be closed.
- **Control Flow**:
    - Check if the file descriptor `fd` is greater than or equal to 0.
    - If the condition is true, call the `close` function to close the socket associated with the file descriptor.
- **Output**: This function does not return any value.


---
### fd\_netlink\_read\_socket<!-- {{#callable:fd_netlink_read_socket}} -->
The `fd_netlink_read_socket` function reads a datagram from a netlink socket, handling specific errors and returning the length of the received message or a negative error code.
- **Inputs**:
    - `fd`: An integer representing the file descriptor of the netlink socket to read from.
    - `buf`: A pointer to an unsigned character array where the received data will be stored.
    - `buf_sz`: An unsigned long representing the size of the buffer `buf`.
- **Control Flow**:
    - The function enters an infinite loop to continuously attempt to read from the socket.
    - It calls `recvfrom` to read a datagram from the socket into the buffer `buf` with size `buf_sz`.
    - If `recvfrom` returns a length less than or equal to zero, it checks for specific error conditions.
    - If the length is zero, it continues the loop to try reading again.
    - If the error is `EINTR`, it continues the loop to retry the read operation.
    - If the error is `ENOBUFS`, it increments the global counter `fd_netlink_enobufs_cnt` and continues the loop.
    - For other errors, it logs a warning message and returns the negative error code as a long integer.
    - If `recvfrom` succeeds and returns a positive length, it exits the loop and returns the length of the received message.
- **Output**: The function returns a long integer, which is the length of the received message if successful, or a negative error code if an error occurs.


---
### fd\_netlink\_init<!-- {{#callable:fd_netlink_init}} -->
The `fd_netlink_init` function initializes a `fd_netlink_t` structure by creating a netlink socket and setting an initial sequence number.
- **Inputs**:
    - `nl`: A pointer to an `fd_netlink_t` structure that will be initialized.
    - `seq0`: An unsigned integer representing the initial sequence number to be set in the `fd_netlink_t` structure.
- **Control Flow**:
    - Call [`fd_nl_create_socket`](#fd_nl_create_socket) to create a netlink socket and assign the file descriptor to `nl->fd`.
    - Check if the socket creation was unsuccessful (i.e., `nl->fd < 0`), and if so, return `NULL`.
    - Set the sequence number `nl->seq` to the provided `seq0`.
    - Return the pointer to the initialized `fd_netlink_t` structure `nl`.
- **Output**: Returns a pointer to the initialized `fd_netlink_t` structure if successful, or `NULL` if the socket creation fails.
- **Functions called**:
    - [`fd_nl_create_socket`](#fd_nl_create_socket)


---
### fd\_netlink\_fini<!-- {{#callable:fd_netlink_fini}} -->
The `fd_netlink_fini` function closes a netlink socket and resets its file descriptor to -1.
- **Inputs**:
    - `nl`: A pointer to an `fd_netlink_t` structure representing the netlink socket to be finalized.
- **Control Flow**:
    - Call [`fd_nl_close_socket`](#fd_nl_close_socket) with the file descriptor from the `fd_netlink_t` structure to close the socket.
    - Set the file descriptor in the `fd_netlink_t` structure to -1 to indicate it is no longer valid.
    - Return the pointer to the `fd_netlink_t` structure.
- **Output**: Returns the pointer to the `fd_netlink_t` structure that was passed in.
- **Functions called**:
    - [`fd_nl_close_socket`](#fd_nl_close_socket)


---
### fd\_netlink\_iter\_recvmsg<!-- {{#callable:fd_netlink_iter_recvmsg}} -->
The `fd_netlink_iter_recvmsg` function reads a message from a netlink socket into a buffer and updates the iterator's message pointers.
- **Inputs**:
    - `iter`: A pointer to an `fd_netlink_iter_t` structure, which contains the buffer and message pointers for iterating over netlink messages.
    - `netlink`: A pointer to an `fd_netlink_t` structure, which contains the file descriptor for the netlink socket.
- **Control Flow**:
    - Call [`fd_netlink_read_socket`](#fd_netlink_read_socket) with the netlink socket file descriptor, buffer, and buffer size to read a message from the socket.
    - Check if the length of the message read (`len`) is negative, indicating an error; if so, set the iterator's error field to the negative of `len` and return.
    - Set `iter->msg0` to the start of the buffer and `iter->msg1` to the end of the message within the buffer.
- **Output**: The function does not return a value; it updates the `iter` structure with the message data and any error encountered.
- **Functions called**:
    - [`fd_netlink_read_socket`](#fd_netlink_read_socket)


---
### fd\_netlink\_iter\_bounds\_check<!-- {{#callable:fd_netlink_iter_bounds_check}} -->
The `fd_netlink_iter_bounds_check` function checks if the current netlink message in the iterator is within valid bounds and logs warnings and sets an error if it is not.
- **Inputs**:
    - `iter`: A pointer to an `fd_netlink_iter_t` structure representing the current state of the netlink message iterator.
- **Control Flow**:
    - Check if the iterator is done using [`fd_netlink_iter_done`](#fd_netlink_iter_done); if true, return immediately.
    - Retrieve the netlink message header from the current message pointer `msg0` using `fd_type_pun_const`.
    - Check if the message header is out-of-bounds by comparing `msg0 + sizeof(struct nlmsghdr)` with `msg1`; if true, log a warning, set `err` to `EPROTO`, and return.
    - Check if the message length in the header is less than the size of the header itself; if true, log a warning, set `err` to `EPROTO`, and return.
    - Check if the entire message is out-of-bounds by comparing `msg0 + nlh->nlmsg_len` with `msg1`; if true, log a warning, set `err` to `EPROTO`, and return.
- **Output**: The function does not return a value but modifies the `iter` structure by setting the `err` field to `EPROTO` if any bounds check fails.
- **Functions called**:
    - [`fd_netlink_iter_done`](#fd_netlink_iter_done)


---
### fd\_netlink\_iter\_init<!-- {{#callable:fd_netlink_iter_init}} -->
The `fd_netlink_iter_init` function initializes a netlink iterator structure for reading netlink messages from a buffer.
- **Inputs**:
    - `iter`: A pointer to an `fd_netlink_iter_t` structure that will be initialized.
    - `netlink`: A pointer to an `fd_netlink_t` structure representing the netlink socket to read from.
    - `buf`: A pointer to a buffer where netlink messages will be stored.
    - `buf_sz`: The size of the buffer in bytes.
- **Control Flow**:
    - The function initializes the `iter` structure with the provided buffer and its size, setting both `msg0` and `msg1` to point to the start of the buffer.
    - It calls [`fd_netlink_iter_recvmsg`](#fd_netlink_iter_recvmsg) to read a netlink message into the buffer using the netlink socket.
    - It then calls [`fd_netlink_iter_bounds_check`](#fd_netlink_iter_bounds_check) to ensure the message is within the buffer bounds.
- **Output**: Returns a pointer to the initialized `fd_netlink_iter_t` structure.
- **Functions called**:
    - [`fd_netlink_iter_recvmsg`](#fd_netlink_iter_recvmsg)
    - [`fd_netlink_iter_bounds_check`](#fd_netlink_iter_bounds_check)


---
### fd\_netlink\_iter\_done<!-- {{#callable:fd_netlink_iter_done}} -->
The `fd_netlink_iter_done` function checks if a netlink message iterator has completed processing all messages or encountered an error.
- **Inputs**:
    - `iter`: A pointer to a constant `fd_netlink_iter_t` structure representing the netlink message iterator to be checked.
- **Control Flow**:
    - Check if the iterator's error code is non-zero or if the difference between `msg1` and `msg0` is less than the size of a `nlmsghdr` structure; if either condition is true, return 1 indicating completion or error.
    - Cast `msg0` to a `nlmsghdr` structure pointer using `fd_type_pun_const`.
    - Return 1 if the `nlmsg_type` of the `nlmsghdr` structure is `NLMSG_DONE`, indicating the end of a multipart message sequence; otherwise, return 0.
- **Output**: Returns an integer: 1 if the iterator is done processing messages or has encountered an error, otherwise 0.


---
### fd\_netlink\_iter\_next<!-- {{#callable:fd_netlink_iter_next}} -->
The `fd_netlink_iter_next` function advances a netlink message iterator to the next message in a sequence, handling multipart messages and ensuring message bounds are respected.
- **Inputs**:
    - `iter`: A pointer to an `fd_netlink_iter_t` structure representing the current state of the netlink message iterator.
    - `netlink`: A pointer to an `fd_netlink_t` structure representing the netlink socket and its associated state.
- **Control Flow**:
    - Check if the iterator is done using [`fd_netlink_iter_done`](#fd_netlink_iter_done); if so, return the iterator as is.
    - Retrieve the current netlink message header using `fd_type_pun_const`.
    - Check if the current message is part of a multipart message using the `nlmsg_flags` field; if not, set the iterator's error to -1 (EOF) and return.
    - Advance the iterator's message pointer `msg0` by the aligned length of the current message.
    - If the advanced `msg0` pointer exceeds or equals `msg1`, call [`fd_netlink_iter_recvmsg`](#fd_netlink_iter_recvmsg) to receive more messages into the buffer.
    - Perform a bounds check on the iterator using [`fd_netlink_iter_bounds_check`](#fd_netlink_iter_bounds_check) to ensure the next message is within valid bounds.
    - Return the updated iterator.
- **Output**: Returns a pointer to the updated `fd_netlink_iter_t` structure, which may have its error field set if an error occurred.
- **Functions called**:
    - [`fd_netlink_iter_done`](#fd_netlink_iter_done)
    - [`fd_netlink_iter_recvmsg`](#fd_netlink_iter_recvmsg)
    - [`fd_netlink_iter_bounds_check`](#fd_netlink_iter_bounds_check)


---
### fd\_netlink\_rtm\_type\_str<!-- {{#callable:fd_netlink_rtm_type_str}} -->
The function `fd_netlink_rtm_type_str` returns a string representation of a given routing message type integer.
- **Inputs**:
    - `rtm_type`: An integer representing the routing message type, typically defined by constants such as RTN_UNSPEC, RTN_UNICAST, etc.
- **Control Flow**:
    - The function uses a switch statement to match the input integer `rtm_type` against predefined constants representing different routing message types.
    - For each case in the switch statement, if the `rtm_type` matches a known constant, the function returns a corresponding string literal describing the routing type (e.g., "unicast", "broadcast").
    - If the `rtm_type` does not match any known constant, the function defaults to returning the string "unknown".
- **Output**: A constant character pointer to a string that describes the routing message type corresponding to the input integer.


---
### fd\_netlink\_rtattr\_str<!-- {{#callable:fd_netlink_rtattr_str}} -->
The `fd_netlink_rtattr_str` function returns a string representation of a given netlink route attribute type.
- **Inputs**:
    - `rta_type`: An integer representing the netlink route attribute type.
- **Control Flow**:
    - The function uses a switch statement to match the input `rta_type` against predefined constants representing different route attribute types.
    - For each case, if the `rta_type` matches a known constant, the function returns a corresponding string literal that describes the attribute type.
    - Some cases are conditionally compiled based on the presence of certain macros (e.g., `RTA_MFC_STATS`, `RTA_VIA`), allowing for additional attribute types to be recognized if those macros are defined.
    - If the `rta_type` does not match any known constant, the function returns the string "unknown".
- **Output**: A constant character pointer to a string that describes the route attribute type, or "unknown" if the type is not recognized.


