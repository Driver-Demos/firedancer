# Purpose
This C header file, `fd_netlink.h`, is designed to facilitate interaction with the Netlink protocol on Linux systems. It provides a structured interface for creating and managing Netlink sockets, which are used for communication between the kernel and user-space processes. The file defines two primary structures: `fd_netlink`, which represents a Netlink session with a socket file descriptor and a sequence number, and `fd_netlink_iter`, which is used for iterating over multipart Netlink messages. The header includes function prototypes for initializing and finalizing Netlink sessions, reading from Netlink sockets, and iterating over Netlink messages. It also includes utility functions for debugging, such as converting route message types and attributes to strings.

The code is intended to be used as part of a larger application or library, providing a specific set of functionalities related to Netlink communication. It is not an executable on its own but rather a component that can be included in other C programs. The header file defines a public API for managing Netlink sessions and processing Netlink messages, making it a crucial part of any system that requires interaction with the Linux kernel's networking stack. The use of macros and conditional compilation ensures that the code is only compiled on Linux systems, reflecting its specialized purpose.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`


# Global Variables

---
### fd\_netlink\_enobufs\_cnt
- **Type**: `ulong`
- **Description**: The `fd_netlink_enobufs_cnt` is a global variable of type `ulong` that counts the number of occurrences of the ENOBUFS error. ENOBUFS is an error indicating that a buffer space is insufficient, typically encountered in network programming when the system is unable to allocate a buffer for a network operation.
- **Use**: This variable is used to track the number of times the ENOBUFS error occurs during netlink operations, providing a metric for error handling and debugging.


---
### fd\_netlink\_init
- **Type**: `fd_netlink_t *`
- **Description**: The `fd_netlink_init` function initializes a new netlink session by creating a netlink socket with explicit acknowledgments. It takes a pointer to an `fd_netlink_t` structure and an initial sequence number `seq0` as parameters. The function returns a pointer to the initialized `fd_netlink_t` structure.
- **Use**: This function is used to set up a netlink session with a specified initial sequence number for communication over netlink sockets.


---
### fd\_netlink\_fini
- **Type**: `function pointer`
- **Description**: The `fd_netlink_fini` is a function that takes a pointer to an `fd_netlink_t` structure and is responsible for closing the netlink socket associated with it. This function is part of the netlink session management, ensuring that resources are properly released when a netlink session is no longer needed.
- **Use**: This function is used to terminate a netlink session by closing the associated socket.


---
### fd\_netlink\_iter\_init
- **Type**: `fd_netlink_iter_t *`
- **Description**: The `fd_netlink_iter_init` function initializes a `fd_netlink_iter_t` structure, which is used to iterate over a sequence of incoming netlink multipart messages. It sets up the iterator with a buffer and its size, preparing it for message processing.
- **Use**: This function is used to prepare a netlink iterator for processing a sequence of netlink messages by initializing its buffer and related parameters.


---
### fd\_netlink\_iter\_next
- **Type**: `fd_netlink_iter_t *`
- **Description**: The `fd_netlink_iter_next` function is a global function that advances a netlink iterator to the next message in a sequence of netlink multipart messages. It operates on an iterator of type `fd_netlink_iter_t` and a netlink session of type `fd_netlink_t`. This function assumes that there are more messages to iterate over, as indicated by the `fd_netlink_iter_done` function.
- **Use**: This function is used to move the iterator to the next netlink message, invalidating any pointers to the current message.


---
### fd\_netlink\_rtm\_type\_str
- **Type**: `function`
- **Description**: The `fd_netlink_rtm_type_str` function is a global function that takes an integer `rtm_type` as an argument and returns a constant character pointer. This function is likely used to convert or map the integer `rtm_type` to a human-readable string representation of the routing message type in a netlink communication context.
- **Use**: This function is used to obtain a string representation of a routing message type based on the integer value provided as `rtm_type`.


---
### fd\_netlink\_rtattr\_str
- **Type**: `function`
- **Description**: The `fd_netlink_rtattr_str` function is a global function that takes an integer `rta_type` as an argument and returns a constant character pointer. This function is likely used to convert or map a netlink route attribute type to a human-readable string representation.
- **Use**: This function is used to obtain a string representation of a netlink route attribute type, aiding in debugging or logging.


# Data Structures

---
### fd\_netlink
- **Type**: `struct`
- **Members**:
    - `fd`: An integer representing the netlink socket.
    - `seq`: An unsigned integer representing the netlink sequence number.
- **Description**: The `fd_netlink` structure is a simple data structure used to manage a netlink socket in a Linux environment. It contains two members: `fd`, which holds the file descriptor for the netlink socket, and `seq`, which is used to track the sequence number of netlink messages. This structure is essential for initializing and managing netlink communication sessions, providing a foundation for sending and receiving messages over the netlink protocol.


---
### fd\_netlink\_t
- **Type**: `struct`
- **Members**:
    - `fd`: An integer representing the netlink socket file descriptor.
    - `seq`: An unsigned integer representing the netlink sequence number.
- **Description**: The `fd_netlink_t` structure is used to manage a netlink session in a Linux environment. It contains a file descriptor for the netlink socket and a sequence number to track netlink messages. This structure is essential for initializing, managing, and closing netlink sessions, as well as for reading from the netlink socket.


---
### fd\_netlink\_iter
- **Type**: `struct`
- **Members**:
    - `buf`: A pointer to an unsigned character buffer used for storing data.
    - `buf_sz`: An unsigned long integer representing the size of the buffer.
    - `msg0`: A pointer to the first message in the buffer.
    - `msg1`: A pointer to the second message in the buffer.
    - `err`: An integer to store error codes encountered during iteration.
- **Description**: The `fd_netlink_iter` structure is designed to facilitate iteration over a sequence of incoming netlink multipart messages. It contains pointers to a buffer and two messages, as well as a buffer size and an error code. This structure is part of a netlink communication system, where it is used to manage and iterate over messages received from a netlink socket, handling errors and maintaining state between iterations.


---
### fd\_netlink\_iter\_t
- **Type**: `struct`
- **Members**:
    - `buf`: A pointer to a buffer used for storing netlink messages.
    - `buf_sz`: The size of the buffer pointed to by buf.
    - `msg0`: A pointer to the current netlink message header being processed.
    - `msg1`: A pointer to the next netlink message header, if available.
    - `err`: An integer representing the error state of the iterator.
- **Description**: The `fd_netlink_iter_t` structure is designed to facilitate the iteration over a sequence of netlink multipart messages. It contains pointers to a buffer and message headers, as well as an error state indicator. This structure is part of a larger API intended to handle netlink communication in a buffered reader style, allowing for efficient processing of incoming netlink messages. The design suggests that it should be used in conjunction with functions that initialize, advance, and check the completion of the iteration process.


# Functions

---
### fd\_netlink\_iter\_msg<!-- {{#callable:fd_netlink_iter_msg}} -->
The function `fd_netlink_iter_msg` returns a pointer to the current netlink message header from an iterator.
- **Inputs**:
    - `iter`: A constant pointer to an `fd_netlink_iter_t` structure, which represents the current state of the netlink message iterator.
- **Control Flow**:
    - The function takes a single argument, `iter`, which is a pointer to a constant `fd_netlink_iter_t` structure.
    - It returns the result of calling `fd_type_pun_const` on `iter->msg0`, which is expected to be a pointer to the current netlink message header.
- **Output**: A constant pointer to a `struct nlmsghdr`, representing the current netlink message header.


---
### fd\_netlink\_iter\_drain<!-- {{#callable:fd_netlink_iter_drain}} -->
The `fd_netlink_iter_drain` function iterates over all remaining netlink messages in an iterator, advancing through each message until completion, and returns the count of messages processed.
- **Inputs**:
    - `iter`: A pointer to an `fd_netlink_iter_t` structure representing the current state of the netlink message iterator.
    - `netlink`: A pointer to an `fd_netlink_t` structure representing the netlink session associated with the iterator.
- **Control Flow**:
    - Initialize a counter `cnt` to zero.
    - Enter a loop that continues as long as `fd_netlink_iter_done(iter)` returns false, indicating there are more messages to process.
    - Within the loop, call `fd_netlink_iter_next(iter, netlink)` to advance the iterator to the next message.
    - Increment the counter `cnt` with each iteration of the loop.
    - Exit the loop when there are no more messages to process.
- **Output**: The function returns an `ulong` representing the number of netlink messages that were processed by the iterator.
- **Functions called**:
    - [`fd_netlink_iter_done`](fd_netlink1.c.driver.md#fd_netlink_iter_done)
    - [`fd_netlink_iter_next`](fd_netlink1.c.driver.md#fd_netlink_iter_next)


# Function Declarations (Public API)

---
### fd\_netlink\_init<!-- {{#callable_declaration:fd_netlink_init}} -->
Initialize a netlink session with a specified sequence number.
- **Description**: This function initializes a netlink session by creating a new netlink socket and setting the initial sequence number for the session. It should be called to set up a netlink session before any netlink communication is performed. The function returns a pointer to the initialized netlink session structure if successful, or NULL if the socket creation fails. This function must be called in a Linux environment as it relies on Linux-specific netlink socket functionality.
- **Inputs**:
    - `netlink`: A pointer to an fd_netlink_t structure that will be initialized. The caller retains ownership and must ensure this pointer is valid and not null.
    - `seq0`: An unsigned integer representing the initial sequence number for the netlink session. This value is used to track netlink message sequences.
- **Output**: Returns a pointer to the initialized fd_netlink_t structure on success, or NULL if the netlink socket could not be created.
- **See also**: [`fd_netlink_init`](fd_netlink1.c.driver.md#fd_netlink_init)  (Implementation)


---
### fd\_netlink\_fini<!-- {{#callable_declaration:fd_netlink_fini}} -->
Closes the netlink socket and resets its file descriptor.
- **Description**: Use this function to properly close a netlink session by closing the associated socket and resetting the file descriptor to an invalid state. This function should be called when the netlink session is no longer needed, ensuring that resources are released and the netlink structure is left in a safe state for potential reuse or deallocation. It is important to ensure that the `fd_netlink_t` structure passed to this function was previously initialized and is valid.
- **Inputs**:
    - `netlink`: A pointer to a `fd_netlink_t` structure representing the netlink session to be closed. The structure must have been previously initialized and must not be null. The function will reset the `fd` field to -1, indicating that the socket is no longer valid.
- **Output**: Returns the pointer to the `fd_netlink_t` structure passed in, with its `fd` field set to -1.
- **See also**: [`fd_netlink_fini`](fd_netlink1.c.driver.md#fd_netlink_fini)  (Implementation)


---
### fd\_netlink\_read\_socket<!-- {{#callable_declaration:fd_netlink_read_socket}} -->
Reads data from a netlink socket, handling specific errors automatically.
- **Description**: This function reads data from a netlink socket specified by the file descriptor. It is designed to handle the EINTR and ENOBUFS errors internally, ensuring that the caller does not need to manage these common issues. The function will block until data is successfully read or an unrecoverable error occurs. It is suitable for use in applications that require robust handling of netlink socket communication, particularly in environments where interruptions or buffer overflows are expected. The function should be called with a valid file descriptor and a sufficiently large buffer to store the incoming data.
- **Inputs**:
    - `fd`: The file descriptor of the netlink socket from which to read. Must be a valid, open socket descriptor.
    - `buf`: A pointer to a buffer where the received data will be stored. Must not be null and should point to a memory area large enough to hold the data.
    - `buf_sz`: The size of the buffer in bytes. Should be large enough to accommodate the expected datagram size.
- **Output**: Returns the number of bytes read on success. On failure, returns a negative value representing the negated errno code.
- **See also**: [`fd_netlink_read_socket`](fd_netlink1.c.driver.md#fd_netlink_read_socket)  (Implementation)


---
### fd\_netlink\_iter\_init<!-- {{#callable_declaration:fd_netlink_iter_init}} -->
Prepares an iterator for processing netlink multipart messages.
- **Description**: This function initializes an iterator to facilitate the processing of a sequence of incoming netlink multipart messages. It should be called before any iteration over netlink messages begins. The function sets up the iterator with a buffer and its size, and prepares it to receive messages from the specified netlink session. It is essential to ensure that the buffer provided is adequately sized to handle the expected message data. This function must be called before using the iterator with other related functions like advancing to the next message or checking for completion.
- **Inputs**:
    - `iter`: A pointer to an fd_netlink_iter_t structure that will be initialized. The caller retains ownership and must ensure it is not null.
    - `netlink`: A pointer to an fd_netlink_t structure representing the netlink session. The caller retains ownership and must ensure it is not null.
    - `buf`: A pointer to a buffer where incoming netlink messages will be stored. The buffer must be large enough to accommodate the expected message data. The caller retains ownership and must ensure it is not null.
    - `buf_sz`: The size of the buffer in bytes. It must be a positive value that reflects the actual size of the buffer provided.
- **Output**: Returns a pointer to the initialized fd_netlink_iter_t structure, which is the same as the iter parameter.
- **See also**: [`fd_netlink_iter_init`](fd_netlink1.c.driver.md#fd_netlink_iter_init)  (Implementation)


---
### fd\_netlink\_iter\_done<!-- {{#callable_declaration:fd_netlink_iter_done}} -->
Check if there are no more netlink messages to iterate over.
- **Description**: Use this function to determine if the iteration over netlink messages is complete. It should be called after initializing the iterator with `fd_netlink_iter_init` and potentially after each call to `fd_netlink_iter_next`. The function returns a non-zero value if there are no more messages to process or if an error condition is detected, such as an invalid message size or a non-zero error state in the iterator.
- **Inputs**:
    - `iter`: A pointer to a `fd_netlink_iter_t` structure representing the current state of the netlink message iteration. Must not be null. The function checks the iterator's error state and message boundaries to determine if iteration is complete.
- **Output**: Returns 0 if there are more messages to iterate over, or 1 if there are no more messages or an error condition is detected.
- **See also**: [`fd_netlink_iter_done`](fd_netlink1.c.driver.md#fd_netlink_iter_done)  (Implementation)


---
### fd\_netlink\_iter\_next<!-- {{#callable_declaration:fd_netlink_iter_next}} -->
Advances the iterator to the next netlink message.
- **Description**: Use this function to move the iterator to the next message in a sequence of netlink multipart messages. It should be called only when there are more messages to process, as indicated by `fd_netlink_iter_done`. This function invalidates any pointers previously obtained from `fd_netlink_iter_msg`. If the current message is not part of a multipart message, the iterator will be marked as having reached the end of the sequence.
- **Inputs**:
    - `iter`: A pointer to an `fd_netlink_iter_t` structure representing the current position in the message sequence. Must not be null and should be initialized properly before calling this function.
    - `netlink`: A pointer to an `fd_netlink_t` structure representing the netlink session. Must not be null and should be initialized properly before calling this function.
- **Output**: Returns a pointer to the updated `fd_netlink_iter_t` structure, which may indicate the end of the message sequence if no further messages are available.
- **See also**: [`fd_netlink_iter_next`](fd_netlink1.c.driver.md#fd_netlink_iter_next)  (Implementation)


---
### fd\_netlink\_rtm\_type\_str<!-- {{#callable_declaration:fd_netlink_rtm_type_str}} -->
Returns a string representation of a routing message type.
- **Description**: Use this function to obtain a human-readable string that describes a given routing message type, identified by the integer parameter. This is useful for debugging or logging purposes when working with netlink routing messages. The function handles a predefined set of routing message types and returns "unknown" for any type not explicitly recognized.
- **Inputs**:
    - `rtm_type`: An integer representing the routing message type. It should correspond to one of the predefined constants like RTN_UNSPEC, RTN_UNICAST, etc. If the value does not match any known type, the function returns "unknown".
- **Output**: A constant string that describes the routing message type, or "unknown" if the type is not recognized.
- **See also**: [`fd_netlink_rtm_type_str`](fd_netlink1.c.driver.md#fd_netlink_rtm_type_str)  (Implementation)


---
### fd\_netlink\_rtattr\_str<!-- {{#callable_declaration:fd_netlink_rtattr_str}} -->
Returns a string representation of a netlink route attribute type.
- **Description**: Use this function to obtain a human-readable string that represents a specific netlink route attribute type, identified by the integer `rta_type`. This is useful for debugging or logging purposes when working with netlink messages. The function maps known route attribute types to their corresponding string names. If the provided `rta_type` does not match any known attribute, the function returns "unknown". This function is available only on Linux systems.
- **Inputs**:
    - `rta_type`: An integer representing the netlink route attribute type. It must correspond to a valid route attribute type defined in the system. If the type is not recognized, the function returns "unknown".
- **Output**: A constant string representing the name of the route attribute type, or "unknown" if the type is not recognized.
- **See also**: [`fd_netlink_rtattr_str`](fd_netlink1.c.driver.md#fd_netlink_rtattr_str)  (Implementation)


