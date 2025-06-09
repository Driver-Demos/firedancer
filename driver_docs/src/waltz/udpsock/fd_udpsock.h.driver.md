# Purpose
This C header file defines an interface for a UDP socket driver, `fd_udpsock`, which is designed for debugging purposes rather than production use. The driver operates over localhost using AF_INET SOCK_DGRAM UDP sockets in non-blocking mode and implements the `fd_aio` abstraction, simulating Ethernet and IP headers. The file provides function prototypes for creating, joining, leaving, and deleting `fd_udpsock` objects, as well as setting and retrieving asynchronous I/O callbacks and handling packet transmission and reception. It also includes utility functions for managing memory alignment and footprint, and for configuring the network layer used by the socket. The implementation is noted to be single-threaded, low-performance, and hacky, making it suitable for development and testing rather than deployment.
# Imports and Dependencies

---
- `../fd_waltz_base.h`
- `../aio/fd_aio.h`


# Global Variables

---
### fd\_udpsock\_new
- **Type**: `function pointer`
- **Description**: The `fd_udpsock_new` function is a constructor for creating a new UDP socket memory region with the specified alignment and footprint. It takes a shared memory pointer, maximum transmission unit (MTU), and packet counts for both receiving and transmitting as parameters. The function returns the shared memory pointer on success or NULL on failure.
- **Use**: This function is used to allocate and prepare a memory region for storing an `fd_udpsock_t` object, which is essential for setting up a UDP socket in the application.


---
### fd\_udpsock\_join
- **Type**: `function pointer`
- **Description**: The `fd_udpsock_join` is a function that joins the caller to a given initialized memory region using a specified UDP socket file descriptor. It returns a pointer to an `fd_udpsock_t` structure, which represents the joined UDP socket context.
- **Use**: This function is used to associate a UDP socket file descriptor with a memory region, effectively joining the caller to the UDP socket context for further operations.


---
### fd\_udpsock\_leave
- **Type**: `function pointer`
- **Description**: The `fd_udpsock_leave` is a function that undoes a local join to the `fd_udpsock_t` object, effectively leaving the UDP socket context that was previously joined. It takes a pointer to an `fd_udpsock_t` structure as its parameter and returns a void pointer.
- **Use**: This function is used to leave or detach from a previously joined `fd_udpsock_t` object, cleaning up any local state associated with the join.


---
### fd\_udpsock\_delete
- **Type**: `function pointer`
- **Description**: The `fd_udpsock_delete` is a function that releases ownership of a memory region back to the caller. It is part of the `fd_udpsock` module, which is a sockets-based driver for UDP applications.
- **Use**: This function is used to clean up and release resources associated with a UDP socket memory region.


---
### fd\_udpsock\_get\_tx
- **Type**: `fd_aio_t const *`
- **Description**: The `fd_udpsock_get_tx` function returns a constant pointer to an `fd_aio_t` structure, which is associated with the transmission (tx) operations of a UDP socket. This function is part of the `fd_udpsock` module, which provides a sockets-based driver for UDP applications.
- **Use**: This function is used to retrieve the asynchronous I/O (AIO) interface for handling transmission requests on a given UDP socket.


---
### fd\_udpsock\_set\_layer
- **Type**: `function pointer`
- **Description**: The `fd_udpsock_set_layer` is a function that sets the layer type for a UDP socket, which can be either Ethernet or IP, as indicated by the `layer` parameter. It takes a pointer to an `fd_udpsock_t` structure and a `uint` representing the layer type, and returns a pointer to the `fd_udpsock_t` structure.
- **Use**: This function is used to configure the layer type of a UDP socket within the `fd_udpsock` framework.


# Data Structures

---
### fd\_udpsock\_t
- **Type**: `typedef struct fd_udpsock fd_udpsock_t;`
- **Description**: The `fd_udpsock_t` is a typedef for a structure `fd_udpsock` that represents an unprivileged sockets-based driver for UDP applications. It uses AF_INET SOCK_DGRAM UDP sockets in non-blocking mode and implements the `fd_aio` abstraction, mocking Ethernet and IP headers to operate over localhost. This structure is designed for debugging purposes, compatible with the loopback interface, and supports only single-threaded operation. It is not suitable for production use due to its hacky and low-performance nature.


# Function Declarations (Public API)

---
### fd\_udpsock\_align<!-- {{#callable_declaration:fd_udpsock_align}} -->
Returns the alignment requirement for an fd_udpsock_t object.
- **Description**: Use this function to determine the memory alignment requirement for an fd_udpsock_t object. This is useful when allocating memory for such objects to ensure proper alignment, which is necessary for correct operation and performance. The function is a constant expression and can be used in compile-time calculations.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes for an fd_udpsock_t object.
- **See also**: [`fd_udpsock_align`](fd_udpsock.c.driver.md#fd_udpsock_align)  (Implementation)


---
### fd\_udpsock\_footprint<!-- {{#callable_declaration:fd_udpsock_footprint}} -->
Calculate the memory footprint required for a UDP socket.
- **Description**: This function calculates the memory footprint needed to store a UDP socket object, including its associated packet buffers and metadata, based on the specified maximum transmission unit (MTU) and the number of receive and transmit packets. It should be used when determining the size of the memory region to allocate for a UDP socket. The function returns zero if any of the input parameters are invalid, such as when the MTU is zero or less than the required headroom, or when the packet counts are zero.
- **Inputs**:
    - `mtu`: The maximum transmission unit size in bytes. Must be greater than zero and exceed the defined headroom. If invalid, the function returns zero.
    - `rx_pkt_cnt`: The number of receive packets. Must be greater than zero. If invalid, the function returns zero.
    - `tx_pkt_cnt`: The number of transmit packets. Must be greater than zero. If invalid, the function returns zero.
- **Output**: Returns the calculated memory footprint in bytes, or zero if any input parameters are invalid.
- **See also**: [`fd_udpsock_footprint`](fd_udpsock.c.driver.md#fd_udpsock_footprint)  (Implementation)


---
### fd\_udpsock\_new<!-- {{#callable_declaration:fd_udpsock_new}} -->
Prepares a new memory region for an fd_udpsock_t object.
- **Description**: This function initializes a memory region to store an fd_udpsock_t object, ensuring the region is properly aligned and has the correct footprint based on the specified parameters. It should be called when setting up a new UDP socket driver instance. The function returns the original memory pointer on success, or NULL if the memory is misaligned, the footprint is invalid, or the memory pointer is NULL. This function does not join the caller to the socket; it only prepares the memory.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be initialized. Must not be NULL and must be aligned according to fd_udpsock_align(). The caller retains ownership.
    - `mtu`: The maximum transmission unit size for the socket. Must be a positive value.
    - `rx_pkt_cnt`: The number of receive packets the socket should handle. Must be a non-negative value.
    - `tx_pkt_cnt`: The number of transmit packets the socket should handle. Must be a non-negative value.
- **Output**: Returns the original shmem pointer on success, or NULL if any input validation fails.
- **See also**: [`fd_udpsock_new`](fd_udpsock.c.driver.md#fd_udpsock_new)  (Implementation)


---
### fd\_udpsock\_join<!-- {{#callable_declaration:fd_udpsock_join}} -->
Joins a caller to an initialized memory region using a UDP socket file descriptor.
- **Description**: This function is used to associate a caller with a pre-initialized memory region that represents a UDP socket, using a specified file descriptor. It is essential to ensure that the memory region pointed to by `shsock` is properly initialized before calling this function. The function will configure the socket with the provided file descriptor and extract the socket's address information. It is important to note that the function only supports IPv4 addresses and will return NULL if the address is not IPv4 or if any errors occur during the process. This function is intended for single-threaded operation and is not suitable for production use due to its hacky and low-performance nature.
- **Inputs**:
    - `shsock`: A pointer to an initialized memory region representing a UDP socket. Must not be null. The caller retains ownership.
    - `fd`: A file descriptor for a UDP socket. Must be valid and associated with an IPv4 address. Invalid or non-IPv4 file descriptors will result in a NULL return.
- **Output**: Returns a pointer to the `fd_udpsock_t` object on success, or NULL on failure.
- **See also**: [`fd_udpsock_join`](fd_udpsock.c.driver.md#fd_udpsock_join)  (Implementation)


---
### fd\_udpsock\_leave<!-- {{#callable_declaration:fd_udpsock_leave}} -->
Undo a local join to a UDP socket object.
- **Description**: This function is used to leave or undo a local join to a `fd_udpsock_t` object, effectively marking the socket as inactive by setting its file descriptor to -1. It should be called when the user no longer needs to interact with the UDP socket object, ensuring that resources are properly released. The function must be called with a valid `fd_udpsock_t` pointer that was previously joined. If the provided pointer is null, the function logs a warning and returns null, indicating that no action was taken.
- **Inputs**:
    - `sock`: A pointer to a `fd_udpsock_t` object representing the UDP socket to leave. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns a pointer to the `fd_udpsock_t` object if successful, or null if the input was null.
- **See also**: [`fd_udpsock_leave`](fd_udpsock.c.driver.md#fd_udpsock_leave)  (Implementation)


---
### fd\_udpsock\_delete<!-- {{#callable_declaration:fd_udpsock_delete}} -->
Releases ownership of a memory region back to the caller.
- **Description**: This function is used to release ownership of a memory region that was previously allocated for an fd_udpsock_t object. It should be called when the memory region is no longer needed, allowing the caller to reclaim the memory. The function expects a valid pointer to the shared memory region; if a null pointer is provided, it logs a warning and returns null. This function is part of the cleanup process and should be used to ensure proper memory management in applications using the fd_udpsock API.
- **Inputs**:
    - `shsock`: A pointer to the shared memory region to be released. Must not be null. If null, the function logs a warning and returns null.
- **Output**: Returns the same pointer passed in if it is valid, or null if the input was null.
- **See also**: [`fd_udpsock_delete`](fd_udpsock.c.driver.md#fd_udpsock_delete)  (Implementation)


---
### fd\_udpsock\_set\_rx<!-- {{#callable_declaration:fd_udpsock_set_rx}} -->
Sets the asynchronous I/O handler for receiving data on a UDP socket.
- **Description**: Use this function to assign an asynchronous I/O handler to a UDP socket for handling incoming data. This function should be called after the socket has been properly initialized and joined. It allows the socket to process incoming data using the specified asynchronous I/O handler. The function does not perform any validation on the input parameters, so it is the caller's responsibility to ensure that the provided socket and handler are valid and properly configured.
- **Inputs**:
    - `sock`: A pointer to an initialized `fd_udpsock_t` structure representing the UDP socket. The socket must be valid and properly configured before calling this function. The caller retains ownership of the socket.
    - `aio`: A pointer to a constant `fd_aio_t` structure representing the asynchronous I/O handler for receiving data. This handler must be valid and properly configured. The caller retains ownership of the handler.
- **Output**: None
- **See also**: [`fd_udpsock_set_rx`](fd_udpsock.c.driver.md#fd_udpsock_set_rx)  (Implementation)


---
### fd\_udpsock\_get\_tx<!-- {{#callable_declaration:fd_udpsock_get_tx}} -->
Retrieve the transmit asynchronous I/O interface from a UDP socket.
- **Description**: Use this function to obtain a constant pointer to the transmit asynchronous I/O (AIO) interface associated with a given UDP socket. This is useful when you need to interact with or inspect the transmit AIO operations of the socket. The function expects a valid, non-null pointer to an `fd_udpsock_t` structure that has been properly initialized and joined. It is important to ensure that the socket is in a valid state before calling this function to avoid undefined behavior.
- **Inputs**:
    - `sock`: A pointer to an `fd_udpsock_t` structure representing the UDP socket. This pointer must not be null and should point to a valid, initialized socket object. The caller retains ownership of the socket.
- **Output**: Returns a constant pointer to an `fd_aio_t` structure representing the transmit AIO interface of the specified UDP socket.
- **See also**: [`fd_udpsock_get_tx`](fd_udpsock.c.driver.md#fd_udpsock_get_tx)  (Implementation)


---
### fd\_udpsock\_service<!-- {{#callable_declaration:fd_udpsock_service}} -->
Services asynchronous I/O callbacks for incoming UDP packets.
- **Description**: This function processes incoming UDP packets for the specified socket, creating mock Ethernet and IP headers for each packet, and dispatches them to the associated asynchronous I/O handler. It is designed for use in single-threaded applications and should be called regularly to handle incoming network traffic. The function operates in non-blocking mode and will return immediately if no packets are available. It is not suitable for production use due to its low performance and hacky implementation, but it is useful for debugging purposes, especially when working with the loopback interface.
- **Inputs**:
    - `sock`: A pointer to an initialized `fd_udpsock_t` structure representing the UDP socket to be serviced. Must not be null. The socket should be properly configured and joined before calling this function. Invalid or uninitialized sockets may lead to undefined behavior.
- **Output**: None
- **See also**: [`fd_udpsock_service`](fd_udpsock.c.driver.md#fd_udpsock_service)  (Implementation)


---
### fd\_udpsock\_get\_ip4\_address<!-- {{#callable_declaration:fd_udpsock_get_ip4_address}} -->
Retrieve the IPv4 address associated with a UDP socket.
- **Description**: Use this function to obtain the IPv4 address of a UDP socket represented by the `fd_udpsock_t` structure. This function is useful when you need to know the local IP address that the socket is bound to. It is a pure function, meaning it does not modify the state of the socket or any other system state, and it can be called at any time after the socket has been properly initialized and joined.
- **Inputs**:
    - `sock`: A pointer to a constant `fd_udpsock_t` structure representing the UDP socket. This pointer must not be null, and the socket must be properly initialized and joined before calling this function. If the pointer is invalid, the behavior is undefined.
- **Output**: Returns the IPv4 address as an unsigned integer, representing the local address the socket is bound to.
- **See also**: [`fd_udpsock_get_ip4_address`](fd_udpsock.c.driver.md#fd_udpsock_get_ip4_address)  (Implementation)


---
### fd\_udpsock\_get\_listen\_port<!-- {{#callable_declaration:fd_udpsock_get_listen_port}} -->
Retrieve the UDP listening port of the specified socket.
- **Description**: Use this function to obtain the UDP port number on which the specified socket is configured to listen. This is useful for applications that need to verify or log the port number being used for incoming UDP traffic. The function requires a valid pointer to an initialized `fd_udpsock_t` object. It is a pure function, meaning it does not modify any state and will consistently return the same result when called with the same input.
- **Inputs**:
    - `sock`: A pointer to a constant `fd_udpsock_t` object representing the UDP socket. This pointer must not be null and should point to a valid, initialized socket structure. Passing an invalid or null pointer results in undefined behavior.
- **Output**: Returns the UDP port number as an unsigned integer on which the socket is listening.
- **See also**: [`fd_udpsock_get_listen_port`](fd_udpsock.c.driver.md#fd_udpsock_get_listen_port)  (Implementation)


---
### fd\_udpsock\_set\_layer<!-- {{#callable_declaration:fd_udpsock_set_layer}} -->
Sets the header size for a UDP socket based on the specified network layer.
- **Description**: This function configures the header size of a UDP socket by setting it according to the specified network layer. It should be used when you need to adjust the socket's header size to match either the Ethernet or IP layer. The function must be called with a valid socket object and a valid layer identifier. If an invalid layer is provided, the function logs a warning and returns NULL. This function is intended for use in debugging environments and is not suitable for production use.
- **Inputs**:
    - `sock`: A pointer to an fd_udpsock_t object representing the UDP socket. Must not be null, and the socket should be properly initialized before calling this function.
    - `layer`: An unsigned integer specifying the network layer. Valid values are FD_UDPSOCK_LAYER_ETH for the Ethernet layer and FD_UDPSOCK_LAYER_IP for the IP layer. If an invalid value is provided, the function logs a warning and returns NULL.
- **Output**: Returns the updated fd_udpsock_t pointer on success, or NULL if an invalid layer is specified.
- **See also**: [`fd_udpsock_set_layer`](fd_udpsock.c.driver.md#fd_udpsock_set_layer)  (Implementation)


