# Purpose
This C header file, `fd_quic_helpers.h`, provides a collection of utility functions and structures designed to facilitate testing and development with QUIC (Quick UDP Internet Connections) protocol implementations. The file is part of a larger test suite and includes various helper functions and data structures that support the creation, configuration, and management of QUIC instances, as well as the simulation of network conditions. It defines several key components, such as `fd_quic_virtual_pair_t` for connecting two local QUIC instances via direct asynchronous I/O (AIO), and `fd_quic_udpsock_t` for managing UDP socket channels. Additionally, it includes functionality for packet capture and logging, as well as network emulation features like packet loss and reordering through `fd_quic_netem_t`.

The file is structured to be included in other C source files, providing a set of public APIs for initializing and managing QUIC test environments. It includes functions for bootstrapping and halting the test environment, creating anonymous QUIC instances, and setting up virtual connections between QUIC instances. The header also defines middleware for Ethernet and UDP socket communication, allowing for flexible network testing scenarios. By offering these utilities, the file serves as a comprehensive toolkit for developers working on QUIC protocol testing, enabling them to simulate various network conditions and configurations efficiently.
# Imports and Dependencies

---
- `../fd_quic.h`
- `../../aio/fd_aio_pcapng.h`
- `../../udpsock/fd_udpsock.h`
- `../../tls/test_tls_helper.h`
- `../../../util/net/fd_eth.h`
- `stdio.h`


# Global Variables

---
### fd\_quic\_test\_pcap
- **Type**: `FILE *`
- **Description**: The `fd_quic_test_pcap` is a global variable of type `FILE *` that is used to handle file operations for packet capture in QUIC tests. It is declared as an external variable, indicating that it is defined elsewhere, likely in a source file associated with the QUIC test suite.
- **Use**: This variable is used to append test traffic to a pcapng 1.0 file, including encryption secrets, as part of the QUIC testing framework.


---
### fd\_quic\_new\_anonymous
- **Type**: `function pointer`
- **Description**: `fd_quic_new_anonymous` is a function that creates an anonymous QUIC instance with specified limits and role. It auto-generates vacant configuration fields except for the role, which can be either server or client. The function returns a pointer to the newly created QUIC instance without performing a local join, and it halts the program on error.
- **Use**: This function is used to initialize a new QUIC instance with specific parameters for testing or other purposes.


---
### fd\_quic\_new\_anonymous\_small
- **Type**: `function pointer`
- **Description**: `fd_quic_new_anonymous_small` is a function that returns a pointer to an `fd_quic_t` structure. It is designed to create an anonymous QUIC instance with predefined small limits for convenience. This function is a simplified version of `fd_quic_new_anonymous`, which allows for quick setup of a QUIC instance without specifying detailed configuration limits.
- **Use**: This function is used to quickly create a QUIC instance with minimal configuration, suitable for testing or scenarios where detailed configuration is unnecessary.


---
### fd\_aio\_eth\_wrap
- **Type**: `function pointer`
- **Description**: The `fd_aio_eth_wrap` is a function that returns a pointer to an `fd_aio_t` structure. It acts as middleware to translate between Layer 2 (Ethernet) and Layer 3 `fd_aio` operations, providing a basic Ethernet layer with predefined MAC addresses.
- **Use**: This function is used to wrap Ethernet frames for transmission over an `fd_aio` interface.


---
### fd\_aio\_eth\_unwrap
- **Type**: `fd_aio_t *`
- **Description**: The `fd_aio_eth_unwrap` is a function that returns a pointer to an `fd_aio_t` structure. It is used to unwrap or translate a Layer 2 (Ethernet) `fd_aio` to a Layer 3 `fd_aio` using the `fd_aio_eth_wrap_t` structure. This function is part of a middleware that provides a simplistic Ethernet layer with hardcoded MAC addresses.
- **Use**: This function is used to obtain the `fd_aio_t` pointer for the unwrapping process in the Ethernet to higher layer translation.


---
### fd\_quic\_udpsock\_create
- **Type**: `fd_quic_udpsock_t *`
- **Description**: The `fd_quic_udpsock_create` function is a global function that creates and initializes a `fd_quic_udpsock_t` structure, which is used to establish a UDP channel over AF_XDP or UDP sockets. It takes parameters for a socket, command-line arguments, a workspace, and a receive asynchronous I/O (AIO) object.
- **Use**: This function is used to set up a UDP socket for QUIC communication, configuring it with the necessary parameters and linking it to the provided workspace and AIO.


---
### fd\_quic\_udpsock\_destroy
- **Type**: `function pointer`
- **Description**: The `fd_quic_udpsock_destroy` is a function pointer that takes a pointer to an `fd_quic_udpsock_t` structure as its argument and returns a void pointer. This function is responsible for destroying or cleaning up resources associated with a QUIC UDP socket encapsulated in the `fd_quic_udpsock_t` structure.
- **Use**: This function is used to release resources and perform cleanup for a QUIC UDP socket when it is no longer needed.


---
### fd\_quic\_netem\_init
- **Type**: `fd_quic_netem_t *`
- **Description**: The `fd_quic_netem_init` function initializes a `fd_quic_netem_t` structure, which is used to simulate network conditions such as packet loss and reordering in an asynchronous I/O (aio) link. It sets up the thresholds for packet dropping and reordering, which are used to control the behavior of the network emulator.
- **Use**: This function is used to configure a `fd_quic_netem_t` instance with specific thresholds for packet drop and reorder, preparing it for use in network emulation scenarios.


# Data Structures

---
### fd\_quic\_virtual\_pair
- **Type**: `struct`
- **Members**:
    - `quic_a`: Pointer to the first QUIC instance in the virtual pair.
    - `quic_b`: Pointer to the second QUIC instance in the virtual pair.
    - `aio_a2b`: Pointer to the first hop of the asynchronous I/O chain from quic_a to quic_b.
    - `aio_b2a`: Pointer to the first hop of the asynchronous I/O chain from quic_b to quic_a.
    - `pcapng_a2b`: Structure for capturing packet data from quic_a to quic_b.
    - `pcapng_b2a`: Structure for capturing packet data from quic_b to quic_a.
- **Description**: The `fd_quic_virtual_pair` structure is designed to facilitate the connection between two local QUIC instances using direct asynchronous I/O (AIO) operations. It includes pointers to the two QUIC instances (`quic_a` and `quic_b`), as well as pointers to the first hop of the AIO chains for communication in both directions (`aio_a2b` and `aio_b2a`). Additionally, it supports optional packet capture through the `pcapng_a2b` and `pcapng_b2a` members, which are used to log packet data for traffic between the two QUIC instances.


---
### fd\_quic\_virtual\_pair\_t
- **Type**: `struct`
- **Members**:
    - `quic_a`: Pointer to the first QUIC instance in the virtual pair.
    - `quic_b`: Pointer to the second QUIC instance in the virtual pair.
    - `aio_a2b`: Pointer to the first hop of the asynchronous I/O chain from quic_a to quic_b.
    - `aio_b2a`: Pointer to the first hop of the asynchronous I/O chain from quic_b to quic_a.
    - `pcapng_a2b`: Packet capture configuration for traffic from quic_a to quic_b.
    - `pcapng_b2a`: Packet capture configuration for traffic from quic_b to quic_a.
- **Description**: The `fd_quic_virtual_pair_t` structure is designed to facilitate the connection between two local QUIC instances using direct asynchronous I/O (AIO) operations. It includes pointers to the two QUIC instances (`quic_a` and `quic_b`), as well as pointers to the AIO chains (`aio_a2b` and `aio_b2a`) that manage the data flow between them. Additionally, it supports optional packet capture through the `pcapng_a2b` and `pcapng_b2a` members, which allow for logging of the traffic between the two QUIC instances. This structure is particularly useful in testing environments where simulating network conditions and capturing traffic is necessary.


---
### fd\_aio\_eth\_wrap\_t
- **Type**: `struct`
- **Members**:
    - `wrap_self`: An fd_aio_t instance representing the self-reference for wrapping operations.
    - `unwrap_self`: An fd_aio_t instance representing the self-reference for unwrapping operations.
    - `wrap_next`: An fd_aio_t instance pointing to the next layer in the wrapping chain.
    - `unwrap_next`: An fd_aio_t instance pointing to the next layer in the unwrapping chain.
    - `template`: An fd_eth_hdr_t structure serving as a template for Ethernet headers.
- **Description**: The `fd_aio_eth_wrap_t` structure is a middleware component designed to facilitate the translation between Layer 2 (Ethernet) and Layer 3 (network layer) in an asynchronous I/O (fd_aio) context. It provides a basic Ethernet layer with predefined MAC addresses, allowing for the encapsulation and decapsulation of network packets as they traverse through different layers of the network stack. The structure includes self-references for both wrapping and unwrapping operations, as well as pointers to the next layers in the chain, ensuring seamless integration and processing of network data.


---
### fd\_quic\_udpsock\_t
- **Type**: `struct`
- **Members**:
    - `type`: An integer representing the type of UDP socket, with a defined constant for UDPSOCK.
    - `listen_ip`: An unsigned integer representing the IP address to listen on.
    - `listen_port`: An unsigned short representing the port number to listen on.
    - `wksp`: A pointer to the workspace that owns the objects associated with this structure.
    - `udpsock`: A union containing a structure with a pointer to a UDP socket and its file descriptor.
    - `aio`: A constant pointer to an asynchronous I/O structure.
- **Description**: The `fd_quic_udpsock_t` structure is a helper for creating a UDP communication channel, either over AF_XDP or traditional UDP sockets. It includes fields for specifying the type of socket, the IP address and port to listen on, and a workspace handle for managing associated resources. The structure also contains a union for handling UDP socket specifics, such as the socket pointer and file descriptor, and a pointer to an asynchronous I/O structure for managing I/O operations.


---
### fd\_quic\_netem\_reorder\_buf
- **Type**: `struct`
- **Members**:
    - `sz`: Represents the size of the data currently stored in the buffer.
    - `buf`: A fixed-size array of 2048 unsigned characters used to store data.
- **Description**: The `fd_quic_netem_reorder_buf` structure is designed to manage a buffer that can hold up to 2048 bytes of data, with a field to track the current size of the data stored. This structure is likely used in network emulation scenarios where packet reordering is simulated, as part of the `fd_quic_netem` system that injects packet loss and reordering into an asynchronous I/O link.


---
### fd\_quic\_netem
- **Type**: `struct`
- **Members**:
    - `local`: Represents the local asynchronous I/O (AIO) interface for the network emulator.
    - `dst`: Points to the destination asynchronous I/O (AIO) interface for the network emulator.
    - `thresh_drop`: Specifies the threshold probability for packet drop in the network emulator.
    - `thresh_reorder`: Specifies the threshold probability for packet reordering in the network emulator.
    - `reorder_buf`: An array of two reorder buffers used to store packets temporarily for reordering.
    - `reorder_mru`: Indicates the most recently used reorder buffer index.
- **Description**: The `fd_quic_netem` structure is designed to simulate network conditions such as packet loss and reordering in a QUIC (Quick UDP Internet Connections) environment. It contains fields for local and destination AIO interfaces, thresholds for packet drop and reordering, and a pair of reorder buffers to manage packet reordering. This structure is used to inject network impairments into an AIO link, allowing for testing and evaluation of QUIC implementations under various network conditions.


---
### fd\_quic\_netem\_t
- **Type**: `struct`
- **Members**:
    - `local`: An fd_aio_t structure representing the local asynchronous I/O endpoint.
    - `dst`: A constant pointer to an fd_aio_t structure representing the destination asynchronous I/O endpoint.
    - `thresh_drop`: A float representing the threshold for packet drop probability.
    - `thresh_reorder`: A float representing the threshold for packet reordering probability.
    - `reorder_buf`: An array of two fd_quic_netem_reorder_buf structures used for buffering packets for reordering.
    - `reorder_mru`: An integer indicating the most recently used reorder buffer.
- **Description**: The `fd_quic_netem_t` structure is designed to simulate network conditions by injecting packet loss and reordering into an asynchronous I/O link. It contains fields for managing local and destination I/O endpoints, thresholds for packet drop and reordering probabilities, and buffers for handling packet reordering. This structure is useful for testing and simulating network behavior in QUIC protocol implementations.


# Function Declarations (Public API)

---
### fd\_quic\_test\_boot<!-- {{#callable_declaration:fd_quic_test_boot}} -->
Boots the QUIC test environment with optional packet capture.
- **Description**: This function initializes the QUIC test environment and should be called after the system has been booted using fd_boot(). It processes command-line arguments to optionally enable packet capture by specifying a file path with the --pcap option. If the --pcap option is provided, the function opens the specified file for appending and sets up a mechanism to flush the capture data upon program exit. This function is essential for setting up the test environment correctly, especially when packet capture is required for debugging or analysis.
- **Inputs**:
    - `pargc`: A pointer to the argument count, typically passed from the main function. It must not be null, and the value it points to should be non-negative.
    - `pargv`: A pointer to the argument vector, typically passed from the main function. It must not be null, and the array it points to should contain valid C strings.
- **Output**: None
- **See also**: [`fd_quic_test_boot`](fd_quic_test_helpers.c.driver.md#fd_quic_test_boot)  (Implementation)


---
### fd\_quic\_test\_halt<!-- {{#callable_declaration:fd_quic_test_halt}} -->
Halts the QUIC test environment.
- **Description**: This function should be called to halt the QUIC test environment, typically before calling fd_halt(). It ensures that any ongoing packet capture is properly closed and resources are released. This function is a counterpart to fd_quic_test_boot and is necessary for clean shutdown of the test environment.
- **Inputs**: None
- **Output**: None
- **See also**: [`fd_quic_test_halt`](fd_quic_test_helpers.c.driver.md#fd_quic_test_halt)  (Implementation)


---
### fd\_quic\_config\_anonymous<!-- {{#callable_declaration:fd_quic_config_anonymous}} -->
Configures a QUIC instance with default settings for anonymous use.
- **Description**: This function sets up a QUIC instance with default configuration values suitable for anonymous operation. It should be called to initialize a QUIC instance before it is used in a test environment. The function assigns default values to various configuration parameters and sets up default callback functions. It is important to ensure that the `quic` parameter is a valid pointer to a `fd_quic_t` structure before calling this function.
- **Inputs**:
    - `quic`: A pointer to an `fd_quic_t` structure that will be configured. Must not be null, and the caller retains ownership.
    - `role`: An integer representing the role of the QUIC instance, typically indicating server or client. The specific values and their meanings should be consistent with the rest of the QUIC configuration.
- **Output**: None
- **See also**: [`fd_quic_config_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_config_anonymous)  (Implementation)


---
### fd\_quic\_config\_test\_signer<!-- {{#callable_declaration:fd_quic_config_test_signer}} -->
Configures a QUIC instance with a test signer context.
- **Description**: This function sets up a QUIC instance to use a specified test signer context, which is useful in testing environments where a specific signing behavior is required. It updates the QUIC configuration with the public key and signing context provided. This function should be called when you need to configure a QUIC instance for testing purposes with a specific signing context. Ensure that the QUIC instance is properly initialized before calling this function.
- **Inputs**:
    - `quic`: A pointer to an initialized `fd_quic_t` instance. This parameter must not be null, as it represents the QUIC instance to be configured.
    - `sign_ctx`: A pointer to an `fd_tls_test_sign_ctx_t` structure containing the test signing context. This parameter must not be null, as it provides the public key and signing function to be used in the QUIC configuration.
- **Output**: None
- **See also**: [`fd_quic_config_test_signer`](fd_quic_test_helpers.c.driver.md#fd_quic_config_test_signer)  (Implementation)


---
### fd\_quic\_new\_anonymous<!-- {{#callable_declaration:fd_quic_new_anonymous}} -->
Creates an anonymous QUIC instance with specified limits and role.
- **Description**: This function initializes a new anonymous QUIC instance with the provided configuration limits and role, which can be either server or client. It automatically generates any vacant configuration fields except for the role. The function must be called with a valid workspace and random number generator. It returns a QUIC instance that is not locally joined, and the caller is responsible for managing and cleaning up the QUIC instance. The function halts the program if an error occurs during the creation process.
- **Inputs**:
    - `wksp`: A pointer to an fd_wksp_t workspace where the QUIC instance will be allocated. Must not be null.
    - `limits`: A pointer to an fd_quic_limits_t structure specifying the configuration limits for the QUIC instance. Must not be null.
    - `role`: An integer specifying the role of the QUIC instance, either as a server or client. Valid values are typically defined elsewhere in the API.
    - `rng`: A pointer to an fd_rng_t random number generator used for generating configuration fields. Must not be null.
- **Output**: Returns a pointer to the newly created fd_quic_t QUIC instance. The instance is not locally joined, and the caller is responsible for cleanup.
- **See also**: [`fd_quic_new_anonymous`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous)  (Implementation)


---
### fd\_quic\_new\_anonymous\_small<!-- {{#callable_declaration:fd_quic_new_anonymous_small}} -->
Creates an anonymous QUIC instance with small default limits.
- **Description**: This function is used to create a new anonymous QUIC instance with predefined small limits for testing or lightweight applications. It is a convenience function that sets up a QUIC instance with minimal resource allocation, making it suitable for scenarios where resource usage needs to be minimized. The function must be called with a valid workspace and random number generator. The caller is responsible for managing the lifecycle of the returned QUIC instance, including cleanup.
- **Inputs**:
    - `wksp`: A pointer to an fd_wksp_t workspace object. This must be a valid workspace where the QUIC instance will be allocated. The caller retains ownership and must ensure it remains valid for the lifetime of the QUIC instance.
    - `role`: An integer specifying the role of the QUIC instance, typically as a server or client. The exact values and their meanings should be consistent with the broader application context.
    - `rng`: A pointer to an fd_rng_t random number generator. This must be a valid and initialized RNG object. The caller retains ownership and must ensure it remains valid for the lifetime of the QUIC instance.
- **Output**: Returns a pointer to a newly created fd_quic_t instance configured with small limits. The caller is responsible for cleanup and ensuring the instance is properly managed.
- **See also**: [`fd_quic_new_anonymous_small`](fd_quic_test_helpers.c.driver.md#fd_quic_new_anonymous_small)  (Implementation)


---
### fd\_quic\_virtual\_pair\_init<!-- {{#callable_declaration:fd_quic_virtual_pair_init}} -->
Sets up an asynchronous I/O loop between two QUIC instances.
- **Description**: This function initializes a virtual pair to facilitate communication between two local QUIC instances using asynchronous I/O. It should be called once per thread to establish a direct or packet-captured connection between the two QUIC instances, depending on whether packet capture is enabled. The function must be called before any communication between the QUIC instances is attempted, and it ensures that any resources allocated for the virtual pair are released upon halting.
- **Inputs**:
    - `pair`: A pointer to an fd_quic_virtual_pair_t structure that will be initialized. The caller must ensure this pointer is valid and points to allocated memory.
    - `quicA`: A pointer to the first fd_quic_t instance to be connected. Must not be null.
    - `quicB`: A pointer to the second fd_quic_t instance to be connected. Must not be null.
- **Output**: None
- **See also**: [`fd_quic_virtual_pair_init`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_init)  (Implementation)


---
### fd\_quic\_virtual\_pair\_fini<!-- {{#callable_declaration:fd_quic_virtual_pair_fini}} -->
Destroys an aio loop between two QUIC objects.
- **Description**: This function is used to finalize and clean up a virtual pair of QUIC objects that were previously connected via an asynchronous I/O loop. It should be called when the virtual pair is no longer needed, ensuring that any resources allocated during the initialization are properly released. This function must be called after the virtual pair has been initialized and used, and it is important to ensure that no further operations are performed on the pair after this function is called.
- **Inputs**:
    - `pair`: A pointer to an fd_quic_virtual_pair_t structure representing the virtual pair of QUIC objects. This parameter must not be null, and it is expected that the pair has been previously initialized using fd_quic_virtual_pair_init. The function will handle the cleanup of resources associated with this pair.
- **Output**: None
- **See also**: [`fd_quic_virtual_pair_fini`](fd_quic_test_helpers.c.driver.md#fd_quic_virtual_pair_fini)  (Implementation)


---
### fd\_quic\_test\_cb\_tls\_keylog<!-- {{#callable_declaration:fd_quic_test_cb_tls_keylog}} -->
Logs TLS key information for QUIC testing.
- **Description**: This function is used to log TLS key information during QUIC testing, specifically when packet capture is enabled. It should be called whenever a TLS key log line needs to be recorded. The function appends the provided key log line to a pcapng file if packet capture is active, as indicated by the presence of a non-null global file pointer. This is useful for debugging and analyzing encrypted traffic in QUIC tests.
- **Inputs**:
    - `quic_ctx`: A context pointer for the QUIC instance. This parameter is not used in the function and can be set to any value.
    - `line`: A non-null, null-terminated string containing the TLS key log line to be recorded. The function does not modify this string.
- **Output**: None
- **See also**: [`fd_quic_test_cb_tls_keylog`](fd_quic_test_helpers.c.driver.md#fd_quic_test_cb_tls_keylog)  (Implementation)


---
### fd\_aio\_eth\_wrap<!-- {{#callable_declaration:fd_aio_eth_wrap}} -->
Wraps an fd_aio_eth_wrap_t structure to provide Ethernet layer functionality.
- **Description**: This function is used to wrap an fd_aio_eth_wrap_t structure, setting up the necessary context and function pointers to enable Ethernet layer operations. It is typically called when you need to translate between Layer 2 (Ethernet) and Layer 3 (network) fd_aio operations, providing a basic Ethernet layer with predefined MAC addresses. The function must be called with a valid fd_aio_eth_wrap_t structure, and it returns a pointer to the fd_aio_t structure that represents the wrapped Ethernet layer.
- **Inputs**:
    - `wrap`: A pointer to an fd_aio_eth_wrap_t structure that will be wrapped. This structure must be properly initialized before calling the function. The caller retains ownership of this structure, and it must not be null.
- **Output**: Returns a pointer to the fd_aio_t structure within the provided fd_aio_eth_wrap_t, representing the wrapped Ethernet layer.
- **See also**: [`fd_aio_eth_wrap`](fd_quic_test_helpers.c.driver.md#fd_aio_eth_wrap)  (Implementation)


---
### fd\_aio\_eth\_unwrap<!-- {{#callable_declaration:fd_aio_eth_unwrap}} -->
Returns the unwrapped fd_aio_t from an fd_aio_eth_wrap_t structure.
- **Description**: Use this function to access the unwrapped fd_aio_t from an fd_aio_eth_wrap_t structure, which is part of a middleware that translates between Ethernet and higher-level protocols. This function is typically used when you need to interact with the underlying fd_aio_t after it has been wrapped for Ethernet processing. Ensure that the fd_aio_eth_wrap_t structure is properly initialized before calling this function.
- **Inputs**:
    - `wrap`: A pointer to an fd_aio_eth_wrap_t structure. This must be a valid, non-null pointer to a properly initialized fd_aio_eth_wrap_t instance. The function assumes ownership of the pointer remains with the caller.
- **Output**: Returns a pointer to the fd_aio_t structure contained within the provided fd_aio_eth_wrap_t.
- **See also**: [`fd_aio_eth_unwrap`](fd_quic_test_helpers.c.driver.md#fd_aio_eth_unwrap)  (Implementation)


---
### fd\_quic\_udpsock\_create<!-- {{#callable_declaration:fd_quic_udpsock_create}} -->
Creates a UDP socket for QUIC communication with specified parameters.
- **Description**: This function initializes a UDP socket for QUIC communication, using command-line arguments to configure parameters such as MTU, receive and transmit depths, and the listening IP and port. It should be called when setting up a QUIC environment that requires UDP socket communication. The function expects a valid workspace and receive AIO configuration, and it modifies the provided socket structure to reflect the created socket's properties. If any errors occur during socket creation or binding, the function returns NULL.
- **Inputs**:
    - `_sock`: A pointer to a pre-allocated fd_quic_udpsock_t structure that will be initialized by the function. The caller retains ownership.
    - `pargc`: A pointer to the argument count, which will be modified as command-line arguments are processed. Must not be null.
    - `pargv`: A pointer to the argument vector, which will be modified as command-line arguments are processed. Must not be null.
    - `wksp`: A pointer to a valid fd_wksp_t workspace used for memory allocation. Must not be null.
    - `rx_aio`: A pointer to a constant fd_aio_t structure for receive AIO configuration. Must not be null.
- **Output**: Returns a pointer to the initialized fd_quic_udpsock_t structure on success, or NULL on failure.
- **See also**: [`fd_quic_udpsock_create`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_create)  (Implementation)


---
### fd\_quic\_udpsock\_destroy<!-- {{#callable_declaration:fd_quic_udpsock_destroy}} -->
Destroys a QUIC UDP socket and releases associated resources.
- **Description**: Use this function to properly destroy a QUIC UDP socket and release any resources associated with it. This function should be called when the UDP socket is no longer needed to ensure that all resources are freed and any open file descriptors are closed. It is important to pass a valid pointer to a `fd_quic_udpsock_t` structure that was previously initialized. If the provided pointer is null, the function will return null without performing any operations.
- **Inputs**:
    - `udpsock`: A pointer to a `fd_quic_udpsock_t` structure representing the UDP socket to be destroyed. Must not be null. The function will handle null pointers by returning null without performing any operations.
- **Output**: Returns the pointer to the `fd_quic_udpsock_t` structure that was destroyed, or null if the input was null.
- **See also**: [`fd_quic_udpsock_destroy`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_destroy)  (Implementation)


---
### fd\_quic\_udpsock\_service<!-- {{#callable_declaration:fd_quic_udpsock_service}} -->
Services a QUIC UDP socket.
- **Description**: This function is used to service a QUIC UDP socket, ensuring that any necessary operations or maintenance tasks are performed on the socket. It should be called when the application needs to process or handle events related to the UDP socket. The function expects a valid `fd_quic_udpsock_t` structure that has been properly initialized and configured. It is important to ensure that the `udpsock` parameter is not null and that the `type` field of the `fd_quic_udpsock_t` structure is set to `FD_QUIC_UDPSOCK_TYPE_UDPSOCK` before calling this function.
- **Inputs**:
    - `udpsock`: A pointer to a constant `fd_quic_udpsock_t` structure representing the UDP socket to be serviced. The `type` field must be set to `FD_QUIC_UDPSOCK_TYPE_UDPSOCK`. The caller retains ownership and must ensure this pointer is not null.
- **Output**: None
- **See also**: [`fd_quic_udpsock_service`](fd_quic_test_helpers.c.driver.md#fd_quic_udpsock_service)  (Implementation)


---
### fd\_quic\_netem\_init<!-- {{#callable_declaration:fd_quic_netem_init}} -->
Initialize a QUIC network emulator with specified packet drop and reorder thresholds.
- **Description**: This function sets up a QUIC network emulator by initializing the provided `fd_quic_netem_t` structure with specified thresholds for packet dropping and reordering. It should be used when you need to simulate network conditions that involve packet loss and reordering in a QUIC test environment. The function must be called with a valid `fd_quic_netem_t` structure, and the caller is responsible for managing the memory of this structure. The thresholds are used to determine the likelihood of packet loss and reordering during network emulation.
- **Inputs**:
    - `netem`: A pointer to an `fd_quic_netem_t` structure that will be initialized. Must not be null, and the caller retains ownership.
    - `thres_drop`: A float representing the threshold for packet dropping. It determines the probability of a packet being dropped during emulation.
    - `thres_reorder`: A float representing the threshold for packet reordering. It determines the probability of a packet being reordered during emulation.
- **Output**: Returns the initialized `fd_quic_netem_t` pointer provided as input.
- **See also**: [`fd_quic_netem_init`](fd_quic_test_helpers.c.driver.md#fd_quic_netem_init)  (Implementation)


---
### fd\_quic\_netem\_send<!-- {{#callable_declaration:fd_quic_netem_send}} -->
Implements packet sending with optional loss and reordering for QUIC network emulation.
- **Description**: This function is used to send a batch of packets through a QUIC network emulator context, potentially introducing packet loss and reordering based on predefined thresholds. It is typically used in testing environments to simulate network conditions such as packet drops and reordering. The function processes each packet in the batch individually, deciding whether to drop, reorder, or send it based on random chance and the thresholds set in the context. It must be called with a valid context initialized for network emulation, and the batch of packets to be sent. The function returns a success status, and the caller should handle any necessary cleanup or further processing.
- **Inputs**:
    - `ctx`: A pointer to an fd_quic_netem_t structure, representing the network emulation context. Must be properly initialized before calling this function.
    - `batch`: A pointer to an array of fd_aio_pkt_info_t structures, each representing a packet to be sent. The caller retains ownership of the data.
    - `batch_cnt`: The number of packets in the batch array. Must be greater than zero.
    - `opt_batch_idx`: An optional pointer to a ulong, which is unused in this function. Can be null.
    - `flush`: An integer flag indicating whether to flush the send operation. Non-zero values typically indicate a flush.
- **Output**: Returns an integer status code, typically indicating success (e.g., FD_AIO_SUCCESS).
- **See also**: [`fd_quic_netem_send`](fd_quic_test_helpers.c.driver.md#fd_quic_netem_send)  (Implementation)


