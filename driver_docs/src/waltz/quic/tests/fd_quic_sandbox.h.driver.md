# Purpose
The provided C header file, `fd_quic_sandbox.h`, defines a testing framework for the QUIC protocol, specifically tailored for use with an `fd_quic_t` instance. This framework, encapsulated in the `fd_quic_sandbox_t` structure, is designed to facilitate the setup and analysis of QUIC conversations by managing an instrumented QUIC instance and recording its outgoing packets. The packet capture mechanism is implemented using a ring buffer, which consists of a memory cache (mcache) and a data cache (dcache) pair, allowing the capture of the last N packets sent by the QUIC instance. The sandbox is single-threaded and not designed for concurrent access across different address spaces, simplifying its implementation by removing the need for lockless concurrency patterns typically associated with mcache access.

The file provides a comprehensive API for managing the lifecycle of the `fd_quic_sandbox_t` object, including functions for alignment, footprint calculation, initialization, and deletion. It also includes mock APIs for simulating QUIC connections and sending frames, which are crucial for testing and debugging QUIC implementations. Additionally, the file defines default network parameters, such as IP addresses and ports, and cryptographic keys for encryption, ensuring a controlled and consistent testing environment. The sandbox's ability to inject established connections and send frames directly to the QUIC instance without decryption highlights its utility in testing various aspects of QUIC protocol handling, making it a valuable tool for developers working on QUIC implementations.
# Imports and Dependencies

---
- `../fd_quic.h`
- `../log/fd_quic_log_user.h`
- `../../../tango/mcache/fd_mcache.h`
- `../../../tango/dcache/fd_dcache.h`
- `../../../util/net/fd_ip4.h`


# Global Variables

---
### fd\_quic\_sandbox\_new
- **Type**: `fd_quic_sandbox_t *`
- **Description**: The `fd_quic_sandbox_new` function is responsible for formatting a given memory region for use as an `fd_quic_sandbox_t` object. It takes a memory pointer, a pointer to `fd_quic_limits_t`, a packet count, and a maximum transmission unit (MTU) as parameters. The function returns a pointer to the formatted memory region on success or NULL on failure.
- **Use**: This function is used to initialize a memory region to be used as a QUIC sandbox for testing and analyzing QUIC protocol interactions.


---
### fd\_quic\_sandbox\_init
- **Type**: `function pointer`
- **Description**: The `fd_quic_sandbox_init` is a function that initializes an `fd_quic_sandbox_t` structure to a common state, preparing it for use in testing QUIC protocol interactions. It resets the sandbox's state, including setting the wallclock to zero, initializing the embedded QUIC instance, and clearing the packet capture ring.
- **Use**: This function is used to reset and prepare a QUIC sandbox environment for testing by initializing its state and embedded components.


---
### fd\_quic\_sandbox\_delete
- **Type**: `function pointer`
- **Description**: `fd_quic_sandbox_delete` is a function that takes a pointer to an `fd_quic_sandbox_t` structure and returns a void pointer. It is used to destroy an `fd_quic_sandbox_t` object and release the associated memory back to the caller.
- **Use**: This function is used to clean up and deallocate resources associated with an `fd_quic_sandbox_t` instance.


---
### FD\_PROTOTYPES\_BEGIN
- **Type**: `Macro`
- **Description**: `FD_PROTOTYPES_BEGIN` is a macro used to mark the beginning of a section in the code where function prototypes are declared. It is typically used to organize and separate different sections of code for clarity and maintainability.
- **Use**: This macro is used to delineate the start of a block of function prototypes, aiding in code organization.


---
### fd\_quic\_sandbox\_peer\_ed25519\_keypair
- **Type**: `uchar const[64]`
- **Description**: The `fd_quic_sandbox_peer_ed25519_keypair` is a global constant array of 64 unsigned characters representing the default Ed25519 key pair for the mock peer in the QUIC sandbox environment. The first 32 bytes of this array are the private key, and the last 32 bytes are the encoded public key.
- **Use**: This variable is used to provide a default cryptographic identity for the mock peer in the QUIC sandbox, facilitating secure communication testing.


---
### fd\_quic\_sandbox\_aes128\_key
- **Type**: `uchar const[16]`
- **Description**: The `fd_quic_sandbox_aes128_key` is a global constant array of 16 unsigned characters, representing the default AES-128-GCM secret key used in the QUIC sandbox environment. This key is utilized for symmetric encryption operations within the sandbox and mock peer communications, except for the QUIC initial layer where protocol-specific keys are used.
- **Use**: This variable is used as the default AES-128-GCM encryption key for secure communications in the QUIC sandbox environment.


---
### fd\_quic\_sandbox\_aes128\_iv
- **Type**: `uchar const[12]`
- **Description**: The `fd_quic_sandbox_aes128_iv` is a global constant array of 12 unsigned characters, representing the initialization vector (IV) for AES-128-GCM encryption used in the QUIC sandbox environment. This IV is part of the symmetric encryption setup for the sandbox and mock peer, ensuring secure communication. It is a fixed value used consistently across the sandbox for encryption purposes, except in the QUIC initial layer where protocol-specific keys are used.
- **Use**: This variable is used as the initialization vector for AES-128-GCM encryption in the QUIC sandbox environment.


---
### fd\_quic\_sandbox\_next\_packet
- **Type**: `fd_frag_meta_t const *`
- **Description**: The `fd_quic_sandbox_next_packet` is a function that returns a pointer to the next buffered packet descriptor that the `fd_quic_t` instance might have sent earlier. It advances the read index if a packet is available and returns NULL if no new packet is present. It also logs a warning if packet loss occurs due to the reader being overrun.
- **Use**: This function is used to retrieve the next packet from the buffer in a QUIC sandbox environment, facilitating packet analysis and testing.


# Data Structures

---
### fd\_quic\_sandbox
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the fd_quic_sandbox_t object, set to FD_QUIC_SANDBOX_MAGIC.
    - `quic`: Pointer to the QUIC instance being tested.
    - `pkt_mcache`: Pointer to the captured packet descriptor.
    - `pkt_dcache`: Pointer to the captured packet data.
    - `pkt_mtu`: Maximum payload size for captured packets.
    - `log_rx`: Array for logging received packets.
    - `pkt_seq_r`: Sequence number of the next packet not yet read.
    - `pkt_seq_w`: Sequence number of the next packet to publish.
    - `pkt_chunk`: Index of the publisher chunk.
    - `wallclock`: Simulated time as seen by fd_quic, in nanoseconds.
- **Description**: The fd_quic_sandbox structure is designed to facilitate the setup and analysis of a conversation with an fd_quic instance. It manages an instrumented fd_quic_t instance and records its outgoing packets using a ring buffer composed of mcache and dcache pairs, capturing the last N packets. This structure is single-threaded and cannot be shared across different address spaces, eliminating the need for lockless concurrency patterns. It includes static members that are only modified during creation and deletion, as well as state members that track packet sequence numbers and simulated time. The sandbox is used to test and log QUIC protocol interactions in a controlled environment.


---
### fd\_quic\_sandbox\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the fd_quic_sandbox_t object, set to FD_QUIC_SANDBOX_MAGIC.
    - `quic`: Pointer to the fd_quic_t instance being tested.
    - `pkt_mcache`: Pointer to the captured packet descriptor.
    - `pkt_dcache`: Pointer to the captured packet data.
    - `pkt_mtu`: Maximum payload size for captured packets.
    - `log_rx`: Array for logging received packets.
    - `pkt_seq_r`: Sequence number of the next packet not yet read.
    - `pkt_seq_w`: Sequence number of the next packet to publish.
    - `pkt_chunk`: Index of the publisher chunk.
    - `wallclock`: Simulated time as seen by fd_quic, in nanoseconds.
- **Description**: The fd_quic_sandbox_t structure is designed to facilitate the setup and analysis of a conversation with an fd_quic instance. It manages an instrumented fd_quic_t instance and records outgoing packets using a ring buffer composed of mcache and dcache pairs, capturing the last N packets. This structure is single-threaded and cannot be shared across different address spaces, eliminating the need for lockless concurrency patterns. It includes static members that are only modified during creation or deletion, as well as state members that track packet sequence numbers and simulated time. The structure is not safe for direct variable declaration and should be managed through its lifecycle API.


# Functions

---
### fd\_quic\_sandbox\_packet\_data<!-- {{#callable:fd_quic_sandbox_packet_data}} -->
The `fd_quic_sandbox_packet_data` function returns a pointer to the first byte of packet data in a QUIC sandbox, given a fragment metadata descriptor.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, representing the QUIC sandbox environment.
    - `frag`: A constant pointer to an `fd_frag_meta_t` structure, which contains metadata about a packet fragment.
- **Control Flow**:
    - The function casts the `sandbox` pointer to a `void *` type, ensuring it is aligned by `FD_CHUNK_ALIGN`.
    - It then calls the `fd_chunk_to_laddr` function, passing the aligned base pointer and the `chunk` field from the `frag` structure.
    - The result of `fd_chunk_to_laddr` is returned as the output of the function.
- **Output**: A pointer to the first byte of the packet data, represented as an `uchar *`.


# Function Declarations (Public API)

---
### fd\_quic\_sandbox\_align<!-- {{#callable_declaration:fd_quic_sandbox_align}} -->
Returns the alignment requirement for an fd_quic_sandbox_t object.
- **Description**: Use this function to determine the alignment requirement for memory regions intended to back an fd_quic_sandbox_t object. This is necessary to ensure that the memory is correctly aligned for the data structures used within the sandbox, which may include various internal components such as caches and buffers. Proper alignment is crucial for performance and correctness, especially in systems with strict alignment requirements.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes.
- **See also**: [`fd_quic_sandbox_align`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_align)  (Implementation)


---
### fd\_quic\_sandbox\_footprint<!-- {{#callable_declaration:fd_quic_sandbox_footprint}} -->
Calculates the memory footprint required for a QUIC sandbox.
- **Description**: Use this function to determine the memory size needed to allocate a `fd_quic_sandbox_t` structure, which is used to manage and analyze QUIC conversations. This function should be called before allocating memory for the sandbox to ensure that the parameters provided are valid and sufficient. It returns zero if any of the parameters are invalid, which can be used for quick validation. The function requires the number of packets to be a power of 2 and the maximum transmission unit (MTU) to be specified for accurate calculation.
- **Inputs**:
    - `quic_limits`: A pointer to a `fd_quic_limits_t` structure containing the parameters for the QUIC instance. Must not be null.
    - `pkt_cnt`: The number of packets that the sandbox will buffer. Must be a power of 2.
    - `mtu`: The maximum size of each packet, specified as the size of the UDP datagram excluding Ethernet or IPv4 headers.
- **Output**: Returns the size in bytes of the memory footprint required for the sandbox, or 0 if any parameters are invalid.
- **See also**: [`fd_quic_sandbox_footprint`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_footprint)  (Implementation)


---
### fd\_quic\_sandbox\_new<!-- {{#callable_declaration:fd_quic_sandbox_new}} -->
Formats a memory region for use as an fd_quic_sandbox_t.
- **Description**: This function initializes a memory region to be used as an fd_quic_sandbox_t, which is a structure for setting up and analyzing a conversation with an fd_quic instance. It requires a properly aligned memory region and valid parameters that match those used with fd_quic_sandbox_footprint. The function returns a pointer to the initialized sandbox on success, or NULL if the memory is null, misaligned, or if the parameters are invalid. It logs a warning in case of failure.
- **Inputs**:
    - `mem`: A pointer to the memory region to be formatted. Must not be null and must be aligned according to fd_quic_sandbox_align(). The caller retains ownership.
    - `quic_limits`: A pointer to an fd_quic_limits_t structure containing parameters for the fd_quic_t instance. Must not be null.
    - `pkt_cnt`: The number of packets to buffer, which must be a power of 2. Used to determine the size of the packet capture ring buffer.
    - `mtu`: The maximum size of each packet, representing the UDP datagram size without Ethernet or IPv4 headers. Must be a valid size for the intended use case.
- **Output**: Returns a pointer to the initialized fd_quic_sandbox_t on success, or NULL on failure.
- **See also**: [`fd_quic_sandbox_new`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_new)  (Implementation)


---
### fd\_quic\_sandbox\_init<!-- {{#callable_declaration:fd_quic_sandbox_init}} -->
Initialize the fd_quic_sandbox_t to a default state.
- **Description**: This function resets the provided fd_quic_sandbox_t instance to a default state, preparing it for use in testing QUIC communications. It should be called after creating or joining a sandbox instance and before any operations that require a fresh state. The function sets the sandbox's role, initializes the embedded fd_quic_t instance, and clears the packet capture ring. It also sets default configuration values such as the idle timeout and initializes the local identity key. The function must be called with a valid sandbox pointer and a role indicating whether the sandbox acts as a client or server.
- **Inputs**:
    - `sandbox`: A pointer to an fd_quic_sandbox_t instance that has been properly allocated and joined. The caller retains ownership and must ensure it is not null.
    - `role`: An integer representing the role of the sandbox, which must be either FD_QUIC_ROLE_CLIENT or FD_QUIC_ROLE_SERVER. Invalid values may result in undefined behavior.
- **Output**: Returns a pointer to the initialized fd_quic_sandbox_t on success, or NULL if initialization fails.
- **See also**: [`fd_quic_sandbox_init`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_init)  (Implementation)


---
### fd\_quic\_sandbox\_delete<!-- {{#callable_declaration:fd_quic_sandbox_delete}} -->
Destroys a QUIC sandbox and releases its memory.
- **Description**: Use this function to properly destroy an fd_quic_sandbox_t object and release the associated memory back to the caller. It should be called when the sandbox is no longer needed to ensure that all resources are correctly freed. The function checks for a valid sandbox object by verifying its magic number. If the provided memory is null or the magic number is invalid, the function logs a warning and returns null. This function is intended for single-threaded use and should not be called concurrently with other operations on the same sandbox.
- **Inputs**:
    - `mem`: A pointer to the fd_quic_sandbox_t object to be deleted. Must not be null and must point to a valid sandbox object with the correct magic number. If invalid, the function logs a warning and returns null.
- **Output**: Returns the original memory pointer if the sandbox was successfully deleted, or null if the input was invalid.
- **See also**: [`fd_quic_sandbox_delete`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_delete)  (Implementation)


---
### fd\_quic\_sandbox\_next\_packet<!-- {{#callable_declaration:fd_quic_sandbox_next_packet}} -->
Reads the next available packet from the sandbox's packet capture buffer.
- **Description**: Use this function to retrieve the next packet that was captured by the fd_quic_sandbox_t instance. It returns a pointer to the packet's metadata if a new packet is available, or NULL if there are no new packets. This function should be called in a single-threaded context as fd_quic_sandbox_t is not thread-safe. If the function detects that packets have been lost due to overruns, it logs a warning. This function advances the read index upon successfully retrieving a packet.
- **Inputs**:
    - `sandbox`: A pointer to an fd_quic_sandbox_t instance. This must not be null and should point to a valid, initialized sandbox object. The caller retains ownership of the sandbox.
- **Output**: Returns a pointer to an fd_frag_meta_t structure representing the next packet's metadata, or NULL if no new packet is available.
- **See also**: [`fd_quic_sandbox_next_packet`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_next_packet)  (Implementation)


---
### fd\_quic\_sandbox\_send\_frame<!-- {{#callable_declaration:fd_quic_sandbox_send_frame}} -->
Send a QUIC frame to the sandbox QUIC instance via a specified connection.
- **Description**: This function is used to send a QUIC frame directly to a sandboxed QUIC instance through a specified connection, bypassing decryption and directly invoking frame handling. It is useful for testing and simulating QUIC frame handling in a controlled environment. The function requires valid packet metadata, which is necessary for certain frame handlers. It is important to ensure that the sandbox and connection are properly initialized before calling this function.
- **Inputs**:
    - `sandbox`: A pointer to an initialized fd_quic_sandbox_t structure representing the sandboxed QUIC environment. Must not be null.
    - `conn`: A pointer to an fd_quic_conn_t structure representing the connection through which the frame will be sent. Must not be null.
    - `pkt_meta`: A pointer to an fd_quic_pkt_t structure containing packet metadata required by some frame handlers. Must not be null.
    - `frame_ptr`: A pointer to a buffer containing the wire-encoded QUIC frame to be sent. Must not be null.
    - `frame_sz`: The size of the frame in bytes. Must be greater than zero and should not exceed the maximum allowed frame size.
- **Output**: None
- **See also**: [`fd_quic_sandbox_send_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_frame)  (Implementation)


---
### fd\_quic\_sandbox\_send\_lone\_frame<!-- {{#callable_declaration:fd_quic_sandbox_send_lone_frame}} -->
Send a single QUIC frame with realistic packet metadata.
- **Description**: This function is used to send a single QUIC frame through a specified connection in the sandbox environment. It simulates the sending of a frame in a single QUIC packet, updating the packet number accordingly. This function should be used when you need to test the transmission of a single frame with realistic packet metadata in a controlled environment. Ensure that the frame size does not exceed the maximum transmission unit (MTU) specified in the sandbox.
- **Inputs**:
    - `sandbox`: A pointer to an fd_quic_sandbox_t structure representing the sandbox environment. Must not be null and should be properly initialized before calling this function.
    - `conn`: A pointer to an fd_quic_conn_t structure representing the connection through which the frame will be sent. Must not be null and should be a valid connection within the sandbox.
    - `frame`: A pointer to the frame data to be sent. The data should be in the wire encoding format and must not be null.
    - `frame_sz`: The size of the frame in bytes. Must be less than or equal to the sandbox's pkt_mtu. If the size exceeds pkt_mtu, the function will not proceed with sending the frame.
- **Output**: None
- **See also**: [`fd_quic_sandbox_send_lone_frame`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_lone_frame)  (Implementation)


---
### fd\_quic\_sandbox\_send\_ping\_pkt<!-- {{#callable_declaration:fd_quic_sandbox_send_ping_pkt}} -->
Send a 1-RTT QUIC packet containing only a PING frame.
- **Description**: This function is used to send a QUIC packet with a PING frame over an established connection within a QUIC sandbox environment. It is typically used for testing or maintaining connection liveness. The function requires a valid sandbox and connection, and a packet number to uniquely identify the packet. The sandbox must be properly initialized and the connection must be established before calling this function. The function does not return a value, and any errors during packet encryption or sending are not reported back to the caller.
- **Inputs**:
    - `sandbox`: A pointer to an initialized fd_quic_sandbox_t structure. This must not be null and should represent a valid sandbox environment for QUIC testing.
    - `conn`: A pointer to an established fd_quic_conn_t connection. This must not be null and should represent a valid connection within the sandbox.
    - `pktnum`: An unsigned long integer representing the packet number. This should be a unique identifier for the packet within the connection's context.
- **Output**: None
- **See also**: [`fd_quic_sandbox_send_ping_pkt`](fd_quic_sandbox.c.driver.md#fd_quic_sandbox_send_ping_pkt)  (Implementation)


