# Purpose
This C source code file is part of a larger system that simulates or tests QUIC (Quick UDP Internet Connections) protocol operations within a controlled environment, referred to as a "sandbox." The primary functionality of this file is to manage the lifecycle and operations of a QUIC sandbox, including capturing outgoing packets, initializing and deleting sandbox instances, and handling QUIC connections and packet transmissions. The file defines several static and non-static functions that facilitate the creation, initialization, and management of a QUIC sandbox, including functions to capture packets, send frames, and manage connections. It also includes cryptographic key definitions and utility functions for memory alignment and footprint calculations.

The file is structured to provide a comprehensive set of operations for managing QUIC protocol interactions in a sandboxed environment. It includes functions for capturing packets ([`fd_quic_sandbox_capture_pkt`](#fd_quic_sandbox_capture_pkt)), sending packets ([`fd_quic_sandbox_aio_send`](#fd_quic_sandbox_aio_send)), and managing the lifecycle of the sandbox ([`fd_quic_sandbox_new`](#fd_quic_sandbox_new), [`fd_quic_sandbox_init`](#fd_quic_sandbox_init), [`fd_quic_sandbox_delete`](#fd_quic_sandbox_delete)). Additionally, it defines cryptographic keys and initialization vectors for secure communications, and it provides utility functions for calculating memory alignment and footprint requirements. The file is intended to be part of a larger system, likely a testing or simulation framework, where it can be used to test QUIC protocol implementations in a controlled and isolated manner.
# Imports and Dependencies

---
- `fd_quic_sandbox.h`
- `../fd_quic_private.h`
- `../templ/fd_quic_parse_util.h`


# Global Variables

---
### fd\_quic\_sandbox\_self\_ed25519\_keypair
- **Type**: `uchar const[64]`
- **Description**: The `fd_quic_sandbox_self_ed25519_keypair` is a global constant array of 64 unsigned characters representing an Ed25519 key pair. The first 32 bytes are the private key, and the remaining 32 bytes are the public key.
- **Use**: This key pair is used for cryptographic operations within the QUIC sandbox, likely for identity verification or secure communication.


---
### fd\_quic\_sandbox\_peer\_ed25519\_keypair
- **Type**: `uchar const[64]`
- **Description**: The `fd_quic_sandbox_peer_ed25519_keypair` is a constant array of 64 unsigned characters representing an Ed25519 key pair. The first 32 bytes are the private key, and the remaining 32 bytes are the public key.
- **Use**: This key pair is used for cryptographic operations within the QUIC sandbox environment, likely for peer identity verification or secure communication.


---
### fd\_quic\_sandbox\_aes128\_key
- **Type**: `uchar const[16]`
- **Description**: The `fd_quic_sandbox_aes128_key` is a constant array of 16 unsigned characters, representing a 128-bit AES encryption key. Each byte in the array is set to the hexadecimal value 0x43.
- **Use**: This variable is used as an AES-128 encryption key within the QUIC sandbox environment for cryptographic operations.


---
### fd\_quic\_sandbox\_aes128\_iv
- **Type**: `uchar const[12]`
- **Description**: The `fd_quic_sandbox_aes128_iv` is a global constant array of 12 unsigned characters, initialized to all zeros. It represents an AES-128 Initialization Vector (IV) used in cryptographic operations within the QUIC sandbox environment.
- **Use**: This variable is used as the initialization vector for AES-128 encryption or decryption processes in the QUIC sandbox.


# Functions

---
### fd\_quic\_sandbox\_capture\_pkt<!-- {{#callable:fd_quic_sandbox_capture_pkt}} -->
The `fd_quic_sandbox_capture_pkt` function captures an outgoing packet in a QUIC sandbox environment by storing its metadata and data in the sandbox's memory structures.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure representing the QUIC sandbox environment where the packet will be captured.
    - `pkt`: A constant pointer to an `fd_aio_pkt_info_t` structure containing information about the packet to be captured, including its buffer and size.
- **Control Flow**:
    - Retrieve the current packet sequence number from the sandbox and store it in `seq`.
    - Access the memory cache (`mcache`) and data cache (`dcache`) from the sandbox.
    - Calculate the initial chunk (`chunk0`) and watermark (`wmark`) for the data cache using helper functions.
    - Determine the depth of the memory cache and the size of the packet buffer (`sz`).
    - Convert the current chunk index to a local address (`data`) where the packet data will be stored.
    - Set control flags (`ctl`) for the packet metadata, indicating the start and end of the message without errors.
    - Copy the packet data from the source buffer to the local address in the data cache.
    - Publish the packet metadata to the memory cache using the `fd_mcache_publish` function.
    - Increment the packet sequence number in the sandbox for the next packet capture.
    - Calculate the next chunk index for the data cache and update the sandbox's current chunk index.
- **Output**: The function does not return a value; it modifies the sandbox's state by capturing the packet's data and metadata.


---
### fd\_quic\_sandbox\_aio\_send<!-- {{#callable:fd_quic_sandbox_aio_send}} -->
The `fd_quic_sandbox_aio_send` function captures a batch of outgoing packets in a QUIC sandbox environment and updates the batch index.
- **Inputs**:
    - `ctx`: A pointer to the context, specifically a `fd_quic_sandbox_t` structure, representing the QUIC sandbox environment.
    - `batch`: A pointer to an array of `fd_aio_pkt_info_t` structures, each representing a packet to be captured.
    - `batch_cnt`: An unsigned long integer representing the number of packets in the batch.
    - `opt_batch_idx`: A pointer to an unsigned long integer where the function will store the index of the last processed packet; if NULL, a local variable is used instead.
    - `flush`: An integer flag indicating whether to flush the operation, though it is not used in this function.
- **Control Flow**:
    - Cast the `ctx` pointer to a `fd_quic_sandbox_t` pointer named `sandbox`.
    - Iterate over each packet in the `batch` array using a loop from 0 to `batch_cnt - 1`.
    - For each packet, call [`fd_quic_sandbox_capture_pkt`](#fd_quic_sandbox_capture_pkt) to capture the packet in the sandbox.
    - Check if `opt_batch_idx` is NULL; if so, use a local `_batch_idx` array to store the batch index.
    - Set the value pointed to by `opt_batch_idx` to `batch_cnt`.
    - Ignore the `flush` parameter as it is not used.
    - Return `FD_AIO_SUCCESS` to indicate successful execution.
- **Output**: The function returns an integer status code, `FD_AIO_SUCCESS`, indicating successful execution.
- **Functions called**:
    - [`fd_quic_sandbox_capture_pkt`](#fd_quic_sandbox_capture_pkt)


---
### fd\_quic\_sandbox\_next\_packet<!-- {{#callable:fd_quic_sandbox_next_packet}} -->
The `fd_quic_sandbox_next_packet` function retrieves the next packet from the sandbox's packet metadata cache, handling sequence number discrepancies and updating the read sequence number.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure, which contains the packet metadata cache and sequence information.
- **Control Flow**:
    - Retrieve the packet metadata cache from the sandbox.
    - Calculate the depth of the metadata cache and the current read sequence number.
    - Determine the line index in the cache for the current sequence number.
    - Retrieve the fragment metadata at the calculated line index.
    - Check if the fragment's sequence number is less than the current sequence number; if so, return NULL indicating no new packet is available.
    - Check if the fragment's sequence number is greater than the current sequence number; if so, log a warning about packet loss and update the sequence number to the fragment's sequence number.
    - Increment the read sequence number in the sandbox.
    - Return the fragment metadata.
- **Output**: A pointer to the `fd_frag_meta_t` structure representing the next packet's metadata, or NULL if no new packet is available.


---
### fd\_quic\_sandbox\_now\_cb<!-- {{#callable:fd_quic_sandbox_now_cb}} -->
The `fd_quic_sandbox_now_cb` function retrieves the current wallclock time from a given sandbox context.
- **Inputs**:
    - `context`: A pointer to a `fd_quic_sandbox_t` structure, which contains the wallclock time to be retrieved.
- **Control Flow**:
    - The function casts the `context` pointer to a `fd_quic_sandbox_t` pointer named `sandbox`.
    - It then returns the `wallclock` field from the `sandbox` structure.
- **Output**: The function returns an `ulong` representing the current wallclock time from the sandbox context.


---
### fd\_quic\_sandbox\_align<!-- {{#callable:fd_quic_sandbox_align}} -->
The `fd_quic_sandbox_align` function calculates the maximum alignment requirement for a QUIC sandbox structure and its associated components.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fd_ulong_max` multiple times to determine the maximum alignment requirement among several components.
    - It first checks the alignment of `fd_quic_sandbox_t` using `alignof`.
    - It then compares this with the alignment requirements of `fd_quic_align()`, `fd_mcache_align()`, `fd_dcache_align()`, and `FD_CHUNK_ALIGN`.
    - The function returns the maximum alignment value found.
- **Output**: The function returns an `ulong` representing the maximum alignment requirement for the QUIC sandbox and its components.


---
### fd\_quic\_sandbox\_footprint<!-- {{#callable:fd_quic_sandbox_footprint}} -->
The `fd_quic_sandbox_footprint` function calculates the memory footprint required for a QUIC sandbox based on given limits, packet count, and MTU.
- **Inputs**:
    - `quic_limits`: A pointer to a `fd_quic_limits_t` structure containing the limits for the QUIC configuration.
    - `pkt_cnt`: An unsigned long integer representing the number of packets.
    - `mtu`: An unsigned long integer representing the maximum transmission unit size.
- **Control Flow**:
    - Calculate the alignment requirement for the sandbox using `fd_quic_sandbox_align()`.
    - Calculate the footprint for the QUIC component using `fd_quic_footprint()` with the provided limits.
    - Calculate the footprint for the memory cache using `fd_mcache_footprint()` with the packet count.
    - Calculate the footprint for the data cache using `fd_dcache_footprint()` with the required data size derived from the MTU and packet count.
    - Check if any of the calculated footprints are zero, and return zero if so, indicating an error or invalid configuration.
    - Initialize a layout variable `l` with `FD_LAYOUT_INIT`.
    - Append the sandbox, QUIC, memory cache, and data cache footprints to the layout using `FD_LAYOUT_APPEND()`, ensuring proper alignment for each component.
    - Finalize the layout with `FD_LAYOUT_FINI()` and return the total calculated footprint.
- **Output**: The function returns an unsigned long integer representing the total memory footprint required for the QUIC sandbox, or zero if any component's footprint is invalid.
- **Functions called**:
    - [`fd_quic_sandbox_align`](#fd_quic_sandbox_align)


---
### fd\_quic\_sandbox\_new<!-- {{#callable:fd_quic_sandbox_new}} -->
The `fd_quic_sandbox_new` function initializes a new QUIC sandbox environment by allocating and setting up memory for QUIC, mcache, and dcache components, and returns a pointer to the newly created sandbox structure.
- **Inputs**:
    - `mem`: A pointer to the memory block where the sandbox and its components will be allocated.
    - `quic_limits`: A constant pointer to a structure defining the limits for the QUIC configuration.
    - `pkt_cnt`: An unsigned long integer specifying the number of packets the sandbox can handle.
    - `mtu`: An unsigned long integer representing the maximum transmission unit size for packets.
- **Control Flow**:
    - Check if the `mem` pointer is NULL and log a warning if so, returning NULL.
    - Verify if the `mem` pointer is properly aligned according to the sandbox alignment requirements, logging a warning and returning NULL if not.
    - Calculate the memory footprint required for the sandbox using [`fd_quic_sandbox_footprint`](#fd_quic_sandbox_footprint) and log a warning if the footprint is invalid, returning NULL.
    - Initialize scratch memory allocation with the provided `mem` pointer.
    - Allocate memory for the sandbox structure, QUIC, mcache, and dcache components using the scratch allocator.
    - Set the initial packet sequence number to 0.
    - Initialize the sandbox structure with joined QUIC, mcache, and dcache components, and set the packet MTU.
    - Attempt to join the QUIC log and log a critical error if it fails.
    - Set the sandbox magic number to a predefined constant to indicate successful initialization.
    - Return the pointer to the newly created sandbox.
- **Output**: A pointer to the newly created `fd_quic_sandbox_t` structure, or NULL if initialization fails.
- **Functions called**:
    - [`fd_quic_sandbox_align`](#fd_quic_sandbox_align)
    - [`fd_quic_sandbox_footprint`](#fd_quic_sandbox_footprint)


---
### fd\_quic\_sandbox\_init<!-- {{#callable:fd_quic_sandbox_init}} -->
The `fd_quic_sandbox_init` function initializes a QUIC sandbox environment with specified configurations and prepares it for operation.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure that represents the QUIC sandbox to be initialized.
    - `role`: An integer representing the role of the QUIC configuration, typically indicating whether it is a client or server.
- **Control Flow**:
    - Retrieve the `fd_quic_t` and `fd_quic_config_t` from the sandbox structure.
    - Set the role and other configuration parameters such as idle timeout and initial maximum stream data.
    - Copy the public key from a predefined keypair into the configuration's identity public key field.
    - Initialize the metrics structure to zero.
    - Set up asynchronous I/O transmission using a predefined send function and context.
    - Assign the current time callback function and context to the QUIC callbacks.
    - Attempt to initialize the QUIC instance with `fd_quic_init`; log a warning and return NULL if it fails.
    - Initialize various sandbox fields such as wallclock, packet sequence numbers, and mark the first packet cache entry as unpublished.
    - Calculate the initial packet chunk using `fd_dcache_compact_chunk0`.
    - Advance the log sequence number by a prime number to avoid collisions.
    - Return the initialized sandbox structure.
- **Output**: Returns a pointer to the initialized `fd_quic_sandbox_t` structure, or NULL if initialization fails.


---
### fd\_quic\_sandbox\_delete<!-- {{#callable:fd_quic_sandbox_delete}} -->
The `fd_quic_sandbox_delete` function safely deletes a QUIC sandbox by validating its memory and magic number, resetting its magic number, and cleaning up associated resources.
- **Inputs**:
    - `mem`: A pointer to the `fd_quic_sandbox_t` structure representing the sandbox to be deleted.
- **Control Flow**:
    - Check if the input `mem` is NULL and log a warning if it is, returning NULL.
    - Cast the `mem` pointer to a `fd_quic_sandbox_t` pointer named `sandbox`.
    - Verify that the `magic` field of `sandbox` matches the expected `FD_QUIC_SANDBOX_MAGIC` value, logging a warning and returning NULL if it does not.
    - Use memory fences (`FD_COMPILER_MFENCE`) to ensure memory operations are completed before and after setting the `magic` field to 0.
    - Call `fd_quic_leave` on `sandbox->quic` and pass the result to `fd_quic_delete` to clean up the QUIC instance.
    - Call `fd_mcache_leave` on `sandbox->pkt_mcache` and pass the result to `fd_mcache_delete` to clean up the memory cache.
    - Call `fd_dcache_leave` on `sandbox->pkt_dcache` and pass the result to `fd_dcache_delete` to clean up the data cache.
    - Return the original `mem` pointer.
- **Output**: Returns the original `mem` pointer if the deletion is successful, or NULL if there is an error.


---
### fd\_quic\_sandbox\_new\_conn\_established<!-- {{#callable:fd_quic_sandbox_new_conn_established}} -->
The function `fd_quic_sandbox_new_conn_established` creates and initializes a new QUIC connection within a sandbox environment, simulating an established connection state.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure representing the sandbox environment where the QUIC connection is to be established.
    - `rng`: A pointer to an `fd_rng_t` structure used to generate random numbers for connection IDs.
- **Control Flow**:
    - Retrieve the `fd_quic_t` instance from the sandbox.
    - Generate a random 8-byte connection ID for the local endpoint using the provided RNG.
    - Generate a random 8-byte connection ID for the peer endpoint using the provided RNG and create a `fd_quic_conn_id_t` structure for it.
    - Call `fd_quic_conn_create` to create a new QUIC connection with the generated connection IDs and predefined IP and port addresses.
    - Check if the connection creation failed; if so, log a warning and return `NULL`.
    - Set the connection state to active and mark it as established.
    - Simulate a completed handshake by setting relevant flags and encryption levels.
    - Set the idle timeout and last activity timestamp for the connection.
    - Reset flow control limits for the connection.
    - Return the newly created and initialized connection.
- **Output**: A pointer to the newly created `fd_quic_conn_t` structure representing the established QUIC connection, or `NULL` if the connection creation failed.


---
### fd\_quic\_sandbox\_send\_frame<!-- {{#callable:fd_quic_sandbox_send_frame}} -->
The `fd_quic_sandbox_send_frame` function sends a QUIC frame by bypassing packet processing checks and handling it directly with a specified packet type.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure representing the QUIC sandbox environment.
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection.
    - `pkt_meta`: A pointer to an `fd_quic_pkt_t` structure containing metadata about the packet.
    - `frame_ptr`: A pointer to an array of unsigned characters representing the frame data to be sent.
    - `frame_sz`: An unsigned long integer representing the size of the frame data.
- **Control Flow**:
    - Retrieve the `fd_quic_t` instance from the sandbox structure.
    - Set the packet type to `FD_QUIC_PKT_TYPE_ONE_RTT`, which allows all frame types.
    - Call `fd_quic_handle_v1_frame` with the provided parameters to handle the frame.
    - Check the return code `rc` from `fd_quic_handle_v1_frame`.
    - If `rc` equals `FD_QUIC_PARSE_FAIL`, exit the function.
    - If `rc` is zero or greater than `frame_sz`, log a critical error message.
- **Output**: The function does not return a value; it performs operations and logs errors if necessary.


---
### fd\_quic\_sandbox\_send\_lone\_frame<!-- {{#callable:fd_quic_sandbox_send_lone_frame}} -->
The `fd_quic_sandbox_send_lone_frame` function sends a single QUIC frame as a standalone packet in a sandbox environment, updating the connection's packet number and logging the transmission.
- **Inputs**:
    - `sandbox`: A pointer to the `fd_quic_sandbox_t` structure representing the sandbox environment.
    - `conn`: A pointer to the `fd_quic_conn_t` structure representing the QUIC connection.
    - `frame`: A constant pointer to an array of unsigned characters representing the frame to be sent.
    - `frame_sz`: An unsigned long integer representing the size of the frame in bytes.
- **Control Flow**:
    - Check that the frame size does not exceed the maximum transmission unit (MTU) of the sandbox.
    - Increment the expected packet number for the connection and store it in `pkt_num`.
    - Set the QUIC packet size to the frame size (with a note to consider packetization overhead).
    - Initialize a `fd_quic_pkt_t` structure `pkt_meta` with metadata for the packet, including IP and UDP headers, packet number, receive time, and encryption level.
    - Call [`fd_quic_sandbox_send_frame`](#fd_quic_sandbox_send_frame) to send the frame using the prepared packet metadata.
    - Call `fd_quic_lazy_ack_pkt` to acknowledge the packet lazily.
    - Update the log sequence number from transmission to reception using `fd_quic_log_tx_seq_update`.
- **Output**: The function does not return a value; it performs actions to send a frame and update connection and logging states.
- **Functions called**:
    - [`fd_quic_sandbox_send_frame`](#fd_quic_sandbox_send_frame)


---
### fd\_quic\_sandbox\_send\_ping\_pkt<!-- {{#callable:fd_quic_sandbox_send_ping_pkt}} -->
The `fd_quic_sandbox_send_ping_pkt` function constructs and sends a QUIC PING packet using the provided connection and packet number within a sandbox environment.
- **Inputs**:
    - `sandbox`: A pointer to an `fd_quic_sandbox_t` structure representing the sandbox environment where the packet will be sent.
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the QUIC connection over which the PING packet will be sent.
    - `pktnum`: An unsigned long integer representing the packet number to be used for the PING packet.
- **Control Flow**:
    - Initialize a buffer `pkt_buf` of 256 bytes to construct the packet.
    - Set the first byte of `pkt_buf` using `fd_quic_one_rtt_h0` with parameters for spin, key phase, and packet number length.
    - Copy the connection's own connection ID into `pkt_buf` starting at the second byte.
    - Convert the packet number to network byte order and copy it into `pkt_buf` starting at the ninth byte.
    - Set the thirteenth byte of `pkt_buf` to `0x01` to indicate a PING frame.
    - Zero out the next 18 bytes of `pkt_buf` starting from the fourteenth byte.
    - Retrieve the encryption keys from the connection's keys for the application data encryption level.
    - Encrypt the packet using `fd_quic_crypto_encrypt`, updating the size of the output packet.
    - Create a `fd_quic_pkt_t` structure to represent the packet metadata, including IP and UDP headers.
    - Call `fd_quic_process_quic_packet_v1` to process and send the constructed QUIC packet.
- **Output**: The function does not return a value; it sends a PING packet over the specified QUIC connection.


