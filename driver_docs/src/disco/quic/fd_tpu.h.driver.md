# Purpose
The provided C header file, `fd_tpu.h`, defines the server-side components of the TPU/QUIC protocol, which is used for submitting transactions to a block producer. This file is part of a larger system that handles transaction processing in a blockchain environment, specifically for the Solana blockchain, as indicated by the reference to the Solana Foundation's specifications. The primary functionality of this file is to manage the reassembly of fragmented transaction data received over QUIC streams. It defines structures and functions for handling transaction fragments, reassembling them into complete transactions, and managing their lifecycle from reception to publication for downstream processing.

Key components of this file include the `fd_tpu_reasm_t` structure, which manages the reassembly process, and the `fd_tpu_reasm_slot_t` structure, which represents individual reassembly slots. The file provides a comprehensive API for constructing, managing, and interacting with these reassembly structures, including functions for creating and deleting reassembly objects, querying and preparing reassembly slots, appending data fragments, and publishing completed transactions. The file also defines constants and macros for managing error codes, state transitions, and memory alignment requirements. The design ensures efficient handling of transaction data, with mechanisms for flow control, eviction policies, and data integrity, making it a critical component for high-performance transaction processing in a distributed ledger system.
# Imports and Dependencies

---
- `../fd_disco_base.h`


# Global Variables

---
### fd\_tpu\_reasm\_new
- **Type**: `function pointer`
- **Description**: `fd_tpu_reasm_new` is a function that initializes a memory region for use as a TPU reassembly object. It takes parameters such as a pointer to shared memory, depth, maximum reassembly transactions, origin ID, and a data cache pointer.
- **Use**: This function is used to set up a TPU reassembly object in memory, preparing it to handle incoming data fragments for transaction processing.


---
### fd\_tpu\_reasm\_join
- **Type**: `fd_tpu_reasm_t *`
- **Description**: The `fd_tpu_reasm_join` is a function that returns a pointer to an `fd_tpu_reasm_t` structure. This function is used to join or attach to a TPU reassembly instance using a shared memory region specified by the `shreasm` parameter.
- **Use**: This function is used to initialize and obtain a handle to a TPU reassembly instance for processing incoming data fragments in the TPU/QUIC protocol.


---
### fd\_tpu\_reasm\_leave
- **Type**: `function pointer`
- **Description**: `fd_tpu_reasm_leave` is a function that takes a pointer to an `fd_tpu_reasm_t` structure and returns a void pointer. This function is likely used to perform cleanup or disassociation tasks related to the `fd_tpu_reasm_t` instance, such as releasing resources or resetting state.
- **Use**: This function is used to leave or disassociate from an `fd_tpu_reasm_t` instance, typically as part of a cleanup or shutdown process.


---
### fd\_tpu\_reasm\_delete
- **Type**: `function pointer`
- **Description**: `fd_tpu_reasm_delete` is a function that takes a pointer to a shared reassembly object (`shreasm`) and deletes it, effectively cleaning up any resources associated with the TPU/QUIC reassembly process.
- **Use**: This function is used to delete a TPU/QUIC reassembly object, freeing its resources.


---
### fd\_tpu\_reasm\_query
- **Type**: `fd_tpu_reasm_slot_t *`
- **Description**: The `fd_tpu_reasm_query` function is a global function that returns a pointer to an `fd_tpu_reasm_slot_t` structure. It is used to query a reassembly slot based on a given connection UID and stream ID within a `fd_tpu_reasm_t` reassembly context.
- **Use**: This function is used to locate and return a specific reassembly slot for a given connection and stream, facilitating the management of data fragments in the TPU/QUIC protocol.


---
### fd\_tpu\_reasm\_prepare
- **Type**: `fd_tpu_reasm_slot_t *`
- **Description**: The `fd_tpu_reasm_prepare` function is a global function that returns a pointer to an `fd_tpu_reasm_slot_t` structure. It is used to prepare a reassembly slot for a new QUIC stream, identified by the connection UID and stream ID, within the TPU/QUIC protocol server-side implementation.
- **Use**: This function is used to allocate and prepare a slot for reassembling incoming data fragments from a QUIC stream.


# Data Structures

---
### fd\_tpu\_reasm\_key
- **Type**: `struct`
- **Members**:
    - `conn_uid`: A unique identifier for the connection, with ULONG_MAX indicating an invalid value.
    - `stream_id`: A 48-bit field representing the stream identifier.
    - `sz`: A 14-bit field representing the size of the data.
    - `state`: A 2-bit field representing the state of the reassembly process.
- **Description**: The `fd_tpu_reasm_key` structure is used to uniquely identify a reassembly process in the TPU/QUIC protocol. It contains fields for a connection unique identifier (`conn_uid`), a stream identifier (`stream_id`), the size of the data (`sz`), and the state of the reassembly (`state`). This structure is crucial for managing the reassembly of fragmented transactions over QUIC streams, ensuring that each fragment is correctly associated with its corresponding transaction.


---
### fd\_tpu\_reasm\_key\_t
- **Type**: `struct`
- **Members**:
    - `conn_uid`: A unique identifier for the connection, with ULONG_MAX indicating an invalid connection.
    - `stream_id`: A 48-bit field representing the stream identifier within the connection.
    - `sz`: A 14-bit field representing the size of the data.
    - `state`: A 2-bit field representing the state of the reassembly process.
- **Description**: The `fd_tpu_reasm_key_t` structure is a compound data type used to uniquely identify and manage the state of a transaction reassembly process in the TPU/QUIC protocol. It contains fields for a connection identifier, a stream identifier, the size of the data, and the current state of the reassembly. This structure is crucial for handling fragmented transactions that are transmitted over multiple packets, ensuring that each fragment is correctly associated with its corresponding transaction and reassembled in the correct order.


---
### fd\_tpu\_reasm\_slot
- **Type**: `struct`
- **Members**:
    - `k`: A compound key represented as a single struct member of type `fd_tpu_reasm_key_t`.
    - `lru_prev`: An unsigned integer representing the previous slot in the least recently used (LRU) list.
    - `lru_next`: An unsigned integer representing the next slot in the least recently used (LRU) list.
    - `chain_next`: An unsigned integer used to link slots in a chain, possibly for hash table collision resolution.
    - `tsorig_comp`: An unsigned integer representing a timestamp or a component related to the original timestamp.
- **Description**: The `fd_tpu_reasm_slot` structure is designed to hold a message reassembly buffer for the TPU/QUIC protocol, specifically for handling fragmented transactions. It includes a compound key for identifying the transaction, and fields for managing the slot's position in a least recently used (LRU) list and a chain, which are used for efficient slot management and eviction policies. The structure is aligned to 16 bytes for performance optimization.


---
### fd\_tpu\_reasm\_slot\_t
- **Type**: `struct`
- **Members**:
    - `k`: A compound key structure containing connection UID, stream ID, size, and state.
    - `lru_prev`: An unsigned integer representing the previous slot in the LRU (Least Recently Used) list.
    - `lru_next`: An unsigned integer representing the next slot in the LRU list.
    - `chain_next`: An unsigned integer used for chaining slots together.
    - `tsorig_comp`: An unsigned integer representing the original timestamp component.
- **Description**: The `fd_tpu_reasm_slot_t` structure is a message reassembly buffer used in the TPU/QUIC protocol for handling fragmented transactions. It is carefully designed to be 32 bytes in size and includes a compound key for identifying the connection and stream, as well as fields for managing the slot's position in a Least Recently Used (LRU) list and chaining slots together. This structure is integral to the reassembly process, allowing for efficient management and retrieval of transaction fragments.


---
### fd\_tpu\_reasm
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to identify the structure, expected to be equal to FD_TPU_REASM_MAGIC.
    - `slots_off`: Offset to the memory region for slots.
    - `pub_slots_off`: Offset to the memory region for published slots.
    - `map_off`: Offset to the memory region for the map.
    - `dcache`: Pointer to the first data cache byte in the local address space.
    - `depth`: The depth of the memory cache (mcache).
    - `burst`: The maximum number of concurrent reassemblies allowed.
    - `head`: Index of the least recent reassembly.
    - `tail`: Index of the most recent reassembly.
    - `slot_cnt`: The count of slots available.
    - `orig`: The Tango origin ID for this reassembly structure.
- **Description**: The `fd_tpu_reasm` structure is designed to handle the reassembly of fragmented transactions in the TPU/QUIC protocol, which is used for submitting transactions to a block producer. It manages an array of message reassembly buffers, known as slots, and coordinates the transition of these slots through various states (FREE, BUSY, PUB) as transactions are prepared, canceled, or published. The structure includes offsets to memory regions for slots and published slots, a pointer to a data cache, and fields for managing the depth of the memory cache, the maximum number of concurrent reassemblies, and the order of reassemblies. It is aligned according to `FD_TPU_REASM_ALIGN` and is identified by a magic number `FD_TPU_REASM_MAGIC`.


---
### fd\_tpu\_reasm\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity of the structure.
    - `slots_off`: Offset to the memory region containing reassembly slots.
    - `pub_slots_off`: Offset to the memory region containing published slots.
    - `map_off`: Offset to the memory region containing the map.
    - `dcache`: Pointer to the first data cache byte in local address space.
    - `depth`: Depth of the mcache, indicating the number of entries it can hold.
    - `burst`: Maximum number of concurrent reassemblies allowed.
    - `head`: Index of the least recent reassembly slot.
    - `tail`: Index of the most recent reassembly slot.
    - `slot_cnt`: Count of the slots currently in use.
    - `orig`: Tango origin ID of the reassembly structure.
- **Description**: The `fd_tpu_reasm_t` structure is designed to handle the reassembly of fragmented transactions in the TPU/QUIC protocol, which is used for submitting transactions to a block producer. It manages an array of reassembly buffers, known as slots, and coordinates the flow of data from QUIC streams to downstream consumers. The structure includes fields for managing memory offsets, cache pointers, and reassembly state, ensuring efficient handling of transaction fragments and maintaining the integrity of the reassembly process. It supports flow control and eviction policies to manage concurrent streams and prevent data loss.


# Functions

---
### fd\_tpu\_reasm\_slots\_laddr<!-- {{#callable:fd_tpu_reasm_slots_laddr}} -->
The `fd_tpu_reasm_slots_laddr` function calculates the local address of the reassembly slots within a `fd_tpu_reasm_t` structure.
- **Inputs**:
    - `reasm`: A pointer to a `fd_tpu_reasm_t` structure, which contains information about the reassembly process, including the offset to the slots.
- **Control Flow**:
    - The function takes a pointer to a `fd_tpu_reasm_t` structure as input.
    - It calculates the address of the reassembly slots by adding the `slots_off` offset to the base address of the `reasm` structure.
    - The result is cast to a pointer of type `fd_tpu_reasm_slot_t *`, which is then returned.
- **Output**: A pointer to the first `fd_tpu_reasm_slot_t` in the reassembly slots array, calculated based on the offset within the `fd_tpu_reasm_t` structure.


---
### fd\_tpu\_reasm\_slots\_laddr\_const<!-- {{#callable:fd_tpu_reasm_slots_laddr_const}} -->
The function `fd_tpu_reasm_slots_laddr_const` returns a constant pointer to the reassembly slots of a given TPU reassembly structure.
- **Inputs**:
    - `reasm`: A constant pointer to an `fd_tpu_reasm_t` structure, representing the TPU reassembly context.
- **Control Flow**:
    - The function takes a constant pointer to an `fd_tpu_reasm_t` structure as input.
    - It calculates the address of the reassembly slots by adding the `slots_off` offset to the base address of the `reasm` structure.
    - The function returns a constant pointer to the calculated address, cast to `fd_tpu_reasm_slot_t const *`.
- **Output**: A constant pointer to the first reassembly slot in the TPU reassembly structure, of type `fd_tpu_reasm_slot_t const *`.


---
### fd\_tpu\_reasm\_pub\_slots\_laddr<!-- {{#callable:fd_tpu_reasm_pub_slots_laddr}} -->
The function `fd_tpu_reasm_pub_slots_laddr` calculates the local address of the public slots memory region within a TPU reassembly structure.
- **Inputs**:
    - `reasm`: A pointer to an `fd_tpu_reasm_t` structure, which represents a TPU reassembly object.
- **Control Flow**:
    - The function takes a pointer to an `fd_tpu_reasm_t` structure as input.
    - It calculates the address of the public slots by adding the `pub_slots_off` offset to the base address of the `reasm` structure.
    - The calculated address is cast to a pointer to `uint` and returned.
- **Output**: A pointer to `uint`, representing the local address of the public slots memory region within the given TPU reassembly structure.


---
### fd\_tpu\_reasm\_req\_data\_sz<!-- {{#callable:fd_tpu_reasm_req_data_sz}} -->
The `fd_tpu_reasm_req_data_sz` function calculates the required data size for TPU reassembly based on the given depth and maximum reassembly slots.
- **Inputs**:
    - `depth`: The number of entries in the target mcache, assumed to be in the range [1, 2^31).
    - `reasm_max`: The maximum number of transactions that can be reassembled concurrently, also assumed to be in the range [1, 2^31).
- **Control Flow**:
    - The function takes two input parameters: `depth` and `reasm_max`.
    - It calculates the required data size by adding `depth` and `reasm_max`, and then multiplying the result by `FD_TPU_REASM_MTU`.
    - The function returns the calculated value.
- **Output**: The function returns an unsigned long integer representing the required data size for TPU reassembly.


---
### fd\_tpu\_reasm\_acquire<!-- {{#callable:fd_tpu_reasm_acquire}} -->
The `fd_tpu_reasm_acquire` function attempts to acquire a reassembly slot for a given connection and stream, preparing a new slot if none is found.
- **Inputs**:
    - `reasm`: A pointer to an `fd_tpu_reasm_t` structure, representing the reassembly context.
    - `conn_uid`: An unsigned long integer representing the unique identifier for the connection.
    - `stream_id`: An unsigned long integer representing the identifier for the stream within the connection.
    - `tspub`: A long integer representing the timestamp for publication.
- **Control Flow**:
    - Call [`fd_tpu_reasm_query`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_query) with `reasm`, `conn_uid`, and `stream_id` to check if a reassembly slot already exists.
    - If a slot is found, return it immediately.
    - If no slot is found, call [`fd_tpu_reasm_prepare`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_prepare) with `reasm`, `conn_uid`, `stream_id`, and `tspub` to prepare a new slot.
    - Return the newly prepared slot.
- **Output**: Returns a pointer to an `fd_tpu_reasm_slot_t` structure, which is the acquired or newly prepared reassembly slot.
- **Functions called**:
    - [`fd_tpu_reasm_query`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_query)
    - [`fd_tpu_reasm_prepare`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_prepare)


---
### fd\_tpu\_reasm\_key\_hash<!-- {{#callable:fd_tpu_reasm_key_hash}} -->
The `fd_tpu_reasm_key_hash` function computes a hash value for a given TPU reassembly key using a seed and a series of bitwise and arithmetic operations.
- **Inputs**:
    - `k`: A pointer to a `fd_tpu_reasm_key_t` structure containing the connection UID and stream ID to be hashed.
    - `seed`: An unsigned long integer used as the initial seed for the hash computation.
- **Control Flow**:
    - Initialize the hash value `h` by adding the seed, constant `C5`, and 16.
    - Extract `conn_uid` and `stream_id` from the key `k` into `w0` and `w1`, respectively.
    - For `w0`: multiply by `C2`, rotate left by 31 bits, multiply by `C1`, XOR with `h`, rotate `h` left by 27 bits, multiply by `C1`, and add `C4`.
    - Repeat the same operations for `w1` as done for `w0`.
    - Perform a series of bitwise XOR and multiplication operations on `h` to finalize the hash value.
- **Output**: The function returns an unsigned long integer representing the computed hash value.


# Function Declarations (Public API)

---
### fd\_tpu\_reasm\_align<!-- {{#callable_declaration:fd_tpu_reasm_align}} -->
Return the required memory alignment for a TPU reassembly structure.
- **Description**: This function provides the alignment requirement for a memory region to be used as a TPU reassembly structure. It is essential to ensure that any memory allocated for a TPU reassembly object meets this alignment requirement to avoid undefined behavior. This function is typically used during the setup or initialization phase when preparing memory for TPU reassembly operations.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes for a TPU reassembly structure.
- **See also**: [`fd_tpu_reasm_align`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_align)  (Implementation)


---
### fd\_tpu\_reasm\_footprint<!-- {{#callable_declaration:fd_tpu_reasm_footprint}} -->
Calculate the memory footprint required for a TPU reassembly structure.
- **Description**: This function calculates the memory footprint needed for a TPU reassembly structure that can handle a specified number of concurrent reassemblies and a given depth of the target mcache. It should be used when setting up memory for TPU reassembly to ensure that the allocated space is sufficient. The function expects the depth to be a power of two and within a specific range, and the burst to be within a defined range. If these conditions are not met, the function returns zero, indicating an invalid configuration.
- **Inputs**:
    - `depth`: The number of entries in the target mcache, which must be a power of two and not exceed 2^31. If this condition is not met, the function returns zero.
    - `burst`: The maximum number of concurrent reassemblies, which must be at least 2 and not exceed 2^31. If this condition is not met, the function returns zero.
- **Output**: Returns the calculated memory footprint in bytes if the input parameters are valid; otherwise, returns zero.
- **See also**: [`fd_tpu_reasm_footprint`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_footprint)  (Implementation)


---
### fd\_tpu\_reasm\_new<!-- {{#callable_declaration:fd_tpu_reasm_new}} -->
Initialize a TPU reassembly object in shared memory.
- **Description**: This function sets up a memory region for use as a TPU reassembly object, which is used to handle incoming data fragments of TPU/QUIC streams. It should be called with a properly aligned and sized memory region, and it requires a valid dcache with sufficient data size. The function returns a pointer to the initialized reassembly object or NULL if any precondition is not met, such as invalid alignment, insufficient memory size, or invalid parameter values.
- **Inputs**:
    - `shmem`: A non-NULL pointer to a memory region in the local address space, which must be aligned to FD_TPU_REASM_ALIGN and have the required footprint for the reassembly object.
    - `depth`: The entry count of the target mcache, assumed to be a power of two within the range {2^0, 2^1, ..., 2^32}.
    - `reasm_max`: The maximum number of transactions that can be reassembled concurrently, assumed to be within the range [1, 2^32).
    - `orig`: The Tango origin ID of the reassembly object, assumed to be within the range [0, FD_FRAG_META_ORIG_MAX).
    - `dcache`: A pointer to a local join of an fd_dcache, which must have at least fd_tpu_reasm_req_data_sz() bytes of data size. The dcache app region is ignored and not written to.
- **Output**: Returns a pointer to the initialized fd_tpu_reasm_t object on success, or NULL if any precondition is violated.
- **See also**: [`fd_tpu_reasm_new`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_new)  (Implementation)


---
### fd\_tpu\_reasm\_join<!-- {{#callable_declaration:fd_tpu_reasm_join}} -->
Validates and joins a TPU reassembly object.
- **Description**: Use this function to join a TPU reassembly object, ensuring it is valid before proceeding. This function checks the integrity of the reassembly object by verifying its magic number. It should be called when you need to work with a TPU reassembly object that has been previously initialized. If the object is invalid, indicated by a mismatched magic number, the function will return NULL, signaling that the join operation failed.
- **Inputs**:
    - `shreasm`: A pointer to a TPU reassembly object in shared memory. It must not be null and should point to a valid, initialized reassembly object. The function checks the magic number to ensure the object is valid.
- **Output**: Returns a pointer to the joined TPU reassembly object if successful, or NULL if the object is invalid.
- **See also**: [`fd_tpu_reasm_join`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_join)  (Implementation)


---
### fd\_tpu\_reasm\_leave<!-- {{#callable_declaration:fd_tpu_reasm_leave}} -->
Leaves a TPU reassembly context.
- **Description**: This function is used to leave a TPU reassembly context, effectively ending the current session with the specified reassembly object. It should be called when the reassembly operations are complete and the context is no longer needed. This function does not perform any cleanup or deallocation of resources; it simply returns the pointer to the reassembly object. It is important to ensure that the reassembly object is valid and has been properly initialized before calling this function.
- **Inputs**:
    - `reasm`: A pointer to an fd_tpu_reasm_t object representing the reassembly context. This pointer must not be null and should point to a valid, initialized reassembly object.
- **Output**: Returns the same pointer to the fd_tpu_reasm_t object that was passed in.
- **See also**: [`fd_tpu_reasm_leave`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_leave)  (Implementation)


---
### fd\_tpu\_reasm\_delete<!-- {{#callable_declaration:fd_tpu_reasm_delete}} -->
Deletes a TPU reassembly object.
- **Description**: Use this function to delete a TPU reassembly object when it is no longer needed. This function should be called to clean up resources associated with a TPU reassembly object. It is important to ensure that the object is not in use by any other operations before calling this function. If the provided pointer is null, the function will return null without performing any operations.
- **Inputs**:
    - `shreasm`: A pointer to the TPU reassembly object to be deleted. Must not be null unless the intention is to perform a no-op. The caller retains ownership and responsibility for ensuring the object is not in use.
- **Output**: Returns the same pointer passed in if the operation is successful, or null if the input pointer is null.
- **See also**: [`fd_tpu_reasm_delete`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_delete)  (Implementation)


---
### fd\_tpu\_reasm\_query<!-- {{#callable_declaration:fd_tpu_reasm_query}} -->
Retrieve a reassembly slot for a specific connection and stream.
- **Description**: This function is used to query the reassembly slot associated with a specific connection and stream within a TPU/QUIC reassembly context. It is typically called when there is a need to access or manage the reassembly state of a particular stream identified by its connection UID and stream ID. The function should be called with a valid reassembly context, and it will return a pointer to the corresponding reassembly slot if it exists. This function does not modify the state of the reassembly slots.
- **Inputs**:
    - `reasm`: A pointer to an fd_tpu_reasm_t structure representing the reassembly context. Must not be null.
    - `conn_uid`: An unsigned long integer representing the unique identifier for the connection. Should be a valid connection UID.
    - `stream_id`: An unsigned long integer representing the identifier for the stream. Should be a valid stream ID.
- **Output**: Returns a pointer to an fd_tpu_reasm_slot_t structure if a matching reassembly slot is found, or NULL if no such slot exists.
- **See also**: [`fd_tpu_reasm_query`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_query)  (Implementation)


---
### fd\_tpu\_reasm\_prepare<!-- {{#callable_declaration:fd_tpu_reasm_prepare}} -->
Prepares a reassembly slot for a new QUIC stream.
- **Description**: This function is used to prepare a reassembly slot for handling a new QUIC stream in the TPU/QUIC protocol. It should be called when a new stream is accepted and a slot is needed to begin reassembling the stream's data. The function updates the slot with the provided connection and stream identifiers, and sets the original timestamp for the slot. It is important to ensure that the reassembly object is properly initialized and that there are available slots for reassembly before calling this function.
- **Inputs**:
    - `reasm`: A pointer to an fd_tpu_reasm_t structure representing the reassembly object. Must not be null and should be properly initialized.
    - `conn_uid`: An unsigned long representing the unique identifier for the connection. It is used to identify the connection associated with the stream.
    - `stream_id`: An unsigned long representing the identifier for the stream. It is masked with FD_TPU_REASM_SID_MASK to ensure it fits within the expected range.
    - `tsorig`: A long integer representing the original timestamp for the stream. It is used to set the timestamp component of the slot.
- **Output**: Returns a pointer to the prepared fd_tpu_reasm_slot_t structure, which is ready for reassembly of the specified stream.
- **See also**: [`fd_tpu_reasm_prepare`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_prepare)  (Implementation)


---
### fd\_tpu\_reasm\_frag<!-- {{#callable_declaration:fd_tpu_reasm_frag}} -->
Appends a data fragment to a reassembly slot.
- **Description**: Use this function to append a fragment of stream data to an active reassembly slot. It is essential that the slot is in the BUSY state before calling this function. The function checks for out-of-order data and size constraints, and it will cancel the reassembly if these conditions are not met. This function is typically used in the context of reassembling fragmented transactions in a TPU/QUIC protocol implementation.
- **Inputs**:
    - `reasm`: A pointer to an fd_tpu_reasm_t structure representing the reassembly context. Must not be null.
    - `slot`: A pointer to an fd_tpu_reasm_slot_t structure representing the reassembly slot. Must be in the BUSY state and not null.
    - `data`: A pointer to the data fragment to be appended. Must not be null.
    - `data_sz`: The size of the data fragment in bytes. Must be non-negative and, when added to the current slot size, must not exceed the maximum transmission unit (MTU).
    - `data_off`: The offset of the data fragment within the stream. Must not exceed the current size of the data in the slot.
- **Output**: Returns FD_TPU_REASM_SUCCESS on success, FD_TPU_REASM_ERR_STATE if the slot is not in the BUSY state, FD_TPU_REASM_ERR_SKIP if the data offset is greater than the current slot size, or FD_TPU_REASM_ERR_SZ if the resulting size exceeds the MTU.
- **See also**: [`fd_tpu_reasm_frag`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_frag)  (Implementation)


---
### fd\_tpu\_reasm\_publish<!-- {{#callable_declaration:fd_tpu_reasm_publish}} -->
Publishes a reassembled message to an mcache for downstream consumption.
- **Description**: This function is used to complete the reassembly of a stream and publish the resulting message to an mcache, making it available for downstream processing. It should be called when a reassembly slot is in the BUSY state, indicating that it holds a complete transaction ready for publication. The function requires a valid base address aligned to FD_CHUNK_ALIGN, and it will abort if the base is invalid. It also manages the lifecycle of reassembly slots, transitioning the current slot to the PUB state and freeing the least recently published slot. This function must be used in a context where the tpu_reasm is the sole writer to the mcache.
- **Inputs**:
    - `reasm`: A pointer to an fd_tpu_reasm_t structure representing the reassembly context. Must not be null.
    - `slot`: A pointer to an fd_tpu_reasm_slot_t structure representing the reassembly slot to be published. Must be in the BUSY state.
    - `mcache`: A pointer to an fd_frag_meta_t structure representing the metadata cache where the message will be published. Must not be null.
    - `base`: A void pointer representing the base address of the chunk, assumed to be aligned to FD_CHUNK_ALIGN. Must be valid for the tpu_reasm.
    - `seq`: An unsigned long representing the sequence number for the mcache fragment.
    - `tspub`: A long integer representing the publication timestamp for the mcache fragment.
- **Output**: Returns FD_TPU_REASM_SUCCESS on successful publication, or FD_TPU_REASM_ERR_STATE if the slot state is invalid or if mcache corruption is detected.
- **See also**: [`fd_tpu_reasm_publish`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_publish)  (Implementation)


---
### fd\_tpu\_reasm\_publish\_fast<!-- {{#callable_declaration:fd_tpu_reasm_publish_fast}} -->
Publishes a data fragment to the reassembly buffer and mcache.
- **Description**: This function is used to publish a data fragment to a reassembly buffer and subsequently to an mcache for downstream consumption. It is a streamlined version that combines acquiring a slot, adding a fragment, and publishing it in one call. The function should be used when you have a complete data fragment ready to be published. It requires that the data size does not exceed the maximum transmission unit (MTU) defined by FD_TPU_REASM_MTU. If the data size is too large, the function will return an error. The base pointer must be aligned according to FD_CHUNK_ALIGN, and the function assumes that the reassembly object is properly initialized and joined to the current context.
- **Inputs**:
    - `reasm`: A pointer to an fd_tpu_reasm_t structure representing the reassembly context. It must be properly initialized and not null.
    - `data`: A pointer to the data fragment to be published. The data must not exceed FD_TPU_REASM_MTU in size.
    - `sz`: The size of the data fragment in bytes. It must not exceed FD_TPU_REASM_MTU.
    - `mcache`: A pointer to an fd_frag_meta_t structure representing the metadata cache where the fragment will be published. It must not be null.
    - `base`: A pointer to the base address of the chunk, which must be aligned to FD_CHUNK_ALIGN. It must not be null.
    - `seq`: An unsigned long representing the sequence number for the fragment. It is used to index into the mcache.
    - `tspub`: A long integer representing the publication timestamp for the fragment.
- **Output**: Returns an integer status code: FD_TPU_REASM_SUCCESS on success, FD_TPU_REASM_ERR_SZ if the data size exceeds the MTU, or FD_TPU_REASM_ERR_STATE if there is a state error.
- **See also**: [`fd_tpu_reasm_publish_fast`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_publish_fast)  (Implementation)


---
### fd\_tpu\_reasm\_cancel<!-- {{#callable_declaration:fd_tpu_reasm_cancel}} -->
Cancels an ongoing stream reassembly.
- **Description**: Use this function to cancel an ongoing reassembly process for a specific stream in the TPU/QUIC protocol. This is typically necessary when a stream is aborted due to errors or other conditions that prevent successful reassembly. The function should be called when the slot is in a busy state, indicating active reassembly. After cancellation, the slot is reset to a free state and made available for new reassembly tasks.
- **Inputs**:
    - `reasm`: A pointer to an fd_tpu_reasm_t structure representing the reassembly context. The caller retains ownership and must ensure it is valid and properly initialized.
    - `slot`: A pointer to an fd_tpu_reasm_slot_t structure representing the reassembly slot to be canceled. The slot must be in a busy state; otherwise, the function will return immediately without making changes.
- **Output**: None
- **See also**: [`fd_tpu_reasm_cancel`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_cancel)  (Implementation)


