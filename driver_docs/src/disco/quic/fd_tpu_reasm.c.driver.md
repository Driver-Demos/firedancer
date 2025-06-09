# Purpose
The provided C source code file is part of a library that implements a reassembly mechanism for handling fragmented data packets, likely in a network or data streaming context. The code defines several functions that manage the lifecycle of reassembly objects (`fd_tpu_reasm_t`), including their creation, initialization, querying, and deletion. The primary functionality revolves around managing slots that hold fragments of data, reassembling these fragments into complete messages, and publishing the reassembled data to a memory cache (`mcache`). The code ensures that memory is properly aligned and that the reassembly process adheres to constraints such as maximum transmission unit (MTU) sizes and burst limits.

Key technical components include functions for calculating memory alignment and footprint ([`fd_tpu_reasm_align`](#fd_tpu_reasm_align), [`fd_tpu_reasm_footprint`](#fd_tpu_reasm_footprint)), creating and initializing reassembly objects ([`fd_tpu_reasm_new`](#fd_tpu_reasm_new), [`fd_tpu_reasm_reset`](#fd_tpu_reasm_reset)), and handling the reassembly process ([`fd_tpu_reasm_frag`](#fd_tpu_reasm_frag), [`fd_tpu_reasm_publish`](#fd_tpu_reasm_publish)). The code also includes mechanisms for managing the state of slots, ensuring that they transition correctly between free, busy, and published states. The use of macros and inline functions suggests a focus on performance, particularly in the context of high-throughput data processing. The file is intended to be part of a larger system, as indicated by its reliance on external headers and functions, and it provides a specialized API for managing data reassembly in a concurrent or high-performance environment.
# Imports and Dependencies

---
- `fd_tpu.h`
- `fd_tpu_reasm_private.h`


# Functions

---
### fd\_tpu\_reasm\_align<!-- {{#callable:fd_tpu_reasm_align}} -->
The `fd_tpu_reasm_align` function returns the alignment requirement of the `fd_tpu_reasm_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the result of the `alignof` operator applied to the `fd_tpu_reasm_t` type.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_tpu_reasm_t` type.


---
### fd\_tpu\_reasm\_footprint<!-- {{#callable:fd_tpu_reasm_footprint}} -->
The `fd_tpu_reasm_footprint` function calculates the memory footprint required for a TPU reassembly structure based on given depth and burst parameters.
- **Inputs**:
    - `depth`: The depth of the reassembly structure, which must be a power of two and less than or equal to 0x7fffffffUL.
    - `burst`: The burst size for the reassembly structure, which must be at least 2 and less than or equal to 0x7fffffffUL.
- **Control Flow**:
    - Check if the input parameters 'depth' and 'burst' meet specific constraints: 'depth' must be a power of two, and both 'depth' and 'burst' must be within specified limits.
    - If any of the constraints are not met, return 0UL indicating an invalid configuration.
    - Calculate 'slot_cnt' as the sum of 'depth' and 'burst'.
    - Estimate 'chain_cnt' using the function 'fd_tpu_reasm_map_chain_cnt_est' with 'slot_cnt'.
    - Calculate the total memory footprint using a series of layout append operations, which include alignment and size calculations for various components of the reassembly structure.
    - Return the calculated memory footprint.
- **Output**: The function returns the calculated memory footprint as an unsigned long integer, or 0UL if the input parameters are invalid.
- **Functions called**:
    - [`fd_tpu_reasm_align`](#fd_tpu_reasm_align)


---
### fd\_tpu\_reasm\_new<!-- {{#callable:fd_tpu_reasm_new}} -->
The `fd_tpu_reasm_new` function initializes a new TPU reassembly object in shared memory with specified parameters for depth, burst, origin, and data cache.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the reassembly object will be initialized.
    - `depth`: The depth of the reassembly, representing the number of slots available for public use.
    - `burst`: The burst size, representing additional slots available for reassembly.
    - `orig`: The origin identifier, which must not exceed `FD_FRAG_META_ORIG_MAX`.
    - `dcache`: A pointer to the data cache used by the reassembly object.
- **Control Flow**:
    - Check if `shmem` is NULL or not aligned to `FD_TPU_REASM_ALIGN`, returning NULL if so.
    - Verify the footprint of the reassembly with [`fd_tpu_reasm_footprint`](#fd_tpu_reasm_footprint), returning NULL if invalid.
    - Ensure `orig` does not exceed `FD_FRAG_META_ORIG_MAX`, returning NULL if it does.
    - Calculate the required data size and check if `dcache` has sufficient size, logging a warning and returning NULL if not.
    - Calculate the total slot count as `depth + burst` and estimate the chain count for mapping.
    - Allocate memory for the reassembly object, public slots, slots, and map memory using `FD_SCRATCH_ALLOC_APPEND`.
    - Initialize the allocated memory to zero using `fd_memset`.
    - Create and join a new map for the reassembly, logging a warning and returning NULL if map creation fails.
    - Set offsets and parameters in the reassembly object, including slots, public slots, map, depth, burst, head, tail, slot count, and origin.
    - Reset the reassembly object to its initial state using [`fd_tpu_reasm_reset`](#fd_tpu_reasm_reset).
    - Set the magic number for the reassembly object to `FD_TPU_REASM_MAGIC` to indicate successful initialization.
    - Return the pointer to the initialized reassembly object.
- **Output**: A pointer to the initialized `fd_tpu_reasm_t` object, or NULL if initialization fails.
- **Functions called**:
    - [`fd_tpu_reasm_footprint`](#fd_tpu_reasm_footprint)
    - [`fd_tpu_reasm_req_data_sz`](fd_tpu.h.driver.md#fd_tpu_reasm_req_data_sz)
    - [`fd_tpu_reasm_align`](#fd_tpu_reasm_align)
    - [`fd_tpu_reasm_reset`](#fd_tpu_reasm_reset)


---
### fd\_tpu\_reasm\_reset<!-- {{#callable:fd_tpu_reasm_reset}} -->
The `fd_tpu_reasm_reset` function initializes and resets the state of a TPU reassembly object by setting up its slots and clearing its hash map.
- **Inputs**:
    - `reasm`: A pointer to an `fd_tpu_reasm_t` structure representing the TPU reassembly object to be reset.
- **Control Flow**:
    - Retrieve the depth, burst, and node count from the `reasm` structure.
    - Get pointers to the slots, public slots, and map associated with the `reasm` object.
    - Initialize the first `depth` slots to the state `FD_TPU_REASM_STATE_PUB` and set their attributes to default values, adding them to the public slots array.
    - Initialize the remaining slots to the state `FD_TPU_REASM_STATE_FREE`, setting their attributes and linking them in an LRU (Least Recently Used) manner.
    - Clear the hash map by setting all its chain entries to `UINT_MAX`.
- **Output**: This function does not return a value; it modifies the state of the `reasm` object in place.
- **Functions called**:
    - [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr)
    - [`fd_tpu_reasm_pub_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_pub_slots_laddr)


---
### fd\_tpu\_reasm\_join<!-- {{#callable:fd_tpu_reasm_join}} -->
The `fd_tpu_reasm_join` function verifies the integrity of a TPU reassembly object by checking its magic number and returns the object if valid, or NULL if invalid.
- **Inputs**:
    - `shreasm`: A pointer to a TPU reassembly object that needs to be verified and joined.
- **Control Flow**:
    - Cast the input `shreasm` to a `fd_tpu_reasm_t` pointer named `reasm`.
    - Check if the `magic` field of `reasm` is equal to `FD_TPU_REASM_MAGIC`.
    - If the `magic` field is not equal, log a warning message 'bad magic' and return NULL.
    - If the `magic` field is valid, return the `reasm` pointer.
- **Output**: Returns a pointer to the `fd_tpu_reasm_t` object if the magic number is valid, otherwise returns NULL.


---
### fd\_tpu\_reasm\_leave<!-- {{#callable:fd_tpu_reasm_leave}} -->
The `fd_tpu_reasm_leave` function returns the pointer to a `fd_tpu_reasm_t` object, effectively allowing the caller to 'leave' or stop using the reassembly object without altering its state.
- **Inputs**:
    - `reasm`: A pointer to a `fd_tpu_reasm_t` object, representing the reassembly object to be left.
- **Control Flow**:
    - The function takes a single argument, `reasm`, which is a pointer to a `fd_tpu_reasm_t` object.
    - It simply returns the same pointer `reasm` without performing any operations on it.
- **Output**: The function returns the same pointer to the `fd_tpu_reasm_t` object that was passed in as an argument.


---
### fd\_tpu\_reasm\_delete<!-- {{#callable:fd_tpu_reasm_delete}} -->
The `fd_tpu_reasm_delete` function resets the magic number of a TPU reassembly object to zero and returns the object.
- **Inputs**:
    - `shreasm`: A pointer to a TPU reassembly object (`fd_tpu_reasm_t`).
- **Control Flow**:
    - Cast the input `shreasm` to a `fd_tpu_reasm_t` pointer named `reasm`.
    - Check if `reasm` is NULL using `FD_UNLIKELY`; if so, return NULL.
    - Set the `magic` field of `reasm` to 0UL.
    - Return the original `shreasm` pointer.
- **Output**: Returns the original `shreasm` pointer, or NULL if the input was NULL.


---
### fd\_tpu\_reasm\_query<!-- {{#callable:fd_tpu_reasm_query}} -->
The `fd_tpu_reasm_query` function retrieves a reassembly slot from a reassembly map based on a connection UID and stream ID.
- **Inputs**:
    - `reasm`: A pointer to an `fd_tpu_reasm_t` structure representing the reassembly context.
    - `conn_uid`: An unsigned long integer representing the connection unique identifier.
    - `stream_id`: An unsigned long integer representing the stream identifier.
- **Control Flow**:
    - The function calls `smap_query` with the provided `reasm`, `conn_uid`, and `stream_id` as arguments.
    - The result of `smap_query` is returned directly.
- **Output**: A pointer to an `fd_tpu_reasm_slot_t` structure, which represents the reassembly slot associated with the given connection UID and stream ID, or NULL if not found.


---
### fd\_tpu\_reasm\_prepare<!-- {{#callable:fd_tpu_reasm_prepare}} -->
The `fd_tpu_reasm_prepare` function prepares a reassembly slot for a new connection and stream by updating its metadata and reinserting it into the reassembly queue.
- **Inputs**:
    - `reasm`: A pointer to the reassembly structure (`fd_tpu_reasm_t`) that manages the reassembly slots.
    - `conn_uid`: An unsigned long integer representing the unique identifier for the connection.
    - `stream_id`: An unsigned long integer representing the stream identifier, which will be masked with `FD_TPU_REASM_SID_MASK`.
    - `tsorig`: A long integer representing the original timestamp to be compressed and stored in the slot.
- **Control Flow**:
    - Pop a slot from the tail of the reassembly queue using `slotq_pop_tail`.
    - Remove the slot from the reassembly map using [`smap_remove`](fd_tpu_reasm_private.h.driver.md#smap_remove).
    - Initialize the slot using [`slot_begin`](fd_tpu_reasm_private.h.driver.md#slot_begin).
    - Push the slot to the head of the reassembly queue using [`slotq_push_head`](fd_tpu_reasm_private.h.driver.md#slotq_push_head).
    - Set the slot's connection UID and stream ID, masking the stream ID with `FD_TPU_REASM_SID_MASK`.
    - Insert the slot back into the reassembly map using [`smap_insert`](fd_tpu_reasm_private.h.driver.md#smap_insert).
    - Compress the original timestamp using `fd_frag_meta_ts_comp` and store it in the slot's `tsorig_comp` field.
    - Return the prepared slot.
- **Output**: Returns a pointer to the prepared `fd_tpu_reasm_slot_t` structure.
- **Functions called**:
    - [`smap_remove`](fd_tpu_reasm_private.h.driver.md#smap_remove)
    - [`slot_begin`](fd_tpu_reasm_private.h.driver.md#slot_begin)
    - [`slotq_push_head`](fd_tpu_reasm_private.h.driver.md#slotq_push_head)
    - [`smap_insert`](fd_tpu_reasm_private.h.driver.md#smap_insert)


---
### fd\_tpu\_reasm\_frag<!-- {{#callable:fd_tpu_reasm_frag}} -->
The `fd_tpu_reasm_frag` function processes a fragment of data for reassembly, ensuring it fits within the constraints of the reassembly slot and updates the slot's state accordingly.
- **Inputs**:
    - `reasm`: A pointer to the reassembly context (`fd_tpu_reasm_t`) which manages the reassembly process.
    - `slot`: A pointer to the reassembly slot (`fd_tpu_reasm_slot_t`) where the fragment is to be reassembled.
    - `data`: A pointer to the data fragment to be reassembled.
    - `data_sz`: The size of the data fragment in bytes.
    - `data_off`: The offset in the reassembly slot where the data fragment should be placed.
- **Control Flow**:
    - Check if the slot's state is not busy; if not, return an error state.
    - Calculate the slot index and retrieve the current size of the data in the slot.
    - If the data offset is greater than the current size, cancel the reassembly and return an error indicating a skip.
    - If the data offset is less than the current size, adjust the data and offset to skip already known parts.
    - Calculate the new size after adding the fragment; if it exceeds the maximum transmission unit (MTU) or causes an overflow, cancel the reassembly and return a size error.
    - Copy the data fragment into the slot's data buffer at the appropriate offset.
    - Update the slot's size to reflect the new total size of the data.
    - Return success indicating the fragment was successfully reassembled.
- **Output**: Returns an integer status code indicating success or the type of error encountered during the reassembly process.
- **Functions called**:
    - [`slot_get_idx`](fd_tpu_reasm_private.h.driver.md#slot_get_idx)
    - [`fd_tpu_reasm_cancel`](#fd_tpu_reasm_cancel)
    - [`slot_get_data`](fd_tpu_reasm_private.h.driver.md#slot_get_data)


---
### fd\_tpu\_reasm\_publish<!-- {{#callable:fd_tpu_reasm_publish}} -->
The `fd_tpu_reasm_publish` function publishes a reassembled data slot to a memory cache and manages the slot's state transitions within a reassembly system.
- **Inputs**:
    - `reasm`: A pointer to the reassembly structure (`fd_tpu_reasm_t`) managing the slots.
    - `slot`: A pointer to the specific reassembly slot (`fd_tpu_reasm_slot_t`) to be published.
    - `mcache`: A pointer to the memory cache (`fd_frag_meta_t`) where the slot data will be published.
    - `base`: A pointer to the base address of the memory region, assumed to be aligned to `FD_CHUNK_ALIGN`.
    - `seq`: An unsigned long integer representing the sequence number for the slot being published.
    - `tspub`: A long integer representing the publication timestamp.
- **Control Flow**:
    - Check if the slot's state is `FD_TPU_REASM_STATE_BUSY`; if not, return an error state.
    - Calculate the chunk index from the slot's data and base address, logging a critical error if the index is invalid.
    - Determine the least recently published slot to free, logging a warning and resetting the reassembly if the index is out of bounds.
    - Publish the slot's data to the memory cache using architecture-specific functions (AVX, SSE, or generic).
    - Update the slot's state to `FD_TPU_REASM_STATE_PUB` and mark it as published in the public slots array.
    - Free the oldest published slot, checking its state and logging a warning if there's a mismatch, then reset the reassembly if needed.
- **Output**: Returns `FD_TPU_REASM_SUCCESS` on successful publication, or an error code if an issue is encountered.
- **Functions called**:
    - [`slot_get_idx`](fd_tpu_reasm_private.h.driver.md#slot_get_idx)
    - [`slot_get_data`](fd_tpu_reasm_private.h.driver.md#slot_get_data)
    - [`fd_tpu_reasm_pub_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_pub_slots_laddr)
    - [`fd_tpu_reasm_reset`](#fd_tpu_reasm_reset)
    - [`slotq_remove`](fd_tpu_reasm_private.h.driver.md#slotq_remove)
    - [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr)
    - [`slotq_push_tail`](fd_tpu_reasm_private.h.driver.md#slotq_push_tail)


---
### fd\_tpu\_reasm\_cancel<!-- {{#callable:fd_tpu_reasm_cancel}} -->
The `fd_tpu_reasm_cancel` function cancels a reassembly operation on a given slot if it is in a busy state, resetting its state and re-queuing it for future use.
- **Inputs**:
    - `reasm`: A pointer to the `fd_tpu_reasm_t` structure, representing the reassembly context.
    - `slot`: A pointer to the `fd_tpu_reasm_slot_t` structure, representing the specific slot to be canceled.
- **Control Flow**:
    - Check if the slot's state is not `FD_TPU_REASM_STATE_BUSY`; if so, return immediately without doing anything.
    - Remove the slot from the slot queue using [`slotq_remove`](fd_tpu_reasm_private.h.driver.md#slotq_remove).
    - Remove the slot from the slot map using [`smap_remove`](fd_tpu_reasm_private.h.driver.md#smap_remove).
    - Set the slot's state to `FD_TPU_REASM_STATE_FREE`.
    - Reset the slot's `conn_uid` to `ULONG_MAX` and `stream_id` to `0UL`.
    - Re-queue the slot to the tail of the slot queue using [`slotq_push_tail`](fd_tpu_reasm_private.h.driver.md#slotq_push_tail).
- **Output**: The function does not return any value; it modifies the state of the slot and the reassembly context in place.
- **Functions called**:
    - [`slotq_remove`](fd_tpu_reasm_private.h.driver.md#slotq_remove)
    - [`smap_remove`](fd_tpu_reasm_private.h.driver.md#smap_remove)
    - [`slotq_push_tail`](fd_tpu_reasm_private.h.driver.md#slotq_push_tail)


---
### fd\_tpu\_reasm\_publish\_fast<!-- {{#callable:fd_tpu_reasm_publish_fast}} -->
The `fd_tpu_reasm_publish_fast` function manages the publication of data into a reassembly structure, ensuring that data is copied into a new slot and the least recently published slot is freed, while handling potential errors and maintaining synchronization.
- **Inputs**:
    - `reasm`: A pointer to the `fd_tpu_reasm_t` structure, which manages the reassembly slots.
    - `data`: A constant pointer to the data to be published.
    - `sz`: The size of the data to be published.
    - `mcache`: A pointer to the `fd_frag_meta_t` structure, which is used for metadata caching.
    - `base`: A pointer to the base address, assumed to be aligned to `FD_CHUNK_ALIGN`.
    - `seq`: The sequence number for the data being published.
    - `tspub`: The timestamp for when the data is published.
- **Control Flow**:
    - Check if the size of the data exceeds the maximum transmission unit (MTU); if so, return an error.
    - Acquire the least recent slot from the reassembly structure and prepare it for new data.
    - Calculate the buffer address for the new slot and verify its validity.
    - Identify the least recently published slot to be freed and check for potential corruption.
    - Copy the data into the new slot and update its state to published.
    - Publish the new slot by updating the metadata cache with the new slot's information.
    - Free the old slot by updating its state and reinserting it into the slot queue.
- **Output**: Returns an integer status code indicating success or specific error conditions, such as size errors or state corruption.
- **Functions called**:
    - [`smap_remove`](fd_tpu_reasm_private.h.driver.md#smap_remove)
    - [`slot_begin`](fd_tpu_reasm_private.h.driver.md#slot_begin)
    - [`slot_get_idx`](fd_tpu_reasm_private.h.driver.md#slot_get_idx)
    - [`slot_get_data`](fd_tpu_reasm_private.h.driver.md#slot_get_data)
    - [`fd_tpu_reasm_pub_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_pub_slots_laddr)
    - [`fd_tpu_reasm_reset`](#fd_tpu_reasm_reset)
    - [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr)
    - [`slotq_push_tail`](fd_tpu_reasm_private.h.driver.md#slotq_push_tail)


