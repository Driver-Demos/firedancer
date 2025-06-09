# Purpose
The provided C header file, `fd_tpu_reasm_private.h`, is designed to support the reassembly of data packets in a Transmission Control Protocol (TCP) or similar network protocol context. It is a private header file, indicating that it is intended for internal use within a larger software system, specifically for testing purposes. The file includes logic for managing reassembly slots, which are used to piece together fragmented data packets into complete messages. This functionality is crucial in network communication where data packets may arrive out of order or be fragmented due to network constraints.

Key components of this file include the definition of a map structure for managing reassembly slots, methods for initializing and manipulating these slots, and a least recently used (LRU) cache mechanism for efficient slot allocation and eviction. The file defines several inline functions for accessing and modifying slot data, as well as functions for managing the slot queue, such as adding and removing slots from the head or tail of the queue. The use of macros and inline functions suggests a focus on performance, which is critical in high-throughput network applications. The file does not define public APIs or external interfaces, as it is intended for internal use, likely as part of a larger library or application dealing with network data reassembly.
# Imports and Dependencies

---
- `fd_tpu.h`
- `assert.h`
- `../../util/tmpl/fd_map_chain.c`


# Functions

---
### slot\_get\_idx<!-- {{#callable:slot_get_idx}} -->
The `slot_get_idx` function calculates the index of a given reassembly slot within a reassembly structure and logs an error if the index is out of bounds.
- **Inputs**:
    - `reasm`: A pointer to a constant `fd_tpu_reasm_t` structure, representing the reassembly context.
    - `slot`: A pointer to a constant `fd_tpu_reasm_slot_t` structure, representing the specific slot whose index is to be calculated.
- **Control Flow**:
    - Calculate the index of the slot by subtracting the base address of the slots array from the slot pointer.
    - Check if the calculated index is greater than or equal to the sum of `reasm->depth` and `reasm->burst`.
    - If the index is out of bounds, log a critical error message with the invalid index and the valid range.
    - Return the calculated index as an unsigned integer.
- **Output**: The function returns the index of the slot as an unsigned integer (`uint`).
- **Functions called**:
    - [`fd_tpu_reasm_slots_laddr_const`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr_const)


---
### slot\_get\_offset<!-- {{#callable:slot_get_offset}} -->
The `slot_get_offset` function calculates the memory offset for a given slot index in a reassembly buffer.
- **Inputs**:
    - `slot_idx`: An unsigned long integer representing the index of the slot for which the offset is to be calculated.
- **Control Flow**:
    - The function takes a single input, `slot_idx`, which is the index of the slot.
    - It multiplies `slot_idx` by the constant `FD_TPU_REASM_MTU` to compute the offset.
- **Output**: The function returns an unsigned long integer representing the calculated offset for the specified slot index.


---
### slot\_get\_data<!-- {{#callable:slot_get_data}} -->
The `slot_get_data` function retrieves a pointer to the data associated with a specific slot index in a reassembly structure.
- **Inputs**:
    - `reasm`: A pointer to an `fd_tpu_reasm_t` structure, which contains the reassembly data cache and other related information.
    - `slot_idx`: An unsigned long integer representing the index of the slot for which the data pointer is to be retrieved.
- **Control Flow**:
    - Calculate the offset for the given slot index by calling `slot_get_offset(slot_idx)`.
    - Add the calculated offset to the base address of the data cache (`reasm->dcache`) to get the pointer to the data for the specified slot.
- **Output**: A pointer to an unsigned character (`uchar *`) that points to the data associated with the specified slot index in the reassembly data cache.
- **Functions called**:
    - [`slot_get_offset`](#slot_get_offset)


---
### slot\_get\_data\_const<!-- {{#callable:slot_get_data_const}} -->
The `slot_get_data_const` function retrieves a constant pointer to the data cache at a specific slot index within a reassembly structure.
- **Inputs**:
    - `reasm`: A constant pointer to an `fd_tpu_reasm_t` structure, representing the reassembly context containing the data cache.
    - `slot_idx`: An unsigned long integer representing the index of the slot whose data is to be accessed.
- **Control Flow**:
    - Calculate the offset within the data cache by calling [`slot_get_offset`](#slot_get_offset) with `slot_idx` as the argument.
    - Return a constant pointer to the data cache at the calculated offset.
- **Output**: A constant pointer to an unsigned character (`uchar const *`) representing the data at the specified slot index in the reassembly's data cache.
- **Functions called**:
    - [`slot_get_offset`](#slot_get_offset)


---
### slot\_begin<!-- {{#callable:slot_begin}} -->
The `slot_begin` function initializes a reassembly slot to a default busy state with specific identifiers.
- **Inputs**:
    - `slot`: A pointer to an `fd_tpu_reasm_slot_t` structure that represents a reassembly slot to be initialized.
- **Control Flow**:
    - The function begins by zeroing out the memory of the `slot` structure using `memset`.
    - It sets the `state` field of the slot's key to `FD_TPU_REASM_STATE_BUSY`, indicating that the slot is currently in use.
    - The `conn_uid` field of the slot's key is set to `ULONG_MAX`, which typically represents an invalid or uninitialized state.
    - The `stream_id` field of the slot's key is set to `FD_TPU_REASM_SID_MASK`, which is likely a mask or default value for stream identifiers.
- **Output**: The function does not return any value; it modifies the `slot` structure in place.


---
### slotq\_push\_head<!-- {{#callable:slotq_push_head}} -->
The `slotq_push_head` function adds a specified slot to the head of a reassembly queue in a least-recently-used (LRU) cache system.
- **Inputs**:
    - `reasm`: A pointer to an `fd_tpu_reasm_t` structure representing the reassembly context, which contains the queue and its metadata.
    - `slot`: A pointer to an `fd_tpu_reasm_slot_t` structure representing the slot to be added to the head of the queue.
- **Control Flow**:
    - Retrieve the index of the slot to be added using [`slot_get_idx`](#slot_get_idx) function.
    - Retrieve the current head index of the reassembly queue from the `reasm` structure.
    - Calculate the address of the current head slot using the head index and the [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr) function.
    - Update the `lru_prev` of the current head slot to point to the new slot index.
    - Set the `lru_prev` of the new slot to `UINT_MAX` to indicate it has no previous slot.
    - Set the `lru_next` of the new slot to the current head index, linking it to the current head.
    - Update the `head` in the `reasm` structure to the new slot index, making it the new head of the queue.
- **Output**: The function does not return a value; it modifies the reassembly queue in place by updating the head and the linked list pointers of the involved slots.
- **Functions called**:
    - [`slot_get_idx`](#slot_get_idx)
    - [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr)


---
### slotq\_push\_tail<!-- {{#callable:slotq_push_tail}} -->
The `slotq_push_tail` function adds a given slot to the tail of a reassembly queue, updating the necessary pointers to maintain the doubly linked list structure.
- **Inputs**:
    - `reasm`: A pointer to an `fd_tpu_reasm_t` structure representing the reassembly context, which contains the queue and its metadata.
    - `slot`: A pointer to an `fd_tpu_reasm_slot_t` structure representing the slot to be added to the tail of the queue.
- **Control Flow**:
    - Retrieve the index of the slot to be added using [`slot_get_idx`](#slot_get_idx) function.
    - Retrieve the current tail index from the `reasm` structure.
    - Assert that the current tail index is within the valid range of slots.
    - Calculate the address of the current tail slot using the tail index.
    - Update the `lru_next` pointer of the current tail slot to point to the new slot index.
    - Set the `lru_prev` pointer of the new slot to the current tail index.
    - Set the `lru_next` pointer of the new slot to `UINT_MAX` to indicate it is the new tail.
    - Update the `reasm` structure's tail index to the new slot index.
- **Output**: The function does not return a value; it modifies the `reasm` structure and the `slot` to update the queue's tail.
- **Functions called**:
    - [`slot_get_idx`](#slot_get_idx)
    - [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr)


---
### slotq\_remove<!-- {{#callable:slotq_remove}} -->
The `slotq_remove` function removes a specified slot from a doubly linked list used as an LRU cache in a reassembly queue.
- **Inputs**:
    - `reasm`: A pointer to the `fd_tpu_reasm_t` structure representing the reassembly context.
    - `slot`: A pointer to the `fd_tpu_reasm_slot_t` structure representing the slot to be removed from the queue.
- **Control Flow**:
    - Retrieve the index of the slot to be removed using [`slot_get_idx`](#slot_get_idx) function.
    - Store the previous and next slot indices from the slot's `lru_prev` and `lru_next` fields.
    - Set the `lru_prev` and `lru_next` fields of the slot to `UINT_MAX` to mark it as removed.
    - Calculate pointers to the previous and next slots in the list using [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr).
    - Check if the slot is the head of the list; if so, update the head to the next slot and set the next slot's `lru_prev` to `UINT_MAX`.
    - Check if the slot is the tail of the list; if so, update the tail to the previous slot and set the previous slot's `lru_next` to `UINT_MAX`.
    - If the slot is neither the head nor the tail, update the `lru_next` of the previous slot and `lru_prev` of the next slot to bypass the removed slot.
    - Perform boundary checks to ensure `lru_prev` and `lru_next` are within valid range, logging errors if they are out of bounds.
- **Output**: The function does not return a value; it modifies the linked list structure in place to remove the specified slot.
- **Functions called**:
    - [`slot_get_idx`](#slot_get_idx)
    - [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr)


---
### smap\_insert<!-- {{#callable:smap_insert}} -->
The `smap_insert` function inserts a reassembly slot into a reassembly map within a reassembly structure.
- **Inputs**:
    - `reasm`: A pointer to an `fd_tpu_reasm_t` structure representing the reassembly context.
    - `slot`: A pointer to an `fd_tpu_reasm_slot_t` structure representing the slot to be inserted into the reassembly map.
- **Control Flow**:
    - The function calls `fd_tpu_reasm_map_ele_insert` with three arguments: the local address of the reassembly map, the slot to be inserted, and the local address of the reassembly slots.
    - The `fd_tpu_reasm_map_ele_insert` function handles the actual insertion of the slot into the map.
- **Output**: The function does not return any value; it performs an insertion operation on the reassembly map.
- **Functions called**:
    - [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr)


---
### smap\_remove<!-- {{#callable:smap_remove}} -->
The `smap_remove` function removes a reassembly slot from a map in the reassembly structure.
- **Inputs**:
    - `reasm`: A pointer to the `fd_tpu_reasm_t` structure, which contains the reassembly map and slots.
    - `slot`: A pointer to the `fd_tpu_reasm_slot_t` structure, representing the slot to be removed from the map.
- **Control Flow**:
    - The function calls `fd_tpu_reasm_map_idx_remove` with the local address of the reassembly map, the key of the slot to be removed, a constant `ULONG_MAX`, and the local address of the reassembly slots.
    - The `fd_tpu_reasm_map_idx_remove` function is responsible for removing the slot from the map based on the provided key.
- **Output**: The function does not return any value; it performs the removal operation as a side effect.
- **Functions called**:
    - [`fd_tpu_reasm_slots_laddr`](fd_tpu.h.driver.md#fd_tpu_reasm_slots_laddr)


# Function Declarations (Public API)

---
### fd\_tpu\_reasm\_reset<!-- {{#callable_declaration:fd_tpu_reasm_reset}} -->
Resets the reassembly slots to their initial state.
- **Description**: Use this function to initialize or reset all reassembly slots within a `fd_tpu_reasm_t` structure to their default state. This function is typically called when setting up the reassembly process or when a complete reset of the reassembly state is required. It prepares the slots for new data by marking the first set of slots as available for publishing and the rest as free. Note that calling this function will corrupt any messages currently visible in the mcache ring, so it should be used with caution in active systems.
- **Inputs**:
    - `reasm`: A pointer to a `fd_tpu_reasm_t` structure representing the reassembly context. This pointer must not be null, and the structure should be properly initialized before calling this function. The caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_tpu_reasm_reset`](fd_tpu_reasm.c.driver.md#fd_tpu_reasm_reset)  (Implementation)


