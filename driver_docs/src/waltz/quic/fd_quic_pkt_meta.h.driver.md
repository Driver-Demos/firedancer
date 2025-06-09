# Purpose
The provided C header file, `fd_quic_pkt_meta.h`, is part of a QUIC (Quick UDP Internet Connections) protocol implementation. It defines data structures and functions for managing packet metadata, which is crucial for tracking the state and details of packets sent over a QUIC connection. The file includes definitions for structures such as `fd_quic_pkt_meta`, `fd_quic_pkt_meta_list`, and `fd_quic_pkt_meta_tracker`, which are used to store metadata about packets, including packet numbers, types, stream IDs, and transmission times. This metadata is essential for handling acknowledgments and retransmissions, as it allows the system to determine which data has been acknowledged by the peer and which needs to be resent.

The file also provides a set of functions and macros for manipulating these data structures, including operations for inserting, removing, and querying packet metadata. It uses a treap data structure to efficiently manage and search through packet metadata, allowing for quick access and updates. The header file defines a public API for initializing metadata trackers, inserting and removing packet metadata, and iterating over metadata entries. This functionality is critical for maintaining the reliability and efficiency of a QUIC connection, as it ensures that data is correctly tracked and managed throughout the communication process.
# Imports and Dependencies

---
- `fd_quic_common.h`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_treap.c`


# Global Variables

---
### fd\_quic\_pkt\_meta\_tracker\_init
- **Type**: `function pointer`
- **Description**: The `fd_quic_pkt_meta_tracker_init` is a function that initializes a QUIC packet metadata tracker for each encoding level. It takes a pointer to a `fd_quic_pkt_meta_tracker_t` structure, a total count of metadata entries, and a pointer to a pool of `fd_quic_pkt_meta_t` structures.
- **Use**: This function is used to set up the metadata tracker, preparing it to manage packet metadata across different encoding levels.


---
### fd\_quic\_pkt\_meta\_min
- **Type**: `function pointer`
- **Description**: The `fd_quic_pkt_meta_min` is a function that returns a pointer to the `fd_quic_pkt_meta_t` structure with the smallest packet number in the given data structure `ds`. It is used to identify the packet metadata with the minimum packet number within a collection of packet metadata entries.
- **Use**: This function is used to retrieve the packet metadata with the smallest packet number from a data structure, which is useful for operations that need to process or remove the earliest sent packet metadata.


# Data Structures

---
### fd\_quic\_pkt\_meta\_t
- **Type**: `struct`
- **Members**:
    - `key`: Stores metadata about what was sent in the identified packet.
    - `val`: Holds the value associated with the packet metadata, either as a scalar or a range.
    - `enc_level`: Indicates the encryption level of the packet.
    - `pn_space`: Represents the packet number space, derived from the encryption level.
    - `tx_time`: Records the time the packet was transmitted.
    - `expiry`: Specifies the time by which an acknowledgment is expected.
    - `parent`: Treap field indicating the parent node in the data structure.
    - `left`: Treap field indicating the left child node in the data structure.
    - `right`: Treap field indicating the right child node in the data structure.
    - `prio`: Treap field representing the priority of the node.
    - `next`: Treap field pointing to the next node in the sequence.
    - `prev`: Treap field pointing to the previous node in the sequence.
- **Description**: The `fd_quic_pkt_meta_t` structure is designed to track metadata for packets sent to a peer in a QUIC protocol implementation. It includes fields for identifying the packet, such as the packet number and type, as well as additional metadata like encryption level, transmission time, and expected acknowledgment time. The structure also incorporates treap fields to facilitate efficient data organization and retrieval, making it suitable for managing packet metadata in a dynamic and high-performance networking environment.


---
### fd\_quic\_pkt\_meta\_list\_t
- **Type**: `typedef struct fd_quic_pkt_meta_list fd_quic_pkt_meta_list_t;`
- **Description**: The `fd_quic_pkt_meta_list_t` is a typedef for a structure that is not explicitly defined in the provided code. It is likely intended to represent a list or collection of packet metadata (`fd_quic_pkt_meta_t`) used in the context of QUIC protocol operations, but without further details or member definitions, its specific structure and purpose remain unspecified in the given code.


---
### fd\_quic\_pkt\_meta\_tracker\_t
- **Type**: `struct`
- **Members**:
    - `sent_pkt_metas`: An array of four data structures that track sent packet metadata for different encoding levels.
    - `pool`: A pointer to a pool of packet metadata structures used for managing memory allocation.
- **Description**: The `fd_quic_pkt_meta_tracker_t` structure is designed to manage and track metadata for QUIC packets that have been sent. It maintains an array of data structures, `sent_pkt_metas`, each corresponding to a different encoding level, to efficiently track and manage the metadata of sent packets. The `pool` member is a pointer to a pool of `fd_quic_pkt_meta_t` structures, which are used to store the metadata of individual packets. This structure is essential for handling packet acknowledgments and retransmissions in the QUIC protocol by keeping track of what data has been sent and needs to be acknowledged.


---
### fd\_quic\_pkt\_meta\_key
- **Type**: `union`
- **Members**:
    - `type`: A 4-bit field indicating the type of frame recorded, such as handshake data or stream data.
    - `pkt_num`: A 60-bit field representing the packet number that carried the data.
    - `stream_id`: An unsigned long representing the stream ID if the type is stream data.
    - `b`: An array of two unsigned long integers used for alternative access to the data.
- **Description**: The `fd_quic_pkt_meta_key` is a union data structure used to track metadata for sent frames in a QUIC protocol implementation. It contains a struct with fields for the frame type, packet number, and stream ID, allowing for efficient storage and retrieval of packet metadata. The union also provides an alternative representation as an array of two unsigned long integers, facilitating operations that require direct manipulation of the underlying data. This structure is integral to managing and tracking the state of sent packets, particularly in handling retransmissions and acknowledgments.


---
### fd\_quic\_pkt\_meta\_key\_t
- **Type**: `union`
- **Members**:
    - `type`: A 4-bit field indicating the type of data, such as handshake data or stream data.
    - `pkt_num`: A 60-bit field representing the packet number that carried the data.
    - `stream_id`: An unsigned long representing the stream ID if the type is stream data.
    - `b`: An array of two unsigned long integers used for accessing the union as raw data.
- **Description**: The `fd_quic_pkt_meta_key_t` is a union data structure used as a key for tracking sent frames in a QUIC protocol implementation. It contains fields for the packet number, type of data, and stream ID, which are used to uniquely identify and manage the metadata of packets sent over the network. The union allows for efficient storage and manipulation of these fields, with the `b` array providing a raw data view for operations that require it. This structure is crucial for handling retransmissions and acknowledgments in the QUIC protocol.


---
### fd\_quic\_pkt\_meta\_value
- **Type**: `union`
- **Members**:
    - `scalar`: A single unsigned long integer value.
    - `range`: A structure of type fd_quic_range_t, representing a range.
- **Description**: The `fd_quic_pkt_meta_value` is a union data structure that can store either a scalar value or a range. This allows for flexible storage of packet metadata values, where the specific type of data stored can be determined at runtime. The union is used within the context of QUIC packet metadata management, providing a way to handle different types of metadata values efficiently.


---
### fd\_quic\_pkt\_meta\_value\_t
- **Type**: `union`
- **Members**:
    - `scalar`: A single unsigned long integer value.
    - `range`: A structure of type fd_quic_range_t, representing a range of values.
- **Description**: The `fd_quic_pkt_meta_value_t` is a union that can store either a single scalar value or a range of values, represented by the `fd_quic_range_t` structure. This union is used within the QUIC packet metadata tracking system to hold additional data associated with a packet, allowing for flexible storage of either a simple numeric value or a more complex range structure.


---
### fd\_quic\_pkt\_meta
- **Type**: `struct`
- **Members**:
    - `key`: Stores the key metadata about the packet, including packet number, type, and stream ID.
    - `val`: Holds the value metadata, which can be a scalar or a range.
    - `enc_level`: Indicates the encryption level of the packet using 2 bits.
    - `pn_space`: Represents the packet number space, derived from the encryption level.
    - `tx_time`: Records the time when the packet was transmitted.
    - `expiry`: Specifies the expiration time of the packet metadata, indicating when an acknowledgment is expected.
    - `parent`: Treap field representing the parent node in the treap structure.
    - `left`: Treap field representing the left child node in the treap structure.
    - `right`: Treap field representing the right child node in the treap structure.
    - `prio`: Treap field representing the priority of the node in the treap structure.
    - `next`: Treap field representing the next node in the treap structure.
    - `prev`: Treap field representing the previous node in the treap structure.
- **Description**: The `fd_quic_pkt_meta` structure is designed to track metadata for packets sent in a QUIC protocol implementation. It includes fields for identifying the packet through a key, storing additional metadata values, and managing packet lifecycle through transmission and expiration times. The structure also incorporates treap fields to facilitate efficient data organization and retrieval, making it suitable for handling acknowledgment processes and packet tracking in a network communication context.


---
### fd\_quic\_pkt\_meta\_tracker
- **Type**: `struct`
- **Members**:
    - `sent_pkt_metas`: An array of four fd_quic_pkt_meta_ds_t structures used to track sent packet metadata.
    - `pool`: A pointer to a pool of fd_quic_pkt_meta_t structures used for managing packet metadata.
- **Description**: The `fd_quic_pkt_meta_tracker` structure is designed to manage and track metadata for QUIC packets that have been sent. It contains an array of `fd_quic_pkt_meta_ds_t` structures, each responsible for tracking metadata for a specific encoding level, and a pointer to a pool of `fd_quic_pkt_meta_t` structures, which are used to store the actual metadata information. This structure is essential for handling acknowledgments and retransmissions in the QUIC protocol by keeping track of what data has been sent and needs to be acknowledged.


# Functions

---
### fd\_quic\_pkt\_meta\_cmp<!-- {{#callable:fd_quic_pkt_meta_cmp}} -->
The `fd_quic_pkt_meta_cmp` function compares a packet metadata key with a packet metadata structure to determine their relative order based on packet number and stream ID.
- **Inputs**:
    - `q`: A `fd_quic_pkt_meta_key_t` structure representing the key to compare.
    - `e`: A pointer to a `fd_quic_pkt_meta_t` structure representing the packet metadata to compare against.
- **Control Flow**:
    - Extracts the first element of the `b` array from both `q` and `e->key` to `q_b` and `e_b`, respectively.
    - Extracts the `stream_id` from both `q` and `e->key` to `q_s` and `e_s`, respectively.
    - Calculates `pkt_num_type_cmp` as a branchless comparison of `q_b` and `e_b`, resulting in -2 if `q_b` is less, 2 if `q_b` is greater, and 0 if they are equal.
    - Calculates `stream_id_cmp` as a branchless comparison of `q_s` and `e_s`, resulting in -1 if `q_s` is less, 1 if `q_s` is greater, and 0 if they are equal.
    - Returns the sum of `pkt_num_type_cmp` and `stream_id_cmp` as the final comparison result.
- **Output**: An integer representing the comparison result: negative if `q` is less than `e`, positive if `q` is greater than `e`, and zero if they are equal.


---
### fd\_quic\_pkt\_meta\_lt<!-- {{#callable:fd_quic_pkt_meta_lt}} -->
The `fd_quic_pkt_meta_lt` function compares two `fd_quic_pkt_meta_t` structures to determine if the first is less than the second based on their packet number and stream ID.
- **Inputs**:
    - `e1`: A pointer to the first `fd_quic_pkt_meta_t` structure to be compared.
    - `e2`: A pointer to the second `fd_quic_pkt_meta_t` structure to be compared.
- **Control Flow**:
    - Extract the first element of the key (b[0]) from both `e1` and `e2` into `e1_b0` and `e2_b0` respectively.
    - Check if `e1_b0` is less than `e2_b0`; if true, return true (1).
    - If `e1_b0` is equal to `e2_b0`, compare the `stream_id` of `e1` and `e2`.
    - Return true (1) if `e1->key.stream_id` is less than `e2->key.stream_id`, otherwise return false (0).
- **Output**: Returns an integer value: 1 if `e1` is considered less than `e2`, otherwise 0.


---
### fd\_quic\_pkt\_meta\_ds\_fwd\_iter\_init<!-- {{#callable:fd_quic_pkt_meta_ds_fwd_iter_init}} -->
The function `fd_quic_pkt_meta_ds_fwd_iter_init` initializes a forward iterator for a QUIC packet metadata data structure.
- **Inputs**:
    - `ds`: A pointer to the QUIC packet metadata data structure (`fd_quic_pkt_meta_ds_t`) to be iterated over.
    - `pool`: A pointer to the pool of packet metadata (`fd_quic_pkt_meta_t`) backing the data structure.
- **Control Flow**:
    - The function calls `fd_quic_pkt_meta_treap_fwd_iter_init` with the provided `ds` and `pool` arguments.
    - It returns the result of the `fd_quic_pkt_meta_treap_fwd_iter_init` function call.
- **Output**: The function returns a forward iterator (`fd_quic_pkt_meta_ds_fwd_iter_t`) that points to the beginning of the data structure.


---
### fd\_quic\_pkt\_meta\_ds\_fwd\_iter\_ele<!-- {{#callable:fd_quic_pkt_meta_ds_fwd_iter_ele}} -->
The function `fd_quic_pkt_meta_ds_fwd_iter_ele` retrieves a packet metadata element from a forward iterator in a packet metadata pool.
- **Inputs**:
    - `iter`: A forward iterator of type `fd_quic_pkt_meta_ds_fwd_iter_t` that points to a specific location in the packet metadata data structure.
    - `pool`: A pointer to the pool of packet metadata elements of type `fd_quic_pkt_meta_t` from which the element is to be retrieved.
- **Control Flow**:
    - The function directly calls `fd_quic_pkt_meta_treap_fwd_iter_ele` with the provided iterator and pool as arguments.
    - The function returns the result of the `fd_quic_pkt_meta_treap_fwd_iter_ele` call, which is a pointer to a packet metadata element.
- **Output**: A pointer to a `fd_quic_pkt_meta_t` structure, representing the packet metadata element at the current position of the iterator in the pool.


---
### fd\_quic\_pkt\_meta\_ds\_fwd\_iter\_next<!-- {{#callable:fd_quic_pkt_meta_ds_fwd_iter_next}} -->
The function `fd_quic_pkt_meta_ds_fwd_iter_next` advances an iterator to the next element in a forward iteration over a packet metadata data structure.
- **Inputs**:
    - `iter`: An iterator of type `fd_quic_pkt_meta_ds_fwd_iter_t` that points to the current element in the data structure.
    - `pool`: A pointer to the pool of packet metadata elements of type `fd_quic_pkt_meta_t`.
- **Control Flow**:
    - The function calls `fd_quic_pkt_meta_treap_fwd_iter_next` with the provided iterator and pool as arguments.
    - The function returns the result of the `fd_quic_pkt_meta_treap_fwd_iter_next` call, which is the next iterator in the sequence.
- **Output**: The function returns an iterator of type `fd_quic_pkt_meta_ds_fwd_iter_t` that points to the next element in the data structure.


---
### fd\_quic\_pkt\_meta\_ds\_fwd\_iter\_done<!-- {{#callable:fd_quic_pkt_meta_ds_fwd_iter_done}} -->
The function `fd_quic_pkt_meta_ds_fwd_iter_done` checks if a forward iterator has reached the end of a data structure.
- **Inputs**:
    - `iter`: A forward iterator of type `fd_quic_pkt_meta_ds_fwd_iter_t` that is used to traverse a data structure.
- **Control Flow**:
    - The function calls `fd_quic_pkt_meta_treap_fwd_iter_done` with the provided iterator `iter`.
- **Output**: The function returns a non-zero integer if the iterator has reached the end of the data structure, otherwise it returns 0.


---
### fd\_quic\_pkt\_meta\_ds\_idx\_ge<!-- {{#callable:fd_quic_pkt_meta_ds_idx_ge}} -->
The function `fd_quic_pkt_meta_ds_idx_ge` returns an iterator pointing to the first packet metadata in a data structure whose packet number is greater than or equal to a specified packet number.
- **Inputs**:
    - `ds`: A pointer to the data structure (`fd_quic_pkt_meta_ds_t`) containing packet metadata.
    - `pkt_number`: An unsigned long integer representing the packet number to search for.
    - `pool`: A pointer to the backing pool (`fd_quic_pkt_meta_t`) where packet metadata is stored.
- **Control Flow**:
    - The function constructs a `fd_quic_pkt_meta_key_t` key with the given `pkt_number`, masking it with `FD_QUIC_PKT_META_PKT_NUM_MASK`, and setting `type` and `stream_id` to 0.
    - It calls `fd_quic_pkt_meta_treap_idx_ge` with the data structure, the constructed key, and the pool to find the appropriate iterator.
- **Output**: An iterator (`fd_quic_pkt_meta_ds_fwd_iter_t`) pointing to the first packet metadata with a packet number greater than or equal to the specified `pkt_number`.


---
### fd\_quic\_pkt\_meta\_ds\_ele\_cnt<!-- {{#callable:fd_quic_pkt_meta_ds_ele_cnt}} -->
The function `fd_quic_pkt_meta_ds_ele_cnt` returns the count of elements in a QUIC packet metadata data structure.
- **Inputs**:
    - `ds`: A pointer to a `fd_quic_pkt_meta_ds_t` data structure, which represents a QUIC packet metadata data structure.
- **Control Flow**:
    - The function calls `fd_quic_pkt_meta_treap_ele_cnt` with the provided data structure pointer `ds`.
    - It directly returns the result of the `fd_quic_pkt_meta_treap_ele_cnt` function call.
- **Output**: The function returns an `ulong` representing the number of elements in the specified QUIC packet metadata data structure.


# Function Declarations (Public API)

---
### fd\_quic\_pkt\_meta\_ds\_init\_pool<!-- {{#callable_declaration:fd_quic_pkt_meta_ds_init_pool}} -->
Initialize the packet metadata pool for QUIC data structures.
- **Description**: This function prepares a pool of packet metadata structures for use in QUIC data structures by performing any necessary setup on the entire pool at once. It is typically called once during initialization to ensure that the pool is ready for subsequent operations. The function does not return a value and assumes that the provided pool pointer is valid and that the total_meta_cnt accurately reflects the number of metadata entries in the pool.
- **Inputs**:
    - `pool`: A pointer to the packet metadata pool to be initialized. Must not be null, and the caller retains ownership.
    - `total_meta_cnt`: The total number of metadata entries in the pool. Must be a positive integer.
- **Output**: None
- **See also**: [`fd_quic_pkt_meta_ds_init_pool`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_ds_init_pool)  (Implementation)


---
### fd\_quic\_pkt\_meta\_tracker\_init<!-- {{#callable_declaration:fd_quic_pkt_meta_tracker_init}} -->
Initialize the packet metadata tracker for each encryption level.
- **Description**: This function sets up a packet metadata tracker for managing metadata associated with sent packets across different encryption levels. It should be called before any packet metadata operations are performed, ensuring that the tracker is properly initialized. The function requires a pre-allocated pool of packet metadata entries, which it uses to track sent packets. If the initialization fails, the function returns NULL, indicating that the tracker is not ready for use.
- **Inputs**:
    - `tracker`: A pointer to an fd_quic_pkt_meta_tracker_t structure that will be initialized. Must not be null.
    - `total_meta_cnt`: The total number of packet metadata entries available in the pool, shared across all encryption levels. Must be a positive number.
    - `pool`: A pointer to a pre-allocated array of fd_quic_pkt_meta_t structures, serving as the backing pool for the tracker. Must not be null.
- **Output**: Returns a pointer to the initialized tracker if successful, or NULL if initialization fails.
- **See also**: [`fd_quic_pkt_meta_tracker_init`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_tracker_init)  (Implementation)


---
### fd\_quic\_pkt\_meta\_insert<!-- {{#callable_declaration:fd_quic_pkt_meta_insert}} -->
Insert a packet metadata entry into the data structure.
- **Description**: Use this function to add a packet metadata entry to a specified data structure, which is part of a QUIC protocol implementation. This function should be called when you need to track a new packet's metadata, such as after preparing a packet for transmission. Ensure that the packet metadata entry (`pkt_meta`) has been properly initialized and acquired from the provided pool before calling this function. The data structure (`ds`) and the pool must be valid and properly initialized before use.
- **Inputs**:
    - `ds`: A pointer to the data structure where the packet metadata will be inserted. Must not be null and should be properly initialized.
    - `pkt_meta`: A pointer to the packet metadata to insert. This metadata should be acquired from the pool and must not be null.
    - `pool`: A pointer to the backing pool from which the packet metadata was acquired. Must not be null and should be properly initialized.
- **Output**: None
- **See also**: [`fd_quic_pkt_meta_insert`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_insert)  (Implementation)


---
### fd\_quic\_pkt\_meta\_remove\_range<!-- {{#callable_declaration:fd_quic_pkt_meta_remove_range}} -->
Removes packet metadata within a specified range from the data structure.
- **Description**: Use this function to remove all packet metadata entries within the specified range of packet numbers from the data structure and return them to the pool. This is useful for managing and cleaning up metadata that is no longer needed, such as after processing acknowledgments. The function will skip any packet numbers within the range that are not present in the data structure, ensuring that only existing entries are affected. It is important to ensure that the data structure and pool are properly initialized before calling this function.
- **Inputs**:
    - `ds`: Pointer to the data structure from which packet metadata will be removed. Must be properly initialized and not null.
    - `pool`: Pointer to the backing pool used for managing packet metadata. Must be properly initialized and not null.
    - `pkt_number_lo`: The lower bound of the packet number range to remove. Must be a valid packet number.
    - `pkt_number_hi`: The upper bound of the packet number range to remove. Must be a valid packet number and greater than or equal to pkt_number_lo.
- **Output**: Returns the number of packet metadata entries removed from the data structure.
- **See also**: [`fd_quic_pkt_meta_remove_range`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_remove_range)  (Implementation)


---
### fd\_quic\_pkt\_meta\_min<!-- {{#callable_declaration:fd_quic_pkt_meta_min}} -->
Returns the packet metadata with the smallest packet number from the data structure.
- **Description**: Use this function to retrieve the packet metadata entry with the smallest packet number from a given data structure. This is useful when you need to process or inspect the earliest packet metadata in a sequence. The function requires a valid data structure and a backing pool to operate. If the data structure is empty, the function returns NULL, indicating that there are no packet metadata entries to retrieve.
- **Inputs**:
    - `ds`: A pointer to the fd_quic_pkt_meta_ds_t data structure from which the smallest packet metadata is to be retrieved. Must not be null.
    - `pool`: A pointer to the fd_quic_pkt_meta_t pool that backs the data structure. Must not be null.
- **Output**: Returns a pointer to the fd_quic_pkt_meta_t structure with the smallest packet number, or NULL if the data structure is empty.
- **See also**: [`fd_quic_pkt_meta_min`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_min)  (Implementation)


---
### fd\_quic\_pkt\_meta\_ds\_clear<!-- {{#callable_declaration:fd_quic_pkt_meta_ds_clear}} -->
Clears all packet metadata tracking for a specified encoding level.
- **Description**: Use this function to reset the packet metadata tracking for a specific encoding level within a QUIC packet metadata tracker. This is typically necessary when you want to discard all existing metadata associated with a particular encoding level, perhaps as part of a reinitialization or cleanup process. Ensure that the tracker has been properly initialized before calling this function. The function does not return any value and does not handle invalid encoding levels explicitly, so ensure that the encoding level provided is within the valid range.
- **Inputs**:
    - `tracker`: A pointer to the fd_quic_pkt_meta_tracker_t structure. This must not be null and should be properly initialized before calling this function. The caller retains ownership.
    - `enc_level`: An unsigned integer representing the encoding level to clear. Valid values are typically within the range of encoding levels supported by the tracker, but the function does not explicitly validate this.
- **Output**: None
- **See also**: [`fd_quic_pkt_meta_ds_clear`](fd_quic_pkt_meta.c.driver.md#fd_quic_pkt_meta_ds_clear)  (Implementation)


