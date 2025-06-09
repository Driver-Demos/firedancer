# Purpose
This C header file, `fd_snapshot_restore_private.h`, is part of a larger system designed to handle the restoration of snapshots, likely in a database or data management context. The file defines several data structures and constants that are used internally to manage the restoration process. The primary focus is on managing memory allocation and tracking the state of the snapshot restoration. The `fd_valloc_limit_t` structure is used to wrap a heap allocator with a quota system, ensuring that memory allocations do not exceed a predefined limit. The `fd_snapshot_accv_map_t` structure and associated functions manage the mapping of account vector files, which are loaded from snapshots, using a hash map to store file size information necessary for processing these files.

The file also defines the `fd_snapshot_restore` structure, which encapsulates the state and parameters required for restoring a snapshot. This includes buffer management for reading file contents, handling account vector files, and managing callbacks for various stages of the restoration process. The state machine for processing snapshot files is defined through a series of state identifiers, which guide the restoration process through different stages such as reading manifests, account headers, and account data. This header file is intended for internal use within the snapshot restoration module, as indicated by its inclusion of private data structures and functions, and it does not define public APIs or external interfaces.
# Imports and Dependencies

---
- `fd_snapshot_restore.h`
- `../../util/tmpl/fd_map.c`


# Global Variables

---
### fd\_snapshot\_accv\_key\_null
- **Type**: `fd_snapshot_accv_key_t`
- **Description**: The `fd_snapshot_accv_key_null` is a constant of type `fd_snapshot_accv_key_t`, which is a structure containing two unsigned long integers, both initialized to zero. This structure is used as a key in a mapping system to represent an invalid or null state.
- **Use**: This variable is used as a sentinel value to represent an invalid or uninitialized key in the `fd_snapshot_accv_map` data structure.


# Data Structures

---
### fd\_valloc\_limit
- **Type**: `struct`
- **Members**:
    - `valloc`: A heap allocator used for memory allocation.
    - `quota`: The current allocation quota, which limits the amount of memory that can be allocated.
    - `quota_orig`: The original allocation quota, used to reset or reference the initial quota value.
- **Description**: The `fd_valloc_limit` structure is designed to manage memory allocation with a specified quota. It wraps around a heap allocator (`fd_valloc_t`) and tracks the allocation quota, which is the maximum amount of memory that can be allocated. If the quota is exceeded, it is set to zero, and further allocation attempts will fail, returning NULL. However, deallocations are always allowed and forwarded to the underlying allocator. This structure is useful for managing memory resources in a controlled manner, ensuring that allocations do not exceed a predefined limit.


---
### fd\_valloc\_limit\_t
- **Type**: `struct`
- **Members**:
    - `valloc`: A heap allocator used for memory allocation.
    - `quota`: The current allocation quota, which decreases with each allocation.
    - `quota_orig`: The original allocation quota set at the beginning.
- **Description**: The `fd_valloc_limit_t` structure is designed to manage memory allocation with a quota limit. It wraps around a heap allocator (`fd_valloc_t`) and tracks the allocation quota. When the quota is exceeded, it is set to zero, and further allocation attempts return NULL, although deallocations are still processed by the underlying allocator. This structure is useful for controlling memory usage in applications where exceeding a certain memory limit is undesirable.


---
### fd\_snapshot\_accv\_key
- **Type**: `struct`
- **Members**:
    - `slot`: Represents a unique slot number associated with the account vector.
    - `id`: Represents a unique identifier for the account vector within the slot.
- **Description**: The `fd_snapshot_accv_key` structure is used to uniquely identify an account vector within a snapshot by combining a slot number and an account vector identifier. This structure is part of a larger system that manages snapshots, which are used to store and retrieve account data efficiently. The `slot` and `id` fields together form a composite key that can be used in hash maps or other data structures to quickly access account vector information.


---
### fd\_snapshot\_accv\_key\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the account vector key.
    - `id`: Represents the identifier for the account vector key.
- **Description**: The `fd_snapshot_accv_key_t` structure is used to uniquely identify account vector files within a snapshot system. It consists of two members: `slot`, which indicates the slot number, and `id`, which serves as an identifier for the account vector. This structure is essential for mapping and managing account data within the snapshot, allowing for efficient retrieval and storage of account-related information.


---
### fd\_snapshot\_accv\_map
- **Type**: `struct`
- **Members**:
    - `key`: A key of type `fd_snapshot_accv_key_t` used to identify the account vector.
    - `sz`: An unsigned long integer representing the size of the account vector.
    - `hash`: An unsigned long integer representing the hash value of the key.
- **Description**: The `fd_snapshot_accv_map` structure is designed to store metadata about account vectors loaded from a snapshot, specifically their size and a hash of their identifying key. This structure is part of a larger system that manages the restoration of snapshots, where each account vector is identified by a unique key and its size is tracked for efficient data management. The hash field is used to quickly access or verify the integrity of the account vector data.


---
### fd\_snapshot\_accv\_map\_t
- **Type**: `struct`
- **Members**:
    - `key`: A key of type `fd_snapshot_accv_key_t` used to identify entries in the map.
    - `sz`: An unsigned long integer representing the size associated with the key.
    - `hash`: An unsigned long integer representing the hash value of the key for efficient lookup.
- **Description**: The `fd_snapshot_accv_map_t` structure is designed to store and manage file size information for account vectors loaded from a snapshot. It uses a key of type `fd_snapshot_accv_key_t` to uniquely identify each entry, and associates a size and a hash value with each key. This structure is part of a larger system that handles snapshot restoration, where it helps in managing the size of account vector files by storing and retrieving this information efficiently using hash-based lookups.


---
### fd\_snapshot\_restore
- **Type**: `struct`
- **Members**:
    - `funk`: Pointer to an fd_funk_t structure.
    - `funk_txn`: Pointer to an fd_funk_txn_t structure.
    - `spad`: Pointer to an fd_spad_t structure.
    - `slot`: Slot number the snapshot was taken at.
    - `state`: Current state of the snapshot restore process.
    - `manifest_done`: Indicates if the manifest processing is complete.
    - `status_cache_done`: Flag indicating if the status cache processing is complete.
    - `failed`: Flag indicating if the restore process has failed.
    - `buf`: Pointer to the first byte of the buffer used for gathering file content.
    - `buf_ctr`: Number of bytes currently allocated in the buffer.
    - `buf_sz`: Target size for the buffer, indicating an incomplete read if buf_ctr is less.
    - `buf_cap`: Total byte capacity of the buffer.
    - `accv_slot`: Slot number for the account vector.
    - `accv_id`: Index of the account vector.
    - `accv_sz`: Size of the account vector.
    - `accv_map`: Pointer to an fd_snapshot_accv_map_t structure for account vector mapping.
    - `acc_sz`: Number of account bytes pending write.
    - `acc_data`: Pointer to the account data pending write.
    - `acc_pad`: Padding size at the end of the account data.
    - `cb_manifest`: Callback function for manifest processing.
    - `cb_manifest_ctx`: Context for the manifest callback function.
    - `cb_status_cache`: Callback function for status cache processing.
    - `cb_status_cache_ctx`: Context for the status cache callback function.
    - `cb_rent_fresh_account`: Callback function for processing fresh account rent.
    - `cb_rent_fresh_account_ctx`: Context for the fresh account rent callback function.
- **Description**: The `fd_snapshot_restore` structure is designed to manage the restoration of a snapshot in a system, likely related to a blockchain or distributed ledger, as indicated by the use of terms like 'account' and 'slot'. It contains pointers to various structures (`fd_funk_t`, `fd_funk_txn_t`, `fd_spad_t`) that are presumably part of the system's state management. The structure also includes fields for managing buffer parameters, account vector parameters, and account size, which are crucial for handling the data restoration process. Additionally, it supports callback functions for processing manifests, status caches, and fresh account rents, allowing for custom handling of these components during the restore process. The presence of state indicators and flags for completion and failure suggests a robust mechanism for tracking the progress and success of the restoration operation.


# Functions

---
### fd\_snapshot\_accv\_key\_hash<!-- {{#callable:fd_snapshot_accv_key_hash}} -->
The `fd_snapshot_accv_key_hash` function computes a hash value for a given `fd_snapshot_accv_key_t` key using a specific seed value.
- **Inputs**:
    - `key`: A `fd_snapshot_accv_key_t` structure containing a `slot` and `id` used to identify an account vector.
- **Control Flow**:
    - The function calls `fd_hash` with a fixed seed value `0x39c49607bf16463aUL`.
    - It passes the address of the `key` and its size to `fd_hash` to compute the hash.
- **Output**: The function returns an `ulong` representing the hash value of the input key.


