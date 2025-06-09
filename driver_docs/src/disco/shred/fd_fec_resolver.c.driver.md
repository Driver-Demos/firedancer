# Purpose
The provided C source code file is part of a larger system designed to handle Forward Error Correction (FEC) for data shreds, which are likely used in a distributed or networked environment to ensure data integrity and reliability. The code defines a `fd_fec_resolver` structure and associated functions to manage FEC sets, which are collections of data and parity shreds. The primary purpose of this code is to track, validate, and reconstruct FEC sets from incoming shreds, ensuring that data can be recovered even in the presence of packet loss. The code includes mechanisms for handling Merkle tree-based integrity checks, signature verification, and Reed-Solomon error correction, which are critical for maintaining data integrity and authenticity.

The file includes several components, such as data structures for managing FEC sets (`set_ctx_t` and `fd_fec_resolver_t`), utility functions for managing linked lists and maps, and functions for creating, joining, and deleting FEC resolver instances. The code also defines functions for adding shreds to the resolver, checking if a shred is part of a completed FEC set, and querying shreds. The use of templates for dynamic data structures like deques and maps indicates a focus on efficient memory management and performance. The code is intended to be part of a library or module that can be integrated into a larger application, providing specialized functionality for FEC management without defining a public API or external interfaces directly in this file.
# Imports and Dependencies

---
- `../../ballet/shred/fd_shred.h`
- `../../ballet/shred/fd_fec_set.h`
- `../../ballet/sha512/fd_sha512.h`
- `../../ballet/reedsol/fd_reedsol.h`
- `../metrics/fd_metrics.h`
- `fd_fec_resolver.h`
- `../../util/tmpl/fd_deque_dynamic.c`
- `../../util/tmpl/fd_map_dynamic.c`


# Global Variables

---
### null\_signature
- **Type**: `wrapped_sig_t`
- **Description**: The `null_signature` is a global constant of type `wrapped_sig_t`, initialized with a zeroed-out signature. It serves as a placeholder or default value for a signature that is considered invalid or uninitialized.
- **Use**: This variable is used as a null or invalid key in maps to identify uninitialized or invalid entries.


# Data Structures

---
### wrapped\_sig\_t
- **Type**: `union`
- **Members**:
    - `u`: A member of type `fd_ed25519_sig_t` used to store an Ed25519 signature.
    - `l`: A member of type `ulong` used to store a long integer representation of the signature.
- **Description**: The `wrapped_sig_t` is a union data structure designed to encapsulate an Ed25519 signature in two different forms: as a `fd_ed25519_sig_t` type and as a `ulong` type. This allows for flexible handling of the signature, enabling operations that require either the signature's original form or a numeric representation. The union is particularly useful in contexts where both forms of the signature might be needed for different operations, such as hashing or comparison.


---
### set\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `sig`: A wrapped signature used for identification and validation.
    - `set`: Pointer to an FEC set structure, representing a collection of shreds.
    - `tree`: Pointer to a Merkle tree commit structure for integrity verification.
    - `prev`: Pointer to the previous context in a linked list.
    - `next`: Pointer to the next context in a linked list.
    - `total_rx_shred_cnt`: Total count of received shreds in this context.
    - `fec_set_idx`: Index of the FEC set within the context.
    - `parity_idx0`: Index of the first parity shred in the FEC set.
    - `data_variant`: Variant type of the data shreds.
    - `parity_variant`: Variant type of the parity shreds.
    - `retransmitter_sig`: Signature of the root of the Merkle tree if the FEC set has resigned shreds.
- **Description**: The `set_ctx_t` structure is a context for managing Forward Error Correction (FEC) sets, which are collections of data and parity shreds used for error correction in data transmission. It includes a signature for identification, pointers to the FEC set and its associated Merkle tree for integrity checks, and links to other contexts in a doubly linked list. The structure also tracks the total number of received shreds, the index of the FEC set, and the index of the first parity shred. Additionally, it stores variant types for data and parity shreds and a retransmitter signature for resigned shreds, facilitating the management and validation of FEC sets in a networked environment.


---
### set\_ctx
- **Type**: `struct`
- **Members**:
    - `sig`: A wrapped signature used as a unique identifier for the context.
    - `set`: A pointer to an FEC set structure associated with this context.
    - `tree`: A pointer to a Merkle tree commit structure for managing Merkle proofs.
    - `prev`: A pointer to the previous context in a linked list.
    - `next`: A pointer to the next context in a linked list.
    - `total_rx_shred_cnt`: The total number of shreds received in this context.
    - `fec_set_idx`: The index of the FEC set within the context.
    - `parity_idx0`: The shred index of the first parity shred in this FEC set.
    - `data_variant`: A variant identifier for data shreds.
    - `parity_variant`: A variant identifier for parity shreds.
    - `retransmitter_sig`: A signature of the root of the Merkle tree if the FEC set has resigned shreds.
- **Description**: The `set_ctx` structure is a context object used in managing Forward Error Correction (FEC) sets within a system that processes shreds, which are data packets used in distributed systems. It contains pointers to an FEC set and a Merkle tree, as well as linked list pointers for managing a collection of contexts. The structure also tracks the number of shreds received, the index of the FEC set, and variant information for data and parity shreds. Additionally, it includes a retransmitter signature for verifying the integrity of the Merkle tree when shreds are resigned.


---
### fd\_fec\_resolver
- **Type**: `struct`
- **Members**:
    - `depth`: Stores the number of FEC sets this resolver can track simultaneously.
    - `partial_depth`: Stores the minimum size of the free FEC set list.
    - `complete_depth`: Stores the size of the completed FEC set list.
    - `done_depth`: Stores the depth of the done tcache, i.e., the number of done FEC set keys remembered.
    - `expected_shred_version`: Specifies the shred version to accept, discarding others.
    - `curr_map`: A map from tags of signatures to context objects, sized at 2*depth for performance.
    - `curr_ll_sentinel`: A sentinel node for a circular doubly linked list of curr_map elements.
    - `done_map`: Stores signatures of recently completed FEC sets, using a linked list.
    - `done_ll_sentinel`: A sentinel node for a circular doubly linked list of done_map elements.
    - `free_list`: A deque of FEC sets not in curr_map contexts.
    - `complete_list`: A deque of completed FEC sets.
    - `bmtree_free_list`: Stores footprints for bmtree objects not in curr_map contexts.
    - `signer`: Function pointer used to sign shreds requiring a retransmitter signature.
    - `sign_ctx`: Context provided as the first argument to the signer function.
    - `max_shred_idx`: Exclusive upper bound for shred indices, rejecting shreds with index >= max_shred_idx.
    - `sha512`: Used for calculations while adding a shred, with indeterminate state outside calls.
    - `reedsol`: Used for calculations while adding a shred, with indeterminate state outside calls.
- **Description**: The `fd_fec_resolver` structure is designed to manage Forward Error Correction (FEC) sets, tracking their states and handling shreds (data packets) within a network. It maintains various lists and maps to efficiently manage the lifecycle of FEC sets, including those that are in progress, completed, or free for reuse. The structure uses maps to associate signatures with context objects, and linked lists to manage the order and state of these objects. It also includes mechanisms for signing shreds and ensuring that only shreds with the expected version and within a certain index range are processed. The structure is aligned to a specific boundary for performance reasons and includes fields for cryptographic operations and error correction calculations.


---
### fd\_fec\_resolver\_t
- **Type**: `struct`
- **Members**:
    - `depth`: Stores the number of FEC sets the resolver can track simultaneously.
    - `partial_depth`: Stores the minimum size of the free FEC set list.
    - `complete_depth`: Stores the size of the completed FEC set list.
    - `done_depth`: Stores the depth of the done tcache, i.e., the number of done FEC set keys remembered.
    - `expected_shred_version`: Specifies the shred version to accept, discarding others.
    - `curr_map`: A map from tags of signatures to context objects, sized at 2*depth for performance.
    - `curr_ll_sentinel`: A sentinel node for the circular doubly linked list of curr_map elements.
    - `done_map`: Stores signatures of recently completed FEC sets, similar to curr_map.
    - `done_ll_sentinel`: A sentinel node for the done map's linked list.
    - `free_list`: A deque of FEC sets not in curr_map contexts, needing reset when popped.
    - `complete_list`: A deque of completed FEC sets, needing reset when popped.
    - `bmtree_free_list`: Stores footprints for bmtree objects not in curr_map contexts.
    - `signer`: Function pointer used to sign shreds requiring a retransmitter signature.
    - `sign_ctx`: Context provided as the first argument to the signer function.
    - `max_shred_idx`: Exclusive upper bound for shred indices, rejecting shreds with index >= max_shred_idx.
    - `sha512`: Used for calculations while adding a shred, with indeterminate state outside calls.
    - `reedsol`: Used for calculations while adding a shred, with indeterminate state outside calls.
- **Description**: The `fd_fec_resolver_t` structure is designed to manage Forward Error Correction (FEC) sets, tracking their state and processing shreds (data packets) within a network. It maintains several lists and maps to handle current, completed, and free FEC sets, ensuring efficient management and retrieval of shreds. The structure also incorporates mechanisms for verifying shred signatures and managing Merkle trees for data integrity. It is aligned to `FD_FEC_RESOLVER_ALIGN` and includes fields for managing shred versions, indices, and signing contexts, making it a comprehensive solution for FEC set resolution in a networked environment.


# Functions

---
### fd\_fec\_resolver\_footprint<!-- {{#callable:fd_fec_resolver_footprint}} -->
The `fd_fec_resolver_footprint` function calculates the memory footprint required for a Forward Error Correction (FEC) resolver based on various depth parameters.
- **Inputs**:
    - `depth`: The number of FEC sets the resolver can track simultaneously.
    - `partial_depth`: The minimum size of the free FEC set list.
    - `complete_depth`: The size of the completed FEC set list.
    - `done_depth`: The depth of the done tcache, i.e., the number of done FEC set keys the resolver remembers.
- **Control Flow**:
    - Check if any of the input depths are zero or if 'depth' or 'done_depth' are too large, returning 0 if so to prevent overflow.
    - Calculate the logarithm of the current and done map counts using the most significant bit of 'depth' and 'done_depth', respectively, and add 2 to each.
    - Calculate the footprint per binary Merkle tree using a predefined constant.
    - Initialize a layout variable and append various components to it, including the FEC resolver structure, context maps, freelists, and binary Merkle trees, each with specific alignments and footprints.
    - Return the finalized layout size, aligned to the FEC resolver's alignment.
- **Output**: The function returns an unsigned long integer representing the total memory footprint required for the FEC resolver, or 0 if the input parameters are invalid.


---
### fd\_fec\_resolver\_align<!-- {{#callable:fd_fec_resolver_align}} -->
The `fd_fec_resolver_align` function returns the alignment requirement for the FEC resolver structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a constant function, meaning it does not modify any state and always returns the same value.
    - It directly returns the value of the macro `FD_FEC_RESOLVER_ALIGN`.
- **Output**: The function returns an `ulong` representing the alignment requirement for the FEC resolver.


---
### fd\_fec\_resolver\_new<!-- {{#callable:fd_fec_resolver_new}} -->
The `fd_fec_resolver_new` function initializes a new Forward Error Correction (FEC) resolver using shared memory and various parameters to manage FEC sets and their associated data structures.
- **Inputs**:
    - `shmem`: A pointer to shared memory where the FEC resolver will be initialized.
    - `signer`: A function pointer for signing shreds that require a retransmitter signature.
    - `sign_ctx`: A context pointer passed to the signer function.
    - `depth`: The number of FEC sets the resolver can track simultaneously.
    - `partial_depth`: The minimum size of the free FEC set list.
    - `complete_depth`: The size of the completed FEC set list.
    - `done_depth`: The depth of the done cache, i.e., the number of completed FEC set keys remembered.
    - `sets`: A pointer to an array of FEC sets.
    - `expected_shred_version`: The expected version of shreds; shreds with a different version are discarded.
    - `max_shred_idx`: The exclusive upper bound for shred indices, used to reject shreds with indices greater than or equal to this value.
- **Control Flow**:
    - Check if any of the depth parameters are zero or exceed a certain limit, returning NULL if so.
    - Calculate the logarithmic map counts for current and done maps based on depth and done_depth.
    - Initialize memory allocations for various components of the resolver using a scratch allocator.
    - Create new maps, freelists, and bmtree lists, logging warnings and returning NULL if any initialization fails.
    - Initialize the free and complete lists with the provided FEC sets.
    - Initialize the bmtree list with memory footprints for bmtree objects.
    - Check if the expected shred version is zero, logging a warning and returning NULL if so.
    - Set up the resolver's linked list sentinels and assign input parameters to the resolver's fields.
    - Return the shared memory pointer if all initializations are successful.
- **Output**: A pointer to the initialized shared memory containing the FEC resolver, or NULL if initialization fails.


---
### fd\_fec\_resolver\_join<!-- {{#callable:fd_fec_resolver_join}} -->
The `fd_fec_resolver_join` function initializes and joins various data structures for a Forward Error Correction (FEC) resolver using shared memory.
- **Inputs**:
    - `shmem`: A pointer to shared memory where the FEC resolver and its associated data structures are stored.
- **Control Flow**:
    - Cast the shared memory pointer to an `fd_fec_resolver_t` pointer to access the resolver structure.
    - Retrieve the `depth`, `partial_depth`, `complete_depth`, and `done_depth` from the resolver structure.
    - Calculate `lg_curr_map_cnt` and `lg_done_map_cnt` using the most significant bit of `depth` and `done_depth`, respectively, plus 2.
    - Initialize scratch memory allocation using `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for various data structures (`curr`, `done`, `free`, `cmplst`, `bmfree`) using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch memory allocation with `FD_SCRATCH_ALLOC_FINI`.
    - Join the `curr_map`, `done_map`, `free_list`, `complete_list`, and `bmtree_free_list` using their respective join functions.
    - Check if any of the join operations failed, returning `NULL` if so.
    - Join the SHA-512 context using `fd_sha512_join` and return `NULL` if it fails.
    - Return the initialized `fd_fec_resolver_t` pointer.
- **Output**: A pointer to the initialized `fd_fec_resolver_t` structure, or `NULL` if any initialization step fails.


---
### ctx\_ll\_remove<!-- {{#callable:ctx_ll_remove}} -->
The `ctx_ll_remove` function removes a node from a doubly linked list and returns the removed node.
- **Inputs**:
    - `r`: A pointer to the node (`set_ctx_t`) to be removed from the linked list.
- **Control Flow**:
    - The function sets the `prev` pointer of the node following `r` to point to the node preceding `r`.
    - The function sets the `next` pointer of the node preceding `r` to point to the node following `r`.
    - The `next` and `prev` pointers of `r` are set to `NULL`, effectively removing it from the list.
    - The function returns the pointer `r`.
- **Output**: The function returns the pointer to the removed node `r`.


---
### ctx\_ll\_insert<!-- {{#callable:ctx_ll_insert}} -->
The `ctx_ll_insert` function inserts a node `c` immediately after node `p` in a doubly linked list and returns the inserted node `c`.
- **Inputs**:
    - `p`: A pointer to a `set_ctx_t` node in the linked list after which the new node `c` will be inserted.
    - `c`: A pointer to a `set_ctx_t` node that is to be inserted into the linked list.
- **Control Flow**:
    - Set `c->next` to `p->next`, linking `c` to the node following `p`.
    - Set `c->prev` to `p`, linking `c` back to `p`.
    - Set `p->next->prev` to `c`, updating the previous link of the node originally following `p` to point to `c`.
    - Set `p->next` to `c`, updating the next link of `p` to point to `c`.
- **Output**: Returns the pointer to the inserted node `c`.


---
### fd\_fec\_resolver\_add\_shred<!-- {{#callable:fd_fec_resolver_add_shred}} -->
The `fd_fec_resolver_add_shred` function processes a shred, validates it, and integrates it into an FEC set for error correction and data recovery.
- **Inputs**:
    - `resolver`: A pointer to an `fd_fec_resolver_t` structure that manages FEC sets and their states.
    - `shred`: A constant pointer to an `fd_shred_t` structure representing the shred to be added.
    - `shred_sz`: The size of the shred in bytes.
    - `leader_pubkey`: A constant pointer to the leader's public key used for signature verification.
    - `out_fec_set`: A pointer to a pointer where the function will store the address of the FEC set that the shred belongs to.
    - `out_shred`: A pointer to a pointer where the function will store the address of the shred within the FEC set.
    - `out_merkle_root`: A pointer to an `fd_bmtree_node_t` where the function will store the Merkle root if applicable.
- **Control Flow**:
    - Unpack variables from the resolver structure for easier access.
    - Check if the shred's signature is invalid or if the FEC set is already completed, returning early if so.
    - Determine the type of shred and validate its version, size, and index against expected values.
    - Calculate the Merkle tree depth and protected sizes for data and parity shreds.
    - If the shred is the first in its FEC set, allocate resources and verify its signature and Merkle root.
    - If the shred is not the first, check for duplicates and consistency with existing shreds in the FEC set.
    - Copy the shred to the resolver's memory and update the received shred count.
    - If enough shreds are received, attempt to reconstruct missing data using Reed-Solomon error correction.
    - Validate the reconstructed FEC set, ensuring consistency and completeness.
    - If successful, finalize the Merkle tree and forward the completed FEC set.
- **Output**: Returns an integer status code indicating the result of the operation, such as `FD_FEC_RESOLVER_SHRED_COMPLETES`, `FD_FEC_RESOLVER_SHRED_OKAY`, or `FD_FEC_RESOLVER_SHRED_REJECTED`.
- **Functions called**:
    - [`ctx_ll_insert`](#ctx_ll_insert)
    - [`ctx_ll_remove`](#ctx_ll_remove)


---
### fd\_fec\_resolver\_done\_contains<!-- {{#callable:fd_fec_resolver_done_contains}} -->
The function `fd_fec_resolver_done_contains` checks if a given signature is present in the 'done' map of a Forward Error Correction (FEC) resolver.
- **Inputs**:
    - `resolver`: A pointer to an `fd_fec_resolver_t` structure, which manages FEC sets and their states.
    - `signature`: A constant pointer to an `fd_ed25519_sig_t` structure representing the signature to be checked in the 'done' map.
- **Control Flow**:
    - Cast the `signature` to a `wrapped_sig_t` pointer named `w_sig`.
    - Check if the key represented by `w_sig` is invalid using `ctx_map_key_inval`; if invalid, return 0.
    - Query the `done_map` of the `resolver` using `ctx_map_query` with `w_sig` as the key.
    - Return the result of the query as a boolean (1 if found, 0 if not).
- **Output**: The function returns an integer: 1 if the signature is found in the 'done' map, and 0 otherwise.


---
### fd\_fec\_resolver\_shred\_query<!-- {{#callable:fd_fec_resolver_shred_query}} -->
The `fd_fec_resolver_shred_query` function retrieves a specific data shred from a Forward Error Correction (FEC) set based on a given signature and shred index.
- **Inputs**:
    - `resolver`: A pointer to an `fd_fec_resolver_t` structure, which manages the FEC sets and their associated data.
    - `signature`: A constant pointer to an `fd_ed25519_sig_t` structure representing the signature used to identify the FEC set.
    - `shred_idx`: An unsigned integer representing the index of the shred within the FEC set to be queried.
    - `out_shred`: A pointer to an unsigned character array where the retrieved shred data will be copied.
- **Control Flow**:
    - Cast the signature to a `wrapped_sig_t` type for internal processing.
    - Check if the signature is invalid using `ctx_map_key_inval`; if so, return `FD_FEC_RESOLVER_SHRED_REJECTED`.
    - Query the current map of the resolver using the signature to find the associated context (`set_ctx_t`); if not found, return `FD_FEC_RESOLVER_SHRED_REJECTED`.
    - Retrieve the FEC set from the context and access the data shred at the specified `shred_idx`.
    - Determine the size of the shred to copy using `fd_ulong_min` between the shred's size and `FD_SHRED_MIN_SZ`.
    - Copy the determined size of the data shred into `out_shred`.
    - Return `FD_FEC_RESOLVER_SHRED_OKAY` to indicate successful retrieval.
- **Output**: The function returns an integer status code: `FD_FEC_RESOLVER_SHRED_OKAY` if the shred is successfully retrieved and copied, or `FD_FEC_RESOLVER_SHRED_REJECTED` if the operation fails due to invalid input or missing data.


---
### fd\_fec\_resolver\_force\_complete<!-- {{#callable:fd_fec_resolver_force_complete}} -->
The `fd_fec_resolver_force_complete` function attempts to forcefully complete a Forward Error Correction (FEC) set based on the provided last shred, ensuring that the set is valid and complete before marking it as done.
- **Inputs**:
    - `resolver`: A pointer to an `fd_fec_resolver_t` structure, which manages the state and operations of the FEC resolver.
    - `last_shred`: A constant pointer to an `fd_shred_t` structure representing the last shred in the FEC set to be completed.
    - `out_fec_set`: A pointer to a constant pointer to an `fd_fec_set_t` structure, where the function will store the completed FEC set if successful.
- **Control Flow**:
    - Calculate the index of the last shred within its FEC set and check if it is valid.
    - Verify that the last shred's signature is valid and not null.
    - Check if the FEC set associated with the last shred is already marked as done; if so, return a status indicating it is ignored.
    - Attempt to find the FEC set associated with the last shred in the current map; if not found, return a rejection status.
    - Ensure that no parity shreds have been received for the FEC set, as this would indicate the set is already complete.
    - Check for any gaps in the received data shreds up to the last shred; if gaps exist, return a rejection status.
    - Ensure that no shreds with a higher index than the last shred have been received; if any exist, return a rejection status.
    - Validate the consistency of the FEC set by comparing each data shred against the base data shred for consistency in variant, slot, version, FEC set index, and parent offset.
    - If validation fails, release resources and return a rejection status.
    - Set the data and parity shred counts for the FEC set to indicate completion.
    - Move the FEC set from the current map to the done map, managing the linked list and map entries accordingly.
    - Release resources associated with the FEC set and update the output pointer to point to the completed FEC set.
    - Return a status indicating the FEC set has been successfully completed.
- **Output**: The function returns an integer status code indicating whether the FEC set was successfully completed (`FD_FEC_RESOLVER_SHRED_COMPLETES`), ignored (`FD_FEC_RESOLVER_SHRED_IGNORED`), or rejected (`FD_FEC_RESOLVER_SHRED_REJECTED`).
- **Functions called**:
    - [`ctx_ll_insert`](#ctx_ll_insert)
    - [`ctx_ll_remove`](#ctx_ll_remove)


---
### fd\_fec\_resolver\_leave<!-- {{#callable:fd_fec_resolver_leave}} -->
The `fd_fec_resolver_leave` function cleans up and releases resources associated with an FEC resolver.
- **Inputs**:
    - `resolver`: A pointer to an `fd_fec_resolver_t` structure representing the FEC resolver to be cleaned up.
- **Control Flow**:
    - Call `fd_sha512_leave` to release resources associated with the SHA-512 context in the resolver.
    - Call `bmtrlist_leave` to release resources associated with the bmtree free list in the resolver.
    - Call `freelist_leave` to release resources associated with the complete list in the resolver.
    - Call `freelist_leave` to release resources associated with the free list in the resolver.
    - Call `ctx_map_leave` to release resources associated with the done map in the resolver.
    - Call `ctx_map_leave` to release resources associated with the current map in the resolver.
    - Return the resolver pointer cast to a `void *`.
- **Output**: A `void *` pointer to the resolver, indicating the resolver has been successfully left.


---
### fd\_fec\_resolver\_delete<!-- {{#callable:fd_fec_resolver_delete}} -->
The `fd_fec_resolver_delete` function deallocates and cleans up resources associated with a Forward Error Correction (FEC) resolver object stored in shared memory.
- **Inputs**:
    - `shmem`: A pointer to the shared memory where the FEC resolver object is stored.
- **Control Flow**:
    - Cast the `shmem` pointer to a `fd_fec_resolver_t` pointer to access the resolver's properties.
    - Calculate the logarithmic sizes for the current and done maps using `fd_ulong_find_msb` based on the resolver's depth properties.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT` to manage memory layout for the resolver components.
    - Append memory allocations for the resolver's components (current map, done map, free list, complete list, and bmtree free list) using `FD_SCRATCH_ALLOC_APPEND`.
    - Finalize the scratch allocator with `FD_SCRATCH_ALLOC_FINI`.
    - Delete the SHA-512 context associated with the resolver using `fd_sha512_delete`.
    - Delete the bmtree free list, complete list, free list, done map, and current map using their respective delete functions (`bmtrlist_delete`, `freelist_delete`, `ctx_map_delete`).
    - Return the original `shmem` pointer.
- **Output**: Returns the original `shmem` pointer after cleaning up the FEC resolver resources.


