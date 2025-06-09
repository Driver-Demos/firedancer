# Purpose
This C header file, `fd_fec_resolver.h`, defines the interface for a Forward Error Correction (FEC) resolver specifically designed for handling shreds in a distributed system. The primary purpose of this file is to provide methods for building and validating FEC sets from received shreds, ensuring data integrity and reliability in data transmission. The file is part of a larger system, as indicated by its inclusion of other headers from the `ballet` directory, which suggests a modular architecture. The FEC resolver is tailored for use within a specific component, the "shred tile," as part of a broader "disco/shred" system, indicating its specialized role in managing data shreds.

The file outlines several key functions and data structures that manage the lifecycle of FEC sets, including their creation, validation, and completion. It employs a sophisticated memory management strategy using a freelist system to handle the ephemeral nature of network buffers and the varying lifetime requirements of FEC sets. This system ensures that memory is efficiently reused without unnecessary copying, which is crucial for performance in high-throughput environments. The header defines public APIs for creating and managing FEC resolvers, adding shreds, querying shred data, and forcing the completion of FEC sets. It also includes mechanisms for signing shreds and validating their integrity using Merkle roots, which are essential for maintaining data authenticity and preventing duplication. Overall, this file provides a comprehensive interface for managing FEC sets in a distributed system, emphasizing efficient memory use and robust data validation.
# Imports and Dependencies

---
- `../../ballet/shred/fd_fec_set.h`
- `../../ballet/bmtree/fd_bmtree.h`
- `../../ballet/ed25519/fd_ed25519.h`


# Global Variables

---
### fd\_fec\_resolver\_new
- **Type**: `function pointer`
- **Description**: `fd_fec_resolver_new` is a function that initializes a region of memory to be used as a Forward Error Correction (FEC) resolver. It takes several parameters including a memory region, a function pointer for signing shreds, context for the signer, and various depth parameters that control the behavior of the FEC resolver.
- **Use**: This function is used to set up an FEC resolver with specific memory and operational parameters, enabling it to manage and validate FEC sets from received shreds.


---
### fd\_fec\_resolver\_join
- **Type**: `fd_fec_resolver_t *`
- **Description**: The `fd_fec_resolver_join` is a function that returns a pointer to an `fd_fec_resolver_t` structure, which is used to manage Forward Error Correction (FEC) sets in a memory region. This function is part of a system designed to handle FEC sets efficiently, ensuring that memory is reused only after certain conditions are met, as described in the detailed comments above.
- **Use**: This function is used to join or access an existing FEC resolver in a shared memory region, allowing further operations on FEC sets.


---
### fd\_fec\_resolver\_leave
- **Type**: `function pointer`
- **Description**: `fd_fec_resolver_leave` is a function pointer that takes a pointer to an `fd_fec_resolver_t` structure as an argument and returns a `void` pointer. It is part of the FEC resolver interface, which manages Forward Error Correction (FEC) sets for shreds in a networked environment.
- **Use**: This function is used to leave or detach from an FEC resolver, likely performing cleanup or state transition operations.


---
### fd\_fec\_resolver\_delete
- **Type**: `function pointer`
- **Description**: The `fd_fec_resolver_delete` is a function pointer that takes a single argument, a pointer to shared memory (`void * shmem`), and returns a pointer to void. This function is likely used to delete or clean up a Forward Error Correction (FEC) resolver instance, freeing any resources or memory associated with it.
- **Use**: This function is used to delete an FEC resolver instance, ensuring that any allocated resources are properly released.


# Data Structures

---
### fd\_fec\_resolver\_t
- **Type**: `typedef struct fd_fec_resolver fd_fec_resolver_t;`
- **Members**:
    - `fd_fec_resolver_t`: An opaque handle for the FEC resolver, which is a structure used to manage Forward Error Correction (FEC) sets.
- **Description**: The `fd_fec_resolver_t` is an opaque data structure used to manage Forward Error Correction (FEC) sets in a networking context. It is designed to handle the complexities of memory management and lifetime requirements for FEC sets, ensuring that memory is efficiently reused without unnecessary copying. The resolver maintains a freelist system to manage in-progress, completed, and free FEC sets, ensuring that memory is not reused prematurely. This structure is crucial for handling shreds in a network, validating them, and ensuring that completed FEC sets are properly managed and returned. The resolver also supports signing shreds and managing shred versions, making it a comprehensive solution for FEC set management in a networked environment.


# Function Declarations (Public API)

---
### fd\_fec\_resolver\_footprint<!-- {{#callable_declaration:fd_fec_resolver_footprint}} -->
Calculates the memory footprint required for an FEC resolver.
- **Description**: Use this function to determine the amount of memory needed to create an FEC resolver capable of managing a specified number of in-progress, partially completed, and completed FEC sets, as well as recognizing a certain number of previously completed sets. This function is essential for allocating the correct amount of memory before initializing an FEC resolver. It should be called with positive values for all depth parameters, as zero or excessively large values will result in a return value of zero, indicating an invalid configuration.
- **Inputs**:
    - `depth`: The number of in-progress FEC sets the resolver can handle. Must be a positive value and less than (1UL<<62)-1UL.
    - `partial_depth`: The number of distinct FEC sets that must be returned before memory can be reused. Must be a positive value.
    - `complete_depth`: The number of completed FEC sets that must be returned before memory can be reused. Must be a positive value.
    - `done_depth`: The number of FEC sets the resolver remembers to recognize duplicates. Must be a positive value and less than (1UL<<62)-1UL.
- **Output**: Returns the required memory footprint in bytes for the specified configuration, or 0 if the configuration is invalid.
- **See also**: [`fd_fec_resolver_footprint`](fd_fec_resolver.c.driver.md#fd_fec_resolver_footprint)  (Implementation)


---
### fd\_fec\_resolver\_align<!-- {{#callable_declaration:fd_fec_resolver_align}} -->
Returns the required memory alignment for an FEC resolver.
- **Description**: Use this function to determine the alignment requirement for a memory region intended to be used as an FEC resolver. This is necessary to ensure that the memory is correctly aligned for optimal access and functionality. The function is constant and does not depend on any input parameters, making it straightforward to use whenever you need to allocate or verify memory for an FEC resolver.
- **Inputs**: None
- **Output**: Returns an unsigned long representing the alignment requirement in bytes.
- **See also**: [`fd_fec_resolver_align`](fd_fec_resolver.c.driver.md#fd_fec_resolver_align)  (Implementation)


---
### fd\_fec\_resolver\_new<!-- {{#callable_declaration:fd_fec_resolver_new}} -->
Formats a memory region as a FEC resolver.
- **Description**: This function initializes a region of memory to be used as a Forward Error Correction (FEC) resolver, which manages FEC sets for processing shreds. It should be called with a properly aligned and sized memory region, as determined by `fd_fec_resolver_footprint` and `fd_fec_resolver_align`. The function requires several parameters to define the behavior and constraints of the resolver, such as the number of in-progress, partially completed, and completed FEC sets it can handle. It also requires a set of FEC sets that it will manage, and a shred version to validate incoming shreds. The function returns the memory region on success or NULL on failure, logging details of any issues encountered.
- **Inputs**:
    - `shmem`: A pointer to a memory region that must be properly aligned and have sufficient footprint for the FEC resolver. The caller retains ownership.
    - `signer`: A function pointer for signing shreds requiring retransmission signatures. Can be NULL, in which case signatures are zeroed.
    - `sign_ctx`: An opaque pointer passed to the signer function. Ignored if signer is NULL.
    - `depth`: The maximum number of in-progress FEC sets. Must be positive and less than (1UL<<62)-1UL.
    - `partial_depth`: The minimum number of distinct FEC sets before memory reuse. Must be positive.
    - `complete_depth`: The minimum number of completed FEC sets before memory reuse. Must be positive.
    - `done_depth`: The number of FEC sets remembered to recognize duplicates. Must be positive and less than (1UL<<62)-1UL.
    - `sets`: A pointer to the first of depth+partial_depth+complete_depth FEC sets. The resolver takes ownership and retains write interest.
    - `expected_shred_version`: The shred version to validate against. Must be non-zero.
    - `max_shred_idx`: The maximum shred index for validation. Should be less than or equal to UINT_MAX.
- **Output**: Returns the shmem pointer on success, or NULL on failure.
- **See also**: [`fd_fec_resolver_new`](fd_fec_resolver.c.driver.md#fd_fec_resolver_new)  (Implementation)


---
### fd\_fec\_resolver\_join<!-- {{#callable_declaration:fd_fec_resolver_join}} -->
Joins a shared memory region as an FEC resolver.
- **Description**: This function is used to join a shared memory region that has been formatted as an FEC resolver, allowing the caller to interact with it. It should be called after the shared memory has been properly initialized using `fd_fec_resolver_new`. The function returns a pointer to the FEC resolver structure if successful, or NULL if any part of the joining process fails. This function is essential for accessing and managing FEC sets within the shared memory.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region that has been formatted as an FEC resolver. The memory must be properly aligned and initialized. If the memory is not correctly formatted or aligned, the function will return NULL.
- **Output**: Returns a pointer to the `fd_fec_resolver_t` structure on success, or NULL on failure.
- **See also**: [`fd_fec_resolver_join`](fd_fec_resolver.c.driver.md#fd_fec_resolver_join)  (Implementation)


---
### fd\_fec\_resolver\_add\_shred<!-- {{#callable_declaration:fd_fec_resolver_add_shred}} -->
Notifies the FEC resolver of a newly received shred.
- **Description**: This function is used to add a new shred to the FEC resolver, which validates the shred and stores it internally. It should be called whenever a new shred is received. The function requires a valid resolver and shred, and it performs various checks to ensure the shred is valid and not a duplicate. If the shred is valid and new, it is added to the FEC set, and the function may return different statuses indicating whether the shred was added successfully, ignored, or rejected. The function also provides output parameters to access the FEC set and shred data, and optionally the Merkle root, if the shred is successfully processed.
- **Inputs**:
    - `resolver`: A pointer to a local join of an FEC resolver. Must not be null.
    - `shred`: A pointer to the new shred to be added. Must not be null and should point to a valid shred structure.
    - `shred_sz`: The size of the shred in bytes. Must be sufficient to cover the shred data.
    - `leader_pubkey`: A pointer to the leader's public key used for signature verification. Must not be null.
    - `out_fec_set`: A pointer to a location where a pointer to the FEC set will be written on success. Must not be null.
    - `out_shred`: A pointer to a location where a pointer to the copied shred will be written on success. Must not be null.
    - `out_merkle_root`: A pointer to a location where the Merkle root will be written on success. Can be null, in which case the Merkle root is not written.
- **Output**: Returns an integer status code: SHRED_OKAY, SHRED_COMPLETES, SHRED_IGNORED, or SHRED_REJECTED, indicating the result of the operation.
- **See also**: [`fd_fec_resolver_add_shred`](fd_fec_resolver.c.driver.md#fd_fec_resolver_add_shred)  (Implementation)


---
### fd\_fec\_resolver\_done\_contains<!-- {{#callable_declaration:fd_fec_resolver_done_contains}} -->
Check if a completed FEC set with a given signature exists in the resolver.
- **Description**: Use this function to determine if a Forward Error Correction (FEC) set, identified by a specific signature, has been completed and is stored in the resolver's done_map. This is useful for checking the completion status of FEC sets without directly accessing or modifying them. The function requires a valid resolver and a signature to perform the check. It returns a boolean-like integer indicating the presence of the FEC set in the done_map.
- **Inputs**:
    - `resolver`: A pointer to an fd_fec_resolver_t structure representing the FEC resolver. It must be a valid, initialized resolver instance. The caller retains ownership.
    - `signature`: A pointer to a constant fd_ed25519_sig_t structure representing the signature of the FEC set to check. It must not be null, and the signature should be valid for the function to perform correctly.
- **Output**: Returns 1 if the FEC set with the given signature is present in the done_map, indicating it is completed; otherwise, returns 0.
- **See also**: [`fd_fec_resolver_done_contains`](fd_fec_resolver.c.driver.md#fd_fec_resolver_done_contains)  (Implementation)


---
### fd\_fec\_resolver\_shred\_query<!-- {{#callable_declaration:fd_fec_resolver_shred_query}} -->
Retrieve a data shred from an FEC set by signature and index.
- **Description**: This function is used to obtain a specific data shred from an in-progress FEC set identified by a given signature and index. It is primarily intended for use with the force completion API, which requires access to the last shred in a set. The function should be called only when the FEC set is known to be in progress and the shred index is within valid bounds. If the FEC set is not found in the current map, the function returns an error code, and the output shred should be ignored. No validation is performed on the shred index or the presence of the shred, so the caller must ensure these conditions are met to avoid undefined behavior.
- **Inputs**:
    - `resolver`: A pointer to an fd_fec_resolver_t structure representing the FEC resolver. Must not be null.
    - `signature`: A pointer to an fd_ed25519_sig_t structure representing the signature of the FEC set. Must not be null.
    - `shred_idx`: An unsigned integer representing the index of the shred within the FEC set. Must be within the valid range for the FEC set.
    - `out_shred`: A pointer to a memory region where the retrieved shred will be copied. Must be large enough to hold up to FD_SHRED_MIN_SZ bytes.
- **Output**: Returns FD_FEC_RESOLVER_SHRED_OKAY on success, with the shred copied to out_shred. Returns FD_FEC_RESOLVER_SHRED_REJECTED if the FEC set is not found, in which case out_shred should be ignored.
- **See also**: [`fd_fec_resolver_shred_query`](fd_fec_resolver.c.driver.md#fd_fec_resolver_shred_query)  (Implementation)


---
### fd\_fec\_resolver\_force\_complete<!-- {{#callable_declaration:fd_fec_resolver_force_complete}} -->
Forces completion of a partial FEC set in the FEC resolver.
- **Description**: This function is used to force the completion of a partial Forward Error Correction (FEC) set when the caller has determined that all data shreds have been received, but no coding shreds are available to complete the set. It should be used when the Repair protocol cannot request coding shreds, and the caller is certain that the provided last shred is indeed the final data shred in the set. The function performs minimal validation, ensuring only that the data shreds are consistent with each other. If the FEC set is already complete or the last shred is invalid, the function will return an appropriate error code. Care should be taken to avoid forcing completion prematurely, as this may result in the FEC set being discarded.
- **Inputs**:
    - `resolver`: A pointer to an fd_fec_resolver_t structure representing the FEC resolver. The resolver must be properly initialized and joined before calling this function.
    - `last_shred`: A pointer to the last data shred in the FEC set. This shred is used to determine the data_shred_cnt. It must be valid and consistent with the FEC set.
    - `out_fec_set`: A pointer to a location where the function will store a pointer to the completed FEC set if the operation is successful. The caller must provide a valid pointer for this output.
- **Output**: Returns FD_FEC_RESOLVER_SHRED_COMPLETES if the FEC set is successfully completed, FD_FEC_RESOLVER_SHRED_IGNORED if the FEC set is already complete, or FD_FEC_RESOLVER_SHRED_REJECTED if the last shred is invalid or the FEC set cannot be completed.
- **See also**: [`fd_fec_resolver_force_complete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_force_complete)  (Implementation)


---
### fd\_fec\_resolver\_leave<!-- {{#callable_declaration:fd_fec_resolver_leave}} -->
Releases resources associated with an FEC resolver.
- **Description**: Use this function to properly release resources associated with an FEC resolver when it is no longer needed. This function should be called after all operations on the resolver are complete to ensure that all internal resources are correctly freed. It is important to ensure that the resolver is in a valid state before calling this function, as it assumes that the resolver has been properly initialized and used.
- **Inputs**:
    - `resolver`: A pointer to an fd_fec_resolver_t structure. This must be a valid, non-null pointer to a resolver that has been previously initialized and used. The function will handle the cleanup of resources associated with this resolver.
- **Output**: Returns a pointer to the resolver, cast to a void pointer, after releasing its resources.
- **See also**: [`fd_fec_resolver_leave`](fd_fec_resolver.c.driver.md#fd_fec_resolver_leave)  (Implementation)


---
### fd\_fec\_resolver\_delete<!-- {{#callable_declaration:fd_fec_resolver_delete}} -->
Deletes an FEC resolver and releases its resources.
- **Description**: Use this function to delete an FEC resolver and release any resources it holds. It should be called when the resolver is no longer needed, ensuring that all associated memory is properly freed. The function takes a pointer to the shared memory region used by the resolver and returns the same pointer. This function must be called only after all operations on the resolver are complete to avoid undefined behavior.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region used by the FEC resolver. Must not be null and should point to a valid FEC resolver initialized by fd_fec_resolver_new. The caller retains ownership of this memory.
- **Output**: Returns the same pointer passed as input, which is the shared memory region used by the FEC resolver.
- **See also**: [`fd_fec_resolver_delete`](fd_fec_resolver.c.driver.md#fd_fec_resolver_delete)  (Implementation)


