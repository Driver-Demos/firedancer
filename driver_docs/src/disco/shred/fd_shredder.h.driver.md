# Purpose
The provided C header file, `fd_shredder.h`, defines the interface and data structures for a "shredder" component, which is part of a larger system likely related to data integrity and distribution, such as a blockchain or distributed ledger technology. The shredder's primary function is to process data into "shreds," which are smaller, manageable pieces that can be distributed, stored, or transmitted more efficiently. This file includes definitions for creating, managing, and finalizing batches of data shreds, as well as calculating the necessary number of data and parity shreds for a given data size. The shredder uses cryptographic techniques, such as SHA-256 hashing and Ed25519 signatures, to ensure data integrity and authenticity, and it employs Reed-Solomon error correction to enhance data reliability.

The file is structured to provide a clear API for interacting with the shredder, including functions for initializing, joining, leaving, and deleting shredder instances. It also includes functions for counting the number of FEC (Forward Error Correction) sets, data shreds, and parity shreds required for a given data size, as well as functions for processing batches of data. The header file imports several other components, such as cryptographic and error correction libraries, indicating that it is part of a broader system with multiple interdependent modules. The use of macros and static inline functions suggests an emphasis on performance and memory alignment, which is critical in high-throughput or resource-constrained environments. Overall, this header file provides a comprehensive interface for a shredder component designed to handle data processing and integrity in a distributed system.
# Imports and Dependencies

---
- `../keyguard/fd_keyguard_client.h`
- `../../ballet/sha256/fd_sha256.h`
- `../../disco/pack/fd_microblock.h`
- `../../ballet/chacha20/fd_chacha20rng.h`
- `../../ballet/wsample/fd_wsample.h`
- `../../ballet/ed25519/fd_ed25519.h`
- `../../ballet/reedsol/fd_reedsol.h`
- `../../ballet/bmtree/fd_bmtree.h`
- `../../ballet/shred/fd_fec_set.h`


# Global Variables

---
### fd\_shredder\_data\_to\_parity\_cnt
- **Type**: `ulong const[33UL]`
- **Description**: The `fd_shredder_data_to_parity_cnt` is a static constant array of unsigned long integers with 33 elements. It maps the number of data shreds to the corresponding number of parity shreds required for Forward Error Correction (FEC) in the shredding process. The array values increase as the index increases, reflecting the need for more parity shreds as the number of data shreds increases.
- **Use**: This array is used to determine the number of parity shreds needed for a given number of data shreds in the FEC process.


---
### fd\_shredder\_new
- **Type**: `function pointer`
- **Description**: `fd_shredder_new` is a function that initializes a region of memory as a shredder object. It takes a memory pointer, a signer function pointer, a signer context, and a shred version as parameters.
- **Use**: This function is used to format a memory region to be used as a shredder object, setting up the necessary context for shred production.


---
### fd\_shredder\_join
- **Type**: `fd_shredder_t *`
- **Description**: The `fd_shredder_join` is a function that returns a pointer to an `fd_shredder_t` structure. This function is used to join a shredder object, which is a data structure used for managing the shredding process in a distributed system.
- **Use**: This function is used to initialize and return a pointer to a shredder object from a given memory region.


---
### fd\_shredder\_leave
- **Type**: `function pointer`
- **Description**: `fd_shredder_leave` is a function pointer that takes a pointer to an `fd_shredder_t` structure as an argument and returns a void pointer. It is likely used to perform cleanup or state transition operations on a shredder object, possibly preparing it for deletion or reuse.
- **Use**: This function is used to leave or detach from a shredder object, potentially performing necessary cleanup operations.


---
### fd\_shredder\_delete
- **Type**: `function pointer`
- **Description**: `fd_shredder_delete` is a function pointer that takes a single argument, a pointer to memory (`void * mem`), and returns a pointer to memory (`void *`).
- **Use**: This function is used to delete or deallocate a shredder object from memory.


---
### fd\_shredder\_init\_batch
- **Type**: `function pointer`
- **Description**: `fd_shredder_init_batch` is a function that initializes a shredder object for processing a new batch of entries. It takes a pointer to a shredder object, a pointer to the entry batch data, the size of the entry batch, a slot identifier, and a pointer to metadata associated with the entry batch.
- **Use**: This function is used to set up the shredder for processing a new batch of data entries, preparing it to generate shreds from the provided entry batch.


---
### fd\_shredder\_skip\_batch
- **Type**: `fd_shredder_t *`
- **Description**: The `fd_shredder_skip_batch` is a function that returns a pointer to an `fd_shredder_t` structure. It is used to update the shredder state to skip processing the current batch of data. This function is part of a larger system for managing data shreds, which are used in data integrity and redundancy systems.
- **Use**: This function is used to update the shredder's state as if a batch of a specified size was processed, without actually processing the data.


---
### fd\_shredder\_next\_fec\_set
- **Type**: `fd_fec_set_t *`
- **Description**: The `fd_shredder_next_fec_set` function is a global function that returns a pointer to an `fd_fec_set_t` structure. It is responsible for extracting the next Forward Error Correction (FEC) set from an ongoing batch in the shredder process. This function computes data and parity shreds, including parity information, Merkle proofs, and signatures, and updates the position of the shredder within the batch.
- **Use**: This function is used to generate and retrieve the next FEC set during the shredding process, advancing the shredder's position within the batch.


---
### fd\_shredder\_fini\_batch
- **Type**: `function pointer`
- **Description**: `fd_shredder_fini_batch` is a function that finalizes the processing of a batch in a shredder object. It ensures that the shredder is no longer in a batch state and is ready to start a new batch.
- **Use**: This function is used to complete the current batch processing in a shredder, allowing the shredder to be reset for a new batch.


# Data Structures

---
### fd\_shred\_features\_activation\_private
- **Type**: `union`
- **Members**:
    - `slots`: An array of unsigned long integers representing feature slots, with a size defined by FD_SHRED_FEATURES_ACTIVATION_SLOT_CNT.
    - `disable_turbine_fanout_experiments`: An unsigned long integer indicating whether turbine fanout experiments are disabled.
    - `enable_turbine_extended_fanout_experiments`: An unsigned long integer indicating whether extended fanout experiments are enabled.
    - `enable_chained_merkle_shreds`: An unsigned long integer indicating whether chained Merkle shreds are enabled.
    - `drop_unchained_merkle_shreds`: An unsigned long integer indicating whether unchained Merkle shreds should be dropped.
- **Description**: The `fd_shred_features_activation_private` is a union data structure designed to manage feature activation states for a shredder system. It provides a flexible way to store and access feature flags using either an array of slots or individual named fields. This structure allows for easy expansion and modification of feature flags by updating the slot count and provides a clear mapping of each feature to a specific slot index. The union ensures that the memory layout is efficient, allowing for both array and structured access to the feature flags.


---
### fd\_shred\_features\_activation\_t
- **Type**: `union`
- **Members**:
    - `slots`: An array of unsigned long integers representing feature activation slots.
    - `disable_turbine_fanout_experiments`: A flag to disable turbine fanout experiments.
    - `enable_turbine_extended_fanout_experiments`: A flag to enable turbine extended fanout experiments.
    - `enable_chained_merkle_shreds`: A flag to enable chained Merkle shreds.
    - `drop_unchained_merkle_shreds`: A flag to drop unchained Merkle shreds.
- **Description**: The `fd_shred_features_activation_t` is a union data structure that encapsulates feature activation flags for a shredder system. It provides a mechanism to manage and toggle various experimental features related to data shredding, such as turbine fanout and Merkle shreds. The union allows for both an array-based access to feature slots and a structured access to individual feature flags, facilitating flexible feature management.


---
### fd\_shredder\_private
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the shredder instance.
    - `shred_version`: Indicates the version of the shred format being used.
    - `sha256`: An array for SHA-256 batch processing.
    - `reedsol`: An array for Reed-Solomon error correction.
    - `bmtree`: A union member for storing a Merkle tree commit.
    - `_bmtree_footprint`: A union member for storing the footprint of a Merkle tree commit.
    - `bmtree_leaves`: An array of nodes representing the leaves of the Merkle tree.
    - `entry_batch`: A pointer to the entry batch being processed.
    - `sz`: The size of the entry batch.
    - `offset`: The offset within the entry batch.
    - `signer_ctx`: A context for the signer function.
    - `signer`: A function pointer for signing shreds.
    - `meta`: Metadata for the entry batch.
    - `slot`: The slot number associated with the entry batch.
    - `data_idx_offset`: Offset for data shred indices.
    - `parity_idx_offset`: Offset for parity shred indices.
- **Description**: The `fd_shredder_private` structure is a complex data structure used in the context of data shredding, specifically for handling and processing data shreds with error correction and cryptographic integrity checks. It includes fields for managing the version and unique identification of the shredder, cryptographic processing with SHA-256 and Reed-Solomon error correction, and Merkle tree operations for data integrity. The structure also manages entry batch processing, including size, offset, and metadata, and supports signing operations through a function pointer and context. This structure is aligned to specific boundaries to optimize performance and ensure data integrity during processing.


---
### fd\_shredder\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the shredder instance, used for validation.
    - `shred_version`: Specifies the version of the shreds produced by the shredder.
    - `sha256`: An array of SHA-256 batch objects used for hashing operations.
    - `reedsol`: An array of Reed-Solomon objects used for error correction coding.
    - `bmtree`: A union containing a BMT (Binary Merkle Tree) commit object for Merkle tree operations.
    - `bmtree_leaves`: An array of BMT node objects representing the leaves of the Merkle tree.
    - `entry_batch`: A pointer to the entry batch data being processed.
    - `sz`: The size of the entry batch data.
    - `offset`: The current offset within the entry batch data.
    - `signer_ctx`: A context pointer for the signing function.
    - `signer`: A function pointer to the signing function used to sign shreds.
    - `meta`: Metadata associated with the entry batch.
    - `slot`: The slot number associated with the current batch.
    - `data_idx_offset`: Offset for the data shred index.
    - `parity_idx_offset`: Offset for the parity shred index.
- **Description**: The `fd_shredder_t` structure is a complex data structure used in the context of data shredding, specifically for creating and managing shreds of data with error correction and cryptographic features. It includes fields for managing the state and configuration of the shredder, such as versioning, hashing, and error correction coding. The structure also supports Merkle tree operations for data integrity verification and includes function pointers for signing shreds, allowing for secure data handling. The shredder is designed to process entry batches, compute shreds, and manage the indices for data and parity shreds, making it a critical component in systems requiring reliable data distribution and recovery.


# Functions

---
### fd\_shredder\_align<!-- {{#callable:fd_shredder_align}} -->
The `fd_shredder_align` function returns the alignment requirement for the `fd_shredder_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and allows for potential inlining by the compiler.
    - It returns a constant value defined by the macro `FD_SHREDDER_ALIGN`.
- **Output**: The function returns an `ulong` representing the alignment requirement for the `fd_shredder_t` structure, which is defined as `128UL`.


---
### fd\_shredder\_footprint<!-- {{#callable:fd_shredder_footprint}} -->
The `fd_shredder_footprint` function returns the size in bytes of the `fd_shredder_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests that the function call overhead is minimized by inlining the function body.
    - The function uses the `sizeof` operator to determine the size of the `fd_shredder_t` structure.
    - The function returns this size as an unsigned long integer.
- **Output**: The function outputs the size of the `fd_shredder_t` structure as an unsigned long integer.


---
### fd\_shredder\_count\_fec\_sets<!-- {{#callable:fd_shredder_count_fec_sets}} -->
The `fd_shredder_count_fec_sets` function calculates the number of Forward Error Correction (FEC) sets required for a given size of data and shred type.
- **Inputs**:
    - `sz_bytes`: The size of the data in bytes for which the number of FEC sets is to be calculated.
    - `type`: The type of shreds, which determines the payload size and can be normal, chained, or resigned.
- **Control Flow**:
    - Check if the shred type is resigned using `fd_shred_is_resigned(type)`; if true, calculate the number of FEC sets using the resigned payload size.
    - If the shred type is not resigned, check if it is chained using `fd_shred_is_chained(type)`; if true, calculate the number of FEC sets using the chained payload size.
    - If neither resigned nor chained, calculate the number of FEC sets using the normal payload size.
    - In each case, use `fd_ulong_max` to ensure the size is at least twice the payload size minus one, then divide by the respective payload size to determine the number of FEC sets.
- **Output**: Returns the number of FEC sets as an unsigned long integer.


---
### fd\_shredder\_count\_data\_shreds<!-- {{#callable:fd_shredder_count_data_shreds}} -->
The `fd_shredder_count_data_shreds` function calculates the number of data shreds required for a given entry batch size and shred type.
- **Inputs**:
    - `sz_bytes`: The size of the entry batch in bytes.
    - `type`: The type of shreds, which can be one of FD_SHRED_TYPE_MERKLE_DATA, FD_SHRED_TYPE_MERKLE_DATA_CHAINED, or FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED.
- **Control Flow**:
    - Calculate the number of normal FEC sets using [`fd_shredder_count_fec_sets`](#fd_shredder_count_fec_sets) and subtract one to get `normal_sets`.
    - Initialize `shreds` as `normal_sets * 32UL`.
    - Check if the shred type is resigned using `fd_shred_is_resigned`.
    - If resigned, calculate `remaining_bytes` and determine additional shreds based on `remaining_bytes` using specific thresholds and formulas.
    - If not resigned, check if the shred type is chained using `fd_shred_is_chained`.
    - If chained, calculate `remaining_bytes` and determine additional shreds based on `remaining_bytes` using specific thresholds and formulas.
    - If neither resigned nor chained, calculate `remaining_bytes` for normal shreds and determine additional shreds based on `remaining_bytes` using specific thresholds and formulas.
    - Return the total number of shreds.
- **Output**: The function returns the total number of data shreds as an unsigned long integer.
- **Functions called**:
    - [`fd_shredder_count_fec_sets`](#fd_shredder_count_fec_sets)


---
### fd\_shredder\_count\_parity\_shreds<!-- {{#callable:fd_shredder_count_parity_shreds}} -->
The `fd_shredder_count_parity_shreds` function calculates the number of parity shreds required for a given size of data and shred type.
- **Inputs**:
    - `sz_bytes`: The size of the data in bytes for which parity shreds need to be calculated.
    - `type`: The type of shreds, which determines the payload size and calculation method (e.g., normal, chained, or resigned).
- **Control Flow**:
    - Calculate the number of normal FEC sets by calling [`fd_shredder_count_fec_sets`](#fd_shredder_count_fec_sets) and subtracting one.
    - Initialize the number of shreds as the product of normal sets and 32.
    - Check if the shred type is resigned using `fd_shred_is_resigned`; if true, calculate remaining bytes and adjust shreds based on specific conditions using a lookup table and arithmetic operations.
    - If the shred type is chained, calculate remaining bytes and adjust shreds similarly, using different conditions and arithmetic operations.
    - If neither resigned nor chained, calculate remaining bytes and adjust shreds using conditions specific to normal shreds.
    - Return the total number of parity shreds calculated.
- **Output**: The function returns an `ulong` representing the total number of parity shreds required.
- **Functions called**:
    - [`fd_shredder_count_fec_sets`](#fd_shredder_count_fec_sets)


# Function Declarations (Public API)

---
### fd\_shredder\_new<!-- {{#callable_declaration:fd_shredder_new}} -->
Formats a region of memory as a shredder object.
- **Description**: This function initializes a memory region to be used as a shredder object, which is responsible for producing shreds with a specified version. It should be called when a new shredder object is needed, and the memory region must be properly aligned and non-null. The function sets up the shredder with the provided signing function and context, and assigns the specified shred version. It is important to ensure that the memory region is aligned according to the shredder's alignment requirements before calling this function.
- **Inputs**:
    - `mem`: A pointer to a memory region where the shredder object will be initialized. Must not be null and must be aligned to the shredder's alignment requirements. If these conditions are not met, the function returns null.
    - `signer`: A pointer to a function that will be used to sign the shreds. This function is called with the provided context and the Merkle root. The caller retains ownership of this function pointer.
    - `signer_ctx`: A pointer to a context that will be passed to the signing function. The caller retains ownership of this context.
    - `shred_version`: A ushort value representing the version of the shreds that the shredder will produce. This value is stored in the shredder object and used in the shreds it creates.
- **Output**: Returns a pointer to the initialized shredder object on success, or null if the memory is null or misaligned.
- **See also**: [`fd_shredder_new`](fd_shredder.c.driver.md#fd_shredder_new)  (Implementation)


---
### fd\_shredder\_join<!-- {{#callable_declaration:fd_shredder_join}} -->
Joins a shredder object from a memory region.
- **Description**: Use this function to obtain a pointer to a shredder object from a previously allocated and formatted memory region. The memory must be properly aligned and initialized with the correct magic number. This function is typically called after memory has been formatted using `fd_shredder_new`. It is important to ensure that the memory is not null and is correctly aligned to `FD_SHREDDER_ALIGN`. If these conditions are not met, or if the magic number is incorrect, the function will return `NULL`, indicating an error.
- **Inputs**:
    - `mem`: A pointer to the memory region that contains the shredder object. This memory must be aligned to `FD_SHREDDER_ALIGN` and must not be null. The memory should have been previously initialized with the correct magic number. If these conditions are not met, the function returns `NULL`.
- **Output**: Returns a pointer to the `fd_shredder_t` object if successful, or `NULL` if the memory is null, misaligned, or has an incorrect magic number.
- **See also**: [`fd_shredder_join`](fd_shredder.c.driver.md#fd_shredder_join)  (Implementation)


---
### fd\_shredder\_leave<!-- {{#callable_declaration:fd_shredder_leave}} -->
Leaves the shredder context.
- **Description**: This function is used to leave a shredder context, effectively ending the current session with the shredder. It should be called when the shredder is no longer needed, allowing the caller to safely exit the shredder context. This function does not perform any cleanup or deallocation, so it is the caller's responsibility to manage the memory associated with the shredder object.
- **Inputs**:
    - `shredder`: A pointer to an `fd_shredder_t` object representing the shredder context to leave. The pointer must not be null, and the shredder must have been previously initialized and joined.
- **Output**: Returns a void pointer to the shredder object, allowing the caller to retain access to the shredder's memory if needed.
- **See also**: [`fd_shredder_leave`](fd_shredder.c.driver.md#fd_shredder_leave)  (Implementation)


---
### fd\_shredder\_delete<!-- {{#callable_declaration:fd_shredder_delete}} -->
Deletes a shredder object from memory.
- **Description**: Use this function to safely delete a shredder object that was previously created with `fd_shredder_new`. It checks the integrity of the shredder object by verifying its magic number before deletion. If the magic number is invalid, a warning is logged, and the function returns `NULL`. This function should be called when the shredder object is no longer needed to ensure proper cleanup and avoid memory leaks.
- **Inputs**:
    - `mem`: A pointer to the memory region containing the shredder object. Must not be null and should point to a valid shredder object created by `fd_shredder_new`. If the magic number is incorrect, the function logs a warning and returns `NULL`.
- **Output**: Returns a pointer to the deleted shredder object if successful, or `NULL` if the magic number check fails.
- **See also**: [`fd_shredder_delete`](fd_shredder.c.driver.md#fd_shredder_delete)  (Implementation)


---
### fd\_shredder\_init\_batch<!-- {{#callable_declaration:fd_shredder_init_batch}} -->
Initializes a shredder for processing an entry batch.
- **Description**: This function prepares a shredder object to begin processing a new entry batch. It must be called with a valid shredder object that has been properly initialized and joined. The entry batch must be a non-empty memory region, and the shredder will maintain a read interest in this region until the batch is finalized. The metadata provided is used for shred production but is not retained by the shredder. This function returns the shredder object, which is ready to process the new batch.
- **Inputs**:
    - `shredder`: A pointer to a valid fd_shredder_t object that has been initialized and joined. The caller retains ownership.
    - `entry_batch`: A pointer to the first byte of a memory region containing the entry batch data. The memory must remain valid and unmodified until the batch is finalized. Must not be null.
    - `entry_batch_sz`: The size of the entry batch in bytes. Must be greater than zero. If zero, the function returns NULL.
    - `slot`: An unsigned long representing the slot number for the batch. It is used to manage shredder state.
    - `metadata`: A pointer to an fd_entry_batch_meta_t structure containing metadata for the entry batch. The shredder does not retain ownership or a read interest in this memory.
- **Output**: Returns a pointer to the initialized fd_shredder_t object, or NULL if the entry batch size is zero.
- **See also**: [`fd_shredder_init_batch`](fd_shredder.c.driver.md#fd_shredder_init_batch)  (Implementation)


---
### fd\_shredder\_skip\_batch<!-- {{#callable_declaration:fd_shredder_skip_batch}} -->
Updates the shredder state to skip processing the current batch.
- **Description**: This function is used to update the state of a shredder object to skip processing a batch of entries. It should be called when the user wants to advance the shredder's internal indices as if a batch of a specified size was processed, without actually processing it. The function requires a valid shredder object and a non-zero entry batch size. If the slot parameter differs from the shredder's current slot, the function resets the data and parity index offsets. This function is useful in scenarios where certain batches need to be skipped without affecting the continuity of the shredder's operation.
- **Inputs**:
    - `shredder`: A pointer to a valid fd_shredder_t object. The caller must ensure this is a valid local join.
    - `entry_batch_sz`: The size of the entry batch to be skipped. Must be strictly positive. If zero, the function returns NULL.
    - `slot`: The slot number associated with the batch. If it differs from the shredder's current slot, the data and parity index offsets are reset.
    - `shred_type`: The type of shreds to be considered. This parameter affects the calculation of data and parity shred counts.
- **Output**: Returns the updated shredder object, or NULL if entry_batch_sz is zero.
- **See also**: [`fd_shredder_skip_batch`](fd_shredder.c.driver.md#fd_shredder_skip_batch)  (Implementation)


---
### fd\_shredder\_next\_fec\_set<!-- {{#callable_declaration:fd_shredder_next_fec_set}} -->
Extracts the next FEC set from the current batch.
- **Description**: This function is used to generate the next Forward Error Correction (FEC) set from an ongoing batch in a shredder. It computes both data and parity shreds, including parity information, Merkle proofs, and signatures, and stores them in the provided result structure. The function should be called after initializing a batch with `fd_shredder_init_batch` and before finalizing it with `fd_shredder_fini_batch`. If the `chained_merkle_root` is provided, it will be updated with the new Merkle root, affecting the type of shreds created. The function returns NULL if all data in the entry batch has been processed, otherwise it returns the result structure.
- **Inputs**:
    - `shredder`: A pointer to a valid `fd_shredder_t` object that is currently processing a batch. The shredder must be properly initialized and joined.
    - `result`: A pointer to an `fd_fec_set_t` structure where the generated FEC set will be stored. The structure will be overwritten by this function.
    - `chained_merkle_root`: A pointer to a 32-byte buffer containing the chained Merkle root of the previous FEC set, or NULL if not used. If not NULL, it will be updated with the new Merkle root.
- **Output**: Returns the `result` pointer on success, or NULL if the entry batch's data has been fully consumed.
- **See also**: [`fd_shredder_next_fec_set`](fd_shredder.c.driver.md#fd_shredder_next_fec_set)  (Implementation)


---
### fd\_shredder\_fini\_batch<!-- {{#callable_declaration:fd_shredder_fini_batch}} -->
Finishes processing the current batch in the shredder.
- **Description**: Use this function to complete the processing of the current batch in a shredder. It must be called on a shredder that is currently processing a batch, and it prepares the shredder to start a new batch with `fd_shredder_init_batch`. This function resets the internal state related to the current batch, ensuring that the shredder is ready for new data.
- **Inputs**:
    - `shredder`: A pointer to an `fd_shredder_t` structure that represents the shredder. It must be a valid local join and currently processing a batch. The function will reset its batch-related state.
- **Output**: Returns the same `fd_shredder_t` pointer passed as input, with its batch-related state reset.
- **See also**: [`fd_shredder_fini_batch`](fd_shredder.c.driver.md#fd_shredder_fini_batch)  (Implementation)


