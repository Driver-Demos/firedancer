# Purpose
This C source code file provides a specialized implementation for managing and verifying Forward Error Correction (FEC) and proof data structures, likely within a distributed or networked system. The file defines several functions that operate on a custom data structure, `fd_eqvoc_t`, which appears to be a container for managing FEC and proof-related operations. The primary functions include creating ([`fd_eqvoc_new`](#fd_eqvoc_new)), joining ([`fd_eqvoc_join`](#fd_eqvoc_join)), leaving ([`fd_eqvoc_leave`](#fd_eqvoc_leave)), and deleting ([`fd_eqvoc_delete`](#fd_eqvoc_delete)) instances of this data structure. Additionally, the file includes functions for inserting and searching FEC entries ([`fd_eqvoc_fec_insert`](#fd_eqvoc_fec_insert), [`fd_eqvoc_fec_search`](#fd_eqvoc_fec_search)), as well as managing proof entries ([`fd_eqvoc_proof_insert`](#fd_eqvoc_proof_insert), [`fd_eqvoc_proof_chunk_insert`](#fd_eqvoc_proof_chunk_insert), [`fd_eqvoc_proof_remove`](#fd_eqvoc_proof_remove), [`fd_eqvoc_proof_verify`](#fd_eqvoc_proof_verify)).

The code is structured to handle memory alignment and allocation for various components, such as FEC pools, maps, and proof pools, using a scratch allocation pattern. It also includes mechanisms for verifying the integrity and consistency of data, such as checking for equivocation in shreds and verifying signatures using Ed25519. The file is not a standalone executable but rather a component intended to be integrated into a larger system, likely providing a backend for handling data integrity and redundancy in a networked environment. The functions defined here do not expose a public API directly but are likely part of an internal library used by other components of the system.
# Imports and Dependencies

---
- `fd_eqvoc.h`
- `../../ballet/shred/fd_shred.h`


# Functions

---
### fd\_eqvoc\_new<!-- {{#callable:fd_eqvoc_new}} -->
The `fd_eqvoc_new` function initializes a new `fd_eqvoc_t` structure in shared memory, setting up various pools and maps for FEC and proof handling, and returns the shared memory pointer.
- **Inputs**:
    - `shmem`: A pointer to the shared memory region where the `fd_eqvoc_t` structure and associated resources will be allocated.
    - `fec_max`: The maximum number of FEC (Forward Error Correction) entries that can be handled.
    - `proof_max`: The maximum number of proof entries that can be handled.
    - `seed`: A seed value used for initializing certain components, likely for randomization or hashing purposes.
- **Control Flow**:
    - Check if `shmem` is NULL and log a warning if so, returning NULL.
    - Check if `shmem` is properly aligned according to `fd_eqvoc_align()` and log a warning if not, returning NULL.
    - Initialize a scratch allocator with `shmem`.
    - Allocate memory for the `fd_eqvoc_t` structure and various pools and maps using the scratch allocator.
    - Finalize the scratch allocation ensuring alignment with `fd_eqvoc_align()`.
    - Set the `fec_max`, `proof_max`, and `shred_version` fields of the `fd_eqvoc_t` structure.
    - Initialize the FEC pool and map with `fd_eqvoc_fec_pool_new` and `fd_eqvoc_fec_map_new`, using `fec_max` and `seed`.
    - Initialize the proof pool and map with `fd_eqvoc_proof_pool_new` and `fd_eqvoc_proof_map_new`, using `proof_max` and `seed`.
    - Initialize a SHA-512 context with `fd_sha512_new`.
    - Return the `shmem` pointer.
- **Output**: Returns the pointer to the shared memory (`shmem`) if successful, or NULL if there is an error in memory alignment or allocation.
- **Functions called**:
    - [`fd_eqvoc_align`](fd_eqvoc.h.driver.md#fd_eqvoc_align)


---
### fd\_eqvoc\_join<!-- {{#callable:fd_eqvoc_join}} -->
The `fd_eqvoc_join` function initializes and joins various memory pools and maps for an `fd_eqvoc_t` structure from a given shared memory region.
- **Inputs**:
    - `sheqvoc`: A pointer to the shared memory region that is expected to contain an `fd_eqvoc_t` structure.
- **Control Flow**:
    - Check if `sheqvoc` is NULL and log a warning if it is, returning NULL.
    - Check if `sheqvoc` is properly aligned according to `fd_eqvoc_align()` and log a warning if it is not, returning NULL.
    - Initialize a scratch allocator with `sheqvoc`.
    - Allocate memory for `fd_eqvoc_t` and its associated pools and maps using the scratch allocator.
    - Join the allocated pools and maps to the `fd_eqvoc_t` structure.
    - Return the `fd_eqvoc_t` structure cast from `sheqvoc`.
- **Output**: Returns a pointer to the `fd_eqvoc_t` structure initialized from the shared memory region, or NULL if there is an error.
- **Functions called**:
    - [`fd_eqvoc_align`](fd_eqvoc.h.driver.md#fd_eqvoc_align)


---
### fd\_eqvoc\_leave<!-- {{#callable:fd_eqvoc_leave}} -->
The `fd_eqvoc_leave` function checks if the given `fd_eqvoc_t` pointer is non-null and returns it cast to a `void *`, logging a warning if it is null.
- **Inputs**:
    - `eqvoc`: A constant pointer to an `fd_eqvoc_t` structure, representing the eqvoc object to be left.
- **Control Flow**:
    - Check if the `eqvoc` pointer is null using `FD_UNLIKELY`; if it is, log a warning message and return `NULL`.
    - If the `eqvoc` pointer is not null, cast it to a `void *` and return it.
- **Output**: Returns the input `eqvoc` pointer cast to a `void *`, or `NULL` if the input is null.


---
### fd\_eqvoc\_delete<!-- {{#callable:fd_eqvoc_delete}} -->
The `fd_eqvoc_delete` function checks if a given `eqvoc` pointer is non-null and properly aligned, logging warnings if not, and returns the pointer if valid.
- **Inputs**:
    - `eqvoc`: A pointer to the eqvoc object to be deleted.
- **Control Flow**:
    - Check if the `eqvoc` pointer is NULL using `FD_UNLIKELY`; if so, log a warning and return NULL.
    - Check if the `eqvoc` pointer is aligned using `fd_ulong_is_aligned` and [`fd_eqvoc_align`](fd_eqvoc.h.driver.md#fd_eqvoc_align); if not, log a warning and return NULL.
    - If both checks pass, return the `eqvoc` pointer.
- **Output**: Returns the `eqvoc` pointer if it is non-null and properly aligned, otherwise returns NULL.
- **Functions called**:
    - [`fd_eqvoc_align`](fd_eqvoc.h.driver.md#fd_eqvoc_align)


---
### fd\_eqvoc\_init<!-- {{#callable:fd_eqvoc_init}} -->
The `fd_eqvoc_init` function initializes an `fd_eqvoc_t` structure by setting its `shred_version` field to a specified value.
- **Inputs**:
    - `eqvoc`: A pointer to an `fd_eqvoc_t` structure that will be initialized.
    - `shred_version`: An unsigned long integer representing the version of the shred to be set in the `fd_eqvoc_t` structure.
- **Control Flow**:
    - The function takes a pointer to an `fd_eqvoc_t` structure and an unsigned long integer as inputs.
    - It assigns the `shred_version` input value to the `shred_version` field of the `fd_eqvoc_t` structure pointed to by `eqvoc`.
- **Output**: The function does not return any value; it modifies the `fd_eqvoc_t` structure in place.


---
### fd\_eqvoc\_fec\_insert<!-- {{#callable:fd_eqvoc_fec_insert}} -->
The `fd_eqvoc_fec_insert` function inserts a new FEC (Forward Error Correction) entry into the FEC map of an `fd_eqvoc_t` structure, ensuring no duplicate keys and sufficient space in the pool.
- **Inputs**:
    - `eqvoc`: A pointer to an `fd_eqvoc_t` structure, which contains the FEC map and pool where the new FEC entry will be inserted.
    - `slot`: An unsigned long integer representing the slot number for the FEC entry.
    - `fec_set_idx`: An unsigned integer representing the FEC set index for the FEC entry.
- **Control Flow**:
    - A key is created using the provided slot and fec_set_idx.
    - If FD_EQVOC_USE_HANDHOLDING is enabled, the function checks if the key already exists in the FEC map and logs an error if it does.
    - The function checks if there is space available in the FEC pool; if not, it logs an error indicating the map is full.
    - A new FEC entry is acquired from the FEC pool.
    - The slot and fec_set_idx are assigned to the new FEC entry's key.
    - The code_cnt, data_cnt, and last_idx fields of the new FEC entry are initialized to 0 and FD_SHRED_IDX_NULL, respectively.
    - The new FEC entry is inserted into the FEC map.
    - The function returns the pointer to the newly inserted FEC entry.
- **Output**: A pointer to the newly inserted `fd_eqvoc_fec_t` structure in the FEC map.


---
### fd\_eqvoc\_fec\_search<!-- {{#callable:fd_eqvoc_fec_search}} -->
The `fd_eqvoc_fec_search` function searches for a Forward Error Correction (FEC) entry in an equivocation vector based on a given shred and checks for conflicts or overlaps with existing entries.
- **Inputs**:
    - `eqvoc`: A pointer to a constant `fd_eqvoc_t` structure representing the equivocation vector.
    - `shred`: A pointer to a constant `fd_shred_t` structure representing the shred to be searched for in the FEC set.
- **Control Flow**:
    - Query the FEC entry for the given shred's slot and FEC set index using [`fd_eqvoc_fec_query`](fd_eqvoc.h.driver.md#fd_eqvoc_fec_query).
    - If an entry is found, check if the signature of the shred matches the entry's signature; if not, return the entry.
    - Check if the shred's index is higher than the entry's last index, indicating equivocation; if so, return the entry.
    - Iterate backward up to `FD_EQVOC_FEC_MAX` indices to check for overlapping FEC sets; if a conflict is found, return it.
    - Iterate forward up to the entry's `data_cnt` indices to check for overlapping FEC sets; if a conflict is found, return it.
    - If no conflicts are found, return `NULL`.
- **Output**: A pointer to a constant `fd_eqvoc_fec_t` structure representing the conflicting FEC entry, or `NULL` if no conflict is found.
- **Functions called**:
    - [`fd_eqvoc_fec_query`](fd_eqvoc.h.driver.md#fd_eqvoc_fec_query)


---
### fd\_eqvoc\_proof\_insert<!-- {{#callable:fd_eqvoc_proof_insert}} -->
The `fd_eqvoc_proof_insert` function inserts a new proof entry into the proof map of an `fd_eqvoc_t` structure, using a specified slot and public key.
- **Inputs**:
    - `eqvoc`: A pointer to an `fd_eqvoc_t` structure, which contains the proof map and proof pool where the new proof entry will be inserted.
    - `slot`: An unsigned long integer representing the slot number associated with the proof entry.
    - `from`: A constant pointer to an `fd_pubkey_t` structure, representing the public key associated with the proof entry.
- **Control Flow**:
    - A `fd_slot_pubkey_t` key is created using the provided slot and public key.
    - If `FD_EQVOC_USE_HANDHOLDING` is defined, the function checks if the key already exists in the proof map using `fd_eqvoc_proof_map_ele_query`; if it does, an error is logged and the function exits.
    - A new proof entry is acquired from the proof pool using `fd_eqvoc_proof_pool_ele_acquire`.
    - The acquired proof entry is initialized to zero using `memset`.
    - The slot and public key are assigned to the proof entry's key fields.
    - The proof entry is inserted into the proof map using `fd_eqvoc_proof_map_ele_insert`.
    - The function returns the pointer to the newly inserted proof entry.
- **Output**: A pointer to the newly inserted `fd_eqvoc_proof_t` structure, representing the proof entry.


---
### fd\_eqvoc\_proof\_chunk\_insert<!-- {{#callable:fd_eqvoc_proof_chunk_insert}} -->
The `fd_eqvoc_proof_chunk_insert` function updates a proof structure with a new chunk of data, ensuring the chunk is valid and not a duplicate before insertion.
- **Inputs**:
    - `proof`: A pointer to an `fd_eqvoc_proof_t` structure that represents the proof to be updated.
    - `chunk`: A constant pointer to an `fd_gossip_duplicate_shred_t` structure representing the chunk of data to be inserted into the proof.
- **Control Flow**:
    - Check if the chunk's wallclock is newer than the proof's wallclock; if so, update the proof's wallclock, chunk count, and reset the proof's set.
    - If the chunk's wallclock is older than the proof's wallclock, log a warning and return without making changes.
    - If the chunk's number of chunks does not match the proof's chunk count, log a warning and return without making changes.
    - Check if the chunk index is already present in the proof's set; if so, log a warning and return without making changes.
    - Copy the chunk data into the appropriate location in the proof's shreds array.
    - Insert the chunk index into the proof's set to mark it as received.
- **Output**: The function does not return a value; it modifies the `proof` structure in place.


---
### fd\_eqvoc\_proof\_init<!-- {{#callable:fd_eqvoc_proof_init}} -->
The `fd_eqvoc_proof_init` function initializes a `fd_eqvoc_proof_t` structure with specified parameters and zeroes out certain fields.
- **Inputs**:
    - `proof`: A pointer to an `fd_eqvoc_proof_t` structure that will be initialized.
    - `producer`: A constant pointer to an `fd_pubkey_t` structure representing the producer's public key.
    - `wallclock`: An unsigned long integer representing the wallclock time.
    - `chunk_cnt`: An unsigned long integer representing the number of chunks.
    - `chunk_sz`: An unsigned long integer representing the size of each chunk.
    - `bmtree_mem`: A pointer to memory allocated for a binary Merkle tree.
- **Control Flow**:
    - Assigns the `producer` public key to the `producer` field of the `proof` structure.
    - Assigns the `bmtree_mem` pointer to the `bmtree_mem` field of the `proof` structure.
    - Sets the `wallclock` field of the `proof` structure to the provided `wallclock` value.
    - Sets the `chunk_cnt` field of the `proof` structure to the provided `chunk_cnt` value.
    - Sets the `chunk_sz` field of the `proof` structure to the provided `chunk_sz` value.
    - Uses `memset` to zero out the `set` array within the `proof` structure, which is 4 times the size of an `ulong`.
    - Uses `memset` to zero out the `shreds` array within the `proof` structure, which is 2472 bytes in size.
- **Output**: The function does not return a value; it initializes the provided `fd_eqvoc_proof_t` structure in place.


---
### fd\_eqvoc\_proof\_remove<!-- {{#callable:fd_eqvoc_proof_remove}} -->
The `fd_eqvoc_proof_remove` function removes a proof entry from the proof map and releases its resources in the proof pool.
- **Inputs**:
    - `eqvoc`: A pointer to an `fd_eqvoc_t` structure, which contains the proof map and proof pool from which the proof entry will be removed.
    - `key`: A constant pointer to an `fd_slot_pubkey_t` structure, representing the key of the proof entry to be removed from the proof map.
- **Control Flow**:
    - Call `fd_eqvoc_proof_map_ele_remove` to attempt to remove the proof entry associated with `key` from the `eqvoc->proof_map` and store the result in `proof`.
    - Check if `proof` is NULL, indicating that the key was not found in the map.
    - If the key was not found, log a warning message and return from the function.
    - If the key was found, call `fd_eqvoc_proof_pool_ele_release` to release the resources associated with the proof entry back to the proof pool.
- **Output**: The function does not return a value; it performs operations to remove a proof entry and release its resources.


---
### fd\_eqvoc\_proof\_verify<!-- {{#callable:fd_eqvoc_proof_verify}} -->
The `fd_eqvoc_proof_verify` function verifies the validity of a proof by checking the consistency and correctness of two shreds associated with the proof.
- **Inputs**:
    - `proof`: A constant pointer to an `fd_eqvoc_proof_t` structure representing the proof to be verified.
- **Control Flow**:
    - The function retrieves two shreds from the proof using [`fd_eqvoc_proof_shred1_const`](fd_eqvoc.h.driver.md#fd_eqvoc_proof_shred1_const) and [`fd_eqvoc_proof_shred2_const`](fd_eqvoc.h.driver.md#fd_eqvoc_proof_shred2_const).
    - It calls [`fd_eqvoc_shreds_verify`](#fd_eqvoc_shreds_verify) with the two shreds, the proof's producer, and the proof's bmtree memory to perform the verification.
    - The result of [`fd_eqvoc_shreds_verify`](#fd_eqvoc_shreds_verify) is returned as the output of the function.
- **Output**: An integer indicating the result of the verification, where specific values represent different verification outcomes or errors.
- **Functions called**:
    - [`fd_eqvoc_shreds_verify`](#fd_eqvoc_shreds_verify)
    - [`fd_eqvoc_proof_shred1_const`](fd_eqvoc.h.driver.md#fd_eqvoc_proof_shred1_const)
    - [`fd_eqvoc_proof_shred2_const`](fd_eqvoc.h.driver.md#fd_eqvoc_proof_shred2_const)


---
### fd\_eqvoc\_shreds\_verify<!-- {{#callable:fd_eqvoc_shreds_verify}} -->
The `fd_eqvoc_shreds_verify` function verifies the integrity and consistency of two shreds by checking their slots, versions, types, signatures, and FEC set indices, returning specific error or success codes based on the verification results.
- **Inputs**:
    - `shred1`: A pointer to the first `fd_shred_t` structure representing the first shred to be verified.
    - `shred2`: A pointer to the second `fd_shred_t` structure representing the second shred to be verified.
    - `producer`: A pointer to the `fd_pubkey_t` structure representing the public key of the producer of the shreds.
    - `bmtree_mem`: A pointer to memory used for storing intermediate data during the Merkle root computation.
- **Control Flow**:
    - Check if the slots of `shred1` and `shred2` are equal; if not, return `FD_EQVOC_PROOF_VERIFY_ERR_SLOT`.
    - Check if the versions of `shred1` and `shred2` are equal; if not, return `FD_EQVOC_PROOF_VERIFY_ERR_VERSION`.
    - Verify that at least one of the shreds is either chained or resigned; if not, return `FD_EQVOC_PROOF_VERIFY_ERR_TYPE`.
    - Compute the Merkle root for both shreds and verify their signatures using the producer's public key; if any verification fails, return the corresponding error code.
    - If the FEC set indices of `shred1` and `shred2` are the same, check for different signatures, coding metadata, or last shred flags, returning success codes if any condition is met.
    - If the FEC set indices are different, ensure the lower index shred is a coding shred and check for overlap or conflicting chained Merkle roots, returning success codes if any condition is met.
    - If none of the conditions for success or error are met, return `FD_EQVOC_PROOF_VERIFY_FAILURE`.
- **Output**: The function returns an integer code indicating the result of the verification, which can be a specific error code, a success code, or a failure code.


---
### fd\_eqvoc\_proof\_from\_chunks<!-- {{#callable:fd_eqvoc_proof_from_chunks}} -->
The `fd_eqvoc_proof_from_chunks` function populates an `fd_eqvoc_proof_t` structure with data from an array of `fd_gossip_duplicate_shred_t` chunks.
- **Inputs**:
    - `chunks`: A pointer to an array of `fd_gossip_duplicate_shred_t` structures, each representing a chunk of data to be inserted into the proof.
    - `proof_out`: A pointer to an `fd_eqvoc_proof_t` structure where the chunks will be inserted to form a complete proof.
- **Control Flow**:
    - Retrieve the number of chunks from the first element of the `chunks` array.
    - Iterate over each chunk in the `chunks` array using a loop that runs `chunk_cnt` times.
    - For each chunk, call [`fd_eqvoc_proof_chunk_insert`](#fd_eqvoc_proof_chunk_insert) to insert the chunk into the `proof_out` structure.
- **Output**: The function does not return a value; it modifies the `proof_out` structure in place by inserting the chunks into it.
- **Functions called**:
    - [`fd_eqvoc_proof_chunk_insert`](#fd_eqvoc_proof_chunk_insert)


---
### fd\_eqvoc\_proof\_to\_chunks<!-- {{#callable:fd_eqvoc_proof_to_chunks}} -->
The function `fd_eqvoc_proof_to_chunks` converts a proof structure into multiple chunk structures for further processing or transmission.
- **Inputs**:
    - `proof`: A pointer to an `fd_eqvoc_proof_t` structure containing the proof data to be converted into chunks.
    - `chunks_out`: A pointer to an array of `fd_gossip_duplicate_shred_t` structures where the resulting chunks will be stored.
- **Control Flow**:
    - Iterate over a fixed number of chunks defined by `FD_EQVOC_PROOF_CHUNK_CNT`.
    - For each chunk, set its `duplicate_shred_index` to the current index `i`.
    - Assign the `from` field of the chunk to the hash from the proof's key.
    - Set the `wallclock` field of the chunk to the current wallclock time using `fd_log_wallclock()`.
    - Assign the `slot` field of the chunk to the slot from the proof's key.
    - Set the `num_chunks` field of the chunk to `FD_EQVOC_PROOF_CHUNK_CNT`.
    - Set the `chunk_len` field of the chunk to `FD_EQVOC_PROOF_CHUNK_MAX`.
    - Calculate the offset `off` for the current chunk based on its index and maximum chunk size.
    - Determine the size `sz` of the data to copy, which is the minimum of the maximum chunk size and the remaining data size.
    - Copy the calculated size of data from the proof's shreds to the current chunk's data field.
- **Output**: The function does not return a value; it populates the `chunks_out` array with the converted chunk data.


