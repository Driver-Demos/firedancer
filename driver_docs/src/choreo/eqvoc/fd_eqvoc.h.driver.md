# Purpose
The provided C header file, `fd_eqvoc.h`, defines an API for detecting and handling equivocation proofs in a distributed system. Equivocation occurs when a shred producer generates multiple conflicting versions of a shred for the same slot and index. The file provides a comprehensive set of functions and data structures to construct, verify, and manage these equivocation proofs. The API is organized into two main components: `fd_eqvoc_proof` for handling the construction and verification of equivocation proofs, and `fd_eqvoc_fec` for managing shred and FEC (Forward Error Correction) set metadata to detect conflicting shreds. The file includes mechanisms for both direct and indirect proof verification, ensuring that shreds are consistent with their metadata and signatures.

The header file is designed to be included in other C source files, providing a public API for equivocation detection. It defines several data structures, such as `fd_eqvoc_fec_t` and `fd_eqvoc_proof_t`, which are used to store metadata and proof information. The file also includes macros and inline functions for efficient memory management and data manipulation. Additionally, it provides functions for initializing, joining, and leaving equivocation contexts, as well as for inserting and querying FEC and proof entries. The API is intended for use in systems where data integrity and consistency are critical, such as blockchain or distributed ledger technologies, where equivocation could undermine the trust and reliability of the system.
# Imports and Dependencies

---
- `../../ballet/shred/fd_shred.h`
- `../../flamenco/leaders/fd_leaders.h`
- `../fd_choreo_base.h`
- `../../flamenco/runtime/fd_blockstore.h`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_map_chain.c`
- `../../util/tmpl/fd_set.c`


# Global Variables

---
### fd\_slot\_fec\_null
- **Type**: ``fd_slot_fec_t``
- **Description**: The `fd_slot_fec_null` is a constant of type `fd_slot_fec_t`, which is a structure containing two fields: `slot` of type `ulong` and `fec_set_idx` of type `uint`. This constant is initialized with both fields set to zero, representing a null or default state for an FEC (Forward Error Correction) slot and index.
- **Use**: This variable is used as a default or null value for FEC slot and index operations, often to signify an uninitialized or invalid state.


---
### fd\_eqvoc\_new
- **Type**: `function pointer`
- **Description**: `fd_eqvoc_new` is a function that initializes a memory region for use as an equivocation detection and proof system (eqvoc). It takes a pointer to shared memory, a maximum number of FEC (Forward Error Correction) sets, a maximum number of proofs, and a seed for hashing as parameters.
- **Use**: This function is used to format a memory region to be used for equivocation detection and proof management.


---
### fd\_eqvoc\_join
- **Type**: `fd_eqvoc_t *`
- **Description**: The `fd_eqvoc_join` function returns a pointer to an `fd_eqvoc_t` structure, which represents an equivocation detection and proof management system. This system is used to detect and manage proofs of equivocation in a distributed environment, particularly in the context of shreds and FEC (Forward Error Correction) sets.
- **Use**: This variable is used to join a caller to an equivocation detection system, allowing the caller to interact with and manage equivocation proofs.


---
### fd\_eqvoc\_leave
- **Type**: `void *`
- **Description**: The `fd_eqvoc_leave` function is a global function that takes a constant pointer to an `fd_eqvoc_t` structure and returns a pointer to a void type. It is used to leave a current local join of an `fd_eqvoc` instance.
- **Use**: This function is used to disconnect from an `fd_eqvoc` instance, returning a pointer to the underlying shared memory region on success.


---
### fd\_eqvoc\_delete
- **Type**: `function pointer`
- **Description**: `fd_eqvoc_delete` is a function that unformats a memory region used as an equivocation detection structure (eqvoc). It assumes that no one is currently joined to the region and returns a pointer to the underlying shared memory region or NULL if there is an error, such as if the provided pointer is not a valid eqvoc.
- **Use**: This function is used to clean up and reclaim the memory region used for equivocation detection once it is no longer needed.


---
### fd\_eqvoc\_fec\_insert
- **Type**: `fd_eqvoc_fec_t *`
- **Description**: The `fd_eqvoc_fec_insert` function is a global function that returns a pointer to an `fd_eqvoc_fec_t` structure. This function is responsible for inserting a new Forward Error Correction (FEC) entry into the `fd_eqvoc` data structure, which is used for managing equivocation proofs in a distributed system. The function takes three parameters: a pointer to an `fd_eqvoc_t` structure, a slot number, and a FEC set index, which are used to index the new FEC entry.
- **Use**: This function is used to add a new FEC entry to the `fd_eqvoc` structure, allowing the system to track and manage FEC set metadata for equivocation detection.


---
### fd\_eqvoc\_fec\_search
- **Type**: `fd_eqvoc_fec_t const *`
- **Description**: The `fd_eqvoc_fec_search` function is a global function that returns a pointer to a constant `fd_eqvoc_fec_t` structure. This function is used to search for a conflicting Forward Error Correction (FEC) set entry that implies equivocation based on the provided `shred`. Equivocation occurs when a shred producer creates multiple versions of a shred for the same slot and index.
- **Use**: This function is used to detect equivocation by checking for conflicts in the indexed FEC sets.


---
### fd\_eqvoc\_proof\_insert
- **Type**: `fd_eqvoc_proof_t *`
- **Description**: The `fd_eqvoc_proof_insert` function is a global function that inserts a proof entry into the equivocation detection system, `eqvoc`, keyed by a specific slot and the public key of the shred producer. It returns a pointer to the `fd_eqvoc_proof_t` structure, which represents the proof of equivocation.
- **Use**: This function is used to add a new proof of equivocation to the `eqvoc` system, allowing for tracking and verification of equivocation events.


# Data Structures

---
### fd\_slot\_fec
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the FEC set.
    - `fec_set_idx`: Indicates the index of the FEC set within the slot.
- **Description**: The `fd_slot_fec` structure is a simple data structure used to represent a key for indexing FEC (Forward Error Correction) set metadata in the context of equivocation detection. It consists of two members: `slot`, which identifies the slot number, and `fec_set_idx`, which specifies the index of the FEC set within that slot. This structure is used as a key in various operations related to managing and querying FEC sets, which are crucial for detecting and handling equivocation in distributed systems.


---
### fd\_slot\_fec\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Represents the slot number associated with the FEC set.
    - `fec_set_idx`: Indicates the index of the FEC set within the slot.
- **Description**: The `fd_slot_fec_t` structure is a simple data structure used to represent metadata for a Forward Error Correction (FEC) set in a distributed system. It consists of two members: `slot`, which identifies the slot number, and `fec_set_idx`, which specifies the index of the FEC set within that slot. This structure is used as a key in various operations related to detecting and managing equivocation in shreds, which are data units in the system. The structure is fundamental in indexing and querying FEC set metadata to ensure data integrity and detect conflicts.


---
### fd\_eqvoc\_fec
- **Type**: `struct`
- **Members**:
    - `key`: A composite key of type `fd_slot_fec_t` used for indexing FEC sets.
    - `next`: An unsigned long integer used to link to the next element in a data structure.
    - `code_cnt`: An unsigned long integer representing the count of coding shreds in the FEC set.
    - `data_cnt`: An unsigned long integer representing the count of data shreds in the FEC set.
    - `last_idx`: An unsigned integer indicating the index of the last data shred in the slot.
    - `sig`: A signature of type `fd_ed25519_sig_t` used to verify the integrity of the FEC set.
- **Description**: The `fd_eqvoc_fec` structure is designed to manage metadata for Forward Error Correction (FEC) sets in a system that detects and handles equivocation in data shreds. It includes a composite key for indexing, counters for coding and data shreds, and a signature for verification purposes. This structure is integral to the process of identifying and managing conflicting shreds, ensuring data integrity and consistency in distributed systems.


---
### fd\_eqvoc\_fec\_t
- **Type**: `struct`
- **Members**:
    - `key`: A `fd_slot_fec_t` structure representing the unique key for the FEC set, consisting of a slot and FEC set index.
    - `next`: An unsigned long integer used to point to the next element in a linked list or chain.
    - `code_cnt`: An unsigned long integer representing the count of coding shreds in the FEC set.
    - `data_cnt`: An unsigned long integer representing the count of data shreds in the FEC set.
    - `last_idx`: An unsigned integer indicating the index of the last data shred in the FEC set.
    - `sig`: A `fd_ed25519_sig_t` structure holding the signature for the FEC set.
- **Description**: The `fd_eqvoc_fec_t` structure is designed to manage metadata for Forward Error Correction (FEC) sets in a system that detects equivocation in data shreds. It includes a key for identifying the FEC set, counters for coding and data shreds, and a signature to ensure integrity. The structure is part of a larger system that verifies and manages proofs of equivocation, ensuring that all shreds in an FEC set have consistent signatures, which is crucial for detecting conflicting shreds produced by the same source.


---
### fd\_eqvoc\_proof
- **Type**: `struct`
- **Members**:
    - `key`: A public key associated with the slot.
    - `prev`: Reserved for data structure use, likely for linking or indexing.
    - `next`: Reserved for data structure use, likely for linking or indexing.
    - `producer`: The public key of the producer of the shreds.
    - `bmtree_mem`: Scratch space for reconstructing the Merkle root.
    - `wallclock`: Represents the wallclock time.
    - `chunk_cnt`: The number of chunks in the proof.
    - `chunk_sz`: The size of each chunk in the proof.
    - `set`: A static declaration of a set that tracks which proof chunks have been received.
    - `shreds`: An array to store two shreds, each prefixed with its size in bytes.
- **Description**: The `fd_eqvoc_proof` structure is designed to represent a proof of equivocation in a distributed system, specifically for handling shreds in a blockchain context. It includes fields for managing the public key of the slot, the producer's public key, and memory for reconstructing Merkle roots. The structure also tracks the number and size of chunks in the proof, and includes a set to monitor received proof chunks. Additionally, it stores two shreds, each prefixed with its size, to facilitate the detection and verification of equivocation events.


---
### fd\_eqvoc\_proof\_t
- **Type**: `struct`
- **Members**:
    - `key`: A unique identifier for the proof, combining slot and producer's public key.
    - `prev`: Reserved for internal data structure use, likely for linked list operations.
    - `next`: Reserved for internal data structure use, likely for linked list operations.
    - `producer`: The public key of the shred producer involved in the proof.
    - `bmtree_mem`: Scratch space for reconstructing the Merkle root.
    - `wallclock`: A timestamp or counter representing the wall clock time.
    - `chunk_cnt`: The number of chunks the proof is divided into.
    - `chunk_sz`: The size of each chunk in the proof.
    - `set`: A static declaration of a set to track which proof chunks have been received.
    - `shreds`: An array storing two shreds, each prefixed with its size in bytes.
- **Description**: The `fd_eqvoc_proof_t` structure is designed to represent a proof of equivocation in a distributed system, specifically for detecting and handling conflicting shreds produced by the same entity. It includes metadata such as the producer's public key, a timestamp, and chunk information for reconstructing the proof from serialized data. The structure also contains fields reserved for internal data structure management, such as linked list pointers, and a set to track received proof chunks. The shreds are stored in a serialized format, with each shred prefixed by its size, facilitating the detection and verification of equivocation.


---
### fd\_eqvoc
- **Type**: `struct`
- **Members**:
    - `me`: This is the public key of the current entity using the structure.
    - `fec_max`: This represents the maximum number of FEC (Forward Error Correction) sets.
    - `proof_max`: This indicates the maximum number of equivocation proofs that can be handled.
    - `shred_version`: This is the expected version of shreds in equivocation-related messages.
    - `fec_pool`: A pointer to a pool of FEC structures used for managing FEC sets.
    - `fec_map`: A pointer to a map structure for indexing FEC set metadata.
    - `proof_pool`: A pointer to a pool of proof structures used for managing equivocation proofs.
    - `proof_map`: A pointer to a map structure for indexing proof metadata.
    - `sha512`: A pointer to a SHA-512 structure used for cryptographic operations.
    - `bmtree_mem`: A pointer to memory used for binary merkle tree operations.
    - `leaders`: A constant pointer to a structure containing epoch leader information.
- **Description**: The `fd_eqvoc` structure is designed to manage and process equivocation proofs and FEC sets in a distributed system. It includes fields for handling public keys, versioning, and maximum limits for FEC and proof sets. The structure also maintains pointers to pools and maps for FEC and proof management, as well as cryptographic and merkle tree operations. Additionally, it references epoch leader information, which is crucial for coordinating operations across different nodes in the system.


---
### fd\_eqvoc\_t
- **Type**: `struct`
- **Members**:
    - `me`: Our public key.
    - `fec_max`: Maximum number of FEC sets.
    - `proof_max`: Maximum number of proofs.
    - `shred_version`: Expected shred version in equivocation-related messages.
    - `fec_pool`: Pointer to the pool of FEC entries.
    - `fec_map`: Pointer to the map of FEC entries.
    - `proof_pool`: Pointer to the pool of proof entries.
    - `proof_map`: Pointer to the map of proof entries.
    - `sha512`: Pointer to SHA-512 hash context.
    - `bmtree_mem`: Pointer to memory for reconstructing the Merkle root.
    - `leaders`: Pointer to the epoch leaders data.
- **Description**: The `fd_eqvoc_t` structure is designed to manage the detection and handling of equivocation proofs in a distributed system. It includes fields for managing public keys, FEC (Forward Error Correction) sets, and proofs, as well as pointers to various pools and maps for organizing these elements. The structure also contains fields for handling cryptographic operations and memory management related to Merkle trees. It is used to ensure data integrity and detect conflicting data (equivocation) in a network by managing and verifying proofs of equivocation.


# Functions

---
### fd\_eqvoc\_align<!-- {{#callable:fd_eqvoc_align}} -->
The `fd_eqvoc_align` function returns the alignment requirement for the `fd_eqvoc_t` data structure.
- **Inputs**: None
- **Control Flow**:
    - The function calls `alignof(fd_eqvoc_t)` to determine the alignment requirement of the `fd_eqvoc_t` type.
    - It returns the result of the `alignof` operation.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_eqvoc_t` type.


---
### fd\_eqvoc\_footprint<!-- {{#callable:fd_eqvoc_footprint}} -->
The `fd_eqvoc_footprint` function calculates the memory footprint required for an equivocation detection and proof system based on specified maximum numbers of FEC and proof entries.
- **Inputs**:
    - `fec_max`: The maximum number of FEC (Forward Error Correction) entries that the system can handle.
    - `proof_max`: The maximum number of proof entries that the system can handle.
- **Control Flow**:
    - Initialize the layout with `FD_LAYOUT_INIT`.
    - Append the alignment and size of `fd_eqvoc_t` to the layout.
    - Append the alignment and footprint of the FEC pool based on `fec_max`.
    - Append the alignment and footprint of the FEC map based on `fec_max`.
    - Append the alignment and footprint of the proof pool based on `proof_max`.
    - Append the alignment and footprint of the proof map based on `proof_max`.
    - Append the alignment and footprint of the SHA-512 context.
    - Append the alignment and footprint of the bmtree commit for the Merkle layer count.
    - Finalize the layout with `FD_LAYOUT_FINI` and return the total footprint.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the equivocation detection and proof system.
- **Functions called**:
    - [`fd_eqvoc_align`](#fd_eqvoc_align)


---
### fd\_eqvoc\_fec\_query<!-- {{#callable:fd_eqvoc_fec_query}} -->
The `fd_eqvoc_fec_query` function retrieves FEC set metadata for a given slot and FEC set index from an equivocation context.
- **Inputs**:
    - `eqvoc`: A pointer to an `fd_eqvoc_t` structure representing the equivocation context.
    - `slot`: An unsigned long integer representing the slot number for which FEC set metadata is being queried.
    - `fec_set_idx`: An unsigned integer representing the index of the FEC set within the specified slot.
- **Control Flow**:
    - A `fd_slot_fec_t` key is created using the provided `slot` and `fec_set_idx`.
    - The function calls `fd_eqvoc_fec_map_ele_query_const` with the FEC map from `eqvoc`, the created key, a NULL pointer, and the FEC pool from `eqvoc`.
    - The result of the query is returned, which is a pointer to the FEC set metadata.
- **Output**: A constant pointer to an `fd_eqvoc_fec_t` structure containing the FEC set metadata, or NULL if no such metadata exists.


---
### fd\_eqvoc\_proof\_query\_const<!-- {{#callable:fd_eqvoc_proof_query_const}} -->
The `fd_eqvoc_proof_query_const` function retrieves a constant pointer to an equivocation proof from a proof map using a specified slot and public key.
- **Inputs**:
    - `eqvoc`: A constant pointer to an `fd_eqvoc_t` structure, which contains the proof map and proof pool.
    - `slot`: An unsigned long integer representing the slot number for which the proof is being queried.
    - `from`: A constant pointer to an `fd_pubkey_t` structure representing the public key of the shred producer.
- **Control Flow**:
    - A `fd_slot_pubkey_t` key is created using the provided `slot` and `from` public key.
    - The function calls `fd_eqvoc_proof_map_ele_query_const` with the proof map, the created key, a NULL value, and the proof pool to retrieve the proof.
- **Output**: Returns a constant pointer to an `fd_eqvoc_proof_t` structure if the proof is found, or NULL if it is not.


---
### fd\_eqvoc\_proof\_complete<!-- {{#callable:fd_eqvoc_proof_complete}} -->
The `fd_eqvoc_proof_complete` function checks if all chunks of an equivocation proof have been received.
- **Inputs**:
    - `proof`: A pointer to a constant `fd_eqvoc_proof_t` structure representing the equivocation proof to be checked for completeness.
- **Control Flow**:
    - Iterates over each chunk index from 0 to `proof->chunk_cnt - 1`.
    - For each index, checks if the chunk is present in the proof's set using `fd_eqvoc_proof_set_test`.
    - If any chunk is not present, returns 0 indicating the proof is incomplete.
    - If all chunks are present, returns 1 indicating the proof is complete.
- **Output**: Returns an integer: 1 if all chunks are present (proof is complete), or 0 if any chunk is missing (proof is incomplete).


---
### fd\_eqvoc\_proof\_shred1<!-- {{#callable:fd_eqvoc_proof_shred1}} -->
The `fd_eqvoc_proof_shred1` function returns a pointer to the first shred in a given equivocation proof structure.
- **Inputs**:
    - `proof`: A pointer to an `fd_eqvoc_proof_t` structure, which contains serialized shreds and metadata for equivocation proof.
- **Control Flow**:
    - The function calculates the memory offset for the first shred by adding the size of an `ulong` to the base address of the `shreds` array within the `proof` structure.
    - It then casts this calculated address to a pointer of type `fd_shred_t` using the `fd_type_pun_const` function.
    - Finally, it returns this pointer, which points to the first shred in the proof.
- **Output**: A pointer to the first shred (`fd_shred_t *`) within the `proof` structure.


---
### fd\_eqvoc\_proof\_shred1\_const<!-- {{#callable:fd_eqvoc_proof_shred1_const}} -->
The function `fd_eqvoc_proof_shred1_const` returns a constant pointer to the first shred in a given equivocation proof.
- **Inputs**:
    - `proof`: A constant pointer to an `fd_eqvoc_proof_t` structure, which contains serialized shreds and other metadata related to equivocation proofs.
- **Control Flow**:
    - The function takes a constant pointer to an `fd_eqvoc_proof_t` structure as input.
    - It calculates the address of the first shred by adding the size of an `ulong` to the base address of the `shreds` array within the `proof` structure.
    - It casts this calculated address to a constant pointer of type `fd_shred_t` and returns it.
- **Output**: A constant pointer to the first `fd_shred_t` within the `shreds` array of the `fd_eqvoc_proof_t` structure.


---
### fd\_eqvoc\_proof\_shred2<!-- {{#callable:fd_eqvoc_proof_shred2}} -->
The function `fd_eqvoc_proof_shred2` retrieves a pointer to the second shred in a proof structure.
- **Inputs**:
    - `proof`: A pointer to an `fd_eqvoc_proof_t` structure, which contains serialized shreds and their sizes.
- **Control Flow**:
    - Retrieve the size of the first shred by casting the beginning of the `shreds` array in `proof` to a `ulong` pointer and dereferencing it.
    - Calculate the offset for the second shred by adding the size of the first shred and twice the size of a `ulong` to the base address of the `shreds` array.
    - Return a pointer to the second shred by casting the calculated address to an `fd_shred_t` pointer.
- **Output**: A pointer to the second shred (`fd_shred_t *`) within the `proof` structure.


---
### fd\_eqvoc\_proof\_shred2\_const<!-- {{#callable:fd_eqvoc_proof_shred2_const}} -->
The function `fd_eqvoc_proof_shred2_const` retrieves a constant pointer to the second shred in a proof structure.
- **Inputs**:
    - `proof`: A constant pointer to an `fd_eqvoc_proof_t` structure, which contains serialized shreds and their sizes.
- **Control Flow**:
    - Retrieve the size of the first shred by casting the `shreds` array in the `proof` structure to a constant pointer to `ulong` and dereferencing it.
    - Calculate the offset to the second shred by adding the size of the first shred and twice the size of `ulong` to the base address of the `shreds` array.
    - Return a constant pointer to the second shred by casting the calculated address to a constant pointer to `fd_shred_t`.
- **Output**: A constant pointer to the second shred (`fd_shred_t const *`) in the `proof` structure.


# Function Declarations (Public API)

---
### fd\_eqvoc\_new<!-- {{#callable_declaration:fd_eqvoc_new}} -->
Initializes a memory region for equivocation detection and proof management.
- **Description**: This function prepares a given memory region for use in detecting and managing equivocation proofs. It should be called with a properly aligned and non-null memory region that meets the required footprint for the specified maximum number of FEC and proof entries. The function initializes various internal structures necessary for equivocation detection and proof management, using the provided seed for randomization purposes. It returns a pointer to the initialized memory region or NULL if the input memory is null or misaligned.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be initialized. Must not be null and must be aligned according to fd_eqvoc_align(). The caller retains ownership.
    - `fec_max`: The maximum number of FEC entries the memory region should support. Must be a positive integer.
    - `proof_max`: The maximum number of proof entries the memory region should support. Must be a positive integer.
    - `seed`: A seed value used for initializing internal randomization processes. Can be any unsigned long integer.
- **Output**: Returns a pointer to the initialized memory region on success, or NULL if the input memory is null or misaligned.
- **See also**: [`fd_eqvoc_new`](fd_eqvoc.c.driver.md#fd_eqvoc_new)  (Implementation)


---
### fd\_eqvoc\_join<!-- {{#callable_declaration:fd_eqvoc_join}} -->
Joins the caller to an equivocation detection and proof system.
- **Description**: This function is used to join a caller to an equivocation detection and proof system by providing access to a shared memory region. It should be called when a caller needs to participate in equivocation detection, typically after the memory region has been properly initialized. The function requires the memory region to be correctly aligned and non-null. If these conditions are not met, the function will log a warning and return NULL, indicating failure to join.
- **Inputs**:
    - `sheqvoc`: A pointer to the shared memory region representing the equivocation system. It must not be null and must be aligned according to the requirements of the equivocation system. If the pointer is null or misaligned, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the local address space representation of the equivocation system on success, or NULL on failure.
- **See also**: [`fd_eqvoc_join`](fd_eqvoc.c.driver.md#fd_eqvoc_join)  (Implementation)


---
### fd\_eqvoc\_leave<!-- {{#callable_declaration:fd_eqvoc_leave}} -->
Leaves a current local join of an eqvoc instance.
- **Description**: This function is used to leave a current local join of an eqvoc instance, effectively detaching from the shared memory region associated with the eqvoc. It should be called when the caller no longer needs to interact with the eqvoc instance. The function returns a pointer to the underlying shared memory region if successful, allowing for potential cleanup or further operations on the memory. If the provided eqvoc pointer is NULL, the function logs a warning and returns NULL, indicating failure.
- **Inputs**:
    - `eqvoc`: A pointer to the eqvoc instance to leave. Must not be NULL. If NULL, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the eqvoc pointer is NULL.
- **See also**: [`fd_eqvoc_leave`](fd_eqvoc.c.driver.md#fd_eqvoc_leave)  (Implementation)


---
### fd\_eqvoc\_delete<!-- {{#callable_declaration:fd_eqvoc_delete}} -->
Unformats a memory region used as an eqvoc.
- **Description**: This function is used to unformat a memory region that was previously formatted for use as an eqvoc, effectively reversing the setup done by `fd_eqvoc_new`. It should be called when the eqvoc is no longer needed, and it is assumed that no processes are currently joined to the eqvoc. The function returns a pointer to the underlying shared memory region, transferring ownership of this memory back to the caller. If the provided pointer is null or misaligned, the function logs a warning and returns null.
- **Inputs**:
    - `sheqvoc`: A pointer to the memory region used as an eqvoc. It must not be null and should be properly aligned according to `fd_eqvoc_align()`. If the pointer is null or misaligned, the function logs a warning and returns null.
- **Output**: Returns a pointer to the underlying shared memory region if successful, or null if the input is invalid.
- **See also**: [`fd_eqvoc_delete`](fd_eqvoc.c.driver.md#fd_eqvoc_delete)  (Implementation)


---
### fd\_eqvoc\_init<!-- {{#callable_declaration:fd_eqvoc_init}} -->
Initialize an fd_eqvoc_t structure with a specified shred version.
- **Description**: This function sets the shred version for an fd_eqvoc_t structure, which is used in equivocation detection and proof handling. It should be called to initialize the eqvoc structure with the expected shred version before using it in any equivocation-related operations. This ensures that all shreds processed by this eqvoc instance are expected to have the specified version.
- **Inputs**:
    - `eqvoc`: A pointer to an fd_eqvoc_t structure that will be initialized. Must not be null, and the caller retains ownership.
    - `shred_version`: An unsigned long integer representing the shred version to be set in the eqvoc structure. There are no specific constraints on the value, but it should match the expected version of shreds to be processed.
- **Output**: None
- **See also**: [`fd_eqvoc_init`](fd_eqvoc.c.driver.md#fd_eqvoc_init)  (Implementation)


---
### fd\_eqvoc\_fec\_insert<!-- {{#callable_declaration:fd_eqvoc_fec_insert}} -->
Inserts a new FEC entry into the equivocation detection system.
- **Description**: This function is used to add a new Forward Error Correction (FEC) entry into the equivocation detection system, indexed by a specific slot and FEC set index. It should be called when a new FEC entry needs to be tracked for equivocation detection. The function assumes that the provided slot and FEC set index are not already present in the system, and it will log an error if they are. Additionally, it requires that there is available space in the FEC pool to accommodate the new entry, logging an error if the pool is full. This function is typically used in systems that need to monitor and detect equivocation in data shreds.
- **Inputs**:
    - `eqvoc`: A pointer to an fd_eqvoc_t structure representing the equivocation detection system. Must not be null, and the system should be properly initialized before calling this function.
    - `slot`: An unsigned long integer representing the slot number for the FEC entry. It should be a valid slot number that is not already in use with the given FEC set index.
    - `fec_set_idx`: An unsigned integer representing the FEC set index for the entry. It should be a valid index that is not already in use with the given slot.
- **Output**: Returns a pointer to the newly inserted fd_eqvoc_fec_t structure representing the FEC entry.
- **See also**: [`fd_eqvoc_fec_insert`](fd_eqvoc.c.driver.md#fd_eqvoc_fec_insert)  (Implementation)


---
### fd\_eqvoc\_fec\_search<!-- {{#callable_declaration:fd_eqvoc_fec_search}} -->
Searches for equivocation conflicts in FEC sets for a given shred.
- **Description**: Use this function to determine if a given shred implies equivocation by checking for conflicts in the currently indexed FEC sets. This function is useful when you need to verify the integrity of shreds and ensure that no equivocation has occurred. It checks both backward and forward for overlapping FEC sets that might indicate equivocation. The function should be called with a valid `fd_eqvoc_t` context and a `fd_shred_t` shred. It returns a pointer to a conflicting FEC entry if a conflict is detected, or NULL if no conflicts are found.
- **Inputs**:
    - `eqvoc`: A pointer to a constant `fd_eqvoc_t` structure representing the equivocation context. Must not be null.
    - `shred`: A pointer to a constant `fd_shred_t` structure representing the shred to be checked for equivocation. Must not be null.
- **Output**: Returns a pointer to a constant `fd_eqvoc_fec_t` structure if a conflict is found, or NULL if no conflicts are detected.
- **See also**: [`fd_eqvoc_fec_search`](fd_eqvoc.c.driver.md#fd_eqvoc_fec_search)  (Implementation)


---
### fd\_eqvoc\_proof\_insert<!-- {{#callable_declaration:fd_eqvoc_proof_insert}} -->
Inserts a proof entry into the equivocation detection system.
- **Description**: This function is used to insert a new proof entry into the equivocation detection system, identified by a specific slot and the public key of the shred producer. It is typically called when a new proof needs to be recorded in the system. The function assumes that the proof entry for the given slot and public key does not already exist in the system. If the entry already exists, and runtime checks are enabled, an error is logged. The function initializes the proof entry and inserts it into the appropriate data structures for tracking.
- **Inputs**:
    - `eqvoc`: A pointer to an fd_eqvoc_t structure representing the equivocation detection system. Must not be null, and the caller retains ownership.
    - `slot`: An unsigned long integer representing the slot number for the proof. It should be a valid slot number within the system's context.
    - `from`: A pointer to an fd_pubkey_t structure representing the public key of the shred producer. Must not be null, and the caller retains ownership.
- **Output**: Returns a pointer to the newly inserted fd_eqvoc_proof_t structure representing the proof entry.
- **See also**: [`fd_eqvoc_proof_insert`](fd_eqvoc.c.driver.md#fd_eqvoc_proof_insert)  (Implementation)


---
### fd\_eqvoc\_proof\_init<!-- {{#callable_declaration:fd_eqvoc_proof_init}} -->
Initialize an equivocation proof structure.
- **Description**: This function initializes a `fd_eqvoc_proof_t` structure with the provided parameters, setting up the initial state for an equivocation proof. It should be called before using the proof structure in any operations related to equivocation detection. The function sets the producer's public key, wallclock time, chunk count, chunk size, and a memory area for Merkle tree operations. It also clears the internal set and shreds arrays to ensure a clean starting state.
- **Inputs**:
    - `proof`: A pointer to a `fd_eqvoc_proof_t` structure that will be initialized. Must not be null, and the caller retains ownership.
    - `producer`: A pointer to a `fd_pubkey_t` representing the producer's public key. Must not be null, and the caller retains ownership.
    - `wallclock`: An unsigned long representing the wallclock time. No specific range is enforced.
    - `chunk_cnt`: An unsigned long representing the number of chunks. No specific range is enforced, but it should be consistent with the expected number of chunks for the proof.
    - `chunk_sz`: An unsigned long representing the size of each chunk. No specific range is enforced, but it should be consistent with the expected chunk size for the proof.
    - `bmtree_mem`: A pointer to a memory area used for Merkle tree operations. The caller retains ownership and is responsible for ensuring it is valid for the duration of its use.
- **Output**: None
- **See also**: [`fd_eqvoc_proof_init`](fd_eqvoc.c.driver.md#fd_eqvoc_proof_init)  (Implementation)


---
### fd\_eqvoc\_proof\_chunk\_insert<!-- {{#callable_declaration:fd_eqvoc_proof_chunk_insert}} -->
Inserts a proof chunk into an equivocation proof.
- **Description**: Use this function to add a chunk of data to an existing equivocation proof. This is necessary when reconstructing proofs that have been divided into chunks for transmission. The function updates the proof's state based on the chunk's wallclock and ensures that chunks are compatible with the proof's current state. It handles cases where the chunk is newer, older, or incompatible by either updating the proof or ignoring the chunk. Ensure that the proof has been initialized and is ready to receive chunks before calling this function.
- **Inputs**:
    - `proof`: A pointer to an fd_eqvoc_proof_t structure where the chunk will be inserted. Must not be null and should be properly initialized before use.
    - `chunk`: A pointer to a constant fd_gossip_duplicate_shred_t structure representing the chunk to be inserted. Must not be null and should contain valid data for the operation.
- **Output**: None
- **See also**: [`fd_eqvoc_proof_chunk_insert`](fd_eqvoc.c.driver.md#fd_eqvoc_proof_chunk_insert)  (Implementation)


---
### fd\_eqvoc\_proof\_remove<!-- {{#callable_declaration:fd_eqvoc_proof_remove}} -->
Removes a proof entry associated with a given key from the equivocation proof map.
- **Description**: Use this function to remove a proof entry from the equivocation proof map within the specified `fd_eqvoc_t` structure. This is typically done when a proof is no longer needed or has been processed. The function requires a valid `fd_eqvoc_t` structure and a `fd_slot_pubkey_t` key that identifies the proof to be removed. If the key is not found in the map, a warning is logged, and no action is taken. Ensure that the `eqvoc` and `key` are properly initialized and valid before calling this function.
- **Inputs**:
    - `eqvoc`: A pointer to an `fd_eqvoc_t` structure representing the equivocation context. Must not be null and should be properly initialized.
    - `key`: A pointer to a `fd_slot_pubkey_t` structure that identifies the proof to be removed. Must not be null and should be a valid key in the proof map.
- **Output**: None
- **See also**: [`fd_eqvoc_proof_remove`](fd_eqvoc.c.driver.md#fd_eqvoc_proof_remove)  (Implementation)


---
### fd\_eqvoc\_proof\_verify<!-- {{#callable_declaration:fd_eqvoc_proof_verify}} -->
Verifies if the shreds in the proof indicate equivocation.
- **Description**: Use this function to determine if the two shreds contained within a given proof demonstrate equivocation by the shred producer. This function should be called when you have a proof and need to verify its validity in terms of equivocation. It performs various checks on the shreds, such as ensuring they belong to the same slot, have the expected shred version, and are signed by the same producer. The function returns specific codes indicating the result of the verification, which can be success, failure, or an error due to invalid inputs.
- **Inputs**:
    - `proof`: A pointer to a constant fd_eqvoc_proof_t structure containing the shreds to be verified. The proof must not be null and should be properly initialized with valid shreds and metadata.
- **Output**: Returns an integer code indicating the result of the verification: success, failure, or an error code if the inputs are invalid.
- **See also**: [`fd_eqvoc_proof_verify`](fd_eqvoc.c.driver.md#fd_eqvoc_proof_verify)  (Implementation)


---
### fd\_eqvoc\_shreds\_verify<!-- {{#callable_declaration:fd_eqvoc_shreds_verify}} -->
Verifies if two shreds indicate equivocation by a producer.
- **Description**: This function checks whether two shreds, `shred1` and `shred2`, produced by the same entity, indicate equivocation, which occurs when a producer creates conflicting shreds for the same slot and index. It should be used when you need to verify the integrity and consistency of shreds in a distributed system. The function requires both shreds to be from the same slot and version, and they must be of a type that supports chaining or resigning. It also verifies the signatures of the shreds against the provided producer's public key. The function returns specific error codes if the shreds do not meet these criteria or if verification fails.
- **Inputs**:
    - `shred1`: A pointer to the first shred to verify. It must not be null and should be a valid shred structure.
    - `shred2`: A pointer to the second shred to verify. It must not be null and should be a valid shred structure.
    - `producer`: A pointer to the public key of the producer of the shreds. It must not be null and should be a valid public key structure.
    - `bmtree_mem`: A pointer to memory used for constructing the Merkle root. It must be valid and properly allocated for the operation.
- **Output**: Returns an integer indicating the result of the verification: success codes for different types of equivocation or error codes for verification failures.
- **See also**: [`fd_eqvoc_shreds_verify`](fd_eqvoc.c.driver.md#fd_eqvoc_shreds_verify)  (Implementation)


---
### fd\_eqvoc\_proof\_from\_chunks<!-- {{#callable_declaration:fd_eqvoc_proof_from_chunks}} -->
Constructs an equivocation proof from an array of duplicate shred chunks.
- **Description**: Use this function to assemble an equivocation proof from a series of duplicate shred chunks. It is essential when reconstructing proofs from serialized data received over a network. The function assumes that the `chunks` array is non-null and contains at least one valid element, with the first element providing necessary metadata such as the number of chunks. The caller must ensure that the `chunk` field in each `fd_gossip_duplicate_shred_t` is a valid pointer and consistent with the metadata. This function is useful in scenarios where proofs are transmitted in parts and need to be reassembled for verification or further processing.
- **Inputs**:
    - `chunks`: A pointer to an array of `fd_gossip_duplicate_shred_t` structures, representing the chunks of a duplicate shred proof. The array must be non-null and contain at least one valid element. The first element provides metadata such as the number of chunks. The `chunk` field in each element must point to valid memory.
    - `proof_out`: A pointer to an `fd_eqvoc_proof_t` structure where the reconstructed proof will be stored. The caller must ensure this pointer is valid and points to sufficient memory to hold the proof.
- **Output**: None
- **See also**: [`fd_eqvoc_proof_from_chunks`](fd_eqvoc.c.driver.md#fd_eqvoc_proof_from_chunks)  (Implementation)


---
### fd\_eqvoc\_proof\_to\_chunks<!-- {{#callable_declaration:fd_eqvoc_proof_to_chunks}} -->
Converts an equivocation proof into an array of duplicate shred chunks.
- **Description**: This function is used to break down an equivocation proof into smaller chunks suitable for transmission or storage. It should be called when you need to serialize a proof into discrete parts, each represented as a `fd_gossip_duplicate_shred_t` structure. The function requires a valid `fd_eqvoc_proof_t` object and an array of `fd_gossip_duplicate_shred_t` structures with sufficient capacity to hold all the chunks. The caller must ensure that the `chunks_out` array is large enough to accommodate all the chunks, which is determined by the constants `FD_EQVOC_PROOF_CHUNK_CNT` and `FD_EQVOC_PROOF_CHUNK_MAX`. Each chunk in the output array will be populated with the appropriate data from the proof.
- **Inputs**:
    - `proof`: A pointer to a `fd_eqvoc_proof_t` structure representing the equivocation proof to be chunked. Must not be null.
    - `chunks_out`: A pointer to an array of `fd_gossip_duplicate_shred_t` structures where the chunks will be stored. The array must have at least `FD_EQVOC_PROOF_CHUNK_CNT` elements, and each element must have a buffer of at least `FD_EQVOC_PROOF_CHUNK_MAX` size available in its `chunk` field.
- **Output**: None
- **See also**: [`fd_eqvoc_proof_to_chunks`](fd_eqvoc.c.driver.md#fd_eqvoc_proof_to_chunks)  (Implementation)


