# Purpose
The provided C header file, `fd_snapshot_create.h`, defines APIs for creating Agave-compatible snapshots from a slot execution context. This file is part of a larger system, likely related to blockchain or distributed ledger technology, as it involves creating snapshots of network states. The primary functionality revolves around the creation of both full and incremental snapshots, which are essential for maintaining and restoring the state of a distributed system. The file includes definitions for various constants, data structures, and function prototypes necessary for snapshot creation, such as `fd_snapshot_ctx_t`, which holds the context for snapshot creation, including parameters like the snapshot slot, output directory, and various handles to runtime data structures.

The header file is structured to provide a clear interface for snapshot creation, with a focus on managing the complexities of snapshot data, such as versioning, manifest creation, and status caching. It includes several utility functions for handling snapshot metadata, such as packing and unpacking sequence numbers to determine snapshot readiness and type (full or incremental). The file also outlines the process of writing snapshot data to a tar archive, which is then compressed, ensuring efficient storage and retrieval. This header file is intended to be included in other parts of the system, providing a modular and reusable interface for snapshot management, crucial for systems that require consistent state management and recovery capabilities.
# Imports and Dependencies

---
- `fd_snapshot_base.h`
- `../../funk/fd_funk_base.h`
- `../runtime/fd_txncache.h`
- `../../util/archive/fd_tar.h`
- `../types/fd_types.h`


# Data Structures

---
### fd\_features\_t
- **Type**: `union`
- **Members**:
    - `fd_features_t`: A typedef for the union fd_features, representing a feature set or configuration.
- **Description**: The `fd_features_t` is a typedef for a union named `fd_features`, which is intended to encapsulate a set of features or configurations. The specific details of the union's members are not provided in the code snippet, indicating that it might be defined elsewhere or intended to be flexible for future extensions. This union is used within the `fd_snapshot_ctx` structure, suggesting its role in managing or representing features related to snapshot creation or configuration.


---
### fd\_snapshot\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `slot`: Slot for the snapshot.
    - `out_dir`: Output directory.
    - `spad`: Bump allocator.
    - `funk`: Funk handle.
    - `status_cache`: Status cache handle.
    - `is_incremental`: Indicates if the snapshot is incremental.
    - `last_snap_slot`: Full snapshot slot.
    - `last_snap_capitalization`: Full snapshot capitalization.
    - `last_snap_acc_hash`: Full snapshot account hash.
    - `tpool`: Thread pool.
    - `tmp_fd`: File descriptor for the temporary tar archive.
    - `snapshot_fd`: File descriptor for the compressed snapshot file.
    - `writer`: Tar writer.
    - `snap_hash`: Snapshot hash.
    - `acc_hash`: Account hash.
    - `slot_bank`: Slot bank obtained from funk.
    - `epoch_bank`: Epoch bank obtained from funk.
    - `features`: Pointer to features.
- **Description**: The `fd_snapshot_ctx_t` structure is designed to manage the context required for creating snapshots in a system compatible with Agave. It includes various fields such as the slot number, output directory, and a bump allocator for memory management. The structure also references runtime data structures like the funk handle and status cache handle. It supports both full and incremental snapshots, with fields to store information about the last full snapshot, including its slot, capitalization, and account hash. Additionally, it manages file descriptors for handling tar archives and their compressed versions, and includes a tar writer and hash fields for snapshot and account verification. The structure is integral to the snapshot creation process, ensuring that all necessary data and resources are organized and accessible.


# Functions

---
### fd\_batch\_fseq\_pack<!-- {{#callable:FD_FN_UNUSED::fd_batch_fseq_pack}} -->
The `fd_batch_fseq_pack` function encodes snapshot and incremental flags along with a slot number into a single 64-bit unsigned long integer.
- **Inputs**:
    - `is_snapshot`: A flag indicating whether the operation is a snapshot (1) or not (0).
    - `is_incremental`: A flag indicating whether the snapshot is incremental (1) or not (0).
    - `smr`: A 62-bit value representing the slot number or other relevant data.
- **Control Flow**:
    - The function takes three unsigned long integer inputs: `is_snapshot`, `is_incremental`, and `smr`.
    - It performs bitwise AND operations on `is_snapshot` and `is_incremental` with `0x1UL` to ensure they are single-bit values.
    - The function shifts the `is_snapshot` bit 63 positions to the left, placing it in the most significant bit of the result.
    - It shifts the `is_incremental` bit 62 positions to the left, placing it in the second most significant bit of the result.
    - The function combines these shifted values with the `smr` value, which is masked to ensure it fits within 62 bits, using bitwise OR operations.
    - The combined result is returned as a single 64-bit unsigned long integer.
- **Output**: A 64-bit unsigned long integer that encodes the snapshot and incremental flags along with the slot number.


---
### fd\_batch\_fseq\_is\_snapshot<!-- {{#callable:FD_FN_UNUSED::fd_batch_fseq_is_snapshot}} -->
The function `fd_batch_fseq_is_snapshot` checks if a given sequence number indicates a snapshot operation by examining the most significant bit.
- **Inputs**:
    - `fseq`: An unsigned long integer representing a sequence number that encodes various flags and a slot number.
- **Control Flow**:
    - The function takes the input `fseq` and performs a bitwise right shift by 63 bits to isolate the most significant bit.
    - It then performs a bitwise AND operation with `0x1UL` to extract the value of this bit.
    - The result of the AND operation is returned, indicating whether the sequence number represents a snapshot operation.
- **Output**: The function returns an unsigned long integer (either 0 or 1) indicating whether the most significant bit of `fseq` is set, which signifies a snapshot operation.


---
### fd\_batch\_fseq\_is\_eah<!-- {{#callable:FD_FN_UNUSED::fd_batch_fseq_is_eah}} -->
The function `fd_batch_fseq_is_eah` checks if a given sequence number indicates that the batch tile should calculate the epoch account hash instead of producing a snapshot.
- **Inputs**:
    - `fseq`: An unsigned long integer representing a sequence number that encodes information about whether to calculate an epoch account hash or produce a snapshot.
- **Control Flow**:
    - The function shifts the input `fseq` 63 bits to the right to isolate the most significant bit (MSB).
    - It performs a bitwise AND operation with `0x1UL` to extract the MSB.
    - The result is negated using the logical NOT operator to determine if the MSB is 0, indicating that the epoch account hash should be calculated.
- **Output**: The function returns a non-zero value if the MSB of `fseq` is 0, indicating that the batch tile should calculate the epoch account hash; otherwise, it returns 0.


---
### fd\_batch\_fseq\_is\_incremental<!-- {{#callable:FD_FN_UNUSED::fd_batch_fseq_is_incremental}} -->
The function `fd_batch_fseq_is_incremental` checks if a given sequence number indicates an incremental snapshot.
- **Inputs**:
    - `fseq`: An unsigned long integer representing a sequence number that encodes snapshot information.
- **Control Flow**:
    - The function takes the input `fseq` and performs a bitwise right shift by 62 bits.
    - It then applies a bitwise AND operation with `0x1UL` to isolate the second most significant bit.
    - The result of the AND operation is returned, indicating whether the snapshot is incremental.
- **Output**: The function returns an unsigned long integer (either 0 or 1) indicating whether the snapshot is incremental (1) or not (0).


---
### fd\_batch\_fseq\_get\_slot<!-- {{#callable:FD_FN_UNUSED::fd_batch_fseq_get_slot}} -->
The `fd_batch_fseq_get_slot` function extracts the slot value from a given `fseq` by masking out the most significant bits.
- **Inputs**:
    - `fseq`: An unsigned long integer representing a packed sequence value containing various flags and a slot number.
- **Control Flow**:
    - The function takes a single input parameter `fseq`.
    - It applies a bitwise AND operation between `fseq` and the mask `0x3FFFFFFFFFFFFFFUL`.
    - This operation zeroes out the most significant bits, leaving only the least significant 56 bits, which represent the slot value.
- **Output**: The function returns an unsigned long integer representing the slot value extracted from the `fseq`.


# Function Declarations (Public API)

---
### fd\_snapshot\_create\_new\_snapshot<!-- {{#callable_declaration:fd_snapshot_create_new_snapshot}} -->
Create a new snapshot from the given execution context.
- **Description**: This function generates a new snapshot from the provided execution context, encapsulating the current state of the network into a compressed tarball. It should be used when a consistent snapshot of the network's state is required, either as a full snapshot or an incremental one, depending on the context's configuration. The function must be called with a properly initialized context, and it will populate the provided hash and capitalization pointers with the resulting snapshot's hash and capitalization values. Ensure that the context is correctly set up before calling this function to avoid errors.
- **Inputs**:
    - `snapshot_ctx`: A pointer to an fd_snapshot_ctx_t structure that holds the necessary data for snapshot creation. Must be properly initialized and not null.
    - `out_hash`: A pointer to an fd_hash_t where the resulting snapshot hash will be stored. Must not be null.
    - `out_capitalization`: A pointer to an ulong where the resulting snapshot capitalization will be stored. Must not be null.
- **Output**: None
- **See also**: [`fd_snapshot_create_new_snapshot`](fd_snapshot_create.c.driver.md#fd_snapshot_create_new_snapshot)  (Implementation)


