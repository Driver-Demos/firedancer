# Purpose
This C header file defines the structures and functions necessary for verifying transactions within a distributed system, specifically focusing on deduplication and signature verification. The file provides a narrow but critical functionality, encapsulating the logic required to ensure that transactions are unique and valid before they are processed further. The primary technical components include the `fd_verify_ctx_t` structure, which maintains the context for transaction verification, including memory management, transaction cache, and metrics for tracking verification failures. The [`fd_txn_verify`](#fd_txn_verify) function is the core of this file, implementing the logic to verify transaction signatures and check for duplicate transactions using a hash-based deduplication mechanism.

The file is designed to be included in other parts of a larger system, as indicated by the use of include guards and the inclusion of other headers. It defines an external interface through the [`fd_txn_verify`](#fd_txn_verify) function, which is intended to be called by other components to perform transaction verification. The file also defines several constants and structures that are used to manage the state and results of the verification process. Overall, this header file is a specialized component of a larger transaction processing system, providing essential functionality for maintaining the integrity and efficiency of transaction handling.
# Imports and Dependencies

---
- `../tiles.h`


# Global Variables

---
### fd\_tile\_verify
- **Type**: `fd_topo_run_tile_t`
- **Description**: The variable `fd_tile_verify` is a global variable of type `fd_topo_run_tile_t`. It is declared as an external variable, indicating that it is defined elsewhere, likely in another source file. This variable is part of the verification tile system, which is used in the context of transaction verification.
- **Use**: This variable is used to represent a tile in the topology that is responsible for verifying transactions.


# Data Structures

---
### fd\_verify\_in\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `mem`: A pointer to an fd_wksp_t structure, representing a memory workspace.
    - `chunk0`: An unsigned long integer representing the starting chunk index.
    - `wmark`: An unsigned long integer representing a watermark or threshold value.
- **Description**: The `fd_verify_in_ctx_t` structure is a context object used for managing each producer's memory cache (mcache) connected to the verify tile in a distributed system. It contains a pointer to a memory workspace (`mem`), a starting chunk index (`chunk0`), and a watermark (`wmark`) to manage and track the memory usage and processing state of the mcache.


---
### fd\_verify\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `sha`: An array of pointers to fd_sha512_t, used for SHA-512 hashing operations.
    - `bundle_failed`: An integer flag indicating if the bundle verification failed.
    - `bundle_id`: An unsigned long representing the unique identifier for the bundle.
    - `round_robin_idx`: An unsigned long used as an index for round-robin operations.
    - `round_robin_cnt`: An unsigned long representing the count for round-robin operations.
    - `tcache_depth`: An unsigned long indicating the depth of the transaction cache.
    - `tcache_map_cnt`: An unsigned long representing the count of the transaction cache map.
    - `tcache_sync`: A pointer to an unsigned long used for synchronizing the transaction cache.
    - `tcache_ring`: A pointer to an unsigned long representing the transaction cache ring buffer.
    - `tcache_map`: A pointer to an unsigned long representing the transaction cache map.
    - `in_kind`: An array of unsigned longs representing the kinds of input transactions.
    - `in`: An array of fd_verify_in_ctx_t structures representing input contexts.
    - `out_mem`: A pointer to fd_wksp_t representing the output memory workspace.
    - `out_chunk0`: An unsigned long representing the initial output chunk.
    - `out_wmark`: An unsigned long representing the watermark for output.
    - `out_chunk`: An unsigned long representing the current output chunk.
    - `hashmap_seed`: An unsigned long used as a seed for hashing operations.
    - `metrics`: A nested structure containing counters for various failure metrics.
- **Description**: The `fd_verify_ctx_t` structure is a comprehensive context used for transaction verification processes, incorporating elements for hashing, transaction caching, and failure metrics. It includes arrays and pointers for managing SHA-512 operations, transaction cache synchronization, and input contexts, as well as fields for tracking the state and results of transaction verification, such as bundle identifiers and failure counts. This structure is integral to managing the verification workflow, ensuring efficient handling of transactions and maintaining performance metrics.


# Functions

---
### fd\_txn\_verify<!-- {{#callable:fd_txn_verify}} -->
The `fd_txn_verify` function verifies the signatures of a transaction and checks for duplicate transactions using a deduplication cache.
- **Inputs**:
    - `ctx`: A pointer to a `fd_verify_ctx_t` structure containing context information for verification, including hash map seed and deduplication cache details.
    - `udp_payload`: A pointer to the UDP payload containing the transaction data.
    - `payload_sz`: The size of the UDP payload in bytes.
    - `txn`: A pointer to a `fd_txn_t` structure containing offsets and counts related to the transaction's signatures and message.
    - `dedup`: An integer flag indicating whether deduplication should be performed (non-zero value) or not (zero value).
    - `opt_sig`: A pointer to an unsigned long where the deduplication tag (signature) will be stored if the transaction is successfully verified.
- **Control Flow**:
    - Extracts signature count and offsets from the `txn` structure to avoid multiple dereferences.
    - Calculates pointers to the signatures, public keys, and message within the UDP payload using the offsets.
    - Computes a deduplication tag using the first signature and the hash map seed from the context.
    - If deduplication is enabled, checks the deduplication cache for the tag; if found, returns `FD_TXN_VERIFY_DEDUP`.
    - Verifies the transaction's signatures using the `fd_ed25519_verify_batch_single_msg` function; if verification fails, returns `FD_TXN_VERIFY_FAILED`.
    - If deduplication is enabled, inserts the deduplication tag into the cache; if a duplicate is detected during insertion, returns `FD_TXN_VERIFY_DEDUP`.
    - Stores the deduplication tag in `opt_sig` and returns `FD_TXN_VERIFY_SUCCESS` if all checks pass.
- **Output**: Returns an integer status code: `FD_TXN_VERIFY_SUCCESS` (0) for successful verification, `FD_TXN_VERIFY_FAILED` (-1) for signature verification failure, or `FD_TXN_VERIFY_DEDUP` (-2) for detected duplicate transactions.


