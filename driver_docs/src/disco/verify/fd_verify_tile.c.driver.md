# Purpose
The provided C code defines a module for a transaction verification system, specifically focusing on verifying transaction signatures and filtering out non-matching transactions. This module is part of a larger system that processes different types of incoming data streams, such as QUIC, bundles, and gossip, and ensures that only valid transactions are passed through. The code is structured around a "verify tile," which acts as a wrapper around a "mux tile," adding the functionality of signature verification to the data processing pipeline. The module is designed to handle various input types, perform signature verification, and manage transaction deduplication, ensuring that only unique and valid transactions are processed further.

Key components of the code include functions for initializing the verification context, handling incoming data fragments, and managing metrics related to transaction verification failures. The code also includes mechanisms for secure memory allocation and initialization, as well as functions for setting up security policies and file descriptor management. The module is intended to be integrated into a larger system, as indicated by its inclusion of external headers and its use of a structured initialization process. The code defines a public API through the `fd_tile_verify` structure, which specifies the module's name, initialization functions, and runtime behavior, making it suitable for use in a modular and extensible transaction processing system.
# Imports and Dependencies

---
- `fd_verify_tile.h`
- `../metrics/fd_metrics.h`
- `generated/fd_verify_tile_seccomp.h`
- `linux/unistd.h`
- `../stem/fd_stem.c`


# Global Variables

---
### fd\_tile\_verify
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_verify` is a global variable of type `fd_topo_run_tile_t`, which is a structure that encapsulates the configuration and operational functions for a 'verify' tile in a topology. This structure includes function pointers for initialization, running, and managing security and file descriptor policies, as well as alignment and footprint specifications for scratch memory.
- **Use**: This variable is used to define and manage the behavior and resources of a 'verify' tile within a larger system topology, ensuring proper initialization, execution, and resource management.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns the alignment requirement for scratch memory used in the program.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use only within the file it is defined and suggests the compiler to embed the function code at each call site for performance reasons.
    - The function returns a constant value, `FD_TCACHE_ALIGN`, which is presumably defined elsewhere in the codebase and represents the alignment requirement for scratch memory.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for scratch memory.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a verification context and associated structures based on the given tile's configuration.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which contains configuration details for the tile, including the depth of the transaction cache.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the size and alignment of `fd_verify_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the size and alignment of the transaction cache, calculated using `fd_tcache_footprint` and `fd_tcache_align`, to `l`.
    - Iterate over a loop `FD_TXN_ACTUAL_SIG_MAX` times, appending the size and alignment of `fd_sha512_t` to `l` in each iteration.
    - Finalize the layout calculation with `FD_LAYOUT_FINI`, using [`scratch_align`](#scratch_align) to determine the final alignment, and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the verification context and associated structures.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates various transaction failure metrics in the given verification context.
- **Inputs**:
    - `ctx`: A pointer to an `fd_verify_ctx_t` structure, which contains the metrics to be updated.
- **Control Flow**:
    - The function uses the `FD_MCNT_SET` macro to update the `TRANSACTION_BUNDLE_PEER_FAILURE` metric with the value from `ctx->metrics.bundle_peer_fail_cnt`.
    - It updates the `TRANSACTION_PARSE_FAILURE` metric with the value from `ctx->metrics.parse_fail_cnt`.
    - It updates the `TRANSACTION_DEDUP_FAILURE` metric with the value from `ctx->metrics.dedup_fail_cnt`.
    - It updates the `TRANSACTION_VERIFY_FAILURE` metric with the value from `ctx->metrics.verify_fail_cnt`.
- **Output**: The function does not return any value; it updates the metrics in the context structure.


---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function determines whether a transaction fragment should be processed by the current verification tile based on its type and the round-robin index.
- **Inputs**:
    - `ctx`: A pointer to the `fd_verify_ctx_t` context structure containing information about the current verification process, including input kinds and round-robin settings.
    - `in_idx`: An unsigned long integer representing the index of the input stream being processed.
    - `seq`: An unsigned long integer representing the sequence number of the transaction fragment.
    - `sig`: An unsigned long integer indicating whether the transaction is a bundle packet (0 for bundle packets, non-zero otherwise).
- **Control Flow**:
    - Check if the transaction is a bundle packet by evaluating if the input kind at `in_idx` is `IN_KIND_BUNDLE` and `sig` is 0.
    - If the transaction is a bundle packet, QUIC, or GOSSIP, return whether the sequence number modulo the round-robin count is not equal to the round-robin index.
    - If the transaction is a bundle, return whether the round-robin index is not 0.
    - Return 0 if none of the above conditions are met.
- **Output**: Returns an integer indicating whether the transaction fragment should be processed by the current verification tile (non-zero) or not (zero).


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes incoming data fragments based on their type and performs memory operations to copy and verify the data.
- **Inputs**:
    - `ctx`: A pointer to the `fd_verify_ctx_t` context structure containing information about the input and output memory and other verification parameters.
    - `in_idx`: An index indicating which input stream is being processed.
    - `seq`: A sequence number for the fragment, marked as unused in this function.
    - `sig`: A signature for the fragment, marked as unused in this function.
    - `chunk`: The chunk identifier within the input memory to be processed.
    - `sz`: The size of the data to be processed.
    - `ctl`: A control parameter, marked as unused in this function.
- **Control Flow**:
    - Determine the kind of input data using `ctx->in_kind[in_idx]`.
    - If the input kind is `IN_KIND_QUIC`, `IN_KIND_GOSSIP`, or `IN_KIND_SEND`, check if the chunk is within valid range and size is within `FD_TPU_MTU`. If not, log an error.
    - For these input kinds, copy the data from the source chunk to the destination, setting the payload size and bundle ID in the destination structure.
    - If the input kind is `IN_KIND_BUNDLE`, check if the chunk is within valid range and size is within `FD_TPU_RAW_MTU`. If not, log an error.
    - Copy the data from the source chunk to the destination for `IN_KIND_BUNDLE`.
    - Verify that the transaction payload size does not exceed `FD_TPU_MTU` for `IN_KIND_BUNDLE`, logging an error if it does.
- **Output**: The function does not return a value; it performs operations on the memory pointed to by the context structure.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes a transaction fragment, verifies its integrity, and updates the context and metrics based on the verification results.
- **Inputs**:
    - `ctx`: A pointer to the `fd_verify_ctx_t` structure, which holds the context for verification, including metrics and state information.
    - `in_idx`: An unsigned long integer representing the index of the input source, though it is not used in this function.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, though it is not used in this function.
    - `sig`: An unsigned long integer representing the signature of the fragment, though it is not used in this function.
    - `sz`: An unsigned long integer representing the size of the fragment, though it is not used in this function.
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment.
    - `_tspub`: An unsigned long integer representing the publication timestamp, though it is not used in this function.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing the transaction.
- **Control Flow**:
    - The function begins by casting the output memory chunk to a transaction memory structure and parsing the transaction payload to determine its size.
    - It checks if the transaction is part of a bundle and updates the context's bundle state if the bundle ID has changed.
    - If the transaction is part of a bundle and the bundle has previously failed, it increments the bundle peer failure count and returns.
    - If the transaction size is zero, it marks the bundle as failed (if applicable), increments the parse failure count, and returns.
    - The function verifies the transaction, updating the bundle failure state and incrementing the appropriate failure metric if verification fails.
    - If verification is successful, it calculates the realized size of the transaction, computes a publication timestamp, and publishes the transaction using the stem context.
    - Finally, it updates the output chunk pointer to the next available chunk in the data cache.
- **Output**: The function does not return a value; it updates the context and metrics based on the transaction processing and verification results.
- **Functions called**:
    - [`fd_txn_verify`](fd_verify_tile.h.driver.md#fd_txn_verify)


---
### privileged\_init<!-- {{#callable:privileged_init}} -->
The `privileged_init` function initializes a privileged context for a verification tile by allocating scratch memory and setting up a secure random seed for the context's hashmap.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration within the topology.
- **Control Flow**:
    - Retrieve the local address of the tile object using `fd_topo_obj_laddr` with the provided `topo` and `tile->tile_obj_id`.
    - Initialize a scratch memory allocator using `FD_SCRATCH_ALLOC_INIT` with the retrieved scratch memory address.
    - Allocate memory for an `fd_verify_ctx_t` structure within the scratch space using `FD_SCRATCH_ALLOC_APPEND`.
    - Generate a secure random seed for the `hashmap_seed` field of the context using `fd_rng_secure`.
- **Output**: The function does not return any value; it initializes the context in the provided scratch memory.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes the unprivileged context for a verification tile, setting up necessary data structures and memory allocations for transaction verification.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the tile configuration.
- **Control Flow**:
    - Allocate scratch memory using `fd_topo_obj_laddr` to get the local address of the tile object ID.
    - Initialize the scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate and initialize a `fd_verify_ctx_t` context structure using `FD_SCRATCH_ALLOC_APPEND`.
    - Create and join a transaction cache (`tcache`) using `fd_tcache_new` and `fd_tcache_join`, checking for errors.
    - Set up round-robin counters using `fd_topo_tile_name_cnt` and `tile->kind_id`.
    - Initialize SHA-512 contexts for transaction signatures in a loop, checking for errors.
    - Initialize various context fields such as `bundle_failed`, `bundle_id`, and `metrics`.
    - Set up transaction cache parameters like depth, map count, sync, ring, and map addresses.
    - Iterate over input links to configure memory, chunk, and watermark settings, and determine input kinds based on link names.
    - Configure output memory, chunk, and watermark settings using the topology and tile configurations.
    - Finalize the scratch allocation and check for overflow errors.
- **Output**: The function does not return a value; it initializes the context and data structures for transaction verification.
- **Functions called**:
    - [`scratch_footprint`](#scratch_footprint)


---
### populate\_allowed\_seccomp<!-- {{#callable:populate_allowed_seccomp}} -->
The `populate_allowed_seccomp` function populates a seccomp filter policy for a verification tile and returns the instruction count of the policy.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure representing the tile configuration.
    - `out_cnt`: An unsigned long integer representing the count of output filters to be populated.
    - `out`: A pointer to a `struct sock_filter` array where the seccomp filter policy will be populated.
- **Control Flow**:
    - The function begins by explicitly ignoring the `topo` and `tile` parameters using `(void)` casts, indicating they are not used in the function body.
    - It calls the [`populate_sock_filter_policy_fd_verify_tile`](generated/fd_verify_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_verify_tile) function with `out_cnt`, `out`, and the file descriptor obtained from `fd_log_private_logfile_fd()` to populate the seccomp filter policy.
    - The function returns the value of `sock_filter_policy_fd_verify_tile_instr_cnt`, which presumably holds the instruction count of the populated seccomp filter policy.
- **Output**: The function returns an unsigned long integer representing the instruction count of the seccomp filter policy.
- **Functions called**:
    - [`populate_sock_filter_policy_fd_verify_tile`](generated/fd_verify_tile_seccomp.h.driver.md#populate_sock_filter_policy_fd_verify_tile)


---
### populate\_allowed\_fds<!-- {{#callable:populate_allowed_fds}} -->
The `populate_allowed_fds` function populates an array with file descriptors that are allowed for use, specifically including the standard error and optionally a log file descriptor.
- **Inputs**:
    - `topo`: A pointer to a constant `fd_topo_t` structure, which is not used in this function.
    - `tile`: A pointer to a constant `fd_topo_tile_t` structure, which is not used in this function.
    - `out_fds_cnt`: An unsigned long integer representing the maximum number of file descriptors that can be stored in the `out_fds` array.
    - `out_fds`: A pointer to an integer array where the allowed file descriptors will be stored.
- **Control Flow**:
    - The function begins by casting `topo` and `tile` to void to indicate they are unused.
    - It checks if `out_fds_cnt` is less than 2, and if so, logs an error and terminates the program.
    - Initializes `out_cnt` to 0 and assigns the file descriptor for standard error (2) to the first position in `out_fds`, incrementing `out_cnt`.
    - Checks if the log file descriptor is valid (not -1) using `fd_log_private_logfile_fd()`, and if valid, assigns it to the next position in `out_fds`, incrementing `out_cnt`.
    - Returns the count of file descriptors added to `out_fds`.
- **Output**: The function returns an unsigned long integer representing the number of file descriptors added to the `out_fds` array.


