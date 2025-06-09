# Purpose
The provided C source code file is part of a larger system, likely related to transaction processing in a blockchain or distributed ledger environment. The code is designed to manage and resolve transactions by maintaining a history of blockhashes and handling transaction fragments. It includes functionality for identifying and processing transactions based on their blockhashes, ensuring that only valid and recent transactions are processed. The code also handles special cases such as durable nonce transactions and transaction bundles, which require additional logic to determine their validity and process them accordingly.

Key components of the code include data structures for managing blockhashes and transactions, such as `blockhash_t`, `blockhash_map_t`, and `fd_stashed_txn_m_t`. The code uses various macros and templates to define and manipulate these structures efficiently. It also includes functions for initializing and running the transaction resolution process, such as [`unprivileged_init`](#unprivileged_init) and `stem_run`. The code is structured to be part of a modular system, with several external dependencies and includes, indicating that it is intended to be integrated into a larger application. The file defines internal logic and data structures rather than public APIs, suggesting it is a core component of the transaction processing system.
# Imports and Dependencies

---
- `../bank/fd_bank_abi.h`
- `../../disco/tiles.h`
- `../../disco/metrics/fd_metrics.h`
- `../../flamenco/runtime/fd_system_ids.h`
- `../../flamenco/runtime/fd_system_ids_pp.h`
- `../../util/simd/fd_avx.h`
- `../../util/tmpl/fd_map.c`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_dlist.c`
- `../../util/tmpl/fd_map_chain.c`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### null\_blockhash
- **Type**: `blockhash_t`
- **Description**: The `null_blockhash` is a constant global variable of type `blockhash_t`, initialized with all zero values. It represents a blockhash with no valid data, essentially serving as a placeholder or sentinel value.
- **Use**: This variable is used as a null or invalid key in blockhash-related operations, such as in hash maps, to signify the absence of a valid blockhash.


---
### \_fd\_ext\_resolv\_tile\_cnt
- **Type**: `ulong`
- **Description**: The variable `_fd_ext_resolv_tile_cnt` is a static global variable of type `ulong` that is used to store the count of resolution tiles in the system. It is initialized and set within the `unprivileged_init` function when the `kind_id` of a tile is zero, indicating the first tile in a round-robin setup.
- **Use**: This variable is used to track the number of resolution tiles, which is crucial for managing and coordinating tasks across multiple tiles in a distributed system.


---
### fd\_tile\_resolv
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_resolv` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define a tile in a topology run. This structure is initialized with specific function pointers and parameters that configure the behavior of the 'resolv' tile, such as its name, alignment, footprint, initialization, and execution functions.
- **Use**: This variable is used to configure and manage the execution of a 'resolv' tile within a larger system topology, providing necessary functions and parameters for its operation.


# Data Structures

---
### blockhash
- **Type**: `struct`
- **Members**:
    - `b`: An array of 32 unsigned characters (uchar) representing the block hash.
- **Description**: The `blockhash` structure is a simple data structure that encapsulates a block hash as an array of 32 unsigned characters. This structure is used to store and manipulate block hashes, which are typically used in blockchain or distributed ledger systems to uniquely identify blocks. The fixed size of 32 bytes suggests that it is designed to hold a cryptographic hash, such as a SHA-256 hash, which is commonly used in such systems.


---
### blockhash\_t
- **Type**: `typedef struct blockhash blockhash_t;`
- **Members**:
    - `b`: An array of 32 unsigned characters representing the block hash.
- **Description**: The `blockhash_t` data structure is a simple struct that encapsulates a block hash as an array of 32 unsigned characters. This structure is used to represent a block hash in a compact form, which is essential for identifying blocks in a blockchain system. The `blockhash_t` is utilized in various contexts within the code, such as in the `blockhash_map` structure, which associates block hashes with slots, and in the `blockhash_ring`, which maintains a history of recent block hashes for transaction validation purposes.


---
### blockhash\_map
- **Type**: `struct`
- **Members**:
    - `key`: A blockhash_t type representing the key in the map.
    - `slot`: An unsigned long integer representing the slot associated with the key.
- **Description**: The `blockhash_map` structure is a simple mapping data structure that associates a blockhash, represented by the `key` field, with a specific slot, represented by the `slot` field. This structure is used to track the slot in which a particular blockhash is relevant, allowing for efficient lookup and management of blockhashes in a system that processes transactions. The `blockhash_map` is part of a larger system that manages transaction processing and ensures that transactions are only processed if they are still valid within the context of the current blockhash history.


---
### blockhash\_map\_t
- **Type**: `struct`
- **Members**:
    - `key`: A `blockhash_t` structure representing the key in the map.
    - `slot`: An `ulong` representing the slot associated with the blockhash.
- **Description**: The `blockhash_map_t` is a structure used to map blockhashes to their corresponding slots. It consists of a `blockhash_t` key, which is a 32-byte array representing the blockhash, and a `slot`, which is an unsigned long integer indicating the slot number associated with the blockhash. This structure is part of a larger system that manages blockhashes and their expiration, ensuring that transactions are only processed if they are still valid within the blockchain's history.


---
### fd\_stashed\_txn\_m\_t
- **Type**: `struct`
- **Members**:
    - `pool_next`: Used to store the next index in the pool when the transaction is released.
    - `lru_next`: Used to store the next index in the LRU list when the transaction is acquired.
    - `lru_prev`: Stores the previous index in the LRU list.
    - `map_next`: Stores the next index in the map chain.
    - `map_prev`: Stores the previous index in the map chain.
    - `blockhash`: Pointer to a blockhash_t structure representing the blockhash associated with the transaction.
    - `_`: An array of unsigned characters aligned to the size of fd_txn_m_t, used to store transaction data.
- **Description**: The `fd_stashed_txn_m_t` structure is designed to manage transactions within a pool, LRU list, and map chain, using a union to efficiently store indices for pool and LRU operations. It includes pointers to manage its position in a map chain and LRU list, and a blockhash pointer to associate a transaction with a specific blockhash. The structure also contains a buffer for transaction data, aligned to the size of `fd_txn_m_t`, allowing for efficient storage and retrieval of transaction information.


---
### fd\_resolv\_in\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `kind`: An integer representing the type of input context, either a fragment or a bank.
    - `mem`: A pointer to a workspace memory structure, fd_wksp_t, associated with the input context.
    - `chunk0`: An unsigned long representing the starting chunk index in the workspace memory.
    - `wmark`: An unsigned long representing the watermark or the maximum chunk index in the workspace memory.
    - `mtu`: An unsigned long representing the maximum transmission unit size for the input context.
- **Description**: The `fd_resolv_in_ctx_t` structure is used to define the context for input data in a resolution process, specifying the type of input (fragment or bank), the associated memory workspace, and parameters for managing data chunks such as the starting chunk index, watermark, and maximum transmission unit size. This structure is part of a larger system for handling and processing data transactions, ensuring that data is correctly managed and processed according to its type and memory constraints.


---
### fd\_resolv\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `round_robin_idx`: Index for round-robin scheduling.
    - `round_robin_cnt`: Count for round-robin scheduling.
    - `bundle_failed`: Flag indicating if a bundle has failed.
    - `bundle_id`: Identifier for the current bundle.
    - `root_bank`: Pointer to the root bank structure.
    - `root_slot`: Slot number of the root bank.
    - `blockhash_map`: Pointer to a map of blockhashes.
    - `flushing_slot`: Slot number currently being flushed.
    - `flush_pool_idx`: Index of the pool being flushed.
    - `pool`: Pointer to a pool of stashed transactions.
    - `map_chain`: Pointer to a map chain structure.
    - `lru_list`: List for least recently used transactions.
    - `completed_slot`: Slot number of the last completed transaction.
    - `blockhash_ring_idx`: Index for the blockhash ring buffer.
    - `blockhash_ring`: Ring buffer storing recent blockhashes.
    - `_bank_msg`: Buffer for bank messages.
    - `metrics`: Structure holding various metrics counters.
    - `in`: Array of input contexts.
    - `out_mem`: Pointer to the output memory workspace.
    - `out_chunk0`: Initial chunk index for output.
    - `out_wmark`: Watermark for output chunks.
    - `out_chunk`: Current chunk index for output.
- **Description**: The `fd_resolv_ctx_t` structure is a complex data structure used in a transaction processing system to manage and resolve transactions. It includes fields for managing round-robin scheduling, tracking transaction bundles, and interfacing with bank structures. The structure also maintains a map of blockhashes and a ring buffer for recent blockhashes to handle transaction expiration. Additionally, it contains a pool for stashed transactions, a map chain, and an LRU list to manage transaction lifecycle. Metrics are tracked within a nested structure, and input/output contexts are managed through arrays and pointers to memory workspaces.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns the alignment requirement of the `fd_resolv_ctx_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the result of the `alignof` operator applied to `fd_resolv_ctx_t`.
- **Output**: The function outputs an `ulong` representing the alignment requirement of the `fd_resolv_ctx_t` structure.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for various components in a system, based on alignment and size requirements.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT`.
    - Append the layout of `fd_resolv_ctx_t` to `l` using `FD_LAYOUT_APPEND`, considering its alignment and size.
    - Append the layout of a pool with a footprint of `1UL<<16UL` to `l`, using `pool_align()` and `pool_footprint()`.
    - Append the layout of a map chain with a footprint of `8192UL` to `l`, using `map_chain_align()` and `map_chain_footprint()`.
    - Append the layout of a map to `l`, using `map_align()` and `map_footprint()`.
    - Finalize the layout with `FD_LAYOUT_FINI`, using `scratch_align()`, and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the specified components.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### fd\_ext\_resolv\_tile\_cnt<!-- {{#callable:fd_ext_resolv_tile_cnt}} -->
The `fd_ext_resolv_tile_cnt` function waits for the static variable `_fd_ext_resolv_tile_cnt` to be non-zero and then returns its value.
- **Inputs**: None
- **Control Flow**:
    - The function enters a while loop that continuously checks if the static variable `_fd_ext_resolv_tile_cnt` is zero.
    - The loop exits only when `_fd_ext_resolv_tile_cnt` becomes non-zero.
    - After exiting the loop, the function returns the value of `_fd_ext_resolv_tile_cnt`.
- **Output**: The function returns an unsigned long integer representing the value of `_fd_ext_resolv_tile_cnt` once it is non-zero.


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates various metrics counters in the `fd_resolv_ctx_t` context structure.
- **Inputs**:
    - `ctx`: A pointer to an `fd_resolv_ctx_t` structure containing metrics data to be updated.
- **Control Flow**:
    - The function uses the macro `FD_MCNT_SET` to set the `BLOCKHASH_EXPIRED` metric with the value from `ctx->metrics.blockhash_expired`.
    - It uses the macro `FD_MCNT_ENUM_COPY` to copy the `LUT_RESOLVED` metrics from `ctx->metrics.lut`.
    - It uses the macro `FD_MCNT_ENUM_COPY` to copy the `STASH_OPERATION` metrics from `ctx->metrics.stash`.
    - Finally, it sets the `TRANSACTION_BUNDLE_PEER_FAILURE` metric using `FD_MCNT_SET` with the value from `ctx->metrics.bundle_peer_failure_cnt`.
- **Output**: The function does not return any value; it updates metrics in the provided context structure.


---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function determines whether a fragment should be processed based on the input context and sequence number.
- **Inputs**:
    - `ctx`: A pointer to an `fd_resolv_ctx_t` structure, which contains context information for resolution.
    - `in_idx`: An unsigned long integer representing the index of the input context to be checked.
    - `seq`: An unsigned long integer representing the sequence number of the fragment.
    - `sig`: An unsigned long integer representing a signature, which is unused in this function.
- **Control Flow**:
    - The function first checks if the input context at `in_idx` is of kind `FD_RESOLV_IN_KIND_BANK` using the `FD_UNLIKELY` macro for branch prediction optimization.
    - If the input context is of kind `FD_RESOLV_IN_KIND_BANK`, the function returns 0, indicating the fragment should not be processed.
    - If the input context is not of kind `FD_RESOLV_IN_KIND_BANK`, the function calculates `(seq % ctx->round_robin_cnt) != ctx->round_robin_idx` to determine if the fragment should be processed based on round-robin scheduling.
    - The result of the calculation is returned as the function's output.
- **Output**: The function returns an integer, 0 if the fragment should not be processed, or 1 if it should be processed based on the round-robin scheduling logic.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes a fragment of data based on its type, either copying it to a bank message buffer or transferring it to an output memory location.
- **Inputs**:
    - `ctx`: A pointer to a `fd_resolv_ctx_t` structure, which contains context information for the resolution process.
    - `in_idx`: An index indicating which input context to use from the `ctx->in` array.
    - `seq`: An unused parameter, likely intended for sequence number tracking.
    - `sig`: An unused parameter, likely intended for signature tracking.
    - `chunk`: The chunk identifier within the input context, representing a specific data fragment.
    - `sz`: The size of the data fragment to be processed.
    - `ctl`: An unused parameter, likely intended for control information.
- **Control Flow**:
    - Check if the `chunk` is within the valid range defined by `ctx->in[in_idx].chunk0` and `ctx->in[in_idx].wmark`, and if `sz` is less than or equal to `ctx->in[in_idx].mtu`; log an error if not.
    - Switch on `ctx->in[in_idx].kind` to determine the type of input context.
    - If the kind is `FD_RESOLV_IN_KIND_BANK`, copy the data from the input memory location to the `_bank_msg` buffer in the context.
    - If the kind is `FD_RESOLV_IN_KIND_FRAGMENT`, copy the data from the input memory location to the output memory location specified by `ctx->out_mem` and `ctx->out_chunk`.
    - Log an error if the input kind is unknown.
- **Output**: The function does not return a value; it performs operations based on the input context and modifies the context's state or logs errors.


---
### publish\_txn<!-- {{#callable:publish_txn}} -->
The `publish_txn` function processes and publishes a transaction from a stashed transaction context to a stem context, handling address lookup table resolution if necessary.
- **Inputs**:
    - `ctx`: A pointer to a `fd_resolv_ctx_t` structure, which contains context information for transaction resolution and publication.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which represents the context for the stem where the transaction will be published.
    - `stashed`: A pointer to a `fd_stashed_txn_m_t` structure, which contains the stashed transaction data to be published.
- **Control Flow**:
    - Convert the stashed transaction data to a local address and copy it to a transaction memory structure (`txnm`).
    - Retrieve the transaction (`txnt`) from the transaction memory structure.
    - Set the `reference_slot` of the transaction memory to the `flushing_slot` from the context.
    - Check if the transaction has additional address lookup tables (`addr_table_adtl_cnt`).
    - If additional address lookup tables are present and the `root_bank` is not set, increment a metric counter and return 0.
    - If the `root_bank` is set, resolve the address lookup tables using `fd_bank_abi_resolve_address_lookup_tables` and update metrics based on the result.
    - If the resolution is unsuccessful, return 0.
    - Calculate the realized size of the transaction and the publication timestamp.
    - Publish the transaction using `fd_stem_publish` with the calculated parameters.
    - Update the `out_chunk` in the context to the next compacted chunk.
    - Return 1 to indicate successful publication.
- **Output**: Returns an integer, 1 if the transaction was successfully published, or 0 if there was an error during address lookup table resolution or other conditions.


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function processes a transaction from a pool, updates metrics, and prepares the context for the next transaction.
- **Inputs**:
    - `ctx`: A pointer to a `fd_resolv_ctx_t` structure, which holds the context for transaction resolution.
    - `stem`: A pointer to a `fd_stem_context_t` structure, which is used for publishing transactions.
    - `opt_poll_in`: A pointer to an integer that will be set to 0, indicating no polling is needed.
    - `charge_busy`: A pointer to an integer that will be set to 1, indicating the system is busy processing.
- **Control Flow**:
    - Check if `ctx->flush_pool_idx` is `ULONG_MAX`; if so, return immediately as there is nothing to process.
    - Set `*charge_busy` to 1 and `*opt_poll_in` to 0 to indicate the system is busy and no polling is needed.
    - Retrieve the next index in the chain using `map_chain_idx_next_const` and store it in `next`.
    - Remove the current index from the map chain using `map_chain_idx_remove_fast`.
    - Attempt to publish the transaction using [`publish_txn`](#publish_txn); if successful, increment the published metric, otherwise increment the removed metric.
    - Remove the current index from the LRU list using `lru_list_idx_remove`.
    - Release the current index back to the pool using `pool_idx_release`.
    - Update `ctx->flush_pool_idx` to the next index.
- **Output**: The function does not return a value; it modifies the state of the context and updates metrics.
- **Functions called**:
    - [`publish_txn`](#publish_txn)


---
### fd\_resolv\_is\_durable\_nonce<!-- {{#callable:fd_resolv_is_durable_nonce}} -->
The `fd_resolv_is_durable_nonce` function checks if a given transaction is a durable nonce transaction by verifying specific conditions in the transaction's first instruction.
- **Inputs**:
    - `txn`: A pointer to a `fd_txn_t` structure representing the transaction to be checked.
    - `payload`: A pointer to a constant unsigned character array representing the payload associated with the transaction.
- **Control Flow**:
    - Check if the transaction's instruction count is zero; if so, return 0 (not a durable nonce).
    - Retrieve the first instruction from the transaction and the associated program ID from the account addresses.
    - Compare the program ID with the SystemProgram ID; if they do not match, return 0.
    - Check if the first instruction has exactly three accounts and a data size of four bytes; if not, return 0.
    - Load a 4-byte unsigned integer from the payload at the data offset of the first instruction and check if it equals 4; return 1 if true, otherwise return 0.
- **Output**: Returns 1 if the transaction is a durable nonce transaction, otherwise returns 0.


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes transaction fragments based on their type and updates the context accordingly, handling bank messages and transaction forwarding.
- **Inputs**:
    - `ctx`: A pointer to the `fd_resolv_ctx_t` structure, which holds the context for transaction resolution.
    - `in_idx`: An unsigned long integer representing the index of the input source in the context's input array.
    - `seq`: An unsigned long integer representing the sequence number of the fragment, though it is not used in the function.
    - `sig`: An unsigned long integer representing the signature or type of the fragment, used to determine the processing path.
    - `sz`: An unsigned long integer representing the size of the fragment, though it is not used in the function.
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment.
    - `_tspub`: An unsigned long integer representing the publication timestamp, though it is not used in the function.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing transactions.
- **Control Flow**:
    - Check if the input kind is `FD_RESOLV_IN_KIND_BANK`; if true, process based on the `sig` value.
    - For `sig` 0, update the root bank and slot in the context with the bank message data.
    - For `sig` 1, update the blockhash map and ring, and set the completed slot in the context.
    - If `sig` is unknown, log an error and return.
    - If the input kind is not a bank, process the transaction message from the output memory.
    - Check if the transaction is part of a bundle and update the bundle status in the context.
    - Query the blockhash map for the recent blockhash and update the transaction's reference slot.
    - If the blockhash is not found and the transaction is not a bundle member or durable nonce, stash the transaction in the pool.
    - If the transaction has address lookup tables, resolve them using the root bank and update metrics.
    - Publish the transaction using the stem context and update the output chunk.
- **Output**: The function does not return a value; it modifies the context and potentially publishes transactions.
- **Functions called**:
    - [`fd_ext_bank_release`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_bank_release)
    - [`fd_resolv_is_durable_nonce`](#fd_resolv_is_durable_nonce)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes a resolution context for a given topology and tile, setting up memory allocations and data structures necessary for transaction processing.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile configuration within the topology.
- **Control Flow**:
    - Allocate scratch memory for the resolution context using `fd_topo_obj_laddr` and `FD_SCRATCH_ALLOC_INIT`.
    - Initialize a `fd_resolv_ctx_t` structure within the allocated scratch memory using `FD_SCRATCH_ALLOC_APPEND`.
    - Set up round-robin counters and initialize various context fields to default values.
    - Create and join a pool for transaction management using `pool_new` and `pool_join`.
    - Create and join a map chain for transaction mapping using `map_chain_new` and `map_chain_join`.
    - Initialize an LRU list for transaction management and verify its creation.
    - If the tile's kind ID is zero, set the external resolution tile count to the round-robin count.
    - Initialize the blockhash ring and metrics structures to zero using `memset`.
    - Create and join a blockhash map using `map_new` and `map_join`.
    - Iterate over input links of the tile, setting up input contexts for each link, including memory, chunk, watermark, and MTU values.
    - Set up the output memory, chunk, and watermark based on the tile's output link.
    - Finalize the scratch memory allocation and check for overflow, logging an error if it occurs.
- **Output**: The function does not return a value; it initializes the resolution context in the provided memory space.
- **Functions called**:
    - [`scratch_footprint`](#scratch_footprint)


# Function Declarations (Public API)

---
### fd\_ext\_bank\_release<!-- {{#callable_declaration:fd_ext_bank_release}} -->
Logs an error message indicating the function is not implemented.
- **Description**: This function is intended to release a bank resource, but it currently only logs an error message indicating that the operation is not implemented. It should be called when a bank resource needs to be released, but users should be aware that it does not perform any actual release operation. This function is a placeholder and may be updated in the future to include the intended functionality.
- **Inputs**:
    - `bank`: A pointer to the bank resource intended to be released. The parameter is marked as unused, indicating it is not currently utilized by the function. The caller retains ownership, and the function does not perform any operations on this parameter.
- **Output**: None
- **See also**: [`fd_ext_bank_release`](../../discof/bank/fd_bank_abi.c.driver.md#fd_ext_bank_release)  (Implementation)


