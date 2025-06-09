# Purpose
This C source code file is part of a larger system that handles transaction processing within a banking or financial application. The file defines a context structure (`fd_bank_ctx_t`) and several functions that manage the lifecycle of transactions, from initialization to execution and commitment. The code is designed to be integrated into a larger application, as indicated by the inclusion of multiple headers from different modules, such as `fd_pack`, `fd_blake3`, and `fd_bmtree`, which suggest functionalities related to data packing, cryptographic hashing, and Merkle tree operations, respectively.

The primary purpose of this file is to manage the processing of transactions in a highly parallel and efficient manner. It defines functions for handling different stages of transaction processing, including loading, executing, and committing transactions, as well as managing transaction metrics. The code also includes mechanisms for handling transaction bundles and microblocks, which are smaller units of transactions that can be processed independently. The file provides a public API for external modules to interact with the transaction processing system, as evidenced by the `extern` declarations for functions like [`fd_ext_bank_execute_and_commit_bundle`](#fd_ext_bank_execute_and_commit_bundle). Additionally, the file includes logic for managing memory and workspace allocations, ensuring that the system can handle high volumes of transactions efficiently. Overall, this code is a critical component of a transaction processing system, providing the necessary infrastructure to handle complex financial operations.
# Imports and Dependencies

---
- `fd_bank_abi.h`
- `../../disco/tiles.h`
- `../../disco/pack/fd_pack.h`
- `../../disco/pack/fd_pack_cost.h`
- `../../ballet/blake3/fd_blake3.h`
- `../../ballet/bmtree/fd_bmtree.h`
- `../../disco/metrics/fd_metrics.h`
- `../../util/pod/fd_pod_format.h`
- `../../disco/pack/fd_pack_rebate_sum.h`
- `../../disco/metrics/generated/fd_metrics_bank.h`
- `../../disco/stem/fd_stem.c`


# Global Variables

---
### fd\_ext\_bank\_pre\_balance\_info
- **Type**: `function pointer`
- **Description**: `fd_ext_bank_pre_balance_info` is a function pointer declared as an external function. It takes three parameters: a constant pointer to a bank, a pointer to transactions, and an unsigned long representing the transaction count. The function returns a void pointer.
- **Use**: This function is used to obtain pre-balance information for a set of transactions before they are executed in the banking context.


---
### fd\_ext\_bank\_load\_and\_execute\_txns
- **Type**: `function pointer`
- **Description**: `fd_ext_bank_load_and_execute_txns` is a function pointer declared as an external function. It is designed to load and execute a set of transactions on a given bank context. The function takes several parameters including the bank context, transactions, transaction count, and various output parameters to capture processing results, transaction errors, consumed execution compute units, consumed account data compute units, timestamps, and tips.
- **Use**: This function is used to process a batch of transactions by loading them into the bank context and executing them, while also capturing various metrics and results of the execution process.


---
### fd\_tile\_bank
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_bank` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define a tile in a topology. This structure is initialized with specific function pointers and parameters that define the behavior and characteristics of the tile, such as its name, memory alignment requirements, memory footprint, initialization function, and run function.
- **Use**: This variable is used to configure and manage a tile in a distributed system, specifically for handling banking operations within the system's topology.


# Data Structures

---
### fd\_bank\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `kind_id`: An identifier for the type of bank context.
    - `blake3`: A pointer to a Blake3 hashing context.
    - `bmtree`: A pointer to a binary merkle tree structure.
    - `txn_abi_mem`: Memory allocated for transaction ABI data.
    - `txn_sidecar_mem`: Memory allocated for transaction sidecar data.
    - `_bank`: A pointer to the bank object associated with this context.
    - `_microblock_idx`: Index of the current microblock being processed.
    - `_txn_idx`: Index of the current transaction within the microblock.
    - `_is_bundle`: Flag indicating if the current context is processing a bundle.
    - `busy_fseq`: Pointer to a sequence number indicating busy status.
    - `pack_in_mem`: Pointer to workspace memory for input packing.
    - `pack_in_chunk0`: Initial chunk index for input packing.
    - `pack_in_wmark`: Watermark for input packing memory.
    - `out_mem`: Pointer to workspace memory for output.
    - `out_chunk0`: Initial chunk index for output memory.
    - `out_wmark`: Watermark for output memory.
    - `out_chunk`: Current chunk index for output memory.
    - `rebate_mem`: Pointer to workspace memory for rebates.
    - `rebate_chunk0`: Initial chunk index for rebate memory.
    - `rebate_wmark`: Watermark for rebate memory.
    - `rebate_chunk`: Current chunk index for rebate memory.
    - `rebates_for_slot`: Slot number for which rebates are being processed.
    - `rebater`: Array for managing rebate sums.
    - `metrics`: Structure containing various metrics related to transaction processing.
- **Description**: The `fd_bank_ctx_t` structure is a comprehensive context used in a banking system to manage and process transactions. It includes various fields for handling transaction data, memory management, and metrics collection. The structure maintains pointers to hashing and merkle tree contexts, memory allocations for transaction data, and indices for tracking the current microblock and transaction. It also includes fields for managing input and output memory chunks, rebate processing, and a set of metrics to track transaction processing outcomes. This structure is integral to the operation of a banking tile, facilitating the execution and management of transactions within a distributed system.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns a constant alignment value of 128 bytes.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - It returns a constant value of 128UL, which is an unsigned long integer representing the alignment size.
- **Output**: The function outputs a constant unsigned long integer value of 128, representing the alignment size.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for various components in a banking context, ensuring proper alignment and size allocation.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which is not used in the function.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the size and alignment of `fd_bank_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the size and alignment of BLAKE3 hash context using `FD_LAYOUT_APPEND`.
    - Append the size and alignment of BMTREE commit context with zero transactions using `FD_LAYOUT_APPEND`.
    - Append the size and alignment for the maximum number of transactions per microblock using `FD_LAYOUT_APPEND`.
    - Append the size and alignment for the maximum sidecar footprint using `FD_LAYOUT_APPEND`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI`, using the alignment from `scratch_align()`, and return the result.
- **Output**: Returns an `ulong` representing the total memory footprint required, including alignment considerations.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### metrics\_write<!-- {{#callable:metrics_write}} -->
The `metrics_write` function updates various transaction-related metrics in the `fd_bank_ctx_t` context structure by copying and setting specific metric values.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bank_ctx_t` structure, which contains the metrics to be updated.
- **Control Flow**:
    - The function begins by copying the `slot_acquire` metrics from the context to the BANK metrics using `FD_MCNT_ENUM_COPY`.
    - It then copies the `txn_load_address_lookup_tables` and `transaction_result` metrics from the context to the BANK metrics using `FD_MCNT_ENUM_COPY`.
    - The function sets the `processing_failed`, `fee_only`, `exec_failed`, and `success` metrics in the BANK using `FD_MCNT_SET`.
- **Output**: The function does not return any value; it updates the metrics in the BANK based on the context provided.


---
### before\_frag<!-- {{#callable:before_frag}} -->
The `before_frag` function checks if a given signature corresponds to a microblock and if it matches the current bank context's kind ID, returning 0 if both conditions are met and 1 otherwise.
- **Inputs**:
    - `ctx`: A pointer to an `fd_bank_ctx_t` structure representing the current bank context.
    - `in_idx`: An unsigned long integer representing the input index, which is not used in the function.
    - `seq`: An unsigned long integer representing the sequence number, which is not used in the function.
    - `sig`: An unsigned long integer representing the signature to be checked.
- **Control Flow**:
    - The function begins by ignoring the `in_idx` and `seq` parameters as they are not used.
    - It checks if the packet type of the signature `sig` is not a microblock using `fd_disco_poh_sig_pkt_type`. If true, it returns 1.
    - It retrieves the target bank index from the signature using `fd_disco_poh_sig_bank_tile`.
    - It checks if the target bank index does not match the `kind_id` of the context `ctx`. If true, it returns 1.
    - If both checks are passed, it returns 0.
- **Output**: The function returns an integer: 0 if the signature is a microblock and matches the bank context's kind ID, otherwise 1.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function processes a fragment of data by copying it from an input memory location to an output memory location, and updates context information based on a trailer structure at the end of the data.
- **Inputs**:
    - `ctx`: A pointer to a `fd_bank_ctx_t` structure that holds the context for the bank operation, including memory locations and various state variables.
    - `in_idx`: An unused parameter of type `ulong` representing the index of the input.
    - `seq`: An unused parameter of type `ulong` representing the sequence number.
    - `sig`: An unused parameter of type `ulong` representing the signature.
    - `chunk`: A `ulong` representing the chunk index in the input memory from which data is to be copied.
    - `sz`: A `ulong` representing the size of the data to be copied.
    - `ctl`: An unused parameter of type `ulong` representing control information.
- **Control Flow**:
    - Convert the input chunk index to a source memory address using `fd_chunk_to_laddr` with `ctx->pack_in_mem` and `chunk`.
    - Convert the output chunk index to a destination memory address using `fd_chunk_to_laddr` with `ctx->out_mem` and `ctx->out_chunk`.
    - Check if the chunk index is within valid range and if the size is not greater than `USHORT_MAX`; log an error if any condition fails.
    - Copy the data from the source to the destination, excluding the size of `fd_microblock_bank_trailer_t`.
    - Retrieve the trailer from the end of the source data and update the context's bank, microblock index, transaction index, and bundle status from the trailer.
- **Output**: The function does not return a value; it updates the context structure `ctx` with information extracted from the data trailer.


---
### hash\_transactions<!-- {{#callable:hash_transactions}} -->
The `hash_transactions` function computes a Merkle root hash of successfully executed transactions and stores it in the provided mixin buffer.
- **Inputs**:
    - `mem`: A pointer to memory used for initializing the Merkle tree commit structure.
    - `txns`: An array of transaction pointers (`fd_txn_p_t`) to be processed.
    - `txn_cnt`: The number of transactions in the `txns` array.
    - `mixin`: A buffer where the resulting Merkle root hash will be stored.
- **Control Flow**:
    - Initialize a Merkle tree commit structure using the provided memory.
    - Iterate over each transaction in the `txns` array.
    - For each transaction, check if it has the `FD_TXN_P_FLAGS_EXECUTE_SUCCESS` flag set; if not, skip it.
    - For each signature in a successful transaction, compute a hash of the signature data and append it to the Merkle tree.
    - Finalize the Merkle tree to obtain the root hash.
    - Copy the root hash into the `mixin` buffer.
- **Output**: The function does not return a value, but it outputs the Merkle root hash of the transactions into the `mixin` buffer.


---
### handle\_microblock<!-- {{#callable:handle_microblock}} -->
The `handle_microblock` function processes a microblock of transactions, sanitizes and executes them, updates metrics, and prepares the results for inclusion in the blockchain.
- **Inputs**:
    - `ctx`: A pointer to the `fd_bank_ctx_t` structure containing the context for the bank operations.
    - `seq`: An unsigned long integer representing the sequence number of the microblock.
    - `sig`: An unsigned long integer representing the signature of the microblock.
    - `sz`: An unsigned long integer representing the size of the microblock.
    - `begin_tspub`: An unsigned long integer representing the timestamp when the microblock processing began.
    - `stem`: A pointer to the `fd_stem_context_t` structure used for publishing the results.
- **Control Flow**:
    - Convert the output memory chunk to a local address using `fd_chunk_to_laddr`.
    - Calculate the number of transactions in the microblock by subtracting the size of the trailer and dividing by the size of a transaction pointer.
    - Initialize arrays and counters for processing transactions, including writable addresses, sanitized transaction count, and sidecar footprint bytes.
    - Iterate over each transaction, initialize ABI transactions, verify precompiles, and update metrics.
    - Load and execute sanitized transactions, capturing processing results, errors, and consumed compute units.
    - Iterate over transactions again to update flags, calculate consumed and rebated compute units, and update metrics based on execution results.
    - Commit the transactions using `fd_ext_bank_commit_txns`, ensuring all executed transactions are committed.
    - Update the sequence number to indicate processing completion and prepare rebates using `fd_pack_rebate_sum_add_txn`.
    - Hash the transactions to produce a Merkle hash for inclusion in the PoH hash.
    - Calculate and set transaction timing percentages in the microblock trailer.
    - Publish the processed microblock using `fd_stem_publish` and update the output chunk for the next operation.
- **Output**: The function does not return a value; it processes transactions, updates metrics, and prepares the results for blockchain inclusion.
- **Functions called**:
    - [`fd_bank_abi_txn_init`](fd_bank_abi.c.driver.md#fd_bank_abi_txn_init)
    - [`fd_bank_abi_get_lookup_addresses`](fd_bank_abi.c.driver.md#fd_bank_abi_get_lookup_addresses)
    - [`hash_transactions`](#hash_transactions)
    - [`metrics_write`](#metrics_write)


---
### handle\_bundle<!-- {{#callable:handle_bundle}} -->
The `handle_bundle` function processes a bundle of transactions, executing and committing them while updating metrics and handling any failures.
- **Inputs**:
    - `ctx`: A pointer to the `fd_bank_ctx_t` structure containing the context for the bank operations.
    - `seq`: An unsigned long integer representing the sequence number of the transaction bundle.
    - `sig`: An unsigned long integer representing the signature of the transaction bundle.
    - `sz`: An unsigned long integer representing the size of the transaction bundle.
    - `begin_tspub`: An unsigned long integer representing the timestamp when the processing of the bundle began.
    - `stem`: A pointer to the `fd_stem_context_t` structure used for publishing transactions.
- **Control Flow**:
    - Convert the output memory chunk to a local address and cast it to a transaction pointer array.
    - Calculate the slot and transaction count from the signature and size, respectively.
    - Initialize an array for writable alternate addresses and set execution success to true.
    - Iterate over each transaction in the bundle to initialize and verify them, updating metrics and setting flags accordingly.
    - If initialization or verification fails, mark execution as unsuccessful and continue to the next transaction.
    - If all transactions are successfully initialized and verified, execute and commit the bundle using `fd_ext_bank_execute_and_commit_bundle`.
    - Update metrics based on the execution success or failure of the bundle.
    - Update the busy sequence to indicate processing completion.
    - Iterate over each transaction to calculate consumed compute units and update transaction flags and metrics based on execution success.
    - Add transactions to the rebate sum for further processing.
    - Copy transactions to a temporary array and publish each transaction separately into its own microblock, updating the chunk and metrics accordingly.
- **Output**: The function does not return a value but updates the context, metrics, and publishes transactions.
- **Functions called**:
    - [`fd_bank_abi_txn_init`](fd_bank_abi.c.driver.md#fd_bank_abi_txn_init)
    - [`fd_bank_abi_get_lookup_addresses`](fd_bank_abi.c.driver.md#fd_bank_abi_get_lookup_addresses)
    - [`hash_transactions`](#hash_transactions)
    - [`metrics_write`](#metrics_write)


---
### after\_frag<!-- {{#callable:after_frag}} -->
The `after_frag` function processes a fragment by handling either a bundle or a microblock, updating rebate information, and publishing results.
- **Inputs**:
    - `ctx`: A pointer to the `fd_bank_ctx_t` structure, which holds the context and state for the bank processing.
    - `in_idx`: An unsigned long integer representing the input index, which is unused in this function.
    - `seq`: An unsigned long integer representing the sequence number of the fragment.
    - `sig`: An unsigned long integer representing the signature of the fragment.
    - `sz`: An unsigned long integer representing the size of the fragment.
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment.
    - `tspub`: An unsigned long integer representing the publication timestamp of the fragment.
    - `stem`: A pointer to the `fd_stem_context_t` structure, which is used for publishing results.
- **Control Flow**:
    - The function begins by calculating the slot from the signature using `fd_disco_poh_sig_slot` and checks if it matches `ctx->rebates_for_slot`.
    - If the slot has changed, it clears the rebate sum using `fd_pack_rebate_sum_clear` and updates `ctx->rebates_for_slot`.
    - It checks if the context indicates a bundle (`ctx->_is_bundle`) and calls [`handle_bundle`](#handle_bundle) if true, otherwise it calls [`handle_microblock`](#handle_microblock).
    - A loop is used to report and publish rebate sums using `fd_pack_rebate_sum_report` and `fd_stem_publish` until no more rebates are reported.
    - The rebate chunk is updated using `fd_dcache_compact_next` after each publication.
- **Output**: The function does not return a value; it performs operations on the context and publishes results.
- **Functions called**:
    - [`handle_bundle`](#handle_bundle)
    - [`handle_microblock`](#handle_microblock)


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes an unprivileged banking context for a specific tile in a topology, setting up memory allocations and linking necessary components.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to initialize.
- **Control Flow**:
    - Allocate scratch memory for the tile using `fd_topo_obj_laddr` to get the local address of the tile object ID.
    - Initialize a scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for the banking context (`fd_bank_ctx_t`), Blake3 hash context, and BMTREE context using `FD_SCRATCH_ALLOC_APPEND`.
    - Allocate memory for transaction ABI and sidecar using `FD_SCRATCH_ALLOC_APPEND`.
    - Set the `kind_id` of the context to the tile's `kind_id`.
    - Initialize the Blake3 context and BMTREE context, ensuring they are not NULL using the `NONNULL` macro.
    - Join the rebate sum context and set `rebates_for_slot` to 0.
    - Query the busy object ID from the topology properties and join the busy sequence, logging an error if it fails.
    - Initialize the metrics structure to zero using `memset`.
    - Set up memory and chunk pointers for input, output, and rebate data caches using `fd_dcache_compact_chunk0` and `fd_dcache_compact_wmark`.
- **Output**: The function does not return a value; it initializes the banking context for the specified tile.


