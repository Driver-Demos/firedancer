# Purpose
This C source code file is part of a system that manages and updates recent blockhashes for a blockchain-like environment, likely inspired by or related to Solana's architecture. The file includes functions to initialize, update, and read the recent blockhashes system variable (sysvar), which is a critical component for maintaining the integrity and efficiency of transaction processing. The code interacts with a blockhash queue, encoding recent blockhashes into a format suitable for storage in a sysvar account. This process involves serializing blockhash data and updating the sysvar with the latest information, ensuring that the system can efficiently verify and process transactions based on recent blockhashes.

The file is structured around several key functions, including [`fd_sysvar_recent_hashes_init`](#fd_sysvar_recent_hashes_init), [`fd_sysvar_recent_hashes_update`](#fd_sysvar_recent_hashes_update), and [`fd_sysvar_recent_hashes_read`](#fd_sysvar_recent_hashes_read), which handle the initialization, updating, and reading of the recent blockhashes sysvar, respectively. The [`encode_rbh_from_blockhash_queue`](#encode_rbh_from_blockhash_queue) function is responsible for encoding the blockhash queue into a buffer, while [`register_blockhash`](#register_blockhash) updates the queue with new blockhashes. The code is designed to be consistent with an existing implementation, as indicated by references to external repositories, ensuring compatibility and correctness. This file is not a standalone executable but rather a component intended to be integrated into a larger system, providing specialized functionality for managing recent blockhashes within a blockchain environment.
# Imports and Dependencies

---
- `stdio.h`
- `../fd_acc_mgr.h`
- `../fd_hashes.h`
- `fd_sysvar.h`
- `../fd_runtime.h`
- `../fd_system_ids.h`
- `../context/fd_exec_slot_ctx.h`


# Functions

---
### encode\_rbh\_from\_blockhash\_queue<!-- {{#callable:encode_rbh_from_blockhash_queue}} -->
The function `encode_rbh_from_blockhash_queue` serializes recent blockhashes from a blockhash queue into a buffer for the recent blockhashes sysvar account.
- **Inputs**:
    - `slot_ctx`: A pointer to `fd_exec_slot_ctx_t` which contains the execution context, including the blockhash queue to be encoded.
    - `enc`: A pointer to an unsigned character buffer where the encoded blockhashes will be stored.
- **Control Flow**:
    - Retrieve the blockhash queue from the `slot_ctx` structure.
    - Calculate the size of the queue and determine the number of blockhashes to encode, limited by `FD_RECENT_BLOCKHASHES_MAX_ENTRIES`.
    - Copy the number of blockhashes to encode into the `enc` buffer and adjust the buffer pointer.
    - Iterate over the blockhash queue, calculating the index for each blockhash in the encoding buffer.
    - For each blockhash, if its index is within the range to be encoded, copy the blockhash and its associated lamports per signature into the `enc` buffer at the calculated index.
- **Output**: The function does not return a value; it modifies the `enc` buffer to contain the serialized blockhashes.


---
### fd\_sysvar\_recent\_hashes\_init<!-- {{#callable:fd_sysvar_recent_hashes_init}} -->
The `fd_sysvar_recent_hashes_init` function initializes the recent blockhashes sysvar for a given execution slot context if the slot is zero.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution slot context.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for runtime memory allocation.
- **Control Flow**:
    - Begin a frame for the runtime scratchpad memory using `FD_SPAD_FRAME_BEGIN`.
    - Check if the `slot` in `slot_ctx->slot_bank` is not zero; if so, return immediately.
    - Calculate the size `sz` for the recent blockhashes account using a predefined maximum size constant.
    - Allocate memory `enc` of size `sz` aligned to `FD_SPAD_ALIGN` using `fd_spad_alloc`.
    - Initialize the allocated memory `enc` to zero using `fd_memset`.
    - Call [`encode_rbh_from_blockhash_queue`](#encode_rbh_from_blockhash_queue) to encode recent blockhashes from the blockhash queue into `enc`.
    - Set the sysvar using [`fd_sysvar_set`](fd_sysvar.c.driver.md#fd_sysvar_set) with the encoded data, owner ID, recent blockhashes ID, and the slot from `slot_ctx`.
    - End the frame for the runtime scratchpad memory using `FD_SPAD_FRAME_END`.
- **Output**: The function does not return a value; it performs initialization and updates the sysvar state.
- **Functions called**:
    - [`encode_rbh_from_blockhash_queue`](#encode_rbh_from_blockhash_queue)
    - [`fd_sysvar_set`](fd_sysvar.c.driver.md#fd_sysvar_set)


---
### FD\_SPAD\_FRAME\_BEGIN<!-- {{#callable:fd_sysvar_recent_hashes_update::FD_SPAD_FRAME_BEGIN}} -->
The `FD_SPAD_FRAME_BEGIN` function updates the blockhash queue, encodes recent blockhashes, and sets the sysvar with the new data.
- **Inputs**:
    - `runtime_spad`: A pointer to the runtime scratchpad memory used for temporary allocations.
- **Control Flow**:
    - The function begins by updating the blockhash queue using the [`register_blockhash`](#register_blockhash) function with the current slot's proof of history (poh).
    - It allocates memory for encoding recent blockhashes using `fd_spad_alloc` and initializes it to zero.
    - The function encodes the recent blockhashes from the blockhash queue into the allocated memory using [`encode_rbh_from_blockhash_queue`](#encode_rbh_from_blockhash_queue).
    - Finally, it sets the sysvar with the encoded data using [`fd_sysvar_set`](fd_sysvar.c.driver.md#fd_sysvar_set), specifying the owner ID, recent blockhashes ID, encoded data, size, and the current slot.
- **Output**: The function does not return a value; it performs operations to update the sysvar with recent blockhashes.
- **Functions called**:
    - [`register_blockhash`](#register_blockhash)
    - [`encode_rbh_from_blockhash_queue`](#encode_rbh_from_blockhash_queue)
    - [`fd_sysvar_set`](fd_sysvar.c.driver.md#fd_sysvar_set)


---
### register\_blockhash<!-- {{#callable:register_blockhash}} -->
The `register_blockhash` function updates a block hash queue with a new hash and manages the queue's size by removing old entries if necessary.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure, which contains context information for the execution slot, including the block hash queue.
    - `hash`: A pointer to a constant `fd_hash_t` structure representing the hash to be registered in the block hash queue.
- **Control Flow**:
    - Increment the `last_hash_index` of the block hash queue.
    - Check if the size of the block hash queue exceeds `max_age`; if so, iterate over the queue to remove entries that are too old.
    - Acquire a new map node from the `ages_pool` and populate it with the new hash and associated metadata, including the current `last_hash_index`, fee calculator, and timestamp.
    - Insert the new node into the block hash queue's map.
    - Update the `last_hash` in the queue to the new hash.
- **Output**: The function does not return a value; it modifies the block hash queue within the `slot_ctx` to include the new hash and potentially removes old entries.


---
### fd\_sysvar\_recent\_hashes\_update<!-- {{#callable:fd_sysvar_recent_hashes_update}} -->
The `fd_sysvar_recent_hashes_update` function updates the recent blockhashes sysvar by registering the latest blockhash, encoding recent blockhashes, and setting the sysvar with the encoded data.
- **Inputs**:
    - `slot_ctx`: A pointer to an `fd_exec_slot_ctx_t` structure representing the execution context for the current slot, which contains information about the slot bank and blockhash queue.
    - `runtime_spad`: A pointer to an `fd_spad_t` structure used for runtime memory allocation and management.
- **Control Flow**:
    - Begin a frame for the runtime scratchpad memory using `FD_SPAD_FRAME_BEGIN` macro.
    - Call [`register_blockhash`](#register_blockhash) to update the blockhash queue with the latest proof of history (poh) from the slot context.
    - Allocate memory for encoding recent blockhashes using `fd_spad_alloc` and initialize it to zero with `fd_memset`.
    - Call [`encode_rbh_from_blockhash_queue`](#encode_rbh_from_blockhash_queue) to encode recent blockhashes from the blockhash queue into the allocated memory.
    - Set the sysvar for recent blockhashes using [`fd_sysvar_set`](fd_sysvar.c.driver.md#fd_sysvar_set) with the encoded data, sysvar owner ID, sysvar recent blockhashes ID, and the current slot.
    - End the frame for the runtime scratchpad memory using `FD_SPAD_FRAME_END` macro.
- **Output**: The function does not return a value; it updates the recent blockhashes sysvar in the system state.
- **Functions called**:
    - [`register_blockhash`](#register_blockhash)
    - [`encode_rbh_from_blockhash_queue`](#encode_rbh_from_blockhash_queue)
    - [`fd_sysvar_set`](fd_sysvar.c.driver.md#fd_sysvar_set)


---
### fd\_sysvar\_recent\_hashes\_read<!-- {{#callable:fd_sysvar_recent_hashes_read}} -->
The function `fd_sysvar_recent_hashes_read` reads and decodes the recent block hashes from a sysvar account in a read-only transaction context.
- **Inputs**:
    - `funk`: A pointer to an `fd_funk_t` structure representing the database context.
    - `funk_txn`: A pointer to an `fd_funk_txn_t` structure representing the transaction context.
    - `spad`: A pointer to an `fd_spad_t` structure used for memory allocation.
- **Control Flow**:
    - Declare a transaction account `acc` using `FD_TXN_ACCOUNT_DECL` macro.
    - Initialize the account `acc` in read-only mode using `fd_txn_account_init_from_funk_readonly` with the sysvar recent block hashes ID, `funk`, and `funk_txn`.
    - If initialization fails, return `NULL`.
    - Set up a `fd_bincode_decode_ctx_t` context `ctx` with data and data end pointers from the account `acc`.
    - Check if the account has zero lamports, indicating non-existence, and return `NULL` if true.
    - Decode the footprint of recent block hashes using `fd_recent_block_hashes_decode_footprint` to determine `total_sz`.
    - If decoding fails, return `NULL`.
    - Allocate memory using `fd_spad_alloc` with alignment and size `total_sz`.
    - If memory allocation fails, log a critical error and return `NULL`.
    - Check again if the account has zero lamports and return `NULL` if true.
    - Decode the global recent block hashes using `fd_recent_block_hashes_decode_global` and return the result.
- **Output**: Returns a pointer to an `fd_recent_block_hashes_global_t` structure containing the decoded recent block hashes, or `NULL` if any error occurs during the process.


