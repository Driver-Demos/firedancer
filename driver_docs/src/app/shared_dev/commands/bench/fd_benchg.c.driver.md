# Purpose
This C source file is designed to implement a benchmarking generator for transaction processing, specifically within a distributed system or blockchain environment. The code defines a context structure (`fd_benchg_ctx_t`) that holds various parameters and state information necessary for generating and managing transactions. It includes fields for random number generation, cryptographic hashing, account management, and transaction mode settings. The file also defines several transaction types (`small_noop_t`, `large_noop_t`, `transfer_t`) that are used to simulate different transaction scenarios, such as small operations, large operations, and fund transfers.

The file includes functions for initializing the benchmarking context, generating transactions based on the current mode, and handling transaction fragments. The [`after_credit`](#after_credit) function is responsible for creating transactions and signing them using Ed25519 cryptography, while the [`during_frag`](#during_frag) function manages blockhash updates. The code is structured to be part of a larger system, as indicated by the inclusion of external headers and the use of macros and functions from those headers. The file defines a public API through the `fd_tile_benchg` structure, which specifies the entry points and configuration for running the benchmarking generator within the system. This setup suggests that the code is intended to be integrated into a larger framework for performance testing or simulation of transaction processing in a distributed ledger or blockchain environment.
# Imports and Dependencies

---
- `../../../../disco/topo/fd_topo.h`
- `../../../../flamenco/types/fd_types_custom.h`
- `../../../../flamenco/runtime/fd_system_ids_pp.h`
- `linux/unistd.h`
- `../../../../disco/stem/fd_stem.c`


# Global Variables

---
### HARDCODED\_PUBKEY
- **Type**: `static const uchar[32]`
- **Description**: `HARDCODED_PUBKEY` is a static constant array of 32 unsigned characters (bytes) representing a hardcoded public key. This array is initialized with a specific sequence of hexadecimal values.
- **Use**: This variable is used to store a predefined public key, which is likely utilized in cryptographic operations or as a reference within the program.


---
### HARDCODED\_SIG
- **Type**: ``static const uchar[64]``
- **Description**: `HARDCODED_SIG` is a static constant array of 64 unsigned characters (bytes) that represents a hardcoded signature. This array is initialized with a specific sequence of hexadecimal values, which likely corresponds to a predefined digital signature used within the application.
- **Use**: This variable is used to provide a fixed signature value, potentially for testing or validation purposes, within the transaction structures of the application.


---
### fd\_tile\_benchg
- **Type**: `fd_topo_run_tile_t`
- **Description**: The `fd_tile_benchg` is a global variable of type `fd_topo_run_tile_t`, which is a structure used to define a tile in a topology for a benchmarking application. It contains configuration and function pointers necessary for initializing and running the tile, such as alignment, footprint, initialization, and execution functions.
- **Use**: This variable is used to configure and manage the execution of a benchmarking tile within a larger system topology.


# Data Structures

---
### fd\_benchg\_ctx\_t
- **Type**: `struct`
- **Members**:
    - `rng`: An array of one fd_rng_t structure for random number generation.
    - `sha`: An array of one fd_sha512_t structure for SHA-512 hashing.
    - `sender_idx`: An unsigned long integer representing the index of the sender.
    - `lamport_idx`: An unsigned long integer representing the Lamport index.
    - `changed_blockhash`: An integer flag indicating if the blockhash has changed.
    - `has_recent_blockhash`: An integer flag indicating if there is a recent blockhash.
    - `recent_blockhash`: An array of 32 unsigned characters storing the recent blockhash.
    - `staged_blockhash`: An array of 32 unsigned characters storing the staged blockhash.
    - `transaction_mode`: An integer representing the mode of the transaction.
    - `contending_fraction`: A float representing the fraction of contending transactions.
    - `cu_price_spread`: A float representing the price spread for compute units.
    - `acct_cnt`: An unsigned long integer representing the count of accounts.
    - `acct_public_keys`: A pointer to an array of fd_pubkey_t structures for account public keys.
    - `acct_private_keys`: A pointer to an array of fd_pubkey_t structures for account private keys.
    - `benchg_cnt`: An unsigned long integer representing the count of benchmark generators.
    - `benchg_idx`: An unsigned long integer representing the index of the benchmark generator.
    - `mem`: A pointer to an fd_wksp_t structure representing the memory workspace.
    - `out_chunk0`: An unsigned long integer representing the initial output chunk.
    - `out_wmark`: An unsigned long integer representing the watermark for output.
    - `out_chunk`: An unsigned long integer representing the current output chunk.
- **Description**: The `fd_benchg_ctx_t` structure is a complex data structure used to manage the context for a benchmarking generator in a distributed system. It includes fields for random number generation, SHA-512 hashing, transaction management, and account handling. The structure maintains state information such as sender and Lamport indices, blockhashes, transaction modes, and account keys. It also manages memory workspaces and output chunking for efficient data handling during benchmarking operations.


---
### single\_signer\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `sig_cnt`: Indicates the number of signatures, set to 1.
    - `signature`: An array of 64 unsigned characters representing the signature.
    - `_sig_cnt`: A duplicate of sig_cnt, also set to 1.
    - `ro_signed_cnt`: An unsigned character with an unspecified purpose, possibly related to read-only signed counts.
    - `ro_unsigned_cnt`: An unsigned character with an unspecified purpose, possibly related to read-only unsigned counts.
    - `acct_addr_cnt`: An unsigned character with an unspecified purpose, possibly related to account address counts.
    - `fee_payer`: An array of 32 unsigned characters representing the fee payer's address.
- **Description**: The `single_signer_hdr_t` structure is a packed data structure used to represent a transaction header for a single signer. It includes fields for signature count, the signature itself, and various counters related to read-only signed and unsigned counts, as well as account address counts. The structure also contains a field for the fee payer's address, which is crucial for transaction processing. The exact purpose of some fields, such as `ro_signed_cnt`, `ro_unsigned_cnt`, and `acct_addr_cnt`, is not explicitly defined in the code, suggesting they may be used for specific transaction configurations or validations.


---
### small\_noop\_t
- **Type**: `struct`
- **Members**:
    - `sig_cnt`: Represents the signature count, initialized to 1.
    - `signature`: An array of 64 unsigned characters representing the signature.
    - `_sig_cnt`: A duplicate of sig_cnt, also initialized to 1.
    - `ro_signed_cnt`: Indicates the count of read-only signed accounts, initialized to 0.
    - `ro_unsigned_cnt`: Indicates the count of read-only unsigned accounts, initialized to 1 for the Compute Budget Program.
    - `acct_addr_cnt`: Represents the account address count, initialized to 2.
    - `fee_payer`: An array of 32 unsigned characters representing the fee payer's public key.
    - `compute_budget_program`: An array of 32 unsigned characters representing the Compute Budget Program ID.
    - `recent_blockhash`: An array of 32 unsigned characters representing the recent blockhash.
    - `instr_cnt`: Indicates the instruction count, initialized to 2.
    - `_1`: A nested struct representing the first instruction with fields for program ID, account count, data size, CU price setting, and micro lamports per CU.
    - `_2`: A nested struct representing the second instruction with fields for program ID, account count, data size, CU limit setting, and CU count.
- **Description**: The `small_noop_t` structure is a packed data structure designed to represent a small transaction with specific attributes for signature, account, and instruction management. It includes fields for handling signature counts, account addresses, and program-specific instructions, particularly for the Compute Budget Program. The structure is optimized for compactness and efficiency, with nested structs to encapsulate instruction details, such as program IDs and computational unit settings. This structure is typically used in scenarios where a minimal transaction footprint is required, such as in benchmarking or testing environments.


---
### large\_noop\_t
- **Type**: `struct`
- **Members**:
    - `sig_cnt`: Represents the number of signatures, initialized to 1.
    - `signature`: An array of 64 unsigned characters representing the signature.
    - `_sig_cnt`: A duplicate of sig_cnt, also initialized to 1.
    - `ro_signed_cnt`: Indicates the count of read-only signed accounts, initialized to 0.
    - `ro_unsigned_cnt`: Indicates the count of read-only unsigned accounts, initialized to 2.
    - `acct_addr_cnt`: Represents the number of account addresses, initialized to 3.
    - `fee_payer`: An array of 32 unsigned characters representing the fee payer's public key.
    - `compute_budget_program`: An array of 32 unsigned characters representing the Compute Budget Program ID.
    - `ed25519_sv_program`: An array of 32 unsigned characters representing the Ed25519SV Program ID.
    - `recent_blockhash`: An array of 32 unsigned characters representing the recent block hash.
    - `instr_cnt`: Indicates the number of instructions, initialized to 2.
    - `_1`: A nested struct representing the first instruction with program ID, account count, data size, CU price, and micro lamports per CU.
    - `_2`: A nested struct representing the second instruction with program ID, account count, data sizes, signature count, offsets, and hardcoded public key and signature.
- **Description**: The `large_noop_t` structure is a packed data structure designed to represent a large no-operation transaction in a blockchain context. It includes fields for managing signatures, account addresses, and program IDs, as well as nested structures for handling specific instructions. The structure is optimized for minimal memory usage and is used to simulate or test transaction processing without performing any actual operations. It includes fields for handling compute budget programs and Ed25519 signature verification, making it suitable for testing transaction validation and execution in a blockchain environment.


---
### transfer\_t
- **Type**: `struct`
- **Members**:
    - `sig_cnt`: Stores the count of signatures, initialized to 1.
    - `signature`: An array of 64 unsigned characters representing the signature.
    - `_sig_cnt`: A duplicate of sig_cnt, also initialized to 1.
    - `ro_signed_cnt`: Indicates the count of read-only signed accounts, initialized to 0.
    - `ro_unsigned_cnt`: Indicates the count of read-only unsigned accounts, initialized to 1 for the system program.
    - `acct_addr_cnt`: Stores the count of account addresses, initialized to 3.
    - `fee_payer`: An array of 32 unsigned characters representing the fee payer's address.
    - `transfer_dest`: An array of 32 unsigned characters representing the transfer destination address.
    - `system_program`: An array of 32 unsigned characters representing the system program, initialized to zeros.
    - `recent_blockhash`: An array of 32 unsigned characters representing the recent blockhash.
    - `instr_cnt`: Stores the count of instructions, initialized to 1.
    - `_1`: A nested struct representing the instruction details for the transfer.
- **Description**: The `transfer_t` structure is a packed data structure used to represent a transaction in a system, specifically for transferring lamports. It includes fields for managing signatures, account addresses, and program identifiers, as well as a nested structure for detailing the instruction of the transfer, such as the program ID, account count, and the amount of lamports to transfer. This structure is designed to be compact and efficient for processing transactions in a blockchain or distributed ledger environment.


# Functions

---
### scratch\_align<!-- {{#callable:scratch_align}} -->
The `scratch_align` function returns the alignment requirement of the `fd_benchg_ctx_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the result of the `alignof` operator applied to the `fd_benchg_ctx_t` type.
- **Output**: The function outputs an `ulong` representing the alignment requirement of the `fd_benchg_ctx_t` structure.


---
### scratch\_footprint<!-- {{#callable:scratch_footprint}} -->
The `scratch_footprint` function calculates the memory footprint required for a specific tile's context and associated public keys based on the number of accounts.
- **Inputs**:
    - `tile`: A pointer to a `fd_topo_tile_t` structure, which contains information about the tile, including the number of accounts (`accounts_cnt`) for which memory needs to be allocated.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the size and alignment of `fd_benchg_ctx_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the size and alignment of an array of `fd_pubkey_t` for the number of accounts specified in `tile->benchg.accounts_cnt` twice to `l` using `FD_LAYOUT_APPEND`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI`, using the alignment from `scratch_align()`, and return the result.
- **Output**: Returns an `ulong` representing the total memory footprint required for the tile's context and associated public keys.
- **Functions called**:
    - [`scratch_align`](#scratch_align)


---
### after\_credit<!-- {{#callable:after_credit}} -->
The `after_credit` function processes a transaction based on the current context, updates the transaction details, signs it, and publishes it to a specified stem.
- **Inputs**:
    - `ctx`: A pointer to an `fd_benchg_ctx_t` structure containing the context for the transaction, including RNG, transaction mode, account keys, and other parameters.
    - `stem`: A pointer to an `fd_stem_context_t` structure used for publishing the transaction.
    - `opt_poll_in`: An optional integer pointer, not used in the function.
    - `charge_busy`: A pointer to an integer that is set to 1 if the function processes a transaction.
- **Control Flow**:
    - Check if the context has a recent blockhash; if not, return immediately.
    - Set `charge_busy` to 1 to indicate the function is processing a transaction.
    - Determine if the transaction is contending based on a random value and the contending fraction from the context.
    - Calculate a price spread for compute units using a normal distribution and the context's spread factor.
    - Convert the output chunk to a local address for transaction processing.
    - Based on the transaction mode, initialize a transaction structure (`small_noop_t`, `large_noop_t`, or `transfer_t`) and set its fields accordingly.
    - Copy the fee payer and recent blockhash into the transaction header.
    - Sign the transaction using the Ed25519 algorithm with the sender's keys and the SHA context.
    - Publish the transaction using `fd_stem_publish` with the calculated transaction size.
    - Update the output chunk to the next compacted chunk position.
    - Increment the sender index and update the lamport index if necessary, handling blockhash changes.
- **Output**: The function does not return a value but modifies the transaction context and publishes a transaction to the specified stem.


---
### during\_frag<!-- {{#callable:during_frag}} -->
The `during_frag` function updates the blockhash in the context if it has changed, using data from a specified memory chunk.
- **Inputs**:
    - `ctx`: A pointer to an `fd_benchg_ctx_t` structure that holds the context for the benchmark, including blockhash information.
    - `in_idx`: An unused parameter of type `ulong`.
    - `seq`: An unused parameter of type `ulong`.
    - `sig`: An unused parameter of type `ulong`.
    - `chunk`: A `ulong` representing the memory chunk from which the blockhash is to be read.
    - `sz`: An unused parameter of type `ulong`.
    - `ctl`: An unused parameter of type `ulong`.
- **Control Flow**:
    - Check if `ctx->has_recent_blockhash` is false, indicating no recent blockhash is stored.
    - If no recent blockhash is stored, copy the blockhash from the memory chunk to `ctx->recent_blockhash`, set `ctx->has_recent_blockhash` to true, and `ctx->changed_blockhash` to false.
    - If a recent blockhash is already stored, compare it with the blockhash from the memory chunk.
    - If the blockhashes are different, copy the new blockhash to `ctx->staged_blockhash` and set `ctx->changed_blockhash` to true.
    - If the blockhashes are the same, return without making changes.
- **Output**: The function does not return a value; it modifies the `ctx` structure in place.


---
### unprivileged\_init<!-- {{#callable:unprivileged_init}} -->
The `unprivileged_init` function initializes a benchmarking context for a given tile in a topology, setting up memory allocations, cryptographic contexts, and transaction parameters.
- **Inputs**:
    - `topo`: A pointer to an `fd_topo_t` structure representing the topology configuration.
    - `tile`: A pointer to an `fd_topo_tile_t` structure representing the specific tile to initialize.
- **Control Flow**:
    - Allocate scratch memory for the tile using `fd_topo_obj_laddr` to get the local address of the tile object.
    - Initialize the scratch allocator with `FD_SCRATCH_ALLOC_INIT`.
    - Allocate memory for the `fd_benchg_ctx_t` context structure and public/private key arrays using `FD_SCRATCH_ALLOC_APPEND`.
    - Initialize random number generator and SHA-512 contexts using `fd_rng_join` and `fd_sha512_join`.
    - Set various context parameters from the tile's benchmarking configuration, such as account count, transaction mode, contending fraction, and CU price spread.
    - For each account, initialize private keys to zero, store the account index, and derive public keys from private keys using `fd_ed25519_public_from_private`.
    - Initialize context fields related to blockhash, sender index, and lamport index.
    - Determine the number of benchmarking tiles and the index of the current tile.
    - Set up memory workspace and data cache parameters for output transactions.
    - Finalize the scratch allocation and check for overflow, logging an error if it occurs.
- **Output**: The function does not return a value but initializes the `fd_benchg_ctx_t` context for the specified tile, setting up memory and cryptographic contexts for benchmarking.
- **Functions called**:
    - [`scratch_footprint`](#scratch_footprint)


