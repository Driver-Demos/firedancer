# Purpose
The provided C header file, `fd_pack.h`, defines a set of functions and data structures for managing and optimizing the scheduling of Solana transactions to maximize the profitability of a validator. This file is part of a larger system, likely a blockchain validator or node software, that processes transactions in a way that adheres to consensus rules while optimizing for performance and profitability. The header file includes definitions for constants, data structures, and functions that handle transaction prioritization, scheduling, and memory management for transaction bundles and microblocks.

Key components of this file include the `fd_pack_limits_t` structure, which encapsulates various consensus-critical limits related to transaction costs and data sizes, and the `fd_pack_t` structure, which represents the main transaction pack object. The file provides a comprehensive API for initializing, managing, and scheduling transactions, including functions for inserting transactions and bundles, scheduling microblocks, handling transaction expiration, and managing block-level state transitions. The header also defines several constants and macros that are critical for maintaining consensus and ensuring that the transaction scheduling adheres to the constraints imposed by the Solana network and the Firedancer implementation. Overall, this file is a crucial part of a system designed to efficiently manage transaction processing in a high-performance blockchain environment.
# Imports and Dependencies

---
- `../../ballet/fd_ballet_base.h`
- `../../ballet/txn/fd_txn.h`
- `fd_est_tbl.h`
- `fd_microblock.h`
- `fd_pack_rebate_sum.h`


# Global Variables

---
### fd\_pack\_new
- **Type**: `function`
- **Description**: The `fd_pack_new` function is responsible for formatting a region of memory to be suitable for use as a pack object. It takes several parameters including memory location, pack depth, bundle metadata size, bank tile count, limits, and a random number generator. The function returns the memory pointer formatted as a pack object on success or NULL on failure.
- **Use**: This function is used to initialize a memory region for a pack object, setting up the necessary parameters and limits for transaction scheduling and management.


---
### fd\_pack\_join
- **Type**: `fd_pack_t *`
- **Description**: The `fd_pack_join` function is a global function that returns a pointer to an `fd_pack_t` structure. This function is used to join a caller to a pack object, which is a data structure used for managing and scheduling Solana transactions in a way that maximizes validator profitability.
- **Use**: This function is used to join a caller to a pack object, allowing the caller to interact with and manage the pack's transaction scheduling capabilities.


---
### fd\_pack\_insert\_txn\_init
- **Type**: `fd_txn_e_t *`
- **Description**: The `fd_pack_insert_txn_init` is a function that returns a pointer to a memory location where a new transaction should be stored. This memory is managed by the `fd_pack` system and is used to insert transactions into the pool of available transactions for scheduling.
- **Use**: This function is used to initialize the process of inserting a new transaction into the transaction pool managed by the `fd_pack` system.


---
### fd\_pack\_insert\_bundle\_init
- **Type**: `fd_txn_e_t * const *`
- **Description**: The `fd_pack_insert_bundle_init` is a function that initializes a bundle of transactions for insertion into a pack object. It returns a pointer to an array of constant pointers to `fd_txn_e_t` structures, which represent the transactions in the bundle.
- **Use**: This function is used to prepare a bundle of transactions for scheduling by populating the bundle with pointers to transaction structures.


---
### fd\_pack\_peek\_bundle\_meta
- **Type**: `function`
- **Description**: `fd_pack_peek_bundle_meta` is a function that returns a constant pointer to the metadata associated with the next bundle in line to be scheduled in a pack object. It provides access to the metadata of bundles that are not initializer bundles and are ready to be scheduled.
- **Use**: This function is used to retrieve metadata for the next bundle to be scheduled, allowing the system to make decisions based on the bundle's metadata.


---
### fd\_pack\_leave
- **Type**: `function`
- **Description**: The `fd_pack_leave` function is a global function that facilitates leaving a local join of a pack object. It is part of the Firedancer pack management system, which is used to handle Solana transactions efficiently.
- **Use**: This function is used to properly exit a local join of a pack object, ensuring that resources are managed correctly.


---
### fd\_pack\_delete
- **Type**: `function pointer`
- **Description**: `fd_pack_delete` is a function pointer that takes a single argument, a pointer to a memory region (`void * mem`), and returns a pointer to the same memory region. It is used to unformat a memory region that was previously formatted to store a pack object, effectively returning the memory ownership back to the caller.
- **Use**: This function is used to clean up and release memory that was allocated for a pack object, ensuring that resources are properly managed and returned to the system.


# Data Structures

---
### fd\_pack\_limits
- **Type**: `struct`
- **Members**:
    - `max_cost_per_block`: Specifies the maximum cost units a block can consume, ensuring it remains valid.
    - `max_vote_cost_per_block`: Limits the total cost units for vote transactions within a block.
    - `max_write_cost_per_acct`: Restricts the cost units for transactions writing to a single account within a block.
    - `max_data_bytes_per_block`: Defines the maximum data size in bytes for a block to prevent excessive shreds.
    - `max_txn_per_microblock`: Sets the maximum number of transactions allowed in a single microblock.
    - `max_microblocks_per_block`: Limits the number of non-empty microblocks that can be produced in a block.
- **Description**: The `fd_pack_limits` structure defines various constraints and limits for blocks and microblocks in the Firedancer system, ensuring consensus-critical operations are adhered to. It includes limits on the total cost units a block can consume, the cost units for vote transactions, and the cost units for transactions writing to a single account. Additionally, it specifies the maximum data size for a block to prevent excessive shreds, and it imposes limits on the number of transactions per microblock and the number of microblocks per block. These constraints are crucial for maintaining system stability and ensuring that blocks are produced within acceptable parameters.


---
### fd\_pack\_limits\_t
- **Type**: `struct`
- **Members**:
    - `max_cost_per_block`: Specifies the maximum cost units a block can consume, ensuring it remains valid.
    - `max_vote_cost_per_block`: Limits the total cost units for vote transactions within a block.
    - `max_write_cost_per_acct`: Restricts the cost units for transactions writing to a single account within a block.
    - `max_data_bytes_per_block`: Defines the maximum data size in bytes that can be included in a block to prevent excessive shreds.
    - `max_txn_per_microblock`: Sets the maximum number of transactions allowed per microblock to control memory usage.
    - `max_microblocks_per_block`: Limits the number of non-empty microblocks in a block to manage memory consumption.
- **Description**: The `fd_pack_limits_t` structure encapsulates various constraints imposed on the Solana network and Firedancer implementation to ensure efficient and valid block production. These constraints include limits on the total cost units a block can consume, the cost units for vote transactions, and the cost units for transactions writing to a single account. Additionally, it defines the maximum data size a block can contain to prevent excessive shreds, and it sets limits on the number of transactions per microblock and the number of non-empty microblocks per block. These limits are crucial for maintaining consensus and optimizing memory usage during block production.


---
### fd\_pack\_t
- **Type**: ``struct``
- **Members**:
    - `fd_pack_private`: An opaque structure representing the internal state of the `fd_pack_t` data structure.
- **Description**: The `fd_pack_t` is a forward-declared opaque structure used in the Firedancer system to manage and schedule Solana transactions for validators. It is designed to prioritize and order transactions to maximize validator profitability while adhering to consensus-critical limits. The structure is part of a larger system that handles transaction scheduling, microblock creation, and bundle management, ensuring that transactions are processed efficiently and within the constraints of the Solana network. The actual implementation details of `fd_pack_t` are hidden, as it is defined as a forward declaration of `struct fd_pack_private`, emphasizing encapsulation and abstraction in its design.


# Functions

---
### fd\_pack\_align<!-- {{#callable:fd_pack_align}} -->
The `fd_pack_align` function returns the required memory alignment for a pack object, which is defined by the constant `FD_PACK_ALIGN`.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests a preference for inlining by the compiler.
    - It returns the value of the macro `FD_PACK_ALIGN`, which is set to `128UL`.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for a pack object, specifically `128UL`.


---
### fd\_pack\_avail\_txn\_cnt<!-- {{#callable:fd_pack_avail_txn_cnt}} -->
The `fd_pack_avail_txn_cnt` function returns the number of unscheduled transactions available in a given pack object.
- **Inputs**:
    - `pack`: A pointer to a constant `fd_pack_t` structure representing the pack object whose available transaction count is to be retrieved.
- **Control Flow**:
    - The function calculates the address of the pending transaction count within the pack object by adding a predefined offset (`FD_PACK_PENDING_TXN_CNT_OFF`) to the base address of the pack.
    - It then casts this address to a pointer to a constant unsigned long and dereferences it to obtain the transaction count.
    - Finally, it returns the transaction count as an unsigned long.
- **Output**: The function returns an unsigned long representing the number of transactions available to be scheduled in the pack object.


# Function Declarations (Public API)

---
### fd\_pack\_footprint<!-- {{#callable_declaration:fd_pack_footprint}} -->
Calculates the memory footprint required for a pack object.
- **Description**: This function determines the memory footprint needed for a pack object based on the specified parameters. It should be used when setting up a memory region for a pack object to ensure that the region is appropriately sized. The function requires valid input parameters, including a non-zero bank_tile_cnt within the allowed range and a pack_depth of at least 4. If these conditions are not met, the function returns 0, indicating an invalid configuration.
- **Inputs**:
    - `pack_depth`: Specifies the maximum number of pending transactions the pack can store. Must be at least 4.
    - `bundle_meta_sz`: Indicates the size of metadata reserved for each bundle if non-zero, enabling bundle-related functions.
    - `bank_tile_cnt`: Sets the number of bank tiles for transaction scheduling. Must be between 1 and FD_PACK_MAX_BANK_TILES inclusive.
    - `limits`: A pointer to a fd_pack_limits_t struct defining various block and microblock limits. Must not be null.
- **Output**: Returns the calculated memory footprint in bytes, or 0 if input parameters are invalid.
- **See also**: [`fd_pack_footprint`](fd_pack.c.driver.md#fd_pack_footprint)  (Implementation)


---
### fd\_pack\_new<!-- {{#callable_declaration:fd_pack_new}} -->
Formats a memory region for use as a pack object.
- **Description**: This function initializes a memory region to be used as a pack object, which is designed to prioritize and order Solana transactions for maximizing validator profitability. It requires a memory region with the correct alignment and footprint, and it sets up various parameters such as transaction depth, bundle metadata size, and bank tile count. The function also requires a random number generator for perturbing estimates. It returns the memory region formatted as a pack object on success, or NULL on failure, logging details of the failure. The caller is not joined to the pack object upon return.
- **Inputs**:
    - `mem`: A non-NULL pointer to a memory region in the local address space with the required alignment and footprint. The caller retains ownership.
    - `pack_depth`: An unsigned long specifying the maximum number of pending transactions the pack can store. Must be at least 4.
    - `bundle_meta_sz`: An unsigned long specifying the size of metadata for each bundle. If non-zero, bundle-related functions can be used.
    - `bank_tile_cnt`: An unsigned long specifying the number of bank tiles for transaction scheduling. Must be in the range [1, FD_PACK_MAX_BANK_TILES].
    - `limits`: A pointer to a constant fd_pack_limits_t struct specifying various limits for blocks and microblocks. Must not be NULL.
    - `rng`: A pointer to a local join of a random number generator used for perturbing estimates. Must not be NULL.
- **Output**: Returns the memory region formatted as a pack object on success, or NULL on failure.
- **See also**: [`fd_pack_new`](fd_pack.c.driver.md#fd_pack_new)  (Implementation)


---
### fd\_pack\_join<!-- {{#callable_declaration:fd_pack_join}} -->
Joins the caller to a pack object.
- **Description**: This function is used to join the caller to a pack object, which is necessary for performing operations on the pack. It should be called after the pack object has been properly initialized with `fd_pack_new`. The function returns a pointer to the pack object, allowing the caller to interact with it. Each successful call to this function should be matched with a corresponding call to `fd_pack_leave` to ensure proper resource management.
- **Inputs**:
    - `mem`: A non-null pointer to a memory region that has been formatted as a pack object. The memory must be properly aligned and have the correct footprint as required by the pack object. If the memory is not correctly formatted, the behavior is undefined.
- **Output**: Returns a pointer to the joined pack object, allowing further operations on it.
- **See also**: [`fd_pack_join`](fd_pack.c.driver.md#fd_pack_join)  (Implementation)


---
### fd\_pack\_current\_block\_cost<!-- {{#callable_declaration:fd_pack_current_block_cost}} -->
Returns the current cumulative block cost in compute units.
- **Description**: Use this function to retrieve the number of compute units (CUs) that have been scheduled in the current block, accounting for any rebates. This value provides insight into the current resource usage of the block and can be used to ensure that the block does not exceed predefined limits. The function should be called on a valid local join of a `fd_pack_t` object. The returned value may slightly exceed the maximum allowed due to temporary cost model adjustments, and it may decrease as the block progresses due to rebates.
- **Inputs**:
    - `pack`: A pointer to a `fd_pack_t` object representing the pack. It must be a valid local join. The function does not modify the pack or take ownership of it.
- **Output**: Returns an unsigned long representing the cumulative block cost in compute units, which may decrease as the block progresses.
- **See also**: [`fd_pack_current_block_cost`](fd_pack.c.driver.md#fd_pack_current_block_cost)  (Implementation)


---
### fd\_pack\_bank\_tile\_cnt<!-- {{#callable_declaration:fd_pack_bank_tile_cnt}} -->
Returns the number of bank tiles configured for the pack object.
- **Description**: This function retrieves the number of bank tiles that were specified when the pack object was initialized using fd_pack_new. It is useful for understanding the configuration of the pack object, particularly in scenarios where transaction scheduling across multiple bank tiles is involved. The function must be called on a valid local join of a pack object, and the returned value will be within the range of 1 to FD_PACK_MAX_BANK_TILES.
- **Inputs**:
    - `pack`: A pointer to a valid fd_pack_t object. The pack object must be a valid local join, and the function will not perform any null checks on this parameter.
- **Output**: The function returns an unsigned long integer representing the number of bank tiles configured for the pack object, which will be in the range [1, FD_PACK_MAX_BANK_TILES].
- **See also**: [`fd_pack_bank_tile_cnt`](fd_pack.c.driver.md#fd_pack_bank_tile_cnt)  (Implementation)


---
### fd\_pack\_set\_block\_limits<!-- {{#callable_declaration:fd_pack_set_block_limits}} -->
Update the block limits for a pack object.
- **Description**: This function updates the block limits of a given pack object with new values specified in the limits parameter. It is typically called immediately after ending a block to set new constraints for the next block. If called after some microblocks have been produced for the current block, and the current block already exceeds the new limits, all remaining microblocks will be empty, but the call remains valid. The pack object must be a valid local join.
- **Inputs**:
    - `pack`: A pointer to a fd_pack_t object whose block limits are to be updated. The pack object must be a valid local join.
    - `limits`: A pointer to a fd_pack_limits_t structure containing the new block limits. The structure must not be null and must have valid values for each limit, adhering to the lower bounds defined by the system. Invalid values will cause the function to assert.
- **Output**: None
- **See also**: [`fd_pack_set_block_limits`](fd_pack.c.driver.md#fd_pack_set_block_limits)  (Implementation)


---
### fd\_pack\_insert\_txn\_init<!-- {{#callable_declaration:fd_pack_insert_txn_init}} -->
Initialize a transaction insertion process for a pack object.
- **Description**: This function begins the process of inserting a new transaction into the transaction pool of a given pack object. It returns a pointer to a memory location where the transaction data should be stored. This memory is managed by the pack object, and the caller should not retain any interest in it after the transaction insertion process is completed or canceled. The function must be followed by a call to either `fd_pack_insert_txn_fini` to finalize the insertion or `fd_pack_insert_txn_cancel` to abort it. The pack object must be a valid local join.
- **Inputs**:
    - `pack`: A pointer to a valid `fd_pack_t` object that is locally joined. The pack object manages the transaction pool and must be properly initialized before calling this function.
- **Output**: Returns a pointer to `fd_txn_e_t`, which is a memory location for storing the transaction data. The caller should use this pointer to populate the transaction details.
- **See also**: [`fd_pack_insert_txn_init`](fd_pack.c.driver.md#fd_pack_insert_txn_init)  (Implementation)


---
### fd\_pack\_insert\_txn\_fini<!-- {{#callable_declaration:fd_pack_insert_txn_fini}} -->
Finalize the insertion of a transaction into the pack object.
- **Description**: This function completes the process of inserting a transaction into the pack object, making it available for scheduling. It should be called after a successful call to `fd_pack_insert_txn_init` and must be paired with either this function or `fd_pack_insert_txn_cancel`. The function evaluates the transaction for acceptance based on various criteria, including expiration time and priority. Transactions that are expired or fail validation will be rejected. The function returns a code indicating whether the transaction was accepted or rejected, and if accepted, whether it replaced an existing transaction.
- **Inputs**:
    - `pack`: A pointer to a valid `fd_pack_t` object, which must be a local join. The caller retains ownership.
    - `txne`: A pointer to an `fd_txn_e_t` object representing the transaction to be finalized. This must be the result of the most recent call to `fd_pack_insert_txn_init`.
    - `expires_at`: An unsigned long integer representing the expiration time of the transaction. If this value is less than the value used in the last call to `fd_pack_expire_before`, the transaction will be rejected as expired.
- **Output**: Returns an integer code indicating the result of the transaction insertion. Non-negative values indicate acceptance, with specific codes for whether the transaction is a vote and if it replaced another transaction. Negative values indicate rejection, with specific codes for different rejection reasons.
- **See also**: [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini)  (Implementation)


---
### fd\_pack\_insert\_txn\_cancel<!-- {{#callable_declaration:fd_pack_insert_txn_cancel}} -->
Cancels a pending transaction insertion.
- **Description**: Use this function to abort the insertion of a transaction into the pack's pool of available transactions. This function should be called if a transaction insertion process, initiated by a prior call to `fd_pack_insert_txn_init`, needs to be canceled before it is finalized. It is important to ensure that every call to `fd_pack_insert_txn_init` is paired with a call to either `fd_pack_insert_txn_fini` or `fd_pack_insert_txn_cancel`. The transaction pointer passed to this function must be the one obtained from the most recent call to `fd_pack_insert_txn_init`. After calling this function, the caller should not retain any interest in the transaction.
- **Inputs**:
    - `pack`: A pointer to a valid `fd_pack_t` object. This must be a local join of a pack object and must not be null.
    - `txn`: A pointer to an `fd_txn_e_t` object representing the transaction to be canceled. This pointer must have been obtained from the most recent call to `fd_pack_insert_txn_init` and must not be null.
- **Output**: None
- **See also**: [`fd_pack_insert_txn_cancel`](fd_pack.c.driver.md#fd_pack_insert_txn_cancel)  (Implementation)


---
### fd\_pack\_insert\_bundle\_init<!-- {{#callable_declaration:fd_pack_insert_bundle_init}} -->
Initialize a bundle of transactions for insertion into a pack.
- **Description**: This function prepares a bundle of transactions for insertion into a pack object, ensuring that the bundle can accommodate the specified number of transactions. It should be called when you want to insert a group of transactions that need to be executed atomically. The function must be paired with a subsequent call to either `fd_pack_insert_bundle_fini` or `fd_pack_insert_bundle_cancel`. The pack must have sufficient capacity to accommodate the transactions, and the transaction count must not exceed the maximum allowed per bundle.
- **Inputs**:
    - `pack`: A pointer to a valid `fd_pack_t` object, representing the pack into which the bundle will be inserted. The pack must be properly initialized and joined.
    - `bundle`: A pointer to an array of `fd_txn_e_t *` pointers, which will be populated with transaction pointers. The array must have space for at least `txn_cnt` elements.
    - `txn_cnt`: The number of transactions to include in the bundle. Must be between 1 and `FD_PACK_MAX_TXN_PER_BUNDLE`, inclusive. If this condition is not met, the behavior is undefined.
- **Output**: Returns the `bundle` pointer, now populated with transaction pointers for the specified number of transactions.
- **See also**: [`fd_pack_insert_bundle_init`](fd_pack.c.driver.md#fd_pack_insert_bundle_init)  (Implementation)


---
### fd\_pack\_insert\_bundle\_fini<!-- {{#callable_declaration:fd_pack_insert_bundle_fini}} -->
Finalizes the insertion of a transaction bundle into the pack.
- **Description**: This function is used to complete the process of inserting a bundle of transactions into a pack object, making them available for scheduling. It should be called after initializing a bundle with `fd_pack_insert_bundle_init` and before any other operations on the bundle. The function checks for various conditions such as expiration and priority, and may reject the bundle if any transaction within it fails validation. If the bundle is marked as an initializer, it will be prioritized in the scheduling queue. The function also allows optional metadata to be associated with the bundle, which can be retrieved later. It returns a status code indicating whether the bundle was accepted or rejected, and if accepted, whether it replaced any existing transactions.
- **Inputs**:
    - `pack`: A pointer to a valid `fd_pack_t` object. The caller must have a local join to this pack.
    - `bundle`: A pointer to an array of `fd_txn_e_t *` pointers, each pointing to a transaction. The array must have at least `txn_cnt` elements.
    - `txn_cnt`: The number of transactions in the bundle. Must be between 1 and `FD_PACK_MAX_TXN_PER_BUNDLE` inclusive.
    - `expires_at`: An expiration timestamp for the bundle. If any transaction in the bundle is expired, the entire bundle will be rejected.
    - `initializer_bundle`: An integer flag indicating if the bundle is an initializer. Non-zero values mark the bundle as an initializer, which affects its scheduling priority and validation checks.
    - `bundle_meta`: An optional pointer to metadata associated with the bundle. If non-NULL, the metadata is copied to the pack's internal storage. The size of the metadata must match the `bundle_meta_sz` specified during pack initialization.
- **Output**: Returns an integer status code. Positive values indicate acceptance, with details on whether the bundle replaced existing transactions. Negative values indicate rejection, with specific reasons for the rejection.
- **See also**: [`fd_pack_insert_bundle_fini`](fd_pack.c.driver.md#fd_pack_insert_bundle_fini)  (Implementation)


---
### fd\_pack\_insert\_bundle\_cancel<!-- {{#callable_declaration:fd_pack_insert_bundle_cancel}} -->
Cancels the insertion of a transaction bundle into the pack.
- **Description**: Use this function to abort the insertion process of a transaction bundle that was previously initiated but should not be completed. This is useful when the bundle is no longer needed or if an error occurred during its preparation. The function must be called with the same bundle and transaction count as provided to the corresponding initialization function. It ensures that resources allocated for the bundle are properly released, preventing memory leaks or resource contention.
- **Inputs**:
    - `pack`: A pointer to a valid fd_pack_t object that represents the pack where the bundle insertion was initiated. Must be a local join.
    - `bundle`: A pointer to the first element of an array of fd_txn_e_t pointers, representing the bundle to be canceled. Must match the bundle provided to the corresponding initialization function.
    - `txn_cnt`: The number of transactions in the bundle. Must be in the range [1, FD_PACK_MAX_TXN_PER_BUNDLE] and match the count used in the initialization function.
- **Output**: None
- **See also**: [`fd_pack_insert_bundle_cancel`](fd_pack.c.driver.md#fd_pack_insert_bundle_cancel)  (Implementation)


---
### fd\_pack\_peek\_bundle\_meta<!-- {{#callable_declaration:fd_pack_peek_bundle_meta}} -->
Returns a pointer to the metadata of the next bundle to be scheduled.
- **Description**: Use this function to retrieve a constant pointer to the metadata associated with the next bundle in line for scheduling. This function is useful when you need to access the metadata of a bundle before it is scheduled. It returns NULL if there are no bundles, if the next bundle is an initializer bundle, or if the bundle state is either pending or failed. The returned pointer is valid until the next modification to the pack object, such as an insert, schedule, delete, or expire operation.
- **Inputs**:
    - `pack`: A pointer to a valid fd_pack_t object. This must be a local join of a pack object. The function will return NULL if the pack's initializer bundle state is pending or failed.
- **Output**: A constant pointer to the bundle metadata, or NULL if no valid metadata is available.
- **See also**: [`fd_pack_peek_bundle_meta`](fd_pack.c.driver.md#fd_pack_peek_bundle_meta)  (Implementation)


---
### fd\_pack\_set\_initializer\_bundles\_ready<!-- {{#callable_declaration:fd_pack_set_initializer_bundles_ready}} -->
Sets the initializer bundle state to ready.
- **Description**: Use this function to transition the initializer bundle state machine to the 'Ready' state, allowing the scheduling of bundles without requiring an initializer bundle. This is particularly useful when the on-chain state is already prepared, and no additional initialization is necessary. The function should be called on a valid local join of a pack object.
- **Inputs**:
    - `pack`: A pointer to a valid fd_pack_t object. The pack object must be a valid local join, and the caller retains ownership.
- **Output**: None
- **See also**: [`fd_pack_set_initializer_bundles_ready`](fd_pack.c.driver.md#fd_pack_set_initializer_bundles_ready)  (Implementation)


---
### fd\_pack\_schedule\_next\_microblock<!-- {{#callable_declaration:fd_pack_schedule_next_microblock}} -->
Schedules pending transactions into a microblock or bundle.
- **Description**: This function is used to schedule pending transactions from a pack object into a microblock or a bundle, depending on the specified scheduling flags. It should be called when you want to organize transactions for execution, ensuring they fit within the specified compute unit and transaction limits. The function respects block-level limits and can handle different types of transactions, including votes and bundles. It must be called with a valid pack object that the caller has joined, and the scheduling behavior is controlled by the provided flags. The function returns the number of transactions successfully scheduled, which may be zero if no eligible transactions are available.
- **Inputs**:
    - `pack`: A pointer to a valid fd_pack_t object that the caller has joined. It must not be null.
    - `total_cus`: The maximum number of compute units (CUs) that the scheduled transactions can consume. It is clamped to ensure it does not exceed block limits.
    - `vote_fraction`: A float representing the fraction of total_cus and transactions that can be allocated to vote transactions. It should be between 0.0 and 1.0.
    - `bank_tile`: An unsigned long representing the bank tile index where transactions will be scheduled. It must be within the valid range of bank tiles for the pack object.
    - `schedule_flags`: An integer bitmask composed of FD_PACK_SCHEDULE_* flags that specify which types of transactions to schedule (e.g., votes, bundles, normal transactions). A value of 0 results in no scheduling.
    - `out`: A pointer to an array of fd_txn_p_t where the scheduled transactions will be copied. The array must be large enough to hold the maximum number of transactions that can be scheduled.
- **Output**: Returns the number of transactions scheduled into the microblock or bundle. The return value may be 0 if no transactions were scheduled.
- **See also**: [`fd_pack_schedule_next_microblock`](fd_pack.c.driver.md#fd_pack_schedule_next_microblock)  (Implementation)


---
### fd\_pack\_rebate\_cus<!-- {{#callable_declaration:fd_pack_rebate_cus}} -->
Adjust compute unit accounting based on actual usage and update pack state accordingly.
- **Description**: This function is used to adjust the compute unit (CU) accounting for transactions after their execution, based on the actual CUs consumed. It should be called after scheduling transactions with `fd_pack_schedule_next_microblock` and before the end of the current block, as CU limits are reset at the end of each block. The function also updates the state of the pack object, particularly in relation to initializer bundles, based on the results of the rebate. It is important to ensure that the `pack` object is a valid local join and that the `rebate` report is valid and corresponds to the transactions executed in the current block.
- **Inputs**:
    - `pack`: A pointer to a `fd_pack_t` object representing the pack. It must be a valid local join and should not be null.
    - `rebate`: A pointer to a `fd_pack_rebate_t` structure containing the rebate information. It must be valid and correspond to the transactions executed in the current block.
- **Output**: None
- **See also**: [`fd_pack_rebate_cus`](fd_pack.c.driver.md#fd_pack_rebate_cus)  (Implementation)


---
### fd\_pack\_microblock\_complete<!-- {{#callable_declaration:fd_pack_microblock_complete}} -->
Signals the completion of a microblock for a specific bank tile.
- **Description**: This function should be called when a bank tile has completed processing its scheduled microblock, allowing the system to schedule new transactions that may conflict with the completed microblock. It is safe to call this function multiple times for the same microblock or even if the bank tile does not have a previously scheduled microblock; in such cases, the function will return 0 and act as a no-op. This function must be called before scheduling another microblock to the same bank tile.
- **Inputs**:
    - `pack`: A pointer to a valid fd_pack_t object. The caller must ensure that this is a valid local join of a pack object.
    - `bank_tile`: An unsigned long representing the index of the bank tile. It must be within the range of bank tiles initialized for the pack object.
- **Output**: Returns 1 if the bank tile had an outstanding, previously scheduled microblock to mark as completed, otherwise returns 0.
- **See also**: [`fd_pack_microblock_complete`](fd_pack.c.driver.md#fd_pack_microblock_complete)  (Implementation)


---
### fd\_pack\_expire\_before<!-- {{#callable_declaration:fd_pack_expire_before}} -->
Deletes transactions with expiration times before a specified threshold.
- **Description**: Use this function to remove transactions from the pack object that have expired based on a given expiration threshold. This is useful for maintaining the relevance of the transaction pool by ensuring that only transactions with valid expiration times are retained. The function should be called with a valid pack object that the caller is joined to. It updates the expiration threshold of the pack object to the maximum of the current threshold and the provided value, ensuring that subsequent calls with the same or smaller values are no-ops.
- **Inputs**:
    - `pack`: A pointer to a valid fd_pack_t object that the caller is joined to. The pack object must not be null.
    - `expire_before`: An unsigned long value representing the expiration threshold. Transactions with expiration times strictly less than this value will be deleted.
- **Output**: Returns the number of transactions deleted as an unsigned long.
- **See also**: [`fd_pack_expire_before`](fd_pack.c.driver.md#fd_pack_expire_before)  (Implementation)


---
### fd\_pack\_delete\_transaction<!-- {{#callable_declaration:fd_pack_delete_transaction}} -->
Removes transactions with a specific signature from the transaction pool.
- **Description**: This function is used to delete all transactions from a transaction pool that match a given signature. It is useful when you need to ensure that no transactions with a specific signature remain in the pool, perhaps due to cancellation or replacement. The function iterates through the pool and removes each transaction that matches the provided signature. It is important to ensure that the `pack` object is properly initialized and that the `sig0` parameter is a valid signature before calling this function.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` object representing the transaction pool. It must be a valid, initialized local join of a pack object.
    - `sig0`: A constant pointer to an `fd_ed25519_sig_t` representing the signature of the transactions to be deleted. It must not be null and should point to a valid signature.
- **Output**: Returns the number of transactions that were successfully deleted from the pool.
- **See also**: [`fd_pack_delete_transaction`](fd_pack.c.driver.md#fd_pack_delete_transaction)  (Implementation)


---
### fd\_pack\_end\_block<!-- {{#callable_declaration:fd_pack_end_block}} -->
Resets the state of a pack object to prepare for the next block.
- **Description**: This function is used to reset various state variables and counters within a `fd_pack_t` object, preparing it for the next block of transactions. It should be called at the end of processing a block to ensure that the pack object is ready to handle new transactions without conflicts from the previous block. This function clears cumulative costs, resets counters, and updates internal states, ensuring that the pack object is in a clean state for the next block. It is important to call this function before starting to schedule new transactions for a new block.
- **Inputs**:
    - `pack`: A pointer to a `fd_pack_t` object. This must be a valid, non-null pointer to a pack object that the caller has joined. The function will modify the state of this object to reset it for the next block.
- **Output**: None
- **See also**: [`fd_pack_end_block`](fd_pack.c.driver.md#fd_pack_end_block)  (Implementation)


---
### fd\_pack\_clear\_all<!-- {{#callable_declaration:fd_pack_clear_all}} -->
Resets the state of the pack object, removing all pending transactions and resetting limits.
- **Description**: Use this function to completely reset a pack object, clearing all pending transactions and resetting any associated limits. This is useful when you need to start fresh with a new set of transactions or after processing a block. Ensure that the pack object is a valid local join before calling this function. It does not return any value and has no side effects beyond resetting the pack's state.
- **Inputs**:
    - `pack`: A pointer to a valid fd_pack_t object. The pack object must be a valid local join, and the caller retains ownership. Passing a null or invalid pointer results in undefined behavior.
- **Output**: None
- **See also**: [`fd_pack_clear_all`](fd_pack.c.driver.md#fd_pack_clear_all)  (Implementation)


---
### fd\_pack\_metrics\_write<!-- {{#callable_declaration:fd_pack_metrics_write}} -->
Writes periodic metric values to the metrics system.
- **Description**: This function is used to update the metrics system with the current state of various transaction counts and metrics related to the pack object. It should be called periodically to ensure that the metrics system reflects the latest state of the pack. The function requires that the pack object is a valid local join, meaning it has been properly initialized and joined by the caller. This function does not return any value and does not modify the pack object itself.
- **Inputs**:
    - `pack`: A pointer to a constant fd_pack_t object representing the pack whose metrics are to be written. The pack must be a valid local join, meaning it has been properly initialized and joined by the caller. The function does not modify the pack object.
- **Output**: None
- **See also**: [`fd_pack_metrics_write`](fd_pack.c.driver.md#fd_pack_metrics_write)  (Implementation)


---
### fd\_pack\_leave<!-- {{#callable_declaration:fd_pack_leave}} -->
Leaves a local join of a pack object.
- **Description**: Use this function to leave a local join of a pack object when it is no longer needed. This is typically done to clean up resources or to prepare for a different operation that does not require the current pack object. It is important to ensure that every successful join has a corresponding leave to maintain resource integrity.
- **Inputs**:
    - `pack`: A pointer to a valid fd_pack_t object that the caller is currently joined to. Must not be null. The function will return this pointer.
- **Output**: Returns the same pointer to the fd_pack_t object that was passed in.
- **See also**: [`fd_pack_leave`](fd_pack.c.driver.md#fd_pack_leave)  (Implementation)


---
### fd\_pack\_delete<!-- {{#callable_declaration:fd_pack_delete}} -->
Unformats a memory region used for a pack object and returns it to the caller.
- **Description**: This function is used to unformat a memory region that was previously formatted as a pack object, effectively returning the memory to the caller for other uses. It should be called when the pack object is no longer needed, ensuring that any resources associated with it are properly released. The function returns the original memory pointer, allowing the caller to reuse or deallocate the memory as needed. It is important to ensure that no operations are performed on the pack object after this function is called.
- **Inputs**:
    - `mem`: A pointer to the memory region that was used as a pack object. The pointer must not be null, and the memory should have been previously formatted by a function like fd_pack_new. The caller retains ownership of the memory.
- **Output**: Returns the original memory pointer passed to the function.
- **See also**: [`fd_pack_delete`](fd_pack.c.driver.md#fd_pack_delete)  (Implementation)


---
### fd\_pack\_verify<!-- {{#callable_declaration:fd_pack_verify}} -->
Verifies the integrity of a pack object by checking its invariants.
- **Description**: This function is primarily used for debugging purposes to ensure that a pack object maintains its internal consistency and invariants. It should be called when there is a need to verify the correctness of the pack's state, especially after complex operations or before critical processing steps. The function requires a scratch memory area that meets the same alignment and footprint constraints as the pack object. It returns 0 if all invariants are satisfied, or a negative value if any invariant is violated, logging a warning with details of the failure.
- **Inputs**:
    - `pack`: A pointer to a fd_pack_t object whose invariants are to be verified. It must be a valid local join of a pack object.
    - `scratch`: A pointer to a memory region used as scratch space during verification. It must meet the same alignment and footprint constraints as the pack object.
- **Output**: Returns 0 if all invariants are satisfied, or a negative value if any invariant is violated, with a warning logged detailing the failure.
- **See also**: [`fd_pack_verify`](fd_pack.c.driver.md#fd_pack_verify)  (Implementation)


