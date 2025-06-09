# Purpose
The provided C source code is a comprehensive implementation of a transaction packing system, likely intended for use in a blockchain or distributed ledger environment. This code is designed to manage and optimize the scheduling of transactions into blocks, ensuring efficient use of computational resources and adherence to various constraints such as cost limits, transaction priorities, and expiration times.

Key components of this code include the definition of several data structures and macros that facilitate the management of transactions. These structures include `fd_pack_ord_txn_t` for ordered transactions, `fd_pack_expq_t` for managing transaction expiration, and `fd_pack_penalty_treap_t` for handling transactions that compete for the same writable account. The code also defines a main structure, `fd_pack_t`, which encapsulates the state and configuration of the transaction packer, including limits on computational cost, data size, and microblock count per block. The code provides functions for inserting transactions and bundles, scheduling transactions into microblocks, handling transaction expiration, and managing the end of a block. Additionally, it includes mechanisms for handling conflicts, estimating transaction costs, and maintaining various metrics for performance monitoring. The code is structured to ensure that transactions are processed efficiently while respecting constraints and priorities, making it suitable for high-throughput environments where transaction ordering and resource management are critical.
# Imports and Dependencies

---
- `fd_pack.h`
- `fd_pack_cost.h`
- `fd_compute_budget_program.h`
- `fd_pack_bitset.h`
- `fd_pack_unwritable.h`
- `fd_chkdup.h`
- `fd_pack_tip_prog_blacklist.h`
- `math.h`
- `stddef.h`
- `../metrics/fd_metrics.h`
- `../../util/tmpl/fd_pool.c`
- `../../util/tmpl/fd_treap.c`
- `../../util/tmpl/fd_map_chain.c`
- `../../util/tmpl/fd_map_dynamic.c`
- `../../util/tmpl/fd_prq.c`


# Global Variables

---
### null\_addr
- **Type**: ``fd_acct_addr_t``
- **Description**: The `null_addr` is a static constant of type `fd_acct_addr_t`, initialized to zero. This suggests it represents a null or invalid account address in the context of the application.
- **Use**: It is used as a sentinel value to represent an invalid or uninitialized account address in various data structures and operations.


# Data Structures

---
### wrapped\_sig\_t
- **Type**: ``struct``
- **Members**:
    - `sig`: An instance of `fd_ed25519_sig_t` representing a digital signature.
- **Description**: The `wrapped_sig_t` structure is a simple wrapper around the `fd_ed25519_sig_t` type, encapsulating a single digital signature. This structure is used to provide a consistent interface for handling signatures within the broader context of the codebase, potentially allowing for easier integration with other components that expect a struct-based signature representation.


---
### fd\_pack\_private\_ord\_txn
- **Type**: `struct`
- **Members**:
    - `union`: A union containing different representations of a transaction, including a transaction pointer, an extended transaction pointer, and a signature structure.
    - `root`: An integer indicating which tree the transaction belongs to, using FD_ORD_TXN_ROOT_* values.
    - `sigmap_next`: A ushort indicating the next element in the sig2txn map chain.
    - `sigmap_prev`: A ushort indicating the previous element in the sig2txn map chain.
    - `expires_at`: A ulong representing the expiration time of the transaction.
    - `expq_idx`: A ulong storing the index in the expiration priority queue.
    - `rewards`: A uint representing the rewards in Lamports, aligned to 64 bytes.
    - `compute_est`: A uint representing the estimated compute units required.
    - `left`: A ushort indicating the left child in the treap.
    - `right`: A ushort indicating the right child in the treap.
    - `parent`: A ushort indicating the parent node in the treap.
    - `prio`: A ushort representing the priority in the treap.
    - `prev`: A ushort indicating the previous node in the treap.
    - `next`: A ushort indicating the next node in the treap.
    - `skip`: A ushort indicating how many times the transaction should be skipped before taking action.
    - `rw_bitset`: A bitset representing all accounts this transaction references.
    - `w_bitset`: A bitset representing accounts this transaction write-locks.
- **Description**: The `fd_pack_private_ord_txn` structure is a complex data structure used to manage and organize transactions within a system. It includes fields for handling transaction expiration, priority, and tree organization, as well as bitsets for tracking account references and write-locks. The structure is designed to be part of multiple trees and includes mechanisms for managing transaction order and priority efficiently. It is aligned to ensure optimal memory usage and performance, particularly in systems with high transaction throughput.


---
### fd\_pack\_ord\_txn\_t
- **Type**: `struct`
- **Members**:
    - `txn`: A union containing an alias for a transaction pointer and a transaction element pointer.
    - `root`: An integer indicating which tree the transaction is part of.
    - `sigmap_next`: A ushort for the next element in the signature map chain.
    - `sigmap_prev`: A ushort for the previous element in the signature map chain.
    - `expires_at`: A ulong representing the expiration time of the transaction.
    - `expq_idx`: A ulong storing the index in the expiration priority queue.
    - `rewards`: A uint representing the rewards in Lamports.
    - `compute_est`: A uint representing the estimated compute units.
    - `left`: A ushort for the left child in the treap.
    - `right`: A ushort for the right child in the treap.
    - `parent`: A ushort for the parent in the treap.
    - `prio`: A ushort for the priority in the treap.
    - `prev`: A ushort for the previous element in the treap.
    - `next`: A ushort for the next element in the treap.
    - `skip`: A ushort indicating how many times to skip the transaction.
    - `rw_bitset`: A bitset for all accounts this transaction references.
    - `w_bitset`: A bitset for accounts this transaction write-locks.
- **Description**: The `fd_pack_ord_txn_t` structure is a complex data structure used to manage transactions in a priority-based ordering system. It contains fields for managing transaction pointers, expiration times, and priority in a treap data structure. The structure also includes fields for managing the transaction's position in various data structures, such as signature maps and expiration queues. Additionally, it has fields for tracking rewards and compute estimates, as well as bitsets for managing account references and write-locks. This structure is designed to efficiently handle transactions in a system where transactions can be part of multiple trees and need to be ordered by priority and expiration.


---
### fd\_pack\_private\_addr\_use\_record
- **Type**: ``struct``
- **Members**:
    - `key`: account address.
    - `_`: anonymous union member for internal use.
    - `in_use_by`: bitmask indicating which banks are using the address.
    - `total_cost`: total cost in cost units (CUs).
    - `carried_cost`: cost carried in cost units.
    - `ref_cnt`: reference count in transactions.
    - `last_use_in`: last use in transactions.
- **Description**: The `fd_pack_private_addr_use_record` structure is used to manage and track the usage of account addresses within a system. It contains a key representing the account address and a union that can store various data related to the address's usage. This includes a bitmask indicating which banks are using the address, the total cost associated with the address in cost units, and additional details such as the carried cost, reference count, and the last transaction in which the address was used. This structure is essential for managing address usage efficiently, ensuring that addresses are not reused prematurely and that costs are tracked accurately.


---
### fd\_pack\_addr\_use\_t
- **Type**: `typedef`
- **Members**:
    - `key`: Stores the account address.
    - `_`: A union field used for different purposes based on context.
    - `in_use_by`: Bitmask indicating which banks are using the address.
    - `total_cost`: Tracks the total cost in cost units for transactions writing to the account.
    - `carried_cost`: Cost carried over in cost units.
    - `ref_cnt`: Reference count indicating how many transactions reference this account.
    - `last_use_in`: Indicates the last transaction that used this account.
- **Description**: The `fd_pack_addr_use_t` structure is used to manage and track the usage of account addresses within a transaction processing system. It serves three main purposes: recording when an address is in use and cannot be reused until certain conditions are met, tracking the cumulative cost of transactions that write to a specific account, and managing the write cost for accounts referenced by transactions in a bundle. The structure combines these functionalities to reduce code duplication and improve efficiency, despite the potential for increased complexity.


---
### fd\_pack\_expq
- **Type**: `struct`
- **Members**:
    - `expires_at`: Stores the expiration time of the transaction.
    - `txn`: Pointer to a transaction of type `fd_pack_ord_txn_t`.
- **Description**: The `fd_pack_expq` structure is used as an element in a priority queue to sort transactions by their expiration time. It maintains a reference to the transaction and its expiration time, ensuring that transactions can be efficiently managed and removed when they expire. This structure is part of a larger system that handles transaction scheduling and prioritization based on time constraints.


---
### fd\_pack\_expq\_t
- **Type**: `struct`
- **Members**:
    - `expires_at`: Stores the expiration time of the transaction.
    - `txn`: Pointer to the transaction associated with this expiration queue element.
- **Description**: The `fd_pack_expq_t` structure is an element of an expiration priority queue used to sort transactions by their timeout. It maintains a reference to the transaction (`txn`) and its expiration time (`expires_at`). This structure is part of a larger system that manages transaction scheduling and expiration, ensuring that transactions are processed or removed based on their expiration criteria. The priority queue is implemented as an array-based heap, which allows for efficient management of transaction expiration.


---
### fd\_pack\_bitset\_acct\_mapping
- **Type**: `struct`
- **Members**:
    - `key`: Stores the account address.
    - `ref_cnt`: Tracks the number of transactions referencing this account.
    - `first_instance`: Points to the first transaction instance referencing this account.
    - `first_instance_was_write`: Indicates if the first instance was a write operation.
    - `bit`: Represents the bit assigned to this account in the bitset.
- **Description**: The `fd_pack_bitset_acct_mapping` structure is used to map an account address to the number of transactions referencing it and to manage the bit assigned to it in a bitset. It includes fields to track the first transaction instance and whether it was a write operation, which is part of an optimization to avoid allocating a bit for accounts referenced only once. The `bit` field can take values within a specified range or special constants indicating specific conditions.


---
### fd\_pack\_bitset\_acct\_mapping\_t
- **Type**: `struct`
- **Members**:
    - `key`: Represents the account address.
    - `ref_cnt`: Stores the number of transactions referencing this account.
    - `first_instance`: Points to the first transaction instance referencing this account.
    - `first_instance_was_write`: Indicates if the first instance was a write operation.
    - `bit`: Holds the bit index reserved for this account in the bitset.
- **Description**: The `fd_pack_bitset_acct_mapping_t` structure is used within a dynamic map to associate an account address with the number of transactions that reference it and to manage a bitset index for efficient tracking. This structure optimizes the handling of accounts referenced only once by not allocating a bit for them, which is crucial for performance in systems with high transaction volumes.


---
### fd\_pack\_smallest
- **Type**: `struct`
- **Members**:
    - `cus`: Stores the smallest compute units (CUs) of a transaction in a treap.
    - `bytes`: Stores the smallest byte size of a transaction in a treap.
- **Description**: The `fd_pack_smallest` structure is used to keep track of the smallest transaction in terms of compute units and byte size within a treap. This allows the system to quickly determine if a transaction can fit within the remaining space of a block, optimizing the scheduling process by potentially skipping the heap if the smallest transaction is too large. The structure maintains conservative estimates to ensure efficient management of transaction scheduling.


---
### fd\_pack\_smallest\_t
- **Type**: `struct`
- **Members**:
    - `cus`: Stores the smallest transaction size in compute units (CUs) in a treap.
    - `bytes`: Stores the smallest transaction size in bytes in a treap.
- **Description**: The `fd_pack_smallest_t` structure is used to keep track of the smallest transaction in terms of compute units and bytes within a treap. This allows the system to quickly determine if there is enough space left in a block to accommodate the smallest transaction, thereby optimizing the scheduling process by potentially skipping the heap if the remaining space is insufficient.


---
### fd\_pack\_penalty\_treap
- **Type**: `struct`
- **Members**:
    - `key`: A unique account address associated with the penalty treap.
    - `penalty_treap`: An array of treap_t structures, representing a treap for managing penalties.
- **Description**: The `fd_pack_penalty_treap` structure is designed to manage transactions that write to a specific account address, identified by `key`. It contains a treap, `penalty_treap`, which is used to store and manage these transactions based on their priority. This structure is part of a larger system that handles transaction scheduling and prioritization, particularly for accounts that are heavily contended. The treap allows for efficient insertion, deletion, and access to transactions, ensuring that the most lucrative transactions are prioritized for scheduling when the account becomes available.


---
### fd\_pack\_penalty\_treap\_t
- **Type**: `struct`
- **Members**:
    - `key`: The account address associated with this penalty treap.
    - `penalty_treap`: An array of treap_t structures representing the penalty treap for transactions writing to the associated account.
- **Description**: The `fd_pack_penalty_treap_t` structure is designed to manage transactions that write to a specific account address when that account is highly contended. It contains a key, which is the account address, and a penalty treap, which is a data structure used to store and manage transactions that write to this account. The penalty treap helps in organizing transactions by priority, allowing the system to efficiently manage and schedule transactions that are in contention for the same account resources. This structure is part of a larger system that handles transaction scheduling and prioritization in a blockchain or distributed ledger environment.


---
### fd\_pack\_private
- **Type**: `struct`
- **Members**:
    - `pack_depth`: Represents the depth of the pack.
    - `bundle_meta_sz`: Size of the bundle metadata; if 0, bundles are disabled.
    - `bank_tile_cnt`: Number of bank tiles.
    - `lim`: Array of fd_pack_limits_t structures defining limits.
    - `pending_txn_cnt`: Count of pending transactions across all treaps.
    - `microblock_cnt`: Number of microblocks generated in the current block.
    - `data_bytes_consumed`: Amount of data consumed in the current block.
    - `rng`: Pointer to a random number generator.
    - `cumulative_block_cost`: Cumulative cost of the block.
    - `cumulative_vote_cost`: Cumulative cost of votes in the block.
    - `expire_before`: Threshold time before which transactions are expired.
    - `outstanding_microblock_mask`: Bitmask indicating which bank tiles have outstanding microblocks.
    - `pool`: Pointer to a pool of ordered transactions.
    - `pending`: Treap of pending transactions sorted by priority.
    - `pending_votes`: Treap of pending votes sorted by priority.
    - `pending_bundles`: Treap of pending bundles sorted by priority.
    - `penalty_treaps`: Pointer to penalty treaps for hotly contended accounts.
    - `initializer_bundle_state`: State of the initializer bundle state machine.
    - `pending_bundle_cnt`: Number of bundles in pending_bundles.
    - `relative_bundle_idx`: Index of bundles inserted since the last empty pending_bundles.
    - `pending_smallest`: Estimate of the smallest transaction in the pending treap.
    - `pending_votes_smallest`: Estimate of the smallest transaction in the pending_votes treap.
    - `expiration_q`: Pointer to an expiration queue for transactions.
    - `acct_in_use`: Map from account addresses to usage bitmask.
    - `bitset_rw_in_use`: Bitset for accounts in use for read or write.
    - `bitset_w_in_use`: Bitset for accounts in use for write only.
    - `writer_costs`: Map from account addresses to the sum of transaction costs writing to them.
    - `written_list`: List of pointers to used elements in writer_costs.
    - `written_list_cnt`: Count of elements in written_list.
    - `written_list_max`: Maximum size of written_list.
    - `signature_map`: Map for deleting transactions by signature.
    - `bundle_temp_map`: Temporary map for storing account usage in bundles.
    - `use_by_bank`: Array of account usage by bank tile.
    - `use_by_bank_cnt`: Count of accounts used by each bank tile.
    - `use_by_bank_txn`: Array of transaction indices for each bank tile.
    - `txn_per_microblock`: Histogram of transactions per microblock.
    - `vote_per_microblock`: Histogram of votes per microblock.
    - `scheduled_cus_per_block`: Histogram of scheduled compute units per block.
    - `rebated_cus_per_block`: Histogram of rebated compute units per block.
    - `net_cus_per_block`: Histogram of net compute units per block.
    - `pct_cus_per_block`: Histogram of percentage compute units per block.
    - `cumulative_rebated_cus`: Cumulative rebated compute units.
    - `compressed_slot_number`: Slot number that advances with each new slot.
    - `bitset_avail`: Stack of available bits for account address representation.
    - `bitset_avail_cnt`: Count of available bits in bitset_avail.
    - `acct_to_bitset`: Map from account addresses to bitset information.
    - `chkdup`: Scratch memory for internal processing.
    - `bundle_meta`: Array for bundle metadata, parallel to the pool.
- **Description**: The `fd_pack_private` structure is a complex data structure used to manage and schedule transactions in a blockchain-like system. It maintains various treaps for pending transactions, votes, and bundles, and uses maps and bitsets to track account usage and transaction costs. The structure also handles transaction expiration, microblock generation, and manages resources like compute units and data bytes within specified limits. It includes mechanisms for handling hotly contended accounts through penalty treaps and supports bundle scheduling with metadata management. The structure is designed to efficiently manage transaction scheduling and resource allocation in a high-throughput environment.


---
### fd\_pack\_t
- **Type**: `typedef struct fd_pack_private fd_pack_t;`
- **Members**:
    - `pack_depth`: The depth of the pack, indicating the maximum number of transactions it can handle.
    - `bundle_meta_sz`: Size of the metadata associated with each bundle.
    - `bank_tile_cnt`: Number of bank tiles available for processing transactions.
    - `lim`: Limits for various parameters like max transactions per microblock, max cost per block, etc.
    - `pending_txn_cnt`: Count of transactions currently pending in the pack.
    - `microblock_cnt`: Number of microblocks generated in the current block.
    - `data_bytes_consumed`: Amount of data consumed in the current block.
    - `rng`: Random number generator used for various probabilistic operations.
    - `cumulative_block_cost`: Cumulative cost of transactions in the current block.
    - `cumulative_vote_cost`: Cumulative cost of vote transactions in the current block.
    - `expire_before`: Timestamp before which transactions are considered expired.
    - `outstanding_microblock_mask`: Bitmask indicating which banking tiles have outstanding microblocks.
    - `pool`: Pool of ordered transactions available for scheduling.
    - `pending`: Treap of pending transactions sorted by priority.
    - `pending_votes`: Treap of pending vote transactions sorted by priority.
    - `pending_bundles`: Treap of pending bundles sorted by priority.
    - `penalty_treaps`: Map of penalty treaps for transactions writing to hotly contested accounts.
    - `initializer_bundle_state`: State of the initialization bundle state machine.
    - `pending_bundle_cnt`: Number of bundles currently pending.
    - `relative_bundle_idx`: Index of the current bundle relative to the last empty state.
    - `pending_smallest`: Estimate of the smallest transaction in terms of cost units and bytes.
    - `pending_votes_smallest`: Estimate of the smallest vote transaction in terms of cost units and bytes.
    - `expiration_q`: Priority queue of transactions sorted by expiration time.
    - `acct_in_use`: Map of account addresses to their usage status by bank tiles.
    - `bitset_rw_in_use`: Bitset indicating accounts in use for read or write.
    - `bitset_w_in_use`: Bitset indicating accounts in use for write only.
    - `writer_costs`: Map of account addresses to the sum of costs of transactions writing to them.
    - `written_list`: List of accounts that have been written to, used for clearing writer costs.
    - `written_list_cnt`: Count of accounts in the written list.
    - `written_list_max`: Maximum number of accounts that can be tracked in the written list.
    - `signature_map`: Map of transaction signatures to their corresponding transactions.
    - `bundle_temp_map`: Temporary map used during bundle scheduling to track account usage.
    - `use_by_bank`: Array tracking account usage by each bank tile.
    - `use_by_bank_cnt`: Count of accounts used by each bank tile.
    - `use_by_bank_txn`: Array tracking transaction usage by each bank tile.
    - `txn_per_microblock`: Histogram of transactions per microblock.
    - `vote_per_microblock`: Histogram of votes per microblock.
    - `scheduled_cus_per_block`: Histogram of scheduled compute units per block.
    - `rebated_cus_per_block`: Histogram of rebated compute units per block.
    - `net_cus_per_block`: Histogram of net compute units per block.
    - `pct_cus_per_block`: Histogram of percentage of compute units per block.
    - `cumulative_rebated_cus`: Cumulative rebated compute units.
    - `compressed_slot_number`: Number indicating the current slot in a compressed format.
    - `bitset_avail`: Stack of available bits for representing account addresses.
    - `bitset_avail_cnt`: Count of available bits in the bitset.
    - `acct_to_bitset`: Map of account addresses to their bitset representation.
    - `chkdup`: Scratch memory for duplicate checking.
    - `bundle_meta`: Array of metadata associated with each bundle.
- **Description**: The `fd_pack_t` structure is a complex data structure designed to manage and schedule transactions in a high-performance environment. It maintains a pool of transactions, organized into various treaps and maps, to efficiently handle transaction scheduling, expiration, and prioritization. The structure includes mechanisms for managing account usage, tracking transaction costs, and handling bundles of transactions. It also incorporates various limits and state machines to ensure efficient operation within defined constraints. The structure is optimized for performance, with careful management of memory and computational resources.


---
### release\_result\_t
- **Type**: ``struct``
- **Members**:
    - `clear_rw_bit`: A `ushort` indicating which bit to clear in the read-write bitset.
    - `clear_w_bit`: A `ushort` indicating which bit to clear in the write bitset.
- **Description**: The `release_result_t` structure is used to store the results of releasing a bit reference in a bitset, specifically indicating which bits should be cleared in the read-write and write bitsets. This is part of a mechanism to manage and track the usage of account references in a transaction processing system, ensuring that resources are properly released and conflicts are avoided.


---
### sched\_return\_t
- **Type**: `struct`
- **Members**:
    - `cus_scheduled`: Stores the number of compute units scheduled.
    - `txns_scheduled`: Stores the number of transactions scheduled.
    - `bytes_scheduled`: Stores the number of bytes scheduled.
- **Description**: The `sched_return_t` structure is used to encapsulate the results of a scheduling operation, specifically within a transaction scheduling context. It holds three fields: `cus_scheduled`, `txns_scheduled`, and `bytes_scheduled`, which respectively track the number of compute units, transactions, and bytes that have been scheduled. This structure is likely used to return or log the outcome of a scheduling function, providing a concise summary of the resources allocated during the scheduling process.


# Functions

---
### fd\_pack\_footprint<!-- {{#callable:fd_pack_footprint}} -->
The `fd_pack_footprint` function calculates the memory footprint required for a transaction pack based on various parameters such as pack depth, bundle metadata size, bank tile count, and limits.
- **Inputs**:
    - `pack_depth`: The depth of the transaction pack, representing the maximum number of transactions that can be handled.
    - `bundle_meta_sz`: The size of the metadata for each bundle, used to determine if bundles are enabled.
    - `bank_tile_cnt`: The number of bank tiles, which should be between 1 and FD_PACK_MAX_BANK_TILES.
    - `limits`: A pointer to a structure containing various limits for the pack, such as maximum transactions per microblock and maximum cost per block.
- **Control Flow**:
    - Check if the bank_tile_cnt is zero or exceeds FD_PACK_MAX_BANK_TILES, returning 0 if true.
    - Check if the pack_depth is less than 4, returning 0 if true.
    - Determine if bundles are enabled based on the bundle_meta_sz.
    - Calculate various parameters such as extra depth, maximum accounts in treap, maximum transactions per microblock, and others based on the inputs and limits.
    - Calculate the size of various components like pools, maps, and lists using helper functions and append them to the layout.
    - Return the final calculated layout size using FD_LAYOUT_FINI.
- **Output**: Returns the calculated memory footprint as an unsigned long integer, representing the total size required for the transaction pack.


---
### fd\_pack\_new<!-- {{#callable:fd_pack_new}} -->
The `fd_pack_new` function initializes a new `fd_pack_t` structure with specified parameters and allocates necessary resources for transaction processing.
- **Inputs**:
    - `mem`: A pointer to the memory location where the `fd_pack_t` structure and its associated resources will be allocated.
    - `pack_depth`: The maximum number of transactions that can be held in the pack at any time.
    - `bundle_meta_sz`: The size of metadata associated with each bundle; if zero, bundles are disabled.
    - `bank_tile_cnt`: The number of bank tiles available for processing transactions.
    - `limits`: A pointer to a `fd_pack_limits_t` structure containing various limits for transaction processing, such as maximum transactions per microblock and maximum cost per block.
    - `rng`: A pointer to a random number generator used for various probabilistic operations within the function.
- **Control Flow**:
    - Determine if bundles are enabled based on `bundle_meta_sz` and calculate `extra_depth` accordingly.
    - Calculate various maximums and limits based on input parameters and constants, such as `max_acct_in_treap`, `max_txn_per_mblk`, and `max_acct_in_flight`.
    - Initialize a scratch allocator with the provided memory and allocate space for the `fd_pack_t` structure and its associated resources.
    - Set initial values for the `fd_pack_t` structure fields, including limits, counters, and random number generator.
    - Initialize various data structures such as pools, maps, and treaps for managing transactions, penalties, and account usage.
    - Return the pointer to the allocated memory, which now contains the initialized `fd_pack_t` structure.
- **Output**: Returns a pointer to the initialized memory location containing the `fd_pack_t` structure and its resources.
- **Functions called**:
    - [`fd_chkdup_new`](fd_chkdup.h.driver.md#fd_chkdup_new)


---
### fd\_pack\_join<!-- {{#callable:fd_pack_join}} -->
The `fd_pack_join` function initializes and joins various data structures for transaction processing in a memory region.
- **Inputs**:
    - `mem`: A pointer to a memory region where the data structures will be initialized and joined.
- **Control Flow**:
    - Initialize a scratch allocator with the provided memory region.
    - Allocate and join a `fd_pack_t` structure from the scratch allocator.
    - Determine if bundles are enabled based on the `bundle_meta_sz` field of the `fd_pack_t` structure.
    - Calculate various parameters such as `pack_depth`, `extra_depth`, `bank_tile_cnt`, and `max_txn_per_microblock` based on the `fd_pack_t` structure and whether bundles are enabled.
    - Join various data structures such as `trp_pool`, `penalty_map`, `expq`, `acct_uses`, `sig2txn`, and `bitset_map` using the scratch allocator and calculated parameters.
    - Set a metric gauge for pending transactions heap size.
    - Return the joined `fd_pack_t` structure.
- **Output**: A pointer to the joined `fd_pack_t` structure, which is used for transaction processing.


---
### fd\_pack\_estimate\_rewards\_and\_compute<!-- {{#callable:fd_pack_estimate_rewards_and_compute}} -->
The function `fd_pack_estimate_rewards_and_compute` calculates the estimated rewards and computational costs for a transaction and updates the output structure with these values.
- **Inputs**:
    - `txne`: A pointer to an `fd_txn_e_t` structure representing the transaction entry to be processed.
    - `out`: A pointer to an `fd_pack_ord_txn_t` structure where the computed rewards and cost estimates will be stored.
- **Control Flow**:
    - Retrieve the transaction from the transaction entry pointer `txne`.
    - Calculate the initial signature rewards based on the number of signatures in the transaction.
    - Call [`fd_pack_compute_cost`](fd_pack_cost.h.driver.md#fd_pack_compute_cost) to estimate the computational cost and retrieve additional transaction details.
    - Check if the cost estimate is valid; if not, return 0 indicating failure.
    - Adjust the signature rewards by adding the rewards for precompiled signatures.
    - Calculate the total rewards by adding priority rewards to the signature rewards, ensuring it does not exceed `UINT_MAX`.
    - Update the output structure `out` with the calculated rewards, compute estimate, and execution cost details.
    - Return 1 if the transaction is a simple vote, otherwise return 2.
- **Output**: Returns an integer indicating success (1 for a simple vote transaction, 2 for a non-vote transaction) or failure (0 if cost estimation fails).
- **Functions called**:
    - [`fd_pack_compute_cost`](fd_pack_cost.h.driver.md#fd_pack_compute_cost)


---
### fd\_pack\_can\_fee\_payer\_afford<!-- {{#callable:fd_pack_can_fee_payer_afford}} -->
The function `fd_pack_can_fee_payer_afford` is a stub that always returns 1, indicating that the fee payer can afford the transaction price.
- **Inputs**:
    - `acct_addr`: A pointer to a constant `fd_acct_addr_t` structure representing the account address of the fee payer.
    - `price`: An unsigned long integer representing the price of the transaction in lamports.
- **Control Flow**:
    - The function takes two parameters: `acct_addr` and `price`, but does not use them in its logic.
    - It explicitly casts `acct_addr` and `price` to void to suppress unused variable warnings.
    - The function returns the integer 1, indicating that the fee payer can afford the transaction price.
- **Output**: The function returns an integer value of 1, indicating that the fee payer can afford the transaction price.


---
### fd\_pack\_insert\_txn\_init<!-- {{#callable:fd_pack_insert_txn_init}} -->
The `fd_pack_insert_txn_init` function initializes a transaction insertion by acquiring a transaction element from a pool within a pack.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure, which represents the pack containing the pool from which a transaction element is to be acquired.
- **Control Flow**:
    - The function calls `trp_pool_ele_acquire` with the pool from the `pack` structure to acquire a transaction element.
    - It returns the `txn_e` member of the acquired transaction element.
- **Output**: A pointer to an `fd_txn_e_t` structure, representing the acquired transaction element.


---
### fd\_pack\_insert\_txn\_cancel<!-- {{#callable:fd_pack_insert_txn_cancel}} -->
The `fd_pack_insert_txn_cancel` function releases a transaction element back to the pool in a pack structure.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure, representing the pack from which the transaction element is to be released.
    - `txn`: A pointer to an `fd_txn_e_t` structure, representing the transaction element to be released back to the pool.
- **Control Flow**:
    - The function calls `trp_pool_ele_release` with the pack's pool and the transaction cast to `fd_pack_ord_txn_t` to release the transaction element back to the pool.
- **Output**: This function does not return any value.


---
### delete\_worst<!-- {{#callable:delete_worst}} -->
The `delete_worst` function attempts to delete the worst transaction from a set of transaction pools based on a probabilistic sampling method and a threshold score.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the transaction pool and related data.
    - `threshold_score`: A float representing the score threshold below which a transaction is considered for deletion.
    - `is_vote`: An integer flag indicating whether the transaction is a vote (non-zero) or not (zero).
- **Control Flow**:
    - Initialize `worst_score` to the maximum float value and `worst` to NULL.
    - Iterate 8 times to sample transactions from the pool.
    - For each sample, check if it is free; if so, find the next non-free transaction.
    - Determine the type of transaction (pending, vote, bundle, penalty) and calculate a multiplier based on its type and conditions.
    - Calculate the 'delete me' score for the transaction using the multiplier and its rewards and compute estimate.
    - Update `worst` and `worst_score` if the current transaction has a lower score than the current worst.
    - After sampling, check if a worst transaction was found and if its score is below the threshold.
    - If a worst transaction is found and its score is below the threshold, delete it using [`delete_transaction`](#delete_transaction) and return 1.
    - If no suitable transaction is found for deletion, return 0.
- **Output**: Returns 1 if a transaction was successfully deleted, 0 otherwise.
- **Functions called**:
    - [`delete_transaction`](#delete_transaction)


---
### validate\_transaction<!-- {{#callable:validate_transaction}} -->
The `validate_transaction` function checks if a transaction meets certain criteria to be considered valid for processing.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure, which contains the state and configuration for transaction processing.
    - `ord`: A pointer to a constant `fd_pack_ord_txn_t` structure, representing the ordered transaction to be validated.
    - `txn`: A pointer to a constant `fd_txn_t` structure, representing the transaction to be validated.
    - `accts`: A pointer to a constant `fd_acct_addr_t` structure, representing the account addresses involved in the transaction.
    - `alt_adj`: A pointer to a constant `fd_acct_addr_t` structure, representing alternative adjusted account addresses.
    - `check_bundle_blacklist`: An integer flag indicating whether to check the transaction against a bundle blacklist.
- **Control Flow**:
    - Initialize `writes_to_sysvar` to 0 and iterate over writable accounts in the transaction to check if any are system variables, updating `writes_to_sysvar` accordingly.
    - Initialize `bundle_blacklist` to 0 and, if `check_bundle_blacklist` is true, iterate over all accounts in the transaction to check against a blacklist, updating `bundle_blacklist` accordingly.
    - Retrieve the alternative accounts and duplicate check structure from the `ord` and `pack` structures, respectively.
    - Check if the transaction is unfunded by calling [`fd_pack_can_fee_payer_afford`](#fd_pack_can_fee_payer_afford) and return `FD_PACK_INSERT_REJECT_UNAFFORDABLE` if it cannot afford the transaction.
    - Check if the transaction's compute estimate exceeds the maximum allowed per block and return `FD_PACK_INSERT_REJECT_TOO_LARGE` if it does.
    - Check if the transaction loads too many accounts and return `FD_PACK_INSERT_REJECT_ACCOUNT_CNT` if it exceeds the limit.
    - Check for duplicate account addresses using [`fd_chkdup_check`](fd_chkdup.h.driver.md#fd_chkdup_check) and return `FD_PACK_INSERT_REJECT_DUPLICATE_ACCT` if duplicates are found.
    - Check if the transaction attempts to write to a system variable and return `FD_PACK_INSERT_REJECT_WRITES_SYSVAR` if it does.
    - Check if the transaction violates bundle rules and return `FD_PACK_INSERT_REJECT_BUNDLE_BLACKLIST` if it does.
    - Return 0 if all checks pass, indicating the transaction is valid.
- **Output**: Returns an integer indicating the validation result: 0 for success, or a specific rejection code if the transaction fails any validation checks.
- **Functions called**:
    - [`fd_pack_tip_prog_check_blacklist`](fd_pack_tip_prog_blacklist.h.driver.md#fd_pack_tip_prog_check_blacklist)
    - [`fd_pack_can_fee_payer_afford`](#fd_pack_can_fee_payer_afford)
    - [`fd_chkdup_check`](fd_chkdup.h.driver.md#fd_chkdup_check)


---
### populate\_bitsets<!-- {{#callable:populate_bitsets}} -->
The `populate_bitsets` function updates bitsets for read-write and write access for a transaction, calculates penalties for account access, and returns the cumulative penalty.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure, which contains data structures and state information for transaction processing.
    - `ord`: A pointer to an `fd_pack_ord_txn_t` structure, representing an ordered transaction with associated metadata.
    - `penalties`: An array of `ushort` to store penalty values for accounts that exceed a reference count threshold.
    - `penalty_idx`: An array of `uchar` to store indices of accounts in the transaction that incur penalties.
- **Control Flow**:
    - Initialize read-write and write bitsets for the transaction to zero.
    - Retrieve the transaction and payload from the `ord` structure.
    - Get account addresses and adjust for alternate accounts if necessary.
    - Iterate over writable accounts in the transaction.
    - For each writable account, query or insert into the bitset map to get or create a mapping.
    - If the account is a first instance, assign a bit from the available bitset and update the first instance's bitsets.
    - Calculate penalties for accounts exceeding the reference count threshold and update the penalties and penalty_idx arrays.
    - Increment the reference count and update the transaction's bitsets with the assigned bit.
    - Repeat similar steps for readonly accounts, skipping unwritable accounts.
    - Return the cumulative penalty calculated from the penalties array.
- **Output**: Returns an `ulong` representing the cumulative penalty for the transaction based on account access.


---
### fd\_pack\_insert\_txn\_fini<!-- {{#callable:fd_pack_insert_txn_fini}} -->
The `fd_pack_insert_txn_fini` function finalizes the insertion of a transaction into a transaction pack, handling validation, priority management, and insertion into appropriate data structures.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the transaction pack where the transaction will be inserted.
    - `txne`: A pointer to an `fd_txn_e_t` structure representing the transaction to be finalized and inserted.
    - `expires_at`: An unsigned long integer representing the expiration time of the transaction.
- **Control Flow**:
    - Cast `txne` to `fd_pack_ord_txn_t` and extract transaction details.
    - Estimate rewards and compute cost using [`fd_pack_estimate_rewards_and_compute`](#fd_pack_estimate_rewards_and_compute); reject if estimation fails.
    - Set the transaction's expiration time and determine if it is a vote.
    - Validate the transaction using [`validate_transaction`](#validate_transaction); reject if validation fails.
    - Check if the transaction has already expired; reject if so.
    - If the pack is full, attempt to delete the worst transaction to make space; reject if unable to do so.
    - Clear specific flags in the transaction and set the skip count.
    - Populate bitsets for account references and determine penalties.
    - Determine the appropriate treap for insertion based on penalties and whether the transaction is a vote.
    - Insert the transaction into the signature map and expiration queue.
    - Insert the transaction into the determined treap and return the appropriate acceptance code.
- **Output**: Returns an integer indicating the result of the insertion, which could be an acceptance or rejection code based on various conditions.
- **Functions called**:
    - [`fd_pack_estimate_rewards_and_compute`](#fd_pack_estimate_rewards_and_compute)
    - [`validate_transaction`](#validate_transaction)
    - [`delete_worst`](#delete_worst)
    - [`populate_bitsets`](#populate_bitsets)


---
### fd\_pack\_insert\_bundle\_init<!-- {{#callable:fd_pack_insert_bundle_init}} -->
The `fd_pack_insert_bundle_init` function initializes a bundle of transactions for insertion into a transaction pack by acquiring transaction elements from a pool.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the transaction pack where the bundle will be inserted.
    - `bundle`: A pointer to an array of `fd_txn_e_t*` where the acquired transaction elements will be stored.
    - `txn_cnt`: An unsigned long representing the number of transactions to be included in the bundle.
- **Control Flow**:
    - Check that the number of transactions (`txn_cnt`) does not exceed the maximum allowed per bundle (`FD_PACK_MAX_TXN_PER_BUNDLE`).
    - Ensure that the pool has enough free elements to accommodate the requested number of transactions (`txn_cnt`).
    - Iterate over the number of transactions (`txn_cnt`) and acquire each transaction element from the pool, storing it in the `bundle` array.
- **Output**: Returns a pointer to the `bundle` array containing the initialized transaction elements.


---
### fd\_pack\_insert\_bundle\_cancel<!-- {{#callable:fd_pack_insert_bundle_cancel}} -->
The `fd_pack_insert_bundle_cancel` function releases a specified number of transaction elements from a pool in reverse order.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure, representing the pack from which transaction elements are to be released.
    - `bundle`: A constant pointer to an array of `fd_txn_e_t` pointers, representing the bundle of transactions to be released.
    - `txn_cnt`: An unsigned long integer representing the number of transactions in the bundle to be released.
- **Control Flow**:
    - Iterate over the range from 0 to `txn_cnt` (exclusive).
    - For each iteration, calculate the index of the transaction to be released as `txn_cnt-1-i`.
    - Call `trp_pool_ele_release` to release the transaction element at the calculated index from the pool.
- **Output**: This function does not return a value; it performs its operation by releasing transaction elements from the pool.


---
### fd\_pack\_insert\_bundle\_fini<!-- {{#callable:fd_pack_insert_bundle_fini}} -->
The `fd_pack_insert_bundle_fini` function finalizes the insertion of a transaction bundle into a pack, handling validation, priority checks, and potential replacement of existing transactions.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the transaction pack where the bundle is to be inserted.
    - `bundle`: A pointer to an array of `fd_txn_e_t` pointers, representing the transactions in the bundle to be inserted.
    - `txn_cnt`: An unsigned long representing the number of transactions in the bundle.
    - `expires_at`: An unsigned long indicating the expiration time for the transactions in the bundle.
    - `initializer_bundle`: An integer flag indicating whether the bundle is an initializer bundle.
    - `bundle_meta`: A pointer to constant void data representing metadata associated with the bundle.
- **Control Flow**:
    - Initialize error status to 0.
    - Check if the bundle exceeds the allowed number of pending bundles and set error if so.
    - Check if the bundle is expired and set error if so.
    - Iterate over each transaction in the bundle to validate and estimate rewards and compute costs.
    - If any transaction fails validation or estimation, set error and cancel the bundle insertion.
    - If the bundle is an initializer and there are existing pending bundles, delete the previous initializer bundle if necessary.
    - While the total pending transactions exceed the pack depth, delete the worst transaction to make space.
    - If the bundle metadata is provided, copy it to the pack's metadata storage.
    - Insert the bundle into the pending bundles treap, adjusting the relative bundle index.
    - Return the appropriate status code based on whether any replacements occurred.
- **Output**: Returns an integer status code indicating the result of the bundle insertion, such as success, replacement, or specific rejection reasons.
- **Functions called**:
    - [`fd_pack_estimate_rewards_and_compute`](#fd_pack_estimate_rewards_and_compute)
    - [`validate_transaction`](#validate_transaction)
    - [`fd_pack_insert_bundle_cancel`](#fd_pack_insert_bundle_cancel)
    - [`delete_transaction`](#delete_transaction)
    - [`delete_worst`](#delete_worst)
    - [`insert_bundle_impl`](#insert_bundle_impl)


---
### insert\_bundle\_impl<!-- {{#callable:insert_bundle_impl}} -->
The `insert_bundle_impl` function inserts a bundle of transactions into a pending bundle treap, assigning rewards and updating various data structures for transaction management.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure, which contains the state and data structures for managing transaction bundles.
    - `bundle_idx`: An unsigned long integer representing the index of the bundle being inserted, used to calculate rewards.
    - `txn_cnt`: An unsigned long integer indicating the number of transactions in the bundle.
    - `bundle`: A pointer to an array of `fd_pack_ord_txn_t` pointers, representing the transactions in the bundle.
    - `expires_at`: An unsigned long integer specifying the expiration time for the transactions in the bundle.
- **Control Flow**:
    - Initialize `prev_reward` and `prev_cost` based on the bundle index and constants.
    - Iterate over the transactions in the bundle from last to first.
    - For each transaction, calculate and assign the `rewards` based on `prev_reward` and `prev_cost`.
    - Set the transaction's `root` to `FD_ORD_TXN_ROOT_PENDING_BUNDLE`.
    - Update `prev_reward` and `prev_cost` with the current transaction's `rewards` and `compute_est`, respectively.
    - Call [`populate_bitsets`](#populate_bitsets) to update bitsets for the transaction, though penalty information is not used for bundles.
    - Insert the transaction into the `pending_bundles` treap and increment the `pending_txn_cnt`.
    - Insert the transaction into the `signature_map` for quick lookup by signature.
    - Create a temporary expiration queue element and insert it into the `expiration_q`.
- **Output**: The function does not return a value; it modifies the state of the `pack` structure by inserting transactions into the pending bundles treap and updating related data structures.
- **Functions called**:
    - [`populate_bitsets`](#populate_bitsets)


---
### fd\_pack\_peek\_bundle\_meta<!-- {{#callable:fd_pack_peek_bundle_meta}} -->
The `fd_pack_peek_bundle_meta` function retrieves metadata for the most recent non-initializer bundle in a pack, if available.
- **Inputs**:
    - `pack`: A pointer to a constant `fd_pack_t` structure representing the pack from which to retrieve the bundle metadata.
- **Control Flow**:
    - Retrieve the `initializer_bundle_state` from the `pack` structure.
    - Check if the `initializer_bundle_state` is either `FD_PACK_IB_STATE_PENDING` or `FD_PACK_IB_STATE_FAILED`; if so, return `NULL`.
    - Initialize a reverse iterator for the `pending_bundles` treap in the `pack`.
    - Check if the iterator indicates the treap is empty; if so, return `NULL`.
    - Retrieve the current element from the iterator, which is a `fd_pack_ord_txn_t` structure.
    - Check if the transaction is an initializer bundle by examining its flags; if so, return `NULL`.
    - Calculate and return the pointer to the bundle metadata using the current iterator index and the `bundle_meta_sz` from the `pack`.
- **Output**: A pointer to the metadata of the most recent non-initializer bundle in the pack, or `NULL` if no such bundle is available.


---
### fd\_pack\_set\_initializer\_bundles\_ready<!-- {{#callable:fd_pack_set_initializer_bundles_ready}} -->
The function `fd_pack_set_initializer_bundles_ready` sets the state of the initializer bundle in the `fd_pack_t` structure to 'READY'.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure, which represents the pack data structure whose initializer bundle state is to be set to 'READY'.
- **Control Flow**:
    - The function accesses the `initializer_bundle_state` field of the `fd_pack_t` structure pointed to by `pack`.
    - It assigns the value `FD_PACK_IB_STATE_READY` to the `initializer_bundle_state` field.
- **Output**: The function does not return any value; it modifies the state of the `fd_pack_t` structure in place.


---
### fd\_pack\_metrics\_write<!-- {{#callable:fd_pack_metrics_write}} -->
The `fd_pack_metrics_write` function updates various metrics related to pending transactions in a `fd_pack_t` structure.
- **Inputs**:
    - `pack`: A pointer to a constant `fd_pack_t` structure representing the pack whose metrics are to be updated.
- **Control Flow**:
    - Calculate the number of pending regular transactions using `treap_ele_cnt` on `pack->pending` and store it in `pending_regular`.
    - Calculate the number of pending vote transactions using `treap_ele_cnt` on `pack->pending_votes` and store it in `pending_votes`.
    - Calculate the number of pending bundle transactions using `treap_ele_cnt` on `pack->pending_bundles` and store it in `pending_bundle`.
    - Calculate the number of conflicting transactions by subtracting `pending_votes`, `pending_bundle`, and the count of `pack->pending` from `pack->pending_txn_cnt`.
    - Update the metric `AVAILABLE_TRANSACTIONS_ALL` with `pack->pending_txn_cnt`.
    - Update the metric `AVAILABLE_TRANSACTIONS_REGULAR` with `pending_regular`.
    - Update the metric `AVAILABLE_TRANSACTIONS_VOTES` with `pending_votes`.
    - Update the metric `AVAILABLE_TRANSACTIONS_CONFLICTING` with `conflicting`.
    - Update the metric `AVAILABLE_TRANSACTIONS_BUNDLES` with `pending_bundle`.
    - Update the metric `SMALLEST_PENDING_TRANSACTION` with `pack->pending_smallest->cus`.
- **Output**: The function does not return any value; it updates metrics using the `FD_MGAUGE_SET` macro.


---
### release\_bit\_reference<!-- {{#callable:release_bit_reference}} -->
The `release_bit_reference` function decrements the reference count of a bitset mapping for a given account and potentially releases the bit if the reference count reaches zero.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure, which contains the state and data structures for managing transactions and accounts.
    - `acct`: A constant pointer to an `fd_acct_addr_t` structure representing the account address whose bitset reference is to be released.
- **Control Flow**:
    - Query the bitset map for the account address to get the corresponding bitset mapping structure `q`.
    - Assert that `q` is not NULL, as it should always be found in the map.
    - Decrement the reference count `q->ref_cnt` of the bitset mapping.
    - If the reference count reaches zero, remove the mapping from the bitset map and release the bit back to the available bitset pool if it is within the valid range.
    - Query the account usage map to check if the account is in use and update its usage flags accordingly.
    - Return a `release_result_t` structure indicating which bits, if any, should be cleared from the read-write and write-only bitsets.
- **Output**: A `release_result_t` structure containing two fields: `clear_rw_bit` and `clear_w_bit`, which indicate the bits to be cleared from the read-write and write-only bitsets, respectively.


---
### fd\_pack\_microblock\_complete<!-- {{#callable:fd_pack_microblock_complete}} -->
The `fd_pack_microblock_complete` function finalizes the processing of a microblock for a specific bank tile, updating account usage and potentially moving transactions from penalty treaps to the main treap.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the current state of the pack, including transaction and account management data.
    - `bank_tile`: An unsigned long integer representing the index of the bank tile for which the microblock is being completed.
- **Control Flow**:
    - Initialize a `clear_mask` to clear the writable bit and the bit for the current bank tile.
    - Check if there are any outstanding microblocks for the given bank tile; if not, return 0 immediately.
    - Copy the current state of `bitset_rw_in_use` and `bitset_w_in_use` to local variables.
    - Iterate over each account in `use_by_bank` for the given bank tile.
    - For each account, clear the bank tile's bit and the writable bit from `in_use_by`.
    - If the account is no longer in use by any bank, clear its bit from the bitsets and check for penalty treaps.
    - If a penalty treap exists for the account, find the best transaction and move it to the main treap if it is better than the current best.
    - Remove the account from `acct_in_use` if it is no longer in use by any bank.
    - Update the `use_by_bank_cnt` for the bank tile to 0 and copy the local bitsets back to the pack's bitsets.
    - Clear the bank tile's bit from `outstanding_microblock_mask` and return 1.
- **Output**: Returns an integer: 1 if the microblock completion was successful and changes were made, or 0 if there were no outstanding microblocks for the bank tile.


---
### fd\_pack\_try\_schedule\_bundle<!-- {{#callable:fd_pack_try_schedule_bundle}} -->
The `fd_pack_try_schedule_bundle` function attempts to schedule a bundle of transactions for execution if they meet certain conditions and constraints.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the current state of the transaction pack.
    - `bank_tile`: An unsigned long integer representing the bank tile to which the bundle is being scheduled.
    - `out`: A pointer to an `fd_txn_p_t` structure where the scheduled transactions will be stored.
- **Control Flow**:
    - Initialize the state of the initializer bundle from the pack structure.
    - Check if the initializer bundle is pending or failed; if so, return `TRY_BUNDLE_NO_READY_BUNDLES`.
    - Determine if an initializer bundle is required based on the current state.
    - Initialize a reverse iterator for the pending bundles treap and check if there are any bundles available.
    - If a bundle is available, check if it is an initializer bundle and if it matches the required state.
    - If the bundle is suitable, attempt to schedule it by checking various constraints such as compute units, byte limits, and conflicts.
    - Iterate through the transactions in the bundle, updating temporary structures to track account usage and conflicts.
    - If the bundle cannot be scheduled due to constraints or conflicts, clean up and return an appropriate error code.
    - If the bundle is successfully validated, update the pack's state to reflect the scheduled transactions and return the number of transactions scheduled.
- **Output**: Returns an integer indicating the result of the scheduling attempt: `TRY_BUNDLE_NO_READY_BUNDLES` if no suitable bundles are ready, `TRY_BUNDLE_HAS_CONFLICTS` if there are conflicts, `TRY_BUNDLE_DOES_NOT_FIT` if the bundle does not fit within the constraints, or `TRY_BUNDLE_SUCCESS(n)` where `n` is the number of transactions scheduled if successful.
- **Functions called**:
    - [`release_bit_reference`](#release_bit_reference)


---
### fd\_pack\_schedule\_next\_microblock<!-- {{#callable:fd_pack_schedule_next_microblock}} -->
The `fd_pack_schedule_next_microblock` function schedules the next microblock of transactions for a given bank tile, considering constraints like compute units, vote fraction, and scheduling flags.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the current state of the transaction pack.
    - `total_cus`: The total compute units available for scheduling in this microblock.
    - `vote_fraction`: The fraction of compute units and transactions reserved for vote transactions.
    - `bank_tile`: The index of the bank tile for which the microblock is being scheduled.
    - `schedule_flags`: Flags indicating which types of transactions (votes, bundles, regular transactions) should be scheduled.
    - `out`: A pointer to an array of `fd_txn_p_t` structures where the scheduled transactions will be stored.
- **Control Flow**:
    - Calculate the maximum compute units and transactions available for vote transactions based on the given vote fraction and limits.
    - Check if the current microblock count or data bytes consumed exceed their respective limits, returning 0 if so.
    - Initialize limits for non-vote transactions based on the remaining compute units and transaction slots after accounting for votes.
    - If scheduling votes is enabled, attempt to schedule vote transactions and update the cumulative costs and limits accordingly.
    - If scheduling bundles is enabled and no votes were scheduled, attempt to schedule a bundle of transactions.
    - If scheduling regular transactions is enabled, attempt to fill the remaining space with non-vote transactions.
    - Update the microblock count, outstanding microblock mask, and data bytes consumed if any transactions were scheduled.
    - Update metrics and return the number of transactions scheduled.
- **Output**: Returns the number of transactions successfully scheduled in the microblock.
- **Functions called**:
    - [`fd_pack_try_schedule_bundle`](#fd_pack_try_schedule_bundle)
    - [`fd_pack_metrics_write`](#fd_pack_metrics_write)


---
### fd\_pack\_bank\_tile\_cnt<!-- {{#callable:fd_pack_bank_tile_cnt}} -->
The function `fd_pack_bank_tile_cnt` retrieves the number of bank tiles associated with a given `fd_pack_t` structure.
- **Inputs**:
    - `pack`: A pointer to a constant `fd_pack_t` structure from which the bank tile count is to be retrieved.
- **Control Flow**:
    - The function accesses the `bank_tile_cnt` member of the `fd_pack_t` structure pointed to by `pack`.
- **Output**: The function returns an unsigned long integer representing the number of bank tiles in the `fd_pack_t` structure.


---
### fd\_pack\_current\_block\_cost<!-- {{#callable:fd_pack_current_block_cost}} -->
The function `fd_pack_current_block_cost` retrieves the cumulative block cost from a given `fd_pack_t` structure.
- **Inputs**:
    - `pack`: A pointer to a constant `fd_pack_t` structure from which the cumulative block cost is to be retrieved.
- **Control Flow**:
    - The function accesses the `cumulative_block_cost` field of the `fd_pack_t` structure pointed to by `pack`.
    - It returns the value of the `cumulative_block_cost` field.
- **Output**: The function returns an unsigned long integer representing the cumulative block cost stored in the `fd_pack_t` structure.


---
### fd\_pack\_set\_block\_limits<!-- {{#callable:fd_pack_set_block_limits}} -->
The `fd_pack_set_block_limits` function sets the block limits for a given `fd_pack_t` structure based on the provided `fd_pack_limits_t` limits, ensuring they meet certain lower bound constraints.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure whose block limits are to be set.
    - `limits`: A pointer to a constant `fd_pack_limits_t` structure containing the new block limits to be applied.
- **Control Flow**:
    - The function begins by asserting that the `max_cost_per_block`, `max_vote_cost_per_block`, and `max_write_cost_per_acct` in `limits` meet their respective lower bound constraints using `FD_TEST` macros.
    - If the assertions pass, the function proceeds to update the `pack->lim` structure with the values from `limits`, setting `max_microblocks_per_block`, `max_data_bytes_per_block`, `max_cost_per_block`, `max_vote_cost_per_block`, and `max_write_cost_per_acct`.
- **Output**: The function does not return a value; it modifies the `pack` structure in place.


---
### fd\_pack\_rebate\_cus<!-- {{#callable:fd_pack_rebate_cus}} -->
The `fd_pack_rebate_cus` function adjusts the cumulative costs and state of a pack based on a rebate structure, potentially updating the initializer bundle state and writer costs.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the current state of the pack, including cumulative costs and initializer bundle state.
    - `rebate`: A pointer to a constant `fd_pack_rebate_t` structure containing rebate information such as total cost rebate, vote cost rebate, data bytes rebate, and writer rebates.
- **Control Flow**:
    - Check if the initializer bundle state is pending and the rebate's `ib_result` is non-zero; if so, update the initializer bundle state based on `ib_result`.
    - Subtract the `total_cost_rebate` from `cumulative_block_cost`.
    - Subtract the `vote_cost_rebate` from `cumulative_vote_cost`.
    - Subtract the `data_bytes_rebate` from `data_bytes_consumed`.
    - Add the `total_cost_rebate` to `cumulative_rebated_cus`.
    - Iterate over each writer rebate in `rebate->writer_rebates` and adjust the corresponding `total_cost` in `writer_costs`.
    - Log an error if a writer rebate is applied to an unknown account.
- **Output**: The function does not return a value; it modifies the `pack` structure in place.


---
### fd\_pack\_expire\_before<!-- {{#callable:fd_pack_expire_before}} -->
The `fd_pack_expire_before` function removes expired transactions from a pack's expiration queue that have an expiration time earlier than a specified threshold.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the pack from which expired transactions are to be removed.
    - `expire_before`: An unsigned long integer representing the threshold expiration time; transactions with an expiration time earlier than this will be removed.
- **Control Flow**:
    - The function updates `expire_before` to be the maximum of the input `expire_before` and the pack's current `expire_before` value.
    - It initializes a counter `deleted_cnt` to zero to keep track of the number of deleted transactions.
    - It retrieves the expiration queue `prq` from the pack.
    - A while loop iterates as long as there are transactions in the expiration queue and the earliest transaction's expiration time is less than `expire_before`.
    - Within the loop, it retrieves the transaction to be deleted and calls [`delete_transaction`](#delete_transaction) to remove it from the pack, incrementing `deleted_cnt`.
    - After the loop, it updates the pack's `expire_before` to the new `expire_before` value.
- **Output**: The function returns the number of transactions that were deleted from the expiration queue as an unsigned long integer.
- **Functions called**:
    - [`delete_transaction`](#delete_transaction)


---
### fd\_pack\_end\_block<!-- {{#callable:fd_pack_end_block}} -->
The `fd_pack_end_block` function resets and clears various metrics and data structures related to transaction processing at the end of a block.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the current state of the transaction pack.
- **Control Flow**:
    - Calculate the percentage of cumulative block cost relative to the maximum cost per block and sample it into a histogram.
    - Sample cumulative block cost, rebated compute units, and scheduled compute units into their respective histograms.
    - Reset various counters and state variables in the `pack` structure, including microblock count, data bytes consumed, cumulative block cost, vote cost, rebated compute units, and outstanding microblock mask.
    - Set the initializer bundle state to `FD_PACK_IB_STATE_NOT_INITIALIZED`.
    - Clear the `acct_in_use` map, which tracks account usage.
    - If the written list count is less than the maximum, remove elements from the `writer_costs` map in reverse order of insertion; otherwise, clear the entire `writer_costs` map.
    - Reset the written list count to zero.
    - Increment the `compressed_slot_number`, ensuring it does not overflow.
    - Clear the `bitset_rw_in_use` and `bitset_w_in_use` bitsets.
    - Reset the `use_by_bank_cnt` array to zero for all bank tiles.
    - Copy various histograms to metrics for reporting purposes.
- **Output**: This function does not return a value; it operates by modifying the state of the `fd_pack_t` structure passed to it.


---
### release\_tree<!-- {{#callable:release_tree}} -->
The `release_tree` function iterates over a treap data structure, freeing each node and removing it from associated data structures.
- **Inputs**:
    - `treap`: A pointer to the treap data structure that needs to be released.
    - `signature_map`: A pointer to the signature map used to track transactions by their signatures.
    - `pool`: A pointer to the pool of transaction nodes from which the treap nodes are allocated.
- **Control Flow**:
    - Initialize a forward iterator for the treap using `treap_fwd_iter_init`.
    - Iterate over the treap using a for loop, checking if the iterator index is valid with `!treap_fwd_iter_idx(it)`.
    - Within the loop, store the next iterator position using `treap_fwd_iter_next`.
    - Retrieve the current node index using `treap_fwd_iter_idx`.
    - Set the node's root to `FD_ORD_TXN_ROOT_FREE` to mark it as free.
    - Remove the node from the treap using `treap_idx_remove`.
    - Remove the node from the signature map using `sig2txn_idx_remove_fast`.
    - Release the node back to the pool using `trp_pool_idx_release`.
- **Output**: The function does not return any value; it performs operations to release resources and update data structures.


---
### fd\_pack\_clear\_all<!-- {{#callable:fd_pack_clear_all}} -->
The `fd_pack_clear_all` function resets and clears all data structures and counters within a `fd_pack_t` structure, effectively resetting it to an initial state.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure that represents the pack to be cleared.
- **Control Flow**:
    - Set various counters in the `pack` structure to zero, including `pending_txn_cnt`, `microblock_cnt`, `cumulative_block_cost`, `cumulative_vote_cost`, and `cumulative_rebated_cus`.
    - Set the smallest transaction estimates in `pending_smallest` and `pending_votes_smallest` to `ULONG_MAX`.
    - Release all transactions from the `pending`, `pending_votes`, and `pending_bundles` treaps using the [`release_tree`](#release_tree) function.
    - Iterate over the `pack->pool` array to release any penalty treaps associated with non-free transactions.
    - Set `compressed_slot_number` to `FD_PACK_SKIP_CNT+1`.
    - Remove all elements from the expiration queue `expiration_q`.
    - Clear the `acct_in_use` and `writer_costs` maps.
    - Clear the `penalty_treaps` map.
    - Clear the `bitset_rw_in_use` and `bitset_w_in_use` bitsets, and reset the `acct_to_bitset` map.
    - Initialize the `bitset_avail` array with available bitset indices.
    - Set all elements in `use_by_bank_cnt` to zero.
- **Output**: The function does not return a value; it operates directly on the `fd_pack_t` structure pointed to by `pack`.
- **Functions called**:
    - [`release_tree`](#release_tree)


---
### delete\_transaction<!-- {{#callable:delete_transaction}} -->
The [`delete_transaction`](#delete_transaction) function removes a specified transaction from a transaction management system, optionally deleting the entire bundle it belongs to and managing penalty treaps.
- **Inputs**:
    - `pack`: A pointer to the `fd_pack_t` structure, which manages the transaction system's state and data structures.
    - `containing`: A pointer to the `fd_pack_ord_txn_t` structure representing the transaction to be deleted.
    - `delete_full_bundle`: An integer flag indicating whether to delete the entire bundle containing the transaction.
    - `move_from_penalty_treap`: An integer flag indicating whether to move the best transaction from a penalty treap to the main treap if the transaction is in the pending treap.
- **Control Flow**:
    - Retrieve the transaction and account addresses from the `containing` transaction structure.
    - Determine the root treap of the transaction based on its root index and set up penalty treap if applicable.
    - If `delete_full_bundle` is set and the transaction is part of a bundle, iterate through the bundle and delete all transactions in it.
    - If `move_from_penalty_treap` is set and the transaction is in the pending treap, find the best transaction in any conflicting penalty treaps and move it to the main treap.
    - Release bit references for all accounts involved in the transaction and update the bitsets accordingly.
    - Remove the transaction from the expiration queue, treap, signature map, and release it from the pool.
    - Decrement the pending transaction count and remove the penalty treap if it becomes empty.
- **Output**: Returns 1 on successful deletion of the transaction.
- **Functions called**:
    - [`delete_transaction`](#delete_transaction)
    - [`release_bit_reference`](#release_bit_reference)


---
### fd\_pack\_delete\_transaction<!-- {{#callable:fd_pack_delete_transaction}} -->
The `fd_pack_delete_transaction` function removes transactions with a specified signature from a transaction pack, potentially deleting entire bundles if necessary.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the transaction pack from which transactions are to be deleted.
    - `sig0`: A constant pointer to an `fd_ed25519_sig_t` structure representing the signature of the transaction(s) to be deleted.
- **Control Flow**:
    - Initialize a counter `cnt` to zero and set `next` to `ULONG_MAX`.
    - Use a loop to query the transaction index `idx` for the given signature `sig0` using `sig2txn_idx_query_const`.
    - While `idx` is not `ULONG_MAX`, continue the loop.
    - Inside the loop, set `next` to the next transaction index using `sig2txn_idx_next_const`.
    - Call [`delete_transaction`](#delete_transaction) to delete the transaction at the current index `idx`, incrementing `cnt` by the result.
    - Return `cnt`, the number of transactions deleted.
- **Output**: Returns an integer representing the number of transactions deleted from the pack.
- **Functions called**:
    - [`delete_transaction`](#delete_transaction)


---
### fd\_pack\_verify<!-- {{#callable:fd_pack_verify}} -->
The `fd_pack_verify` function verifies the integrity and consistency of various data structures within a `fd_pack_t` instance, ensuring that all invariants and constraints are maintained.
- **Inputs**:
    - `pack`: A pointer to the `fd_pack_t` structure that contains the data structures to be verified.
    - `scratch`: A pointer to a memory area used for temporary storage during the verification process.
- **Control Flow**:
    - Define a macro `VERIFY_TEST` to log a warning and return an error code if a condition fails.
    - Calculate the maximum number of accounts in a treap and determine the size of the bitset map.
    - Copy the current state of the `acct_to_bitset` map to a temporary location for verification.
    - Initialize bitsets to track processed bits and verify that each bit is in exactly one place.
    - Iterate over the `bitset_avail` array to ensure no bit is listed twice and update the `processed` bitset.
    - Iterate over the `bitset_copy` to verify reference counts and ensure no bit is used twice, updating the `processed` bitset.
    - Iterate over all possible bits to ensure none are missing from the `processed` bitset, updating the `full` bitset.
    - Iterate over the `pending` and `pending_votes` treaps to verify each transaction's consistency with the `signature_map` and expiration queue.
    - For each transaction, verify account references and update reference counts, ensuring no extra bits are in the transaction's bitsets.
    - Leave the temporary `bitset_copy` map and verify that all references have been accounted for.
    - Verify that the number of transactions matches the number of keys in the `signature_map`.
    - Copy the current state of the `acct_in_use` map to a temporary location for verification.
    - Initialize bitsets to track complements of the `rw` and `w` bitsets and verify consistency with the `acct_in_use` map.
    - Iterate over each bank's `use_by_bank` array to verify consistency with the `acct_in_use` map and update bitsets.
    - Ensure no stray uses remain in the `acct_in_use` map and verify that no extra bits are in the `rw` and `w` bitsets.
    - Leave the temporary `acct_in_use_copy` map and restore the original `acct_in_use` map.
- **Output**: Returns 0 if all verifications pass, otherwise returns a negative error code indicating the line number where a verification failed.


---
### fd\_pack\_leave<!-- {{#callable:fd_pack_leave}} -->
The `fd_pack_leave` function ensures memory fence synchronization and returns a pointer to the `fd_pack_t` structure.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure, representing the pack instance to be left.
- **Control Flow**:
    - The function calls `FD_COMPILER_MFENCE()` to ensure memory operations are completed before proceeding.
    - It then returns the input `pack` cast to a `void *` type.
- **Output**: A `void *` pointer to the `fd_pack_t` structure that was passed in.


---
### fd\_pack\_delete<!-- {{#callable:fd_pack_delete}} -->
The `fd_pack_delete` function ensures memory fence synchronization and returns the given memory pointer.
- **Inputs**:
    - `mem`: A pointer to the memory that is to be returned after ensuring memory fence synchronization.
- **Control Flow**:
    - The function calls `FD_COMPILER_MFENCE()` to ensure memory operations are completed before proceeding.
    - The function returns the input memory pointer `mem`.
- **Output**: The function returns the input memory pointer `mem` after ensuring memory fence synchronization.


# Function Declarations (Public API)

---
### delete\_transaction<!-- {{#callable_declaration:delete_transaction}} -->
Deletes a transaction from the specified pack.
- **Description**: Use this function to remove a transaction from the pack, optionally deleting the entire bundle if the transaction is part of one. This function should be called when a transaction is no longer needed or should be removed due to expiration or other criteria. It is important to ensure that the pack is in a consistent state before calling this function, as it will modify the internal structures of the pack.
- **Inputs**:
    - `pack`: A pointer to the fd_pack_t structure from which the transaction will be deleted. The caller must ensure this is a valid and initialized pack.
    - `containing`: A pointer to the fd_pack_ord_txn_t structure representing the transaction to be deleted. This must be a valid transaction currently in the pack.
    - `delete_full_bundle`: An integer flag indicating whether to delete the entire bundle if the transaction is part of one. Non-zero to delete the full bundle, zero to delete only the specified transaction.
    - `move_from_penalty_treap`: An integer flag indicating whether to move the best transaction from any conflicting penalty treap to the main treap if the transaction is in the pending treap. Non-zero to perform the move, zero otherwise.
- **Output**: Returns 1 on successful deletion of the transaction or bundle, or 0 if the operation was not possible (e.g., invalid state).
- **See also**: [`delete_transaction`](#delete_transaction)  (Implementation)


---
### insert\_bundle\_impl<!-- {{#callable_declaration:insert_bundle_impl}} -->
Insert a bundle of transactions into the pack.
- **Description**: Use this function to insert a bundle of transactions into the pack, assigning them a specific expiration time. This function is typically called when a set of transactions needs to be processed together as a bundle. Ensure that the pack has been initialized and has enough capacity to accommodate the transactions. The function handles the insertion of transactions in reverse order, updating their rewards and inserting them into the pending bundles treap. It also updates the expiration queue and signature map accordingly.
- **Inputs**:
    - `pack`: A pointer to an fd_pack_t structure representing the pack where the bundle will be inserted. Must not be null.
    - `bundle_idx`: An unsigned long representing the index of the bundle. It is used to calculate the rewards for the transactions in the bundle.
    - `txn_cnt`: An unsigned long indicating the number of transactions in the bundle. Must be greater than zero and less than or equal to the maximum allowed transactions per bundle.
    - `bundle`: A pointer to an array of fd_pack_ord_txn_t pointers, each representing a transaction in the bundle. The array must contain txn_cnt elements.
    - `expires_at`: An unsigned long representing the expiration time for the transactions in the bundle. Transactions will be considered expired if the current time exceeds this value.
- **Output**: None
- **See also**: [`insert_bundle_impl`](#insert_bundle_impl)  (Implementation)


