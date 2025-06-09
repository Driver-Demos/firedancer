# Purpose
This C source code file is a comprehensive test suite for a transaction packing system, likely part of a blockchain or distributed ledger technology. The code is structured to test various aspects of transaction handling, including insertion, scheduling, validation, and performance under different constraints and scenarios. The file includes multiple test functions, each designed to validate specific features or limits of the transaction packing system, such as handling of transaction costs, vote transactions, system variable protection, and duplicate signatures.

The code is organized into several key components: initialization functions to set up the transaction environment, transaction creation functions to simulate different transaction types, and test functions to validate the system's behavior under various conditions. The tests cover scenarios like transaction scheduling, microblock validation, performance benchmarking, and edge cases like heap overflow and system variable protection. The file also includes performance tests to measure the efficiency of transaction handling and scheduling. Overall, this file serves as a critical component in ensuring the robustness and efficiency of the transaction packing system by systematically verifying its functionality and performance.
# Imports and Dependencies

---
- `../../ballet/fd_ballet.h`
- `fd_pack.h`
- `fd_pack_cost.h`
- `fd_compute_budget_program.h`
- `../../ballet/txn/fd_txn.h`
- `../../ballet/base58/fd_base58.h`
- `../../disco/metrics/fd_metrics.h`
- `math.h`
- `../../util/tmpl/fd_smallset.c`


# Global Variables

---
### txn\_scratch
- **Type**: `uchar`
- **Description**: `txn_scratch` is a two-dimensional array of unsigned characters (uchar) with dimensions defined by `MAX_TEST_TXNS` and `FD_TXN_MAX_SZ`. It is used to store transaction data for a maximum number of test transactions, where each transaction can have a size up to `FD_TXN_MAX_SZ`.
- **Use**: This variable is used to store and manage transaction data during the execution of various test functions in the code.


---
### payload\_scratch
- **Type**: `uchar`
- **Description**: `payload_scratch` is a two-dimensional array of unsigned characters (uchar) with dimensions defined by `MAX_TEST_TXNS` and `DUMMY_PAYLOAD_MAX_SZ`. It is used to store payload data for transactions in a scratch space.
- **Use**: This variable is used to temporarily hold transaction payloads during the creation and manipulation of transactions in the system.


---
### payload\_sz
- **Type**: `ulong[]`
- **Description**: `payload_sz` is a global array of unsigned long integers with a size defined by the constant `MAX_TEST_TXNS`, which is set to 1024. This array is used to store the size of the payload for each transaction in a test suite.
- **Use**: The `payload_sz` array is used to keep track of the size of each transaction's payload, which is crucial for managing and processing transactions within the test framework.


---
### pack\_scratch
- **Type**: `uchar array`
- **Description**: The `pack_scratch` variable is a global array of unsigned characters (uchar) with a size defined by the macro `PACK_SCRATCH_SZ`, which is set to 400 megabytes. It is aligned to a 128-byte boundary using the GCC `__attribute__((aligned(128)))` directive.
- **Use**: This variable is used as a scratch space for operations related to packing, likely to store temporary data during the execution of packing algorithms.


---
### pack\_verify\_scratch
- **Type**: `uchar array`
- **Description**: The `pack_verify_scratch` is a global array of unsigned characters (uchar) with a size defined by `PACK_SCRATCH_SZ`, which is 400 megabytes. It is aligned to a 128-byte boundary to optimize memory access and performance.
- **Use**: This variable is used as a scratch space for verification processes in the code, likely to temporarily store data during the verification of packed transactions or blocks.


---
### metrics\_scratch
- **Type**: `uchar array`
- **Description**: `metrics_scratch` is a global variable defined as an array of unsigned characters (`uchar`). The size of this array is determined by the macro `FD_METRICS_FOOTPRINT(0, 0)`, which is likely a function or macro that calculates the required footprint for metrics storage. The array is aligned according to `FD_METRICS_ALIGN`, ensuring that it meets specific memory alignment requirements.
- **Use**: This variable is used to store metrics data, likely for performance monitoring or logging purposes, in a memory-aligned manner.


---
### SIGNATURE\_SUFFIX
- **Type**: `const char`
- **Description**: `SIGNATURE_SUFFIX` is a constant character array that holds a string used as a suffix in transaction signatures. The size of this array is determined by subtracting the sizes of `ulong` and `uint` from `FD_TXN_SIGNATURE_SZ`. The string it contains is ": this is the fake signature of transaction number ". This string is likely used to append a descriptive suffix to transaction signatures for testing or debugging purposes.
- **Use**: This variable is used to append a descriptive suffix to transaction signatures, likely for testing or debugging purposes.


---
### WORK\_PROGRAM\_ID
- **Type**: `const char`
- **Description**: `WORK_PROGRAM_ID` is a constant character array that holds a string identifier for a work program. The string is initialized with the value "Work Program Id Consumes 1<<j CU".
- **Use**: This variable is used to identify the work program within transactions, specifically when adding the work program to the list of accounts in a transaction.


---
### \_rng
- **Type**: `fd_rng_t[1]`
- **Description**: The variable `_rng` is a global array of type `fd_rng_t` with a single element. It is used to store a random number generator state. The `fd_rng_t` type is likely a structure or typedef defined elsewhere in the codebase, which encapsulates the state and functionality needed for random number generation.
- **Use**: This variable is used to initialize and maintain the state of a random number generator throughout the program.


---
### rng
- **Type**: `fd_rng_t *`
- **Description**: The `rng` variable is a pointer to an instance of the `fd_rng_t` type, which is likely a structure or type related to random number generation. It is declared as a global variable, indicating it is accessible throughout the file and possibly used in multiple functions.
- **Use**: This variable is used to provide a random number generator instance to functions that require random number generation capabilities.


---
### extra\_verify
- **Type**: `int`
- **Description**: The `extra_verify` variable is a global integer variable that is used to control whether additional verification steps are performed during the execution of the program. It is likely used as a flag to enable or disable certain checks or validations.
- **Use**: This variable is used to determine if extra verification should be performed, as seen in the `schedule_validate_microblock` function where it conditionally calls `fd_pack_verify` based on its value.


---
### outcome
- **Type**: `pack_outcome_t`
- **Description**: The `outcome` variable is a global instance of the `pack_outcome_t` structure, which is used to store the results of transaction scheduling and microblock processing. This structure contains fields for counting microblocks, tracking read and write accounts in use, and storing transaction results.
- **Use**: This variable is used to keep track of the state and results of transaction processing within the system, including the number of microblocks processed and the accounts involved.


# Data Structures

---
### pack\_outcome
- **Type**: `struct`
- **Members**:
    - `microblock_cnt`: Stores the count of microblocks processed.
    - `r_accts_in_use`: An array of aset_t representing read accounts in use for each bank tile.
    - `w_accts_in_use`: An array of aset_t representing write accounts in use for each bank tile.
    - `results`: An array of fd_txn_p_t storing the results of transactions.
- **Description**: The `pack_outcome` structure is designed to track the outcome of transaction packing operations in a blockchain system. It maintains a count of microblocks processed, and tracks the accounts that are read and written during these operations across multiple bank tiles. Additionally, it stores the results of up to 1024 transactions, providing a comprehensive view of the transaction processing state.


---
### pack\_outcome\_t
- **Type**: `struct`
- **Members**:
    - `microblock_cnt`: Stores the count of microblocks processed.
    - `r_accts_in_use`: An array of aset_t representing read accounts currently in use for each bank tile.
    - `w_accts_in_use`: An array of aset_t representing write accounts currently in use for each bank tile.
    - `results`: An array of fd_txn_p_t pointers storing the results of transactions.
- **Description**: The `pack_outcome_t` structure is designed to track the outcome of transaction packing operations within a system. It maintains a count of microblocks processed, and arrays of aset_t structures to keep track of accounts that are currently being read or written to, across multiple bank tiles. Additionally, it holds an array of transaction results, which are pointers to fd_txn_p_t structures, allowing the system to store and access the results of up to 1024 transactions. This structure is crucial for managing and verifying the state of transactions and account usage during the packing process.


# Functions

---
### init\_all<!-- {{#callable:init_all}} -->
The `init_all` function initializes a packing structure with specified parameters and prepares an outcome structure for transaction processing.
- **Inputs**:
    - `pack_depth`: The depth of the pack, which determines the number of transactions that can be processed in parallel.
    - `bank_tile_cnt`: The number of bank tiles, which are used for parallel processing of transactions.
    - `max_txn_per_microblock`: The maximum number of transactions allowed per microblock.
    - `outcome`: A pointer to a `pack_outcome_t` structure that will store the results of the transaction processing.
- **Control Flow**:
    - Initialize a `fd_pack_limits_t` structure with predefined constants and the `max_txn_per_microblock` parameter.
    - Calculate the memory footprint required for the pack using [`fd_pack_footprint`](fd_pack.c.driver.md#fd_pack_footprint) with the given parameters.
    - Check if the calculated footprint exceeds the available scratch size (`PACK_SCRATCH_SZ`), and log an error if it does.
    - Create a new pack using [`fd_pack_new`](fd_pack.c.driver.md#fd_pack_new) and join it using [`fd_pack_join`](fd_pack.c.driver.md#fd_pack_join), storing the result in a `fd_pack_t` pointer.
    - Initialize the `microblock_cnt` of the `outcome` structure to zero.
    - Iterate over the maximum number of bank tiles (`FD_PACK_MAX_BANK_TILES`) and set the read and write account sets in the `outcome` structure to null using `aset_null`.
    - Return the initialized `fd_pack_t` pointer.
- **Output**: A pointer to an initialized `fd_pack_t` structure, which is used for managing and processing transactions.
- **Functions called**:
    - [`fd_pack_footprint`](fd_pack.c.driver.md#fd_pack_footprint)
    - [`fd_pack_join`](fd_pack.c.driver.md#fd_pack_join)
    - [`fd_pack_new`](fd_pack.c.driver.md#fd_pack_new)


---
### make\_transaction<!-- {{#callable:make_transaction}} -->
The `make_transaction` function constructs a transaction with specified parameters, including compute units, data size, priority, and account reads/writes, and stores it in designated scratch spaces, optionally calculating priority fees and cost estimates.
- **Inputs**:
    - `i`: An index indicating which transaction scratch space to use.
    - `compute`: The number of compute units requested for the transaction.
    - `loaded_data_sz`: The size of the loaded accounts data in bytes.
    - `priority`: A double value representing the transaction's priority, affecting fee calculation.
    - `writes`: A string of characters representing writable accounts, each character corresponding to an account.
    - `reads`: A string of characters representing readonly accounts, each character corresponding to an account.
    - `priority_fees`: A pointer to a ulong where the calculated priority fee will be stored, if non-null.
    - `pack_cost_estimate`: A pointer to a ulong where the estimated packing cost will be stored, if non-null.
- **Control Flow**:
    - Initialize pointers to the payload and transaction scratch spaces for the given index `i`.
    - Set up the transaction's signature and version information, and calculate the number of accounts involved.
    - Add the signer account to the payload, followed by writable accounts, compute budget, work program, and readonly accounts.
    - Set up the transaction's instruction count based on the compute units and populate the instructions with program IDs and data offsets.
    - Calculate the rewards per compute unit based on the priority and store it in the payload.
    - Iterate over the bits of the compute value to add additional instructions for each set bit.
    - Calculate the total payload size and store it in the global `payload_sz` array.
    - If `priority_fees` is non-null, calculate and store the priority fee based on the rewards per compute unit and compute value.
    - If `pack_cost_estimate` is non-null, calculate and store the estimated packing cost using the transaction and payload data.
- **Output**: The function does not return a value but modifies the transaction and payload scratch spaces, and optionally updates the `priority_fees` and `pack_cost_estimate` pointers with calculated values.
- **Functions called**:
    - [`fd_pack_compute_cost`](fd_pack_cost.h.driver.md#fd_pack_compute_cost)


---
### make\_vote\_transaction<!-- {{#callable:make_vote_transaction}} -->
The `make_vote_transaction` function creates a unique vote transaction by copying a sample vote payload and modifying specific bytes to ensure uniqueness, then parses the transaction to verify its structure.
- **Inputs**:
    - `i`: An unsigned long integer representing the index of the transaction in the payload and transaction scratch arrays.
- **Control Flow**:
    - Retrieve a pointer to the payload scratch space for the given index `i`.
    - Copy the sample vote data into the payload scratch space at index `i`.
    - Set the payload size for index `i` to the size of the sample vote.
    - Modify specific bytes in the payload to make the signature and two writable accounts unique based on the index `i`.
    - Parse the transaction using `fd_txn_parse` to ensure it is correctly structured.
- **Output**: The function does not return a value but modifies the global `payload_scratch` and `payload_sz` arrays to store the unique vote transaction data.


---
### insert<!-- {{#callable:insert}} -->
The `insert` function initializes a transaction slot, copies transaction data into it, and finalizes the insertion into a transaction pack.
- **Inputs**:
    - `i`: An unsigned long integer representing the index of the transaction in the scratch arrays.
    - `pack`: A pointer to an `fd_pack_t` structure representing the transaction pack where the transaction will be inserted.
- **Control Flow**:
    - Initialize a transaction slot by calling [`fd_pack_insert_txn_init`](fd_pack.c.driver.md#fd_pack_insert_txn_init) with the provided `pack`.
    - Retrieve the transaction data from `txn_scratch` using the index `i`.
    - Set the payload size of the transaction slot using `payload_sz[i]`.
    - Copy the payload data from `payload_scratch[i]` to the transaction slot's payload.
    - Copy the transaction data from `txn_scratch[i]` to the transaction slot using `fd_txn_footprint` to determine the size.
    - Finalize the transaction insertion by calling [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini) with the `pack`, the transaction slot, and the index `i`.
- **Output**: Returns an integer status code from [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini), indicating the success or failure of the transaction insertion.
- **Functions called**:
    - [`fd_pack_insert_txn_init`](fd_pack.c.driver.md#fd_pack_insert_txn_init)
    - [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini)


---
### schedule\_validate\_microblock<!-- {{#callable:schedule_validate_microblock}} -->
The `schedule_validate_microblock` function schedules and validates a microblock of transactions, ensuring they meet certain criteria and do not conflict with other microblocks.
- **Inputs**:
    - `pack`: A pointer to an `fd_pack_t` structure representing the transaction pack.
    - `total_cus`: The total compute units available for scheduling transactions in the microblock.
    - `vote_fraction`: The fraction of votes to be considered when scheduling the microblock.
    - `min_txns`: The minimum number of transactions that must be scheduled in the microblock.
    - `min_rewards`: The minimum total rewards that must be achieved by the scheduled transactions.
    - `bank_tile`: The index of the bank tile for which the microblock is being scheduled.
    - `outcome`: A pointer to a `pack_outcome_t` structure where the results of the scheduling will be stored.
- **Control Flow**:
    - Retrieve the number of available transactions before scheduling using [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt).
    - Complete the current microblock for the specified bank tile using [`fd_pack_microblock_complete`](fd_pack.c.driver.md#fd_pack_microblock_complete).
    - Schedule the next microblock using [`fd_pack_schedule_next_microblock`](fd_pack.c.driver.md#fd_pack_schedule_next_microblock) and store the number of scheduled transactions.
    - Retrieve the number of available transactions after scheduling.
    - Log the scheduling details if detailed status messages are enabled.
    - Verify that the number of scheduled transactions meets the minimum required and that the transaction count matches the difference in available transactions before and after scheduling.
    - Initialize sets for read and write accounts to track account usage.
    - Iterate over each scheduled transaction to calculate rewards, compute units, and account data costs, updating the total rewards.
    - For each transaction, update the read and write account sets based on the transaction's account addresses.
    - Verify that the total rewards meet the minimum required and that there are no conflicts between read and write accounts.
    - Check for conflicts with microblocks on other bank tiles by ensuring no overlapping accounts.
    - Update the outcome structure with the new read and write account sets and increment the microblock count.
    - If extra verification is enabled, verify the pack using [`fd_pack_verify`](fd_pack.c.driver.md#fd_pack_verify).
- **Output**: The function does not return a value but updates the `outcome` structure with the results of the microblock scheduling and validation.
- **Functions called**:
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)
    - [`fd_pack_microblock_complete`](fd_pack.c.driver.md#fd_pack_microblock_complete)
    - [`fd_pack_schedule_next_microblock`](fd_pack.c.driver.md#fd_pack_schedule_next_microblock)
    - [`fd_compute_budget_program_init`](fd_compute_budget_program.h.driver.md#fd_compute_budget_program_init)
    - [`fd_compute_budget_program_parse`](fd_compute_budget_program.h.driver.md#fd_compute_budget_program_parse)
    - [`fd_compute_budget_program_finalize`](fd_compute_budget_program.h.driver.md#fd_compute_budget_program_finalize)
    - [`fd_pack_bank_tile_cnt`](fd_pack.c.driver.md#fd_pack_bank_tile_cnt)
    - [`fd_pack_verify`](fd_pack.c.driver.md#fd_pack_verify)


---
### test0<!-- {{#callable:test0}} -->
The `test0` function initializes a transaction pack, creates and inserts several transactions, and schedules microblocks for validation while handling conflicts.
- **Inputs**: None
- **Control Flow**:
    - Log the start of test 0 with a notice message.
    - Initialize a transaction pack with specific parameters using [`init_all`](#init_all).
    - Declare and initialize variables for transaction index, reward, cost estimate, total rewards, and total cost estimate.
    - Create and insert a series of transactions with varying parameters, updating total rewards and cost estimates after each insertion.
    - Schedule and validate a microblock with the current total cost estimate and rewards, specifying the bank tile and outcome.
    - Create and insert an additional transaction, updating totals, and attempt to schedule microblocks on different bank tiles, noting conflicts.
    - Resolve conflicts by scheduling a microblock on a bank tile where conflicts are resolved.
- **Output**: The function does not return any value; it performs operations on the transaction pack and logs outcomes.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`insert`](#insert)
    - [`schedule_validate_microblock`](#schedule_validate_microblock)


---
### test1<!-- {{#callable:test1}} -->
The `test1` function initializes a transaction pack, creates two transactions with specific parameters, inserts them into the pack, and schedules them for validation in microblocks.
- **Inputs**: None
- **Control Flow**:
    - Log a notice indicating the start of TEST 1.
    - Initialize a transaction pack with specific parameters using [`init_all`](#init_all).
    - Set up variables for transaction index, cost estimates, and rewards.
    - Create the first transaction with specific parameters, insert it into the pack, and update the total cost estimate.
    - Create the second transaction with specific parameters, insert it into the pack, and update the total cost estimate.
    - Schedule the first transaction for validation in a microblock with specific parameters.
    - Schedule the second transaction for validation in a microblock with specific parameters.
- **Output**: The function does not return any value; it performs operations on the transaction pack and logs notices.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`insert`](#insert)
    - [`schedule_validate_microblock`](#schedule_validate_microblock)


---
### test2<!-- {{#callable:test2}} -->
The `test2` function initializes a transaction pack, creates and inserts four transactions with decreasing priority, and schedules them for validation in two microblocks.
- **Inputs**: None
- **Control Flow**:
    - Log a notice indicating the start of TEST 2.
    - Initialize a transaction pack with specific parameters using [`init_all`](#init_all).
    - Set initial values for transaction index `i`, priority `j`, and cost estimates.
    - Create and insert four transactions with decreasing priority, updating the total cost estimate after each insertion.
    - Schedule and validate two microblocks using the total cost estimate and specific reward sums.
- **Output**: The function does not return any value; it performs operations on the transaction pack and logs notices.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`insert`](#insert)
    - [`schedule_validate_microblock`](#schedule_validate_microblock)


---
### test\_vote<!-- {{#callable:test_vote}} -->
The `test_vote` function tests the voting transaction handling and scheduling within a transaction pack, ensuring correct transaction counts and outcomes.
- **Inputs**: None
- **Control Flow**:
    - Log the start of the test with 'TEST VOTE'.
    - Initialize a transaction pack with specific parameters using [`init_all`](#init_all).
    - Set up variables for transaction index, cost estimate, and flags.
    - Create and insert four voting transactions into the pack, updating the cost estimate for each.
    - Verify that the pack contains four transactions using `FD_TEST`.
    - Schedule and validate a microblock with no votes, ensuring the transaction count remains four.
    - Schedule and validate a microblock with a 25% vote fraction, reducing the transaction count to three.
    - Schedule and validate a microblock with a 100% vote fraction, reducing the transaction count to zero.
    - Verify that the flags of the first three outcomes indicate simple votes.
- **Output**: The function does not return a value; it performs assertions to validate the transaction handling logic.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_vote_transaction`](#make_vote_transaction)
    - [`fd_pack_compute_cost`](fd_pack_cost.h.driver.md#fd_pack_compute_cost)
    - [`insert`](#insert)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)
    - [`schedule_validate_microblock`](#schedule_validate_microblock)


---
### test\_delete<!-- {{#callable:test_delete}} -->
The `test_delete` function tests the deletion of transactions from a transaction pack and validates the behavior of the pack after deletions and scheduling operations.
- **Inputs**: None
- **Control Flow**:
    - Initialize a transaction pack with specific parameters using [`init_all`](#init_all) and log the start of the test.
    - Create and insert six transactions into the pack, updating the total cost estimate with each insertion.
    - Verify that the pack contains six transactions using `FD_TEST` and [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt).
    - Retrieve signatures for transactions at indices 0, 2, and 4, and attempt to delete these transactions from the pack, verifying successful deletion and failed re-deletion.
    - Check that the pack now contains three transactions and schedule a microblock to validate the remaining transactions, reducing the transaction count to zero.
    - Attempt to delete transactions at indices 1, 3, and 5, which should fail as they were scheduled, and verify the pack is empty.
    - Re-initialize the transaction index and create six new transactions with potential conflicts, updating the total cost estimate.
    - Schedule a microblock with specific parameters and verify the pack contains five transactions.
    - Adjust the total cost estimate and attempt to delete specific transactions, verifying the pack contains three transactions.
    - Schedule multiple microblocks with varying parameters to handle gaps and validate the pack's state.
    - Finally, delete remaining transactions and verify the pack is empty.
- **Output**: The function does not return any value; it performs tests and uses assertions to validate the expected behavior of transaction deletion and scheduling within a transaction pack.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`insert`](#insert)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)
    - [`fd_pack_delete_transaction`](fd_pack.c.driver.md#fd_pack_delete_transaction)
    - [`schedule_validate_microblock`](#schedule_validate_microblock)


---
### test\_expiration<!-- {{#callable:test_expiration}} -->
The `test_expiration` function tests the expiration logic of transactions within a transaction pack, ensuring that expired transactions are correctly identified and handled.
- **Inputs**: None
- **Control Flow**:
    - Initialize a transaction pack with specific parameters using [`init_all`](#init_all).
    - Create and insert six transactions into the pack with varying priorities and account interactions.
    - Verify that the pack contains six transactions using [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt).
    - Expire the first two transactions using [`fd_pack_expire_before`](fd_pack.c.driver.md#fd_pack_expire_before) and verify the count of expired transactions.
    - Attempt to delete an expired transaction and verify that it fails.
    - Validate a microblock with the remaining transactions and verify that the pack is empty afterwards.
    - Attempt to expire transactions with a higher threshold and verify that no additional transactions expire.
    - Insert four new transactions that should be rejected due to expiration and verify the pack remains empty.
    - Insert three more transactions and verify they are accepted.
    - Validate microblocks with the new transactions and verify the pack's transaction count after each validation.
    - Insert 200 transactions to test the penalty treap logic and verify the expiration of the first 100 transactions.
    - Validate microblocks for the remaining transactions.
- **Output**: The function does not return a value; it performs assertions to verify the correct behavior of transaction expiration logic.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`insert`](#insert)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)
    - [`fd_pack_expire_before`](fd_pack.c.driver.md#fd_pack_expire_before)
    - [`fd_pack_delete_transaction`](fd_pack.c.driver.md#fd_pack_delete_transaction)
    - [`schedule_validate_microblock`](#schedule_validate_microblock)


---
### performance\_test2<!-- {{#callable:performance_test2}} -->
The `performance_test2` function evaluates the performance of a transaction packing system by inserting and scheduling a large number of minimal transactions, measuring the time taken for these operations.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the performance test with a notice message.
    - Initializes transaction limits for the test, including maximum costs and transaction counts per block and microblock.
    - Creates 1024 minimal transactions with unique fee payers and no instructions or additional accounts, storing them in scratch arrays.
    - Calculates the footprint of the pack and verifies it is within the scratch size limit.
    - Defines the number of inner and outer rounds for the test based on maximum cost per block and transaction count.
    - Initializes a pack object for transaction insertion and scheduling.
    - For each outer round, measures the elapsed time for inserting and scheduling transactions.
    - In each inner round, inserts all transactions into the pack, schedules them into microblocks, and verifies the scheduled count matches the expected number.
    - Completes the block after each outer round and accumulates the elapsed time.
    - Logs the total number of transactions inserted and scheduled, along with the average time per transaction.
- **Output**: The function does not return a value but logs the performance results, including the number of transactions processed and the time taken per transaction.
- **Functions called**:
    - [`fd_pack_footprint`](fd_pack.c.driver.md#fd_pack_footprint)
    - [`fd_pack_join`](fd_pack.c.driver.md#fd_pack_join)
    - [`fd_pack_new`](fd_pack.c.driver.md#fd_pack_new)
    - [`fd_pack_insert_txn_init`](fd_pack.c.driver.md#fd_pack_insert_txn_init)
    - [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini)
    - [`fd_pack_schedule_next_microblock`](fd_pack.c.driver.md#fd_pack_schedule_next_microblock)
    - [`fd_pack_microblock_complete`](fd_pack.c.driver.md#fd_pack_microblock_complete)
    - [`fd_pack_end_block`](fd_pack.c.driver.md#fd_pack_end_block)


---
### performance\_test<!-- {{#callable:performance_test}} -->
The `performance_test` function evaluates the performance of transaction packing and scheduling under various conditions and configurations.
- **Inputs**:
    - `extra_bench`: An integer flag that determines whether to use extended benchmarking parameters, affecting the maximum heap size and linear increment for heap size.
- **Control Flow**:
    - Initialize transaction costs for two sample transactions using [`make_transaction`](#make_transaction).
    - Create an anonymous workspace using `fd_wksp_new_anonymous`.
    - Determine `max_heap_sz` and `linear_inc` based on `extra_bench`.
    - Log the performance test header and column descriptions.
    - Iterate over heap sizes from 16 to `max_heap_sz`, doubling or incrementing by `linear_inc` each time.
    - For each heap size, calculate the footprint and allocate memory for the pack.
    - Initialize timing variables for different phases of transaction processing.
    - Perform a series of iterations (`ITER_CNT`) to warm up and measure performance.
    - In each iteration, join a new pack and perform pre-insert, insert, end block, and scheduling operations, measuring time for each phase.
    - Log the performance metrics for the current heap size.
    - Free allocated memory and delete the workspace if applicable.
- **Output**: The function does not return a value; it logs performance metrics to the console.
- **Functions called**:
    - [`make_transaction`](#make_transaction)
    - [`fd_pack_footprint`](fd_pack.c.driver.md#fd_pack_footprint)
    - [`fd_pack_align`](fd_pack.h.driver.md#fd_pack_align)
    - [`fd_pack_join`](fd_pack.c.driver.md#fd_pack_join)
    - [`fd_pack_new`](fd_pack.c.driver.md#fd_pack_new)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)
    - [`fd_pack_insert_txn_init`](fd_pack.c.driver.md#fd_pack_insert_txn_init)
    - [`fd_pack_insert_txn_cancel`](fd_pack.c.driver.md#fd_pack_insert_txn_cancel)
    - [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini)
    - [`fd_pack_end_block`](fd_pack.c.driver.md#fd_pack_end_block)
    - [`fd_pack_schedule_next_microblock`](fd_pack.c.driver.md#fd_pack_schedule_next_microblock)
    - [`fd_pack_microblock_complete`](fd_pack.c.driver.md#fd_pack_microblock_complete)


---
### performance\_end\_block<!-- {{#callable:performance_end_block}} -->
The `performance_end_block` function measures the performance of ending a block in a transaction packing system by simulating transaction insertions and scheduling, and then logging the time taken to end the block.
- **Inputs**:
    - `void`: This function does not take any input arguments.
- **Control Flow**:
    - Create a new anonymous workspace with a gigantic page size using `fd_wksp_new_anonymous`.
    - Check if the workspace creation was unsuccessful and log a notice if so, then return early.
    - Log a notice indicating the start of the performance test for ending a block.
    - Define transaction packing limits with specific constraints on costs, data bytes, and transaction counts.
    - Calculate the memory footprint required for the transaction pack and allocate memory in the workspace.
    - Create a sample transaction using [`make_transaction`](#make_transaction).
    - Log a header for the performance results table.
    - Initialize a transaction pack with the allocated memory and join it.
    - Iterate over a range of writer counts, doubling each time, to simulate different levels of transaction insertion.
    - For each writer count, initialize a timer for measuring the end block performance.
    - Iterate over a predefined number of iterations to simulate transaction insertions and scheduling.
    - For each writer, make the transaction signature and signer unique to avoid conflicts.
    - Insert the transaction into the pack using [`fd_pack_insert_txn_init`](fd_pack.c.driver.md#fd_pack_insert_txn_init) and [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini).
    - While there are available transactions in the pack, schedule the next microblock and complete it.
    - Measure the time taken to end the block using [`fd_pack_end_block`](fd_pack.c.driver.md#fd_pack_end_block) and log the result.
    - Free the allocated memory and delete the anonymous workspace.
- **Output**: The function does not return any value; it logs performance metrics to the console.
- **Functions called**:
    - [`fd_pack_footprint`](fd_pack.c.driver.md#fd_pack_footprint)
    - [`fd_pack_align`](fd_pack.h.driver.md#fd_pack_align)
    - [`make_transaction`](#make_transaction)
    - [`fd_pack_join`](fd_pack.c.driver.md#fd_pack_join)
    - [`fd_pack_new`](fd_pack.c.driver.md#fd_pack_new)
    - [`fd_pack_insert_txn_init`](fd_pack.c.driver.md#fd_pack_insert_txn_init)
    - [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)
    - [`fd_pack_schedule_next_microblock`](fd_pack.c.driver.md#fd_pack_schedule_next_microblock)
    - [`fd_pack_microblock_complete`](fd_pack.c.driver.md#fd_pack_microblock_complete)
    - [`fd_pack_end_block`](fd_pack.c.driver.md#fd_pack_end_block)


---
### heap\_overflow\_test<!-- {{#callable:heap_overflow_test}} -->
The `heap_overflow_test` function tests the behavior of a transaction pack when subjected to a large number of transactions, including handling of low and high priority transactions and ensuring the pack's capacity is not exceeded.
- **Inputs**: None
- **Control Flow**:
    - Log the start of the heap overflow test with a notice message.
    - Initialize a transaction pack with a depth of 1024, 1 bank tile, and a maximum of 2 transactions per microblock using [`init_all`](#init_all).
    - Insert 1024 low-priority transactions into the pack, each with specific compute units and payload size, using a loop and functions like [`make_transaction`](#make_transaction), [`fd_pack_insert_txn_init`](fd_pack.c.driver.md#fd_pack_insert_txn_init), and [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini).
    - Verify that the pack contains 1024 transactions using `FD_TEST` and [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt).
    - Insert 1024 high-priority transactions into the pack, which probabilistically replace the low-priority ones due to conflicts, using similar functions as before.
    - Verify again that the pack contains 1024 transactions.
    - Schedule and validate microblocks for the transactions, ensuring that only one transaction can fit per microblock due to a compute unit limit, using [`schedule_validate_microblock`](#schedule_validate_microblock).
    - Verify that the pack is empty after scheduling all transactions.
- **Output**: The function does not return any value; it performs tests and uses assertions to verify expected behavior.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`fd_pack_insert_txn_init`](fd_pack.c.driver.md#fd_pack_insert_txn_init)
    - [`fd_pack_insert_txn_fini`](fd_pack.c.driver.md#fd_pack_insert_txn_fini)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)
    - [`schedule_validate_microblock`](#schedule_validate_microblock)


---
### test\_gap<!-- {{#callable:test_gap}} -->
The `test_gap` function tests the behavior of transaction scheduling and validation with varying gaps between bank tiles in a transaction pack.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the 'TEST GAP' test using `FD_LOG_NOTICE`.
    - Iterates over a range of gaps from 1 to `FD_PACK_MAX_BANK_TILES`.
    - For each gap, initializes a transaction pack with [`init_all`](#init_all) using a specific depth, gap, and transaction limit.
    - Creates two transactions with [`make_transaction`](#make_transaction), inserting them into the pack using [`insert`](#insert).
    - Schedules and validates a microblock with a limited number of compute units using [`schedule_validate_microblock`](#schedule_validate_microblock), ensuring only one transaction fits.
    - Iterates over the range of gaps, scheduling and validating microblocks with no transactions fitting, to simulate the gap effect.
    - Asserts that only one transaction remains available in the pack using `FD_TEST`.
    - Schedules and validates the remaining transaction in the pack.
- **Output**: The function does not return any value; it performs tests and assertions to validate transaction scheduling behavior.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`insert`](#insert)
    - [`schedule_validate_microblock`](#schedule_validate_microblock)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)


---
### test\_limits<!-- {{#callable:test_limits}} -->
The `test_limits` function tests various transaction and block limits in a transaction packing system, including maximum transactions per microblock, compute unit limits, block vote limits, block writer limits, total cost block limits, and data size limits.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the 'TEST LIMITS' test.
    - Initializes a rebate sum and report structure for tracking transaction rebates.
    - Tests the maximum transactions per microblock limit by iterating over different maximum values, inserting transactions, and validating the microblock schedule.
    - Tests the compute unit (CU) limit by inserting transactions and gradually increasing the CU limit to validate the correct number of votes scheduled.
    - Tests the block vote limit by inserting transactions and validating the microblock schedule against the maximum vote cost per block.
    - Tests the block writer limit by inserting transactions and validating the microblock schedule against the maximum write cost per account.
    - Tests the total cost block limit by inserting transactions in batches and validating the microblock schedule against the maximum cost per block.
    - Tests the data size limit by inserting transactions until the maximum data per block is nearly reached and validating the microblock schedule.
- **Output**: The function does not return any value; it performs tests and uses assertions to validate the behavior of the transaction packing system.
- **Functions called**:
    - [`fd_pack_rebate_sum_new`](fd_pack_rebate_sum.c.driver.md#fd_pack_rebate_sum_new)
    - [`init_all`](#init_all)
    - [`make_vote_transaction`](#make_vote_transaction)
    - [`insert`](#insert)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)
    - [`schedule_validate_microblock`](#schedule_validate_microblock)
    - [`fd_pack_end_block`](fd_pack.c.driver.md#fd_pack_end_block)
    - [`make_transaction`](#make_transaction)
    - [`fd_pack_rebate_sum_add_txn`](fd_pack_rebate_sum.c.driver.md#fd_pack_rebate_sum_add_txn)
    - [`fd_pack_rebate_sum_report`](fd_pack_rebate_sum.c.driver.md#fd_pack_rebate_sum_report)
    - [`fd_pack_rebate_cus`](fd_pack.c.driver.md#fd_pack_rebate_cus)


---
### test\_vote\_qos<!-- {{#callable:test_vote_qos}} -->
The `test_vote_qos` function tests the quality of service (QoS) rules for handling vote and non-vote transactions in a transaction pack.
- **Inputs**: None
- **Control Flow**:
    - Log the start of the test with 'TEST VOTE QOS'.
    - Initialize a transaction pack with specific parameters using [`init_all`](#init_all).
    - Insert 16 vote transactions into the pack, ensuring each insertion is accepted as a vote add.
    - Insert several non-vote transactions with low priority, which are accepted due to an imbalanced treap.
    - Insert another non-vote transaction, which is rejected due to priority as the treap becomes balanced.
    - Insert higher priority non-vote transactions, replacing the previous non-votes and maintaining 12 pending votes.
    - Attempt to delete non-vote transactions, ensuring they cannot be deleted.
    - Replace 8 votes with non-votes, maintaining exactly 25% votes, which is allowed by QoS rules.
    - Attempt to insert another non-vote transaction, which is rejected due to low vote percentage.
- **Output**: The function does not return any value; it performs tests and assertions to validate the behavior of the transaction pack under QoS rules.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_vote_transaction`](#make_vote_transaction)
    - [`insert`](#insert)
    - [`make_transaction`](#make_transaction)
    - [`fd_pack_delete_transaction`](fd_pack.c.driver.md#fd_pack_delete_transaction)


---
### test\_reject\_writes\_to\_sysvars<!-- {{#callable:test_reject_writes_to_sysvars}} -->
The function `test_reject_writes_to_sysvars` tests that transactions attempting to write to system variables are correctly rejected.
- **Inputs**: None
- **Control Flow**:
    - Log a notice indicating the start of the test for system variables.
    - Initialize a `fd_pack_t` object using [`init_all`](#init_all) with specific parameters.
    - Define an array `sysvars` containing 31 system variable account keys.
    - Iterate over each system variable in `sysvars`.
    - For each system variable, create a transaction using [`make_transaction`](#make_transaction) with specific parameters.
    - Replace the writable account 'A' in the transaction with the current system variable using `fd_base58_decode_32`.
    - Modify the transaction payload to ensure it is not recognized as a compute budget program.
    - Attempt to insert the transaction into the pack using [`insert`](#insert) and verify it is rejected with `FD_PACK_INSERT_REJECT_WRITES_SYSVAR`.
    - Verify that the available transaction count in the pack remains zero after each insertion attempt.
- **Output**: The function does not return any value; it performs assertions to verify that transactions writing to system variables are rejected.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`insert`](#insert)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)


---
### test\_reject<!-- {{#callable:test_reject}} -->
The `test_reject` function tests various rejection scenarios for transaction insertion into a pack, including estimation failure, account count issues, and duplicate accounts.
- **Inputs**:
    - `void`: This function does not take any input arguments.
- **Control Flow**:
    - Logs a notice indicating the start of the 'TEST REJECT'.
    - Initializes a pack with specific parameters using [`init_all`](#init_all).
    - Sets up a transaction with specific parameters and modifies its payload to simulate an estimation failure, then tests if the insertion is rejected due to estimation failure.
    - Increments the transaction index and sets up another transaction with parameters that exceed account count limits, then tests if the insertion is rejected due to account count issues.
    - Increments the transaction index again and sets up a transaction with duplicate accounts, then tests if the insertion is rejected due to duplicate accounts.
    - Clears the transaction scratch space for all transactions processed in this function.
- **Output**: The function does not return any value; it performs assertions to verify that transactions are rejected under specific conditions.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`insert`](#insert)


---
### test\_duplicate\_sig<!-- {{#callable:test_duplicate_sig}} -->
The `test_duplicate_sig` function tests the handling of duplicate transaction signatures in a transaction pack.
- **Inputs**: None
- **Control Flow**:
    - Log the start of the test with a notice message.
    - Initialize a transaction pack with specific parameters using [`init_all`](#init_all).
    - Create a transaction with [`make_transaction`](#make_transaction) and insert it three times into the pack, checking that each insertion is successful.
    - Verify that the available transaction count in the pack is 3.
    - Retrieve the signature of the first transaction and attempt to delete it twice, checking that the first deletion is successful and the second is not.
    - Verify that the available transaction count in the pack is 0 after deletion.
    - Re-insert the transaction and copy its data to another index, then insert a new transaction with an incremented index.
    - Check that the available transaction count is 2 and expire transactions before a certain time, reducing the count to 1.
    - Attempt to delete the transaction again, verifying the deletion and the count is 0.
- **Output**: The function does not return any value; it performs assertions to validate the behavior of transaction signature handling in the pack.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`make_transaction`](#make_transaction)
    - [`insert`](#insert)
    - [`fd_pack_avail_txn_cnt`](fd_pack.h.driver.md#fd_pack_avail_txn_cnt)
    - [`fd_pack_delete_transaction`](fd_pack.c.driver.md#fd_pack_delete_transaction)
    - [`fd_pack_expire_before`](fd_pack.c.driver.md#fd_pack_expire_before)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of tests and performance benchmarks, and then cleans up resources before exiting.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments passed to the program.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with the command-line arguments.
    - Create and join a random number generator using `fd_rng_new` and `fd_rng_join`.
    - Register metrics using `fd_metrics_register`.
    - Check for the presence of `--extra-bench` and `--extra-verify` flags in the command-line arguments and set `extra_benchmark` and `extra_verify` accordingly.
    - Execute a series of test functions: [`test0`](#test0), [`test1`](#test1), [`test2`](#test2), [`test_vote`](#test_vote), [`heap_overflow_test`](#heap_overflow_test), [`test_delete`](#test_delete), [`test_expiration`](#test_expiration), [`test_gap`](#test_gap), [`test_limits`](#test_limits), [`test_reject_writes_to_sysvars`](#test_reject_writes_to_sysvars), [`test_reject`](#test_reject), [`test_duplicate_sig`](#test_duplicate_sig).
    - Optionally execute [`test_vote_qos`](#test_vote_qos) if a certain condition is met (currently always false).
    - Run performance tests [`performance_test`](#performance_test) and [`performance_test2`](#performance_test2), and finalize with [`performance_end_block`](#performance_end_block).
    - Delete the random number generator using `fd_rng_delete` and `fd_rng_leave`.
    - Log a notice indicating the tests passed and halt the program using `fd_halt`.
- **Output**: Returns 0 to indicate successful execution.
- **Functions called**:
    - [`test0`](#test0)
    - [`test1`](#test1)
    - [`test2`](#test2)
    - [`test_vote`](#test_vote)
    - [`heap_overflow_test`](#heap_overflow_test)
    - [`test_delete`](#test_delete)
    - [`test_expiration`](#test_expiration)
    - [`test_gap`](#test_gap)
    - [`test_limits`](#test_limits)
    - [`test_vote_qos`](#test_vote_qos)
    - [`test_reject_writes_to_sysvars`](#test_reject_writes_to_sysvars)
    - [`test_reject`](#test_reject)
    - [`test_duplicate_sig`](#test_duplicate_sig)
    - [`performance_test`](#performance_test)
    - [`performance_test2`](#performance_test2)
    - [`performance_end_block`](#performance_end_block)


