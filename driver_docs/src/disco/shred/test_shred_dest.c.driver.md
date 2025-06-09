# Purpose
This C source code file is a comprehensive test suite designed to validate the functionality and performance of a system related to "shred" destination computation, likely in a distributed or blockchain context. The file includes a series of test functions that assess various aspects of the system, such as the computation of first and child matches, distribution properties, batching, stake variation, and performance metrics. The tests are structured to ensure that the system behaves correctly under different configurations and scenarios, including edge cases and potential error conditions.

The code imports binary data from several fixture files, which are used to simulate real-world data inputs for the tests. It defines constants and data structures necessary for the tests, such as `fd_shred_dest_weighted_t` and `fd_pubkey_t`, and uses these to create and manipulate shred destination objects. The test functions are designed to verify the correctness of the shred destination computation logic, ensuring that the system can handle various input sizes, stake distributions, and network configurations. Additionally, the performance test measures the efficiency of the system in processing a large number of shreds, providing insights into its scalability. Overall, this file serves as a critical component in ensuring the reliability and robustness of the shred destination computation system.
# Imports and Dependencies

---
- `fd_shred_dest.h`


# Global Variables

---
### \_sd\_footprint
- **Type**: `uchar[]`
- **Description**: The `_sd_footprint` is a global array of unsigned characters with a size defined by `TEST_MAX_FOOTPRINT`, which is 4 megabytes. It is aligned according to the `FD_SHRED_DEST_ALIGN` attribute, ensuring proper memory alignment for efficient access.
- **Use**: This variable is used to store data related to the footprint of shred destinations, which is crucial for the operations involving `fd_shred_dest_t` structures.


---
### \_l\_footprint
- **Type**: `uchar array`
- **Description**: The `_l_footprint` is a global array of unsigned characters with a size defined by `TEST_MAX_FOOTPRINT`. It is aligned according to the `FD_EPOCH_LEADERS_ALIGN` attribute, which ensures that the memory address of the array is aligned to a specific boundary for performance optimization.
- **Use**: This variable is used to store data related to epoch leaders, as seen in its use with functions like `fd_epoch_leaders_new` and `fd_epoch_leaders_join`.


---
### stakes
- **Type**: `fd_stake_weight_t[]`
- **Description**: The `stakes` variable is a global array of `fd_stake_weight_t` structures, with a size defined by `TEST_MAX_VALIDATORS`. Each element in the array represents a validator's stake information, including the public key and the amount of stake in lamports.
- **Use**: This array is used to store and manage the stake information for up to `TEST_MAX_VALIDATORS` validators, which is utilized in various functions to compute leader schedules and shred destinations.


# Functions

---
### test\_compute\_first\_matches\_agave<!-- {{#callable:test_compute_first_matches_agave}} -->
The function `test_compute_first_matches_agave` tests the functionality of computing the first matching shred destination in a distributed ledger system, ensuring it conforms to expected results using predefined data.
- **Inputs**: None
- **Control Flow**:
    - Initialize `cnt` as the number of destination info entries and pointers to destination info and source key.
    - Calculate the total number of staked entries and populate the `stakes` array with public keys and stakes from the destination info.
    - Verify that the memory footprint for shred destinations and epoch leaders does not exceed the maximum allowed footprint.
    - Create and join an epoch leaders schedule and a shred destination using the initialized data.
    - Iterate over slots from 0 to 9999, checking if the current slot's leader matches the source key; if not, continue to the next slot.
    - For each matching slot, iterate over two shred types and indices, compute the first shred destination, and verify the result against expected broadcast peers.
    - Ensure the number of processed peers matches the size of the broadcast peers data.
    - Clean up by deleting and leaving the shred destination and epoch leaders schedule.
- **Output**: The function does not return any value; it performs tests and assertions to validate the correctness of the shred destination computation.
- **Functions called**:
    - [`fd_shred_dest_footprint`](fd_shred_dest.c.driver.md#fd_shred_dest_footprint)
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)
    - [`fd_shred_dest_compute_first`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_first)
    - [`fd_shred_dest_idx_to_dest`](fd_shred_dest.h.driver.md#fd_shred_dest_idx_to_dest)
    - [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)
    - [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)


---
### test\_compute\_children\_matches\_agave<!-- {{#callable:test_compute_children_matches_agave}} -->
The function `test_compute_children_matches_agave` tests the computation of child destinations for shreds against expected results using a predefined dataset.
- **Inputs**: None
- **Control Flow**:
    - Initialize `cnt` as the number of destination info entries and set up pointers to destination info and source key data.
    - Calculate the number of staked entries and populate the `stakes` array with public keys and stakes from the destination info.
    - Verify that the memory footprint for shred destinations and epoch leaders is within the allowed maximum footprint.
    - Create and join an epoch leaders schedule and a shred destination using the initialized data.
    - Iterate over a range of slots and shred types, setting up shreds with varying slots, types, and indices.
    - For each shred, compute the child destinations using [`fd_shred_dest_compute_children`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_children) and verify the result against expected answers from `t1_retransmit_peers`.
    - Check that the number of computed destinations matches the expected count and that the public keys of the computed destinations match the expected values.
    - Ensure that any remaining destination slots in the result array are marked as no destination.
    - Clean up by deleting the shred destination and epoch leaders schedule.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correctness of child destination computations.
- **Functions called**:
    - [`fd_shred_dest_footprint`](fd_shred_dest.c.driver.md#fd_shred_dest_footprint)
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)
    - [`fd_shred_dest_compute_children`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_children)
    - [`fd_shred_dest_idx_to_dest`](fd_shred_dest.h.driver.md#fd_shred_dest_idx_to_dest)
    - [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)
    - [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)


---
### test\_distribution\_is\_tree<!-- {{#callable:test_distribution_is_tree}} -->
The function `test_distribution_is_tree` verifies that a distribution of shreds forms a valid tree structure based on the given parameters and leader schedule.
- **Inputs**:
    - `info`: A pointer to an array of `fd_shred_dest_weighted_t` structures containing information about the destinations.
    - `cnt`: The number of destinations in the `info` array.
    - `lsched`: A pointer to the leader schedule (`fd_epoch_leaders_t`) for the current epoch.
    - `fanout`: The maximum number of children each node can have in the tree.
    - `slot`: The slot number for which the distribution is being tested.
    - `is_data`: An integer flag indicating whether the shred is data (non-zero) or code (zero).
    - `idx`: The index of the shred within the slot.
- **Control Flow**:
    - Initialize an array `hit` to track which nodes have been visited and arrays `out` and `shred` for processing shreds.
    - Perform initial checks to ensure `cnt` is less than 2048, `fanout` is less than 1024, and `cnt` is less than or equal to `fanout * (fanout + 1)`.
    - Set the `slot`, `variant`, and `idx` fields of the `shred` structure based on the input parameters.
    - Retrieve the leader's public key for the given slot from the leader schedule.
    - Iterate over each source index from 0 to `cnt` to process each destination.
    - For each destination, create a new shred destination object and determine if the current source is the leader.
    - If the source is the leader, compute the first destination and mark it as visited; otherwise, compute the children destinations.
    - For each computed child destination, check if it is valid and mark it as visited.
    - Delete the shred destination object after processing each source.
    - Finally, verify that all destinations have been visited by checking the `hit` array.
- **Output**: The function does not return a value but uses assertions to ensure that the distribution forms a valid tree structure.
- **Functions called**:
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)
    - [`fd_shred_dest_compute_first`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_first)
    - [`fd_shred_dest_compute_children`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_children)
    - [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)
    - [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)


---
### test\_batching<!-- {{#callable:test_batching}} -->
The `test_batching` function tests the batching of shreds for different slots and verifies the consistency of computed destinations for both leader and non-leader scenarios.
- **Inputs**: None
- **Control Flow**:
    - Initialize a random number generator `r` using `fd_rng_new` and `fd_rng_join`.
    - Set up an array `info` of `fd_shred_dest_weighted_t` structures with 32 elements, initializing them to zero.
    - Iterate 1000 times to simulate different scenarios.
    - In each iteration, assign random stakes to the `info` array and update the `stakes` array accordingly.
    - Create a leader schedule `lsched` using `fd_epoch_leaders_new` and `fd_epoch_leaders_join`.
    - Create a shred destination `sdest` using [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new) and [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join).
    - Define constants and arrays for batch processing of shreds, including `result1`, `result2`, `shred`, and `shred_ptr`.
    - Initialize `result1` and `result2` with specific values (0x11 and 0x22 respectively).
    - Loop over slots from 0 to 100 in steps of 4, setting up shreds with random indices and variants.
    - Check if the current slot's leader matches the source key; if not, compute children destinations using [`fd_shred_dest_compute_children`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_children) and verify consistency between batch and individual computations.
    - If the current slot's leader matches the source key, compute first destinations using [`fd_shred_dest_compute_first`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_first) and verify consistency between batch and individual computations.
    - Delete the shred destination and leader schedule objects at the end of each iteration.
- **Output**: The function does not return any value; it performs tests and assertions to verify the correctness of shred batching and destination computation.
- **Functions called**:
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)
    - [`fd_shred_dest_compute_children`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_children)
    - [`fd_shred_dest_compute_first`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_first)
    - [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)
    - [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)


---
### test\_vary\_stake<!-- {{#callable:test_vary_stake}} -->
The `test_vary_stake` function simulates varying stake distributions for shred destinations and leader schedules, testing the distribution of stakes over multiple iterations.
- **Inputs**: None
- **Control Flow**:
    - Initialize a random number generator `r` using `fd_rng_new` and `fd_rng_join`.
    - Set `cnt` to 32 and initialize an array `info` of `fd_shred_dest_weighted_t` with zeroed memory.
    - Iterate 1000 times, each time generating random stakes for shred destinations and leader schedules.
    - For each iteration, generate a random number `staked_cnt` to determine how many of the 32 destinations will have non-zero stakes.
    - For each destination, assign a public key and a stake, ensuring stakes are non-increasing and some are zero.
    - Generate a separate set of stakes for a leader schedule, ensuring all are positive and different from the shred destination stakes.
    - Create a new epoch leader schedule `lsched` using `fd_epoch_leaders_new` and `fd_epoch_leaders_join`.
    - Call [`test_distribution_is_tree`](#test_distribution_is_tree) to verify the distribution of stakes forms a valid tree structure.
    - Delete the epoch leader schedule using `fd_epoch_leaders_delete` and `fd_epoch_leaders_leave`.
    - Delete the random number generator using `fd_rng_delete` and `fd_rng_leave`.
- **Output**: The function does not return any value; it performs tests and logs results.
- **Functions called**:
    - [`test_distribution_is_tree`](#test_distribution_is_tree)


---
### test\_t1\_vary\_radix<!-- {{#callable:test_t1_vary_radix}} -->
The `test_t1_vary_radix` function tests the distribution of shred destinations across varying fanout values to ensure the distribution forms a tree structure.
- **Inputs**: None
- **Control Flow**:
    - Initialize a random number generator `r` using `fd_rng_new` and `fd_rng_join`.
    - Calculate the number of staked validators by iterating over `t1_dest_info` and summing up non-zero stakes.
    - Create an epoch leaders schedule `lsched` using `fd_epoch_leaders_new` and `fd_epoch_leaders_join` with the calculated staked validators.
    - Iterate over fanout values from 35 to 649 in steps of 11.
    - For each fanout value, log the current fanout and call [`test_distribution_is_tree`](#test_distribution_is_tree) to verify the distribution forms a tree structure.
    - Delete the epoch leaders schedule and random number generator using `fd_epoch_leaders_delete` and `fd_rng_delete`.
- **Output**: The function does not return any value; it performs tests and logs results.
- **Functions called**:
    - [`test_distribution_is_tree`](#test_distribution_is_tree)


---
### test\_change\_contact<!-- {{#callable:test_change_contact}} -->
The `test_change_contact` function tests the ability to change and verify the IP address of a shred destination in a distributed ledger system.
- **Inputs**: None
- **Control Flow**:
    - Calculate the number of destination info entries by dividing `t1_dest_info_sz` by the size of `fd_shred_dest_weighted_t`.
    - Cast `t1_dest_info` to a pointer of type `fd_shred_dest_weighted_t` and `t1_pubkey` to a pointer of type `fd_pubkey_t`.
    - Initialize a variable `staked` to zero and iterate over each destination info entry to populate the `stakes` array and count the number of staked entries.
    - Create a new epoch leaders schedule using `fd_epoch_leaders_new` and join it using `fd_epoch_leaders_join`.
    - Create a new shred destination using [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new) and join it using [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join).
    - Change the IP address of the first shred destination to 12 and verify the change using `FD_TEST`.
    - Change the IP address of the first shred destination to 14 and verify the change using `FD_TEST`.
    - Delete the shred destination and epoch leaders schedule using [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete) and `fd_epoch_leaders_delete` respectively.
- **Output**: The function does not return any value; it performs tests and assertions to verify the functionality of changing a shred destination's IP address.
- **Functions called**:
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)
    - [`fd_shred_dest_idx_to_dest`](fd_shred_dest.h.driver.md#fd_shred_dest_idx_to_dest)
    - [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)
    - [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)


---
### test\_errors<!-- {{#callable:test_errors}} -->
The `test_errors` function performs a series of tests to verify error handling in the creation and joining of `fd_shred_dest_t` and `fd_epoch_leaders_t` objects.
- **Inputs**: None
- **Control Flow**:
    - The function begins by testing the [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new) function with invalid parameters, expecting it to return `NULL`.
    - It initializes a `stakes` array with a single entry, setting a key and a stake value.
    - A `fd_epoch_leaders_t` object is created and joined using `fd_epoch_leaders_new` and `fd_epoch_leaders_join`.
    - A `fd_shred_dest_t` object is attempted to be created and joined using [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new) and [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join), expecting it to return `NULL`.
    - Finally, the `fd_epoch_leaders_t` object is deleted and left using `fd_epoch_leaders_delete` and `fd_epoch_leaders_leave`.
- **Output**: The function does not return any value; it uses assertions to verify expected behavior.
- **Functions called**:
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)


---
### test\_indeterminate<!-- {{#callable:test_indeterminate}} -->
The `test_indeterminate` function tests the behavior of a system under conditions where some data is truncated, comparing full and truncated data processing results.
- **Inputs**: None
- **Control Flow**:
    - Initialize a random number generator and set up variables for counting stakes.
    - Iterate over the destination information to populate stakes and count the number of staked entries.
    - Calculate the truncated count and excluded stake based on a 99.5% truncation of the staked count.
    - Allocate memory for full and truncated leader schedules and verify memory constraints.
    - Create full and truncated leader schedules using the allocated memory and stakes information.
    - Allocate memory for full and truncated shred destinations and verify memory constraints.
    - Run a loop 5000 times to simulate the process of selecting a source, creating shred destinations, and computing destinations for shreds.
    - Within the loop, determine if the source is a leader and compute destinations accordingly, updating match and no-destination counts.
    - Log the results of the matching and no-destination counts.
    - Clean up by deleting the created leader schedules and random number generator.
- **Output**: The function does not return a value but logs the number of matched and unmatched destinations due to truncation.
- **Functions called**:
    - [`fd_shred_dest_footprint`](fd_shred_dest.c.driver.md#fd_shred_dest_footprint)
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)
    - [`fd_shred_dest_compute_first`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_first)
    - [`fd_shred_dest_compute_children`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_children)
    - [`fd_shred_dest_delete`](fd_shred_dest.c.driver.md#fd_shred_dest_delete)
    - [`fd_shred_dest_leave`](fd_shred_dest.c.driver.md#fd_shred_dest_leave)


---
### test\_performance<!-- {{#callable:test_performance}} -->
The `test_performance` function evaluates the performance of computing shred destinations by simulating the processing of shreds in batches and measuring the time taken for these operations.
- **Inputs**: None
- **Control Flow**:
    - Initialize `cnt` as the number of destination info entries and `info` as a pointer to the destination info data.
    - Set `src_key` to the public key of the 18th entry in the destination info.
    - Verify that `cnt` does not exceed `TEST_MAX_VALIDATORS`.
    - Initialize `staked` to count the number of entries with positive stake lamports.
    - Verify that the footprint of shred destinations and epoch leaders does not exceed `TEST_MAX_FOOTPRINT`.
    - Measure the time taken to create and join epoch leaders and shred destinations.
    - Initialize arrays for shreds, shred pointers, and results.
    - Set up shreds with specific slot and variant values.
    - Measure the time taken to compute children for 1 shred per batch over `TEST_CNT` iterations and log the result.
    - Measure the time taken to compute children for 16 shreds per batch over `TEST_CNT` iterations and log the result.
- **Output**: The function does not return a value but logs the performance metrics of shred destination computations.
- **Functions called**:
    - [`fd_shred_dest_footprint`](fd_shred_dest.c.driver.md#fd_shred_dest_footprint)
    - [`fd_shred_dest_join`](fd_shred_dest.c.driver.md#fd_shred_dest_join)
    - [`fd_shred_dest_new`](fd_shred_dest.c.driver.md#fd_shred_dest_new)
    - [`fd_shred_dest_compute_children`](fd_shred_dest.c.driver.md#fd_shred_dest_compute_children)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of tests on the system's functionality, and then halts the system.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - The function begins by calling `fd_boot` to initialize the system with the command-line arguments.
    - It checks the alignment of `fd_shred_dest` using `FD_TEST`.
    - The function then sequentially calls various test functions: [`test_errors`](#test_errors), [`test_compute_first_matches_agave`](#test_compute_first_matches_agave), [`test_compute_children_matches_agave`](#test_compute_children_matches_agave), [`test_vary_stake`](#test_vary_stake), [`test_t1_vary_radix`](#test_t1_vary_radix), [`test_batching`](#test_batching), [`test_change_contact`](#test_change_contact), [`test_indeterminate`](#test_indeterminate), and [`test_performance`](#test_performance), each followed by logging a notice message.
    - After all tests are executed, it logs a 'pass' message.
    - Finally, it calls `fd_halt` to terminate the system and returns 0.
- **Output**: The function returns an integer 0, indicating successful execution.
- **Functions called**:
    - [`fd_shred_dest_align`](fd_shred_dest.h.driver.md#fd_shred_dest_align)
    - [`test_errors`](#test_errors)
    - [`test_compute_first_matches_agave`](#test_compute_first_matches_agave)
    - [`test_compute_children_matches_agave`](#test_compute_children_matches_agave)
    - [`test_vary_stake`](#test_vary_stake)
    - [`test_t1_vary_radix`](#test_t1_vary_radix)
    - [`test_batching`](#test_batching)
    - [`test_change_contact`](#test_change_contact)
    - [`test_indeterminate`](#test_indeterminate)
    - [`test_performance`](#test_performance)


