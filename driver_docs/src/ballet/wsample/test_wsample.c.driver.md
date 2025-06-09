# Purpose
This C source code file is a comprehensive test suite for a weighted sampling library, which appears to be part of a larger software system. The primary functionality of this code is to validate the correctness and performance of various weighted sampling operations, such as sampling with and without replacement, using a chi-squared goodness-of-fit test to ensure that the observed distribution of samples matches the expected distribution. The code utilizes a pseudo-random number generator (PRNG) based on the ChaCha20 algorithm to ensure deterministic and reproducible test results. The tests cover a wide range of scenarios, including sampling with different probability distributions, handling of edge cases like empty or poisoned samples, and verifying the integrity of the sampling process through various assertions.

The file includes several static inline functions and static functions that encapsulate specific test cases, such as [`test_probability_dist_replacement`](#test_probability_dist_replacement), [`test_probability_dist_noreplacement`](#test_probability_dist_noreplacement), and [`test_matches_solana`](#test_matches_solana), among others. These functions are designed to test the library's ability to handle different sampling strategies and configurations, including the restoration of samples, sharing of sampling trees, and the handling of indeterminate states. The code also includes utility functions for calculating the memory footprint of sampling structures and ensuring that the implementation adheres to expected memory constraints. Overall, this file serves as a critical component in ensuring the reliability and accuracy of the weighted sampling library, providing a robust framework for testing and validation.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `fd_wsample.h`
- `math.h`


# Global Variables

---
### \_shmem
- **Type**: `uchar array`
- **Description**: The `_shmem` variable is a global array of unsigned characters (`uchar`) with a size defined by `MAX_FOOTPRINT`. It is aligned to a 128-byte boundary using the `__attribute__((aligned(128)))` directive, which is often used for performance optimization on certain hardware architectures.
- **Use**: This variable is used as a shared memory buffer for operations involving weighted sampling, as seen in functions like `fd_wsample_new_init`.


---
### \_shmem2
- **Type**: `uchar array`
- **Description**: The variable `_shmem2` is a global array of unsigned characters (`uchar`) with a size defined by `MAX_FOOTPRINT`. It is aligned to a 128-byte boundary using the `__attribute__((aligned(128)))` directive, which ensures that the memory address of the array starts at a 128-byte aligned address.
- **Use**: This variable is used as a shared memory buffer for operations involving weighted sampling, as seen in functions like `fd_wsample_new_init`.


---
### weights
- **Type**: `ulong[MAX]`
- **Description**: The `weights` variable is a global array of unsigned long integers with a size defined by the constant `MAX`, which is set to 1024. This array is used to store weight values for sampling operations in the program.
- **Use**: The `weights` array is used to store and manage weight values for various sampling functions, influencing the probability distribution of sampled elements.


---
### counts
- **Type**: `ulong[MAX]`
- **Description**: The `counts` variable is a global array of unsigned long integers with a size defined by the constant `MAX`, which is set to 1024. This array is used to store counts of occurrences or samples in various statistical tests and sampling operations throughout the program.
- **Use**: The `counts` array is used to accumulate and store the number of times each index is sampled during statistical tests and probability distribution simulations.


---
### seed
- **Type**: `uchar[32]`
- **Description**: The `seed` variable is a global array of 32 unsigned characters, initialized with values ranging from 0 to 31. This array serves as a seed for random number generation, specifically for initializing a ChaCha20 random number generator.
- **Use**: The `seed` is used to initialize the random number generator in various test functions to ensure deterministic behavior during testing.


# Functions

---
### chi\_squared\_test<!-- {{#callable:chi_squared_test}} -->
The `chi_squared_test` function performs a chi-squared goodness of fit test to compare observed and expected frequency distributions, using a precomputed critical value for a significance level of 1%.
- **Inputs**:
    - `observed`: An array of unsigned long integers representing the observed frequency counts.
    - `expected`: An array of unsigned long integers representing the expected frequency counts.
    - `cnt`: An unsigned long integer representing the number of elements in the observed and expected arrays.
- **Control Flow**:
    - Initialize a float variable `stat` to 0.0 to accumulate the chi-squared statistic.
    - Iterate over each element in the `observed` and `expected` arrays, converting them to floats, and update `stat` with the chi-squared contribution for each element.
    - Determine the critical value based on the `cnt` using a switch statement with precomputed values for specific counts.
    - Log the `cnt`, `stat`, and `critical_value` for informational purposes.
    - Use `FD_TEST` to assert that the calculated `stat` is less than the `critical_value`, indicating the null hypothesis is not rejected.
- **Output**: The function does not return a value but logs the chi-squared statistic and critical value, and asserts the test result using `FD_TEST`.


---
### test\_probability\_dist\_replacement<!-- {{#callable:test_probability_dist_replacement}} -->
The `test_probability_dist_replacement` function tests the correctness of a weighted sampling algorithm with replacement using a chi-squared statistical test.
- **Inputs**: None
- **Control Flow**:
    - Initialize a ChaCha20 random number generator with a predefined seed.
    - Set up an array of weights inversely proportional to their index.
    - Iterate over different sample sizes, initializing a weighted sampling structure for each size.
    - For each sample size, calculate the total weight sum and perform sampling with replacement, updating a count array for each sample.
    - Perform a chi-squared test to verify the distribution of samples matches the expected distribution based on weights.
    - Repeat the sampling and chi-squared test using a batch sampling method.
    - Clean up the sampling structure after each iteration.
- **Output**: The function does not return any value; it performs tests and asserts correctness using internal checks.
- **Functions called**:
    - [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)
    - [`fd_wsample_new_add`](fd_wsample.c.driver.md#fd_wsample_new_add)
    - [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)
    - [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)
    - [`fd_wsample_sample`](fd_wsample.c.driver.md#fd_wsample_sample)
    - [`chi_squared_test`](#chi_squared_test)
    - [`fd_wsample_sample_many`](fd_wsample.c.driver.md#fd_wsample_sample_many)
    - [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)
    - [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)


---
### test\_probability\_dist\_noreplacement<!-- {{#callable:test_probability_dist_noreplacement}} -->
The function `test_probability_dist_noreplacement` tests the correctness of a weighted sampling algorithm that samples without replacement, ensuring that the distribution of samples matches expected probabilities.
- **Inputs**: None
- **Control Flow**:
    - Initialize a ChaCha20 random number generator with a predefined seed.
    - Iterate over sample sizes from 1 to 1024, incrementing by 113 each time.
    - For each sample size, initialize a weighted sampling structure with power-law removal hint.
    - Add weights to the sampling structure inversely proportional to the index.
    - Join the sampling structure to create a sampling tree.
    - Sample and remove elements from the tree, ensuring each element is sampled exactly once.
    - Restore all elements to the tree and repeat sampling in batches of 100, checking for correct sampling and removal.
    - Delete the sampling tree after tests for each sample size.
    - Perform a specific test with a 4-element set to verify the distribution of 4-tuples against manually computed probabilities.
    - Conduct a chi-squared test to compare observed and expected distributions.
    - Delete the sampling tree after the chi-squared test.
- **Output**: The function does not return a value but performs tests to ensure the sampling without replacement behaves as expected, using assertions to validate the results.
- **Functions called**:
    - [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)
    - [`fd_wsample_new_add`](fd_wsample.c.driver.md#fd_wsample_new_add)
    - [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)
    - [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)
    - [`fd_wsample_sample_and_remove`](fd_wsample.c.driver.md#fd_wsample_sample_and_remove)
    - [`fd_wsample_restore_all`](fd_wsample.c.driver.md#fd_wsample_restore_all)
    - [`fd_wsample_sample_and_remove_many`](fd_wsample.c.driver.md#fd_wsample_sample_and_remove_many)
    - [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)
    - [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)
    - [`chi_squared_test`](#chi_squared_test)


---
### test\_matches\_solana<!-- {{#callable:test_matches_solana}} -->
The `test_matches_solana` function tests the functionality of a weighted sampling algorithm using a ChaCha20 random number generator to ensure it matches expected outcomes in two scenarios.
- **Inputs**: None
- **Control Flow**:
    - Initialize a ChaCha20 random number generator in MOD mode and set a zero seed.
    - Create a weighted sampling tree with two elements and specific weights, then seed the tree's RNG with the zero seed.
    - Perform a series of tests to ensure the sampling from the tree matches expected outcomes (mostly zeros, with one occurrence of one).
    - Delete the sampling tree and RNG resources.
    - Reinitialize the RNG in SHIFT mode and set a new seed with all bytes set to 48.
    - Create a new weighted sampling tree with 18 elements and specific weights, then seed the tree's RNG with the new seed.
    - Perform a series of tests to ensure the sampling and removal from the tree matches expected outcomes in a specific order.
    - Delete the sampling tree and RNG resources.
- **Output**: The function does not return any value; it performs tests and uses assertions to validate the behavior of the sampling algorithm.
- **Functions called**:
    - [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)
    - [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)
    - [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)
    - [`fd_wsample_new_add`](fd_wsample.c.driver.md#fd_wsample_new_add)
    - [`fd_wsample_seed_rng`](fd_wsample.c.driver.md#fd_wsample_seed_rng)
    - [`fd_wsample_get_rng`](fd_wsample.c.driver.md#fd_wsample_get_rng)
    - [`fd_wsample_sample`](fd_wsample.c.driver.md#fd_wsample_sample)
    - [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)
    - [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)
    - [`fd_wsample_sample_and_remove`](fd_wsample.c.driver.md#fd_wsample_sample_and_remove)


---
### test\_sharing<!-- {{#callable:test_sharing}} -->
The `test_sharing` function tests the interchangeability of two weighted sampling structures initialized with the same random number generator and weights.
- **Inputs**: None
- **Control Flow**:
    - Initialize a ChaCha20 random number generator with a zero seed.
    - Loop 256 times, each time creating a new random number generator instance and initializing it with the zero seed.
    - For each iteration, initialize two weighted sampling structures (`pl1` and `pl2`) with the same random number generator and weights.
    - Join and finalize the weighted sampling structures to create `ws1` and `ws2`.
    - Perform a series of tests to ensure that sampling from either `ws1` or `ws2` yields the expected results based on the iteration index `i`.
    - Delete the weighted sampling structures and leave the random number generator.
- **Output**: The function does not return any value; it performs tests and assertions to verify the behavior of the weighted sampling structures.
- **Functions called**:
    - [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)
    - [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)
    - [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)
    - [`fd_wsample_new_add`](fd_wsample.c.driver.md#fd_wsample_new_add)
    - [`fd_wsample_sample`](fd_wsample.c.driver.md#fd_wsample_sample)
    - [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)
    - [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)


---
### test\_restore\_disabled<!-- {{#callable:test_restore_disabled}} -->
The `test_restore_disabled` function tests the behavior of the `fd_wsample` library when attempting to restore samples from a weighted sample set that has been exhausted, specifically checking that restoration is disabled for one set and enabled for another.
- **Inputs**: None
- **Control Flow**:
    - Initialize a ChaCha20 random number generator with a zero seed.
    - Create two weighted sample sets (`ws1` and `ws2`) with different restoration settings using [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init) and related functions.
    - Perform sampling and removal operations on both sample sets, ensuring they are not empty initially.
    - Check that both sample sets become empty after sufficient removals.
    - Attempt to restore all samples in both sets, expecting `ws1` to not restore (return NULL) and `ws2` to restore (return itself).
    - Verify that `ws1` remains empty after the restore attempt, while `ws2` is not empty.
    - Clean up by deleting the sample sets and the random number generator.
- **Output**: The function does not return any value; it performs assertions to validate the expected behavior of the sample sets.
- **Functions called**:
    - [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)
    - [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)
    - [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)
    - [`fd_wsample_new_add`](fd_wsample.c.driver.md#fd_wsample_new_add)
    - [`fd_wsample_sample_and_remove`](fd_wsample.c.driver.md#fd_wsample_sample_and_remove)
    - [`fd_wsample_restore_all`](fd_wsample.c.driver.md#fd_wsample_restore_all)
    - [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)
    - [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)


---
### test\_remove\_idx<!-- {{#callable:test_remove_idx}} -->
The `test_remove_idx` function tests the behavior of removing an index from a weighted sample and verifies the sampling results after removal.
- **Inputs**: None
- **Control Flow**:
    - Initialize a ChaCha20 random number generator with a zero seed.
    - Create a new weighted sample with two elements and add weights to them.
    - Remove the element at index 1 from the sample.
    - Verify that sampling the modified sample does not return the removed index.
    - Attempt to remove the same index again, which should be a no-op, and verify the sample returns the expected result.
    - Sample and remove elements from the sample, checking for expected results and empty conditions.
    - Restore all elements in the sample and verify sampling and removal behavior again.
    - Clean up by deleting the sample and the random number generator.
- **Output**: The function does not return any value; it performs tests and assertions to verify the behavior of the weighted sample operations.
- **Functions called**:
    - [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)
    - [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)
    - [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)
    - [`fd_wsample_new_add`](fd_wsample.c.driver.md#fd_wsample_new_add)
    - [`fd_wsample_remove_idx`](fd_wsample.c.driver.md#fd_wsample_remove_idx)
    - [`fd_wsample_sample`](fd_wsample.c.driver.md#fd_wsample_sample)
    - [`fd_wsample_sample_and_remove`](fd_wsample.c.driver.md#fd_wsample_sample_and_remove)
    - [`fd_wsample_restore_all`](fd_wsample.c.driver.md#fd_wsample_restore_all)
    - [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)
    - [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)


---
### test\_map<!-- {{#callable:test_map}} -->
The `test_map` function tests the mapping of samples to indices in a weighted sampling tree using a deterministic random number generator.
- **Inputs**: None
- **Control Flow**:
    - Initialize a ChaCha20 random number generator with a specific mode.
    - Set the size of the sample space to 1018 and initialize a weighted sampling structure with a power-law distribution hint.
    - Add weights to the sampling structure inversely proportional to the index plus one.
    - Finalize the sampling structure and join it to create a sampling tree.
    - Iterate over the sample space, using the [`fd_wsample_map_sample`](fd_wsample.c.driver.md#fd_wsample_map_sample) function to verify that each sample maps to the correct index based on the weights.
    - Delete the sampling tree and the random number generator to clean up resources.
- **Output**: The function does not return any value; it performs tests and assertions to verify the correctness of the sample mapping.
- **Functions called**:
    - [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)
    - [`fd_wsample_new_add`](fd_wsample.c.driver.md#fd_wsample_new_add)
    - [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)
    - [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)
    - [`fd_wsample_map_sample`](fd_wsample.c.driver.md#fd_wsample_map_sample)
    - [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)
    - [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)


---
### test\_empty<!-- {{#callable:test_empty}} -->
The `test_empty` function tests the behavior of a weighted sampling tree when it is initialized with zero elements, ensuring that sampling operations return an empty result.
- **Inputs**: None
- **Control Flow**:
    - Initialize a ChaCha20 random number generator.
    - Create a weighted sampling tree with zero elements using [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init) and [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini).
    - Join the tree and verify its creation with `FD_TEST`.
    - Test that sampling and sampling with removal both return `FD_WSAMPLE_EMPTY`.
    - Delete the tree and repeat the process with a poisoned tree (using a different initialization parameter).
    - Ensure that even with a poisoned tree, sampling operations return `FD_WSAMPLE_EMPTY`.
    - Delete the tree and clean up the random number generator.
- **Output**: The function does not return any value; it performs tests and assertions to verify expected behavior.
- **Functions called**:
    - [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)
    - [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)
    - [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)
    - [`fd_wsample_sample`](fd_wsample.c.driver.md#fd_wsample_sample)
    - [`fd_wsample_sample_and_remove`](fd_wsample.c.driver.md#fd_wsample_sample_and_remove)
    - [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)
    - [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)


---
### test\_footprint<!-- {{#callable:test_footprint}} -->
The `test_footprint` function verifies that the `FD_WSAMPLE_FOOTPRINT` macro and the [`fd_wsample_footprint`](fd_wsample.c.driver.md#fd_wsample_footprint) function produce identical results for various input values.
- **Inputs**: None
- **Control Flow**:
    - The function iterates over integers from 0 to 999, checking that `FD_WSAMPLE_FOOTPRINT(i, 0)` equals `fd_wsample_footprint(i, 0)` and `FD_WSAMPLE_FOOTPRINT(i, 1)` equals `fd_wsample_footprint(i, 1)`.
    - It then iterates over integers starting from 729, multiplying by 3 each time, up to `UINT_MAX`, checking the same equality for `i-1`, `i`, and `i+1` with both 0 and 1 as the second argument.
    - Finally, it iterates over integers starting from 512, multiplying by 2 each time, up to `UINT_MAX`, performing the same checks as the previous loop.
- **Output**: The function does not return any value; it performs assertions to ensure the correctness of the footprint calculations.
- **Functions called**:
    - [`fd_wsample_footprint`](fd_wsample.c.driver.md#fd_wsample_footprint)


---
### test\_poison<!-- {{#callable:test_poison}} -->
The `test_poison` function tests the behavior of a weighted sampling system, particularly focusing on the handling of indeterminate samples and ensuring statistical correctness through a chi-squared test.
- **Inputs**: None
- **Control Flow**:
    - Initialize a ChaCha20 random number generator with a predefined seed.
    - Create a weighted sampling structure with 23 elements and a special 'poison' weight for the 24th element.
    - Calculate the sum of all weights.
    - Perform a sampling loop for the total weight sum, checking that samples are either valid indices or indeterminate, and count occurrences.
    - Conduct a chi-squared test to verify the distribution of samples matches expected weights.
    - Perform multiple sampling rounds to ensure that once an indeterminate sample is encountered, subsequent samples remain indeterminate, and count total indeterminate occurrences.
    - Assert that the total number of indeterminate samples is less than a specified threshold.
    - Clean up by deleting the sampling structure and the random number generator.
- **Output**: The function does not return a value but performs assertions to validate the behavior of the sampling system.
- **Functions called**:
    - [`fd_wsample_new_init`](fd_wsample.c.driver.md#fd_wsample_new_init)
    - [`fd_wsample_new_add`](fd_wsample.c.driver.md#fd_wsample_new_add)
    - [`fd_wsample_join`](fd_wsample.c.driver.md#fd_wsample_join)
    - [`fd_wsample_new_fini`](fd_wsample.c.driver.md#fd_wsample_new_fini)
    - [`fd_wsample_sample`](fd_wsample.c.driver.md#fd_wsample_sample)
    - [`chi_squared_test`](#chi_squared_test)
    - [`fd_wsample_sample_and_remove`](fd_wsample.c.driver.md#fd_wsample_sample_and_remove)
    - [`fd_wsample_restore_all`](fd_wsample.c.driver.md#fd_wsample_restore_all)
    - [`fd_wsample_delete`](fd_wsample.c.driver.md#fd_wsample_delete)
    - [`fd_wsample_leave`](fd_wsample.c.driver.md#fd_wsample_leave)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of tests on weighted sampling functions, and logs the results before halting the program.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Perform a test to ensure the footprint of a weighted sample does not exceed a maximum footprint.
    - Execute a series of test functions: [`test_matches_solana`](#test_matches_solana), [`test_map`](#test_map), [`test_sharing`](#test_sharing), [`test_restore_disabled`](#test_restore_disabled), [`test_remove_idx`](#test_remove_idx), [`test_empty`](#test_empty), [`test_footprint`](#test_footprint), [`test_poison`](#test_poison), [`test_probability_dist_replacement`](#test_probability_dist_replacement), and [`test_probability_dist_noreplacement`](#test_probability_dist_noreplacement).
    - Log a notice indicating the tests have passed.
    - Call `fd_halt` to terminate the program.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`fd_wsample_footprint`](fd_wsample.c.driver.md#fd_wsample_footprint)
    - [`test_matches_solana`](#test_matches_solana)
    - [`test_map`](#test_map)
    - [`test_sharing`](#test_sharing)
    - [`test_restore_disabled`](#test_restore_disabled)
    - [`test_remove_idx`](#test_remove_idx)
    - [`test_empty`](#test_empty)
    - [`test_footprint`](#test_footprint)
    - [`test_poison`](#test_poison)
    - [`test_probability_dist_replacement`](#test_probability_dist_replacement)
    - [`test_probability_dist_noreplacement`](#test_probability_dist_noreplacement)


# Function Declarations (Public API)

---
### fd\_wsample\_map\_sample<!-- {{#callable_declaration:fd_wsample_map_sample}} -->
Maps a query value to a sample index using a weighted sampler.
- **Description**: This function is used to map a given query value to a sample index based on the weights defined in the sampler. It is typically used in scenarios where weighted sampling is required, such as probabilistic data structures or simulations. The function requires a properly initialized sampler and a valid query value. It is important to ensure that the sampler is correctly set up with the desired weights before calling this function.
- **Inputs**:
    - `sampler`: A pointer to an fd_wsample_t structure representing the weighted sampler. Must be properly initialized and not null. The caller retains ownership.
    - `query`: An unsigned long integer representing the query value to be mapped. The value should be within the valid range for the sampler's configuration.
- **Output**: Returns an unsigned long integer representing the index of the sample corresponding to the query value.
- **See also**: [`fd_wsample_map_sample`](fd_wsample.c.driver.md#fd_wsample_map_sample)  (Implementation)


