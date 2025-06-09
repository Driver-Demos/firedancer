# Purpose
This C source code file is designed to test and evaluate the performance and accuracy of a duplicate checking mechanism, likely implemented in the `fd_chkdup` library. The file includes several static functions that perform various tests on the duplicate checking functions, such as `fd_chkdup_check`, `fd_chkdup_check_slow`, and `fd_chkdup_check_fast`. These tests include checking the false positive rate, testing for null inputs, and verifying the handling of duplicate entries. The [`populate_unique`](#populate_unique) function is used to fill memory with unique values, ensuring that no aligned 4-byte sequence occurs twice, which is crucial for testing the duplicate detection logic.

The main function orchestrates the execution of these tests, using a random number generator to create test cases and validate the expected behavior of the duplicate checking functions. It also measures the performance of these functions by calculating the time taken per transaction. The file defines a constant array `FALSE_POSITIVE_RATE` to store expected false positive rates for different configurations, which are used in the tests to verify the accuracy of the duplicate detection. Overall, this file serves as a comprehensive test suite for evaluating the correctness and efficiency of the duplicate checking functions provided by the `fd_chkdup` library.
# Imports and Dependencies

---
- `fd_chkdup.h`
- `math.h`


# Global Variables

---
### FALSE\_POSITIVE\_RATE
- **Type**: `const float[3][129]`
- **Description**: The `FALSE_POSITIVE_RATE` is a global constant two-dimensional array of floats with dimensions 3x129. It contains precomputed false positive rates for different configurations or scenarios, likely used in testing or validating the performance of a duplicate checking algorithm.
- **Use**: This variable is used to provide expected false positive rates for different test cases in the `test_false_positive_rate` function.


# Functions

---
### populate\_unique<!-- {{#callable:populate_unique}} -->
The `populate_unique` function fills a memory region with unique 4-byte sequences derived from a seed, ensuring no sequence repeats, and returns an updated seed for further use.
- **Inputs**:
    - `seed`: An unsigned long integer used as the initial value for generating unique sequences, must be in the range [1, P).
    - `mem`: A pointer to the memory region where the unique sequences will be stored.
    - `sz`: The size of the memory region in bytes, which must be a multiple of 4.
- **Control Flow**:
    - The function asserts that the size `sz` is a multiple of the size of `uint` (4 bytes).
    - It iterates over the memory region in steps of 4 bytes, from 0 to `sz`.
    - In each iteration, it computes a hash of the current seed using `fd_ulong_hash` and stores it as a 4-byte unsigned integer at the current offset in the memory.
    - The seed is then updated using the formula `(seed*2208550410UL)%P` to ensure the next sequence is unique.
- **Output**: The function returns the updated seed value, which can be used to continue generating unique sequences.


---
### test\_false\_positive\_rate<!-- {{#callable:test_false_positive_rate}} -->
The `test_false_positive_rate` function evaluates the false positive rate of a given checker function against expected values using a large number of iterations and statistical analysis.
- **Inputs**:
    - `expected`: A float representing the expected false positive rate.
    - `f`: A function pointer to a checker function that takes two sets of addresses and their counts, and returns an integer indicating false positives.
    - `rng`: A pointer to a random number generator state used for generating random numbers.
    - `l0_cnt`: An unsigned long representing the number of elements in the first set of addresses.
    - `l1_cnt`: An unsigned long representing the number of elements in the second set of addresses.
- **Control Flow**:
    - Initialize constants and variables for iterations and false positives count.
    - Create and join a new `fd_chkdup_t` instance using the provided random number generator.
    - Iterate 1,000,000 times, generating a random base and populating two address arrays with unique values.
    - Invoke the checker function `f` with the populated address arrays and accumulate the false positives count.
    - Calculate the acceptable number of false positives using a normal approximation to the binomial distribution.
    - Log the results and compare the observed false positives to the acceptable threshold.
    - Return 1 if the observed false positives are within the acceptable range, otherwise return 0.
- **Output**: Returns an integer indicating whether the observed false positive rate is within the acceptable range based on the expected rate.
- **Functions called**:
    - [`fd_chkdup_join`](fd_chkdup.h.driver.md#fd_chkdup_join)
    - [`fd_chkdup_new`](fd_chkdup.h.driver.md#fd_chkdup_new)
    - [`populate_unique`](#populate_unique)
    - [`fd_chkdup_delete`](fd_chkdup.h.driver.md#fd_chkdup_delete)
    - [`fd_chkdup_leave`](fd_chkdup.h.driver.md#fd_chkdup_leave)


---
### test\_null<!-- {{#callable:test_null}} -->
The `test_null` function tests a checker function for false positives when zeroed elements are introduced into an array of unique addresses.
- **Inputs**:
    - `f`: A function pointer to a checker function that takes a `fd_chkdup_t` pointer and two arrays of `fd_acct_addr_t` with their sizes.
    - `rng`: A pointer to a random number generator of type `fd_rng_t`.
- **Control Flow**:
    - Initialize an array `l0` of 128 `fd_acct_addr_t` elements and a `fd_chkdup_t` object using the provided random number generator `rng`.
    - Populate `l0` with unique values using [`populate_unique`](#populate_unique).
    - Iterate over each element in `l0`, temporarily zeroing it, and use the checker function `f` to check for false positives in the surrounding 8 elements, updating `false_positive_count` accordingly.
    - Iterate over all 8-bit numbers, zeroing elements in `l0` based on the bit pattern of the number, and use the checker function `f` to check for false positives.
    - If the number of zeroed elements is not a power of two and the checker function returns 0, return 0 indicating a failure.
    - If the number of zeroed elements is a power of two and the checker function returns a positive result, increment `false_positive_count`.
    - Log the number of false positives encountered.
    - Clean up by deleting the `fd_chkdup_t` object and return 1 indicating success.
- **Output**: Returns 1 if the checker function behaves as expected with zeroed elements, otherwise returns 0 if an unexpected result is encountered.
- **Functions called**:
    - [`fd_chkdup_join`](fd_chkdup.h.driver.md#fd_chkdup_join)
    - [`fd_chkdup_new`](fd_chkdup.h.driver.md#fd_chkdup_new)
    - [`populate_unique`](#populate_unique)
    - [`fd_chkdup_delete`](fd_chkdup.h.driver.md#fd_chkdup_delete)
    - [`fd_chkdup_leave`](fd_chkdup.h.driver.md#fd_chkdup_leave)


---
### test\_duplicates<!-- {{#callable:test_duplicates}} -->
The `test_duplicates` function tests for duplicate detection by modifying a list of unique addresses and checking if a given checker function can detect the duplicates.
- **Inputs**:
    - `f`: A function pointer to a checker function that checks for duplicates.
    - `rng`: A pointer to a random number generator used for generating random numbers.
- **Control Flow**:
    - Initialize an array `l0` of 128 `fd_acct_addr_t` elements.
    - Create a `fd_chkdup_t` object using [`fd_chkdup_new`](fd_chkdup.h.driver.md#fd_chkdup_new) and join it with [`fd_chkdup_join`](fd_chkdup.h.driver.md#fd_chkdup_join).
    - Generate a random base using `fd_rng_uint_roll` and populate `l0` with unique values using [`populate_unique`](#populate_unique).
    - Iterate over each pair of indices `i` and `j` in `l0`, skipping when `i` equals `j`.
    - Temporarily set `l0[j]` to `l0[i]` to create a duplicate.
    - Calculate `l0_cnt` and `l1_cnt` such that their sum is greater than the maximum of `i` and `j`, and `l0_cnt + l1_cnt <= 128`.
    - Call the checker function `f` with `chkdup`, `l0`, `l0_cnt`, `l0+l0_cnt`, and `l1_cnt` as arguments.
    - If the checker function returns 0, indicating a failure to detect duplicates, return 0.
    - Restore `l0[j]` to its original value.
    - After all iterations, delete the `chkdup` object and return 1, indicating success.
- **Output**: Returns 1 if all duplicate checks pass, otherwise returns 0 if any duplicate is not detected.
- **Functions called**:
    - [`fd_chkdup_join`](fd_chkdup.h.driver.md#fd_chkdup_join)
    - [`fd_chkdup_new`](fd_chkdup.h.driver.md#fd_chkdup_new)
    - [`populate_unique`](#populate_unique)
    - [`fd_chkdup_delete`](fd_chkdup.h.driver.md#fd_chkdup_delete)
    - [`fd_chkdup_leave`](fd_chkdup.h.driver.md#fd_chkdup_leave)


---
### performance\_test<!-- {{#callable:performance_test}} -->
The `performance_test` function measures the execution time of different `fd_chkdup` check functions over a series of iterations and returns the average time per transaction.
- **Inputs**:
    - `rng`: A pointer to a random number generator state (`fd_rng_t *`) used for generating random numbers.
    - `which`: An integer indicating which `fd_chkdup` check function to use: 0 for [`fd_chkdup_check`](fd_chkdup.h.driver.md#fd_chkdup_check), 1 for [`fd_chkdup_check_slow`](fd_chkdup.h.driver.md#fd_chkdup_check_slow), and 2 for [`fd_chkdup_check_fast`](fd_chkdup.h.driver.md#fd_chkdup_check_fast).
- **Control Flow**:
    - Initialize an array `l0` of 32 `fd_acct_addr_t` elements and a `fd_chkdup_t` structure for duplicate checking.
    - Generate a random base using `fd_rng_uint_roll` and populate `l0` with unique values using [`populate_unique`](#populate_unique).
    - Set `false_positives` to 0 and `iters` to 100,000, then start timing with `fd_log_wallclock`.
    - Loop over `iters`, and within each iteration, loop 10 times to perform checks with varying `l0_cnt` values based on the inner loop index `k`.
    - For each `k`, determine `l0_cnt` using a switch statement, then use another switch statement to select and execute the appropriate `fd_chkdup` check function based on `which`, accumulating false positives.
    - After the loops, stop timing and calculate the average time per transaction by dividing the elapsed time by `iters * 10`.
    - Clean up by deleting the `fd_chkdup` structure.
- **Output**: Returns the average time per transaction as an unsigned long integer, representing the time in nanoseconds.
- **Functions called**:
    - [`fd_chkdup_join`](fd_chkdup.h.driver.md#fd_chkdup_join)
    - [`fd_chkdup_new`](fd_chkdup.h.driver.md#fd_chkdup_new)
    - [`populate_unique`](#populate_unique)
    - [`fd_chkdup_check`](fd_chkdup.h.driver.md#fd_chkdup_check)
    - [`fd_chkdup_check_slow`](fd_chkdup.h.driver.md#fd_chkdup_check_slow)
    - [`fd_chkdup_check_fast`](fd_chkdup.h.driver.md#fd_chkdup_check_fast)
    - [`fd_chkdup_delete`](fd_chkdup.h.driver.md#fd_chkdup_delete)
    - [`fd_chkdup_leave`](fd_chkdup.h.driver.md#fd_chkdup_leave)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, performs a series of tests on false positive rates and performance of different duplicate checking functions, and logs the results.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Extract the `--test-interval` value from the command-line arguments using `fd_env_strip_cmdline_ulong`, defaulting to 4 if not provided.
    - Initialize a random number generator `rng` with a seed using `fd_rng_new` and `fd_rng_join`.
    - Retrieve the false positive rate array for the current implementation using `FALSE_POSITIVE_RATE[FD_CHKDUP_IMPL]`.
    - Loop over a range of values for `l0` and perform false positive rate tests using [`test_false_positive_rate`](#test_false_positive_rate) with different checking functions (`fd_chkdup_check`, `fd_chkdup_check_slow`, `fd_chkdup_check_fast`).
    - Loop over a range of values for `l` and `k`, calculate `l0` and `l1`, and perform false positive rate tests similarly as above.
    - Perform a specific false positive rate test with `l0` and `l1` set to 4.
    - Log the performance of each checking function using [`performance_test`](#performance_test) and `FD_LOG_NOTICE`.
    - Perform null tests using [`test_null`](#test_null) for each checking function.
    - Perform duplicate tests using [`test_duplicates`](#test_duplicates) for each checking function.
    - Log a success message with `FD_LOG_NOTICE`.
    - Terminate the program using `fd_halt` and return 0.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_false_positive_rate`](#test_false_positive_rate)
    - [`performance_test`](#performance_test)
    - [`test_null`](#test_null)
    - [`test_duplicates`](#test_duplicates)


