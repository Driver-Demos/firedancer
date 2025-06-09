# Purpose
This C source code file is a comprehensive test suite for a transaction cache system, likely part of a larger software project. The file includes various test functions that validate the functionality of a transaction cache, which is designed to store and manage transaction data efficiently. The code is structured to test different aspects of the transaction cache, such as initialization, insertion, querying, and concurrency handling. It uses a series of static functions to perform operations like inserting transactions, checking for their presence, and managing root slots, which are likely used to organize or prioritize transactions within the cache.

The file is not intended to be a standalone executable but rather a test harness for the transaction cache module, as indicated by the inclusion of the header file "fd_txncache.h" and the use of functions prefixed with `fd_txncache_`. The main function orchestrates the execution of various test cases, ensuring that the transaction cache behaves as expected under different scenarios, including edge cases and concurrent access. The use of assertions and logging throughout the code helps in identifying and diagnosing issues during the testing process. This file is crucial for maintaining the reliability and performance of the transaction cache component within the broader system.
# Imports and Dependencies

---
- `fd_txncache.h`
- `pthread.h`
- `../../util/tmpl/fd_sort.c`


# Global Variables

---
### txncache\_scratch\_sz
- **Type**: `ulong`
- **Description**: `txncache_scratch_sz` is a global variable of type `ulong` that represents the size of the memory allocated for the transaction cache scratch space. It is used to ensure that the allocated memory is sufficient for the operations performed on the transaction cache.
- **Use**: This variable is used to check if the allocated scratch space is large enough to accommodate the required footprint for transaction cache operations.


---
### txncache\_scratch
- **Type**: `uchar *`
- **Description**: `txncache_scratch` is a global pointer to an unsigned character array, which serves as a scratch memory buffer for transaction cache operations. It is used to store temporary data required for various transaction cache operations, such as initialization, insertion, and querying of transactions.
- **Use**: This variable is used as a memory buffer for transaction cache operations, providing the necessary space for storing and manipulating transaction data.


---
### go
- **Type**: `int`
- **Description**: The `go` variable is a static volatile integer that is used to control the execution flow of concurrent threads. It is declared as volatile to ensure that changes to its value are immediately visible to all threads, preventing compiler optimizations that could lead to stale reads.
- **Use**: The `go` variable is used as a flag to signal threads to start executing their tasks in a concurrent environment.


# Functions

---
### init\_all<!-- {{#callable:init_all}} -->
The `init_all` function initializes a transaction cache with specified parameters and returns a pointer to the cache.
- **Inputs**:
    - `max_rooted_slots`: The maximum number of rooted slots the transaction cache can handle.
    - `max_live_slots`: The maximum number of live slots the transaction cache can handle.
    - `max_transactions_per_slot`: The maximum number of transactions per slot the transaction cache can handle.
- **Control Flow**:
    - Calculate the memory footprint required for the transaction cache using [`fd_txncache_footprint`](fd_txncache.c.driver.md#fd_txncache_footprint) with the provided parameters.
    - Check if the calculated footprint is valid using `FD_TEST`.
    - Compare the calculated footprint with `txncache_scratch_sz` to ensure there is enough scratch memory available; log an error if not.
    - Create a new transaction cache using [`fd_txncache_new`](fd_txncache.c.driver.md#fd_txncache_new) with the provided parameters and join it using [`fd_txncache_join`](fd_txncache.c.driver.md#fd_txncache_join).
    - Check if the transaction cache was successfully created and joined using `FD_TEST`.
    - Return the pointer to the initialized transaction cache.
- **Output**: A pointer to the initialized `fd_txncache_t` transaction cache.
- **Functions called**:
    - [`fd_txncache_footprint`](fd_txncache.c.driver.md#fd_txncache_footprint)
    - [`fd_txncache_join`](fd_txncache.c.driver.md#fd_txncache_join)
    - [`fd_txncache_new`](fd_txncache.c.driver.md#fd_txncache_new)


---
### insert<!-- {{#callable:insert}} -->
The `insert` function attempts to insert a transaction into a transaction cache using provided blockhash, txnhash, and slot values.
- **Inputs**:
    - `_blockhash`: An unsigned long integer representing the block hash to be inserted.
    - `_txnhash`: An unsigned long integer representing the transaction hash to be inserted.
    - `slot`: An unsigned long integer representing the slot in which the transaction should be inserted.
- **Control Flow**:
    - Initialize arrays `blockhash`, `txnhash`, and `result` to store the block hash, transaction hash, and result respectively.
    - Store the `_blockhash` and `_txnhash` values into the `blockhash` and `txnhash` arrays using the `FD_STORE` macro.
    - Create an `fd_txncache_insert_t` structure named `insert` and populate it with the `blockhash`, `txnhash`, `slot`, and `result` values.
    - Call [`fd_txncache_insert_batch`](fd_txncache.c.driver.md#fd_txncache_insert_batch) to attempt to insert the transaction into the cache using the `insert` structure.
    - If the insertion fails (indicated by [`fd_txncache_insert_batch`](fd_txncache.c.driver.md#fd_txncache_insert_batch) returning false), log an error message with the provided blockhash, txnhash, and slot values.
- **Output**: The function does not return a value; it performs an insertion operation and logs an error if the insertion fails.
- **Functions called**:
    - [`fd_txncache_insert_batch`](fd_txncache.c.driver.md#fd_txncache_insert_batch)


---
### no\_insert<!-- {{#callable:no_insert}} -->
The `no_insert` function attempts to insert a transaction into a transaction cache and asserts that the insertion fails.
- **Inputs**:
    - `_blockhash`: An unsigned long integer representing the block hash to be inserted.
    - `_txnhash`: An unsigned long integer representing the transaction hash to be inserted.
    - `slot`: An unsigned long integer representing the slot in which the transaction should be inserted.
- **Control Flow**:
    - Initialize arrays `blockhash`, `txnhash`, and `result` to store the block hash, transaction hash, and result respectively.
    - Store the `_blockhash` and `_txnhash` into the `blockhash` and `txnhash` arrays using the `FD_STORE` macro.
    - Create an `fd_txncache_insert_t` structure named `insert` with the initialized arrays and the provided `slot`.
    - Call [`fd_txncache_insert_batch`](fd_txncache.c.driver.md#fd_txncache_insert_batch) to attempt inserting the transaction into the cache and use `FD_TEST` to assert that the insertion fails.
- **Output**: The function does not return any value; it asserts that the insertion operation fails.
- **Functions called**:
    - [`fd_txncache_insert_batch`](fd_txncache.c.driver.md#fd_txncache_insert_batch)


---
### query\_fn<!-- {{#callable:query_fn}} -->
The `query_fn` function checks if a given slot matches a slot value stored in a context pointer.
- **Inputs**:
    - `slot`: An unsigned long integer representing the slot to be checked.
    - `ctx`: A pointer to a context, expected to point to an unsigned long integer representing the slot value to compare against.
- **Control Flow**:
    - The function dereferences the context pointer to obtain the slot value stored in it.
    - It compares the input slot with the dereferenced slot value from the context.
    - The function returns the result of this comparison as a boolean integer (0 for false, non-zero for true).
- **Output**: An integer representing the result of the comparison: 1 if the slot matches the value pointed to by ctx, 0 otherwise.


---
### contains<!-- {{#callable:contains}} -->
The `contains` function checks if a transaction with specified blockhash and txnhash exists in a given slot of the transaction cache and logs an error if it does not.
- **Inputs**:
    - `_blockhash`: An unsigned long integer representing the block hash to be checked.
    - `_txnhash`: An unsigned long integer representing the transaction hash to be checked.
    - `slot`: An unsigned long integer representing the slot in which to check for the transaction.
- **Control Flow**:
    - Initialize two 32-byte arrays, `blockhash` and `txnhash`, to zero.
    - Store the `_blockhash` and `_txnhash` values into the `blockhash` and `txnhash` arrays respectively using the `FD_STORE` macro.
    - Create a `fd_txncache_query_t` structure named `query` and assign the `blockhash` and `txnhash` arrays to its respective fields.
    - Declare an integer array `results` of size 1 to store the query result.
    - Call [`fd_txncache_query_batch`](fd_txncache.c.driver.md#fd_txncache_query_batch) with the transaction cache, the `query` structure, the number of queries (1), the slot, a query function `query_fn`, and the `results` array to check if the transaction exists in the specified slot.
    - If the result indicates the transaction does not exist (i.e., `results[0]` is false), log an error message with the expected blockhash, txnhash, and slot values.
- **Output**: The function does not return a value but logs an error if the transaction is not found in the specified slot.
- **Functions called**:
    - [`fd_txncache_query_batch`](fd_txncache.c.driver.md#fd_txncache_query_batch)


---
### no\_contains<!-- {{#callable:no_contains}} -->
The `no_contains` function checks if a transaction with specified blockhash and txnhash is not present in a given slot of the transaction cache and logs an error if it is found.
- **Inputs**:
    - `_blockhash`: An unsigned long integer representing the block hash to be checked.
    - `_txnhash`: An unsigned long integer representing the transaction hash to be checked.
    - `slot`: An unsigned long integer representing the slot in the transaction cache to be checked.
- **Control Flow**:
    - Initialize two 32-byte arrays, `blockhash` and `txnhash`, to zero.
    - Store the `_blockhash` and `_txnhash` values into the `blockhash` and `txnhash` arrays respectively using the `FD_STORE` macro.
    - Create a `fd_txncache_query_t` structure named `query` and assign the `blockhash` and `txnhash` arrays to its respective fields.
    - Declare an integer array `results` of size 1 to store the query result.
    - Call [`fd_txncache_query_batch`](fd_txncache.c.driver.md#fd_txncache_query_batch) with the transaction cache, the `query` structure, the number of queries (1), the `slot`, a query function `query_fn`, and the `results` array to perform the query.
    - Check if the first element of `results` is non-zero, indicating the transaction is present in the slot.
    - If the transaction is found, log an error message using `FD_LOG_ERR` with the expected absence of the transaction.
- **Output**: The function does not return a value but logs an error if the transaction is unexpectedly found in the specified slot.
- **Functions called**:
    - [`fd_txncache_query_batch`](fd_txncache.c.driver.md#fd_txncache_query_batch)


---
### test0<!-- {{#callable:test0}} -->
The `test0` function initializes a transaction cache, inserts a transaction, and verifies its presence and absence in various slots.
- **Inputs**: None
- **Control Flow**:
    - Logs a notice indicating the start of 'TEST 0'.
    - Calls [`init_all`](#init_all) to initialize the transaction cache with specific parameters (2 rooted slots, 4 live slots, 4 transactions per slot).
    - Inserts a transaction with blockhash 0, txnhash 0, and slot 0 using the [`insert`](#insert) function.
    - Checks if the transaction is present in slot 0 using the [`contains`](#contains) function.
    - Verifies that the transaction is not present in other slots (1, 0, 0), (0, 1, 0), (1, 0, 0), and (1, 1, 1) using the [`no_contains`](#no_contains) function.
- **Output**: The function does not return any value; it performs a series of operations to test the transaction cache functionality.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`insert`](#insert)
    - [`contains`](#contains)
    - [`no_contains`](#no_contains)


---
### test\_new\_join\_leave\_delete<!-- {{#callable:test_new_join_leave_delete}} -->
The function `test_new_join_leave_delete` tests the creation, joining, leaving, and deletion of transaction caches with various configurations and edge cases.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the test with a notice message.
    - Tests the [`fd_txncache_new`](fd_txncache.c.driver.md#fd_txncache_new) function with various invalid parameters to ensure it returns NULL, indicating failure.
    - Tests the [`fd_txncache_new`](fd_txncache.c.driver.md#fd_txncache_new) function with valid parameters to ensure it returns a non-NULL pointer, indicating success.
    - Logs the start of the join test with a notice message.
    - Tests the [`fd_txncache_join`](fd_txncache.c.driver.md#fd_txncache_join) function with invalid parameters to ensure it returns NULL, indicating failure.
    - Tests the [`fd_txncache_join`](fd_txncache.c.driver.md#fd_txncache_join) function with valid parameters to ensure it returns a valid transaction cache pointer.
    - Tests the [`fd_txncache_leave`](fd_txncache.c.driver.md#fd_txncache_leave) function with invalid parameters to ensure it returns NULL, indicating failure.
    - Tests the [`fd_txncache_leave`](fd_txncache.c.driver.md#fd_txncache_leave) function with valid parameters to ensure it returns the original memory address, indicating success.
    - Tests the [`fd_txncache_delete`](fd_txncache.c.driver.md#fd_txncache_delete) function with invalid parameters to ensure it returns NULL, indicating failure.
    - Tests the [`fd_txncache_delete`](fd_txncache.c.driver.md#fd_txncache_delete) function with valid parameters to ensure it returns the original memory address, indicating success.
- **Output**: The function does not return any value; it performs tests and logs results to verify the correctness of transaction cache operations.
- **Functions called**:
    - [`fd_txncache_new`](fd_txncache.c.driver.md#fd_txncache_new)
    - [`fd_txncache_join`](fd_txncache.c.driver.md#fd_txncache_join)
    - [`fd_txncache_leave`](fd_txncache.c.driver.md#fd_txncache_leave)
    - [`fd_txncache_delete`](fd_txncache.c.driver.md#fd_txncache_delete)


---
### test\_register\_root\_slot\_simple<!-- {{#callable:test_register_root_slot_simple}} -->
The function `test_register_root_slot_simple` tests the functionality of registering root slots in a transaction cache and verifies the correct ordering and uniqueness of these slots.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the test with a notice message.
    - Initializes a transaction cache with a maximum of 6 rooted slots using [`init_all`](#init_all).
    - Retrieves the current root slots into an array `slots` and checks that all slots are initially set to `ULONG_MAX`.
    - Registers a root slot with value `15UL` and verifies that it is correctly placed in the first position of the `slots` array, with the rest remaining `ULONG_MAX`.
    - Registers additional root slots with values `9UL` and `20UL`, verifying that they are inserted in ascending order and that the remaining slots are `ULONG_MAX`.
    - Attempts to register duplicate slots (`9UL`, `15UL`, `20UL`) and verifies that the order and values of the slots remain unchanged.
    - Registers more slots (`1UL`, `2UL`, `30UL`) and verifies the correct order and values in the `slots` array.
    - Attempts to register a slot with value `0UL` and verifies that it does not affect the current order and values of the slots.
    - Registers a slot with value `3UL` and verifies the updated order and values in the `slots` array.
    - Registers a slot with value `27UL` and verifies the final order and values in the `slots` array.
- **Output**: The function does not return any value; it performs assertions to verify the correct behavior of the transaction cache's root slot registration.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`fd_txncache_root_slots`](fd_txncache.c.driver.md#fd_txncache_root_slots)
    - [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot)


---
### test\_register\_root\_slot<!-- {{#callable:test_register_root_slot}} -->
The `test_register_root_slot` function tests the functionality of registering root slots in a transaction cache and verifies the correct ordering and uniqueness of these slots.
- **Inputs**: None
- **Control Flow**:
    - Log the start of the test with a notice message.
    - Initialize a transaction cache with default parameters using [`init_all`](#init_all).
    - Create a new transaction cache instance and verify its creation with `FD_TEST`.
    - Initialize an array `slots` of size 300 to store root slots.
    - Call [`fd_txncache_root_slots`](fd_txncache.c.driver.md#fd_txncache_root_slots) to populate `slots` with current root slots and verify all are `ULONG_MAX`.
    - Register root slots with specific values (0, 2, 999, 500, 1) using [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot) and verify the order and uniqueness of slots in `slots` after each registration.
    - Reinitialize the transaction cache and register 300 root slots in descending order, then verify the slots are in ascending order in `slots`.
    - Register additional root slots (16, 96, 128) and verify no change in `slots` as they are already present.
    - Register root slots (0, 1, 3, 1000) and verify the correct order and uniqueness in `slots`.
- **Output**: The function does not return a value but uses assertions (`FD_TEST`) to verify the correct behavior of the transaction cache's root slot registration and ordering.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`fd_txncache_new`](fd_txncache.c.driver.md#fd_txncache_new)
    - [`fd_txncache_root_slots`](fd_txncache.c.driver.md#fd_txncache_root_slots)
    - [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot)


---
### test\_register\_root\_slot\_random<!-- {{#callable:test_register_root_slot_random}} -->
The function `test_register_root_slot_random` tests the functionality of registering random root slots in a transaction cache and verifies the correct ordering and management of these slots.
- **Inputs**: None
- **Control Flow**:
    - Log the start of the test with a notice message.
    - Initialize a transaction cache with default parameters using [`init_all`](#init_all).
    - Declare arrays `slots` and `slots_self` to store slot numbers, and initialize `slots_self` with `ULONG_MAX`.
    - Initialize a random number generator `rng` and join it to prepare for generating random numbers.
    - Iterate 262,144 times to simulate the registration of random root slots.
    - In each iteration, generate a random slot number using `fd_rng_ulong`.
    - Register the generated slot number as a root slot in the transaction cache using [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot).
    - Check if the generated slot number is already in `slots_self`; if not, add it, sort `slots_self`, and maintain its size to a maximum of 300 by removing the oldest entry if necessary.
    - Retrieve the current root slots from the transaction cache into `slots`.
    - Verify that the slots in `slots` match the slots in `slots_self`.
- **Output**: The function does not return any value; it performs tests and uses assertions to verify the correctness of the transaction cache's root slot management.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot)
    - [`fd_txncache_root_slots`](fd_txncache.c.driver.md#fd_txncache_root_slots)


---
### test\_full\_blockhash<!-- {{#callable:test_full_blockhash}} -->
The `test_full_blockhash` function tests the insertion and querying of transaction hashes in a transaction cache over a large range of indices, verifying the presence or absence of these hashes at specific points.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the test with a notice message.
    - Initializes the transaction cache with default parameters for maximum rooted slots, live slots, and transactions per slot.
    - Iterates over a large range (150 * 524288) and inserts transaction hashes with a blockhash of 0 and varying transaction hashes into the cache.
    - For the first index (i=0), checks that all indices up to the current index are contained in the cache and those beyond are not.
    - For the last index (i=150 * 524288 - 1), checks that the last 4096 indices are contained in the cache and those beyond are not.
    - For a middle index (i=31 + 150 * 524288 / 2), checks that a range around this index is contained in the cache and those beyond are not.
    - Attempts to insert transactions with blockhashes 1 and 2 and verifies that certain transactions cannot be inserted.
- **Output**: The function does not return any value; it performs tests and logs errors if any assertions fail.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`insert`](#insert)
    - [`contains`](#contains)
    - [`no_contains`](#no_contains)
    - [`no_insert`](#no_insert)


---
### test\_insert\_forks<!-- {{#callable:test_insert_forks}} -->
The `test_insert_forks` function tests the insertion and verification of transactions in a transaction cache, simulating the registration of root slots and checking the presence or absence of transactions in those slots.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the test with a notice message.
    - Initializes a transaction cache with default parameters using [`init_all`](#init_all).
    - Inserts 1024 transactions into the cache, each with a unique blockhash and slot, using the [`insert`](#insert) function.
    - Verifies that each of the 1024 transactions is present in the cache using the [`contains`](#contains) function.
    - Registers the first 450 slots as root slots in the transaction cache using [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot).
    - Checks that the first 150 transactions are no longer present in the cache using the [`no_contains`](#no_contains) function, while the remaining transactions are still present.
    - Registers slot 450 as a root slot and verifies that transaction 150 is not present, while transactions from 151 to 1023 are present.
- **Output**: The function does not return any value; it performs a series of tests and logs errors if any test fails.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`insert`](#insert)
    - [`contains`](#contains)
    - [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot)
    - [`no_contains`](#no_contains)


---
### test\_purge\_gap<!-- {{#callable:test_purge_gap}} -->
The `test_purge_gap` function tests the behavior of a transaction cache when a gap in registered root slots causes certain transactions to be purged.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the 'TEST PURGE GAP'.
    - Initializes a transaction cache with default parameters using [`init_all`](#init_all).
    - Inserts five transactions with specific blockhash, txnhash, and slot values into the cache.
    - Verifies that all inserted transactions are present in the cache using [`contains`](#contains).
    - Registers root slots from 0 to 999 in the transaction cache.
    - Verifies that the transaction in slot 0 is still present, but the transaction in slot 1 is purged, while others remain present.
- **Output**: The function does not return any value; it performs assertions to verify the expected behavior of the transaction cache.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`insert`](#insert)
    - [`contains`](#contains)
    - [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot)
    - [`no_contains`](#no_contains)


---
### test\_many\_blockhashes<!-- {{#callable:test_many_blockhashes}} -->
The `test_many_blockhashes` function tests the insertion and querying of multiple blockhashes in a transaction cache, ensuring correct behavior when slots are registered as root slots.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the test with a notice message.
    - Initializes a transaction cache with default parameters using [`init_all`](#init_all).
    - Iterates over 1024 blockhashes, inserting each into the cache and verifying its presence with [`contains`](#contains).
    - Attempts to insert a blockhash beyond the 1024th index and expects it to fail using [`no_insert`](#no_insert).
    - Registers 301 slots as root slots in descending order starting from 1023.
    - Verifies that blockhashes from 1023 to 724 are still present in the cache using [`contains`](#contains).
    - Checks that blockhashes from 0 to 723 are not present in the cache using [`no_contains`](#no_contains).
- **Output**: The function does not return any value; it performs tests and logs errors if any assertions fail.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`insert`](#insert)
    - [`contains`](#contains)
    - [`no_insert`](#no_insert)
    - [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot)
    - [`no_contains`](#no_contains)


---
### full\_blockhash\_concurrent\_fn<!-- {{#callable:full_blockhash_concurrent_fn}} -->
The `full_blockhash_concurrent_fn` function inserts transaction hashes into a cache in a concurrent manner, iterating over a range of values with a specific step size.
- **Inputs**:
    - `arg`: A pointer to an unsigned long integer, which is used as the starting index for the loop.
- **Control Flow**:
    - The function casts the input argument `arg` to an unsigned long integer `i`.
    - It enters a for-loop starting from `i`, iterating up to `150UL*524288UL`, incrementing by `30UL` in each iteration.
    - In each iteration, it calls the [`insert`](#insert) function with parameters `0UL`, the current loop index `j`, and `0UL`.
    - The function returns `NULL` after completing the loop.
- **Output**: The function returns `NULL` after completing the insertion operations.
- **Functions called**:
    - [`insert`](#insert)


---
### full\_blockhash\_concurrent\_query\_fn<!-- {{#callable:full_blockhash_concurrent_query_fn}} -->
The `full_blockhash_concurrent_query_fn` function performs a series of random queries on a transaction cache to check for the presence or absence of specific blockhash and txnhash combinations.
- **Inputs**:
    - `arg`: A pointer to an unsigned long integer, which is used as a seed for the random number generator.
- **Control Flow**:
    - The function casts the input argument `arg` to an unsigned long integer `x`.
    - A random number generator `rng` is initialized using `fd_rng_new` with `x` as the seed and `x+10UL` as the range, and joined using `fd_rng_join`.
    - A loop runs 1000 times, each time generating a random unsigned long integer using `fd_rng_ulong` and performing three queries: [`contains`](#contains), [`no_contains`](#no_contains) with different parameters.
    - The [`contains`](#contains) function checks if a specific blockhash and txnhash combination is present in the cache.
    - The [`no_contains`](#no_contains) function checks if a specific blockhash and txnhash combination is absent from the cache.
    - The function returns `NULL` after completing the loop.
- **Output**: The function returns `NULL` after executing the queries.
- **Functions called**:
    - [`contains`](#contains)
    - [`no_contains`](#no_contains)


---
### test\_full\_blockhash\_concurrent<!-- {{#callable:test_full_blockhash_concurrent}} -->
The function `test_full_blockhash_concurrent` tests the concurrent insertion and querying of blockhashes in a transaction cache using multiple threads.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the test with a notice message.
    - Initializes the transaction cache with default parameters using [`init_all`](#init_all).
    - Creates 30 threads, each executing `full_blockhash_concurrent_fn`, to perform concurrent blockhash insertions.
    - Joins the 30 threads to ensure all insertions are completed before proceeding.
    - Creates 1024 threads, each executing `full_blockhash_concurrent_query_fn`, to perform concurrent queries on the transaction cache.
    - Joins the 1024 threads to ensure all queries are completed before proceeding.
    - Performs two [`no_insert`](#no_insert) operations to verify that certain blockhashes are not inserted.
    - Performs two [`insert`](#insert) operations to verify that certain blockhashes can be inserted.
- **Output**: The function does not return any value; it performs a series of tests and logs errors if any test fails.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`no_insert`](#no_insert)
    - [`insert`](#insert)


---
### full\_blockhash\_concurrent\_insert\_fn2<!-- {{#callable:full_blockhash_concurrent_insert_fn2}} -->
The `full_blockhash_concurrent_insert_fn2` function inserts blockhashes into a transaction cache in a concurrent manner, starting from a given index and incrementing by 30, once a global flag is set.
- **Inputs**:
    - `arg`: A pointer to an unsigned long integer, which represents the starting index for the insertion loop.
- **Control Flow**:
    - The function enters a busy-wait loop until the global variable `go` is set to a non-zero value, indicating that the function can proceed.
    - It casts the input argument `arg` to an unsigned long integer `x`, which serves as the starting index for the loop.
    - A for-loop iterates from `x` to 1024, incrementing by 30 in each iteration.
    - In each iteration, the [`insert`](#insert) function is called with the current index `i`, a transaction hash of 0, and a slot calculated as `i/300`.
    - The function returns `NULL` after completing the loop.
- **Output**: The function returns `NULL` after completing its execution.
- **Functions called**:
    - [`insert`](#insert)


---
### test\_many\_blockhashes\_concurrent<!-- {{#callable:test_many_blockhashes_concurrent}} -->
The function `test_many_blockhashes_concurrent` tests the concurrent insertion and verification of blockhashes using multiple threads.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the test with a notice message.
    - Initializes the transaction cache with default parameters using [`init_all`](#init_all).
    - Creates 30 threads, each executing `full_blockhash_concurrent_insert_fn2`, passing the thread index as an argument.
    - Sets the volatile variable `go` to 1, signaling the threads to start their operations.
    - Joins all 30 threads, ensuring they complete before proceeding.
    - Calls [`no_insert`](#no_insert) to verify that a specific blockhash and transaction hash combination is not inserted.
    - Iterates over 1024 blockhashes, calling [`contains`](#contains) to verify that each blockhash is present in the expected slot.
- **Output**: The function does not return any value; it performs a series of tests and logs errors if any assertions fail.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`no_insert`](#no_insert)
    - [`contains`](#contains)


---
### test\_cache\_full<!-- {{#callable:test_cache_full}} -->
The `test_cache_full` function tests the behavior of a transaction cache when it is filled to its maximum capacity and then attempts further insertions and root slot registrations.
- **Inputs**: None
- **Control Flow**:
    - Logs the start of the 'TEST CACHE FULL' test.
    - Initializes a transaction cache with default maximum rooted slots, live slots, and transactions per slot using [`init_all`](#init_all).
    - Inserts transactions into the cache for each live slot using a loop from 0 to `TXNCACHE_LIVE_SLOTS`.
    - Attempts to insert a transaction with blockhash 1024, which should not be inserted, using [`no_insert`](#no_insert).
    - Registers the first 500 slots as root slots in the transaction cache using a loop.
    - Attempts to insert transactions again for the first 10 slots.
- **Output**: The function does not return any value; it performs operations to test the transaction cache's behavior under full conditions.
- **Functions called**:
    - [`init_all`](#init_all)
    - [`insert`](#insert)
    - [`no_insert`](#no_insert)
    - [`fd_txncache_register_root_slot`](fd_txncache.c.driver.md#fd_txncache_register_root_slot)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment and memory for transaction cache testing, executes a series of test functions to validate transaction cache operations, and then terminates the program.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Calculate the maximum memory footprint required for the transaction cache using [`fd_txncache_footprint`](fd_txncache.c.driver.md#fd_txncache_footprint).
    - Acquire shared memory for the transaction cache using `fd_shmem_acquire` and store its size in `txncache_scratch_sz`.
    - Verify the acquired memory and alignment using `FD_TEST`.
    - Execute a series of test functions ([`test0`](#test0), [`test_new_join_leave_delete`](#test_new_join_leave_delete), etc.) to validate various transaction cache operations.
    - Log a success message using `FD_LOG_NOTICE`.
    - Call `fd_halt` to terminate the program.
- **Output**: The function returns an integer value `0` indicating successful execution.
- **Functions called**:
    - [`fd_txncache_footprint`](fd_txncache.c.driver.md#fd_txncache_footprint)
    - [`fd_txncache_align`](fd_txncache.c.driver.md#fd_txncache_align)
    - [`test0`](#test0)
    - [`test_new_join_leave_delete`](#test_new_join_leave_delete)
    - [`test_register_root_slot_simple`](#test_register_root_slot_simple)
    - [`test_register_root_slot`](#test_register_root_slot)
    - [`test_register_root_slot_random`](#test_register_root_slot_random)
    - [`test_full_blockhash`](#test_full_blockhash)
    - [`test_insert_forks`](#test_insert_forks)
    - [`test_purge_gap`](#test_purge_gap)
    - [`test_many_blockhashes`](#test_many_blockhashes)
    - [`test_full_blockhash_concurrent`](#test_full_blockhash_concurrent)
    - [`test_many_blockhashes_concurrent`](#test_many_blockhashes_concurrent)
    - [`test_cache_full`](#test_cache_full)


