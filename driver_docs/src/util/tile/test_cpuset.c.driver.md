# Purpose
This C source code file is designed to test the functionality of a custom CPU set data structure, `fd_cpuset_t`, which is intended to be a replacement for the standard `cpu_set_t` API provided by POSIX. The file includes a series of test functions that validate the behavior of `fd_cpuset_t` in various scenarios, such as zero initialization, insertion, removal, and set operations (intersection, union, and XOR). These tests ensure that the custom data structure behaves equivalently to the standard `cpu_set_t` when interfaced with POSIX functions, thereby verifying its compatibility and correctness.

The code is structured around several static functions that perform specific tests on the `fd_cpuset_t` data structure. Each test function compares the behavior of `fd_cpuset_t` operations with their `cpu_set_t` counterparts, using assertions to confirm that the results are consistent. The main function initializes the testing environment, executes the test functions, and logs the results. This file is not intended to be a library or a header file for external use but rather a standalone executable for internal testing purposes. It does not define public APIs or external interfaces but focuses on ensuring the reliability and compatibility of the `fd_cpuset_t` implementation.
# Imports and Dependencies

---
- `../fd_util.h`
- `fd_tile_private.h`
- `sched.h`


# Functions

---
### fd\_cpuset\_from\_libc<!-- {{#callable:fd_cpuset_from_libc}} -->
The `fd_cpuset_from_libc` function copies a `cpu_set_t` structure into a `fd_cpuset_t` structure, initializing the destination structure to null before copying.
- **Inputs**:
    - `out`: A pointer to a `fd_cpuset_t` structure where the `cpu_set_t` data will be copied.
    - `pun`: A constant pointer to a `cpu_set_t` structure that contains the data to be copied.
- **Control Flow**:
    - The function begins by calling `fd_cpuset_null` to initialize the `fd_cpuset_t` structure pointed to by `out` to a null state.
    - It then uses `fd_memcpy` to copy the contents of the `cpu_set_t` structure pointed to by `pun` into the `fd_cpuset_t` structure pointed to by `out`.
    - Finally, the function returns the pointer `out`.
- **Output**: The function returns a pointer to the `fd_cpuset_t` structure that has been initialized and populated with data from the `cpu_set_t` structure.


---
### fd\_cpuset\_to\_libc<!-- {{#callable:fd_cpuset_to_libc}} -->
The `fd_cpuset_to_libc` function converts a custom `fd_cpuset_t` type to a standard `cpu_set_t` type by zeroing the output and copying the data.
- **Inputs**:
    - `out`: A pointer to a `cpu_set_t` structure where the converted data will be stored.
    - `pun`: A constant pointer to an `fd_cpuset_t` structure that contains the data to be converted.
- **Control Flow**:
    - The function begins by zeroing the `cpu_set_t` structure pointed to by `out` using the `CPU_ZERO` macro.
    - It then copies the contents of the `fd_cpuset_t` structure pointed to by `pun` into the `cpu_set_t` structure pointed to by `out` using `fd_memcpy`.
    - Finally, the function returns the pointer to the `cpu_set_t` structure `out`.
- **Output**: A pointer to the `cpu_set_t` structure that has been populated with the converted data.


---
### test\_cpu\_zero<!-- {{#callable:test_cpu_zero}} -->
The `test_cpu_zero` function tests the zero initialization and zeroing of CPU sets using both `fd_cpuset_t` and `cpu_set_t` types to ensure compatibility and correctness.
- **Inputs**: None
- **Control Flow**:
    - The function begins with a block to test zero initialization using `FD_CPUSET_DECL` to declare a `fd_cpuset_t` variable `foo`, converts it to a `cpu_set_t` using [`fd_cpuset_to_libc`](#fd_cpuset_to_libc), and asserts that the CPU count is zero using `FD_TEST`.
    - The second block tests the `CPU_ZERO` operation by zeroing a `cpu_set_t` array `foo`, converting it to a `fd_cpuset_t` using [`fd_cpuset_from_libc`](#fd_cpuset_from_libc), and asserting that the CPU count is zero using `FD_TEST`.
- **Output**: The function does not return any value; it performs assertions to validate the zeroing operations.
- **Functions called**:
    - [`fd_cpuset_to_libc`](#fd_cpuset_to_libc)
    - [`fd_cpuset_from_libc`](#fd_cpuset_from_libc)


---
### test\_cpu\_insert<!-- {{#callable:test_cpu_insert}} -->
The `test_cpu_insert` function tests the insertion of random CPU indices into custom and standard CPU set data structures, ensuring their equivalence in behavior.
- **Inputs**:
    - `rng`: A pointer to a random number generator of type `fd_rng_t` used to generate random CPU indices.
- **Control Flow**:
    - Calculate `load_cnt` as a random number between 8 and one-third of `CPU_SETSIZE`, ensuring it is less than half of `CPU_SETSIZE`.
    - Declare a custom CPU set `foo` and insert `load_cnt` random indices into it using `fd_cpuset_insert`.
    - Convert `foo` to a standard `cpu_set_t` named `pun` using [`fd_cpuset_to_libc`](#fd_cpuset_to_libc).
    - Verify that each index in `foo` matches the corresponding index in `pun` using `fd_cpuset_test` and `CPU_ISSET`.
    - Check that the count of set indices in `foo` matches the count in `pun` using `fd_cpuset_cnt` and `CPU_COUNT`.
    - Declare a standard `cpu_set_t` `foo`, zero it, and insert `load_cnt` random indices using `CPU_SET`.
    - Convert `foo` to a custom CPU set `pun` using [`fd_cpuset_from_libc`](#fd_cpuset_from_libc).
    - Verify that each index in `pun` matches the corresponding index in `foo` using `fd_cpuset_test` and `CPU_ISSET`.
    - Check that the count of set indices in `pun` matches the count in `foo` using `fd_cpuset_cnt` and `CPU_COUNT`.
- **Output**: The function does not return a value; it performs assertions to verify the correctness of CPU set operations.
- **Functions called**:
    - [`fd_cpuset_to_libc`](#fd_cpuset_to_libc)
    - [`fd_cpuset_from_libc`](#fd_cpuset_from_libc)


---
### test\_cpu\_remove<!-- {{#callable:test_cpu_remove}} -->
The `test_cpu_remove` function tests the removal of CPU indices from a CPU set using both custom and POSIX APIs, ensuring consistency between them.
- **Inputs**:
    - `rng`: A pointer to a random number generator of type `fd_rng_t` used to generate random indices for CPU set operations.
- **Control Flow**:
    - Calculate `load_cnt` as a random number between 8 and one-third of `CPU_SETSIZE`, ensuring it is greater than 0 and less than half of `CPU_SETSIZE`.
    - Initialize a CPU set `foo` with all bits set and remove `load_cnt` random indices using `fd_cpuset_remove`.
    - Convert `foo` to a POSIX `cpu_set_t` and verify that each index's presence matches between `foo` and the POSIX set, and that the count of set bits is the same.
    - Initialize a POSIX `cpu_set_t` `foo` with all indices set and remove `load_cnt` random indices using `CPU_CLR`.
    - Convert the POSIX `cpu_set_t` to a custom CPU set and verify that each index's presence matches between the custom set and the POSIX set, and that the count of set bits is the same.
- **Output**: The function does not return a value; it performs tests and assertions to verify the correctness of CPU set operations.
- **Functions called**:
    - [`fd_cpuset_to_libc`](#fd_cpuset_to_libc)
    - [`fd_cpuset_from_libc`](#fd_cpuset_from_libc)


---
### test\_cpu\_set<!-- {{#callable:test_cpu_set}} -->
The `test_cpu_set` function tests the functionality of `fd_cpuset_t` operations by comparing them with equivalent `cpu_set_t` operations using random CPU indices.
- **Inputs**:
    - `rng`: A pointer to a random number generator of type `fd_rng_t` used to generate random CPU indices.
- **Control Flow**:
    - Initialize `load_cnt` with a random value between 8 and `CPU_SETSIZE/3`, ensuring it is greater than 0 and less than `CPU_SETSIZE/2`.
    - Declare two `fd_cpuset_t` sets, `foo0` and `foo1`, and populate them with random indices using `fd_cpuset_insert`.
    - Declare `fd_cpuset_t` sets `foo_and`, `foo_or`, and `foo_xor` and perform intersection, union, and XOR operations on `foo0` and `foo1`.
    - Convert `foo0` and `foo1` to `cpu_set_t` types `bar0` and `bar1` using [`fd_cpuset_to_libc`](#fd_cpuset_to_libc).
    - Perform intersection, union, and XOR operations on `bar0` and `bar1` to create `bar_and`, `bar_or`, and `bar_xor`.
    - Verify that the results of `fd_cpuset_t` operations match the `cpu_set_t` operations for each index in `CPU_SETSIZE`.
    - Convert `bar_and`, `bar_or`, and `bar_xor` back to `fd_cpuset_t` and verify equality with `foo_and`, `foo_or`, and `foo_xor`.
    - Test equality of `bar0` with itself and `foo0` with itself, then modify `bar0` and `bar1` and verify they are not equal to each other.
- **Output**: The function does not return a value but performs a series of tests to ensure the correctness of `fd_cpuset_t` operations compared to `cpu_set_t` operations, using assertions to validate the results.
- **Functions called**:
    - [`fd_cpuset_to_libc`](#fd_cpuset_to_libc)
    - [`fd_cpuset_from_libc`](#fd_cpuset_from_libc)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of tests on CPU set operations, logs the results, and then cleans up before exiting.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Create and join a random number generator using `fd_rng_new` and `fd_rng_join`.
    - Assert that the footprint of `fd_cpuset` is at least the size of `cpu_set_t`.
    - Call [`test_cpu_zero`](#test_cpu_zero) to test zero initialization of CPU sets.
    - Call [`test_cpu_insert`](#test_cpu_insert) with the random number generator to test insertion operations on CPU sets.
    - Call [`test_cpu_remove`](#test_cpu_remove) with the random number generator to test removal operations on CPU sets.
    - Call [`test_cpu_set`](#test_cpu_set) with the random number generator to test set operations (intersection, union, xor) on CPU sets.
    - Log a notice indicating the tests passed using `FD_LOG_NOTICE`.
    - Delete the random number generator using `fd_rng_delete` after leaving it with `fd_rng_leave`.
    - Call `fd_halt` to perform any necessary cleanup before exiting.
    - Return 0 to indicate successful execution.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`test_cpu_zero`](#test_cpu_zero)
    - [`test_cpu_insert`](#test_cpu_insert)
    - [`test_cpu_remove`](#test_cpu_remove)
    - [`test_cpu_set`](#test_cpu_set)


