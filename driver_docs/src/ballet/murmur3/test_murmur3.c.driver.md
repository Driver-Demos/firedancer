# Purpose
This C source code file is designed to test and benchmark the Murmur3 hash function, specifically the 32-bit variant, as well as related hash functions like `fd_pchash` and `fd_pchash_inverse`. The file includes a series of predefined test vectors, each consisting of a message, its size, a seed, and the expected hash value. These vectors are used to verify the correctness of the `fd_murmur3_32` function by comparing the computed hash against the expected value. The main function initializes a random number generator and iterates over these test vectors to ensure the hash function produces the correct output.

In addition to correctness testing, the file includes benchmarking routines to measure the performance of the hash functions. It benchmarks the Murmur3 hash function on small inputs and generic data, as well as the `fd_pchash` and `fd_pchash_inverse` functions. The benchmarking sections involve warming up the functions and then measuring the time taken to process a large number of hash computations, reporting the results in terms of nanoseconds per hash or gigabytes per second. The file is structured as an executable C program, with a [`main`](#main) function that orchestrates the testing and benchmarking processes, and it relies on external functions and macros from included headers for logging, random number generation, and other utilities.
# Imports and Dependencies

---
- `../fd_ballet.h`
- `fd_murmur3.h`


# Global Variables

---
### fd\_murmur3\_32\_test\_vector
- **Type**: `fd_murmur3_32_test_vector_t const[]`
- **Description**: The `fd_murmur3_32_test_vector` is a static constant array of `fd_murmur3_32_test_vector_t` structures. Each element in the array contains a precomputed hash value, a message string, the size of the message, and a seed value. This array is used to test the correctness of the Murmur3 32-bit hash function implementation by comparing computed hash values against expected ones.
- **Use**: This variable is used to verify the correctness of the Murmur3 32-bit hash function by iterating over the test vectors and comparing computed hash values with expected results.


# Data Structures

---
### fd\_murmur3\_32\_test\_vector
- **Type**: `struct`
- **Members**:
    - `hash`: Stores the expected hash value for the test vector.
    - `msg`: Points to the message string to be hashed.
    - `sz`: Indicates the size of the message in bytes.
    - `seed`: Specifies the seed value used in the hash function.
- **Description**: The `fd_murmur3_32_test_vector` structure is used to define test vectors for verifying the correctness of the Murmur3 32-bit hash function implementation. Each instance of this structure contains a message, its size, a seed for the hash function, and the expected hash result. This allows for automated testing of the hash function by comparing the computed hash against the expected value for various inputs.


---
### fd\_murmur3\_32\_test\_vector\_t
- **Type**: `struct`
- **Members**:
    - `hash`: Stores the expected hash value for the test vector.
    - `msg`: A pointer to a constant character string representing the message to be hashed.
    - `sz`: The size of the message in bytes.
    - `seed`: The seed value used for the hash function.
- **Description**: The `fd_murmur3_32_test_vector_t` structure is used to define test vectors for verifying the correctness of the Murmur3 32-bit hash function implementation. Each instance of this structure contains a precomputed hash value (`hash`), a message (`msg`) to be hashed, the size of the message (`sz`), and a seed (`seed`) used in the hash computation. This structure is primarily used in testing scenarios to ensure that the hash function produces the expected results for a given set of inputs.


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, performs hash function tests and benchmarks using Murmur3 and custom hash functions, and logs the results.
- **Inputs**:
    - `argc`: The number of command-line arguments.
    - `argv`: An array of command-line argument strings.
- **Control Flow**:
    - Initialize the environment with `fd_boot` and set up a random number generator.
    - Iterate over a set of test vectors to verify the correctness of the [`fd_murmur3_32`](fd_murmur3.c.driver.md#fd_murmur3_32) hash function against expected values, logging errors if mismatches occur.
    - Perform a series of tests to verify the [`fd_pchash`](fd_murmur3.h.driver.md#fd_pchash) and [`fd_pchash_inverse`](fd_murmur3.h.driver.md#fd_pchash_inverse) functions for a range of values.
    - Log a notice about benchmarking small inputs and perform a warmup loop followed by a benchmarking loop for the [`fd_murmur3_32`](fd_murmur3.c.driver.md#fd_murmur3_32) function with small inputs, logging the time per hash.
    - Log a notice about benchmarking generic hashrate, generate random data, and perform warmup and benchmarking loops for the [`fd_murmur3_32`](fd_murmur3.c.driver.md#fd_murmur3_32) function with larger inputs, logging the throughput in GiB/s.
    - Log a notice about benchmarking `pchash` and perform warmup and benchmarking loops for the [`fd_pchash`](fd_murmur3.h.driver.md#fd_pchash) function, logging the time per hash.
    - Log a notice about benchmarking `pchash_inverse` and perform warmup and benchmarking loops for the [`fd_pchash_inverse`](fd_murmur3.h.driver.md#fd_pchash_inverse) function, logging the time per hash.
    - Clean up the random number generator and log a final notice indicating the tests passed.
    - Terminate the program with `fd_halt` and return 0.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`fd_murmur3_32`](fd_murmur3.c.driver.md#fd_murmur3_32)
    - [`fd_pchash`](fd_murmur3.h.driver.md#fd_pchash)
    - [`fd_pchash_inverse`](fd_murmur3.h.driver.md#fd_pchash_inverse)


