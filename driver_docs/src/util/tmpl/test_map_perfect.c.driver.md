# Purpose
This C source code file is designed to implement and test a series of perfect hash maps, which are specialized data structures that allow for efficient key-value lookups with guaranteed constant-time complexity. The file includes multiple instances of perfect hash maps, each tailored for different types of keys and values. The primary technical components include the definition of data structures and macros that configure the properties of each hash map, such as the table size, hash constants, and key types. The file also includes test functions to verify the correctness of these hash maps, ensuring that they correctly identify the presence of keys and compute associated values.

The code is structured to be part of a larger project, as indicated by the inclusion of external files like "fd_util.h" and "fd_map_perfect.c". It defines several hash maps with varying configurations, such as maps for prime numbers, primitive roots, and permutations. Each map is defined using a set of macros that specify its characteristics, and the maps are tested using inline functions that validate their behavior. Additionally, the file contains AVX-512 optimized functions for finding constants related to specific data sets, demonstrating the use of SIMD instructions for performance optimization. The presence of a `main` function suggests that this file is intended to be compiled into an executable for testing purposes.
# Imports and Dependencies

---
- `../fd_util.h`
- `fd_map_perfect.c`
- `../simd/fd_avx512.h`


# Data Structures

---
### wrapped\_ul
- **Type**: `struct`
- **Members**:
    - `key`: A member of type 'ulong' that stores a key value.
- **Description**: The 'wrapped_ul' structure is a simple data structure that encapsulates a single unsigned long integer, referred to as 'key'. This structure is used to represent a key in various mapping operations, as indicated by its usage in the code. The typedef 'wrapped_ul_t' provides a convenient alias for this structure, allowing it to be used more easily in the codebase.


---
### wrapped\_ul\_t
- **Type**: `struct`
- **Members**:
    - `key`: A single unsigned long integer used as the key in the structure.
- **Description**: The `wrapped_ul_t` is a simple structure that encapsulates a single unsigned long integer, referred to as `key`. This structure is used as a type definition for various mapping operations, where the `key` serves as the primary identifier or value within the map. The structure is designed to be lightweight and efficient for operations that require a single key value, such as perfect hashing or other mapping techniques.


---
### prime\_to\_primitive\_root\_t
- **Type**: `struct`
- **Members**:
    - `prime`: An integer representing a prime number.
    - `primitive_root`: An integer representing a primitive root of the prime number.
- **Description**: The `prime_to_primitive_root_t` structure is designed to associate a prime number with its corresponding primitive root. This data structure is useful in mathematical computations and cryptographic applications where the relationship between a prime and its primitive root is significant. The structure contains two integer fields: `prime`, which holds the prime number, and `primitive_root`, which holds the primitive root of that prime.


---
### b3\_t
- **Type**: `union`
- **Members**:
    - `key`: An array of 3 unsigned characters used as a key.
    - `_ukey`: An unsigned integer representation of the key.
- **Description**: The `b3_t` data structure is a union that provides two different representations of a key: as an array of three unsigned characters (`uchar`) and as a single unsigned integer (`uint`). This allows for flexible handling of the key data, enabling operations that may require either byte-level manipulation or integer-level operations. The union is particularly useful in contexts where both representations are needed, such as in hash functions or data serialization.


---
### b3\_idx\_t
- **Type**: `struct`
- **Members**:
    - `key`: An array of 3 unsigned characters used as a key.
    - `index`: An unsigned long integer representing an index.
    - `dummy`: An integer used as a placeholder or for padding.
- **Description**: The `b3_idx_t` structure is a compound data type that encapsulates a small key-value pair, where the key is a 3-byte array and the value is an index represented by an unsigned long integer. The structure also includes an integer field named `dummy`, which may serve as a placeholder or for alignment purposes. This structure is likely used in contexts where small, fixed-size keys are mapped to indices, possibly in a hash table or similar data structure.


# Functions

---
### test\_primes<!-- {{#callable:test_primes}} -->
The `test_primes` function calculates the sum of squares of prime numbers less than 100 and verifies the result against a known value.
- **Inputs**: None
- **Control Flow**:
    - Initialize a variable `ssq` to 0 to store the sum of squares.
    - Iterate over numbers from 0 to 99 using a for loop.
    - For each number, check if it is a prime using the `prime100_contains` function.
    - If the number is prime, add its square to `ssq`.
    - After the loop, use `FD_TEST` to assert that `ssq` equals 65796.
- **Output**: The function does not return a value; it performs an assertion to verify the correctness of the sum of squares of primes.


---
### test\_primitive\_root<!-- {{#callable:test_primitive_root}} -->
The `test_primitive_root` function verifies that for each prime number between 3 and 99, the associated primitive root satisfies the mathematical property that the primitive root raised to the power of (prime-1)/2 is congruent to -1 modulo the prime.
- **Inputs**: None
- **Control Flow**:
    - The function iterates over integers `j` from 3 to 99.
    - For each `j`, it queries the `prim_root100` map to retrieve the corresponding `prime_to_primitive_root_t` structure, which contains the prime and its primitive root.
    - If the query returns a non-null result, it calculates the product of the primitive root raised to the power of (j-1)/2 modulo the prime.
    - It then checks if this product is equal to the prime minus one, using the `FD_TEST` macro to assert this condition.
- **Output**: The function does not return any value; it performs assertions to validate the mathematical property of primitive roots for primes.


---
### test\_is\_permutation<!-- {{#callable:test_is_permutation}} -->
The `test_is_permutation` function verifies that a given 3-element array is a permutation of the set {0, 1, 2} and checks if the `permq_contains` function correctly identifies such permutations.
- **Inputs**: None
- **Control Flow**:
    - Initialize a 4-element uchar array `query` with alignment of 4 bytes.
    - Iterate over all possible values of `a`, `b`, and `c` from 0 to 3 using nested loops.
    - Assign `a`, `b`, and `c` to the first three elements of `query`, and set the fourth element to 0.
    - Call `permq_contains` with `query` to check if it is a valid permutation of {0, 1, 2}.
    - Calculate `should_contain` to determine if `query` should be a valid permutation based on the condition that all elements are distinct and the maximum value is less than 3.
    - Use `FD_TEST` to assert that the result of `permq_contains` matches `should_contain`.
- **Output**: The function does not return a value but uses assertions to verify the correctness of the permutation check.


---
### test\_permutation\_idx<!-- {{#callable:test_permutation_idx}} -->
The `test_permutation_idx` function tests the correctness of a perfect hash function by iterating over a range of values, checking their hash results against expected permutations, and verifying the cumulative count of matched permutations.
- **Inputs**: None
- **Control Flow**:
    - Initialize a counter `cnt` to zero.
    - Iterate over a range of unsigned integers from 0 to 0xFFFFFF.
    - For each integer `i`, compute its hash using `permq2_hash_or_default(i)`.
    - Use a switch statement to compare the hash result against predefined permutation hash values.
    - For each matching case, update the counter `cnt` by adding a power of two corresponding to the matched permutation index.
    - If the hash result is `UINT_MAX`, do nothing and continue.
    - If the hash result does not match any case, log an error indicating a bad value was returned.
    - After the loop, assert that the counter `cnt` equals 0x3F, which indicates all permutations were correctly matched.
- **Output**: The function does not return a value but performs an assertion to verify the correctness of the hash function.


---
### test\_zero<!-- {{#callable:test_zero}} -->
The `test_zero` function verifies the presence and absence of specific keys in two different hash tables, `table_with_0` and `table_without_0`, using assertions.
- **Inputs**: None
- **Control Flow**:
    - The function calls `FD_TEST` to assert that `table_with_0_contains(0)` returns true, indicating that the key 0 is present in `table_with_0`.
    - It asserts that `table_with_0_contains(1)` returns false, indicating that the key 1 is not present in `table_with_0`.
    - It asserts that `table_without_0_contains(0)` returns false, indicating that the key 0 is not present in `table_without_0`.
    - It asserts that `table_without_0_contains(1)` returns true, indicating that the key 1 is present in `table_without_0`.
    - It asserts that `table_without_0_tbl[0].key` is non-zero, checking the validity of the key at index 0 in `table_without_0_tbl`.
    - It asserts that `table_without_0_tbl[1].key` is non-zero, checking the validity of the key at index 1 in `table_without_0_tbl`.
- **Output**: The function does not return any value; it uses assertions to validate conditions and will terminate the program if any assertion fails.


---
### find32<!-- {{#callable:find32}} -->
The `find32` function searches for the smallest positive integer `c` such that a set of 32-bit values, when multiplied by `c` and right-shifted, results in a unique set of `cnt` values.
- **Inputs**:
    - `vals`: An array of 32 unsigned integers, where the first `cnt` elements are the values to be processed.
    - `cnt`: An unsigned long integer representing the number of valid elements in the `vals` array to be considered.
- **Control Flow**:
    - The function fills the `vals` array from index `cnt` to 31 with the last valid value in the array to ensure all 32 elements are initialized.
    - Two 16-element wide vectors `w0` and `w1` are loaded from the `vals` array using SIMD operations.
    - A loop iterates over possible values of `c` starting from 1 up to `UINT_MAX`.
    - For each `c`, it is broadcasted to a vector `_c`, and then multiplied with `w0` and `w1`, followed by a right shift to obtain `p0` and `p1`.
    - Bit masks `mask0` and `mask1` are created by left-shifting a vector of ones by `p0` and `p1`, respectively.
    - The masks are combined using a bitwise OR operation, and the result is reduced to a single integer `ored_all` using `_mm512_reduce_or_epi32`.
    - The function checks if the population count of `ored_all` equals `cnt`, and if so, returns the current value of `c`.
    - If no such `c` is found, the function returns 0.
- **Output**: The function returns the smallest positive integer `c` that satisfies the condition, or 0 if no such `c` is found.


---
### find16<!-- {{#callable:find16}} -->
The `find16` function searches for the smallest positive integer `c` such that a bitwise operation on a vector of 16 unsigned integers results in a bitmask with a population count equal to a given count `cnt`.
- **Inputs**:
    - `vals`: An array of 16 unsigned integers, where the first `cnt` elements are the values to be processed.
    - `cnt`: The number of valid entries in the `vals` array that should be considered for processing.
- **Control Flow**:
    - The function first fills any extra entries in the `vals` array (from index `cnt` to 15) with the last valid entry (at index `cnt-1`).
    - It loads the first 16 values from the `vals` array into a SIMD register `w0`.
    - A SIMD register `one` is initialized with the broadcasted value of 1.
    - The function enters a loop starting from `c=1` and continues until `UINT_MAX`, incrementing `c` in each iteration.
    - In each iteration, it broadcasts the current value of `c` into a SIMD register `_c`.
    - It calculates a shifted product `p0` by multiplying `_c` with `w0` and then right-shifting the result by 28 bits.
    - A bitmask `mask0` is created by left-shifting the `one` register by the values in `p0`.
    - The function reduces the `mask0` using a bitwise OR operation across all elements to produce a single integer `ored_all`.
    - It checks if the population count of `ored_all` equals `cnt` using `fd_uint_popcnt`.
    - If the condition is met, it returns the current value of `c`.
    - If no such `c` is found by the end of the loop, the function returns 0.
- **Output**: The function returns the smallest positive integer `c` that satisfies the condition, or 0 if no such `c` is found.


