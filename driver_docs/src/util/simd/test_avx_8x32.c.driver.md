# Purpose
This C source code file is a comprehensive test suite for verifying the functionality of various vector operations using AVX (Advanced Vector Extensions) instructions. The file includes a [`main`](#main) function that executes a series of tests on different data types, such as integers, unsigned integers, floats, and doubles, encapsulated in vector types like `wc_t`, `wf_t`, `wi_t`, `wu_t`, `wd_t`, `wl_t`, and `wv_t`. The tests cover a wide range of operations, including constructors, arithmetic operations, logical operations, bit manipulation, and conversion operations. Each test is designed to ensure that the vector operations produce the expected results, and the tests are executed using a random number generator to provide a variety of input scenarios.

The file is structured to test the correctness and performance of vector operations, which are crucial for applications that require high-performance computing, such as scientific simulations, graphics processing, and data analysis. The code makes extensive use of macros to define random number generation and vector operations, ensuring that the tests are both comprehensive and efficient. The inclusion of various test cases, such as reduction operations and miscellaneous operations like transposition, highlights the file's role in validating the robustness and accuracy of the vector operations implemented in the associated AVX library. The file does not define public APIs or external interfaces but serves as an internal validation tool to ensure the reliability of the vector operations provided by the library.
# Imports and Dependencies

---
- `../fd_util.h`
- `fd_avx.h`
- `math.h`


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function initializes a random number generator and performs extensive testing on various vector operations for different data types, including logical, arithmetic, and conversion operations, using predefined macros and test functions.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the random number generator using `fd_rng_new` and `fd_rng_join`.
    - Define macros for generating random numbers of various types (e.g., `crand`, `frand`, `irand`, etc.).
    - Perform tests on wide character (wc) operations, including constructors, logical operations, conversions, and reductions.
    - Perform tests on wide float (wf) operations, including constructors, arithmetic operations, logical operations, and conversions.
    - Perform tests on wide integer (wi) operations, including constructors, bit operations, arithmetic operations, logical operations, and conversions.
    - Perform tests on wide unsigned integer (wu) operations, including constructors, bit operations, arithmetic operations, logical operations, and conversions.
    - Delete the random number generator using `fd_rng_delete` and `fd_rng_leave`.
    - Log a notice indicating the tests passed and halt the program.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`wc_test`](test_avx_common.c.driver.md#wc_test)
    - [`wc_bcast`](fd_avx_wc.h.driver.md#wc_bcast)
    - [`wc_bcast_pair`](fd_avx_wc.h.driver.md#wc_bcast_pair)
    - [`wc_bcast_lohi`](fd_avx_wc.h.driver.md#wc_bcast_lohi)
    - [`wc_bcast_quad`](fd_avx_wc.h.driver.md#wc_bcast_quad)
    - [`wc_bcast_wide`](fd_avx_wc.h.driver.md#wc_bcast_wide)
    - [`wc_exch_adj_quad`](fd_avx_wc.h.driver.md#wc_exch_adj_quad)
    - [`wi_test`](test_avx_common.c.driver.md#wi_test)
    - [`wu_test`](test_avx_common.c.driver.md#wu_test)
    - [`wf_test`](test_avx_common.c.driver.md#wf_test)
    - [`wd_test`](test_avx_common.c.driver.md#wd_test)
    - [`wl_test`](test_avx_common.c.driver.md#wl_test)
    - [`wv_test`](test_avx_common.c.driver.md#wv_test)
    - [`wc_narrow`](fd_avx_wc.h.driver.md#wc_narrow)
    - [`wf_bcast_pair`](fd_avx_wf.h.driver.md#wf_bcast_pair)
    - [`wf_bcast_lohi`](fd_avx_wf.h.driver.md#wf_bcast_lohi)
    - [`wf_bcast_quad`](fd_avx_wf.h.driver.md#wf_bcast_quad)
    - [`wf_bcast_wide`](fd_avx_wf.h.driver.md#wf_bcast_wide)
    - [`wf_exch_adj_quad`](fd_avx_wf.h.driver.md#wf_exch_adj_quad)
    - [`wf_to_wu_fast`](fd_avx_wf.h.driver.md#wf_to_wu_fast)
    - [`wf_to_wl`](fd_avx_wf.h.driver.md#wf_to_wl)
    - [`wf_to_wv`](fd_avx_wf.h.driver.md#wf_to_wv)
    - [`wf_sum_all`](fd_avx_wf.h.driver.md#wf_sum_all)
    - [`wf_min_all`](fd_avx_wf.h.driver.md#wf_min_all)
    - [`wf_max_all`](fd_avx_wf.h.driver.md#wf_max_all)
    - [`wi_bcast_pair`](fd_avx_wi.h.driver.md#wi_bcast_pair)
    - [`wi_bcast_lohi`](fd_avx_wi.h.driver.md#wi_bcast_lohi)
    - [`wi_bcast_quad`](fd_avx_wi.h.driver.md#wi_bcast_quad)
    - [`wi_bcast_wide`](fd_avx_wi.h.driver.md#wi_bcast_wide)
    - [`wi_exch_adj_quad`](fd_avx_wi.h.driver.md#wi_exch_adj_quad)
    - [`wi_rol_variable`](fd_avx_wi.h.driver.md#wi_rol_variable)
    - [`wi_ror_variable`](fd_avx_wi.h.driver.md#wi_ror_variable)
    - [`wi_sum_all`](fd_avx_wi.h.driver.md#wi_sum_all)
    - [`wi_min_all`](fd_avx_wi.h.driver.md#wi_min_all)
    - [`wi_max_all`](fd_avx_wi.h.driver.md#wi_max_all)
    - [`wu_bcast_pair`](fd_avx_wu.h.driver.md#wu_bcast_pair)
    - [`wu_bcast_lohi`](fd_avx_wu.h.driver.md#wu_bcast_lohi)
    - [`wu_bcast_quad`](fd_avx_wu.h.driver.md#wu_bcast_quad)
    - [`wu_bcast_wide`](fd_avx_wu.h.driver.md#wu_bcast_wide)
    - [`wu_exch_adj_quad`](fd_avx_wu.h.driver.md#wu_exch_adj_quad)
    - [`wu_bswap`](fd_avx_wu.h.driver.md#wu_bswap)
    - [`wu_rol_variable`](fd_avx_wu.h.driver.md#wu_rol_variable)
    - [`wu_ror_variable`](fd_avx_wu.h.driver.md#wu_ror_variable)
    - [`wu_to_wf`](fd_avx_wu.h.driver.md#wu_to_wf)
    - [`wu_to_wd`](fd_avx_wu.h.driver.md#wu_to_wd)
    - [`wu_sum_all`](fd_avx_wu.h.driver.md#wu_sum_all)
    - [`wu_min_all`](fd_avx_wu.h.driver.md#wu_min_all)
    - [`wu_max_all`](fd_avx_wu.h.driver.md#wu_max_all)


# Function Declarations (Public API)

---
### wc\_test<!-- {{#callable_declaration:wc_test}} -->
Tests the correctness of various operations on a wc_t vector.
- **Description**: This function is used to verify the correctness of operations on a wc_t vector, which represents a vector of boolean values. It checks the packing and unpacking of the vector, extraction of individual elements, and various store and load operations. The function should be called with a wc_t vector and its corresponding boolean values for each element. It returns 1 if all tests pass, indicating the operations are correct, and 0 if any test fails. This function is typically used in testing environments to ensure the integrity of vector operations.
- **Inputs**:
    - `c`: A wc_t vector representing a vector of boolean values. The caller must ensure this is a valid wc_t vector.
    - `c0`: An integer representing the boolean value of the first element in the vector. Must be either 0 or 1.
    - `c1`: An integer representing the boolean value of the second element in the vector. Must be either 0 or 1.
    - `c2`: An integer representing the boolean value of the third element in the vector. Must be either 0 or 1.
    - `c3`: An integer representing the boolean value of the fourth element in the vector. Must be either 0 or 1.
    - `c4`: An integer representing the boolean value of the fifth element in the vector. Must be either 0 or 1.
    - `c5`: An integer representing the boolean value of the sixth element in the vector. Must be either 0 or 1.
    - `c6`: An integer representing the boolean value of the seventh element in the vector. Must be either 0 or 1.
    - `c7`: An integer representing the boolean value of the eighth element in the vector. Must be either 0 or 1.
- **Output**: Returns 1 if all tests pass, indicating the operations on the wc_t vector are correct, and 0 if any test fails.
- **See also**: [`wc_test`](test_avx_common.c.driver.md#wc_test)  (Implementation)


---
### wf\_test<!-- {{#callable_declaration:wf_test}} -->
Tests if a vector of floats matches specified values and performs various vector operations.
- **Description**: This function is used to verify that a given vector of floats, represented by `wf_t`, matches a set of specified float values. It performs a series of checks and operations on the vector, including extraction, insertion, and comparison of elements, as well as storing and loading operations. The function is useful for validating the integrity and correctness of vector operations in a system that uses SIMD (Single Instruction, Multiple Data) processing. It returns a success or failure status based on whether all checks pass. This function should be called when you need to ensure that a vector matches expected values and behaves correctly under various operations.
- **Inputs**:
    - `f`: A vector of floats (`wf_t`) to be tested. The vector should contain 8 float elements.
    - `f0`: The expected value of the first element in the vector. Must be a valid float.
    - `f1`: The expected value of the second element in the vector. Must be a valid float.
    - `f2`: The expected value of the third element in the vector. Must be a valid float.
    - `f3`: The expected value of the fourth element in the vector. Must be a valid float.
    - `f4`: The expected value of the fifth element in the vector. Must be a valid float.
    - `f5`: The expected value of the sixth element in the vector. Must be a valid float.
    - `f6`: The expected value of the seventh element in the vector. Must be a valid float.
    - `f7`: The expected value of the eighth element in the vector. Must be a valid float.
- **Output**: Returns 1 if all tests pass, otherwise returns 0.
- **See also**: [`wf_test`](test_avx_common.c.driver.md#wf_test)  (Implementation)


---
### wi\_test<!-- {{#callable_declaration:wi_test}} -->
Tests if a vector of integers matches specified values and performs various vector operations.
- **Description**: This function is used to verify if each element of a given vector of integers matches the corresponding specified integer values. It performs a series of checks and operations on the vector, including extraction, insertion, and comparison of elements. The function is useful for validating the integrity of vector operations and ensuring that vector elements are correctly manipulated. It should be called when you need to confirm that a vector's elements match expected values after various vector operations. The function returns early if any mismatch is found, ensuring efficient validation.
- **Inputs**:
    - `i`: A vector of integers (wi_t) to be tested. The caller must ensure this vector is properly initialized and contains valid integer values.
    - `i0`: An integer representing the expected value of the first element in the vector. Must be a valid integer.
    - `i1`: An integer representing the expected value of the second element in the vector. Must be a valid integer.
    - `i2`: An integer representing the expected value of the third element in the vector. Must be a valid integer.
    - `i3`: An integer representing the expected value of the fourth element in the vector. Must be a valid integer.
    - `i4`: An integer representing the expected value of the fifth element in the vector. Must be a valid integer.
    - `i5`: An integer representing the expected value of the sixth element in the vector. Must be a valid integer.
    - `i6`: An integer representing the expected value of the seventh element in the vector. Must be a valid integer.
    - `i7`: An integer representing the expected value of the eighth element in the vector. Must be a valid integer.
- **Output**: Returns 1 if all elements match the specified values and vector operations are successful; returns 0 if any mismatch is found or an operation fails.
- **See also**: [`wi_test`](test_avx_common.c.driver.md#wi_test)  (Implementation)


---
### wu\_test<!-- {{#callable_declaration:wu_test}} -->
Tests if a wide unsigned integer vector matches specified elements.
- **Description**: This function checks if each element of the wide unsigned integer vector `u` matches the corresponding elements `u0` through `u7`. It is used to verify that a vector contains the expected values at each position. The function returns 1 if all elements match and 0 otherwise. It is typically used in testing scenarios to validate vector operations.
- **Inputs**:
    - `u`: A wide unsigned integer vector to be tested. The caller must ensure it is properly initialized and contains 8 elements.
    - `u0`: An unsigned integer representing the expected value of the first element of the vector. Must be a valid unsigned integer.
    - `u1`: An unsigned integer representing the expected value of the second element of the vector. Must be a valid unsigned integer.
    - `u2`: An unsigned integer representing the expected value of the third element of the vector. Must be a valid unsigned integer.
    - `u3`: An unsigned integer representing the expected value of the fourth element of the vector. Must be a valid unsigned integer.
    - `u4`: An unsigned integer representing the expected value of the fifth element of the vector. Must be a valid unsigned integer.
    - `u5`: An unsigned integer representing the expected value of the sixth element of the vector. Must be a valid unsigned integer.
    - `u6`: An unsigned integer representing the expected value of the seventh element of the vector. Must be a valid unsigned integer.
    - `u7`: An unsigned integer representing the expected value of the eighth element of the vector. Must be a valid unsigned integer.
- **Output**: Returns 1 if all elements of the vector match the specified values, otherwise returns 0.
- **See also**: [`wu_test`](test_avx_common.c.driver.md#wu_test)  (Implementation)


---
### wd\_test<!-- {{#callable_declaration:wd_test}} -->
Validates a wide double vector against specified double values.
- **Description**: This function checks if the elements of a wide double vector match the provided double values. It is used to verify that a wide double vector `d` contains the specified values `d0`, `d1`, `d2`, and `d3` at positions 0, 1, 2, and 3, respectively. The function returns a success indicator based on these comparisons. It is typically used in testing scenarios to ensure that vector operations produce expected results. The function assumes that the input vector and doubles are valid and does not handle null or invalid inputs.
- **Inputs**:
    - `d`: A wide double vector to be tested. The vector should be valid and initialized before calling this function.
    - `d0`: A double value expected at position 0 in the vector. Must be a valid double.
    - `d1`: A double value expected at position 1 in the vector. Must be a valid double.
    - `d2`: A double value expected at position 2 in the vector. Must be a valid double.
    - `d3`: A double value expected at position 3 in the vector. Must be a valid double.
- **Output**: Returns 1 if the vector matches the specified values at the given positions; otherwise, returns 0.
- **See also**: [`wd_test`](test_avx_common.c.driver.md#wd_test)  (Implementation)


---
### wl\_test<!-- {{#callable_declaration:wl_test}} -->
Tests if a wide long vector matches specified elements.
- **Description**: This function checks if the elements of a wide long vector `l` match the specified long values `l0`, `l1`, `l2`, and `l3`. It performs a series of extraction and comparison operations to verify the equality of each element in the vector with the corresponding input value. The function is useful for validating that a vector has been correctly initialized or transformed to contain the expected values. It returns a success indicator based on the match results.
- **Inputs**:
    - `l`: A wide long vector to be tested. The vector should be initialized and contain at least four elements.
    - `l0`: The expected value for the first element of the vector. Must be a valid long integer.
    - `l1`: The expected value for the second element of the vector. Must be a valid long integer.
    - `l2`: The expected value for the third element of the vector. Must be a valid long integer.
    - `l3`: The expected value for the fourth element of the vector. Must be a valid long integer.
- **Output**: Returns 1 if all elements of the vector match the specified values; otherwise, returns 0.
- **See also**: [`wl_test`](test_avx_common.c.driver.md#wl_test)  (Implementation)


---
### wv\_test<!-- {{#callable_declaration:wv_test}} -->
Tests if a vector matches specified elements and performs various vector operations.
- **Description**: This function checks if the elements of a given vector match the specified values and performs a series of vector operations to validate the vector's integrity. It is used to verify that the vector operations such as extraction, insertion, loading, storing, and gathering work correctly. The function should be called with a vector and four unsigned long values that are expected to match the vector's elements. It returns a success or failure status based on these checks.
- **Inputs**:
    - `v`: A vector of type `wv_t` whose elements are to be tested against the provided values. The caller retains ownership and it must be a valid vector.
    - `v0`: An unsigned long representing the expected value of the first element of the vector. Must be a valid unsigned long.
    - `v1`: An unsigned long representing the expected value of the second element of the vector. Must be a valid unsigned long.
    - `v2`: An unsigned long representing the expected value of the third element of the vector. Must be a valid unsigned long.
    - `v3`: An unsigned long representing the expected value of the fourth element of the vector. Must be a valid unsigned long.
- **Output**: Returns 1 if all tests pass, indicating the vector matches the specified values and operations are successful; otherwise, returns 0.
- **See also**: [`wv_test`](test_avx_common.c.driver.md#wv_test)  (Implementation)


