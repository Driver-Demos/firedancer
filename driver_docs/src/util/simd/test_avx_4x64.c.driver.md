# Purpose
This C source code file is a comprehensive test suite for verifying the functionality of various vector operations using AVX (Advanced Vector Extensions) instructions. The code is structured to test a wide range of operations on different data types, including double-precision floating-point numbers (`wd_t`), long integers (`wl_t`), and unsigned long integers (`wv_t`). The file includes tests for constructors, arithmetic operations, logical operations, bitwise operations, and conversion operations. Each test is designed to validate the correctness of the operations by comparing the results of vector operations against expected values, which are calculated using standard C library functions or predefined logic.

The code is organized into sections that test specific types of operations, such as arithmetic (addition, subtraction, multiplication, division), logical (and, or, not), and bitwise operations (shift, rotate). It also includes tests for more complex operations like fused multiply-add (FMA) and fast reciprocal and square root calculations. The use of macros and random number generation functions (`fd_rng_uint`) allows for the generation of test cases with varying input values, ensuring a thorough examination of the vector operations. The file is intended to be executed as a standalone program, as indicated by the presence of a [`main`](#main) function, and it utilizes a custom logging and testing framework (`FD_TEST`, `FD_LOG_NOTICE`) to report the results of the tests.
# Imports and Dependencies

---
- `../fd_util.h`
- `fd_avx.h`
- `math.h`


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function initializes a random number generator and performs extensive testing on various vector operations for different data types, including constructors, arithmetic, logical, conversion, and reduction operations.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the random number generator using `fd_rng_new` and `fd_rng_join`.
    - Define macros for generating random numbers of various types (e.g., `crand`, `frand`, `irand`, etc.).
    - Perform tests on wide double (`wd_t`) operations, including constructors, arithmetic, logical, conversion, and reduction operations, using a loop that iterates 65536 times.
    - Perform similar tests for wide long (`wl_t`) and wide unsigned long (`wv_t`) operations, each within their respective loops of 65536 iterations.
    - Delete the random number generator using `fd_rng_delete` and `fd_rng_leave`.
    - Log a notice indicating the tests passed and halt the program with `fd_halt`.
- **Output**: The function returns an integer value of 0, indicating successful execution.
- **Functions called**:
    - [`wd_test`](test_avx_common.c.driver.md#wd_test)
    - [`wc_bcast_wide`](fd_avx_wc.h.driver.md#wc_bcast_wide)
    - [`wd_bcast_pair`](fd_avx_wd.h.driver.md#wd_bcast_pair)
    - [`wd_bcast_wide`](fd_avx_wd.h.driver.md#wd_bcast_wide)
    - [`wc_test`](test_avx_common.c.driver.md#wc_test)
    - [`wf_test`](test_avx_common.c.driver.md#wf_test)
    - [`wi_test`](test_avx_common.c.driver.md#wi_test)
    - [`wu_test`](test_avx_common.c.driver.md#wu_test)
    - [`wd_to_wu_fast`](fd_avx_wd.h.driver.md#wd_to_wu_fast)
    - [`wl_test`](test_avx_common.c.driver.md#wl_test)
    - [`wd_to_wl`](fd_avx_wd.h.driver.md#wd_to_wl)
    - [`wv_test`](test_avx_common.c.driver.md#wv_test)
    - [`wd_to_wv`](fd_avx_wd.h.driver.md#wd_to_wv)
    - [`wd_sum_all`](fd_avx_wd.h.driver.md#wd_sum_all)
    - [`wd_min_all`](fd_avx_wd.h.driver.md#wd_min_all)
    - [`wd_max_all`](fd_avx_wd.h.driver.md#wd_max_all)
    - [`wl_bcast_pair`](fd_avx_wl.h.driver.md#wl_bcast_pair)
    - [`wl_bcast_wide`](fd_avx_wl.h.driver.md#wl_bcast_wide)
    - [`wl_permute`](fd_avx_wl.h.driver.md#wl_permute)
    - [`wl_shr_variable`](fd_avx_wl.h.driver.md#wl_shr_variable)
    - [`wl_rol_variable`](fd_avx_wl.h.driver.md#wl_rol_variable)
    - [`wl_ror_variable`](fd_avx_wl.h.driver.md#wl_ror_variable)
    - [`wl_abs`](fd_avx_wl.h.driver.md#wl_abs)
    - [`wl_min`](fd_avx_wl.h.driver.md#wl_min)
    - [`wl_max`](fd_avx_wl.h.driver.md#wl_max)
    - [`wl_to_wf`](fd_avx_wl.h.driver.md#wl_to_wf)
    - [`wl_to_wi`](fd_avx_wl.h.driver.md#wl_to_wi)
    - [`wl_to_wu`](fd_avx_wl.h.driver.md#wl_to_wu)
    - [`wl_to_wd`](fd_avx_wl.h.driver.md#wl_to_wd)
    - [`wl_sum_all`](fd_avx_wl.h.driver.md#wl_sum_all)
    - [`wl_min_all`](fd_avx_wl.h.driver.md#wl_min_all)
    - [`wl_max_all`](fd_avx_wl.h.driver.md#wl_max_all)
    - [`wv_bcast_pair`](fd_avx_wv.h.driver.md#wv_bcast_pair)
    - [`wv_bcast_wide`](fd_avx_wv.h.driver.md#wv_bcast_wide)
    - [`wv_permute`](fd_avx_wv.h.driver.md#wv_permute)
    - [`wv_rol_variable`](fd_avx_wv.h.driver.md#wv_rol_variable)
    - [`wv_ror_variable`](fd_avx_wv.h.driver.md#wv_ror_variable)
    - [`wv_min`](fd_avx_wv.h.driver.md#wv_min)
    - [`wv_max`](fd_avx_wv.h.driver.md#wv_max)
    - [`wv_to_wf`](fd_avx_wv.h.driver.md#wv_to_wf)
    - [`wv_to_wi`](fd_avx_wv.h.driver.md#wv_to_wi)
    - [`wv_to_wu`](fd_avx_wv.h.driver.md#wv_to_wu)
    - [`wv_to_wd`](fd_avx_wv.h.driver.md#wv_to_wd)
    - [`wv_sum_all`](fd_avx_wv.h.driver.md#wv_sum_all)
    - [`wv_min_all`](fd_avx_wv.h.driver.md#wv_min_all)
    - [`wv_max_all`](fd_avx_wv.h.driver.md#wv_max_all)


# Function Declarations (Public API)

---
### wc\_test<!-- {{#callable_declaration:wc_test}} -->
Tests the correctness of various operations on a wide character type.
- **Description**: This function is used to verify the correctness of operations on a wide character type `wc_t` by comparing the results of various operations with expected values derived from the input parameters. It is typically used in testing environments to ensure that the operations on wide character types behave as expected. The function checks packing, unpacking, extraction, insertion, and memory operations, among others. It returns a success or failure status based on whether all tests pass. This function should be called with valid wide character data and corresponding expected boolean values for each bit position.
- **Inputs**:
    - `c`: A wide character type representing the data to be tested. The caller must ensure it is a valid `wc_t` type.
    - `c0`: An integer representing the expected boolean value of the first bit in `c`. Must be either 0 or 1.
    - `c1`: An integer representing the expected boolean value of the second bit in `c`. Must be either 0 or 1.
    - `c2`: An integer representing the expected boolean value of the third bit in `c`. Must be either 0 or 1.
    - `c3`: An integer representing the expected boolean value of the fourth bit in `c`. Must be either 0 or 1.
    - `c4`: An integer representing the expected boolean value of the fifth bit in `c`. Must be either 0 or 1.
    - `c5`: An integer representing the expected boolean value of the sixth bit in `c`. Must be either 0 or 1.
    - `c6`: An integer representing the expected boolean value of the seventh bit in `c`. Must be either 0 or 1.
    - `c7`: An integer representing the expected boolean value of the eighth bit in `c`. Must be either 0 or 1.
- **Output**: Returns 1 if all tests pass, otherwise returns 0.
- **See also**: [`wc_test`](test_avx_common.c.driver.md#wc_test)  (Implementation)


---
### wf\_test<!-- {{#callable_declaration:wf_test}} -->
Validates a wide float vector against specified float values.
- **Description**: This function checks if each element of a wide float vector matches the corresponding float values provided as parameters. It is used to verify the integrity and correctness of vector operations by comparing extracted and inserted values. The function returns a success indicator based on the equality of the vector elements and the provided values. It should be called when you need to ensure that a wide float vector has been correctly constructed or manipulated.
- **Inputs**:
    - `f`: A wide float vector to be tested. The vector should be initialized and contain 8 elements.
    - `f0`: The expected float value for the first element of the vector. Must be a valid float.
    - `f1`: The expected float value for the second element of the vector. Must be a valid float.
    - `f2`: The expected float value for the third element of the vector. Must be a valid float.
    - `f3`: The expected float value for the fourth element of the vector. Must be a valid float.
    - `f4`: The expected float value for the fifth element of the vector. Must be a valid float.
    - `f5`: The expected float value for the sixth element of the vector. Must be a valid float.
    - `f6`: The expected float value for the seventh element of the vector. Must be a valid float.
    - `f7`: The expected float value for the eighth element of the vector. Must be a valid float.
- **Output**: Returns 1 if all elements of the vector match the provided float values; otherwise, returns 0.
- **See also**: [`wf_test`](test_avx_common.c.driver.md#wf_test)  (Implementation)


---
### wi\_test<!-- {{#callable_declaration:wi_test}} -->
Validates a wide integer vector against individual integer elements.
- **Description**: This function checks if each element of a wide integer vector matches the corresponding individual integer parameters. It is used to verify that the vector `i` contains the integers `i0` through `i7` in the correct order. The function returns 1 if all elements match and 0 otherwise. It is typically used in testing scenarios to ensure the integrity of vector operations. The function assumes that the vector `i` and the integer parameters are valid and correctly initialized before calling.
- **Inputs**:
    - `i`: A wide integer vector of type `wi_t` that is expected to contain the integers `i0` through `i7`. The caller must ensure this vector is properly initialized.
    - `i0`: An integer representing the expected value of the first element in the vector `i`.
    - `i1`: An integer representing the expected value of the second element in the vector `i`.
    - `i2`: An integer representing the expected value of the third element in the vector `i`.
    - `i3`: An integer representing the expected value of the fourth element in the vector `i`.
    - `i4`: An integer representing the expected value of the fifth element in the vector `i`.
    - `i5`: An integer representing the expected value of the sixth element in the vector `i`.
    - `i6`: An integer representing the expected value of the seventh element in the vector `i`.
    - `i7`: An integer representing the expected value of the eighth element in the vector `i`.
- **Output**: Returns 1 if all elements in the vector `i` match the corresponding integer parameters `i0` through `i7`; otherwise, returns 0.
- **See also**: [`wi_test`](test_avx_common.c.driver.md#wi_test)  (Implementation)


---
### wu\_test<!-- {{#callable_declaration:wu_test}} -->
Validates a wide unsigned integer vector against expected values.
- **Description**: This function checks if each element of the wide unsigned integer vector `u` matches the corresponding expected values provided by `u0` through `u7`. It performs a series of validation checks using extraction and insertion operations on the vector. If all checks pass, the function returns 1, indicating success. Otherwise, it returns 0, indicating a mismatch. This function is useful for testing and validating vector operations in environments where wide unsigned integer vectors are used.
- **Inputs**:
    - `u`: A wide unsigned integer vector to be tested. The vector must be initialized and contain 8 elements.
    - `u0`: The expected value for the first element of the vector. Must be a valid unsigned integer.
    - `u1`: The expected value for the second element of the vector. Must be a valid unsigned integer.
    - `u2`: The expected value for the third element of the vector. Must be a valid unsigned integer.
    - `u3`: The expected value for the fourth element of the vector. Must be a valid unsigned integer.
    - `u4`: The expected value for the fifth element of the vector. Must be a valid unsigned integer.
    - `u5`: The expected value for the sixth element of the vector. Must be a valid unsigned integer.
    - `u6`: The expected value for the seventh element of the vector. Must be a valid unsigned integer.
    - `u7`: The expected value for the eighth element of the vector. Must be a valid unsigned integer.
- **Output**: Returns 1 if all elements of the vector match the expected values; otherwise, returns 0.
- **See also**: [`wu_test`](test_avx_common.c.driver.md#wu_test)  (Implementation)


---
### wd\_test<!-- {{#callable_declaration:wd_test}} -->
Tests if a wide double vector matches specified double values.
- **Description**: This function checks if the elements of a wide double vector `d` match the specified double values `d0`, `d1`, `d2`, and `d3`. It is used to verify the correctness of operations involving wide double vectors. The function returns a non-zero value if all elements match the specified values, and zero otherwise. It is typically used in testing scenarios to ensure that vector operations produce expected results.
- **Inputs**:
    - `d`: A wide double vector to be tested. The vector should contain four double values to be compared against `d0`, `d1`, `d2`, and `d3`.
    - `d0`: The expected value for the first element of the vector `d`. Must be a valid double.
    - `d1`: The expected value for the second element of the vector `d`. Must be a valid double.
    - `d2`: The expected value for the third element of the vector `d`. Must be a valid double.
    - `d3`: The expected value for the fourth element of the vector `d`. Must be a valid double.
- **Output**: Returns 1 if all elements of the vector `d` match the specified values `d0`, `d1`, `d2`, and `d3`; otherwise, returns 0.
- **See also**: [`wd_test`](test_avx_common.c.driver.md#wd_test)  (Implementation)


---
### wl\_test<!-- {{#callable_declaration:wl_test}} -->
Validates a wide long vector against specified long values.
- **Description**: This function checks if the elements of a wide long vector `l` match the specified long values `l0`, `l1`, `l2`, and `l3`. It performs a series of tests to ensure that the vector's elements can be correctly extracted, stored, loaded, and compared using various operations. The function is useful for verifying the integrity and correctness of vector operations in applications that utilize wide long vectors. It returns a success indicator based on the outcome of these tests.
- **Inputs**:
    - `l`: A wide long vector to be tested. The vector should contain four elements that are expected to match the provided long values.
    - `l0`: The expected value of the first element in the wide long vector. Must be a valid long integer.
    - `l1`: The expected value of the second element in the wide long vector. Must be a valid long integer.
    - `l2`: The expected value of the third element in the wide long vector. Must be a valid long integer.
    - `l3`: The expected value of the fourth element in the wide long vector. Must be a valid long integer.
- **Output**: Returns 1 if all tests pass, indicating the vector matches the specified values; otherwise, returns 0.
- **See also**: [`wl_test`](test_avx_common.c.driver.md#wl_test)  (Implementation)


---
### wv\_test<!-- {{#callable_declaration:wv_test}} -->
Validates a vector against specified elements.
- **Description**: Use this function to verify that a vector `v` matches the specified elements `v0`, `v1`, `v2`, and `v3`. It checks if the elements extracted from the vector correspond to the provided values. This function is useful for testing and validation purposes, ensuring that vector operations produce the expected results. It returns a success indicator based on the comparison outcomes.
- **Inputs**:
    - `v`: A vector of type `wv_t` to be tested. The vector should contain four elements that will be compared against `v0`, `v1`, `v2`, and `v3`.
    - `v0`: An unsigned long integer representing the expected value of the first element in the vector `v`.
    - `v1`: An unsigned long integer representing the expected value of the second element in the vector `v`.
    - `v2`: An unsigned long integer representing the expected value of the third element in the vector `v`.
    - `v3`: An unsigned long integer representing the expected value of the fourth element in the vector `v`.
- **Output**: Returns an integer: 1 if the vector matches the specified elements, 0 otherwise.
- **See also**: [`wv_test`](test_avx_common.c.driver.md#wv_test)  (Implementation)


