# Purpose
This C source code file is designed to provide functionality for encoding and decoding data using the Base58 encoding scheme. Base58 is commonly used in applications like Bitcoin to encode large integers into a string format that is more human-readable and less error-prone. The file includes functions for both encoding and decoding operations, specifically tailored for 32-byte and 64-byte data blocks. The primary functions, [`fd_base58_encode_ref`](#fd_base58_encode_ref) and [`fd_base58_decode_ref`](#fd_base58_decode_ref), handle the conversion of byte arrays to Base58 strings and vice versa, using a reference algorithm. These functions are complemented by optimized versions for fixed-size conversions, which are recommended for performance-critical applications.

The file also includes a comprehensive suite of tests to validate the correctness and performance of the encoding and decoding functions. These tests cover basic functionality, boundary conditions, and performance metrics, ensuring that the implementation is robust and efficient. Additionally, the file contains AVX-optimized functions for environments that support AVX instructions, further enhancing performance for large-scale data processing. The code is structured to be part of a larger library, as indicated by the inclusion of external headers and the use of macros for configuration and testing. Overall, this file provides a focused and efficient implementation of Base58 encoding and decoding, with extensive testing to ensure reliability.
# Imports and Dependencies

---
- `fd_base58.h`
- `fd_base58_avx.h`


# Global Variables

---
### base58\_inverse
- **Type**: `uchar const[]`
- **Description**: The `base58_inverse` is an external constant array of unsigned characters (uchar) that is used to map base58 characters to their corresponding integer values. This array is likely used in the decoding process of base58 encoded strings to convert each character back to its numerical representation.
- **Use**: This variable is used in the `fd_base58_decode_ref` function to translate base58 characters into their respective integer values during the decoding process.


---
### base58\_chars
- **Type**: `char const[]`
- **Description**: The `base58_chars` is a static constant character array that contains the characters used in the Base58 encoding scheme. Base58 is a binary-to-text encoding scheme that is commonly used in cryptocurrencies like Bitcoin to encode addresses and other data.
- **Use**: This array is used to map numerical values to their corresponding Base58 characters during the encoding process.


# Functions

---
### fd\_base58\_encode\_ref<!-- {{#callable:fd_base58_encode_ref}} -->
The `fd_base58_encode_ref` function encodes a given byte array into a Base58 string, ensuring the output buffer is large enough to hold the result.
- **Inputs**:
    - `bytes`: A pointer to the input byte array to be encoded.
    - `byte_cnt`: The number of bytes in the input array.
    - `out`: A pointer to the output buffer where the Base58 encoded string will be stored.
    - `out_cnt`: The size of the output buffer, including space for the null terminator.
- **Control Flow**:
    - Check if the input byte count exceeds 64 or the output buffer size exceeds 128; return NULL if true.
    - Check if the output buffer size is less than the input byte count plus one; return NULL if true.
    - Copy the input bytes into a local array for manipulation.
    - Count leading zero bytes in the input array.
    - Perform a long division of the byte array by 58, storing remainders in a raw Base58 array.
    - Check if the output buffer is large enough to store the result, including leading zeros; return NULL if not.
    - Convert the raw Base58 values to Base58 characters and store them in the output buffer.
    - Terminate the output string with a null character and return the output buffer.
- **Output**: Returns a pointer to the output buffer containing the Base58 encoded string, or NULL if the output buffer is not large enough.


---
### fd\_base58\_decode\_ref<!-- {{#callable:fd_base58_decode_ref}} -->
The `fd_base58_decode_ref` function decodes a base58-encoded string into a big-endian byte array, ensuring the output matches a specified length.
- **Inputs**:
    - `encoded`: A pointer to a base58-encoded string that needs to be decoded.
    - `encoded_len`: The length of the encoded string, excluding the null-terminator.
    - `out`: A pointer to the output buffer where the decoded bytes will be stored.
    - `out_cnt`: The expected number of bytes in the output buffer.
- **Control Flow**:
    - Initialize `zero_cnt` to count leading '1's in the encoded string, which represent leading zeros in the decoded output.
    - Copy leading zeros to the output buffer and adjust pointers and lengths accordingly.
    - Check if the output buffer is too small for the remaining encoded data and return NULL if so.
    - Ensure the encoded length does not exceed 128 characters, returning NULL if it does.
    - Convert each character in the encoded string to its base58 value using a lookup table, storing results in `raw_base58`.
    - Perform a grade-school long division algorithm to convert the base58 values into bytes, storing results in the output buffer.
    - Check if the number of leading zeros in the output buffer matches the number of leading '1's in the encoded string, returning NULL if not.
    - Ensure all base58 values have been processed, returning NULL if any remain unprocessed.
    - Return the pointer to the start of the decoded output.
- **Output**: Returns a pointer to the start of the decoded byte array on success, or NULL if decoding fails due to invalid input or size mismatches.


---
### fd\_base58\_encode\_32\_ref<!-- {{#callable:fd_base58_encode_32_ref}} -->
The `fd_base58_encode_32_ref` function encodes a 32-byte array into a Base58 string and optionally stores the length of the encoded string.
- **Inputs**:
    - `bytes`: A pointer to an array of 32 unsigned characters (bytes) that represent the data to be encoded.
    - `opt_len`: An optional pointer to an unsigned long where the length of the encoded Base58 string will be stored if provided.
    - `out`: A pointer to a character array where the resulting Base58 encoded string will be stored.
- **Control Flow**:
    - The function calls [`fd_base58_encode_ref`](#fd_base58_encode_ref) with the input bytes, a fixed byte count of 32, the output buffer, and a predefined size for the encoded output.
    - It checks if `opt_len` is not NULL and, if so, stores the length of the encoded string (calculated using `strlen`) into the location pointed to by `opt_len`.
    - The function returns the pointer to the output buffer containing the Base58 encoded string.
- **Output**: A pointer to the output buffer containing the Base58 encoded string.
- **Functions called**:
    - [`fd_base58_encode_ref`](#fd_base58_encode_ref)


---
### fd\_base58\_encode\_64\_ref<!-- {{#callable:fd_base58_encode_64_ref}} -->
The `fd_base58_encode_64_ref` function encodes a 64-byte array into a Base58 string and optionally stores the length of the encoded string.
- **Inputs**:
    - `bytes`: A pointer to an array of 64 bytes that need to be encoded.
    - `opt_len`: An optional pointer to a `ulong` where the length of the encoded string will be stored if not NULL.
    - `out`: A pointer to a character array where the encoded Base58 string will be stored.
- **Control Flow**:
    - The function calls [`fd_base58_encode_ref`](#fd_base58_encode_ref) with the `bytes` array, a fixed byte count of 64, the `out` buffer, and a predefined size constant `FD_BASE58_ENCODED_64_SZ` to perform the Base58 encoding.
    - It then checks if `opt_len` is not NULL and, if so, stores the length of the encoded string (calculated using `strlen`) into the location pointed to by `opt_len`.
    - Finally, it returns the `out` buffer containing the encoded string.
- **Output**: The function returns a pointer to the `out` buffer containing the Base58 encoded string.
- **Functions called**:
    - [`fd_base58_encode_ref`](#fd_base58_encode_ref)


---
### fd\_base58\_decode\_32\_ref<!-- {{#callable:fd_base58_decode_32_ref}} -->
The `fd_base58_decode_32_ref` function decodes a base58-encoded string into a 32-byte big-endian integer.
- **Inputs**:
    - `encoded`: A constant character pointer to the base58-encoded string that needs to be decoded.
    - `out`: A pointer to an unsigned character array where the decoded 32-byte integer will be stored.
- **Control Flow**:
    - The function calls [`fd_base58_decode_ref`](#fd_base58_decode_ref) with the `encoded` string, its length (calculated using `strlen`), the `out` buffer, and a fixed output size of 32 bytes.
    - The [`fd_base58_decode_ref`](#fd_base58_decode_ref) function performs the actual decoding process, checking for valid base58 characters and converting them into a big-endian integer stored in `out`.
    - If the decoding is successful and the output is exactly 32 bytes, the function returns the `out` pointer; otherwise, it returns `NULL`.
- **Output**: A pointer to the `out` buffer containing the decoded 32-byte integer, or `NULL` if the decoding fails or the output size is incorrect.
- **Functions called**:
    - [`fd_base58_decode_ref`](#fd_base58_decode_ref)


---
### fd\_base58\_decode\_64\_ref<!-- {{#callable:fd_base58_decode_64_ref}} -->
The `fd_base58_decode_64_ref` function decodes a base58-encoded string into a 64-byte big-endian integer.
- **Inputs**:
    - `encoded`: A constant character pointer to the base58-encoded string that needs to be decoded.
    - `out`: A pointer to an unsigned character array where the decoded 64-byte integer will be stored.
- **Control Flow**:
    - The function calls [`fd_base58_decode_ref`](#fd_base58_decode_ref) with the `encoded` string, its length (calculated using `strlen`), the `out` buffer, and a fixed output size of 64 bytes.
    - The [`fd_base58_decode_ref`](#fd_base58_decode_ref) function performs the actual decoding process, checking for valid base58 characters and converting them into a big-endian integer representation.
    - If the decoding is successful and the output buffer is correctly sized, the function returns the `out` buffer; otherwise, it returns `NULL`.
- **Output**: The function returns a pointer to the `out` buffer containing the decoded 64-byte integer, or `NULL` if the decoding fails.
- **Functions called**:
    - [`fd_base58_decode_ref`](#fd_base58_decode_ref)


---
### battery\_encode\_basic32<!-- {{#callable:battery_encode_basic32}} -->
The `battery_encode_basic32` function tests the correctness of a 32-byte base58 encoding function by comparing its output against expected base58 strings for various input byte arrays.
- **Inputs**:
    - `encode_func`: A function pointer to a base58 encoding function that takes a byte array, a pointer to a length variable, and a buffer to store the encoded string.
- **Control Flow**:
    - Initialize a buffer `buf` to store the encoded base58 string, a byte array `bytes` of size 32, and a length array `len` of size 1.
    - Set all elements of `bytes` to zero and verify that encoding it results in the base58 string '11111111111111111111111111111111' with a length of 32.
    - Increment the last byte of `bytes` and verify that encoding it results in the base58 string '11111111111111111111111111111112' with a length of 32.
    - Increment the second last byte of `bytes` and verify that encoding it results in the base58 string '1111111111111111111111111111115S' with a length of 32.
    - Set all elements of `bytes` to 0xFF and verify that encoding it results in the base58 string 'JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG' with a length of 44.
    - Decrement the last byte of `bytes` and verify that encoding it results in the base58 string 'JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFF' with a length of 44.
- **Output**: The function does not return a value; it uses assertions to verify the correctness of the encoding function.


---
### battery\_encode\_basic64<!-- {{#callable:battery_encode_basic64}} -->
The `battery_encode_basic64` function tests the correctness of a 64-byte base58 encoding function by comparing its output against expected base58-encoded strings for various input byte arrays.
- **Inputs**:
    - `encode_func`: A function pointer to a base58 encoding function that takes a byte array, a pointer to a length variable, and a buffer to store the encoded string.
- **Control Flow**:
    - Initialize a buffer `buf` for the encoded string, a byte array `bytes` of 64 bytes, and a length array `len` of one element.
    - Set all elements of `bytes` to zero and verify that the encoded result matches the expected base58 string of 64 '1's and that the length is 64.
    - Increment the last byte of `bytes` and verify that the encoded result matches the expected base58 string ending in '2' and that the length is 64.
    - Increment the second last byte of `bytes` and verify that the encoded result matches the expected base58 string ending in '5S' and that the length is 64.
    - Set all elements of `bytes` to 0xFF and verify that the encoded result matches a specific expected base58 string and that the length is 88.
    - Decrement the last byte of `bytes` and verify that the encoded result matches a slightly different expected base58 string and that the length is 88.
- **Output**: The function does not return a value; it uses assertions to verify the correctness of the encoding function.


---
### battery\_encode\_bounds<!-- {{#callable:battery_encode_bounds}} -->
The `battery_encode_bounds` function tests the encoding function by setting specific byte patterns and verifying the encoded output against expected conditions.
- **Inputs**:
    - `encode_func`: A function pointer to the encoding function that takes a byte array, a length pointer, and a buffer, and returns a pointer to the buffer.
    - `n`: The number of bytes in the `bytes` array, representing the size of the data to be encoded.
    - `encode_sz`: The size of the buffer `buf`, representing the maximum size of the encoded output.
    - `buf`: A character buffer where the encoded output is stored, indexed from 0 to `encode_sz`.
    - `bytes`: An array of unsigned characters representing the data to be encoded, indexed from 0 to `n`.
- **Control Flow**:
    - Initialize the `bytes` array to zero using `fd_memset`.
    - Iterate over each byte in the `bytes` array, setting each byte to 1 in reverse order.
    - For each iteration, reset the `buf` to a pattern of '\xCC' to ensure no leftover data from previous operations.
    - Call the `encode_func` with the current `bytes` array, a length array `len`, and the `buf`, and verify the return value is the `buf`.
    - Check that the length of the encoded data is between `n` and `encode_sz` and matches the actual string length of `buf`.
    - Verify that all positions in `buf` beyond the encoded length are still set to '\xCC'.
- **Output**: The function does not return a value; it performs tests and assertions to validate the encoding function's behavior.


---
### battery\_decode\_fail32<!-- {{#callable:battery_decode_fail32}} -->
The `battery_decode_fail32` function tests a given decoding function with a set of predefined invalid base58-encoded strings to ensure that the decoding function correctly identifies and fails on these invalid inputs.
- **Inputs**:
    - `decode_func`: A function pointer to a decoding function that takes a base58-encoded string and a buffer to store the decoded output.
- **Control Flow**:
    - Define a constant `N_TESTS` with the value 15, representing the number of test cases.
    - Initialize an array `encoded` with 15 invalid base58-encoded strings, each designed to test different failure scenarios.
    - Declare a buffer `buf` of 32 unsigned characters to store the decoded output.
    - Iterate over each test case in the `encoded` array.
    - For each test case, call the `decode_func` with the current encoded string and `buf`, and use `FD_TEST` to assert that the decoding function returns a failure (i.e., returns NULL or a false value).
- **Output**: The function does not return any value; it uses assertions to verify that the decoding function fails for each invalid input.


---
### battery\_decode\_fail64<!-- {{#callable:battery_decode_fail64}} -->
The `battery_decode_fail64` function tests a given decoding function with a set of predefined base58-encoded strings to ensure that the function correctly identifies and fails to decode invalid or improperly sized inputs.
- **Inputs**:
    - `decode_func`: A function pointer to a decoding function that takes a base58-encoded string and a buffer to store the decoded output.
- **Control Flow**:
    - Defines a constant `N_TESTS` with the value 15, representing the number of test cases.
    - Initializes an array `encoded` with 15 base58-encoded strings, each representing a test case with various invalid or edge-case characteristics.
    - Declares a buffer `buf` of 64 bytes to store the decoded output from the decoding function.
    - Iterates over each test case in the `encoded` array, calling the `decode_func` with the current test case and the buffer `buf`.
    - Uses `FD_TEST` to assert that the decoding function returns a failure (i.e., returns NULL) for each test case, indicating that the input was invalid or improperly sized.
- **Output**: The function does not return any value; it uses assertions to validate the behavior of the decoding function.


---
### battery\_sample32<!-- {{#callable:battery_sample32}} -->
The `battery_sample32` function tests the encoding and decoding of 32-byte binary data to and from Base58 strings using provided encode and decode functions.
- **Inputs**:
    - `encode_func`: A function pointer to an encoding function that converts binary data to a Base58 string.
    - `decode_func`: A function pointer to a decoding function that converts a Base58 string back to binary data.
- **Control Flow**:
    - Define a constant `N_TESTS` with a value of 7, representing the number of test cases.
    - Initialize a static array `encoded` with 7 Base58 encoded strings.
    - Initialize a static 2D array `binary` with 7 sets of 32-byte binary data corresponding to the encoded strings.
    - Iterate over each test case (from 0 to N_TESTS-1).
    - For each test case, declare a buffer `buf` for storing the encoded result and a buffer `buf2` for storing the decoded result.
    - Use the `encode_func` to encode the binary data and compare the result with the expected encoded string using `FD_TEST` and `strcmp`.
    - Use the `decode_func` to decode the encoded string and compare the result with the expected binary data using `FD_TEST` and `memcmp`.
- **Output**: The function does not return any value; it performs tests and uses assertions to validate the correctness of the encoding and decoding functions.


---
### battery\_sample64<!-- {{#callable:battery_sample64}} -->
The `battery_sample64` function tests the encoding and decoding of 64-byte binary data to and from Base58 strings using provided encode and decode functions.
- **Inputs**:
    - `encode_func`: A function pointer to an encoding function that converts binary data to a Base58 string.
    - `decode_func`: A function pointer to a decoding function that converts a Base58 string back to binary data.
- **Control Flow**:
    - Define a constant `N_TESTS` with a value of 6, representing the number of test cases.
    - Initialize a static array `encoded` with 6 Base58 encoded strings.
    - Initialize a static 2D array `binary` with 6 sets of 64-byte binary data corresponding to the encoded strings.
    - Iterate over each test case (from 0 to `N_TESTS-1`).
    - For each test case, use `encode_func` to encode the binary data and compare the result with the expected encoded string using `FD_TEST` and `strcmp`.
    - Use `decode_func` to decode the encoded string back to binary and compare the result with the expected binary data using `FD_TEST` and `memcmp`.
- **Output**: The function does not return any value; it performs tests and uses assertions to validate the correctness of encoding and decoding functions.


---
### battery\_match<!-- {{#callable:battery_match}} -->
The `battery_match` function tests the consistency and correctness of encoding and decoding functions by comparing their outputs against reference implementations using random data.
- **Inputs**:
    - `encode_func_ref`: A reference encoding function that takes input bytes, a length pointer, and an output buffer, and returns the encoded string.
    - `encode_func`: An encoding function to be tested, which takes input bytes, a length pointer, and an output buffer, and returns the encoded string.
    - `decode_func`: A decoding function to be tested, which takes an encoded string and an output buffer, and returns the decoded bytes.
    - `n`: The number of bytes to encode/decode, assumed to be a power of 2.
    - `encode_sz`: The size of the buffer for the encoded string.
    - `rng`: A random number generator used to create random input data.
    - `cnt`: The number of test iterations to perform.
    - `buf_ref`: A buffer to store the reference encoded string, indexed from 0 to encode_sz.
    - `bytes_ref`: A buffer to store the reference bytes, indexed from 0 to n.
    - `buf`: A buffer to store the test encoded string, indexed from 0 to encode_sz.
    - `bytes`: A buffer to store the test decoded bytes, indexed from 0 to n.
- **Control Flow**:
    - Initialize a mask as n-1UL to assist with cyclic operations.
    - For each test iteration (from 0 to cnt):
    - Generate random bytes for bytes_ref using the random number generator.
    - Introduce a random length cyclic wrap-around streak of zeros in bytes_ref.
    - Encode bytes_ref using the reference encoding function and store the result in buf_ref, validating the output length and content.
    - Encode bytes_ref using the test encoding function with a NULL length pointer, and compare the result with buf_ref.
    - Encode bytes_ref using the test encoding function with a non-NULL length pointer, and compare the result and length with buf_ref and len_ref respectively.
    - Decode buf using the test decoding function and compare the result with bytes_ref.
- **Output**: The function does not return a value; it performs tests and asserts correctness using FD_TEST macros.


---
### battery\_performance<!-- {{#callable:battery_performance}} -->
The `battery_performance` function measures the performance of encoding and decoding functions by timing their execution over a series of test iterations.
- **Inputs**:
    - `encode_func`: A function pointer to the encoding function to be tested.
    - `decode_func`: A function pointer to the decoding function to be tested.
    - `n`: The number of bytes to be processed by the encode and decode functions.
    - `encode_sz`: The size of the buffer used for encoding.
    - `rng`: A pointer to a random number generator used to fill the byte array with random data.
    - `buf`: A character buffer used to store the encoded data, indexed from 0 to encode_sz.
    - `bytes`: An unsigned character array used to store the data to be encoded, indexed from 0 to n.
- **Control Flow**:
    - Initialize a constant `test_count` to 3000 for the number of iterations to perform.
    - Calculate the overhead of non-conversion work by timing the process of filling the `bytes` array with random data and accessing the `buf` array.
    - Warm up the instruction cache by calling the `encode_func` three times with the `bytes` array and `buf`.
    - Measure the time taken to encode the `bytes` array by calling `encode_func` in a loop for `test_count` iterations, filling `bytes` with random data each time.
    - Warm up the instruction cache by calling the `decode_func` three times with the `buf` and `bytes` arrays.
    - Measure the time taken for an encode-decode pair by calling `encode_func` followed by `decode_func` in a loop for `test_count` iterations, filling `bytes` with random data each time.
    - Log the average time per encode call and per decode call, excluding the overhead.
- **Output**: The function does not return a value but logs the average time per encode and decode call in nanoseconds.


---
### test\_count\_leading\_zeros<!-- {{#callable:test_count_leading_zeros}} -->
The `test_count_leading_zeros` function tests the correctness of the [`count_leading_zeros_32`](fd_base58_avx.h.driver.md#count_leading_zeros_32) and [`count_leading_zeros_45`](fd_base58_avx.h.driver.md#count_leading_zeros_45) functions by verifying their outputs against expected values for various buffer configurations.
- **Inputs**: None
- **Control Flow**:
    - Initialize a 64-byte buffer aligned to 32 bytes and set all bytes to zero using `fd_memset`.
    - Test [`count_leading_zeros_32`](fd_base58_avx.h.driver.md#count_leading_zeros_32) and [`count_leading_zeros_45`](fd_base58_avx.h.driver.md#count_leading_zeros_45) with the buffer and verify they return 32 and 45 respectively.
    - Set the first byte of the buffer to 2 and verify both functions return 0.
    - Set the first byte to 0 and the second byte to 7, then verify both functions return 1.
    - Set the second byte to 255 and verify both functions still return 1.
    - Set all bytes in the buffer to 123, then iterate over the first 32 bytes, setting each to 0 one by one, and verify the functions return the correct number of leading zeros.
    - Continue iterating over bytes 32 to 44, setting each to 0, and verify [`count_leading_zeros_32`](fd_base58_avx.h.driver.md#count_leading_zeros_32) returns 32 and [`count_leading_zeros_45`](fd_base58_avx.h.driver.md#count_leading_zeros_45) returns the correct number of leading zeros.
    - Iterate over bytes 45 to 63, setting each to 0, and verify the functions return 32 and 45 respectively.
- **Output**: The function does not return any value; it uses assertions to verify the correctness of the [`count_leading_zeros_32`](fd_base58_avx.h.driver.md#count_leading_zeros_32) and [`count_leading_zeros_45`](fd_base58_avx.h.driver.md#count_leading_zeros_45) functions.
- **Functions called**:
    - [`count_leading_zeros_32`](fd_base58_avx.h.driver.md#count_leading_zeros_32)
    - [`wuc_ld`](fd_base58_avx.h.driver.md#wuc_ld)
    - [`count_leading_zeros_45`](fd_base58_avx.h.driver.md#count_leading_zeros_45)


---
### test\_raw\_to\_base58<!-- {{#callable:test_raw_to_base58}} -->
The `test_raw_to_base58` function tests the conversion of raw byte data to a base58 encoded format and verifies the correctness of the conversion.
- **Inputs**:
    - `None`: This function does not take any input parameters.
- **Control Flow**:
    - Initialize two arrays `in` and `out` of 32 unsigned characters each, aligned to 32 bytes.
    - Iterate over `i` from 0 to 57 (inclusive) to test each possible base58 character.
    - For each `i`, fill the `in` array with values calculated as `(i+j)%58` for each index `j` from 0 to 31.
    - Convert the `in` array to base58 using [`raw_to_base58`](fd_base58_avx.h.driver.md#raw_to_base58) and store the result in `out`.
    - Verify that each character in `out` matches the expected base58 character corresponding to the value in `in` using `FD_TEST`.
- **Output**: The function does not return any value; it performs assertions to verify the correctness of the base58 conversion.
- **Functions called**:
    - [`wuc_st`](fd_base58_avx.h.driver.md#wuc_st)
    - [`raw_to_base58`](fd_base58_avx.h.driver.md#raw_to_base58)
    - [`wuc_ld`](fd_base58_avx.h.driver.md#wuc_ld)


---
### test\_intermediate\_to\_raw<!-- {{#callable:test_intermediate_to_raw}} -->
The `test_intermediate_to_raw` function tests the conversion of intermediate values to raw values and verifies the correctness of the conversion by comparing the output against expected values.
- **Inputs**: None
- **Control Flow**:
    - Initialize four unsigned long variables `c1`, `c2`, `c3`, and `c4` with specific starting values.
    - Declare an aligned array `out` of 32 unsigned characters to store the output.
    - Iterate a loop 1,000,000 times, incrementing `c1`, `c2`, `c3`, and `c4` by specific values in each iteration.
    - In each iteration, create an intermediate value using `wl` function with `c1`, `c2`, `c3`, and `c4` as inputs.
    - Convert the intermediate value to a raw value using [`intermediate_to_raw`](fd_base58_avx.h.driver.md#intermediate_to_raw) function.
    - Store the raw value into the `out` array using [`wuc_st`](fd_base58_avx.h.driver.md#wuc_st).
    - Perform a series of tests using `FD_TEST` to verify that each element of `out` matches the expected value based on calculations involving `c1`, `c2`, `c3`, and `c4`.
- **Output**: The function does not return any value; it performs tests to verify the correctness of the conversion process.
- **Functions called**:
    - [`intermediate_to_raw`](fd_base58_avx.h.driver.md#intermediate_to_raw)
    - [`wuc_st`](fd_base58_avx.h.driver.md#wuc_st)


---
### test\_ten\_per\_slot\_down<!-- {{#callable:test_ten_per_slot_down}} -->
The function `test_ten_per_slot_down` tests the functionality of the `ten_per_slot_down_32` and `ten_per_slot_down_64` functions by verifying that they correctly transform input data into expected output data.
- **Inputs**: None
- **Control Flow**:
    - Initialize two arrays `in` and `out` for the 32B test, both aligned to 32 bytes, and set their contents to zero using `fd_memset`.
    - Populate the `in` array with values from 1 to 45, distributed across three 32-byte blocks, with each block containing 10 values.
    - Load three 32-byte vectors `a`, `b`, and `c` from the `in` array using [`wuc_ld`](fd_base58_avx.h.driver.md#wuc_ld).
    - Call `ten_per_slot_down_32` with `a`, `b`, `c`, and two output vectors `out0` and `out1`.
    - Store the results `out0` and `out1` into the `out` array using [`wuc_st`](fd_base58_avx.h.driver.md#wuc_st).
    - Verify that the `out` array contains values from 1 to 45 using `FD_TEST`.
    - Repeat the above steps for the 64B test, initializing `in` and `out` arrays for five and three 32-byte blocks respectively, and populating `in` with values from 1 to 90.
    - Load five 32-byte vectors `a`, `b`, `c`, `d`, and `e` from the `in` array.
    - Call `ten_per_slot_down_64` with `a`, `b`, `c`, `d`, `e`, and three output vectors `out0`, `out1`, and `out2`.
    - Store the results `out0`, `out1`, and `out2` into the `out` array.
    - Verify that the `out` array contains values from 1 to 90 using `FD_TEST`.
- **Output**: The function does not return any value; it performs tests and uses assertions to verify correctness.
- **Functions called**:
    - [`wuc_ld`](fd_base58_avx.h.driver.md#wuc_ld)
    - [`wuc_st`](fd_base58_avx.h.driver.md#wuc_st)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, sets up a random number generator, and performs a series of tests on base58 encoding and decoding functions, including performance and correctness tests for both 256-bit and 512-bit conversions.
- **Inputs**:
    - `argc`: An integer representing the number of command-line arguments.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Retrieve the `--cnt` command-line argument as an unsigned long, defaulting to 100000 if not provided.
    - Initialize a random number generator `rng` using `fd_rng_new` and `fd_rng_join`.
    - If AVX is available, log a notice and run AVX-specific tests: [`test_intermediate_to_raw`](#test_intermediate_to_raw), [`test_raw_to_base58`](#test_raw_to_base58), [`test_count_leading_zeros`](#test_count_leading_zeros), and [`test_ten_per_slot_down`](#test_ten_per_slot_down).
    - Log a notice and run reference 256-bit conversion tests: `test_encode_basic32_ref`, `test_encode_bounds32_ref`, `test_decode_fail32_ref`, `test_sample32_ref`, `test_match32_ref`, and `test_performance32_ref`.
    - Log a notice and run reference 512-bit conversion tests: `test_encode_basic64_ref`, `test_encode_bounds64_ref`, `test_decode_fail64_ref`, `test_sample64_ref`, `test_match64_ref`, and `test_performance64_ref`.
    - Log a notice and run optimized 256-bit conversion tests: `test_encode_basic32`, `test_encode_bounds32`, `test_decode_fail32`, `test_sample32`, `test_match32`, and `test_performance32`.
    - Log a notice and run optimized 512-bit conversion tests: `test_encode_basic64`, `test_encode_bounds64`, `test_decode_fail64`, `test_sample64`, `test_match64`, and `test_performance64`.
    - Delete the random number generator using `fd_rng_delete` and `fd_rng_leave`.
    - Log a notice indicating all tests passed and call `fd_halt` to terminate the program.
- **Output**: The function returns an integer, specifically 0, indicating successful execution.
- **Functions called**:
    - [`test_intermediate_to_raw`](#test_intermediate_to_raw)
    - [`test_raw_to_base58`](#test_raw_to_base58)
    - [`test_count_leading_zeros`](#test_count_leading_zeros)
    - [`test_ten_per_slot_down`](#test_ten_per_slot_down)


