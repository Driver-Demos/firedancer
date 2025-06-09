# Purpose
This C source code file is designed to test the functionality of Zstandard (ZSTD) decompression within a specific framework. It includes necessary headers for Zstandard operations and utility functions, and it checks for the presence of Zstandard support at compile time. The file defines a static function [`test_decompress`](#test_decompress) that performs various decompression tests using predefined compressed data arrays (`test_zstd_comp_0` and `test_zstd_comp_1`). These tests validate the alignment and memory footprint of the decompression stream, ensure successful decompression of data, and handle different scenarios such as byte-by-byte decompression and partial decompression resets. The file also includes a [`main`](#main) function that initializes the environment, performs a series of decompression tests, and logs the estimated size of Zstandard compression contexts for different levels.

The code is structured to ensure that the Zstandard decompression functionality is robust and reliable. It uses assertions to verify the correctness of decompression operations and memory management. The file is not intended to be a library or a header file for external use but rather a standalone executable for testing purposes. It does not define public APIs or external interfaces but instead focuses on internal testing of the decompression process, ensuring that the Zstandard integration within the framework operates as expected.
# Imports and Dependencies

---
- `fd_zstd.h`
- `fd_zstd_private.h`
- `../../util/fd_util.h`
- `stdalign.h`
- `stddef.h`
- `zstd.h`


# Global Variables

---
### test\_zstd\_comp\_0
- **Type**: ``static uchar const[]``
- **Description**: The `test_zstd_comp_0` variable is a static constant array of unsigned characters that represents a Zstandard compressed data block. It contains the compressed representation of the string "AAAA" using the Zstandard compression algorithm.
- **Use**: This variable is used as a test vector for verifying the decompression functionality of the Zstandard decompression stream in the `test_decompress` function.


---
### test\_zstd\_comp\_1
- **Type**: ``static uchar const[]``
- **Description**: The `test_zstd_comp_1` variable is a static constant array of unsigned characters that represents a compressed data block using the Zstandard (zstd) compression algorithm. The array contains the compressed form of the string "ABCD".
- **Use**: This variable is used as a test vector for verifying the correctness of Zstandard decompression functionality in the `test_decompress` function.


# Functions

---
### test\_decompress<!-- {{#callable:test_decompress}} -->
The `test_decompress` function tests the decompression capabilities of a Zstandard decompression stream by verifying the decompression of predefined compressed data and checking the integrity of the decompressed output.
- **Inputs**: None
- **Control Flow**:
    - The function begins by asserting that the alignment of the decompression stream matches the expected alignment constant.
    - It calculates the memory size required for the decompression stream based on a predefined window size and allocates memory accordingly.
    - A new decompression stream is created using the allocated memory, and its properties are verified to ensure correct initialization.
    - The function tests successful decompression by reading from a predefined compressed input (`test_zstd_comp_0`) and verifying the output matches the expected decompressed data ('AAAAAAAA').
    - It then tests decompression by reading input and output byte by byte, cycling over the input message (`test_zstd_comp_1`) and verifying the output matches the expected decompressed data ('ABCDABCD').
    - The function further tests decompression by reading input byte by byte and output byte by byte separately, ensuring the output matches the expected results ('ABCDABCD' and 'ABCD', respectively).
    - A partial decompression is tested and aborted, followed by a reset of the decompression stream, and a subsequent decompression is verified to match expected results ('AAAA').
    - Finally, the function deletes the decompression stream and verifies that the memory is correctly released and the stream's magic number is reset.
- **Output**: The function does not return any value; it uses assertions to verify the correctness of the decompression process and outputs test results through these assertions.
- **Functions called**:
    - [`fd_zstd_dstream_align`](fd_zstd.c.driver.md#fd_zstd_dstream_align)
    - [`fd_zstd_dstream_footprint`](fd_zstd.c.driver.md#fd_zstd_dstream_footprint)
    - [`fd_zstd_dstream_new`](fd_zstd.c.driver.md#fd_zstd_dstream_new)
    - [`fd_zstd_dstream_read`](fd_zstd.c.driver.md#fd_zstd_dstream_read)
    - [`fd_zstd_dstream_reset`](fd_zstd.c.driver.md#fd_zstd_dstream_reset)
    - [`fd_zstd_dstream_delete`](fd_zstd.c.driver.md#fd_zstd_dstream_delete)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, tests Zstandard compression and decompression functionalities, and logs the results.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Declare a `fd_zstd_peek_t` array `_peek` for testing purposes.
    - Test [`fd_zstd_peek`](fd_zstd.h.driver.md#fd_zstd_peek) with `NULL` input and small sizes of `test_zstd_comp_0`, expecting `NULL` results.
    - For larger sizes of `test_zstd_comp_0`, test [`fd_zstd_peek`](fd_zstd.h.driver.md#fd_zstd_peek) and verify the properties of `_peek`.
    - Call [`test_decompress`](#test_decompress) to perform decompression tests on predefined test vectors.
    - Iterate over compression levels from 0 to 19, logging the estimated context size for each level using `ZSTD_estimateCCtxSize`.
    - Log a notice indicating the tests passed.
    - Call `fd_halt` to clean up and terminate the program.
- **Output**: The function returns an integer `0`, indicating successful execution.
- **Functions called**:
    - [`fd_zstd_peek`](fd_zstd.h.driver.md#fd_zstd_peek)
    - [`test_decompress`](#test_decompress)


