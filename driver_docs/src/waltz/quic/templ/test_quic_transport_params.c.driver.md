# Purpose
This C source code file is designed to test and validate the encoding and decoding of QUIC (Quick UDP Internet Connections) transport parameters and preferred addresses. It includes several static functions that perform specific tests, such as [`test_preferred_address`](#test_preferred_address), which verifies the encoding and decoding of a `fd_quic_preferred_address_t` structure, ensuring that the encoded data matches expected byte sequences and that the decoded data is equivalent to the original. The [`test_max_size`](#test_max_size) function constructs a transport parameter object with the largest possible values for each field, testing the system's ability to handle maximum-sized data structures. Additionally, the [`test_grease`](#test_grease) function checks the decoder's compliance with RFC 9000 Section 7.4.2, which mandates that unknown transport parameters should be ignored, ensuring robustness against future protocol extensions.

The file serves as a comprehensive test suite for QUIC transport parameters, focusing on encoding, decoding, and compliance with protocol specifications. It includes necessary headers and dependencies, such as `fd_quic_conn_id.h`, `fd_quic_enum.h`, and `fd_quic_proto.h`, indicating its reliance on external definitions and functions for QUIC protocol operations. The presence of a [`main`](#main) function suggests that this file is intended to be compiled into an executable for running these tests. The code does not define public APIs or external interfaces but rather focuses on internal validation and testing of QUIC-related functionalities, ensuring that the implementation adheres to the expected standards and can handle edge cases effectively.
# Imports and Dependencies

---
- `../../../util/fd_util.h`
- `../fd_quic_conn_id.h`
- `../fd_quic_enum.h`
- `../fd_quic_proto.h`
- `../fd_quic_proto.c`
- `fd_quic_transport_params.h`


# Functions

---
### preferred\_address\_equal<!-- {{#callable:preferred_address_equal}} -->
The `preferred_address_equal` function checks if two `fd_quic_preferred_address_t` structures are equal by comparing their IPv4 and IPv6 addresses, ports, connection ID lengths, connection IDs, and reset tokens.
- **Inputs**:
    - `p1`: A pointer to the first `fd_quic_preferred_address_t` structure to compare.
    - `p2`: A pointer to the second `fd_quic_preferred_address_t` structure to compare.
- **Control Flow**:
    - The function uses `memcmp` to compare the IPv4 addresses of `p1` and `p2` for equality.
    - It checks if the IPv4 ports of `p1` and `p2` are equal.
    - It uses `memcmp` to compare the IPv6 addresses of `p1` and `p2` for equality.
    - It checks if the IPv6 ports of `p1` and `p2` are equal.
    - It checks if the connection ID lengths of `p1` and `p2` are equal.
    - It uses `memcmp` to compare the connection IDs of `p1` and `p2` for equality, using the connection ID length.
    - It uses `memcmp` to compare the reset tokens of `p1` and `p2` for equality.
- **Output**: The function returns an integer that is non-zero if all components of the two preferred addresses are equal, and zero otherwise.


---
### test\_preferred\_address<!-- {{#callable:test_preferred_address}} -->
The `test_preferred_address` function tests the encoding and decoding of a QUIC preferred address structure, ensuring correctness and consistency.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `fd_quic_preferred_address_t` structure with specific IPv4, IPv6, port, connection ID, and reset token values.
    - Encode the `preferred_address` structure into a byte array `encoded` using `fd_quic_encode_preferred_address` and verify the encoded size matches the expected maximum size.
    - Compare the encoded byte array with a predefined expected byte array `expected_0` to ensure correct encoding.
    - Decode the encoded byte array back into a `fd_quic_preferred_address_t` structure and verify it matches the original `preferred_address` using [`preferred_address_equal`](#preferred_address_equal).
    - Modify the `conn_id_len` of `preferred_address` to 0, re-encode it, and verify the encoding does not fail.
    - Compare the new encoded byte array with another predefined expected byte array `expected_1` to ensure correct encoding with a zero-length connection ID.
    - Decode the new encoded byte array and verify the decoded structure matches the modified `preferred_address`.
- **Output**: The function does not return any value; it performs tests and uses assertions to validate the encoding and decoding processes.
- **Functions called**:
    - [`preferred_address_equal`](#preferred_address_equal)


---
### test\_max\_size<!-- {{#callable:test_max_size}} -->
The `test_max_size` function constructs a QUIC transport parameters object with maximum possible values for each parameter, encodes it, and logs the size of the resulting encoded data.
- **Inputs**: None
- **Control Flow**:
    - Initialize a `fd_quic_transport_params_t` structure named `params` with maximum values for each transport parameter, setting all present flags to 1.
    - Declare a buffer `buf` of size 4096 bytes to hold the encoded transport parameters.
    - Call [`fd_quic_encode_transport_params`](fd_quic_transport_params.c.driver.md#fd_quic_encode_transport_params) to encode the `params` structure into `buf`, storing the size of the encoded data in `sz`.
    - Use `FD_TEST` to assert that the encoding did not fail (i.e., `sz` is not equal to `FD_QUIC_ENCODE_FAIL`).
    - Log the size of the encoded transport parameter blob using `FD_LOG_NOTICE`.
- **Output**: The function does not return a value; it logs the size of the encoded transport parameters.
- **Functions called**:
    - [`fd_quic_encode_transport_params`](fd_quic_transport_params.c.driver.md#fd_quic_encode_transport_params)


---
### test\_grease<!-- {{#callable:test_grease}} -->
The `test_grease` function tests the ability of the QUIC transport parameter decoder to correctly skip unknown transport parameters and handle known parameters.
- **Inputs**: None
- **Control Flow**:
    - Define a static array `unknown_params` containing a mix of unknown and known transport parameters.
    - Initialize a `fd_quic_transport_params_t` structure `params` to zero.
    - Call [`fd_quic_decode_transport_params`](fd_quic_transport_params.c.driver.md#fd_quic_decode_transport_params) with `unknown_params` excluding the last two bytes and assert that it returns 0, indicating successful decoding without the known parameter.
    - Call [`fd_quic_decode_transport_params`](fd_quic_transport_params.c.driver.md#fd_quic_decode_transport_params) with `unknown_params` excluding the last byte and assert that it returns -1, indicating a failure due to incomplete known parameter data.
    - Assert that `params.disable_active_migration_present` is 0, confirming that the known parameter was not set.
    - Call [`fd_quic_decode_transport_params`](fd_quic_transport_params.c.driver.md#fd_quic_decode_transport_params) with the full `unknown_params` array and assert that it returns 0, indicating successful decoding including the known parameter.
    - Assert that `params.disable_active_migration_present` is 1, confirming that the known parameter was correctly set.
- **Output**: The function does not return any value; it uses assertions to validate the behavior of the decoder.
- **Functions called**:
    - [`fd_quic_decode_transport_params`](fd_quic_transport_params.c.driver.md#fd_quic_decode_transport_params)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, runs a series of tests on QUIC transport parameters, logs a success message, and then halts the program.
- **Inputs**:
    - `argc`: The count of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Execute [`test_preferred_address`](#test_preferred_address) to test encoding and decoding of preferred addresses in QUIC.
    - Execute [`test_max_size`](#test_max_size) to test the encoding of the largest possible QUIC transport parameter object.
    - Execute [`test_grease`](#test_grease) to ensure the decoder skips unknown transport parameters as per RFC 9000.
    - Call [`fd_quic_dump_transport_param_desc`](fd_quic_transport_params.c.driver.md#fd_quic_dump_transport_param_desc) to output the transport parameter description to `stdout`.
    - Log a notice message indicating the tests passed using `FD_LOG_NOTICE`.
    - Call `fd_halt` to terminate the program.
- **Output**: The function returns an integer value `0` indicating successful execution.
- **Functions called**:
    - [`test_preferred_address`](#test_preferred_address)
    - [`test_max_size`](#test_max_size)
    - [`test_grease`](#test_grease)
    - [`fd_quic_dump_transport_param_desc`](fd_quic_transport_params.c.driver.md#fd_quic_dump_transport_param_desc)


