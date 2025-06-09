# Purpose
This C source code file is a test script designed to verify the correct mapping of HTTP/2 frame and setting identifiers to their respective names. It includes a function [`test_h2_enum`](#test_h2_enum) that uses assertions (`FD_TEST`) to check if the function `fd_h2_frame_name` correctly returns the expected string names for various HTTP/2 frame types, as defined by the HTTP/2 protocol. Similarly, it checks if `fd_h2_setting_name` returns the correct names for HTTP/2 settings. The script ensures that known identifiers return their expected names, while unknown or reserved identifiers return "unknown" or "reserved" as appropriate. This file is likely part of a larger test suite for validating HTTP/2 protocol handling in a software project.
# Imports and Dependencies

---
- `fd_h2_proto.h`
- `../../util/log/fd_log.h`


# Functions

---
### test\_h2\_enum<!-- {{#callable:test_h2_enum}} -->
The `test_h2_enum` function verifies that the frame and setting names returned by [`fd_h2_frame_name`](fd_h2_proto.c.driver.md#fd_h2_frame_name) and [`fd_h2_setting_name`](fd_h2_proto.c.driver.md#fd_h2_setting_name) match expected HTTP/2 protocol names for given identifiers.
- **Inputs**: None
- **Control Flow**:
    - The function begins by testing frame types, using `FD_TEST` to assert that the string returned by [`fd_h2_frame_name`](fd_h2_proto.c.driver.md#fd_h2_frame_name) for each frame type identifier matches the expected name.
    - It checks specific frame type identifiers from 0x00 to 0x10, each corresponding to a known HTTP/2 frame type name, and expects 'unknown' for certain identifiers.
    - A loop iterates over frame type identifiers from 0x11 to 0xff, asserting that each returns 'unknown'.
    - The function then tests setting names, using `FD_TEST` to assert that the string returned by [`fd_h2_setting_name`](fd_h2_proto.c.driver.md#fd_h2_setting_name) for each setting identifier matches the expected name.
    - It checks specific setting identifiers from 0x00 to 0x07, each corresponding to a known HTTP/2 setting name, and expects 'unknown' for identifier 0x07.
- **Output**: The function does not return a value; it uses assertions to verify correctness, which may trigger a failure if any test fails.
- **Functions called**:
    - [`fd_h2_frame_name`](fd_h2_proto.c.driver.md#fd_h2_frame_name)
    - [`fd_h2_setting_name`](fd_h2_proto.c.driver.md#fd_h2_setting_name)


---
### test\_h2\_proto<!-- {{#callable:test_h2_proto}} -->
The function `test_h2_proto` is a simple wrapper that calls the [`test_h2_enum`](#test_h2_enum) function to perform tests on HTTP/2 frame and setting names.
- **Inputs**: None
- **Control Flow**:
    - The function `test_h2_proto` is defined as a static void function, meaning it does not return a value and is limited to the file scope.
    - The function contains a single line of code that calls another function, [`test_h2_enum`](#test_h2_enum).
    - There are no input parameters or complex logic within `test_h2_proto`.
- **Output**: The function does not produce any output as it is a void function and simply calls another function.
- **Functions called**:
    - [`test_h2_enum`](#test_h2_enum)


