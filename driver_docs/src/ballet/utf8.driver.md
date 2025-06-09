
## Files
- **[fd_utf8.c](utf8/fd_utf8.c.driver.md)**: The `fd_utf8.c` file in the `firedancer` codebase provides a basic UTF-8 validation function, originally imported from Rust, to verify the validity of UTF-8 encoded strings.
- **[fd_utf8.h](utf8/fd_utf8.h.driver.md)**: The `fd_utf8.h` file in the `firedancer` codebase provides a function to verify whether a byte array contains valid UTF-8 according to the validation rules of Rust's `std::str::from_utf8`.
- **[Local.mk](utf8/Local.mk.driver.md)**: The `Local.mk` file in the `firedancer` codebase specifies the headers, object files, and unit tests related to UTF-8 functionality, including the execution of a unit test named `test_utf8`.
- **[test_utf8.c](utf8/test_utf8.c.driver.md)**: The `test_utf8.c` file in the `firedancer` codebase contains a series of tests to verify the correctness of UTF-8 encoding validation using predefined test vectors and various edge cases.
