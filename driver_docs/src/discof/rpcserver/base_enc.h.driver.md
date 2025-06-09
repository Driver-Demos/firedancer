# Purpose
This code is a C header file that declares a function prototype for [`b58tobin`](#b58tobin). The function is intended to convert a Base58-encoded string (`b58`) into its binary representation (`bin`). The function takes four parameters: a pointer to the binary output buffer (`bin`), a pointer to an unsigned long that holds the size of the binary buffer (`binszp`), the Base58 string to be converted (`b58`), and the size of the Base58 string (`b58sz`). The inclusion of `"../../util/fd_util.h"` suggests that this file relies on utility functions or definitions provided in that header, which might be part of a larger project or library dealing with data encoding or decoding.
# Imports and Dependencies

---
- `../../util/fd_util.h`


# Function Declarations (Public API)

---
### b58tobin<!-- {{#callable_declaration:b58tobin}} -->
Converts a Base58-encoded string to binary data.
- **Description**: This function is used to decode a Base58-encoded string into its binary representation. It is useful when you need to convert data encoded in Base58 back to its original binary form. The function requires a buffer to store the binary output and the size of this buffer, which should be provided by the caller. The function will update the size to reflect the actual number of bytes written. It is important to ensure that the buffer is large enough to hold the decoded data. The function returns an error if the input contains invalid Base58 characters or if the output buffer is too small to hold the decoded data.
- **Inputs**:
    - `bin`: A pointer to a buffer where the decoded binary data will be stored. The buffer must be pre-allocated by the caller and should be large enough to hold the decoded data.
    - `binszp`: A pointer to an unsigned long that initially contains the size of the buffer pointed to by 'bin'. Upon successful completion, it is updated to reflect the actual number of bytes written to 'bin'. Must not be null.
    - `b58`: A pointer to a null-terminated string containing the Base58-encoded data. Must not be null.
    - `b58sz`: The length of the Base58-encoded string 'b58'. This should not include the null terminator.
- **Output**: Returns 0 on success. Returns 1 if the input contains invalid Base58 characters or if the output buffer is too small.
- **See also**: [`b58tobin`](base_enc.c.driver.md#b58tobin)  (Implementation)


