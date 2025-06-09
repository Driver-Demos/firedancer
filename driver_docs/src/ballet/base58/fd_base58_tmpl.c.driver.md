# Purpose
This C source code file provides a template for encoding and decoding binary data to and from Base58 format, specifically for binary data of lengths 32 or 64 bytes. The code is designed to be included multiple times with different configurations, as it uses preprocessor directives to define the size of the binary data (`N`), the size of the intermediate representation (`INTERMEDIATE_SZ`), and the size of the binary data in 32-bit limbs (`BINARY_SIZE`). The file defines two main functions: `fd_base58_encode` and `fd_base58_decode`, which handle the conversion of binary data to a Base58 encoded string and vice versa. The encoding process involves converting the binary data into an intermediate format and then into Base58, while the decoding process reverses this transformation.

The code is highly optimized for performance, utilizing AVX instructions when available to accelerate the encoding and decoding processes. It includes detailed handling of edge cases, such as leading zeros in the binary data and ensuring that the encoded string has the correct number of leading '1' characters. The file does not define a public API directly but provides a mechanism for generating specific encoding and decoding functions based on the defined size of the binary data. This makes it a specialized utility for applications that require efficient Base58 encoding and decoding of fixed-size binary data, such as cryptographic applications or data serialization tasks.
# Functions

---
### SUFFIX<!-- {{#callable:SUFFIX}} -->
The `SUFFIX(fd_base58_decode)` function decodes a Base58-encoded string into its original binary form, ensuring the input is valid and properly formatted.
- **Inputs**:
    - `encoded`: A constant character pointer to the Base58-encoded string that needs to be decoded.
    - `out`: A pointer to an unsigned character array where the decoded binary data will be stored.
- **Control Flow**:
    - Initialize a character count and iterate over the encoded string to validate each character against the Base58 inverse table.
    - If any character is invalid or the string is too long, return NULL.
    - Prepend zeros to the raw Base58 array to ensure it has a fixed size, then convert the Base58 characters to their corresponding values using the inverse table.
    - Convert the raw Base58 values to an intermediate format using base 58^5.
    - Transform the intermediate values into a binary format using a conversion table, ensuring no overflow occurs by adjusting values to fit within 32-bit limits.
    - Check if the largest binary term exceeds 2^32, returning NULL if it does.
    - Convert the binary terms to big-endian format and store them in the output array.
    - Ensure the number of leading '1's in the encoded string matches the number of leading zeros in the decoded output, returning NULL if they do not match.
    - Return the output array if all checks pass.
- **Output**: The function returns a pointer to the output array containing the decoded binary data, or NULL if the input is invalid or improperly formatted.
- **Functions called**:
    - [`SUFFIX`](#SUFFIX)


