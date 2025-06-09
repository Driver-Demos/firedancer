# Purpose
This C source code file provides functionality for encoding and decoding hexadecimal data. It includes two primary functions: [`fd_hex_decode`](#fd_hex_decode) and [`fd_hex_encode`](#fd_hex_encode). The [`fd_hex_decode`](#fd_hex_decode) function converts a hexadecimal string into its binary representation, storing the result in a destination buffer. It uses a helper function, [`fd_hex_unhex`](#fd_hex_unhex), to convert individual hexadecimal characters to their numeric values. The [`fd_hex_encode`](#fd_hex_encode) function performs the reverse operation, converting binary data into a hexadecimal string using a lookup table (LUT) for efficient character mapping. The code is designed to handle data of arbitrary size, as indicated by the `sz` parameter in both functions, which specifies the number of bytes to process.

The file is likely part of a larger library or application, as it includes a header file (`fd_hex.h`) and does not contain a `main` function, indicating it is not an executable on its own. The presence of comments such as "FIXME" and "TODO" suggests areas for potential optimization and future enhancements, such as using a lookup table for the [`fd_hex_unhex`](#fd_hex_unhex) function or adding an AVX-optimized version of the decoding process. The code is focused on providing a specific utility for hexadecimal data manipulation, which can be a common requirement in applications dealing with data serialization, cryptography, or network communication.
# Imports and Dependencies

---
- `fd_hex.h`


# Functions

---
### fd\_hex\_unhex<!-- {{#callable:fd_hex_unhex}} -->
The `fd_hex_unhex` function converts a single hexadecimal character to its integer value.
- **Inputs**:
    - `c`: An integer representing a character, expected to be a hexadecimal digit ('0'-'9', 'a'-'f', or 'A'-'F').
- **Control Flow**:
    - Check if the character is between '0' and '9'; if true, return the integer value by subtracting '0'.
    - Check if the character is between 'a' and 'f'; if true, return the integer value by subtracting 'a' and adding 10.
    - Check if the character is between 'A' and 'F'; if true, return the integer value by subtracting 'A' and adding 10.
    - If none of the above conditions are met, return -1 indicating an invalid hexadecimal character.
- **Output**: Returns the integer value of the hexadecimal character if valid, otherwise returns -1.


---
### fd\_hex\_decode<!-- {{#callable:fd_hex_decode}} -->
The `fd_hex_decode` function decodes a hexadecimal string into its binary representation, storing the result in a destination buffer.
- **Inputs**:
    - `_dst`: A pointer to the destination buffer where the decoded binary data will be stored.
    - `hex`: A constant character pointer to the hexadecimal string that needs to be decoded.
    - `sz`: An unsigned long integer representing the number of bytes to decode from the hexadecimal string.
- **Control Flow**:
    - Initialize a pointer `dst` to point to the destination buffer `_dst`.
    - Iterate over the range from 0 to `sz`, processing two characters from `hex` per iteration.
    - For each iteration, convert the next two hexadecimal characters to their integer values using [`fd_hex_unhex`](#fd_hex_unhex).
    - Check if either of the converted values is negative, indicating an invalid hexadecimal character, and return the current index `i` if so.
    - Combine the two integer values into a single byte and store it in the destination buffer `dst`.
    - Increment the `dst` pointer to store the next byte in the subsequent position.
- **Output**: Returns the number of bytes successfully decoded, which is the same as the number of iterations completed before encountering an invalid character.
- **Functions called**:
    - [`fd_hex_unhex`](#fd_hex_unhex)


---
### fd\_hex\_encode<!-- {{#callable:fd_hex_encode}} -->
The `fd_hex_encode` function converts a binary data buffer into a hexadecimal string representation.
- **Inputs**:
    - `dst`: A pointer to the destination buffer where the hexadecimal string will be stored.
    - `_src`: A pointer to the source buffer containing the binary data to be encoded.
    - `sz`: The size of the source buffer in bytes.
- **Control Flow**:
    - The function begins by casting the `_src` pointer to a `uchar` pointer named `src`.
    - A static lookup table `lut` is defined, containing the hexadecimal characters '0' to 'f'.
    - A loop iterates over each byte in the source buffer, from index 0 to `sz-1`.
    - For each byte, the high nibble (4 bits) is extracted and used to index into `lut` to get the corresponding hexadecimal character, which is then stored in `dst`.
    - Similarly, the low nibble is extracted and used to index into `lut` to get the corresponding hexadecimal character, which is also stored in `dst`.
    - The `dst` pointer is incremented after storing each character.
- **Output**: The function returns a pointer to the end of the destination buffer, which is the position after the last written character.


