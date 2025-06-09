# Purpose
This C source code file provides a specific functionality for converting Base58-encoded strings into binary data. The primary function, [`b58tobin`](#b58tobin), is responsible for this conversion process. It takes a Base58 string and its size as input, along with a buffer to store the resulting binary data and its size. The function processes the input string, handling leading zeros and invalid characters, and populates the binary buffer with the decoded data. The code includes a static mapping array, `b58digits_map`, which is used to translate Base58 characters into their corresponding integer values. This mapping is crucial for the conversion process, as it allows the function to interpret the Base58 string correctly.

The file is likely part of a larger library or application that deals with Base58 encoding and decoding, which is commonly used in applications like cryptocurrency addresses. The code is not intended to be an executable on its own but rather a utility function that can be integrated into other programs. It does not define a public API or external interface directly but provides a critical internal function for Base58 decoding. The use of typedefs and constants, such as `b58_maxint_t` and `b58_almostmaxint_t`, helps manage the conversion process efficiently by handling large integers and ensuring the correct size of the output buffer.
# Imports and Dependencies

---
- `base_enc.h`
- `stdint.h`


# Global Variables

---
### b58digits\_map
- **Type**: `int8_t array`
- **Description**: The `b58digits_map` is a static constant array of type `int8_t` that maps ASCII character values to their corresponding Base58 digit values. The array is initialized with 256 elements, where each element corresponds to an ASCII character code, and the value is either the Base58 digit or -1 for invalid characters.
- **Use**: This array is used to quickly look up the Base58 digit value of a character during Base58 decoding operations.


---
### b58\_almostmaxint\_mask
- **Type**: `b58_almostmaxint_t`
- **Description**: The variable `b58_almostmaxint_mask` is a constant of type `b58_almostmaxint_t`, which is defined as an unsigned integer type. It is calculated by shifting a 1 of type `b58_maxint_t` left by the number of bits in `b58_almostmaxint_t` and then subtracting 1, effectively creating a mask with all bits set to 1 for the size of `b58_almostmaxint_t`. This mask is used to ensure that values fit within the bit-width of `b58_almostmaxint_t`. 
- **Use**: This variable is used to mask values to ensure they fit within the bit-width of `b58_almostmaxint_t` during base58 encoding operations.


# Functions

---
### b58tobin<!-- {{#callable:b58tobin}} -->
The `b58tobin` function converts a Base58 encoded string into a binary representation, handling leading zeros and validating input characters.
- **Inputs**:
    - `bin`: A pointer to the buffer where the binary output will be stored.
    - `binszp`: A pointer to an unsigned long that initially contains the size of the binary buffer and will be updated to reflect the actual size of the binary data after conversion.
    - `b58`: A pointer to the Base58 encoded input string.
    - `b58sz`: The length of the Base58 encoded input string.
- **Control Flow**:
    - Initialize variables and calculate the size of the output integer array `outi` based on the binary size.
    - Set all elements of `outi` to zero using `memset`.
    - Count leading zeros in the Base58 input string and store the count in `zerocount`.
    - Iterate over the Base58 input string starting from the first non-zero character.
    - For each character, check if it is a valid Base58 character using `b58digits_map`; return 1 if invalid.
    - Convert the Base58 character to its corresponding value and update the `outi` array using multiplication and addition, handling carry-over.
    - Check for overflow conditions and return 1 if the output number is too big.
    - Convert the `outi` array to a binary format and store it in the `bin` buffer, handling any remaining bytes.
    - Adjust the binary size `binszp` to account for leading zeros and the actual number of bytes used.
    - Return 0 to indicate successful conversion.
- **Output**: Returns 0 on successful conversion, or 1 if an error occurs due to invalid input or overflow.


