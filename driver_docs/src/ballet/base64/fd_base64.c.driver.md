# Purpose
This C source code file provides functionality for encoding and decoding data using the Base64 encoding scheme. It includes two primary functions: [`fd_base64_decode`](#fd_base64_decode) and [`fd_base64_encode`](#fd_base64_encode). The [`fd_base64_decode`](#fd_base64_decode) function takes a Base64-encoded input string and decodes it into its original binary form, handling padding and alignment checks to ensure the input is valid. It uses an inverse lookup table (`invlut`) to map ASCII characters to their corresponding Base64 values, facilitating efficient decoding. The [`fd_base64_encode`](#fd_base64_encode) function, on the other hand, converts binary data into a Base64-encoded string, ensuring that the output is properly padded to meet Base64 encoding standards. This function uses a character set defined by `base64_alphabet` to map binary data to Base64 characters.

The file is designed to be part of a larger codebase, as indicated by the inclusion of a header file (`fd_base64.h`). It provides a focused functionality specifically for Base64 encoding and decoding, which is a common requirement for data serialization and transmission in various applications. The code is structured to handle typical edge cases, such as input length alignment and padding, ensuring robustness in its operations. The functions are likely intended to be used as part of a library or module that can be integrated into other software systems requiring Base64 processing capabilities.
# Imports and Dependencies

---
- `fd_base64.h`


# Global Variables

---
### base64\_alphabet
- **Type**: ``const char[]``
- **Description**: The `base64_alphabet` is a static constant character array that contains the 64 characters used in Base64 encoding. These characters include uppercase and lowercase letters, digits, and the symbols '+' and '/'. This array is used to map binary data to Base64 encoded characters.
- **Use**: This variable is used in the `fd_base64_encode` function to convert binary data into a Base64 encoded string by mapping each 6-bit group of the input data to a character in the Base64 alphabet.


---
### invlut
- **Type**: `uchar const[256]`
- **Description**: The `invlut` variable is a static constant array of 256 unsigned characters, used as an inverse lookup table for Base64 decoding. It maps ASCII byte values to their corresponding Base64 code points, with non-Base64 characters mapped to 0xff, indicating invalid input.
- **Use**: This variable is used in the `fd_base64_decode` function to quickly translate Base64 encoded characters into their respective values for decoding.


# Functions

---
### fd\_base64\_decode<!-- {{#callable:fd_base64_decode}} -->
The `fd_base64_decode` function decodes a Base64 encoded input string into its original binary form.
- **Inputs**:
    - `out`: A pointer to an unsigned character array where the decoded output will be stored.
    - `in`: A constant character pointer to the Base64 encoded input string.
    - `in_len`: An unsigned long integer representing the length of the input string.
- **Control Flow**:
    - Initialize a pointer `out_orig` to the start of the output buffer `out`.
    - Return 0 if the input length `in_len` is zero.
    - Check if `in_len` is aligned to 4; if not, return -1 indicating an error.
    - Count padding characters ('=') at the end of the input and adjust `in_len` accordingly.
    - Return -1 if the adjusted `in_len` modulo 4 equals 1, indicating invalid padding.
    - Enter a loop to process chunks of 4 characters from the input while `in_len` is at least 4.
    - For each chunk, use an inverse lookup table `invlut` to convert Base64 characters to their binary values.
    - Check for errors in conversion; if any character is invalid, return -1.
    - Combine the 4 converted values into a 24-bit integer and extract 3 bytes to store in the output buffer.
    - Adjust pointers and lengths to process the next chunk.
    - After the loop, handle any remaining characters (less than 4) in the input.
    - Convert the remaining characters using the lookup table and handle errors similarly.
    - Combine the remaining values into a 24-bit integer, swap byte order, and extract bytes to store in the output buffer.
    - Return the number of bytes written to the output buffer by subtracting `out_orig` from `out`.
- **Output**: Returns a long integer representing the number of bytes written to the output buffer, or -1 if an error occurs during decoding.


---
### fd\_base64\_encode<!-- {{#callable:fd_base64_encode}} -->
The `fd_base64_encode` function encodes binary data into a Base64 string.
- **Inputs**:
    - `encoded`: A pointer to a character array where the encoded Base64 string will be stored.
    - `_data`: A pointer to the binary data that needs to be encoded.
    - `data_len`: The length of the binary data to be encoded.
- **Control Flow**:
    - Initialize `encoded_len`, `accumulator`, and `bits_collected` to zero.
    - Convert `_data` to a `uchar` pointer `data` using `fd_type_pun_const`.
    - Iterate over each byte of `data` while `data_len` is greater than zero.
    - For each byte, shift `accumulator` left by 8 bits and add the byte to `accumulator`, then increase `bits_collected` by 8.
    - While `bits_collected` is at least 6, extract the top 6 bits from `accumulator`, map them to a Base64 character using `base64_alphabet`, and append it to `encoded`.
    - If there are remaining bits in `accumulator` after processing all bytes, pad the last Base64 character with zeroes and append it to `encoded`.
    - Add '=' padding characters to `encoded` until its length is a multiple of 4.
    - Return the length of the encoded Base64 string.
- **Output**: The function returns the length of the encoded Base64 string.


