# Purpose
This C source code file provides a UTF-8 validation function, [`fd_utf8_verify`](#fd_utf8_verify), which checks whether a given string is a valid UTF-8 encoded sequence. The file includes a static array, `fd_utf8_char_width`, which maps each possible byte value (0-255) to the expected width of the UTF-8 character it might start. This array is crucial for determining how many subsequent bytes should be checked to validate a multi-byte UTF-8 character. The function iterates over the input string, using this array to guide the validation process, ensuring that each character adheres to the UTF-8 encoding rules. If any character does not conform, the function returns 0, indicating invalid UTF-8; otherwise, it returns 1 for valid UTF-8.

The code is a focused implementation, primarily concerned with UTF-8 validation, and does not define a broad API or external interfaces beyond the [`fd_utf8_verify`](#fd_utf8_verify) function. It is designed to be a utility function that can be integrated into larger systems requiring UTF-8 validation. The file also includes a comment indicating a potential future enhancement to add a high-performance AVX version, suggesting an interest in optimizing the function for specific hardware capabilities. The inclusion of a header file, `fd_utf8.h`, implies that this function might be part of a larger library or module dealing with UTF-8 or character encoding functionalities.
# Imports and Dependencies

---
- `fd_utf8.h`


# Global Variables

---
### fd\_utf8\_char\_width
- **Type**: ``uchar const[256]``
- **Description**: The `fd_utf8_char_width` is a static constant array of unsigned characters with 256 elements, representing the width in bytes of UTF-8 encoded characters based on their leading byte value. The array is used to determine how many bytes a UTF-8 character occupies, with values ranging from 0 to 4, where 0 indicates an invalid or non-start byte.
- **Use**: This array is used in UTF-8 validation to quickly determine the byte width of a character from its leading byte.


# Functions

---
### fd\_utf8\_verify<!-- {{#callable:fd_utf8_verify}} -->
The `fd_utf8_verify` function checks if a given string is a valid UTF-8 encoded sequence.
- **Inputs**:
    - `str`: A pointer to the string to be verified for UTF-8 validity.
    - `sz`: The size of the string in bytes.
- **Control Flow**:
    - Initialize a pointer `cur` to the start of the string and check if it is NULL, returning 1 if so.
    - Set `end` to point to the end of the string based on the size `sz`.
    - Iterate over the string using `cur` until it reaches `end`.
    - For each character, check if it is a non-ASCII character (>= 0x80).
    - Determine the width of the UTF-8 character using `fd_utf8_char_width` and check if there are enough bytes remaining in the string for this character width, returning 0 if not.
    - For each width case (2, 3, or 4 bytes), validate the subsequent bytes according to UTF-8 encoding rules, returning 0 if any validation fails.
    - If the character is ASCII (< 0x80), simply move to the next character.
    - Return 1 if the entire string is validated successfully.
- **Output**: Returns 1 if the string is a valid UTF-8 sequence, otherwise returns 0.


