# Purpose
This code is a C header file designed to facilitate buffered line reading from input streams. It provides function prototypes for [`fd_io_fgets`](#fd_io_fgets) and [`fd_io_fgetc`](#fd_io_fgetc), which are used to read lines and characters, respectively, from a buffered input stream (`fd_io_buffered_istream_t`). The [`fd_io_fgets`](#fd_io_fgets) function reads bytes into a provided character array until a newline, the maximum specified length, or the end of the file is reached, handling errors and end-of-file conditions by setting an error code. The header file includes necessary dependencies and uses include guards to prevent multiple inclusions, ensuring efficient and error-free compilation. This file is part of a larger system, likely dealing with input/output operations, and is intended to provide a robust interface for reading data line-by-line from streams.
# Imports and Dependencies

---
- `../../util/io/fd_io.h`


# Global Variables

---
### fd\_io\_fgets
- **Type**: `function`
- **Description**: The `fd_io_fgets` function reads bytes from a buffered input stream (`istream`) into a character array (`str`) until a specified maximum number of bytes (`str_max-1`) is reached, a newline character is encountered, or the end of the file is reached. It returns a pointer to the null-terminated string if successful, or NULL if an error occurs or EOF is reached before reading any bytes.
- **Use**: This function is used to read lines from a buffered input stream into a string, handling errors and end-of-file conditions.


# Function Declarations (Public API)

---
### fd\_io\_fgets<!-- {{#callable_declaration:fd_io_fgets}} -->
Reads a line from a buffered input stream into a string.
- **Description**: This function reads bytes from a buffered input stream into the provided string buffer until a newline character is encountered, the specified maximum number of characters is read, or the end of the stream is reached. It is useful for reading lines from a file or other input source that supports buffered reading. The function must be called with a valid input stream and a sufficiently large buffer to store the line. It handles errors by returning NULL and setting the error code appropriately. The function assumes the input stream is non-blocking and that its buffer size is at least as large as the maximum string size specified.
- **Inputs**:
    - `str`: A pointer to a character array where the read line will be stored. The array must be large enough to hold up to str_max characters, including the null terminator. The caller retains ownership and must ensure it is not null.
    - `str_max`: The maximum number of characters to read, including the null terminator. Must be at least 1. If less than 1, it is clamped to 1.
    - `istream`: A pointer to a buffered input stream from which the line will be read. Must not be null. The stream should be non-blocking and have a buffer size at least as large as str_max.
    - `err`: A pointer to an integer where the error code will be stored. Must not be null. On success, it is set to 0 if a newline is found or -1 if EOF is reached without a newline. On error, it is set to a positive errno value.
- **Output**: Returns a pointer to the string buffer containing the read line on success, or NULL on error or if EOF is reached before reading any bytes.
- **See also**: [`fd_io_fgets`](fd_io_readline.c.driver.md#fd_io_fgets)  (Implementation)


---
### fd\_io\_fgetc<!-- {{#callable_declaration:fd_io_fgetc}} -->
Reads a single character from a buffered input stream.
- **Description**: Use this function to read the next character from a buffered input stream represented by `istream`. It attempts to fetch a character from the stream, returning it as an integer. If the stream is empty, it will attempt to refill the buffer once. The function sets the error code in `perr` to indicate success or the type of error encountered. This function is useful when reading data character by character from a non-blocking input stream.
- **Inputs**:
    - `istream`: A pointer to a `fd_io_buffered_istream_t` representing the buffered input stream. Must not be null. The stream should be properly initialized and open for reading.
    - `perr`: A pointer to an integer where the function will store the error code. Must not be null. On success, `*perr` is set to 0. If an error occurs, `*perr` is set to a positive error code, or -1 if EOF is reached.
- **Output**: Returns the next character from the stream as an integer on success. Returns -1 if an error occurs or EOF is reached, with the error code set in `*perr`.
- **See also**: [`fd_io_fgetc`](fd_io_readline.c.driver.md#fd_io_fgetc)  (Implementation)


