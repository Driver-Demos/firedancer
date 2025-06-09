# Purpose
The provided C source code file defines two functions, [`fd_io_fgets`](#fd_io_fgets) and [`fd_io_fgetc`](#fd_io_fgetc), which are designed to read data from a buffered input stream. These functions are part of a broader input/output system, as indicated by the inclusion of headers like "fd_io_readline.h" and "../../util/cstr/fd_cstr.h". The [`fd_io_fgets`](#fd_io_fgets) function reads a line from the input stream into a provided string buffer, handling newline characters and ensuring that the buffer does not overflow. It uses a peek mechanism to efficiently read from the stream and handles errors by setting an error code. The [`fd_io_fgetc`](#fd_io_fgetc) function reads a single character from the input stream, also using the peek mechanism to check the availability of data and manage errors similarly.

This code provides a narrow functionality focused on reading operations from a buffered input stream, which is likely part of a larger library or application dealing with file or stream I/O. The functions are designed to be robust, handling various edge cases such as buffer limits and stream errors. The use of utility functions like `fd_cstr_append_text` and `fd_io_buffered_istream_peek` suggests that these functions are part of a modular system where string manipulation and stream handling are abstracted into reusable components. The code does not define public APIs or external interfaces directly but rather implements specific functionalities that could be used internally within a larger system.
# Imports and Dependencies

---
- `fd_io_readline.h`
- `../../util/cstr/fd_cstr.h`


# Functions

---
### fd\_io\_fgets<!-- {{#callable:fd_io_fgets}} -->
The `fd_io_fgets` function reads a line from a buffered input stream into a string, handling errors and buffer limitations.
- **Inputs**:
    - `str`: A pointer to a character array where the read line will be stored.
    - `str_max`: The maximum number of characters to read into the string, including the null terminator.
    - `istream`: A pointer to a `fd_io_buffered_istream_t` structure representing the buffered input stream.
    - `perr`: A pointer to an integer where error codes will be stored.
- **Control Flow**:
    - Initialize the error code to 0 and calculate the maximum number of characters to read, excluding the null terminator.
    - Attempt to read from the input stream up to two times.
    - Peek into the input stream to check for a newline character within the available buffer size.
    - If a newline is found, calculate the size to read, append the text to the string, skip the read characters in the stream, and return the string.
    - If no newline is found, attempt to fetch more data into the buffer.
    - If fetching data results in an error, set the error code and return NULL if the error is positive, or continue if negative.
    - If the buffer is empty after fetching, set the error code to -1 and return NULL.
    - If no newline is found after two attempts, read as much as possible from the buffer, append it to the string, and return the string.
- **Output**: Returns the pointer to the string containing the read line, or NULL if an error occurs.


---
### fd\_io\_fgetc<!-- {{#callable:fd_io_fgetc}} -->
The `fd_io_fgetc` function attempts to read a single character from a buffered input stream, returning the character or an error code.
- **Inputs**:
    - `istream`: A pointer to a `fd_io_buffered_istream_t` structure representing the buffered input stream from which to read a character.
    - `perr`: A pointer to an integer where the function will store an error code if an error occurs during the read operation.
- **Control Flow**:
    - The function enters a loop that will attempt to read a character from the input stream up to two times.
    - In each iteration, it first tries to peek at the next character in the stream using `fd_io_buffered_istream_peek` and checks the size of the available data with `fd_io_buffered_istream_peek_sz`.
    - If there is data available (`peek_max` is non-zero), it sets `*perr` to 0 and returns the character as an integer.
    - If no data is available, it attempts to fetch more data into the stream buffer using `fd_io_buffered_istream_fetch`.
    - If fetching data results in an error (`err` is non-zero), it sets `*perr` to the error code and returns -1.
    - If the loop completes without successfully reading a character, it sets `*perr` to -1 and returns -1, although this part of the code is marked as unreachable.
- **Output**: The function returns the next character from the input stream as an integer if successful, or -1 if an error occurs or no character is available.


