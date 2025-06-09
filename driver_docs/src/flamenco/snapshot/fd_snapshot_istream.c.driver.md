# Purpose
This C source code file provides functionality for handling input streams with different underlying data sources and formats, specifically focusing on Zstandard (ZSTD) compressed streams, file streams, and TAR archive streams. The file defines three main components: `fd_io_istream_zstd_t`, `fd_io_istream_file_t`, and `fd_tar_io_reader_t`. Each of these components is designed to facilitate reading from a specific type of input stream. The `fd_io_istream_zstd_t` structure and its associated functions manage the decompression and reading of ZSTD compressed data streams. The `fd_io_istream_file_t` structure provides a simple interface for reading data from file descriptors. Lastly, the `fd_tar_io_reader_t` structure is used to read and process TAR archive streams, advancing through the archive and handling the data accordingly.

The file is structured to be part of a larger system, likely a library, as it includes headers from other parts of the project and defines specific data structures and functions for stream handling. It does not define a main function, indicating that it is not an executable but rather a component intended to be integrated into other software. The code includes conditional compilation directives to ensure that ZSTD-related functionality is only included if the ZSTD library is available, demonstrating modularity and adaptability to different build environments. The file also defines virtual table structures (`fd_io_istream_vt_t`) for the ZSTD and file input streams, which suggests a design pattern that allows for polymorphic behavior, enabling the use of different stream types interchangeably through a common interface.
# Imports and Dependencies

---
- `fd_snapshot_istream.h`
- `fd_snapshot_restore.h`
- `../../util/fd_util.h`
- `errno.h`


# Global Variables

---
### fd\_io\_istream\_zstd\_vt
- **Type**: `fd_io_istream_vt_t const`
- **Description**: The `fd_io_istream_zstd_vt` is a constant instance of the `fd_io_istream_vt_t` structure, which is used to define a virtual table for input stream operations. It specifically provides a function pointer to `fd_io_istream_zstd_read`, which is responsible for reading data from a Zstandard compressed input stream.
- **Use**: This variable is used to define the read operation for Zstandard compressed input streams, allowing for decompression and data retrieval.


---
### fd\_io\_istream\_file\_vt
- **Type**: `fd_io_istream_vt_t const`
- **Description**: The `fd_io_istream_file_vt` is a constant instance of the `fd_io_istream_vt_t` structure, which is used to define a virtual table for input stream operations specific to file-based streams. It contains a single function pointer, `read`, which is set to the `fd_io_istream_file_read` function, responsible for reading data from a file descriptor.
- **Use**: This variable is used to provide a standardized interface for reading data from file-based input streams.


# Functions

---
### fd\_io\_istream\_zstd\_new<!-- {{#callable:fd_io_istream_zstd_new}} -->
The `fd_io_istream_zstd_new` function initializes a new Zstandard decompression input stream object using provided memory, a Zstandard decompression stream, and a source input stream object.
- **Inputs**:
    - `mem`: A pointer to the memory location where the new `fd_io_istream_zstd_t` object will be initialized.
    - `dstream`: A pointer to an `fd_zstd_dstream_t` object, representing the Zstandard decompression stream to be used.
    - `src`: An `fd_io_istream_obj_t` object, representing the source input stream from which compressed data will be read.
- **Control Flow**:
    - The function casts the provided memory pointer `mem` to a `fd_io_istream_zstd_t` pointer named `this`.
    - It initializes the `fd_io_istream_zstd_t` object with the provided `dstream` and `src`, and sets the `in_cur` and `in_end` pointers to the start of the input buffer `in_buf`.
    - The `dirty` flag is initialized to 0, indicating that the buffer is not yet filled with new data.
    - The function returns the initialized `fd_io_istream_zstd_t` object.
- **Output**: A pointer to the newly initialized `fd_io_istream_zstd_t` object.


---
### fd\_io\_istream\_zstd\_delete<!-- {{#callable:fd_io_istream_zstd_delete}} -->
The `fd_io_istream_zstd_delete` function resets a `fd_io_istream_zstd_t` structure to zero and returns a pointer to it.
- **Inputs**:
    - `this`: A pointer to a `fd_io_istream_zstd_t` structure that is to be reset.
- **Control Flow**:
    - The function calls `fd_memset` to set the memory of the `fd_io_istream_zstd_t` structure pointed to by `this` to zero, effectively resetting it.
    - The function then returns the pointer `this` cast to a `void *`.
- **Output**: A `void *` pointer to the reset `fd_io_istream_zstd_t` structure.


---
### fd\_io\_istream\_zstd\_read<!-- {{#callable:fd_io_istream_zstd_read}} -->
The `fd_io_istream_zstd_read` function reads and decompresses data from a Zstandard compressed input stream into a destination buffer.
- **Inputs**:
    - `_this`: A pointer to the `fd_io_istream_zstd_t` structure representing the Zstandard input stream.
    - `dst`: A pointer to the destination buffer where decompressed data will be stored.
    - `dst_max`: The maximum number of bytes that can be written to the destination buffer.
    - `dst_sz`: A pointer to a variable where the function will store the number of bytes actually written to the destination buffer.
- **Control Flow**:
    - Check if the input stream needs to be refilled by verifying if it is not dirty and the current position equals the end position.
    - If a refill is needed, attempt to read data from the source into the input buffer and handle errors or end-of-file conditions appropriately.
    - Set the current and end pointers of the input buffer based on the amount of data read.
    - If no data was read, set the output size to zero and return success.
    - Initialize pointers for the output buffer and attempt to decompress data using `fd_zstd_dstream_read`.
    - If decompression fails, log a warning and return an error code.
    - Update the dirty flag based on whether the output buffer is full.
    - Calculate the number of bytes written to the destination buffer and store it in `dst_sz`.
    - Return success.
- **Output**: Returns 0 on success, -1 on unexpected EOF, or an error code if reading or decompression fails.
- **Functions called**:
    - [`fd_io_istream_obj_read`](fd_snapshot_istream.h.driver.md#fd_io_istream_obj_read)


---
### fd\_io\_istream\_file\_new<!-- {{#callable:fd_io_istream_file_new}} -->
The function `fd_io_istream_file_new` initializes a new `fd_io_istream_file_t` structure with a given file descriptor.
- **Inputs**:
    - `mem`: A pointer to memory where the `fd_io_istream_file_t` structure will be initialized.
    - `fd`: An integer representing the file descriptor to be associated with the new `fd_io_istream_file_t` structure.
- **Control Flow**:
    - The function casts the `mem` pointer to a `fd_io_istream_file_t` pointer named `this`.
    - It initializes the `fd` field of the `fd_io_istream_file_t` structure with the provided file descriptor `fd`.
    - The function returns the pointer `this`, which points to the newly initialized `fd_io_istream_file_t` structure.
- **Output**: A pointer to the newly initialized `fd_io_istream_file_t` structure.


---
### fd\_io\_istream\_file\_delete<!-- {{#callable:fd_io_istream_file_delete}} -->
The `fd_io_istream_file_delete` function resets the memory of a `fd_io_istream_file_t` object to zero and returns a pointer to it.
- **Inputs**:
    - `this`: A pointer to a `fd_io_istream_file_t` object that is to be deleted.
- **Control Flow**:
    - The function calls `fd_memset` to set the memory of the `this` object to zero, effectively clearing its contents.
    - The function then returns the pointer `this` cast to a `void *`.
- **Output**: A `void *` pointer to the zeroed `fd_io_istream_file_t` object.


---
### fd\_io\_istream\_file\_read<!-- {{#callable:fd_io_istream_file_read}} -->
The `fd_io_istream_file_read` function reads data from a file descriptor into a destination buffer.
- **Inputs**:
    - `_this`: A pointer to an `fd_io_istream_file_t` structure, which contains the file descriptor to read from.
    - `dst`: A pointer to the destination buffer where the read data will be stored.
    - `dst_max`: The maximum number of bytes to read into the destination buffer.
    - `dst_sz`: A pointer to a variable where the actual number of bytes read will be stored.
- **Control Flow**:
    - Cast the `_this` pointer to an `fd_io_istream_file_t` pointer to access the file descriptor.
    - Call the `fd_io_read` function with the file descriptor, destination buffer, minimum read size of 1 byte, maximum read size (`dst_max`), and a pointer to store the size of data read (`dst_sz`).
    - Return the result of the `fd_io_read` function call.
- **Output**: The function returns an integer status code from the `fd_io_read` function, indicating success or an error code.


---
### fd\_tar\_io\_reader\_new<!-- {{#callable:fd_tar_io_reader_new}} -->
The `fd_tar_io_reader_new` function initializes a new `fd_tar_io_reader_t` object with a given memory location, TAR reader, and input stream source.
- **Inputs**:
    - `mem`: A pointer to the memory location where the new `fd_tar_io_reader_t` object will be initialized.
    - `reader`: A pointer to an `fd_tar_reader_t` object that will be used to read TAR data.
    - `src`: An `fd_io_istream_obj_t` object representing the input stream source from which data will be read.
- **Control Flow**:
    - Check if the `reader` is NULL; if so, log a warning and return NULL.
    - Check if the `src.vt` (virtual table) is NULL; if so, log a warning and return NULL.
    - Cast the `mem` pointer to `fd_tar_io_reader_t *` and assign it to `this`.
    - Initialize the `reader` and `src` fields of `this` with the provided `reader` and `src` arguments.
    - Return the initialized `fd_tar_io_reader_t` object.
- **Output**: Returns a pointer to the newly initialized `fd_tar_io_reader_t` object, or NULL if the `reader` or `src.vt` is NULL.


---
### fd\_tar\_io\_reader\_delete<!-- {{#callable:fd_tar_io_reader_delete}} -->
The `fd_tar_io_reader_delete` function resets the memory of a `fd_tar_io_reader_t` object to zero and returns a pointer to it.
- **Inputs**:
    - `this`: A pointer to the `fd_tar_io_reader_t` object that is to be deleted.
- **Control Flow**:
    - The function uses `fd_memset` to set the memory of the `fd_tar_io_reader_t` object pointed to by `this` to zero, effectively clearing its contents.
    - The function then returns the pointer `this` cast to a `void *`.
- **Output**: A `void *` pointer to the `fd_tar_io_reader_t` object that was reset.


---
### fd\_tar\_io\_reader\_advance<!-- {{#callable:fd_tar_io_reader_advance}} -->
The `fd_tar_io_reader_advance` function reads data from a source stream into a buffer and processes it using a TAR reader, handling various error conditions and end-of-stream scenarios.
- **Inputs**:
    - `this`: A pointer to an `fd_tar_io_reader_t` structure, which contains the source stream and TAR reader to be used for reading and processing data.
- **Control Flow**:
    - Initialize a buffer of 16384 bytes and a buffer size variable to zero.
    - Attempt to read data from the source stream into the buffer using [`fd_io_istream_obj_read`](fd_snapshot_istream.h.driver.md#fd_io_istream_obj_read).
    - Check the result of the read operation: if successful, proceed; if EOF is encountered, return -1; if an error occurs, log a warning and return the error code.
    - Pass the read data to the TAR reader using `fd_tar_read` and check the result.
    - If `fd_tar_read` returns `MANIFEST_DONE`, log a notice and return the result.
    - If `fd_tar_read` returns a positive error code, log a warning and return the error code.
    - If `fd_tar_read` returns a negative value, log a notice indicating the end of the TAR stream and return -1.
    - If no errors occur, return 0 indicating successful advancement.
- **Output**: The function returns 0 on successful advancement, -1 on EOF or end of TAR stream, or a positive error code if an error occurs during reading or processing.
- **Functions called**:
    - [`fd_io_istream_obj_read`](fd_snapshot_istream.h.driver.md#fd_io_istream_obj_read)


