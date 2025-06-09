# Purpose
The provided C header file, `fd_tar.h`, defines a specialized implementation of the TAR file format, specifically supporting the ustar and old-GNU versions. This implementation is not a general-purpose TAR utility but is tailored for handling Solana snapshots, which suggests its use in a specific application context where TAR archives are used to store and retrieve snapshot data. The file includes definitions for handling TAR metadata, such as the `fd_tar_meta_t` structure, which represents the TAR header, and provides constants for known file types within a TAR archive. The header also defines several utility functions for manipulating TAR headers, such as setting and retrieving file sizes and modification times.

The file further defines two main components: a streaming TAR reader and a streaming TAR writer. The reader, encapsulated in the `fd_tar_reader_t` structure, uses a callback API to process TAR streams, allowing for efficient reading of TAR files by invoking user-defined callbacks for file headers and data chunks. The writer, represented by the `fd_tar_writer_t` structure, facilitates the creation of TAR archives by providing functions to write file headers, data, and finalize files within the archive. This design supports streaming operations, making it suitable for applications that need to process large TAR files incrementally. The header file is intended to be included in other C source files, providing a public API for TAR file manipulation within the context of Solana snapshot management.
# Imports and Dependencies

---
- `../io/fd_io.h`


# Global Variables

---
### fd\_tar\_reader\_t
- **Type**: `struct fd_tar_reader`
- **Description**: The `fd_tar_reader_t` is a data structure representing a streaming TAR reader that uses a callback API to deliver data. It is designed to process TAR streams by reading chunks of data and issuing callbacks when file headers or content are encountered. The structure includes fields for buffering file headers, tracking the number of bytes consumed, and managing callback parameters.
- **Use**: This variable is used to manage the state and operations of a streaming TAR reader, facilitating the reading and processing of TAR file streams in a structured manner.


---
### fd\_tar\_reader\_new
- **Type**: `fd_tar_reader_t *`
- **Description**: The `fd_tar_reader_new` function is a constructor for creating a new instance of a TAR reader, which is represented by the `fd_tar_reader_t` type. This function initializes the TAR reader with a specified memory region, a virtual table of callback functions, and a callback argument.
- **Use**: This function is used to allocate and initialize a new TAR reader object, which can then be used to process TAR streams using a callback-based API.


---
### fd\_tar\_reader\_delete
- **Type**: `function pointer`
- **Description**: `fd_tar_reader_delete` is a function that destroys a TAR reader and frees any allocated resources associated with it. It is designed to return the underlying memory region back to the caller, effectively cleaning up the resources used by the `fd_tar_reader_t` instance.
- **Use**: This function is used to properly dispose of a `fd_tar_reader_t` instance, ensuring that any resources it used are released and the memory is returned to the caller.


---
### fd\_tar\_writer\_new
- **Type**: `fd_tar_writer_t *`
- **Description**: The `fd_tar_writer_new` function is a constructor for creating a new TAR writer object, which is represented by the `fd_tar_writer_t` structure. This function initializes the TAR writer with a specified memory region and an open file descriptor, allowing the user to write or stream files into a TAR archive.
- **Use**: This variable is used to create and initialize a new TAR writer object for writing files into a TAR archive.


---
### fd\_tar\_writer\_delete
- **Type**: `function pointer`
- **Description**: `fd_tar_writer_delete` is a function that takes a pointer to an `fd_tar_writer_t` structure and returns a void pointer. It is responsible for destroying a TAR writer instance, freeing any allocated resources, writing out the TAR archive trailer, and closing the underlying file descriptor.
- **Use**: This function is used to clean up and finalize a TAR writer instance, ensuring that all resources are properly released and the TAR archive is correctly closed.


# Data Structures

---
### fd\_tar\_meta
- **Type**: `struct`
- **Members**:
    - `name`: A character array of size 100 to store the name of the file.
    - `mode`: A character array of size 8 to store the file mode.
    - `uid`: A character array of size 8 to store the user ID of the file owner.
    - `gid`: A character array of size 8 to store the group ID of the file owner.
    - `size`: A character array of size 12 to store the size of the file.
    - `mtime`: A character array of size 12 to store the last modification time of the file.
    - `chksum`: A character array of size 8 to store the checksum for the header.
    - `typeflag`: A character to store the type of file.
    - `linkname`: A character array of size 100 to store the name of the linked file.
    - `magic`: A character array of size 6 to store the magic value indicating the tar format.
    - `version`: A character array of size 2 to store the version of the tar format.
    - `uname`: A character array of size 32 to store the user name of the file owner.
    - `gname`: A character array of size 32 to store the group name of the file owner.
    - `devmajor`: A character array of size 8 to store the major device number.
    - `devminor`: A character array of size 8 to store the minor device number.
    - `prefix`: A character array of size 155 to store the prefix for file names longer than 100 characters.
    - `padding`: A character array of size 12 used for padding to align the structure.
- **Description**: The `fd_tar_meta` structure is a packed data structure representing the header of a file in a TAR archive, specifically supporting the ustar and old-GNU formats. It contains fields for storing metadata about a file, such as its name, size, owner information, and type, as well as special fields for handling linked files and device numbers. The structure is designed to fit within a 512-byte block, which is the standard block size for TAR archives, and includes padding to ensure proper alignment.


---
### fd\_tar\_meta\_t
- **Type**: `struct`
- **Members**:
    - `name`: A character array of size 100 to store the file name.
    - `mode`: A character array of size 8 to store the file mode.
    - `uid`: A character array of size 8 to store the user ID of the file owner.
    - `gid`: A character array of size 8 to store the group ID of the file owner.
    - `size`: A character array of size 12 to store the size of the file.
    - `mtime`: A character array of size 12 to store the last modification time of the file.
    - `chksum`: A character array of size 8 to store the checksum for the header.
    - `typeflag`: A character to store the type of file.
    - `linkname`: A character array of size 100 to store the name of the linked file.
    - `magic`: A character array of size 6 to store the magic value indicating the tar format.
    - `version`: A character array of size 2 to store the version of the tar format.
    - `uname`: A character array of size 32 to store the user name of the file owner.
    - `gname`: A character array of size 32 to store the group name of the file owner.
    - `devmajor`: A character array of size 8 to store the major device number.
    - `devminor`: A character array of size 8 to store the minor device number.
    - `prefix`: A character array of size 155 to store the prefix for file names longer than 100 characters.
    - `padding`: A character array of size 12 used for padding to align the structure to 512 bytes.
- **Description**: The `fd_tar_meta_t` structure represents the header of a file in a TAR archive, specifically adhering to the ustar and old-GNU formats. It contains metadata about the file, such as its name, size, type, and ownership information, all stored as character arrays. The structure is packed to ensure it fits within a 512-byte block, which is the standard block size for TAR headers. This structure is crucial for reading and writing TAR files, as it provides the necessary information to interpret the file data that follows the header in the archive.


---
### fd\_tar\_read\_vtable
- **Type**: `struct`
- **Members**:
    - `file`: A function pointer to a callback function that is called when a new file is encountered in the TAR stream.
    - `read`: A function pointer to a callback function that is called when a new chunk of data is read from the TAR stream.
- **Description**: The `fd_tar_read_vtable` structure is a virtual function table used by the `fd_tar_reader_t` to handle callbacks during the reading of a TAR archive. It contains function pointers for handling file and data read events, allowing the user to define custom behavior when a new file is encountered or when data is read from the TAR stream. This structure is essential for the streaming reader functionality, enabling the processing of TAR files in a flexible and extensible manner.


---
### fd\_tar\_read\_vtable\_t
- **Type**: `struct`
- **Members**:
    - `file`: A function pointer for handling new file encounters in the TAR stream.
    - `read`: A function pointer for handling data chunks read from the TAR stream.
- **Description**: The `fd_tar_read_vtable_t` is a virtual function table structure used in the context of a TAR file reader, specifically `fd_tar_reader_t`. It contains function pointers that define the behavior for processing new files and reading data chunks from a TAR archive. This allows for a flexible callback mechanism where different implementations can be provided for handling files and data as they are encountered in the TAR stream.


---
### fd\_tar\_reader
- **Type**: `struct`
- **Members**:
    - `buf`: A buffer to hold the file header, which may be split across multiple reads.
    - `header`: An alias for the buffer, representing the file header as a structured type.
    - `pos`: Tracks the number of bytes consumed from the current file.
    - `buf_ctr`: Indicates the write position within the file header buffer.
    - `file_sz`: Stores the number of bytes remaining in the current file.
    - `cb_vt`: Holds the virtual function table for callback functions.
    - `cb_arg`: A pointer to the callback context, typically used to pass user data.
- **Description**: The `fd_tar_reader` structure is designed for streaming TAR file reading, utilizing a callback API to process file headers and content. It maintains a buffer for the TAR file header, which may be split across multiple read operations, and tracks the position and size of the current file being processed. The structure also includes a virtual function table and a context pointer for handling callbacks, allowing for flexible integration with user-defined functions to process file data as it is read.


---
### fd\_tar\_writer
- **Type**: `struct`
- **Members**:
    - `fd`: The file descriptor for the tar archive.
    - `header_pos`: The position in the file for the current file's header, or ULONG_MAX if no file is being streamed.
    - `data_sz`: The size of the current file's data, or ULONG_MAX if no file is being streamed.
    - `wb_pos`: The position to write back to with fd_tar_writer_fill_space, or ULONG_MAX if not applicable.
- **Description**: The `fd_tar_writer` structure is used to manage the writing of files into a tar archive. It maintains the state of the current file being written, including its header position, data size, and a position for potential write-backs. This structure is part of a system designed to handle tar archives specifically for Solana snapshots, and it provides functionality to stream files into a tarball, manage file headers, and handle write-backs to specific positions in the archive.


---
### fd\_tar\_writer\_t
- **Type**: `struct`
- **Members**:
    - `fd`: The file descriptor for the tar archive.
    - `header_pos`: The position in the file for the current file's header, or ULONG_MAX if no file is being streamed.
    - `data_sz`: The size of the current file's data, or ULONG_MAX if no file is being streamed.
    - `wb_pos`: The position to write back to with a call to fd_tar_writer_fill_space, or ULONG_MAX if not applicable.
- **Description**: The `fd_tar_writer_t` structure is used to manage the process of writing files into a TAR archive. It maintains the state of the current file being written, including its header position, data size, and any reserved space for future writes. The structure is designed to facilitate streaming file data into a TAR archive, allowing for the creation of a continuous stream of files. It also supports writing back to specific positions in the stream, which is useful for updating file headers after data has been written. The `fd_tar_writer_t` is intended to persist for the duration of a single TAR archive creation process.


# Functions

---
### fd\_tar\_meta\_is\_reg<!-- {{#callable:fd_tar_meta_is_reg}} -->
The `fd_tar_meta_is_reg` function checks if a TAR file's type is 'regular' or 'null', returning 1 if true and 0 otherwise.
- **Inputs**:
    - `meta`: A pointer to a constant `fd_tar_meta_t` structure representing the TAR file metadata.
- **Control Flow**:
    - The function evaluates if the `typeflag` of the `meta` structure is equal to `FD_TAR_TYPE_NULL` or `FD_TAR_TYPE_REGULAR`.
    - It uses a bitwise OR operation to combine the results of these two comparisons.
    - The function returns the result of the bitwise OR operation, which will be 1 if either condition is true, otherwise 0.
- **Output**: An integer value, 1 if the file type is 'regular' or 'null', and 0 otherwise.


---
### fd\_tar\_meta\_set\_size<!-- {{#callable:fd_tar_meta_set_size}} -->
The `fd_tar_meta_set_size` function sets the size field in a TAR header using the OLDGNU size extension format.
- **Inputs**:
    - `meta`: A pointer to an `fd_tar_meta_t` structure representing the TAR header where the size will be set.
    - `sz`: An unsigned long integer representing the size to be set in the TAR header.
- **Control Flow**:
    - Set the first byte of the `size` field in the `meta` structure to 0x80, indicating the use of the OLDGNU size extension.
    - Store the size `sz` in the `size` field of the `meta` structure starting from the 5th byte, after converting it to big-endian format using `fd_ulong_bswap`.
    - Return 1 to indicate success.
- **Output**: The function returns an integer value of 1, indicating that the size was successfully set.


---
### fd\_tar\_meta\_set\_mtime<!-- {{#callable:fd_tar_meta_set_mtime}} -->
The `fd_tar_meta_set_mtime` function sets the modification time field in a TAR header structure to a specified value in octal format.
- **Inputs**:
    - `meta`: A pointer to an `fd_tar_meta_t` structure representing the TAR header where the modification time will be set.
    - `mtime`: An unsigned long integer representing the modification time to be set in the TAR header.
- **Control Flow**:
    - The function calls [`fd_tar_set_octal`](fd_tar_reader.c.driver.md#fd_tar_set_octal), passing the `mtime` field of the `meta` structure and the `mtime` value as arguments.
    - The [`fd_tar_set_octal`](fd_tar_reader.c.driver.md#fd_tar_set_octal) function is responsible for converting the `mtime` value to a 12-byte octal string and storing it in the `mtime` field of the `meta` structure.
- **Output**: The function returns an integer indicating success (1) or failure (0) of setting the modification time in the TAR header.
- **Functions called**:
    - [`fd_tar_set_octal`](fd_tar_reader.c.driver.md#fd_tar_set_octal)


---
### fd\_tar\_reader\_align<!-- {{#callable:fd_tar_reader_align}} -->
The `fd_tar_reader_align` function returns the alignment requirement for the `fd_tar_reader_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and suggests that it is a small, frequently used function.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_tar_reader_t` type.
    - The function returns the result of the `alignof` operator, which is the alignment requirement in bytes.
- **Output**: The function returns an `ulong` representing the alignment requirement for the `fd_tar_reader_t` structure.


---
### fd\_tar\_reader\_footprint<!-- {{#callable:fd_tar_reader_footprint}} -->
The `fd_tar_reader_footprint` function returns the size in bytes of the `fd_tar_reader_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests a preference for inlining by the compiler.
    - The function does not take any parameters.
    - It returns the result of the `sizeof` operator applied to the `fd_tar_reader_t` type, which gives the size of the structure in bytes.
- **Output**: The function returns an `ulong` representing the size of the `fd_tar_reader_t` structure in bytes.


---
### fd\_tar\_writer\_align<!-- {{#callable:fd_tar_writer_align}} -->
The `fd_tar_writer_align` function returns the alignment requirement of the `fd_tar_writer_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the result of the `alignof` operator applied to the `fd_tar_writer_t` type, which determines the alignment requirement for this type.
- **Output**: The function outputs an `ulong` value representing the alignment requirement of the `fd_tar_writer_t` structure.


---
### fd\_tar\_writer\_footprint<!-- {{#callable:fd_tar_writer_footprint}} -->
The `fd_tar_writer_footprint` function returns the size in bytes of the `fd_tar_writer_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests that the compiler should attempt to embed the function's code directly at the call site for performance reasons.
    - The function is marked with `FD_FN_CONST`, indicating that it does not read or write any global memory and its return value depends only on its parameters, which in this case are none.
    - The function simply returns the result of the `sizeof` operator applied to the `fd_tar_writer_t` type, which gives the size in bytes of the `fd_tar_writer_t` structure.
- **Output**: The function returns an `ulong` representing the size in bytes of the `fd_tar_writer_t` structure.


# Function Declarations (Public API)

---
### fd\_tar\_meta\_get\_size<!-- {{#callable_declaration:fd_tar_meta_get_size}} -->
Parses the size field of a TAR header.
- **Description**: Use this function to retrieve the size of a file from a TAR header represented by `fd_tar_meta_t`. It interprets the size field, which may be encoded in either octal or binary format, depending on the TAR version. This function is useful when processing TAR archives to determine the size of each file entry. It returns `ULONG_MAX` if the size cannot be parsed, indicating an error in the size field.
- **Inputs**:
    - `meta`: A pointer to a `fd_tar_meta_t` structure representing the TAR header. This pointer must not be null, and the structure should be properly initialized with valid TAR header data.
- **Output**: Returns the size of the file as an `ulong`. If parsing fails, it returns `ULONG_MAX`.
- **See also**: [`fd_tar_meta_get_size`](fd_tar_reader.c.driver.md#fd_tar_meta_get_size)  (Implementation)


---
### fd\_tar\_set\_octal<!-- {{#callable_declaration:fd_tar_set_octal}} -->
Converts an unsigned long integer to an 11-character octal string.
- **Description**: This function is used to convert an unsigned long integer into an octal string representation, storing the result in a provided buffer. The buffer must be at least 12 characters long to accommodate the 11-character octal string and a null terminator. This function is typically used when preparing data for TAR headers, which require numeric fields to be represented in octal format. The function returns a success indicator based on whether the entire value was successfully converted to octal.
- **Inputs**:
    - `buf`: A character array with a minimum size of 12. It is used to store the resulting octal string. The caller must ensure this buffer is valid and has sufficient space.
    - `val`: An unsigned long integer to be converted into an octal string. There are no restrictions on the value, but if it cannot be fully represented in 11 octal digits, the function will return 0.
- **Output**: Returns 1 if the entire value was successfully converted to octal and fits within 11 characters; otherwise, returns 0.
- **See also**: [`fd_tar_set_octal`](fd_tar_reader.c.driver.md#fd_tar_set_octal)  (Implementation)


---
### fd\_tar\_reader\_new<!-- {{#callable_declaration:fd_tar_reader_new}} -->
Creates a new TAR reader with specified memory and callbacks.
- **Description**: This function initializes a new TAR reader using a provided memory region and a set of callback functions. It is intended for processing TAR streams, particularly for Solana snapshots. The memory region must be properly aligned and of sufficient size to hold the reader structure. The callback virtual table must include valid file and read function pointers. If any of these preconditions are not met, the function will return NULL and log a warning. This function is typically called once to set up the reader before processing any TAR data.
- **Inputs**:
    - `mem`: A pointer to a memory region that will hold the fd_tar_reader_t structure. This memory must be aligned according to fd_tar_reader_align() and must not be NULL. The caller retains ownership of this memory.
    - `cb_vt`: A pointer to a fd_tar_read_vtable_t structure containing the callback function pointers for file and read operations. This pointer must not be NULL, and both the file and read function pointers within it must be valid.
    - `cb_arg`: A pointer to a user-defined context that will be passed to the callback functions. This can be NULL if no context is needed.
- **Output**: Returns a pointer to the initialized fd_tar_reader_t structure on success, or NULL on failure.
- **See also**: [`fd_tar_reader_new`](fd_tar_reader.c.driver.md#fd_tar_reader_new)  (Implementation)


---
### fd\_tar\_reader\_delete<!-- {{#callable_declaration:fd_tar_reader_delete}} -->
Destroys a TAR reader and returns the memory region to the caller.
- **Description**: Use this function to properly clean up and release resources associated with a TAR reader when it is no longer needed. It should be called to ensure that any memory allocated for the TAR reader is returned to the caller. This function must be called with a valid pointer to a TAR reader that was previously created using `fd_tar_reader_new`. If the provided pointer is NULL, the function will return NULL without performing any operations.
- **Inputs**:
    - `reader`: A pointer to an `fd_tar_reader_t` object that is to be destroyed. Must not be NULL unless the intention is to perform a no-op and return NULL.
- **Output**: Returns the underlying memory region back to the caller, or NULL if the input was NULL.
- **See also**: [`fd_tar_reader_delete`](fd_tar_reader.c.driver.md#fd_tar_reader_delete)  (Implementation)


---
### fd\_tar\_read<!-- {{#callable_declaration:fd_tar_read}} -->
Processes a chunk of a TAR stream and issues callbacks for file headers or content.
- **Description**: This function processes a given chunk of a TAR stream using a streaming reader and issues callbacks when file headers or content are encountered. It should be called with a valid TAR reader and data chunk, ensuring that the data is supplied in order and without gaps. The function returns 0 on success, -1 on end-of-file, or a positive error code on failure. If the specified track_err is encountered during processing, it will be returned after the entire data buffer is processed, unless another error occurs. Passing 0 for track_err disables this functionality.
- **Inputs**:
    - `reader`: A pointer to an fd_tar_reader_t object. Must be a valid, initialized TAR reader.
    - `data`: A pointer to the first byte of the data chunk to be processed. Must not be null.
    - `data_sz`: The size of the data chunk in bytes. A value of 0 results in a no-op.
    - `track_err`: An integer error code to track. If this error is encountered, it will be returned after processing the entire data buffer, unless another error occurs. Pass 0 to disable this feature.
- **Output**: Returns 0 on success, -1 on end-of-file, or a positive errno-compatible error code on failure. If track_err is encountered, it is returned after processing the data buffer.
- **See also**: [`fd_tar_read`](fd_tar_reader.c.driver.md#fd_tar_read)  (Implementation)


---
### fd\_tar\_writer\_new<!-- {{#callable_declaration:fd_tar_writer_new}} -->
Create a new TAR writer using the provided memory and file descriptor.
- **Description**: This function initializes a TAR writer object in the provided memory region, which must be properly aligned and of sufficient size. It requires a valid, open file descriptor to write the TAR archive to. The function will truncate the file associated with the file descriptor to zero length, effectively clearing any existing content. It returns a handle to the TAR writer on success, or NULL if the memory is null, improperly aligned, or if the file descriptor is invalid. This function should be called before any other operations on the TAR writer.
- **Inputs**:
    - `mem`: A pointer to a memory region where the TAR writer will be initialized. This memory must be aligned according to fd_tar_writer_align() and must not be null. The caller retains ownership of this memory.
    - `fd`: An integer representing a valid, open file descriptor where the TAR archive will be written. It must be greater than zero. If the file descriptor is invalid, the function will return NULL.
- **Output**: Returns a pointer to the initialized fd_tar_writer_t on success, or NULL on failure due to invalid input or errors during file truncation.
- **See also**: [`fd_tar_writer_new`](fd_tar_writer.c.driver.md#fd_tar_writer_new)  (Implementation)


---
### fd\_tar\_writer\_delete<!-- {{#callable_declaration:fd_tar_writer_delete}} -->
Finalizes and deletes a TAR writer, writing the archive trailer.
- **Description**: Use this function to properly close a TAR writer after all files have been added to the archive. It writes the necessary EOF blocks to mark the end of the TAR archive and returns the memory region back to the caller. This function should be called only after all file data has been written and finalized using the appropriate writer functions. It also handles the cleanup of resources associated with the writer, including closing the file descriptor.
- **Inputs**:
    - `writer`: A pointer to an fd_tar_writer_t structure representing the TAR writer to be deleted. Must not be null. The writer should have been previously initialized and used to write files to the TAR archive.
- **Output**: Returns a pointer to the underlying memory region of the writer, or NULL if an error occurred during the finalization process.
- **See also**: [`fd_tar_writer_delete`](fd_tar_writer.c.driver.md#fd_tar_writer_delete)  (Implementation)


---
### fd\_tar\_writer\_new\_file<!-- {{#callable_declaration:fd_tar_writer_new_file}} -->
Writes a new file header to the TAR archive.
- **Description**: This function is used to start writing a new file into a TAR archive by writing its header. It should be called after initializing the TAR writer with `fd_tar_writer_new` and before writing any file data with `fd_tar_writer_write_file_data`. The function prepares the TAR archive to receive a new file by writing a header with basic metadata, such as the file name, and setting up internal state for subsequent data writing. It is important to ensure that the file name is valid and that the writer is properly aligned before calling this function. If the function fails, it returns an error code and logs a warning.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure representing the TAR writer. It must be initialized and valid. The caller retains ownership.
    - `file_name`: A constant character pointer to the name of the file to be added to the TAR archive. The file name must be a valid, null-terminated string. The caller retains ownership.
- **Output**: Returns 0 on success. On failure, returns -1 and logs a warning.
- **See also**: [`fd_tar_writer_new_file`](fd_tar_writer.c.driver.md#fd_tar_writer_new_file)  (Implementation)


---
### fd\_tar\_writer\_write\_file\_data<!-- {{#callable_declaration:fd_tar_writer_write_file_data}} -->
Writes file data to a TAR archive.
- **Description**: Use this function to write a block of data to the current file in a TAR archive being created by the writer. It must be called after initializing a new file with `fd_tar_writer_new_file` and before finalizing the file with `fd_tar_writer_fini_file`. The function will log a warning and return an error if there is no corresponding TAR header for the data being written. Ensure that the writer is properly initialized and that the data size is correctly specified to avoid partial writes.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure representing the TAR writer. Must not be null and should be properly initialized with a valid file descriptor.
    - `data`: A pointer to the data buffer containing the file data to be written. The caller retains ownership and must ensure the buffer is valid and non-null.
    - `data_sz`: The size in bytes of the data to be written. Must be a non-zero value and should not exceed the available space in the TAR archive.
- **Output**: Returns 0 on success. Returns -1 and logs a warning if there is no corresponding TAR header or if writing the data fails.
- **See also**: [`fd_tar_writer_write_file_data`](fd_tar_writer.c.driver.md#fd_tar_writer_write_file_data)  (Implementation)


---
### fd\_tar\_writer\_fini\_file<!-- {{#callable_declaration:fd_tar_writer_fini_file}} -->
Finalize the current file in the TAR writer by padding and updating the header.
- **Description**: This function should be called to finalize the current file being written to a TAR archive using the TAR writer. It ensures that the file data is padded to meet the TAR block size alignment requirements and updates the file header with the correct file size and checksum. This function must be called after writing all file data using `fd_tar_writer_write_file_data` and before starting a new file with `fd_tar_writer_new_file`. It handles any necessary padding and updates the TAR header to reflect the actual size and checksum of the file. If any errors occur during these operations, the function returns an error code.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure representing the TAR writer. This must be a valid, initialized writer object, and must not be null. The function will return an error if the writer is not properly set up or if any I/O operations fail.
- **Output**: Returns 0 on success, indicating the file was finalized correctly. Returns -1 on failure, indicating an error occurred during padding or header update operations.
- **See also**: [`fd_tar_writer_fini_file`](fd_tar_writer.c.driver.md#fd_tar_writer_fini_file)  (Implementation)


---
### fd\_tar\_writer\_make\_space<!-- {{#callable_declaration:fd_tar_writer_make_space}} -->
Reserves space in a TAR archive for future data writing.
- **Description**: This function is used to extend the size of a TAR archive by reserving a specified amount of space, allowing for future data to be written back at a later time. It should be called when there is no outstanding write-back position, indicated by the writer's `wb_pos` being `ULONG_MAX`. This function is typically used in conjunction with `fd_tar_writer_fill_space` to manage space allocation and data writing in a TAR archive. It is important to ensure that the writer is in a valid state and that the file descriptor is open and valid before calling this function.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure representing the TAR writer. Must not be null and must be properly initialized.
    - `data_sz`: The size of the space to reserve in the TAR archive, specified in bytes. Must be a positive value.
- **Output**: Returns 0 on success, or -1 if an error occurs, such as an outstanding write-back position or failure to extend the file size.
- **See also**: [`fd_tar_writer_make_space`](fd_tar_writer.c.driver.md#fd_tar_writer_make_space)  (Implementation)


---
### fd\_tar\_writer\_fill\_space<!-- {{#callable_declaration:fd_tar_writer_fill_space}} -->
Writes data to a reserved space in a TAR archive.
- **Description**: This function is used to write data into a previously reserved space within a TAR archive managed by a `fd_tar_writer_t` instance. It should be called after `fd_tar_writer_make_space` has been used to reserve space. The function will attempt to write the specified data to the reserved position in the archive. If the write operation fails or if the reserved position is invalid, the function will return an error. This function is essential for modifying existing entries in a TAR archive without altering the rest of the archive structure.
- **Inputs**:
    - `writer`: A pointer to a `fd_tar_writer_t` structure representing the TAR writer. This must be a valid, initialized writer instance with a reserved space for writing. The writer must not be null.
    - `data`: A pointer to the data to be written into the reserved space. The data must not be null and should point to a valid memory region containing at least `data_sz` bytes.
    - `data_sz`: The size in bytes of the data to be written. It must match the size of the reserved space. If the size does not match, the function will return an error.
- **Output**: Returns 0 on success. Returns -1 on failure, such as when the reserved position is invalid or the write operation fails.
- **See also**: [`fd_tar_writer_fill_space`](fd_tar_writer.c.driver.md#fd_tar_writer_fill_space)  (Implementation)


