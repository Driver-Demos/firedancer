# Purpose
This C source code file provides functionality for creating and managing tar archives, specifically focusing on writing files into a tarball. The code defines a set of functions that handle the creation of a new tar writer, adding new files to the archive, writing file data, finalizing files, and managing space within the tar archive. The primary technical components include functions for initializing a tar writer ([`fd_tar_writer_new`](#fd_tar_writer_new)), adding new files ([`fd_tar_writer_new_file`](#fd_tar_writer_new_file)), writing file data ([`fd_tar_writer_write_file_data`](#fd_tar_writer_write_file_data)), and finalizing the file entries ([`fd_tar_writer_fini_file`](#fd_tar_writer_fini_file)). The code also includes utility functions for managing space within the tar file ([`fd_tar_writer_make_space`](#fd_tar_writer_make_space) and [`fd_tar_writer_fill_space`](#fd_tar_writer_fill_space)). These functions ensure that the tar archive adheres to the tar format specifications, such as aligning data to 512-byte blocks and calculating checksums for file headers.

The file is intended to be part of a larger library or application, as indicated by the inclusion of custom headers like "fd_tar.h" and "../fd_util.h". It does not define a main function, suggesting that it is not an executable but rather a component to be integrated into a larger system. The code is structured to handle errors robustly, with extensive use of logging to report issues. The functions defined in this file are likely part of a public API for managing tar archives, providing a programmatic interface for creating and manipulating tar files. The code is designed to be extendable, with comments indicating potential areas for future enhancements, such as making file permissions configurable and optimizing space allocation.
# Imports and Dependencies

---
- `fd_tar.h`
- `../fd_util.h`
- `errno.h`
- `fcntl.h`
- `unistd.h`
- `stdio.h`


# Global Variables

---
### null\_tar\_block
- **Type**: `char array`
- **Description**: The `null_tar_block` is a static character array initialized with zeros, with a size defined by `FD_TAR_BLOCK_SZ`. It serves as a block of zeroed bytes, typically used to pad or mark the end of a tar archive.
- **Use**: This variable is used to write zero-filled blocks to a file descriptor, ensuring proper tar archive formatting and alignment.


# Functions

---
### fd\_tar\_writer\_new<!-- {{#callable:fd_tar_writer_new}} -->
The `fd_tar_writer_new` function initializes a new TAR writer object using provided memory and a file descriptor, ensuring proper alignment and truncating the file if it already exists.
- **Inputs**:
    - `mem`: A pointer to the memory location where the TAR writer object will be initialized.
    - `fd`: An integer representing the file descriptor for the TAR file to be written.
- **Control Flow**:
    - Check if the provided memory pointer is NULL and log a warning if so, returning NULL.
    - Verify if the memory is properly aligned using `fd_tar_writer_align()` and log a warning if not, returning NULL.
    - Cast the memory pointer to a `fd_tar_writer_t` pointer for further operations.
    - Check if the file descriptor is valid (greater than 0) and log a warning if not, returning NULL.
    - Attempt to truncate the file associated with the file descriptor to zero length and log a warning if it fails, returning NULL.
    - Initialize the `fd_tar_writer_t` structure fields `fd`, `header_pos`, `data_sz`, and `wb_pos` to the file descriptor and `ULONG_MAX` respectively.
    - Return the initialized `fd_tar_writer_t` pointer.
- **Output**: A pointer to the initialized `fd_tar_writer_t` structure, or NULL if an error occurs during initialization.
- **Functions called**:
    - [`fd_tar_writer_align`](fd_tar.h.driver.md#fd_tar_writer_align)


---
### fd\_tar\_writer\_delete<!-- {{#callable:fd_tar_writer_delete}} -->
The `fd_tar_writer_delete` function finalizes a tar archive by writing two 512-byte blocks of zeros to mark the end of the archive and returns the writer object.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure representing the tar writer object.
- **Control Flow**:
    - Initialize `out_sz` to 0 and attempt to write a 512-byte block of zeros to the file descriptor in `writer` using `fd_io_write`.
    - Check if the write operation failed using `FD_UNLIKELY`; if it did, log a warning and return `NULL`.
    - Repeat the write operation for a second 512-byte block of zeros.
    - Check again for failure of the second write operation; if it failed, log a warning and return `NULL`.
    - If both writes succeed, return the `writer` object cast to a `void*`.
- **Output**: Returns a `void*` pointing to the `writer` object if successful, or `NULL` if an error occurs during the write operations.


---
### fd\_tar\_writer\_new\_file<!-- {{#callable:fd_tar_writer_new_file}} -->
The `fd_tar_writer_new_file` function initializes a new file entry in a tar archive by writing a header with basic metadata to the file descriptor associated with the tar writer.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure, which manages the state of the tar writing process.
    - `file_name`: A constant character pointer representing the name of the file to be added to the tar archive.
- **Control Flow**:
    - The function begins by obtaining the current file position using `lseek` and checks for errors.
    - It verifies that the current position is aligned to the tar block size, logging a warning and returning -1 if not.
    - A `fd_tar_meta_t` structure is initialized to zero, and the file name is copied into its `name` field.
    - The file mode is set to a default value of 0644, and the tar magic version is copied into the `magic` field.
    - A default checksum value is set in the `chksum` field, as required by the tar format.
    - The header is written to the file using `fd_io_write`, and the function checks for errors and correct write size.
    - If successful, the function resets the `data_sz` field of the writer to prepare for writing the file's data.
- **Output**: Returns 0 on success, or -1 if any error occurs during the process, such as file position errors, alignment issues, or write failures.


---
### fd\_tar\_writer\_write\_file\_data<!-- {{#callable:fd_tar_writer_write_file_data}} -->
The `fd_tar_writer_write_file_data` function writes a specified amount of data to a file descriptor associated with a tar writer and updates the data size field.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure, which contains information about the tar file being written.
    - `data`: A pointer to the data to be written to the tar file.
    - `data_sz`: The size of the data to be written, in bytes.
- **Control Flow**:
    - Check if the `header_pos` in the writer is set to `ULONG_MAX`, indicating no corresponding tar header, and log a warning if true, returning -1.
    - Attempt to write the data to the file descriptor using `fd_io_write`, capturing the output size in `out_sz`.
    - If the write operation fails, log a warning with the error details and return -1.
    - Check if the actual written size `out_sz` does not match the expected `data_sz`, log a warning, and return -1 if they differ.
    - Update the `data_sz` field in the writer by adding the size of the data written.
    - Return 0 to indicate success.
- **Output**: Returns 0 on successful data write, or -1 if an error occurs during the write operation or if there is no corresponding tar header.


---
### fd\_tar\_writer\_fini\_file<!-- {{#callable:fd_tar_writer_fini_file}} -->
The `fd_tar_writer_fini_file` function finalizes the writing of a file to a tar archive by padding it to the required alignment, updating the header with the file size and checksum, and resetting the writer state.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure representing the tar writer context, which includes file descriptor and metadata for the current file being written.
- **Control Flow**:
    - Calculate the padding needed to align the file size to the tar block size (512 bytes) and write this padding to the file.
    - Check for errors during the padding write operation and log warnings if any occur.
    - Seek to the header position of the file in the tar archive and read the existing header data into a `fd_tar_meta_t` structure.
    - Verify the read operation and log warnings if it fails.
    - Seek back to the header position to prepare for updating the header.
    - Update the file size in the header using [`fd_tar_meta_set_size`](fd_tar.h.driver.md#fd_tar_meta_set_size).
    - Calculate the checksum for the header and update the checksum field in the header structure.
    - Write the updated header back to the file and check for errors, logging warnings if necessary.
    - Seek to the end of the file to prepare for writing the next file.
    - Reset the `header_pos` and `data_sz` fields in the writer structure to indicate no outstanding writes.
- **Output**: Returns 0 on success, or -1 if any error occurs during the process, with warnings logged for specific failures.
- **Functions called**:
    - [`fd_tar_meta_set_size`](fd_tar.h.driver.md#fd_tar_meta_set_size)


---
### fd\_tar\_writer\_make\_space<!-- {{#callable:fd_tar_writer_make_space}} -->
The `fd_tar_writer_make_space` function extends the size of a tarball file to accommodate additional data by updating the file size and setting the write-back position.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure representing the tar writer context.
    - `data_sz`: The size of the data (in bytes) for which space needs to be made in the tarball.
- **Control Flow**:
    - Check if there is an outstanding write-back position in the writer; if so, log a warning and return -1.
    - Use `lseek` to find the current end of the file and store it in `file_sz`; if it fails, log a warning and return -1.
    - Call `ftruncate` to extend the file size by `data_sz`; if it fails, log a warning and return -1.
    - Use `lseek` again to verify the new end of the file matches the expected size; if not, log a warning and return -1.
    - Update the writer's `data_sz` to `data_sz` and `wb_pos` to the original file size.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or -1 if an error occurs during the process.


---
### fd\_tar\_writer\_fill\_space<!-- {{#callable:fd_tar_writer_fill_space}} -->
The `fd_tar_writer_fill_space` function writes data to a specified position in a file, ensuring the file pointer is correctly managed before and after the operation.
- **Inputs**:
    - `writer`: A pointer to an `fd_tar_writer_t` structure, which contains information about the file descriptor and write-back position.
    - `data`: A constant pointer to the data to be written into the file.
    - `data_sz`: The size of the data to be written, in bytes.
- **Control Flow**:
    - Check if there is an outstanding write-back position in the writer; if not, log a warning and return -1.
    - Seek to the end of the file to get the current end-of-file position; if this fails, log a warning and return -1.
    - Seek to the write-back position specified in the writer; if this fails, log a warning and return -1.
    - Attempt to write the specified data to the file at the write-back position; if this fails or the written size does not match the data size, log a warning and return -1.
    - Reset the write-back position in the writer to `ULONG_MAX` to indicate no outstanding write-back position.
    - Seek to the end of the file again to ensure the file pointer is correctly positioned; if this fails, log a warning and return -1.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or -1 on failure, with warnings logged for any errors encountered.


