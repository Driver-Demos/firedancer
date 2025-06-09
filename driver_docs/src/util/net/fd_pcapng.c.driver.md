# Purpose
This C source code file is designed to handle the reading and writing of PCAP Next Generation (pcapng) files, which are used for storing network packet data. The file provides a set of functions to manage pcapng file operations, including setting default options for section header blocks (SHB) and interface description blocks (IDB), parsing pcapng blocks, and writing various types of blocks to a file. The code includes functions to initialize and manage iterators for reading pcapng files, allowing for the sequential processing of blocks within a file. It also includes error handling and logging to ensure robust file operations.

The file is structured to support both reading and writing operations, with functions like [`fd_pcapng_iter_new`](#fd_pcapng_iter_new) and [`fd_pcapng_iter_next`](#fd_pcapng_iter_next) for reading, and [`fd_pcapng_fwrite_shb`](#fd_pcapng_fwrite_shb), [`fd_pcapng_fwrite_idb`](#fd_pcapng_fwrite_idb), and [`fd_pcapng_fwrite_pkt`](#fd_pcapng_fwrite_pkt) for writing. The code is modular, with clear separation between different block types and their respective operations. It also includes platform-specific code to handle different operating systems, such as Linux and FreeBSD. The file is intended to be part of a larger library, as indicated by the inclusion of private headers and utility functions, and it provides a public API for interacting with pcapng files, making it a crucial component for applications that need to process network capture data.
# Imports and Dependencies

---
- `fd_pcapng_private.h`
- `../fd_util.h`
- `errno.h`
- `net/if.h`
- `stdio.h`


# Functions

---
### fd\_pcapng\_shb\_defaults<!-- {{#callable:fd_pcapng_shb_defaults}} -->
The `fd_pcapng_shb_defaults` function initializes default values for the hardware, operating system, and user application fields in a `fd_pcapng_shb_opts_t` structure.
- **Inputs**:
    - `opt`: A pointer to a `fd_pcapng_shb_opts_t` structure where default values for hardware, operating system, and user application will be set.
- **Control Flow**:
    - Check if the macro `FD_HAS_X86` is defined; if so, set `opt->hardware` to "x86_64".
    - Check if the macro `__linux__` is defined; if so, set `opt->os` to "Linux".
    - Set `opt->userappl` to "Firedancer".
- **Output**: The function does not return a value; it modifies the `fd_pcapng_shb_opts_t` structure pointed to by `opt`.


---
### fd\_pcapng\_idb\_defaults<!-- {{#callable:fd_pcapng_idb_defaults}} -->
The `fd_pcapng_idb_defaults` function initializes default values for a pcapng interface description block (IDB) options structure, including setting the interface name and timestamp resolution.
- **Inputs**:
    - `opt`: A pointer to an `fd_pcapng_idb_opts_t` structure where default options for the interface description block will be set.
    - `if_idx`: An unsigned integer representing the index of the network interface for which the defaults are being set.
- **Control Flow**:
    - Check if the code is being compiled on Linux or FreeBSD systems.
    - Declare a static thread-local character array `_name` to store the interface name.
    - Use `if_indextoname` to get the interface name corresponding to `if_idx` and store it in `_name`.
    - If `if_indextoname` fails, return 0 indicating failure.
    - Copy the interface name from `_name` to `opt->name`, ensuring it does not exceed 16 characters.
    - Set the timestamp resolution `opt->tsresol` to `FD_PCAPNG_TSRESOL_NS`.
    - Return 1 to indicate success.
- **Output**: Returns an integer: 1 on success, indicating that the defaults were set, or 0 on failure, indicating that the interface name could not be retrieved.


---
### fd\_pcapng\_iter\_align<!-- {{#callable:fd_pcapng_iter_align}} -->
The `fd_pcapng_iter_align` function returns the alignment requirement of the `fd_pcapng_iter_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the result of the `alignof` operator applied to `fd_pcapng_iter_t`.
- **Output**: The function outputs an `ulong` representing the alignment requirement of the `fd_pcapng_iter_t` type.


---
### fd\_pcapng\_iter\_footprint<!-- {{#callable:fd_pcapng_iter_footprint}} -->
The function `fd_pcapng_iter_footprint` returns the size of the `fd_pcapng_iter_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a constant function, meaning it does not modify any global or static state.
    - It directly returns the result of the `sizeof` operator applied to the `fd_pcapng_iter_t` type.
- **Output**: The function returns an `ulong` representing the size in bytes of the `fd_pcapng_iter_t` structure.


---
### fd\_pcapng\_iter\_strerror<!-- {{#callable:fd_pcapng_iter_strerror}} -->
The `fd_pcapng_iter_strerror` function generates a human-readable error message based on the provided error code and file stream position.
- **Inputs**:
    - `error`: An integer representing the error code encountered during pcapng file processing.
    - `file`: A pointer to a FILE object representing the file stream being processed.
- **Control Flow**:
    - Initialize a static buffer `err_cstr_buf` for error message storage.
    - Initialize a character pointer `err_cstr` using `fd_cstr_init` to point to the start of `err_cstr_buf`.
    - Check if the error code is `EPROTO`; if true, format a parse error message with the current file position using `fd_cstr_printf` and return it.
    - Check if the error code is `-1` and the file is not at EOF; if true, return the string "end of section".
    - For other error codes, format a message with the error code and its string representation using `fd_cstr_printf` and return it.
- **Output**: A constant character pointer to a formatted error message string.


---
### fd\_pcapng\_peek\_block<!-- {{#callable:fd_pcapng_peek_block}} -->
The `fd_pcapng_peek_block` function reads and validates a block header and footer from a pcapng file stream, ensuring they match and are correctly aligned.
- **Inputs**:
    - `stream`: A pointer to a FILE object representing the pcapng file stream to read from.
    - `_hdr`: A pointer to an fd_pcapng_block_hdr_t structure where the block header information will be stored.
    - `end_ptr`: A pointer to a long where the end position of the block will be stored, or NULL if not needed.
- **Control Flow**:
    - Retrieve the current position in the file stream using ftell and check for errors or misalignment.
    - Read the block header from the stream into a local fd_pcapng_block_hdr_t structure and check for end-of-file or read errors.
    - Validate the block size in the header to ensure it is within acceptable limits and aligned.
    - Seek to the block footer position in the stream and read the footer size.
    - Restore the file stream position to the original block start position.
    - Compare the block size in the header and footer to ensure they match.
    - Store the header in the provided _hdr pointer and calculate the end position if end_ptr is not NULL.
- **Output**: Returns 0 on success, -1 if end-of-file is reached, or an error code if an error occurs during reading or validation.


---
### fd\_pcapng\_read\_option<!-- {{#callable:fd_pcapng_read_option}} -->
The `fd_pcapng_read_option` function reads a pcapng option from a file stream and stores it in a provided option structure, handling alignment and potential errors.
- **Inputs**:
    - `stream`: A pointer to a FILE object representing the input stream from which the pcapng option is read.
    - `opt`: A pointer to an fd_pcapng_option_t structure where the read option data will be stored.
- **Control Flow**:
    - Define a packed structure `opt_hdr` to hold the option type and size.
    - Attempt to read 4 bytes from the stream into `opt_hdr`; if unsuccessful, return the stream error.
    - Calculate `end_off` as the aligned size of the option data and `read_sz` as the minimum of `end_off` and the size available in `opt->sz`.
    - If `read_sz` is non-zero, attempt to read `read_sz` bytes into `opt->value`; if unsuccessful, return the stream error.
    - Subtract `read_sz` from `end_off` to determine remaining bytes to skip.
    - Attempt to seek forward by `end_off` bytes in the stream; if unsuccessful, return the error code.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or an error code if reading or seeking in the stream fails.


---
### fd\_pcapng\_iter\_new<!-- {{#callable:fd_pcapng_iter_new}} -->
The `fd_pcapng_iter_new` function initializes a new PCAPNG iterator for reading a PCAPNG file from a given memory location and file stream.
- **Inputs**:
    - `mem`: A pointer to a memory location where the iterator will be initialized; it must be aligned to the alignment requirements of `fd_pcapng_iter_t`.
    - `_file`: A pointer to a file stream (of type `FILE *`) from which the PCAPNG data will be read.
- **Control Flow**:
    - Check if `mem` is NULL; if so, log a warning and return NULL.
    - Check if `mem` is properly aligned; if not, log a warning and return NULL.
    - Check if `_file` is NULL; if so, log a warning and return NULL.
    - Cast `_file` to a `FILE *` and assign it to `file`.
    - Initialize the memory pointed to by `mem` to zero and cast it to `fd_pcapng_iter_t *`, assigning it to `iter`.
    - Set the `stream` member of `iter` to `file`.
    - Peek at the first block in the file to ensure it is a valid Section Header Block (SHB); if not, log a warning and return NULL.
    - Read the SHB from the file and check its version; if the version is not supported, log a warning and return NULL.
    - Return the initialized iterator `iter`.
- **Output**: Returns a pointer to an initialized `fd_pcapng_iter_t` structure if successful, or NULL if any error occurs during initialization.
- **Functions called**:
    - [`fd_pcapng_peek_block`](#fd_pcapng_peek_block)
    - [`fd_pcapng_iter_strerror`](#fd_pcapng_iter_strerror)


---
### fd\_pcapng\_iter\_delete<!-- {{#callable:fd_pcapng_iter_delete}} -->
The `fd_pcapng_iter_delete` function clears and returns the memory associated with a `fd_pcapng_iter_t` iterator.
- **Inputs**:
    - `iter`: A pointer to a `fd_pcapng_iter_t` structure that represents the iterator to be deleted.
- **Control Flow**:
    - The function casts the `iter` pointer to a `void*` and assigns it to a local variable `mem`.
    - It uses `memset` to set all bytes of the memory pointed to by `mem` to zero, effectively clearing the `fd_pcapng_iter_t` structure.
    - The function returns the `mem` pointer, which is the same as the input `iter` pointer.
- **Output**: A `void*` pointer to the cleared memory, which is the same as the input `iter` pointer.


---
### fd\_pcapng\_iter\_next<!-- {{#callable:fd_pcapng_iter_next}} -->
The `fd_pcapng_iter_next` function iterates through a PCAPNG file stream to find and return the next frame of a known type, handling various block types and errors.
- **Inputs**:
    - `iter`: A pointer to an `fd_pcapng_iter_t` structure, which contains the state of the iteration, including the file stream and error status.
- **Control Flow**:
    - Initialize a static `fd_pcapng_frame_t` structure `pkt` and clear its fields.
    - Retrieve the file stream from the `iter` structure.
    - Attempt up to 256 times to find a frame of a known type by peeking at the next block in the stream.
    - If an error occurs during block peeking, log a warning and return `NULL`.
    - Switch on the block type to handle different PCAPNG block types:
    - For `FD_PCAPNG_BLOCK_TYPE_SHB`, set error to -1 (EOF) and return `NULL`.
    - For `FD_PCAPNG_BLOCK_TYPE_IDB`, read the IDB block, add the interface to the list, read options, and seek to the end of the block.
    - For `FD_PCAPNG_BLOCK_TYPE_SPB`, read the SPB block, set packet fields, and return the packet.
    - For `FD_PCAPNG_BLOCK_TYPE_EPB`, read the EPB block, read options, set packet fields, and return the packet.
    - For `FD_PCAPNG_BLOCK_TYPE_DSB`, read the DSB block, read options, set packet fields, and return the packet.
    - For unknown block types, skip the block and continue to the next attempt.
    - If no interesting blocks are found after 256 attempts, set error to EPROTO, log a warning, and return `NULL`.
- **Output**: Returns a pointer to an `fd_pcapng_frame_t` structure containing the next frame of a known type, or `NULL` if no such frame is found or an error occurs.
- **Functions called**:
    - [`fd_pcapng_peek_block`](#fd_pcapng_peek_block)
    - [`fd_pcapng_iter_strerror`](#fd_pcapng_iter_strerror)
    - [`fd_pcapng_read_option`](#fd_pcapng_read_option)


---
### fd\_pcapng\_iter\_err<!-- {{#callable:fd_pcapng_iter_err}} -->
The `fd_pcapng_iter_err` function retrieves the error code from a given `fd_pcapng_iter_t` iterator structure.
- **Inputs**:
    - `iter`: A pointer to a constant `fd_pcapng_iter_t` structure from which the error code is to be retrieved.
- **Control Flow**:
    - The function accesses the `error` member of the `fd_pcapng_iter_t` structure pointed to by `iter`.
- **Output**: Returns the integer value of the `error` member from the `fd_pcapng_iter_t` structure.


---
### fd\_pcapng\_fwrite\_shb<!-- {{#callable:fd_pcapng_fwrite_shb}} -->
The function `fd_pcapng_fwrite_shb` writes a Section Header Block (SHB) to a file in the PCAPNG format, optionally including hardware, OS, and user application options.
- **Inputs**:
    - `opt`: A pointer to a `fd_pcapng_shb_opts_t` structure containing optional metadata such as hardware, OS, and user application information to be included in the SHB.
    - `file`: A pointer to a file stream where the SHB will be written.
- **Control Flow**:
    - Initialize a buffer `buf` of size `FD_PCAPNG_BLOCK_SZ` to hold the SHB data.
    - Cast the buffer to a `fd_pcapng_shb_t` pointer `block` and set its fields with default values, including block type, byte order magic, version, and section size.
    - Set the cursor to the size of `fd_pcapng_shb_t` to track the current position in the buffer.
    - If `opt` is provided, write optional fields for hardware, OS, and user application using the `FD_PCAPNG_FWRITE_OPT` macro, which handles alignment and size checks.
    - Write a null option to terminate the options list using `FD_PCAPNG_FWRITE_NULLOPT`.
    - Finalize the block by setting its size and writing a terminating block size using `FD_PCAPNG_FWRITE_BLOCK_TERM`.
    - Write the buffer to the file using `fwrite`, returning the result of this operation.
- **Output**: The function returns the result of the `fwrite` operation, which is the number of elements successfully written to the file (should be 1 if successful).


---
### fd\_pcapng\_fwrite\_idb<!-- {{#callable:fd_pcapng_fwrite_idb}} -->
The `fd_pcapng_fwrite_idb` function writes an Interface Description Block (IDB) to a file in the PCAPNG format, including optional metadata if provided.
- **Inputs**:
    - `link_type`: An unsigned integer representing the link type for the interface.
    - `opt`: A pointer to a `fd_pcapng_idb_opts_t` structure containing optional metadata for the IDB, such as name, IP address, MAC address, and hardware information.
    - `file`: A pointer to a file stream where the IDB will be written.
- **Control Flow**:
    - Initialize a buffer `buf` of size `FD_PCAPNG_BLOCK_SZ` to hold the IDB data.
    - Cast the buffer to a `fd_pcapng_idb_t` pointer `block` and set its initial fields, including `block_type` and `link_type`.
    - Set a default timestamp resolution option using `FD_PCAPNG_FWRITE_OPT`.
    - If `opt` is not NULL, check and write optional fields such as name, IPv4 address, MAC address, and hardware using `FD_PCAPNG_FWRITE_OPT`.
    - Write a null option to terminate the options list using `FD_PCAPNG_FWRITE_NULLOPT`.
    - Terminate the block by setting the block size and writing a footer using `FD_PCAPNG_FWRITE_BLOCK_TERM`.
    - Write the buffer to the file using `fwrite` and return the result.
- **Output**: Returns the number of elements successfully written to the file, which should be 1 if successful.


---
### fd\_pcapng\_fwrite\_pkt<!-- {{#callable:fd_pcapng_fwrite_pkt}} -->
The `fd_pcapng_fwrite_pkt` function writes a packet to a PCAPNG file, ensuring proper alignment and formatting according to the PCAPNG Enhanced Packet Block (EPB) structure.
- **Inputs**:
    - `ts`: A long integer representing the timestamp of the packet.
    - `payload`: A pointer to the packet data to be written.
    - `payload_sz`: An unsigned long integer representing the size of the packet data.
    - `_file`: A pointer to a FILE object where the packet will be written.
- **Control Flow**:
    - The function begins by casting the `_file` pointer to a `FILE` pointer and checks if the current file position is 4-byte aligned using `fd_ulong_is_aligned`.
    - It initializes a cursor to the size of `fd_pcapng_epb_t` and sets up an `fd_pcapng_epb_t` block with the appropriate fields, including the timestamp and payload size.
    - The payload size is aligned to the next 4-byte boundary, and padding is calculated if necessary.
    - The cursor is incremented by the aligned payload size and an additional 4 bytes for an empty option list.
    - The block size is calculated and set in the `block_sz` field of the block.
    - The function writes the block header to the file using `fwrite` and checks for errors.
    - It writes the payload to the file and checks for errors.
    - If padding is needed, it writes the padding to the file and checks for errors.
    - It writes an empty options block to the file and checks for errors.
    - Finally, it writes the block size trailer to the file and checks for errors.
    - If all writes are successful, the function returns 1UL; otherwise, it returns 0UL on any failure.
- **Output**: The function returns 1UL on successful writing of the packet to the file, or 0UL if any write operation fails.


---
### fd\_pcapng\_fwrite\_tls\_key\_log<!-- {{#callable:fd_pcapng_fwrite_tls_key_log}} -->
The function `fd_pcapng_fwrite_tls_key_log` writes a TLS key log entry to a file in the PCAPNG format, ensuring proper alignment and block structure.
- **Inputs**:
    - `log`: A pointer to the TLS key log data to be written.
    - `log_sz`: The size of the TLS key log data in bytes.
    - `_file`: A pointer to a FILE object where the TLS key log will be written.
- **Control Flow**:
    - The function begins by casting the `_file` pointer to a `FILE` pointer and checks if the current file position is 4-byte aligned using `fd_ulong_is_aligned`.
    - It initializes a `fd_pcapng_dsb_t` structure named `block` with the block type set to `FD_PCAPNG_BLOCK_TYPE_DSB`, secret type to `FD_PCAPNG_SECRET_TYPE_TLS`, and secret size to `log_sz`.
    - The function calculates the aligned size of the log data (`log_sz_align`) and the padding size (`pad_sz`) needed to ensure 4-byte alignment.
    - The cursor is updated to account for the aligned log size and an additional 4 bytes for the end of options block.
    - The total block size is calculated and stored in `block.block_sz`.
    - The function writes the `block` header to the file and checks for successful write operations using `fwrite`.
    - It writes the log data to the file, followed by any necessary padding to maintain alignment.
    - An empty options block is written, followed by the block size trailer.
    - If any `fwrite` operation fails, the function returns `0UL` to indicate failure; otherwise, it returns `1UL` to indicate success.
- **Output**: The function returns `1UL` on successful writing of the TLS key log entry, or `0UL` if any write operation fails.


