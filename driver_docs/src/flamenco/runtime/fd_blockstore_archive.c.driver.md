# Purpose
The provided C source code file is part of a blockstore archival system, which is responsible for managing the storage and retrieval of data blocks in a file-based archive. This code is not a standalone executable but rather a component of a larger system, likely intended to be compiled into a library or used as part of a larger application. The primary functionality of this code revolves around reading from and writing to an archival file, managing block indices, and ensuring data integrity during these operations.

Key technical components include functions for reading and writing data with wraparound logic, which allows the archival file to be treated as a circular buffer. This is evident in functions like [`read_with_wraparound`](#read_with_wraparound) and [`write_with_wraparound`](#write_with_wraparound), which handle the complexities of reading and writing data that may span the end and start of the file. The code also includes error-checking mechanisms, such as [`check_read_write_err`](#check_read_write_err) and `check_read_err_safe`, to handle unexpected conditions during file operations. Additionally, the code manages block indices and metadata, ensuring that the archival file's structure is maintained and that data can be efficiently retrieved. Functions like [`fd_blockstore_archiver_lrw_slot`](#fd_blockstore_archiver_lrw_slot), [`fd_blockstore_block_info_restore`](#fd_blockstore_block_info_restore), and [`fd_blockstore_post_checkpt_update`](#fd_blockstore_post_checkpt_update) are crucial for maintaining the integrity and consistency of the blockstore's state. Overall, this code provides a specialized and robust solution for managing archival storage in a blockstore system.
# Imports and Dependencies

---
- `fd_blockstore_archive.h`
- `errno.h`
- `unistd.h`


# Functions

---
### check\_read\_write\_err<!-- {{#callable:check_read_write_err}} -->
The `check_read_write_err` function logs an error message if a read or write operation encounters an unexpected end-of-file or other error.
- **Inputs**:
    - `err`: An integer representing the error code from a read or write operation.
- **Control Flow**:
    - The function checks if the error code `err` is less than 0, indicating an unexpected EOF, and logs an error message with the system error string.
    - The function checks if the error code `err` is greater than 0, indicating a read/write failure, and logs an error message with the system error string.
- **Output**: The function does not return any value; it logs error messages based on the error code.


---
### fd\_blockstore\_archiver\_lrw\_slot<!-- {{#callable:fd_blockstore_archiver_lrw_slot}} -->
The function `fd_blockstore_archiver_lrw_slot` retrieves the slot number of the least recently written block from a blockstore archive, restoring its information and data.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore from which the least recently written block's slot is to be retrieved.
    - `fd`: An integer file descriptor used for reading the block information from the archive.
    - `lrw_block_info`: A pointer to an `fd_block_info_t` structure where the restored block information will be stored.
    - `lrw_block_out`: A pointer to an `fd_block_t` structure where the restored block data will be stored.
- **Control Flow**:
    - Retrieve the block index from the blockstore using `fd_blockstore_block_idx` function.
    - Check if the block index is empty using `fd_block_idx_key_cnt`; if it is, return `FD_SLOT_NULL`.
    - Initialize a `fd_block_idx_t` structure `lrw_block_idx` and set its offset to the head of the archiver in the blockstore's shared memory.
    - Call [`fd_blockstore_block_info_restore`](#fd_blockstore_block_info_restore) to restore the block information and data from the archive into `lrw_block_info` and `lrw_block_out`.
    - Check for read/write errors using [`check_read_write_err`](#check_read_write_err).
    - Return the slot number from `lrw_block_info`.
- **Output**: The function returns an `ulong` representing the slot number of the least recently written block, or `FD_SLOT_NULL` if the block index is empty.
- **Functions called**:
    - [`fd_blockstore_block_info_restore`](#fd_blockstore_block_info_restore)
    - [`check_read_write_err`](#check_read_write_err)


---
### fd\_blockstore\_archiver\_verify<!-- {{#callable:fd_blockstore_archiver_verify}} -->
The `fd_blockstore_archiver_verify` function checks if the metadata of a blockstore archiver is valid by comparing its head, tail, and maximum file descriptor size against predefined constants and the blockstore's shared memory values.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore whose archiver metadata is being verified.
    - `fd_metadata`: A pointer to an `fd_blockstore_archiver_t` structure containing the metadata of the blockstore archiver to be verified.
- **Control Flow**:
    - The function checks if `fd_metadata->head` is less than `FD_BLOCKSTORE_ARCHIVE_START`.
    - It checks if `fd_metadata->tail` is less than `FD_BLOCKSTORE_ARCHIVE_START`.
    - It checks if `fd_metadata->fd_size_max` is not equal to `blockstore->shmem->archiver.fd_size_max`.
    - If any of the above conditions are true, the function returns `true`, indicating invalid metadata; otherwise, it returns `false`.
- **Output**: A boolean value indicating whether the blockstore archiver metadata is invalid (`true`) or valid (`false`).


---
### read\_with\_wraparound<!-- {{#callable:read_with_wraparound}} -->
The `read_with_wraparound` function reads data from a file descriptor into a buffer, handling wraparound if the read extends beyond the end of the file.
- **Inputs**:
    - `archvr`: A pointer to an `fd_blockstore_archiver_t` structure that contains metadata about the file, including its maximum size.
    - `fd`: An integer representing the file descriptor from which data is to be read.
    - `dst`: A pointer to a buffer where the read data will be stored.
    - `dst_sz`: An unsigned long representing the size of the buffer `dst`.
    - `rsz`: A pointer to an unsigned long where the actual number of bytes read will be stored.
    - `read_off`: A pointer to an unsigned long indicating the current read offset in the file, which will be updated after the read operation.
- **Control Flow**:
    - Seek to the current read offset in the file using `lseek` and check for errors.
    - Calculate the remaining size from the current offset to the end of the file.
    - If the remaining size is less than the desired read size (`dst_sz`), read the remaining data, reset the offset to the start of the file, and continue reading the rest of the data from the beginning of the file.
    - If the remaining size is sufficient, read the data directly into the buffer.
    - Update the read offset based on the number of bytes read.
    - If the read offset reaches or exceeds the maximum file size, reset it to the start of the file.
- **Output**: Returns `FD_BLOCKSTORE_SUCCESS` on successful read operation, or an error code if any operation fails.


---
### wrap\_offset<!-- {{#callable:wrap_offset}} -->
The `wrap_offset` function calculates a wrapped offset within a blockstore archive, ensuring it stays within valid bounds.
- **Inputs**:
    - `archvr`: A pointer to an `fd_blockstore_archiver_t` structure, which contains metadata about the blockstore archive, including the maximum file size.
    - `off`: An unsigned long integer representing the current offset that needs to be wrapped within the archive.
- **Control Flow**:
    - Check if the offset `off` is equal to `archvr->fd_size_max`; if true, return `FD_BLOCKSTORE_ARCHIVE_START`.
    - If `off` is greater than `archvr->fd_size_max`, calculate the wrapped offset by adding the difference between `off` and `archvr->fd_size_max` to `FD_BLOCKSTORE_ARCHIVE_START`, and return this value.
    - If neither condition is met, return the original offset `off`.
- **Output**: The function returns an unsigned long integer representing the wrapped offset within the blockstore archive.


---
### build\_idx<!-- {{#callable:FD_FN_UNUSED::build_idx}} -->
The `build_idx` function constructs an index for a blockstore archival file by reading and verifying metadata, then iterating through blocks to populate the index, handling duplicates and evictions as necessary.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore to be indexed.
    - `fd`: An integer file descriptor for the archival file to be indexed.
- **Control Flow**:
    - Check if the file descriptor `fd` is -1, and return immediately if true.
    - Log the start of the index building process.
    - Retrieve the block index from the blockstore and initialize block information structures.
    - Seek to the end of the file to determine its size; log an error and return if seeking fails or if the file is empty.
    - Seek back to the start of the file and read the metadata; verify the metadata and log an error if invalid.
    - Initialize variables for block offsets and counts based on metadata.
    - Iterate over the blocks in the file, reading each block's information and updating the index.
    - Check if the block index is full; if so, evict the least recently written block to make space.
    - Check for duplicate slots in the index and remove them if found.
    - Insert the current block into the index and update its metadata.
    - Log the successful reading of each block and update the offset for the next block.
    - Log the successful completion of the index building process.
- **Output**: The function does not return a value; it modifies the blockstore's index and logs messages to indicate progress and errors.
- **Functions called**:
    - [`check_read_write_err`](#check_read_write_err)
    - [`fd_blockstore_archiver_verify`](#fd_blockstore_archiver_verify)
    - [`fd_blockstore_block_info_restore`](#fd_blockstore_block_info_restore)
    - [`fd_blockstore_archiver_lrw_slot`](#fd_blockstore_archiver_lrw_slot)
    - [`wrap_offset`](#wrap_offset)


---
### write\_with\_wraparound<!-- {{#callable:write_with_wraparound}} -->
The `write_with_wraparound` function writes data to a file descriptor with wraparound logic when the end of the file is reached, ensuring continuous writing from the start of the file if necessary.
- **Inputs**:
    - `archvr`: A pointer to an `fd_blockstore_archiver_t` structure that contains metadata about the file, including its maximum size.
    - `fd`: An integer representing the file descriptor to which data will be written.
    - `src`: A pointer to the source data (of type `uchar`) that needs to be written to the file.
    - `src_sz`: An unsigned long integer representing the size of the source data to be written.
    - `write_off`: An unsigned long integer representing the offset in the file where writing should begin.
- **Control Flow**:
    - Check if the file descriptor can be set to the specified write offset using `lseek`; log an error if it fails.
    - Calculate the remaining size from the current offset to the maximum file size.
    - If the remaining size is less than the source size, write the remaining size of data, reset the offset to the start, and write the rest of the data from the beginning of the file.
    - If the remaining size is sufficient, write the entire source data at the current offset.
    - Update the write offset by the number of bytes written.
    - If the updated write offset exceeds the maximum file size, reset it to the start of the file.
- **Output**: The function returns the next valid write offset, which is either the position right after the last written byte or the start of the file if wraparound occurred.
- **Functions called**:
    - [`check_read_write_err`](#check_read_write_err)


---
### start\_archive\_write<!-- {{#callable:start_archive_write}} -->
The `start_archive_write` function initializes the process of writing to an archive by seeking to the start of the file and writing the archiver metadata to it.
- **Inputs**:
    - `archvr`: A pointer to an `fd_blockstore_archiver_t` structure that contains metadata about the blockstore archiver.
    - `fd`: An integer file descriptor representing the file to which the archive metadata will be written.
- **Control Flow**:
    - The function attempts to seek to the start of the file using `lseek` with `SEEK_SET` to ensure writing begins at the start of the file.
    - If seeking fails, it logs an error message using `FD_LOG_ERR`.
    - It then writes the `fd_blockstore_archiver_t` metadata to the file using `fd_io_write`.
    - The function checks for errors in the write operation using [`check_read_write_err`](#check_read_write_err).
- **Output**: The function does not return any value; it performs operations directly on the file and logs errors if they occur.
- **Functions called**:
    - [`check_read_write_err`](#check_read_write_err)


---
### end\_archive\_write<!-- {{#callable:end_archive_write}} -->
The `end_archive_write` function finalizes the writing process to an archive file by seeking to the start of the file and writing the archiver metadata.
- **Inputs**:
    - `archvr`: A pointer to an `fd_blockstore_archiver_t` structure containing metadata about the archive.
    - `fd`: An integer file descriptor representing the open file to which the archive metadata is written.
- **Control Flow**:
    - The function attempts to seek to the start of the file using `lseek` with `SEEK_SET` and checks for errors using `FD_UNLIKELY` and `FD_LOG_ERR` if the seek fails.
    - It then writes the `fd_blockstore_archiver_t` metadata to the file using `fd_io_write`, capturing the number of bytes written in `wsz`.
    - The function checks for any read/write errors using [`check_read_write_err`](#check_read_write_err).
- **Output**: The function does not return any value; it performs its operations directly on the file and logs errors if they occur.
- **Functions called**:
    - [`check_read_write_err`](#check_read_write_err)


---
### fd\_blockstore\_lrw\_archive\_clear<!-- {{#callable:fd_blockstore_lrw_archive_clear}} -->
The `fd_blockstore_lrw_archive_clear` function clears blocks in the archive that are to be overwritten, updating the block index and archiver metadata accordingly.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure, representing the blockstore containing the shared memory and archiver metadata.
    - `fd`: An integer file descriptor representing the archive file.
    - `wsz`: An unsigned long representing the size of the write operation.
    - `write_off`: An unsigned long representing the offset in the archive where writing is intended to start.
- **Control Flow**:
    - Retrieve the archiver and block index from the blockstore.
    - Calculate the non-wrapped and wrapped end offsets based on the write offset and size.
    - Check if the block index is empty; if so, return immediately.
    - Initialize variables for block mapping and block data.
    - Determine the least recently written (LRW) slot and query the block index for this slot.
    - Enter a loop to evict blocks that fall within the write range or wrap around the archive.
    - Log a debug message indicating the overwriting of an LRW block.
    - Remove the block from the block index and update the archiver's head and block count.
    - Recalculate the LRW slot and query the block index again.
    - Check for block index mismatch and log an error if detected.
- **Output**: The function does not return a value; it modifies the block index and archiver metadata in place.
- **Functions called**:
    - [`wrap_offset`](#wrap_offset)
    - [`fd_blockstore_archiver_lrw_slot`](#fd_blockstore_archiver_lrw_slot)


---
### fd\_blockstore\_post\_checkpt\_update<!-- {{#callable:fd_blockstore_post_checkpt_update}} -->
The `fd_blockstore_post_checkpt_update` function updates the block index and archiver metadata after successfully archiving a block in the blockstore.
- **Inputs**:
    - `blockstore`: A pointer to the `fd_blockstore_t` structure representing the blockstore.
    - `ser`: A pointer to the `fd_blockstore_ser_t` structure containing serialized block data.
    - `fd`: An integer file descriptor for the blockstore archive file.
    - `slot`: An unsigned long representing the slot number of the block.
    - `wsz`: An unsigned long representing the size of the written block data.
    - `write_off`: An unsigned long representing the offset in the archive file where the block was written.
- **Control Flow**:
    - Retrieve the archiver and block index from the blockstore.
    - Check if the block index is full by comparing the current key count with the maximum key count.
    - If the block index is full, find the least recently written (LRW) block using [`fd_blockstore_archiver_lrw_slot`](#fd_blockstore_archiver_lrw_slot), remove it from the index, and update the archiver's head offset and block count.
    - Insert a new entry into the block index for the given slot, setting its offset, block hash, and bank hash from the serialized data.
    - Increment the archiver's block count and update the tail offset using [`wrap_offset`](#wrap_offset).
    - Update the blockstore's most recently written (MRW) slot to the current slot.
- **Output**: The function does not return a value; it updates the blockstore's internal state and metadata.
- **Functions called**:
    - [`fd_blockstore_archiver_lrw_slot`](#fd_blockstore_archiver_lrw_slot)
    - [`wrap_offset`](#wrap_offset)


---
### fd\_blockstore\_block\_checkpt<!-- {{#callable:fd_blockstore_block_checkpt}} -->
The `fd_blockstore_block_checkpt` function archives a block from a blockstore to a file descriptor, handling potential overwrites and updating the blockstore's metadata.
- **Inputs**:
    - `blockstore`: A pointer to an `fd_blockstore_t` structure representing the blockstore to be archived.
    - `ser`: A pointer to an `fd_blockstore_ser_t` structure containing serialized block data to be archived.
    - `fd`: An integer file descriptor where the block data will be written.
    - `slot`: An unsigned long integer representing the slot number of the block being archived.
- **Control Flow**:
    - Initialize `write_off` to the current tail of the blockstore's archiver and store it in `og_write_off`.
    - Check if `fd` is -1, log a debug message, and return 0 if true.
    - Attempt to seek to `write_off` in the file descriptor; log an error and exit if it fails.
    - Calculate `total_wsz` as the sum of sizes of `fd_block_info_t`, `fd_block_t`, and the block's data size.
    - Clear any potential overwrites in the archive using [`fd_blockstore_lrw_archive_clear`](#fd_blockstore_lrw_archive_clear).
    - Start the archive write process with [`start_archive_write`](#start_archive_write).
    - Write the block map, block, and block data to the file descriptor using [`write_with_wraparound`](#write_with_wraparound), updating `write_off` each time.
    - Update the blockstore's metadata post-checkpoint using [`fd_blockstore_post_checkpt_update`](#fd_blockstore_post_checkpt_update).
    - End the archive write process with [`end_archive_write`](#end_archive_write).
    - Log a notice indicating the block has been archived and return `total_wsz`.
- **Output**: Returns the total size of the written block data as an unsigned long integer.
- **Functions called**:
    - [`fd_blockstore_lrw_archive_clear`](#fd_blockstore_lrw_archive_clear)
    - [`start_archive_write`](#start_archive_write)
    - [`write_with_wraparound`](#write_with_wraparound)
    - [`fd_blockstore_post_checkpt_update`](#fd_blockstore_post_checkpt_update)
    - [`end_archive_write`](#end_archive_write)


---
### fd\_blockstore\_block\_info\_restore<!-- {{#callable:fd_blockstore_block_info_restore}} -->
The `fd_blockstore_block_info_restore` function reads and restores block information and block data from a file descriptor into provided output structures using wraparound reading.
- **Inputs**:
    - `archvr`: A pointer to an `fd_blockstore_archiver_t` structure, which contains metadata about the blockstore archiver.
    - `fd`: An integer representing the file descriptor from which the block information and block data are to be read.
    - `block_idx_entry`: A pointer to an `fd_block_idx_t` structure that contains the offset information for the block to be restored.
    - `block_info_out`: A pointer to an `fd_block_info_t` structure where the restored block information will be stored.
    - `block_out`: A pointer to an `fd_block_t` structure where the restored block data will be stored.
- **Control Flow**:
    - Initialize `rsz` and set `read_off` to the offset from `block_idx_entry`.
    - Call [`read_with_wraparound`](#read_with_wraparound) to read block information into `block_info_out` from the file descriptor, updating `rsz` and `read_off`.
    - Check for errors using `check_read_err_safe` after reading block information.
    - Call [`read_with_wraparound`](#read_with_wraparound) again to read block data into `block_out`, updating `rsz` and `read_off`.
    - Check for errors using `check_read_err_safe` after reading block data.
    - Return `FD_BLOCKSTORE_SUCCESS` to indicate successful restoration.
- **Output**: Returns `FD_BLOCKSTORE_SUCCESS` on successful restoration of block information and data, or an error code if a read error occurs.
- **Functions called**:
    - [`read_with_wraparound`](#read_with_wraparound)


---
### fd\_blockstore\_block\_data\_restore<!-- {{#callable:fd_blockstore_block_data_restore}} -->
The `fd_blockstore_block_data_restore` function restores block data from a file descriptor into a buffer, ensuring the data fits within the buffer's maximum size and handling potential wraparound in the file.
- **Inputs**:
    - `archvr`: A pointer to an `fd_blockstore_archiver_t` structure, which contains metadata about the blockstore archiver.
    - `fd`: An integer representing the file descriptor from which the block data is to be read.
    - `block_idx_entry`: A pointer to an `fd_block_idx_t` structure that contains the offset information for the block data to be restored.
    - `buf_out`: A pointer to a buffer where the restored block data will be stored.
    - `buf_max`: An unsigned long representing the maximum size of the buffer `buf_out`.
    - `data_sz`: An unsigned long representing the size of the block data to be restored.
- **Control Flow**:
    - Calculate the data offset by adding the size of `fd_block_info_t` and `fd_block_t` to the offset in `block_idx_entry` and wrapping it using [`wrap_offset`](#wrap_offset).
    - Check if `buf_max` is less than `data_sz`; if so, log an error and return -1.
    - Attempt to seek to the calculated data offset in the file; if it fails, log a warning and return `FD_BLOCKSTORE_ERR_SLOT_MISSING`.
    - Call [`read_with_wraparound`](#read_with_wraparound) to read the block data from the file into `buf_out`, handling any potential wraparound in the file.
    - Check for errors in reading using `check_read_err_safe` and return `FD_BLOCKSTORE_SUCCESS` if successful.
- **Output**: Returns `FD_BLOCKSTORE_SUCCESS` on successful restoration of block data, or an error code if an error occurs during the process.
- **Functions called**:
    - [`wrap_offset`](#wrap_offset)
    - [`read_with_wraparound`](#read_with_wraparound)


