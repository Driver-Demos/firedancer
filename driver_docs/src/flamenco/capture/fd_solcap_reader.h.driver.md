# Purpose
This C header file defines a set of functions and data structures for reading and iterating over chunks in a "solcap" file, which appears to be a specialized file format used in the context of the Flamenco project. The file includes definitions for a chunk iterator (`fd_solcap_chunk_iter_t`) that facilitates sequential access to chunks within a solcap file, providing functions to initialize the iterator, read the next chunk, and handle errors. Additionally, it includes utility functions for finding specific chunks by their magic number, reading bank preimage metadata, and handling account table data. The header relies on external protobuf definitions (`fd_solcap.pb.h` and `fd_solcap_proto.h`) and is conditionally compiled based on the `FD_HAS_HOSTED` macro, indicating it is intended for use in hosted environments.
# Imports and Dependencies

---
- `fd_solcap.pb.h`
- `fd_solcap_proto.h`


# Data Structures

---
### fd\_solcap\_chunk\_iter
- **Type**: `struct`
- **Members**:
    - `stream`: A pointer to the stream being iterated over.
    - `chunk`: An instance of fd_solcap_chunk_t representing the current chunk.
    - `err`: An integer storing the error code of the last operation.
    - `chunk_off`: The absolute file offset of the current chunk.
    - `chunk_end`: The absolute file offset of the next chunk.
- **Description**: The `fd_solcap_chunk_iter` structure is designed to facilitate the iteration over chunks within a solcap file. It maintains the state of the iteration, including the current position in the file (`chunk_off`), the position of the next chunk (`chunk_end`), and any errors encountered (`err`). The `stream` member points to the file stream being read, and `chunk` holds the current chunk's data. This structure is used in conjunction with functions that initialize the iterator, move to the next chunk, and handle errors, providing a robust mechanism for sequentially accessing chunks in a file.


---
### fd\_solcap\_chunk\_iter\_t
- **Type**: `struct`
- **Members**:
    - `stream`: A pointer to the file stream being iterated over.
    - `chunk`: An instance of fd_solcap_chunk_t representing the current chunk.
    - `err`: An integer storing the error code of the last operation.
    - `chunk_off`: An unsigned long indicating the absolute file offset of the current chunk.
    - `chunk_end`: An unsigned long indicating the absolute file offset of the next chunk.
- **Description**: The `fd_solcap_chunk_iter_t` structure is designed to facilitate the iteration over chunks within a solcap file. It maintains the state of the iteration, including the current position in the file (`chunk_off`), the position of the next chunk (`chunk_end`), and any errors encountered (`err`). The `stream` member points to the file being read, while `chunk` holds the current chunk's data. This structure is used in conjunction with functions that initialize the iterator, move to the next chunk, and handle errors, providing a robust mechanism for sequentially accessing chunks in a solcap file.


# Functions

---
### fd\_solcap\_chunk\_iter\_err<!-- {{#callable:fd_solcap_chunk_iter_err}} -->
The function `fd_solcap_chunk_iter_err` returns the error code of the last failure encountered by the chunk iterator.
- **Inputs**:
    - `iter`: A pointer to a constant `fd_solcap_chunk_iter_t` structure, which represents the current state of the chunk iterator.
- **Control Flow**:
    - The function accesses the `err` field of the `fd_solcap_chunk_iter_t` structure pointed to by `iter`.
    - It returns the value of the `err` field, which indicates the error code of the last failure.
- **Output**: The function returns an integer representing the error code of the last failure; it returns 0 if the last failure was due to reaching the end-of-file.


---
### fd\_solcap\_chunk\_iter\_item<!-- {{#callable:fd_solcap_chunk_iter_item}} -->
The function `fd_solcap_chunk_iter_item` returns a pointer to the last successfully read chunk header from a chunk iterator.
- **Inputs**:
    - `iter`: A pointer to a `fd_solcap_chunk_iter_t` structure, which represents the current state of a chunk iterator.
- **Control Flow**:
    - The function takes a single argument, `iter`, which is a pointer to a `fd_solcap_chunk_iter_t` structure.
    - It returns the address of the `chunk` member within the `fd_solcap_chunk_iter_t` structure pointed to by `iter`.
- **Output**: A pointer to a `fd_solcap_chunk_t` structure, representing the last successfully read chunk header.


---
### fd\_solcap\_chunk\_iter\_find<!-- {{#callable:fd_solcap_chunk_iter_find}} -->
The `fd_solcap_chunk_iter_find` function iterates through chunks in a solcap file to find a chunk with a specified magic number and returns its file offset.
- **Inputs**:
    - `iter`: A pointer to an `fd_solcap_chunk_iter_t` structure, which is used to iterate through the chunks of a solcap file.
    - `magic`: An unsigned long integer representing the magic number to search for in the chunks.
- **Control Flow**:
    - The function enters an infinite loop to iterate through chunks.
    - It calls [`fd_solcap_chunk_iter_next`](fd_solcap_reader.c.driver.md#fd_solcap_chunk_iter_next) to get the next chunk's file offset.
    - If the returned offset is negative, indicating an error or end-of-file, the function returns -1L.
    - It checks if the iteration is done using [`fd_solcap_chunk_iter_done`](fd_solcap_reader.c.driver.md#fd_solcap_chunk_iter_done), and if so, returns -1L.
    - It retrieves the current chunk using [`fd_solcap_chunk_iter_item`](#fd_solcap_chunk_iter_item) and checks if its magic number matches the specified magic.
    - If a match is found, it returns the current chunk's file offset.
- **Output**: The function returns the absolute file offset of the chunk with the specified magic number, or -1L if no such chunk is found or an error occurs.
- **Functions called**:
    - [`fd_solcap_chunk_iter_next`](fd_solcap_reader.c.driver.md#fd_solcap_chunk_iter_next)
    - [`fd_solcap_chunk_iter_done`](fd_solcap_reader.c.driver.md#fd_solcap_chunk_iter_done)
    - [`fd_solcap_chunk_iter_item`](#fd_solcap_chunk_iter_item)


---
### fd\_solcap\_includes\_account\_data<!-- {{#callable:fd_solcap_includes_account_data}} -->
The function `fd_solcap_includes_account_data` checks if a capture account chunk includes account data by evaluating the presence of data offset and size.
- **Inputs**:
    - `meta`: A pointer to a constant `fd_solcap_AccountMeta` structure, which contains metadata about the account, including data offset and size.
- **Control Flow**:
    - The function checks if `meta->data_coff` (data offset) is non-zero by using the double negation `!!` to convert it to a boolean value.
    - It checks if `meta->data_sz` (data size) is non-zero in the same manner.
    - It performs a bitwise AND operation between the boolean results of the two checks.
    - The function returns the result of the bitwise AND operation, which will be 1 if both checks are true (non-zero) and 0 otherwise.
- **Output**: The function returns an integer value: 1 if both the data offset and data size are non-zero, indicating that account data is included, and 0 otherwise.


# Function Declarations (Public API)

---
### fd\_solcap\_chunk\_iter\_next<!-- {{#callable_declaration:fd_solcap_chunk_iter_next}} -->
Reads the next chunk header from the solcap file.
- **Description**: Use this function to advance the iterator to the next chunk in a solcap file, starting from the current position of the stream. It is safe to call even if the stream cursor was modified by the user. On success, it returns the file offset of the first byte of the chunk, allowing the user to seek to specific data within the chunk. On failure, it returns -1L, which can occur due to end-of-file, I/O errors, or parse errors. The function logs warnings for errors other than EOF, and the error code can be retrieved using fd_solcap_chunk_iter_err.
- **Inputs**:
    - `iter`: A pointer to an fd_solcap_chunk_iter_t structure, which must have been initialized using fd_solcap_chunk_iter_new. The structure is used to track the current state of iteration through the solcap file. The caller retains ownership and must ensure it is not null.
- **Output**: Returns the file offset of the first byte of the chunk on success, or -1L on failure. The iter->err field is updated with an errno-like code on failure, or 0 if the failure was due to EOF.
- **See also**: [`fd_solcap_chunk_iter_next`](fd_solcap_reader.c.driver.md#fd_solcap_chunk_iter_next)  (Implementation)


---
### fd\_solcap\_chunk\_iter\_done<!-- {{#callable_declaration:fd_solcap_chunk_iter_done}} -->
Check if the iteration over solcap file chunks is complete.
- **Description**: Use this function to determine if there are no more chunks to iterate over in a solcap file or if an error occurred during the last read operation. It should be called after attempting to read chunks using the iteration functions provided. This function is useful for controlling loop termination when processing chunks in a solcap file.
- **Inputs**:
    - `iter`: A pointer to a constant fd_solcap_chunk_iter_t structure representing the current state of the chunk iteration. Must not be null. The function checks the end-of-file status and any errors associated with this iterator.
- **Output**: Returns 1 if the end-of-file is reached or if an error occurred during the last chunk read; otherwise, returns 0.
- **See also**: [`fd_solcap_chunk_iter_done`](fd_solcap_reader.c.driver.md#fd_solcap_chunk_iter_done)  (Implementation)


---
### fd\_solcap\_read\_bank\_preimage<!-- {{#callable_declaration:fd_solcap_read_bank_preimage}} -->
Reads and parses the bank preimage metadata blob.
- **Description**: This function is used to read and parse the bank preimage metadata from a specified chunk in a file stream. It should be called when you need to extract and decode the bank preimage data from a chunk identified by its offset and header. The function requires a valid file stream, a chunk offset, a preimage structure to populate, and a header structure that describes the chunk. It returns an error code if the operation fails due to invalid magic numbers, file seeking issues, or decoding errors.
- **Inputs**:
    - `stream`: A pointer to a file stream (e.g., FILE *). The stream must be open and valid. The caller retains ownership and is responsible for managing the stream's lifecycle.
    - `chunk_goff`: The file offset of the chunk containing the bank preimage. It must be a valid offset within the file.
    - `preimage`: A pointer to an fd_solcap_BankPreimage structure where the parsed preimage data will be stored. Must not be null.
    - `hdr`: A pointer to a constant fd_solcap_chunk_t structure that contains the header information for the chunk. The header must have a valid magic number and metadata size.
- **Output**: Returns 0 on success. On failure, returns an errno-like error code indicating the type of error encountered, such as EPROTO for protocol errors or ENOMEM for memory issues.
- **See also**: [`fd_solcap_read_bank_preimage`](fd_solcap_reader.c.driver.md#fd_solcap_read_bank_preimage)  (Implementation)


---
### fd\_solcap\_find\_account\_table<!-- {{#callable_declaration:fd_solcap_find_account_table}} -->
Reads account table metadata and seeks to the first account table row.
- **Description**: This function is used to read the metadata of an account table from a file stream and position the stream cursor to the start of the first account table row. It should be called when you need to access account table data from a file, using the file offset of the chunk containing the account table. The function writes the account metadata to the provided `meta` structure. It returns an error code if it fails to read the metadata or seek to the correct position, which can occur due to I/O errors or if the data format is incorrect.
- **Inputs**:
    - `_file`: A pointer to a file stream (FILE *). The caller retains ownership and it must be a valid, open file stream. The function will seek within this stream.
    - `meta`: A pointer to an `fd_solcap_AccountTableMeta` structure where the account table metadata will be written. Must not be null.
    - `acc_tbl_goff`: The file offset of the chunk containing the account table. Must be a valid offset within the file.
- **Output**: Returns 0 on success, or an errno-like error code on failure.
- **See also**: [`fd_solcap_find_account_table`](fd_solcap_reader.c.driver.md#fd_solcap_find_account_table)  (Implementation)


---
### fd\_solcap\_find\_account<!-- {{#callable_declaration:fd_solcap_find_account}} -->
Reads an account meta and optionally sets the file offset to account data.
- **Description**: This function is used to read an account meta from a file stream and, if account data is included, set the file offset to the account data. It should be called when you need to retrieve account metadata from a specific location in a file. The function requires a valid file stream and an account table record to locate the account meta. If the account data is included and the optional data offset pointer is provided, the function will set the offset to the account data. The function returns 0 on success or an errno-like error code on failure, such as when the file cannot be read or the data is not in the expected format.
- **Inputs**:
    - `_file`: A pointer to a file stream (FILE *). Must be a valid, open file stream. The caller retains ownership and is responsible for closing the file.
    - `meta`: A pointer to an fd_solcap_AccountMeta structure where the account meta will be stored. Must not be null.
    - `opt_data_off`: An optional pointer to a ulong where the file offset to the account data will be stored if account data is included. Can be null if the offset is not needed.
    - `rec`: A pointer to a constant fd_solcap_account_tbl_t structure representing the account table record. Must not be null.
    - `acc_tbl_goff`: An unsigned long representing the file offset of the account table chunk. Must be a valid offset within the file.
- **Output**: Returns 0 on success or an errno-like error code on failure. If opt_data_off is provided and account data is included, it is set to the file offset of the account data.
- **See also**: [`fd_solcap_find_account`](fd_solcap_reader.c.driver.md#fd_solcap_find_account)  (Implementation)


