# Purpose
This C header file defines the interface for a deserialization utility, specifically a "deshredder," which is responsible for reconstructing block entries from a series of data shreds. The file includes the definition of the `fd_deshredder_t` structure, which holds the state necessary for the deserialization process, such as a vector of shreds, a buffer for concatenated data, and a result code. It provides two main functions: [`fd_deshredder_init`](#fd_deshredder_init), which initializes the deshredder with a buffer and a set of shreds, and [`fd_deshredder_next`](#fd_deshredder_next), which processes these shreds in batches, concatenating them into the provided buffer. The header ensures that the deshredder can handle multiple calls to process all shreds, returning specific error codes if issues arise, such as insufficient buffer size or invalid shred types.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `fd_shred.h`


# Data Structures

---
### fd\_deshredder\_t
- **Type**: `struct`
- **Members**:
    - `shreds`: A pointer to a vector of data shreds.
    - `shred_cnt`: The number of shreds left in the buffer.
    - `buf`: A cursor pointing to the target buffer where deserialized data is stored.
    - `bufsz`: The size of the free space available in the target buffer.
    - `result`: A cached return code indicating the status of the deshredder operation.
- **Description**: The `fd_deshredder_t` structure is designed to manage the deserialization of a vector of shreds into block entries. It maintains a pointer to the shreds, tracks the number of shreds remaining, and manages a buffer where the deserialized data is stored. The structure also keeps track of the available buffer size and caches the result of the deserialization process, which can indicate various states or errors encountered during the operation.


# Function Declarations (Public API)

---
### fd\_deshredder\_init<!-- {{#callable_declaration:fd_deshredder_init}} -->
Initialize the deshredder with a buffer and shreds.
- **Description**: This function prepares a deshredder for operation by setting up its internal state with a provided buffer and a vector of shreds. It should be called before any deshredding operations are performed. The buffer is where concatenated shreds will be written, and its size must be specified. The shreds vector must contain validated and ideally authenticated shreds, with each shred's index incrementing by one and having the same slot and version. The function does not perform any operations on the shreds themselves, but merely sets up the deshredder for future processing.
- **Inputs**:
    - `shredder`: A pointer to an fd_deshredder_t structure that will be initialized. The caller must allocate this structure before calling the function.
    - `buf`: A pointer to a buffer where concatenated shreds will be written. The buffer must be allocated by the caller and must not be null.
    - `bufsz`: The size of the buffer in bytes. It must be large enough to hold the concatenated shreds.
    - `shreds`: A pointer to a contiguous vector of fd_shred_t pointers, representing the shreds to be deserialized. Each shred must be validated and ideally authenticated before being passed to this function.
    - `shred_cnt`: The number of shreds in the shreds vector. It must accurately reflect the number of shreds provided.
- **Output**: None
- **See also**: [`fd_deshredder_init`](fd_deshredder.c.driver.md#fd_deshredder_init)  (Implementation)


---
### fd\_deshredder\_next<!-- {{#callable_declaration:fd_deshredder_next}} -->
Concatenates a batch of shreds into a buffer.
- **Description**: This function processes a batch of shreds, concatenating their data into a buffer previously provided during initialization. It should be called after `fd_deshredder_init` has been used to set up the deshredder with a valid buffer and shred vector. The function may need to be called multiple times to process all shreds, as each call handles a batch. It returns the number of bytes written to the buffer if successful, or a negative error code if an issue occurs, such as an invalid shred type or insufficient buffer space. The function updates the deshredder's result code to indicate the status of the operation, which can be used to determine if more shreds are available or if the end of a batch or slot has been reached.
- **Inputs**:
    - `shredder`: A pointer to an initialized `fd_deshredder_t` structure. Must not be null and should have been initialized with `fd_deshredder_init`. The function will update the internal state of this structure, including the buffer cursor and result code.
- **Output**: Returns the number of bytes written to the buffer if successful. Returns a negative error code if an error occurs, such as `-FD_SHRED_ENOMEM` for insufficient buffer space or `-FD_SHRED_EINVAL` for an invalid shred type. The deshredder's result code is updated to reflect the operation's outcome.
- **See also**: [`fd_deshredder_next`](fd_deshredder.c.driver.md#fd_deshredder_next)  (Implementation)


