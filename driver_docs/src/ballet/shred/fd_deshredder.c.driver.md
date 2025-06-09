# Purpose
This C source code file provides functionality for processing and reconstructing data from a series of "shreds," which are likely fragments of a larger data set. The code is centered around the `fd_deshredder_t` structure, which is initialized and manipulated by the functions [`fd_deshredder_init`](#fd_deshredder_init) and [`fd_deshredder_next`](#fd_deshredder_next). The [`fd_deshredder_init`](#fd_deshredder_init) function sets up the deshredder by assigning a buffer and a collection of shreds to be processed, while [`fd_deshredder_next`](#fd_deshredder_next) iterates over these shreds, appending their data into a contiguous buffer until a complete data entry is reconstructed or an error condition is encountered. The code handles various conditions such as buffer overflow, invalid shred types, and completion flags, ensuring robust processing of the shred data.

The file is likely part of a larger library or application dealing with data reconstruction, possibly in a network or storage context where data is fragmented and needs to be reassembled. The inclusion of headers like "fd_shred.h" and "fd_deshredder.h" suggests that this file is part of a modular system, with `fd_deshredder` providing a specific functionality related to data reassembly. The functions defined here do not appear to be public APIs but rather internal components meant to be used within the broader system, as they operate on specific data structures and rely on other components for full functionality.
# Imports and Dependencies

---
- `fd_shred.h`
- `fd_deshredder.h`


# Functions

---
### fd\_deshredder\_init<!-- {{#callable:fd_deshredder_init}} -->
The `fd_deshredder_init` function initializes a deshredder structure with provided buffer and shred information, setting initial state values.
- **Inputs**:
    - `shredder`: A pointer to an `fd_deshredder_t` structure that will be initialized.
    - `buf`: A pointer to a buffer where the deshredded data will be stored.
    - `bufsz`: The size of the buffer pointed to by `buf`.
    - `shreds`: A pointer to an array of pointers to `fd_shred_t` structures, representing the shreds to be processed.
    - `shred_cnt`: The number of shreds in the `shreds` array.
- **Control Flow**:
    - Assigns the `shreds` pointer to the `shreds` field of the `shredder` structure.
    - Casts `shred_cnt` to an unsigned integer and assigns it to the `shred_cnt` field of the `shredder` structure.
    - Assigns the `buf` pointer to the `buf` field of the `shredder` structure.
    - Assigns `bufsz` to the `bufsz` field of the `shredder` structure.
    - Sets the `result` field of the `shredder` structure to `FD_SHRED_EPIPE`, indicating an initial state.
- **Output**: This function does not return a value; it initializes the `fd_deshredder_t` structure with the provided parameters.


---
### fd\_deshredder\_next<!-- {{#callable:fd_deshredder_next}} -->
The `fd_deshredder_next` function processes a batch of shreds, appending their data to a buffer until a complete entry is formed or an error occurs.
- **Inputs**:
    - `shredder`: A pointer to an `fd_deshredder_t` structure that contains the buffer, buffer size, shreds, and shred count to be processed.
- **Control Flow**:
    - Initialize a pointer to the start of the buffer for later use.
    - Enter an infinite loop to process each shred.
    - Check if there are no more shreds to process; if so, set the result to `FD_SHRED_EPIPE` and break the loop.
    - Retrieve the current shred from the shredder's shreds array.
    - Check if the shred type is a data shred; if not, return `-FD_SHRED_EINVAL`.
    - Ensure the buffer has enough space for the shred's payload; if not, return `-FD_SHRED_ENOMEM`.
    - Copy the shred's payload data into the buffer.
    - Update the buffer pointer and size to reflect the copied data.
    - Advance the shred pointer and decrement the shred count.
    - Check if the current shred marks the end of a slot or batch; if so, set the appropriate result and break the loop.
    - Return the number of bytes written to the buffer.
- **Output**: The function returns the number of bytes written to the buffer, or a negative error code if an error occurs during processing.
- **Functions called**:
    - [`fd_shred_type`](fd_shred.h.driver.md#fd_shred_type)
    - [`fd_shred_is_data`](fd_shred.h.driver.md#fd_shred_is_data)
    - [`fd_shred_payload_sz`](fd_shred.h.driver.md#fd_shred_payload_sz)
    - [`fd_shred_data_payload`](fd_shred.h.driver.md#fd_shred_data_payload)


