# Purpose
This C source code file provides functionality for managing QUIC (Quick UDP Internet Connections) streams, specifically focusing on buffer management and stream lifecycle operations. The code includes functions for storing and loading data in a circular buffer, which is a common data structure used to efficiently manage data streams in network programming. The [`fd_quic_buffer_store`](#fd_quic_buffer_store) and [`fd_quic_buffer_load`](#fd_quic_buffer_load) functions handle the insertion and retrieval of data from this buffer, ensuring that data is correctly managed even when it wraps around the end of the buffer. These functions are critical for maintaining the integrity and performance of data transmission in a QUIC stream.

Additionally, the file defines functions for creating, deleting, and managing the context of QUIC streams. The [`fd_quic_stream_new`](#fd_quic_stream_new) function initializes a new stream, allocating memory for the stream's transmission buffer and acknowledgment buffer, while ensuring proper alignment. The [`fd_quic_stream_delete`](#fd_quic_stream_delete) function handles the cleanup of a stream, and the [`fd_quic_stream_set_context`](#fd_quic_stream_set_context) and [`fd_quic_stream_get_context`](#fd_quic_stream_get_context) functions allow for associating and retrieving user-defined context with a stream. This file is likely part of a larger library or application that implements QUIC protocol functionality, providing essential operations for stream management and data handling.
# Imports and Dependencies

---
- `fd_quic_stream.h`
- `fd_quic_enum.h`


# Functions

---
### fd\_quic\_buffer\_store<!-- {{#callable:fd_quic_buffer_store}} -->
The `fd_quic_buffer_store` function stores data into a circular buffer, ensuring that the data fits within the available space and handling cases where the data needs to be split across the buffer's end and start.
- **Inputs**:
    - `buf`: A pointer to an `fd_quic_buffer_t` structure representing the circular buffer where data will be stored.
    - `data`: A pointer to the data to be stored in the buffer.
    - `data_sz`: The size of the data to be stored, in bytes.
- **Control Flow**:
    - Calculate the current used and free space in the buffer using the head and tail indices.
    - Check if there is enough free space to store the data; if not, return immediately.
    - Determine if the data can be stored contiguously or needs to be split across the buffer's end and start.
    - If the data fits contiguously, copy it directly into the buffer at the head position.
    - If the data needs to be split, copy the first part to the end of the buffer and the remaining part to the start of the buffer.
- **Output**: The function does not return a value; it modifies the buffer in place to store the data.


---
### fd\_quic\_buffer\_load<!-- {{#callable:fd_quic_buffer_load}} -->
The `fd_quic_buffer_load` function loads data from a circular buffer into a provided data array, handling potential buffer wrap-around.
- **Inputs**:
    - `buf`: A pointer to an `fd_quic_buffer_t` structure representing the circular buffer from which data is to be loaded.
    - `offs`: An unsigned long integer representing the offset in the buffer from which to start loading data.
    - `data`: A pointer to an unsigned char array where the loaded data will be stored.
    - `data_sz`: An unsigned long integer representing the size of the data to be loaded from the buffer.
- **Control Flow**:
    - Initialize local variables for buffer properties such as capacity, mask, head, and tail based on the input buffer structure.
    - Check if the operation is valid by ensuring the offset is within the valid range; if not, return immediately.
    - Determine if the data to be loaded fits within the free contiguous space at the calculated tail position or if it needs to be split across the buffer wrap-around.
    - If the data fits within the contiguous space, use `fd_memcpy` to copy the data directly from the buffer to the provided data array.
    - If the data needs to be split, copy the first part from the end of the buffer and the remaining part from the beginning of the buffer using `fd_memcpy`.
- **Output**: The function does not return a value; it directly modifies the contents of the `data` array with the loaded data from the buffer.


---
### fd\_quic\_stream\_footprint<!-- {{#callable:fd_quic_stream_footprint}} -->
The `fd_quic_stream_footprint` function calculates the total memory footprint required for a QUIC stream, including the stream instance, transmission buffer, and acknowledgment buffer, all aligned to a specific boundary.
- **Inputs**:
    - `tx_buf_sz`: The size of the transmission buffer in bytes.
- **Control Flow**:
    - Retrieve the alignment size using `fd_quic_stream_align()`.
    - Initialize the offset `offs` to zero.
    - Calculate the size of the acknowledgment buffer as one-eighth of the transmission buffer size (`tx_ack_sz = tx_buf_sz >> 3`).
    - Align the size of the stream instance, transmission buffer, and acknowledgment buffer to the alignment boundary using `fd_ulong_align_up()`.
    - Increment the offset `offs` by the aligned sizes of the stream instance, transmission buffer, and acknowledgment buffer.
    - Return the total offset `offs`, which represents the total memory footprint.
- **Output**: The function returns an unsigned long integer representing the total aligned memory footprint required for the QUIC stream.
- **Functions called**:
    - [`fd_quic_stream_align`](fd_quic_stream.h.driver.md#fd_quic_stream_align)


---
### fd\_quic\_stream\_new<!-- {{#callable:fd_quic_stream_new}} -->
The `fd_quic_stream_new` function initializes a new QUIC stream with allocated memory for transmission buffers and associates it with a given connection.
- **Inputs**:
    - `mem`: A pointer to the memory block where the stream and its buffers will be allocated, which must be aligned to [`fd_quic_stream_align`](fd_quic_stream.h.driver.md#fd_quic_stream_align) and have at least `fd_quic_stream_footprint(tx_buf_sz)` bytes.
    - `conn`: A pointer to the `fd_quic_conn_t` connection object that the new stream will be associated with.
    - `tx_buf_sz`: The size of the transmission buffer to be allocated for the stream.
- **Control Flow**:
    - Calculate the alignment size using [`fd_quic_stream_align`](fd_quic_stream.h.driver.md#fd_quic_stream_align).
    - Determine the size of the acknowledgment buffer as one-eighth of the transmission buffer size.
    - Align the sizes of the stream structure, transmission buffer, and acknowledgment buffer to the calculated alignment size.
    - Initialize the offset and base address for memory allocation.
    - Allocate memory for the stream structure at the base address and update the offset.
    - Allocate memory for the transmission buffer at the updated offset, set its capacity, and update the offset again.
    - Allocate memory for the acknowledgment buffer at the updated offset and update the offset again.
    - Check if the total allocated size matches the expected footprint size; log an error if it does not.
    - Initialize the stream's connection pointer, set the stream ID to unused, and set the stream's next and previous pointers to itself, indicating it is not part of any list.
    - Return the pointer to the newly initialized stream.
- **Output**: A pointer to the newly initialized `fd_quic_stream_t` structure.
- **Functions called**:
    - [`fd_quic_stream_align`](fd_quic_stream.h.driver.md#fd_quic_stream_align)
    - [`fd_quic_stream_footprint`](#fd_quic_stream_footprint)


---
### fd\_quic\_stream\_delete<!-- {{#callable:fd_quic_stream_delete}} -->
The `fd_quic_stream_delete` function removes a QUIC stream from any list it may be part of by setting its next and previous pointers to itself and marking it as not a member of any list.
- **Inputs**:
    - `stream`: A pointer to the `fd_quic_stream_t` structure representing the QUIC stream to be deleted.
- **Control Flow**:
    - The function sets the `next` and `prev` pointers of the `stream` to point to itself, effectively removing it from any linked list it may be part of.
    - The `list_memb` field of the `stream` is set to `FD_QUIC_STREAM_LIST_MEMB_NONE`, indicating that the stream is not a member of any list.
- **Output**: The function does not return any value; it modifies the `stream` in place to remove it from any list.


---
### fd\_quic\_stream\_set\_context<!-- {{#callable:fd_quic_stream_set_context}} -->
The function `fd_quic_stream_set_context` assigns a user-defined context to a QUIC stream.
- **Inputs**:
    - `stream`: A pointer to an `fd_quic_stream_t` structure representing the QUIC stream to which the context will be associated.
    - `context`: A pointer to a user-defined context that will be associated with the specified stream.
- **Control Flow**:
    - The function takes two parameters: a stream and a context.
    - It assigns the context to the `context` field of the `fd_quic_stream_t` structure pointed to by the stream.
- **Output**: This function does not return any value.


---
### fd\_quic\_stream\_get\_context<!-- {{#callable:fd_quic_stream_get_context}} -->
The function `fd_quic_stream_get_context` retrieves the user-defined context associated with a given QUIC stream.
- **Inputs**:
    - `stream`: A pointer to an `fd_quic_stream_t` structure from which the context is to be retrieved.
- **Control Flow**:
    - The function accesses the `context` member of the `fd_quic_stream_t` structure pointed to by `stream`.
    - It returns the value of the `context` member.
- **Output**: The function returns a pointer to the user-defined context associated with the specified stream.


# Function Declarations (Public API)

---
### fd\_quic\_stream\_align<!-- {{#callable_declaration:fd_quic_stream_align}} -->
Return the required memory alignment for QUIC streams.
- **Description**: This function provides the memory alignment requirement for QUIC streams, which is necessary when allocating memory for stream operations. It should be used whenever memory is allocated for QUIC streams to ensure proper alignment and avoid potential issues with unaligned memory access. The alignment value is constant and should be used in conjunction with other functions that require aligned memory, such as memory allocation or footprint calculation functions.
- **Inputs**: None
- **Output**: Returns the alignment size in bytes as an unsigned long integer.
- **See also**: [`fd_quic_stream_align`](fd_quic_stream.h.driver.md#fd_quic_stream_align)  (Implementation)


