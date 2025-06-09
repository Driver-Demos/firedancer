# Purpose
The provided C header file, `fd_dbl_buf.h`, defines a concurrent lock-free double buffer system designed for use in multi-threaded environments. This double buffer is optimized for scenarios where there is a single producer thread and multiple consumer threads, with a focus on rare updates and frequent polling, such as configuration updates. The double buffer alternates between two internal buffers to manage message storage and retrieval, allowing a producer to write new messages while consumers read the current message. The implementation assumes a memory model that maintains store order across threads, such as x86-TSO, and does not rely on atomic operations or hardware memory fences, which simplifies the design and potentially improves performance in suitable environments.

Key components of this header file include the `fd_dbl_buf_t` union, which serves as the structure for the double buffer, and a set of functions for managing the buffer's lifecycle and operations. These functions include [`fd_dbl_buf_new`](#fd_dbl_buf_new) for initializing a buffer, [`fd_dbl_buf_insert`](#fd_dbl_buf_insert) for adding messages, and [`fd_dbl_buf_try_read`](#fd_dbl_buf_try_read) for attempting to read the most recent message. The file also provides utility functions to query buffer properties, such as [`fd_dbl_buf_obj_mtu`](#fd_dbl_buf_obj_mtu) for the maximum message size and [`fd_dbl_buf_seq_query`](#fd_dbl_buf_seq_query) for the current sequence number. The header defines a public API for creating and interacting with double buffers, making it suitable for integration into larger systems where efficient, lock-free message passing is required.
# Imports and Dependencies

---
- `../../util/bits/fd_bits.h`
- `emmintrin.h`


# Global Variables

---
### fd\_dbl\_buf\_new
- **Type**: `function pointer`
- **Description**: The `fd_dbl_buf_new` function is a global function that initializes a memory region to be used as a double buffer. It takes a pointer to a shared memory region (`shmem`), the maximum transmission unit (`mtu`), and an initial sequence number (`seq0`) as parameters.
- **Use**: This function is used to format a memory region for use as a double buffer, setting up the initial state with a specified sequence number and zero byte size.


---
### fd\_dbl\_buf\_join
- **Type**: `fd_dbl_buf_t *`
- **Description**: The `fd_dbl_buf_join` is a function that returns a pointer to a `fd_dbl_buf_t` structure, which represents a concurrent lock-free double buffer. This double buffer is designed to handle messages between a single producer thread and multiple consumer threads, optimized for scenarios with infrequent updates and frequent polling.
- **Use**: This function is used to join or attach to an existing double buffer in shared memory, allowing the caller to interact with the buffer for message passing.


---
### fd\_dbl\_buf\_leave
- **Type**: `function`
- **Description**: The `fd_dbl_buf_leave` function is a part of the double buffer management system, which is designed to handle concurrent lock-free operations. This function is responsible for leaving or detaching from a double buffer, which is represented by the `fd_dbl_buf_t` structure.
- **Use**: This function is used to detach a consumer or producer from the double buffer, effectively cleaning up or finalizing the use of the buffer by the calling entity.


---
### fd\_dbl\_buf\_delete
- **Type**: `function pointer`
- **Description**: The `fd_dbl_buf_delete` is a function that unformats the memory region backing a double buffer and releases ownership back to the caller. It takes a pointer to the shared buffer (`shbuf`) as an argument and returns the same pointer after performing the unformatting operation.
- **Use**: This function is used to clean up and release the memory resources associated with a double buffer when it is no longer needed.


# Data Structures

---
### fd\_dbl\_buf
- **Type**: `union`
- **Members**:
    - `magic`: A unique identifier for the double buffer, expected to be equal to FD_DBL_BUF_MAGIC.
    - `mtu`: The maximum transmission unit, representing the largest possible message size.
    - `buf0`: Offset to the first buffer from the beginning of the struct.
    - `buf1`: Offset to the second buffer from the beginning of the struct.
    - `seq`: The sequence number of the latest message.
    - `sz`: The size of the latest message.
    - `pad`: Padding to align the structure to 16 bytes.
    - `magic_mtu`: A 128-bit SSE register combining magic and mtu for optimized access.
    - `buf0_buf1`: A 128-bit SSE register combining buf0 and buf1 for optimized access.
    - `seq_sz`: A 128-bit SSE register combining seq and sz for optimized access.
    - `pad2`: A 128-bit SSE register for padding to align the structure to 16 bytes.
- **Description**: The `fd_dbl_buf` is a union representing a concurrent lock-free double buffer designed for a single producer and multiple consumers. It contains two buffers that alternate roles between holding a message for consumers and receiving a new message from a producer. The structure is optimized for rare updates and frequent polling, making it suitable for configurations where updates are infrequent but reads are common. It assumes a memory model that preserves store order across threads and does not use atomic operations or hardware fences. The union provides both a standard struct layout and an SSE-optimized layout for systems with SSE support, ensuring efficient data handling and alignment.


---
### fd\_dbl\_buf\_t
- **Type**: `union`
- **Members**:
    - `magic`: A magic number used to identify the double buffer structure.
    - `mtu`: The maximum transmission unit, representing the largest possible message size.
    - `buf0`: Offset to the first buffer from the beginning of the structure.
    - `buf1`: Offset to the second buffer from the beginning of the structure.
    - `seq`: The latest message sequence number.
    - `sz`: The size of the latest message.
    - `pad`: Padding to align the structure.
    - `magic_mtu`: A 128-bit SSE register combining magic and mtu for optimized operations.
    - `buf0_buf1`: A 128-bit SSE register combining buf0 and buf1 for optimized operations.
    - `seq_sz`: A 128-bit SSE register combining seq and sz for optimized operations.
    - `pad2`: Padding for SSE alignment.
- **Description**: The `fd_dbl_buf_t` is a union representing a concurrent lock-free double buffer designed for a single producer and multiple consumers. It contains two buffers that alternate roles between holding a message for consumers and receiving a new message from a producer. The structure is optimized for rare updates and frequent polling, making it suitable for scenarios like configuration updates. It assumes a memory model that preserves store order across threads and does not use atomic operations or hardware fences. The union provides both a standard struct layout and an SSE-optimized layout for systems with SSE support.


# Functions

---
### fd\_dbl\_buf\_obj\_mtu<!-- {{#callable:fd_dbl_buf_obj_mtu}} -->
The `fd_dbl_buf_obj_mtu` function retrieves the maximum message size that a double buffer can store.
- **Inputs**:
    - `buf`: A pointer to an `fd_dbl_buf_t` structure, representing the double buffer whose maximum message size is to be retrieved.
- **Control Flow**:
    - The function accesses the `mtu` field of the `fd_dbl_buf_t` structure pointed to by `buf`.
    - It returns the value of the `mtu` field, which represents the maximum message size the double buffer can store.
- **Output**: The function returns an `ulong` value representing the maximum message size (MTU) that the double buffer can store.


---
### fd\_dbl\_buf\_seq\_query<!-- {{#callable:fd_dbl_buf_seq_query}} -->
The `fd_dbl_buf_seq_query` function retrieves the current sequence number from a double buffer in a thread-safe manner.
- **Inputs**:
    - `buf`: A pointer to an `fd_dbl_buf_t` structure representing the double buffer from which the sequence number is to be queried.
- **Control Flow**:
    - The function begins by executing a memory fence (`FD_COMPILER_MFENCE`) to ensure memory ordering before accessing the sequence number.
    - It then reads the sequence number from the `seq` field of the `fd_dbl_buf_t` structure using a volatile read (`FD_VOLATILE_CONST`).
    - Another memory fence is executed to ensure memory ordering after reading the sequence number.
    - Finally, the function returns the sequence number.
- **Output**: The function returns an `ulong` representing the current sequence number of the double buffer.


---
### fd\_dbl\_buf\_slot<!-- {{#callable:fd_dbl_buf_slot}} -->
The `fd_dbl_buf_slot` function returns a pointer to the appropriate buffer within a double buffer structure based on the provided sequence number.
- **Inputs**:
    - `buf`: A pointer to an `fd_dbl_buf_t` structure, which represents the double buffer.
    - `seq`: An unsigned long integer representing the sequence number used to determine which buffer to access.
- **Control Flow**:
    - The function checks if the least significant bit of the sequence number (`seq`) is set (i.e., `seq & 1`).
    - If the least significant bit is set, it returns a pointer to the buffer at the offset `buf->buf1` from the start of the `fd_dbl_buf_t` structure.
    - If the least significant bit is not set, it returns a pointer to the buffer at the offset `buf->buf0` from the start of the `fd_dbl_buf_t` structure.
- **Output**: A pointer to the buffer within the double buffer structure corresponding to the given sequence number.


---
### fd\_dbl\_buf\_try\_read<!-- {{#callable:fd_dbl_buf_try_read}} -->
The `fd_dbl_buf_try_read` function attempts to read the most recent message from a double buffer in a lock-free manner, returning the message size or indicating failure if an overrun occurs.
- **Inputs**:
    - `buf`: A pointer to the `fd_dbl_buf_t` structure representing the double buffer from which to read.
    - `out`: A pointer to a buffer where the read message will be copied, with a size of at least `fd_dbl_buf_obj_mtu(buf)` bytes.
    - `opt_seqp`: An optional pointer to a `ulong` where the sequence number of the read message will be stored, or `NULL` if not needed.
- **Control Flow**:
    - Query the current sequence number of the buffer using [`fd_dbl_buf_seq_query`](#fd_dbl_buf_seq_query) and store it in `seq`.
    - Determine the source buffer for the current sequence using [`fd_dbl_buf_slot`](#fd_dbl_buf_slot).
    - Retrieve the size of the message from the buffer's `sz` field using `FD_VOLATILE_CONST`.
    - Copy the message from the source buffer to the `out` buffer using `fd_memcpy`.
    - Check if the sequence number has changed since the initial query; if it has, return `ULONG_MAX` to indicate a read failure due to an overrun.
    - If `opt_seqp` is not `NULL`, store the sequence number in the location pointed to by `opt_seqp`.
    - Return the size of the message read.
- **Output**: Returns the size of the message read on success, or `ULONG_MAX` if the read was overrun by a writer.
- **Functions called**:
    - [`fd_dbl_buf_seq_query`](#fd_dbl_buf_seq_query)
    - [`fd_dbl_buf_slot`](#fd_dbl_buf_slot)


# Function Declarations (Public API)

---
### fd\_dbl\_buf\_align<!-- {{#callable_declaration:fd_dbl_buf_align}} -->
Returns the alignment requirement for a double buffer.
- **Description**: Use this function to obtain the alignment requirement for a double buffer when allocating memory for it. This is necessary to ensure that the memory region used for the double buffer is correctly aligned, which is crucial for the proper functioning of the buffer in a concurrent environment. The function does not require any parameters and can be called at any time to retrieve the alignment value.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the alignment requirement in bytes for a double buffer.
- **See also**: [`fd_dbl_buf_align`](fd_dbl_buf.c.driver.md#fd_dbl_buf_align)  (Implementation)


---
### fd\_dbl\_buf\_footprint<!-- {{#callable_declaration:fd_dbl_buf_footprint}} -->
Calculate the memory footprint required for a double buffer with a given MTU.
- **Description**: This function calculates the memory footprint needed to allocate a double buffer that can handle messages up to a specified maximum transmission unit (MTU) size. It is useful for determining the amount of memory to allocate when setting up a double buffer. The function should be called before allocating memory for the double buffer to ensure that the allocated region is appropriately sized. The MTU parameter must be a positive integer representing the largest message size the buffer will handle.
- **Inputs**:
    - `mtu`: The maximum transmission unit size, representing the largest message size the double buffer can store. It must be a positive integer.
- **Output**: Returns the size in bytes of the memory footprint required for the double buffer.
- **See also**: [`fd_dbl_buf_footprint`](fd_dbl_buf.c.driver.md#fd_dbl_buf_footprint)  (Implementation)


---
### fd\_dbl\_buf\_new<!-- {{#callable_declaration:fd_dbl_buf_new}} -->
Formats a memory region for use as a double buffer.
- **Description**: This function initializes a memory region to be used as a double buffer, which supports a single producer and multiple consumer threads. The memory region pointed to by `shmem` must be properly aligned and have a size that matches the requirements defined by `fd_dbl_buf_align` and `fd_dbl_buf_footprint` for the given `mtu`. The function sets the initial sequence number of the buffer to `seq0` and initializes the buffer with zero byte size. It is important to ensure that `shmem` is not null and is correctly aligned, as the function will return null and log a warning if these conditions are not met.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted as a double buffer. Must not be null and must be aligned according to `FD_DBL_BUF_ALIGN`. The caller retains ownership.
    - `mtu`: The maximum transmission unit, representing the largest possible message size that the buffer can handle. It is aligned internally to `FD_DBL_BUF_ALIGN`.
    - `seq0`: The initial sequence number for the double buffer. It is used to track the order of messages.
- **Output**: Returns a pointer to the initialized double buffer structure on success, or null if `shmem` is null or misaligned.
- **See also**: [`fd_dbl_buf_new`](fd_dbl_buf.c.driver.md#fd_dbl_buf_new)  (Implementation)


---
### fd\_dbl\_buf\_join<!-- {{#callable_declaration:fd_dbl_buf_join}} -->
Joins a shared memory region as a double buffer.
- **Description**: This function is used to join a shared memory region that has been formatted as a double buffer, allowing access to its functionality. It should be called with a pointer to a memory region that has been previously initialized using `fd_dbl_buf_new`. The function checks that the provided memory region is non-null, properly aligned, and has the correct magic number to ensure it is a valid double buffer. If any of these checks fail, the function returns `NULL`, indicating an error. This function is typically used in environments where a single producer and multiple consumers need to access a shared buffer efficiently.
- **Inputs**:
    - `shbuf`: A pointer to the shared memory region to be joined as a double buffer. Must not be null, must be aligned to `FD_DBL_BUF_ALIGN`, and must have a valid magic number (`FD_DBL_BUF_MAGIC`). If these conditions are not met, the function returns `NULL`.
- **Output**: Returns a pointer to the `fd_dbl_buf_t` structure if successful, or `NULL` if the input is invalid.
- **See also**: [`fd_dbl_buf_join`](fd_dbl_buf.c.driver.md#fd_dbl_buf_join)  (Implementation)


---
### fd\_dbl\_buf\_leave<!-- {{#callable_declaration:fd_dbl_buf_leave}} -->
Leaves the double buffer context.
- **Description**: This function is used to leave the context of a double buffer that was previously joined. It should be called when the operations on the double buffer are complete, allowing the caller to cleanly exit the buffer context. This function does not perform any operations on the buffer itself other than returning a pointer to it. It is typically used in conjunction with `fd_dbl_buf_join` to manage the lifecycle of a double buffer context.
- **Inputs**:
    - `buf`: A pointer to an `fd_dbl_buf_t` structure representing the double buffer context to leave. The pointer must not be null, and it should have been previously obtained from a successful call to `fd_dbl_buf_join`. The function does not modify the buffer or check its validity beyond returning it.
- **Output**: Returns the same pointer to the `fd_dbl_buf_t` structure that was passed in.
- **See also**: [`fd_dbl_buf_leave`](fd_dbl_buf.c.driver.md#fd_dbl_buf_leave)  (Implementation)


---
### fd\_dbl\_buf\_delete<!-- {{#callable_declaration:fd_dbl_buf_delete}} -->
Unformats a double buffer and releases its memory region.
- **Description**: Use this function to unformat a memory region that was previously formatted as a double buffer using `fd_dbl_buf_new`. This function should be called when the double buffer is no longer needed, and the memory region should be released back to the caller. The function checks if the provided pointer is non-null and properly aligned before proceeding. If these conditions are not met, it logs a warning and returns NULL. This function is intended to be used in environments where the memory model preserves store order across threads.
- **Inputs**:
    - `shbuf`: A pointer to the memory region backing the double buffer. Must not be null and must be aligned to `FD_DBL_BUF_ALIGN`. If the pointer is null or misaligned, the function logs a warning and returns NULL.
- **Output**: Returns the original pointer `shbuf` if successful, or NULL if the input is invalid.
- **See also**: [`fd_dbl_buf_delete`](fd_dbl_buf.c.driver.md#fd_dbl_buf_delete)  (Implementation)


---
### fd\_dbl\_buf\_insert<!-- {{#callable_declaration:fd_dbl_buf_insert}} -->
Appends a message to the double buffer.
- **Description**: This function is used to insert a message into a double buffer, which is designed for concurrent lock-free operations with a single producer and multiple consumers. It should be called by the producer thread to add a new message to the buffer. The function ensures that the message size does not exceed the maximum transmission unit (MTU) of the buffer. It is important to note that this function is not thread-safe for multiple producers, so it should not be called concurrently from multiple threads.
- **Inputs**:
    - `buf`: A pointer to an fd_dbl_buf_t structure representing the double buffer. The caller must ensure that this pointer is valid and properly initialized before calling the function.
    - `msg`: A pointer to the message data to be inserted into the buffer. The caller retains ownership of the message data, and it must not be null.
    - `sz`: The size of the message in bytes. The function will clamp this size to the buffer's MTU if it exceeds it.
- **Output**: None
- **See also**: [`fd_dbl_buf_insert`](fd_dbl_buf.c.driver.md#fd_dbl_buf_insert)  (Implementation)


---
### fd\_dbl\_buf\_read<!-- {{#callable_declaration:fd_dbl_buf_read}} -->
Performs a blocking read of the most recent message from a double buffer.
- **Description**: This function is used to read the most recent message from a double buffer in a blocking manner, ensuring that the read is not overrun by a writer. It is suitable for use in scenarios where a single producer thread updates the buffer and multiple consumer threads read from it. The function will repeatedly attempt to read until it successfully retrieves a message, making it ideal for cases where message integrity is critical. It should be called when a consumer needs to ensure it has the latest complete message from the buffer.
- **Inputs**:
    - `buf`: A pointer to an fd_dbl_buf_t structure representing the double buffer. Must not be null and should be properly initialized before calling this function.
    - `obj`: A pointer to a buffer where the read message will be stored. The buffer should be large enough to hold the maximum message size defined by fd_dbl_buf_obj_mtu(buf). Must not be null.
    - `opt_seqp`: An optional pointer to a ulong where the sequence number of the read message will be stored. Can be null if the sequence number is not needed by the caller.
- **Output**: Returns the size of the message read from the buffer. The message is copied into the buffer pointed to by obj, and if opt_seqp is non-null, the sequence number of the message is stored there.
- **See also**: [`fd_dbl_buf_read`](fd_dbl_buf.c.driver.md#fd_dbl_buf_read)  (Implementation)


