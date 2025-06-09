# Purpose
The provided C header file, `fd_h2_rbuf.h`, defines a byte-oriented, unaligned ring buffer structure and its associated operations. This file is intended to be included in other C source files to provide functionality for managing a circular buffer, which is a data structure that uses a single, fixed-size buffer as if it were connected end-to-end. The primary structure defined is `fd_h2_rbuf_t`, which includes pointers to manage the buffer's start and end, as well as offsets and size information to track the buffer's state.

The file offers a comprehensive set of inline functions to initialize the buffer, check its used and free space, append data, and manage data consumption. Functions like `fd_h2_rbuf_init`, [`fd_h2_rbuf_push`](#fd_h2_rbuf_push), [`fd_h2_rbuf_pop`](#fd_h2_rbuf_pop), and [`fd_h2_rbuf_skip`](#fd_h2_rbuf_skip) provide mechanisms to manipulate the buffer's contents efficiently. The header also includes utility functions to check if the buffer is empty and to handle data in contiguous and non-contiguous memory regions. This header file is designed to be a reusable component in larger systems where efficient, low-level data buffering is required, such as in network data processing or streaming applications.
# Imports and Dependencies

---
- `fd_h2_base.h`
- `../../util/log/fd_log.h`


# Data Structures

---
### fd\_h2\_rbuf
- **Type**: `struct`
- **Members**:
    - `buf0`: Points to the first byte of the buffer.
    - `buf1`: Points one past the last byte of the buffer.
    - `lo`: Points to the current start of the unconsumed data within the buffer.
    - `hi`: Points to the current end of the unconsumed data within the buffer.
    - `lo_off`: Offset of the 'lo' pointer from the start of the buffer.
    - `hi_off`: Offset of the 'hi' pointer from the start of the buffer.
    - `bufsz`: Size of the buffer in bytes.
- **Description**: The `fd_h2_rbuf` structure defines a byte-oriented, unaligned ring buffer used for managing a continuous stream of data. It maintains pointers to the start and end of the buffer (`buf0` and `buf1`), as well as pointers to the current read (`lo`) and write (`hi`) positions within the buffer. The structure also tracks the offsets of these positions (`lo_off` and `hi_off`) and the total buffer size (`bufsz`). This design allows for efficient data management in scenarios where data is continuously written to and read from the buffer, such as in network communication or streaming applications.


# Functions

---
### fd\_h2\_rbuf\_used\_sz<!-- {{#callable:fd_h2_rbuf_used_sz}} -->
The `fd_h2_rbuf_used_sz` function calculates the number of unconsumed bytes in a ring buffer by subtracting the low offset from the high offset.
- **Inputs**:
    - `rbuf`: A pointer to a constant `fd_h2_rbuf_t` structure representing the ring buffer whose used size is to be calculated.
- **Control Flow**:
    - The function accesses the `hi_off` and `lo_off` members of the `fd_h2_rbuf_t` structure pointed to by `rbuf`.
    - It calculates the difference between `hi_off` and `lo_off` to determine the number of unconsumed bytes in the buffer.
- **Output**: The function returns an `ulong` representing the number of unconsumed bytes in the ring buffer.


---
### fd\_h2\_rbuf\_free\_sz<!-- {{#callable:fd_h2_rbuf_free_sz}} -->
The function `fd_h2_rbuf_free_sz` calculates the number of free bytes available for appending in a ring buffer.
- **Inputs**:
    - `rbuf`: A pointer to a constant `fd_h2_rbuf_t` structure representing the ring buffer.
- **Control Flow**:
    - Call [`fd_h2_rbuf_used_sz`](#fd_h2_rbuf_used_sz) to determine the number of bytes currently used in the buffer and store it in `used`.
    - Calculate the total buffer size by subtracting `buf0` from `buf1`.
    - Subtract the `used` bytes from the total buffer size to determine the free space.
    - Use `fd_long_max` to ensure the result is not negative, returning the maximum of 0 and the calculated free space.
- **Output**: Returns an `ulong` representing the number of free bytes available for appending in the ring buffer.
- **Functions called**:
    - [`fd_h2_rbuf_used_sz`](#fd_h2_rbuf_used_sz)


---
### fd\_h2\_rbuf\_push<!-- {{#callable:fd_h2_rbuf_push}} -->
The `fd_h2_rbuf_push` function appends a chunk of data to a ring buffer, handling potential buffer wrap-around.
- **Inputs**:
    - `rbuf`: A pointer to the `fd_h2_rbuf_t` structure representing the ring buffer.
    - `chunk`: A pointer to the data to be appended to the ring buffer.
    - `chunk_sz`: The size of the data chunk to be appended, in bytes.
- **Control Flow**:
    - Initialize local pointers to the buffer's start (`buf0`), end (`buf1`), and current high (`hi`) and low (`lo`) positions.
    - Increment the `hi_off` offset by `chunk_sz` to reflect the addition of new data.
    - Check if the new data will wrap around the end of the buffer (`hi + chunk_sz > buf1`).
    - If wrapping is needed, check for overflow by ensuring `lo` is not greater than `hi`; log a critical error if overflow is detected.
    - Calculate the split point for the data if wrapping is needed, and copy the data in two parts: from `hi` to `buf1` and from `buf0` onward.
    - If no wrapping is needed, perform a single copy from `hi` to `hi + chunk_sz`.
    - Update the `hi` pointer to the new position, wrapping it to `buf0` if it reaches `buf1`.
- **Output**: The function does not return a value; it modifies the ring buffer in place by updating its internal state to include the new data.


---
### fd\_h2\_rbuf\_peek\_used<!-- {{#callable:fd_h2_rbuf_peek_used}} -->
The `fd_h2_rbuf_peek_used` function returns a pointer to the first contiguous fragment of unconsumed data in a ring buffer and provides the sizes of contiguous and split data fragments.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer.
    - `sz`: A pointer to an `ulong` where the size of the contiguous unconsumed data will be stored.
    - `split_sz`: A pointer to an `ulong` where the size of the split unconsumed data will be stored if the data wraps around the buffer.
- **Control Flow**:
    - Calculate the total used size of the buffer using [`fd_h2_rbuf_used_sz`](#fd_h2_rbuf_used_sz) function.
    - Determine the end of the used data by adding the used size to the `lo` pointer.
    - Check if the end of the used data is within the buffer (`end <= buf1`).
    - If true, set `sz` to the difference between `hi` and `lo`, and `split_sz` to 0, indicating no split data.
    - If false, set `sz` to the difference between `buf1` and `lo`, and `split_sz` to the difference between `hi` and `buf0`, indicating split data across the buffer boundary.
    - Return the `lo` pointer, which points to the start of the contiguous unconsumed data.
- **Output**: Returns a pointer to the start of the first contiguous fragment of unconsumed data in the ring buffer.
- **Functions called**:
    - [`fd_h2_rbuf_used_sz`](#fd_h2_rbuf_used_sz)


---
### fd\_h2\_rbuf\_peek\_free<!-- {{#callable:fd_h2_rbuf_peek_free}} -->
The function `fd_h2_rbuf_peek_free` returns a pointer to the start of the free region in a ring buffer and calculates the size of contiguous and split free regions.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer.
    - `sz`: A pointer to an `ulong` where the size of the contiguous free region will be stored.
    - `split_sz`: A pointer to an `ulong` where the size of the split free region will be stored, if any.
- **Control Flow**:
    - Calculate the total free size in the buffer using [`fd_h2_rbuf_free_sz`](#fd_h2_rbuf_free_sz) function.
    - Determine the end of the free region by adding the free size to the current high pointer (`hi`).
    - Check if the end of the free region is within the buffer (`end <= buf1`).
    - If true, set `sz` to the size of the contiguous free region from `hi` to `buf1` and `split_sz` to 0.
    - If false, set `sz` to the size from `hi` to `buf1` and `split_sz` to the size from `buf0` to `lo`.
    - Return the current high pointer (`hi`) as the start of the free region.
- **Output**: Returns a pointer to the start of the free region in the ring buffer.
- **Functions called**:
    - [`fd_h2_rbuf_free_sz`](#fd_h2_rbuf_free_sz)


---
### fd\_h2\_rbuf\_skip<!-- {{#callable:fd_h2_rbuf_skip}} -->
The `fd_h2_rbuf_skip` function advances the read pointer of a ring buffer by a specified number of bytes, wrapping around if necessary.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer.
    - `n`: The number of bytes to skip in the ring buffer.
- **Control Flow**:
    - Retrieve the current position of the read pointer (`lo`) and the buffer size (`bufsz`).
    - Increment the logical offset (`lo_off`) and the read pointer (`lo`) by `n`.
    - Check if the new position of `lo` exceeds or equals the end of the buffer (`buf1`).
    - If so, wrap `lo` around by subtracting the buffer size (`bufsz`).
    - Update the read pointer (`lo`) in the ring buffer structure.
- **Output**: The function does not return a value; it modifies the state of the ring buffer in place.


---
### fd\_h2\_rbuf\_alloc<!-- {{#callable:fd_h2_rbuf_alloc}} -->
The `fd_h2_rbuf_alloc` function marks the next `n` free bytes in a ring buffer as used, updating the buffer's high offset and pointer accordingly.
- **Inputs**:
    - `rbuf`: A pointer to an `fd_h2_rbuf_t` structure representing the ring buffer.
    - `n`: An unsigned long integer representing the number of bytes to mark as used.
- **Control Flow**:
    - Retrieve the current high pointer (`hi`) and buffer size (`bufsz`) from the ring buffer structure.
    - Increment the high offset (`hi_off`) by `n` to reflect the newly allocated bytes.
    - Advance the high pointer (`hi`) by `n` bytes.
    - Check if the new high pointer exceeds the buffer's end (`buf1`); if so, wrap it around by subtracting the buffer size (`bufsz`).
    - Update the ring buffer's high pointer (`hi`) with the new value.
- **Output**: The function does not return a value; it modifies the ring buffer's state in place.


---
### fd\_h2\_rbuf\_pop<!-- {{#callable:fd_h2_rbuf_pop}} -->
The `fd_h2_rbuf_pop` function consumes a specified number of bytes from a ring buffer, returning a pointer to the bytes if they are contiguous or copying them into a scratch buffer if they are not.
- **Inputs**:
    - `rbuf`: A pointer to the `fd_h2_rbuf_t` structure representing the ring buffer from which bytes are to be consumed.
    - `scratch`: A pointer to a scratch memory area with space for at least `n` bytes, used if the bytes to be consumed are not contiguous.
    - `n`: The number of bytes to consume from the ring buffer.
- **Control Flow**:
    - Initialize local variables `lo`, `buf0`, `buf1`, `bufsz`, and `ret` from the `rbuf` structure.
    - Increment the `lo_off` field of `rbuf` by `n` to reflect the consumption of bytes.
    - Calculate the `end` pointer as `lo + n`.
    - Check if `end` is greater than or equal to `buf1`, and if so, adjust `end` by subtracting `bufsz` to wrap around the buffer.
    - If `end` is greater than `buf1`, indicating a wrap-around, calculate `part0` and `part1` to determine the split between the two buffer segments.
    - Copy the first segment of bytes from `lo` to `scratch` and the second segment from `buf0` to `scratch + part0`, then set `ret` to `scratch`.
    - Update `rbuf->lo` to point to `end`.
    - Return `ret`, which points to the contiguous bytes or the scratch buffer.
- **Output**: A pointer to the consumed bytes, either directly from the ring buffer if contiguous or from the scratch buffer if not.


---
### fd\_h2\_rbuf\_pop\_copy<!-- {{#callable:fd_h2_rbuf_pop_copy}} -->
The `fd_h2_rbuf_pop_copy` function copies a specified number of bytes from a ring buffer to an output buffer, handling potential wrap-around in the buffer.
- **Inputs**:
    - `rbuf`: A pointer to the `fd_h2_rbuf_t` structure representing the ring buffer from which bytes are to be copied.
    - `out`: A pointer to the destination buffer where the bytes will be copied.
    - `n`: The number of bytes to copy from the ring buffer to the output buffer.
- **Control Flow**:
    - Initialize local variables `lo`, `buf0`, `buf1`, and `bufsz` from the `rbuf` structure.
    - Increment the `lo_off` field of `rbuf` by `n` to update the offset of the low pointer.
    - Calculate the `end` pointer as `lo + n` and adjust it if it exceeds `buf1` by subtracting `bufsz`.
    - Check if the end pointer exceeds `buf1`, indicating a wrap-around in the buffer.
    - If wrap-around occurs, calculate `part0` as the number of bytes from `lo` to `buf1` and `part1` as the remaining bytes to copy from `buf0`.
    - Copy `part0` bytes from `lo` to `out` and `part1` bytes from `buf0` to the continuation of `out`.
    - If no wrap-around occurs, copy `n` bytes directly from `lo` to `out`.
    - Update the `lo` pointer in `rbuf` to the calculated `end` position.
- **Output**: The function does not return a value; it modifies the `out` buffer by copying `n` bytes from the ring buffer.


---
### fd\_h2\_rbuf\_is\_empty<!-- {{#callable:fd_h2_rbuf_is_empty}} -->
The function `fd_h2_rbuf_is_empty` checks if a ring buffer is empty by comparing its low and high offsets.
- **Inputs**:
    - `rbuf`: A pointer to a constant `fd_h2_rbuf_t` structure representing the ring buffer to be checked.
- **Control Flow**:
    - The function compares the `lo_off` and `hi_off` members of the `rbuf` structure.
    - If `lo_off` is equal to `hi_off`, the function returns true (non-zero), indicating the buffer is empty.
    - If `lo_off` is not equal to `hi_off`, the function returns false (zero), indicating the buffer is not empty.
- **Output**: An integer value indicating whether the ring buffer is empty (non-zero if empty, zero if not).


