# Purpose
This C source code file implements a circular queue (or circular buffer) data structure, which is a common data structure used for buffering data streams. The file provides a set of functions to manage the lifecycle and operations of a circular queue, including creation, joining, leaving, and deletion of the queue, as well as pushing and popping messages to and from the queue. The circular queue is designed to operate in shared memory, allowing multiple processes or threads to interact with the queue concurrently. The code includes mechanisms to handle message alignment and footprint within the buffer, ensuring efficient use of memory and proper data alignment.

The file defines a private structure `fd_circq_message_private` to manage individual messages within the queue, and a typedef `fd_circq_message_t` for ease of use. Key functions include [`fd_circq_new`](#fd_circq_new) for initializing a new queue, [`fd_circq_push_back`](#fd_circq_push_back) for adding messages to the queue, and [`fd_circq_pop_front`](#fd_circq_pop_front) for removing messages. The [`evict`](#evict) function is used to manage buffer space by removing old messages when necessary. The code also includes utility functions like [`fd_circq_align`](#fd_circq_align) and [`fd_circq_footprint`](#fd_circq_footprint) to calculate alignment and memory footprint requirements. The file is intended to be part of a larger system, likely as a library component, providing a robust and efficient mechanism for message passing in concurrent applications.
# Imports and Dependencies

---
- `fd_circq.h`


# Data Structures

---
### fd\_circq\_message\_private
- **Type**: `struct`
- **Members**:
    - `align`: Specifies the alignment requirement for the message within the circular buffer.
    - `footprint`: Indicates the size of the message in the circular buffer.
    - `next`: Holds the offset within the circular buffer where the next message starts.
- **Description**: The `fd_circq_message_private` structure is a component of a circular queue implementation, designed to manage messages within a circular buffer. It ensures that each message is properly aligned and tracks the size of the message (footprint) and the position of the next message in the buffer (next). This structure is crucial for maintaining the integrity and efficiency of the circular queue, especially when messages wrap around the end of the buffer.


---
### fd\_circq\_message\_t
- **Type**: `struct`
- **Members**:
    - `align`: Specifies the alignment requirement for the message within the circular buffer.
    - `footprint`: Indicates the size of the message in the circular buffer.
    - `next`: Holds the offset within the circular buffer where the next message starts.
- **Description**: The `fd_circq_message_t` structure is a private data structure used to represent a message within a circular queue buffer. It contains metadata about the message, including its alignment (`align`), size (`footprint`), and the offset to the next message (`next`). This structure is crucial for managing the placement and retrieval of messages in a circular buffer, ensuring that messages are correctly aligned and that the buffer can wrap around efficiently.


# Functions

---
### fd\_circq\_align<!-- {{#callable:fd_circq_align}} -->
The `fd_circq_align` function returns the alignment requirement for a circular queue.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a constant function, meaning it does not modify any global state or depend on any external state.
    - It simply returns the value of the macro `FD_CIRCQ_ALIGN`.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for a circular queue, as defined by the macro `FD_CIRCQ_ALIGN`.


---
### fd\_circq\_footprint<!-- {{#callable:fd_circq_footprint}} -->
The `fd_circq_footprint` function calculates the memory footprint required for a circular queue structure and its associated data.
- **Inputs**:
    - `sz`: The size of the data region in the circular queue, specified as an unsigned long integer.
- **Control Flow**:
    - The function takes a single input parameter `sz`, which represents the size of the data region.
    - It calculates the total memory footprint by adding the size of the `fd_circq_t` structure to the input size `sz`.
    - The function returns the calculated total size.
- **Output**: The function returns an unsigned long integer representing the total memory footprint required for the circular queue structure and its data region.


---
### fd\_circq\_new<!-- {{#callable:fd_circq_new}} -->
The `fd_circq_new` function initializes a circular queue structure in shared memory with a specified size.
- **Inputs**:
    - `shmem`: A pointer to the shared memory location where the circular queue structure will be initialized.
    - `sz`: The size of the circular queue to be initialized.
- **Control Flow**:
    - Cast the shared memory pointer `shmem` to a `fd_circq_t` pointer named `circq`.
    - Initialize the `cnt` (count) field of `circq` to 0, indicating the queue is empty.
    - Set the `head` and `tail` fields of `circq` to 0, marking the start of the queue.
    - Assign the provided size `sz` to the `size` field of `circq`.
    - Return the original shared memory pointer `shmem`.
- **Output**: Returns the original shared memory pointer `shmem` after initializing the circular queue structure.


---
### fd\_circq\_join<!-- {{#callable:fd_circq_join}} -->
The `fd_circq_join` function casts a shared buffer pointer to a circular queue pointer type.
- **Inputs**:
    - `shbuf`: A pointer to a shared buffer that is intended to be used as a circular queue.
- **Control Flow**:
    - The function takes a single argument, `shbuf`, which is a pointer to a shared buffer.
    - It casts the `shbuf` pointer to a `fd_circq_t` pointer type.
    - The function returns the casted pointer.
- **Output**: A pointer to `fd_circq_t`, which is the circular queue type.


---
### fd\_circq\_leave<!-- {{#callable:fd_circq_leave}} -->
The `fd_circq_leave` function returns a pointer to the circular queue buffer passed to it.
- **Inputs**:
    - `buf`: A pointer to an `fd_circq_t` structure representing the circular queue buffer.
- **Control Flow**:
    - The function takes a single argument, `buf`, which is a pointer to a circular queue buffer.
    - It casts the `buf` pointer to a `void *` type and returns it.
- **Output**: A `void *` pointer to the circular queue buffer that was passed as an argument.


---
### fd\_circq\_delete<!-- {{#callable:fd_circq_delete}} -->
The `fd_circq_delete` function returns the input pointer without modification.
- **Inputs**:
    - `shbuf`: A pointer to a shared buffer, presumably representing a circular queue.
- **Control Flow**:
    - The function takes a single input parameter, `shbuf`.
    - It immediately returns the `shbuf` parameter without performing any operations on it.
- **Output**: The function returns the same pointer that was passed to it as an argument.


---
### verify<!-- {{#callable:FD_FN_UNUSED::verify}} -->
The `verify` function checks the integrity and consistency of a circular queue structure by validating its head, tail, and message alignment properties.
- **Inputs**:
    - `circq`: A pointer to an `fd_circq_t` structure representing the circular queue to be verified.
- **Control Flow**:
    - Check if the `head` and `tail` indices are within the bounds of the circular queue size.
    - Ensure that if the `tail` equals the `head`, the count of messages (`cnt`) is at most 1.
    - If the queue is empty (`cnt` is 0), verify that both `head` and `tail` are set to 0.
    - If the queue has exactly one message (`cnt` is 1), ensure `head` equals `tail`.
    - Initialize a buffer pointer to the memory location immediately after the `fd_circq_t` structure.
    - Iterate over each message in the queue, checking alignment and size constraints for each message.
    - For each message, calculate the start and end positions, ensuring they are valid and within the queue's size.
    - Update the `current` position to the `next` message's offset, and track if the queue has wrapped around.
- **Output**: The function does not return a value; it performs assertions to verify the integrity of the circular queue.


---
### evict<!-- {{#callable:evict}} -->
The `evict` function removes messages from a circular queue that overlap with a specified range, updating the queue's state accordingly.
- **Inputs**:
    - `circq`: A pointer to the circular queue structure (`fd_circq_t`) from which messages may be evicted.
    - `from`: The start of the range to check for overlapping messages.
    - `to`: The end of the range to check for overlapping messages.
- **Control Flow**:
    - The function enters an infinite loop to process messages in the queue.
    - It first checks if the queue is empty (`circq->cnt` is zero); if so, it returns immediately.
    - It retrieves the message at the head of the queue and calculates its start and end positions in the buffer.
    - It checks if the message overlaps with the specified range (`from` to `to`).
    - If there is an overlap, it decrements the message count (`circq->cnt`) and increments the drop count (`circq->metrics.drop_cnt`).
    - If the queue becomes empty after removing the message, it resets the head and tail pointers to zero; otherwise, it updates the head pointer to the next message.
    - If there is no overlap, the loop breaks, ending the eviction process.
- **Output**: The function does not return a value; it modifies the state of the circular queue in place.


---
### fd\_circq\_push\_back<!-- {{#callable:fd_circq_push_back}} -->
The `fd_circq_push_back` function attempts to add a new message to the end of a circular queue, ensuring proper alignment and handling buffer overflow by evicting old messages if necessary.
- **Inputs**:
    - `circq`: A pointer to the circular queue structure (`fd_circq_t`) where the message will be added.
    - `align`: The alignment requirement for the new message, which must be a power of 2 and not exceed `FD_CIRCQ_ALIGN`.
    - `footprint`: The size of the message to be added to the circular queue.
- **Control Flow**:
    - Check if `align` is a power of 2 and does not exceed `FD_CIRCQ_ALIGN`; if not, log a warning and return `NULL`.
    - Calculate the total required space for the new message, including alignment and footprint; if it exceeds the queue size, log a warning and return `NULL`.
    - Determine the current position in the buffer where the new message can be added, considering the alignment of the last message if the queue is not empty.
    - If the required space exceeds the remaining buffer size, evict messages from the current position to the end of the buffer and from the start to the required position, then reset the tail to 0.
    - If there is enough space, evict messages from the current position to the end of the required space.
    - Update the tail position and the `next` pointer of the last message if the queue is not empty.
    - Increment the message count and set the alignment and footprint for the new message.
    - Return a pointer to the start of the new message's data area.
- **Output**: A pointer to the start of the new message's data area in the circular queue, or `NULL` if the message could not be added due to alignment or size constraints.
- **Functions called**:
    - [`evict`](#evict)


---
### fd\_circq\_pop\_front<!-- {{#callable:fd_circq_pop_front}} -->
The `fd_circq_pop_front` function removes and returns the front message from a circular queue if it is not empty.
- **Inputs**:
    - `circq`: A pointer to the circular queue (`fd_circq_t`) from which the front message is to be popped.
- **Control Flow**:
    - Check if the circular queue is empty by evaluating `circq->cnt`; if it is, return `NULL`.
    - Decrement the message count `circq->cnt` by one.
    - Calculate the address of the front message using the `circq->head` offset and cast it to `fd_circq_message_t *`.
    - If the queue becomes empty after popping, reset both `circq->head` and `circq->tail` to `0UL`.
    - Otherwise, update `circq->head` to point to the next message using `message->next`.
    - Assert that the new `circq->head` is within the valid range of the circular queue size.
    - Return a pointer to the message data, which is located immediately after the `fd_circq_message_t` structure.
- **Output**: A pointer to the data of the message that was at the front of the queue, or `NULL` if the queue was empty.


