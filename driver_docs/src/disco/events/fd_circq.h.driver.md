# Purpose
This C header file defines the interface for a circular queue (circular buffer) implementation, which is a data structure used to store a queue of messages with fixed size. The primary operations supported by this circular queue are `push_back` and `pop_front`, which allow for adding new messages to the back of the queue and removing messages from the front, respectively. The circular queue is designed to ensure that the `push_back` operation always succeeds by evicting the oldest messages if necessary to make room for new ones. This is particularly useful in scenarios where continuous data flow needs to be managed without the risk of buffer overflow, such as in real-time data processing or event handling systems.

The file defines a structure `fd_circq_private` that holds the queue's metadata, including the current count of elements, head and tail offsets, and metrics for dropped messages. The circular queue is aligned to a 4096-byte boundary, which is specified by the `FD_CIRCQ_ALIGN` macro. The file provides function prototypes for creating, joining, leaving, and deleting circular queues, as well as for pushing and popping messages. These functions form the public API of the circular queue, allowing other parts of a program to interact with the queue without needing to know its internal implementation details. The design ensures that the queue's operations are efficient and that memory usage is optimized by storing message metadata within the data buffer itself.
# Imports and Dependencies

---
- `../fd_disco_base.h`


# Global Variables

---
### fd\_circq\_new
- **Type**: `function pointer`
- **Description**: The `fd_circq_new` is a function that initializes a new circular queue in shared memory. It takes a pointer to shared memory (`shmem`) and a size (`sz`) as parameters, and returns a pointer to the newly created circular queue.
- **Use**: This function is used to allocate and initialize a circular queue structure in a specified shared memory region.


---
### fd\_circq\_join
- **Type**: `fd_circq_t *`
- **Description**: The `fd_circq_join` function is a global function that returns a pointer to an `fd_circq_t` structure, which represents a circular queue. This function is used to join or attach to an existing circular queue that is stored in shared memory, as indicated by the `shbuf` parameter.
- **Use**: This function is used to access and manipulate a circular queue stored in shared memory by returning a pointer to its data structure.


---
### fd\_circq\_leave
- **Type**: `function pointer`
- **Description**: The `fd_circq_leave` is a function that takes a pointer to an `fd_circq_t` structure as an argument and returns a void pointer. This function is likely used to perform cleanup or disassociation operations related to the circular queue represented by the `fd_circq_t` structure.
- **Use**: This function is used to leave or disassociate from a circular queue, possibly freeing resources or performing necessary cleanup.


---
### fd\_circq\_delete
- **Type**: `function pointer`
- **Description**: The `fd_circq_delete` is a function that takes a pointer to a shared buffer (`shbuf`) and is responsible for deleting or cleaning up the circular queue associated with that buffer. It returns a void pointer, which typically indicates the result of the deletion operation or the state of the buffer after deletion.
- **Use**: This function is used to delete or clean up a circular queue from a shared buffer, likely freeing resources or resetting the buffer state.


---
### fd\_circq\_push\_back
- **Type**: `function`
- **Description**: The `fd_circq_push_back` function is designed to append a message to a circular buffer, which is a fixed-size data structure that stores a queue of messages. This function ensures that the push operation always succeeds by evicting old messages if necessary to make room for the new one. It returns the address of the memory contents in the buffer on success, or NULL on failure if the message size exceeds the buffer capacity or if the alignment is invalid.
- **Use**: This function is used to add new messages to the circular buffer, ensuring that the buffer's fixed size is respected by evicting older messages if needed.


---
### fd\_circq\_pop\_front
- **Type**: `function`
- **Description**: The `fd_circq_pop_front` function is designed to remove and return the oldest message from a circular buffer, which is implemented as a fixed-size queue. The function returns a pointer to the memory contents of the oldest message, or NULL if the buffer is empty.
- **Use**: This function is used to retrieve and remove the oldest message from the circular buffer, ensuring that the memory contents remain valid until the next insertion operation.


# Data Structures

---
### fd\_circq\_private
- **Type**: `struct`
- **Members**:
    - `cnt`: Current count of elements in the queue.
    - `head`: Offset relative to the end of this struct for the metadata of the first message in the queue.
    - `tail`: Offset relative to the end of this struct for the metadata of the last message in the queue.
    - `size`: Size of the circular queue.
    - `metrics`: Contains a single field 'drop_cnt' which tracks the number of dropped messages.
- **Description**: The `fd_circq_private` structure is a data structure used to implement a circular queue with a fixed size, designed to store messages efficiently. It maintains the current count of elements, offsets for the head and tail of the queue, and the total size of the queue. Additionally, it includes a metrics sub-structure to track the number of messages dropped due to space constraints. The structure is aligned to 4096 bytes to optimize memory access and performance.


---
### fd\_circq\_t
- **Type**: `struct`
- **Members**:
    - `cnt`: Current count of elements in the queue.
    - `head`: Offset relative to the end of the struct for the metadata of the first message in the queue.
    - `tail`: Offset relative to the end of the struct for the metadata of the last message in the queue.
    - `size`: Size of the circular buffer.
    - `metrics`: Contains a field 'drop_cnt' which tracks the number of dropped messages.
- **Description**: The `fd_circq_t` structure represents a circular queue designed to store a fixed-size queue of messages, where new messages can be added using `push_back` and old messages can be removed using `pop_front`. The structure ensures that `push_back` operations always succeed by evicting old messages if necessary. It includes metadata about the messages within the data buffer itself, without a separate metadata region, and uses offsets to track the head and tail of the queue. The structure is aligned to 4096 bytes and includes a metrics field to track dropped messages.


# Function Declarations (Public API)

---
### fd\_circq\_align<!-- {{#callable_declaration:fd_circq_align}} -->
Returns the alignment requirement for the circular buffer.
- **Description**: Use this function to obtain the alignment requirement for the circular buffer used in the circular queue implementation. This alignment value is necessary when allocating memory for the circular buffer to ensure proper alignment and performance. The function can be called at any time and does not depend on the state of any circular buffer instance.
- **Inputs**: None
- **Output**: Returns an unsigned long integer representing the alignment requirement, which is a constant value.
- **See also**: [`fd_circq_align`](fd_circq.c.driver.md#fd_circq_align)  (Implementation)


---
### fd\_circq\_footprint<!-- {{#callable_declaration:fd_circq_footprint}} -->
Calculate the memory footprint required for a circular queue of a given size.
- **Description**: Use this function to determine the total memory size needed to allocate a circular queue that can store a specified amount of data. This is useful when planning memory allocation for the queue, ensuring that enough space is reserved to accommodate both the queue's metadata and the data itself. The function should be called before creating a new circular queue to understand the memory requirements.
- **Inputs**:
    - `sz`: The size in bytes of the data portion of the circular queue. It must be a non-negative value, as it represents the amount of data the queue is expected to handle.
- **Output**: Returns the total memory footprint in bytes required to store the circular queue, including its metadata.
- **See also**: [`fd_circq_footprint`](fd_circq.c.driver.md#fd_circq_footprint)  (Implementation)


---
### fd\_circq\_new<!-- {{#callable_declaration:fd_circq_new}} -->
Initialize a circular queue in shared memory.
- **Description**: This function initializes a circular queue structure in a provided shared memory region. It sets up the queue to be empty and ready for use, with a specified maximum size. The function should be called when a new circular queue is needed, and the shared memory region must be properly allocated and aligned according to the requirements of the circular queue. The size parameter determines the maximum number of elements the queue can hold. The function returns a pointer to the initialized shared memory region, which can then be used with other circular queue operations.
- **Inputs**:
    - `shmem`: A pointer to a shared memory region where the circular queue will be initialized. This memory must be allocated and aligned according to the circular queue's requirements. The caller retains ownership of this memory.
    - `sz`: The maximum number of elements the circular queue can hold. It must be a positive integer.
- **Output**: Returns a pointer to the initialized shared memory region, which is the same as the input 'shmem' pointer.
- **See also**: [`fd_circq_new`](fd_circq.c.driver.md#fd_circq_new)  (Implementation)


---
### fd\_circq\_join<!-- {{#callable_declaration:fd_circq_join}} -->
Joins a shared memory buffer as a circular queue.
- **Description**: This function is used to interpret a given shared memory buffer as a circular queue structure. It is typically called after allocating or obtaining a shared memory buffer that is intended to be used as a circular queue. The function does not perform any validation on the input buffer, so it is the caller's responsibility to ensure that the buffer is correctly aligned and sized according to the requirements of the circular queue. This function does not modify the buffer or perform any initialization; it simply casts the buffer to the appropriate type.
- **Inputs**:
    - `shbuf`: A pointer to a shared memory buffer that is intended to be used as a circular queue. The buffer must be properly aligned and sized according to the circular queue's requirements. The caller retains ownership of the buffer, and the function does not check for null pointers or validate the buffer's contents.
- **Output**: Returns a pointer to the circular queue structure interpreted from the shared memory buffer.
- **See also**: [`fd_circq_join`](fd_circq.c.driver.md#fd_circq_join)  (Implementation)


---
### fd\_circq\_leave<!-- {{#callable_declaration:fd_circq_leave}} -->
Leaves the circular queue and returns a pointer to it.
- **Description**: Use this function to leave or detach from a circular queue that was previously joined. It is typically called when the operations on the circular queue are complete, and the user wants to release any resources or references associated with it. This function does not modify the state of the circular queue or its contents, and it is safe to call multiple times. Ensure that the `buf` parameter is a valid pointer to a circular queue structure obtained from a successful call to `fd_circq_join`.
- **Inputs**:
    - `buf`: A pointer to a `fd_circq_t` structure representing the circular queue. It must be a valid pointer obtained from a previous call to `fd_circq_join`. Passing a null or invalid pointer results in undefined behavior.
- **Output**: Returns a pointer to the `fd_circq_t` structure that was passed in, allowing for potential further use or inspection.
- **See also**: [`fd_circq_leave`](fd_circq.c.driver.md#fd_circq_leave)  (Implementation)


---
### fd\_circq\_delete<!-- {{#callable_declaration:fd_circq_delete}} -->
Deletes a circular buffer from shared memory.
- **Description**: Use this function to delete a circular buffer that was previously created in shared memory. This function should be called when the circular buffer is no longer needed, to ensure proper cleanup of resources. It is important to ensure that no other operations are being performed on the buffer at the time of deletion to avoid undefined behavior. The function returns the same pointer that was passed to it, allowing for potential chaining or further handling by the caller.
- **Inputs**:
    - `shbuf`: A pointer to the shared memory region where the circular buffer resides. The pointer must not be null, and it should point to a valid circular buffer that was previously created. The caller retains ownership of the memory and is responsible for managing its lifecycle.
- **Output**: Returns the same pointer that was passed as input, allowing for further handling or chaining by the caller.
- **See also**: [`fd_circq_delete`](fd_circq.c.driver.md#fd_circq_delete)  (Implementation)


---
### fd\_circq\_push\_back<!-- {{#callable_declaration:fd_circq_push_back}} -->
Appends a message to the circular buffer, evicting old messages if necessary.
- **Description**: This function is used to add a new message to a circular buffer, ensuring that the operation always succeeds by evicting older messages if needed to make space. It should be called when you need to store a new message in the buffer, and it handles the necessary alignment and footprint requirements. The function will fail and return NULL if the alignment is not a power of 2, exceeds the maximum allowed alignment, or if the total size of the message and its metadata exceeds the buffer's capacity.
- **Inputs**:
    - `circq`: A pointer to the circular buffer where the message will be appended. Must not be null and should point to a valid, initialized circular buffer.
    - `align`: The alignment requirement for the message. Must be a power of 2 and not exceed 4096. If invalid, the function returns NULL.
    - `footprint`: The size of the message to be appended. Combined with metadata, it must not exceed the buffer's total size. If it does, the function returns NULL.
- **Output**: Returns a pointer to the location in the buffer where the message is stored on success, or NULL on failure.
- **See also**: [`fd_circq_push_back`](fd_circq.c.driver.md#fd_circq_push_back)  (Implementation)


---
### fd\_circq\_pop\_front<!-- {{#callable_declaration:fd_circq_pop_front}} -->
Pops the oldest message from the circular buffer.
- **Description**: Use this function to retrieve and remove the oldest message from a circular buffer. It should be called when you need to process or access the oldest message stored in the buffer. This function is safe to call only when the buffer is not empty, as it will return NULL if there are no messages to pop. The returned message data remains valid until the next call to fd_circq_push_back, which may overwrite the data.
- **Inputs**:
    - `circq`: A pointer to an fd_circq_t structure representing the circular buffer. Must not be null and should point to a valid, initialized circular buffer.
- **Output**: Returns a pointer to the memory contents of the oldest message in the buffer, or NULL if the buffer is empty.
- **See also**: [`fd_circq_pop_front`](fd_circq.c.driver.md#fd_circq_pop_front)  (Implementation)


