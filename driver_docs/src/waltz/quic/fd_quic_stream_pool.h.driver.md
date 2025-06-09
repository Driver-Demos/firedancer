# Purpose
This C header file defines a structure and associated functions for managing a pool of QUIC streams, which are part of a network protocol for fast and reliable internet communication. The `fd_quic_stream_pool` structure includes fields for the pool's capacity, the current count of streams, and a linked list head for managing free streams. The file provides function prototypes for creating, deleting, allocating, and freeing streams within the pool, as well as utility functions to determine the pool's alignment and footprint requirements. The design ensures efficient management of stream resources, allowing for dynamic allocation and deallocation while maintaining alignment and memory constraints.
# Imports and Dependencies

---
- `fd_quic_stream.h`


# Global Variables

---
### fd\_quic\_stream\_pool\_new
- **Type**: `fd_quic_stream_pool_t *`
- **Description**: The `fd_quic_stream_pool_new` is a function that initializes and returns a pointer to a new `fd_quic_stream_pool_t` structure. This structure is used to manage a pool of QUIC streams, with a specified capacity and transmission buffer size.
- **Use**: This function is used to create a new stream pool, allocating memory and setting up the initial state for managing multiple QUIC streams.


---
### fd\_quic\_stream\_pool\_alloc
- **Type**: `function pointer`
- **Description**: The `fd_quic_stream_pool_alloc` is a function that allocates a stream from a given stream pool. It takes a pointer to a `fd_quic_stream_pool_t` structure as an argument and returns a pointer to a `fd_quic_stream_t` structure, representing the newly allocated stream. If no streams are available in the pool, it returns NULL.
- **Use**: This function is used to obtain a new stream from the specified stream pool for use in QUIC protocol operations.


# Data Structures

---
### fd\_quic\_stream\_pool
- **Type**: `struct`
- **Members**:
    - `cap`: The capacity of the pool.
    - `cur_cnt`: The current number of streams in the pool.
    - `head`: The head of the linked list of free streams, or NULL if none.
- **Description**: The `fd_quic_stream_pool` structure is designed to manage a pool of QUIC streams, providing efficient allocation and deallocation of stream resources. It maintains a capacity (`cap`) indicating the maximum number of streams it can handle, and a current count (`cur_cnt`) of streams currently in use. The `head` member serves as the starting point of a linked list of available streams, facilitating quick access to free streams for allocation. This structure is crucial for managing stream lifecycles in a QUIC protocol implementation, ensuring that resources are utilized effectively and that stream operations are performed with minimal overhead.


---
### fd\_quic\_stream\_pool\_t
- **Type**: `struct`
- **Members**:
    - `cap`: The capacity of the pool, indicating the maximum number of streams it can manage.
    - `cur_cnt`: The current number of streams in the pool.
    - `head`: The head of the linked list of free streams, or NULL if there are no free streams.
- **Description**: The `fd_quic_stream_pool_t` is a data structure designed to manage a pool of QUIC streams, providing efficient allocation and deallocation of stream resources. It maintains a linked list of free streams, allowing for quick access and management of available streams. The structure includes a capacity field to denote the maximum number of streams it can handle, a current count of streams in use, and a head pointer to the linked list of free streams. This design facilitates the management of stream resources in a QUIC protocol implementation, ensuring that streams can be efficiently reused and managed within the constraints of the pool's capacity.


# Functions

---
### fd\_quic\_stream\_pool\_align<!-- {{#callable:fd_quic_stream_pool_align}} -->
The `fd_quic_stream_pool_align` function returns the alignment requirement for a QUIC stream pool.
- **Inputs**: None
- **Control Flow**:
    - The function directly returns the value of the macro `FD_QUIC_STREAM_POOL_ALIGN`, which is defined as 128ul.
- **Output**: The function outputs an unsigned long integer representing the alignment requirement for a QUIC stream pool, specifically 128.


---
### fd\_quic\_stream\_pool\_avail<!-- {{#callable:fd_quic_stream_pool_avail}} -->
The function `fd_quic_stream_pool_avail` returns the current number of streams available in a given QUIC stream pool.
- **Inputs**:
    - `pool`: A pointer to an `fd_quic_stream_pool_t` structure representing the stream pool whose available stream count is to be retrieved.
- **Control Flow**:
    - The function accesses the `cur_cnt` member of the `fd_quic_stream_pool_t` structure pointed to by `pool`.
    - It returns the value of `cur_cnt`, which represents the current number of streams available in the pool.
- **Output**: The function returns an `ulong` representing the number of streams currently available in the specified stream pool.


# Function Declarations (Public API)

---
### fd\_quic\_stream\_pool\_footprint<!-- {{#callable_declaration:fd_quic_stream_pool_footprint}} -->
Calculate the memory footprint required for a QUIC stream pool.
- **Description**: Use this function to determine the amount of memory needed to allocate a QUIC stream pool that can manage a specified number of streams, each with a given transmission buffer size. This is useful for ensuring that sufficient memory is allocated before initializing a stream pool. The function computes the total memory requirement by considering both the base size of the stream pool structure and the additional memory needed for each stream's buffer. It is important to call this function before allocating memory for the stream pool to avoid memory allocation errors.
- **Inputs**:
    - `count`: The number of streams the pool will manage. Must be a non-negative integer.
    - `tx_buf_sz`: The size of the transmission buffer for each stream. Must be a non-negative integer.
- **Output**: Returns the total memory footprint in bytes required to allocate a stream pool capable of managing the specified number of streams with the given buffer size.
- **See also**: [`fd_quic_stream_pool_footprint`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_footprint)  (Implementation)


---
### fd\_quic\_stream\_pool\_new<!-- {{#callable_declaration:fd_quic_stream_pool_new}} -->
Initializes a new QUIC stream pool with a specified number of streams.
- **Description**: This function initializes a new QUIC stream pool using the provided memory, which must be aligned to the required alignment and have sufficient size to accommodate the pool and its streams. It sets up the pool to manage a specified number of streams, each with a given transmission buffer size. The function should be called when a new stream pool is needed, and the memory provided must remain valid for the lifetime of the pool. The caller is responsible for ensuring that the memory is properly aligned and sized according to the pool's requirements.
- **Inputs**:
    - `mem`: A pointer to memory that must be aligned to `fd_quic_stream_pool_align()` and have at least `fd_quic_stream_pool_footprint(count, tx_buf_sz)` bytes. The caller retains ownership and must ensure the memory remains valid for the pool's lifetime.
    - `count`: The number of streams the pool will manage. Must be a positive integer.
    - `tx_buf_sz`: The size of the transmission buffer for each stream. Must be a valid size for stream buffers.
- **Output**: Returns a pointer to the newly initialized `fd_quic_stream_pool_t` structure.
- **See also**: [`fd_quic_stream_pool_new`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_new)  (Implementation)


---
### fd\_quic\_stream\_pool\_delete<!-- {{#callable_declaration:fd_quic_stream_pool_delete}} -->
Deletes a stream pool and all associated streams.
- **Description**: Use this function to delete a stream pool when it is no longer needed. Before calling this function, ensure that all streams have been returned to the pool. This function does not perform any operations if the stream pool is null, and it is the caller's responsibility to manage the memory associated with the stream pool.
- **Inputs**:
    - `stream_pool`: A pointer to the stream pool to be deleted. Must not be null, and all streams should be returned to the pool before calling this function. The caller retains ownership of the memory.
- **Output**: None
- **See also**: [`fd_quic_stream_pool_delete`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_delete)  (Implementation)


---
### fd\_quic\_stream\_pool\_alloc<!-- {{#callable_declaration:fd_quic_stream_pool_alloc}} -->
Allocates a stream from the specified pool.
- **Description**: Use this function to obtain a stream from a pre-initialized stream pool. It should be called when a new stream is needed for operations. The function will return a pointer to a stream if one is available, or NULL if the pool is exhausted. Ensure that the pool has been properly initialized and contains available streams before calling this function. This function reduces the count of available streams in the pool by one.
- **Inputs**:
    - `pool`: A pointer to the fd_quic_stream_pool_t from which to allocate a stream. Must not be null and should point to a valid, initialized stream pool. If the pool is empty, the function returns NULL.
- **Output**: Returns a pointer to an fd_quic_stream_t if a stream is available, or NULL if the pool is empty.
- **See also**: [`fd_quic_stream_pool_alloc`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_alloc)  (Implementation)


---
### fd\_quic\_stream\_pool\_free<!-- {{#callable_declaration:fd_quic_stream_pool_free}} -->
Return a stream to the specified pool.
- **Description**: Use this function to return a previously allocated stream back to its originating pool, making it available for future allocations. This function should be called whenever a stream is no longer needed, ensuring efficient reuse of resources. The stream must have been previously allocated from the same pool, and the pool must be valid and properly initialized. This function increases the count of available streams in the pool.
- **Inputs**:
    - `pool`: A pointer to the stream pool to which the stream will be returned. Must not be null and must point to a valid, initialized stream pool.
    - `stream`: A pointer to the stream to be returned to the pool. Must not be null and must have been previously allocated from the same pool.
- **Output**: None
- **See also**: [`fd_quic_stream_pool_free`](fd_quic_stream_pool.c.driver.md#fd_quic_stream_pool_free)  (Implementation)


