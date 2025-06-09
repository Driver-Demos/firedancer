# Purpose
This C header file, `fd_quic_stream.h`, is part of a library that provides functionality for managing QUIC protocol streams. The file defines data structures and functions necessary for handling QUIC streams, which are essential components in the QUIC protocol for data transmission. The primary data structure defined is `fd_quic_stream_t`, which represents a QUIC stream and includes fields for managing stream state, flow control, and data buffers. The file also defines a circular buffer structure, `fd_quic_buffer_t`, used for efficient data storage and retrieval within streams. Additionally, the file includes macros for managing stream states and linked list operations, facilitating the organization and manipulation of streams within a connection.

The header file provides a public API for creating, deleting, and managing QUIC streams, including functions for storing and loading data in the circular buffer, setting and retrieving user-defined contexts, and initializing streams with specific memory alignments and buffer sizes. The file is designed to be included in other C source files, allowing developers to integrate QUIC stream management into their applications. The use of forward declarations and typedefs ensures that the file can be used in various contexts without requiring full definitions of related structures, promoting modularity and reusability in software development.
# Imports and Dependencies

---
- `fd_quic_common.h`
- `../../util/fd_util.h`


# Global Variables

---
### fd\_quic\_stream\_new
- **Type**: `function pointer`
- **Description**: The `fd_quic_stream_new` is a function that returns a pointer to a newly initialized `fd_quic_stream_t` structure. It takes three parameters: a memory pointer `mem` that is aligned and has sufficient size, a pointer to a `fd_quic_conn_t` connection, and a `tx_buf_sz` which specifies the size of the transmit buffer.
- **Use**: This function is used to create and initialize a new QUIC stream with the specified memory and connection parameters.


---
### fd\_quic\_stream\_get\_context
- **Type**: `function pointer`
- **Description**: The `fd_quic_stream_get_context` is a function that retrieves the user-defined context associated with a given QUIC stream. It takes a pointer to an `fd_quic_stream_t` structure as an argument and returns a void pointer to the context.
- **Use**: This function is used to access the user-defined context that has been previously set for a specific QUIC stream, allowing for custom data or state to be associated with the stream.


# Data Structures

---
### fd\_quic\_conn\_t
- **Type**: `typedef struct fd_quic_conn fd_quic_conn_t;`
- **Members**:
    - `fd_quic_conn_t`: A forward declaration for a structure representing a QUIC connection.
- **Description**: The `fd_quic_conn_t` is a forward declaration for a structure that represents a QUIC connection in the codebase. It is used as a placeholder for a more detailed definition that is likely found elsewhere in the code. This structure is integral to managing and maintaining the state and operations of a QUIC connection, which is a protocol designed for fast and reliable internet communication.


---
### fd\_quic\_stream\_t
- **Type**: `struct`
- **Members**:
    - `conn`: Pointer to the associated QUIC connection.
    - `stream_id`: Unique identifier for the stream, with all 1's indicating an unused stream.
    - `context`: User-defined context for callbacks.
    - `tx_buf`: Transmit buffer for the stream.
    - `tx_ack`: Acknowledgment bits for each byte in the transmit buffer.
    - `tx_sent`: Offset of the first unsent byte in the transmit buffer.
    - `stream_flags`: Flags indicating required actions for the stream.
    - `sentinel`: Indicates if the stream is a sentinel.
    - `state`: Current state of the stream, represented by a mask of state flags.
    - `list_memb`: Indicates the list membership status of the stream.
    - `tx_max_stream_data`: Maximum number of bytes allowed to be sent to the peer on this stream.
    - `tx_tot_data`: Total number of bytes transmitted on this stream.
    - `rx_tot_data`: Total number of bytes received on this stream.
    - `upd_pkt_number`: Packet number for the last transmitted packet with a stream frame.
    - `next`: Pointer to the next stream in a doubly linked list.
    - `prev`: Pointer to the previous stream in a doubly linked list.
- **Description**: The `fd_quic_stream_t` structure represents a QUIC stream within a connection, managing data transmission and reception, flow control, and stream state. It includes a transmit buffer, acknowledgment tracking, and various flags and state indicators to manage the stream's lifecycle and actions. The structure also supports linked list operations for managing multiple streams and includes user-defined context for callback operations.


---
### fd\_quic\_stream\_map\_t
- **Type**: `struct`
- **Members**:
    - `stream_id`: The unique identifier for the stream, used as a key in the map.
    - `hash`: The hash value associated with the stream_id for efficient lookup.
    - `stream`: A pointer to the fd_quic_stream_t structure, representing the value associated with the stream_id.
- **Description**: The `fd_quic_stream_map_t` structure is a mapping data structure used to associate a unique stream identifier (`stream_id`) with its corresponding `fd_quic_stream_t` object. It includes a `hash` field to facilitate efficient lookups and a `stream` pointer to the actual stream object. This structure is likely used in dynamic maps to manage and access QUIC streams efficiently within the QUIC protocol implementation.


---
### fd\_quic\_buffer
- **Type**: `struct`
- **Members**:
    - `buf`: A pointer to an unsigned character array representing the buffer storage.
    - `cap`: An unsigned long representing the capacity of the buffer, which must be a power of two.
    - `head`: An unsigned long indicating the first unused byte of the stream, used as an offset.
    - `tail`: An unsigned long indicating the first byte of the used range, used as an offset.
- **Description**: The `fd_quic_buffer` is a circular buffer data structure used in QUIC protocol implementations to manage data streams efficiently. It contains a buffer pointer `buf` for data storage, a `cap` field to denote the buffer's capacity, and `head` and `tail` fields to manage the offsets for reading and writing data within the buffer. The circular nature of the buffer allows for efficient use of memory by reusing space as data is consumed, and the capacity is required to be a power of two to facilitate efficient masking operations for index calculations.


---
### fd\_quic\_buffer\_t
- **Type**: `struct`
- **Members**:
    - `buf`: A pointer to an unsigned character array representing the buffer storage.
    - `cap`: An unsigned long representing the capacity of the buffer, which must be a power of two.
    - `head`: An unsigned long indicating the first unused byte of the stream, used as an offset.
    - `tail`: An unsigned long indicating the first byte of the used range, used as an offset.
- **Description**: The `fd_quic_buffer_t` is a circular buffer data structure used in the context of QUIC (Quick UDP Internet Connections) protocol implementations. It is designed to efficiently manage data streams by utilizing a buffer with a capacity that is a power of two, allowing for optimized memory usage and access patterns. The structure maintains two offsets, `head` and `tail`, which are used to track the beginning and end of the data stream within the buffer, facilitating operations such as data storage and retrieval. This design supports high-performance network communication by enabling quick access to data and efficient buffer management.


---
### fd\_quic\_stream
- **Type**: `struct`
- **Members**:
    - `conn`: Pointer to the associated QUIC connection.
    - `stream_id`: Unique identifier for the stream, with all 1's indicating an unused stream.
    - `context`: User-defined context for callbacks.
    - `tx_buf`: Transmit buffer for the stream.
    - `tx_ack`: Acknowledgment bits for each byte in the transmit buffer.
    - `tx_sent`: Offset of the first unsent byte in the transmit buffer.
    - `stream_flags`: Flags indicating actions required for the stream.
    - `sentinel`: Indicates if the stream is a sentinel.
    - `state`: Current state of the stream, represented by a mask.
    - `list_memb`: Membership status in a list.
    - `tx_max_stream_data`: Maximum number of bytes allowed to be sent to the peer.
    - `tx_tot_data`: Total number of bytes transmitted on the stream.
    - `rx_tot_data`: Total number of bytes received on the stream.
    - `upd_pkt_number`: Last packet number with a stream frame referring to this stream.
    - `next`: Pointer to the next stream in a doubly linked list.
    - `prev`: Pointer to the previous stream in a doubly linked list.
- **Description**: The `fd_quic_stream` structure represents a stream in a QUIC connection, managing data transmission and reception, flow control, and state management. It includes a transmit buffer, acknowledgment tracking, and various flags and states to handle stream lifecycle and actions. The structure also supports list operations for managing streams in a linked list, and it maintains context for user-defined callbacks. The stream's state and actions are controlled through defined flags and state masks, allowing for efficient management of stream operations within a QUIC connection.


---
### fd\_quic\_stream\_map
- **Type**: `struct`
- **Members**:
    - `stream_id`: A unique identifier for the stream, used as a key.
    - `hash`: A hash value associated with the stream for quick lookup.
    - `stream`: A pointer to the fd_quic_stream_t structure, representing the stream's data.
- **Description**: The `fd_quic_stream_map` structure is designed to facilitate the mapping of QUIC streams within a dynamic map. It contains a unique stream identifier (`stream_id`) that serves as the key, a `hash` for efficient retrieval, and a pointer to the actual stream data (`stream`). This structure is essential for managing and accessing streams in a QUIC connection, allowing for efficient stream lookup and management.


# Functions

---
### fd\_quic\_stream\_align<!-- {{#callable:fd_quic_stream_align}} -->
The `fd_quic_stream_align` function returns the alignment requirement for the `fd_quic_stream_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as `FD_FN_CONST inline`, indicating it is a constant function that can be inlined by the compiler.
    - The function takes no arguments and directly returns a constant value.
    - The constant value returned is `128ul`, representing the alignment requirement.
- **Output**: The function returns an `ulong` value of `128ul`, which specifies the alignment requirement for the `fd_quic_stream_t` structure.


# Function Declarations (Public API)

---
### fd\_quic\_buffer\_store<!-- {{#callable_declaration:fd_quic_buffer_store}} -->
Stores data into a circular buffer.
- **Description**: This function is used to store a specified amount of data into a circular buffer. It is essential to ensure that there is enough available space in the buffer to accommodate the data before calling this function, as it does not handle cases where the buffer is full. The function will not modify the buffer if the data size exceeds the available space, and it is the caller's responsibility to check for sufficient space using helper functions like `fd_quic_buffer_avail`. This function is typically used in scenarios where data needs to be buffered for later processing or transmission.
- **Inputs**:
    - `buf`: A pointer to an `fd_quic_buffer_t` structure representing the circular buffer where data will be stored. The buffer must be properly initialized and have enough capacity to store the incoming data.
    - `data`: A pointer to the data to be stored in the buffer. The data must be valid and the caller retains ownership. It must not be null.
    - `data_sz`: The size of the data to be stored in the buffer, in bytes. It must not exceed the available space in the buffer, which should be checked by the caller beforehand.
- **Output**: None
- **See also**: [`fd_quic_buffer_store`](fd_quic_stream.c.driver.md#fd_quic_buffer_store)  (Implementation)


---
### fd\_quic\_buffer\_load<!-- {{#callable_declaration:fd_quic_buffer_load}} -->
Load data from a circular buffer into a provided buffer.
- **Description**: This function is used to load a specified amount of data from a circular buffer into a user-provided buffer. It should be called when you need to retrieve data from a specific offset within the buffer. The function assumes that the operation is valid, meaning the caller must ensure that the offset and data size are within the bounds of the used portion of the buffer. If the offset is invalid or the operation is not feasible, the function will return without performing any action. This function does not modify the state of the circular buffer.
- **Inputs**:
    - `buf`: A pointer to an fd_quic_buffer_t structure representing the circular buffer. The buffer must be properly initialized and must not be null.
    - `offs`: An unsigned long representing the offset from which to start loading data. It must be within the range of used data in the buffer.
    - `data`: A pointer to an unsigned char array where the loaded data will be stored. The array must be large enough to hold the specified data size and must not be null.
    - `data_sz`: An unsigned long indicating the number of bytes to load from the buffer. It must not exceed the available data from the specified offset.
- **Output**: None
- **See also**: [`fd_quic_buffer_load`](fd_quic_stream.c.driver.md#fd_quic_buffer_load)  (Implementation)


---
### fd\_quic\_stream\_footprint<!-- {{#callable_declaration:fd_quic_stream_footprint}} -->
Calculate the memory footprint required for a QUIC stream.
- **Description**: This function calculates the total memory footprint required for a QUIC stream, given the size of the transmit buffer. It is useful for determining the amount of memory to allocate when creating a new stream. The function takes into account the alignment requirements and the additional space needed for acknowledgment data. It should be called before allocating memory for a stream to ensure sufficient space is reserved.
- **Inputs**:
    - `tx_buf_sz`: The size of the transmit buffer in bytes. It must be a positive integer, and the function will handle alignment internally. Invalid values, such as zero, may lead to an incorrect footprint calculation.
- **Output**: The function returns the total memory footprint in bytes required for the stream, including alignment and additional data structures.
- **See also**: [`fd_quic_stream_footprint`](fd_quic_stream.c.driver.md#fd_quic_stream_footprint)  (Implementation)


---
### fd\_quic\_stream\_new<!-- {{#callable_declaration:fd_quic_stream_new}} -->
Create a new QUIC stream with specified memory and connection.
- **Description**: This function initializes a new QUIC stream using the provided memory block and associates it with a given connection. It should be called when a new stream is needed, ensuring that the memory block is properly aligned and of sufficient size as determined by `fd_quic_stream_align` and `fd_quic_stream_footprint`. The function sets up internal buffers for transmission and acknowledgment, and initializes the stream's state. It is important to ensure that the memory provided is not null and meets the alignment and size requirements to avoid errors.
- **Inputs**:
    - `mem`: A pointer to a memory block that must be aligned to `fd_quic_stream_align` and have at least `fd_quic_stream_footprint(tx_buf_sz)` bytes. The caller retains ownership and must ensure it is valid and non-null.
    - `conn`: A pointer to an `fd_quic_conn_t` structure representing the connection to associate with the new stream. Must be valid and non-null.
    - `tx_buf_sz`: An unsigned long specifying the size of the transmission buffer. It determines the capacity of the stream's transmit buffer and should be a positive value.
- **Output**: Returns a pointer to the newly initialized `fd_quic_stream_t` structure, or logs an error if the memory size does not match the expected footprint.
- **See also**: [`fd_quic_stream_new`](fd_quic_stream.c.driver.md#fd_quic_stream_new)  (Implementation)


---
### fd\_quic\_stream\_delete<!-- {{#callable_declaration:fd_quic_stream_delete}} -->
Removes a QUIC stream from any list it belongs to.
- **Description**: This function is used to remove a QUIC stream from any list it is currently a member of, effectively isolating it. It should be called when a stream is no longer needed and should be detached from any list it was part of. This function does not free the memory associated with the stream; it only updates the stream's list pointers and membership status. It is important to ensure that the stream is not accessed through any list after this function is called, as it will no longer be part of any list.
- **Inputs**:
    - `stream`: A pointer to the fd_quic_stream_t structure representing the stream to be removed from any list. Must not be null. The function assumes the stream is valid and does not perform null checks.
- **Output**: None
- **See also**: [`fd_quic_stream_delete`](fd_quic_stream.c.driver.md#fd_quic_stream_delete)  (Implementation)


---
### fd\_quic\_stream\_set\_context<!-- {{#callable_declaration:fd_quic_stream_set_context}} -->
Associates a user-defined context with a QUIC stream.
- **Description**: Use this function to associate a user-defined context with a specific QUIC stream. This is useful for storing additional information or state that is relevant to the stream's operation or lifecycle. The function does not perform any validation on the context pointer, so it is the caller's responsibility to ensure that the context is valid and remains accessible for the duration of its use with the stream. This function should be called whenever you need to set or update the context associated with a stream.
- **Inputs**:
    - `stream`: A pointer to the `fd_quic_stream_t` structure representing the stream. Must not be null, and the stream should be properly initialized before calling this function.
    - `context`: A pointer to the user-defined context to associate with the stream. This can be any pointer type, including null, depending on the user's needs.
- **Output**: None
- **See also**: [`fd_quic_stream_set_context`](fd_quic_stream.c.driver.md#fd_quic_stream_set_context)  (Implementation)


---
### fd\_quic\_stream\_get\_context<!-- {{#callable_declaration:fd_quic_stream_get_context}} -->
Retrieve the user-defined context associated with a QUIC stream.
- **Description**: Use this function to obtain the user-defined context that has been associated with a specific QUIC stream. This is useful when you need to access or manipulate the context data that was previously set for the stream. Ensure that the stream has been properly initialized and that a context has been set using `fd_quic_stream_set_context` before calling this function.
- **Inputs**:
    - `stream`: A pointer to an `fd_quic_stream_t` structure representing the QUIC stream. Must not be null. The stream should be properly initialized and have a context set.
- **Output**: Returns a pointer to the user-defined context associated with the stream. If no context has been set, the return value is undefined.
- **See also**: [`fd_quic_stream_get_context`](fd_quic_stream.c.driver.md#fd_quic_stream_get_context)  (Implementation)


