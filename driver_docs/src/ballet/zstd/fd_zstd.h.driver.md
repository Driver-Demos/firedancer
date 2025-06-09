# Purpose
This C header file, `fd_zstd.h`, provides a set of APIs for handling Zstandard compressed streams, specifically focusing on decompression functionalities. It is designed to interface with the Zstandard compression library (`libzstd`) in a static mode, offering a streamlined approach to decompressing Zstandard frames. The file defines structures and functions necessary for managing decompression streams (`fd_zstd_dstream_t`) and peeking into frame headers (`fd_zstd_peek_t`). The header ensures that no dynamic memory allocations or system calls are performed, requiring the caller to manage memory allocation for the decompression objects. This design choice emphasizes efficiency and control over memory usage, which is crucial for applications with strict resource constraints.

The file includes detailed documentation on the memory management requirements and the constraints of the decompression process, such as the handling of window sizes and frame dependencies. It provides functions to create, delete, reset, and read from decompression streams, allowing for the processing of compressed data in a streaming fashion. The header also defines constants for alignment and header size, ensuring that the memory regions used are appropriately configured. While the file currently focuses on decompression, it hints at potential future enhancements, such as integrating compression logic. Overall, this header file is a specialized component intended for use in systems that require efficient and controlled decompression of Zstandard data streams.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_zstd\_dstream\_new
- **Type**: `fd_zstd_dstream_t *`
- **Description**: The `fd_zstd_dstream_new` function is responsible for creating a new Zstandard decompression stream object. It takes a memory region and a maximum window size as parameters, and returns a handle to the newly created decompression stream object. This function ensures that the memory region provided meets the alignment and footprint requirements for the specified maximum window size.
- **Use**: This variable is used to initialize a new decompression stream for handling Zstandard compressed frames, allowing for streaming decompression operations.


---
### fd\_zstd\_dstream\_delete
- **Type**: `function pointer`
- **Description**: The `fd_zstd_dstream_delete` is a function that takes a pointer to an `fd_zstd_dstream_t` object and releases its associated memory back to the caller. It is part of the memory management for Zstandard decompression streams, ensuring that resources are properly cleaned up after use.
- **Use**: This function is used to destroy a Zstandard decompression stream object and return its memory to the caller.


# Data Structures

---
### fd\_zstd\_dstream\_t
- **Type**: `typedef struct fd_zstd_dstream fd_zstd_dstream_t;`
- **Description**: The `fd_zstd_dstream_t` is a typedef for a structure used in the streaming decompression of Zstandard frames. It is designed to handle one frame at a time and is backed by a contiguous memory region managed by the caller. This data structure is part of the `fd_zstd` API, which provides functionality for working with Zstandard compressed streams without dynamic heap allocations or syscalls. The memory footprint of `fd_zstd_dstream_t` is dependent on the window size required for decompression, and it is crucial for handling the decompression process in a stateless manner between frames.


---
### fd\_zstd\_peek
- **Type**: `struct`
- **Members**:
    - `window_sz`: Represents the size of the window required for decompression.
    - `frame_content_sz`: Indicates the size of the frame content, with ULONG_MAX if the size is unknown.
    - `frame_is_skippable`: A flag indicating whether the frame can be skipped.
- **Description**: The `fd_zstd_peek` structure is used to store metadata about a Zstandard compressed frame, specifically the window size needed for decompression, the size of the frame content, and whether the frame is skippable. This structure is essential for handling Zstandard frames, as it provides necessary information for decompression processes without requiring the entire frame to be loaded or processed initially.


---
### fd\_zstd\_peek\_t
- **Type**: `struct`
- **Members**:
    - `window_sz`: Represents the window size required for decompression of a Zstandard frame.
    - `frame_content_sz`: Indicates the size of the frame content, or ULONG_MAX if the size is unknown.
    - `frame_is_skippable`: A flag indicating whether the frame can be skipped during processing.
- **Description**: The `fd_zstd_peek_t` structure is used to store metadata about a Zstandard frame, specifically the window size needed for decompression, the size of the frame content, and whether the frame is skippable. This structure is essential for managing the decompression process, as it allows the system to understand the requirements and characteristics of each frame before processing. The `fd_zstd_peek` function populates this structure by analyzing the frame header, providing necessary information for efficient and correct decompression.


# Function Declarations (Public API)

---
### fd\_zstd\_dstream\_align<!-- {{#callable_declaration:fd_zstd_dstream_align}} -->
Return the alignment requirement for a Zstandard decompression stream.
- **Description**: Use this function to determine the memory alignment requirement for a `fd_zstd_dstream_t` object. This is necessary when allocating memory for a decompression stream to ensure proper alignment, which is crucial for performance and correctness. The function does not require any parameters and can be called at any time to retrieve the alignment value.
- **Inputs**: None
- **Output**: Returns an unsigned long representing the alignment requirement in bytes for a `fd_zstd_dstream_t` object.
- **See also**: [`fd_zstd_dstream_align`](fd_zstd.c.driver.md#fd_zstd_dstream_align)  (Implementation)


---
### fd\_zstd\_dstream\_footprint<!-- {{#callable_declaration:fd_zstd_dstream_footprint}} -->
Returns the memory footprint required for a decompression stream with a specified maximum window size.
- **Description**: Use this function to determine the amount of memory needed to back a `fd_zstd_dstream_t` object for streaming decompression of Zstandard frames. This is essential for allocating the correct size of memory before creating a decompression stream. The function calculates the footprint based on the maximum window size, which is a parameter that influences the decompression process. Ensure that the `max_window_sz` is set to the largest window size the stream is expected to handle.
- **Inputs**:
    - `max_window_sz`: Specifies the largest window size that the decompression stream is expected to handle. It must be a valid window size for the Zstandard frames to be decompressed. Invalid or excessively large values may lead to incorrect memory footprint calculations.
- **Output**: Returns the size in bytes of the memory footprint required for a `fd_zstd_dstream_t` object with the specified maximum window size.
- **See also**: [`fd_zstd_dstream_footprint`](fd_zstd.c.driver.md#fd_zstd_dstream_footprint)  (Implementation)


---
### fd\_zstd\_dstream\_new<!-- {{#callable_declaration:fd_zstd_dstream_new}} -->
Creates a new Zstandard decompression stream object.
- **Description**: This function initializes a new decompression stream object for handling Zstandard compressed frames, using a memory region provided by the caller. It should be used when you need to decompress data streams that are compressed using the Zstandard format. The memory region must meet the alignment and size requirements specified by the `fd_zstd_dstream_align` and `fd_zstd_dstream_footprint` functions for the given maximum window size. The function returns a handle to the newly created decompression stream object, which is ready to process a new frame. If the initialization fails, the function returns NULL, indicating that the provided memory or parameters were invalid or insufficient.
- **Inputs**:
    - `mem`: A pointer to a memory region that will back the decompression stream object. This memory must be properly aligned and sized according to the requirements for the specified `max_window_sz`. The caller retains ownership of this memory.
    - `max_window_sz`: The maximum window size that the decompression stream can handle. This value determines the memory footprint of the stream object and must be chosen based on the expected maximum window size of the compressed frames to be decompressed.
- **Output**: Returns a pointer to the initialized `fd_zstd_dstream_t` object on success, or NULL on failure.
- **See also**: [`fd_zstd_dstream_new`](fd_zstd.c.driver.md#fd_zstd_dstream_new)  (Implementation)


---
### fd\_zstd\_dstream\_delete<!-- {{#callable_declaration:fd_zstd_dstream_delete}} -->
Destroys a Zstandard decompression stream object.
- **Description**: Use this function to destroy a previously created Zstandard decompression stream object and release its associated memory back to the caller. This function should be called when the decompression stream is no longer needed, ensuring that resources are properly freed. It is safe to call this function with a null pointer, in which case it performs no operation. The function returns a pointer to the memory region originally provided during the creation of the decompression stream, allowing the caller to reuse or deallocate the memory as needed.
- **Inputs**:
    - `dstream`: A pointer to the fd_zstd_dstream_t object to be destroyed. Must not be null unless the intention is to perform a no-op. The function checks for memory corruption by verifying a magic number; if corruption is detected, a critical log message is generated.
- **Output**: Returns a pointer to the memory region originally backing the dstream object, or NULL if dstream was null.
- **See also**: [`fd_zstd_dstream_delete`](fd_zstd.c.driver.md#fd_zstd_dstream_delete)  (Implementation)


---
### fd\_zstd\_dstream\_reset<!-- {{#callable_declaration:fd_zstd_dstream_reset}} -->
Reset the state of a Zstandard decompression stream.
- **Description**: Use this function to reset a Zstandard decompression stream object to its initial state, making it ready to process a new frame. This is useful when you want to reuse the same decompression stream for multiple frames without reallocating resources. Ensure that the `dstream` object is valid and properly initialized before calling this function. This function does not perform any dynamic memory allocation or deallocation.
- **Inputs**:
    - `dstream`: A pointer to a valid `fd_zstd_dstream_t` object. This object must have been previously created and initialized. The pointer must not be null, as passing a null pointer will result in undefined behavior.
- **Output**: None
- **See also**: [`fd_zstd_dstream_reset`](fd_zstd.c.driver.md#fd_zstd_dstream_reset)  (Implementation)


---
### fd\_zstd\_dstream\_read<!-- {{#callable_declaration:fd_zstd_dstream_read}} -->
Decompress a fragment of Zstandard compressed stream data.
- **Description**: This function is used to decompress a portion of a Zstandard compressed stream, updating the input and output pointers to reflect the progress made. It should be called with valid pointers to the current position in the input and output buffers, and the end of these buffers. The function returns an error code indicating the status of the decompression process, such as whether more data is needed or if the frame is complete. It is important to handle the return values correctly, especially in the case of errors, where the decompression stream should be reset. The function does not perform any dynamic memory allocation.
- **Inputs**:
    - `dstream`: A pointer to an initialized fd_zstd_dstream_t object. The caller must ensure this is a valid decompression stream object.
    - `in_p`: A pointer to a pointer to the next byte of compressed data. The pointer it points to is updated to reflect the new position after decompression. Must not be null.
    - `in_end`: A pointer to one byte past the end of the compressed data fragment. Must not be null and must be greater than or equal to *in_p.
    - `out_p`: A pointer to a pointer to the next free byte in the destination buffer. The pointer it points to is updated to reflect the new position after decompression. Must not be null.
    - `out_end`: A pointer to one byte past the end of the destination buffer. Must not be null and must be greater than or equal to *out_p.
    - `opt_errcode`: An optional pointer to a ulong where an error code will be stored if an error occurs. If null, an internal variable is used instead.
- **Output**: Returns 0 if decompression is ongoing and more data is needed, -1 if the current frame is fully decompressed, or an error code (e.g., EPROTO) if an error occurs. Updates *in_p and *out_p to reflect the new positions in the input and output buffers.
- **See also**: [`fd_zstd_dstream_read`](fd_zstd.c.driver.md#fd_zstd_dstream_read)  (Implementation)


