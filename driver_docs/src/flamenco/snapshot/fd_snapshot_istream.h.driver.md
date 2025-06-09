# Purpose
This C header file defines an input stream API designed to facilitate streaming read operations, particularly in the context of handling compressed data and file streams. The file introduces an object-oriented approach to managing input streams by utilizing virtual function tables, akin to C++ style dynamic dispatch. This allows for flexible and extensible stream handling, where different types of input streams can be managed through a common interface. The file includes implementations for reading from Zstandard compressed streams and file descriptors, providing a structured way to handle these data sources through the `fd_io_istream_vt` interface.

The header file also outlines the structure and function prototypes for managing these input streams, including the creation and deletion of stream objects and the reading operations. It includes specific implementations for Zstandard streams (`fd_io_istream_zstd_t`) and file streams (`fd_io_istream_file_t`), each implementing the virtual table interface. Additionally, the file provides a mechanism for reading tar archives from an input stream object, further extending its utility in handling complex data formats. The file is intended to be included in other C source files, providing a modular and reusable API for input stream management, with a focus on scalability and performance improvements in future iterations.
# Imports and Dependencies

---
- `../../util/archive/fd_tar.h`
- `../../ballet/zstd/fd_zstd.h`


# Global Variables

---
### fd\_io\_istream\_zstd\_delete
- **Type**: `function pointer`
- **Description**: The `fd_io_istream_zstd_delete` is a function pointer that is used to delete or clean up an instance of `fd_io_istream_zstd_t`. This function is responsible for freeing any resources or memory associated with the ZSTD input stream object.
- **Use**: This function is used to properly dispose of a `fd_io_istream_zstd_t` object, ensuring that any allocated resources are released.


---
### fd\_io\_istream\_zstd\_vt
- **Type**: `fd_io_istream_vt_t const`
- **Description**: The `fd_io_istream_zstd_vt` is a constant instance of the `fd_io_istream_vt_t` structure, which represents a virtual table for input stream operations. This virtual table is specifically tailored for handling Zstandard (ZSTD) compressed data streams.
- **Use**: This variable is used to provide a set of function pointers for reading from ZSTD compressed input streams, enabling polymorphic behavior in the input stream API.


---
### fd\_io\_istream\_file\_delete
- **Type**: `function pointer`
- **Description**: The `fd_io_istream_file_delete` is a function pointer that is used to delete or clean up an instance of `fd_io_istream_file_t`. This function is responsible for handling the deallocation or cleanup of resources associated with a file input stream object.
- **Use**: This function is used to delete an instance of `fd_io_istream_file_t`, ensuring proper resource management and cleanup.


---
### fd\_io\_istream\_file\_vt
- **Type**: `fd_io_istream_vt_t const`
- **Description**: The `fd_io_istream_file_vt` is a constant instance of the `fd_io_istream_vt_t` structure, which represents a virtual table for input stream operations specifically for file-based streams. This virtual table is part of an object-oriented API in C, providing a mechanism for dynamic dispatch of the `read` function for file input streams.
- **Use**: This variable is used to define the behavior of file input streams by providing a specific implementation of the `read` function for file-based input operations.


---
### fd\_tar\_io\_reader\_delete
- **Type**: `function pointer`
- **Description**: The `fd_tar_io_reader_delete` is a function that takes a pointer to an `fd_tar_io_reader_t` structure and deletes or cleans up the resources associated with it. This function is part of the API for handling input streams, specifically for reading tar files from a source defined by `fd_io_istream_obj_t`. It is likely responsible for freeing memory or performing other cleanup tasks necessary when the `fd_tar_io_reader_t` object is no longer needed.
- **Use**: This function is used to delete or clean up an `fd_tar_io_reader_t` object, ensuring proper resource management.


# Data Structures

---
### fd\_io\_istream\_vt
- **Type**: `struct`
- **Members**:
    - `read`: A function pointer to a read function that takes a context pointer, a destination buffer, a maximum size for the destination buffer, and a pointer to store the size of data read.
- **Description**: The `fd_io_istream_vt` structure is a virtual table for input stream objects, providing a function pointer for a read operation. This structure is part of an object-oriented API in C, allowing for dynamic dispatch of the read function, similar to virtual functions in C++. The read function is expected to be blocking, and the structure is designed to be used in a streaming read pipeline, potentially across multiple cores for better scalability and performance.


---
### fd\_io\_istream\_vt\_t
- **Type**: `struct`
- **Members**:
    - `read`: A function pointer to a virtual version of the fd_io_read function, assumed to be blocking.
- **Description**: The `fd_io_istream_vt_t` structure is a virtual table used in an object-oriented API for handling input streams of data in C. It provides a dynamically dispatched interface, similar to C++ style virtual function tables, allowing for the implementation of different input stream types. The structure contains a single member, `read`, which is a function pointer to a read function that is expected to be blocking. This design allows for flexibility in implementing various input stream behaviors while maintaining a consistent interface.


---
### fd\_io\_istream\_obj
- **Type**: `struct`
- **Members**:
    - `this`: A pointer to an instance of the object that implements the input stream functionality.
    - `vt`: A pointer to a constant virtual table structure that defines the interface for input stream operations.
- **Description**: The `fd_io_istream_obj` structure is a part of an experimental object-oriented API in C for handling input streams of data. It uses a virtual function table (vt) to dynamically dispatch input stream operations, similar to C++ style virtual functions. The `this` pointer is used to reference the specific instance of the input stream, allowing for polymorphic behavior where different types of input streams can be handled through a common interface.


---
### fd\_io\_istream\_obj\_t
- **Type**: `struct`
- **Members**:
    - `this`: A pointer to an instance-specific data structure, allowing for object-oriented behavior.
    - `vt`: A pointer to a constant virtual table structure, enabling dynamic method dispatch.
- **Description**: The `fd_io_istream_obj_t` structure is part of an experimental object-oriented API for handling input streams in C. It uses a virtual function table (`fd_io_istream_vt_t`) to support dynamic method dispatch, similar to C++ virtual functions, allowing different implementations of input streams to be used interchangeably. The `this` pointer refers to the specific instance data, while the `vt` pointer refers to the virtual table that contains function pointers for operations on the stream, such as reading data. This design facilitates polymorphism and encapsulation in C, enabling flexible and extensible stream handling.


---
### fd\_io\_istream\_zstd
- **Type**: `struct`
- **Members**:
    - `dstream`: A pointer to a Zstandard decompression stream, borrowed for the lifetime of the structure.
    - `src`: An input stream object that serves as the source for the Zstandard decompression.
    - `in_buf`: A buffer of fixed size (8192 bytes) used to store input data for decompression.
    - `in_cur`: A pointer indicating the current position within the input buffer.
    - `in_end`: A pointer indicating the end of valid data within the input buffer.
    - `dirty`: An integer flag indicating the state of the stream, possibly used for error or status tracking.
- **Description**: The `fd_io_istream_zstd` structure is designed to handle input streams that require Zstandard decompression. It integrates a Zstandard decompression stream (`dstream`) with a source input stream (`src`) and manages a buffer (`in_buf`) for storing input data. The structure maintains pointers (`in_cur` and `in_end`) to track the current position and the end of valid data within the buffer, facilitating efficient data processing. The `dirty` flag is likely used to indicate the state of the stream, such as whether it needs to be reset or if an error has occurred. This structure is part of a larger framework for handling input streams in a modular and extensible manner.


---
### fd\_io\_istream\_zstd\_t
- **Type**: `struct`
- **Members**:
    - `dstream`: A pointer to an fd_zstd_dstream_t, borrowed for the lifetime of the structure.
    - `src`: An fd_io_istream_obj_t representing the source input stream.
    - `in_buf`: A buffer of size FD_IO_ISTREAM_ZSTD_BUFSZ used for input data.
    - `in_cur`: A pointer indicating the current position in the input buffer.
    - `in_end`: A pointer indicating the end of valid data in the input buffer.
    - `dirty`: An integer flag indicating if the stream state is dirty.
- **Description**: The fd_io_istream_zstd_t structure is designed to handle input streams that are compressed using the Zstandard (Zstd) compression algorithm. It implements the fd_io_istream_vt_t interface, allowing it to be used in a polymorphic manner with other input stream types. The structure maintains a Zstd decompression stream, a source input stream object, and a buffer for managing input data. It also includes pointers to track the current position and end of the valid data within the buffer, as well as a flag to indicate if the stream's state is dirty, which may require reinitialization or cleanup.


---
### fd\_io\_istream\_file
- **Type**: `struct`
- **Members**:
    - `fd`: An integer representing a file descriptor.
- **Description**: The `fd_io_istream_file` structure is a simple data structure that encapsulates a file descriptor, represented by an integer, for use in input stream operations. It is part of a larger framework for handling input streams in a modular and object-oriented manner, allowing for the reading of data from files using a virtual function table approach. This structure is specifically designed to interface with file-based input streams, providing a basic building block for more complex input stream handling.


---
### fd\_io\_istream\_file\_t
- **Type**: `struct`
- **Members**:
    - `fd`: An integer representing a file descriptor for the input stream.
- **Description**: The `fd_io_istream_file_t` structure is a simple data structure that implements the `fd_io_istream_vt_t` interface for file-based input streams. It contains a single member, `fd`, which is an integer file descriptor used to perform read operations on the file. This structure is part of a larger object-oriented API designed to handle input streams in a flexible and dynamically dispatched manner, allowing for different types of input sources to be used interchangeably.


---
### fd\_tar\_io\_reader\_t
- **Type**: `struct`
- **Members**:
    - `reader`: A pointer to an fd_tar_reader_t, borrowed for the lifetime of the fd_tar_io_reader_t.
    - `src`: An fd_io_istream_obj_t that serves as the source for reading the tar.
- **Description**: The fd_tar_io_reader_t structure is designed to facilitate reading tar files from a source defined by an fd_io_istream_obj_t. It contains a pointer to an fd_tar_reader_t, which is used to manage the reading process, and an fd_io_istream_obj_t that specifies the input stream source. This structure is part of a larger framework for handling input streams in a flexible and potentially multi-core environment, although the current implementation is noted to be suboptimal and subject to future improvements.


# Functions

---
### fd\_io\_istream\_obj\_read<!-- {{#callable:fd_io_istream_obj_read}} -->
The `fd_io_istream_obj_read` function reads data from an input stream object into a destination buffer using a virtual function table for dynamic dispatch.
- **Inputs**:
    - `obj`: A pointer to an `fd_io_istream_obj_t` structure, which contains the input stream object and its associated virtual function table.
    - `dst`: A pointer to the destination buffer where the read data will be stored.
    - `dst_max`: An unsigned long integer specifying the maximum number of bytes to read into the destination buffer.
    - `dst_sz`: A pointer to an unsigned long integer where the actual number of bytes read will be stored.
- **Control Flow**:
    - The function accesses the virtual function table (`vt`) of the input stream object (`obj`).
    - It calls the `read` function pointer from the virtual function table, passing the `this` pointer from the object, the destination buffer (`dst`), the maximum size (`dst_max`), and the pointer to store the size of data read (`dst_sz`).
    - The function returns the result of the `read` function call, which is typically an integer indicating success or failure.
- **Output**: The function returns an integer, which is the result of the `read` function call from the virtual function table, indicating the success or failure of the read operation.


---
### fd\_io\_istream\_zstd\_virtual<!-- {{#callable:fd_io_istream_zstd_virtual}} -->
The function `fd_io_istream_zstd_virtual` creates and returns a virtual input stream object for Zstandard decompression.
- **Inputs**:
    - `this`: A pointer to an `fd_io_istream_zstd_t` structure, representing the Zstandard input stream object.
- **Control Flow**:
    - The function takes a pointer to an `fd_io_istream_zstd_t` structure as input.
    - It constructs an `fd_io_istream_obj_t` object, initializing its `this` member with the input pointer and its `vt` member with the address of `fd_io_istream_zstd_vt`.
    - The constructed `fd_io_istream_obj_t` object is returned.
- **Output**: The function returns an `fd_io_istream_obj_t` object, which is a virtual input stream object configured for Zstandard decompression.


---
### fd\_io\_istream\_file\_virtual<!-- {{#callable:fd_io_istream_file_virtual}} -->
The function `fd_io_istream_file_virtual` initializes and returns a `fd_io_istream_obj_t` object for a given file input stream, associating it with the appropriate virtual function table.
- **Inputs**:
    - `this`: A pointer to an `fd_io_istream_file_t` structure, representing the file input stream to be wrapped in an object-oriented interface.
- **Control Flow**:
    - The function takes a pointer to an `fd_io_istream_file_t` structure as input.
    - It creates and returns an `fd_io_istream_obj_t` object.
    - The `this` member of the returned object is set to the input `fd_io_istream_file_t` pointer.
    - The `vt` member of the returned object is set to point to `fd_io_istream_file_vt`, which is the virtual function table for file input streams.
- **Output**: The function returns an `fd_io_istream_obj_t` object that encapsulates the file input stream and its associated virtual function table.


# Function Declarations (Public API)

---
### fd\_io\_istream\_zstd\_delete<!-- {{#callable_declaration:fd_io_istream_zstd_delete}} -->
Deletes a Zstandard input stream object.
- **Description**: Use this function to delete a Zstandard input stream object when it is no longer needed. This function resets the memory of the input stream object to zero, effectively cleaning up any state associated with it. It is important to ensure that the object is not used after deletion, as its state will be invalidated. This function should be called to prevent memory leaks and to maintain proper resource management in applications using Zstandard input streams.
- **Inputs**:
    - `this`: A pointer to the Zstandard input stream object to be deleted. Must not be null. The caller retains ownership and is responsible for ensuring the object is not used after deletion.
- **Output**: Returns a pointer to the deleted Zstandard input stream object, which is now reset to zero.
- **See also**: [`fd_io_istream_zstd_delete`](fd_snapshot_istream.c.driver.md#fd_io_istream_zstd_delete)  (Implementation)


---
### fd\_io\_istream\_zstd\_read<!-- {{#callable_declaration:fd_io_istream_zstd_read}} -->
Reads decompressed data from a Zstandard-compressed input stream.
- **Description**: This function reads data from a Zstandard-compressed input stream and writes the decompressed data into the provided destination buffer. It should be used when you need to process data from a compressed source in a streaming manner. The function assumes that the input stream object has been properly initialized and is ready for reading. It handles end-of-file and error conditions by returning specific error codes. The function must be called with a valid destination buffer and a pointer to a variable where the size of the decompressed data will be stored.
- **Inputs**:
    - `_this`: A pointer to an initialized fd_io_istream_zstd_t object representing the Zstandard-compressed input stream. Must not be null.
    - `dst`: A pointer to the destination buffer where decompressed data will be written. Must not be null and should have enough space to hold up to dst_max bytes.
    - `dst_max`: The maximum number of bytes that can be written to the destination buffer. Must be a positive value.
    - `dst_sz`: A pointer to a ulong where the function will store the number of bytes actually written to the destination buffer. Must not be null.
- **Output**: Returns 0 on success, -1 on end-of-file, or a positive error code on failure. The number of bytes written to the destination buffer is stored in *dst_sz.
- **See also**: [`fd_io_istream_zstd_read`](fd_snapshot_istream.c.driver.md#fd_io_istream_zstd_read)  (Implementation)


---
### fd\_io\_istream\_file\_delete<!-- {{#callable_declaration:fd_io_istream_file_delete}} -->
Deletes a file input stream object.
- **Description**: Use this function to delete a file input stream object when it is no longer needed. This function resets the memory of the given file input stream object to zero, effectively clearing its state. It is important to ensure that the object is not used after deletion, as its state will be invalidated. This function should be called to clean up resources associated with the file input stream object.
- **Inputs**:
    - `this`: A pointer to the file input stream object to be deleted. Must not be null. The caller retains ownership and is responsible for ensuring the object is not used after deletion.
- **Output**: Returns a pointer to the deleted file input stream object, which is now reset to zero.
- **See also**: [`fd_io_istream_file_delete`](fd_snapshot_istream.c.driver.md#fd_io_istream_file_delete)  (Implementation)


---
### fd\_io\_istream\_file\_read<!-- {{#callable_declaration:fd_io_istream_file_read}} -->
Reads data from a file descriptor into a buffer.
- **Description**: This function reads data from a file descriptor associated with the input stream object into a provided buffer. It is typically used when implementing a streaming read pipeline, where data needs to be read from a file descriptor in a controlled manner. The function attempts to read up to a specified maximum number of bytes into the destination buffer and reports the actual number of bytes read. It is important to ensure that the destination buffer is large enough to hold the maximum number of bytes specified. The function is blocking and will wait until data is available to read.
- **Inputs**:
    - `_this`: A pointer to the input stream object, specifically of type `fd_io_istream_file_t`. This must not be null and should be properly initialized before calling this function.
    - `dst`: A pointer to the destination buffer where the read data will be stored. This buffer must be allocated by the caller and must not be null.
    - `dst_max`: The maximum number of bytes to read into the destination buffer. This value should be positive and should not exceed the size of the buffer pointed to by `dst`.
    - `dst_sz`: A pointer to a variable where the function will store the actual number of bytes read. This must not be null.
- **Output**: Returns an integer status code indicating the success or failure of the read operation. The actual number of bytes read is stored in the location pointed to by `dst_sz`.
- **See also**: [`fd_io_istream_file_read`](fd_snapshot_istream.c.driver.md#fd_io_istream_file_read)  (Implementation)


---
### fd\_tar\_io\_reader\_delete<!-- {{#callable_declaration:fd_tar_io_reader_delete}} -->
Deletes a tar I/O reader object.
- **Description**: Use this function to delete a `fd_tar_io_reader_t` object when it is no longer needed. This function resets the memory of the object to zero, effectively cleaning up any state associated with it. It is important to ensure that the object is not used after deletion, as its state will be invalidated. This function should be called to prevent memory leaks and to maintain proper resource management in applications using tar I/O readers.
- **Inputs**:
    - `this`: A pointer to the `fd_tar_io_reader_t` object to be deleted. Must not be null. The caller retains ownership of the memory and is responsible for managing its lifecycle.
- **Output**: Returns a pointer to the deleted `fd_tar_io_reader_t` object, now reset to zero.
- **See also**: [`fd_tar_io_reader_delete`](fd_snapshot_istream.c.driver.md#fd_tar_io_reader_delete)  (Implementation)


---
### fd\_tar\_io\_reader\_advance<!-- {{#callable_declaration:fd_tar_io_reader_advance}} -->
Advances the tar stream reader to the next entry.
- **Description**: Use this function to read the next entry from a tar stream using the provided tar stream reader object. It should be called repeatedly to process each entry in the tar stream. The function reads data from the input stream associated with the reader and processes it as a tar archive. It handles end-of-file and error conditions, returning specific codes to indicate these states. Ensure that the `fd_tar_io_reader_t` object is properly initialized before calling this function.
- **Inputs**:
    - `this`: A pointer to an `fd_tar_io_reader_t` object, which must be initialized and not null. The function reads from the input stream and processes the data as a tar archive.
- **Output**: Returns 0 on success, -1 on end-of-file, or a positive error code on failure.
- **See also**: [`fd_tar_io_reader_advance`](fd_snapshot_istream.c.driver.md#fd_tar_io_reader_advance)  (Implementation)


