# Purpose
The provided C header file defines a set of APIs for managing fast, parallel, compressed checkpoint and restore operations. The primary purpose of this file is to facilitate the creation and restoration of checkpoints, which are collections of data frames that can be stored and retrieved efficiently. The file outlines the structure and functionality for handling checkpoints, including the ability to manage frames in both raw and LZ4 compressed formats. It supports both streaming and memory-mapped I/O modes, allowing for flexible data handling across different storage mediums. The header defines constants, data structures, and function prototypes necessary for initializing, managing, and finalizing checkpoints and restores, ensuring that operations can be performed in parallel and are bit-level identical regardless of the mode used.

Key components of this file include the definitions of `fd_checkpt_t` and `fd_restore_t` structures, which serve as handles for in-progress checkpoint and restore operations, respectively. The file also specifies various constants for buffer sizes, alignment, and error codes, which are crucial for ensuring the correct operation of the checkpoint and restore processes. The APIs provided allow for opening and closing frames, writing and reading data, and handling errors, with a focus on maintaining data integrity and supporting parallel operations. This header file is intended to be included in other C source files, providing a public API for developers to integrate checkpoint and restore functionality into their applications.
# Imports and Dependencies

---
- `../log/fd_log.h`


# Global Variables

---
### fd\_checkpt\_init\_mmio
- **Type**: `fd_checkpt_t *`
- **Description**: The `fd_checkpt_init_mmio` is a function that initializes a checkpoint in memory-mapped I/O (mmio) mode. It takes a memory region `mem`, a pointer to the mmio region `mmio`, and the size of the mmio region `mmio_sz` as parameters. The function returns a pointer to a `fd_checkpt_t` structure, which represents an in-progress checkpoint.
- **Use**: This function is used to set up a checkpoint in memory-mapped I/O mode, allowing frames to be stored in a specified memory region.


---
### fd\_checkpt\_fini
- **Type**: `function pointer`
- **Description**: `fd_checkpt_fini` is a function that finalizes a checkpoint operation. It takes a pointer to a `fd_checkpt_t` structure, which represents an in-progress checkpoint, and ensures that the checkpoint is properly closed and resources are released.
- **Use**: This function is used to complete a checkpoint operation, returning ownership of resources and ensuring the checkpoint is no longer valid.


---
### fd\_restore\_init\_stream
- **Type**: `fd_restore_t *`
- **Description**: The `fd_restore_init_stream` function initializes a memory region as a `fd_restore_t` structure in streaming mode. This structure is used to manage the restoration process from a checkpoint, utilizing a file descriptor and a read buffer for streaming data.
- **Use**: This variable is used to set up and manage the state of a restoration process from a checkpoint in streaming mode, handling the file descriptor and read buffer.


---
### fd\_restore\_init\_mmio
- **Type**: `fd_restore_t *`
- **Description**: The `fd_restore_init_mmio` function initializes a memory-mapped I/O (mmio) restore operation. It returns a pointer to an `fd_restore_t` structure, which is used to manage the state of the restore process.
- **Use**: This function is used to set up a restore operation from a memory-mapped region, allowing for efficient data restoration from a checkpoint.


---
### fd\_restore\_fini
- **Type**: `function pointer`
- **Description**: The `fd_restore_fini` is a function pointer that is used to finalize the restoration process from a checkpoint. It takes a pointer to an `fd_restore_t` structure as an argument and returns a void pointer. This function is responsible for cleaning up and releasing resources associated with the restoration process.
- **Use**: This function is used to properly terminate a restoration operation, ensuring that resources are released and the restoration object is invalidated.


---
### fd\_checkpt\_strerror
- **Type**: `function`
- **Description**: The `fd_checkpt_strerror` function is a global function that converts error codes related to checkpoint operations into human-readable strings. It takes an integer error code as an argument and returns a constant character pointer to a string that describes the error. The returned string is non-NULL and has an infinite lifetime.
- **Use**: This function is used to provide descriptive error messages for error codes returned by various checkpoint-related operations.


# Data Structures

---
### fd\_checkpt\_t
- **Type**: `typedef struct fd_checkpt_private fd_checkpt_t;`
- **Members**:
    - `fd`: File descriptor for the checkpoint, used in streaming mode.
    - `frame_style`: Specifies the style of the frame, indicating if it is in a frame or not.
    - `lz4`: Handle of the underlying compressor used for LZ4 compression.
    - `gbuf_cursor`: Cursor for small buffer gather optimizations.
    - `off`: Offset of the next byte to write in memory-mapped I/O mode.
    - `wbuf`: Used in streaming mode for write buffering.
    - `mmio`: Used in memory-mapped I/O mode for managing checkpoint memory region.
    - `gbuf`: Buffer used for gather optimization.
- **Description**: The `fd_checkpt_t` is a semi-opaque handle used for managing in-progress checkpoints, supporting both streaming and memory-mapped I/O modes. It encapsulates various fields to handle file descriptors, frame styles, compression handles, and buffer management for efficient checkpointing operations. The structure allows for parallel processing of frames, ensuring bit-level identical results regardless of the mode or distribution of operations across threads.


---
### fd\_restore\_t
- **Type**: `typedef struct fd_restore_private fd_restore_t;`
- **Members**:
    - `fd`: File descriptor for the restore, used in streaming mode.
    - `frame_style`: Specifies the style of frame being restored.
    - `lz4`: Handle of the underlying decompressor used.
    - `sbuf_cursor`: Cursor for small buffer scatter optimizations.
    - `sz`: Size of the checkpoint or memory region.
    - `off`: Offset of the next byte to read.
    - `rbuf`: Buffer of compressed bytes read from file descriptor, used in streaming mode.
    - `mmio`: Checkpoint memory region, used in mmio mode.
    - `sbuf`: Scatter optimization buffer.
- **Description**: The `fd_restore_t` is a semi-opaque handle used for managing the restoration process of checkpoints, supporting both streaming and memory-mapped I/O modes. It encapsulates the state and resources needed to restore data from a checkpoint, including file descriptors, buffer management, and decompression handles. The structure allows for parallel restoration of frames, ensuring bit-level identical results regardless of the mode or distribution of restoration tasks across threads.


---
### fd\_checkpt\_private\_wbuf
- **Type**: `struct`
- **Members**:
    - `mem`: Buffer of compressed bytes not yet written to fd, byte indexed [0,wbuf_sz).
    - `sz`: Buffer size in bytes, must be greater than or equal to FD_CHECKPT_WBUF_MIN.
    - `used`: Indicates the number of buffer bytes not yet written to fd, with bytes [wbuf_used,wbuf_sz) being free.
- **Description**: The `fd_checkpt_private_wbuf` structure is designed to manage a buffer of compressed bytes that are pending to be written to a file descriptor (fd). It is part of a system for handling checkpoints, which are used to save the state of a program at a particular point in time. The structure contains a pointer to the memory buffer (`mem`), the total size of the buffer (`sz`), and the number of bytes currently used in the buffer (`used`). This allows for efficient management of data that needs to be written, ensuring that the buffer is utilized effectively and that data is written in a controlled manner.


---
### fd\_checkpt\_private\_wbuf\_t
- **Type**: `struct`
- **Members**:
    - `mem`: Buffer of compressed bytes not yet written to fd, byte indexed [0,wbuf_sz).
    - `sz`: Buffer size in bytes, must be greater than or equal to FD_CHECKPT_WBUF_MIN.
    - `used`: Indicates the number of buffer bytes [0,wbuf_used) that are not yet written to fd, with [wbuf_used,wbuf_sz) being free.
- **Description**: The `fd_checkpt_private_wbuf_t` structure is designed to manage a write buffer for streaming mode in a checkpointing system. It holds a memory buffer (`mem`) for storing compressed bytes that are yet to be written to a file descriptor, with `sz` specifying the total size of this buffer. The `used` field tracks the portion of the buffer that is currently occupied with data that has not been written, allowing efficient management of the buffer space during streaming operations.


---
### fd\_checkpt\_private\_mmio
- **Type**: `struct`
- **Members**:
    - `mem`: Pointer to the checkpoint memory region, indexed from 0 to sz.
    - `sz`: Size of the checkpoint memory region in bytes.
- **Description**: The `fd_checkpt_private_mmio` structure is used to represent a memory-mapped I/O region for checkpointing purposes. It contains a pointer to the memory region and the size of this region in bytes, allowing for efficient access and manipulation of checkpoint data in memory.


---
### fd\_checkpt\_private\_mmio\_t
- **Type**: `typedef struct`
- **Members**:
    - `mem`: Checkpoint memory region, indexed [0,sz).
    - `sz`: Checkpoint memory region size in bytes.
- **Description**: The `fd_checkpt_private_mmio_t` structure is used to represent a memory-mapped input/output (MMIO) region for a checkpoint in a checkpointing system. It contains a pointer to a memory region (`mem`) and the size of that region (`sz`). This structure is part of a larger system designed to handle fast parallel compressed checkpoint and restore operations, allowing for efficient memory management and data access during these processes.


---
### fd\_checkpt\_private
- **Type**: `struct`
- **Members**:
    - `fd`: File descriptor for the checkpoint, used in streaming mode (>=0) or -1 in mmio mode.
    - `frame_style`: Indicates the frame style, with positive values for valid frames, 0 for not in frame, and -1 for failed frames.
    - `lz4`: Pointer to the handle of the underlying LZ4 compressor.
    - `gbuf_cursor`: Cursor for small buffer gather optimizations, ranging from 0 to FD_CHECKPT_PRIVATE_GBUF_SZ.
    - `off`: Offset of the next byte to write, relative to the checkpoint's first byte, used in mmio mode.
    - `wbuf`: Used in streaming mode, represents a write buffer for compressed bytes not yet written to fd.
    - `mmio`: Used in mmio mode, represents a memory-mapped I/O region for the checkpoint.
    - `gbuf`: Buffer used for gather optimization, with a size defined by FD_CHECKPT_PRIVATE_GBUF_SZ.
- **Description**: The `fd_checkpt_private` structure is a core component of a checkpointing system designed for fast parallel compressed checkpoint and restore operations. It manages both streaming and memory-mapped I/O (mmio) modes, allowing for efficient data handling and compression using LZ4. The structure includes fields for managing file descriptors, frame styles, compression handles, and buffer optimizations, with a union to switch between streaming and mmio modes. This design facilitates the creation and restoration of checkpoints in a manner that supports parallel processing and ensures bit-level identical results across different modes.


---
### fd\_restore\_private\_rbuf
- **Type**: `struct`
- **Members**:
    - `mem`: Buffer of compressed bytes read from fd, byte indexed [0,rbuf_sz).
    - `sz`: Buffer size in bytes, must be at least FD_RESTORE_RBUF_MIN.
    - `lo`: Buffer bytes [0,rbuf_lo) have been read and restored.
    - `ready`: Number of compressed bytes that haven't been processed, ensuring 0<=rbuf_lo<=(rbuf_lo+rbuf_ready)<=rbuf_sz.
- **Description**: The `fd_restore_private_rbuf` structure is designed to manage a buffer of compressed bytes that are read from a file descriptor during a restore operation. It maintains a buffer (`mem`) of a specified size (`sz`), which must be at least the minimum required for a restore operation. The structure tracks the portion of the buffer that has been read and restored (`lo`) and the number of bytes that are ready to be processed (`ready`). This structure is crucial for handling streaming data efficiently during the restoration process, ensuring that data is processed in a controlled and orderly manner.


---
### fd\_restore\_private\_rbuf\_t
- **Type**: `typedef struct fd_restore_private_rbuf fd_restore_private_rbuf_t;`
- **Members**:
    - `mem`: Buffer of compressed bytes read from fd, byte indexed [0,rbuf_sz).
    - `sz`: Buffer size in bytes, must be at least FD_RESTORE_RBUF_MIN.
    - `lo`: Buffer bytes [0,rbuf_lo) have been read and restored.
    - `ready`: Number of compressed bytes that haven't been processed, ensuring 0<=rbuf_lo<=(rbuf_lo+rbuf_ready)<=rbuf_sz.
- **Description**: The `fd_restore_private_rbuf_t` structure is designed to manage a buffer of compressed bytes that are read from a file descriptor during a restore operation. It keeps track of the buffer's size, the portion of the buffer that has been read and restored, and the number of bytes that are ready to be processed. This structure is crucial for handling streaming mode restores efficiently, ensuring that data is read and processed correctly from the buffer.


---
### fd\_restore\_private\_mmio
- **Type**: `struct`
- **Members**:
    - `mem`: A pointer to a constant unsigned character array representing a checkpoint memory region.
- **Description**: The `fd_restore_private_mmio` structure is used to represent a memory-mapped input/output (MMIO) region for restoring checkpoints. It contains a single member, `mem`, which is a pointer to a constant unsigned character array. This array represents the memory region that is indexed from 0 to the size of the region, which is not explicitly stored in this structure. This structure is part of the internal implementation for handling checkpoint restoration in memory-mapped mode, where the checkpoint data is directly accessed from memory rather than through streaming I/O.


---
### fd\_restore\_private\_mmio\_t
- **Type**: `struct`
- **Members**:
    - `mem`: Pointer to the checkpoint memory region, indexed [0,sz).
    - `sz`: Size of the checkpoint memory region in bytes.
- **Description**: The `fd_restore_private_mmio_t` structure is used to manage memory-mapped I/O operations for restoring checkpoints. It contains a pointer to a memory region (`mem`) and the size of this region (`sz`), allowing for efficient access and manipulation of checkpoint data stored in memory.


---
### fd\_restore\_private
- **Type**: `struct`
- **Members**:
    - `fd`: File descriptor for the restore, with a value of -1 for mmio mode.
    - `frame_style`: Indicates the frame style, with positive values for valid frames, 0 for not in frame, and -1 for failed frames.
    - `lz4`: Pointer to the handle of the underlying decompressor used.
    - `sbuf_cursor`: Cursor for small buffer scatter optimizations, ranging from 0 to FD_RESTORE_PRIVATE_SBUF_SZ.
    - `sz`: Size of the file or mmio region, with ULONG_MAX indicating non-seekable streams.
    - `off`: Offset of the next byte to read, relative to the start of the file or mmio region.
    - `rbuf`: Used in streaming mode for buffered reading.
    - `mmio`: Used in mmio mode for memory-mapped I/O.
    - `sbuf`: Buffer for scatter optimization, with a size defined by FD_RESTORE_PRIVATE_SBUF_SZ.
- **Description**: The `fd_restore_private` structure is designed to manage the state and operations of a restore process, either in streaming or memory-mapped I/O (mmio) mode. It holds critical information such as the file descriptor, frame style, and decompression handle, along with buffers and cursors for optimizing data restoration. The structure supports both streaming and mmio modes through a union, allowing it to handle different I/O strategies efficiently. The `sbuf` is used for scatter optimizations, enhancing performance during data restoration.


# Functions

---
### fd\_checkpt\_is\_mmio<!-- {{#callable:fd_checkpt_is_mmio}} -->
The function `fd_checkpt_is_mmio` checks if a given checkpoint is in memory-mapped I/O mode by evaluating the file descriptor.
- **Inputs**:
    - `checkpt`: A pointer to a constant `fd_checkpt_t` structure representing the checkpoint to be checked.
- **Control Flow**:
    - The function accesses the `fd` field of the `fd_checkpt_t` structure pointed to by `checkpt`.
    - It checks if the `fd` field is less than 0, which indicates memory-mapped I/O mode.
- **Output**: Returns an integer: 1 if the checkpoint is in memory-mapped I/O mode (i.e., `fd` is less than 0), otherwise 0.


---
### fd\_checkpt\_fd<!-- {{#callable:fd_checkpt_fd}} -->
The `fd_checkpt_fd` function retrieves the file descriptor associated with a given checkpoint object.
- **Inputs**:
    - `checkpt`: A pointer to a constant `fd_checkpt_t` structure representing the checkpoint from which the file descriptor is to be retrieved.
- **Control Flow**:
    - The function accesses the `fd` member of the `fd_checkpt_t` structure pointed to by `checkpt`.
- **Output**: The function returns an integer representing the file descriptor associated with the checkpoint.


---
### fd\_checkpt\_wbuf<!-- {{#callable:fd_checkpt_wbuf}} -->
The `fd_checkpt_wbuf` function returns the memory buffer used for write operations in a streaming checkpoint.
- **Inputs**:
    - `checkpt`: A pointer to a `fd_checkpt_t` structure representing the checkpoint in streaming mode.
- **Control Flow**:
    - The function accesses the `wbuf` member of the `checkpt` structure, which is a union member used in streaming mode.
    - It returns the `mem` field of the `wbuf`, which is a pointer to the memory buffer used for write operations.
- **Output**: A pointer to the memory buffer (`void *`) used for write operations in the checkpoint.


---
### fd\_checkpt\_wbuf\_sz<!-- {{#callable:fd_checkpt_wbuf_sz}} -->
The `fd_checkpt_wbuf_sz` function returns the size of the write buffer used in a streaming checkpoint.
- **Inputs**:
    - `checkpt`: A pointer to a constant `fd_checkpt_t` structure representing the checkpoint whose write buffer size is to be retrieved.
- **Control Flow**:
    - The function accesses the `wbuf` member of the `fd_checkpt_t` structure pointed to by `checkpt`.
    - It retrieves the `sz` field from the `wbuf` structure, which represents the size of the write buffer.
- **Output**: The function returns an `ulong` representing the size of the write buffer in bytes.


---
### fd\_checkpt\_mmio<!-- {{#callable:fd_checkpt_mmio}} -->
The `fd_checkpt_mmio` function retrieves the memory region pointer used for memory-mapped I/O in a checkpoint.
- **Inputs**:
    - `checkpt`: A pointer to an `fd_checkpt_t` structure, which represents an in-progress checkpoint.
- **Control Flow**:
    - The function accesses the `mmio` member of the `fd_checkpt_t` structure pointed to by `checkpt`.
    - It returns the `mem` field of the `mmio` structure, which is a pointer to the memory region used for memory-mapped I/O.
- **Output**: A pointer to the memory region used for memory-mapped I/O in the checkpoint.


---
### fd\_checkpt\_mmio\_sz<!-- {{#callable:fd_checkpt_mmio_sz}} -->
The `fd_checkpt_mmio_sz` function returns the size of the memory-mapped I/O region for a given checkpoint.
- **Inputs**:
    - `checkpt`: A pointer to a constant `fd_checkpt_t` structure representing the checkpoint whose memory-mapped I/O size is to be retrieved.
- **Control Flow**:
    - The function accesses the `mmio` member of the `fd_checkpt_t` structure pointed to by `checkpt`.
    - It then retrieves the `sz` member from the `mmio` structure, which represents the size of the memory-mapped I/O region.
- **Output**: The function returns an `ulong` representing the size of the memory-mapped I/O region for the specified checkpoint.


---
### fd\_checkpt\_can\_open<!-- {{#callable:fd_checkpt_can_open}} -->
The `fd_checkpt_can_open` function checks if a new frame can be opened in a checkpoint by verifying if the current frame style is zero.
- **Inputs**:
    - `checkpt`: A pointer to a constant `fd_checkpt_t` structure representing the checkpoint to be checked.
- **Control Flow**:
    - The function accesses the `frame_style` member of the `fd_checkpt_t` structure pointed to by `checkpt`.
    - It returns the negation of the `frame_style` value, which evaluates to true (1) if `frame_style` is zero, indicating that a new frame can be opened.
- **Output**: An integer value, 1 if a new frame can be opened (i.e., `frame_style` is zero), or 0 otherwise.


---
### fd\_checkpt\_in\_frame<!-- {{#callable:fd_checkpt_in_frame}} -->
The `fd_checkpt_in_frame` function checks if a given checkpoint is currently within a frame.
- **Inputs**:
    - `checkpt`: A pointer to a constant `fd_checkpt_t` structure representing the checkpoint to be checked.
- **Control Flow**:
    - The function accesses the `frame_style` member of the `fd_checkpt_t` structure pointed to by `checkpt`.
    - It evaluates whether `frame_style` is greater than 0, indicating that the checkpoint is in a frame.
- **Output**: The function returns an integer value: 1 if the checkpoint is in a frame (i.e., `frame_style` is greater than 0), and 0 otherwise.


---
### fd\_checkpt\_open<!-- {{#callable:fd_checkpt_open}} -->
The `fd_checkpt_open` function opens a new frame in a checkpoint with a specified frame style.
- **Inputs**:
    - `checkpt`: A pointer to an `fd_checkpt_t` structure representing the checkpoint to open a frame in.
    - `frame_style`: An integer specifying the style of the frame to open, which can be one of the defined frame styles like `FD_CHECKPT_FRAME_STYLE_RAW` or `FD_CHECKPT_FRAME_STYLE_LZ4`.
- **Control Flow**:
    - Declare a variable `off` of type `ulong` to store the offset of the frame.
    - Call the [`fd_checkpt_open_advanced`](fd_checkpt.c.driver.md#fd_checkpt_open_advanced) function with `checkpt`, `frame_style`, and the address of `off` as arguments.
    - Return the result of the [`fd_checkpt_open_advanced`](fd_checkpt.c.driver.md#fd_checkpt_open_advanced) function call.
- **Output**: Returns an integer indicating success (`FD_CHECKPT_SUCCESS`) or an error code (`FD_CHECKPT_ERR_*`) if the operation fails.
- **Functions called**:
    - [`fd_checkpt_open_advanced`](fd_checkpt.c.driver.md#fd_checkpt_open_advanced)


---
### fd\_checkpt\_close<!-- {{#callable:fd_checkpt_close}} -->
The `fd_checkpt_close` function closes the current frame in a checkpoint and returns the result of the closure operation.
- **Inputs**:
    - `checkpt`: A pointer to an `fd_checkpt_t` structure representing the checkpoint that is currently in a frame.
- **Control Flow**:
    - Declare a variable `off` of type `ulong` to store the offset of the closed frame.
    - Call the [`fd_checkpt_close_advanced`](fd_checkpt.c.driver.md#fd_checkpt_close_advanced) function with `checkpt` and the address of `off` as arguments.
    - Return the result of the [`fd_checkpt_close_advanced`](fd_checkpt.c.driver.md#fd_checkpt_close_advanced) function call.
- **Output**: Returns an integer indicating the success or failure of closing the current frame, with `FD_CHECKPT_SUCCESS` (0) on success or a negative error code on failure.
- **Functions called**:
    - [`fd_checkpt_close_advanced`](fd_checkpt.c.driver.md#fd_checkpt_close_advanced)


---
### fd\_restore\_is\_mmio<!-- {{#callable:fd_restore_is_mmio}} -->
The `fd_restore_is_mmio` function checks if a given `fd_restore_t` object is operating in memory-mapped I/O mode.
- **Inputs**:
    - `restore`: A pointer to a constant `fd_restore_t` structure representing the restore operation to be checked.
- **Control Flow**:
    - The function takes a pointer to a `fd_restore_t` structure as input.
    - It checks the `fd` field of the `fd_restore_t` structure.
    - If the `fd` field is less than 0, it indicates that the restore operation is in memory-mapped I/O mode.
    - The function returns the result of the comparison (`restore->fd < 0`).
- **Output**: An integer value, 1 if the restore operation is in memory-mapped I/O mode, and 0 if it is in streaming mode.


---
### fd\_restore\_fd<!-- {{#callable:fd_restore_fd}} -->
The `fd_restore_fd` function retrieves the file descriptor from a given `fd_restore_t` structure.
- **Inputs**:
    - `restore`: A pointer to a constant `fd_restore_t` structure from which the file descriptor is to be retrieved.
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and should be inlined by the compiler for performance.
    - The function takes a single argument, a pointer to a constant `fd_restore_t` structure.
    - It directly accesses the `fd` member of the `fd_restore_t` structure and returns its value.
- **Output**: The function returns an integer representing the file descriptor stored in the `fd_restore_t` structure.


---
### fd\_restore\_rbuf<!-- {{#callable:fd_restore_rbuf}} -->
The `fd_restore_rbuf` function retrieves the memory buffer used for reading compressed data in a streaming restore operation.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure representing the current restore operation.
- **Control Flow**:
    - The function accesses the `rbuf` member of the `restore` structure, which is a union containing the read buffer information.
    - It returns the `mem` field of the `rbuf`, which points to the memory buffer used for reading compressed data.
- **Output**: A pointer to the memory buffer (`void *`) used for reading compressed data in the restore operation.


---
### fd\_restore\_rbuf\_sz<!-- {{#callable:fd_restore_rbuf_sz}} -->
The `fd_restore_rbuf_sz` function retrieves the size of the read buffer from a given `fd_restore_t` structure.
- **Inputs**:
    - `restore`: A pointer to a constant `fd_restore_t` structure from which the read buffer size is to be retrieved.
- **Control Flow**:
    - The function accesses the `rbuf` member of the `fd_restore_t` structure pointed to by `restore`.
    - It then returns the `sz` member of the `rbuf` structure, which represents the size of the read buffer.
- **Output**: The function returns an `ulong` representing the size of the read buffer in the `fd_restore_t` structure.


---
### fd\_restore\_mmio<!-- {{#callable:fd_restore_mmio}} -->
The `fd_restore_mmio` function retrieves the memory-mapped input/output (MMIO) memory region from a given `fd_restore_t` structure.
- **Inputs**:
    - `restore`: A pointer to a constant `fd_restore_t` structure from which the MMIO memory region is to be retrieved.
- **Control Flow**:
    - The function accesses the `mmio` member of the `restore` structure, which is a union containing a `fd_restore_private_mmio_t` structure.
    - It returns the `mem` member of the `fd_restore_private_mmio_t` structure, which points to the MMIO memory region.
- **Output**: A constant pointer to the MMIO memory region within the `fd_restore_t` structure.


---
### fd\_restore\_mmio\_sz<!-- {{#callable:fd_restore_mmio_sz}} -->
The `fd_restore_mmio_sz` function returns the size of the memory-mapped I/O region for a given restore operation.
- **Inputs**:
    - `restore`: A pointer to a constant `fd_restore_t` structure representing the restore operation.
- **Control Flow**:
    - The function accesses the `sz` field of the `fd_restore_t` structure pointed to by `restore`.
    - It returns the value of the `sz` field, which represents the size of the memory-mapped I/O region.
- **Output**: The function returns an `ulong` representing the size of the memory-mapped I/O region for the restore operation.


---
### fd\_restore\_can\_open<!-- {{#callable:fd_restore_can_open}} -->
The `fd_restore_can_open` function checks if a restore operation can open a new frame by evaluating the frame style of the restore object.
- **Inputs**:
    - `restore`: A pointer to a constant `fd_restore_t` structure representing the restore operation.
- **Control Flow**:
    - The function takes a single argument, `restore`, which is a pointer to a constant `fd_restore_t` structure.
    - It checks the `frame_style` member of the `restore` structure.
    - The function returns the negation of the `frame_style`, meaning it returns 1 if `frame_style` is 0, indicating that a new frame can be opened, and 0 otherwise.
- **Output**: An integer value, 1 if a new frame can be opened (i.e., `frame_style` is 0), and 0 otherwise.


---
### fd\_restore\_in\_frame<!-- {{#callable:fd_restore_in_frame}} -->
The `fd_restore_in_frame` function checks if a restore operation is currently within a frame by evaluating the `frame_style` attribute of the `fd_restore_t` structure.
- **Inputs**:
    - `restore`: A pointer to a constant `fd_restore_t` structure, representing the current state of a restore operation.
- **Control Flow**:
    - The function accesses the `frame_style` attribute of the `restore` structure.
    - It checks if `frame_style` is greater than 0.
    - If `frame_style` is greater than 0, it returns 1, indicating that the restore is in a frame.
    - If `frame_style` is not greater than 0, it returns 0, indicating that the restore is not in a frame.
- **Output**: The function returns an integer: 1 if the restore is in a frame, and 0 otherwise.


---
### fd\_restore\_sz<!-- {{#callable:fd_restore_sz}} -->
The `fd_restore_sz` function returns the size of the checkpoint associated with a given `fd_restore_t` object.
- **Inputs**:
    - `restore`: A pointer to a constant `fd_restore_t` structure representing the restore operation whose checkpoint size is to be retrieved.
- **Control Flow**:
    - The function accesses the `sz` member of the `fd_restore_t` structure pointed to by `restore`.
    - It returns the value of the `sz` member, which represents the size of the checkpoint.
- **Output**: The function returns an `ulong` representing the size of the checkpoint associated with the `fd_restore_t` object.


---
### fd\_restore\_open<!-- {{#callable:fd_restore_open}} -->
The `fd_restore_open` function opens a new frame for restoration using a specified frame style.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure representing the restore context.
    - `frame_style`: An integer specifying the style of the frame to be opened, which can be one of the predefined frame styles like `FD_CHECKPT_FRAME_STYLE_RAW` or `FD_CHECKPT_FRAME_STYLE_LZ4`.
- **Control Flow**:
    - Declare a variable `off` of type `ulong` to store the offset of the frame.
    - Call the [`fd_restore_open_advanced`](fd_restore.c.driver.md#fd_restore_open_advanced) function with `restore`, `frame_style`, and the address of `off` as arguments.
    - Return the result of the [`fd_restore_open_advanced`](fd_restore.c.driver.md#fd_restore_open_advanced) function call.
- **Output**: Returns an integer indicating success (`FD_CHECKPT_SUCCESS`) or an error code (`FD_CHECKPT_ERR_*`) if the operation fails.
- **Functions called**:
    - [`fd_restore_open_advanced`](fd_restore.c.driver.md#fd_restore_open_advanced)


---
### fd\_restore\_close<!-- {{#callable:fd_restore_close}} -->
The `fd_restore_close` function closes the current frame in a restore operation and returns the offset of one past the last byte of the closed frame.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure representing the current restore operation.
- **Control Flow**:
    - Declare a variable `off` of type `ulong`.
    - Call the function [`fd_restore_close_advanced`](fd_restore.c.driver.md#fd_restore_close_advanced) with `restore` and the address of `off` as arguments.
    - Return the result of [`fd_restore_close_advanced`](fd_restore.c.driver.md#fd_restore_close_advanced).
- **Output**: An integer indicating success (`FD_CHECKPT_SUCCESS`) or a specific error code (`FD_CHECKPT_ERR_*`) if the operation fails.
- **Functions called**:
    - [`fd_restore_close_advanced`](fd_restore.c.driver.md#fd_restore_close_advanced)


# Function Declarations (Public API)

---
### fd\_checkpt\_init\_mmio<!-- {{#callable_declaration:fd_checkpt_init_mmio}} -->
Initializes a checkpoint in memory-mapped I/O mode.
- **Description**: This function sets up a checkpoint object in memory-mapped I/O mode using a specified memory region. It should be called when you want to create a checkpoint that writes frames directly into a memory region instead of streaming to a file. The function requires a properly aligned memory region for the checkpoint object and a valid memory region for the memory-mapped I/O. If the inputs are invalid, such as a null memory pointer or misaligned memory, the function will return null and log a warning.
- **Inputs**:
    - `mem`: A pointer to a memory region where the checkpoint object will be initialized. Must not be null and must be aligned according to FD_CHECKPT_ALIGN. The caller retains ownership.
    - `mmio`: A pointer to the memory-mapped I/O region where checkpoint frames will be stored. Can be null if mmio_sz is zero. The caller retains ownership.
    - `mmio_sz`: The size of the memory-mapped I/O region in bytes. If non-zero, mmio must not be null.
- **Output**: Returns a pointer to the initialized checkpoint object on success, or null on failure.
- **See also**: [`fd_checkpt_init_mmio`](fd_checkpt.c.driver.md#fd_checkpt_init_mmio)  (Implementation)


---
### fd\_checkpt\_fini<!-- {{#callable_declaration:fd_checkpt_fini}} -->
Finalize a checkpoint operation and release resources.
- **Description**: This function is used to finalize a checkpoint operation, ensuring that all resources associated with the checkpoint are properly released. It should be called when a checkpoint is no longer needed and must not be in a frame when called. If the checkpoint is in a frame or if the provided pointer is null, the function will log a warning and return null, indicating failure. On successful completion, it returns the memory region associated with the checkpoint, and the caller regains ownership of any resources used during the checkpoint process.
- **Inputs**:
    - `checkpt`: A pointer to a valid fd_checkpt_t structure representing the checkpoint to be finalized. It must not be null and must not be in a frame. If these conditions are not met, the function logs a warning and returns null.
- **Output**: Returns a pointer to the memory region associated with the checkpoint on success, or null on failure.
- **See also**: [`fd_checkpt_fini`](fd_checkpt.c.driver.md#fd_checkpt_fini)  (Implementation)


---
### fd\_checkpt\_open\_advanced<!-- {{#callable_declaration:fd_checkpt_open_advanced}} -->
Opens a new frame in a checkpoint with a specified style.
- **Description**: Use this function to open a new frame in a checkpoint, specifying the frame style to be used. This function should be called when the checkpoint is valid and not currently in a frame or failed. It allows for parallel restoration of frames by providing the offset of the frame from the beginning of the checkpoint. Ensure that the frame style is supported on the target platform. If the function fails, it logs the error and returns a negative error code, leaving the checkpoint in a failed state.
- **Inputs**:
    - `checkpt`: A pointer to a valid fd_checkpt_t structure. Must not be null and should not be in a frame or failed state.
    - `frame_style`: An integer specifying the frame style, using FD_CHECKPT_FRAME_STYLE_* constants. A value of 0 defaults to FD_CHECKPT_FRAME_STYLE_DEFAULT. Unsupported styles will result in an error.
    - `_off`: A pointer to an unsigned long where the offset of the frame will be stored. Must not be null.
- **Output**: Returns FD_CHECKPT_SUCCESS (0) on success, with *_off set to the frame's offset. On failure, returns a negative FD_CHECKPT_ERR code and leaves *_off unchanged.
- **See also**: [`fd_checkpt_open_advanced`](fd_checkpt.c.driver.md#fd_checkpt_open_advanced)  (Implementation)


---
### fd\_checkpt\_close\_advanced<!-- {{#callable_declaration:fd_checkpt_close_advanced}} -->
Closes the current frame in a checkpoint.
- **Description**: Use this function to close a frame in a checkpoint when it is valid and currently in a frame. This function finalizes the frame, ensuring all data is written and updates the offset to reflect the end of the frame. It is important to call this function after finishing data operations on a frame to maintain the integrity of the checkpoint. If the function fails, it logs the error and the checkpoint should be considered failed, requiring cleanup and discard of the checkpoint data.
- **Inputs**:
    - `checkpt`: A pointer to a valid fd_checkpt_t structure that is currently in a frame. Must not be null.
    - `_off`: A pointer to an unsigned long where the function will store the offset of one past the last byte of the closed frame. Must not be null.
- **Output**: Returns FD_CHECKPT_SUCCESS (0) on success, or a negative FD_CHECKPT_ERR code on failure. On success, *_off is updated with the new offset.
- **See also**: [`fd_checkpt_close_advanced`](fd_checkpt.c.driver.md#fd_checkpt_close_advanced)  (Implementation)


---
### fd\_checkpt\_meta<!-- {{#callable_declaration:fd_checkpt_meta}} -->
Checkpoints a metadata buffer into a frame.
- **Description**: Use this function to checkpoint a metadata buffer into an existing frame within a checkpoint. It is essential that the checkpoint is valid and currently in a frame before calling this function. The size of the buffer must not exceed FD_CHECKPT_META_MAX, and it is permissible for the size to be zero, in which case the buffer can be null. This function does not retain any interest in the buffer after execution, and it returns a status code indicating success or the type of error encountered.
- **Inputs**:
    - `checkpt`: A pointer to a valid fd_checkpt_t structure that is currently in a frame. Must not be null.
    - `buf`: A pointer to the buffer containing the metadata to be checkpointed. Can be null if sz is zero.
    - `sz`: The size of the buffer in bytes. Must be at most FD_CHECKPT_META_MAX. Zero is allowed.
- **Output**: Returns FD_CHECKPT_SUCCESS on success, or a negative FD_CHECKPT_ERR code on failure, indicating the type of error.
- **See also**: [`fd_checkpt_meta`](fd_checkpt.c.driver.md#fd_checkpt_meta)  (Implementation)


---
### fd\_checkpt\_data<!-- {{#callable_declaration:fd_checkpt_data}} -->
Checkpoints a data buffer into an ongoing frame.
- **Description**: Use this function to add a data buffer to an ongoing frame within a checkpoint. The checkpoint must be valid and currently in a frame. The function allows for checkpointing of data buffers of any practical size, including zero-length buffers. It is important to ensure that the data buffer remains unchanged and accessible until the frame is closed, as the checkpoint retains an interest in the buffer until that point. This function is suitable for checkpointing large data buffers, whereas `fd_checkpt_meta` should be used for smaller metadata buffers.
- **Inputs**:
    - `checkpt`: A pointer to a valid `fd_checkpt_t` structure that is currently in a frame. Must not be null.
    - `buf`: A pointer to the data buffer to be checkpointed. Can be null if `sz` is zero. The buffer must remain unchanged and accessible until the frame is closed.
    - `sz`: The size of the data buffer in bytes. Can be zero, in which case `buf` can be null.
- **Output**: Returns `FD_CHECKPT_SUCCESS` (0) on success. On failure, returns a negative `FD_CHECKPT_ERR` code and logs details. Possible errors include invalid input, I/O errors, or compression errors.
- **See also**: [`fd_checkpt_data`](fd_checkpt.c.driver.md#fd_checkpt_data)  (Implementation)


---
### fd\_restore\_init\_stream<!-- {{#callable_declaration:fd_restore_init_stream}} -->
Initializes a restore operation in streaming mode.
- **Description**: This function sets up a memory region to be used as a restore handle for reading checkpoint data from a file descriptor in streaming mode. It should be called when you want to begin restoring data from a checkpoint that is stored in a file or stream. The function requires a memory region with proper alignment and a read buffer of sufficient size. It returns a handle that can be used for subsequent restore operations. If any input parameters are invalid, the function logs a warning and returns NULL, indicating failure.
- **Inputs**:
    - `mem`: A pointer to a memory region that will be formatted as a fd_restore_t. Must not be null and must be properly aligned according to FD_RESTORE_ALIGN.
    - `fd`: An open file descriptor from which the checkpoint data will be read. Must be non-negative.
    - `rbuf`: A pointer to a memory region used for read buffering. Must not be null.
    - `rbuf_sz`: The size of the read buffer. Must be at least FD_RESTORE_RBUF_MIN.
- **Output**: Returns a pointer to the initialized fd_restore_t on success, or NULL on failure.
- **See also**: [`fd_restore_init_stream`](fd_restore.c.driver.md#fd_restore_init_stream)  (Implementation)


---
### fd\_restore\_init\_mmio<!-- {{#callable_declaration:fd_restore_init_mmio}} -->
Initializes a memory-mapped I/O restore operation.
- **Description**: This function sets up a memory region for a restore operation using memory-mapped I/O. It should be used when you have a memory-mapped region containing checkpoint frames that need to be restored. The function requires a properly aligned memory region for the restore state and a valid memory-mapped region with a specified size. It returns a pointer to the initialized restore structure or NULL if any input validation fails, such as misaligned memory or invalid size parameters.
- **Inputs**:
    - `mem`: A pointer to a memory region where the restore state will be initialized. Must not be null and must be aligned according to FD_RESTORE_ALIGN. The caller retains ownership.
    - `mmio`: A pointer to the start of the memory-mapped region containing the checkpoint frames. Can be null if mmio_sz is zero. The caller retains ownership.
    - `mmio_sz`: The size of the memory-mapped region in bytes. Must be less than or equal to LONG_MAX. If mmio is null, this must be zero.
- **Output**: Returns a pointer to the initialized fd_restore_t structure on success, or NULL on failure due to invalid input parameters.
- **See also**: [`fd_restore_init_mmio`](fd_restore.c.driver.md#fd_restore_init_mmio)  (Implementation)


---
### fd\_restore\_fini<!-- {{#callable_declaration:fd_restore_fini}} -->
Finalize a restore operation and release resources.
- **Description**: This function is used to finalize a restore operation, ensuring that all resources associated with the restore are properly released. It should be called when the restore process is complete and the `fd_restore_t` is no longer needed. The function must be called when the restore is not in a frame, and it will return ownership of the memory, file descriptor, and buffer used during the restore process. If the restore is in a frame or if the `restore` pointer is null, the function will log a warning and return `NULL`, indicating that the operation failed.
- **Inputs**:
    - `restore`: A pointer to a `fd_restore_t` structure representing the restore operation to be finalized. Must not be null and must not be in a frame. If invalid, the function logs a warning and returns `NULL`.
- **Output**: Returns a pointer to the memory region used for the restore on success, or `NULL` on failure.
- **See also**: [`fd_restore_fini`](fd_restore.c.driver.md#fd_restore_fini)  (Implementation)


---
### fd\_restore\_open\_advanced<!-- {{#callable_declaration:fd_restore_open_advanced}} -->
Opens a new frame for restoring data from a checkpoint.
- **Description**: This function is used to open a new frame in a checkpoint for restoration, allowing different frames to be restored in parallel. It should be called when the restore object is valid and not currently in a frame or failed state. The function supports different frame styles, and the frame style specified should match the one used during the frame's creation. On success, it provides the offset of the frame from the beginning of the checkpoint, which can be used for parallel processing. If the function fails, it logs the error and returns a negative error code, leaving the offset unchanged. The restore object should be considered failed if an error occurs, and appropriate cleanup should be performed.
- **Inputs**:
    - `restore`: A pointer to a valid fd_restore_t object. Must not be null and should not be in a frame or failed state.
    - `frame_style`: An integer specifying the frame style to use, which should be a valid FD_CHECKPT_FRAME_STYLE_* value. If zero, the default frame style is used.
    - `_off`: A pointer to an unsigned long where the offset of the frame will be stored on success. Must not be null.
- **Output**: Returns FD_CHECKPT_SUCCESS (0) on success, with *_off set to the frame's offset. On failure, returns a negative FD_CHECKPT_ERR code and leaves *_off unchanged.
- **See also**: [`fd_restore_open_advanced`](fd_restore.c.driver.md#fd_restore_open_advanced)  (Implementation)


---
### fd\_restore\_close\_advanced<!-- {{#callable_declaration:fd_restore_close_advanced}} -->
Closes the current frame in a restore operation and provides the offset of the next byte.
- **Description**: Use this function to close a frame during a restore operation when the restore is valid and currently in a frame. It finalizes the frame restoration and provides the offset of the next byte after the frame, which is useful for tracking the range of bytes used by the frame. This function should be called only when the restore is in a frame, and it will return an error if the restore is null or not in a frame. On success, it updates the provided offset pointer with the next byte's offset.
- **Inputs**:
    - `restore`: A pointer to a valid fd_restore_t object that is currently in a frame. Must not be null.
    - `_off`: A pointer to an unsigned long where the offset of the next byte after the closed frame will be stored. Must not be null.
- **Output**: Returns FD_CHECKPT_SUCCESS (0) on success, updating *_off with the offset of the next byte after the frame. Returns FD_CHECKPT_ERR_INVAL (-1) if the restore is null or not in a frame, leaving *_off unchanged.
- **See also**: [`fd_restore_close_advanced`](fd_restore.c.driver.md#fd_restore_close_advanced)  (Implementation)


---
### fd\_restore\_seek<!-- {{#callable_declaration:fd_restore_seek}} -->
Sets the restore position to a specified offset.
- **Description**: Use this function to set the current position of a restore operation to a specific offset within the checkpoint data. This function should be called when the restore is valid, openable, and the underlying data is seekable. The offset must be within the valid range of the checkpoint size. If the restore is in streaming mode, seeking may flush the read-ahead buffer, so it should be minimized. On success, the restore will be ready to open a frame at the specified offset. If the function fails, it logs the error and returns a negative error code, indicating that the restore operation should be considered failed.
- **Inputs**:
    - `restore`: A pointer to a valid fd_restore_t structure. Must not be null and must be openable and seekable.
    - `off`: An unsigned long representing the offset to seek to. Must be within the range [0, sz], where sz is the size of the checkpoint.
- **Output**: Returns FD_CHECKPT_SUCCESS (0) on success, or a negative FD_CHECKPT_ERR_* code on failure, indicating the type of error.
- **See also**: [`fd_restore_seek`](fd_restore.c.driver.md#fd_restore_seek)  (Implementation)


---
### fd\_restore\_meta<!-- {{#callable_declaration:fd_restore_meta}} -->
Restores metadata from a checkpoint frame into a buffer.
- **Description**: This function is used to restore a specified amount of metadata from a checkpoint frame into a provided buffer. It should be called when the restore process is in a frame, and the size of the data to be restored does not exceed the maximum allowed size. The function is part of a sequence that must match the checkpoint creation sequence, ensuring that the metadata is restored correctly. It is important to handle the return value to check for any errors during the restoration process.
- **Inputs**:
    - `restore`: A pointer to a valid fd_restore_t structure, which must be in a frame. The caller retains ownership, and it must not be null.
    - `buf`: A pointer to the memory region where the restored metadata will be stored. It must be valid and non-null if sz is non-zero. The caller retains ownership.
    - `sz`: The size in bytes of the metadata to restore. It must be at most FD_RESTORE_META_MAX. A value of zero is allowed, in which case buf can be null.
- **Output**: Returns FD_CHECKPT_SUCCESS (0) on success, indicating that the metadata has been successfully restored into the buffer. On failure, it returns a negative FD_CHECKPT_ERR code, and the restore process should be considered failed.
- **See also**: [`fd_restore_meta`](fd_restore.c.driver.md#fd_restore_meta)  (Implementation)


---
### fd\_restore\_data<!-- {{#callable_declaration:fd_restore_data}} -->
Restores data from a checkpoint frame into a specified buffer.
- **Description**: Use this function to restore a specified number of bytes from a checkpoint frame into a provided buffer. It should be called when the restore object is valid and currently in a frame. This function is part of a sequence that must match the checkpoint creation sequence exactly, ensuring data integrity and consistency. The function handles both streaming and memory-mapped I/O modes, and it is crucial to maintain the buffer's existence and state until the frame is closed to avoid data corruption.
- **Inputs**:
    - `restore`: A pointer to a valid fd_restore_t object that is currently in a frame. Must not be null.
    - `buf`: A pointer to the memory region where the restored data will be placed. Must not be null if sz is non-zero.
    - `sz`: The number of bytes to restore into the buffer. There is no practical limitation on this size, and it can be zero, in which case buf can be null.
- **Output**: Returns FD_CHECKPT_SUCCESS (0) on success, indicating that the data has been restored into the buffer. On failure, it returns a negative FD_CHECKPT_ERR code, and the restore process should be considered failed.
- **See also**: [`fd_restore_data`](fd_restore.c.driver.md#fd_restore_data)  (Implementation)


---
### fd\_checkpt\_frame\_style\_is\_supported<!-- {{#callable_declaration:fd_checkpt_frame_style_is_supported}} -->
Determine if a frame style is supported on the current target.
- **Description**: Use this function to check if a specific frame style, identified by an integer code, is supported on the current target system. This is useful for ensuring compatibility before attempting to use a particular frame style in checkpoint operations. The function returns a non-zero value if the frame style is supported and zero if it is not. It is important to verify support for frame styles, especially when working with optional compression methods like LZ4, which may not be available on all systems.
- **Inputs**:
    - `frame_style`: An integer representing the frame style to check. Valid values are positive integers corresponding to defined frame styles, such as FD_CHECKPT_FRAME_STYLE_RAW or FD_CHECKPT_FRAME_STYLE_LZ4. The function will return zero for unsupported or invalid frame styles.
- **Output**: Returns 1 if the frame style is supported, otherwise returns 0.
- **See also**: [`fd_checkpt_frame_style_is_supported`](fd_checkpt.c.driver.md#fd_checkpt_frame_style_is_supported)  (Implementation)


---
### fd\_checkpt\_strerror<!-- {{#callable_declaration:fd_checkpt_strerror}} -->
Convert a checkpoint error code to a human-readable string.
- **Description**: Use this function to obtain a descriptive string for a given checkpoint error code, which can be useful for logging or displaying error messages to users. The function accepts an error code and returns a constant string that describes the error. It handles known error codes by returning specific messages and defaults to "unknown" for unrecognized codes. This function is safe to call with any integer value, and it will always return a valid string.
- **Inputs**:
    - `err`: An integer representing the error code to be converted. Valid values include FD_CHECKPT_SUCCESS, FD_CHECKPT_ERR_INVAL, FD_CHECKPT_ERR_UNSUP, FD_CHECKPT_ERR_IO, and FD_CHECKPT_ERR_COMP. The function will return "unknown" for any other values.
- **Output**: A constant string describing the error code. The string is always valid and non-null.
- **See also**: [`fd_checkpt_strerror`](fd_checkpt.c.driver.md#fd_checkpt_strerror)  (Implementation)


