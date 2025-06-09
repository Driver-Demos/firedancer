# Purpose
This C header file defines the interface for managing file-backed instances of a "funk" data structure, which appears to be a specialized data management or transaction system. It includes an enumeration `fd_funk_file_mode` to specify different modes for opening or creating files, such as read-only, read-write, create, overwrite, and exclusive creation. The file also defines a structure `fd_funk_close_file_args_t` to hold parameters necessary for closing a file, which are initialized during the file opening process. The functions [`fd_funk_open_file`](#fd_funk_open_file), [`fd_funk_recover_checkpoint`](#fd_funk_recover_checkpoint), and [`fd_funk_close_file`](#fd_funk_close_file) provide the core functionality for opening, recovering, and closing these funk instances, respectively. These functions facilitate the management of file-backed data, allowing for operations like creating new instances, recovering from checkpoints, and ensuring proper resource cleanup.
# Imports and Dependencies

---
- `fd_funk.h`


# Global Variables

---
### fd\_funk\_open\_file
- **Type**: `fd_funk_t *`
- **Description**: The `fd_funk_open_file` function is a global function that returns a pointer to a `fd_funk_t` structure. It is responsible for opening or creating a funk instance, potentially with a memory-mapped file as backing storage. The function takes several parameters, including a filename for the backing file, workspace partition tag, hash seed, maximum number of transactions and records, total workspace size, file mode, and an optional pointer to a structure for closing arguments.
- **Use**: This function is used to initialize and open a funk instance, setting up necessary resources and configurations based on the provided parameters.


---
### fd\_funk\_recover\_checkpoint
- **Type**: `function pointer`
- **Description**: `fd_funk_recover_checkpoint` is a function that loads a workspace checkpoint containing a funk instance. It takes parameters for a local join, a funk filename, a workspace tag, a checkpoint filename, and a pointer to a structure for closing file arguments.
- **Use**: This function is used to recover a funk instance from a checkpoint file, allowing the system to restore its state from a saved point.


# Data Structures

---
### fd\_funk\_file\_mode
- **Type**: `enum`
- **Members**:
    - `FD_FUNK_READONLY`: Only open the file if it already exists, memory is marked readonly.
    - `FD_FUNK_READ_WRITE`: Only open the file if it already exists, can be written to.
    - `FD_FUNK_CREATE`: Use an existing file if available, otherwise create.
    - `FD_FUNK_OVERWRITE`: Create new or overwrite existing with a fresh instance.
    - `FD_FUNK_CREATE_EXCL`: Fail if file exists, only create new.
- **Description**: The `fd_funk_file_mode` is an enumeration that defines various modes for handling file operations in the context of a funk instance. It specifies whether a file should be opened in read-only mode, read-write mode, created if it doesn't exist, overwritten, or exclusively created if it doesn't already exist. This enumeration is used to control the behavior of file operations, ensuring that the correct mode is applied based on the desired file handling strategy.


---
### fd\_funk\_file\_mode\_t
- **Type**: `enum`
- **Members**:
    - `FD_FUNK_READONLY`: Only open the file if it already exists, memory is marked readonly.
    - `FD_FUNK_READ_WRITE`: Only open the file if it already exists, can be written to.
    - `FD_FUNK_CREATE`: Use an existing file if available, otherwise create.
    - `FD_FUNK_OVERWRITE`: Create new or overwrite existing with a fresh instance.
    - `FD_FUNK_CREATE_EXCL`: Fail if file exists, only create new.
- **Description**: The `fd_funk_file_mode_t` is an enumeration that defines various modes for handling file operations in the context of a funk instance. It specifies whether a file should be opened in read-only mode, read-write mode, created if it doesn't exist, overwritten, or exclusively created if it doesn't already exist. This enumeration is used to control the behavior of file operations in functions like `fd_funk_open_file`, ensuring that the file handling aligns with the desired operational requirements.


---
### fd\_funk\_close\_file\_args
- **Type**: `struct`
- **Members**:
    - `shmem`: A pointer to shared memory associated with the file.
    - `fd`: An integer representing the file descriptor of the open file.
    - `total_sz`: An unsigned long representing the total size of the file or memory region.
- **Description**: The `fd_funk_close_file_args` structure is used to encapsulate the parameters required for closing a file in the funk file mapping system. It includes a pointer to shared memory (`shmem`), a file descriptor (`fd`), and the total size of the file or memory region (`total_sz`). This structure is typically initialized during the file opening process and is necessary for properly releasing resources when closing the file.


---
### fd\_funk\_close\_file\_args\_t
- **Type**: `struct`
- **Members**:
    - `shmem`: A pointer to shared memory associated with the file.
    - `fd`: An integer representing the file descriptor of the open file.
    - `total_sz`: An unsigned long representing the total size of the funk workspace.
- **Description**: The `fd_funk_close_file_args_t` structure is used to store the necessary parameters for closing a funk file, specifically in the `fd_funk_close_file` function. It is initialized when a file is opened using `fd_funk_open_file` and contains a pointer to shared memory (`shmem`), the file descriptor (`fd`), and the total size of the funk workspace (`total_sz`). This structure is crucial for managing resources and ensuring proper closure of file mappings in the funk system.


# Function Declarations (Public API)

---
### fd\_funk\_open\_file<!-- {{#callable_declaration:fd_funk_open_file}} -->
Open or create a funk instance with an optional mmap backing file.
- **Description**: This function is used to open or create a funk instance, which can be backed by a memory-mapped file or be anonymous. It is suitable for scenarios where a persistent or temporary funk database is needed. The function requires a workspace partition tag, a hash seed, and limits on transactions and records, although these are ignored if an existing file is opened without being overwritten. The mode parameter determines the behavior regarding file creation and access permissions. If a file is used, it must be a valid path unless the mode allows for anonymous instances. The function can also output necessary parameters for closing the funk instance if a pointer is provided.
- **Inputs**:
    - `ljoin`: A pointer to a location where the funk instance will be joined. Must not be null.
    - `filename`: The name of the backing file for the funk instance, or NULL for an anonymous instance. If non-null, must be a valid file path.
    - `wksp_tag`: An unsigned long representing the workspace partition tag for the funk instance, typically set to 1.
    - `seed`: An unsigned long used as a randomized hash seed. Ignored if an existing file is opened without being overwritten.
    - `txn_max`: An unsigned long indicating the maximum number of transactions. Ignored if an existing file is opened without being overwritten.
    - `rec_max`: An unsigned long indicating the maximum number of records. Ignored if an existing file is opened without being overwritten.
    - `total_sz`: An unsigned long specifying the total size of the funk workspace. Must be a multiple of the system's page size. Ignored if an existing file is opened without being overwritten.
    - `mode`: A value of type fd_funk_file_mode_t that specifies the file mode, determining whether the file is opened, created, or overwritten.
    - `close_args_out`: An optional pointer to a fd_funk_close_file_args_t structure that will be filled with parameters needed to close the funk instance. Can be null if not needed.
- **Output**: Returns a pointer to the opened or created fd_funk_t instance, or NULL if an error occurs.
- **See also**: [`fd_funk_open_file`](fd_funk_filemap.c.driver.md#fd_funk_open_file)  (Implementation)


---
### fd\_funk\_recover\_checkpoint<!-- {{#callable_declaration:fd_funk_recover_checkpoint}} -->
Load a workspace checkpoint containing a funk instance.
- **Description**: This function is used to load a previously saved workspace checkpoint that contains a funk instance, allowing the user to restore the state of a funk from a checkpoint file. It can optionally use a backing file for memory mapping, or operate anonymously if no file is specified. The function requires a valid checkpoint file and a workspace partition tag, and it can output necessary parameters for closing the funk instance later. It returns a pointer to the loaded funk instance or NULL if an error occurs during the recovery process.
- **Inputs**:
    - `ljoin`: A pointer used for joining the funk instance. The caller retains ownership and it must be valid.
    - `funk_filename`: The name of the backing file for the funk instance, or NULL for an anonymous instance. If provided, it must be a valid file path or an empty string for anonymous operation.
    - `wksp_tag`: The workspace partition tag for the funk, typically set to 1. It must be a valid tag used to identify the partition within the workspace.
    - `checkpt_filename`: The name of the checkpoint file to be loaded. It must be a valid file path to an existing checkpoint file.
    - `close_args_out`: An optional pointer to a fd_funk_close_file_args_t structure that will be filled with parameters needed for closing the funk instance. If provided, it must be a valid pointer.
- **Output**: Returns a pointer to the loaded fd_funk_t instance if successful, or NULL if an error occurs during the recovery process.
- **See also**: [`fd_funk_recover_checkpoint`](fd_funk_filemap.c.driver.md#fd_funk_recover_checkpoint)  (Implementation)


---
### fd\_funk\_close\_file<!-- {{#callable_declaration:fd_funk_close_file}} -->
Release the resources associated with a funk file map.
- **Description**: This function should be called to properly release resources associated with a funk file map that was previously opened or created using `fd_funk_open_file` or `fd_funk_recover_checkpoint`. It ensures that any shared memory mappings and file descriptors are correctly closed, preventing resource leaks. This function must be called when the funk instance is no longer needed, and the `fd_funk_close_file_args_t` structure must have been properly initialized by one of the opening functions. Failure to call this function may result in resource leaks.
- **Inputs**:
    - `close_args`: A pointer to an `fd_funk_close_file_args_t` structure containing the parameters needed to close the funk file map. This structure must have been initialized by `fd_funk_open_file` or `fd_funk_recover_checkpoint`. The pointer must not be null, and the structure must contain valid data.
- **Output**: None
- **See also**: [`fd_funk_close_file`](fd_funk_filemap.c.driver.md#fd_funk_close_file)  (Implementation)


