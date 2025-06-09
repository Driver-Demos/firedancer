# Purpose
The provided C source code file, `fd_file_util.c`, is a utility library designed to perform various file and directory operations. It offers a collection of functions that facilitate reading and writing unsigned long and unsigned int values to and from files, creating directories recursively with specific ownership and permissions, removing directories and their contents, retrieving the path of the current executable, and reading the entire contents of a file into memory. These functions are implemented with a focus on error handling and robustness, using system calls and standard library functions to interact with the file system.

The file includes several key technical components, such as file descriptors, directory streams, and memory mapping, to achieve its functionality. It defines a set of public APIs that can be used by other parts of a program to perform file-related tasks efficiently. The functions are designed to handle edge cases, such as checking for errors during file operations and ensuring that resources like file descriptors are properly closed. This utility library is intended to be imported and used by other C programs that require file manipulation capabilities, providing a consistent and reliable interface for common file operations.
# Imports and Dependencies

---
- `fd_file_util.h`
- `stdio.h`
- `errno.h`
- `limits.h`
- `dirent.h`
- `fcntl.h`
- `stdlib.h`
- `unistd.h`
- `sys/stat.h`
- `sys/mman.h`


# Functions

---
### fd\_file\_util\_read\_ulong<!-- {{#callable:fd_file_util_read_ulong}} -->
The `fd_file_util_read_ulong` function reads an unsigned long integer from a file specified by its path.
- **Inputs**:
    - `path`: A constant character pointer representing the file path from which to read the unsigned long integer.
    - `value`: A pointer to an unsigned long where the read value will be stored.
- **Control Flow**:
    - Open the file at the specified path in read-only mode.
    - Check if the file descriptor is valid; if not, return -1 indicating an error.
    - Read up to 31 bytes from the file into a buffer, leaving space for a null terminator.
    - Check if the read operation was successful; if not, close the file and return -1.
    - Ensure that the number of bytes read is within the expected range; if not, set errno to EINVAL, close the file, and return -1.
    - Null-terminate the buffer to safely convert it to a string.
    - Close the file and check for errors during closing; if an error occurs, return -1.
    - Convert the string in the buffer to an unsigned long using `strtoul`, checking for range errors.
    - Ensure the conversion consumed the entire string (except for a newline or null terminator); if not, set errno to EINVAL and return -1.
    - Store the converted value in the provided `value` pointer and return 0 to indicate success.
- **Output**: Returns 0 on success, with the read unsigned long stored in the provided `value` pointer, or -1 on failure with errno set appropriately.


---
### fd\_file\_util\_read\_uint<!-- {{#callable:fd_file_util_read_uint}} -->
The `fd_file_util_read_uint` function reads an unsigned integer from a file specified by a path and stores it in a provided variable, ensuring the value fits within the range of an unsigned int.
- **Inputs**:
    - `path`: A constant character pointer representing the file path from which to read the unsigned integer.
    - `value`: A pointer to an unsigned integer where the read value will be stored.
- **Control Flow**:
    - Declare a variable `_value` of type `ulong` to temporarily store the read value.
    - Call [`fd_file_util_read_ulong`](#fd_file_util_read_ulong) with `path` and `_value` to read an unsigned long integer from the file.
    - Check if the return code `rc` from [`fd_file_util_read_ulong`](#fd_file_util_read_ulong) is -1, indicating an error, and return -1 if so.
    - Check if `_value` exceeds `UINT_MAX`, set `errno` to `ERANGE`, and return -1 if it does.
    - Cast `_value` to `uint` and store it in the location pointed to by `value`.
    - Return 0 to indicate success.
- **Output**: Returns 0 on success, or -1 if an error occurs (e.g., if the file cannot be read or the value exceeds the range of an unsigned int).
- **Functions called**:
    - [`fd_file_util_read_ulong`](#fd_file_util_read_ulong)


---
### fd\_file\_util\_write\_ulong<!-- {{#callable:fd_file_util_write_ulong}} -->
The `fd_file_util_write_ulong` function writes an unsigned long integer to a specified file, creating or truncating the file as necessary.
- **Inputs**:
    - `path`: A constant character pointer representing the file path where the unsigned long integer will be written.
    - `value`: An unsigned long integer that is to be written to the file.
- **Control Flow**:
    - Open the file at the specified path with write-only access, creating it if it doesn't exist and truncating it if it does.
    - Check if the file descriptor is valid; if not, return -1 indicating an error.
    - Format the unsigned long integer into a string buffer with a newline character appended.
    - Ensure the formatted string length is valid and within buffer limits.
    - Write the formatted string to the file and check if the write operation was successful and complete.
    - If the write operation fails or is incomplete, close the file and return -1 indicating an error.
    - Close the file descriptor and return 0 to indicate success.
- **Output**: Returns 0 on successful write and close operations, or -1 if any error occurs during file operations.


---
### fd\_file\_util\_mkdir\_all<!-- {{#callable:fd_file_util_mkdir_all}} -->
The `fd_file_util_mkdir_all` function creates a directory and all necessary parent directories specified by a given path, setting ownership and permissions for newly created directories.
- **Inputs**:
    - `_path`: A constant character pointer representing the path of the directory to be created.
    - `uid`: An unsigned integer representing the user ID to set as the owner of newly created directories.
    - `gid`: An unsigned integer representing the group ID to set as the group owner of newly created directories.
- **Control Flow**:
    - Initialize a character array `path` with a size of `PATH_MAX+1` and copy the input `_path` into it.
    - Set a pointer `p` to the start of `path` and increment it if the first character is a '/'.
    - Iterate through each character in `path` until the end of the string is reached.
    - If a '/' is encountered, temporarily replace it with a null terminator to create a sub-path and attempt to create a directory with `mkdir`.
    - If `mkdir` fails with an error other than `EEXIST`, return -1.
    - If a directory is successfully created, change its ownership to the specified `uid` and `gid` using `chown`, and set its permissions to `S_IRUSR | S_IWUSR | S_IXUSR` using `chmod`.
    - Restore the '/' character and continue iterating through the path.
    - After the loop, attempt to create the final directory specified by the full path, and apply the same ownership and permission settings if it is newly created.
    - Return 0 if all directories are successfully created or already exist.
- **Output**: Returns 0 on success, or -1 if an error occurs during directory creation, ownership change, or permission setting.


---
### fd\_file\_util\_rmtree<!-- {{#callable:fd_file_util_rmtree}} -->
The [`fd_file_util_rmtree`](#fd_file_util_rmtree) function recursively deletes a directory and its contents, optionally removing the root directory itself.
- **Inputs**:
    - `path`: A constant character pointer representing the path to the directory to be removed.
    - `remove_root`: An integer flag indicating whether the root directory should be removed (1 for true, 0 for false).
- **Control Flow**:
    - Open the directory specified by `path` using `opendir` and check if it was successful.
    - If the directory cannot be opened and the error is `ENOENT` (no such file or directory), return 0; otherwise, return -1.
    - Iterate over each entry in the directory using `readdir`.
    - Skip the entries for the current directory (`.`) and parent directory (`..`).
    - Construct the full path for each entry using `fd_cstr_printf_check` and check for buffer overflow.
    - Use `lstat` to get the status of each entry; if it fails and the error is `ENOENT`, continue to the next entry.
    - If the entry is a directory, recursively call [`fd_file_util_rmtree`](#fd_file_util_rmtree) on it with `remove_root` set to 1.
    - If the entry is a file, attempt to unlink (delete) it, and if it fails with an error other than `ENOENT`, return -1.
    - After processing all entries, close the directory stream with `closedir`.
    - If `remove_root` is true, attempt to remove the root directory using `rmdir`.
    - Return 0 on successful completion of all operations.
- **Output**: Returns 0 on successful deletion of the directory and its contents, or -1 if an error occurs during the process.
- **Functions called**:
    - [`fd_file_util_rmtree`](#fd_file_util_rmtree)


---
### fd\_file\_util\_self\_exe<!-- {{#callable:fd_file_util_self_exe}} -->
The `fd_file_util_self_exe` function retrieves the absolute path of the currently running executable and stores it in the provided buffer.
- **Inputs**:
    - `path`: A character array with a minimum size of PATH_MAX where the function will store the path of the current executable.
- **Control Flow**:
    - The function calls `readlink` on "/proc/self/exe" to get the path of the current executable and stores it in the `path` buffer.
    - It checks if `readlink` returns -1, indicating an error, and returns -1 in this case.
    - It checks if the number of bytes read is greater than or equal to PATH_MAX, sets `errno` to ERANGE, and returns -1 if true.
    - If successful, it null-terminates the string in `path` at the position indicated by the number of bytes read.
    - Finally, it returns 0 to indicate success.
- **Output**: Returns 0 on success, and -1 on failure, with `errno` set appropriately.


---
### fd\_file\_util\_read\_all<!-- {{#callable:fd_file_util_read_all}} -->
The `fd_file_util_read_all` function reads the entire contents of a file into memory and returns a pointer to the mapped memory region, while also providing the size of the file.
- **Inputs**:
    - `path`: A constant character pointer representing the file path to be read.
    - `out_sz`: A pointer to an unsigned long where the size of the file will be stored.
- **Control Flow**:
    - Open the file specified by the path in read-only mode.
    - Check if the file descriptor is valid; if not, return `MAP_FAILED`.
    - Retrieve file statistics using `fstat` and check for errors; if any, close the file and return `MAP_FAILED`.
    - Check if the file size is zero; if so, close the file, set `errno` to `EINVAL`, and return `MAP_FAILED`.
    - Map the file into memory using `mmap` with read-only and private flags, and check for errors; if any, close the file and return `MAP_FAILED`.
    - Close the file descriptor and log a warning if closing fails.
    - Store the file size in the `out_sz` pointer.
    - Return a pointer to the mapped memory region.
- **Output**: A pointer to the mapped memory region containing the file's contents, or `MAP_FAILED` if an error occurs.


