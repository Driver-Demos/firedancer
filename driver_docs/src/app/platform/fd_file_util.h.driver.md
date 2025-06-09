# Purpose
This C header file, `fd_file_util.h`, provides a collection of utility functions for file operations, focusing on reading, writing, and managing files and directories. It includes functions to read and write unsigned integers (`uint` and `ulong`) from and to files, ensuring proper error handling with return values and `errno` settings. Additionally, it offers directory management utilities, such as [`fd_file_util_mkdir_all`](#fd_file_util_mkdir_all) for recursively creating directories with specific ownership and permissions, and [`fd_file_util_rmtree`](#fd_file_util_rmtree) for recursively removing directory contents. The file also includes a function to retrieve the path of the current executable and another to read the entire contents of a file into memory using `mmap`. These utilities are designed to simplify common file and directory operations while providing robust error handling.
# Imports and Dependencies

---
- `../../util/fd_util.h`


# Global Variables

---
### fd\_file\_util\_read\_all
- **Type**: `function`
- **Description**: The `fd_file_util_read_all` function reads the entire contents of a file specified by the `path` into a newly `mmap(2)`ed memory region. It returns a pointer to this memory region or `MAP_FAILED` on failure. The size of the file is stored in the `out_sz` variable if the operation is successful.
- **Use**: This function is used to read the entire contents of a file into memory for further processing, with the caller responsible for managing the memory.


# Functions

---
### fd\_file\_util\_write\_uint<!-- {{#callable:fd_file_util_write_uint}} -->
The `fd_file_util_write_uint` function writes an unsigned integer to a specified file path by internally calling [`fd_file_util_write_ulong`](fd_file_util.c.driver.md#fd_file_util_write_ulong).
- **Inputs**:
    - `path`: A constant character pointer representing the file path where the unsigned integer will be written.
    - `value`: An unsigned integer value that is to be written to the specified file path.
- **Control Flow**:
    - The function is defined as an inline function, which suggests it is intended to be expanded in place where it is called, rather than being invoked through a regular function call.
    - The function takes two parameters: a file path and an unsigned integer value.
    - It calls another function, [`fd_file_util_write_ulong`](fd_file_util.c.driver.md#fd_file_util_write_ulong), passing the same file path and the unsigned integer value as arguments.
    - The function returns the result of the [`fd_file_util_write_ulong`](fd_file_util.c.driver.md#fd_file_util_write_ulong) call, which is an integer indicating success or failure.
- **Output**: The function returns an integer, where zero indicates success and -1 indicates failure, with `errno` set appropriately in case of failure.
- **Functions called**:
    - [`fd_file_util_write_ulong`](fd_file_util.c.driver.md#fd_file_util_write_ulong)


# Function Declarations (Public API)

---
### fd\_file\_util\_read\_ulong<!-- {{#callable_declaration:fd_file_util_read_ulong}} -->
Read an unsigned long integer from a file.
- **Description**: This function reads an unsigned long integer from the specified file path. It should be used when you need to retrieve a numeric value stored in a file, where the file contains a single line with the number followed by either a newline or EOF. The function returns zero on success and writes the parsed value to the provided pointer. If the file cannot be opened, read, or does not contain a valid unsigned long integer, the function returns -1 and sets errno to indicate the error. Ensure the file is formatted correctly to avoid errors.
- **Inputs**:
    - `path`: A pointer to a null-terminated string representing the file path. Must not be null. The file should be readable and contain a valid unsigned long integer.
    - `value`: A pointer to an unsigned long where the read value will be stored. Must not be null. The caller retains ownership and is responsible for ensuring the pointer is valid.
- **Output**: Returns 0 on success, with the unsigned long integer written to the location pointed to by 'value'. Returns -1 on failure, with errno set to indicate the error.
- **See also**: [`fd_file_util_read_ulong`](fd_file_util.c.driver.md#fd_file_util_read_ulong)  (Implementation)


---
### fd\_file\_util\_read\_uint<!-- {{#callable_declaration:fd_file_util_read_uint}} -->
Read an unsigned integer from a file.
- **Description**: This function reads an unsigned integer from a file specified by the given path. It should be used when you need to retrieve a uint value stored in a file. The function expects the file to start with a single line containing a uint followed by EOF or a newline character. If the file does not meet this format or if the value exceeds the maximum representable uint, the function will fail, returning -1 and setting errno to ERANGE. On success, it returns 0 and writes the value to the provided pointer.
- **Inputs**:
    - `path`: A pointer to a null-terminated string representing the file path. Must not be null. The file at this path should contain a valid uint at the start.
    - `value`: A pointer to a uint where the read value will be stored. Must not be null. The caller retains ownership of this pointer.
- **Output**: Returns 0 on success, with the uint value written to the location pointed to by 'value'. Returns -1 on failure, with errno set to indicate the error.
- **See also**: [`fd_file_util_read_uint`](fd_file_util.c.driver.md#fd_file_util_read_uint)  (Implementation)


---
### fd\_file\_util\_write\_ulong<!-- {{#callable_declaration:fd_file_util_write_ulong}} -->
Writes an unsigned long integer to a specified file path.
- **Description**: Use this function to write an unsigned long integer to a file at the specified path. It creates the file if it does not exist, truncates it if it does, and writes the value followed by a newline. This function is useful for persisting numeric data to a file. It returns zero on success. If the operation fails, it returns -1 and sets errno to indicate the error. Common errors include issues with file permissions or invalid paths. Ensure the path is valid and writable before calling this function.
- **Inputs**:
    - `path`: A pointer to a null-terminated string specifying the file path where the unsigned long integer will be written. The path must be valid and writable. The caller retains ownership of the string. If the path is invalid or the file cannot be opened, the function returns -1 and sets errno.
    - `value`: The unsigned long integer to be written to the file. There are no restrictions on the value itself, as it is formatted as a string before writing.
- **Output**: Returns zero on success. On failure, returns -1 and sets errno to indicate the error.
- **See also**: [`fd_file_util_write_ulong`](fd_file_util.c.driver.md#fd_file_util_write_ulong)  (Implementation)


---
### fd\_file\_util\_mkdir\_all<!-- {{#callable_declaration:fd_file_util_mkdir_all}} -->
Recursively create directories along a specified path.
- **Description**: This function is used to ensure that all directories in a specified path exist, creating any that do not. It is useful when setting up directory structures where intermediate directories may not yet exist. The function assigns ownership of newly created directories to the specified user and group IDs and sets their permissions to allow read, write, and execute access only to the owner. It should be noted that if the function fails, it may leave a partially created directory structure, and directories may not have the intended ownership or permissions.
- **Inputs**:
    - `path`: A null-terminated string representing the path for which directories should be created. The path must not exceed PATH_MAX characters. The caller retains ownership and must ensure it is a valid path.
    - `uid`: The user ID to assign as the owner of any newly created directories. Must be a valid user ID.
    - `gid`: The group ID to assign as the owner of any newly created directories. Must be a valid group ID.
- **Output**: Returns 0 on success. On failure, returns -1 and sets errno to indicate the error. Possible errors include those from mkdir(2), chown(2), and chmod(2).
- **See also**: [`fd_file_util_mkdir_all`](fd_file_util.c.driver.md#fd_file_util_mkdir_all)  (Implementation)


---
### fd\_file\_util\_rmtree<!-- {{#callable_declaration:fd_file_util_rmtree}} -->
Recursively removes directory contents and optionally the directory itself.
- **Description**: Use this function to delete all contents within a specified directory, and optionally the directory itself, by setting the `remove_root` parameter. It is useful for cleaning up directories and their contents. The function returns zero on success and -1 on failure, with `errno` set to indicate the error. If the operation fails, the directory may be left in a partially deleted state, with some files or subdirectories removed and others not.
- **Inputs**:
    - `path`: A string representing the path to the directory whose contents are to be removed. Must not be null. The directory should exist, or the function will return immediately with success if it does not.
    - `remove_root`: An integer flag indicating whether to remove the directory itself after its contents are deleted. If non-zero, the directory is removed; if zero, the directory is left empty but intact.
- **Output**: Returns zero on success. On failure, returns -1 and sets errno to indicate the error. The directory may be left in a partially deleted state on failure.
- **See also**: [`fd_file_util_rmtree`](fd_file_util.c.driver.md#fd_file_util_rmtree)  (Implementation)


---
### fd\_file\_util\_self\_exe<!-- {{#callable_declaration:fd_file_util_self_exe}} -->
Retrieves the full path of the current executable.
- **Description**: This function is used to obtain the absolute path of the currently running executable and store it in the provided buffer. It should be called when the full path of the executable is needed, for example, for logging or configuration purposes. The function requires a buffer with at least PATH_MAX elements to store the path. It returns zero on success, indicating that the path has been successfully written to the buffer. If the function fails, it returns -1 and sets errno to indicate the error, such as if the path length exceeds PATH_MAX or if there is an issue reading the link.
- **Inputs**:
    - `path`: A buffer with at least PATH_MAX elements where the full path of the current executable will be stored. The buffer must be writable and large enough to hold the path, including the null terminator. If the path length exceeds PATH_MAX, the function will fail, set errno to ERANGE, and return -1.
- **Output**: Returns 0 on success, with the path written to the provided buffer. Returns -1 on failure, with errno set to indicate the error.
- **See also**: [`fd_file_util_self_exe`](fd_file_util.c.driver.md#fd_file_util_self_exe)  (Implementation)


---
### fd\_file\_util\_read\_all<!-- {{#callable_declaration:fd_file_util_read_all}} -->
Reads the entire contents of a file into memory.
- **Description**: Use this function to read the entire contents of a file specified by the path into a memory-mapped region. It is suitable for cases where the entire file needs to be accessed in memory. The function returns a pointer to the memory-mapped region on success, and the size of the file is stored in the location pointed to by out_sz. If the function fails, it returns MAP_FAILED, and the value of out_sz is undefined. The caller is responsible for unmapping the region when it is no longer needed. Ensure that the file exists and is accessible for reading before calling this function.
- **Inputs**:
    - `path`: A pointer to a null-terminated string specifying the path to the file to be read. The file must exist and be accessible for reading. The caller retains ownership of the string.
    - `out_sz`: A pointer to an unsigned long where the size of the file will be stored on success. Must not be null. The value is undefined if the function fails.
- **Output**: Returns a pointer to the memory-mapped region containing the file contents on success, or MAP_FAILED on failure.
- **See also**: [`fd_file_util_read_all`](fd_file_util.c.driver.md#fd_file_util_read_all)  (Implementation)


