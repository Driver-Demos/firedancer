# Purpose
The provided C source code file, `fd_fuzz_stub.c`, serves as a stub fuzz harness for build targets that lack an actual fuzzing engine. Its primary purpose is to simulate the command-line interface of libFuzzer, allowing for regression testing against existing input files without performing any actual fuzz exploration. This is particularly useful for environments where a fuzzing engine is not available or when the code is compiled without fuzzing capabilities. The file includes functions to initialize the fuzzing environment, process input files, and handle directory traversal to execute tests on multiple files. It also provides a weakly defined [`LLVMFuzzerMutate`](#LLVMFuzzerMutate) function, which can be overridden if needed.

The code is structured around a main function that processes command-line arguments, opening files or directories specified by the user, and executing the [`LLVMFuzzerTestOneInput`](#LLVMFuzzerTestOneInput) function on the contents of each file. The [`execute`](#execute) function is responsible for reading file contents and invoking the test function, while error handling is performed throughout to ensure robustness. The stub also includes a helper function, [`i_am_a_stub`](#i_am_a_stub), which informs the user that the fuzz target was compiled without a fuzz engine and provides guidance on how to compile with libFuzzer. This file is not intended to be a standalone executable but rather a component of a larger testing framework, providing a mock interface for fuzz testing in the absence of a full fuzzing engine.
# Imports and Dependencies

---
- `fd_fuzz.h`
- `../fd_util.h`
- `errno.h`
- `dirent.h`
- `fcntl.h`
- `stdlib.h`
- `stdio.h`
- `sys/stat.h`
- `sys/types.h`
- `unistd.h`


# Functions

---
### i\_am\_a\_stub<!-- {{#callable:i_am_a_stub}} -->
The `i_am_a_stub` function outputs a message indicating the absence of a fuzz engine and provides instructions for compiling with a fuzz engine, then returns an error code.
- **Inputs**: None
- **Control Flow**:
    - The function uses `fputs` to print a multi-line error message to `stderr`, indicating that the fuzz target was compiled without a fuzz engine.
    - The message includes instructions on how to re-run individual test cases and a hint on how to compile with a fuzz engine using `clang`.
    - The function returns the integer `1` to indicate an error or failure state.
- **Output**: The function returns an integer value `1`, indicating an error or failure due to the absence of a fuzz engine.


---
### LLVMFuzzerMutate<!-- {{#callable:LLVMFuzzerMutate}} -->
The `LLVMFuzzerMutate` function is a stub implementation that does nothing and returns zero, intended for use in builds without a fuzz engine.
- **Inputs**:
    - `data`: A pointer to an array of unsigned characters (bytes) that is intended to be mutated.
    - `data_sz`: The current size of the data array in bytes.
    - `max_sz`: The maximum allowable size for the mutated data array in bytes.
- **Control Flow**:
    - The function begins by explicitly casting the input parameters to void to suppress unused variable warnings.
    - The function immediately returns 0UL, indicating no mutation has occurred.
- **Output**: The function returns an unsigned long integer with a value of 0, indicating no mutation was performed.


---
### execute<!-- {{#callable:execute}} -->
The `execute` function reads the contents of a file and passes it to a fuzz testing function, handling errors related to file operations and memory allocation.
- **Inputs**:
    - `file`: An integer file descriptor representing the file to be processed.
- **Control Flow**:
    - The function begins by declaring a `struct stat` variable `st` to hold file status information.
    - It checks if `fstat` on the file descriptor fails, logging an error and returning the error number if so.
    - The function checks if the file is a directory, returning `EISDIR` if true, and checks if it is a regular file, returning `EBADF` if not.
    - It retrieves the file size from `st.st_size` and attempts to allocate a buffer of that size using `malloc`.
    - If memory allocation fails, it logs an error message.
    - The function reads the file into the buffer using `fd_io_read`, logging an error and returning 1 if the read fails.
    - It calls `LLVMFuzzerTestOneInput` with the buffer and the actual size of data read.
    - Finally, it frees the allocated buffer and returns 0 to indicate success.
- **Output**: The function returns 0 on success, `EISDIR` if the file is a directory, `EBADF` if the file is not a regular file, or an error code if a file operation fails.


---
### main<!-- {{#callable:main}} -->
The `main` function initializes a fuzzing environment and processes each command-line argument as a file or directory to execute fuzz tests on them.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Check if the number of arguments is less than or equal to 1; if so, call `i_am_a_stub()` and return its result.
    - Initialize the fuzzing environment using `LLVMFuzzerInitialize`.
    - Iterate over each command-line argument starting from index 1.
    - Skip arguments that start with a dash ('-').
    - Attempt to open each argument as a file with read-only access.
    - If opening the file fails, log an error and continue to the next argument.
    - Call [`execute`](#execute) on the opened file descriptor to perform fuzz testing.
    - If [`execute`](#execute) returns `EISDIR`, treat the argument as a directory, open it, and iterate over its contents.
    - For each entry in the directory, open it and call [`execute`](#execute) on it; log success or failure messages accordingly.
    - Close the directory and continue to the next argument if it was a directory.
    - Log success or failure messages for each file processed.
    - Close the file descriptor after processing each argument.
- **Output**: The function returns 0 upon successful completion of all operations.
- **Functions called**:
    - [`i_am_a_stub`](#i_am_a_stub)
    - [`execute`](#execute)


