# Purpose
This C source code file is designed to handle workspace checkpoint operations, including reading, previewing, creating, restoring, and printing checkpoint data. The file provides a set of functions that interact with checkpoint files, which are used to store and retrieve the state of a workspace. The primary functions include [`fd_wksp_preview`](#fd_wksp_preview), which reads and validates checkpoint headers to extract metadata; [`fd_wksp_checkpt_tpool`](#fd_wksp_checkpt_tpool), which creates a checkpoint with a specified style; [`fd_wksp_restore_tpool`](#fd_wksp_restore_tpool), which restores a workspace from a checkpoint; and [`fd_wksp_printf`](#fd_wksp_printf), which outputs checkpoint information to a file descriptor. The code supports multiple checkpoint styles, including V1, V2, and V3, with V3 being a compressed version of V2.

The file includes both static and public functions, indicating that it is part of a larger library or application. The static function [`fd_wksp_private_checkpt_read`](#fd_wksp_private_checkpt_read) is used internally to read checkpoint data from a file, while the other functions are likely intended for external use, providing a public API for managing workspace checkpoints. The code makes use of error handling and logging to ensure robustness, and it includes checks for input validation and error conditions. The use of macros like `FD_UNLIKELY` and `FD_LOG_WARNING` suggests an emphasis on performance and debugging. Overall, this file is a specialized component focused on the management of workspace state through checkpoint files, providing essential functionality for applications that require state persistence and recovery.
# Imports and Dependencies

---
- `fd_wksp_private.h`
- `stdio.h`
- `errno.h`
- `unistd.h`
- `fcntl.h`


# Functions

---
### fd\_wksp\_private\_checkpt\_read<!-- {{#callable:fd_wksp_private_checkpt_read}} -->
The function `fd_wksp_private_checkpt_read` reads up to `buf_max` bytes from a file specified by `path` into a buffer `buf` and returns the number of bytes read through `_buf_sz`.
- **Inputs**:
    - `path`: A constant character pointer representing the file path to read from; assumed to be valid.
    - `buf`: A pointer to a buffer where the read data will be stored; assumed to be valid.
    - `buf_max`: An unsigned long indicating the maximum number of bytes to read; assumed to be at least 12.
    - `_buf_sz`: A pointer to an unsigned long where the function will store the number of bytes actually read; assumed to be non-NULL.
- **Control Flow**:
    - Open the file at the specified `path` in read-only mode.
    - Check if the file descriptor `fd` is valid; if not, return the error code `errno`.
    - Call `fd_io_read` to read up to `buf_max` bytes from the file into `buf`, starting with a minimum of 12 bytes, and store the number of bytes read in `_buf_sz`.
    - Attempt to close the file descriptor `fd`; if closing fails, log a warning message but continue execution.
    - Return the result of the `fd_io_read` operation.
- **Output**: Returns 0 on success, with `_buf_sz` updated to the number of bytes read; on failure, returns an error code compatible with `fd_io_strerror`, and `_buf_sz` remains unchanged.


---
### fd\_wksp\_preview<!-- {{#callable:fd_wksp_preview}} -->
The `fd_wksp_preview` function reads a workspace checkpoint header from a file and extracts preview information if the header is valid and supported.
- **Inputs**:
    - `path`: A constant character pointer representing the file path to the workspace checkpoint.
    - `_opt_preview`: A pointer to an `fd_wksp_preview_t` structure where the preview information will be stored; if NULL, a local stack variable is used.
- **Control Flow**:
    - Check if the `path` is NULL and return `FD_WKSP_ERR_INVAL` if true.
    - If `_opt_preview` is NULL, use a local stack variable for preview storage.
    - Call [`fd_wksp_private_checkpt_read`](#fd_wksp_private_checkpt_read) to read the checkpoint header into a buffer and check for errors, returning `FD_WKSP_ERR_FAIL` if any occur.
    - Cast the buffer to a `fd_wksp_checkpt_v2_hdr_t` structure and check if it contains a valid V2 header with specific conditions; if valid, populate `_opt_preview` with the header information and return `FD_WKSP_SUCCESS`.
    - If the V2 header is not valid, decode the buffer as a V1 header using `fd_ulong_svw_dec` and check for validity with specific conditions; if valid, populate `_opt_preview` with the header information and return `FD_WKSP_SUCCESS`.
    - If neither V1 nor V2 headers are valid, return `FD_WKSP_ERR_CORRUPT`.
- **Output**: Returns an integer status code: `FD_WKSP_SUCCESS` if a valid header is found and preview information is extracted, `FD_WKSP_ERR_INVAL` if the path is invalid, `FD_WKSP_ERR_FAIL` if reading the header fails, or `FD_WKSP_ERR_CORRUPT` if the header is not supported or valid.
- **Functions called**:
    - [`fd_wksp_private_checkpt_read`](#fd_wksp_private_checkpt_read)
    - [`fd_wksp_footprint`](fd_wksp_admin.c.driver.md#fd_wksp_footprint)


---
### fd\_wksp\_checkpt\_tpool<!-- {{#callable:fd_wksp_checkpt_tpool}} -->
The `fd_wksp_checkpt_tpool` function creates a checkpoint of a workspace using a specified style and writes it to a given path.
- **Inputs**:
    - `tpool`: A pointer to a thread pool (`fd_tpool_t`) used for managing threads during the checkpoint operation.
    - `t0`: An unsigned long integer representing the start time or a timestamp for the checkpoint operation.
    - `t1`: An unsigned long integer representing the end time or a timestamp for the checkpoint operation.
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) that is to be checkpointed.
    - `path`: A constant character pointer representing the file path where the checkpoint will be saved.
    - `mode`: An unsigned long integer representing the file mode for the checkpoint file.
    - `style`: An integer indicating the style/version of the checkpoint to be created.
    - `uinfo`: A constant character pointer for user information or metadata to be included in the checkpoint.
- **Control Flow**:
    - Check if the `wksp` pointer is NULL and log a warning if so, returning an invalid argument error.
    - Check if the `path` pointer is NULL and log a warning if so, returning an invalid argument error.
    - Verify that the `mode` is valid by checking if it can be cast to `mode_t` without change, logging a warning and returning an error if not.
    - Determine the checkpoint style to use, defaulting to V3 if LZ4 is available, otherwise V2, unless a specific style is provided.
    - Set `uinfo` to an empty string if it is NULL.
    - Set `binfo` to the build information string, defaulting to an empty string if it is NULL.
    - Use a switch statement to call the appropriate private checkpoint function based on the `style` value, returning its result.
    - Log a warning and return an invalid argument error if the `style` is unsupported.
- **Output**: Returns an integer status code, where 0 typically indicates success and non-zero values indicate various errors.
- **Functions called**:
    - [`fd_wksp_private_checkpt_v1`](fd_wksp_checkpt_v1.c.driver.md#fd_wksp_private_checkpt_v1)
    - [`fd_wksp_private_checkpt_v2`](fd_wksp_checkpt_v2.c.driver.md#fd_wksp_private_checkpt_v2)


---
### fd\_wksp\_restore\_tpool<!-- {{#callable:fd_wksp_restore_tpool}} -->
The `fd_wksp_restore_tpool` function restores a workspace from a checkpoint file using a specified thread pool and seed, determining the appropriate restoration method based on the checkpoint's version.
- **Inputs**:
    - `tpool`: A pointer to the thread pool (`fd_tpool_t`) used for the restoration process.
    - `t0`: An unsigned long integer representing the start time or a specific time parameter for the restoration.
    - `t1`: An unsigned long integer representing the end time or a specific time parameter for the restoration.
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) to be restored.
    - `path`: A constant character pointer to the file path of the checkpoint to be restored.
    - `new_seed`: An unsigned integer representing a new seed value for the restoration process, which is arbitrary.
- **Control Flow**:
    - Check if the `wksp` pointer is NULL and log a warning if so, returning an invalid argument error.
    - Check if the `path` pointer is NULL and log a warning if so, returning an invalid argument error.
    - Call [`fd_wksp_preview`](#fd_wksp_preview) to determine the version of the checkpoint file at the given path.
    - If [`fd_wksp_preview`](#fd_wksp_preview) returns an error, log a warning and return the error code.
    - Use a switch statement on the `style` field of the `preview` structure to determine the appropriate restoration function to call.
    - If the style is `FD_WKSP_CHECKPT_STYLE_V1`, call [`fd_wksp_private_restore_v1`](fd_wksp_restore_v1.c.driver.md#fd_wksp_private_restore_v1).
    - If the style is `FD_WKSP_CHECKPT_STYLE_V2`, call [`fd_wksp_private_restore_v2`](fd_wksp_restore_v2.c.driver.md#fd_wksp_private_restore_v2).
    - Log a warning and return a corruption error if an unsupported style is encountered.
- **Output**: The function returns an integer status code, which is 0 on success or an error code on failure, indicating the result of the restoration process.
- **Functions called**:
    - [`fd_wksp_preview`](#fd_wksp_preview)
    - [`fd_wksp_private_restore_v1`](fd_wksp_restore_v1.c.driver.md#fd_wksp_private_restore_v1)
    - [`fd_wksp_private_restore_v2`](fd_wksp_restore_v2.c.driver.md#fd_wksp_private_restore_v2)


---
### fd\_wksp\_printf<!-- {{#callable:fd_wksp_printf}} -->
The `fd_wksp_printf` function prints information about a workspace checkpoint to a specified file descriptor, with verbosity controlled by the `verbose` parameter.
- **Inputs**:
    - `fd`: An integer representing the file descriptor to which the output will be printed.
    - `path`: A constant character pointer representing the path to the workspace checkpoint.
    - `verbose`: An integer that controls the verbosity level of the output.
- **Control Flow**:
    - Initialize the return value `ret` to 0 and define a macro `TRAP` to handle errors and accumulate return values.
    - If `verbose` is less than 0, return `ret` immediately.
    - Use `dprintf` to print a checkpoint message to the file descriptor `fd`, including the `path` and `verbose` level, and handle errors using `TRAP`.
    - Call [`fd_wksp_preview`](#fd_wksp_preview) to get a preview of the workspace checkpoint at `path` into a `preview` structure.
    - If [`fd_wksp_preview`](#fd_wksp_preview) returns an error, print an error message to `fd` using `dprintf` and `TRAP`.
    - If no error, print the details of the `preview` (style, name, seed, part_max, data_max) to `fd` using `dprintf` and `TRAP`.
    - If `verbose` is less than 1, return `ret`.
    - Based on the `style` in `preview`, call the appropriate version-specific print function ([`fd_wksp_private_printf_v1`](fd_wksp_restore_v1.c.driver.md#fd_wksp_private_printf_v1) or [`fd_wksp_private_printf_v2`](fd_wksp_restore_v2.c.driver.md#fd_wksp_private_printf_v2)) using `TRAP`.
    - If the style is unsupported, print an unsupported style message to `fd` using `dprintf` and `TRAP`.
    - Return the accumulated return value `ret`.
- **Output**: The function returns an integer representing the total number of characters printed to the file descriptor, or an error code if an error occurs during execution.
- **Functions called**:
    - [`fd_wksp_preview`](#fd_wksp_preview)
    - [`fd_wksp_strerror`](fd_wksp_admin.c.driver.md#fd_wksp_strerror)
    - [`fd_wksp_private_printf_v1`](fd_wksp_restore_v1.c.driver.md#fd_wksp_private_printf_v1)
    - [`fd_wksp_private_printf_v2`](fd_wksp_restore_v2.c.driver.md#fd_wksp_private_printf_v2)


