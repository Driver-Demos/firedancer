# Purpose
This C source file is part of a larger system that deals with restoring workspace checkpoints, specifically version 2 (v2) checkpoints, into a workspace (wksp). The file provides detailed implementations for restoring various components of a checkpoint, such as headers, information frames, and footers, into a workspace. It includes functions for both memory-mapped I/O (mmio) and streaming I/O, allowing it to handle different types of input sources, such as files or sockets. The code is structured to handle errors robustly, logging warnings and returning specific error codes when operations fail. It also includes mechanisms for parallel processing using thread pools to efficiently restore large checkpoints.

The file defines several macros and static functions to encapsulate common operations, such as seeking within a restore stream, opening and closing frames, and validating data. These operations are used to ensure that the restoration process is both efficient and reliable. The main functions, such as [`fd_wksp_private_restore_v2_mmio`](#fd_wksp_private_restore_v2_mmio) and [`fd_wksp_private_restore_v2_stream`](#fd_wksp_private_restore_v2_stream), are responsible for orchestrating the restoration process, including locking the workspace, validating the restored data, and rebuilding the workspace's internal structures. The file also includes a function for printing checkpoint metadata, which can be used for debugging or logging purposes. Overall, this file provides a comprehensive implementation for restoring workspace checkpoints, with a focus on correctness, efficiency, and error handling.
# Imports and Dependencies

---
- `fd_wksp_private.h`
- `stdio.h`
- `errno.h`
- `unistd.h`
- `fcntl.h`
- `sys/stat.h`


# Functions

---
### fd\_wksp\_restore\_v2\_hdr<!-- {{#callable:fd_wksp_restore_v2_hdr}} -->
The `fd_wksp_restore_v2_hdr` function restores the header frame from a workspace checkpoint, validating its contents and ensuring it meets specific criteria.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure, representing the restore context and state.
    - `hdr`: A pointer to an `fd_wksp_checkpt_v2_hdr_t` structure, where the restored header data will be stored.
- **Control Flow**:
    - Initialize a variable `frame_off` to store the frame offset.
    - Open the restore frame using `RESTORE_OPEN` with `FD_CHECKPT_FRAME_STYLE_RAW`.
    - Restore the header data into `hdr` using `RESTORE_DATA`.
    - Close the restore frame using `RESTORE_CLOSE`.
    - Calculate the length of the name in the header using `fd_shmem_name_len`.
    - Perform a series of tests using `RESTORE_TEST` to validate the header's magic number, style, frame style support, reserved field, name length, and footprint.
    - Return `FD_WKSP_SUCCESS` if all tests pass.
    - Jump to `fail` and return `FD_WKSP_ERR_FAIL` if any test fails.
- **Output**: Returns `FD_WKSP_SUCCESS` on successful restoration and validation of the header, or `FD_WKSP_ERR_FAIL` if any validation test fails.
- **Functions called**:
    - [`fd_wksp_footprint`](fd_wksp_admin.c.driver.md#fd_wksp_footprint)


---
### fd\_wksp\_restore\_v2\_info<!-- {{#callable:fd_wksp_restore_v2_info}} -->
The `fd_wksp_restore_v2_info` function restores the info frame from a workspace checkpoint, populating the info structure and extracting string pointers into an info buffer.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure, representing the restore context.
    - `hdr`: A constant pointer to an `fd_wksp_checkpt_v2_hdr_t` structure, containing header information from the checkpoint.
    - `info`: A pointer to an `fd_wksp_checkpt_v2_info_t` structure, where the restored info will be stored.
    - `info_buf`: A character buffer where the info data will be restored.
    - `info_buf_max`: The maximum size of the `info_buf` buffer.
    - `info_cstr`: An array of 9 constant character pointers, which will be populated with pointers to strings within `info_buf`.
- **Control Flow**:
    - The function begins by opening a restore frame using the `hdr->frame_style_compressed` style.
    - It restores metadata into the `info` structure using the `RESTORE_META` macro.
    - The total size of the info buffer is calculated by summing the sizes of various fields in the `info` structure.
    - A test is performed to ensure the calculated buffer size does not exceed `info_buf_max`.
    - The info data is restored into `info_buf` using the `RESTORE_DATA` macro.
    - The restore frame is closed using the `RESTORE_CLOSE` macro.
    - A pointer `p` is initialized to the start of `info_buf`.
    - A macro `NEXT` is defined to extract strings from `info_buf` based on sizes specified in `info`, performing validation checks on each string.
    - The `info_cstr` array is populated with pointers to strings extracted from `info_buf` using the `NEXT` macro.
    - If any step fails, the function jumps to the `fail` label and returns `FD_WKSP_ERR_FAIL`.
- **Output**: Returns `FD_WKSP_SUCCESS` on success, or `FD_WKSP_ERR_FAIL` on failure.


---
### fd\_wksp\_restore\_v2\_ftr<!-- {{#callable:fd_wksp_restore_v2_ftr}} -->
The `fd_wksp_restore_v2_ftr` function restores and validates the footer frame from a workspace checkpoint, ensuring compatibility with the header and verifying the integrity of the restored data.
- **Inputs**:
    - `restore`: A pointer to an `fd_restore_t` structure, representing the restore context.
    - `hdr`: A constant pointer to an `fd_wksp_checkpt_v2_hdr_t` structure, containing the header information of the checkpoint.
    - `ftr`: A pointer to an `fd_wksp_checkpt_v2_ftr_t` structure, where the footer data will be restored.
    - `checkpt_sz`: An unsigned long integer representing the size of the checkpoint.
- **Control Flow**:
    - The function begins by declaring a variable `frame_off` to track the frame offset.
    - It opens the restore frame using the `RESTORE_OPEN` macro with `FD_CHECKPT_FRAME_STYLE_RAW` style.
    - The footer data is restored into the `ftr` structure using the `RESTORE_DATA` macro.
    - The restore frame is closed using the `RESTORE_CLOSE` macro.
    - Several `RESTORE_TEST` macros are used to validate that the restored footer matches the expected values from the header and the checkpoint size.
    - If any test fails, the function jumps to the `fail` label and returns `FD_WKSP_ERR_FAIL`.
    - If all tests pass, the function returns `FD_WKSP_SUCCESS`.
- **Output**: The function returns `FD_WKSP_SUCCESS` on successful restoration and validation of the footer, or `FD_WKSP_ERR_FAIL` if any validation test fails.


---
### fd\_wksp\_private\_restore\_v2\_common<!-- {{#callable:fd_wksp_private_restore_v2_common}} -->
The function `fd_wksp_private_restore_v2_common` restores the header and info frames from a workspace checkpoint and logs the restored information.
- **Inputs**:
    - `hdr`: A pointer to an `fd_wksp_checkpt_v2_hdr_t` structure where the restored header data will be stored.
    - `restore`: A pointer to an `fd_restore_t` structure representing the restore context from which data is being restored.
- **Control Flow**:
    - Log the start of the restoration process for header and info frames.
    - Call [`fd_wksp_restore_v2_hdr`](#fd_wksp_restore_v2_hdr) to restore the header frame and verify its success using `RESTORE_TEST`.
    - Declare and initialize local variables for storing info data and buffers.
    - Call [`fd_wksp_restore_v2_info`](#fd_wksp_restore_v2_info) to restore the info frame and verify its success using `RESTORE_TEST`.
    - Format the wallclock time from the info structure into a string.
    - Log detailed information about the restored header and info, including style, name, seed, part_max, data_max, magic, wallclock, and other fields.
    - Log additional verbose information about path, binfo, and uinfo fields separately to avoid truncation by the logger.
    - Return `FD_WKSP_SUCCESS` if all operations are successful.
    - Jump to `fail` and return `FD_WKSP_ERR_FAIL` if any restoration test fails.
- **Output**: Returns `FD_WKSP_SUCCESS` on successful restoration and logging of header and info frames, or `FD_WKSP_ERR_FAIL` if an error occurs during restoration.
- **Functions called**:
    - [`fd_wksp_restore_v2_hdr`](#fd_wksp_restore_v2_hdr)
    - [`fd_wksp_restore_v2_info`](#fd_wksp_restore_v2_info)


---
### fd\_wksp\_private\_restore\_v2\_cgroup<!-- {{#callable:fd_wksp_private_restore_v2_cgroup}} -->
The function `fd_wksp_private_restore_v2_cgroup` restores a cgroup's allocation metadata and data into a workspace from a checkpoint, ensuring the restored data fits within the workspace's data region.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) where the cgroup allocations will be restored.
    - `restore`: A pointer to the restore object (`fd_restore_t`) used to manage the restoration process.
    - `hdr`: A constant pointer to the checkpoint header (`fd_wksp_checkpt_v2_hdr_t`) containing metadata about the restore operation.
    - `frame_off_lo`: The lower bound of the frame offset where the cgroup frame to restore is located.
    - `frame_off_hi`: The upper bound of the frame offset where the cgroup frame to restore is located.
    - `part_lo`: The lower index of the workspace partition range to use for this frame's allocations.
    - `part_hi`: The upper index of the workspace partition range to use for this frame's allocations.
    - `_dirty`: A pointer to an integer that will be set to 1 if the workspace was modified during the restore, otherwise 0.
- **Control Flow**:
    - Initialize the `dirty` flag to 0 and retrieve workspace private information and data region bounds.
    - Calculate the data region bounds from the checkpoint header.
    - Seek to the start of the frame using `RESTORE_SEEK` and open the frame with `RESTORE_OPEN`.
    - Iterate over the partitions from `part_lo` to `part_hi` to restore cgroup allocation metadata.
    - For each partition, restore metadata using `RESTORE_META` and validate it with `RESTORE_TEST`.
    - Check if the restored metadata fits within the workspace's data region; log a warning and fail if not.
    - Mark the workspace as dirty and update the workspace's private information with the restored metadata.
    - Restore the data command using `RESTORE_META` and validate it with `RESTORE_TEST`.
    - Iterate over the partitions again to restore cgroup allocation data into the workspace's data region.
    - Mark the workspace as dirty and restore the data using `RESTORE_DATA`.
    - Close the frame with `RESTORE_CLOSE` and validate the frame offsets with `RESTORE_TEST`.
    - Set the `_dirty` flag to indicate if the workspace was modified and return success or failure.
- **Output**: Returns `FD_WKSP_SUCCESS` on successful restoration, or `FD_WKSP_ERR_FAIL` if an error occurs, with `_dirty` indicating if the workspace was modified.
- **Functions called**:
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_data_off`](fd_wksp_private.h.driver.md#fd_wksp_private_data_off)
    - [`fd_wksp_checkpt_v2_cmd_is_meta`](fd_wksp_private.h.driver.md#fd_wksp_checkpt_v2_cmd_is_meta)
    - [`fd_wksp_checkpt_v2_cmd_is_data`](fd_wksp_private.h.driver.md#fd_wksp_checkpt_v2_cmd_is_data)
    - [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast)


---
### fd\_wksp\_private\_restore\_v2\_node<!-- {{#callable:fd_wksp_private_restore_v2_node}} -->
The `fd_wksp_private_restore_v2_node` function dispatches and manages the restoration of cgroup allocations into a workspace using a thread pool, handling errors and modifications during the process.
- **Inputs**:
    - `tpool`: A pointer to the thread pool used for executing tasks.
    - `tpool_t0`: The starting index of the thread range in the thread pool.
    - `tpool_t1`: The ending index of the thread range in the thread pool, assumed to be greater than tpool_t0.
    - `_wksp`: A pointer to the workspace where the cgroup allocations will be restored.
    - `_restore`: A pointer to the restore object used for the restoration process.
    - `_hdr`: A pointer to the header information of the workspace checkpoint.
    - `_cgroup_frame_off`: A pointer to an array of offsets for the cgroup frames.
    - `_cgroup_pinfo_lo`: A pointer to an array of partition indices for the cgroup allocations.
    - `_cgroup_nxt`: A pointer to a counter used for tracking the next cgroup to restore.
    - `cgroup_cnt`: The total number of cgroups to be restored.
    - `_err`: A pointer to an integer where the first encountered error code will be stored.
    - `_dirty`: A pointer to an integer where a flag indicating if the workspace was modified will be stored.
- **Control Flow**:
    - Calculate the number of threads in the range [tpool_t0, tpool_t1).
    - If more than one thread is available, split the range into two halves and recursively call the function for each half, using the first thread of the right half to handle the right half and the current thread to handle the left half.
    - Wait for the right half to complete and then combine the results, storing the first error encountered and accumulating the dirty flag.
    - If only one thread is available, unpack the input arguments and initialize a local restore object for the thread.
    - Enter a loop to restore each cgroup, using an atomic increment to get the next cgroup index to process.
    - For each cgroup, call [`fd_wksp_private_restore_v2_cgroup`](#fd_wksp_private_restore_v2_cgroup) to perform the restoration and update the dirty flag.
    - If an error occurs during restoration, break out of the loop.
    - Finalize the local restore object and store the error and dirty flag results.
- **Output**: The function does not return a value but updates the integer pointed to by _err with the first error encountered and the integer pointed to by _dirty with a flag indicating if the workspace was modified.
- **Functions called**:
    - [`fd_wksp_private_restore_v2_cgroup`](#fd_wksp_private_restore_v2_cgroup)


---
### fd\_wksp\_private\_restore\_v2\_mmio<!-- {{#callable:fd_wksp_private_restore_v2_mmio}} -->
The `fd_wksp_private_restore_v2_mmio` function restores workspace allocations from a checkpoint using memory-mapped I/O, ensuring the workspace is rebuilt with the restored allocations.
- **Inputs**:
    - `tpool`: A pointer to a thread pool (`fd_tpool_t`) used for parallel processing of the restore operation.
    - `t0`: The starting index of the thread pool range to be used for the restore operation.
    - `t1`: The ending index of the thread pool range to be used for the restore operation.
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) where the allocations will be restored.
    - `restore`: A pointer to the restore object (`fd_restore_t`) that contains the checkpoint data to be restored.
    - `new_seed`: A new seed value (`uint`) used for rebuilding the workspace after restoration.
- **Control Flow**:
    - Initialize variables for tracking frame offsets, lock status, and modification status.
    - Calculate the size of the restore data and determine offsets for header, info, and footer frames.
    - Validate the frame offsets to ensure they are in the correct order and within bounds.
    - Restore and validate the header and footer frames using helper functions.
    - Check if the workspace has enough partitions to accommodate the allocations from the restore data.
    - Lock the workspace to prevent concurrent modifications during the restore process.
    - Iterate over volumes in the restore data, restoring each volume's appendix and cgroup allocations.
    - Dispatch work to thread pool threads to restore cgroup allocations in parallel.
    - Ensure all volumes and cgroups have been processed and position the restore at the end of the data.
    - Rebuild the workspace with the restored allocations, freeing any remaining old allocations.
    - Unlock the workspace and return success if the restore was completed without errors.
    - Handle any errors by unlocking the workspace if it was locked and returning an appropriate error code.
- **Output**: Returns `FD_WKSP_SUCCESS` on successful restoration, `FD_WKSP_ERR_FAIL` if an error occurred before modifications, or `FD_WKSP_ERR_CORRUPT` if an error occurred after modifications.
- **Functions called**:
    - [`fd_wksp_private_restore_v2_common`](#fd_wksp_private_restore_v2_common)
    - [`fd_wksp_restore_v2_ftr`](#fd_wksp_restore_v2_ftr)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_checkpt_v2_cmd_is_appendix`](fd_wksp_private.h.driver.md#fd_wksp_checkpt_v2_cmd_is_appendix)
    - [`fd_wksp_private_restore_v2_node`](#fd_wksp_private_restore_v2_node)
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_rebuild`](fd_wksp_admin.c.driver.md#fd_wksp_rebuild)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)


---
### fd\_wksp\_private\_restore\_v2\_stream<!-- {{#callable:fd_wksp_private_restore_v2_stream}} -->
The `fd_wksp_private_restore_v2_stream` function restores a workspace from a checkpoint stream, ensuring data integrity and rebuilding the workspace with the restored allocations.
- **Inputs**:
    - `wksp`: A pointer to the workspace (`fd_wksp_t`) where the checkpoint data will be restored.
    - `restore`: A pointer to the restore object (`fd_restore_t`) that provides the checkpoint data stream.
    - `new_seed`: An unsigned integer representing the new seed for rebuilding the workspace.
- **Control Flow**:
    - Initialize variables for tracking the lock state and modification state of the workspace.
    - Call [`fd_wksp_private_restore_v2_common`](#fd_wksp_private_restore_v2_common) to restore the header and info frames from the checkpoint stream.
    - Attempt to lock the workspace using [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock); if unsuccessful, log details and jump to the fail label.
    - Initialize pointers and variables for workspace partition and data limits.
    - Iterate over volumes in the checkpoint, logging the restoration process for each volume.
    - Within each volume, iterate over cgroups, opening frames and reading commands to determine frame types (cgroup, appendix, or end of volumes).
    - For cgroup frames, restore allocation metadata and data into the workspace, updating the `pinfo` array and marking the workspace as modified.
    - For appendix frames, validate and close the frame, then proceed to the next volume.
    - If an end of volumes frame is encountered, validate and close the frame, then proceed to footer processing.
    - Restore and validate the footer, ensuring all checkpoint data has been decompressed into the workspace but not yet indexed.
    - Rebuild the workspace with the restored allocations, freeing any remaining old allocations.
    - Unlock the workspace and return success if all operations complete without error.
    - If any operation fails, release resources, unlock the workspace if locked, and return an error code indicating whether the workspace was corrupted or the operation simply failed.
- **Output**: Returns `FD_WKSP_SUCCESS` on successful restoration, or an error code (`FD_WKSP_ERR_CORRUPT` or `FD_WKSP_ERR_FAIL`) if the restoration fails, indicating whether the workspace was corrupted.
- **Functions called**:
    - [`fd_wksp_private_restore_v2_common`](#fd_wksp_private_restore_v2_common)
    - [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)
    - [`fd_wksp_private_pinfo`](fd_wksp_private.h.driver.md#fd_wksp_private_pinfo)
    - [`fd_wksp_private_data_off`](fd_wksp_private.h.driver.md#fd_wksp_private_data_off)
    - [`fd_wksp_checkpt_v2_cmd_is_appendix`](fd_wksp_private.h.driver.md#fd_wksp_checkpt_v2_cmd_is_appendix)
    - [`fd_wksp_checkpt_v2_cmd_is_volumes`](fd_wksp_private.h.driver.md#fd_wksp_checkpt_v2_cmd_is_volumes)
    - [`fd_wksp_checkpt_v2_cmd_is_data`](fd_wksp_private.h.driver.md#fd_wksp_checkpt_v2_cmd_is_data)
    - [`fd_wksp_checkpt_v2_cmd_is_meta`](fd_wksp_private.h.driver.md#fd_wksp_checkpt_v2_cmd_is_meta)
    - [`fd_wksp_laddr_fast`](fd_wksp.h.driver.md#fd_wksp_laddr_fast)
    - [`fd_wksp_restore_v2_ftr`](#fd_wksp_restore_v2_ftr)
    - [`fd_wksp_rebuild`](fd_wksp_admin.c.driver.md#fd_wksp_rebuild)
    - [`fd_wksp_private_unlock`](fd_wksp_private.h.driver.md#fd_wksp_private_unlock)


---
### fd\_wksp\_private\_restore\_v2<!-- {{#callable:fd_wksp_private_restore_v2}} -->
The `fd_wksp_private_restore_v2` function restores a workspace from a checkpoint file, using either memory-mapped I/O or streaming, and updates the workspace with the restored data.
- **Inputs**:
    - `tpool`: A pointer to a thread pool used for parallel processing during the restore operation.
    - `t0`: The starting index of the thread pool range to be used for the restore operation.
    - `t1`: The ending index of the thread pool range to be used for the restore operation.
    - `wksp`: A pointer to the workspace structure where the checkpoint will be restored.
    - `path`: A constant character pointer to the file path of the checkpoint to be restored.
    - `new_seed`: An unsigned integer representing the new seed to be used for the workspace after restoration.
- **Control Flow**:
    - Log the start of the restoration process with the checkpoint path and workspace name.
    - Attempt to open the checkpoint file in read-only mode; if it fails, log a warning and jump to the fail label.
    - Initialize memory-mapped I/O (mmio) for the file; if successful, proceed with mmio restoration.
    - If mmio initialization fails, log the error and proceed with streaming restoration.
    - For mmio restoration, initialize the restore object with mmio and call [`fd_wksp_private_restore_v2_mmio`](#fd_wksp_private_restore_v2_mmio); handle errors by jumping to the fail label.
    - For streaming restoration, initialize the restore object with a stream and call [`fd_wksp_private_restore_v2_stream`](#fd_wksp_private_restore_v2_stream); handle errors by jumping to the fail label.
    - Log the closing of the checkpoint file and finalize the restore object.
    - Close the file descriptor and handle any errors by logging warnings.
    - Return the error code from the restoration process.
    - In the fail label, handle cleanup by finalizing the restore object and closing the file descriptor if necessary, then return a failure code.
- **Output**: Returns an integer error code indicating the success or failure of the restoration process, with specific error codes for different failure scenarios.
- **Functions called**:
    - [`fd_wksp_private_restore_v2_mmio`](#fd_wksp_private_restore_v2_mmio)
    - [`fd_wksp_private_restore_v2_stream`](#fd_wksp_private_restore_v2_stream)


---
### fd\_wksp\_private\_printf\_v2<!-- {{#callable:fd_wksp_private_printf_v2}} -->
The `fd_wksp_private_printf_v2` function reads and prints metadata from a workspace checkpoint file, with verbosity-controlled output.
- **Inputs**:
    - `out`: An integer file descriptor where the output will be written.
    - `path`: A constant character pointer representing the path to the checkpoint file to be read.
    - `verbose`: An integer controlling the verbosity level of the output.
- **Control Flow**:
    - Initialize return value `ret` to 0 and define a macro `TRAP` for error handling.
    - Declare and initialize file descriptor `fd` to -1 and `restore` pointer to NULL.
    - If `verbose` is greater than or equal to 1, attempt to open the file at `path` for reading.
    - If file opening fails, log a warning and jump to the `fail` label.
    - Initialize a restore stream with the opened file and a buffer, logging details.
    - If restore initialization fails, jump to the `fail` label.
    - Restore the header from the checkpoint file using [`fd_wksp_restore_v2_hdr`](#fd_wksp_restore_v2_hdr).
    - Restore additional info from the checkpoint file using [`fd_wksp_restore_v2_info`](#fd_wksp_restore_v2_info).
    - Format and print the restored header and info to the output file descriptor `out` using `dprintf`, handling errors with `TRAP`.
    - If `verbose` is greater than or equal to 2, print additional info fields.
    - Finish the restore process and close the file, logging any warnings if failures occur.
    - If any errors occur during the process, release resources and log warnings in the `fail` section.
- **Output**: Returns an integer `ret`, which is 0 on success or a negative error code if an error occurred during execution.
- **Functions called**:
    - [`fd_wksp_restore_v2_hdr`](#fd_wksp_restore_v2_hdr)
    - [`fd_wksp_restore_v2_info`](#fd_wksp_restore_v2_info)


