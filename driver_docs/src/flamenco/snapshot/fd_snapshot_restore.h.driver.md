# Purpose
This C header file, `fd_snapshot_restore.h`, defines the interface for restoring execution contexts from snapshot files in a software system. It is part of a snapshot loading pipeline, specifically handling the restoration phase after decompression and extraction of snapshot data. The file declares a structure, `fd_snapshot_restore_t`, which implements a streaming TAR reader to parse archive records, including manifests and account data, while performing dynamic heap allocations. It provides function prototypes for creating and deleting restore objects, handling file and chunk data, and managing callbacks for processing deserialized manifests and slot deltas. The header also defines constants and callback types to facilitate the integration of custom logic during the restoration process, ensuring flexibility and extensibility in handling complex data structures without size restrictions.
# Imports and Dependencies

---
- `fd_snapshot_base.h`
- `../../util/archive/fd_tar.h`
- `../runtime/context/fd_exec_slot_ctx.h`


# Global Variables

---
### fd\_snapshot\_restore\_new
- **Type**: `fd_snapshot_restore_t *`
- **Description**: The `fd_snapshot_restore_new` function is a constructor for creating a new `fd_snapshot_restore_t` object, which is used to manage the restoration of execution contexts from snapshot files. It initializes the restore object in a specified memory region and sets up callbacks for handling the manifest, status cache, and account restoration processes.
- **Use**: This variable is used to create and return a handle to a new snapshot restore object, facilitating the restoration of snapshot data through specified callbacks.


---
### fd\_snapshot\_restore\_delete
- **Type**: `function pointer`
- **Description**: The `fd_snapshot_restore_delete` is a function that takes a pointer to an `fd_snapshot_restore_t` object and destroys the restore object, freeing any resources associated with it. It returns the allocated memory region back to the caller.
- **Use**: This function is used to clean up and deallocate resources associated with a snapshot restore object once it is no longer needed.


---
### fd\_snapshot\_restore\_tar\_vt
- **Type**: `fd_tar_read_vtable_t const`
- **Description**: The `fd_snapshot_restore_tar_vt` is a constant variable of type `fd_tar_read_vtable_t`, which is a structure that defines a set of function pointers for reading TAR files. This variable is used to implement the TAR reading functionality specifically for the snapshot restore process.
- **Use**: This variable is used as a vtable to provide the necessary function implementations for reading TAR files during the snapshot restoration process.


# Data Structures

---
### fd\_snapshot\_restore\_t
- **Type**: `struct`
- **Description**: The `fd_snapshot_restore_t` is a data structure that implements a streaming TAR reader for parsing archive records on-the-fly, specifically designed for restoring execution contexts from snapshot files. It handles the deserialization of complex data structures, such as manifests and account data, and performs dynamic heap allocations during the snapshot loading process. This structure is part of a larger API that manages the restoration of execution contexts, allowing for the integration of manifest data throughout the codebase.


# Function Declarations (Public API)

---
### fd\_snapshot\_restore\_align<!-- {{#callable_declaration:fd_snapshot_restore_align}} -->
Return the required memory alignment for a snapshot restore object.
- **Description**: This function provides the memory alignment requirement for creating a `fd_snapshot_restore_t` object. It is essential to call this function before allocating memory for a snapshot restore object to ensure that the memory is correctly aligned. This alignment is necessary for the proper functioning of the restore process, which involves complex data structures and potentially large heap allocations. The function is a constant function, meaning it does not depend on any external state and will always return the same value.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes for a `fd_snapshot_restore_t` object.
- **See also**: [`fd_snapshot_restore_align`](fd_snapshot_restore.c.driver.md#fd_snapshot_restore_align)  (Implementation)


---
### fd\_snapshot\_restore\_footprint<!-- {{#callable_declaration:fd_snapshot_restore_footprint}} -->
Calculate the memory footprint required for a snapshot restore object.
- **Description**: This function calculates and returns the memory footprint necessary to create a `fd_snapshot_restore_t` object. It should be used when determining the size of the memory region required to store a snapshot restore object, ensuring that the memory allocation meets the necessary alignment and size requirements. This is typically called before allocating memory for a snapshot restore operation to ensure that the allocated space is sufficient.
- **Inputs**: None
- **Output**: Returns the size in bytes of the memory footprint required for a `fd_snapshot_restore_t` object, including alignment considerations.
- **See also**: [`fd_snapshot_restore_footprint`](fd_snapshot_restore.c.driver.md#fd_snapshot_restore_footprint)  (Implementation)


---
### fd\_snapshot\_restore\_new<!-- {{#callable_declaration:fd_snapshot_restore_new}} -->
Creates a new snapshot restore object in the specified memory region.
- **Description**: This function initializes a snapshot restore object in a given memory region, which must be properly aligned and have sufficient footprint as specified by the alignment and footprint functions. It is used to restore execution context from snapshot files, handling complex data structures and potentially large heap allocations. The function requires a valid memory region, a funk object, and a spad allocator, among other parameters. Callbacks for manifest, status cache, and account restoration can be provided, with the option to pass a context pointer to these callbacks. If any required parameter is invalid, the function logs a warning and returns NULL.
- **Inputs**:
    - `mem`: A pointer to the memory region where the restore object will be created. Must be non-null and properly aligned.
    - `funk`: A pointer to an fd_funk_t object. Must be non-null.
    - `funk_txn`: A pointer to an fd_funk_txn_t object. Can be null if not used.
    - `spad`: A pointer to an fd_spad_t object, which acts as a bump allocator. Must be non-null and outlive the restore object.
    - `cb_manifest_ctx`: An opaque pointer passed to the manifest callback. Can be null.
    - `cb_manifest`: A callback function for handling the deserialized manifest. Can be null if not needed.
    - `cb_status_cache`: A callback function for handling the deserialized status cache. Can be null for testing purposes.
    - `cb_rent_fresh_account`: A callback function for handling fresh account restoration. Can be null if not needed.
- **Output**: Returns a pointer to the newly created fd_snapshot_restore_t object on success, or NULL on failure.
- **See also**: [`fd_snapshot_restore_new`](fd_snapshot_restore.c.driver.md#fd_snapshot_restore_new)  (Implementation)


---
### fd\_snapshot\_restore\_delete<!-- {{#callable_declaration:fd_snapshot_restore_delete}} -->
Destroys a snapshot restore object and releases its resources.
- **Description**: Use this function to properly dispose of a snapshot restore object when it is no longer needed. It ensures that all resources associated with the object are freed and the memory is returned to the caller. This function should be called to prevent memory leaks after the snapshot restore process is complete. The function returns a pointer to the memory region that was used for the restore object, allowing the caller to reuse or deallocate it as needed. If the provided pointer is null, the function does nothing and returns null.
- **Inputs**:
    - `self`: A pointer to the fd_snapshot_restore_t object to be deleted. Must not be null; if null, the function returns null without performing any operations.
- **Output**: Returns a pointer to the memory region that was used for the restore object, or null if the input pointer was null.
- **See also**: [`fd_snapshot_restore_delete`](fd_snapshot_restore.c.driver.md#fd_snapshot_restore_delete)  (Implementation)


---
### fd\_snapshot\_restore\_file<!-- {{#callable_declaration:fd_snapshot_restore_file}} -->
Provides a file to the snapshot restore process.
- **Description**: This function is used to supply a file to an existing snapshot restore context, which is responsible for processing snapshot files during the restore operation. It should be called with a valid snapshot restore object and metadata describing the file. The function handles different types of files based on their metadata, such as account vector files and snapshot manifests, and prepares the restore context accordingly. It is suitable for use as a callback in a TAR file reading process. The function must be called with a valid restore object that has not failed, and it expects the file size and metadata to be correctly specified.
- **Inputs**:
    - `restore_`: A pointer to a fd_snapshot_restore_t object. This must be a valid restore context that has not previously failed. The caller retains ownership.
    - `meta`: A pointer to a constant fd_tar_meta_t structure containing metadata about the file. This metadata is used to determine how the file should be processed. Must not be null.
    - `sz`: An unsigned long representing the size of the file. Must be a non-negative value. If the size is zero or the file is not a regular file, the function will ignore the file.
- **Output**: Returns 0 on success, or EINVAL if the restore context has failed or if an unsupported file type is encountered before the manifest is processed.
- **See also**: [`fd_snapshot_restore_file`](fd_snapshot_restore.c.driver.md#fd_snapshot_restore_file)  (Implementation)


---
### fd\_snapshot\_restore\_chunk<!-- {{#callable_declaration:fd_snapshot_restore_chunk}} -->
Processes a chunk of data for snapshot restoration.
- **Description**: This function is used to process a chunk of data as part of restoring a snapshot from a TAR archive. It should be called with a valid restore object and a buffer containing the data chunk to be processed. The function will handle the data in the buffer and update the restore state accordingly. It is important to ensure that the restore object has not previously failed, as this will result in an error. The function also checks for the completion of the manifest processing and returns a specific code if the manifest is fully processed.
- **Inputs**:
    - `restore`: A pointer to a fd_snapshot_restore_t object. This must be a valid restore object that has not previously encountered a failure. The caller retains ownership.
    - `buf`: A pointer to a constant memory region containing the data chunk to be processed. The buffer must be valid and non-null, and the caller retains ownership.
    - `bufsz`: The size of the buffer in bytes. It must be a positive value indicating the number of bytes available in the buffer.
- **Output**: Returns 0 on success, EINVAL if the restore object has failed or if an error occurs during processing, and MANIFEST_DONE if the manifest processing is completed.
- **See also**: [`fd_snapshot_restore_chunk`](fd_snapshot_restore.c.driver.md#fd_snapshot_restore_chunk)  (Implementation)


---
### fd\_snapshot\_restore\_get\_slot<!-- {{#callable_declaration:fd_snapshot_restore_get_slot}} -->
Retrieve the current slot from a snapshot restore object.
- **Description**: Use this function to obtain the current slot value from a snapshot restore object, which is part of the snapshot loading pipeline. This function is typically called when you need to access the slot information that is being processed or restored. Ensure that the `restore` object is properly initialized and valid before calling this function to avoid undefined behavior.
- **Inputs**:
    - `restore`: A pointer to a `fd_snapshot_restore_t` object. This must be a valid, non-null pointer to a properly initialized snapshot restore object. Passing a null or invalid pointer results in undefined behavior.
- **Output**: Returns the current slot value as an unsigned long integer from the provided snapshot restore object.
- **See also**: [`fd_snapshot_restore_get_slot`](fd_snapshot_restore.c.driver.md#fd_snapshot_restore_get_slot)  (Implementation)


