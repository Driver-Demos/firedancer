# Purpose
The `fd_snapshot_loader.h` file is a C header file that defines the interface for a snapshot loading pipeline, which is part of a larger system dealing with data snapshots. This file provides high-level APIs for streaming and loading snapshots from either the local file system or over HTTP. The snapshot loading process involves reading, decompressing (using Zstandard), and extracting (using tar) the snapshot data, followed by restoring it. The header file outlines the structure and functions necessary to manage this process, including the definition of `fd_snapshot_loader_t` and `fd_snapshot_src_t` types, which handle the file descriptors, buffers, and source information for the snapshot loading.

The file includes several key components: it defines the `fd_snapshot_loader_t` structure for managing the loading process, and the `fd_snapshot_src_t` structure for specifying the source of the snapshot, which can be a file or an HTTP endpoint. The header provides function prototypes for creating, initializing, and advancing the snapshot loader, as well as parsing the snapshot source. The [`fd_snapshot_loader_init`](#fd_snapshot_loader_init) function configures the loader to send data to a restore object, while [`fd_snapshot_loader_advance`](#fd_snapshot_loader_advance) is used to poll for data and process it through the pipeline. This header is intended to be included in other C files that implement or utilize the snapshot loading functionality, providing a clear API for managing the snapshot loading process.
# Imports and Dependencies

---
- `fd_snapshot.h`
- `fd_snapshot_istream.h`
- `fd_snapshot_restore.h`


# Global Variables

---
### fd\_snapshot\_loader
- **Type**: `struct fd_snapshot_loader`
- **Description**: The `fd_snapshot_loader` is a structure that manages file descriptors and buffers used during the process of loading a snapshot. It is part of a single-threaded streaming pipeline designed to load snapshots from the local file system or over HTTP. The structure is defined but not detailed in the provided code, indicating it is likely used internally to handle the complexities of snapshot loading.
- **Use**: This variable is used to manage resources and operations involved in the snapshot loading process, facilitating the reading, decompressing, and restoring of snapshot data.


---
### fd\_snapshot\_loader\_new
- **Type**: `fd_snapshot_loader_t *`
- **Description**: The `fd_snapshot_loader_new` function is a constructor for creating a new instance of the `fd_snapshot_loader_t` structure. It initializes the loader with a specified memory location and a Zstandard window size, which is used for managing file descriptors and buffers during the snapshot loading process.
- **Use**: This function is used to allocate and initialize a new snapshot loader object, preparing it for use in the snapshot loading pipeline.


---
### fd\_snapshot\_loader\_delete
- **Type**: `void *`
- **Description**: The `fd_snapshot_loader_delete` function is a global function that takes a pointer to an `fd_snapshot_loader_t` structure and returns a `void *`. It is used to delete or clean up resources associated with a snapshot loader.
- **Use**: This function is used to release resources and perform cleanup for a snapshot loader instance.


---
### fd\_snapshot\_loader\_init
- **Type**: `fd_snapshot_loader_t *`
- **Description**: The `fd_snapshot_loader_init` function initializes a snapshot loader object, configuring it to send data into a specified restore object. It takes parameters that define the loader, the restore target, the source of the snapshot, a base slot, and a validation flag.
- **Use**: This function is used to set up the snapshot loader for processing data from a specified source and directing it to a restore object.


---
### fd\_snapshot\_loader\_get\_name
- **Type**: `FD_FN_CONST fd_snapshot_name_t const *`
- **Description**: The `fd_snapshot_loader_get_name` function returns a constant pointer to an `fd_snapshot_name_t` type, which may be nullable. This function is part of the snapshot loading API and is used to retrieve the name associated with a snapshot loader instance.
- **Use**: This function is used to obtain the name of the snapshot being processed by a given `fd_snapshot_loader_t` instance.


---
### fd\_snapshot\_src\_parse
- **Type**: `function pointer`
- **Description**: The `fd_snapshot_src_parse` is a function that takes a pointer to an `fd_snapshot_src_t` structure, a character string, and an integer representing the source type. It returns a pointer to an `fd_snapshot_src_t` structure. This function is likely used to parse and initialize the `fd_snapshot_src_t` structure based on the provided string and source type.
- **Use**: This function is used to parse a snapshot source from a string and initialize the `fd_snapshot_src_t` structure accordingly.


---
### fd\_snapshot\_src\_parse\_type\_unknown
- **Type**: `function pointer`
- **Description**: The `fd_snapshot_src_parse_type_unknown` is a function pointer that takes a pointer to an `fd_snapshot_src_t` structure and a character string as arguments. It is used to determine the source type of a snapshot from a given string, particularly for testing and development purposes.
- **Use**: This function is used to parse and identify the type of snapshot source when the type is not explicitly set, primarily in non-production environments.


# Data Structures

---
### fd\_snapshot\_loader\_t
- **Type**: `typedef struct fd_snapshot_loader fd_snapshot_loader_t;`
- **Description**: The `fd_snapshot_loader_t` is a typedef for a structure that manages file descriptors and buffers used during the loading of a snapshot. It is part of a high-level API designed for streaming the loading of snapshots from either the local file system or over HTTP. The loader operates as a single-threaded streaming pipeline, which may be adapted to a tile architecture in the future. The structure itself is not defined in the provided code, indicating it is likely defined elsewhere or is an opaque type meant to be manipulated through provided API functions.


---
### fd\_snapshot\_src
- **Type**: `struct`
- **Members**:
    - `type`: An integer indicating the type of snapshot source, either file or HTTP.
    - `file`: A nested structure containing a single member, 'path', which is a constant character pointer to the file path.
    - `http`: A nested structure containing 'dest', 'ip4', 'port', 'path', and 'path_len' for HTTP source details.
    - `snapshot_dir`: A constant character pointer to the directory where the snapshot is stored.
- **Description**: The 'fd_snapshot_src' structure is used to define the source of a snapshot, which can either be a local file or an HTTP source. It contains a union that allows for two different configurations: one for file-based sources, which includes a file path, and another for HTTP-based sources, which includes destination address, IP, port, path, and path length. Additionally, it holds a pointer to the directory where the snapshot is located, allowing the snapshot loader to determine the source type and access the necessary data for loading snapshots.


---
### fd\_snapshot\_src\_t
- **Type**: `struct`
- **Members**:
    - `type`: An integer representing the type of snapshot source.
    - `file`: A structure containing a constant character pointer 'path' for file-based snapshot sources.
    - `http`: A structure containing destination address, IP, port, path, and path length for HTTP-based snapshot sources.
    - `snapshot_dir`: A constant character pointer to the directory of the snapshot.
- **Description**: The `fd_snapshot_src_t` structure is used to specify the source of a snapshot, which can either be a file or an HTTP source. It contains a type field to indicate the source type, and a union that holds specific details for file or HTTP sources. For file sources, it includes a path, while for HTTP sources, it includes destination details, IP address, port, path, and path length. Additionally, it has a field for the snapshot directory path.


# Function Declarations (Public API)

---
### fd\_snapshot\_loader\_align<!-- {{#callable_declaration:fd_snapshot_loader_align}} -->
Returns the alignment requirement for a snapshot loader.
- **Description**: Use this function to determine the memory alignment requirement for creating a snapshot loader. This is necessary when allocating memory for a snapshot loader to ensure proper alignment, which is crucial for performance and correctness on some architectures. The function provides the maximum alignment requirement between the snapshot loader structure and the Zstandard decompression stream.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes.
- **See also**: [`fd_snapshot_loader_align`](fd_snapshot_loader.c.driver.md#fd_snapshot_loader_align)  (Implementation)


---
### fd\_snapshot\_loader\_footprint<!-- {{#callable_declaration:fd_snapshot_loader_footprint}} -->
Calculates the memory footprint required for a snapshot loader.
- **Description**: Use this function to determine the amount of memory needed to allocate for a snapshot loader, which is part of the snapshot loading pipeline. This function is essential when setting up the memory layout for the loader, ensuring that enough space is reserved based on the specified Zstandard decompression window size. It is typically called before initializing a snapshot loader to allocate the correct amount of memory.
- **Inputs**:
    - `zstd_window_sz`: Specifies the Zstandard decompression window size in bytes. This value influences the memory footprint calculation and should be chosen based on the expected size of the compressed data. The function assumes this value is valid and does not perform error checking on it.
- **Output**: Returns the calculated memory footprint in bytes required for the snapshot loader.
- **See also**: [`fd_snapshot_loader_footprint`](fd_snapshot_loader.c.driver.md#fd_snapshot_loader_footprint)  (Implementation)


---
### fd\_snapshot\_loader\_new<!-- {{#callable_declaration:fd_snapshot_loader_new}} -->
Creates a new snapshot loader instance.
- **Description**: This function allocates and initializes a new `fd_snapshot_loader_t` instance using the provided memory buffer. It is used to set up the upstream part of a snapshot loading pipeline, which involves reading, decompressing, and restoring data. The function must be called with a properly aligned memory buffer, and the size of the buffer should be sufficient to accommodate the loader and its associated resources. The function returns a pointer to the newly created loader instance, or `NULL` if the memory is `NULL` or not properly aligned.
- **Inputs**:
    - `mem`: A pointer to a memory buffer where the loader will be allocated. Must not be null and must be aligned according to `fd_snapshot_loader_align()`. The caller retains ownership of the memory.
    - `zstd_window_sz`: The size of the Zstandard decompression window. This value determines the memory footprint required for decompression.
- **Output**: Returns a pointer to the newly created `fd_snapshot_loader_t` instance, or `NULL` if the input memory is null or not properly aligned.
- **See also**: [`fd_snapshot_loader_new`](fd_snapshot_loader.c.driver.md#fd_snapshot_loader_new)  (Implementation)


---
### fd\_snapshot\_loader\_delete<!-- {{#callable_declaration:fd_snapshot_loader_delete}} -->
Deletes a snapshot loader and releases its resources.
- **Description**: Use this function to safely delete a snapshot loader object and release all associated resources, such as file descriptors and buffers. It should be called when the loader is no longer needed to ensure proper cleanup. The function checks for a valid loader and its magic number before proceeding with the deletion. If the loader is invalid or has an incorrect magic number, the function returns NULL without performing any operations.
- **Inputs**:
    - `loader`: A pointer to the fd_snapshot_loader_t object to be deleted. Must not be null and must have a valid magic number. If the pointer is null or the magic number is invalid, the function returns NULL.
- **Output**: Returns the pointer to the loader if deletion is successful, or NULL if the loader is invalid or has an incorrect magic number.
- **See also**: [`fd_snapshot_loader_delete`](fd_snapshot_loader.c.driver.md#fd_snapshot_loader_delete)  (Implementation)


---
### fd\_snapshot\_loader\_init<!-- {{#callable_declaration:fd_snapshot_loader_init}} -->
Initialize a snapshot loader for streaming data from a specified source.
- **Description**: This function sets up a snapshot loader to stream data from a specified source, either a local file system or an HTTP endpoint, into a restore object. It configures the loader to handle the data source specified by the `src` parameter and prepares it for data streaming. The function must be called with a valid `fd_snapshot_loader_t` object and a `fd_snapshot_restore_t` object. The `base_slot` and `validate_slot` parameters are used to validate the snapshot slot if required. The function returns a pointer to the initialized loader on success or `NULL` on failure, logging any errors encountered during initialization.
- **Inputs**:
    - `loader`: A pointer to an `fd_snapshot_loader_t` object that will be initialized. Must not be null.
    - `restore`: A pointer to an `fd_snapshot_restore_t` object where the snapshot data will be restored. Must not be null.
    - `src`: A pointer to an `fd_snapshot_src_t` object specifying the source of the snapshot. Must not be null and must be properly configured to indicate either a file or HTTP source.
    - `base_slot`: An unsigned long integer representing the base slot for validation purposes. Used only if `validate_slot` is non-zero.
    - `validate_slot`: An integer flag indicating whether to validate the snapshot slot against `base_slot`. Non-zero to enable validation, zero to disable.
- **Output**: Returns a pointer to the initialized `fd_snapshot_loader_t` on success, or `NULL` on failure.
- **See also**: [`fd_snapshot_loader_init`](fd_snapshot_loader.c.driver.md#fd_snapshot_loader_init)  (Implementation)


---
### fd\_snapshot\_loader\_advance<!-- {{#callable_declaration:fd_snapshot_loader_advance}} -->
Polls the tar reader for data and advances the snapshot loading process.
- **Description**: This function is the primary polling entry point for the snapshot loader, advancing the loading process by reading data from the tar reader. It should be called repeatedly to process the snapshot data until the end of the file is reached or an error occurs. The function returns different codes to indicate the status of the operation, including successful advancement, end of file, or an error. It is important to handle these return codes appropriately to ensure the snapshot loading process completes successfully.
- **Inputs**:
    - `dumper`: A pointer to an fd_snapshot_loader_t structure, which manages the file descriptors and buffers used during the snapshot load. Must not be null, and should be properly initialized before calling this function.
- **Output**: Returns 0 if the advance was successful, -1 if the end of the file is reached, or an errno-compatible code on failure. Errors are also logged.
- **See also**: [`fd_snapshot_loader_advance`](fd_snapshot_loader.c.driver.md#fd_snapshot_loader_advance)  (Implementation)


---
### fd\_snapshot\_loader\_get\_name<!-- {{#callable_declaration:fd_snapshot_loader_get_name}} -->
Retrieve the name of the snapshot from the loader.
- **Description**: Use this function to obtain the name associated with a snapshot loader. It is useful when you need to identify or log the specific snapshot being processed by the loader. This function should be called only after the loader has been properly initialized. The function returns a pointer to the snapshot name, which may be null if the loader does not have a name set.
- **Inputs**:
    - `loader`: A pointer to an `fd_snapshot_loader_t` structure. This must not be null, as the function expects a valid loader object to retrieve the name from. If the loader is not properly initialized, the behavior is undefined.
- **Output**: A pointer to a constant `fd_snapshot_name_t` structure representing the snapshot name, or null if no name is set.
- **See also**: [`fd_snapshot_loader_get_name`](fd_snapshot_loader.c.driver.md#fd_snapshot_loader_get_name)  (Implementation)


---
### fd\_snapshot\_src\_parse<!-- {{#callable_declaration:fd_snapshot_src_parse}} -->
Parses a snapshot source from a string based on the specified source type.
- **Description**: This function initializes and parses a snapshot source structure from a given string, interpreting it according to the specified source type. It supports parsing for HTTP URLs and file paths. When the source type is HTTP, it validates the URL format, extracts the hostname, port, and path, and resolves the hostname to an IPv4 address. If the source type is a file, it simply assigns the file path. The function must be called with a valid source type, and the input string must conform to the expected format for the specified type. It returns a pointer to the initialized source structure on success, or NULL if parsing fails due to invalid input or an unrecognized source type.
- **Inputs**:
    - `src`: A pointer to an fd_snapshot_src_t structure that will be initialized and populated. The caller retains ownership and must ensure it is a valid, non-null pointer.
    - `cstr`: A string representing the source to be parsed. For HTTP sources, it must be a valid URL. For file sources, it should be a valid file path. The string must be null-terminated.
    - `src_type`: An integer indicating the type of source to parse. Must be either FD_SNAPSHOT_SRC_HTTP for HTTP URLs or FD_SNAPSHOT_SRC_FILE for file paths. Unrecognized types will result in an error.
- **Output**: Returns a pointer to the initialized fd_snapshot_src_t structure on success, or NULL if parsing fails.
- **See also**: [`fd_snapshot_src_parse`](fd_snapshot_loader.c.driver.md#fd_snapshot_src_parse)  (Implementation)


---
### fd\_snapshot\_src\_parse\_type\_unknown<!-- {{#callable_declaration:fd_snapshot_src_parse_type_unknown}} -->
Determines the snapshot source type from a given string.
- **Description**: This function is used to determine the type of snapshot source based on the provided string, which is expected to represent a URL or file path. It is primarily intended for testing and development purposes, as production environments should explicitly set the snapshot source type in configuration files. The function examines the beginning of the string to decide whether the source is an HTTP URL or a file path, and then delegates to another function to parse the source accordingly.
- **Inputs**:
    - `src`: A pointer to an fd_snapshot_src_t structure where the parsed source information will be stored. The caller must ensure this pointer is valid and points to a writable memory location.
    - `cstr`: A string representing the snapshot source, which can be a URL or a file path. The string must be null-terminated and must not be null. The function uses the string to determine the source type.
- **Output**: Returns a pointer to the fd_snapshot_src_t structure provided in the src parameter, populated with the parsed source information.
- **See also**: [`fd_snapshot_src_parse_type_unknown`](fd_snapshot_loader.c.driver.md#fd_snapshot_src_parse_type_unknown)  (Implementation)


