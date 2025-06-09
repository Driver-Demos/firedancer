# Purpose
The provided C code defines a module for loading snapshots from different sources, specifically HTTP and file I/O, and processing them using a Zstandard decompressor and a tar reader. The primary structure, `fd_snapshot_loader_t`, encapsulates all necessary components for handling snapshot data, including memory management for HTTP and Zstandard streams, file descriptors for file I/O, and tar reading capabilities. The code includes functions to initialize, configure, and manage the lifecycle of a snapshot loader, such as [`fd_snapshot_loader_new`](#fd_snapshot_loader_new), [`fd_snapshot_loader_delete`](#fd_snapshot_loader_delete), and [`fd_snapshot_loader_init`](#fd_snapshot_loader_init). These functions ensure proper memory alignment, resource allocation, and error handling, making the module robust for snapshot loading tasks.

The module also provides functionality to parse snapshot source information from strings, distinguishing between HTTP and file sources, and resolving network addresses when necessary. The [`fd_snapshot_src_parse`](#fd_snapshot_src_parse) and [`fd_snapshot_src_parse_type_unknown`](#fd_snapshot_src_parse_type_unknown) functions handle this parsing, supporting both explicit and inferred source types. The code is designed to be integrated into a larger system, likely as a library, given its focus on providing a structured API for snapshot loading and its reliance on external components like `fd_snapshot_http_t` and `fd_zstd_dstream_t`. The module's design emphasizes modularity and extensibility, allowing it to be adapted for various snapshot loading scenarios.
# Imports and Dependencies

---
- `fd_snapshot_loader.h`
- `fd_snapshot_base.h`
- `fd_snapshot_http.h`
- `errno.h`
- `fcntl.h`
- `netdb.h`
- `regex.h`
- `stdlib.h`
- `unistd.h`
- `sys/types.h`
- `sys/socket.h`
- `netinet/in.h`


# Data Structures

---
### fd\_snapshot\_loader
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, used for validation.
    - `http_mem`: Memory allocated for HTTP operations.
    - `http`: Pointer to an HTTP snapshot structure.
    - `snapshot_fd`: File descriptor for the snapshot file.
    - `vfile`: File input stream abstraction.
    - `vsrc`: Generic input stream abstraction.
    - `zstd`: Pointer to a Zstandard decompression stream.
    - `vzstd`: Zstandard input stream abstraction.
    - `tar`: Tar archive reader abstraction.
    - `vtar`: Tar input stream abstraction.
    - `restore`: Pointer to a snapshot restore structure.
    - `name`: Structure holding hash and slot numbers derived from the filename.
- **Description**: The `fd_snapshot_loader` structure is designed to manage the loading of snapshot data from various sources, such as HTTP or file I/O, and facilitate its decompression and processing. It includes members for handling HTTP connections, file descriptors, and input stream abstractions for both file and Zstandard compressed data. Additionally, it manages tar archive reading and provides a mechanism for restoring snapshots. The structure is initialized with a unique magic number for validation purposes and contains a name field for storing metadata extracted from filenames.


---
### fd\_snapshot\_loader\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier to verify the integrity of the structure.
    - `http_mem`: Memory allocated for HTTP operations.
    - `http`: Pointer to an HTTP snapshot structure.
    - `snapshot_fd`: File descriptor for the snapshot file.
    - `vfile`: File input stream abstraction.
    - `vsrc`: Generic input stream abstraction.
    - `zstd`: Pointer to a Zstandard decompression stream.
    - `vzstd`: Zstandard input stream abstraction.
    - `tar`: Tar archive reader.
    - `vtar`: Tar input stream abstraction.
    - `restore`: Pointer to a snapshot restore structure.
    - `name`: Structure to hold hash and slot numbers from the filename.
- **Description**: The `fd_snapshot_loader_t` structure is designed to manage the loading of snapshot data from various sources, such as HTTP or file I/O, and facilitate its decompression and processing. It includes members for handling HTTP connections, file descriptors, and Zstandard decompression, as well as abstractions for input streams and tar archive reading. The structure also maintains a unique magic number for integrity checks and a name structure for managing hash and slot numbers derived from filenames.


# Functions

---
### fd\_snapshot\_loader\_align<!-- {{#callable:fd_snapshot_loader_align}} -->
The `fd_snapshot_loader_align` function returns the maximum alignment requirement between the `fd_snapshot_loader_t` structure and the Zstandard decompression stream.
- **Inputs**: None
- **Control Flow**:
    - The function calls `fd_ulong_max` with two arguments: `alignof(fd_snapshot_loader_t)` and `fd_zstd_dstream_align()`.
    - It returns the result of `fd_ulong_max`, which is the maximum of the two alignment values.
- **Output**: The function returns an `ulong` representing the maximum alignment requirement between the `fd_snapshot_loader_t` structure and the Zstandard decompression stream.


---
### fd\_snapshot\_loader\_footprint<!-- {{#callable:fd_snapshot_loader_footprint}} -->
The `fd_snapshot_loader_footprint` function calculates the memory footprint required for a snapshot loader, including its components like the Zstandard decompressor and HTTP structures, based on a given Zstandard window size.
- **Inputs**:
    - `zstd_window_sz`: The size of the Zstandard decompression window, which affects the memory footprint of the decompressor.
- **Control Flow**:
    - Initialize a variable `l` with `FD_LAYOUT_INIT` to start the layout calculation.
    - Append the memory alignment and size of `fd_snapshot_loader_t` to `l` using `FD_LAYOUT_APPEND`.
    - Append the alignment and footprint of the Zstandard decompressor, calculated with `fd_zstd_dstream_align()` and `fd_zstd_dstream_footprint(zstd_window_sz)`, to `l`.
    - Append the alignment and size of `fd_snapshot_http_t` to `l`.
    - Finalize the layout calculation with `FD_LAYOUT_FINI`, using the alignment of the snapshot loader from `fd_snapshot_loader_align()`, and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the snapshot loader and its components.
- **Functions called**:
    - [`fd_snapshot_loader_align`](#fd_snapshot_loader_align)


---
### fd\_snapshot\_loader\_new<!-- {{#callable:fd_snapshot_loader_new}} -->
The `fd_snapshot_loader_new` function initializes a new `fd_snapshot_loader_t` structure using provided memory and a specified Zstandard decompression window size.
- **Inputs**:
    - `mem`: A pointer to the memory block where the snapshot loader will be initialized.
    - `zstd_window_sz`: The size of the Zstandard decompression window to be used.
- **Control Flow**:
    - Check if the `mem` pointer is NULL and log a warning if it is, returning NULL.
    - Check if the `mem` pointer is properly aligned according to `fd_snapshot_loader_align()` and log a warning if it is not, returning NULL.
    - Initialize a scratch allocator with the provided memory.
    - Allocate memory for the `fd_snapshot_loader_t` structure, Zstandard decompression stream, and HTTP memory using the scratch allocator.
    - Finalize the scratch allocation ensuring alignment with `fd_snapshot_loader_align()`.
    - Zero out the memory for the `fd_snapshot_loader_t` structure.
    - Initialize the Zstandard decompression stream with the allocated memory and specified window size.
    - Set the `magic` field of the loader to `FD_SNAPSHOT_LOADER_MAGIC` to indicate successful initialization.
    - Return the pointer to the initialized `fd_snapshot_loader_t` structure.
- **Output**: A pointer to the newly initialized `fd_snapshot_loader_t` structure, or NULL if initialization fails due to invalid input or alignment issues.
- **Functions called**:
    - [`fd_snapshot_loader_align`](#fd_snapshot_loader_align)


---
### fd\_snapshot\_loader\_delete<!-- {{#callable:fd_snapshot_loader_delete}} -->
The `fd_snapshot_loader_delete` function safely deletes a snapshot loader by releasing its resources and resetting its state.
- **Inputs**:
    - `loader`: A pointer to an `fd_snapshot_loader_t` structure that represents the snapshot loader to be deleted.
- **Control Flow**:
    - Check if the `loader` is NULL and return NULL if true.
    - Verify the `magic` field of the loader to ensure it is valid; log a warning and return NULL if it is not.
    - Delete various components associated with the loader, including Zstandard decompressor, tar reader, and HTTP components.
    - If the `snapshot_fd` is open (>=0), attempt to close it and log a warning if the close operation fails.
    - Set the `snapshot_fd` to -1 to indicate it is closed.
    - Use memory fences to ensure memory operations are completed before resetting the `magic` field to 0.
    - Return the pointer to the loader.
- **Output**: Returns a pointer to the `fd_snapshot_loader_t` structure if successful, or NULL if the loader is invalid or deletion fails.
- **Functions called**:
    - [`fd_tar_io_reader_delete`](fd_snapshot_istream.c.driver.md#fd_tar_io_reader_delete)
    - [`fd_io_istream_zstd_delete`](fd_snapshot_istream.c.driver.md#fd_io_istream_zstd_delete)
    - [`fd_io_istream_file_delete`](fd_snapshot_istream.c.driver.md#fd_io_istream_file_delete)
    - [`fd_snapshot_http_delete`](fd_snapshot_http.c.driver.md#fd_snapshot_http_delete)


---
### fd\_snapshot\_loader\_init<!-- {{#callable:fd_snapshot_loader_init}} -->
The `fd_snapshot_loader_init` function initializes a snapshot loader for either file or HTTP sources, setting up the necessary streams and readers for snapshot restoration.
- **Inputs**:
    - `d`: A pointer to an `fd_snapshot_loader_t` structure that will be initialized.
    - `restore`: A pointer to an `fd_snapshot_restore_t` structure used for restoring snapshots.
    - `src`: A constant pointer to an `fd_snapshot_src_t` structure that specifies the source of the snapshot, either file or HTTP.
    - `base_slot`: An unsigned long integer representing the base slot number for validation.
    - `validate_slot`: An integer flag indicating whether to validate the slot number.
- **Control Flow**:
    - Assigns the `restore` pointer to the `d->restore` field.
    - Checks the type of the source (`src->type`) to determine if it is a file or HTTP source.
    - If the source is a file, it attempts to open the file and validate the slot if required, setting up a file input stream.
    - If the source is HTTP, it initializes an HTTP connection and sets the path, setting up an HTTP input stream.
    - Sets up a tar reader for the snapshot restoration process.
    - Resets the Zstandard decompressor stream.
    - Creates a Zstandard input stream and a tar input stream for reading the snapshot.
    - Returns the initialized `fd_snapshot_loader_t` structure or `NULL` if any step fails.
- **Output**: Returns a pointer to the initialized `fd_snapshot_loader_t` structure, or `NULL` if initialization fails at any step.
- **Functions called**:
    - [`fd_snapshot_name_slot_validate`](fd_snapshot_base.c.driver.md#fd_snapshot_name_slot_validate)
    - [`fd_io_istream_file_virtual`](fd_snapshot_istream.h.driver.md#fd_io_istream_file_virtual)
    - [`fd_snapshot_http_new`](fd_snapshot_http.c.driver.md#fd_snapshot_http_new)
    - [`fd_snapshot_http_set_path`](fd_snapshot_http.c.driver.md#fd_snapshot_http_set_path)
    - [`fd_io_istream_snapshot_http_virtual`](fd_snapshot_http.h.driver.md#fd_io_istream_snapshot_http_virtual)
    - [`fd_io_istream_zstd_virtual`](fd_snapshot_istream.h.driver.md#fd_io_istream_zstd_virtual)


---
### fd\_snapshot\_loader\_advance<!-- {{#callable:fd_snapshot_loader_advance}} -->
The `fd_snapshot_loader_advance` function advances the state of a snapshot loader by processing the next entry in a tar archive, handling various outcomes such as successful advancement, end of manifest, or errors.
- **Inputs**:
    - `dumper`: A pointer to an `fd_snapshot_loader_t` structure, which contains the state and resources for loading a snapshot.
- **Control Flow**:
    - Retrieve the tar reader from the `dumper` structure.
    - Call [`fd_tar_io_reader_advance`](fd_snapshot_istream.c.driver.md#fd_tar_io_reader_advance) on the tar reader to attempt to advance to the next entry.
    - Check the return value `untar_err` from [`fd_tar_io_reader_advance`](fd_snapshot_istream.c.driver.md#fd_tar_io_reader_advance):
    - If `untar_err` is 0, the advancement was successful, and the function returns 0.
    - If `untar_err` is `MANIFEST_DONE`, the manifest has been completely read, and the function returns `MANIFEST_DONE`.
    - If `untar_err` is negative, it indicates an EOF, and the function returns -1.
    - For any other positive `untar_err`, log a warning message and return the error code.
- **Output**: The function returns 0 on successful advancement, `MANIFEST_DONE` if the manifest is completely read, -1 on EOF, or an error code if an error occurs.
- **Functions called**:
    - [`fd_tar_io_reader_advance`](fd_snapshot_istream.c.driver.md#fd_tar_io_reader_advance)


---
### fd\_snapshot\_src\_parse<!-- {{#callable:fd_snapshot_src_parse}} -->
The `fd_snapshot_src_parse` function initializes and parses a snapshot source from a given string and source type, supporting both HTTP and file sources.
- **Inputs**:
    - `src`: A pointer to an `fd_snapshot_src_t` structure that will be initialized and populated based on the parsed source.
    - `cstr`: A string representing the source, which could be a URL for HTTP sources or a file path for file sources.
    - `src_type`: An integer indicating the type of source, either `FD_SNAPSHOT_SRC_HTTP` for HTTP sources or `FD_SNAPSHOT_SRC_FILE` for file sources.
- **Control Flow**:
    - The function begins by zeroing out the `src` structure using `fd_memset`.
    - If the `src_type` is `FD_SNAPSHOT_SRC_HTTP`, it compiles a regular expression to match HTTP URLs and attempts to match the `cstr` against this pattern.
    - If the URL is valid, it extracts the hostname, port, and path from the URL and populates the `src` structure accordingly.
    - If no port is specified in the URL, it defaults to port 80; otherwise, it parses the port number and checks its validity.
    - The function then attempts to resolve the hostname to an IPv4 address using `getaddrinfo`, and if successful, stores the address in the `src` structure.
    - If the `src_type` is `FD_SNAPSHOT_SRC_FILE`, it simply sets the `src` type to file and assigns the `cstr` as the file path.
    - If the `src_type` is unrecognized, it logs an error and terminates.
- **Output**: Returns a pointer to the initialized `fd_snapshot_src_t` structure if successful, or `NULL` if an error occurs during parsing or resolution.


---
### fd\_snapshot\_src\_parse\_type\_unknown<!-- {{#callable:fd_snapshot_src_parse_type_unknown}} -->
The function `fd_snapshot_src_parse_type_unknown` determines the type of snapshot source from a given string and parses it accordingly.
- **Inputs**:
    - `src`: A pointer to an `fd_snapshot_src_t` structure where the parsed snapshot source information will be stored.
    - `cstr`: A character string representing the snapshot source, which could be a URL or a file path.
- **Control Flow**:
    - The function checks if the input string `cstr` starts with "http://".
    - If it does, it calls [`fd_snapshot_src_parse`](#fd_snapshot_src_parse) with `FD_SNAPSHOT_SRC_HTTP` as the source type.
    - If it does not, it calls [`fd_snapshot_src_parse`](#fd_snapshot_src_parse) with `FD_SNAPSHOT_SRC_FILE` as the source type.
    - The function ends with `__builtin_unreachable()` indicating that the code should never reach this point.
- **Output**: Returns a pointer to the `fd_snapshot_src_t` structure with the parsed source information, or `NULL` if parsing fails.
- **Functions called**:
    - [`fd_snapshot_src_parse`](#fd_snapshot_src_parse)


---
### fd\_snapshot\_loader\_get\_name<!-- {{#callable:fd_snapshot_loader_get_name}} -->
The function `fd_snapshot_loader_get_name` retrieves the name of the snapshot associated with a given snapshot loader.
- **Inputs**:
    - `loader`: A pointer to a constant `fd_snapshot_loader_t` structure from which the snapshot name is to be retrieved.
- **Control Flow**:
    - The function takes a single input, a pointer to a `fd_snapshot_loader_t` structure.
    - It returns the address of the `name` field within the `fd_snapshot_loader_t` structure.
- **Output**: A pointer to a constant `fd_snapshot_name_t` structure, representing the name of the snapshot, or `NULL` if the input is `NULL`.


