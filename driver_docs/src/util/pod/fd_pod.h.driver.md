# Purpose
The provided C header file defines a comprehensive API for managing "pods," which are flexible, hierarchical data structures designed to store typed key-value pairs. These pods are optimized for in-memory storage, serialization, and distribution across different systems and architectures. The file outlines the structure and operations of pods, including creation, querying, serialization, and manipulation of key-value pairs. It supports various data types, including primitive types and nested pods, allowing for complex data hierarchies. The header also includes error codes, value type definitions, and utility functions for handling pods efficiently.

The file is structured to facilitate the use of pods in distributed environments, providing functions for creating, joining, and deleting pods, as well as querying and iterating over their contents. It includes mechanisms for handling different data types, including custom user-defined types, and supports operations like resizing and compacting pods to optimize memory usage. The API is designed to be robust and flexible, making it suitable for applications that require dynamic configuration management, data serialization, and efficient data exchange across networked systems.
# Imports and Dependencies

---
- `../cstr/fd_cstr.h`


# Global Variables

---
### fd\_pod\_list
- **Type**: `fd_pod_info_t *`
- **Description**: The `fd_pod_list` function returns a pointer to a `fd_pod_info_t` structure, which contains details about the current key-value pairs in a pod. This function does not recurse into any subpods within the pod.
- **Use**: This variable is used to retrieve and store information about the key-value pairs present in a pod, facilitating operations like listing or querying these pairs.


---
### fd\_pod\_list\_recursive
- **Type**: `fd_pod_info_t *`
- **Description**: The `fd_pod_list_recursive` function is a global function that returns a pointer to a `fd_pod_info_t` structure. It is designed to list all key-value pairs in a pod, including those within subpods, by performing a depth-first recursive traversal. This function is part of a set of APIs for managing flexible hierarchies of typed key-value pairs in a pod data structure.
- **Use**: This function is used to obtain a comprehensive list of all key-value pairs in a pod, including nested subpods, by recursively traversing the pod structure.


---
### fd\_pod\_strerror
- **Type**: ``FD_FN_CONST char const *``
- **Description**: The `fd_pod_strerror` function is a global function that returns a constant character pointer. It is used to convert error codes related to the `fd_pod` APIs into human-readable strings. The function ensures that the returned string is always non-NULL and has an infinite lifetime.
- **Use**: This function is used to provide descriptive error messages for error codes encountered in `fd_pod` operations.


---
### fd\_pod\_val\_type\_to\_cstr
- **Type**: `function`
- **Description**: The `fd_pod_val_type_to_cstr` function converts a given integer value type, `val_type`, into its corresponding C-string representation. It populates the provided buffer `cstr` with this string, assuming the buffer has enough space for the maximum possible string length defined by `FD_POD_VAL_TYPE_CSTR_MAX`.
- **Use**: This function is used to obtain a human-readable string representation of a value type stored in a pod, facilitating easier debugging and logging.


---
### fd\_pod\_alloc
- **Type**: `function`
- **Description**: The `fd_pod_alloc` function is a global function that allocates space in a pod for a key at the end of a specified path, with a given value type and size. It returns the offset in the pod where the value should be stored, or 0 on failure. This function is part of a set of APIs for managing flexible hierarchies of typed key-value pairs in a pod data structure.
- **Use**: This function is used to allocate space for a new key-value pair in a pod, potentially creating subpods along the path if they do not exist.


---
### fd\_pod\_insert
- **Type**: `ulong`
- **Description**: The `fd_pod_insert` function is a static function that inserts a key-value pair into a pod data structure. It allocates space for the value in the pod and copies the value into the allocated space.
- **Use**: This function is used to add a new key-value pair to a pod, ensuring the value is stored at the correct location within the pod's memory.


---
### fd\_pod\_remove
- **Type**: `function`
- **Description**: The `fd_pod_remove` function is designed to remove a key from a pod data structure. The key to be removed is specified by a path, which can navigate through nested subpods to reach the desired key. If the path ends on a subpod, that subpod and all its contents will be removed.
- **Use**: This function is used to delete a key or subpod from a pod, potentially affecting the structure and contents of the pod.


---
### fd\_pod\_alloc\_subpod
- **Type**: `function`
- **Description**: The `fd_pod_alloc_subpod` function is a static inline function that allocates space for a new subpod within an existing pod data structure. It takes a pointer to the pod, a path to where the subpod should be allocated, and the maximum size of the subpod. The function ensures that the subpod is created with enough space to hold up to the specified maximum number of bytes.
- **Use**: This function is used to create a new subpod within a pod, allowing for hierarchical organization of data within the pod structure.


---
### fd\_pod\_alloc\_buf
- **Type**: `function`
- **Description**: The `fd_pod_alloc_buf` function is a static inline function that allocates space for a buffer within a pod data structure. It takes a pointer to the pod, a path to where the buffer should be allocated, and the size of the buffer to be allocated. The function returns the offset within the pod where the buffer is allocated.
- **Use**: This function is used to allocate a buffer of a specified size within a pod, allowing for the storage of raw data in a structured manner.


---
### fd\_pod\_alloc\_cstr
- **Type**: `function`
- **Description**: `fd_pod_alloc_cstr` is a static inline function that allocates space in a pod for a C-style string (cstr) at a specified path. It ensures that the allocated space can accommodate the string's length, including the terminating null character ('\0').
- **Use**: This function is used to allocate memory for a cstr within a pod, facilitating the storage of string data in a structured manner.


---
### fd\_pod\_insert\_subpod
- **Type**: `function`
- **Description**: The `fd_pod_insert_subpod` function is a static inline function that inserts a subpod into a given pod at a specified path. It uses the `fd_pod_insert` function to perform the insertion, specifying the value type as `FD_POD_VAL_TYPE_SUBPOD` and determining the size of the subpod using `fd_pod_max`. The function returns the offset where the subpod is inserted within the pod.
- **Use**: This function is used to insert a subpod into a pod data structure at a specified path, facilitating the management of hierarchical data within the pod.


---
### fd\_pod\_insert\_buf
- **Type**: `function`
- **Description**: `fd_pod_insert_buf` is a static inline function that inserts a buffer into a pod data structure at a specified path. It takes a pointer to the pod, a path string, a pointer to the buffer value, and the size of the buffer as arguments.
- **Use**: This function is used to insert a buffer into a pod, facilitating the storage of raw data within the pod's hierarchical key-value structure.


---
### fd\_pod\_insert\_cstr
- **Type**: `function`
- **Description**: The `fd_pod_insert_cstr` function is a static inline function that inserts a C-style string (cstr) into a pod data structure at a specified path. It uses the `fd_pod_insert` function to perform the insertion, specifying the value type as `FD_POD_VAL_TYPE_CSTR` and calculating the size of the value based on the length of the string plus one for the null terminator.
- **Use**: This function is used to insert a null-terminated string into a pod at a given path, facilitating the management of string data within the pod structure.


---
### fd\_pod\_insert\_uint128
- **Type**: `static inline ulong`
- **Description**: The `fd_pod_insert_uint128` function is a static inline function that inserts a 128-bit unsigned integer (`uint128`) into a pod data structure at a specified path. It handles the encoding of the 128-bit value into two 64-bit parts and allocates space in the pod for this value.
- **Use**: This function is used to insert a 128-bit unsigned integer into a pod, ensuring the value is stored in a compact and efficient manner.


---
### fd\_pod\_insert\_int128
- **Type**: `function`
- **Description**: The `fd_pod_insert_int128` function is a static inline function that inserts a 128-bit signed integer (`int128`) into a pod data structure at a specified path. It encodes the integer using a zig-zag encoding scheme to handle negative values efficiently and then stores it in the pod.
- **Use**: This function is used to insert a 128-bit signed integer into a pod, which is a flexible data structure for managing key-value pairs.


# Data Structures

---
### fd\_pod\_info\_t
- **Type**: `struct`
- **Members**:
    - `key_sz`: Size of key in pod, including the terminating '\0'.
    - `key`: Pointer to the first byte of the pod key C-string.
    - `val_type`: Type of value, represented as an integer corresponding to FD_POD_VAL_TYPE_*.
    - `val_sz`: Size of the value in bytes, in its pod-encoded form.
    - `val`: Pointer to the first byte of the value in its pod-encoded form.
    - `parent`: Pointer to the parent pod info if the key is in a subpod, otherwise NULL.
- **Description**: The `fd_pod_info_t` structure is used to represent information about key-value pairs within a pod, which is a flexible data structure for managing hierarchies of typed key-value pairs. This structure is not stored within the pod itself but is used when listing or querying the contents of a pod. It includes details about the key size, key string, value type, value size, and a pointer to the value, as well as a pointer to the parent pod info for recursive listings.


---
### fd\_pod\_info
- **Type**: `struct`
- **Members**:
    - `key_sz`: Size of key in pod (includes terminating '\0').
    - `key`: Pointer to first byte of this pod key cstr.
    - `val_type`: Type of val (in [0,255], a FD_POD_VAL_TYPE_*).
    - `val_sz`: Size of val in bytes (pod encoded form).
    - `val`: Pointer to first byte of val (in pod encoded form).
    - `parent`: Pointer to an earlier info with details about the subpod, or NULL if not in a subpod.
- **Description**: The `fd_pod_info` structure is used to represent information about key-value pairs within a pod, which is a flexible hierarchy of typed key-value pairs stored contiguously in memory. This structure is not stored explicitly in the pod but is used when listing the contents of a pod. It includes details such as the size and pointer to the key, the type and size of the value, and a pointer to the value itself. Additionally, it can reference a parent `fd_pod_info` structure for recursive listings, indicating the hierarchical relationship of subpods within the main pod.


---
### fd\_pod\_iter\_private
- **Type**: `struct`
- **Members**:
    - `cursor`: A pointer to the current position in the pod iteration.
    - `stop`: A pointer to the end position in the pod iteration.
- **Description**: The `fd_pod_iter_private` structure is used to manage the iteration over key-value pairs in a pod data structure. It contains two pointers, `cursor` and `stop`, which define the current position and the end position of the iteration, respectively. This structure is part of the pod API, which facilitates the management of flexible hierarchies of typed key-value pairs stored contiguously in memory. The iterator does not recurse into subpods and assumes the pod remains unchanged during iteration.


---
### fd\_pod\_iter\_t
- **Type**: `struct`
- **Members**:
    - `cursor`: A pointer to the current position in the pod during iteration.
    - `stop`: A pointer to the end position in the pod, marking the end of iteration.
- **Description**: The `fd_pod_iter_t` is a structure used to iterate over key-value pairs in a pod data structure. It contains two pointers, `cursor` and `stop`, which are used to track the current position and the end position within the pod, respectively. This iterator allows for efficient traversal of the pod's contents without recursion into subpods, and is typically used in non-critical path initialization processes.


# Functions

---
### fd\_pod\_align<!-- {{#callable:fd_pod_align}} -->
The `fd_pod_align` function returns the alignment requirement for a pod, which is always 1 byte.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be inlined by the compiler for performance reasons.
    - It is marked with `FD_FN_CONST`, indicating that it is a pure function with no side effects and its return value depends only on its parameters (in this case, none).
    - The function simply returns the constant value `1UL`, indicating that the alignment requirement for a pod is 1 byte.
- **Output**: The function returns an unsigned long integer value of 1, representing the alignment requirement for a pod.


---
### fd\_pod\_footprint<!-- {{#callable:fd_pod_footprint}} -->
The `fd_pod_footprint` function calculates the memory footprint required for a pod, returning the maximum size if it meets the minimum requirement, or zero otherwise.
- **Inputs**:
    - `max`: An unsigned long integer representing the maximum size of the pod in bytes.
- **Control Flow**:
    - The function checks if the input `max` is greater than or equal to `FD_POD_FOOTPRINT_MIN`.
    - If `max` is greater than or equal to `FD_POD_FOOTPRINT_MIN`, it returns `max`.
    - If `max` is less than `FD_POD_FOOTPRINT_MIN`, it returns 0UL.
- **Output**: The function returns an unsigned long integer representing the footprint size, which is either `max` or 0UL depending on the input value.


---
### fd\_pod\_new<!-- {{#callable:fd_pod_new}} -->
The `fd_pod_new` function initializes a new pod data structure in a given memory region with specified maximum size.
- **Inputs**:
    - `shmem`: A pointer to the memory region where the pod will be initialized.
    - `max`: The maximum size in bytes that the pod can occupy, including its header.
- **Control Flow**:
    - Check if the `shmem` pointer is NULL; if so, return NULL.
    - Calculate the footprint of the pod using `fd_pod_footprint(max)`; if the footprint is zero, return NULL.
    - Cast the `shmem` pointer to an `uchar` pointer named `pod`.
    - Calculate the size of the symmetric-variable-width (svw) encoding for `max` using `fd_ulong_svw_enc_sz(max)`.
    - Encode `max` at the start of the pod using `fd_ulong_svw_enc_fixed`.
    - Encode the initial 'used' size (3 times the svw size) at the next position in the pod.
    - Encode the initial 'cnt' (0) at the next position in the pod.
    - Return the original `shmem` pointer.
- **Output**: Returns the original `shmem` pointer if successful, or NULL if the input is invalid or the footprint is zero.
- **Functions called**:
    - [`fd_pod_footprint`](#fd_pod_footprint)


---
### fd\_pod\_join<!-- {{#callable:fd_pod_join}} -->
The `fd_pod_join` function casts a generic pointer to a `uchar` pointer, effectively joining a shared memory pod for use as a `uchar` array.
- **Inputs**:
    - `shpod`: A void pointer to the shared memory pod that needs to be joined.
- **Control Flow**:
    - The function takes a single input, `shpod`, which is a void pointer.
    - It casts the `shpod` pointer to a `uchar` pointer.
    - The casted pointer is returned, allowing the caller to interact with the pod as a `uchar` array.
- **Output**: A `uchar` pointer that represents the joined pod, allowing access to the pod's data as a `uchar` array.


---
### fd\_pod\_leave<!-- {{#callable:fd_pod_leave}} -->
The `fd_pod_leave` function casts a constant unsigned character pointer to a void pointer.
- **Inputs**:
    - `pod`: A constant pointer to an unsigned character, representing a pod structure.
- **Control Flow**:
    - The function takes a single input parameter, `pod`, which is a constant pointer to an unsigned character.
    - It returns the input `pod` cast to a void pointer.
- **Output**: A void pointer that is the result of casting the input `pod`.


---
### fd\_pod\_delete<!-- {{#callable:fd_pod_delete}} -->
The `fd_pod_delete` function returns the input pointer `shpod` without performing any operations on it.
- **Inputs**:
    - `shpod`: A pointer to a shared memory region representing a pod, which is intended to be deleted.
- **Control Flow**:
    - The function takes a single input argument `shpod`.
    - It immediately returns the input argument `shpod` without any modification or additional operations.
- **Output**: The function returns the same pointer `shpod` that was passed as input.


---
### fd\_pod\_max<!-- {{#callable:fd_pod_max}} -->
The `fd_pod_max` function retrieves the maximum size of a pod in bytes from its encoded header.
- **Inputs**:
    - `pod`: A pointer to the pod's memory location, which is a contiguous block of memory containing the pod's data structure.
- **Control Flow**:
    - Calculate the size of the encoded maximum size using `fd_ulong_svw_dec_sz` with the pod pointer.
    - Decode the fixed-size maximum size from the pod using `fd_ulong_svw_dec_fixed` with the pod pointer and the calculated size.
- **Output**: The function returns an `ulong` representing the maximum size of the pod in bytes.


---
### fd\_pod\_used<!-- {{#callable:fd_pod_used}} -->
The `fd_pod_used` function calculates the number of bytes currently used in a pod, including the header.
- **Inputs**:
    - `pod`: A pointer to the beginning of the pod data structure, represented as a constant unsigned character array.
- **Control Flow**:
    - Calculate the size of the encoded 'used' field using `fd_ulong_svw_dec_sz` with the `pod` pointer.
    - Decode the 'used' field using `fd_ulong_svw_dec_fixed`, starting from the position after the 'max' field, and return the result.
- **Output**: The function returns an unsigned long integer representing the number of bytes currently used in the pod, including the header.


---
### fd\_pod\_cnt<!-- {{#callable:fd_pod_cnt}} -->
The `fd_pod_cnt` function calculates the number of key-value pairs in a given pod data structure.
- **Inputs**:
    - `pod`: A pointer to an unsigned character array representing the pod data structure.
- **Control Flow**:
    - Calculate the size of the symmetric-variable-width (svw) encoded unsigned long at the start of the pod using `fd_ulong_svw_dec_sz`.
    - Use the calculated size to decode the number of key-value pairs from the pod using `fd_ulong_svw_dec_fixed`, starting from an offset of twice the size.
- **Output**: Returns an unsigned long representing the number of key-value pairs in the pod.


---
### fd\_pod\_avail<!-- {{#callable:fd_pod_avail}} -->
The `fd_pod_avail` function calculates the number of bytes available for storing key-value pairs in a pod data structure.
- **Inputs**:
    - `pod`: A pointer to the beginning of the pod data structure, represented as an array of unsigned characters (`uchar`).
- **Control Flow**:
    - Calculate the size of the symmetric-variable-width (svw) encoded unsigned long at the start of the pod using `fd_ulong_svw_dec_sz(pod)`, storing it in `csz`.
    - Decode the maximum size of the pod using `fd_ulong_svw_dec_fixed(pod, csz)` and subtract the number of used bytes in the pod, decoded using `fd_ulong_svw_dec_fixed(pod + csz, csz)`.
    - Return the result of the subtraction, which represents the available space in the pod.
- **Output**: The function returns an unsigned long integer representing the number of bytes available for storing additional key-value pairs in the pod.


---
### fd\_pod\_iter\_init<!-- {{#callable:fd_pod_iter_t::fd_pod_iter_init}} -->
The `fd_pod_iter_init` function initializes an iterator for iterating over key-value pairs in a POD (Plain Old Data) structure.
- **Inputs**:
    - `pod`: A pointer to the first byte of a well-formed static POD structure or NULL.
- **Control Flow**:
    - Check if the input `pod` is NULL; if so, return an iterator with both `cursor` and `stop` set to NULL.
    - Calculate the size of the encoded header using `fd_ulong_svw_dec_sz` on the `pod`.
    - Initialize the iterator's `cursor` to point to the start of the key-value pairs, which is `pod + csz*3UL`.
    - Set the iterator's `stop` to the end of the used portion of the POD, calculated using `fd_ulong_svw_dec_fixed`.
    - Return the initialized iterator.
- **Output**: Returns an `fd_pod_iter_t` structure initialized to iterate over the key-value pairs in the POD, or an iterator with NULL pointers if the input `pod` is NULL.
- **See also**: [`fd_pod_iter_t`](#fd_pod_iter_t)  (Data Structure)


---
### fd\_pod\_iter\_done<!-- {{#callable:fd_pod_iter_done}} -->
The `fd_pod_iter_done` function checks if an iterator has reached the end of a pod's key-value pairs.
- **Inputs**:
    - `iter`: An `fd_pod_iter_t` structure representing the current state of iteration over a pod's key-value pairs.
- **Control Flow**:
    - The function compares the `cursor` field of the `iter` structure with its `stop` field.
    - If `cursor` is greater than or equal to `stop`, it indicates that the iteration is complete.
- **Output**: The function returns a non-zero integer if the iteration is complete (i.e., no more key-value pairs to iterate over), and zero if there are more pairs to iterate.


---
### fd\_pod\_iter\_next<!-- {{#callable:fd_pod_iter_t::fd_pod_iter_next}} -->
The `fd_pod_iter_next` function advances an iterator to the next key-value pair in a POD data structure.
- **Inputs**:
    - `iter`: An `fd_pod_iter_t` structure representing the current state of the iterator, including the current position in the POD.
- **Control Flow**:
    - Retrieve the current cursor position from the iterator.
    - Calculate the size of the current key using `fd_ulong_svw_dec_sz` and `fd_ulong_svw_dec_fixed`, and advance the cursor past the key.
    - Advance the cursor by one byte to skip over the current value type.
    - Calculate the size of the current value using `fd_ulong_svw_dec_sz` and `fd_ulong_svw_dec_fixed`, and advance the cursor past the value.
    - Update the iterator's cursor to the new position and return the updated iterator.
- **Output**: Returns an updated `fd_pod_iter_t` structure with the cursor advanced to the next key-value pair in the POD.
- **See also**: [`fd_pod_iter_t`](#fd_pod_iter_t)  (Data Structure)


---
### fd\_pod\_iter\_info<!-- {{#callable:fd_pod_info_t::fd_pod_iter_info}} -->
The `fd_pod_iter_info` function extracts and returns detailed information about the current key-value pair from a pod iterator.
- **Inputs**:
    - `iter`: An iterator of type `fd_pod_iter_t` that points to the current position in a pod from which information is to be extracted.
- **Control Flow**:
    - Initialize a cursor from the iterator's current position.
    - Decode the size of the key using `fd_ulong_svw_dec_sz` and `fd_ulong_svw_dec_fixed`, then update the cursor position.
    - Assign the decoded key to `info.key` and update the cursor position.
    - Extract the value type from the cursor and update the cursor position.
    - Decode the size of the value using `fd_ulong_svw_dec_sz` and `fd_ulong_svw_dec_fixed`, then update the cursor position.
    - Assign the decoded value to `info.val` and update the cursor position.
    - Set `info.parent` to NULL, indicating no parent in the current context.
    - Return the populated `fd_pod_info_t` structure.
- **Output**: A `fd_pod_info_t` structure containing the size and pointer to the key, the value type, the size and pointer to the value, and a NULL parent pointer.
- **See also**: [`fd_pod_info_t`](#fd_pod_info_t)  (Data Structure)


---
### fd\_pod\_reset<!-- {{#callable:fd_pod_reset}} -->
The `fd_pod_reset` function resets a pod by clearing all key-value pairs and subpods, effectively setting the used and count fields to zero.
- **Inputs**:
    - `pod`: A pointer to the pod data structure that needs to be reset.
- **Control Flow**:
    - Check if the input `pod` is NULL using `FD_UNLIKELY`; if so, return NULL immediately.
    - Calculate the size of the encoded header using `fd_ulong_svw_dec_sz(pod)`.
    - Set the 'used' field in the pod header to `3UL*csz` using `fd_ulong_svw_enc_fixed`.
    - Set the 'cnt' field in the pod header to `0UL` using `fd_ulong_svw_enc_fixed`.
    - Return the pointer to the `pod`.
- **Output**: Returns the pointer to the reset pod, or NULL if the input pod was NULL.


---
### fd\_pod\_query\_subpod<!-- {{#callable:fd_pod_query_subpod}} -->
The `fd_pod_query_subpod` function queries a pod for a subpod at a specified path and returns a pointer to it if found and valid.
- **Inputs**:
    - `pod`: A pointer to the pod data structure to be queried.
    - `path`: A string representing the path to the desired subpod within the pod, using '.' as a delimiter for nested keys.
- **Control Flow**:
    - Initialize a `fd_pod_info_t` structure to store query results.
    - Call [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query) with the provided `pod` and `path` to fill the `info` structure with details about the queried path.
    - Check if the query was unsuccessful or if the value type at the path is not a subpod; if either condition is true, return `NULL`.
    - If the query is successful and the value type is a subpod, return a pointer to the subpod's data.
- **Output**: A pointer to the subpod data if the query is successful and the value type is a subpod, otherwise `NULL`.
- **Functions called**:
    - [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query)


---
### fd\_pod\_query\_buf<!-- {{#callable:fd_pod_query_buf}} -->
The `fd_pod_query_buf` function retrieves a buffer from a POD (Plain Old Data) structure at a specified path and optionally returns its size.
- **Inputs**:
    - `pod`: A pointer to the POD structure from which the buffer is to be queried.
    - `path`: A string representing the path to the buffer within the POD structure.
    - `opt_buf_sz`: An optional pointer to a variable where the size of the buffer will be stored if the buffer is successfully retrieved.
- **Control Flow**:
    - Initialize a `fd_pod_info_t` structure to store information about the queried buffer.
    - Call [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query) to retrieve information about the buffer at the specified path in the POD.
    - Check if the query was unsuccessful or if the value type is not a buffer (`FD_POD_VAL_TYPE_BUF`); if so, return `NULL`.
    - If `opt_buf_sz` is not `NULL`, store the size of the buffer in `opt_buf_sz`.
    - Return the pointer to the buffer.
- **Output**: A pointer to the buffer in the POD if successful, or `NULL` if the query fails or the value type is not a buffer.
- **Functions called**:
    - [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query)


---
### fd\_pod\_query\_cstr<!-- {{#callable:fd_pod_query_cstr}} -->
The `fd_pod_query_cstr` function retrieves a C-style string from a pod data structure based on a specified path, returning a default value if the path does not resolve to a valid C-string.
- **Inputs**:
    - `pod`: A pointer to the pod data structure from which the C-string is to be queried.
    - `path`: A C-string representing the hierarchical path to the desired key within the pod.
    - `def`: A default C-string to return if the query fails or the path does not resolve to a valid C-string.
- **Control Flow**:
    - Initialize a `fd_pod_info_t` structure to store information about the queried key-value pair.
    - Call [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query) with the pod, path, and info structure to attempt to resolve the path to a key-value pair.
    - Check if the query was unsuccessful or if the resolved value type is not a C-string (`FD_POD_VAL_TYPE_CSTR`).
    - If either condition is true, return the default value `def`.
    - If the value size (`val_sz`) is non-zero, return the C-string value from the info structure; otherwise, return `NULL`.
- **Output**: Returns a pointer to the C-string if the query is successful and the value is a valid C-string; otherwise, returns the default C-string `def` or `NULL` if the value size is zero.
- **Functions called**:
    - [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query)


---
### fd\_pod\_query\_uint128<!-- {{#callable:fd_pod_query_uint128}} -->
The `fd_pod_query_uint128` function retrieves a 128-bit unsigned integer value from a POD (Plain Old Data) structure based on a specified path, returning a default value if the path is invalid or the value type is incorrect.
- **Inputs**:
    - `pod`: A pointer to the POD structure from which the 128-bit unsigned integer value is to be queried.
    - `path`: A string representing the path to the desired key within the POD structure.
    - `def`: A default 128-bit unsigned integer value to return if the query fails or the value type is not `FD_POD_VAL_TYPE_UINT128`.
- **Control Flow**:
    - Initialize a `fd_pod_info_t` structure to store information about the queried key-value pair.
    - Call [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query) to attempt to retrieve information about the key specified by `path` from the `pod`.
    - Check if the query was unsuccessful or if the value type is not `FD_POD_VAL_TYPE_UINT128`; if either condition is true, return the default value `def`.
    - If the query is successful and the value type is correct, decode the 128-bit unsigned integer value from the POD using `fd_ulong_svw_dec` and store it in a temporary union.
    - Return the decoded 128-bit unsigned integer value.
- **Output**: The function returns a 128-bit unsigned integer value retrieved from the POD, or the default value `def` if the query fails or the value type is incorrect.
- **Functions called**:
    - [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query)


---
### fd\_pod\_query\_int128<!-- {{#callable:fd_pod_query_int128}} -->
The `fd_pod_query_int128` function retrieves a 128-bit integer value from a pod data structure based on a specified path, returning a default value if the path is invalid or the value type is not a 128-bit integer.
- **Inputs**:
    - `pod`: A pointer to the pod data structure from which the 128-bit integer value is to be queried.
    - `path`: A string representing the path to the key within the pod whose value is to be queried.
    - `def`: The default 128-bit integer value to return if the query fails or the value type is not a 128-bit integer.
- **Control Flow**:
    - Initialize a `fd_pod_info_t` structure to store information about the queried key-value pair.
    - Call [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query) to attempt to retrieve information about the key specified by `path` in the `pod`.
    - Check if the query was unsuccessful or if the value type is not `FD_POD_VAL_TYPE_INT128`; if so, return the default value `def`.
    - If the query is successful and the value type is correct, decode the 128-bit integer value from the pod using `fd_ulong_svw_dec` and `fd_int128_zz_dec`.
    - Return the decoded 128-bit integer value.
- **Output**: The function returns the 128-bit integer value associated with the specified path in the pod, or the default value if the query fails or the value type is incorrect.
- **Functions called**:
    - [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query)


# Function Declarations (Public API)

---
### fd\_pod\_list<!-- {{#callable_declaration:fd_pod_list}} -->
Lists key-value pairs in a pod.
- **Description**: Use this function to retrieve details about the key-value pairs stored in a pod. It populates the provided `info` array with information about each key-value pair, such as key size, key, value type, value size, and value. This function does not recurse into subpods, meaning it only lists the top-level key-value pairs. It returns the `info` array on success or `NULL` if the `pod` parameter is `NULL`. Ensure that the `info` array has enough space to hold all key-value pairs in the pod, which can be determined using `fd_pod_cnt(pod)`.
- **Inputs**:
    - `pod`: A pointer to the pod from which key-value pairs are to be listed. Must not be null. If null, the function returns null.
    - `info`: A pointer to an array of `fd_pod_info_t` structures where the function will store information about each key-value pair. The caller must ensure this array is large enough to hold all key-value pairs in the pod.
- **Output**: Returns the `info` array populated with details of each key-value pair in the pod, or `NULL` if the `pod` is `NULL`.
- **See also**: [`fd_pod_list`](fd_pod.c.driver.md#fd_pod_list)  (Implementation)


---
### fd\_pod\_cnt\_subpod<!-- {{#callable_declaration:fd_pod_cnt_subpod}} -->
Counts the number of subpods in a given pod.
- **Description**: Use this function to determine the number of subpods contained within a given pod. It is useful for understanding the structure of a pod without delving into its subpods. This function does not recurse into subpods, meaning it only counts subpods directly within the specified pod. It is efficient for pods with a large number of key-value pairs, as it operates in O(fd_pod_cnt(pod)) time complexity. If the input pod is NULL, the function returns 0.
- **Inputs**:
    - `pod`: A pointer to the pod to be examined. It must be a valid, non-null pointer to a pod structure. If the pointer is NULL, the function will return 0.
- **Output**: Returns the number of subpods directly contained within the specified pod. If the pod is NULL, returns 0.
- **See also**: [`fd_pod_cnt_subpod`](fd_pod.c.driver.md#fd_pod_cnt_subpod)  (Implementation)


---
### fd\_pod\_cnt\_recursive<!-- {{#callable_declaration:fd_pod_cnt_recursive}} -->
Counts all key-value pairs in a pod, including nested subpods.
- **Description**: Use this function to determine the total number of key-value pairs within a pod, including those in any nested subpods. This function is useful when you need a comprehensive count of all entries in a pod hierarchy. It should be called with a valid pod pointer, and it will return zero if the provided pointer is null. This function is read-only and does not modify the pod.
- **Inputs**:
    - `pod`: A pointer to the pod data structure to be counted. Must not be null; if null, the function returns 0.
- **Output**: Returns the total count of key-value pairs in the pod, including those in nested subpods.
- **See also**: [`fd_pod_cnt_recursive`](fd_pod.c.driver.md#fd_pod_cnt_recursive)  (Implementation)


---
### fd\_pod\_list\_recursive<!-- {{#callable_declaration:fd_pod_list_recursive}} -->
Recursively lists all key-value pairs in a pod, including subpods.
- **Description**: This function is used to obtain a comprehensive list of all key-value pairs within a pod, traversing into any subpods recursively. It is useful when a complete overview of the pod's structure and contents is needed, including nested elements. The function should be called with a valid pod pointer, and it will populate the provided `fd_pod_info_t` structure with details about each key-value pair. If the `pod` parameter is null, the function returns the `info` structure without modification.
- **Inputs**:
    - `pod`: A pointer to the pod to be listed. Must not be null for the function to perform any operation. If null, the function returns the `info` structure unchanged.
    - `info`: A pointer to an `fd_pod_info_t` structure where the function will store information about each key-value pair. The caller retains ownership and must ensure it is valid.
- **Output**: Returns the `info` structure populated with details of all key-value pairs, including those in subpods, or unchanged if `pod` is null.
- **See also**: [`fd_pod_list_recursive`](fd_pod.c.driver.md#fd_pod_list_recursive)  (Implementation)


---
### fd\_pod\_query<!-- {{#callable_declaration:fd_pod_query}} -->
Queries a pod for information about a specified path.
- **Description**: Use this function to retrieve information about a key-value pair in a pod, specified by a path. The path is a string of keys separated by dots, allowing for navigation through nested subpods. The function returns success if the path resolves to a valid key, and optionally fills a provided structure with details about the key. It returns specific error codes if the path is invalid, if a non-subpod type is encountered where a subpod is expected, or if the path does not resolve to a key. Ensure that the pod and path are not null before calling this function.
- **Inputs**:
    - `pod`: A pointer to the pod to be queried. Must not be null. The pod should be a valid, initialized pod structure.
    - `path`: A string representing the path to the key within the pod. Must not be null. The path should be formatted as keys separated by dots (e.g., 'key1.key2').
    - `opt_info`: An optional pointer to a fd_pod_info_t structure where information about the found key will be stored. Can be null if the caller does not need this information.
- **Output**: Returns 0 (FD_POD_SUCCESS) on success, or a negative error code (FD_POD_ERR_*) on failure. If successful and opt_info is non-null, it is populated with details about the found key.
- **See also**: [`fd_pod_query`](fd_pod.c.driver.md#fd_pod_query)  (Implementation)


---
### fd\_pod\_strerror<!-- {{#callable_declaration:fd_pod_strerror}} -->
Convert an error code to a human-readable string.
- **Description**: Use this function to obtain a descriptive string for a given error code returned by the fd_pod APIs. This is useful for logging or displaying error messages to users. The function accepts an error code and returns a constant string that describes the error. It handles known error codes defined in the API and returns "unknown" for any unrecognized codes.
- **Inputs**:
    - `err`: An integer representing the error code. Valid values are FD_POD_SUCCESS, FD_POD_ERR_INVAL, FD_POD_ERR_TYPE, FD_POD_ERR_RESOLVE, and FD_POD_ERR_FULL. Any other value will result in the return of "unknown".
- **Output**: A constant string describing the error associated with the provided error code.
- **See also**: [`fd_pod_strerror`](fd_pod.c.driver.md#fd_pod_strerror)  (Implementation)


---
### fd\_pod\_resize<!-- {{#callable_declaration:fd_pod_resize}} -->
Resizes a pod to fit within a specified maximum size.
- **Description**: This function adjusts the maximum size of a pod to the largest possible value that does not exceed the specified `new_max`. It is used when you want to change the size constraints of a pod, typically to make more space available for additional key-value pairs. The function must be called with a valid pod pointer, and the current used size of the pod must not exceed `new_max`. If the pod is null or the current used size is greater than `new_max`, the function will return 0, indicating failure. This operation may invalidate any pointers or references to the pod's contents.
- **Inputs**:
    - `pod`: A pointer to the pod to be resized. Must not be null. The pod must be a valid, initialized pod structure.
    - `new_max`: The desired maximum size for the pod in bytes. Must be greater than or equal to the current used size of the pod.
- **Output**: Returns the new maximum size of the pod on success, or 0 on failure.
- **See also**: [`fd_pod_resize`](fd_pod.c.driver.md#fd_pod_resize)  (Implementation)


---
### fd\_pod\_compact<!-- {{#callable_declaration:fd_pod_compact}} -->
Eliminates internal padding in a pod and optionally reduces its maximum size.
- **Description**: Use this function to compact a pod by removing any internal padding, which can help optimize storage and potentially improve performance when accessing the pod. If the `full` parameter is non-zero, the function will also reduce the pod's maximum size to match its used size, effectively sealing the pod. This function should be called when you want to minimize the memory footprint of a pod, especially before saving it to storage or transmitting it over a network. The function assumes the pod is a current local join and will return the compacted size of the pod. It returns 0 if the pod is NULL. Note that this is an invalidating operation, meaning it may alter the internal structure of the pod.
- **Inputs**:
    - `pod`: A pointer to the pod to be compacted. Must not be NULL, as a NULL value will result in a return value of 0.
    - `full`: An integer flag indicating whether to perform a full compaction. If non-zero, the pod's maximum size will be reduced to its used size.
- **Output**: Returns the compacted size of the pod on success, or 0 if the pod is NULL.
- **See also**: [`fd_pod_compact`](fd_pod.c.driver.md#fd_pod_compact)  (Implementation)


---
### fd\_cstr\_to\_pod\_val\_type<!-- {{#callable_declaration:fd_cstr_to_pod_val_type}} -->
Converts a string to a POD value type identifier.
- **Description**: This function is used to convert a given string into a corresponding POD value type identifier, which is an integer representing a specific type of value stored in a POD key-value pair. It should be used when you need to determine the type of a value based on its string representation. The function expects a non-null string as input and performs a case-insensitive comparison to match the string with predefined value types. If the string matches a known type, the corresponding type identifier is returned. If the string is null or does not match any known type, an error code indicating invalid input is returned.
- **Inputs**:
    - `cstr`: A pointer to a constant character string representing the value type. Must not be null. The function returns an error code if the string is null or does not match any known value type.
- **Output**: Returns an integer representing the POD value type identifier if successful, or a negative error code if the input is invalid or unrecognized.
- **See also**: [`fd_cstr_to_pod_val_type`](fd_pod.c.driver.md#fd_cstr_to_pod_val_type)  (Implementation)


---
### fd\_pod\_val\_type\_to\_cstr<!-- {{#callable_declaration:fd_pod_val_type_to_cstr}} -->
Converts a value type identifier to its corresponding string representation.
- **Description**: This function is used to convert a value type identifier, specified by `val_type`, into a human-readable string representation, which is stored in the buffer pointed to by `cstr`. It is useful for debugging or logging purposes where a textual representation of the value type is needed. The function requires that `cstr` is a valid pointer with enough space to hold the resulting string, including the null terminator. If `cstr` is NULL, the function returns NULL immediately. The function handles both predefined and user-defined value types, returning a formatted string for user-defined types if the identifier is within the valid range.
- **Inputs**:
    - `val_type`: An integer representing the value type identifier, which should be in the range [0, 255]. Identifiers outside this range will result in a NULL return.
    - `cstr`: A pointer to a character buffer where the resulting string will be stored. This buffer must have enough space to accommodate the string, including the null terminator. The pointer must not be NULL.
- **Output**: Returns the pointer `cstr` on success, containing the string representation of the value type. Returns NULL if `cstr` is NULL or if `val_type` is outside the valid range.
- **See also**: [`fd_pod_val_type_to_cstr`](fd_pod.c.driver.md#fd_pod_val_type_to_cstr)  (Implementation)


