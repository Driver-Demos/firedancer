# Purpose
The provided C code is a comprehensive implementation of a data structure known as a "pod" (plain old data), which is used to manage key-value pairs in a hierarchical manner. This code is part of a library that provides various functionalities for manipulating these pods, including querying, listing, counting, resizing, compacting, and removing key-value pairs. The code defines several macros and functions that facilitate the traversal and manipulation of the pod structure, allowing for operations such as splitting paths, iterating over all key-value pairs, and handling nested subpods.

Key components of this code include macros like `FD_POD_PATH_SPLIT` for path manipulation and [`FD_POD_FOR_ALL_BEGIN`](#FD_POD_FOR_ALL_BEGIN)/`FD_POD_FOR_ALL_END` for iterating over pod entries. Functions such as [`fd_pod_list`](#fd_pod_list), [`fd_pod_cnt_subpod`](#fd_pod_cnt_subpod), and [`fd_pod_query`](#fd_pod_query) provide interfaces for interacting with the pod, allowing users to list entries, count subpods, and query specific paths, respectively. The code also includes error handling through functions like [`fd_pod_strerror`](#fd_pod_strerror), which translates error codes into human-readable strings. Additionally, the code supports dynamic resizing and compacting of pods to optimize memory usage. Overall, this file is a part of a broader library intended to be used as a utility for managing hierarchical data structures in C programs.
# Imports and Dependencies

---
- `fd_pod.h`


# Global Variables

---
### fd\_pod\_alloc
- **Type**: `ulong`
- **Description**: The `fd_pod_alloc` function is a global function that attempts to allocate space for a new key-value pair in a pod data structure. It takes a pointer to the pod, a path string, a value type, and a value size as parameters.
- **Use**: This function is used to allocate space for a new key-value pair in a pod, returning the offset of the allocated value within the pod.


---
### fd\_pod\_remove
- **Type**: `int`
- **Description**: The `fd_pod_remove` function is a global function that attempts to remove a key-value pair from a pod data structure based on a specified path. It returns an integer status code indicating success or the type of error encountered.
- **Use**: This function is used to delete a key-value pair from a pod, potentially recursing into subpods if the path specifies nested keys.


# Data Structures

---
### fd\_pod\_subpod\_path\_t
- **Type**: `struct`
- **Members**:
    - `pod`: Points to the subpod value of a subpod key-value pair.
    - `parent`: Points to the subpod that contains the current subpod, or NULL if this subpod is in the root pod.
- **Description**: The `fd_pod_subpod_path_t` structure is used to represent a path to a subpod within a nested hierarchy of subpods. It contains a pointer to the current subpod and a pointer to its parent subpod, allowing traversal and manipulation of nested subpod structures. This structure is particularly useful for operations that require navigating through or modifying deeply nested subpod paths, such as growing the space for key-value pairs in the deepest nested subpod.


---
### fd\_pod\_subpod\_path
- **Type**: `struct`
- **Members**:
    - `pod`: Points to the subpod value of a subpod key-value pair.
    - `parent`: Points to the subpod that contains the current subpod, or NULL if this subpod is in the root pod.
- **Description**: The `fd_pod_subpod_path` structure is used to represent a path within a nested hierarchy of subpods, where each subpod is a key-value pair within a larger pod structure. The `pod` member points to the specific subpod value, while the `parent` member provides a link to the parent subpod, allowing traversal up the hierarchy. This structure is useful for managing and navigating complex nested data structures within a pod.


# Functions

---
### fd\_pod\_list<!-- {{#callable:fd_pod_list}} -->
The `fd_pod_list` function iterates over all key-value pairs in a pod and populates an array of `fd_pod_info_t` structures with information about each pair.
- **Inputs**:
    - `pod`: A pointer to the pod data structure, which is a sequence of encoded key-value pairs.
    - `info`: A pointer to an array of `fd_pod_info_t` structures where information about each key-value pair will be stored.
- **Control Flow**:
    - Check if the `pod` pointer is NULL and return NULL if it is.
    - Initialize an index `idx` to 0 for tracking the position in the `info` array.
    - Use the `FD_POD_FOR_ALL_BEGIN` macro to iterate over each key-value pair in the pod.
    - For each key-value pair, populate the corresponding `fd_pod_info_t` structure in the `info` array with the key size, key, value type, value size, and value.
    - Set the `parent` field of each `fd_pod_info_t` structure to NULL.
    - Increment the index `idx` after processing each key-value pair.
    - End the iteration with the `FD_POD_FOR_ALL_END` macro.
    - Return the `info` pointer after populating it with the pod's key-value pair information.
- **Output**: A pointer to the `info` array, which is populated with information about each key-value pair in the pod.


---
### FD\_POD\_FOR\_ALL\_BEGIN<!-- {{#callable:FD_POD_FOR_ALL_BEGIN}} -->
The `FD_POD_FOR_ALL_BEGIN` macro iterates over all key-value pairs in a pod, providing access to each pair's key, value, and associated metadata.
- **Inputs**:
    - `pod`: A pointer to the pod data structure to iterate over.
    - `pair`: A pointer to the first byte of the current key-value pair.
    - `next`: A pointer to the byte after the last byte of the current key-value pair.
    - `ksz`: The SVW encoded width of the key size field.
    - `key_sz`: The length of the key string plus one for the null terminator.
    - `key`: A pointer to the first byte of the key string.
    - `val_type`: The type of the value associated with the key.
    - `vsz`: The SVW encoded width of the value size field.
    - `val_sz`: The number of bytes in the encoded value.
    - `val`: A pointer to the first byte of the encoded value.
- **Control Flow**:
    - Initialize the pod header variables `_csz`, `_used`, `_cursor`, and `_stop` to manage the iteration.
    - Enter a while loop that continues as long as `_cursor` is less than `_stop`.
    - Within the loop, decode the key size (`ksz`) and key (`key_sz`, `key`) from the current cursor position.
    - Decode the value type (`val_type`) and value size (`vsz`, `val_sz`) from the cursor.
    - Update the cursor to point to the next key-value pair and assign `next` to this position.
    - The loop iterates over each key-value pair, providing access to the key, value, and their metadata.
- **Output**: The macro does not produce a direct output but facilitates iteration over key-value pairs in a pod, allowing operations to be performed on each pair.


---
### fd\_pod\_cnt\_subpod<!-- {{#callable:fd_pod_cnt_subpod}} -->
The function `fd_pod_cnt_subpod` counts the number of subpod entries in a given pod.
- **Inputs**:
    - `pod`: A pointer to a constant unsigned character array representing the pod to be examined.
- **Control Flow**:
    - Check if the input `pod` is NULL and return 0 if it is.
    - Initialize a counter `cnt` to 0.
    - Iterate over all key-value pairs in the pod using the `FD_POD_FOR_ALL_BEGIN` and `FD_POD_FOR_ALL_END` macros.
    - For each key-value pair, check if the value type is `FD_POD_VAL_TYPE_SUBPOD`.
    - If the value type is `FD_POD_VAL_TYPE_SUBPOD`, increment the counter `cnt`.
    - Return the counter `cnt` which represents the number of subpod entries.
- **Output**: The function returns an unsigned long integer representing the count of subpod entries in the given pod.


---
### fd\_pod\_cnt\_recursive<!-- {{#callable:fd_pod_cnt_recursive}} -->
The [`fd_pod_cnt_recursive`](#fd_pod_cnt_recursive) function counts the total number of key-value pairs in a pod, including those in nested subpods, recursively.
- **Inputs**:
    - `pod`: A pointer to the root of the pod structure, which is a sequence of encoded key-value pairs.
- **Control Flow**:
    - Check if the input pod is NULL, and return 0 if it is.
    - Initialize a counter `cnt` to 0 to keep track of the number of key-value pairs.
    - Use the `FD_POD_FOR_ALL_BEGIN` macro to iterate over each key-value pair in the pod.
    - For each key-value pair, increment the counter `cnt`.
    - If the value type of the current key-value pair is a subpod (`FD_POD_VAL_TYPE_SUBPOD`), recursively call [`fd_pod_cnt_recursive`](#fd_pod_cnt_recursive) on the subpod and add the result to `cnt`.
    - End the iteration with the `FD_POD_FOR_ALL_END` macro.
    - Return the total count of key-value pairs, including those in subpods.
- **Output**: The function returns an `ulong` representing the total number of key-value pairs in the pod, including those in any nested subpods.
- **Functions called**:
    - [`fd_pod_cnt_recursive`](#fd_pod_cnt_recursive)


---
### fd\_pod\_list\_recursive\_node<!-- {{#callable:fd_pod_list_recursive_node}} -->
The `fd_pod_list_recursive_node` function recursively traverses a POD structure, populating an array of `fd_pod_info_t` structures with information about each key-value pair, including nested subpods.
- **Inputs**:
    - `parent`: A pointer to the parent `fd_pod_info_t` structure, representing the parent node in the POD hierarchy.
    - `pod`: A pointer to the POD data structure to be traversed, represented as a constant unsigned character array.
    - `info`: A pointer to an array of `fd_pod_info_t` structures where information about each key-value pair will be stored.
- **Control Flow**:
    - Initialize local variables for iteration over the POD structure, including pointers and size variables for keys and values.
    - Begin iterating over all key-value pairs in the provided POD using the `FD_POD_FOR_ALL_BEGIN` macro.
    - For each key-value pair, populate the `info` structure with the key size, key, value type, value size, value, and parent information.
    - Increment the `info` pointer to move to the next `fd_pod_info_t` structure in the array.
    - If the current value type is a subpod, recursively call `fd_pod_list_recursive_node` to process the subpod, passing the current `info` pointer and the subpod data.
    - End the iteration with the `FD_POD_FOR_ALL_END` macro.
    - Return the updated `info` pointer, which now points to the next available position in the `fd_pod_info_t` array.
- **Output**: Returns a pointer to the next available position in the `fd_pod_info_t` array after populating it with information about the traversed POD structure.


---
### fd\_pod\_list\_recursive<!-- {{#callable:fd_pod_list_recursive}} -->
The `fd_pod_list_recursive` function recursively lists all key-value pairs in a pod structure, including those in nested subpods, and stores the information in an array of `fd_pod_info_t` structures.
- **Inputs**:
    - `pod`: A pointer to the start of the pod data structure, which is a serialized collection of key-value pairs.
    - `info`: A pointer to an array of `fd_pod_info_t` structures where the function will store information about each key-value pair found in the pod.
- **Control Flow**:
    - Check if the `pod` pointer is NULL; if so, return the `info` pointer immediately.
    - Call the helper function [`fd_pod_list_recursive_node`](#fd_pod_list_recursive_node) with `NULL` as the parent, the `pod` pointer, and the `info` pointer to recursively process the pod and its subpods.
    - Return the `info` pointer after processing.
- **Output**: Returns a pointer to the `fd_pod_info_t` array (`info`) containing information about all key-value pairs in the pod, including those in nested subpods.
- **Functions called**:
    - [`fd_pod_list_recursive_node`](#fd_pod_list_recursive_node)


---
### fd\_pod\_query<!-- {{#callable:fd_pod_query}} -->
The [`fd_pod_query`](#fd_pod_query) function searches for a key-value pair in a POD (Plain Old Data) structure based on a given path and optionally returns information about the found pair.
- **Inputs**:
    - `pod`: A pointer to the POD structure where the search is to be performed.
    - `path`: A string representing the path to the desired key in the POD structure.
    - `opt_info`: An optional pointer to a `fd_pod_info_t` structure where information about the found key-value pair will be stored if the search is successful.
- **Control Flow**:
    - Check if the `pod` or `path` is NULL and return `FD_POD_ERR_INVAL` if so.
    - Split the `path` into a prefix and suffix using the `FD_POD_PATH_SPLIT` macro.
    - Iterate over all key-value pairs in the `pod` using the `FD_POD_FOR_ALL_BEGIN` and `FD_POD_FOR_ALL_END` macros.
    - For each key-value pair, check if the key matches the prefix of the `path`.
    - If a match is found and there is no suffix (i.e., the path is a single key), populate `opt_info` with the key-value pair details and return `FD_POD_SUCCESS`.
    - If a match is found and there is a suffix, check if the value type is a subpod; if not, return `FD_POD_ERR_TYPE`.
    - If the value type is a subpod, recursively call [`fd_pod_query`](#fd_pod_query) with the subpod and the suffix.
    - If no matching key is found, return `FD_POD_ERR_RESOLVE`.
- **Output**: Returns an integer status code: `FD_POD_SUCCESS` if the key is found, `FD_POD_ERR_INVAL` if inputs are invalid, `FD_POD_ERR_TYPE` if a non-subpod type is encountered when a subpod is expected, or `FD_POD_ERR_RESOLVE` if the key is not found.
- **Functions called**:
    - [`fd_pod_query`](#fd_pod_query)


---
### fd\_pod\_strerror<!-- {{#callable:fd_pod_strerror}} -->
The `fd_pod_strerror` function returns a human-readable string describing the error code passed to it.
- **Inputs**:
    - `err`: An integer representing an error code, which corresponds to specific error conditions in the FD_POD system.
- **Control Flow**:
    - The function uses a switch statement to match the input error code `err` with predefined error codes.
    - For each case, it returns a corresponding string that describes the error condition.
    - If the error code does not match any predefined cases, it defaults to returning "unknown".
- **Output**: A constant character pointer to a string that describes the error code.


---
### fd\_pod\_resize<!-- {{#callable:fd_pod_resize}} -->
The `fd_pod_resize` function adjusts the size of a pod to a new maximum size, ensuring the pod's data fits within the new constraints.
- **Inputs**:
    - `pod`: A pointer to the pod (an array of unsigned characters) that needs resizing.
    - `new_max`: The new maximum size (in bytes) for the pod.
- **Control Flow**:
    - Check if the pod pointer is NULL and return 0 if it is.
    - Decode the current size of the pod header using `fd_ulong_svw_dec_sz`.
    - Decode the used size of the pod and check if it exceeds `new_max`; return 0 if it does.
    - Decode the count of elements in the pod.
    - Calculate the body size of the pod by subtracting the header size from the used size.
    - Enter a loop to determine the new header size (`new_csz`) and new used size (`new_used`) that fit within `new_max`.
    - If the new used size exceeds `new_max`, decrement `new_max` and retry.
    - Move the pod's body data to accommodate the new header size using `memmove`.
    - Encode the new maximum size, used size, and count into the pod's header using `fd_ulong_svw_enc_fixed`.
- **Output**: Returns the new maximum size of the pod after resizing.


---
### fd\_pod\_compact<!-- {{#callable:fd_pod_compact}} -->
The [`fd_pod_compact`](#fd_pod_compact) function compacts a pod data structure by minimizing the space used by its key-value pairs and optionally its header and trailing padding.
- **Inputs**:
    - `pod`: A pointer to the pod data structure to be compacted.
    - `full`: An integer flag indicating whether to fully compact the pod, including its header and trailing padding.
- **Control Flow**:
    - Check if the `pod` pointer is NULL and return 0 if it is.
    - Decode the size of the pod's header and retrieve the maximum size, used size, and body pointer.
    - Iterate over all key-value pairs in the pod using the `FD_POD_FOR_ALL_BEGIN` and `FD_POD_FOR_ALL_END` macros.
    - For each key-value pair, calculate the new sizes for the key and value, compact the pair, and update the iterator internals.
    - Calculate the new body size after compaction.
    - If `full` is false, calculate the new header size and used size without changing the maximum size.
    - If `full` is true, iteratively calculate the new header size, maximum size, and used size until they stabilize.
    - Move the compacted body to its new position and update the pod's header with the new sizes.
    - Return the new maximum size of the pod.
- **Output**: The function returns the new maximum size of the compacted pod as an unsigned long integer.
- **Functions called**:
    - [`fd_pod_compact`](#fd_pod_compact)
    - [`fd_pod_max`](fd_pod.h.driver.md#fd_pod_max)


---
### fd\_cstr\_to\_pod\_val\_type<!-- {{#callable:fd_cstr_to_pod_val_type}} -->
The `fd_cstr_to_pod_val_type` function converts a string representation of a POD value type to its corresponding integer constant.
- **Inputs**:
    - `cstr`: A constant character pointer representing the string to be converted to a POD value type.
- **Control Flow**:
    - Check if the input string `cstr` is NULL; if so, return `FD_POD_ERR_INVAL`.
    - Compare `cstr` case-insensitively with predefined strings like "subpod", "buf", "cstr", etc., and return the corresponding POD value type constant if a match is found.
    - If `cstr` starts with "user", attempt to convert the following characters to an integer using `fd_cstr_to_int` and return it if it is within the range 0 to 255.
    - If no match is found, return `FD_POD_ERR_INVAL`.
- **Output**: Returns an integer representing the POD value type corresponding to the input string, or `FD_POD_ERR_INVAL` if the input is invalid or unrecognized.


---
### fd\_pod\_val\_type\_to\_cstr<!-- {{#callable:fd_pod_val_type_to_cstr}} -->
The function `fd_pod_val_type_to_cstr` converts a given POD value type integer to its corresponding string representation and stores it in a provided character buffer.
- **Inputs**:
    - `val_type`: An integer representing the POD value type to be converted to a string.
    - `cstr`: A pointer to a character buffer where the resulting string representation of the POD value type will be stored.
- **Control Flow**:
    - Check if the `cstr` pointer is NULL and return NULL if it is.
    - Use a switch statement to match the `val_type` with predefined POD value types and copy the corresponding string to `cstr` using `strcpy`.
    - If `val_type` does not match any predefined types, check if it is within the range 0 to 255.
    - If `val_type` is within the range, format it as a user-defined type string using `fd_cstr_printf` and store it in `cstr`.
    - Return the `cstr` pointer.
- **Output**: A pointer to the `cstr` buffer containing the string representation of the POD value type, or NULL if the input is invalid.


---
### fd\_pod\_subpod\_grow<!-- {{#callable:fd_pod_subpod_grow}} -->
The `fd_pod_subpod_grow` function increases the space allocated for key-value pairs in a subpod, potentially affecting the parent pods if additional space is required.
- **Inputs**:
    - `node`: A pointer to a `fd_pod_subpod_path_t` structure representing the current subpod node in the path.
    - `needed`: An unsigned long integer specifying the additional space required for key-value pairs in the subpod.
- **Control Flow**:
    - Check if no additional space is needed; if so, return success immediately.
    - Retrieve the parent of the current node; if there is no parent, return an error indicating the root pod cannot be grown.
    - Calculate the current size and capacity of the pod and determine the new required size.
    - If the new size can fit within the current pod's allocated space, repack the pod to accommodate the new size and return success.
    - If the new size requires more space than currently allocated, calculate the new size for the parent pod and check if it can accommodate the growth.
    - If the parent pod cannot accommodate the growth, recursively grow the parent pod and adjust the current pod's position accordingly.
    - Repack the parent pod and the current pod to reflect the new sizes and update the pod structure.
    - Return success after successfully growing and repacking the pods.
- **Output**: Returns an integer status code: `FD_POD_SUCCESS` on success or an error code such as `FD_POD_ERR_FULL` if the operation fails.


---
### fd\_pod\_private\_alloc\_node<!-- {{#callable:fd_pod_private_alloc_node}} -->
The `fd_pod_private_alloc_node` function allocates a new key-value pair or subpod in a hierarchical pod structure, handling nested paths and expanding pods as necessary.
- **Inputs**:
    - `parent`: A pointer to the parent subpod path structure, which helps track the hierarchy of pods.
    - `pod`: A pointer to the current pod where the allocation is to be made.
    - `path`: A string representing the hierarchical path where the new value or subpod should be allocated.
    - `new_val_type`: An integer representing the type of the new value to be allocated.
    - `new_val_sz`: The size in bytes of the new value to be allocated.
- **Control Flow**:
    - Initialize a new subpod path node with the current pod and its parent.
    - Split the path into a prefix and suffix using `FD_POD_PATH_SPLIT`.
    - Iterate over all key-value pairs in the current pod using `FD_POD_FOR_ALL_BEGIN` and `FD_POD_FOR_ALL_END`.
    - If a key matching the prefix is found, check if the path is a single key or has a suffix.
    - If the path is a single key and already exists, return NULL indicating failure.
    - If the path has a suffix, check if the value type is a subpod and recurse into it if true.
    - If no matching key is found, calculate the available space in the pod.
    - If the path has a suffix, calculate the space needed for a new subpod and expand the pod if necessary.
    - Insert the new subpod and update the pod header, then recurse into the new subpod.
    - If the path is a single key, calculate the space needed for the new value and expand the pod if necessary.
    - Allocate the new value, update the pod header, and return a pointer to the new value.
- **Output**: A pointer to the newly allocated value or subpod, or NULL if the allocation fails.
- **Functions called**:
    - [`fd_pod_footprint`](fd_pod.h.driver.md#fd_pod_footprint)
    - [`fd_pod_subpod_grow`](#fd_pod_subpod_grow)
    - [`fd_pod_join`](fd_pod.h.driver.md#fd_pod_join)
    - [`fd_pod_new`](fd_pod.h.driver.md#fd_pod_new)


