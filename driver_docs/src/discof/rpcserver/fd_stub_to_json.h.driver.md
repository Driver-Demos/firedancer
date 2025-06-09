# Purpose
This C header file defines the interface for managing and interacting with `fd_rpc_json_t` objects, which are likely used for handling JSON data in the context of an RPC (Remote Procedure Call) server. The file includes function prototypes for creating, initializing, and deleting these JSON objects, as well as functions to determine memory alignment and footprint requirements. It also provides a function, [`fd_rpc_json_walk`](#fd_rpc_json_walk), which appears to be used for traversing or processing JSON data structures, possibly in conjunction with a web server, as indicated by the inclusion of `fd_webserver.h`. The use of macros like `FD_FN_PURE` suggests an emphasis on function purity, likely for optimization or correctness guarantees. Overall, this header file is part of a larger system that integrates JSON handling with web server functionalities in an RPC server environment.
# Imports and Dependencies

---
- `fd_webserver.h`
- `../../flamenco/types/fd_types_meta.h`


# Global Variables

---
### fd\_rpc\_json\_new
- **Type**: `fd_rpc_json_t *`
- **Description**: The `fd_rpc_json_new` function is a factory function that creates a new instance of the `fd_rpc_json_t` structure. It takes a pointer to a memory location as an argument, which is used to allocate the necessary resources for the new JSON RPC object.
- **Use**: This function is used to instantiate a new JSON RPC object, which can then be used for further JSON RPC operations.


---
### fd\_rpc\_json\_delete
- **Type**: `function pointer`
- **Description**: The `fd_rpc_json_delete` is a function that takes a pointer to an `fd_rpc_json_t` structure and returns a void pointer. It is likely used to deallocate or clean up resources associated with the `fd_rpc_json_t` object.
- **Use**: This function is used to delete or free resources associated with an `fd_rpc_json_t` object.


---
### fd\_rpc\_json\_init
- **Type**: `function pointer`
- **Description**: The `fd_rpc_json_init` is a function that initializes an `fd_rpc_json_t` object, which is a structure used for handling JSON-RPC (Remote Procedure Call) operations in conjunction with a web server. It takes two parameters: a pointer to an `fd_rpc_json_t` object and a pointer to an `fd_webserver_t` object, which likely represents the web server context or configuration.
- **Use**: This function is used to set up and prepare an `fd_rpc_json_t` object for JSON-RPC operations, linking it with a web server instance.


# Data Structures

---
### fd\_rpc\_json\_t
- **Type**: `typedef struct fd_rpc_json fd_rpc_json_t;`
- **Members**:
    - `fd_rpc_json_t`: A typedef for the struct fd_rpc_json, representing a JSON RPC object.
- **Description**: The `fd_rpc_json_t` is a typedef for a structure that represents a JSON RPC object within the system. It is used in conjunction with functions that manage its lifecycle, such as creation, initialization, and deletion. The structure is designed to work with a web server context, as indicated by its initialization function which takes a `fd_webserver_t` pointer. The `fd_rpc_json_t` is part of a larger framework for handling JSON RPC requests, providing a mechanism to walk through JSON data structures and interact with them in a structured manner.


# Function Declarations (Public API)

---
### fd\_rpc\_json\_align<!-- {{#callable_declaration:fd_rpc_json_align}} -->
Return the alignment requirement of the fd_rpc_json_t type.
- **Description**: Use this function to determine the memory alignment requirement for the fd_rpc_json_t type. This is useful when allocating memory manually for fd_rpc_json_t objects to ensure proper alignment, which is necessary for correct and efficient access to the data structure. The function does not require any parameters and can be called at any time.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer, representing the number of bytes.
- **See also**: [`fd_rpc_json_align`](fd_stub_to_json.c.driver.md#fd_rpc_json_align)  (Implementation)


---
### fd\_rpc\_json\_footprint<!-- {{#callable_declaration:fd_rpc_json_footprint}} -->
Return the memory footprint of an fd_rpc_json_t object.
- **Description**: Use this function to determine the amount of memory required to store an fd_rpc_json_t object. This is useful for memory allocation purposes when creating new instances of fd_rpc_json_t. The function does not require any parameters and can be called at any time to retrieve the size information.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the size in bytes of an fd_rpc_json_t object.
- **See also**: [`fd_rpc_json_footprint`](fd_stub_to_json.c.driver.md#fd_rpc_json_footprint)  (Implementation)


---
### fd\_rpc\_json\_new<!-- {{#callable_declaration:fd_rpc_json_new}} -->
Creates a new fd_rpc_json_t object in the provided memory.
- **Description**: Use this function to initialize a new fd_rpc_json_t object in a pre-allocated memory region. This function is essential for setting up a JSON object that can be used with the RPC server. It must be called with a valid memory pointer that has enough space to accommodate the fd_rpc_json_t structure. If the provided memory pointer is NULL, the function will log a warning and return NULL, indicating that the initialization failed. This function does not allocate memory; it only initializes the given memory region.
- **Inputs**:
    - `mem`: A pointer to a pre-allocated memory region where the fd_rpc_json_t object will be initialized. Must not be NULL. The caller retains ownership of the memory and is responsible for ensuring it is large enough to hold a fd_rpc_json_t structure. If NULL is passed, the function logs a warning and returns NULL.
- **Output**: Returns a pointer to the initialized fd_rpc_json_t object if successful, or NULL if the input memory pointer is NULL.
- **See also**: [`fd_rpc_json_new`](fd_stub_to_json.c.driver.md#fd_rpc_json_new)  (Implementation)


---
### fd\_rpc\_json\_delete<!-- {{#callable_declaration:fd_rpc_json_delete}} -->
Deletes a JSON RPC object.
- **Description**: Use this function to delete a JSON RPC object when it is no longer needed. This function should be called to properly dispose of a `fd_rpc_json_t` object, ensuring any associated resources are released. It is important to ensure that the `json` parameter is a valid pointer to a `fd_rpc_json_t` object that was previously created, and it should not be used after this function is called.
- **Inputs**:
    - `json`: A pointer to a `fd_rpc_json_t` object to be deleted. Must be a valid, non-null pointer to an object previously created by `fd_rpc_json_new`. The function returns this pointer, but the object should not be used after deletion.
- **Output**: Returns the pointer to the `fd_rpc_json_t` object that was deleted.
- **See also**: [`fd_rpc_json_delete`](fd_stub_to_json.c.driver.md#fd_rpc_json_delete)  (Implementation)


---
### fd\_rpc\_json\_init<!-- {{#callable_declaration:fd_rpc_json_init}} -->
Initialize a fd_rpc_json_t object with a webserver reference.
- **Description**: Use this function to initialize a fd_rpc_json_t object, associating it with a given webserver. This function must be called before using the fd_rpc_json_t object for any operations. The function requires a valid fd_rpc_json_t pointer and a webserver reference. If the provided fd_rpc_json_t pointer is NULL, the function will log a warning and return NULL, indicating initialization failure.
- **Inputs**:
    - `json`: A pointer to an fd_rpc_json_t object to be initialized. Must not be NULL. The caller retains ownership.
    - `ws`: A pointer to an fd_webserver_t object that the fd_rpc_json_t will be associated with. Can be NULL if no webserver association is needed.
- **Output**: Returns the initialized fd_rpc_json_t pointer on success, or NULL if the input json pointer is NULL.
- **See also**: [`fd_rpc_json_init`](fd_stub_to_json.c.driver.md#fd_rpc_json_init)  (Implementation)


---
### fd\_rpc\_json\_walk<!-- {{#callable_declaration:fd_rpc_json_walk}} -->
Processes a JSON node and formats it for web server response.
- **Description**: This function is used to process a JSON node within a hierarchical structure and format it for output to a web server. It should be called as part of a JSON traversal operation, where each node is processed in sequence. The function handles different JSON types, including collections and primitive types, and formats them appropriately for web server responses. It requires a valid JSON context and web server object to function correctly. The function assumes that the level parameter does not exceed a predefined maximum stack height, and it logs a warning if this condition is violated. It is important to ensure that the JSON context is properly initialized before calling this function.
- **Inputs**:
    - `self`: A pointer to a fd_rpc_json_t object representing the current JSON context. Must not be null.
    - `arg`: A pointer to the data associated with the current JSON node. The type of data depends on the type parameter. Must not be null for non-nullable types.
    - `name`: A string representing the name of the JSON node. Can be null if the node is unnamed.
    - `type`: An integer representing the type of the JSON node. Must be a valid type as defined by the FD_FLAMENCO_TYPE_* constants.
    - `type_name`: A string representing the name of the type. This parameter is not used in the function and can be ignored.
    - `level`: An unsigned integer representing the current depth in the JSON hierarchy. Must be less than STACK_HEIGHT-1 to avoid warnings.
- **Output**: None
- **See also**: [`fd_rpc_json_walk`](fd_stub_to_json.c.driver.md#fd_rpc_json_walk)  (Implementation)


