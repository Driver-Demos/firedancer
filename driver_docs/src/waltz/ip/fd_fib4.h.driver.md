# Purpose
The provided C header file defines a data structure and associated functions for managing a Forwarding Information Base (FIB) specifically for IPv4 routes, referred to as `fib4`. This file is part of a larger codebase, as indicated by the inclusion of a utility header from a relative path. The `fib4` structure is designed to store IPv4 routing information in a manner optimized for query operations, although it does not scale well with a large number of routes due to its O(n) lookup complexity. The header outlines the basic operations for creating, managing, and querying the `fib4` structure, including functions for constructing and destructing the FIB, adding and clearing routes, and performing route lookups. It supports multi-threaded environments with many reader threads and a single writer thread, typical of x86-TSO-like environments.

The header file defines several constants and types, such as route types (`FD_FIB4_RTYPE_UNICAST`, `FD_FIB4_RTYPE_LOCAL`, etc.) and a structure (`fd_fib4_hop_t`) to hold the results of a FIB lookup. The API is designed to be thread-safe for read operations, allowing multiple threads to perform lookups concurrently. However, write operations require a full rewrite of the FIB, temporarily returning a "blackhole" route during updates to prevent incorrect routing decisions. The file also includes utility functions for printing the routing table and checking the number of routes. This header file is intended to be included in other C source files that require IPv4 routing capabilities, providing a focused and specialized functionality within a larger system.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`


# Global Variables

---
### fd\_fib4\_new
- **Type**: `function pointer`
- **Description**: The `fd_fib4_new` function is a constructor for creating a new fib4 object, which is a data structure optimized for querying IPv4 routes. It takes a memory pointer and a maximum number of routes as parameters, and returns a pointer to the newly created fib4 object.
- **Use**: This function is used to initialize a fib4 object in memory, setting it up to store and manage IPv4 routing information.


---
### fd\_fib4\_join
- **Type**: `fd_fib4_t *`
- **Description**: The `fd_fib4_join` is a function that returns a pointer to an `fd_fib4_t` structure, which represents a local handle to a fib4 object. The fib4 is a data structure optimized for querying IPv4 routes, although it does not scale well with a large number of routes and does not support packet forwarding.
- **Use**: This function is used to join or attach to an existing fib4 object using a memory pointer, allowing further operations on the fib4 data structure.


---
### fd\_fib4\_leave
- **Type**: `function pointer`
- **Description**: The `fd_fib4_leave` function is a global function pointer that is used to leave or detach from a `fd_fib4_t` object, which represents a Forwarding Information Base (FIB) for IPv4 routes. This function is part of the API for managing the lifecycle of a `fd_fib4_t` object, allowing users to properly release resources associated with the FIB when it is no longer needed.
- **Use**: This function is used to detach from a `fd_fib4_t` object, effectively cleaning up resources associated with the FIB.


---
### fd\_fib4\_delete
- **Type**: `void *`
- **Description**: The `fd_fib4_delete` function is a global function that takes a pointer to memory as its parameter and returns a void pointer. It is part of the API for managing a fib4 data structure, which is used to store IPv4 routes in a query-optimized manner. This function is likely responsible for deallocating or cleaning up resources associated with a fib4 instance.
- **Use**: This function is used to delete or clean up a fib4 data structure, freeing any resources it may have allocated.


---
### fd\_fib4\_append
- **Type**: `fd_fib4_hop_t *`
- **Description**: The `fd_fib4_append` function is a global function that attempts to add a new route entry to a fib4 data structure, which is used to store IPv4 routes. It returns a pointer to an `fd_fib4_hop_t` object, which represents a FIB lookup result, to be filled by the caller upon successful addition of the route.
- **Use**: This function is used to append a new route to the fib4 data structure, ensuring that the route table can be updated with new entries.


---
### fd\_fib4\_lookup
- **Type**: `fd_fib4_hop_t const *`
- **Description**: The `fd_fib4_lookup` function is a global function that performs a lookup in an IPv4 Forwarding Information Base (FIB) to resolve the next hop for a given IPv4 destination address. It returns a pointer to a `fd_fib4_hop_t` structure, which contains the result of the lookup, including gateway address, interface index, and route type.
- **Use**: This function is used to determine the next hop for packet forwarding based on the destination IPv4 address, supporting multi-threaded read operations.


# Data Structures

---
### fd\_fib4\_t
- **Type**: `typedef struct fd_fib4 fd_fib4_t;`
- **Members**:
    - `fd_fib4_t`: A local handle to a fib4 object, used for managing IPv4 routes.
- **Description**: The `fd_fib4_t` is a data structure designed to store and manage IPv4 routes in a query-optimized manner. It is not suitable for large numbers of routes as each route lookup is O(n), where n is the number of routes. The structure supports multi-threaded operations with many reader threads and one writer thread, but does not support packet forwarding. It includes a dummy route at index 0 and requires a full rewrite for updates, as incremental updates are not supported. The structure is aligned to 16 bytes and provides various APIs for constructing, joining, and managing the route table.


---
### fd\_fib4\_hop
- **Type**: `struct`
- **Members**:
    - `ip4_gw`: Gateway address in big endian format.
    - `if_idx`: Output interface index.
    - `ip4_src`: Override source address in big endian format; 0 implies unset.
    - `rtype`: Route type, such as FD_FIB4_RTYPE_UNICAST.
    - `scope`: Used to select the source address.
    - `flags`: Application-specific flags.
- **Description**: The `fd_fib4_hop` structure is designed to hold the result of a Forwarding Information Base (FIB) lookup for IPv4 routing. It contains information about the gateway address, the output interface index, an optional source address override, the type of route, the scope for source address selection, and application-specific flags. This structure is aligned to 16 bytes and is used in conjunction with the `fd_fib4` data structure to manage and resolve IPv4 routing paths.


---
### fd\_fib4\_hop\_t
- **Type**: `struct`
- **Members**:
    - `ip4_gw`: Gateway address in big endian format.
    - `if_idx`: Output interface index.
    - `ip4_src`: Override source address in big endian format, with 0 implying unset.
    - `rtype`: Route type, such as FD_FIB4_RTYPE_UNICAST.
    - `scope`: Used to select the source address.
    - `flags`: Application-specific flags.
- **Description**: The `fd_fib4_hop_t` structure is used to store the result of a Forwarding Information Base (FIB) lookup for IPv4 routes. It contains information about the next hop, including the gateway address, output interface index, and an optional source address override. Additionally, it holds metadata about the route type, scope, and any application-specific flags. This structure is aligned to 16 bytes and is integral to the operation of the `fd_fib4` routing table, which is optimized for query operations in a multi-threaded environment.


# Functions

---
### fd\_fib4\_hop\_or<!-- {{#callable:fd_fib4_hop_or}} -->
The `fd_fib4_hop_or` function returns the left hop if its route type is not 'throw', otherwise it returns the right hop.
- **Inputs**:
    - `left`: A pointer to a `fd_fib4_hop_t` structure representing the left hop.
    - `right`: A pointer to a `fd_fib4_hop_t` structure representing the right hop.
- **Control Flow**:
    - Check if the route type (`rtype`) of the `left` hop is not equal to `FD_FIB4_RTYPE_THROW`.
    - If the condition is true, return the `left` hop.
    - If the condition is false, return the `right` hop.
- **Output**: A pointer to a `fd_fib4_hop_t` structure, either `left` or `right`, depending on the route type of `left`.


# Function Declarations (Public API)

---
### fd\_fib4\_align<!-- {{#callable_declaration:fd_fib4_align}} -->
Returns the alignment requirement for a fib4 object.
- **Description**: Use this function to determine the memory alignment requirement for a fib4 object, which is necessary when allocating memory for such objects. This function is useful when setting up memory regions that will store fib4 objects, ensuring that they are correctly aligned for optimal access and performance. It is a constant function and can be called at any time without any preconditions.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the alignment requirement in bytes for a fib4 object.
- **See also**: [`fd_fib4_align`](fd_fib4.c.driver.md#fd_fib4_align)  (Implementation)


---
### fd\_fib4\_footprint<!-- {{#callable_declaration:fd_fib4_footprint}} -->
Calculate the memory footprint required for a fib4 structure with a specified maximum number of routes.
- **Description**: Use this function to determine the amount of memory needed to store a fib4 structure that can accommodate up to a specified number of routes. This is useful for allocating memory before creating a fib4 instance. The function returns 0 if the specified maximum number of routes is 0 or exceeds the maximum allowable value for an unsigned integer, indicating that the input is invalid.
- **Inputs**:
    - `route_max`: Specifies the maximum number of routes the fib4 structure should support. Must be a positive number not exceeding UINT_MAX. If 0 or greater than UINT_MAX, the function returns 0, indicating an invalid input.
- **Output**: Returns the memory footprint in bytes required for the fib4 structure if the input is valid; otherwise, returns 0 for invalid input.
- **See also**: [`fd_fib4_footprint`](fd_fib4.c.driver.md#fd_fib4_footprint)  (Implementation)


---
### fd\_fib4\_new<!-- {{#callable_declaration:fd_fib4_new}} -->
Creates a new IPv4 routing table structure.
- **Description**: This function initializes a new fib4 structure for storing IPv4 routes, optimized for query operations. It should be used when a new routing table is needed, with a specified maximum number of routes. The function requires a memory block that is properly aligned and large enough to accommodate the routing table structure. It is important to ensure that the memory block is not null and is aligned according to the requirements of fd_fib4_align. The maximum number of routes must be a positive number and not exceed UINT_MAX. If any of these conditions are not met, the function will return NULL and log a warning.
- **Inputs**:
    - `mem`: A pointer to a memory block where the fib4 structure will be created. Must not be null and must be aligned according to fd_fib4_align. The caller retains ownership of this memory.
    - `route_max`: The maximum number of routes the fib4 structure can hold. Must be greater than 0 and not exceed UINT_MAX. If invalid, the function returns NULL.
- **Output**: Returns a pointer to the newly created fib4 structure on success, or NULL if the input parameters are invalid.
- **See also**: [`fd_fib4_new`](fd_fib4.c.driver.md#fd_fib4_new)  (Implementation)


---
### fd\_fib4\_join<!-- {{#callable_declaration:fd_fib4_join}} -->
Converts a memory pointer to a fib4 handle.
- **Description**: Use this function to obtain a handle to a fib4 object from a memory pointer. This is typically called after allocating or initializing memory for a fib4 structure. The function is thread-safe and can be used in environments with multiple reader threads and one writer thread. Ensure that the memory provided is correctly aligned and allocated for a fib4 object before calling this function.
- **Inputs**:
    - `mem`: A pointer to memory that is expected to be a valid fib4 object. The memory must be properly aligned and allocated for a fib4 structure. The caller retains ownership of the memory, and passing an invalid or null pointer results in undefined behavior.
- **Output**: Returns a pointer to a fd_fib4_t object, which serves as a handle to the fib4 structure.
- **See also**: [`fd_fib4_join`](fd_fib4.c.driver.md#fd_fib4_join)  (Implementation)


---
### fd\_fib4\_leave<!-- {{#callable_declaration:fd_fib4_leave}} -->
Leaves the fd_fib4_t object.
- **Description**: Use this function to leave or detach from a previously joined fd_fib4_t object. This is typically called when the operations on the fib4 object are complete, and you want to clean up or prepare for deletion. It is important to ensure that no other operations are being performed on the fib4 object when calling this function, especially in a multi-threaded environment.
- **Inputs**:
    - `fib4`: A pointer to an fd_fib4_t object that the caller is currently joined to. Must not be null. The caller should ensure that no other threads are using this object when calling this function.
- **Output**: Returns the same pointer that was passed in, allowing for potential chaining or verification of the leave operation.
- **See also**: [`fd_fib4_leave`](fd_fib4.c.driver.md#fd_fib4_leave)  (Implementation)


---
### fd\_fib4\_delete<!-- {{#callable_declaration:fd_fib4_delete}} -->
Deletes a fib4 object.
- **Description**: Use this function to delete a fib4 object that was previously created with fd_fib4_new. This function should be called when the fib4 object is no longer needed, to free up resources. It is important to ensure that no other operations are being performed on the fib4 object at the time of deletion, as this function does not handle concurrent access. The function is thread-safe in the sense that it can be called by the single writer thread in a multi-threaded environment.
- **Inputs**:
    - `mem`: A pointer to the memory location of the fib4 object to be deleted. This pointer must not be null and should point to a valid fib4 object that was previously created. The caller retains ownership of the memory and is responsible for ensuring it is valid.
- **Output**: Returns the same pointer passed as input, allowing for potential chaining of operations or checks.
- **See also**: [`fd_fib4_delete`](fd_fib4.c.driver.md#fd_fib4_delete)  (Implementation)


---
### fd\_fib4\_clear<!-- {{#callable_declaration:fd_fib4_clear}} -->
Removes all route table entries except the first.
- **Description**: Use this function to reset the routing table to its initial state, retaining only the default dummy route. This is useful when you need to clear all existing routes and start fresh without deleting the fib4 object. The function must be called with a valid fib4 object, and it is thread-safe in environments with one writer thread and multiple reader threads. Ensure that no other write operations are in progress when calling this function to avoid inconsistent states.
- **Inputs**:
    - `fib4`: A pointer to a valid fd_fib4_t object representing the routing table. Must not be null, and the caller retains ownership. The function assumes the object is properly initialized and joined.
- **Output**: None
- **See also**: [`fd_fib4_clear`](fd_fib4.c.driver.md#fd_fib4_clear)  (Implementation)


---
### fd\_fib4\_append<!-- {{#callable_declaration:fd_fib4_append}} -->
Attempts to add a new route entry to the FIB.
- **Description**: This function is used to append a new route entry to a fib4 object, which is a data structure optimized for querying IPv4 routes. It should be called when there is a need to add a new route to the FIB, and it is guaranteed to succeed if there was at least one free slot as indicated by a prior call to fd_fib4_free_cnt. The function is designed for use in a multi-threaded environment with one writer thread. If the route table is full, the function logs a warning and returns NULL.
- **Inputs**:
    - `fib`: A pointer to an fd_fib4_t object representing the FIB. Must not be null and should be properly initialized before calling this function.
    - `ip4_dst`: An unsigned integer representing the destination IPv4 address in big-endian format. This is the address for which the route is being added.
    - `prefix`: An integer representing the prefix length of the route. It determines the subnet mask applied to the destination address.
    - `prio`: An unsigned integer representing the priority of the route. Lower values indicate higher priority.
- **Output**: Returns a pointer to an fd_fib4_hop_t object on success, which the caller should fill with route details. Returns NULL if the route table is full.
- **See also**: [`fd_fib4_append`](fd_fib4.c.driver.md#fd_fib4_append)  (Implementation)


---
### fd\_fib4\_lookup<!-- {{#callable_declaration:fd_fib4_lookup}} -->
Resolves the next hop for a given IPv4 address.
- **Description**: This function is used to determine the next hop for a specified IPv4 destination address using a Forwarding Information Base (FIB) structure. It is thread-safe for concurrent reads, allowing multiple threads to perform lookups simultaneously without interference. However, during a write operation, lookups may temporarily return a blackhole route until the update is complete. The function requires a valid FIB structure and an output buffer to store the result. It returns a pointer to the resolved hop information, or a blackhole route if the destination is not found or if the FIB is being updated.
- **Inputs**:
    - `fib`: A pointer to a constant fd_fib4_t structure representing the FIB. Must not be null. The caller retains ownership.
    - `out`: A pointer to an fd_fib4_hop_t structure where the result will be stored. Must not be null. The caller retains ownership.
    - `ip4_dst`: An unsigned integer representing the IPv4 destination address in big-endian format. There are no specific constraints on the value.
    - `flags`: An unsigned long integer used for additional options. If non-zero, the function immediately returns a dead route.
- **Output**: Returns a pointer to an fd_fib4_hop_t structure containing the next hop information. If the FIB is being updated or the destination is not found, it may return a blackhole route.
- **See also**: [`fd_fib4_lookup`](fd_fib4.c.driver.md#fd_fib4_lookup)  (Implementation)


---
### fd\_fib4\_max<!-- {{#callable_declaration:fd_fib4_max}} -->
Retrieve the maximum number of routes supported by the FIB.
- **Description**: Use this function to determine the maximum capacity of the fd_fib4_t structure in terms of the number of routes it can store. This is useful for understanding the limits of the FIB when planning route additions or assessing the need for a larger data structure. The function is thread-safe and can be called concurrently by multiple threads without affecting each other.
- **Inputs**:
    - `fib`: A pointer to a constant fd_fib4_t structure. This must not be null, as the function will attempt to access the structure's data. The caller retains ownership of the memory.
- **Output**: Returns an unsigned long representing the maximum number of routes that the FIB can store.
- **See also**: [`fd_fib4_max`](fd_fib4.c.driver.md#fd_fib4_max)  (Implementation)


---
### fd\_fib4\_cnt<!-- {{#callable_declaration:fd_fib4_cnt}} -->
Return the number of routes in the FIB.
- **Description**: Use this function to determine how many routes are currently stored in the given FIB (Forwarding Information Base). This can be useful for monitoring or managing the size of the routing table. The function is thread-safe and can be called concurrently by multiple threads without affecting each other. It is important to ensure that the FIB has been properly initialized and joined before calling this function.
- **Inputs**:
    - `fib`: A pointer to a constant fd_fib4_t structure representing the FIB. The pointer must not be null, and the FIB should be properly initialized and joined before use. If the pointer is invalid, the behavior is undefined.
- **Output**: Returns the number of routes currently stored in the FIB as an unsigned long integer.
- **See also**: [`fd_fib4_cnt`](fd_fib4.c.driver.md#fd_fib4_cnt)  (Implementation)


---
### fd\_fib4\_free\_cnt<!-- {{#callable_declaration:fd_fib4_free_cnt}} -->
Return the number of additional routes that can be added to the FIB.
- **Description**: Use this function to determine how many more routes can be added to the FIB without exceeding its capacity. This is useful for ensuring that subsequent calls to add routes will succeed. The function should be called on a valid FIB object, and it assumes that the FIB is in a consistent state where the current route count does not exceed the maximum allowed routes.
- **Inputs**:
    - `fib`: A pointer to a constant fd_fib4_t structure representing the FIB. The pointer must not be null, and the FIB must be in a valid state where the current route count does not exceed the maximum.
- **Output**: Returns the number of additional routes that can be added to the FIB, calculated as the difference between the maximum number of routes and the current number of routes.
- **See also**: [`fd_fib4_free_cnt`](fd_fib4.c.driver.md#fd_fib4_free_cnt)  (Implementation)


---
### fd\_fib4\_fprintf<!-- {{#callable_declaration:fd_fib4_fprintf}} -->
Prints the routing table to a specified file.
- **Description**: Use this function to output the current state of the routing table stored in a `fd_fib4_t` object to a specified file or file-like object. This function is useful for debugging or logging purposes, allowing you to capture the routing table's contents in a human-readable format. The function outputs the routes in an undefined but stable order, ensuring consistency across multiple calls. It is thread-safe in a multi-threaded environment with many reader threads and one writer thread. The function returns 0 on success and an error code on failure, such as when a torn read is detected.
- **Inputs**:
    - `fib`: A pointer to a `fd_fib4_t` object representing the routing table to be printed. Must not be null, and the object should be properly initialized and joined before calling this function.
    - `file_`: A pointer to a `FILE` object or equivalent where the routing table will be printed. Must not be null, and the caller is responsible for ensuring the file is open and writable.
- **Output**: Returns 0 on success. If a torn read is detected during the operation, it returns an error code.
- **See also**: [`fd_fib4_fprintf`](fd_fib4.c.driver.md#fd_fib4_fprintf)  (Implementation)


