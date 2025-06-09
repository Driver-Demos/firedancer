# Purpose
This C source code file implements a data structure and associated functions for managing a Forwarding Information Base (FIB) for IPv4 routing, specifically a trie-based structure for storing and querying routing information. The primary functionality provided by this code is the creation, manipulation, and querying of a routing table that can store a maximum number of routes specified by the user. The code includes functions to initialize a new FIB ([`fd_fib4_new`](#fd_fib4_new)), join and leave a FIB ([`fd_fib4_join`](#fd_fib4_join), [`fd_fib4_leave`](#fd_fib4_leave)), clear the FIB ([`fd_fib4_clear`](#fd_fib4_clear)), and append new routes ([`fd_fib4_append`](#fd_fib4_append)). It also provides a lookup function ([`fd_fib4_lookup`](#fd_fib4_lookup)) to find the best matching route for a given destination IP address.

The file includes both public and private headers, indicating that it is part of a larger library or application. The code is designed to be efficient and robust, with checks for memory alignment and route table capacity. It also includes functionality for printing the routing table to a file, which is conditionally compiled if the `FD_HAS_HOSTED` macro is defined, suggesting that this feature is intended for environments where file I/O is available. The code uses several macros and utility functions for memory management and logging, indicating a focus on performance and error handling. Overall, this file provides a focused and specialized implementation for IPv4 routing table management within a larger system.
# Imports and Dependencies

---
- `fd_fib4.h`
- `fd_fib4_private.h`
- `../../util/fd_util.h`
- `errno.h`
- `stdio.h`
- `../../util/net/fd_ip4.h`


# Global Variables

---
### fd\_fib4\_hop\_blackhole
- **Type**: `fd_fib4_hop_t`
- **Description**: The `fd_fib4_hop_blackhole` is a constant instance of the `fd_fib4_hop_t` structure, initialized with a route type (`rtype`) set to `FD_FIB4_RTYPE_BLACKHOLE`. This indicates that any traffic matching this route should be discarded, effectively acting as a 'blackhole' for network packets.
- **Use**: This variable is used as a default or fallback route in the routing table to discard packets when no other route is applicable or when a torn read is detected.


# Functions

---
### fd\_fib4\_align<!-- {{#callable:fd_fib4_align}} -->
The `fd_fib4_align` function returns the alignment requirement of the `fd_fib4_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function simply returns the result of the `alignof` operator applied to `fd_fib4_t`.
- **Output**: The function outputs an `ulong` representing the alignment requirement of the `fd_fib4_t` type.


---
### fd\_fib4\_footprint<!-- {{#callable:fd_fib4_footprint}} -->
The `fd_fib4_footprint` function calculates the memory footprint required for a FIB4 routing table based on the maximum number of routes it can hold.
- **Inputs**:
    - `route_max`: The maximum number of routes that the FIB4 routing table is expected to hold.
- **Control Flow**:
    - Check if `route_max` is 0 or greater than `UINT_MAX`; if so, return 0UL as the footprint.
    - Use `FD_LAYOUT_INIT` to start the layout calculation for the FIB4 structure.
    - Append the size and alignment of `fd_fib4_t` to the layout.
    - Append the size and alignment of `fd_fib4_key_t` multiplied by `route_max` to the layout.
    - Append the size and alignment of `fd_fib4_hop_t` multiplied by `route_max` to the layout.
    - Finalize the layout calculation with `FD_LAYOUT_FINI` and return the result.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the FIB4 routing table, or 0UL if the input is invalid.


---
### fd\_fib4\_new<!-- {{#callable:fd_fib4_new}} -->
The `fd_fib4_new` function initializes a new IPv4 forwarding information base (FIB) structure in a given memory region with a specified maximum number of routes.
- **Inputs**:
    - `mem`: A pointer to the memory region where the FIB structure will be initialized.
    - `route_max`: The maximum number of routes that the FIB can hold, which must be greater than 0 and less than or equal to UINT_MAX.
- **Control Flow**:
    - Check if the `mem` pointer is NULL and log a warning if it is, returning NULL.
    - Check if the `mem` pointer is properly aligned according to `fd_fib4_align()` and log a warning if it is not, returning NULL.
    - Check if `route_max` is 0 or greater than UINT_MAX and log a warning if it is, returning NULL.
    - Initialize a scratch allocator with the memory region `mem`.
    - Allocate memory for the FIB structure, keys, and values using the scratch allocator.
    - Finalize the scratch allocator setup.
    - Zero out the allocated memory for the FIB structure, keys, and values.
    - Set the maximum number of routes in the FIB structure and calculate the offset for the hop table.
    - Initialize the first key's priority to UINT_MAX and the first value's route type to `FD_FIB4_RTYPE_THROW`.
    - Clear the FIB structure using `fd_fib4_clear()`.
    - Return a pointer to the initialized FIB structure.
- **Output**: A pointer to the initialized `fd_fib4_t` structure, or NULL if initialization fails due to invalid inputs or memory alignment issues.
- **Functions called**:
    - [`fd_fib4_align`](#fd_fib4_align)
    - [`fd_fib4_clear`](#fd_fib4_clear)


---
### fd\_fib4\_join<!-- {{#callable:fd_fib4_join}} -->
The `fd_fib4_join` function casts a given memory pointer to a `fd_fib4_t` pointer and returns it.
- **Inputs**:
    - `mem`: A pointer to memory that is expected to be of type `fd_fib4_t`.
- **Control Flow**:
    - The function takes a single input parameter, `mem`.
    - It casts the `mem` pointer to a `fd_fib4_t` pointer.
    - The function returns the casted pointer.
- **Output**: A pointer of type `fd_fib4_t` that points to the same memory location as the input `mem`.


---
### fd\_fib4\_leave<!-- {{#callable:fd_fib4_leave}} -->
The `fd_fib4_leave` function returns the pointer to the `fd_fib4_t` structure passed to it.
- **Inputs**:
    - `fib4`: A pointer to an `fd_fib4_t` structure, representing a Forwarding Information Base (FIB) for IPv4 routing.
- **Control Flow**:
    - The function takes a single argument, `fib4`, which is a pointer to an `fd_fib4_t` structure.
    - It simply returns the same pointer `fib4` that was passed to it.
- **Output**: The function returns the same pointer to the `fd_fib4_t` structure that was passed as an argument.


---
### fd\_fib4\_delete<!-- {{#callable:fd_fib4_delete}} -->
The `fd_fib4_delete` function returns the memory pointer passed to it without any modification.
- **Inputs**:
    - `mem`: A pointer to a memory block that is intended to be deleted or freed.
- **Control Flow**:
    - The function takes a single input parameter, `mem`.
    - It immediately returns the `mem` pointer without performing any operations on it.
- **Output**: The function returns the same memory pointer (`void *`) that was passed as input.


---
### fd\_fib4\_clear<!-- {{#callable:fd_fib4_clear}} -->
The `fd_fib4_clear` function resets the count of routes in a `fd_fib4_t` structure to 1.
- **Inputs**:
    - `fib4`: A pointer to a `fd_fib4_t` structure, which represents a Forwarding Information Base (FIB) for IPv4 routing.
- **Control Flow**:
    - The function directly sets the `cnt` field of the `fd_fib4_t` structure pointed to by `fib4` to 1UL, effectively resetting the route count.
- **Output**: This function does not return any value; it modifies the `cnt` field of the `fd_fib4_t` structure in place.


---
### fd\_fib4\_max<!-- {{#callable:fd_fib4_max}} -->
The `fd_fib4_max` function retrieves the maximum number of routes that can be stored in a given `fd_fib4_t` structure.
- **Inputs**:
    - `fib`: A pointer to a constant `fd_fib4_t` structure from which the maximum route count is to be retrieved.
- **Control Flow**:
    - The function accesses the `max` field of the `fd_fib4_t` structure pointed to by `fib`.
- **Output**: The function returns an `ulong` representing the maximum number of routes that the `fd_fib4_t` structure can hold.


---
### fd\_fib4\_cnt<!-- {{#callable:fd_fib4_cnt}} -->
The `fd_fib4_cnt` function returns the current count of routes in a given FIB (Forwarding Information Base) structure.
- **Inputs**:
    - `fib`: A pointer to a constant `fd_fib4_t` structure representing the FIB from which the route count is to be retrieved.
- **Control Flow**:
    - The function accesses the `cnt` member of the `fd_fib4_t` structure pointed to by `fib`.
- **Output**: The function returns an `ulong` representing the number of routes currently stored in the FIB.


---
### fd\_fib4\_free\_cnt<!-- {{#callable:fd_fib4_free_cnt}} -->
The `fd_fib4_free_cnt` function calculates the number of available slots in a FIB4 (Forwarding Information Base for IPv4) routing table by subtracting the current count of routes from the maximum allowed routes.
- **Inputs**:
    - `fib`: A pointer to a constant `fd_fib4_t` structure representing the FIB4 routing table.
- **Control Flow**:
    - Check if the current route count (`fib->cnt`) exceeds the maximum allowed routes (`fib->max`); if so, log an error and terminate the program.
    - Return the difference between the maximum allowed routes (`fib->max`) and the current route count (`fib->cnt`).
- **Output**: The function returns an unsigned long integer representing the number of free slots available in the FIB4 routing table.


---
### fd\_fib4\_append<!-- {{#callable:fd_fib4_append}} -->
The `fd_fib4_append` function adds a new route to a FIB (Forwarding Information Base) table if there is space available.
- **Inputs**:
    - `fib`: A pointer to the FIB table (`fd_fib4_t`) where the new route will be added.
    - `ip4_dst`: The destination IPv4 address for the route, specified as an unsigned integer.
    - `prefix`: The prefix length of the route, indicating the subnet mask.
    - `prio`: The priority of the route, used to determine route preference.
- **Control Flow**:
    - Check if the FIB table is full by comparing `fib->cnt` with `fib->max`; if full, log a warning and return `NULL`.
    - Increment the `generation` field of the FIB table to indicate a change.
    - Calculate the index for the new route as the current count of routes (`fib->cnt`) and increment the count.
    - Create a new key for the route with the destination address, subnet mask, and priority, and store it in the key table at the calculated index.
    - Retrieve the corresponding entry in the hop table for the new route.
    - Increment the `generation` field again to finalize the change.
    - Return a pointer to the new hop entry.
- **Output**: A pointer to the newly added `fd_fib4_hop_t` entry in the FIB table, or `NULL` if the table is full.


---
### fd\_fib4\_lookup<!-- {{#callable:fd_fib4_lookup}} -->
The `fd_fib4_lookup` function performs a lookup in an IPv4 forwarding information base (FIB) to find the best matching route for a given destination IP address.
- **Inputs**:
    - `fib`: A pointer to a constant `fd_fib4_t` structure representing the forwarding information base.
    - `out`: A pointer to an `fd_fib4_hop_t` structure where the result of the lookup will be stored.
    - `ip4_dst`: An unsigned integer representing the destination IPv4 address to look up.
    - `flags`: An unsigned long integer used to control the behavior of the lookup; if non-zero, a dead route is immediately returned.
- **Control Flow**:
    - Check if `flags` is non-zero; if so, return a dead route immediately.
    - Byte-swap the `ip4_dst` to match the internal representation.
    - Retrieve the constant key table from the FIB structure.
    - Store the current generation of the FIB and perform a memory fence to ensure memory consistency.
    - Initialize `best_idx` to 0 and `best_mask` to 32, representing the least specific match.
    - Iterate over each entry in the FIB key table to find the best matching route based on the destination address and mask specificity.
    - For each entry, check if the destination address matches the entry's address and mask.
    - Determine if the current entry is more specific or less costly than the best match found so far.
    - If a better match is found, update `best_idx` and `best_mask`.
    - Store the best matching hop in the `out` parameter.
    - Perform another memory fence and check if the FIB generation has changed; if so, return a blackhole route to indicate a torn read.
    - Return the `out` parameter containing the best matching hop.
- **Output**: A pointer to a constant `fd_fib4_hop_t` structure representing the best matching route, or a blackhole route if a torn read is detected.
- **Functions called**:
    - [`fd_fib4_hop_tbl_const`](fd_fib4_private.h.driver.md#fd_fib4_hop_tbl_const)
    - [`fd_fib4_key_tbl_const`](fd_fib4_private.h.driver.md#fd_fib4_key_tbl_const)


---
### fd\_fib4\_fprintf\_route<!-- {{#callable:fd_fib4_fprintf_route}} -->
The `fd_fib4_fprintf_route` function formats and prints a routing entry to a specified file stream based on the provided key and hop information.
- **Inputs**:
    - `key`: A pointer to an `fd_fib4_key_t` structure containing the routing key information, including the address, mask, and priority.
    - `hop`: A pointer to an `fd_fib4_hop_t` structure containing the routing hop information, including the route type, gateway IP, interface index, scope, and source IP.
    - `file`: A pointer to a `FILE` stream where the formatted routing information will be printed.
- **Control Flow**:
    - The function begins by checking the `rtype` field of the `hop` structure and prints a corresponding string to the file for each recognized route type, or an 'invalid' message for unrecognized types.
    - It then checks the `mask` field of the `key` structure; if the mask is zero, it prints 'default', otherwise it prints the IP address and, if applicable, the subnet mask length.
    - If the `ip4_gw` field of the `hop` structure is non-zero, it prints the gateway IP address.
    - If the `if_idx` field of the `hop` structure is non-zero, it prints the interface index.
    - The function checks the `scope` field of the `hop` structure and prints a corresponding scope string for recognized values, or the numeric scope for unrecognized values.
    - If the `ip4_src` field of the `hop` structure is non-zero, it prints the source IP address.
    - If the `prio` field of the `key` structure is non-zero, it prints the metric value.
    - Finally, it prints a newline character to the file.
- **Output**: The function returns 0 on successful execution, or an error code if any of the file operations fail.


---
### fd\_fib4\_fprintf<!-- {{#callable:fd_fib4_fprintf}} -->
The `fd_fib4_fprintf` function prints the routing table entries of a given FIB (Forwarding Information Base) to a specified file, ensuring data consistency by checking for torn reads.
- **Inputs**:
    - `fib`: A pointer to a constant `fd_fib4_t` structure representing the FIB whose routing table entries are to be printed.
    - `file_`: A pointer to a `FILE` object where the routing table entries will be printed.
- **Control Flow**:
    - Initialize local variables `file`, `key_tbl`, and `hop_tbl` from the input `fib` structure.
    - Perform a memory fence to ensure memory consistency before reading `cnt` and `generation` from `fib`.
    - Iterate over each entry in the routing table using a loop that runs from 0 to `cnt`.
    - Within the loop, perform a memory fence and read the current key and hop from `key_tbl` and `hop_tbl`.
    - Check for torn reads by comparing the current generation with the initial generation; if they differ, print '=== TORN READ ===' and return 0.
    - Call [`fd_fib4_fprintf_route`](#fd_fib4_fprintf_route) to print the current route entry to the file.
    - Continue the loop until all entries are processed.
- **Output**: The function returns 0, indicating successful completion or a torn read was detected.
- **Functions called**:
    - [`fd_fib4_key_tbl_const`](fd_fib4_private.h.driver.md#fd_fib4_key_tbl_const)
    - [`fd_fib4_hop_tbl_const`](fd_fib4_private.h.driver.md#fd_fib4_hop_tbl_const)
    - [`fd_fib4_fprintf_route`](#fd_fib4_fprintf_route)


