# Purpose
This C header file, `fd_fseq.h`, defines a set of APIs for managing sequence numbers as persistent shared memory objects, primarily intended for use in flow control communications between receiver and transmitter processes. The file provides a structured way to handle sequence numbers in a shared memory context, allowing multiple processes to access and update these numbers safely and efficiently. The key components include functions for creating, joining, leaving, and deleting a sequence number object (`fseq`), as well as querying and updating the sequence number. The file specifies alignment and footprint requirements for memory regions used as `fseq`, ensuring proper memory management and minimizing issues like false sharing.

The header file is designed to be included in other C source files, providing a public API for sequence number management in shared memory. It defines constants for alignment and footprint, ensuring that memory regions are correctly sized and aligned. The functions provided facilitate the lifecycle management of `fseq` objects, from initialization ([`fd_fseq_new`](#fd_fseq_new)) to cleanup ([`fd_fseq_delete`](#fd_fseq_delete)), and include mechanisms for safely accessing and modifying the sequence number ([`fd_fseq_query`](#fd_fseq_query) and [`fd_fseq_update`](#fd_fseq_update)). The use of compiler fences ensures memory operations are performed in a consistent order, which is crucial in a concurrent processing environment. Overall, this file offers a robust interface for handling sequence numbers in applications requiring inter-process communication.
# Imports and Dependencies

---
- `../fd_tango_base.h`


# Global Variables

---
### fd\_fseq\_new
- **Type**: `function`
- **Description**: The `fd_fseq_new` function is responsible for formatting an unused memory region to be used as a sequence number object in shared memory. It initializes the sequence number to `seq0` and clears the application region to zero. This function is part of a system designed to manage sequence numbers for inter-process communication.
- **Use**: This function is used to initialize a memory region for use as a sequence number object, ensuring it is properly formatted and ready for subsequent operations.


---
### fd\_fseq\_join
- **Type**: `function`
- **Description**: The `fd_fseq_join` function is designed to join the caller to a sequence number wrapped in a shared memory object, known as a fseq. It takes a pointer to the first byte of the memory region backing the fseq and returns a pointer in the local address space to the fseq on success.
- **Use**: This function is used to establish a connection to a fseq, allowing the caller to interact with the sequence number stored in shared memory.


---
### fd\_fseq\_leave
- **Type**: `function pointer`
- **Description**: The `fd_fseq_leave` function is a global function that facilitates leaving a current local join to a sequence number shared memory object. It takes a pointer to a constant unsigned long integer, which represents the sequence number object, and returns a pointer to the underlying shared memory region on success or NULL on failure.
- **Use**: This function is used to safely disconnect from a shared memory sequence number object, ensuring proper resource management and cleanup.


---
### fd\_fseq\_delete
- **Type**: `function pointer`
- **Description**: The `fd_fseq_delete` function is a global function pointer that unformats a memory region used as a fseq (sequence number in shared memory). It assumes that no process is currently joined to the region and returns a pointer to the underlying shared memory region or NULL if there is an error.
- **Use**: This function is used to delete a formatted fseq memory region, transferring ownership of the memory back to the caller.


# Functions

---
### fd\_fseq\_app\_laddr<!-- {{#callable:fd_fseq_app_laddr}} -->
The `fd_fseq_app_laddr` function returns the local address of the application region of a sequence number object, offset by two elements from the start of the sequence.
- **Inputs**:
    - `fseq`: A pointer to an unsigned long integer array representing the sequence number object.
- **Control Flow**:
    - The function takes a pointer to a sequence number object (`fseq`).
    - It calculates the address by adding an offset of two to the `fseq` pointer.
    - The function returns this calculated address cast to a `void *` type.
- **Output**: A `void *` pointer to the local address of the application region of the sequence number object, offset by two elements.


---
### fd\_fseq\_app\_laddr\_const<!-- {{#callable:fd_fseq_app_laddr_const}} -->
The function `fd_fseq_app_laddr_const` returns a constant pointer to the application region of a sequence number object in shared memory.
- **Inputs**:
    - `fseq`: A constant pointer to an unsigned long integer, representing the base address of a sequence number object in shared memory.
- **Control Flow**:
    - The function takes a constant pointer `fseq` as input.
    - It calculates the address of the application region by adding 2 to the `fseq` pointer.
    - The function returns this calculated address cast to a constant void pointer.
- **Output**: A constant void pointer to the application region of the sequence number object, offset by two ulong positions from the base address.


---
### fd\_fseq\_seq0<!-- {{#callable:fd_fseq_seq0}} -->
The `fd_fseq_seq0` function retrieves the initial sequence number used when the fseq was created.
- **Inputs**:
    - `fseq`: A pointer to a constant unsigned long integer, representing a current local join of a sequence number object.
- **Control Flow**:
    - The function accesses the memory location immediately before the given pointer `fseq` to retrieve the initial sequence number.
- **Output**: The function returns an unsigned long integer representing the initial sequence number used when the fseq was created.


---
### fd\_fseq\_query<!-- {{#callable:fd_fseq_query}} -->
The `fd_fseq_query` function reads and returns the current sequence number from a sequence number object in shared memory, ensuring memory consistency with compiler fences.
- **Inputs**:
    - `fseq`: A pointer to a constant unsigned long integer representing the sequence number object in shared memory.
- **Control Flow**:
    - A memory fence is executed to ensure memory operations are completed before reading the sequence number.
    - The sequence number is read from the first element of the `fseq` array using a volatile read to prevent compiler optimizations that could reorder operations.
    - Another memory fence is executed to ensure memory operations are completed after reading the sequence number.
    - The read sequence number is returned.
- **Output**: The function returns the current sequence number as an unsigned long integer.


---
### fd\_fseq\_update<!-- {{#callable:fd_fseq_update}} -->
The `fd_fseq_update` function updates the sequence number stored in a shared memory sequence object, ensuring memory consistency with compiler fences.
- **Inputs**:
    - `fseq`: A pointer to an unsigned long representing the shared memory sequence object to be updated.
    - `seq`: An unsigned long value representing the new sequence number to be stored in the sequence object.
- **Control Flow**:
    - A memory fence is executed to ensure memory operations are completed before updating the sequence number.
    - The sequence number at the first position of the `fseq` array is updated to the new `seq` value using a volatile write to ensure visibility across threads.
    - Another memory fence is executed to ensure the update is visible to other threads.
- **Output**: The function does not return a value; it updates the sequence number in the provided sequence object.


# Function Declarations (Public API)

---
### fd\_fseq\_align<!-- {{#callable_declaration:fd_fseq_align}} -->
Return the required alignment for a memory region suitable for use as a fseq.
- **Description**: Use this function to obtain the alignment requirement for a memory region intended to be used as a fseq. This is particularly useful when setting up shared memory for sequence number management in flow control communications. The alignment value returned is a positive integer power of 2, which is recommended to be at least double the cache line size to mitigate false sharing. This function does not require any prior initialization and can be called at any time.
- **Inputs**: None
- **Output**: Returns the alignment requirement as an unsigned long integer.
- **See also**: [`fd_fseq_align`](fd_fseq.c.driver.md#fd_fseq_align)  (Implementation)


---
### fd\_fseq\_footprint<!-- {{#callable_declaration:fd_fseq_footprint}} -->
Returns the memory footprint required for a sequence number object.
- **Description**: Use this function to determine the size of the memory region needed to store a sequence number object in shared memory. This is useful for allocating the correct amount of memory when setting up a sequence number for inter-process communication. The function is constant and does not depend on any input parameters or state.
- **Inputs**: None
- **Output**: The function returns an unsigned long integer representing the required memory footprint in bytes.
- **See also**: [`fd_fseq_footprint`](fd_fseq.c.driver.md#fd_fseq_footprint)  (Implementation)


---
### fd\_fseq\_new<!-- {{#callable_declaration:fd_fseq_new}} -->
Formats a memory region for use as a sequence number object.
- **Description**: This function initializes a given memory region to be used as a sequence number object, which is primarily intended for flow control communications in shared memory environments. It requires the memory region to be non-null, properly aligned, and of sufficient size. The sequence number is initialized to the provided value, and the application region is cleared. If the memory region is invalid, the function logs a warning and returns NULL.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted as a sequence number object. It must not be null, must be aligned according to fd_fseq_align(), and must have a footprint of at least FD_FSEQ_FOOTPRINT bytes. If these conditions are not met, the function returns NULL.
    - `seq0`: The initial sequence number to set in the sequence number object. This value is used to initialize the sequence number fields in the memory region.
- **Output**: Returns the pointer to the formatted memory region on success, or NULL if the input memory region is invalid.
- **See also**: [`fd_fseq_new`](fd_fseq.c.driver.md#fd_fseq_new)  (Implementation)


---
### fd\_fseq\_join<!-- {{#callable_declaration:fd_fseq_join}} -->
Joins the caller to a sequence number shared memory object.
- **Description**: Use this function to join a sequence number shared memory object, allowing the caller to interact with it. The function requires a pointer to the first byte of the memory region backing the sequence number object in the caller's address space. It returns a pointer to the sequence number on success, which should not be assumed to be a simple cast of the input pointer. Ensure that the memory region is correctly aligned and initialized as a sequence number object before calling this function. A successful join must be matched with a corresponding leave to properly manage resources.
- **Inputs**:
    - `shfseq`: A pointer to the first byte of the memory region backing the sequence number object in the caller's address space. Must not be null and must be aligned according to fd_fseq_align(). The memory region must be properly initialized as a sequence number object. If these conditions are not met, the function returns NULL and logs a warning.
- **Output**: Returns a pointer to the sequence number in the local address space on success, or NULL on failure.
- **See also**: [`fd_fseq_join`](fd_fseq.c.driver.md#fd_fseq_join)  (Implementation)


---
### fd\_fseq\_leave<!-- {{#callable_declaration:fd_fseq_leave}} -->
Leaves a current local join to a sequence number shared memory object.
- **Description**: Use this function to leave a current local join to a sequence number shared memory object, typically after operations on the sequence number are complete. This function should be called after a successful join using `fd_fseq_join`. It returns a pointer to the underlying shared memory region on success, which is not simply a cast of the input pointer. If the input is NULL, the function logs a warning and returns NULL, indicating failure.
- **Inputs**:
    - `fseq`: A pointer to the sequence number shared memory object. Must not be NULL. The function logs a warning and returns NULL if this parameter is NULL.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL on failure.
- **See also**: [`fd_fseq_leave`](fd_fseq.c.driver.md#fd_fseq_leave)  (Implementation)


---
### fd\_fseq\_delete<!-- {{#callable_declaration:fd_fseq_delete}} -->
Unformats a memory region used as a fseq.
- **Description**: Use this function to unformat a memory region that was previously formatted as a fseq, assuming no processes are currently joined to it. This function should be called when the fseq is no longer needed, and it transfers ownership of the memory region back to the caller upon success. It returns a pointer to the underlying shared memory region or NULL if the input is invalid, such as when the pointer does not point to a valid fseq. The function logs details of any errors encountered.
- **Inputs**:
    - `shfseq`: A pointer to the memory region that is currently formatted as a fseq. It must be aligned according to fd_fseq_align() and must not be NULL. The function will return NULL and log a warning if the pointer is NULL, misaligned, or does not point to a valid fseq.
- **Output**: Returns a pointer to the underlying shared memory region on success, or NULL if the input is invalid.
- **See also**: [`fd_fseq_delete`](fd_fseq.c.driver.md#fd_fseq_delete)  (Implementation)


