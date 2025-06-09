# Purpose
This C header file provides an interface for integrating AddressSanitizer (ASan) functionality into a program, specifically for managing memory regions in a way that complements ASan's capabilities. AddressSanitizer is a tool used to detect memory errors such as out-of-bounds accesses and use-after-free bugs. The file defines macros and inline functions that allow developers to mark memory regions as "poisoned" (unaddressable) or "unpoisoned" (addressable), which helps in identifying illegal memory accesses during runtime. The functions [`fd_asan_poison`](#fd_asan_poison), [`fd_asan_unpoison`](#fd_asan_unpoison), [`fd_asan_test`](#fd_asan_test), and [`fd_asan_query`](#fd_asan_query) are central to this functionality, providing mechanisms to manipulate and query the state of memory regions with respect to ASan's tracking.

The header file is designed to be included in other C source files, providing a public API for memory management in environments where ASan is used. It conditionally compiles its functionality based on whether ASan is available, using preprocessor directives to check for ASan support and to define the necessary attributes and functions accordingly. If ASan is not available, the functions default to no-operations, ensuring compatibility across different build environments. This file is part of a larger project, likely involving custom memory management, and it ensures that memory regions managed by the project are properly tracked by ASan, enhancing the robustness and reliability of the software by catching memory-related errors during development and testing.
# Imports and Dependencies

---
- `../fd_util_base.h`


# Global Variables

---
### \_\_asan\_region\_is\_poisoned
- **Type**: `function pointer`
- **Description**: `__asan_region_is_poisoned` is a function pointer that takes a memory address and a size as parameters and returns a pointer. It is part of the AddressSanitizer (ASan) interface used to check if any part of a specified memory region is poisoned, meaning it is marked as unaddressable by ASan.
- **Use**: This function is used internally to determine if a memory region has been poisoned by ASan, which helps in detecting out-of-bounds memory access errors.


# Functions

---
### fd\_asan\_poison<!-- {{#callable:fd_asan_poison}} -->
The `fd_asan_poison` function marks a memory region as unaddressable for AddressSanitizer (ASan) instrumentation, or simply returns the address if ASan is not enabled.
- **Inputs**:
    - `addr`: A pointer to the start of the memory region to be poisoned.
    - `sz`: The size of the memory region to be poisoned, in bytes.
- **Control Flow**:
    - If ASan is enabled, the function calls `__asan_poison_memory_region` to mark the memory region `[addr, addr+sz)` as unaddressable.
    - If ASan is not enabled, the function does nothing with `sz` and simply returns `addr`.
- **Output**: The function returns the input address `addr`.


---
### fd\_asan\_unpoison<!-- {{#callable:fd_asan_unpoison}} -->
The `fd_asan_unpoison` function marks a memory region as addressable and returns the address of the region.
- **Inputs**:
    - `addr`: A pointer to the start of the memory region to be marked as addressable.
    - `sz`: The size of the memory region to be marked as addressable, though it is not used in the function implementation.
- **Control Flow**:
    - The function takes two parameters: a pointer to a memory address (`addr`) and a size (`sz`).
    - The size parameter (`sz`) is explicitly cast to void to indicate it is unused in the function logic.
    - The function simply returns the `addr` parameter, effectively making the memory region starting at `addr` addressable.
- **Output**: The function returns the `addr` pointer, indicating the start of the now addressable memory region.


---
### fd\_asan\_test<!-- {{#callable:fd_asan_test}} -->
The `fd_asan_test` function checks if a given memory address is poisoned by AddressSanitizer (ASan) and returns 0 if ASan is not enabled.
- **Inputs**:
    - `addr`: A pointer to the memory address to be tested for poisoning.
- **Control Flow**:
    - The function takes a single input, `addr`, which is a pointer to a memory address.
    - If ASan is enabled (`FD_HAS_ASAN` is set), the function calls `__asan_address_is_poisoned` to check if the address is poisoned and returns the result.
    - If ASan is not enabled, the function simply returns 0, indicating the address is not poisoned.
- **Output**: Returns 1 if the address is poisoned (when ASan is enabled), otherwise returns 0.


---
### fd\_asan\_query<!-- {{#callable:fd_asan_query}} -->
The `fd_asan_query` function checks if any part of a specified memory region is poisoned and returns the address of the first poisoned byte, or NULL if none is poisoned.
- **Inputs**:
    - `addr`: A pointer to the start of the memory region to be checked for poisoning.
    - `sz`: The size of the memory region in bytes to be checked for poisoning.
- **Control Flow**:
    - The function takes two parameters, `addr` and `sz`, which represent the starting address and size of the memory region to be checked.
    - If AddressSanitizer (ASan) is enabled (`FD_HAS_ASAN` is set), the function calls `__asan_region_is_poisoned` to check the region and returns the address of the first poisoned byte if any.
    - If ASan is not enabled, the function simply returns NULL without performing any checks.
- **Output**: The function returns the address of the first poisoned byte in the specified memory region if any byte is poisoned; otherwise, it returns NULL.


# Function Declarations (Public API)

---
### fd\_asan\_check\_watch<!-- {{#callable_declaration:fd_asan_check_watch}} -->
Monitors memory regions for ASan watchpoints and logs updates.
- **Description**: This function is used to check if any addresses within a specified memory region are being monitored by AddressSanitizer (ASan) watchpoints. It logs a message to standard error if any such addresses are found, indicating whether they are now poisoned or not. This function is typically used in conjunction with manual ASan memory poisoning to ensure that changes to memory regions are tracked and reported. It should be called whenever a memory region's poison status is updated, and it assumes that the ASan watchpoints have been set up correctly beforehand.
- **Inputs**:
    - `poison`: An integer indicating the poison status to be set for the memory region. A non-zero value indicates the region is poisoned, while zero indicates it is not poisoned.
    - `addr`: A pointer to the start of the memory region to be checked. Must not be null and should point to a valid memory region.
    - `sz`: The size of the memory region in bytes. Must be a positive value.
- **Output**: None
- **See also**: [`fd_asan_check_watch`](fd_asan.c.driver.md#fd_asan_check_watch)  (Implementation)


---
### fd\_asan\_watch<!-- {{#callable_declaration:fd_asan_watch}} -->
Monitors a memory address for ASan poisoning status.
- **Description**: Use this function to track a specific memory address for its poisoning status under AddressSanitizer (ASan). This is particularly useful in environments where ASan's default instrumentation might be missing, such as in custom memory allocators or shared memory segments. The function logs the current poisoning status of the address and maintains a watch list of addresses being monitored. It is important to note that there is a limit to the number of addresses that can be watched simultaneously, and exceeding this limit will result in a critical log message. This function should be used in debugging scenarios where memory safety is a concern.
- **Inputs**:
    - `addr`: A pointer to the memory address to be monitored. The address must be valid and previously allocated by the program. The function does not take ownership of the memory and expects the address to be non-null. If the address is null or invalid, the behavior is undefined.
- **Output**: None
- **See also**: [`fd_asan_watch`](fd_asan.c.driver.md#fd_asan_watch)  (Implementation)


