# Purpose
This C header file, `fd_msan.h`, is designed to interface with MemorySanitizer (MSan), a tool used to detect uninitialized memory accesses in C and C++ programs. The file provides macros and inline functions that facilitate the use of MSan's capabilities, such as marking memory regions as uninitialized or initialized and checking if memory is initialized. The header checks if the MemorySanitizer feature is available using the `__has_feature` macro and defines the `FD_HAS_MSAN` macro accordingly. If MSan is available, it provides function prototypes for internal use, such as [`__msan_poison`](#__msan_poison), [`__msan_unpoison`](#__msan_unpoison), and [`__msan_check_mem_is_initialized`](#__msan_check_mem_is_initialized), which are used to manipulate the memory state for MSan's analysis.

The file defines three main inline functions: [`fd_msan_poison`](#fd_msan_poison), [`fd_msan_unpoison`](#fd_msan_unpoison), and [`fd_msan_check`](#fd_msan_check). These functions are used to mark memory as uninitialized, mark memory as initialized, and check if memory is initialized, respectively. These operations are crucial for ensuring that MSan can accurately detect and report uninitialized memory usage, which is a common source of bugs in software. The header is part of a larger utility library, as indicated by the inclusion of `fd_util_base.h`, and is intended to be used internally within a project to enhance memory safety during development and debugging. The file is structured to be compatible with environments where MSan is not available, providing no-op implementations of the functions in such cases.
# Imports and Dependencies

---
- `../fd_util_base.h`


# Functions

---
### fd\_msan\_poison<!-- {{#callable:fd_msan_poison}} -->
The `fd_msan_poison` function marks a region of memory as uninitialized for MemorySanitizer (MSan) to detect uninitialized memory usage.
- **Inputs**:
    - `addr`: A pointer to the start of the memory region to be marked as uninitialized.
    - `sz`: The size of the memory region to be marked as uninitialized, in bytes.
- **Control Flow**:
    - If MemorySanitizer (MSan) is enabled (`FD_HAS_MSAN` is true), the function calls `__msan_poison` with the provided address and size to mark the memory as uninitialized.
    - If MSan is not enabled, the function does nothing with the size and simply returns the address.
- **Output**: The function returns the same address that was passed in as the input.


---
### fd\_msan\_unpoison<!-- {{#callable:fd_msan_unpoison}} -->
The `fd_msan_unpoison` function marks a region of memory as initialized, effectively telling MemorySanitizer (MSan) to ignore uninitialized memory warnings for that region.
- **Inputs**:
    - `addr`: A pointer to the start of the memory region to be marked as initialized.
    - `sz`: The size of the memory region to be marked as initialized, in bytes.
- **Control Flow**:
    - If MemorySanitizer (MSan) is enabled (`FD_HAS_MSAN` is true), the function calls `__msan_unpoison` with the provided address and size to mark the memory as initialized.
    - If MSan is not enabled, the function simply returns the address without performing any operation, as the `sz` parameter is cast to void to avoid unused variable warnings.
- **Output**: The function returns the same address that was passed in as the `addr` parameter.


---
### fd\_msan\_check<!-- {{#callable:fd_msan_check}} -->
The `fd_msan_check` function is a no-op placeholder that checks if a region of memory is initialized when MemorySanitizer is enabled, but does nothing otherwise.
- **Inputs**:
    - `addr`: A pointer to the start of the memory region to be checked.
    - `sz`: The size of the memory region to be checked, in bytes.
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests inlining by the compiler.
    - If MemorySanitizer (MSan) is enabled (`FD_HAS_MSAN` is true), the function calls `__msan_check_mem_is_initialized` to check if the memory region is initialized.
    - If MSan is not enabled, the function does nothing, as indicated by the casting of `addr` and `sz` to void to suppress unused variable warnings.
- **Output**: The function does not return any value.


