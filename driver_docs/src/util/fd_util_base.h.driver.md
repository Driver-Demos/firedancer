# Purpose
The provided C header file, `fd_util_base.h`, is a foundational component of a software development environment, specifically designed to ensure compatibility and performance across various build targets. It defines a set of macros and type definitions that facilitate the development of portable and high-performance code. The file includes compiler checks to ensure that the code is compiled with at least C17 or C++17 standards, and it defines a series of capability macros (e.g., `FD_HAS_HOSTED`, `FD_HAS_ATOMIC`) that indicate the presence of specific features on the build target, such as atomic operations, threading, and specific hardware optimizations like SSE or AVX.

The file also provides a collection of utility macros and functions that enhance code portability and performance. These include memory manipulation functions ([`fd_memcpy`](#fd_memcpy), [`fd_memset`](#fd_memset)), hashing functions ([`fd_hash`](#fd_hash)), and atomic operations. Additionally, it defines macros for compiler optimizations and tricks, such as `FD_LIKELY`, `FD_UNLIKELY`, and `FD_FN_PURE`, which help guide the compiler's optimization decisions. The file is intended to be included in other C or C++ source files, providing a consistent and optimized base for further development. It does not define any public APIs or external interfaces directly but rather sets up an environment for writing efficient and portable code.
# Imports and Dependencies

---
- `stdalign.h`
- `string.h`
- `limits.h`
- `float.h`


# Global Variables

---
### \_\_msan\_memcpy
- **Type**: `function pointer`
- **Description**: `__msan_memcpy` is a function pointer that points to a memory copy function specifically designed for use with MemorySanitizer (MSan). MSan is a tool that detects uninitialized memory reads in C/C++ programs. This function is used to perform memory copying operations while ensuring that MSan can track and check the memory being copied for uninitialized reads.
- **Use**: This function is used to perform memory copying operations in environments where MemorySanitizer is enabled, ensuring that uninitialized memory reads are detected.


---
### fd\_memset\_explicit
- **Type**: `pointer to a volatile function pointer`
- **Description**: `fd_memset_explicit` is a static volatile function pointer that points to a function with the signature `void *(*)(void *, int, size_t)`, which matches the standard `memset` function. This function pointer is initialized to point to the `memset` function, allowing it to be used to explicitly set memory blocks to a specific value.
- **Use**: This variable is used to perform memory setting operations in a way that prevents the compiler from optimizing away the call, ensuring the operation is always executed.


# Functions

---
### fd\_type\_pun<!-- {{#callable:fd_type_pun}} -->
The `fd_type_pun` function allows type punning by returning the input pointer after an inline assembly operation that prevents the compiler from optimizing away the operation.
- **Inputs**:
    - `p`: A void pointer to any data type that needs to be type-punned.
- **Control Flow**:
    - The function takes a single void pointer as input.
    - An inline assembly block is executed, which includes a comment with the source location and a constraint that modifies the input pointer in place.
    - The inline assembly uses the "+r" constraint to indicate that the pointer is both read and written, and the "memory" clobber to prevent the compiler from optimizing away memory accesses around this operation.
    - The function returns the input pointer without any modification.
- **Output**: The function returns the same void pointer that was passed as input, allowing for type punning while maintaining strict aliasing rules.


---
### fd\_type\_pun\_const<!-- {{#callable:fd_type_pun_const}} -->
The `fd_type_pun_const` function allows type punning of a constant pointer while maintaining strict aliasing optimizations.
- **Inputs**:
    - `p`: A constant pointer to any data type that needs to be type-punned.
- **Control Flow**:
    - The function takes a constant pointer `p` as input.
    - An inline assembly block is used to perform a no-operation (NOP) with the pointer `p`, ensuring the compiler does not optimize away the type punning operation.
    - The function returns the input pointer `p` without modification.
- **Output**: The function returns the same constant pointer `p` that was passed as input.


---
### fd\_memcpy<!-- {{#callable:fd_memcpy}} -->
The `fd_memcpy` function is a wrapper around the standard `memcpy` function, with additional checks for zero-size operations under certain conditions.
- **Inputs**:
    - `d`: A pointer to the destination memory where the content is to be copied.
    - `s`: A pointer to the source memory from which the content is to be copied.
    - `sz`: The number of bytes to copy from the source to the destination.
- **Control Flow**:
    - The function checks if the `CBMC` or `FD_HAS_ASAN` macros are defined.
    - If either macro is defined, it checks if `sz` is zero using `FD_UNLIKELY`.
    - If `sz` is zero, the function returns the destination pointer `d` immediately, as copying zero bytes is considered undefined behavior in some standards.
    - If `sz` is not zero or the macros are not defined, the function proceeds to call the standard `memcpy` function to perform the memory copy.
- **Output**: The function returns a pointer to the destination memory `d`.


---
### fd\_memset<!-- {{#callable:fd_memset}} -->
The `fd_memset` function sets a block of memory to a specified value using an optimized approach if available, otherwise it defaults to the standard `memset` function.
- **Inputs**:
    - `d`: A pointer to the block of memory to be set.
    - `c`: The value to set each byte of the memory block to, interpreted as an unsigned char.
    - `sz`: The number of bytes to set in the memory block.
- **Control Flow**:
    - If the CBMC macro is defined and the size `sz` is zero, the function returns the pointer `d` immediately.
    - If the conditions for using an optimized assembly version of `memset` are met (e.g., on x86 architecture and certain build configurations), the function uses inline assembly to perform the memory set operation using the `rep stosb` instruction.
    - If the conditions for using the optimized version are not met, the function defaults to using the standard `memset` function from the C standard library.
- **Output**: The function returns the pointer `d`, which is the same as the input pointer to the memory block.


---
### fd\_memeq<!-- {{#callable:fd_memeq}} -->
The `fd_memeq` function compares two memory blocks for equality and returns 1 if they are equal or if the size is zero, otherwise it returns 0.
- **Inputs**:
    - `s1`: A pointer to the first memory block to be compared.
    - `s2`: A pointer to the second memory block to be compared.
    - `sz`: The size in bytes of the memory blocks to be compared.
- **Control Flow**:
    - The function calls `memcmp` to compare the memory blocks `s1` and `s2` for `sz` bytes.
    - It checks if the result of `memcmp` is zero, indicating the blocks are equal.
    - The function returns the result of the comparison as an integer.
- **Output**: The function returns an integer: 1 if the memory blocks are equal or if `sz` is zero, and 0 otherwise.


# Function Declarations (Public API)

---
### fd\_hash\_memcpy<!-- {{#callable_declaration:fd_hash_memcpy}} -->
Copies memory from source to destination while computing a hash.
- **Description**: This function is used to copy a block of memory from a source to a destination while simultaneously computing a hash of the data. It is useful when both operations are needed, as it can be more efficient than performing them separately. The function requires valid pointers for both the source and destination, and the size of the data to be copied and hashed. It handles cases where the size is zero by returning a hash based on the seed and a constant. The function does not handle overlapping source and destination memory regions.
- **Inputs**:
    - `seed`: An initial hash value used to compute the final hash. It can be any unsigned long value.
    - `dst`: A pointer to the destination memory where the data will be copied. Must not be null and must have enough space to hold 'sz' bytes.
    - `src`: A pointer to the source memory from which the data will be copied. Must not be null and must point to at least 'sz' bytes of readable memory.
    - `sz`: The number of bytes to copy and hash. Can be zero, in which case the function returns a hash based on the seed and a constant.
- **Output**: Returns an unsigned long hash value computed from the seed and the data in the source buffer.
- **See also**: [`fd_hash_memcpy`](fd_hash.c.driver.md#fd_hash_memcpy)  (Implementation)


---
### fd\_yield<!-- {{#callable_declaration:fd_yield}} -->
Yields the calling thread to the operating system scheduler.
- **Description**: This function is used to voluntarily yield the processor from the calling thread, allowing other threads to be scheduled by the operating system. It is typically used in multi-threaded applications to improve concurrency and responsiveness by giving other threads a chance to execute. This function should be called when the current thread can afford to wait, such as when it is waiting for a resource to become available or when it has completed its current task and is waiting for more work. It is only available in hosted environments where the operating system supports thread scheduling.
- **Inputs**: None
- **Output**: None
- **See also**: [`fd_yield`](fd_util.c.driver.md#fd_yield)  (Implementation)


