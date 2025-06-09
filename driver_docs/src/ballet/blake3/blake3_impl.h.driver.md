# Purpose
This C header file, `blake3_impl.h`, is part of the BLAKE3 cryptographic hash function implementation. It provides internal definitions and declarations necessary for the BLAKE3 hashing algorithm, focusing on low-level operations and optimizations. The file defines several constants, macros, and inline functions that are used to manipulate data and perform bitwise operations essential for the hash computation. It includes definitions for internal flags used to control the hashing process, such as `CHUNK_START`, `CHUNK_END`, and `ROOT`, which help manage the state of the hash computation across different stages.

The file also declares several functions for compressing and hashing data blocks, with specific implementations optimized for different CPU architectures, such as SSE2, AVX2, and AVX512 for x86 processors, and NEON for ARM processors. These functions are designed to be used internally within the BLAKE3 library to perform the core operations of the hash function efficiently. The presence of architecture-specific functions indicates a focus on performance optimization by leveraging SIMD (Single Instruction, Multiple Data) capabilities. This header file is not intended to be a public API but rather serves as a crucial component of the BLAKE3 library's internal implementation, providing the necessary building blocks for the hash function's operation.
# Imports and Dependencies

---
- `assert.h`
- `stdbool.h`
- `stddef.h`
- `stdint.h`
- `string.h`
- `blake3.h`


# Global Variables

---
### IV
- **Type**: `array of uint32_t`
- **Description**: The `IV` variable is a static constant array of 8 unsigned 32-bit integers. It represents the initial values used in the BLAKE3 cryptographic hash function, which are derived from the fractional parts of the square roots of the first 8 prime numbers.
- **Use**: This variable is used as the initial chaining value in the BLAKE3 hash function to ensure consistent and secure hash computations.


---
### MSG\_SCHEDULE
- **Type**: ``uint8_t[7][16]``
- **Description**: `MSG_SCHEDULE` is a static constant two-dimensional array of unsigned 8-bit integers with dimensions 7x16. It is used in the BLAKE3 cryptographic hash function implementation to define a message schedule for the compression function.
- **Use**: This variable is used to determine the order of message words during the compression process in the BLAKE3 hash function.


# Data Structures

---
### blake3\_flags
- **Type**: `enum`
- **Members**:
    - `CHUNK_START`: Indicates the start of a chunk in the BLAKE3 hashing process.
    - `CHUNK_END`: Marks the end of a chunk in the BLAKE3 hashing process.
    - `PARENT`: Denotes a parent node in the BLAKE3 hash tree.
    - `ROOT`: Represents the root node in the BLAKE3 hash tree.
    - `KEYED_HASH`: Specifies that the hash is keyed, used for keyed hashing.
    - `DERIVE_KEY_CONTEXT`: Indicates the context for key derivation in BLAKE3.
    - `DERIVE_KEY_MATERIAL`: Specifies the material for key derivation in BLAKE3.
- **Description**: The `blake3_flags` enumeration defines a set of flags used in the BLAKE3 cryptographic hash function to indicate various states and operations within the hashing process. These flags are used to manage the structure of the hash tree, such as identifying the start and end of chunks, marking parent and root nodes, and handling keyed hashing and key derivation contexts. Each flag is represented as a bitwise shift of 1, allowing them to be combined using bitwise operations for efficient state management.


# Functions

---
### highest\_one<!-- {{#callable:highest_one}} -->
The `highest_one` function determines the index of the highest set bit in a non-zero 64-bit unsigned integer.
- **Inputs**:
    - `x`: A 64-bit unsigned integer input, assumed to be non-zero, for which the highest set bit index is to be found.
- **Control Flow**:
    - The function uses different implementations based on the compiler and architecture to find the highest set bit index.
    - For GCC or Clang compilers, it uses the `__builtin_clzll` function to count leading zeros and calculates the index by subtracting this count from 63.
    - For MSVC on x86_64 architecture, it uses the `_BitScanReverse64` intrinsic to find the index directly.
    - For MSVC on x86_32 architecture, it checks if the higher 32 bits are non-zero and uses `_BitScanReverse` on the appropriate 32-bit segment, adjusting the index accordingly.
    - For other compilers or architectures, it manually shifts the input and increments a counter to determine the index of the highest set bit.
- **Output**: The function returns an unsigned integer representing the index of the highest set bit in the input.


---
### popcnt<!-- {{#callable:popcnt}} -->
The `popcnt` function counts the number of set bits (1s) in a 64-bit unsigned integer.
- **Inputs**:
    - `x`: A 64-bit unsigned integer whose set bits are to be counted.
- **Control Flow**:
    - If compiled with GCC or Clang, the function uses the built-in `__builtin_popcountll` to count the set bits in `x`.
    - If not using GCC or Clang, the function initializes a counter to zero and enters a loop that continues until `x` becomes zero.
    - Within the loop, the counter is incremented, and `x` is updated using the expression `x &= x - 1`, which clears the least significant set bit.
    - The loop effectively counts the number of set bits by counting how many times it can clear a set bit before `x` becomes zero.
    - The function returns the count of set bits.
- **Output**: The function returns an unsigned integer representing the number of set bits in the input `x`.


---
### round\_down\_to\_power\_of\_2<!-- {{#callable:round_down_to_power_of_2}} -->
The `round_down_to_power_of_2` function calculates the largest power of two that is less than or equal to a given 64-bit unsigned integer.
- **Inputs**:
    - `x`: A 64-bit unsigned integer for which the largest power of two less than or equal to it is to be found.
- **Control Flow**:
    - The function first ensures that the input `x` is non-zero by performing a bitwise OR with 1, which does not affect the value if `x` is already non-zero.
    - It then calls the [`highest_one`](#highest_one) function to find the index of the highest set bit in the modified `x`.
    - The function returns the value of `1ULL` left-shifted by the index of the highest set bit, effectively calculating the largest power of two less than or equal to `x`.
- **Output**: A 64-bit unsigned integer representing the largest power of two less than or equal to the input `x`.
- **Functions called**:
    - [`highest_one`](#highest_one)


---
### counter\_low<!-- {{#callable:counter_low}} -->
The `counter_low` function extracts the lower 32 bits from a 64-bit counter value.
- **Inputs**:
    - `counter`: A 64-bit unsigned integer representing the counter from which the lower 32 bits are to be extracted.
- **Control Flow**:
    - The function takes a 64-bit unsigned integer as input.
    - It casts the 64-bit integer to a 32-bit unsigned integer, effectively extracting the lower 32 bits of the input.
- **Output**: The function returns a 32-bit unsigned integer representing the lower 32 bits of the input counter.


---
### counter\_high<!-- {{#callable:counter_high}} -->
The `counter_high` function extracts the higher 32 bits from a 64-bit counter and returns them as a 32-bit unsigned integer.
- **Inputs**:
    - `counter`: A 64-bit unsigned integer from which the higher 32 bits are to be extracted.
- **Control Flow**:
    - The function takes a 64-bit unsigned integer `counter` as input.
    - It performs a right bitwise shift by 32 positions on `counter`, effectively moving the higher 32 bits to the lower 32-bit position.
    - The result of the shift is then cast to a 32-bit unsigned integer and returned.
- **Output**: A 32-bit unsigned integer representing the higher 32 bits of the input `counter`.


---
### load32<!-- {{#callable:load32}} -->
The `load32` function reads four bytes from a given memory location and combines them into a single 32-bit unsigned integer.
- **Inputs**:
    - `src`: A pointer to the source memory location from which four bytes will be read.
- **Control Flow**:
    - Cast the input pointer `src` to a pointer of type `const uint8_t*` and assign it to `p`.
    - Read the first byte from `p[0]` and shift it by 0 bits to form the least significant byte of the result.
    - Read the second byte from `p[1]` and shift it by 8 bits to form the second least significant byte of the result.
    - Read the third byte from `p[2]` and shift it by 16 bits to form the second most significant byte of the result.
    - Read the fourth byte from `p[3]` and shift it by 24 bits to form the most significant byte of the result.
    - Combine all four shifted bytes using bitwise OR operations to form the final 32-bit unsigned integer.
- **Output**: A 32-bit unsigned integer constructed from the four bytes read from the source memory location.


---
### load\_key\_words<!-- {{#callable:load_key_words}} -->
The `load_key_words` function loads 32-bit words from an 8-byte key into an array of 32-bit integers.
- **Inputs**:
    - `key`: A constant array of 8-bit unsigned integers with a length defined by `BLAKE3_KEY_LEN`, representing the key from which 32-bit words will be loaded.
    - `key_words`: An array of 32-bit unsigned integers with a size of 8, where the loaded 32-bit words from the key will be stored.
- **Control Flow**:
    - The function iterates over the key in 4-byte increments, from index 0 to 7.
    - For each 4-byte segment of the key, it calls the [`load32`](#load32) function to convert the segment into a 32-bit unsigned integer.
    - The resulting 32-bit integer is stored in the corresponding index of the `key_words` array.
- **Output**: The function does not return a value; it modifies the `key_words` array in place.
- **Functions called**:
    - [`load32`](#load32)


---
### store32<!-- {{#callable:store32}} -->
The `store32` function stores a 32-bit unsigned integer into a destination memory location in little-endian byte order.
- **Inputs**:
    - `dst`: A pointer to the destination memory location where the 32-bit integer will be stored.
    - `w`: The 32-bit unsigned integer to be stored in the destination memory location.
- **Control Flow**:
    - Cast the destination pointer `dst` to a `uint8_t` pointer `p`.
    - Store the least significant byte of `w` into `p[0]`.
    - Store the second least significant byte of `w` into `p[1]`.
    - Store the third least significant byte of `w` into `p[2]`.
    - Store the most significant byte of `w` into `p[3]`.
- **Output**: The function does not return a value; it modifies the memory at the destination pointer `dst`.


---
### store\_cv\_words<!-- {{#callable:store_cv_words}} -->
The `store_cv_words` function stores eight 32-bit words from an array into a byte array in little-endian format.
- **Inputs**:
    - `bytes_out`: A pointer to a 32-byte array where the 32-bit words will be stored.
    - `cv_words`: A pointer to an array of eight 32-bit words that need to be stored in the byte array.
- **Control Flow**:
    - The function iterates over the `cv_words` array, using the [`store32`](#store32) function to store each 32-bit word into the `bytes_out` array.
    - Each word from `cv_words` is stored in a consecutive 4-byte segment of `bytes_out`, starting from the beginning of the array.
    - The [`store32`](#store32) function is called eight times, once for each word in `cv_words`, storing them in little-endian format.
- **Output**: The function does not return a value; it modifies the `bytes_out` array in place.
- **Functions called**:
    - [`store32`](#store32)


# Function Declarations (Public API)

---
### fd\_blake3\_compress\_in\_place<!-- {{#callable_declaration:fd_blake3_compress_in_place}} -->
Compress a BLAKE3 block in place using the provided chaining value and parameters.
- **Description**: This function compresses a single BLAKE3 block in place, updating the provided chaining value (cv) with the result. It is typically used as part of the BLAKE3 hashing process, where multiple blocks are processed sequentially. The function requires a valid chaining value, a block of data to compress, and additional parameters such as block length, a counter, and flags to control the compression behavior. The function must be called with a block length that does not exceed BLAKE3_BLOCK_LEN, and the flags parameter should be set according to the desired compression context, such as indicating the start or end of a chunk.
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value. This array is updated in place with the result of the compression. The caller must ensure this array is properly initialized before calling the function.
    - `block`: A constant array of bytes with a length of BLAKE3_BLOCK_LEN, representing the data block to be compressed. The caller retains ownership and must ensure the array is not null.
    - `block_len`: A uint8_t value representing the length of the block to be compressed. It must not exceed BLAKE3_BLOCK_LEN. If the value is invalid, the behavior is undefined.
    - `counter`: A uint64_t value used as a counter in the compression process. It helps in maintaining uniqueness across different blocks.
    - `flags`: A uint8_t value representing various internal flags that control the compression process. These flags can indicate the start or end of a chunk, among other things. The caller must set these flags appropriately based on the context of the compression.
- **Output**: None
- **See also**: [`fd_blake3_compress_in_place`](blake3_dispatch.c.driver.md#fd_blake3_compress_in_place)  (Implementation)


---
### fd\_blake3\_compress\_xof<!-- {{#callable_declaration:fd_blake3_compress_xof}} -->
Compresses a BLAKE3 input block into an output buffer using extended output format.
- **Description**: This function is used to compress a single BLAKE3 input block into a 64-byte output buffer using the extended output format (XOF). It is typically called as part of a larger hashing process where the chaining value, input block, block length, counter, and flags are specified. The function requires the caller to provide a valid chaining value and input block, and it writes the compressed output to the provided output buffer. The function does not return a value, and it is the caller's responsibility to ensure that all input parameters are valid and that the output buffer is properly allocated.
- **Inputs**:
    - `cv`: A pointer to an array of 8 uint32_t values representing the chaining value. The caller must ensure this array is valid and properly initialized.
    - `block`: A pointer to an array of bytes with a length of BLAKE3_BLOCK_LEN, representing the input block to be compressed. The caller must ensure this array is valid and properly initialized.
    - `block_len`: A uint8_t value representing the length of the input block. It must not exceed BLAKE3_BLOCK_LEN.
    - `counter`: A uint64_t value representing the counter for the current block. It is used to differentiate between different blocks in the hashing process.
    - `flags`: A uint8_t value representing various internal flags that modify the behavior of the compression. These flags are defined in the blake3_flags enumeration.
    - `out`: A pointer to an array of 64 bytes where the compressed output will be written. The caller must ensure this array is valid and properly allocated.
- **Output**: None
- **See also**: [`fd_blake3_compress_xof`](blake3_dispatch.c.driver.md#fd_blake3_compress_xof)  (Implementation)


---
### fd\_blake3\_hash\_many<!-- {{#callable_declaration:fd_blake3_hash_many}} -->
Computes BLAKE3 hashes for multiple input blocks.
- **Description**: This function computes the BLAKE3 hash for multiple input data blocks, allowing for parallel processing of the inputs. It is designed to handle multiple inputs efficiently, leveraging SIMD instructions if available. The function requires a key, a counter, and various flags to control the hashing process. It is suitable for applications needing high-performance hashing of multiple data segments. The caller must ensure that the inputs and output buffers are properly allocated and that the number of inputs and blocks are correctly specified.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed. The caller retains ownership and must ensure the pointers are valid and not null.
    - `num_inputs`: The number of input blocks to hash. Must be greater than zero.
    - `blocks`: The number of blocks in each input. Must be greater than zero.
    - `key`: An array of 8 uint32_t values representing the key used for hashing. Must not be null.
    - `counter`: A 64-bit counter value used in the hashing process. It can be incremented based on the increment_counter flag.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each input.
    - `flags`: A uint8_t value representing internal flags for the hashing process. Must be set according to the BLAKE3 specification.
    - `flags_start`: A uint8_t value representing flags to be applied at the start of the hashing process.
    - `flags_end`: A uint8_t value representing flags to be applied at the end of the hashing process.
    - `out`: A pointer to a buffer where the resulting hash will be stored. The buffer must be large enough to hold the hash output for all inputs.
- **Output**: None
- **See also**: [`fd_blake3_hash_many`](blake3_dispatch.c.driver.md#fd_blake3_hash_many)  (Implementation)


---
### fd\_blake3\_simd\_degree<!-- {{#callable_declaration:fd_blake3_simd_degree}} -->
Determine the SIMD degree for BLAKE3 hashing.
- **Description**: This function returns the SIMD (Single Instruction, Multiple Data) degree used by the BLAKE3 hashing algorithm, which indicates the level of parallelism available for processing data. It should be called to understand the degree of parallelism that the BLAKE3 implementation can utilize on the current hardware. The function does not require any initialization or setup before being called and is safe to use at any point in the program. The returned value is dependent on the hardware capabilities, specifically whether AVX (Advanced Vector Extensions) is available.
- **Inputs**: None
- **Output**: Returns the SIMD degree as a size_t value, which is 8 if AVX is available, otherwise 1.
- **See also**: [`fd_blake3_simd_degree`](blake3_dispatch.c.driver.md#fd_blake3_simd_degree)  (Implementation)


---
### fd\_blake3\_compress\_in\_place\_portable<!-- {{#callable_declaration:fd_blake3_compress_in_place_portable}} -->
Compresses a BLAKE3 block in place using a portable implementation.
- **Description**: This function performs an in-place compression of a BLAKE3 block using a portable implementation. It is used to update the chaining value (`cv`) with the compressed result of the input block. This function is typically called as part of the BLAKE3 hashing process, where it processes a single block of input data. The function requires a valid chaining value and block, and it modifies the chaining value directly. It is important to ensure that the `block_len` does not exceed `BLAKE3_BLOCK_LEN` and that the `flags` parameter is set appropriately to indicate the context of the compression (e.g., chunk start, chunk end).
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value. This array is updated in place with the result of the compression. The caller must ensure this array is properly initialized before calling the function.
    - `block`: A constant array of bytes with a length of `BLAKE3_BLOCK_LEN` representing the input block to be compressed. The data in this block is not modified by the function.
    - `block_len`: A uint8_t value representing the length of the block to be compressed. It must not exceed `BLAKE3_BLOCK_LEN`. If the value is invalid, the behavior is undefined.
    - `counter`: A uint64_t value used as a counter in the compression process. It helps in maintaining the state across multiple blocks.
    - `flags`: A uint8_t value representing various internal flags that modify the behavior of the compression. These flags must be set according to the context, such as indicating the start or end of a chunk.
- **Output**: None
- **See also**: [`fd_blake3_compress_in_place_portable`](blake3_portable.c.driver.md#fd_blake3_compress_in_place_portable)  (Implementation)


---
### fd\_blake3\_compress\_xof\_portable<!-- {{#callable_declaration:fd_blake3_compress_xof_portable}} -->
Compresses a BLAKE3 input block into an output array using a portable implementation.
- **Description**: This function performs a compression operation on a BLAKE3 input block, producing a 64-byte output. It is intended for use in cryptographic applications where a portable implementation is required. The function requires a chaining value, an input block, and several parameters that control the compression process. The output is written to a provided buffer. This function should be used when a non-SIMD, portable version of the BLAKE3 compression is needed.
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value. The caller must ensure this array is properly initialized and remains valid for the duration of the call.
    - `block`: A pointer to an array of bytes with a length defined by BLAKE3_BLOCK_LEN, representing the input block to be compressed. The caller must ensure this array is properly initialized and remains valid for the duration of the call.
    - `block_len`: A uint8_t value representing the length of the block. It must not exceed BLAKE3_BLOCK_LEN. The function does not perform any checks on this value, so the caller must ensure it is valid.
    - `counter`: A uint64_t value used as a counter in the compression process. It should be set according to the specific requirements of the BLAKE3 algorithm.
    - `flags`: A uint8_t value representing various flags that modify the behavior of the compression. These flags are defined in the blake3_flags enum and should be set according to the specific requirements of the BLAKE3 algorithm.
    - `out`: A pointer to an array of 64 bytes where the output of the compression will be stored. The caller must ensure this array is properly allocated and remains valid for the duration of the call.
- **Output**: The function writes the result of the compression to the provided 'out' array, which must be 64 bytes in size.
- **See also**: [`fd_blake3_compress_xof_portable`](blake3_portable.c.driver.md#fd_blake3_compress_xof_portable)  (Implementation)


---
### fd\_blake3\_hash\_many\_portable<!-- {{#callable_declaration:fd_blake3_hash_many_portable}} -->
Hashes multiple input blocks using the BLAKE3 algorithm.
- **Description**: This function processes multiple input blocks using the BLAKE3 cryptographic hash function in a portable manner. It is designed to handle a series of input data blocks, applying the BLAKE3 hash algorithm to each block in sequence. The function is suitable for scenarios where multiple data inputs need to be hashed with a consistent key and counter setup. It requires a valid key and outputs the hash results to the specified output buffer. The function can optionally increment the counter after processing each input, which is useful for generating unique hashes for each input block. The caller must ensure that the output buffer is large enough to hold the hash results for all input blocks.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed. The array must contain 'num_inputs' elements, and each input must be non-null.
    - `num_inputs`: The number of input blocks to process. Must be greater than zero.
    - `blocks`: The number of blocks in each input to be processed. Must be a positive integer.
    - `key`: A 256-bit key used for hashing, represented as an array of 8 uint32_t values. Must not be null.
    - `counter`: A 64-bit counter value used in the hashing process. It can be incremented if 'increment_counter' is true.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each input block.
    - `flags`: A set of flags that modify the hashing behavior. These are internal flags specific to the BLAKE3 algorithm.
    - `flags_start`: Flags to be applied at the start of processing each input block.
    - `flags_end`: Flags to be applied at the end of processing each input block.
    - `out`: A pointer to the output buffer where the hash results will be stored. The buffer must be large enough to hold the hash output for all input blocks.
- **Output**: None
- **See also**: [`fd_blake3_hash_many_portable`](blake3_portable.c.driver.md#fd_blake3_hash_many_portable)  (Implementation)


---
### fd\_blake3\_compress\_in\_place\_sse2<!-- {{#callable_declaration:fd_blake3_compress_in_place_sse2}} -->
Compresses a BLAKE3 block in place using SSE2 instructions.
- **Description**: This function performs in-place compression of a BLAKE3 block using SSE2 instructions, updating the chaining value. It is intended for use in environments where SSE2 is supported. The function requires a valid chaining value and block, and it modifies the chaining value based on the provided block, block length, counter, and flags. It is crucial to ensure that the input parameters are correctly initialized and that the block length does not exceed the defined BLAKE3 block length.
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value. This array is updated in place. The caller must ensure it is properly initialized before calling the function.
    - `block`: A constant array of bytes with a length defined by BLAKE3_BLOCK_LEN, representing the input block to be compressed. The caller must ensure this array is correctly populated with the data to be compressed.
    - `block_len`: A uint8_t value representing the length of the block. It must not exceed BLAKE3_BLOCK_LEN. The function does not handle invalid block lengths.
    - `counter`: A uint64_t value used as a counter in the compression process. It should be set according to the specific requirements of the BLAKE3 hashing process.
    - `flags`: A uint8_t value representing various internal flags used during compression. These flags should be set according to the BLAKE3 specification and the specific use case.
- **Output**: None
- **See also**: [`fd_blake3_compress_in_place_sse2`](blake3_sse2.c.driver.md#fd_blake3_compress_in_place_sse2)  (Implementation)


---
### fd\_blake3\_compress\_xof\_sse2<!-- {{#callable_declaration:fd_blake3_compress_xof_sse2}} -->
Performs the BLAKE3 compression function using SSE2 instructions.
- **Description**: This function executes the BLAKE3 compression operation on a given input block using SSE2 instructions, producing a 64-byte output. It is intended for use in environments where SSE2 is supported and provides optimized performance for the BLAKE3 hashing algorithm. The function requires a chaining value, an input block, and several parameters that control the compression process. It is crucial to ensure that the input parameters are correctly set, as invalid values may lead to undefined behavior. The function does not perform any internal validation of the input parameters.
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value. The caller must ensure this array is correctly initialized and not null.
    - `block`: An array of bytes with a length defined by BLAKE3_BLOCK_LEN, representing the input block to be compressed. The caller must ensure this array is correctly initialized and not null.
    - `block_len`: A uint8_t value representing the length of the block. It must not exceed BLAKE3_BLOCK_LEN.
    - `counter`: A uint64_t value used as a counter in the compression process. It should be set according to the specific requirements of the BLAKE3 algorithm.
    - `flags`: A uint8_t value representing various flags that modify the behavior of the compression function. These flags are defined in the blake3_flags enumeration.
    - `out`: An array of 64 bytes where the output of the compression function will be stored. The caller must ensure this array is correctly allocated and not null.
- **Output**: The function writes a 64-byte output to the provided 'out' array.
- **See also**: [`fd_blake3_compress_xof_sse2`](blake3_sse2.c.driver.md#fd_blake3_compress_xof_sse2)  (Implementation)


---
### fd\_blake3\_hash\_many\_sse2<!-- {{#callable_declaration:fd_blake3_hash_many_sse2}} -->
Hashes multiple input blocks using the BLAKE3 algorithm with SSE2 optimizations.
- **Description**: This function processes multiple input blocks using the BLAKE3 cryptographic hash function, optimized for SSE2 instruction sets. It is suitable for hashing large amounts of data in parallel, leveraging SIMD capabilities for improved performance. The function requires a set of input pointers, a key, and various flags to control the hashing process. It is important to ensure that the number of inputs and the output buffer are correctly sized to accommodate the results. The function can optionally increment a counter for each block processed, which is useful for certain cryptographic applications.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed. The array must contain at least 'num_inputs' valid pointers. Must not be null.
    - `num_inputs`: The number of input blocks to process. Must be greater than zero.
    - `blocks`: The number of blocks in each input to be processed. Must be a positive integer.
    - `key`: An array of 8 uint32_t values representing the key used in the hashing process. Must not be null.
    - `counter`: A 64-bit integer used as a counter in the hashing process. It can be incremented if 'increment_counter' is true.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each block.
    - `flags`: A uint8_t value representing internal flags for the hashing process. These flags control specific behaviors of the BLAKE3 algorithm.
    - `flags_start`: A uint8_t value representing flags to be applied at the start of the hashing process.
    - `flags_end`: A uint8_t value representing flags to be applied at the end of the hashing process.
    - `out`: A pointer to a buffer where the hash output will be stored. The buffer must be large enough to hold the output for all input blocks. Must not be null.
- **Output**: None
- **See also**: [`fd_blake3_hash_many_sse2`](blake3_sse2.c.driver.md#fd_blake3_hash_many_sse2)  (Implementation)


---
### fd\_blake3\_compress\_in\_place\_sse41<!-- {{#callable_declaration:fd_blake3_compress_in_place_sse41}} -->
Compresses a BLAKE3 block in place using SSE4.1 instructions.
- **Description**: This function performs in-place compression of a BLAKE3 block using SSE4.1 SIMD instructions, which is suitable for systems supporting these instructions. It is typically used as part of the BLAKE3 hashing process to update the chaining value with a new block of input data. The function requires a valid chaining value and block of data, along with a block length, counter, and flags to control the compression behavior. It is important to ensure that the system supports SSE4.1 instructions before calling this function.
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value. This array is updated in place. Must not be null.
    - `block`: A constant array of bytes with length BLAKE3_BLOCK_LEN representing the input block to be compressed. Must not be null.
    - `block_len`: A uint8_t representing the length of the block. It should be less than or equal to BLAKE3_BLOCK_LEN.
    - `counter`: A uint64_t value used as a counter in the compression process. It can be any 64-bit integer.
    - `flags`: A uint8_t representing various internal flags that modify the compression behavior. These flags are defined in the blake3_flags enum.
- **Output**: None
- **See also**: [`fd_blake3_compress_in_place_sse41`](blake3_sse41.c.driver.md#fd_blake3_compress_in_place_sse41)  (Implementation)


---
### fd\_blake3\_compress\_xof\_sse41<!-- {{#callable_declaration:fd_blake3_compress_xof_sse41}} -->
Compresses a BLAKE3 input block using SSE4.1 instructions.
- **Description**: This function performs a compression operation on a BLAKE3 input block using SSE4.1 instructions, producing a 64-byte output. It is intended for use in environments where SSE4.1 is supported, and is part of the BLAKE3 cryptographic hash function implementation. The function requires a chaining value, an input block, a block length, a counter, and flags to control the compression process. The output is written to a provided buffer, which must be at least 64 bytes in size. This function is typically used internally within the BLAKE3 hashing process and assumes that the input parameters are valid and correctly initialized.
- **Inputs**:
    - `cv`: A pointer to an array of 8 uint32_t values representing the chaining value. The caller retains ownership and it must not be null.
    - `block`: A pointer to an array of bytes with a length defined by BLAKE3_BLOCK_LEN, representing the input block to be compressed. The caller retains ownership and it must not be null.
    - `block_len`: A uint8_t representing the length of the block. It must be less than or equal to BLAKE3_BLOCK_LEN.
    - `counter`: A uint64_t value used as a counter in the compression process. It should be initialized appropriately by the caller.
    - `flags`: A uint8_t representing flags that control the compression process. These flags are defined in the blake3_flags enum and can be combined using bitwise OR.
    - `out`: A pointer to an array of at least 64 bytes where the output will be written. The caller retains ownership and it must not be null.
- **Output**: The function writes a 64-byte output to the provided 'out' buffer.
- **See also**: [`fd_blake3_compress_xof_sse41`](blake3_sse41.c.driver.md#fd_blake3_compress_xof_sse41)  (Implementation)


---
### fd\_blake3\_hash\_many\_sse41<!-- {{#callable_declaration:fd_blake3_hash_many_sse41}} -->
Hashes multiple input blocks using the BLAKE3 algorithm with SSE4.1 optimizations.
- **Description**: This function processes multiple input blocks using the BLAKE3 cryptographic hash function, optimized for SSE4.1 instruction sets. It is suitable for applications requiring fast, parallel hashing of multiple data blocks. The function requires a key, a counter, and specific flags to control the hashing process. It is important to ensure that the number of inputs and the size of the output buffer are correctly specified to avoid buffer overflows or incomplete hashing. The function can increment the counter automatically if specified, which is useful for processing sequential data.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed. The array must contain at least 'num_inputs' valid pointers. Must not be null.
    - `num_inputs`: The number of input blocks to process. Must be greater than zero.
    - `blocks`: The number of blocks in each input. Must be a positive integer.
    - `key`: An array of 8 uint32_t values representing the key for the hash function. Must not be null.
    - `counter`: A 64-bit integer used as a counter in the hashing process. It can be incremented automatically if 'increment_counter' is true.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each input block.
    - `flags`: A uint8_t value representing the flags for the hash function. These control various aspects of the hashing process.
    - `flags_start`: A uint8_t value representing the flags to be used at the start of the hashing process.
    - `flags_end`: A uint8_t value representing the flags to be used at the end of the hashing process.
    - `out`: A pointer to a buffer where the hash output will be stored. The buffer must be large enough to hold the output for all input blocks. Must not be null.
- **Output**: None
- **See also**: [`fd_blake3_hash_many_sse41`](blake3_sse41.c.driver.md#fd_blake3_hash_many_sse41)  (Implementation)


---
### fd\_blake3\_hash\_many\_avx2<!-- {{#callable_declaration:fd_blake3_hash_many_avx2}} -->
Hashes multiple inputs using the BLAKE3 algorithm with AVX2 optimizations.
- **Description**: This function processes multiple input blocks using the BLAKE3 cryptographic hash function, optimized for AVX2 instruction sets. It is designed to handle a batch of inputs efficiently, leveraging SIMD parallelism where possible. The function should be used when hashing multiple data blocks with a common key and counter setup. It requires the caller to provide input data, a key, and a counter, and it outputs the hash results to a specified buffer. The function can optionally increment the counter after processing each block. It is important to ensure that the output buffer is large enough to hold the results for all inputs.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed. The array must contain at least 'num_inputs' elements, and each input must be non-null.
    - `num_inputs`: The number of input blocks to process. Must be greater than or equal to zero.
    - `blocks`: The number of blocks in each input. Must be greater than zero.
    - `key`: An array of 8 uint32_t values representing the key for the hash function. The caller retains ownership and must ensure it is valid for the duration of the call.
    - `counter`: A 64-bit counter value used in the hash computation. It can be incremented if 'increment_counter' is true.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each block.
    - `flags`: A uint8_t value representing internal flags for the hash function. Must be set according to the desired hashing behavior.
    - `flags_start`: A uint8_t value representing flags to be applied at the start of the hash process.
    - `flags_end`: A uint8_t value representing flags to be applied at the end of the hash process.
    - `out`: A pointer to a buffer where the hash results will be stored. The buffer must be large enough to hold the output for all input blocks.
- **Output**: None
- **See also**: [`fd_blake3_hash_many_avx2`](blake3_avx2.c.driver.md#fd_blake3_hash_many_avx2)  (Implementation)


---
### fd\_blake3\_compress\_in\_place\_avx512<!-- {{#callable_declaration:fd_blake3_compress_in_place_avx512}} -->
Compresses a BLAKE3 block in place using AVX-512 instructions.
- **Description**: This function performs an in-place compression of a BLAKE3 block using AVX-512 SIMD instructions, which is part of the BLAKE3 cryptographic hash function. It is intended for use in environments where AVX-512 is supported and provides optimized performance for hashing operations. The function modifies the chaining value array `cv` based on the input block and other parameters. It should be used when processing data blocks as part of the BLAKE3 hashing process, ensuring that the input parameters meet the expected constraints.
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value. This array is modified in place. The caller must ensure it is properly initialized before calling the function.
    - `block`: A constant array of bytes with a length defined by BLAKE3_BLOCK_LEN, representing the input block to be compressed. The data must be valid and properly aligned.
    - `block_len`: A uint8_t value representing the length of the block. It must not exceed BLAKE3_BLOCK_LEN.
    - `counter`: A uint64_t value used as a counter in the compression process. It should be incremented appropriately by the caller for each block processed.
    - `flags`: A uint8_t value representing various internal flags that modify the behavior of the compression. These flags are defined in the blake3_flags enum and can be combined using bitwise OR operations.
- **Output**: None
- **See also**: [`fd_blake3_compress_in_place_avx512`](blake3_avx512.c.driver.md#fd_blake3_compress_in_place_avx512)  (Implementation)


---
### fd\_blake3\_compress\_xof\_avx512<!-- {{#callable_declaration:fd_blake3_compress_xof_avx512}} -->
Performs an AVX-512 optimized BLAKE3 compression operation.
- **Description**: This function executes a BLAKE3 compression operation using AVX-512 instructions, which is part of the BLAKE3 cryptographic hash function. It is designed to process a single block of input data and produce a 64-byte output. This function should be used when AVX-512 support is available and optimal performance is desired. It requires a chaining value, a block of data, a block length, a counter, and flags to control the compression operation. The output is written to a provided buffer. Ensure that the input parameters meet the specified requirements to avoid undefined behavior.
- **Inputs**:
    - `cv`: An array of 8 uint32_t values representing the chaining value. The caller must ensure this array is properly initialized and remains valid for the duration of the function call.
    - `block`: A pointer to an array of bytes with a length of BLAKE3_BLOCK_LEN, representing the input block to be compressed. The caller must ensure this array is properly initialized and remains valid for the duration of the function call.
    - `block_len`: A uint8_t value representing the length of the block. It must not exceed BLAKE3_BLOCK_LEN.
    - `counter`: A uint64_t value used as a counter in the compression operation. It should be properly initialized by the caller.
    - `flags`: A uint8_t value representing flags that modify the behavior of the compression. These flags are defined in the blake3_flags enum and should be set appropriately by the caller.
    - `out`: A pointer to an array of 64 bytes where the output of the compression will be stored. The caller must ensure this array is properly allocated and remains valid for the duration of the function call.
- **Output**: The function writes a 64-byte output to the provided 'out' buffer.
- **See also**: [`fd_blake3_compress_xof_avx512`](blake3_avx512.c.driver.md#fd_blake3_compress_xof_avx512)  (Implementation)


---
### fd\_blake3\_hash\_many\_avx512<!-- {{#callable_declaration:fd_blake3_hash_many_avx512}} -->
Hashes multiple input blocks using the BLAKE3 algorithm with AVX-512 optimization.
- **Description**: This function processes multiple input blocks using the BLAKE3 cryptographic hash function, optimized for AVX-512 capable hardware. It is designed to handle a large number of inputs efficiently by processing them in batches, leveraging SIMD parallelism. The function requires a key, a counter, and various flags to control the hashing process. It is suitable for applications that need to hash multiple data blocks simultaneously, such as in parallel data processing or cryptographic applications. The function must be called with valid input pointers and a sufficiently large output buffer to store the resulting hashes.
- **Inputs**:
    - `inputs`: A pointer to an array of pointers, each pointing to a block of input data to be hashed. The array must contain at least 'num_inputs' valid pointers. Must not be null.
    - `num_inputs`: The number of input blocks to hash. Must be greater than zero.
    - `blocks`: The number of blocks in each input. Must be a positive integer.
    - `key`: An array of 8 uint32_t values representing the key for the hash function. Must not be null.
    - `counter`: A 64-bit counter value used in the hashing process. It can be incremented based on the 'increment_counter' flag.
    - `increment_counter`: A boolean flag indicating whether the counter should be incremented after processing each batch of inputs.
    - `flags`: A uint8_t value representing the flags for the hash function, controlling various aspects of the hashing process.
    - `flags_start`: A uint8_t value representing the starting flags for the hash function.
    - `flags_end`: A uint8_t value representing the ending flags for the hash function.
    - `out`: A pointer to a buffer where the output hashes will be stored. The buffer must be large enough to hold the hashes for all input blocks. Must not be null.
- **Output**: None
- **See also**: [`fd_blake3_hash_many_avx512`](blake3_avx512.c.driver.md#fd_blake3_hash_many_avx512)  (Implementation)


