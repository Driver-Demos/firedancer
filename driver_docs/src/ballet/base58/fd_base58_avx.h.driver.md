# Purpose
This C source code file is designed to perform operations related to Base58 encoding using AVX2 SIMD (Single Instruction, Multiple Data) instructions for high-performance vectorized computations. The file is not a standalone header and is intended to be included only in specific source files, namely `fd_base58.c` and `test_base58_avx.c`, as indicated by the absence of an include guard. The code provides specialized functions for loading, storing, and manipulating 256-bit AVX2 registers, which are used to handle data in parallel, thereby optimizing the performance of Base58 encoding operations.

The primary functionality of this file revolves around converting data into Base58 format, a common encoding scheme used in applications like Bitcoin addresses. The code includes functions to convert intermediate vector forms into raw Base58 digits, map these digits to their corresponding Base58 characters, and count leading zeros in byte sequences. Additionally, it provides macros for packing Base58 digits into contiguous AVX2 registers. The use of AVX2 instructions allows for efficient handling of multiple data elements simultaneously, making the code suitable for performance-critical applications that require fast encoding and decoding of Base58 data.
# Imports and Dependencies

---
- `../../util/simd/fd_avx.h`
- `immintrin.h`


# Functions

---
### wuc\_ld<!-- {{#callable:wuc_ld}} -->
The `wuc_ld` function loads a 256-bit vector from a memory address aligned to 32 bytes using AVX2 instructions.
- **Inputs**:
    - `p`: A pointer to an unsigned char array, which should be aligned to 32 bytes for optimal performance.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`, which is suitable for AVX2 operations.
    - It then uses the `_mm256_load_si256` intrinsic to load a 256-bit vector from the memory location pointed to by the casted pointer.
- **Output**: The function returns a `wuc_t` type, which is defined as `__m256i`, representing a 256-bit vector loaded from the specified memory location.


---
### wuc\_ldu<!-- {{#callable:wuc_ldu}} -->
The `wuc_ldu` function loads 256 bits of unaligned data from a given memory address into an AVX2 register.
- **Inputs**:
    - `p`: A pointer to an unaligned memory location of type `uchar` from which 256 bits of data will be loaded.
- **Control Flow**:
    - The function casts the input pointer `p` to a pointer of type `__m256i const *`, which is suitable for AVX2 operations.
    - It then uses the `_mm256_loadu_si256` intrinsic to load 256 bits of data from the unaligned memory location pointed to by `p` into an AVX2 register.
- **Output**: The function returns a `wuc_t` type, which is an alias for `__m256i`, containing the loaded 256 bits of data.


---
### wuc\_st<!-- {{#callable:wuc_st}} -->
The `wuc_st` function stores a 256-bit AVX2 vector into a memory location aligned to 32 bytes.
- **Inputs**:
    - `p`: A pointer to an unsigned char array where the 256-bit vector will be stored.
    - `i`: A 256-bit AVX2 vector of type `wuc_t` to be stored at the memory location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm256_store_si256` intrinsic to store the 256-bit vector `i` into the memory location pointed to by `p`, which must be aligned to 32 bytes.
- **Output**: The function does not return any value; it performs an in-place store operation.


---
### wuc\_stu<!-- {{#callable:wuc_stu}} -->
The `wuc_stu` function stores a 256-bit AVX2 vector into a memory location without alignment requirements.
- **Inputs**:
    - `p`: A pointer to an unsigned char array where the 256-bit vector will be stored.
    - `i`: A 256-bit AVX2 vector of type `wuc_t` to be stored at the location pointed to by `p`.
- **Control Flow**:
    - The function uses the `_mm256_storeu_si256` intrinsic to store the 256-bit vector `i` into the memory location pointed to by `p` without requiring the memory to be aligned.
- **Output**: The function does not return any value; it performs an in-place operation on the memory location pointed to by `p`.


---
### intermediate\_to\_raw<!-- {{#callable:intermediate_to_raw}} -->
The `intermediate_to_raw` function converts a vector of four intermediate form terms into 20 raw base58 digits, compactly stored in an AVX2 register.
- **Inputs**:
    - `intermediate`: A vector of type `wl_t` containing four terms in intermediate form, each representing digits in the range [0, 58^5).
- **Control Flow**:
    - Initialize constants for division by 58 and 58^2 using magic multiplication.
    - Define macros for division by 58 and 58^2 using these constants and bit shifts.
    - Compute successive divisions and remainders to extract base58 digits from the intermediate form.
    - Store the remainders in separate registers, each representing a digit in base58.
    - Shuffle and shift the remainders to compact them into a single AVX2 register, maintaining the correct order of digits.
- **Output**: A `wuc_t` type AVX2 register containing 20 base58 digits, stored in two groups of 10 in the lower 10 bytes of each 128-bit half of the register.


---
### raw\_to\_base58<!-- {{#callable:raw_to_base58}} -->
The `raw_to_base58` function converts each byte in an AVX2 register from raw base58 values [0,58) to base58 character digits ('1'-'z') using arithmetic expressions and SIMD operations.
- **Inputs**:
    - `in`: An AVX2 register (`wuc_t`) containing bytes in the range [0,58) representing raw base58 values.
- **Control Flow**:
    - Initialize five comparison vectors (`gt0` to `gt4`) using `_mm256_cmpgt_epi8` to determine if each byte in `in` exceeds certain thresholds (8, 16, 21, 32, 43).
    - Compute two vectors (`gt0_7` and `gt3_6`) by ANDing the comparison results with -7 and -6, respectively, to create offsets for the base58 conversion.
    - Sum all the negative offsets using `_mm256_add_epi8` to calculate the total adjustment needed for each byte.
    - Subtract the computed sum from the input vector `in` using `_mm256_sub_epi8` to obtain the final base58 character values.
- **Output**: An AVX2 register (`wuc_t`) containing the base58 character values corresponding to the input raw base58 values.


---
### count\_leading\_zeros\_26<!-- {{#callable:count_leading_zeros_26}} -->
The function `count_leading_zeros_26` counts the number of leading zero bytes in a 256-bit AVX2 register up to a maximum of 26 bytes.
- **Inputs**:
    - `in`: A 256-bit AVX2 register (`wuc_t`) containing the data to be analyzed for leading zeros.
- **Control Flow**:
    - The function first compares each byte in the input register `in` with zero using `_mm256_cmpeq_epi8`, resulting in a mask where each byte is either 0xFF (if equal to zero) or 0x00 (if not).
    - The mask is then converted to a 32-bit integer using `_mm256_movemask_epi8`, which creates a bitmask where each bit represents whether the corresponding byte in the input was zero.
    - A mask for the first 27 bits is created using `fd_ulong_mask_lsb(27)`, and the first 26 bits of the zero comparison mask are flipped using XOR with `fd_ulong_mask_lsb(26)`.
    - The function then finds the least significant bit set in the resulting mask using `fd_ulong_find_lsb`, which effectively counts the number of leading zero bytes in the input.
- **Output**: The function returns an `ulong` representing the number of leading zero bytes in the input, up to a maximum of 26.


---
### count\_leading\_zeros\_32<!-- {{#callable:count_leading_zeros_32}} -->
The function `count_leading_zeros_32` calculates the number of leading zero bytes in a 32-byte AVX2 register.
- **Inputs**:
    - `in`: A 32-byte AVX2 register (`wuc_t`) containing the data to be analyzed for leading zero bytes.
- **Control Flow**:
    - The function first compares each byte in the input register `in` with zero using `_mm256_cmpeq_epi8`, resulting in a mask where each byte is either 0xFF (if the byte was zero) or 0x00 (if the byte was non-zero).
    - The `_mm256_movemask_epi8` function is used to create a 32-bit integer mask from the comparison results, where each bit represents whether the corresponding byte in the input was zero.
    - The function then creates a mask with the least significant 33 bits set using `fd_ulong_mask_lsb(33)` and XORs it with the 32-bit integer mask to flip the bits, effectively marking the position of the first non-zero byte.
    - Finally, `fd_ulong_find_lsb` is called to find the position of the least significant set bit in the resulting mask, which corresponds to the number of leading zero bytes in the input.
- **Output**: The function returns an `ulong` representing the number of leading zero bytes in the input register, ranging from 0 to 32.


---
### count\_leading\_zeros\_45<!-- {{#callable:count_leading_zeros_45}} -->
The function `count_leading_zeros_45` calculates the number of leading zero bytes in the first 45 bytes of two 256-bit AVX2 vectors.
- **Inputs**:
    - `in0`: The first 256-bit AVX2 vector containing the first 32 bytes to be checked for leading zeros.
    - `in1`: The second 256-bit AVX2 vector containing the next 13 bytes to be checked for leading zeros.
- **Control Flow**:
    - Compute a mask for `in0` by comparing each byte to zero and converting the result to a bitmask using `_mm256_movemask_epi8`.
    - Compute a mask for `in1` in the same way, but only consider the first 13 bytes by applying a mask with `fd_ulong_mask_lsb(13)` and shifting the result left by 32 bits.
    - Combine the two masks using a bitwise OR operation and XOR the result with a mask that has the least significant 46 bits set to 1 using `fd_ulong_mask_lsb(46)`.
    - Find the least significant bit set in the resulting mask using `fd_ulong_find_lsb`, which indicates the number of leading zero bytes.
- **Output**: The function returns an `ulong` representing the number of leading zero bytes in the first 45 bytes of the input vectors.


---
### count\_leading\_zeros\_64<!-- {{#callable:count_leading_zeros_64}} -->
The `count_leading_zeros_64` function calculates the number of leading zero bytes in two 32-byte AVX2 vectors, returning a count up to 64.
- **Inputs**:
    - `in0`: The first 32-byte AVX2 vector of type `wuc_t` to be analyzed for leading zeros.
    - `in1`: The second 32-byte AVX2 vector of type `wuc_t` to be analyzed for leading zeros.
- **Control Flow**:
    - Compute a mask for `in0` by comparing each byte to zero and converting the result to a bitmask using `_mm256_movemask_epi8`.
    - Compute a mask for `in1` similarly, resulting in a second bitmask.
    - Combine the two masks by shifting the second mask left by 32 bits and performing a bitwise OR with the first mask.
    - Invert the combined mask to prepare for finding the least significant bit set to 1.
    - Use `fd_ulong_find_lsb_w_default` to find the position of the least significant bit set to 1 in the inverted mask, defaulting to 64 if no such bit is found.
- **Output**: The function returns an `ulong` representing the number of leading zero bytes in the combined 64-byte input.


