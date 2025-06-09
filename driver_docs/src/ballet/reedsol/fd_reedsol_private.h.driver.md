# Purpose
This C header file, `fd_reedsol_private.h`, is part of an implementation of Reed-Solomon error correction codes, specifically focusing on internal encoding and recovery functions. The file is not intended for public API exposure but rather serves as a private component within a larger library, likely used internally by other parts of the system. It provides function declarations for encoding data into parity shreds and recovering data from potentially corrupted or missing shreds. The file includes conditional compilation directives to select different implementations of Galois Field arithmetic, which is crucial for the performance of Reed-Solomon encoding and decoding. These implementations range from unaccelerated to various levels of hardware acceleration using AVX and GFNI instructions, depending on the capabilities of the host system.

The file defines several functions for encoding and recovering data, each tailored to different sizes of data shreds, such as 16, 32, 64, 128, and 256. It also includes functions for generating specific mathematical constructs (Pi and 1/Pi') used in the encoding and recovery processes, based on the presence of erasures. The header file is structured to optimize performance by allowing pre-computed values for common cases, although these are not yet defined. The use of macros and conditional compilation ensures that the most efficient arithmetic implementation is selected at compile time, enhancing the performance of the Reed-Solomon operations. Overall, this file is a specialized component of a Reed-Solomon library, focusing on the internal mechanics of encoding and recovery, with an emphasis on performance optimization through hardware acceleration.
# Imports and Dependencies

---
- `fd_reedsol.h`
- `fd_reedsol_arith_none.h`
- `fd_reedsol_arith_avx2.h`
- `fd_reedsol_arith_gfni.h`


# Function Declarations (Public API)

---
### fd\_reedsol\_private\_encode\_16<!-- {{#callable_declaration:fd_reedsol_private_encode_16}} -->
Generates parity shreds for Reed-Solomon encoding.
- **Description**: This function is used to generate parity shreds for a set of data shreds using Reed-Solomon encoding. It should be called when you have a set of data shreds and need to produce parity shreds for error correction purposes. The function requires that the number of data shreds does not exceed 16. It processes each shred position individually and updates the parity shreds accordingly. The function does not return a value but modifies the parity shreds in place. Ensure that the parity shreds array is properly allocated and that the total number of shreds (data plus parity) does not exceed the implementation limits.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes. Must be a positive integer.
    - `data_shred`: An array of pointers to the data shreds. Each pointer must point to a valid memory location of at least shred_sz bytes. The array must contain data_shred_cnt elements.
    - `data_shred_cnt`: The number of data shreds. Must be between 1 and 16, inclusive.
    - `parity_shred`: An array of pointers to the parity shreds. Each pointer must point to a valid memory location of at least shred_sz bytes. The array must contain parity_shred_cnt elements.
    - `parity_shred_cnt`: The number of parity shreds to generate. Must be a non-negative integer such that data_shred_cnt + parity_shred_cnt does not exceed 16.
- **Output**: None
- **See also**: [`fd_reedsol_private_encode_16`](fd_reedsol_encode_16.c.driver.md#fd_reedsol_private_encode_16)  (Implementation)


---
### fd\_reedsol\_private\_encode\_32<!-- {{#callable_declaration:fd_reedsol_private_encode_32}} -->
Generates parity shreds for Reed-Solomon encoding.
- **Description**: This function is used to generate parity shreds for a set of data shreds using Reed-Solomon encoding. It should be called when you have a set of data shreds and need to compute the corresponding parity shreds for error correction purposes. The function requires that the number of data shreds does not exceed 32. It processes the data in chunks and writes the computed parity shreds to the provided parity shred buffers. The function does not return a value, and it is the caller's responsibility to ensure that the input pointers are valid and that the buffers are appropriately sized.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes. It must be a positive integer.
    - `data_shred`: A pointer to an array of pointers, each pointing to a data shred. The array must contain at least 'data_shred_cnt' valid pointers, and each pointer must point to a buffer of at least 'shred_sz' bytes. The caller retains ownership.
    - `data_shred_cnt`: The number of data shreds. It must be less than or equal to 32.
    - `parity_shred`: A pointer to an array of pointers, each pointing to a parity shred buffer. The array must contain at least 'parity_shred_cnt' valid pointers, and each pointer must point to a buffer of at least 'shred_sz' bytes. The caller retains ownership.
    - `parity_shred_cnt`: The number of parity shreds to generate. It must be a non-negative integer.
- **Output**: None
- **See also**: [`fd_reedsol_private_encode_32`](fd_reedsol_encode_32.c.driver.md#fd_reedsol_private_encode_32)  (Implementation)


---
### fd\_reedsol\_private\_encode\_64<!-- {{#callable_declaration:fd_reedsol_private_encode_64}} -->
Generates parity shreds for Reed-Solomon encoding.
- **Description**: This function is used to generate parity shreds for a set of data shreds using Reed-Solomon encoding. It should be called when you have a set of data shreds and need to produce parity shreds for error correction purposes. The function requires that the number of data shreds does not exceed 64. It processes the data shreds and writes the resulting parity shreds into the provided parity shred buffers. The function does not return a value, and it is the caller's responsibility to ensure that the input parameters meet the required conditions.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes. It must be a positive integer.
    - `data_shred`: A pointer to an array of pointers, each pointing to a data shred. The array must contain at least 'data_shred_cnt' valid pointers, and each pointer must point to a buffer of at least 'shred_sz' bytes. The caller retains ownership of the data.
    - `data_shred_cnt`: The number of data shreds. It must be less than or equal to 64.
    - `parity_shred`: A pointer to an array of pointers, each pointing to a parity shred buffer. The array must contain at least 'parity_shred_cnt' valid pointers, and each pointer must point to a buffer of at least 'shred_sz' bytes. The function writes the generated parity shreds into these buffers.
    - `parity_shred_cnt`: The number of parity shreds to generate. It must be a non-negative integer.
- **Output**: None
- **See also**: [`fd_reedsol_private_encode_64`](fd_reedsol_encode_64.c.driver.md#fd_reedsol_private_encode_64)  (Implementation)


---
### fd\_reedsol\_private\_encode\_128<!-- {{#callable_declaration:fd_reedsol_private_encode_128}} -->
Generates parity shreds for Reed-Solomon encoding.
- **Description**: This function is used to generate parity shreds for a set of data shreds using Reed-Solomon encoding. It should be called when you have a set of data shreds and need to produce parity shreds for error correction purposes. The function requires that the number of data shreds does not exceed 128. It processes each shred position up to the specified shred size, generating the necessary parity shreds and storing them in the provided parity shred buffers. The function does not return a value, and it is expected that the parity shred buffers are pre-allocated and large enough to hold the generated parity data.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes. It must be a positive integer.
    - `data_shred`: A pointer to an array of pointers, each pointing to a data shred. The array must contain at least 'data_shred_cnt' valid pointers, and each data shred must be at least 'shred_sz' bytes long. The caller retains ownership.
    - `data_shred_cnt`: The number of data shreds. It must be less than or equal to 128.
    - `parity_shred`: A pointer to an array of pointers, each pointing to a buffer where parity shreds will be stored. The array must contain at least 'parity_shred_cnt' valid pointers, and each buffer must be at least 'shred_sz' bytes long. The caller retains ownership.
    - `parity_shred_cnt`: The number of parity shreds to generate. It must be a non-negative integer.
- **Output**: None
- **See also**: [`fd_reedsol_private_encode_128`](fd_reedsol_encode_128.c.driver.md#fd_reedsol_private_encode_128)  (Implementation)


---
### fd\_reedsol\_private\_recover\_var\_16<!-- {{#callable_declaration:fd_reedsol_private_recover_var_16}} -->
Recovers missing data from Reed-Solomon encoded shreds.
- **Description**: This function attempts to recover missing data from a set of Reed-Solomon encoded shreds, given the size of each shred, the number of data and parity shreds, and an array indicating which shreds are erased. It requires that at least `data_shred_cnt` of the first 16 shreds are not erased. The function modifies the `shred` array in place, filling in the missing data for shreds marked as erased. It should be used when you need to restore data integrity in a set of shreds where some data might be missing or corrupted. The function returns a status code indicating success, partial recovery, or data corruption.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes. Must be a positive integer.
    - `shred`: An array of pointers to shreds, where each pointer points to a buffer of size `shred_sz`. The array must have at least `data_shred_cnt + parity_shred_cnt` elements.
    - `data_shred_cnt`: The number of data shreds. Must be less than or equal to 16.
    - `parity_shred_cnt`: The number of parity shreds. The sum of `data_shred_cnt` and `parity_shred_cnt` must not exceed 16.
    - `erased`: An array of bytes indicating which shreds are erased (1) or not erased (0). Must have at least `data_shred_cnt + parity_shred_cnt` elements.
- **Output**: Returns `FD_REEDSOL_SUCCESS` on successful recovery, `FD_REEDSOL_ERR_CORRUPT` if the shreds are inconsistent, or `FD_REEDSOL_ERR_PARTIAL` if there is insufficient data to recover the shreds.
- **See also**: [`fd_reedsol_private_recover_var_16`](fd_reedsol_recover_16.c.driver.md#fd_reedsol_private_recover_var_16)  (Implementation)


---
### fd\_reedsol\_private\_recover\_var\_32<!-- {{#callable_declaration:fd_reedsol_private_recover_var_32}} -->
Recovers missing data from Reed-Solomon encoded shreds.
- **Description**: This function is used to verify the consistency of Reed-Solomon encoded data and recover any missing data shreds. It requires at least `data_shred_cnt` un-erased shreds among the first `data_shred_cnt + parity_shred_cnt` shreds. The function modifies the `shred` array in place, filling in the missing data for shreds marked as erased. It should be called when you need to ensure data integrity and recover lost data in a set of shreds. The function returns an error code if the data cannot be recovered due to insufficient un-erased shreds or if the shreds are inconsistent with a valid Reed-Solomon encoding.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes. Must be a positive integer.
    - `shred`: An array of pointers to shreds, where each shred is a byte array of size `shred_sz`. The caller retains ownership, and the function will modify the contents of shreds marked as erased.
    - `data_shred_cnt`: The number of data shreds. Must be less than or equal to 32.
    - `parity_shred_cnt`: The number of parity shreds. The sum of `data_shred_cnt` and `parity_shred_cnt` must not exceed 134.
    - `erased`: An array indicating which shreds are erased (1) and which are not (0). Must have at least `data_shred_cnt + parity_shred_cnt` elements.
- **Output**: Returns `FD_REEDSOL_SUCCESS` if recovery is successful, `FD_REEDSOL_ERR_CORRUPT` if the shreds are inconsistent, or `FD_REEDSOL_ERR_PARTIAL` if there are not enough un-erased shreds to recover the data.
- **See also**: [`fd_reedsol_private_recover_var_32`](fd_reedsol_recover_32.c.driver.md#fd_reedsol_private_recover_var_32)  (Implementation)


---
### fd\_reedsol\_private\_recover\_var\_64<!-- {{#callable_declaration:fd_reedsol_private_recover_var_64}} -->
Recovers missing data from Reed-Solomon encoded shreds.
- **Description**: This function is used to verify the consistency of Reed-Solomon encoded data and recover any missing data shreds. It requires at least `data_shred_cnt` un-erased shreds among the first `data_shred_cnt + parity_shred_cnt` shreds. The function modifies the `shred` array in place, filling in the missing data for shreds marked as erased. It should be called when you need to restore data integrity after some shreds have been lost or corrupted. The function returns a status code indicating success, partial recovery, or data corruption.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes. Must be a positive integer.
    - `shred`: An array of pointers to shreds, where each shred is a byte array of size `shred_sz`. The array must contain at least `data_shred_cnt + parity_shred_cnt` elements. The function modifies this array in place.
    - `data_shred_cnt`: The number of data shreds. Must be less than or equal to 64.
    - `parity_shred_cnt`: The number of parity shreds. The sum of `data_shred_cnt` and `parity_shred_cnt` must not exceed 134.
    - `erased`: An array indicating which shreds are erased (1) or not erased (0). Must have at least `data_shred_cnt + parity_shred_cnt` elements. Values must be either 0 or 1.
- **Output**: Returns `FD_REEDSOL_SUCCESS` on successful recovery, `FD_REEDSOL_ERR_CORRUPT` if the shreds are inconsistent, or `FD_REEDSOL_ERR_PARTIAL` if there is insufficient data to recover the shreds.
- **See also**: [`fd_reedsol_private_recover_var_64`](fd_reedsol_recover_64.c.driver.md#fd_reedsol_private_recover_var_64)  (Implementation)


---
### fd\_reedsol\_private\_recover\_var\_128<!-- {{#callable_declaration:fd_reedsol_private_recover_var_128}} -->
Recovers missing data from Reed-Solomon encoded shreds.
- **Description**: This function attempts to recover missing data from a set of Reed-Solomon encoded shreds, given the size of each shred, the number of data and parity shreds, and an array indicating which shreds are erased. It requires that at least `data_shred_cnt` of the first 128 shreds are un-erased. The function modifies the `shred` array to restore missing data where possible. It should be used when you need to verify and recover data from a potentially incomplete or corrupted set of shreds. The function returns a status code indicating success, partial recovery, or corruption.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes. Must be a positive integer.
    - `shred`: An array of pointers to shreds, where each shred is a byte array of size `shred_sz`. The array must have at least `data_shred_cnt + parity_shred_cnt` elements. The function modifies this array to restore missing data.
    - `data_shred_cnt`: The number of data shreds. Must be less than or equal to 128.
    - `parity_shred_cnt`: The number of parity shreds. The sum of `data_shred_cnt` and `parity_shred_cnt` must not exceed 134.
    - `erased`: An array of bytes indicating the erasure status of each shred. Each element must be 0 if the corresponding shred is valid or 1 if it is erased. The array must have at least `data_shred_cnt + parity_shred_cnt` elements.
- **Output**: Returns an integer status code: `FD_REEDSOL_SUCCESS` if recovery is successful, `FD_REEDSOL_ERR_CORRUPT` if the shreds are inconsistent, or `FD_REEDSOL_ERR_PARTIAL` if there is insufficient data to recover all shreds.
- **See also**: [`fd_reedsol_private_recover_var_128`](fd_reedsol_recover_128.c.driver.md#fd_reedsol_private_recover_var_128)  (Implementation)


---
### fd\_reedsol\_private\_recover\_var\_256<!-- {{#callable_declaration:fd_reedsol_private_recover_var_256}} -->
Recovers missing data from Reed-Solomon encoded shreds.
- **Description**: This function attempts to recover missing data from a set of Reed-Solomon encoded shreds, given the size of each shred, the number of data and parity shreds, and an array indicating which shreds are erased. It requires that at least `data_shred_cnt` of the first `data_shred_cnt + parity_shred_cnt` shreds are un-erased. The function modifies the `shred` array in place, overwriting erased shreds with recovered data. It returns a status code indicating success, partial recovery due to insufficient data, or corruption if the shreds are inconsistent with a valid Reed-Solomon encoding.
- **Inputs**:
    - `shred_sz`: The size of each shred in bytes. Must be a positive integer.
    - `shred`: An array of pointers to shreds, where each pointer points to a buffer of size `shred_sz`. The array must have at least `data_shred_cnt + parity_shred_cnt` elements. The function modifies this array in place.
    - `data_shred_cnt`: The number of data shreds. Must be less than or equal to 256.
    - `parity_shred_cnt`: The number of parity shreds. The sum of `data_shred_cnt` and `parity_shred_cnt` must not exceed 134.
    - `erased`: An array of bytes indicating which shreds are erased (1) or not erased (0). Must have at least `data_shred_cnt + parity_shred_cnt` elements.
- **Output**: Returns `FD_REEDSOL_SUCCESS` on successful recovery, `FD_REEDSOL_ERR_PARTIAL` if there is not enough un-erased data to recover, or `FD_REEDSOL_ERR_CORRUPT` if the shreds are inconsistent with a valid encoding.
- **See also**: [`fd_reedsol_private_recover_var_256`](fd_reedsol_recover_256.c.driver.md#fd_reedsol_private_recover_var_256)  (Implementation)


---
### fd\_reedsol\_private\_gen\_pi\_16<!-- {{#callable_declaration:fd_reedsol_private_gen_pi_16}} -->
Generates Pi and 1/Pi' values for Reed-Solomon erasure codes.
- **Description**: This function computes the Pi and 1/Pi' values for a set of elements used in Reed-Solomon erasure codes, based on whether each element is erased or not. It should be used when you need to determine these values for elements indexed from 0 to 15. The function requires that both input arrays, `is_erased` and `output`, are aligned to 32 bytes. The `is_erased` array must contain only 0s and 1s, where 0 indicates a non-erased element and 1 indicates an erased element. The function will store the Pi value for non-erased elements and the 1/Pi' value for erased elements in the `output` array. Undefined behavior occurs if `is_erased` contains values other than 0 or 1.
- **Inputs**:
    - `is_erased`: A pointer to an array of 16 unsigned characters, each representing whether the corresponding element is erased (1) or not (0). The array must be aligned to 32 bytes and contain only 0s and 1s.
    - `output`: A pointer to an array of 16 unsigned characters where the function will store the computed Pi or 1/Pi' values. The array must be aligned to 32 bytes.
- **Output**: None
- **See also**: [`fd_reedsol_private_gen_pi_16`](fd_reedsol_pi.c.driver.md#fd_reedsol_private_gen_pi_16)  (Implementation)


---
### fd\_reedsol\_private\_gen\_pi\_32<!-- {{#callable_declaration:fd_reedsol_private_gen_pi_32}} -->
Generates Pi and 1/Pi' values for Reed-Solomon erasure codes.
- **Description**: This function computes the Pi and 1/Pi' values for a set of elements used in Reed-Solomon erasure codes, based on whether each element is erased or not. It should be used when you need to determine these values for elements indexed from 0 to 31. The function requires that both input arrays, `is_erased` and `output`, are aligned to 32 bytes. The `is_erased` array must contain only 0s and 1s, where 0 indicates the element is not erased and 1 indicates it is erased. The function will store the computed Pi value in the `output` array for non-erased elements and 1/Pi' for erased elements.
- **Inputs**:
    - `is_erased`: A pointer to an array of 32 bytes, each byte must be either 0 or 1, indicating whether the corresponding element is erased (1) or not (0). The array must be 32-byte aligned.
    - `output`: A pointer to an array of 32 bytes where the function will store the computed Pi or 1/Pi' values. The array must be 32-byte aligned.
- **Output**: None
- **See also**: [`fd_reedsol_private_gen_pi_32`](fd_reedsol_pi.c.driver.md#fd_reedsol_private_gen_pi_32)  (Implementation)


---
### fd\_reedsol\_private\_gen\_pi\_64<!-- {{#callable_declaration:fd_reedsol_private_gen_pi_64}} -->
Generates Pi and 1/Pi' values for Reed-Solomon erasure codes.
- **Description**: This function computes the Pi and 1/Pi' values for a set of elements used in Reed-Solomon erasure codes, based on whether each element is erased or not. It should be used when you need to generate these values for 64 elements, where the erasure status of each element is provided. The function requires that both input arrays, `is_erased` and `output`, are aligned to 32 bytes and indexed from 0 to 63. The function assumes that `is_erased` contains only 0s and 1s, where 0 indicates the element is not erased and 1 indicates it is erased. The output array will store the computed Pi value for non-erased elements and 1/Pi' for erased elements.
- **Inputs**:
    - `is_erased`: A pointer to an array of 64 unsigned characters, each representing whether the corresponding element is erased (1) or not (0). The array must be aligned to 32 bytes and contain only 0s and 1s.
    - `output`: A pointer to an array of 64 unsigned characters where the function will store the computed Pi or 1/Pi' values. The array must be aligned to 32 bytes.
- **Output**: The `output` array is populated with Pi values for non-erased elements and 1/Pi' values for erased elements.
- **See also**: [`fd_reedsol_private_gen_pi_64`](fd_reedsol_pi.c.driver.md#fd_reedsol_private_gen_pi_64)  (Implementation)


---
### fd\_reedsol\_private\_gen\_pi\_128<!-- {{#callable_declaration:fd_reedsol_private_gen_pi_128}} -->
Generates Pi and 1/Pi' values for Reed-Solomon erasure codes.
- **Description**: This function computes the Pi and 1/Pi' values for elements in a Reed-Solomon erasure code, based on whether each element is erased or not. It should be used when you need to generate these values for a set of 128 elements, where the erasure status of each element is known. The function requires that both input arrays, `is_erased` and `output`, are aligned to 32 bytes and indexed from 0 to 127. The function assumes that `is_erased` contains only 0s and 1s, where 0 indicates a non-erased element and 1 indicates an erased element. The output array will store the computed Pi value for non-erased elements and 1/Pi' for erased elements. Undefined behavior occurs if `is_erased` contains values other than 0 or 1.
- **Inputs**:
    - `is_erased`: A pointer to an array of 128 bytes indicating the erasure status of each element. Each byte must be either 0 (not erased) or 1 (erased). The array must be 32-byte aligned.
    - `output`: A pointer to an array of 128 bytes where the function will store the computed Pi or 1/Pi' values. The array must be 32-byte aligned and will be overwritten by the function.
- **Output**: None
- **See also**: [`fd_reedsol_private_gen_pi_128`](fd_reedsol_pi.c.driver.md#fd_reedsol_private_gen_pi_128)  (Implementation)


---
### fd\_reedsol\_private\_gen\_pi\_256<!-- {{#callable_declaration:fd_reedsol_private_gen_pi_256}} -->
Generates Pi and 1/Pi' values for Reed-Solomon erasure codes.
- **Description**: This function computes the Pi and 1/Pi' values for a set of elements used in Reed-Solomon erasure codes, based on whether each element is erased or not. It should be used when you need to generate these values for 256 elements, where the input specifies which elements are erased. The function requires that both input arrays are aligned to 32 bytes. The output array will contain the Pi value for non-erased elements and the 1/Pi' value for erased elements. It is important to ensure that the `is_erased` array only contains values of 0 or 1, as other values will result in undefined behavior.
- **Inputs**:
    - `is_erased`: A pointer to an array of 256 unsigned characters, each indicating whether the corresponding element is erased (1) or not (0). The array must be aligned to 32 bytes and contain only 0s and 1s.
    - `output`: A pointer to an array of 256 unsigned characters where the function will store the computed Pi or 1/Pi' values. The array must be aligned to 32 bytes.
- **Output**: None
- **See also**: [`fd_reedsol_private_gen_pi_256`](fd_reedsol_pi.c.driver.md#fd_reedsol_private_gen_pi_256)  (Implementation)


