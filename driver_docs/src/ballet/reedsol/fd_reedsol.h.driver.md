# Purpose
The provided C header file, `fd_reedsol.h`, defines a set of APIs for implementing Reed-Solomon encoding and decoding operations, specifically tailored for use within the Solana blockchain's data handling processes. Reed-Solomon codes are a type of error-correcting code that can generate parity data to recover lost or corrupted data. This file provides a highly optimized implementation for encoding data into parity shreds and reconstructing missing data from these parity shreds, operating in the finite field GF(2^8). The file is structured to support a maximum of 67 data and parity shreds, which aligns with Solana's performance requirements.

The file defines a `fd_reedsol_t` structure, which encapsulates the state and data necessary for encoding and recovery operations. It includes functions to initialize, add data and parity shreds, and finalize or abort encoding and recovery processes. The encoding functions allow for the addition of data and parity shreds, while the recovery functions facilitate the reconstruction of missing data from received and erased shreds. Error handling is also addressed, with specific error codes defined for corrupt or partial data recovery scenarios. Additionally, the file provides utility functions for determining memory alignment and footprint requirements, as well as converting error codes to human-readable strings. This header file is intended to be included in other C source files, providing a robust interface for Reed-Solomon coding operations within the Solana ecosystem.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Global Variables

---
### fd\_reedsol\_strerror
- **Type**: ``FD_FN_CONST char const *``
- **Description**: The `fd_reedsol_strerror` function is a global function that converts error codes related to Reed-Solomon operations into human-readable strings. It takes an integer error code as input and returns a constant character pointer to a string describing the error. The returned string is guaranteed to be non-NULL and has an infinite lifetime.
- **Use**: This function is used to provide descriptive error messages for error codes returned by Reed-Solomon operations.


# Data Structures

---
### fd\_reedsol\_private
- **Type**: `struct`
- **Members**:
    - `scratch`: An array of 1024 unsigned characters used for high-performance operations.
    - `shred_sz`: The size of each shred in bytes, ensuring all shreds are the same size.
    - `data_shred_cnt`: The count of data shreds added to the current operation.
    - `parity_shred_cnt`: The count of parity shreds added to the current operation.
    - `encode`: A struct containing pointers to data and parity shreds for encoding operations.
    - `recover`: A struct containing pointers to shreds and an array indicating erased shreds for recovery operations.
- **Description**: The `fd_reedsol_private` structure is designed to facilitate Reed-Solomon encoding and recovery operations, specifically optimized for high-performance scenarios. It includes fields for managing shred sizes and counts, and it uses a union to differentiate between encoding and recovery operations. The encoding part holds pointers to data and parity shreds, while the recovery part manages pointers to all shreds and tracks which shreds are erased. This structure is aligned to `FD_REEDSOL_ALIGN` to meet performance requirements and is integral to the Reed-Solomon implementation for handling data redundancy and recovery in distributed systems.


---
### fd\_reedsol\_t
- **Type**: `struct`
- **Members**:
    - `scratch`: Used for the ultra high performance implementation.
    - `shred_sz`: The size of each shred in bytes, with all shreds required to be the same size.
    - `data_shred_cnt`: The number of data shreds added to the current operation.
    - `parity_shred_cnt`: The number of parity shreds added to the current operation.
    - `encode`: A union member containing pointers to data and parity shreds for encoding operations.
    - `recover`: A union member containing pointers to shreds and an erasure status array for recovery operations.
- **Description**: The `fd_reedsol_t` structure is a private data structure used in the implementation of Reed-Solomon encoding and recovery operations. It is designed to handle operations on data and parity shreds, which are fixed-size pieces of data. The structure includes fields for managing the size and count of these shreds, as well as union members for encoding and recovery operations. The encoding member holds pointers to the data and parity shreds, while the recovery member holds pointers to all shreds and an array indicating which shreds are erased. This structure is aligned to 128 bytes and has a footprint of 2304 bytes, optimized for high-performance operations in the context of Solana's data handling needs.


# Functions

---
### fd\_reedsol\_align<!-- {{#callable:fd_reedsol_align}} -->
The `fd_reedsol_align` function returns the alignment requirement in bytes for a `fd_reedsol_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and should be inlined by the compiler for performance.
    - It returns a constant value defined by the macro `FD_REEDSOL_ALIGN`.
- **Output**: The function outputs an `ulong` representing the alignment requirement in bytes for a `fd_reedsol_t` structure, which is defined as `FD_REEDSOL_ALIGN`.


---
### fd\_reedsol\_footprint<!-- {{#callable:fd_reedsol_footprint}} -->
The `fd_reedsol_footprint` function returns the memory footprint required for a `fd_reedsol_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as an inline function, which suggests it is intended to be expanded in place where it is called, rather than being invoked through a typical function call.
    - It is marked with `FD_FN_CONST`, indicating that it does not read or write any global memory and returns the same result given the same arguments.
    - The function simply returns the value of the macro `FD_REEDSOL_FOOTPRINT`.
- **Output**: The function returns an `ulong` representing the memory footprint size in bytes, specifically `2304UL` as defined by the `FD_REEDSOL_FOOTPRINT` macro.


---
### fd\_reedsol\_encode\_init<!-- {{#callable:fd_reedsol_encode_init}} -->
The `fd_reedsol_encode_init` function initializes a Reed-Solomon encoding operation by setting up a memory structure to store encoding parameters and counters.
- **Inputs**:
    - `mem`: A pointer to a memory block that will be used to store the Reed-Solomon encoding state; it must be properly aligned and sized.
    - `shred_sz`: The size of each shred in bytes, which must be at least 32.
- **Control Flow**:
    - Cast the provided memory pointer `mem` to a `fd_reedsol_t` pointer `rs`.
    - Set the `shred_sz` field of `rs` to the provided `shred_sz` value.
    - Initialize `data_shred_cnt` and `parity_shred_cnt` fields of `rs` to zero, indicating no shreds have been added yet.
    - Return the initialized `fd_reedsol_t` pointer `rs`.
- **Output**: Returns a pointer to the initialized `fd_reedsol_t` structure, which is ready for use in a Reed-Solomon encoding operation.


---
### fd\_reedsol\_encode\_add\_data\_shred<!-- {{#callable:fd_reedsol_encode_add_data_shred}} -->
The `fd_reedsol_encode_add_data_shred` function adds a data shred to an ongoing Reed-Solomon encoding operation.
- **Inputs**:
    - `rs`: A pointer to an initialized `fd_reedsol_t` structure representing the current encoding operation.
    - `ptr`: A constant pointer to the memory location of the data shred to be added.
- **Control Flow**:
    - The function casts the `ptr` to a `uchar const*` and assigns it to the `data_shred` array at the current `data_shred_cnt` index of the `rs` structure.
    - The `data_shred_cnt` is then incremented to reflect the addition of the new data shred.
    - Finally, the function returns the `rs` pointer.
- **Output**: The function returns the same `fd_reedsol_t` pointer that was passed in, now with the added data shred.


---
### fd\_reedsol\_encode\_add\_parity\_shred<!-- {{#callable:fd_reedsol_encode_add_parity_shred}} -->
The function `fd_reedsol_encode_add_parity_shred` adds a memory block as a parity shred to an ongoing Reed-Solomon encoding operation and updates the parity shred count.
- **Inputs**:
    - `rs`: A pointer to a `fd_reedsol_t` structure, which represents the current state of the Reed-Solomon encoding operation.
    - `ptr`: A pointer to the memory block that will be added as a parity shred in the encoding operation.
- **Control Flow**:
    - The function accesses the `encode` union within the `fd_reedsol_t` structure pointed to by `rs`.
    - It assigns the memory block pointed to by `ptr` to the next available slot in the `parity_shred` array.
    - The `parity_shred_cnt` is incremented to reflect the addition of a new parity shred.
    - The function returns the updated `fd_reedsol_t` pointer `rs`.
- **Output**: The function returns the updated `fd_reedsol_t` pointer, which now includes the newly added parity shred.


---
### fd\_reedsol\_encode\_abort<!-- {{#callable:fd_reedsol_encode_abort}} -->
The `fd_reedsol_encode_abort` function aborts an ongoing Reed-Solomon encoding operation by resetting the data and parity shred counts to zero.
- **Inputs**:
    - `rs`: A pointer to an `fd_reedsol_t` structure representing the current Reed-Solomon encoding operation.
- **Control Flow**:
    - The function sets the `data_shred_cnt` field of the `fd_reedsol_t` structure pointed to by `rs` to 0.
    - The function sets the `parity_shred_cnt` field of the `fd_reedsol_t` structure pointed to by `rs` to 0.
- **Output**: The function does not return any value; it modifies the state of the `fd_reedsol_t` structure in place.


---
### fd\_reedsol\_recover\_init<!-- {{#callable:fd_reedsol_recover_init}} -->
The `fd_reedsol_recover_init` function initializes a Reed-Solomon recovery operation by setting up a memory structure to handle shreds of a specified size.
- **Inputs**:
    - `mem`: A pointer to a memory block that will be used to store the `fd_reedsol_t` structure, which must meet specific alignment and size constraints.
    - `shred_sz`: An unsigned long integer representing the size of each shred in bytes, which must be at least 32.
- **Control Flow**:
    - Cast the `mem` pointer to a `fd_reedsol_t` pointer and store it in `rs`.
    - Set the `shred_sz` field of `rs` to the provided `shred_sz` value.
    - Initialize `data_shred_cnt` and `parity_shred_cnt` fields of `rs` to zero.
    - Return the initialized `fd_reedsol_t` pointer `rs`.
- **Output**: Returns a pointer to the initialized `fd_reedsol_t` structure, which is ready for a recovery operation.


---
### fd\_reedsol\_recover\_add\_rcvd\_shred<!-- {{#callable:fd_reedsol_recover_add_rcvd_shred}} -->
The function `fd_reedsol_recover_add_rcvd_shred` adds a received shred to the in-progress Reed-Solomon recovery operation, updating the internal state to track the shred as either data or parity.
- **Inputs**:
    - `rs`: A pointer to a `fd_reedsol_t` structure, which represents the current state of the Reed-Solomon recovery operation.
    - `is_data_shred`: An integer flag indicating whether the shred is a data shred (non-zero) or a parity shred (zero).
    - `ptr`: A constant pointer to the memory location of the shred to be added to the recovery operation.
- **Control Flow**:
    - The function assumes that if `is_data_shred` is true (non-zero), then `rs->parity_shred_cnt` is zero, ensuring that data shreds are added before parity shreds.
    - The function stores the pointer `ptr` in the `rs->recover.shred` array at the index determined by the sum of `rs->data_shred_cnt` and `rs->parity_shred_cnt`.
    - It marks the shred as not erased by setting the corresponding index in `rs->recover.erased` to zero.
    - The function increments `rs->data_shred_cnt` if `is_data_shred` is true, otherwise it increments `rs->parity_shred_cnt`.
    - Finally, the function returns the updated `fd_reedsol_t` pointer `rs`.
- **Output**: The function returns the updated `fd_reedsol_t` pointer `rs`, reflecting the addition of the received shred to the recovery operation.


---
### fd\_reedsol\_recover\_add\_erased\_shred<!-- {{#callable:fd_reedsol_recover_add_erased_shred}} -->
The function `fd_reedsol_recover_add_erased_shred` adds an erased shred to the Reed-Solomon recovery operation, marking it as a data or parity shred based on the input flag.
- **Inputs**:
    - `rs`: A pointer to a `fd_reedsol_t` structure representing the current state of the Reed-Solomon recovery operation.
    - `is_data_shred`: An integer flag indicating whether the shred is a data shred (non-zero) or a parity shred (zero).
    - `ptr`: A pointer to the memory block representing the erased shred to be added to the recovery operation.
- **Control Flow**:
    - The function first calculates the index for the new shred by adding the current data shred count and parity shred count.
    - It assigns the pointer `ptr` to the `shred` array at the calculated index, indicating the location of the erased shred.
    - It sets the corresponding index in the `erased` array to 1, marking the shred as erased.
    - The function increments the `data_shred_cnt` if `is_data_shred` is non-zero, otherwise it increments the `parity_shred_cnt`.
- **Output**: The function returns the updated `fd_reedsol_t` pointer, reflecting the addition of the erased shred to the recovery operation.


---
### fd\_reedsol\_recover\_abort<!-- {{#callable:fd_reedsol_recover_abort}} -->
The `fd_reedsol_recover_abort` function aborts an in-progress Reed-Solomon recovery operation by resetting the data and parity shred counts to zero.
- **Inputs**:
    - `rs`: A pointer to an `fd_reedsol_t` structure representing the current Reed-Solomon recovery operation.
- **Control Flow**:
    - The function takes a pointer to an `fd_reedsol_t` structure as input.
    - It sets the `data_shred_cnt` field of the structure to 0.
    - It sets the `parity_shred_cnt` field of the structure to 0.
- **Output**: The function does not return any value; it modifies the state of the `fd_reedsol_t` structure pointed to by `rs`.


# Function Declarations (Public API)

---
### fd\_reedsol\_encode\_fini<!-- {{#callable_declaration:fd_reedsol_encode_fini}} -->
Completes the Reed-Solomon encoding operation and writes parity data.
- **Description**: This function finalizes an in-progress Reed-Solomon encoding operation, ensuring that the parity shreds are filled with the correct encoded parity data. It should be called after all data and parity shreds have been added using the appropriate functions. Once called, the function releases any read or write interests in the shreds, and the encoder is no longer initialized. This function must be paired with a prior call to `fd_reedsol_encode_init` and should be used in normal execution to complete the encoding process.
- **Inputs**:
    - `rs`: A pointer to an initialized `fd_reedsol_t` structure representing the encoder. It must have been initialized with `fd_reedsol_encode_init` and have data and parity shreds added. The pointer must not be null.
- **Output**: None
- **See also**: [`fd_reedsol_encode_fini`](fd_reedsol.c.driver.md#fd_reedsol_encode_fini)  (Implementation)


---
### fd\_reedsol\_recover\_fini<!-- {{#callable_declaration:fd_reedsol_recover_fini}} -->
Finalizes the Reed-Solomon recovery operation.
- **Description**: This function completes an in-progress Reed-Solomon recovery operation, attempting to reconstruct missing data shreds using available data and parity shreds. It should be called after all necessary shreds have been added using the appropriate functions. The function will reset the shred counts in the provided recovery context and attempt to recover the data. If the recovery is successful, the erased shreds will be filled with the correct data. If the operation fails due to insufficient un-erased data or data inconsistency, the contents of the erased shreds are undefined. The function returns an error code indicating the success or failure of the recovery process.
- **Inputs**:
    - `rs`: A pointer to an initialized fd_reedsol_t structure representing the recovery context. The structure must have been initialized with fd_reedsol_recover_init and have shreds added using fd_reedsol_recover_add_rcvd_shred and fd_reedsol_recover_add_erased_shred. The pointer must not be null.
- **Output**: Returns FD_REEDSOL_SUCCESS on successful recovery, FD_REEDSOL_ERR_CORRUPT if the shreds are inconsistent, or FD_REEDSOL_ERR_PARTIAL if there is insufficient data to recover all data shreds.
- **See also**: [`fd_reedsol_recover_fini`](fd_reedsol.c.driver.md#fd_reedsol_recover_fini)  (Implementation)


---
### fd\_reedsol\_strerror<!-- {{#callable_declaration:fd_reedsol_strerror}} -->
Converts a Reed-Solomon error code to a human-readable string.
- **Description**: Use this function to obtain a human-readable description of a Reed-Solomon error code, which can be useful for logging or debugging purposes. The function accepts an error code and returns a constant string describing the error. It handles known error codes such as success, corrupt, and partial, and returns 'unknown' for any unrecognized error codes. The returned string is always non-null and has an infinite lifetime.
- **Inputs**:
    - `err`: An integer representing a Reed-Solomon error code. Valid values include FD_REEDSOL_SUCCESS, FD_REEDSOL_ERR_CORRUPT, and FD_REEDSOL_ERR_PARTIAL. Any other value will result in the return of 'unknown'.
- **Output**: A constant string describing the error code. The string is non-null and has an infinite lifetime.
- **See also**: [`fd_reedsol_strerror`](fd_reedsol.c.driver.md#fd_reedsol_strerror)  (Implementation)


