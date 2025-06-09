# Purpose
The provided C header file, `fd_lthash.h`, defines a set of APIs for a lattice-based incremental hash function that leverages the BLAKE3 cryptographic hash function. This file is part of a larger codebase, as indicated by its inclusion of other headers such as `fd_ballet_base.h` and `fd_blake3.h`. The primary purpose of this file is to offer a specialized hashing mechanism that can be used in applications requiring incremental hashing capabilities, which is particularly useful in scenarios where data is processed in chunks or streams. The file defines a data structure, `fd_lthash_value_t`, which is a union designed to store hash values in both byte and word formats, ensuring alignment with the BLAKE3 hash function's requirements.

The header file provides several inline functions and macros that facilitate the initialization, updating, and finalization of hash computations. Functions like `fd_lthash_init`, `fd_lthash_append`, and [`fd_lthash_fini`](#fd_lthash_fini) are directly mapped to their BLAKE3 counterparts, indicating that the underlying hashing operations are performed using BLAKE3. Additionally, the file includes operations for zeroing, adding, and subtracting hash values, which are implemented using word-level arithmetic. The file also defines macros for encoding hash values into Base58 format and logging operations, which are useful for debugging and tracking hash computations. Overall, this header file serves as a specialized interface for lattice-based hashing operations, providing both low-level hash manipulation functions and higher-level utilities for encoding and logging.
# Imports and Dependencies

---
- `../fd_ballet_base.h`
- `../blake3/fd_blake3.h`


# Data Structures

---
### fd\_lthash\_value
- **Type**: `union`
- **Members**:
    - `bytes`: An array of unsigned characters with a length defined by FD_LTHASH_LEN_BYTES.
    - `words`: An array of unsigned short integers with a length defined by FD_LTHASH_LEN_ELEMS.
- **Description**: The `fd_lthash_value` is a union data structure designed to store hash values in two different formats: as an array of bytes and as an array of words. This allows for flexible manipulation and representation of hash data, which is aligned according to the `FD_LTHASH_ALIGN` specification. The union is used in the context of lattice-based incremental hashing, specifically utilizing the Blake3 hash function, and provides a means to handle hash values in both byte and word formats for various operations such as addition, subtraction, and finalization of hash computations.


---
### fd\_lthash\_value\_t
- **Type**: `union`
- **Members**:
    - `bytes`: An array of unsigned characters with a length defined by FD_LTHASH_LEN_BYTES.
    - `words`: An array of unsigned short integers with a length defined by FD_LTHASH_LEN_ELEMS.
- **Description**: The `fd_lthash_value_t` is a union data structure that provides two different views of the same memory space: one as an array of bytes and the other as an array of words. This allows for flexible manipulation of hash values, which are used in lattice-based incremental hashing operations. The union is aligned according to the `FD_LTHASH_ALIGN` macro, ensuring proper memory alignment for efficient processing.


# Functions

---
### fd\_lthash\_fini<!-- {{#callable:fd_lthash_fini}} -->
The `fd_lthash_fini` function finalizes a lattice-based hash computation using the BLAKE3 algorithm and stores the result in a provided hash structure.
- **Inputs**:
    - `sha`: A pointer to an `fd_lthash_t` structure, which is an alias for `fd_blake3_t`, representing the state of the hash computation.
    - `hash`: A pointer to an `fd_lthash_value_t` structure where the finalized hash value will be stored.
- **Control Flow**:
    - The function calls `fd_blake3_fini_varlen`, passing the `sha` pointer, the `bytes` array from the `hash` structure, and the constant `FD_LTHASH_LEN_BYTES` as arguments.
    - The `fd_blake3_fini_varlen` function finalizes the BLAKE3 hash computation and writes the result into the `bytes` array of the `hash` structure.
- **Output**: The function returns a pointer to the `fd_lthash_value_t` structure containing the finalized hash value.


---
### fd\_lthash\_zero<!-- {{#callable:fd_lthash_zero}} -->
The `fd_lthash_zero` function sets all bytes of a `fd_lthash_value_t` structure to zero.
- **Inputs**:
    - `r`: A pointer to a `fd_lthash_value_t` structure whose bytes are to be set to zero.
- **Control Flow**:
    - The function calls `fd_memset` with the `bytes` field of the `fd_lthash_value_t` structure, a value of 0, and the size `FD_LTHASH_LEN_BYTES` to set all bytes to zero.
    - The function returns the pointer `r` after zeroing its bytes.
- **Output**: A pointer to the `fd_lthash_value_t` structure with all bytes set to zero.


---
### fd\_lthash\_add<!-- {{#callable:fd_lthash_add}} -->
The `fd_lthash_add` function adds corresponding elements of two `fd_lthash_value_t` structures and stores the result in the first structure.
- **Inputs**:
    - `r`: A pointer to an `fd_lthash_value_t` structure where the result of the addition will be stored.
    - `a`: A pointer to a constant `fd_lthash_value_t` structure whose elements will be added to the elements of `r`.
- **Control Flow**:
    - The function iterates over each element of the `words` array in the `fd_lthash_value_t` structure, which has a length defined by `FD_LTHASH_LEN_ELEMS`.
    - For each element, it adds the corresponding elements from the `a` structure to the `r` structure.
    - The result of each addition is cast to a `ushort` and stored back in the `r` structure.
- **Output**: The function returns a pointer to the `fd_lthash_value_t` structure `r`, which now contains the result of the addition.


---
### fd\_lthash\_sub<!-- {{#callable:fd_lthash_sub}} -->
The `fd_lthash_sub` function performs element-wise subtraction of two `fd_lthash_value_t` structures, storing the result in the first structure.
- **Inputs**:
    - `r`: A pointer to an `fd_lthash_value_t` structure where the result of the subtraction will be stored.
    - `a`: A pointer to a constant `fd_lthash_value_t` structure whose elements will be subtracted from the corresponding elements of `r`.
- **Control Flow**:
    - Iterates over each element of the `words` array within the `fd_lthash_value_t` structure.
    - For each element, subtracts the corresponding element in `a` from `r` and stores the result back in `r`.
    - Continues this process for all elements in the `words` array.
- **Output**: Returns a pointer to the `fd_lthash_value_t` structure `r` containing the result of the subtraction.


---
### fd\_lthash\_hash<!-- {{#callable:fd_lthash_hash}} -->
The `fd_lthash_hash` function computes a 32-byte hash of a given `fd_lthash_value_t` structure using the BLAKE3 hashing algorithm, or sets the hash to zero if the input is all zeros.
- **Inputs**:
    - `r`: A pointer to a constant `fd_lthash_value_t` structure, which contains the data to be hashed.
    - `hash`: An array of 32 unsigned characters where the resulting hash will be stored.
- **Control Flow**:
    - Cast the `bytes` array of the input `fd_lthash_value_t` to a pointer to `ulong` for efficient iteration.
    - Iterate over the `ulong` elements of the input data.
    - Check if any `ulong` element is non-zero; if found, initialize a BLAKE3 context, append the input data to it, finalize the hash, and store the result in the `hash` array, then return.
    - If all `ulong` elements are zero, set the `hash` array to all zeros.
- **Output**: The function outputs a 32-byte hash stored in the `hash` array, or a zeroed array if the input data is all zeros.


