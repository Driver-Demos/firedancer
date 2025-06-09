# Purpose
This C source code file defines data structures and functions for implementing the Galois/Counter Mode (GCM) of operation for AES encryption. It includes a union `fd_gcm128` for handling 128-bit data, which can be represented using different data types depending on the platform's capabilities. The `fd_aes_gcm_ref_state` structure is defined to maintain the state of the GCM operation, including various components like `Yi`, `EKi`, `EK0`, `len`, `Xi`, `H`, and a precomputed `Htable` for efficient multiplication operations. The file also declares three functions: [`fd_gcm_init_4bit`](#fd_gcm_init_4bit) for initializing the GCM state, [`fd_gcm_gmult_4bit`](#fd_gcm_gmult_4bit) for performing Galois field multiplication, and [`fd_gcm_ghash_4bit`](#fd_gcm_ghash_4bit) for computing the GCM hash. This code is likely part of a cryptographic library focused on providing efficient AES-GCM encryption and decryption capabilities.
# Imports and Dependencies

---
- `fd_aes_base.h`


# Data Structures

---
### fd\_gcm128
- **Type**: `union`
- **Members**:
    - `hi`: Represents the higher 64 bits of a 128-bit value.
    - `lo`: Represents the lower 64 bits of a 128-bit value.
    - `u128`: Represents a 128-bit integer value, available if FD_HAS_INT128 is defined.
- **Description**: The `fd_gcm128` union is a data structure designed to represent a 128-bit value using either two 64-bit unsigned long integers (`hi` and `lo`) or a single 128-bit integer (`u128`) if the platform supports it. This union is used in cryptographic operations, specifically in the Galois/Counter Mode (GCM) of operation for block ciphers, to efficiently handle 128-bit data manipulations. The choice of representation allows for flexibility in environments with or without native 128-bit integer support.


---
### fd\_gcm128\_t
- **Type**: `union`
- **Members**:
    - `hi`: Represents the higher 64 bits of a 128-bit value.
    - `lo`: Represents the lower 64 bits of a 128-bit value.
    - `u128`: Represents the entire 128-bit value as a single entity, available if 128-bit integers are supported.
- **Description**: The `fd_gcm128_t` is a union data structure designed to represent a 128-bit value, which can be accessed either as two separate 64-bit unsigned long integers (`hi` and `lo`) or as a single 128-bit integer (`u128`) if the platform supports 128-bit integers. This structure is used in cryptographic operations, specifically in the Galois/Counter Mode (GCM) of operation for block ciphers, to efficiently handle 128-bit data manipulations.


---
### fd\_aes\_gcm\_ref\_state
- **Type**: `struct`
- **Members**:
    - `Yi`: A union representing a 128-bit value used in GCM specification.
    - `EKi`: A union representing a 128-bit value used in GCM specification.
    - `EK0`: A union representing a 128-bit value used in GCM specification.
    - `len`: A union representing a 128-bit value used in GCM specification.
    - `Xi`: A union representing a 128-bit value used in GCM specification.
    - `H`: A union representing a 128-bit value used in GCM specification.
    - `Htable`: An array of 16 fd_gcm128_t elements used for GCM multiplication.
    - `mres`: An unsigned integer representing message residue.
    - `ares`: An unsigned integer representing additional data residue.
    - `Xn`: An array of 48 unsigned characters used in GCM operations.
    - `key`: An fd_aes_key_ref_t type representing the AES key.
- **Description**: The `fd_aes_gcm_ref_state` structure is a data structure aligned to 64 bytes, designed to hold the state for AES-GCM encryption and decryption operations. It includes several unions representing 128-bit values that are crucial for the GCM (Galois/Counter Mode) specification, such as `Yi`, `EKi`, `EK0`, `len`, `Xi`, and `H`. The structure also contains an array `Htable` of type `fd_gcm128_t` for precomputed values used in GCM multiplication, as well as fields for message and additional data residues (`mres` and `ares`). Additionally, it holds an array `Xn` for intermediate values and a `key` of type `fd_aes_key_ref_t` for the AES encryption key.


---
### fd\_aes\_gcm\_ref\_t
- **Type**: `struct`
- **Members**:
    - `Yi`: A union representing the GCM specification's Yi value with multiple data type views.
    - `EKi`: A union representing the GCM specification's EKi value with multiple data type views.
    - `EK0`: A union representing the GCM specification's EK0 value with multiple data type views.
    - `len`: A union representing the GCM specification's len value with multiple data type views.
    - `Xi`: A union representing the GCM specification's Xi value with multiple data type views.
    - `H`: A union representing the GCM specification's H value with multiple data type views.
    - `Htable`: An array of 16 fd_gcm128_t elements used for GCM hash table computations.
    - `mres`: An unsigned integer representing the message residue.
    - `ares`: An unsigned integer representing the additional data residue.
    - `Xn`: An array of 48 unsigned characters used in GCM computations.
    - `key`: An fd_aes_key_ref_t representing the AES key used in GCM operations.
- **Description**: The `fd_aes_gcm_ref_t` is a structure used in AES-GCM (Galois/Counter Mode) cryptographic operations, aligning with the GCM specification. It contains several unions for different representations of cryptographic values such as Yi, EKi, EK0, len, Xi, and H, which are essential for the GCM algorithm. The structure also includes a hash table `Htable` for efficient multiplication operations, and fields `mres` and `ares` for tracking message and additional data residues. The `Xn` array is used in the GCM process, and the `key` field holds the AES key necessary for encryption and decryption.


# Function Declarations (Public API)

---
### fd\_gcm\_init\_4bit<!-- {{#callable_declaration:fd_gcm_init_4bit}} -->
Initialize a 4-bit GCM hash table.
- **Description**: This function initializes a 4-bit GCM hash table used in Galois/Counter Mode (GCM) cryptographic operations. It should be called to prepare the hash table before performing any GCM operations that require it. The function populates the provided hash table based on the input hash value, which is a critical step in setting up the GCM environment. Ensure that the hash table and the hash value are correctly allocated and initialized before calling this function.
- **Inputs**:
    - `Htable`: An array of 16 fd_gcm128_t elements that will be initialized by the function. The caller must ensure this array is properly allocated and passed by reference.
    - `H`: A pointer to an array of two unsigned long integers representing the hash value. This array must be properly initialized and must not be null, as it provides the initial value for setting up the hash table.
- **Output**: None
- **See also**: [`fd_gcm_init_4bit`](fd_aes_gcm_ref_ghash.c.driver.md#fd_gcm_init_4bit)  (Implementation)


---
### fd\_gcm\_gmult\_4bit<!-- {{#callable_declaration:fd_gcm_gmult_4bit}} -->
Performs a 4-bit Galois field multiplication on a 128-bit block.
- **Description**: This function is used to perform a Galois field multiplication on a 128-bit block represented by the Xi array, using a precomputed table of constants, Htable. It is typically used in cryptographic operations such as Galois/Counter Mode (GCM) for block ciphers. The function modifies the Xi array in place to store the result of the multiplication. It is important to ensure that the Htable has been properly initialized before calling this function, typically using a function like fd_gcm_init_4bit. The function does not return a value, and the caller is responsible for ensuring that the Xi and Htable arrays are correctly sized and aligned.
- **Inputs**:
    - `Xi`: An array of two unsigned long integers representing a 128-bit block. The array is modified in place to store the result of the multiplication. The caller must ensure that this array is properly initialized and aligned.
    - `Htable`: A constant array of 16 fd_gcm128_t elements, representing a precomputed table of constants used for the multiplication. This table must be initialized before calling this function, and the caller retains ownership.
- **Output**: None
- **See also**: [`fd_gcm_gmult_4bit`](fd_aes_gcm_ref_ghash.c.driver.md#fd_gcm_gmult_4bit)  (Implementation)


---
### fd\_gcm\_ghash\_4bit<!-- {{#callable_declaration:fd_gcm_ghash_4bit}} -->
Performs a 4-bit Galois/Counter Mode (GCM) GHASH operation on input data.
- **Description**: This function computes the GHASH operation as part of the Galois/Counter Mode (GCM) encryption process, using a 4-bit table-based approach. It processes the input data in blocks of 128 bits (16 bytes) and updates the provided hash value `Xi` with the result. The function should be called with a precomputed hash table `Htable` and is typically used in cryptographic applications where GCM is employed. The input length `len` must be a multiple of 16, as the function processes data in 16-byte blocks. The caller must ensure that the input data `inp` is valid and that `Xi` and `Htable` are properly initialized before calling this function.
- **Inputs**:
    - `Xi`: An array of two unsigned long integers representing the current hash value. It must be initialized before calling the function, and it will be updated with the result of the GHASH operation.
    - `Htable`: A constant array of 16 `fd_gcm128_t` structures representing the precomputed hash table. It must be initialized using `fd_gcm_init_4bit` before calling this function. The caller retains ownership.
    - `inp`: A pointer to the input data to be hashed. The data must be at least `len` bytes long, and `len` must be a multiple of 16. The caller retains ownership of the data.
    - `len`: The length of the input data in bytes. It must be a multiple of 16, as the function processes data in 16-byte blocks.
- **Output**: None
- **See also**: [`fd_gcm_ghash_4bit`](fd_aes_gcm_ref_ghash.c.driver.md#fd_gcm_ghash_4bit)  (Implementation)


