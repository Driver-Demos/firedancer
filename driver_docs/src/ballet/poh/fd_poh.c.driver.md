# Purpose
This C source code file defines two functions, [`fd_poh_append`](#fd_poh_append) and [`fd_poh_mixin`](#fd_poh_mixin), which are likely part of a cryptographic or hashing library, as suggested by the inclusion of "fd_poh.h" and the use of SHA-256 hashing functions. The [`fd_poh_append`](#fd_poh_append) function repeatedly hashes a given pointer `poh` using the SHA-256 algorithm for a specified number of iterations `n`, effectively transforming the input data through multiple hash operations. The [`fd_poh_mixin`](#fd_poh_mixin) function combines the hash of the input `poh` with an additional data `mixin`, producing a new hash that incorporates both inputs. These functions are designed to manipulate and transform data using cryptographic hashing, potentially for purposes such as data integrity verification or blockchain-related operations.
# Imports and Dependencies

---
- `fd_poh.h`


# Functions

---
### fd\_poh\_append<!-- {{#callable:fd_poh_append}} -->
The `fd_poh_append` function repeatedly hashes a given buffer using SHA-256 for a specified number of iterations.
- **Inputs**:
    - `poh`: A pointer to the buffer that will be hashed repeatedly.
    - `n`: An unsigned long integer representing the number of times the buffer should be hashed.
- **Control Flow**:
    - The function enters a while loop that continues as long as 'n' is greater than zero.
    - Within each iteration of the loop, the function calls `fd_sha256_hash_32`, passing the buffer 'poh' as both the input and output, effectively hashing the buffer in place.
    - The loop decrements 'n' after each iteration, eventually terminating when 'n' reaches zero.
- **Output**: The function returns the pointer 'poh', which now contains the result of the repeated hashing operations.


---
### fd\_poh\_mixin<!-- {{#callable:fd_poh_mixin}} -->
The `fd_poh_mixin` function combines a given hash with a mixin using SHA-256 and updates the original hash with the result.
- **Inputs**:
    - `poh`: A pointer to the original hash data that will be updated with the mixin.
    - `mixin`: A pointer to the mixin data that will be combined with the original hash.
- **Control Flow**:
    - Initialize a SHA-256 context using `fd_sha256_init`.
    - Append the original hash data (`poh`) to the SHA-256 context using `fd_sha256_append`.
    - Append the mixin data to the SHA-256 context using `fd_sha256_append`.
    - Finalize the SHA-256 hash computation and store the result back in the original hash location (`poh`) using `fd_sha256_fini`.
    - Return the updated hash pointer (`poh`).
- **Output**: A pointer to the updated hash data, which is the result of mixing the original hash with the mixin using SHA-256.


