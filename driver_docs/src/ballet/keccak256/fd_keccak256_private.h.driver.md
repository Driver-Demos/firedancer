# Purpose
This C header file, `fd_keccak256_private.h`, provides a private implementation of the core function for the Keccak-256 cryptographic hash function, which is the basis for the SHA-3 standard. The file defines a static inline function, [`fd_keccak256_core`](#fd_keccak256_core), which performs the Keccak permutation on a given state array. This function is designed to be highly efficient and can be replaced with high-performance computing (HPC) implementations tailored to specific machine capabilities without altering the interface for the caller code. The implementation follows the Keccak specification, utilizing constants and operations such as bitwise rotations and XORs to perform the cryptographic transformations.

The file is structured to be included in other C source files, as indicated by the inclusion guards and the `FD_PROTOTYPES_BEGIN` and `FD_PROTOTYPES_END` macros, which suggest a modular design. The function is not intended to be part of a public API, as it is marked static, meaning it is private to the translation unit in which it is included. The code is focused on the internal workings of the Keccak-256 algorithm, specifically implementing the theta, rho, pi, chi, and iota steps of the Keccak permutation. This file is part of a broader cryptographic library, likely providing foundational cryptographic operations for higher-level functions or applications.
# Imports and Dependencies

---
- `../fd_ballet_base.h`


# Functions

---
### fd\_keccak256\_core<!-- {{#callable:fd_keccak256_core}} -->
The `fd_keccak256_core` function performs the core transformation steps of the Keccak-256 cryptographic hash function on a given state array.
- **Inputs**:
    - `state`: A pointer to an array of unsigned long integers representing the state of the Keccak-256 hash function, which will be transformed in place.
- **Control Flow**:
    - Initialize constants for the 24 rounds of the Keccak permutation, including round constants, rho offsets, and pi indices.
    - Define the number of rounds and a macro for left rotation of unsigned long integers.
    - Iterate over 24 rounds, performing the following steps in each round:
    - Theta step: Calculate parity of columns and update the state based on these parities.
    - Rho and Pi steps: Rotate and permute the state according to predefined constants.
    - Chi step: Apply a non-linear transformation to each row of the state.
    - Iota step: XOR the first element of the state with a round constant.
- **Output**: The function modifies the input state array in place, applying the Keccak-256 permutation to it.


