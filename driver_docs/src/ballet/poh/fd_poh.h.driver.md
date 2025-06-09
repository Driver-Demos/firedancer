# Purpose
This C header file defines the interface for a software-based implementation of a Proof-of-History (PoH) hash chain, a concept used in blockchain technologies to provide a verifiable sequence of events. The file includes function prototypes for two primary operations: [`fd_poh_append`](#fd_poh_append), which performs a specified number of recursive hash operations on a given PoH state, and [`fd_poh_mixin`](#fd_poh_mixin), which integrates a 32-byte value into the current PoH state. The header file relies on an external SHA-256 implementation, as indicated by the inclusion of `fd_sha256.h`, to perform the cryptographic hashing operations. The file is structured with include guards to prevent multiple inclusions and uses macros to manage function prototypes, ensuring compatibility and modularity within larger projects.
# Imports and Dependencies

---
- `../sha256/fd_sha256.h`


# Global Variables

---
### fd\_poh\_append
- **Type**: `function pointer`
- **Description**: `fd_poh_append` is a function that performs a specified number of recursive hash operations on a Proof-of-History (PoH) state. It takes a pointer to a 32-byte memory region representing the current PoH state and an unsigned long integer indicating the number of hash operations to perform.
- **Use**: This function is used to update the PoH state by performing multiple hash operations recursively.


---
### fd\_poh\_mixin
- **Type**: `function pointer`
- **Description**: The `fd_poh_mixin` is a function that takes a pointer to a 32-byte memory region representing the current state of a Proof-of-History (PoH) hashchain and a pointer to a 32-byte value to be mixed into this state. It is part of a software-based implementation of the PoH hashchain, which is a cryptographic structure used to verify the passage of time between events.
- **Use**: This function is used to incorporate a new 32-byte value into the existing PoH state, effectively updating the hashchain with additional data.


# Function Declarations (Public API)

---
### fd\_poh\_append<!-- {{#callable_declaration:fd_poh_append}} -->
Perform recursive hash operations on a Proof-of-History state.
- **Description**: This function performs a specified number of recursive hash operations on a Proof-of-History (PoH) state. It is used to advance the PoH state by applying the SHA-256 hash function iteratively. The function should be called when you need to update the PoH state by a given number of hash iterations. The memory region pointed to by the poh parameter must be at least 32 bytes in size and contain the current PoH state. The function returns a pointer to the updated PoH state.
- **Inputs**:
    - `poh`: A pointer to a 32-byte memory region that stores the current PoH state. The caller must ensure this pointer is valid and points to a writable memory region of at least 32 bytes. The function will update this memory region with the new PoH state.
    - `n`: The number of recursive hash operations to perform. It must be a non-negative integer. If n is zero, the function will return immediately without modifying the PoH state.
- **Output**: Returns a pointer to the updated PoH state, which is the same as the input poh pointer.
- **See also**: [`fd_poh_append`](fd_poh.c.driver.md#fd_poh_append)  (Implementation)


---
### fd\_poh\_mixin<!-- {{#callable_declaration:fd_poh_mixin}} -->
Mixes a 32-byte value into the current Proof-of-History state.
- **Description**: This function is used to incorporate an additional 32-byte value into the existing Proof-of-History (PoH) state, which is stored in a 32-byte memory region pointed to by `poh`. It is typically called when there is a need to update the PoH state with new data. The function must be called with valid pointers to ensure correct operation. The `poh` parameter is both an input and output, as it is updated in place with the new state after mixing in the `mixin` value.
- **Inputs**:
    - `poh`: A pointer to a 32-byte memory region that holds the current PoH state. This must not be null and must point to a valid memory region of at least 32 bytes. The caller retains ownership, and the content is updated in place.
    - `mixin`: A pointer to a 32-byte value to be mixed into the PoH state. This must not be null and must point to a valid memory region of at least 32 bytes. The caller retains ownership, and the content is read-only.
- **Output**: Returns the updated `poh` pointer, which now contains the new PoH state after mixing in the `mixin` value.
- **See also**: [`fd_poh_mixin`](fd_poh.c.driver.md#fd_poh_mixin)  (Implementation)


