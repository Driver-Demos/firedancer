# Purpose
This C header file, `fd_fib4_private.h`, is part of a larger system that deals with routing and forwarding information bases, specifically for IPv4 addresses. The file defines private structures and functions related to a Forwarding Information Base (FIB) for IPv4, which is a data structure used in networking to store and manage routing information. The primary structures defined are `fd_fib4_key` and `fd_fib4`, which represent the key components of the FIB, including address prefixes, masks, and priority levels. These structures are aligned according to a specific alignment requirement (`FD_FIB4_ALIGN`), which suggests performance optimization considerations.

The file also provides inline functions to access the key and hop tables within the `fd_fib4` structure. These functions are marked with attributes like `FD_FN_CONST` and `FD_FN_PURE`, indicating that they are pure functions with no side effects, which can be optimized by the compiler. The header is intended for internal use within the system, as indicated by its naming convention and the lack of public API definitions. It is likely included in other source files that implement the logic for managing and utilizing the FIB for routing purposes. The file's focus on alignment and efficient access to data structures suggests an emphasis on performance, which is critical in networking applications.
# Imports and Dependencies

---
- `fd_fib4.h`


# Data Structures

---
### fd\_fib4\_key
- **Type**: `struct`
- **Members**:
    - `addr`: Prefix bits in little endian format, with low bits outside of mask being undefined.
    - `mask`: Bit pattern used for masking.
    - `prio`: Priority value where lower numbers indicate higher priority.
- **Description**: The `fd_fib4_key` structure is designed to represent a key in a forwarding information base (FIB) for IPv4 routing. It contains three fields: `addr`, which holds the prefix bits in a little-endian format; `mask`, which defines the bit pattern for the prefix; and `prio`, which indicates the priority of the key, with lower values representing higher priority. The structure is aligned according to `FD_FIB4_ALIGN` to ensure efficient memory access.


---
### fd\_fib4\_key\_t
- **Type**: `struct`
- **Members**:
    - `addr`: Prefix bits in little endian format, with low bits outside of mask being undefined.
    - `mask`: Bit pattern used for masking.
    - `prio`: Priority value where lower numbers indicate higher priority.
- **Description**: The `fd_fib4_key_t` structure is designed to represent a key in a forwarding information base (FIB) for IPv4 routing. It contains fields for an address (`addr`), a mask (`mask`), and a priority (`prio`). The address is stored in a little-endian format, and the mask is used to determine which bits of the address are significant. The priority field is used to resolve conflicts between multiple routes, with lower values indicating higher priority. The structure is aligned according to `FD_FIB4_ALIGN` to ensure efficient access and manipulation.


---
### fd\_fib4
- **Type**: `struct`
- **Members**:
    - `generation`: A counter indicating the version or state of the data structure.
    - `cnt`: The current number of entries in the data structure.
    - `max`: The maximum number of entries the data structure can hold.
    - `hop_off`: An offset used to locate the hop table within the data structure.
- **Description**: The `fd_fib4` structure is designed to manage a collection of routing entries, specifically for IPv4 forwarding information base (FIB). It includes metadata such as the current generation or version of the data, the count of current entries, and the maximum capacity of entries it can hold. The structure also contains an offset to locate the hop table, which is used for routing decisions. The structure is aligned according to `FD_FIB4_ALIGN` to ensure efficient memory access, and it is followed by arrays of `fd_fib4_key_t` and `fd_fib4_hop_t` which store the actual routing keys and hops, respectively.


# Functions

---
### fd\_fib4\_key\_tbl\_laddr<!-- {{#callable:fd_fib4_key_tbl_laddr}} -->
The function `fd_fib4_key_tbl_laddr` calculates the memory address of the start of the key table within a `fd_fib4_t` structure.
- **Inputs**:
    - `fib`: A pointer to a constant `fd_fib4_t` structure, representing a Forwarding Information Base (FIB) for IPv4 routing.
- **Control Flow**:
    - The function takes a pointer to a `fd_fib4_t` structure as input.
    - It casts the pointer to an unsigned long integer type.
    - It adds the size of the `fd_fib4_t` structure to the casted pointer value.
    - The resulting value, which represents the address of the key table, is returned.
- **Output**: The function returns an unsigned long integer representing the memory address of the key table within the `fd_fib4_t` structure.


---
### fd\_fib4\_hop\_tbl\_laddr<!-- {{#callable:fd_fib4_hop_tbl_laddr}} -->
The function `fd_fib4_hop_tbl_laddr` calculates the memory address of the hop table within a `fd_fib4_t` structure by adding the hop offset to the base address of the structure.
- **Inputs**:
    - `fib`: A pointer to a constant `fd_fib4_t` structure, which contains information about the FIB (Forwarding Information Base) including the hop offset.
- **Control Flow**:
    - The function takes a pointer to a `fd_fib4_t` structure as input.
    - It casts the pointer to an unsigned long integer to get the base address of the structure.
    - It adds the `hop_off` value from the `fd_fib4_t` structure to this base address.
    - The resulting value, which is the address of the hop table, is returned as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the memory address of the hop table within the `fd_fib4_t` structure.


---
### fd\_fib4\_key\_tbl\_const<!-- {{#callable:fd_fib4_key_tbl_const}} -->
The function `fd_fib4_key_tbl_const` returns a constant pointer to the start of the key table within a given FIB4 structure.
- **Inputs**:
    - `fib`: A constant pointer to an `fd_fib4_t` structure, representing a Forwarding Information Base (FIB) for IPv4 routing.
- **Control Flow**:
    - The function calls [`fd_fib4_key_tbl_laddr`](#fd_fib4_key_tbl_laddr) with the `fib` argument to calculate the memory address where the key table starts.
    - It casts the resulting address to a constant pointer of type `fd_fib4_key_t` and returns it.
- **Output**: A constant pointer to `fd_fib4_key_t`, which is the start of the key table in the FIB4 structure.
- **Functions called**:
    - [`fd_fib4_key_tbl_laddr`](#fd_fib4_key_tbl_laddr)


---
### fd\_fib4\_hop\_tbl\_const<!-- {{#callable:fd_fib4_hop_tbl_const}} -->
The `fd_fib4_hop_tbl_const` function returns a constant pointer to the hop table within a given FIB4 structure.
- **Inputs**:
    - `fib`: A constant pointer to an `fd_fib4_t` structure, representing a Forwarding Information Base (FIB) for IPv4 routing.
- **Control Flow**:
    - The function calls [`fd_fib4_hop_tbl_laddr`](#fd_fib4_hop_tbl_laddr) with the `fib` argument to calculate the local address of the hop table within the FIB structure.
    - It casts the result of [`fd_fib4_hop_tbl_laddr`](#fd_fib4_hop_tbl_laddr) to a constant pointer of type `fd_fib4_hop_t`.
    - The function returns this constant pointer.
- **Output**: A constant pointer to an `fd_fib4_hop_t` type, representing the hop table within the FIB structure.
- **Functions called**:
    - [`fd_fib4_hop_tbl_laddr`](#fd_fib4_hop_tbl_laddr)


