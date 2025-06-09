# Purpose
This C header file provides utility functions for handling IPv6 addresses that are mapped from IPv4 addresses, a common scenario in dual-stack network environments. It includes three static inline functions: [`fd_ip6_addr_ip4_mapped`](#fd_ip6_addr_ip4_mapped), which constructs an IPv6 address from an IPv4 address by setting the first 10 bytes to zero and the next two bytes to 0xFF, followed by the IPv4 address; [`fd_ip6_addr_is_ip4_mapped`](#fd_ip6_addr_is_ip4_mapped), which checks if a given IPv6 address is an IPv4-mapped address by verifying the specific byte pattern; and [`fd_ip6_addr_to_ip4`](#fd_ip6_addr_to_ip4), which extracts the original IPv4 address from an IPv6 address that is known to be IPv4-mapped. These functions are designed to be efficient and are likely intended for use in performance-critical networking code where inline expansion can reduce function call overhead.
# Imports and Dependencies

---
- `../bits/fd_bits.h`


# Functions

---
### fd\_ip6\_addr\_ip4\_mapped<!-- {{#callable:fd_ip6_addr_ip4_mapped}} -->
The function `fd_ip6_addr_ip4_mapped` converts an IPv4 address into an IPv6 address in the IPv4-mapped IPv6 address format.
- **Inputs**:
    - `ip6_addr`: A 16-byte array where the resulting IPv4-mapped IPv6 address will be stored.
    - `ip4_addr`: A 32-bit unsigned integer representing the IPv4 address to be mapped into IPv6 format.
- **Control Flow**:
    - Initialize the first 10 bytes of the `ip6_addr` array to zero using `memset`.
    - Set the 11th and 12th bytes of `ip6_addr` to 0xff, which is the standard prefix for IPv4-mapped IPv6 addresses.
    - Copy the 4 bytes of the IPv4 address `ip4_addr` into the last 4 bytes of the `ip6_addr` array using `memcpy`.
- **Output**: The function does not return a value; it modifies the `ip6_addr` array in place to contain the IPv4-mapped IPv6 address.


---
### fd\_ip6\_addr\_is\_ip4\_mapped<!-- {{#callable:fd_ip6_addr_is_ip4_mapped}} -->
The function `fd_ip6_addr_is_ip4_mapped` checks if a given IPv6 address is an IPv4-mapped IPv6 address.
- **Inputs**:
    - `ip6_addr`: A constant array of 16 unsigned characters representing an IPv6 address.
- **Control Flow**:
    - The function checks if the first 10 bytes of the `ip6_addr` array are all zero.
    - It then checks if the 11th and 12th bytes are both 0xff.
    - The function returns the result of these checks as a single integer value, which is 1 if all conditions are met (indicating an IPv4-mapped IPv6 address) and 0 otherwise.
- **Output**: An integer value indicating whether the provided IPv6 address is an IPv4-mapped address (1 if true, 0 if false).


---
### fd\_ip6\_addr\_to\_ip4<!-- {{#callable:fd_ip6_addr_to_ip4}} -->
The function `fd_ip6_addr_to_ip4` extracts an IPv4 address from the last 4 bytes of an IPv6 address that is in IPv4-mapped IPv6 format.
- **Inputs**:
    - `ip6_addr`: A constant array of 16 unsigned characters representing an IPv6 address.
- **Control Flow**:
    - Declare a variable `ip4_addr` of type `uint` to store the extracted IPv4 address.
    - Use `memcpy` to copy 4 bytes from the `ip6_addr` array starting at the 13th byte (index 12) into `ip4_addr`.
    - Return the `ip4_addr` as the result of the function.
- **Output**: The function returns a `uint` representing the extracted IPv4 address from the IPv6 address.


