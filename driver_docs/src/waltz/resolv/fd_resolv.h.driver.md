# Purpose
This code is a C header file that provides function prototypes for DNS resolution operations, specifically within a project or library that uses a custom namespace, indicated by the `fd_` prefix. The file defines two functions, [`fd_dn_expand`](#fd_dn_expand) and [`fd_res_mkquery`](#fd_res_mkquery), both of which are marked with the `__attribute__((__visibility__("hidden")))` attribute, suggesting they are intended for internal use within the library and not exposed to external linkage. The [`fd_dn_expand`](#fd_dn_expand) function appears to be responsible for expanding domain names from a compressed format, while [`fd_res_mkquery`](#fd_res_mkquery) is likely used to construct DNS query messages. The inclusion of `fd_util_base.h` suggests that these functions may rely on utility functions or types defined elsewhere in the project. The use of `FD_PROTOTYPES_BEGIN` and `FD_PROTOTYPES_END` macros indicates a structured approach to managing function prototypes, possibly for compatibility or organizational purposes.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`


# Function Declarations (Public API)

---
### fd\_dn\_expand<!-- {{#callable_declaration:fd_dn_expand}} -->
Expands a compressed domain name to a full domain name.
- **Description**: This function is used to expand a compressed domain name, as found in DNS messages, into a full domain name and store it in a provided buffer. It should be called when you need to interpret DNS message data that uses name compression. The function requires a valid range of memory for the DNS message and a buffer with sufficient space to store the expanded name. It handles edge cases such as pointer loops and ensures the expanded name does not exceed the provided buffer space. If the input is invalid or the buffer is too small, the function returns an error.
- **Inputs**:
    - `base`: Pointer to the start of the DNS message. Must not be null and should point to a valid memory region containing the DNS message.
    - `end`: Pointer to the end of the DNS message. Must not be null and should be greater than or equal to 'base'.
    - `src`: Pointer to the start of the compressed domain name within the DNS message. Must not be null and should be within the range [base, end).
    - `dest`: Pointer to the buffer where the expanded domain name will be stored. Must not be null and should have enough space to store the expanded name.
    - `space`: The size of the buffer pointed to by 'dest'. Must be greater than 0. If the space is insufficient, the function will return an error.
- **Output**: Returns the length of the expanded domain name on success, or -1 if an error occurs (e.g., invalid input or insufficient buffer space).
- **See also**: [`fd_dn_expand`](fd_dn_expand.c.driver.md#fd_dn_expand)  (Implementation)


---
### fd\_res\_mkquery<!-- {{#callable_declaration:fd_res_mkquery}} -->
Constructs a DNS query message.
- **Description**: This function constructs a DNS query message based on the provided parameters and writes it into the specified buffer. It is typically used when preparing to send a DNS query over a network. The function requires a valid domain name, operation code, class, and type to form the query. The buffer must be large enough to hold the constructed query, and the function will return an error if any parameters are out of their valid ranges or if the buffer is insufficiently sized.
- **Inputs**:
    - `op`: The operation code for the DNS query. Valid values are between 0 and 15 inclusive. Values outside this range will result in an error.
    - `dname`: A null-terminated string representing the domain name for the DNS query. The domain name must not end with more than one period, and its length must not exceed 253 characters. The caller retains ownership of this string.
    - `class`: The class of the DNS query, typically 1 for Internet (IN). Valid values are between 0 and 255 inclusive. Values outside this range will result in an error.
    - `type`: The type of the DNS query, such as A, AAAA, MX, etc. Valid values are between 0 and 255 inclusive. Values outside this range will result in an error.
    - `buf`: A pointer to a buffer where the constructed DNS query will be written. The buffer must be pre-allocated by the caller and must be large enough to hold the query.
    - `buflen`: The length of the buffer pointed to by buf. It must be at least as large as the constructed query, otherwise, the function will return an error.
- **Output**: Returns the size of the constructed query on success, or -1 on error if any parameter is invalid or the buffer is too small.
- **See also**: [`fd_res_mkquery`](fd_res_mkquery.c.driver.md#fd_res_mkquery)  (Implementation)


