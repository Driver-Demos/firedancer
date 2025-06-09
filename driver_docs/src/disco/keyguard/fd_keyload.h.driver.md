# Purpose
This C header file defines a set of functions for securely handling cryptographic keypairs, specifically in the context of reading, loading, and unloading keys from memory. The `fd_keyload_read` function reads a JSON-encoded keypair from a file descriptor, while `fd_keyload_load` reads a key file from disk, storing it in a protected memory page that is resistant to core dumps and paging. The [`fd_keyload_unload`](#fd_keyload_unload) function is used to remove a key from shared memory, ensuring it is no longer accessible. Additionally, [`fd_keyload_alloc_protected_pages`](#fd_keyload_alloc_protected_pages) allocates memory pages with guard pages for enhanced security, preventing unauthorized access and ensuring the memory is not paged out or included in core dumps. This file is crucial for applications requiring secure key management, particularly in environments where sensitive data protection is paramount.
# Imports and Dependencies

---
- `../fd_disco_base.h`


# Global Variables

---
### fd\_keyload\_alloc\_protected\_pages
- **Type**: `function`
- **Description**: The `fd_keyload_alloc_protected_pages` function is designed to allocate a specified number of regular memory pages, each 4 kB in size, that are protected by a specified number of guard pages on each side. These guard pages are unreadable and unwritable, providing a layer of protection against memory access violations. The allocated pages are configured to not be paged out to disk, not appear in core dumps, and be wiped on fork to prevent access by child processes.
- **Use**: This function is used to allocate protected memory pages for secure data handling, ensuring that sensitive information is not exposed through memory dumps or unauthorized access.


# Function Declarations (Public API)

---
### fd\_keyload\_unload<!-- {{#callable_declaration:FD_FN_SENSITIVE::fd_keyload_unload}} -->
Unloads a key from shared memory.
- **Description**: Use this function to unload a key that was previously loaded into shared memory using `fd_keyload_load`. It is crucial that the `public_key_only` parameter matches the value used during the loading process. After calling this function, the key should not be accessed as the memory will no longer be valid. This function ensures that the key is securely removed from memory, preventing any further access or potential leaks.
- **Inputs**:
    - `key`: A pointer to the key in shared memory that was loaded with `fd_keyload_load`. The pointer must not be null and should point to the correct memory location as returned by the load function.
    - `public_key_only`: An integer indicating whether only the public key was loaded (non-zero) or the full key (zero). This must match the value used when the key was loaded.
- **Output**: None
- **See also**: [`FD_FN_SENSITIVE::fd_keyload_unload`](fd_keyload.c.driver.md#FD_FN_SENSITIVEfd_keyload_unload)  (Implementation)


---
### fd\_keyload\_alloc\_protected\_pages<!-- {{#callable_declaration:FD_FN_SENSITIVE::fd_keyload_alloc_protected_pages}} -->
Allocates protected memory pages with guard pages.
- **Description**: This function allocates a specified number of regular memory pages, each 4 kB in size, surrounded by guard pages that are unreadable and unwritable. The allocated memory is configured to prevent paging to disk, appearing in core dumps, and being accessible by child processes after a fork. It is intended for use cases where sensitive data needs to be protected in memory. The function will terminate the process with an error message if the allocation or protection setup fails. The allocated memory is not intended to be freed, as no deallocation function is provided.
- **Inputs**:
    - `page_cnt`: The number of regular 4 kB pages to allocate. Must be a positive integer. The allocated pages will be readable and writable.
    - `guard_page_cnt`: The number of guard pages to allocate on each side of the regular pages. Must be a non-negative integer. These pages will be unreadable and unwritable, providing protection against buffer overflows.
- **Output**: Returns a pointer to the first byte of the allocated protected memory. The memory within the specified range is readable and writable, while the guard pages will cause a SIGSEGV if accessed.
- **See also**: [`FD_FN_SENSITIVE::fd_keyload_alloc_protected_pages`](fd_keyload.c.driver.md#FD_FN_SENSITIVEfd_keyload_alloc_protected_pages)  (Implementation)


