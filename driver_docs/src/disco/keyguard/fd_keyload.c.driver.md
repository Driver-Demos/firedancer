# Purpose
This C source code file is designed to securely handle cryptographic key material, specifically for reading, loading, and unloading validator identity keys formatted as a 64-element JSON array. The code provides a focused functionality, primarily dealing with the secure management of sensitive key data. It includes functions to read a key from a file, load it into a protected memory space, and unload it safely. The key is read from a specified file path, parsed, and stored in a memory region that is protected against unauthorized access, such as being paged to disk or included in core dumps. This is achieved through the use of memory protection techniques like `mmap`, `mprotect`, `mlock`, and `madvise`.

The file defines several key functions: `fd_keyload_read`, which reads and parses the key file; `fd_keyload_load`, which allocates protected memory pages and loads the key into them; and [`fd_keyload_unload`](#FD_FN_SENSITIVEfd_keyload_unload), which clears and unmaps the memory when the key is no longer needed. Additionally, [`fd_keyload_alloc_protected_pages`](#FD_FN_SENSITIVEfd_keyload_alloc_protected_pages) is responsible for setting up the memory pages with guard pages to prevent buffer overflows and ensure the key material is not exposed. The code is structured to be part of a larger system, likely a library, given its focus on key management and the absence of a `main` function. It does not define public APIs or external interfaces directly but provides internal functions that are likely used by other components of the system to handle cryptographic keys securely.
# Imports and Dependencies

---
- `fd_keyload.h`
- `errno.h`
- `string.h`
- `fcntl.h`
- `unistd.h`
- `stdio.h`
- `sys/mman.h`


# Functions

---
### read\_key<!-- {{#callable:FD_FN_SENSITIVE::read_key}} -->
The `read_key` function opens a key file from a specified path and reads its contents into a provided buffer.
- **Inputs**:
    - `key_path`: A constant character pointer representing the file path to the key file to be read.
    - `key`: A pointer to an unsigned character array where the key data will be stored.
- **Control Flow**:
    - The function attempts to open the file at the specified `key_path` in read-only mode using `open()`.
    - If the file cannot be opened, it checks if the error is due to the file not existing (`ENOENT`).
    - If the file does not exist, it logs an error message indicating the absence of the key file and suggests generating a new key.
    - If the file exists but cannot be opened for another reason, it logs a generic error message with the error details.
    - If the file is successfully opened, it calls `fd_keyload_read` to read the key data from the file descriptor into the `key` buffer.
- **Output**: The function returns a pointer to the buffer containing the key data, which is the same as the `key` input parameter.


---
### fd\_keyload\_unload<!-- {{#callable:FD_FN_SENSITIVE::fd_keyload_unload}} -->
The `fd_keyload_unload` function securely unloads a key from memory by clearing its contents and unmapping the memory pages used.
- **Inputs**:
    - `key`: A pointer to the key data that needs to be unloaded from memory.
    - `public_key_only`: An integer flag indicating whether only the public key is being used (non-zero) or the full key (zero).
- **Control Flow**:
    - Determine the starting address of the key page based on whether only the public key is used.
    - Calculate the size of the memory region to be unmapped, which includes the key page and additional guard pages.
    - Attempt to change the memory protection of the key page to allow read and write access.
    - If changing memory protection fails, log an error and exit.
    - Clear the contents of the key page using `explicit_bzero` to ensure the key data is erased from memory.
    - Attempt to unmap the memory region starting from the key page minus two guard pages.
    - If unmapping fails, log an error and exit.
- **Output**: This function does not return any value; it performs operations to securely unload and erase key data from memory.


---
### fd\_keyload\_alloc\_protected\_pages<!-- {{#callable:FD_FN_SENSITIVE::fd_keyload_alloc_protected_pages}} -->
The `fd_keyload_alloc_protected_pages` function allocates a specified number of memory pages with additional guard pages for protection, locks them in memory, and configures them to be non-dumpable and wiped on fork.
- **Inputs**:
    - `page_cnt`: The number of pages to allocate for use.
    - `guard_page_cnt`: The number of guard pages to allocate on either side of the usable pages for protection.
- **Control Flow**:
    - Define the page size as 4096 bytes.
    - Use `mmap` to allocate memory for the total number of pages, including guard pages, with read and write permissions.
    - Check if `mmap` failed and log an error if it did.
    - Calculate the starting address of the usable pages by skipping the initial guard pages.
    - Use `mprotect` to set the initial guard pages to be inaccessible (PROT_NONE).
    - Use `mprotect` to set the trailing guard pages to be inaccessible (PROT_NONE).
    - Use `mlock` to lock the usable pages in memory to prevent them from being paged out to disk.
    - Use `madvise` to set the usable pages to be wiped on fork and not included in core dumps.
    - Return the pointer to the start of the usable pages.
- **Output**: A pointer to the start of the allocated usable pages, with guard pages on either side.


