# Purpose
This C source code file provides functionality for parsing and validating snapshot file names, specifically for a system that manages different types of snapshots, such as full and incremental snapshots. The code defines functions that convert a buffer or a C-style string into a structured `fd_snapshot_name_t` object, which encapsulates details about the snapshot, including its type, slot number, incremental slot number, and a hash derived from the file name. The primary functions, [`fd_snapshot_name_from_buf`](#fd_snapshot_name_from_buf) and [`fd_snapshot_name_from_cstr`](#fd_snapshot_name_from_cstr), handle the parsing of snapshot names, identifying the type of snapshot based on predefined prefixes, and extracting relevant metadata from the file name. The code also includes a validation function, [`fd_snapshot_name_slot_validate`](#fd_snapshot_name_slot_validate), which ensures that incremental snapshots are correctly associated with their corresponding full snapshots by comparing slot numbers.

The file is likely part of a larger system dealing with snapshot management, as indicated by its inclusion of a header file `fd_snapshot_base.h` and its use of specific data types and constants like `FD_SNAPSHOT_TYPE_FULL` and `FD_SNAPSHOT_TYPE_INCREMENTAL`. The code is designed to be integrated into other parts of a software system, providing a narrow but essential functionality focused on snapshot name handling. It does not define a public API or external interface directly but rather offers utility functions that can be used internally within the system to ensure the integrity and correctness of snapshot file naming conventions.
# Imports and Dependencies

---
- `fd_snapshot_base.h`
- `stdlib.h`


# Functions

---
### fd\_snapshot\_name\_from\_buf<!-- {{#callable:fd_snapshot_name_from_buf}} -->
The function `fd_snapshot_name_from_buf` converts a buffer containing a snapshot name into a structured `fd_snapshot_name_t` object.
- **Inputs**:
    - `id`: A pointer to an `fd_snapshot_name_t` structure where the parsed snapshot name will be stored.
    - `str`: A constant character pointer to the buffer containing the snapshot name string.
    - `str_len`: An unsigned long integer representing the length of the string in the buffer.
- **Control Flow**:
    - Declare a character buffer `buf` of size 4096.
    - Determine the minimum of `sizeof(buf)-1` and `str_len` to ensure the buffer does not overflow, and update `str_len` accordingly.
    - Copy `str_len` characters from `str` to `buf` using `fd_memcpy`.
    - Null-terminate the `buf` string by setting `buf[str_len]` to '\0'.
    - Call [`fd_snapshot_name_from_cstr`](#fd_snapshot_name_from_cstr) with `id` and `buf` to parse the snapshot name and return the result.
- **Output**: Returns a pointer to the `fd_snapshot_name_t` structure containing the parsed snapshot name, or `NULL` if parsing fails.
- **Functions called**:
    - [`fd_snapshot_name_from_cstr`](#fd_snapshot_name_from_cstr)


---
### fd\_snapshot\_name\_from\_cstr<!-- {{#callable:fd_snapshot_name_from_cstr}} -->
The function `fd_snapshot_name_from_cstr` parses a snapshot file name string to populate a `fd_snapshot_name_t` structure with snapshot type, slot, incremental slot, and hash information.
- **Inputs**:
    - `id`: A pointer to an `fd_snapshot_name_t` structure that will be populated with parsed data from the snapshot file name.
    - `cstr`: A constant character pointer to the snapshot file name string to be parsed.
- **Control Flow**:
    - Initialize the `fd_snapshot_name_t` structure pointed to by `id` to zero using `fd_memset`.
    - Store the original `cstr` pointer for logging purposes.
    - Find the last occurrence of '/' in `cstr` and adjust `cstr` to point to the character after the last slash if it exists.
    - Check if `cstr` starts with 'snapshot-' or 'incremental-snapshot-' to determine the snapshot type and adjust `cstr` accordingly.
    - If the snapshot type is unrecognized, log a warning and return `NULL`.
    - Parse the slot number from `cstr` using `strtoul` and check for a '-' delimiter; log a warning and return `NULL` if parsing fails.
    - If the snapshot type is incremental, parse the incremental slot number from `cstr` and check for a '-' delimiter; log a warning and return `NULL` if parsing fails.
    - Find the file extension in `cstr` by locating the '.' character; log a warning and return `NULL` if not found.
    - Copy the hash part of `cstr` into a buffer and terminate it properly based on the file extension position.
    - Copy the file extension into the `id->file_ext` field.
    - Decode the base58 hash from the buffer into `id->fhash.hash`; log a warning and return `NULL` if decoding fails.
    - Return the populated `fd_snapshot_name_t` structure pointer `id`.
- **Output**: Returns a pointer to the populated `fd_snapshot_name_t` structure if successful, or `NULL` if parsing fails at any step.


---
### fd\_snapshot\_name\_slot\_validate<!-- {{#callable:fd_snapshot_name_slot_validate}} -->
The function `fd_snapshot_name_slot_validate` checks if the slot of an incremental snapshot matches a given base slot.
- **Inputs**:
    - `id`: A pointer to an `fd_snapshot_name_t` structure representing the snapshot name and its associated metadata.
    - `base_slot`: An unsigned long integer representing the expected base slot number for validation.
- **Control Flow**:
    - Check if the snapshot type in `id` is `FD_SNAPSHOT_TYPE_INCREMENTAL`.
    - If it is incremental, compare `base_slot` with `id->slot`.
    - If `base_slot` does not match `id->slot`, log a warning message and return -1.
    - If the snapshot type is not incremental or the slots match, return 0.
- **Output**: Returns 0 if the snapshot is not incremental or if the base slot matches the snapshot's slot; returns -1 if there is a mismatch for an incremental snapshot.


