# Purpose
The provided C header file, `fd_linux_bpf.h`, offers a set of inline functions that serve as wrappers for the BPF (Berkeley Packet Filter) system calls on Linux. This file is designed to facilitate interaction with BPF maps and objects by providing a higher-level interface to the underlying BPF syscalls. The file includes functions for common BPF operations such as retrieving the next key in a map ([`fd_bpf_map_get_next_key`](#fd_bpf_map_get_next_key)), updating or creating map entries ([`fd_bpf_map_update_elem`](#fd_bpf_map_update_elem)), deleting map entries ([`fd_bpf_map_delete_elem`](#fd_bpf_map_delete_elem)), and managing BPF objects through filesystem paths ([`fd_bpf_obj_get`](#fd_bpf_obj_get) and [`fd_bpf_obj_pin`](#fd_bpf_obj_pin)). Each function is implemented as a static inline function, which suggests that they are intended for use within the same translation unit to minimize function call overhead.

The header file is specifically tailored for Linux environments, as indicated by the conditional compilation directives that check for the presence of Linux-specific macros. It includes necessary system headers such as `<sys/syscall.h>`, `<unistd.h>`, and `<linux/bpf.h>`, which provide the definitions and declarations required for BPF operations. The file does not define a public API in the traditional sense but rather provides utility functions that can be used by other parts of a program to interact with BPF maps and objects. The use of inline functions and direct syscall invocations suggests that this file is intended to be included in other C source files where BPF functionality is needed, rather than being compiled into a standalone library.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`
- `sys/syscall.h`
- `unistd.h`
- `linux/bpf.h`


# Functions

---
### bpf<!-- {{#callable:bpf}} -->
The `bpf` function is a wrapper for the Linux `bpf` syscall, allowing interaction with the BPF (Berkeley Packet Filter) subsystem.
- **Inputs**:
    - `cmd`: An integer representing the specific BPF command to execute.
    - `attr`: A pointer to a `bpf_attr` union, which contains the attributes required for the BPF command.
    - `attr_sz`: An unsigned long representing the size of the `bpf_attr` structure.
- **Control Flow**:
    - The function directly calls the `syscall` function with `SYS_bpf` as the syscall number, passing `cmd`, `attr`, and `attr_sz` as arguments.
    - The `syscall` function executes the BPF syscall with the provided parameters.
- **Output**: The function returns a `long` which is the result of the `syscall` function, typically indicating success or failure of the BPF operation.


---
### fd\_bpf\_map\_get\_next\_key<!-- {{#callable:fd_bpf_map_get_next_key}} -->
The `fd_bpf_map_get_next_key` function retrieves the next key in a BPF map given a current key and map file descriptor.
- **Inputs**:
    - `map_fd`: An integer representing the file descriptor of the BPF map.
    - `key`: A constant pointer to the current key in the BPF map.
    - `next_key`: A pointer where the next key in the BPF map will be stored.
- **Control Flow**:
    - A `bpf_attr` union is initialized with the map file descriptor, current key, and next key pointers.
    - The [`bpf`](#bpf) syscall is invoked with the command `BPF_MAP_GET_NEXT_KEY`, passing the `bpf_attr` union and its size.
    - The function returns the result of the [`bpf`](#bpf) syscall, which is 0 on success or -1 on failure.
- **Output**: The function returns 0 on success, indicating the next key was successfully retrieved, or -1 on failure, with `errno` set to indicate the error (e.g., `ENOENT` if the given key is the last in the map).
- **Functions called**:
    - [`bpf`](#bpf)


---
### fd\_bpf\_map\_update\_elem<!-- {{#callable:fd_bpf_map_update_elem}} -->
The `fd_bpf_map_update_elem` function updates or creates an entry in a BPF map using the BPF_MAP_UPDATE_ELEM operation.
- **Inputs**:
    - `map_fd`: An integer representing the file descriptor of the BPF map.
    - `key`: A constant pointer to the key of the entry to be updated or created, which must match the key size of the map.
    - `value`: A constant pointer to the value to be associated with the key, which must match the value size of the map.
    - `flags`: An unsigned long integer specifying the operation mode, which can be BPF_ANY, BPF_NOEXIST, or BPF_EXIST.
- **Control Flow**:
    - A `bpf_attr` union is initialized with the provided `map_fd`, `key`, `value`, and `flags` values.
    - The [`bpf`](#bpf) function is called with the command `BPF_MAP_UPDATE_ELEM`, the address of the `bpf_attr` union, and the size of the union.
    - The result of the [`bpf`](#bpf) syscall is cast to an integer and returned.
- **Output**: Returns 0 on success and -1 on failure, with `errno` set to indicate the error.
- **Functions called**:
    - [`bpf`](#bpf)


---
### fd\_bpf\_map\_delete\_elem<!-- {{#callable:fd_bpf_map_delete_elem}} -->
The `fd_bpf_map_delete_elem` function deletes an entry from a BPF map using a specified key.
- **Inputs**:
    - `map_fd`: An integer representing the file descriptor of the BPF map from which an entry is to be deleted.
    - `key`: A constant pointer to the key of the entry that needs to be deleted from the BPF map.
- **Control Flow**:
    - A `bpf_attr` union is initialized with the map file descriptor and the key cast to appropriate types.
    - The [`bpf`](#bpf) function is called with the command `BPF_MAP_DELETE_ELEM`, the address of the `bpf_attr` union, and the size of the union.
    - The result of the [`bpf`](#bpf) syscall is returned as an integer.
- **Output**: Returns 0 on successful deletion of the entry, or -1 on failure, with `errno` set to indicate the error (e.g., `ENOENT` if the key does not exist).
- **Functions called**:
    - [`bpf`](#bpf)


---
### fd\_bpf\_obj\_get<!-- {{#callable:fd_bpf_obj_get}} -->
The `fd_bpf_obj_get` function opens a BPF map located at a specified filesystem path and returns a file descriptor for the map.
- **Inputs**:
    - `pathname`: A constant character pointer representing the filesystem path to the BPF map, which must be within a valid bpffs mount and point to a BPF map pinned via BPF_OBJ_PIN.
- **Control Flow**:
    - A `union bpf_attr` structure is initialized with the `pathname` cast to an unsigned long and assigned to the `pathname` field of the union.
    - The [`bpf`](#bpf) function is called with the command `BPF_OBJ_GET`, the address of the `attr` union, and the size of the `union bpf_attr`.
    - The result of the [`bpf`](#bpf) syscall is cast to an integer and returned.
- **Output**: The function returns an integer which is the file descriptor number on success, or a negative integer on failure.
- **Functions called**:
    - [`bpf`](#bpf)


---
### fd\_bpf\_obj\_pin<!-- {{#callable:fd_bpf_obj_pin}} -->
The `fd_bpf_obj_pin` function pins a BPF object to a specified filesystem path using the BPF_OBJ_PIN operation.
- **Inputs**:
    - `bpf_fd`: An integer file descriptor representing the BPF object to be pinned.
    - `pathname`: A constant character pointer to the filesystem path where the BPF object will be pinned.
- **Control Flow**:
    - A union `bpf_attr` is initialized with the `bpf_fd` and `pathname` values cast to `uint` and `ulong`, respectively.
    - The [`bpf`](#bpf) function is called with the command `BPF_OBJ_PIN`, the address of the `attr` union, and the size of the `bpf_attr` union.
    - The result of the [`bpf`](#bpf) syscall is returned as an integer.
- **Output**: Returns 0 on success and -1 on failure, indicating whether the BPF object was successfully pinned to the specified path.
- **Functions called**:
    - [`bpf`](#bpf)


