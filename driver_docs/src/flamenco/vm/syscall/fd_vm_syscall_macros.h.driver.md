# Purpose
This C header file, `fd_vm_syscall_macros.h`, defines a set of macros and inline functions that facilitate the management of virtual machine (VM) resources, specifically focusing on compute units and memory operations. The file is part of a larger system, likely a virtual machine or emulator, that implements a syscall interface. The macros provided in this file are designed to be used by syscall implementations, ensuring they conform to the VM-syscall ABI interface. The primary functionality includes updating compute units, translating virtual addresses to host addresses, and performing memory operations with various levels of safety checks. These operations are crucial for managing the execution environment of the VM, ensuring that resources are allocated and accessed correctly, and that errors are handled gracefully.

The file includes macros for charging compute units (`FD_VM_CU_UPDATE` and `FD_VM_CU_MEM_OP_UPDATE`), which are essential for tracking the computational budget of the VM. It also provides macros for memory address translation (`FD_VM_MEM_HADDR_LD`, `FD_VM_MEM_HADDR_ST`, etc.), which convert virtual addresses to host addresses, allowing the VM to interact with the host's memory. These macros include checks for alignment, size, and access violations, ensuring robust error handling. Additionally, the file includes mechanisms to prevent overlapping memory operations, which could lead to data corruption. Overall, this header file is a critical component of the VM's syscall infrastructure, providing essential utilities for resource management and error handling.
# Imports and Dependencies

---
- `../fd_vm_private.h`


# Functions

---
### FD\_VM\_MEM\_HADDR\_ST\_<!-- {{#callable:FD_VM_MEM_HADDR_ST_}} -->
The `FD_VM_MEM_HADDR_ST_` function translates a virtual memory address to a host address for a writable memory region, ensuring alignment and size constraints are met, and returns an error code if any checks fail.
- **Inputs**:
    - `vm`: A pointer to a constant `fd_vm_t` structure representing the virtual machine context.
    - `vaddr`: An unsigned long integer representing the virtual address to be translated.
    - `align`: An unsigned long integer specifying the required alignment for the host address.
    - `sz`: An unsigned long integer representing the size of the memory region to be accessed.
    - `err`: A pointer to an integer where the function will store an error code if an error occurs.
- **Control Flow**:
    - Initialize local variables `_vm`, `_is_multi`, `_vaddr`, and `_haddr` using the input parameters and a call to `fd_vm_mem_haddr` to translate the virtual address to a host address.
    - Check if the size `sz` exceeds `LONG_MAX`, log an error, set `*err` to `FD_VM_SYSCALL_ERR_SEGFAULT`, and return `0` if true.
    - Check if `_haddr` is `0` or if `_is_multi` is true, log an error, set `*err` to `FD_VM_SYSCALL_ERR_SEGFAULT`, and return `0` if true.
    - Check if `_sigbus` is true, indicating a misalignment, log an error, set `*err` to `FD_VM_SYSCALL_ERR_SEGFAULT`, and return `0` if true.
    - Return the translated host address `_haddr` cast to a `void *` if all checks pass.
- **Output**: Returns a `void *` pointer to the translated host address if successful, or `0` if an error occurs, with the error code stored in `*err`.


