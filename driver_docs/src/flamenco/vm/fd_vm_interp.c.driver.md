# Purpose
This C source code file defines two functions, [`fd_vm_exec_notrace`](#fd_vm_exec_notrace) and [`fd_vm_exec_trace`](#fd_vm_exec_trace), which are part of a virtual machine (VM) execution framework. The primary purpose of these functions is to execute a virtual machine's instruction set, with the key difference being that [`fd_vm_exec_trace`](#fd_vm_exec_trace) includes execution and memory tracing capabilities, while [`fd_vm_exec_notrace`](#fd_vm_exec_notrace) does not. Both functions extract necessary variables from a `fd_vm_t` structure, which represents the state of the virtual machine, including the instruction text, call destinations, system calls, memory regions, and registers. The execution logic is encapsulated in an included file, `fd_vm_interp_core.c`, which is presumably a template for the VM's core interpretation logic.

The file is part of a broader system that likely supports different configurations and optimizations, as indicated by the comments suggesting the need for different versions based on alignment checks and tracing options. The functions are designed to be part of a library or module that can be integrated into larger systems, as they rely on external headers (`fd_vm_base.h` and `fd_vm_private.h`) and do not define a `main` function. The use of macros to enable or disable tracing features suggests a flexible design that allows for runtime or compile-time configuration, making the code adaptable to various debugging and performance needs.
# Imports and Dependencies

---
- `fd_vm_base.h`
- `fd_vm_private.h`
- `fd_vm_interp_core.c`


# Functions

---
### fd\_vm\_exec\_notrace<!-- {{#callable:fd_vm_exec_notrace}} -->
The `fd_vm_exec_notrace` function executes a virtual machine instance without enabling execution or memory tracing.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine instance to be executed.
- **Control Flow**:
    - Check if the `vm` pointer is NULL and return an error code `FD_VM_ERR_INVAL` if it is.
    - Extract various configuration and state variables from the `vm` structure, such as `text`, `text_cnt`, `entry_pc`, `calldests`, `syscalls`, `region_haddr`, `region_ld_sz`, `region_st_sz`, `reg`, and `shadow`.
    - Set `frame_max` to a constant `FD_VM_STACK_FRAME_MAX`, with a note to make it runtime configurable in the future.
    - Include and execute the core virtual machine interpreter logic from `fd_vm_interp_core.c`.
    - Return the error code `err`, which is initialized to `FD_VM_SUCCESS`.
- **Output**: The function returns an integer error code, `FD_VM_SUCCESS` on success or `FD_VM_ERR_INVAL` if the `vm` pointer is NULL.


---
### fd\_vm\_exec\_trace<!-- {{#callable:fd_vm_exec_trace}} -->
The `fd_vm_exec_trace` function executes a virtual machine with execution and memory tracing enabled.
- **Inputs**:
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine to be executed.
- **Control Flow**:
    - Check if the `vm` pointer is NULL and return an error code `FD_VM_ERR_INVAL` if it is.
    - Define macros `FD_VM_INTERP_EXE_TRACING_ENABLED` and `FD_VM_INTERP_MEM_TRACING_ENABLED` to enable tracing.
    - Extract various parameters from the `vm` structure needed for execution, such as `text`, `text_cnt`, `entry_pc`, `calldests`, `syscalls`, `region_haddr`, `region_ld_sz`, `region_st_sz`, `reg`, and `shadow`.
    - Set `frame_max` to a constant `FD_VM_STACK_FRAME_MAX`.
    - Include and execute the core interpreter logic from `fd_vm_interp_core.c`.
    - Undefine the tracing macros after execution.
    - Return the error code `err`, which is initialized to `FD_VM_SUCCESS`.
- **Output**: Returns an integer error code, `FD_VM_SUCCESS` on success or `FD_VM_ERR_INVAL` if the `vm` pointer is NULL.


