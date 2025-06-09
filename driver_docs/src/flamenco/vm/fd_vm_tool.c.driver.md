# Purpose
This C source code file is designed to handle operations related to a virtual machine (VM) environment, specifically for processing and executing programs in a binary format. The file provides a set of functionalities that include disassembling, validating, tracing, and running binary programs. The core functionality revolves around reading a binary file, extracting its ELF (Executable and Linkable Format) information, and preparing it for execution within a VM context. The code defines a structure `fd_vm_tool_prog_t` to encapsulate the program's binary buffer, the program itself, and associated syscalls, which are essential for managing the execution environment.

The file includes several command functions ([`cmd_disasm`](#cmd_disasm), [`cmd_validate`](#cmd_validate), [`cmd_trace`](#cmd_trace), and [`cmd_run`](#cmd_run)) that perform specific tasks on the binary program, such as disassembling the program to human-readable instructions, validating the program's integrity, tracing its execution for debugging purposes, and running the program with input data. The [`main`](#main) function serves as the entry point, parsing command-line arguments to determine which operation to perform. The code is structured to be part of a larger application, likely a command-line tool, that interacts with a virtual machine framework to manage and execute binary programs. The use of external libraries and functions, such as `fd_sbpf_program_load` and `fd_vm_exec`, indicates that this file is part of a broader system that supports program execution in a simulated environment.
# Imports and Dependencies

---
- `fd_vm_base.h`
- `fd_vm_private.h`
- `stdio.h`
- `stdlib.h`
- `errno.h`
- `sys/stat.h`


# Data Structures

---
### fd\_vm\_tool\_prog
- **Type**: `struct`
- **Members**:
    - `bin_buf`: A pointer to a buffer containing the binary data of the program.
    - `prog`: A pointer to an fd_sbpf_program_t structure representing the loaded program.
    - `syscalls`: A pointer to an fd_sbpf_syscalls_t structure representing the system calls available to the program.
- **Description**: The `fd_vm_tool_prog` structure is designed to encapsulate the necessary components for managing and executing a virtual machine program. It includes a buffer for the binary data of the program, a pointer to the program structure that contains the executable code and metadata, and a pointer to the syscalls structure that provides the system call interface for the program. This structure is used to facilitate operations such as disassembly, validation, tracing, and execution of the program within a virtual machine environment.


---
### fd\_vm\_tool\_prog\_t
- **Type**: `struct`
- **Members**:
    - `bin_buf`: A pointer to a buffer holding the binary data of the program.
    - `prog`: A pointer to an fd_sbpf_program_t structure representing the loaded program.
    - `syscalls`: A pointer to an fd_sbpf_syscalls_t structure managing the system calls for the program.
- **Description**: The `fd_vm_tool_prog_t` structure is designed to encapsulate the necessary components for managing and executing a virtual machine program. It includes a buffer for the binary data, a program structure for the loaded program, and a syscalls structure for handling system calls. This structure is used in various operations such as disassembly, validation, tracing, and execution of the program, providing a cohesive way to manage the program's lifecycle and interactions with the system.


# Functions

---
### fd\_vm\_tool\_prog\_create<!-- {{#callable:fd_vm_tool_prog_create}} -->
The `fd_vm_tool_prog_create` function initializes a `fd_vm_tool_prog_t` structure by loading and preparing an ELF binary file for execution in a virtual machine environment.
- **Inputs**:
    - `tool_prog`: A pointer to an `fd_vm_tool_prog_t` structure that will be initialized with the program data.
    - `bin_path`: A constant character pointer representing the file path to the binary ELF file to be loaded.
- **Control Flow**:
    - Open the binary file specified by `bin_path` for reading.
    - Check if the file is successfully opened; if not, log an error and exit.
    - Retrieve file statistics using `fstat` to ensure it is a regular file; log an error if it is not.
    - Allocate a buffer to hold the file's contents plus an additional 8 bytes for alignment.
    - Read the entire file into the allocated buffer; log an error if reading fails.
    - Close the file after reading its contents.
    - Extract ELF information from the binary buffer using `fd_sbpf_elf_peek`.
    - Allocate memory for the read-only data segment based on the ELF information.
    - Determine the alignment and footprint for the program buffer, then allocate and initialize it using `fd_sbpf_program_new`.
    - Allocate and initialize the syscalls structure using `fd_sbpf_syscalls_new` and register all syscalls.
    - Load the program into the virtual machine environment using `fd_sbpf_program_load`; log an error if loading fails.
    - Assign the allocated buffers and structures to the `tool_prog` fields.
    - Return the initialized `tool_prog` structure.
- **Output**: Returns a pointer to the initialized `fd_vm_tool_prog_t` structure containing the loaded program and associated resources.
- **Functions called**:
    - [`fd_vm_syscall_register_all`](fd_vm_base.h.driver.md#fd_vm_syscall_register_all)


---
### fd\_vm\_tool\_prog\_free<!-- {{#callable:fd_vm_tool_prog_free}} -->
The `fd_vm_tool_prog_free` function deallocates memory associated with a `fd_vm_tool_prog_t` structure, including its program, binary buffer, and syscalls.
- **Inputs**:
    - `prog`: A pointer to an `fd_vm_tool_prog_t` structure whose resources are to be freed.
- **Control Flow**:
    - The function begins by freeing the read-only data segment (`rodata`) of the program contained within the `prog` structure.
    - It then frees the binary buffer (`bin_buf`) associated with the `prog` structure.
    - The function calls `fd_sbpf_program_delete` to delete the program and frees the returned pointer.
    - Finally, it calls `fd_sbpf_syscalls_delete` to delete the syscalls and frees the returned pointer.
- **Output**: This function does not return any value; it performs cleanup by freeing allocated memory.


---
### cmd\_disasm<!-- {{#callable:cmd_disasm}} -->
The `cmd_disasm` function disassembles a binary program file and prints the disassembled output to the console.
- **Inputs**:
    - `bin_path`: A constant character pointer representing the path to the binary file to be disassembled.
- **Control Flow**:
    - Initialize a `fd_vm_tool_prog_t` structure named `tool_prog` and create it using [`fd_vm_tool_prog_create`](#fd_vm_tool_prog_create) with the provided `bin_path`.
    - Calculate the maximum output buffer size `out_max` as 128 times the number of text instructions in the program.
    - Allocate memory for the output buffer `out` with size `out_max` and check for successful allocation.
    - Call [`fd_vm_disasm_program`](fd_vm_disasm.c.driver.md#fd_vm_disasm_program) to disassemble the program's text section, storing the disassembled output in `out` and updating `out_len` with the length of the output.
    - Print the disassembled output stored in `out` to the console using `puts`.
    - Free the allocated memory for `out`.
    - Free the resources associated with `tool_prog` using [`fd_vm_tool_prog_free`](#fd_vm_tool_prog_free).
    - Return the error code from [`fd_vm_disasm_program`](fd_vm_disasm.c.driver.md#fd_vm_disasm_program).
- **Output**: The function returns an integer error code from the [`fd_vm_disasm_program`](fd_vm_disasm.c.driver.md#fd_vm_disasm_program) function, indicating success or failure of the disassembly process.
- **Functions called**:
    - [`fd_vm_tool_prog_create`](#fd_vm_tool_prog_create)
    - [`fd_vm_disasm_program`](fd_vm_disasm.c.driver.md#fd_vm_disasm_program)
    - [`fd_vm_tool_prog_free`](#fd_vm_tool_prog_free)


---
### cmd\_validate<!-- {{#callable:cmd_validate}} -->
The `cmd_validate` function validates a binary program file by creating a virtual machine (VM) environment and checking its correctness.
- **Inputs**:
    - `bin_path`: A constant character pointer representing the file path to the binary program that needs to be validated.
- **Control Flow**:
    - Create a `fd_vm_tool_prog_t` structure named `tool_prog` to hold the program and syscalls information.
    - Call [`fd_vm_tool_prog_create`](#fd_vm_tool_prog_create) to initialize `tool_prog` with the binary program specified by `bin_path`.
    - Initialize a `fd_vm_t` structure named `vm` using the program and syscalls information from `tool_prog`.
    - Call [`fd_vm_validate`](fd_vm.c.driver.md#fd_vm_validate) with the `vm` structure to validate the program.
    - Free the resources allocated for `tool_prog` using [`fd_vm_tool_prog_free`](#fd_vm_tool_prog_free).
    - Return the error code from [`fd_vm_validate`](fd_vm.c.driver.md#fd_vm_validate) as the result of the function.
- **Output**: An integer error code indicating the result of the validation process, where a non-zero value typically indicates an error.
- **Functions called**:
    - [`fd_vm_tool_prog_create`](#fd_vm_tool_prog_create)
    - [`fd_vm_validate`](fd_vm.c.driver.md#fd_vm_validate)
    - [`fd_vm_tool_prog_free`](#fd_vm_tool_prog_free)


---
### read\_input\_file<!-- {{#callable:read_input_file}} -->
The `read_input_file` function reads the contents of a file specified by a path into a dynamically allocated buffer and returns the buffer while also setting the size of the file in a provided variable.
- **Inputs**:
    - `input_path`: A constant character pointer representing the path to the input file to be read.
    - `_input_sz`: A pointer to an unsigned long where the size of the input file will be stored.
- **Control Flow**:
    - Check if the _input_sz pointer is NULL and log an error if it is.
    - Open the file at the specified input_path in read mode and log an error if the file cannot be opened.
    - Use fstat to obtain the file status and log an error if it fails or if the file is not a regular file.
    - Allocate a buffer of size equal to the file size and log an error if memory allocation fails.
    - Read the entire file into the allocated buffer and log an error if the read operation fails.
    - Close the file and store the file size in the location pointed to by _input_sz.
- **Output**: Returns a pointer to a dynamically allocated buffer containing the file's contents.


---
### cmd\_trace<!-- {{#callable:cmd_trace}} -->
The `cmd_trace` function executes a virtual machine program with tracing enabled, using a specified binary and input file, and logs execution details.
- **Inputs**:
    - `bin_path`: A constant character pointer representing the file path to the binary program to be executed.
    - `input_path`: A constant character pointer representing the file path to the input data file to be used by the program.
- **Control Flow**:
    - Initialize a `fd_vm_tool_prog_t` structure and load the binary program from `bin_path` using [`fd_vm_tool_prog_create`](#fd_vm_tool_prog_create).
    - Read the input file from `input_path` into memory and store its size.
    - Create a memory region for the input data to be used by the virtual machine.
    - Allocate and initialize a trace object for logging execution details, with a default storage size of 1 GiB and memory range capture size of 2 KiB.
    - Initialize a SHA-256 context for hashing purposes.
    - Set up a `fd_vm_t` virtual machine structure with the program, input memory region, trace, and SHA-256 context.
    - Set specific registers in the virtual machine for memory mapping.
    - Measure the execution time by logging the wall clock time before and after executing the virtual machine with [`fd_vm_exec`](fd_vm.h.driver.md#fd_vm_exec).
    - Log the execution details including the result, return value, instruction counter, and execution time.
    - Free the trace object and return the error code from the trace logging operation.
- **Output**: The function returns an integer error code, which indicates the success or failure of the trace logging operation.
- **Functions called**:
    - [`fd_vm_tool_prog_create`](#fd_vm_tool_prog_create)
    - [`read_input_file`](#read_input_file)
    - [`fd_vm_trace_join`](fd_vm_trace.c.driver.md#fd_vm_trace_join)
    - [`fd_vm_trace_new`](fd_vm_trace.c.driver.md#fd_vm_trace_new)
    - [`fd_vm_trace_align`](fd_vm_trace.c.driver.md#fd_vm_trace_align)
    - [`fd_vm_trace_footprint`](fd_vm_trace.c.driver.md#fd_vm_trace_footprint)
    - [`fd_vm_exec`](fd_vm.h.driver.md#fd_vm_exec)
    - [`fd_vm_trace_printf`](fd_vm_trace.c.driver.md#fd_vm_trace_printf)
    - [`fd_vm_strerror`](fd_vm.c.driver.md#fd_vm_strerror)
    - [`fd_vm_trace_delete`](fd_vm_trace.c.driver.md#fd_vm_trace_delete)
    - [`fd_vm_trace_leave`](fd_vm_trace.c.driver.md#fd_vm_trace_leave)


---
### cmd\_run<!-- {{#callable:cmd_run}} -->
The `cmd_run` function executes a virtual machine program using a binary file and an input file, and logs the execution results.
- **Inputs**:
    - `bin_path`: A constant character pointer representing the path to the binary file to be executed.
    - `input_path`: A constant character pointer representing the path to the input file to be used by the program.
- **Control Flow**:
    - Create a `fd_vm_tool_prog_t` structure and initialize it using the binary file path with [`fd_vm_tool_prog_create`](#fd_vm_tool_prog_create).
    - Read the input file specified by `input_path` into memory and store its size.
    - Create an `fd_vm_input_region_t` structure to represent the input as a single memory region.
    - Initialize a SHA-256 context for hashing purposes.
    - Set up a `fd_vm_t` structure to configure the virtual machine with program text, read-only data, entry point, and input memory regions.
    - Set specific registers in the virtual machine for memory mapping purposes.
    - Measure the wall-clock time before and after executing the virtual machine with [`fd_vm_exec`](fd_vm.h.driver.md#fd_vm_exec).
    - Log the execution result, return value, instruction counter, and execution time using `printf`.
    - Return `FD_VM_SUCCESS` to indicate successful execution.
- **Output**: The function returns `FD_VM_SUCCESS`, indicating successful execution of the virtual machine program.
- **Functions called**:
    - [`fd_vm_tool_prog_create`](#fd_vm_tool_prog_create)
    - [`read_input_file`](#read_input_file)
    - [`fd_vm_exec`](fd_vm.h.driver.md#fd_vm_exec)
    - [`fd_vm_strerror`](fd_vm.c.driver.md#fd_vm_strerror)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, parses command-line arguments to determine the command to execute, and then calls the appropriate function to handle the specified command, logging success or failure.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Call `fd_boot` to initialize the environment with command-line arguments.
    - Extract the command from the command-line arguments using `fd_env_strip_cmdline_cstr`.
    - If the command is not specified, log an error and exit.
    - Check if the command is 'disasm', 'validate', 'trace', or 'run'.
    - For 'disasm' and 'validate', extract the `--program-file` argument and call [`cmd_disasm`](#cmd_disasm) or [`cmd_validate`](#cmd_validate) respectively, logging errors if the file is not specified or the command fails.
    - For 'trace' and 'run', extract both `--program-file` and `--input-file` arguments and call [`cmd_trace`](#cmd_trace) or [`cmd_run`](#cmd_run) respectively, logging errors if the files are not specified or the command fails.
    - If the command is unknown, log an error and exit.
    - Call `fd_halt` to clean up and exit the program.
- **Output**: The function returns an integer, always 0, indicating successful execution.
- **Functions called**:
    - [`cmd_disasm`](#cmd_disasm)
    - [`fd_vm_strerror`](fd_vm.c.driver.md#fd_vm_strerror)
    - [`cmd_validate`](#cmd_validate)
    - [`cmd_trace`](#cmd_trace)
    - [`cmd_run`](#cmd_run)


