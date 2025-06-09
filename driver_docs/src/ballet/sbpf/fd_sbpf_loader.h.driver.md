# Purpose
The provided C header file, `fd_sbpf_loader.h`, is designed to facilitate the preparation and execution of sBPF (Solana Berkeley Packet Filter) programs. It primarily focuses on parsing and dynamically relocating sBPF programs, which are typically stored in ELF (Executable and Linkable Format) binaries. The file defines several data structures and functions that manage the loading and execution of these programs, including handling the read-only data segments and executable code sections. The header file is not a pure static linker or a dynamic loader but combines elements of both to load specific sections at predefined addresses while performing dynamic relocations.

Key components of this file include the definition of error types, program structures, and syscall mappings. The `fd_sbpf_elf_info_t` structure extracts and stores essential information from an ELF binary, such as section offsets and sizes, while the `fd_sbpf_program_t` structure describes a loaded program in memory, including its read-only data and executable code. The file also defines a callback type for implementing sBPF syscalls and a mapping structure for associating syscall IDs with their corresponding functions. The header provides function prototypes for parsing ELF files, creating and loading sBPF programs, and managing their lifecycle. This file is intended to be included in other C source files that require the functionality of loading and executing sBPF programs, and it does not define a public API or external interface on its own.
# Imports and Dependencies

---
- `../../util/fd_util_base.h`
- `../elf/fd_elf64.h`
- `../../util/tmpl/fd_set_dynamic.c`
- `../../util/tmpl/fd_map.c`


# Global Variables

---
### fd\_sbpf\_program\_new
- **Type**: `fd_sbpf_program_t *`
- **Description**: The `fd_sbpf_program_new` function is responsible for initializing a new `fd_sbpf_program_t` structure. It takes a memory region `prog_mem` to format as a program object, an `elf_info` structure containing ELF binary information, and a `rodata` buffer for the read-only segment.
- **Use**: This function is used to allocate and set up a new sBPF program in memory, preparing it for execution by configuring it with the necessary ELF and read-only segment data.


---
### fd\_sbpf\_program\_delete
- **Type**: `function pointer`
- **Description**: The `fd_sbpf_program_delete` is a function that takes a pointer to an `fd_sbpf_program_t` structure and is responsible for destroying the program object and unformatting the memory regions holding it. This function is part of the lifecycle management of an sBPF program, ensuring that resources are properly released when the program is no longer needed.
- **Use**: This function is used to clean up and deallocate resources associated with an sBPF program after its execution is complete.


---
### fd\_sbpf\_strerror
- **Type**: `function pointer returning a constant character pointer`
- **Description**: The `fd_sbpf_strerror` function is a global function that returns a constant character pointer. It is designed to provide a string description of the error that occurred during the last call to `fd_sbpf_program_load` if it returned a non-zero value, indicating an error. The function always returns a valid string, but the content is undefined if the last call to `fd_sbpf_program_load` was successful (returned zero).
- **Use**: This function is used to retrieve a human-readable error message after a failed attempt to load an sBPF program.


# Data Structures

---
### fd\_sbpf\_syscalls
- **Type**: `struct`
- **Members**:
    - `key`: Murmur3-32 hash of the function name used as a unique identifier.
    - `func`: Function pointer to the syscall implementation.
    - `name`: Pointer to the function name with an infinite lifetime.
- **Description**: The `fd_sbpf_syscalls` structure is designed to map syscall identifiers to their corresponding function implementations and names within an sBPF (Solana Berkeley Packet Filter) virtual machine environment. It uses a Murmur3-32 hash as a key to uniquely identify each syscall by its name, allowing for efficient lookup and execution of the syscall function via a function pointer. The structure also maintains a constant pointer to the syscall's name, ensuring that the name is accessible throughout the lifetime of the program. This structure is integral to the dynamic relocation and execution of sBPF programs, facilitating the mapping of syscall IDs to their respective functions and names.


---
### fd\_sbpf\_syscalls\_t
- **Type**: `struct`
- **Members**:
    - `key`: Murmur3-32 hash of the function name used as a unique identifier.
    - `func`: Function pointer to the syscall implementation.
    - `name`: Pointer to the function name with an infinite lifetime.
- **Description**: The `fd_sbpf_syscalls_t` structure is designed to map syscall IDs to their corresponding function names and VM-specific contexts. It uses a Murmur3-32 hash as a key to uniquely identify each syscall, which is stored in the `key` member. The `func` member is a function pointer that points to the actual implementation of the syscall, allowing the VM to execute the appropriate function when a syscall is invoked. The `name` member holds a pointer to the function name, ensuring that the name is accessible for the lifetime of the program. This structure is crucial for managing syscalls within the sBPF virtual machine environment, providing a mechanism to dynamically link syscall functions by their hashed names.


---
### fd\_sbpf\_elf\_info
- **Type**: `struct`
- **Members**:
    - `text_off`: File offset of the .text section, which overlaps with the rodata segment.
    - `text_cnt`: Count of instructions in the text segment.
    - `text_sz`: Length of the text segment in bytes.
    - `dynstr_off`: File offset of the .dynstr section, with 0 indicating it is missing.
    - `dynstr_sz`: Character count of the .dynstr section.
    - `rodata_sz`: Size of the rodata segment in bytes.
    - `rodata_footprint`: Size of the entire ELF binary.
    - `shndx_text`: Index of the .text section, with -1 indicating it is not found.
    - `shndx_symtab`: Index of the symbol table section, with -1 indicating it is not found.
    - `shndx_strtab`: Index of the string table section, with -1 indicating it is not found.
    - `shndx_dyn`: Index of the dynamic section, with -1 indicating it is not found.
    - `shndx_dynstr`: Index of the dynamic string section, with -1 indicating it is not found.
    - `phndx_dyn`: Index of the dynamic program header, with -1 indicating it is not found.
    - `entry_pc`: Program counter of the entry point, which might be out of bounds.
    - `loaded_sections`: Bitmap indicating which sections are to be loaded, with each bit representing a section.
    - `sbpf_version`: Version of the SBPF, following the SIMD-0161 specification.
- **Description**: The `fd_sbpf_elf_info` structure is designed to store essential metadata extracted from an ELF binary, specifically for use with SBPF (Solana Berkeley Packet Filter) programs. It includes offsets and sizes for various sections such as .text and .dynstr, indices for known sections and program headers, and a bitmap for loaded sections. Additionally, it tracks the program counter for the entry point and the SBPF version, providing a comprehensive overview necessary for loading and executing SBPF programs.


---
### fd\_sbpf\_elf\_info\_t
- **Type**: `struct`
- **Members**:
    - `text_off`: File offset of the .text section, which overlaps with the rodata segment.
    - `text_cnt`: Count of instructions in the .text section.
    - `text_sz`: Size of the text segment in bytes.
    - `dynstr_off`: File offset of the .dynstr section, with 0 indicating it is missing.
    - `dynstr_sz`: Character count of the .dynstr section.
    - `rodata_sz`: Size of the rodata segment in bytes.
    - `rodata_footprint`: Size of the entire ELF binary.
    - `shndx_text`: Index of the .text section, with -1 indicating it is not found.
    - `shndx_symtab`: Index of the symbol table section, with -1 indicating it is not found.
    - `shndx_strtab`: Index of the string table section, with -1 indicating it is not found.
    - `shndx_dyn`: Index of the dynamic section, with -1 indicating it is not found.
    - `shndx_dynstr`: Index of the dynamic string section, with -1 indicating it is not found.
    - `phndx_dyn`: Index of the dynamic program header, with -1 indicating it is not found.
    - `entry_pc`: Program counter of the entry point, which might be out of bounds.
    - `loaded_sections`: Bitmap indicating which sections are to be loaded, with each bit representing a section.
    - `sbpf_version`: Version of the SBPF, as per SIMD-0161.
- **Description**: The `fd_sbpf_elf_info_t` structure is designed to encapsulate essential information extracted from an ELF binary, which is necessary for loading and executing an sBPF program. It includes details about the offsets and sizes of various sections such as .text and .dynstr, as well as indices for known sections and program headers. Additionally, it maintains a bitmap of sections to be loaded and specifies the SBPF version. This structure is crucial for determining the memory and buffer requirements for fully loading the program.


---
### fd\_sbpf\_program
- **Type**: `struct`
- **Members**:
    - `info`: Contains basic information extracted from an ELF binary.
    - `rodata`: Pointer to the read-only data segment to be mapped into VM memory.
    - `rodata_sz`: Size of the read-only data segment.
    - `text`: Pointer to the text section within the rodata segment containing executable code.
    - `text_cnt`: Count of instructions in the text section.
    - `text_off`: Offset for instructions used in CALL_REG instructions.
    - `text_sz`: Size of the text segment.
    - `entry_pc`: Program counter of the entry point in the text section.
    - `calldests_shmem`: Pointer to shared memory bit vector of valid call destinations.
    - `calldests`: Local join to the bit vector of valid call destinations.
- **Description**: The `fd_sbpf_program` structure represents a loaded sBPF program in memory, containing essential information for execution within a virtual machine. It includes metadata about the ELF binary, such as the read-only data segment (`rodata`) and its size, as well as the text section which holds executable instructions. The structure also manages a bit vector for valid call destinations, facilitating the execution of the program by ensuring that calls are made to valid locations. This structure is aligned to 32 bytes for optimal memory access and is crucial for preparing and executing sBPF programs.


---
### fd\_sbpf\_program\_t
- **Type**: `struct`
- **Members**:
    - `info`: Contains basic information extracted from an ELF binary.
    - `rodata`: Pointer to the read-only segment data to be mapped into VM memory.
    - `rodata_sz`: Size of the read-only segment data.
    - `text`: Pointer to the text section within the rodata segment containing executable code.
    - `text_cnt`: Instruction count in the text section.
    - `text_off`: Instruction offset for use in CALL_REG instructions.
    - `text_sz`: Size of the text segment.
    - `entry_pc`: Program counter of the entry point in the text section.
    - `calldests_shmem`: Pointer to shared memory for the bit vector of valid call destinations.
    - `calldests`: Local join to the bit vector of valid call destinations.
- **Description**: The `fd_sbpf_program_t` structure describes a loaded sBPF program in memory, detailing both the read-only data segment and the executable code segment. It includes metadata about the ELF binary, such as section offsets and sizes, and manages the memory layout for execution within a virtual machine. The structure also maintains a bit vector for valid call destinations, ensuring that the program can be executed safely and efficiently. This data structure is crucial for preparing and managing the execution of sBPF programs, particularly in environments that require dynamic relocation and precise memory management.


# Function Declarations (Public API)

---
### fd\_sbpf\_program\_align<!-- {{#callable_declaration:fd_sbpf_program_align}} -->
Returns the alignment requirement of the fd_sbpf_program_t structure.
- **Description**: Use this function to determine the memory alignment requirement for the fd_sbpf_program_t structure. This is useful when allocating memory for an sBPF program to ensure that the memory is correctly aligned, which is necessary for proper operation. This function does not require any parameters and can be called at any time to retrieve the alignment value.
- **Inputs**: None
- **Output**: The function returns an unsigned long representing the alignment requirement of the fd_sbpf_program_t structure.
- **See also**: [`fd_sbpf_program_align`](fd_sbpf_loader.c.driver.md#fd_sbpf_program_align)  (Implementation)


---
### fd\_sbpf\_program\_footprint<!-- {{#callable_declaration:fd_sbpf_program_footprint}} -->
Calculate the memory footprint required for an sBPF program.
- **Description**: This function calculates the memory footprint needed to store an sBPF program based on the provided ELF information. It is useful for determining the size of the memory allocation required before loading an sBPF program. The function should be called with a valid pointer to an `fd_sbpf_elf_info_t` structure that contains the necessary ELF binary information. The function is pure, meaning it does not modify any state and its output depends solely on the input parameters.
- **Inputs**:
    - `info`: A pointer to a constant `fd_sbpf_elf_info_t` structure containing information about the ELF binary. This parameter must not be null, and it is expected to be properly initialized with valid ELF data. The function does not modify the contents of this structure.
- **Output**: Returns an unsigned long representing the size in bytes of the memory footprint required for the sBPF program.
- **See also**: [`fd_sbpf_program_footprint`](fd_sbpf_loader.c.driver.md#fd_sbpf_program_footprint)  (Implementation)


---
### fd\_sbpf\_program\_new<!-- {{#callable_declaration:fd_sbpf_program_new}} -->
Formats memory to hold an sBPF program.
- **Description**: This function initializes a memory region to hold an sBPF program based on the provided ELF information and read-only data segment. It should be called when you need to prepare a program for execution, ensuring that the memory region is correctly formatted and aligned. The function requires valid pointers for the program memory, ELF information, and, if applicable, the read-only data segment. It returns a pointer to the initialized program structure or NULL if any input is invalid or alignment requirements are not met.
- **Inputs**:
    - `prog_mem`: A pointer to the memory region where the program will be formatted. Must not be null and should meet the footprint requirements of the provided ELF information.
    - `elf_info`: A pointer to a constant fd_sbpf_elf_info_t structure containing information extracted from an ELF binary. Must not be null and can be deallocated after the function returns.
    - `rodata`: A pointer to the read-only data segment buffer. Must be valid for the program's lifetime and 8-byte aligned if the ELF information indicates a non-zero rodata footprint. Can be null if the rodata footprint is zero.
- **Output**: Returns a pointer to the initialized fd_sbpf_program_t structure on success, or NULL on failure due to invalid inputs or alignment issues.
- **See also**: [`fd_sbpf_program_new`](fd_sbpf_loader.c.driver.md#fd_sbpf_program_new)  (Implementation)


---
### fd\_sbpf\_program\_load<!-- {{#callable_declaration:fd_sbpf_program_load}} -->
Loads an eBPF program for execution.
- **Description**: This function initializes and populates a program object with information from an ELF file, preparing it for execution. It must be called with a program object that has been allocated using `fd_sbpf_program_new`, and the memory region containing the ELF file must be specified. The function also requires a mapping of syscall IDs to their respective functions and a flag to enable additional ELF deployment checks. On success, the function returns 0, while on error, it returns a non-zero error code and leaves the program object in an undefined state.
- **Inputs**:
    - `prog`: A pointer to an `fd_sbpf_program_t` object, which must be allocated with `fd_sbpf_program_new` and match the footprint requirements of the ELF file. The caller retains ownership.
    - `bin`: A pointer to the memory region containing the ELF file to be loaded. The memory must be valid and accessible for the duration of the function call. The caller retains ownership.
    - `bin_sz`: The size of the ELF file in bytes. It must accurately reflect the size of the memory region pointed to by `bin`.
    - `syscalls`: A pointer to an `fd_sbpf_syscalls_t` structure mapping syscall IDs to their respective functions. This parameter must not be null, and the caller retains ownership.
    - `elf_deploy_checks`: An integer flag indicating whether to enable additional ELF deployment checks. Non-zero values enable the checks, while zero disables them.
- **Output**: Returns 0 on success. On error, returns a non-zero error code and leaves the program object in an undefined state.
- **See also**: [`fd_sbpf_program_load`](fd_sbpf_loader.c.driver.md#fd_sbpf_program_load)  (Implementation)


---
### fd\_sbpf\_program\_delete<!-- {{#callable_declaration:fd_sbpf_program_delete}} -->
Destroys an sBPF program object and resets its memory.
- **Description**: Use this function to properly destroy an sBPF program object when it is no longer needed. This function ensures that any resources associated with the program are released and the memory is reset to a clean state. It should be called only on program objects that were previously initialized and are no longer in use. This function returns a pointer to the memory that held the program object, which can be reused or deallocated as needed.
- **Inputs**:
    - `program`: A pointer to an fd_sbpf_program_t object that is to be destroyed. Must not be null and should point to a valid, initialized program object.
- **Output**: Returns a pointer to the memory that held the program object, allowing for potential reuse or deallocation.
- **See also**: [`fd_sbpf_program_delete`](fd_sbpf_loader.c.driver.md#fd_sbpf_program_delete)  (Implementation)


---
### fd\_sbpf\_strerror<!-- {{#callable_declaration:fd_sbpf_strerror}} -->
Returns a string describing the last error from fd_sbpf_program_load.
- **Description**: Use this function to retrieve a human-readable description of the last error encountered by fd_sbpf_program_load in the current thread. It should be called after fd_sbpf_program_load returns a non-zero value to understand the nature of the error. The function always returns a valid string, but the content is only meaningful if the last call to fd_sbpf_program_load failed.
- **Inputs**: None
- **Output**: A constant character pointer to a string describing the last error, or "ok" if no error occurred.
- **See also**: [`fd_sbpf_strerror`](fd_sbpf_loader.c.driver.md#fd_sbpf_strerror)  (Implementation)


