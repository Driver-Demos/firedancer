# Purpose
The provided C code is a comprehensive implementation of an ELF (Executable and Linkable Format) loader specifically designed for sBPF (Solana Berkeley Packet Filter) programs. This code is part of a larger system that handles the loading, validation, and preparation of ELF files for execution within an sBPF virtual machine environment. The primary functionality of this code is to parse ELF files, validate their headers and sections, apply necessary relocations, and prepare the program for execution by setting up the required memory segments and handling dynamic symbols and relocations.

Key components of this code include functions for error handling, ELF header and section validation, and dynamic relocation processing. The code defines several macros and static functions to manage errors and validate various parts of the ELF file, such as the file header, program headers, and section headers. It also includes functions to handle specific relocation types, such as `R_BPF_64_64`, `R_BPF_64_RELATIVE`, and `R_BPF_64_32`, which are crucial for adjusting addresses and symbols within the ELF file to fit the sBPF virtual machine's memory layout. Additionally, the code provides mechanisms to manage thread-local storage for error reporting and uses various utility functions and data structures to facilitate the loading process. Overall, this code is a critical component of an sBPF execution environment, ensuring that ELF files are correctly loaded and prepared for execution in a secure and efficient manner.
# Imports and Dependencies

---
- `fd_sbpf_loader.h`
- `fd_sbpf_opcodes.h`
- `../../util/fd_util.h`
- `../../util/bits/fd_sat.h`
- `../murmur3/fd_murmur3.h`
- `assert.h`
- `stdio.h`


# Global Variables

---
### ldr\_errno
- **Type**: `int`
- **Description**: `ldr_errno` is a thread-local static integer variable used to store the last error code encountered by the loader functions in the program. It is initialized to 0, indicating no error by default.
- **Use**: This variable is used to remember the error ID when an error occurs, allowing functions to report and handle errors consistently.


---
### ldr\_err\_srcln
- **Type**: `int`
- **Description**: `ldr_err_srcln` is a thread-local static integer variable initialized to -1. It is used to store the source line number where the last error occurred in the current file.
- **Use**: This variable is updated by the `fd_sbpf_loader_seterr` function to remember the line number of the last error.


---
### fd\_sbpf\_errbuf
- **Type**: `char array`
- **Description**: `fd_sbpf_errbuf` is a thread-local character array used to store error messages related to the sBPF loader operations. It is initialized with a size defined by `FD_SBPF_ERRBUF_SZ`, which is set to 128 bytes, and is initially filled with zeros.
- **Use**: This variable is used to store and return error messages when the `fd_sbpf_strerror` function is called, providing a human-readable description of the last error encountered.


---
### 
- **Type**: `union`
- **Description**: The `fd_sbpf_elf` is a union that provides two different views of ELF (Executable and Linkable Format) data. It can be accessed either as an ELF header (`fd_elf64_ehdr`) or as a binary array (`uchar bin[0]`). This allows for flexible handling of ELF data, enabling both structured and raw data access.
- **Use**: This union is used to facilitate the processing and validation of ELF files by providing access to both the ELF header and the raw binary data.


# Data Structures

---
### fd\_sbpf\_elf
- **Type**: `union`
- **Members**:
    - `ehdr`: Represents the ELF file header using the `fd_elf64_ehdr` type.
    - `bin`: A flexible array member representing the binary content of the ELF file.
- **Description**: The `fd_sbpf_elf` union is designed to provide convenient access to both the ELF file header and the binary content of an ELF file. It allows for operations on the ELF header through the `ehdr` member, while the `bin` member provides access to the raw binary data of the ELF file. This structure is particularly useful in scenarios where both the header and the binary data need to be accessed or manipulated, such as in ELF file parsing or validation processes.


---
### fd\_sbpf\_elf\_t
- **Type**: `union`
- **Members**:
    - `ehdr`: Represents the ELF file header for 64-bit ELF files.
    - `bin`: A flexible array member to access the raw binary data of the ELF file.
- **Description**: The `fd_sbpf_elf_t` is a union data structure that provides convenient access to the ELF file header and its binary content. It is designed to facilitate operations on ELF files by allowing direct access to the file header through the `ehdr` member, which is of type `fd_elf64_ehdr`, and to the raw binary data through the `bin` member, which is a flexible array member. This structure is particularly useful in the context of ELF file parsing and manipulation, as it allows for efficient handling of the ELF file's contents.


---
### fd\_sbpf\_loader
- **Type**: `struct`
- **Members**:
    - `calldests`: Pointer to an array of call destinations, owned by the program.
    - `syscalls`: Pointer to a structure containing system calls, owned by the caller.
    - `dyn_off`: File offset of the dynamic table, with UINT_MAX indicating it is missing.
    - `dyn_cnt`: Number of entries in the dynamic table.
    - `dt_rel`: Offset to the relocation table.
    - `dt_relent`: Size of each entry in the relocation table.
    - `dt_relsz`: Total size of the relocation table.
    - `dt_symtab`: Offset to the symbol table.
    - `dynsym_off`: File offset of the .dynsym section, with 0 indicating it is missing.
    - `dynsym_cnt`: Number of symbols in the dynamic symbol table.
    - `elf_deploy_checks`: Flag indicating whether ELF deployment checks are enabled.
- **Description**: The `fd_sbpf_loader` structure is used to manage the state during the loading of an sBPF (Solana Berkeley Packet Filter) program. It contains pointers to external objects such as call destinations and system calls, which are managed by the program and caller respectively. The structure also maintains information about the dynamic table, including its offset and entry count, as well as details about the relocation and symbol tables. Additionally, it includes a flag for enabling ELF deployment checks, which are used to ensure the integrity and correctness of the ELF file being loaded.


---
### fd\_sbpf\_loader\_t
- **Type**: ``struct``
- **Members**:
    - `calldests`: Pointer to a calldests bitmap owned by the program.
    - `syscalls`: Pointer to a syscalls structure owned by the caller.
    - `dyn_off`: File offset of the dynamic table, UINT_MAX if missing.
    - `dyn_cnt`: Number of entries in the dynamic table.
    - `dt_rel`: Offset to the relocation table.
    - `dt_relent`: Size of each entry in the relocation table.
    - `dt_relsz`: Total size of the relocation table.
    - `dt_symtab`: Offset to the symbol table.
    - `dynsym_off`: File offset of the .dynsym section, 0 if missing.
    - `dynsym_cnt`: Count of symbols in the dynamic symbol table.
    - `elf_deploy_checks`: Flag indicating whether ELF deployment checks are enabled.
- **Description**: The `fd_sbpf_loader_t` structure is used to maintain temporary state during the loading of an sBPF (Solana Berkeley Packet Filter) program. It includes pointers to external objects such as the calldests bitmap and syscalls, as well as various offsets and counts related to the dynamic table and symbol table within the ELF file. This structure is crucial for managing the dynamic relocation and symbol resolution processes required to prepare an sBPF program for execution.


# Functions

---
### fd\_sbpf\_loader\_seterr<!-- {{#callable:fd_sbpf_loader_seterr}} -->
The `fd_sbpf_loader_seterr` function sets the error code and source line number for the last error encountered in the sBPF loader.
- **Inputs**:
    - `err`: An integer representing the error code to be set.
    - `srcln`: An integer representing the source line number where the error occurred.
- **Control Flow**:
    - The function assigns the value of `err` to the thread-local variable `ldr_errno`.
    - The function assigns the value of `srcln` to the thread-local variable `ldr_err_srcln`.
    - The function returns the error code `err`.
- **Output**: The function returns the error code `err` that was passed as an input.


---
### fd\_sbpf\_strerror<!-- {{#callable:fd_sbpf_strerror}} -->
The `fd_sbpf_strerror` function returns a string representation of the last error encountered by the sBPF loader, or "ok" if no error has occurred.
- **Inputs**: None
- **Control Flow**:
    - Check if `ldr_errno` is zero using `FD_UNLIKELY`; if true, copy "ok" into `fd_sbpf_errbuf`.
    - If `ldr_errno` is not zero, format a string with the error code, file name, and line number into `fd_sbpf_errbuf` using `snprintf`.
    - Return the `fd_sbpf_errbuf` containing the error message or "ok".
- **Output**: A constant character pointer to the error message string stored in `fd_sbpf_errbuf`.


---
### \_fd\_int\_store\_if\_negative<!-- {{#callable:_fd_int_store_if_negative}} -->
The function `_fd_int_store_if_negative` stores a given integer `x` into the location pointed by `p` if the current value at `p` is negative, using a branchless approach.
- **Inputs**:
    - `p`: A pointer to an integer where the value will be stored if the current value is negative.
    - `x`: An integer value to be stored at the location pointed by `p` if the condition is met.
- **Control Flow**:
    - The function uses the `fd_int_if` function to evaluate whether the value pointed by `p` is negative.
    - If the value is negative, `x` is stored at the location pointed by `p`; otherwise, the current value at `p` is retained.
    - The assignment is performed in a branchless manner, meaning it avoids conditional branching for efficiency.
- **Output**: The function returns the new value stored at the location pointed by `p`, which is either `x` or the original value at `p`.


---
### fd\_sbpf\_check\_ehdr<!-- {{#callable:fd_sbpf_check_ehdr}} -->
The `fd_sbpf_check_ehdr` function validates the ELF file header for compliance with specific criteria and checks for coherence and bounds in the program and section header tables.
- **Inputs**:
    - `ehdr`: A pointer to a constant `fd_elf64_ehdr` structure representing the ELF file header to be validated.
    - `elf_sz`: An unsigned long integer representing the size of the ELF file in bytes.
    - `min_version`: An unsigned integer specifying the minimum acceptable version for the ELF file.
    - `max_version`: An unsigned integer specifying the maximum acceptable version for the ELF file, or zero if no maximum version is enforced.
- **Control Flow**:
    - The function begins by validating the ELF magic number and various identification fields in the ELF header using the `REQUIRE` macro to ensure they match expected values.
    - It checks the coherence of the ELF header by verifying the sizes of the ELF, program, and section headers, and ensures the section header string table index is within bounds.
    - The function checks that the ELF version flags are within the specified version range, considering the `min_version` and `max_version` parameters.
    - It performs bounds checks on the program header table, ensuring alignment and that the table does not exceed the ELF size or overlap with the file header.
    - The function checks the section header table for alignment, bounds, and ensures there are enough sections, also verifying that the table does not overlap with the file header.
    - Finally, it checks for overlaps between the program and section header tables, ensuring they do not overlap each other.
- **Output**: The function returns an integer, specifically 0, indicating successful validation of the ELF header.


---
### shdr\_get\_loaded\_size<!-- {{#callable:shdr_get_loaded_size}} -->
The function `shdr_get_loaded_size` calculates the loaded size of an ELF section, returning zero if the section type is `SHT_NOBITS`, otherwise returning the section's size.
- **Inputs**:
    - `shdr`: A pointer to a constant `fd_elf64_shdr` structure representing an ELF section header.
- **Control Flow**:
    - The function checks if the section type (`sh_type`) of the provided section header is `FD_ELF_SHT_NOBITS`.
    - If the section type is `FD_ELF_SHT_NOBITS`, the function returns 0.
    - If the section type is not `FD_ELF_SHT_NOBITS`, the function returns the section size (`sh_size`).
- **Output**: The function returns an `ulong` representing the loaded size of the section, which is either 0 or the section's size depending on the section type.


---
### check\_cstr<!-- {{#callable:check_cstr}} -->
The `check_cstr` function verifies if a string within a binary data buffer is null-terminated and does not exceed a specified maximum length.
- **Inputs**:
    - `bin`: A pointer to the binary data buffer where the string is located.
    - `bin_sz`: The size of the binary data buffer.
    - `off`: The offset within the binary data buffer where the string starts.
    - `max`: The maximum number of non-null characters allowed in the string.
    - `opt_sz`: An optional pointer to store the length of the string if it is valid.
- **Control Flow**:
    - Check if the offset is out of bounds of the binary data buffer; if so, return NULL.
    - Adjust the maximum length to include the null terminator and ensure it does not exceed the available buffer size from the offset.
    - Cast the binary data at the offset to a string pointer and calculate its length using `strnlen`.
    - If `opt_sz` is provided, store the calculated length in it.
    - Return the string pointer if the length is less than the adjusted maximum; otherwise, return NULL.
- **Output**: Returns a pointer to the string if it is valid and null-terminated within the specified constraints, or NULL if it is not.


---
### fd\_sbpf\_load\_phdrs<!-- {{#callable:fd_sbpf_load_phdrs}} -->
The `fd_sbpf_load_phdrs` function processes the program header table of an ELF file, storing relevant information and performing validations.
- **Inputs**:
    - `info`: A pointer to an `fd_sbpf_elf_info_t` structure where information about the ELF file will be stored.
    - `elf`: A constant pointer to an `fd_sbpf_elf_t` structure representing the ELF file to be processed.
    - `elf_sz`: An unsigned long representing the size of the ELF file in bytes.
- **Control Flow**:
    - Calculate the offset and count of the program header table from the ELF header.
    - Initialize a variable to track the virtual address of the last seen LOAD segment.
    - Iterate over each program header in the table.
    - For each header, check its type:
    - If the type is `FD_ELF_PT_DYNAMIC`, store the index of the first dynamic segment if not already stored.
    - If the type is `FD_ELF_PT_LOAD`, ensure the segments are ordered by virtual address and within file bounds.
    - Ignore other segment types.
    - Return 0 to indicate successful processing.
- **Output**: The function returns an integer, 0, indicating successful processing of the program headers.
- **Functions called**:
    - [`_fd_int_store_if_negative`](#_fd_int_store_if_negative)


---
### fd\_sbpf\_load\_shdrs<!-- {{#callable:fd_sbpf_load_shdrs}} -->
The `fd_sbpf_load_shdrs` function processes and validates the section header table of an ELF file, ensuring sections are correctly loaded and aligned, and updates the ELF information structure with relevant section data.
- **Inputs**:
    - `info`: A pointer to an `fd_sbpf_elf_info_t` structure where the function will store information about the ELF sections.
    - `elf`: A pointer to a constant `fd_sbpf_elf_t` structure representing the ELF file to be processed.
    - `elf_sz`: An unsigned long integer representing the size of the ELF file in bytes.
    - `elf_deploy_checks`: An integer flag indicating whether additional deployment checks should be performed.
- **Control Flow**:
    - Initialize constants for file header and section header table offsets and sizes.
    - Perform overlap checks to ensure the section header table does not overlap with the file header or program header table.
    - Verify the presence and validity of the section name string table (SHT_STRTAB).
    - Clear the loaded sections bitmap in the `info` structure.
    - Iterate over each section header to validate its type, bounds, and order, and to check for overlaps.
    - For each section, determine if it should be loaded based on its name and type, updating the `info` structure accordingly.
    - Calculate the virtual and physical address ranges for the sections to determine the size of the read-only data segment (rodata).
    - Perform additional checks on the `.text` section to ensure the entry point is within its bounds.
    - Update the `info` structure with the offsets and sizes of relevant sections, such as `.text` and `.dynstr`.
    - Return 0 to indicate successful processing.
- **Output**: The function returns an integer, 0, indicating successful processing of the section headers.
- **Functions called**:
    - [`_fd_int_store_if_negative`](#_fd_int_store_if_negative)
    - [`check_cstr`](#check_cstr)
    - [`shdr_get_loaded_size`](#shdr_get_loaded_size)


---
### fd\_sbpf\_elf\_peek<!-- {{#callable:fd_sbpf_elf_peek}} -->
The `fd_sbpf_elf_peek` function initializes and validates an ELF file, extracting relevant information into a provided structure.
- **Inputs**:
    - `info`: A pointer to an `fd_sbpf_elf_info_t` structure where the ELF information will be stored.
    - `bin`: A pointer to the binary data of the ELF file.
    - `elf_sz`: The size of the ELF file in bytes.
    - `elf_deploy_checks`: An integer flag indicating whether to perform additional deployment checks.
    - `sbpf_min_version`: The minimum supported sBPF version for the ELF file.
    - `sbpf_max_version`: The maximum supported sBPF version for the ELF file.
- **Control Flow**:
    - Check if the ELF size is less than or equal to the size of an ELF header; if so, return NULL.
    - Check if the ELF size exceeds the maximum allowable size (UINT_MAX); if so, return NULL.
    - Initialize the `info` structure with default values.
    - Cast the binary data to an `fd_sbpf_elf_t` structure for easier access to the ELF header.
    - Validate the ELF file header using [`fd_sbpf_check_ehdr`](#fd_sbpf_check_ehdr); if validation fails, return NULL.
    - Load and validate the program headers using [`fd_sbpf_load_phdrs`](#fd_sbpf_load_phdrs); if loading fails, return NULL.
    - Load and validate the section headers using [`fd_sbpf_load_shdrs`](#fd_sbpf_load_shdrs); if loading fails, return NULL.
    - Set the sBPF version in the `info` structure based on the ELF header flags and the maximum version parameter.
    - Return the pointer to the `info` structure.
- **Output**: Returns a pointer to the `fd_sbpf_elf_info_t` structure if successful, or NULL if any validation or loading step fails.
- **Functions called**:
    - [`fd_sbpf_check_ehdr`](#fd_sbpf_check_ehdr)
    - [`fd_sbpf_load_phdrs`](#fd_sbpf_load_phdrs)
    - [`fd_sbpf_load_shdrs`](#fd_sbpf_load_shdrs)


---
### fd\_sbpf\_program\_align<!-- {{#callable:fd_sbpf_program_align}} -->
The `fd_sbpf_program_align` function returns the alignment requirement of the `fd_sbpf_program_t` type.
- **Inputs**: None
- **Control Flow**:
    - The function calls the `alignof` operator on the `fd_sbpf_program_t` type to determine its alignment requirement.
    - It returns the result of the `alignof` operation.
- **Output**: The function returns an `ulong` representing the alignment requirement of the `fd_sbpf_program_t` type.


---
### fd\_sbpf\_program\_footprint<!-- {{#callable:fd_sbpf_program_footprint}} -->
The `fd_sbpf_program_footprint` function calculates the memory footprint required for an sBPF program based on ELF information.
- **Inputs**:
    - `info`: A pointer to a constant `fd_sbpf_elf_info_t` structure containing ELF information, specifically the size of the read-only data section (`rodata_sz`).
- **Control Flow**:
    - The function begins by marking the `info` parameter as unpredictable to hint at potential future dependencies on its contents.
    - It initializes a layout using `FD_LAYOUT_INIT` and appends the alignment and size of `fd_sbpf_program_t`.
    - It further appends the alignment and footprint of the call destinations bitmap, calculated using `fd_sbpf_calldests_align()` and `fd_sbpf_calldests_footprint()` respectively, based on the size of the read-only data section divided by 8.
    - Finally, it appends the alignment of `fd_sbpf_program_t` again and finalizes the layout using `FD_LAYOUT_FINI`, returning the total footprint.
- **Output**: The function returns an `ulong` representing the total memory footprint required for the sBPF program, including the program structure and call destinations bitmap.


---
### fd\_sbpf\_program\_new<!-- {{#callable:fd_sbpf_program_new}} -->
The `fd_sbpf_program_new` function initializes a new sBPF program structure using provided memory, ELF information, and read-only data.
- **Inputs**:
    - `prog_mem`: A pointer to the memory where the program structure will be allocated.
    - `elf_info`: A constant pointer to an `fd_sbpf_elf_info_t` structure containing ELF metadata necessary for program initialization.
    - `rodata`: A pointer to the read-only data segment, which must be aligned and non-null if the ELF info indicates a non-zero rodata footprint.
- **Control Flow**:
    - Check if `prog_mem` is NULL and log a warning if so, returning NULL.
    - Check if `elf_info` is NULL and log a warning if so, returning NULL.
    - Check if `rodata` is NULL when `elf_info` indicates a non-zero rodata footprint, log a warning, and return NULL if so.
    - Check if `rodata` is not aligned to 8 bytes, log a warning, and return NULL if so.
    - Initialize a program structure in the provided memory using `FD_SCRATCH_ALLOC_INIT` and `FD_SCRATCH_ALLOC_APPEND`.
    - Populate the program structure with information from `elf_info` and `rodata`.
    - Calculate the maximum program counter (`pc_max`) based on the rodata size.
    - Initialize the `calldests` map using `fd_sbpf_calldests_new` and `fd_sbpf_calldests_join`.
    - Return the initialized program structure.
- **Output**: A pointer to the newly initialized `fd_sbpf_program_t` structure, or NULL if any input validation fails.


---
### fd\_sbpf\_program\_delete<!-- {{#callable:fd_sbpf_program_delete}} -->
The `fd_sbpf_program_delete` function cleans up and resets an `fd_sbpf_program_t` structure, releasing associated resources and zeroing its memory.
- **Inputs**:
    - `mem`: A pointer to an `fd_sbpf_program_t` structure that is to be deleted and reset.
- **Control Flow**:
    - Call `fd_sbpf_calldests_leave` on `mem->calldests` to leave the calldests context.
    - Pass the result to `fd_sbpf_calldests_delete` to delete the calldests resources.
    - Use `fd_memset` to zero out the memory of the `fd_sbpf_program_t` structure pointed to by `mem`.
- **Output**: Returns a void pointer to the `fd_sbpf_program_t` structure that was reset.


---
### fd\_sbpf\_find\_dynamic<!-- {{#callable:fd_sbpf_find_dynamic}} -->
The `fd_sbpf_find_dynamic` function locates the dynamic section in an ELF file, either from the program header or section header, and updates the loader with its offset and count.
- **Inputs**:
    - `loader`: A pointer to an `fd_sbpf_loader_t` structure that will be updated with the dynamic section's offset and count.
    - `elf`: A constant pointer to an `fd_sbpf_elf_t` structure representing the ELF file being processed.
    - `elf_sz`: An unsigned long representing the size of the ELF file.
    - `info`: A constant pointer to an `fd_sbpf_elf_info_t` structure containing information about the ELF file, including indices of dynamic sections.
- **Control Flow**:
    - Retrieve the section headers and program headers from the ELF file using offsets from the ELF header.
    - Check if a dynamic section is indicated in the program header table using `info->phndx_dyn`.
    - If a valid dynamic section is found in the program header, verify its bounds and alignment, then update the loader with its offset and count.
    - If the program header does not contain a valid dynamic section, check the section header table using `info->shndx_dyn`.
    - If a valid dynamic section is found in the section header, verify its bounds and alignment, then update the loader with its offset and count.
    - If no valid dynamic section is found in either header, return without updating the loader.
- **Output**: The function returns 0 on success, indicating that the dynamic section was found and the loader was updated, or that no valid dynamic section was found.


---
### fd\_sbpf\_load\_dynamic<!-- {{#callable:fd_sbpf_load_dynamic}} -->
The `fd_sbpf_load_dynamic` function processes the dynamic section of an ELF file to extract and store relevant dynamic table entries and dynamic symbol table information into a loader structure.
- **Inputs**:
    - `loader`: A pointer to an `fd_sbpf_loader_t` structure that will be populated with dynamic table and symbol table information.
    - `elf`: A pointer to a constant `fd_sbpf_elf_t` structure representing the ELF file being processed.
    - `elf_sz`: An unsigned long integer representing the size of the ELF file in bytes.
- **Control Flow**:
    - Check if the dynamic table count (`dyn_cnt`) in the loader is zero; if so, return immediately as there is no dynamic table to process.
    - Retrieve the dynamic table from the ELF binary using the offset stored in the loader and iterate over its entries.
    - For each entry in the dynamic table, check the tag and store the corresponding value in the loader's fields (`dt_rel`, `dt_relent`, `dt_relsz`, `dt_symtab`) based on the tag type.
    - If a dynamic symbol table is indicated by `dt_symtab`, search the section headers for the corresponding section and verify its type as either `FD_ELF_SHT_SYMTAB` or `FD_ELF_SHT_DYNSYM`.
    - Ensure the dynamic symbol table section is within bounds and properly aligned, then store its offset and count in the loader.
- **Output**: The function returns an integer, always 0, indicating successful processing of the dynamic section.


---
### fd\_sbpf\_r\_bpf\_64\_64<!-- {{#callable:fd_sbpf_r_bpf_64_64}} -->
The function `fd_sbpf_r_bpf_64_64` relocates an absolute address into the extended immediate field of an lddw-form instruction in an ELF file for sBPF virtual machine execution.
- **Inputs**:
    - `loader`: A pointer to a `fd_sbpf_loader_t` structure containing dynamic symbol information and other loader state.
    - `elf`: A pointer to a `fd_sbpf_elf_t` structure representing the ELF file being processed.
    - `elf_sz`: The size of the ELF file in bytes.
    - `rodata`: A pointer to the read-only data segment where the relocation will be applied.
    - `info`: A pointer to a `fd_sbpf_elf_info_t` structure containing information about the ELF file.
    - `rel`: A pointer to a `fd_elf64_rel` structure representing the relocation entry to be processed.
- **Control Flow**:
    - Extract the symbol index and offset from the relocation entry using `FD_ELF64_R_SYM` and `rel->r_offset` respectively.
    - Perform a bounds check to ensure the relocation offset and its immediate fields are within the ELF size.
    - Calculate the offsets for the low and high parts of the immediate field in the instruction slots.
    - Ensure the low part of the immediate field is within bounds of the ELF size.
    - Retrieve the symbol value from the dynamic symbol table using the symbol index.
    - Load the implicit addend from the read-only data segment at the calculated offset.
    - Compute the virtual address by adding the symbol value and the implicit addend, adjusting it if necessary to ensure it is within the program address space.
    - Store the computed virtual address back into the read-only data segment, splitting it into low and high parts for storage.
- **Output**: The function returns an integer, 0 on success, indicating successful relocation.


---
### fd\_sbpf\_r\_bpf\_64\_relative<!-- {{#callable:fd_sbpf_r_bpf_64_relative}} -->
The `fd_sbpf_r_bpf_64_relative` function handles the R_BPF_64_RELATIVE relocation type for sBPF ELF files, adjusting addresses in the .text section or performing 64-bit writes outside of it.
- **Inputs**:
    - `elf`: A pointer to the ELF file structure containing the binary data and headers.
    - `elf_sz`: The size of the ELF file in bytes.
    - `rodata`: A pointer to the read-only data segment where relocations will be applied.
    - `info`: A pointer to the ELF information structure containing indices and sizes of relevant sections.
    - `rel`: A pointer to the relocation entry that specifies the offset and type of relocation to be applied.
- **Control Flow**:
    - Retrieve the relocation offset from the `rel` structure.
    - Determine if the relocation target is within the .text section by comparing the offset with the .text section's boundaries.
    - If the target is in the .text section, perform a relocation similar to R_BPF_64_64, ignoring the symbol and adjusting the address if it appears to be a physical address.
    - If the target is outside the .text section, perform a 64-bit write by reading the implicit addend, adding a constant offset, and writing back the result.
- **Output**: The function returns 0 to indicate successful completion of the relocation process.
- **Functions called**:
    - [`shdr_get_loaded_size`](#shdr_get_loaded_size)


---
### fd\_sbpf\_r\_bpf\_64\_32<!-- {{#callable:fd_sbpf_r_bpf_64_32}} -->
The `fd_sbpf_r_bpf_64_32` function handles the relocation of 32-bit immediate fields in call instructions within an ELF file, converting them to either a function ID or a syscall ID based on the symbol type.
- **Inputs**:
    - `loader`: A pointer to a `fd_sbpf_loader_t` structure containing information about the dynamic symbols and syscalls.
    - `elf`: A pointer to a `fd_sbpf_elf_t` structure representing the ELF file being processed.
    - `elf_sz`: The size of the ELF file in bytes.
    - `rodata`: A pointer to the read-only data segment where the relocation will be applied.
    - `info`: A pointer to a `fd_sbpf_elf_info_t` structure containing information about the ELF sections and symbols.
    - `rel`: A pointer to a `fd_elf64_rel` structure representing the relocation entry to be processed.
- **Control Flow**:
    - Extract the symbol index and offset from the relocation entry.
    - Verify that the symbol index is within bounds of the dynamic symbol table.
    - Retrieve the symbol and its value from the dynamic symbol table.
    - Verify the presence and type of the .dynstr section.
    - Check the symbol name and determine its length.
    - Determine if the symbol is a function call by checking its type and value.
    - If it's a function call, verify that the symbol's address is within the text section's virtual memory range.
    - Calculate the target program counter for the function call.
    - If the symbol name is 'entrypoint', skip insertion into calldests but apply a fixed hash.
    - Otherwise, compute a hash of the target program counter and insert it into calldests if within bounds.
    - Ensure no collision with existing syscall IDs using the computed hash.
    - If not a function call, compute a Murmur3 hash of the symbol name and verify its existence if deployment checks are enabled.
    - Perform bounds checks on the relocation offset.
    - Store the computed value (hash) into the rodata segment at the specified offset.
- **Output**: The function returns 0 on successful relocation, indicating that the relocation was applied without errors.
- **Functions called**:
    - [`check_cstr`](#check_cstr)


---
### fd\_sbpf\_apply\_reloc<!-- {{#callable:fd_sbpf_apply_reloc}} -->
The `fd_sbpf_apply_reloc` function applies a specific relocation to an ELF file based on the relocation type.
- **Inputs**:
    - `loader`: A pointer to a `fd_sbpf_loader_t` structure containing temporary state during loading.
    - `elf`: A pointer to a `fd_sbpf_elf_t` structure representing the ELF file.
    - `elf_sz`: The size of the ELF file in bytes.
    - `rodata`: A pointer to a writable memory area where the read-only data segment of the ELF file is stored.
    - `info`: A pointer to a `fd_sbpf_elf_info_t` structure containing information about the ELF file.
    - `rel`: A pointer to a `fd_elf64_rel` structure representing the relocation entry to be applied.
- **Control Flow**:
    - The function begins by determining the type of relocation using the `FD_ELF64_R_TYPE` macro on `rel->r_info`.
    - It uses a switch statement to handle different relocation types: `FD_ELF_R_BPF_64_64`, `FD_ELF_R_BPF_64_RELATIVE`, and `FD_ELF_R_BPF_64_32`.
    - For each case, it calls a specific function ([`fd_sbpf_r_bpf_64_64`](#fd_sbpf_r_bpf_64_64), [`fd_sbpf_r_bpf_64_relative`](#fd_sbpf_r_bpf_64_relative), or [`fd_sbpf_r_bpf_64_32`](#fd_sbpf_r_bpf_64_32)) to apply the relocation.
    - If the relocation type is not recognized, it triggers an error using the `ERR` macro with `FD_SBPF_ERR_INVALID_ELF`.
- **Output**: The function returns an integer status code, where 0 indicates success and a non-zero value indicates an error.
- **Functions called**:
    - [`fd_sbpf_r_bpf_64_64`](#fd_sbpf_r_bpf_64_64)
    - [`fd_sbpf_r_bpf_64_relative`](#fd_sbpf_r_bpf_64_relative)
    - [`fd_sbpf_r_bpf_64_32`](#fd_sbpf_r_bpf_64_32)


---
### fd\_sbpf\_hash\_calls<!-- {{#callable:fd_sbpf_hash_calls}} -->
The `fd_sbpf_hash_calls` function processes the text section of an ELF file to convert call instructions with program counter relative immediates into hashed values, ensuring no collision with syscall IDs.
- **Inputs**:
    - `loader`: A pointer to an `fd_sbpf_loader_t` structure, which contains temporary state during loading, including a calldests array and syscalls.
    - `prog`: A pointer to an `fd_sbpf_program_t` structure, which contains information about the ELF program, including the read-only data segment.
    - `elf`: A constant pointer to an `fd_sbpf_elf_t` structure, representing the ELF file being processed.
- **Control Flow**:
    - Retrieve section headers and program information from the ELF file and program structure.
    - Calculate the starting pointer and instruction count for the text section of the ELF file.
    - Iterate over each instruction in the text section, checking if it is a call instruction with a valid immediate value.
    - For each valid call instruction, calculate the target program counter and insert it into the calldests map.
    - Replace the immediate value in the call instruction with a hash of the target program counter, ensuring no collision with syscall IDs.
    - Store the hashed value back into the instruction.
- **Output**: The function returns an integer, 0 on success, indicating that the call instructions were successfully processed and hashed.
- **Functions called**:
    - [`shdr_get_loaded_size`](#shdr_get_loaded_size)


---
### fd\_sbpf\_relocate<!-- {{#callable:fd_sbpf_relocate}} -->
The `fd_sbpf_relocate` function applies dynamic relocations to an ELF file's read-only data segment based on relocation entries and loader information.
- **Inputs**:
    - `loader`: A pointer to a `fd_sbpf_loader_t` structure containing dynamic table entries and other loader state information.
    - `elf`: A pointer to a `fd_sbpf_elf_t` structure representing the ELF file to be relocated.
    - `elf_sz`: The size of the ELF file in bytes.
    - `rodata`: A pointer to the read-only data segment where relocations will be applied.
    - `info`: A pointer to a `fd_sbpf_elf_info_t` structure containing information about the ELF file, such as section indices and sizes.
- **Control Flow**:
    - Check if the dynamic relocation table (DT_REL) is present; if not, return 0 to skip relocation.
    - Validate the relocation table parameters, ensuring the entry size and total size are correct.
    - Attempt to resolve the virtual address of DT_REL to a file offset by searching through the program headers.
    - If not found in program headers, search the section headers for the first dynamic relocation section.
    - Ensure the resolved file offset is aligned and within bounds of the ELF size.
    - Load the relocation entries from the resolved file offset and calculate the number of entries.
    - Iterate over each relocation entry, applying the relocation using [`fd_sbpf_apply_reloc`](#fd_sbpf_apply_reloc) and return any error encountered.
    - Return 0 if all relocations are successfully applied.
- **Output**: Returns 0 on successful relocation or an error code if a relocation fails.
- **Functions called**:
    - [`fd_sbpf_apply_reloc`](#fd_sbpf_apply_reloc)


---
### fd\_sbpf\_zero\_rodata<!-- {{#callable:fd_sbpf_zero_rodata}} -->
The `fd_sbpf_zero_rodata` function zeroes out gaps between loaded sections in the read-only data segment of an ELF file.
- **Inputs**:
    - `elf`: A pointer to an `fd_sbpf_elf_t` structure representing the ELF file.
    - `rodata`: A pointer to the read-only data segment where gaps between sections will be zeroed out.
    - `info`: A pointer to a constant `fd_sbpf_elf_info_t` structure containing information about the ELF file, including loaded sections and the size of the read-only data segment.
- **Control Flow**:
    - Initialize a cursor to track the current position in the `rodata` segment.
    - Iterate over each section header in the ELF file's section header table.
    - For each section, check if it is loaded by examining the `loaded_sections` bitmap in `info`.
    - Skip sections that are not loaded or are of type `FD_ELF_SHT_NOBITS`.
    - For loaded sections, calculate the gap between the current cursor position and the section's offset.
    - Use `fd_memset` to fill the gap with zeros.
    - Update the cursor to the end of the current section.
    - After processing all sections, zero out any remaining space in the `rodata` segment from the cursor to the end of the segment.
- **Output**: Returns 0 upon successful completion, indicating that the gaps have been zeroed out without errors.


---
### fd\_sbpf\_program\_load<!-- {{#callable:fd_sbpf_program_load}} -->
The `fd_sbpf_program_load` function loads an sBPF program from an ELF binary, processes its dynamic sections, applies relocations, and prepares it for execution.
- **Inputs**:
    - `prog`: A pointer to an `fd_sbpf_program_t` structure where the loaded program information will be stored.
    - `_bin`: A pointer to the ELF binary data to be loaded.
    - `elf_sz`: The size of the ELF binary data in bytes.
    - `syscalls`: A pointer to an `fd_sbpf_syscalls_t` structure containing syscall information.
    - `elf_deploy_checks`: An integer flag indicating whether to perform additional deployment checks on the ELF binary.
- **Control Flow**:
    - Initialize error handling by setting the error state to zero.
    - Cast the binary data to an `fd_sbpf_elf_t` pointer for easier manipulation.
    - Initialize an `fd_sbpf_loader_t` structure with the program's call destinations and syscalls, and set other fields to zero or the provided `elf_deploy_checks`.
    - Attempt to find the dynamic section in the ELF binary using [`fd_sbpf_find_dynamic`](#fd_sbpf_find_dynamic); return an error if unsuccessful.
    - Load the dynamic section using [`fd_sbpf_load_dynamic`](#fd_sbpf_load_dynamic); return an error if unsuccessful.
    - Register the program's entry point in the call destinations map.
    - Copy the read-only data segment from the ELF binary to the program's memory.
    - Convert PC-relative call instructions to hashed values using [`fd_sbpf_hash_calls`](#fd_sbpf_hash_calls); return an error if unsuccessful.
    - Apply relocations to the program using [`fd_sbpf_relocate`](#fd_sbpf_relocate); return an error if unsuccessful.
    - Zero out non-interesting parts of the read-only data segment using [`fd_sbpf_zero_rodata`](#fd_sbpf_zero_rodata); return an error if unsuccessful.
    - Return 0 to indicate successful loading of the program.
- **Output**: Returns 0 on success, or an error code if any step in the loading process fails.
- **Functions called**:
    - [`fd_sbpf_loader_seterr`](#fd_sbpf_loader_seterr)
    - [`fd_sbpf_find_dynamic`](#fd_sbpf_find_dynamic)
    - [`fd_sbpf_load_dynamic`](#fd_sbpf_load_dynamic)
    - [`fd_sbpf_hash_calls`](#fd_sbpf_hash_calls)
    - [`fd_sbpf_relocate`](#fd_sbpf_relocate)
    - [`fd_sbpf_zero_rodata`](#fd_sbpf_zero_rodata)


