# Purpose
This C header file, `fd_elf64.h`, defines a set of data structures that represent various components of the ELF64 (Executable and Linkable Format) file type. The file provides a detailed specification of the ELF64 format by defining structures for the ELF file header (`fd_elf64_ehdr`), program header (`fd_elf64_phdr`), section header (`fd_elf64_shdr`), symbol table entry (`fd_elf64_sym`), and relocation entries (`fd_elf64_rel` and `fd_elf64_rela`). Additionally, it includes a structure for dynamic section entries (`fd_elf64_dyn`). Each structure is packed to ensure that there is no padding between the fields, which is crucial for accurately mapping the binary layout of ELF files.

The primary purpose of this header file is to facilitate the manipulation and interpretation of ELF64 files within a C program. By providing these structures, the file allows developers to read, modify, and write ELF64 files, which are commonly used for executables, object code, shared libraries, and core dumps on Unix-like systems. This header file is intended to be included in other C source files that require direct interaction with ELF64 files, making it a critical component for applications dealing with low-level binary file operations. The inclusion of `fd_elf.h` suggests that this file builds upon or complements other ELF-related definitions, providing a comprehensive toolkit for ELF64 file handling.
# Imports and Dependencies

---
- `fd_elf.h`


# Data Structures

---
### fd\_elf64\_ehdr\_
- **Type**: `struct`
- **Members**:
    - `e_ident`: An array of unsigned characters used to identify the file as an ELF object file.
    - `e_type`: An unsigned short that specifies the object file type.
    - `e_machine`: An unsigned short that specifies the architecture for which the file is intended.
    - `e_version`: An unsigned integer that specifies the version of the ELF specification to which the file conforms.
    - `e_entry`: An unsigned long that holds the virtual address to which the system first transfers control, thus starting the process.
    - `e_phoff`: An unsigned long that holds the program header table's file offset in bytes.
    - `e_shoff`: An unsigned long that holds the section header table's file offset in bytes.
    - `e_flags`: An unsigned integer that holds processor-specific flags associated with the file.
    - `e_ehsize`: An unsigned short that holds the ELF header's size in bytes.
    - `e_phentsize`: An unsigned short that holds the size in bytes of one entry in the file's program header table.
    - `e_phnum`: An unsigned short that holds the number of entries in the program header table.
    - `e_shentsize`: An unsigned short that holds the size in bytes of one entry in the section header table.
    - `e_shnum`: An unsigned short that holds the number of entries in the section header table.
    - `e_shstrndx`: An unsigned short that holds the section header table index of the entry associated with the section name string table.
- **Description**: The `fd_elf64_ehdr_` structure represents the header of an ELF64 file, which is a standard format for executable files, object code, shared libraries, and core dumps in Unix-based systems. This packed structure contains various fields that provide essential metadata about the ELF file, such as its type, architecture, entry point, and offsets to the program and section headers. The structure is crucial for the operating system to correctly interpret and execute the contents of the ELF file.


---
### fd\_elf64\_ehdr
- **Type**: `struct`
- **Members**:
    - `e_ident`: An array of unsigned characters that identifies the file as an ELF file.
    - `e_type`: An unsigned short that specifies the object file type.
    - `e_machine`: An unsigned short that specifies the architecture for which the file is intended.
    - `e_version`: An unsigned integer that specifies the version of the ELF specification.
    - `e_entry`: An unsigned long that specifies the entry point address.
    - `e_phoff`: An unsigned long that specifies the offset of the program header table.
    - `e_shoff`: An unsigned long that specifies the offset of the section header table.
    - `e_flags`: An unsigned integer that specifies processor-specific flags.
    - `e_ehsize`: An unsigned short that specifies the size of this header.
    - `e_phentsize`: An unsigned short that specifies the size of a program header table entry.
    - `e_phnum`: An unsigned short that specifies the number of entries in the program header table.
    - `e_shentsize`: An unsigned short that specifies the size of a section header table entry.
    - `e_shnum`: An unsigned short that specifies the number of entries in the section header table.
    - `e_shstrndx`: An unsigned short that specifies the section header string table index.
- **Description**: The `fd_elf64_ehdr` structure represents the header of an ELF64 file, which is a standard file format for executables, object code, shared libraries, and core dumps. This structure contains essential metadata about the ELF file, including its type, architecture, version, entry point, and offsets to the program and section header tables. It is packed to ensure no padding is added between its fields, which is crucial for correctly interpreting the binary data of an ELF file.


---
### fd\_elf64\_phdr\_
- **Type**: `struct`
- **Members**:
    - `p_type`: Specifies the type of the segment.
    - `p_flags`: Contains flags relevant to the segment.
    - `p_offset`: Offset of the segment in the file image.
    - `p_vaddr`: Virtual address of the segment in memory.
    - `p_paddr`: Physical address of the segment, if relevant.
    - `p_filesz`: Size of the segment in the file image.
    - `p_memsz`: Size of the segment in memory.
    - `p_align`: Alignment of the segment in memory.
- **Description**: The `fd_elf64_phdr_` structure represents a segment header in an ELF64 file, which is used to describe a segment or other information the system needs to prepare the program for execution. Each member of the structure provides specific details about the segment, such as its type, memory and file size, and alignment requirements. This structure is crucial for the loader to map the segments into memory correctly.


---
### fd\_elf64\_phdr
- **Type**: `struct`
- **Members**:
    - `p_type`: Specifies the type of the segment.
    - `p_flags`: Contains flags relevant to the segment.
    - `p_offset`: Offset of the segment in the file image.
    - `p_vaddr`: Virtual address of the segment in memory.
    - `p_paddr`: Physical address of the segment, if relevant.
    - `p_filesz`: Size of the segment in the file image.
    - `p_memsz`: Size of the segment in memory.
    - `p_align`: Alignment of the segment in memory and file.
- **Description**: The `fd_elf64_phdr` structure represents a segment header in an ELF64 file, which is used to describe a segment or other information the system needs to prepare the program for execution. Each member of the structure provides specific details about the segment, such as its type, memory and file size, and alignment requirements, which are crucial for the loader to correctly map the segment into memory.


---
### fd\_elf64\_shdr\_
- **Type**: `struct`
- **Members**:
    - `sh_name`: An unsigned integer representing the name of the section.
    - `sh_type`: An unsigned integer indicating the type of the section.
    - `sh_flags`: An unsigned long representing the flags associated with the section.
    - `sh_addr`: An unsigned long indicating the address of the section in memory.
    - `sh_offset`: An unsigned long representing the offset of the section in the file.
    - `sh_size`: An unsigned long indicating the size of the section.
    - `sh_link`: An unsigned integer used for linking information.
    - `sh_info`: An unsigned integer providing additional section information.
    - `sh_addralign`: An unsigned long specifying the alignment of the section.
    - `sh_entsize`: An unsigned long indicating the size of each entry in the section.
- **Description**: The `fd_elf64_shdr_` structure represents a section header in an ELF64 file, which is used to describe the properties and location of a section within the file. Each member of the structure provides specific information about the section, such as its name, type, memory address, file offset, size, and alignment. This structure is crucial for understanding how sections are organized and accessed in an ELF64 file.


---
### fd\_elf64\_shdr
- **Type**: `struct`
- **Members**:
    - `sh_name`: An index into the section header string table section, giving the location of a null-terminated string that names the section.
    - `sh_type`: Categorizes the section's contents and semantics.
    - `sh_flags`: Describes the attributes of the section.
    - `sh_addr`: The virtual address at which the section's first byte should reside in memory.
    - `sh_offset`: The offset of the section's first byte from the beginning of the file.
    - `sh_size`: The size of the section in bytes.
    - `sh_link`: Holds a section header table index link, whose interpretation depends on the section type.
    - `sh_info`: Holds extra information, whose interpretation depends on the section type.
    - `sh_addralign`: Specifies the required alignment of the section.
    - `sh_entsize`: The size of each entry in the section, if the section holds a table of fixed-size entries.
- **Description**: The `fd_elf64_shdr` structure represents a section header in an ELF64 file, which is used to describe the properties and location of a section within the file. Each member of the structure provides specific information about the section, such as its name, type, size, and memory alignment requirements. This structure is crucial for understanding how different sections of an ELF file are organized and accessed.


---
### fd\_elf64\_sym\_
- **Type**: `struct`
- **Members**:
    - `st_name`: An unsigned integer representing the name of the symbol.
    - `st_info`: An unsigned character containing symbol type and binding attributes.
    - `st_other`: An unsigned character for additional symbol visibility information.
    - `st_shndx`: An unsigned short indicating the section index associated with the symbol.
    - `st_value`: An unsigned long representing the value or address of the symbol.
    - `st_size`: An unsigned long specifying the size of the symbol.
- **Description**: The `fd_elf64_sym_` structure is a packed data structure used to represent a symbol table entry in the ELF64 (Executable and Linkable Format) file format. It contains fields for the symbol's name, type, binding, visibility, associated section index, value, and size, which are essential for linking and relocation processes in executable files.


---
### fd\_elf64\_sym
- **Type**: `struct`
- **Members**:
    - `st_name`: An unsigned integer representing the name of the symbol.
    - `st_info`: An unsigned char containing symbol type and binding attributes.
    - `st_other`: An unsigned char for symbol visibility.
    - `st_shndx`: An unsigned short indicating the section index.
    - `st_value`: An unsigned long representing the symbol's value.
    - `st_size`: An unsigned long indicating the size of the symbol.
- **Description**: The `fd_elf64_sym` structure represents a symbol in the ELF64 format, encapsulating information such as the symbol's name, type, binding, visibility, section index, value, and size. This structure is crucial for linking and relocation processes in ELF files, providing metadata necessary for symbol resolution and manipulation.


---
### fd\_elf64\_rel\_
- **Type**: `struct`
- **Members**:
    - `r_offset`: Specifies the location at which the relocation should be applied.
    - `r_info`: Contains both the symbol index and the type of relocation.
- **Description**: The `fd_elf64_rel_` structure is used to represent a relocation entry in an ELF64 file format without an explicit addend. It is packed to ensure no padding is added between its members, which is crucial for binary compatibility. The `r_offset` member indicates where the relocation should be applied in the binary, while `r_info` encodes both the symbol index and the type of relocation, allowing the loader to adjust the binary at runtime.


---
### fd\_elf64\_rel
- **Type**: `struct`
- **Members**:
    - `r_offset`: Specifies the location at which the relocation should be applied.
    - `r_info`: Contains both the symbol table index and the type of relocation to be applied.
- **Description**: The `fd_elf64_rel` structure is used to represent a relocation entry in an ELF64 file format, specifically for relocations that do not include an explicit addend. It contains two members: `r_offset`, which indicates where the relocation is to be applied, and `r_info`, which encodes both the symbol and the type of relocation. This structure is typically used in scenarios where the addend is stored elsewhere, such as in the section to be relocated.


---
### fd\_elf64\_rela\_
- **Type**: `struct`
- **Members**:
    - `r_offset`: Specifies the location at which to apply the relocation action.
    - `r_info`: Contains both the symbol table index and the type of relocation to apply.
    - `r_addend`: Provides a constant addend used to compute the value to be stored in the relocated field.
- **Description**: The `fd_elf64_rela_` structure is used in ELF64 files to represent a relocation entry with an explicit addend. It contains fields for the offset where the relocation is to be applied, information about the relocation type and symbol, and an addend that is used in the relocation calculation. This structure is crucial for dynamic linking and loading, as it allows the adjustment of addresses in a program's code and data sections.


---
### fd\_elf64\_rela
- **Type**: `struct`
- **Members**:
    - `r_offset`: Specifies the location at which the relocation should be applied.
    - `r_info`: Contains both the symbol table index and the type of relocation.
    - `r_addend`: Provides a constant addend used to compute the value to be stored in the relocated field.
- **Description**: The `fd_elf64_rela` structure is used in ELF64 files to represent a relocation entry with an explicit addend. It contains three fields: `r_offset`, which indicates where the relocation is to be applied; `r_info`, which encodes both the symbol and the type of relocation; and `r_addend`, which is an additional constant used in the relocation calculation. This structure is crucial for dynamic linking and loading of ELF64 binaries, allowing for the adjustment of addresses and pointers at runtime.


---
### fd\_elf64\_dyn\_
- **Type**: `struct`
- **Members**:
    - `d_tag`: A long integer representing the type of dynamic entry.
    - `d_un`: A union containing either a value or a pointer, depending on the type of dynamic entry.
- **Description**: The `fd_elf64_dyn_` structure represents an entry in the dynamic section of an ELF64 file, which is used for dynamic linking. It contains a tag (`d_tag`) that specifies the type of dynamic entry, and a union (`d_un`) that can hold either a value (`d_val`) or a pointer (`d_ptr`), depending on the context of the dynamic entry.


---
### fd\_elf64\_dyn
- **Type**: `struct`
- **Members**:
    - `d_tag`: A long integer representing the type of dynamic entry.
    - `d_un`: A union containing either a value or a pointer, depending on the type of dynamic entry.
- **Description**: The `fd_elf64_dyn` structure represents an entry in the dynamic section of an ELF64 file, which is used for dynamic linking. It contains a tag (`d_tag`) that specifies the type of dynamic entry, and a union (`d_un`) that can hold either a value (`d_val`) or a pointer (`d_ptr`), depending on the entry type. This structure is crucial for managing dynamic linking information in ELF64 binaries.


