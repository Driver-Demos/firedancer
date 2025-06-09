# Purpose
The provided C header file, `fd_vm_cpi.h`, defines data structures and type definitions for a cross-program invocation (CPI) API used in a virtual machine environment. This file is part of a larger system that interfaces with the Solana blockchain protocol, providing both C and Rust ABI (Application Binary Interface) representations for handling CPI syscalls. The file includes detailed struct definitions that represent various components of the CPI, such as instructions, account metadata, and account information, in both C and Rust styles. These structures are designed to be used by syscall handlers within the virtual machine, and they include specific alignment and size requirements to ensure compatibility with the VM's address space.

The header file is not intended to be included directly; instead, it should be accessed through another header, `fd_vm_syscall.h`, as indicated by the preprocessor directives. The file provides a clear separation between C and Rust ABI structures, reflecting the dual nature of the Solana protocol's API. It includes packed struct definitions to ensure that data is laid out in memory without padding, which is crucial for maintaining the integrity of data passed between the VM and the syscall handlers. Additionally, the file defines structures for handling Rust's `Rc<RefCell<T>>` types, facilitating checks on Rust account information fields. Overall, this header file is a critical component for enabling secure and efficient cross-program interactions within a virtual machine environment that interfaces with the Solana blockchain.
# Data Structures

---
### fd\_vm\_c\_instruction
- **Type**: `struct`
- **Members**:
    - `program_id_addr`: Stores the address of the program ID in the VM address space.
    - `accounts_addr`: Holds the address of the accounts array in the VM address space.
    - `accounts_len`: Indicates the length of the accounts array.
    - `data_addr`: Contains the address of the data array in the VM address space.
    - `data_len`: Specifies the length of the data array.
- **Description**: The `fd_vm_c_instruction` structure is a packed data structure used in the C ABI for cross-program invocation (CPI) syscall API within a virtual machine environment. It encapsulates information about a program invocation, including the addresses and lengths of the program ID, accounts, and data arrays, all of which are specified in the VM's address space. This structure is designed to facilitate communication between the virtual machine and CPI syscall handlers, ensuring that the necessary data is correctly aligned and accessible despite potential differences in host and VM address space alignments.


---
### fd\_vm\_c\_instruction\_t
- **Type**: `struct`
- **Members**:
    - `program_id_addr`: Holds the address of the program ID in the VM address space.
    - `accounts_addr`: Stores the address of the accounts array in the VM address space.
    - `accounts_len`: Indicates the number of accounts in the accounts array.
    - `data_addr`: Contains the address of the data buffer in the VM address space.
    - `data_len`: Specifies the length of the data buffer.
- **Description**: The `fd_vm_c_instruction_t` structure is part of the C ABI for the cross-program invocation syscall API, used in a virtual machine environment. It encapsulates information necessary for executing a program instruction, including the addresses and lengths of program IDs, accounts, and data buffers, all within the VM's address space. This structure is designed to be packed and has specific alignment and size requirements to ensure compatibility and efficient access in the VM context.


---
### fd\_vm\_c\_account\_meta
- **Type**: `struct`
- **Members**:
    - `pubkey_addr`: Stores the address of the public key in the VM address space.
    - `is_writable`: Indicates if the account is writable (1 for true, 0 for false).
    - `is_signer`: Indicates if the account is a signer (1 for true, 0 for false).
- **Description**: The `fd_vm_c_account_meta` structure is part of the C ABI for the cross-program invocation syscall API, used in the context of virtual machines. It encapsulates metadata about an account, specifically its public key address, and flags indicating whether the account is writable and whether it is a signer. This structure is designed to be used in untrusted environments, with addresses specified in the VM address space, and it supports unaligned access to accommodate potential misalignments between VM and host address spaces.


---
### fd\_vm\_c\_account\_meta\_t
- **Type**: `struct`
- **Members**:
    - `pubkey_addr`: Stores the address of the public key in the VM address space.
    - `is_writable`: Indicates if the account is writable, represented as an unsigned char.
    - `is_signer`: Indicates if the account is a signer, represented as an unsigned char.
- **Description**: The `fd_vm_c_account_meta_t` structure is part of the C ABI for the cross-program invocation syscall API, used in the context of virtual machines. It encapsulates metadata about an account, specifically its public key address, and flags indicating whether the account is writable and whether it is a signer. This structure is designed to be compact and is packed to ensure no padding is added, which is crucial for maintaining alignment and size consistency in the VM address space.


---
### fd\_vm\_c\_account\_info
- **Type**: `struct`
- **Members**:
    - `pubkey_addr`: Stores the address of the public key in the VM address space.
    - `lamports_addr`: Holds the address of the lamports (Solana's native token) in the VM address space.
    - `data_sz`: Indicates the size of the account data.
    - `data_addr`: Points to the address of the account data in the VM address space.
    - `owner_addr`: Contains the address of the account owner in the VM address space.
    - `rent_epoch`: Specifies the epoch at which the account will next be charged rent.
    - `is_signer`: A flag indicating if the account is a signer.
    - `is_writable`: A flag indicating if the account is writable.
    - `executable`: A flag indicating if the account is executable.
- **Description**: The `fd_vm_c_account_info` structure is part of the C ABI for the cross-program invocation syscall API in a virtual machine environment. It encapsulates information about a Solana account, including addresses for the public key, lamports, data, and owner, all within the VM address space. Additionally, it includes metadata such as the size of the account data, the rent epoch, and flags indicating whether the account is a signer, writable, or executable. This structure is crucial for managing account interactions in a secure and efficient manner within the VM.


---
### fd\_vm\_c\_account\_info\_t
- **Type**: `struct`
- **Members**:
    - `pubkey_addr`: Stores the address of the public key in VM address space.
    - `lamports_addr`: Holds the address of the lamports (currency unit) in VM address space.
    - `data_sz`: Indicates the size of the data associated with the account.
    - `data_addr`: Points to the address of the data in VM address space.
    - `owner_addr`: Contains the address of the account owner in VM address space.
    - `rent_epoch`: Specifies the rent epoch for the account.
    - `is_signer`: Indicates if the account is a signer.
    - `is_writable`: Denotes if the account is writable.
    - `executable`: Shows if the account is executable.
- **Description**: The `fd_vm_c_account_info_t` structure is part of the C ABI for the cross-program invocation syscall API, used in the context of virtual machines. It encapsulates information about an account, including addresses for the public key, lamports, data, and owner, as well as metadata such as data size, rent epoch, and flags indicating if the account is a signer, writable, or executable. This structure is designed to be used in untrusted environments, with all addresses being in VM address space, and it supports unaligned access to accommodate potential misalignments between VM and host address spaces.


---
### fd\_vm\_rust\_vec
- **Type**: `struct`
- **Members**:
    - `addr`: Holds the address of the data buffer in the virtual machine's address space.
    - `cap`: Represents the capacity of the vector, indicating the total number of elements it can hold.
    - `len`: Indicates the current number of elements stored in the vector.
- **Description**: The `fd_vm_rust_vec` structure is a packed representation of a Rust-style vector used in the cross-program-invocation (CPI) syscall API, specifically for the Rust ABI. It encapsulates the essential components of a vector: the address of the data buffer (`addr`), the capacity of the vector (`cap`), and the current length of the vector (`len`). This structure is designed to facilitate the handling of dynamic arrays in a virtual machine environment, ensuring that the vector's memory layout is compatible with both the virtual machine and the host system.


---
### fd\_vm\_rust\_vec\_t
- **Type**: `struct`
- **Members**:
    - `addr`: Stores the address of the allocated memory for the vector.
    - `cap`: Represents the capacity of the vector, indicating the total number of elements it can hold without reallocating.
    - `len`: Indicates the current number of elements stored in the vector.
- **Description**: The `fd_vm_rust_vec_t` is a C representation of the Rust `Vec<_>` type, using the default allocator. It is designed to be part of the Rust ABI for the cross-program-invocation syscall API, providing a way to handle dynamic arrays in a memory-efficient manner. The structure includes fields for the memory address, capacity, and current length of the vector, allowing for efficient management and manipulation of dynamic data within the constraints of the virtual machine environment.


---
### fd\_vm\_rust\_instruction
- **Type**: `struct`
- **Members**:
    - `accounts`: A vector pointing to fd_vm_rust_account_meta_t structures.
    - `data`: A vector pointing to a sequence of bytes.
    - `pubkey`: A 32-byte array representing a public key.
- **Description**: The `fd_vm_rust_instruction` structure is part of the Rust ABI for the cross-program-invocation (CPI) syscall API. It encapsulates the necessary information for a CPI instruction, including a vector of account metadata, a vector of data bytes, and a public key. This structure is packed to ensure no padding is added between its fields, which is crucial for maintaining the correct memory layout when interfacing with the virtual machine's address space.


---
### fd\_vm\_rust\_instruction\_t
- **Type**: `struct`
- **Members**:
    - `accounts`: A vector pointing to fd_vm_rust_account_meta_t structures.
    - `data`: A vector pointing to a byte array.
    - `pubkey`: A 32-byte array representing the public key.
- **Description**: The `fd_vm_rust_instruction_t` structure is part of the Rust ABI for the cross-program-invocation (CPI) syscall API. It encapsulates the necessary information for a CPI instruction, including a vector of account metadata, a vector of data bytes, and a public key. This structure is used to facilitate the interaction between the virtual machine and the CPI syscall handlers, ensuring that the instruction data is correctly formatted and aligned according to the Rust ABI requirements.


---
### fd\_vm\_rust\_account\_meta
- **Type**: `struct`
- **Members**:
    - `pubkey`: An array of 32 unsigned characters representing the public key.
    - `is_signer`: An unsigned character indicating if the account is a signer.
    - `is_writable`: An unsigned character indicating if the account is writable.
- **Description**: The `fd_vm_rust_account_meta` structure is a packed data structure used in the Rust ABI for cross-program invocation syscall API. It encapsulates metadata about an account, specifically its public key, and flags indicating whether the account is a signer and whether it is writable. This structure is designed to be compact, with a total size of 34 bytes, and is used to facilitate communication between the virtual machine and the syscall handlers in a Solana-based environment.


---
### fd\_vm\_rust\_account\_meta\_t
- **Type**: `struct`
- **Members**:
    - `pubkey`: A 32-byte array representing the public key of the account.
    - `is_signer`: A single byte indicating if the account is a signer.
    - `is_writable`: A single byte indicating if the account is writable.
- **Description**: The `fd_vm_rust_account_meta_t` structure is part of the Rust ABI for the cross-program-invocation syscall API. It encapsulates metadata about an account, specifically its public key, and flags indicating whether the account is a signer and whether it is writable. This structure is used to convey account metadata from the virtual machine to the syscall handlers, ensuring that the necessary account attributes are available for processing within the Rust environment.


---
### fd\_vm\_rust\_account\_info
- **Type**: `struct`
- **Members**:
    - `pubkey_addr`: Points to an array of 32 unsigned characters representing the public key.
    - `lamports_box_addr`: Points to a reference-counted object with an embedded RefCell pointing to a 64-bit unsigned integer.
    - `data_box_addr`: Points to a reference-counted object with an embedded RefCell containing a slice pointing to bytes.
    - `owner_addr`: Points to an array of 32 unsigned characters representing the owner's public key.
    - `rent_epoch`: Stores the rent epoch as an unsigned long integer.
    - `is_signer`: Indicates if the account is a signer with a single unsigned character.
    - `is_writable`: Indicates if the account is writable with a single unsigned character.
    - `executable`: Indicates if the account is executable with a single unsigned character.
    - `_padding_0`: A 5-byte padding to ensure proper alignment.
- **Description**: The `fd_vm_rust_account_info` structure is a packed data structure used in the Rust ABI for cross-program invocation syscall API. It encapsulates information about an account, including pointers to its public key, lamports, data, and owner, as well as metadata such as rent epoch, signer status, writability, and executability. The structure is designed to be compact and aligned for use in a virtual machine address space, with specific fields pointing to reference-counted objects and slices to manage memory efficiently.


---
### fd\_vm\_rust\_account\_info\_t
- **Type**: `struct`
- **Members**:
    - `pubkey_addr`: Points to a 32-byte public key.
    - `lamports_box_addr`: Points to a reference-counted box containing a RefCell pointing to a 64-bit unsigned integer.
    - `data_box_addr`: Points to a reference-counted box containing a RefCell with a slice pointing to bytes.
    - `owner_addr`: Points to a 32-byte owner public key.
    - `rent_epoch`: Stores the rent epoch as an unsigned long integer.
    - `is_signer`: Indicates if the account is a signer with a single byte.
    - `is_writable`: Indicates if the account is writable with a single byte.
    - `executable`: Indicates if the account is executable with a single byte.
    - `_padding_0`: Padding for alignment, consisting of 5 bytes.
- **Description**: The `fd_vm_rust_account_info_t` structure is part of the Rust ABI for the cross-program-invocation (CPI) syscall API. It encapsulates information about an account, including its public key, lamports, data, owner, and various flags indicating its properties such as whether it is a signer, writable, or executable. The structure uses reference-counted boxes with embedded RefCells to manage memory and ensure safe concurrent access to mutable data. It is designed to align with the memory layout requirements of the Rust ABI, facilitating interactions between the virtual machine and the CPI syscall handlers.


---
### fd\_vm\_rc\_refcell
- **Type**: `struct`
- **Members**:
    - `strong`: Represents the strong reference count for the Rc.
    - `weak`: Represents the weak reference count for the Rc.
    - `borrow`: Tracks the borrow state for the RefCell.
    - `payload`: Holds the underlying data in a flexible array member.
- **Description**: The `fd_vm_rc_refcell` structure is a packed data structure that combines the concepts of Rust's `Rc` (reference counting) and `RefCell` (interior mutability) in a C-compatible format. It includes fields for managing strong and weak reference counts, as well as a borrow count to track mutable and immutable borrows. The `payload` field is a flexible array member that stores the actual data managed by this reference-counted cell. This structure is used to facilitate memory management and safe data access in environments where Rust and C interoperate, particularly in the context of cross-program invocation (CPI) syscalls.


---
### fd\_vm\_rc\_refcell\_t
- **Type**: `struct`
- **Members**:
    - `strong`: Represents the strong reference count for the Rc.
    - `weak`: Represents the weak reference count for the Rc.
    - `borrow`: Tracks the borrow state for the RefCell.
    - `payload`: Holds the underlying data managed by the Rc<RefCell<T>>.
- **Description**: The `fd_vm_rc_refcell_t` structure is a packed data structure that models the in-memory layout of a Rust `Rc<RefCell<T>>` type, which is used to manage shared ownership and interior mutability of data. It includes fields for strong and weak reference counts (`strong` and `weak`), a borrow state (`borrow`), and a flexible array member (`payload`) to store the actual data. This structure is crucial for handling Rust's reference counting and borrowing semantics in a C environment, particularly in the context of cross-program invocation (CPI) syscalls.


---
### fd\_vm\_rc\_refcell\_vec
- **Type**: `struct`
- **Members**:
    - `strong`: Represents the strong reference count for the Rc.
    - `weak`: Represents the weak reference count for the Rc.
    - `borrow`: Tracks the borrow state for the RefCell.
    - `addr`: Holds the address of the slice data.
    - `len`: Stores the length of the slice data.
- **Description**: The `fd_vm_rc_refcell_vec` structure is a packed data structure that combines elements of Rust's Rc and RefCell with a slice, providing a way to manage reference counting and borrowing for a vector-like data structure. It includes fields for strong and weak reference counts, a borrow state, and slice information (address and length), facilitating memory management and data access in a virtual machine context.


---
### fd\_vm\_rc\_refcell\_vec\_t
- **Type**: `struct`
- **Members**:
    - `strong`: Represents the strong reference count for the Rc (Reference Counted) component.
    - `weak`: Represents the weak reference count for the Rc component.
    - `borrow`: Tracks the borrow state for the RefCell component.
    - `addr`: Holds the address of the slice in memory.
    - `len`: Indicates the length of the slice.
- **Description**: The `fd_vm_rc_refcell_vec_t` structure is a packed data structure that combines elements of Rust's Rc (Reference Counted) and RefCell with a vector-like slice. It is designed to manage memory and borrowing semantics in a way that is compatible with Rust's ownership model, while being used in a C environment. The structure includes fields for managing reference counts (`strong` and `weak`), borrow state (`borrow`), and slice information (`addr` and `len`). This allows for safe, concurrent access to shared data, with the ability to dynamically resize the underlying data storage.


---
### fd\_vm\_rc\_refcell\_ref
- **Type**: `struct`
- **Members**:
    - `strong`: Represents the strong reference count for the Rc.
    - `weak`: Represents the weak reference count for the Rc.
    - `borrow`: Tracks the borrow state for the RefCell.
    - `addr`: Holds the address for the Ref.
- **Description**: The `fd_vm_rc_refcell_ref` structure is a packed data structure that combines elements of reference counting and borrowing, typically used in memory management scenarios. It includes fields for managing strong and weak references, as well as a borrow count, which are common in reference-counted smart pointers like Rust's `Rc<RefCell<T>>`. The `addr` field is used to store the address of the reference, facilitating operations that require direct memory access or manipulation.


---
### fd\_vm\_rc\_refcell\_ref\_t
- **Type**: `struct`
- **Members**:
    - `strong`: Represents the strong reference count for the Rc.
    - `weak`: Represents the weak reference count for the Rc.
    - `borrow`: Tracks the borrow state for the RefCell.
    - `addr`: Holds the address of the reference.
- **Description**: The `fd_vm_rc_refcell_ref_t` structure is a packed data structure that models a reference-counted cell with a reference in a virtual machine context. It is designed to handle the memory management of objects that are shared across different parts of a program, using a combination of strong and weak reference counts to manage the lifecycle of the data. The `borrow` field is used to track the borrowing state of the data, ensuring safe access patterns, while the `addr` field holds the address of the reference, allowing for efficient access to the underlying data.


---
### fd\_vm\_cpi\_caller\_account
- **Type**: `struct`
- **Members**:
    - `lamports`: Pointer to the lamports associated with the account.
    - `owner`: Pointer to the public key of the account owner.
    - `orig_data_len`: Original length of the account data.
    - `serialized_data`: Pointer to serialized data, NULL if direct mapping is used.
    - `serialized_data_len`: Length of the serialized data.
    - `vm_data_vaddr`: Virtual machine address of the data.
    - `ref_to_len_in_vm`: Union containing either a pointer to translated length or a virtual address, depending on mapping type.
- **Description**: The `fd_vm_cpi_caller_account` structure is part of the cross-program invocation (CPI) API, used to represent an account in a virtual machine environment. It includes pointers to the account's lamports and owner, as well as information about the account's data, such as its original length and serialized form. The structure also contains a union to handle different mapping scenarios, either storing a pointer to a translated length or a virtual address, depending on whether direct mapping is used. This structure is crucial for managing account data and permissions during CPI operations.


---
### fd\_vm\_cpi\_caller\_account\_t
- **Type**: `struct`
- **Members**:
    - `lamports`: Pointer to the lamports associated with the account.
    - `owner`: Pointer to the public key of the account owner.
    - `orig_data_len`: Original length of the account data.
    - `serialized_data`: Pointer to the serialized data of the account, NULL if direct mapping is used.
    - `serialized_data_len`: Length of the serialized data.
    - `vm_data_vaddr`: Virtual machine address of the data.
    - `ref_to_len_in_vm`: Union containing either a pointer to the translated length or a virtual address, depending on mapping type.
- **Description**: The `fd_vm_cpi_caller_account_t` structure is used in the cross-program-invocation (CPI) syscall API to represent an account in the virtual machine's address space. It includes pointers to the account's lamports and owner, as well as information about the account's data length and serialized data. The structure also contains a union to handle different mapping scenarios, either storing a pointer to the translated length or a virtual address, depending on whether direct mapping is used. This structure is crucial for managing account data and permissions during CPI operations.


