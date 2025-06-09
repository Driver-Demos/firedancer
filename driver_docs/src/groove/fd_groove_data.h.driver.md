# Purpose
The provided C header file, `fd_groove_data.h`, defines a sophisticated memory management system for handling "groove data objects" within a high-performance computing (HPC) environment. This file is part of a larger system that manages memory allocation and deallocation in a lock-free manner, optimized for memory-mapped I/O operations. The core functionality revolves around organizing data into "groove data objects," which are stored in contiguous blocks and grouped into superblocks based on size classes. These superblocks are further organized into larger structures up to the size of an entire groove volume, which are managed by a lock-free volume pool. The file provides detailed structures and functions to manage these allocations, including creating, joining, and deleting groove data, as well as allocating and freeing individual data objects.

Key components of this file include the `fd_groove_data_szc_cfg` structure, which defines the configuration for different size classes, and the [`fd_groove_data_hdr`](#fd_groove_data_hdr_tfd_groove_data_hdr) structure, which encodes metadata about each groove data object. The file also defines several macros for alignment and footprint calculations, ensuring that memory is managed efficiently. The functions provided allow for the creation and management of groove data, including allocation and deallocation of memory, and verification of the integrity of the data structures. This header file is intended to be included in other C source files, providing a public API for managing groove data within the broader system. The design emphasizes performance and scalability, making it suitable for applications requiring efficient memory management in a concurrent environment.
# Imports and Dependencies

---
- `fd_groove_meta.h`
- `fd_groove_volume.h`


# Global Variables

---
### fd\_groove\_data\_szc\_cfg
- **Type**: `fd_groove_data_szc_cfg_t const[32]`
- **Description**: The `fd_groove_data_szc_cfg` is an array of 32 constant structures, each of type `fd_groove_data_szc_cfg_t`. This structure defines the configuration for different size classes of groove data objects, including their footprint, object count, concurrency group mask, and parent size class.
- **Use**: This variable is used to specify the configuration for each size class in the groove data system, allowing for efficient memory management and allocation.


---
### fd\_groove\_data\_new
- **Type**: `void *`
- **Description**: The `fd_groove_data_new` is a function that initializes a memory region to be used as a `fd_groove_data` structure. It takes a pointer to a shared memory region (`shmem`) and formats it to hold the state of a `fd_groove_data`. The function returns the same pointer on success, indicating that the memory region is now owned by the `fd_groove_data` structure.
- **Use**: This function is used to allocate and initialize a memory region for a `fd_groove_data` structure, preparing it for use in managing groove data objects.


---
### fd\_groove\_data\_join
- **Type**: `fd_groove_data_t *`
- **Description**: The `fd_groove_data_join` is a function that returns a pointer to a `fd_groove_data_t` structure. This function is used to join a groove data instance, which involves setting up a local join state for managing groove data objects and volumes.
- **Use**: This function is used to establish a local join to a groove data instance, allowing the caller to manage groove data objects and volumes within the specified memory region.


---
### fd\_groove\_data\_leave
- **Type**: `function pointer`
- **Description**: `fd_groove_data_leave` is a function pointer that takes a pointer to `fd_groove_data_t` as an argument and returns a `void *`. It is used to leave a current local join of a `fd_groove_data` instance, effectively releasing the resources associated with the join.
- **Use**: This function is used to leave a `fd_groove_data` join, returning the memory used for the local join and relinquishing ownership back to the caller.


---
### fd\_groove\_data\_delete
- **Type**: `function pointer`
- **Description**: `fd_groove_data_delete` is a function pointer that takes a single argument, a void pointer `shdata`, and returns a void pointer. This function is responsible for unformatting a memory region that was previously used as a `fd_groove_data` structure.
- **Use**: This function is used to delete or unformat a `fd_groove_data` instance, returning the memory region to the caller and ensuring no current joins exist globally.


---
### fd\_groove\_data\_alloc
- **Type**: `function pointer`
- **Description**: The `fd_groove_data_alloc` function is a global function that allocates a groove data object in the groove data store with specified alignment, size, and an arbitrary user tag. It returns a pointer to the created object, which is aligned and has room for the specified size.
- **Use**: This function is used to allocate memory for groove data objects with specific alignment and size requirements, and it returns a pointer to the allocated memory.


# Data Structures

---
### fd\_groove\_data\_szc\_cfg
- **Type**: `struct`
- **Members**:
    - `obj_footprint`: Defines the footprint of an object, used to calculate the superblock footprint.
    - `obj_cnt`: Specifies the number of objects in the superblock for this size class, ranging from 2 to 64.
    - `cgroup_mask`: Indicates the number of concurrency groups for this size class superblock, as a power-of-2 minus 1.
    - `parent_szc`: Denotes the parent size class, with a special value indicating the use of an entire volume data region.
- **Description**: The `fd_groove_data_szc_cfg` structure is used to configure size classes for groove data objects, which are grouped into superblocks based on their size. Each field in the structure provides specific configuration details: `obj_footprint` helps determine the total footprint of a superblock, `obj_cnt` sets the number of objects within a superblock, `cgroup_mask` configures concurrency groups for parallel processing, and `parent_szc` identifies the parent size class or indicates full volume usage. This configuration is crucial for optimizing memory allocation and management in high-performance computing environments.


---
### fd\_groove\_data\_szc\_cfg\_t
- **Type**: `struct`
- **Members**:
    - `obj_footprint`: Specifies the footprint of an object in the size class, which is a multiple of FD_GROOVE_BLOCK_FOOTPRINT.
    - `obj_cnt`: Indicates the number of objects in the superblock for this size class, ranging from 2 to 64.
    - `cgroup_mask`: Defines the number of concurrency groups for this size class superblock, as a power-of-2 minus 1.
    - `parent_szc`: Specifies the parent size class, with SZC_CNT indicating the use of an entire volume data region.
- **Description**: The `fd_groove_data_szc_cfg_t` structure defines the configuration for a specific size class in the groove data system. It includes details about the footprint of objects within the size class, the number of objects that can be contained within a superblock, the concurrency group mask for managing parallel operations, and the parent size class which can indicate the use of an entire volume data region. This configuration is crucial for organizing and managing memory allocation and usage efficiently within the groove data system, particularly in high-performance computing environments.


---
### fd\_groove\_data\_hdr
- **Type**: `struct`
- **Members**:
    - `bits`: A 64-bit unsigned long integer used to encode various attributes of the groove data object, such as type, index, size class, alignment, and size.
    - `info`: A 64-bit unsigned long integer used to store additional information about the groove data object, such as an object tag or the next superblock.
- **Description**: The `fd_groove_data_hdr` structure is a header for groove data objects, aligned to `FD_GROOVE_DATA_HDR_ALIGN`. It encodes essential metadata about the groove data object, including its type, index within a parent, size class, alignment, and size, using the `bits` field. The `info` field provides additional information, such as an object tag or the next superblock in the case of a superblock type. This structure is designed to be flexible, allowing for the inclusion of additional header-type dependent data, and is optimized for high-performance computing environments with memory-mapped I/O.


---
### fd\_groove\_data\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `bits`: Encodes various details about the groove data object, including type, index, size class, alignment, and size.
    - `info`: Stores additional information about the groove data object, such as an object tag or the next superblock.
- **Description**: The `fd_groove_data_hdr_t` structure is a header that encodes essential details about a groove data object, which is part of a memory management system optimized for high-performance computing. It uses bit fields to store information such as the object's type, index within its parent, size class, alignment, and size. This compact encoding allows efficient management and retrieval of object metadata, facilitating operations like allocation and deallocation within the groove data system. The structure is aligned to 16 bytes and is designed to fit within a single cache line, optimizing access speed.


---
### fd\_groove\_data\_shmem
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity and version of the data structure.
    - `active_slot`: An array indexed by size class and concurrency group, used to track active slots.
    - `inactive_stack`: An array used to track inactive slots, with the least significant 9 bits used as an ABA tag.
    - `volume_pool`: A single-element array of type fd_groove_volume_pool_shmem_t, used for managing volume pools.
- **Description**: The `fd_groove_data_shmem` structure is designed to manage memory allocation and deallocation in a high-performance computing environment. It is aligned to `FD_GROOVE_DATA_ALIGN` and contains fields for managing active and inactive memory slots, as well as a volume pool for lock-free memory management. The structure uses a magic number for integrity checks and employs advanced techniques like ABA tagging to handle concurrency issues. This structure is part of a larger system that organizes memory into size classes and superblocks, optimizing for memory-mapped I/O and bounded size objects.


---
### fd\_groove\_data\_shmem\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A magic number used to verify the integrity and version of the data structure.
    - `active_slot`: An array indexed by size class and concurrency group, used to track active allocations.
    - `inactive_stack`: An array used to track inactive allocations, with ABA tagging for concurrency control.
    - `volume_pool`: A single-element array representing the pool of volumes available for allocation.
- **Description**: The `fd_groove_data_shmem_t` structure is designed to manage memory allocation in a high-performance computing environment, specifically for groove data objects. It includes fields for tracking active and inactive memory slots, ensuring alignment and integrity through a magic number, and managing a pool of memory volumes. The structure is aligned to 128 bytes to optimize memory access patterns and is intended to work with lock-free algorithms for efficient memory management.


---
### fd\_groove\_data
- **Type**: `struct`
- **Members**:
    - `volume_pool`: An array of fd_groove_volume_pool_t representing the local join of the volume pool.
    - `active_slot`: A pointer to the active slot for a specific sizeclass and concurrency group in the local address space.
    - `inactive_stack`: A pointer to the inactive stack for a specific sizeclass in the local address space.
    - `cgroup_hint`: An unsigned long integer representing the concurrency group hint for this join.
- **Description**: The `fd_groove_data` structure is designed to manage groove data objects within a memory-mapped I/O system optimized for high-performance computing. It includes a local join of a volume pool, pointers to active and inactive slots for managing sizeclasses and concurrency groups, and a concurrency group hint. This structure facilitates the organization and allocation of memory blocks in a lock-free manner, supporting efficient data management and retrieval in a concurrent environment.


---
### fd\_groove\_data\_t
- **Type**: `struct`
- **Members**:
    - `volume_pool`: An array of fd_groove_volume_pool_t representing the local join of the volume pool.
    - `active_slot`: A pointer to an array of ulong representing active slots for sizeclass and concurrency group.
    - `inactive_stack`: A pointer to an array of ulong representing inactive stacks for sizeclass.
    - `cgroup_hint`: A ulong representing the concurrency group hint for this join.
- **Description**: The `fd_groove_data_t` structure is designed to manage groove data objects within a memory-mapped I/O environment optimized for high-performance computing. It encapsulates a local join of a volume pool, active slots for managing concurrency groups and size classes, and inactive stacks for managing unused resources. The structure is part of a larger system that organizes data into superblocks and volumes, ensuring efficient allocation and deallocation of memory resources. It supports lock-free operations and is tailored for environments where memory alignment and footprint are critical for performance.


# Functions

---
### fd\_groove\_data\_align<!-- {{#callable:fd_groove_data_align}} -->
The `fd_groove_data_align` function returns the alignment requirement for a memory region to hold a `fd_groove_data`'s state.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended to be used within the same translation unit and optimized by the compiler for performance.
    - It uses the `alignof` operator to determine the alignment requirement of the `fd_groove_data_shmem_t` type.
    - The function returns this alignment value as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the alignment requirement for a `fd_groove_data` memory region.


---
### fd\_groove\_data\_footprint<!-- {{#callable:fd_groove_data_footprint}} -->
The `fd_groove_data_footprint` function returns the memory footprint size of the `fd_groove_data_shmem_t` structure.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, meaning it is intended for use within the same translation unit and suggests the compiler to inline it for performance.
    - It uses the `sizeof` operator to determine the size of the `fd_groove_data_shmem_t` structure.
    - The function returns this size as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the size of the `fd_groove_data_shmem_t` structure.


---
### fd\_groove\_data\_shdata\_const<!-- {{#callable:fd_groove_data_shdata_const}} -->
The `fd_groove_data_shdata_const` function returns a constant pointer to the shared data memory region associated with a given `fd_groove_data_t` structure.
- **Inputs**:
    - `data`: A constant pointer to an `fd_groove_data_t` structure, which contains information about the active slot and other metadata for groove data management.
- **Control Flow**:
    - The function takes a single input, `data`, which is a pointer to a constant `fd_groove_data_t` structure.
    - It calculates the address of the shared data memory region by subtracting `FD_GROOVE_DATA_ALIGN` from the `active_slot` member of the `data` structure.
    - The result is cast to a `void const *` type and returned.
- **Output**: A constant pointer to the shared data memory region, calculated by adjusting the `active_slot` pointer within the `fd_groove_data_t` structure.


---
### fd\_groove\_data\_volume0\_const<!-- {{#callable:fd_groove_data_volume0_const}} -->
The `fd_groove_data_volume0_const` function retrieves a constant pointer to the first volume in the volume pool of a given groove data structure.
- **Inputs**:
    - `data`: A pointer to a constant `fd_groove_data_t` structure, which contains information about the groove data, including its volume pool.
- **Control Flow**:
    - The function calls `fd_groove_volume_pool_shele_const` with the `volume_pool` member of the `data` structure as an argument.
    - It returns the result of the `fd_groove_volume_pool_shele_const` function call.
- **Output**: A constant pointer to the first volume in the volume pool associated with the provided groove data structure.


---
### fd\_groove\_data\_volume1\_const<!-- {{#callable:fd_groove_data_volume1_const}} -->
The `fd_groove_data_volume1_const` function returns a constant pointer to the end of the groove data region within a volume pool.
- **Inputs**:
    - `data`: A pointer to a constant `fd_groove_data_t` structure, which contains information about the groove data and its associated volume pool.
- **Control Flow**:
    - The function first calls `fd_groove_volume_pool_shele_const` with `data->volume_pool` to get a constant pointer to the start of the volume pool.
    - It then casts this pointer to a `fd_groove_volume_t` pointer type.
    - The function adds the result of `fd_groove_volume_pool_ele_max(data->volume_pool)` to this pointer, which represents the maximum number of elements in the volume pool.
    - Finally, it casts the result to a `void const *` and returns it.
- **Output**: A constant pointer to the end of the groove data region, calculated as the start of the volume pool plus the maximum number of elements in the pool.


---
### fd\_groove\_data\_volume\_max<!-- {{#callable:fd_groove_data_volume_max}} -->
The `fd_groove_data_volume_max` function retrieves the maximum number of elements that can be stored in the volume pool of a given groove data structure.
- **Inputs**:
    - `data`: A pointer to a constant `fd_groove_data_t` structure, which contains the volume pool whose maximum element count is to be retrieved.
- **Control Flow**:
    - The function calls `fd_groove_volume_pool_ele_max` with the `volume_pool` member of the `data` structure as an argument.
    - The result of the `fd_groove_volume_pool_ele_max` function call is returned as the output of `fd_groove_data_volume_max`.
- **Output**: The function returns an `ulong` representing the maximum number of elements that can be stored in the volume pool of the provided groove data structure.


---
### fd\_groove\_data\_cgroup\_hint<!-- {{#callable:fd_groove_data_cgroup_hint}} -->
The function `fd_groove_data_cgroup_hint` retrieves the concurrency group hint from a given `fd_groove_data_t` structure.
- **Inputs**:
    - `data`: A pointer to a constant `fd_groove_data_t` structure from which the concurrency group hint is to be retrieved.
- **Control Flow**:
    - The function is defined as a static inline function, which suggests it is intended for use within the same translation unit and optimized for performance.
    - It is marked with `FD_FN_PURE`, indicating that it has no side effects and its return value depends only on its parameters.
    - The function directly accesses the `cgroup_hint` member of the `fd_groove_data_t` structure pointed to by `data` and returns its value.
- **Output**: The function returns an `ulong` representing the concurrency group hint stored in the `fd_groove_data_t` structure.


---
### fd\_groove\_data\_shdata<!-- {{#callable:fd_groove_data_shdata}} -->
The `fd_groove_data_shdata` function calculates and returns a pointer to the shared data memory region associated with a given `fd_groove_data_t` structure.
- **Inputs**:
    - `data`: A pointer to an `fd_groove_data_t` structure, which contains information about the active slot and other metadata for groove data management.
- **Control Flow**:
    - The function takes a single argument, `data`, which is a pointer to an `fd_groove_data_t` structure.
    - It calculates the address of the shared data memory region by subtracting `FD_GROOVE_DATA_ALIGN` from the `active_slot` pointer within the `data` structure.
    - The result is cast to a `void *` and returned.
- **Output**: A `void *` pointer to the shared data memory region, calculated by adjusting the `active_slot` pointer within the `fd_groove_data_t` structure.


---
### fd\_groove\_data\_volume0<!-- {{#callable:fd_groove_data_volume0}} -->
The `fd_groove_data_volume0` function retrieves the base address of the first volume in a groove data's volume pool.
- **Inputs**:
    - `data`: A pointer to an `fd_groove_data_t` structure, which contains information about the groove data's volume pool and other related data.
- **Control Flow**:
    - The function takes a single argument, `data`, which is a pointer to an `fd_groove_data_t` structure.
    - It calls the function `fd_groove_volume_pool_shele` with `data->volume_pool` as the argument.
    - The result of `fd_groove_volume_pool_shele` is returned as the output of the function.
- **Output**: A pointer to the base address of the first volume in the groove data's volume pool.


---
### fd\_groove\_data\_volume1<!-- {{#callable:fd_groove_data_volume1}} -->
The `fd_groove_data_volume1` function calculates and returns a pointer to the end of the groove data region in a volume pool.
- **Inputs**:
    - `data`: A pointer to an `fd_groove_data_t` structure, which contains information about the volume pool and other related data.
- **Control Flow**:
    - The function first retrieves the base address of the volume pool using `fd_groove_volume_pool_shele(data->volume_pool)`.
    - It then calculates the offset to the end of the groove data region by adding the maximum number of elements in the volume pool, obtained via `fd_groove_volume_pool_ele_max(data->volume_pool)`.
    - The result is cast to a `void *` and returned as the end address of the groove data region.
- **Output**: A `void *` pointer to the end of the groove data region in the volume pool.


---
### fd\_groove\_data\_hdr<!-- {{#callable:fd_groove_data_hdr_t::fd_groove_data_hdr}} -->
The `fd_groove_data_hdr` function constructs a `fd_groove_data_hdr_t` structure by encoding various parameters into a single `bits` field and assigns an `info` field.
- **Inputs**:
    - `type`: An unsigned long integer representing the type of the groove data, assumed to be in the range [0, 2^16).
    - `idx`: An unsigned long integer representing the object index in the parent, assumed to be in the range [0, 2^6).
    - `szc`: An unsigned long integer representing the size class, assumed to be in the range [0, 2^7).
    - `align`: An unsigned long integer representing the alignment, assumed to be in the range [0, 2^10).
    - `sz`: An unsigned long integer representing the size, assumed to be in the range [0, 2^25).
    - `info`: An unsigned long integer representing arbitrary additional information.
- **Control Flow**:
    - Initialize a `fd_groove_data_hdr_t` structure named `hdr`.
    - Compute the `bits` field by combining the `type`, `idx`, `szc`, `align`, and `sz` parameters using bitwise operations and shifts.
    - Assign the `info` parameter to the `info` field of the `hdr` structure.
    - Return the constructed `hdr` structure.
- **Output**: The function returns a `fd_groove_data_hdr_t` structure with encoded `bits` and `info` fields.
- **See also**: [`fd_groove_data_hdr_t`](#fd_groove_data_hdr_t)  (Data Structure)


---
### fd\_groove\_data\_hdr\_type<!-- {{#callable:fd_groove_data_hdr_type}} -->
The `fd_groove_data_hdr_type` function extracts the 16-bit magic type from the `bits` field of a `fd_groove_data_hdr_t` structure.
- **Inputs**:
    - `h`: A `fd_groove_data_hdr_t` structure containing the `bits` field from which the magic type is extracted.
- **Control Flow**:
    - The function takes a `fd_groove_data_hdr_t` structure as input.
    - It performs a bitwise AND operation between the `bits` field of the structure and the constant `65535UL` (which is equivalent to `0xFFFF` in hexadecimal) to isolate the lower 16 bits.
    - The result of the bitwise operation, which represents the magic type, is returned as an unsigned long integer.
- **Output**: The function returns an unsigned long integer representing the 16-bit magic type extracted from the `bits` field of the input structure.


---
### fd\_groove\_data\_hdr\_idx<!-- {{#callable:fd_groove_data_hdr_idx}} -->
The `fd_groove_data_hdr_idx` function extracts the object index from a `fd_groove_data_hdr_t` structure's `bits` field.
- **Inputs**:
    - `h`: A `fd_groove_data_hdr_t` structure containing the `bits` field from which the object index is to be extracted.
- **Control Flow**:
    - The function takes a `fd_groove_data_hdr_t` structure as input.
    - It shifts the `bits` field of the structure 16 bits to the right.
    - It applies a bitwise AND operation with `63UL` to extract the 6-bit object index.
- **Output**: The function returns an unsigned long integer representing the object index, which is a value less than 64.


---
### fd\_groove\_data\_hdr\_szc<!-- {{#callable:fd_groove_data_hdr_szc}} -->
The function `fd_groove_data_hdr_szc` extracts the size class index from a `fd_groove_data_hdr_t` structure.
- **Inputs**:
    - `h`: A `fd_groove_data_hdr_t` structure containing encoded groove data object details.
- **Control Flow**:
    - The function takes a `fd_groove_data_hdr_t` structure as input.
    - It shifts the `bits` field of the structure 22 bits to the right.
    - It applies a bitwise AND operation with 127UL to extract the 7-bit size class index.
- **Output**: The function returns an unsigned long integer representing the size class index, which is less than 128.


---
### fd\_groove\_data\_hdr\_align<!-- {{#callable:fd_groove_data_hdr_align}} -->
The function `fd_groove_data_hdr_align` extracts the alignment information from a `fd_groove_data_hdr_t` structure by shifting and masking its `bits` field.
- **Inputs**:
    - `h`: A `fd_groove_data_hdr_t` structure containing encoded groove data object details.
- **Control Flow**:
    - The function takes a `fd_groove_data_hdr_t` structure as input.
    - It shifts the `bits` field of the structure 29 bits to the right.
    - It applies a bitwise AND operation with `1023UL` to extract the 10-bit alignment information.
- **Output**: The function returns an `ulong` representing the alignment of the groove data object, which is a value less than `2^10`.


---
### fd\_groove\_data\_hdr\_sz<!-- {{#callable:fd_groove_data_hdr_sz}} -->
The `fd_groove_data_hdr_sz` function extracts the size of a groove data object or superblock from a given header.
- **Inputs**:
    - `h`: A `fd_groove_data_hdr_t` structure representing the header of a groove data object or superblock.
- **Control Flow**:
    - The function takes a `fd_groove_data_hdr_t` structure as input.
    - It shifts the `bits` field of the structure 39 bits to the right.
    - The result of the shift operation is returned as the size of the groove data object or superblock.
- **Output**: The function returns an `ulong` representing the size of the groove data object or superblock, extracted from the header.


---
### fd\_groove\_data\_hdr\_info<!-- {{#callable:fd_groove_data_hdr_info}} -->
The `fd_groove_data_hdr_info` function retrieves the `info` field from a `fd_groove_data_hdr_t` structure.
- **Inputs**:
    - `h`: A `fd_groove_data_hdr_t` structure from which the `info` field is to be extracted.
- **Control Flow**:
    - The function takes a single argument `h` of type `fd_groove_data_hdr_t`.
    - It directly returns the `info` field of the `h` structure.
- **Output**: The function returns an `ulong` value representing the `info` field of the provided `fd_groove_data_hdr_t` structure.


---
### fd\_groove\_data\_object\_hdr\_const<!-- {{#callable:fd_groove_data_object_hdr_const}} -->
The `fd_groove_data_object_hdr_const` function calculates and returns a pointer to the constant header of a groove data object, given a pointer to the object itself.
- **Inputs**:
    - `obj`: A constant pointer to the groove data object whose header is to be retrieved.
- **Control Flow**:
    - The function takes a constant pointer `obj` as input, which points to a groove data object.
    - It calculates the address of the header by subtracting `FD_GROOVE_DATA_HDR_FOOTPRINT` from the address of `obj`.
    - The resulting address is then aligned down to the nearest multiple of `FD_GROOVE_BLOCK_ALIGN` using the `fd_ulong_align_dn` function.
    - The aligned address is cast to a pointer of type `fd_groove_data_hdr_t const *` and returned.
- **Output**: A pointer to the constant header (`fd_groove_data_hdr_t const *`) of the specified groove data object.


---
### fd\_groove\_data\_superblock\_hdr\_const<!-- {{#callable:fd_groove_data_superblock_hdr_const}} -->
The function `fd_groove_data_superblock_hdr_const` calculates the address of the header for a superblock containing a groove data object, given the object's pointer, size class, and index within its parent superblock.
- **Inputs**:
    - `obj`: A constant pointer to the first byte of the groove data object in the caller's address space.
    - `obj_szc`: An unsigned long integer representing the size class of the object.
    - `parent_idx`: An unsigned long integer representing the index of the object within its parent superblock.
- **Control Flow**:
    - Aligns the object pointer `obj` downwards by subtracting `FD_GROOVE_DATA_HDR_FOOTPRINT` and aligning to `FD_GROOVE_BLOCK_ALIGN`.
    - Calculates the offset for the parent index by multiplying `parent_idx` with the footprint of the object size class from `fd_groove_data_szc_cfg[obj_szc]`.
    - Subtracts the calculated offset and `FD_GROOVE_BLOCK_FOOTPRINT` from the aligned object pointer to get the superblock header address.
- **Output**: Returns a constant pointer to the `fd_groove_data_hdr_t` structure representing the header of the superblock containing the object.


---
### fd\_groove\_data\_szc<!-- {{#callable:fd_groove_data_szc}} -->
The `fd_groove_data_szc` function determines the index of the smallest size class that can accommodate a given footprint from a predefined configuration.
- **Inputs**:
    - `footprint`: An unsigned long integer representing the size of the footprint for which the appropriate size class index is to be determined.
- **Control Flow**:
    - Initialize two variables, `l` and `h`, to represent the lower and upper bounds of the size class index range, respectively.
    - Enter a fixed-count loop that iterates 5 times, assuming the number of size classes (`SZC_CNT`) is less than or equal to 32.
    - In each iteration, calculate the midpoint `m` of the current range `[l, h)` and determine if the size class at `m` can accommodate the given footprint by comparing it to the `obj_footprint` of the size class configuration.
    - Use conditional move operations (`fd_ulong_if`) to adjust the bounds `l` and `h` based on whether the current size class at `m` is large enough to accommodate the footprint.
    - After the loop, return the value of `h`, which represents the index of the tightest fitting size class.
- **Output**: The function returns an unsigned long integer representing the index of the tightest fitting size class for the given footprint.


---
### fd\_groove\_data\_volume\_add<!-- {{#callable:fd_groove_data_volume_add}} -->
The `fd_groove_data_volume_add` function adds a volume to a groove data's volume pool.
- **Inputs**:
    - `data`: A pointer to an `fd_groove_data_t` structure, representing the groove data to which the volume will be added.
    - `volume`: A pointer to the volume to be added to the groove data's volume pool.
    - `footprint`: An unsigned long integer representing the size of the volume to be added.
    - `info`: A constant pointer to additional information associated with the volume.
    - `info_sz`: An unsigned long integer representing the size of the additional information.
- **Control Flow**:
    - The function checks if the `data` pointer is non-null.
    - If `data` is non-null, it uses `data->volume_pool` as the volume pool; otherwise, it uses `NULL`.
    - It calls [`fd_groove_volume_pool_add`](fd_groove_volume.c.driver.md#fd_groove_volume_pool_add) with the determined volume pool, `volume`, `footprint`, `info`, and `info_sz` as arguments.
- **Output**: The function returns the result of the [`fd_groove_volume_pool_add`](fd_groove_volume.c.driver.md#fd_groove_volume_pool_add) function call, which is an integer indicating success or failure.
- **Functions called**:
    - [`fd_groove_volume_pool_add`](fd_groove_volume.c.driver.md#fd_groove_volume_pool_add)


---
### fd\_groove\_data\_volume\_remove<!-- {{#callable:fd_groove_data_volume_remove}} -->
The `fd_groove_data_volume_remove` function removes a volume from the volume pool of a given `fd_groove_data_t` structure.
- **Inputs**:
    - `data`: A pointer to an `fd_groove_data_t` structure, which contains the volume pool from which a volume is to be removed.
- **Control Flow**:
    - The function checks if the `data` pointer is non-null.
    - If `data` is non-null, it accesses the `volume_pool` member of the `fd_groove_data_t` structure.
    - It calls [`fd_groove_volume_pool_remove`](fd_groove_volume.c.driver.md#fd_groove_volume_pool_remove) with the `volume_pool` or `NULL` if `data` is null.
- **Output**: Returns a pointer to the removed volume from the volume pool, or `NULL` if the `data` pointer is null.
- **Functions called**:
    - [`fd_groove_volume_pool_remove`](fd_groove_volume.c.driver.md#fd_groove_volume_pool_remove)


---
### fd\_groove\_data\_free<!-- {{#callable:fd_groove_data_free}} -->
The `fd_groove_data_free` function frees a groove data object from the groove data store.
- **Inputs**:
    - `data`: A pointer to an `fd_groove_data_t` structure representing the groove data store from which the object is to be freed.
    - `obj`: A pointer to the object in the caller's address space that is to be freed from the groove data store.
- **Control Flow**:
    - The function calls [`fd_groove_data_private_free`](fd_groove_data.c.driver.md#fd_groove_data_private_free) with the provided `data` and `obj` pointers, along with a constant `FD_GROOVE_DATA_HDR_TYPE_ALLOC` to specify the type of header expected.
    - The function returns the result of the [`fd_groove_data_private_free`](fd_groove_data.c.driver.md#fd_groove_data_private_free) call.
- **Output**: The function returns an integer indicating success (0) or failure (a negative error code) of the free operation.
- **Functions called**:
    - [`fd_groove_data_private_free`](fd_groove_data.c.driver.md#fd_groove_data_private_free)


---
### fd\_groove\_data\_alloc\_align<!-- {{#callable:fd_groove_data_alloc_align}} -->
The `fd_groove_data_alloc_align` function retrieves the alignment requirement of a groove data object from its header.
- **Inputs**:
    - `obj`: A pointer to a constant object, representing the first byte of a groove data object in the caller's address space.
- **Control Flow**:
    - The function calls [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const) with `obj` to obtain a constant pointer to the object's header.
    - It then dereferences this pointer to get the header structure.
    - Finally, it calls [`fd_groove_data_hdr_align`](#fd_groove_data_hdr_align) with the header to extract and return the alignment value.
- **Output**: The function returns an `ulong` representing the alignment requirement of the groove data object.
- **Functions called**:
    - [`fd_groove_data_hdr_align`](#fd_groove_data_hdr_align)
    - [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const)


---
### fd\_groove\_data\_alloc\_sz<!-- {{#callable:fd_groove_data_alloc_sz}} -->
The `fd_groove_data_alloc_sz` function retrieves the size of a groove data object from its header.
- **Inputs**:
    - `obj`: A pointer to a groove data object whose size is to be determined.
- **Control Flow**:
    - The function calls [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const) with `obj` to get a constant pointer to the object's header.
    - It then dereferences this header pointer to pass it to [`fd_groove_data_hdr_sz`](#fd_groove_data_hdr_sz), which extracts the size information from the header.
    - Finally, it returns the size obtained from [`fd_groove_data_hdr_sz`](#fd_groove_data_hdr_sz).
- **Output**: The function returns an `ulong` representing the size of the groove data object.
- **Functions called**:
    - [`fd_groove_data_hdr_sz`](#fd_groove_data_hdr_sz)
    - [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const)


---
### fd\_groove\_data\_alloc\_tag<!-- {{#callable:fd_groove_data_alloc_tag}} -->
The `fd_groove_data_alloc_tag` function retrieves the tag information from the header of a groove data object.
- **Inputs**:
    - `obj`: A constant pointer to a groove data object from which the tag information is to be retrieved.
- **Control Flow**:
    - The function first calls [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const) with the `obj` pointer to obtain a constant pointer to the object's header.
    - It then dereferences this header pointer to pass it to [`fd_groove_data_hdr_info`](#fd_groove_data_hdr_info), which extracts the tag information from the header.
    - Finally, the function returns the extracted tag information.
- **Output**: The function returns an unsigned long integer representing the tag information of the groove data object.
- **Functions called**:
    - [`fd_groove_data_hdr_info`](#fd_groove_data_hdr_info)
    - [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const)


---
### fd\_groove\_data\_alloc\_start<!-- {{#callable:fd_groove_data_alloc_start}} -->
The `fd_groove_data_alloc_start` function calculates the starting address of a groove data allocation by offsetting the object's header address by 16 bytes.
- **Inputs**:
    - `obj`: A pointer to the groove data object whose allocation start address is to be calculated.
- **Control Flow**:
    - The function calls [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const) with `obj` to get the constant header address of the groove data object.
    - It casts the result to an unsigned long and adds 16 to it, which accounts for the header footprint.
    - The resulting address is cast back to a void pointer and returned as the start of the data allocation.
- **Output**: A void pointer representing the start address of the groove data allocation, offset by 16 bytes from the object's header.
- **Functions called**:
    - [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const)


---
### fd\_groove\_data\_alloc\_stop<!-- {{#callable:fd_groove_data_alloc_stop}} -->
The `fd_groove_data_alloc_stop` function calculates the end address of a groove data object allocation based on its header and size class configuration.
- **Inputs**:
    - `obj`: A pointer to the groove data object whose allocation end address is to be calculated.
- **Control Flow**:
    - Retrieve the constant header of the groove data object using [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const) function.
    - Determine the size class of the object using [`fd_groove_data_hdr_szc`](#fd_groove_data_hdr_szc) function on the header.
    - Access the size class configuration array `fd_groove_data_szc_cfg` using the size class index to get the object's footprint.
    - Calculate the end address by adding the object's footprint to the header's address and return it.
- **Output**: A pointer to the end address of the allocated groove data object.
- **Functions called**:
    - [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const)
    - [`fd_groove_data_hdr_szc`](#fd_groove_data_hdr_szc)


---
### fd\_groove\_data\_alloc\_start\_const<!-- {{#callable:fd_groove_data_alloc_start_const}} -->
The `fd_groove_data_alloc_start_const` function returns a pointer to the start of the data section of a groove data object, offset by 16 bytes from its header.
- **Inputs**:
    - `obj`: A constant pointer to the groove data object whose data section start is to be determined.
- **Control Flow**:
    - The function calls [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const) with `obj` to get a pointer to the object's header.
    - It casts the result to an unsigned long and adds 16 to it, effectively moving the pointer 16 bytes past the header.
    - The result is cast back to a constant void pointer and returned.
- **Output**: A constant void pointer to the start of the data section of the groove data object, 16 bytes past the header.
- **Functions called**:
    - [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const)


---
### fd\_groove\_data\_alloc\_stop\_const<!-- {{#callable:fd_groove_data_alloc_stop_const}} -->
The `fd_groove_data_alloc_stop_const` function calculates the end address of a groove data object based on its header and size class configuration.
- **Inputs**:
    - `obj`: A constant pointer to the groove data object whose end address is to be calculated.
- **Control Flow**:
    - Retrieve the constant header of the groove data object using [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const) function.
    - Extract the size class (szc) from the header using [`fd_groove_data_hdr_szc`](#fd_groove_data_hdr_szc).
    - Access the size class configuration array `fd_groove_data_szc_cfg` using the extracted szc to get the object's footprint.
    - Calculate the end address by adding the object's footprint to the header's address and return it as a constant pointer.
- **Output**: A constant pointer to the calculated end address of the groove data object.
- **Functions called**:
    - [`fd_groove_data_object_hdr_const`](#fd_groove_data_object_hdr_const)
    - [`fd_groove_data_hdr_szc`](#fd_groove_data_hdr_szc)


# Function Declarations (Public API)

---
### fd\_groove\_data\_new<!-- {{#callable_declaration:fd_groove_data_new}} -->
Formats a memory region into a groove data object.
- **Description**: This function initializes a memory region to be used as a groove data object, provided the memory is correctly aligned and has the necessary footprint. It should be called when you need to set up a new groove data object in a shared memory region. The function requires that the memory region is aligned according to the groove data alignment requirements and that it has a sufficient footprint. If these conditions are not met, or if the memory region is null, the function will return null and log a warning. On success, it returns the pointer to the initialized memory region, which the groove data object will own.
- **Inputs**:
    - `shmem`: A pointer to the memory region to be formatted as a groove data object. It must not be null and must be aligned according to the groove data alignment requirements. If the pointer is null or misaligned, the function returns null and logs a warning.
- **Output**: Returns the pointer to the initialized memory region on success, or null on failure.
- **See also**: [`fd_groove_data_new`](fd_groove_data.c.driver.md#fd_groove_data_new)  (Implementation)


---
### fd\_groove\_data\_join<!-- {{#callable_declaration:fd_groove_data_join}} -->
Joins a groove data structure to the caller's address space.
- **Description**: This function is used to join a groove data structure, allowing the caller to interact with it in their address space. It requires valid pointers to a local join state, shared memory data, and a reserved volume mapping area. The function also takes a maximum volume count and a concurrency group hint. It must be called with properly aligned and non-null pointers, and the shared memory data must have a valid magic number. If any preconditions are not met, the function will log a warning and return NULL.
- **Inputs**:
    - `ljoin`: A pointer to a memory region in the caller's address space for the local join state. Must not be null and must be properly aligned.
    - `shdata`: A pointer to the shared memory region containing the groove data. Must not be null, must be properly aligned, and must have a valid magic number.
    - `volume0`: A pointer to the start of the reserved area for mapping groove volumes in the caller's address space. Must not be null and must be properly aligned.
    - `volume_max`: The maximum number of volumes that can be mapped starting at volume0. If zero, a default maximum is used.
    - `cgroup_hint`: A concurrency group hint for the join operation.
- **Output**: Returns a pointer to the local join on success, or NULL on failure.
- **See also**: [`fd_groove_data_join`](fd_groove_data.c.driver.md#fd_groove_data_join)  (Implementation)


---
### fd\_groove\_data\_leave<!-- {{#callable_declaration:fd_groove_data_leave}} -->
Leaves a groove data join and returns the memory used for the local join.
- **Description**: This function is used to leave a current local join of a groove data instance. It should be called when the caller no longer needs to be joined to the groove data, allowing the caller to reclaim the memory used for the local join. The function must be called with a valid pointer to a current local join. If the join is null or if leaving the volume pool fails, the function will log a warning and return null, indicating that the leave operation was unsuccessful.
- **Inputs**:
    - `join`: A pointer to a fd_groove_data_t structure representing the current local join. Must not be null. The caller retains ownership of the memory.
- **Output**: Returns a pointer to the memory used for the local join on success, allowing the caller to reclaim it. Returns null on failure, indicating that the leave operation was unsuccessful.
- **See also**: [`fd_groove_data_leave`](fd_groove_data.c.driver.md#fd_groove_data_leave)  (Implementation)


---
### fd\_groove\_data\_delete<!-- {{#callable_declaration:fd_groove_data_delete}} -->
Unformats a memory region used as a groove data object.
- **Description**: This function is used to unformat a memory region that was previously formatted as a groove data object, effectively deleting the groove data structure. It should be called when the groove data is no longer needed and there are no active joins globally. This function returns the memory region to the caller, who regains ownership. It logs a warning and returns NULL if the input is NULL, misaligned, or if the magic number does not match the expected value, indicating potential misuse or corruption.
- **Inputs**:
    - `shdata`: A pointer to the memory region containing the groove data. It must not be NULL, must be properly aligned according to fd_groove_data_align(), and must have a valid magic number (FD_GROOVE_DATA_MAGIC). If these conditions are not met, the function logs a warning and returns NULL.
- **Output**: Returns the input pointer on success, indicating the caller has regained ownership of the memory region. Returns NULL on failure, with no change in ownership.
- **See also**: [`fd_groove_data_delete`](fd_groove_data.c.driver.md#fd_groove_data_delete)  (Implementation)


---
### fd\_groove\_data\_alloc<!-- {{#callable_declaration:fd_groove_data_alloc}} -->
Allocates a groove data object with specified alignment, size, and tag.
- **Description**: This function is used to allocate a groove data object within a groove data store, providing control over the alignment, size, and an arbitrary user-defined tag for the object. It should be called when a new data object is needed in a groove data store that has been properly initialized and joined. The function ensures that the alignment is a power of two and within the allowed maximum, defaulting to a predefined alignment if zero is specified. The size and alignment must be such that the total footprint does not exceed the maximum allowed. On success, it returns a pointer to the allocated object, which remains valid until the object is freed or the data store is destroyed. If an error occurs, the function returns NULL and sets an error code if the optional error pointer is provided.
- **Inputs**:
    - `data`: A pointer to a fd_groove_data_t structure representing the current local join of the groove data store. Must not be NULL.
    - `align`: The desired alignment for the allocation, which must be a power of two and not exceed FD_GROOVE_DATA_ALLOC_ALIGN_MAX. If zero, defaults to FD_GROOVE_DATA_ALLOC_ALIGN_DEFAULT.
    - `sz`: The size of the allocation in bytes. Must be such that the total footprint does not exceed FD_GROOVE_DATA_ALLOC_FOOTPRINT_MAX.
    - `tag`: An arbitrary user-defined tag associated with the allocation.
    - `_err`: A pointer to an integer where the error code will be stored if the allocation fails. If NULL, a temporary storage is used internally.
- **Output**: Returns a pointer to the allocated object on success, or NULL on failure. If _err is provided, it will contain an error code indicating the reason for failure.
- **See also**: [`fd_groove_data_alloc`](fd_groove_data.c.driver.md#fd_groove_data_alloc)  (Implementation)


---
### fd\_groove\_data\_private\_free<!-- {{#callable_declaration:fd_groove_data_private_free}} -->
Frees a groove data object from the data store.
- **Description**: Use this function to free a previously allocated groove data object, ensuring that the object is no longer valid in the groove data store. This function should be called when the object is no longer needed, and it is important to ensure that the object is not used after this call. The function requires a valid local join to the groove data and a valid object pointer. It performs various checks to ensure the integrity of the data store and logs warnings if any issues are detected. The function returns an error code if the operation fails due to invalid inputs or data corruption.
- **Inputs**:
    - `data`: A pointer to a valid fd_groove_data_t structure representing the current local join. Must not be null.
    - `_obj`: A pointer to the first byte of the object to be freed in the caller's address space. Must not be null.
    - `exp_type`: An unsigned long representing the expected type of the object. This is used for validation purposes.
- **Output**: Returns FD_GROOVE_SUCCESS (0) on success, or a negative FD_GROOVE_ERR code on failure, indicating the type of error encountered.
- **See also**: [`fd_groove_data_private_free`](fd_groove_data.c.driver.md#fd_groove_data_private_free)  (Implementation)


---
### fd\_groove\_data\_verify<!-- {{#callable_declaration:fd_groove_data_verify}} -->
Verifies the integrity of a groove data instance.
- **Description**: Use this function to ensure that a given groove data instance is correctly configured and not corrupted. It checks the alignment, volume pool, data shmem, sizeclass configuration, and both active and inactive superblocks. This function should be called when the groove data is idle and assumes that the provided data is a current local join. It returns a success code if the data is valid and a corruption error code otherwise.
- **Inputs**:
    - `data`: A pointer to a constant fd_groove_data_t structure representing the groove data instance to verify. Must not be null and must be aligned according to the alignment requirements of fd_groove_data_t. The caller retains ownership.
- **Output**: Returns FD_GROOVE_SUCCESS if the groove data instance is valid, or FD_GROOVE_ERR_CORRUPT if it is not, logging details in the latter case.
- **See also**: [`fd_groove_data_verify`](fd_groove_data.c.driver.md#fd_groove_data_verify)  (Implementation)


---
### fd\_groove\_data\_volume\_verify<!-- {{#callable_declaration:fd_groove_data_volume_verify}} -->
Verifies the integrity of a groove volume within a groove data instance.
- **Description**: Use this function to ensure that a specific groove volume, mapped into the caller's address space, is valid and correctly structured within a groove data instance. This function should be called when the groove data is idle and the caller is currently joined to the groove data. It is suitable for parallel execution, allowing multiple volumes to be verified simultaneously. The function checks various structural and alignment properties of the volume and logs details if any corruption is detected.
- **Inputs**:
    - `data`: A pointer to a constant fd_groove_data_t structure representing the groove data instance. Must not be null and should be a current local join.
    - `_volume`: A pointer to a constant fd_groove_volume_t structure representing the volume to verify. Must be within the valid range of volumes for the given groove data instance.
- **Output**: Returns FD_GROOVE_SUCCESS if the volume is valid, or FD_GROOVE_ERR_CORRUPT if any issues are detected, with details logged.
- **See also**: [`fd_groove_data_volume_verify`](fd_groove_data.c.driver.md#fd_groove_data_volume_verify)  (Implementation)


