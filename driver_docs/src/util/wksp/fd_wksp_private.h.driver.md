# Purpose
The provided C header file, `fd_wksp_private.h`, is a private header for managing workspace partitions in a memory management system. It defines the internal structures and functions necessary for handling memory partitions within a workspace (`fd_wksp_t`). The file includes definitions for managing partition information (`fd_wksp_private_pinfo_t`), which includes details about memory ranges, partition status (free or used), and relationships between partitions. The header also defines constants and macros for aligning and managing partition indices, as well as functions for manipulating partition stacks and treaps (tree-heap data structures) used to efficiently manage free and used memory partitions.

The file provides a comprehensive set of APIs for internal use, including functions for locking and unlocking workspaces, managing idle partition stacks, and inserting or removing partitions from used and free treaps. It also includes structures and functions for handling workspace checkpoints, which are used to save and restore the state of a workspace. The header is designed to be used internally within a larger system, as indicated by its focus on private data structures and functions, and it does not define public APIs or external interfaces. The file is intended to be included in other source files that require direct access to the internal workings of the workspace management system.
# Imports and Dependencies

---
- `fd_wksp.h`


# Data Structures

---
### fd\_wksp\_private\_pinfo
- **Type**: `struct`
- **Members**:
    - `gaddr_lo`: Specifies the lower bound of the global address range for the partition, or 0 if idle.
    - `gaddr_hi`: Specifies the upper bound of the global address range for the partition, or 0 if idle.
    - `tag`: Indicates if the partition is free (0) or allocated (non-zero).
    - `heap_prio`: A 31-bit field representing the heap priority, with 1 bit reserved for infinite priority operations.
    - `in_same`: A 1-bit flag indicating if the partition is part of a list of partitions with the same size.
    - `prev_cidx`: Compressed index of the previous partition, or a null index if none.
    - `next_cidx`: Compressed index of the next partition, or a null index if none.
    - `left_cidx`: Compressed index of the left child in a binary tree structure, or a null index if none.
    - `right_cidx`: Compressed index of the right child in a binary tree structure, or a null index if none.
    - `parent_cidx`: Compressed index of the parent partition, or a null index if none.
    - `same_cidx`: Compressed index of the next partition of the same size, or a null index if none.
    - `stack_cidx`: Used internally for stack operations.
    - `cycle_tag`: Used internally for cycle detection.
- **Description**: The `fd_wksp_private_pinfo` structure is used to manage partitions within a workspace, detailing their address range, allocation status, and relationships to other partitions. It supports operations for both used and free partitions, organizing them into treaps for efficient searching and management. The structure includes fields for managing binary tree relationships, priority for balancing, and internal use fields for stack and cycle operations. This structure is crucial for maintaining the integrity and efficiency of workspace partitioning and allocation.


---
### fd\_wksp\_private\_pinfo\_t
- **Type**: `struct`
- **Members**:
    - `gaddr_lo`: Specifies the lower bound of the global address range for the partition, or 0 if idle.
    - `gaddr_hi`: Specifies the upper bound of the global address range for the partition, or 0 if idle.
    - `tag`: Indicates whether the partition is free (tag==0) or allocated.
    - `heap_prio`: A 31-bit field representing the heap priority for balancing treaps.
    - `in_same`: A 1-bit flag indicating if the partition is part of a list of same-sized partitions.
    - `prev_cidx`: Compressed index of the previous partition, or IDX_NULL if none.
    - `next_cidx`: Compressed index of the next partition, or IDX_NULL if none.
    - `left_cidx`: Compressed index of the left child in the treap, or IDX_NULL if none.
    - `right_cidx`: Compressed index of the right child in the treap, or IDX_NULL if none.
    - `parent_cidx`: Compressed index of the parent partition in the treap, or IDX_NULL if none.
    - `same_cidx`: Compressed index of the next partition of the same size, or IDX_NULL if none.
    - `stack_cidx`: Used internally for managing the idle stack.
    - `cycle_tag`: Used internally for cycle detection.
- **Description**: The `fd_wksp_private_pinfo_t` structure is used to manage partitions within a workspace, detailing their boundaries, status, and relationships with other partitions. It supports both free and used partitions, organizing them into treaps for efficient management. The structure includes fields for managing partition indices, heap priorities for balancing, and flags for indicating partition status. It is aligned to 64 bytes and is designed to be efficient in both space and access time, supporting operations like allocation, deallocation, and partition merging or splitting.


---
### fd\_wksp\_private
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the memory layout, expected to be FD_WKSP_MAGIC.
    - `part_max`: Specifies the maximum number of workspace partitions.
    - `data_max`: Defines the size of the data region.
    - `gaddr_lo`: The lower bound of the data region offsets, calculated as fd_wksp_private_data_off(part_max).
    - `gaddr_hi`: The upper bound of the data region offsets, calculated as gaddr_lo + data_max.
    - `name`: A string representing the name of the backing fd_shmem region.
    - `seed`: A random number seed used for heap priority.
    - `idle_top_cidx`: Index of the top of the stack of partition infos not in use.
    - `part_head_cidx`: Index for the leftmost partition information.
    - `part_tail_cidx`: Index for the rightmost partition information.
    - `part_used_cidx`: Index for the treap of currently used partitions, searchable by gaddr.
    - `part_free_cidx`: Index for the treap of currently free partitions, searchable by size.
    - `cycle_tag`: Used for detecting cycles in the data structure.
    - `owner`: Thread group ID of the owner or NULL if unowned.
- **Description**: The `fd_wksp_private` structure defines the internal layout of a workspace, managing both static and dynamic metadata for partitioning and memory allocation. It includes fields for identifying the workspace, managing partition limits, and maintaining auxiliary data structures for efficient memory management. The structure is designed to be cache-friendly, with static fields aligned to the first cache line and dynamic fields in the adjacent cache line. It supports operations such as partition allocation and deallocation, with auxiliary structures like idle stacks and treaps for used and free partitions, ensuring efficient and reliable workspace management.


---
### fd\_wksp\_checkpt\_v2\_hdr
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the structure, must be equal to FD_WKSP_MAGIC.
    - `style`: Indicates the workspace checkpoint style.
    - `frame_style_compressed`: Specifies the frame style used for compressed frames.
    - `reserved`: Padding for alignment purposes.
    - `name`: A character string holding the original workspace name, with a maximum length defined by FD_SHMEM_NAME_MAX.
    - `seed`: The seed value used when the workspace was checkpointed, likely the same as used during construction.
    - `part_max`: The maximum number of partitions used to construct the workspace.
    - `data_max`: The maximum data size used to construct the workspace.
- **Description**: The `fd_wksp_checkpt_v2_hdr` structure defines the header layout for a version 2 workspace checkpoint. It includes metadata such as a magic number for validation, style indicators for the checkpoint and frame compression, and workspace-specific details like its name, seed, and maximum partition and data sizes. This header is crucial for identifying and managing the workspace's checkpointed state.


---
### fd\_wksp\_checkpt\_v2\_hdr\_t
- **Type**: `struct`
- **Members**:
    - `magic`: A unique identifier for the memory layout, must be FD_WKSP_MAGIC.
    - `style`: Specifies the checkpoint style.
    - `frame_style_compressed`: Indicates the compression style used for frames.
    - `reserved`: Padding for alignment purposes.
    - `name`: A string holding the original workspace name.
    - `seed`: The seed used for the workspace when checkpointed.
    - `part_max`: The maximum number of partitions used to construct the workspace.
    - `data_max`: The maximum data size used to construct the workspace.
- **Description**: The `fd_wksp_checkpt_v2_hdr_t` structure defines the header for a version 2 workspace checkpoint. It contains metadata about the checkpoint, including a magic number for validation, the style of the checkpoint, compression details, and workspace-specific information such as its name, seed, and partition and data limits. This header is crucial for interpreting the subsequent frames in the checkpoint file, ensuring that the data is correctly understood and processed.


---
### fd\_wksp\_checkpt\_v2\_info
- **Type**: `struct`
- **Members**:
    - `mode`: Represents the mode of the checkpoint.
    - `wallclock`: Stores the wallclock time associated with the checkpoint.
    - `app_id`: Identifier for the application.
    - `thread_id`: Identifier for the thread.
    - `host_id`: Identifier for the host.
    - `cpu_id`: Identifier for the CPU.
    - `group_id`: Identifier for the group.
    - `tid`: Thread identifier.
    - `user_id`: Identifier for the user.
    - `sz_app`: Size of the application name, in the range [1, FD_LOG_NAME_MAX].
    - `sz_thread`: Size of the thread name, in the range [1, FD_LOG_NAME_MAX].
    - `sz_host`: Size of the host name, in the range [1, FD_LOG_NAME_MAX].
    - `sz_cpu`: Size of the CPU name, in the range [1, FD_LOG_NAME_MAX].
    - `sz_group`: Size of the group name, in the range [1, FD_LOG_NAME_MAX].
    - `sz_user`: Size of the user name, in the range [1, FD_LOG_NAME_MAX].
    - `sz_path`: Size of the path, in the range [1, PATH_MAX].
    - `sz_binfo`: Size of the build info, in the range [1, FD_WKSP_CHECKPT_V2_BINFO_MAX].
    - `sz_uinfo`: Size of the user info, in the range [1, FD_WKSP_CHECKPT_V2_UINFO_MAX].
- **Description**: The `fd_wksp_checkpt_v2_info` structure is used to store metadata information for a version 2 workspace checkpoint. It includes various identifiers such as application, thread, host, CPU, group, and user IDs, along with their respective sizes. The structure also holds information about the mode and wallclock time of the checkpoint. The size fields are used to define the layout of the buffer that follows the info structure, ensuring that the data is stored compactly and efficiently. This structure is crucial for managing and restoring workspace checkpoints in a consistent and organized manner.


---
### fd\_wksp\_checkpt\_v2\_info\_t
- **Type**: `struct`
- **Members**:
    - `mode`: Represents the mode of the checkpoint.
    - `wallclock`: Stores the wallclock time when the checkpoint was created.
    - `app_id`: Holds the application identifier.
    - `thread_id`: Contains the thread identifier.
    - `host_id`: Stores the host identifier.
    - `cpu_id`: Holds the CPU identifier.
    - `group_id`: Contains the group identifier.
    - `tid`: Stores the thread ID.
    - `user_id`: Holds the user identifier.
    - `sz_app`: Indicates the size of the application name string.
    - `sz_thread`: Indicates the size of the thread name string.
    - `sz_host`: Indicates the size of the host name string.
    - `sz_cpu`: Indicates the size of the CPU name string.
    - `sz_group`: Indicates the size of the group name string.
    - `sz_user`: Indicates the size of the user name string.
    - `sz_path`: Indicates the size of the path string.
    - `sz_binfo`: Indicates the size of the build info string.
    - `sz_uinfo`: Indicates the size of the user info string.
- **Description**: The `fd_wksp_checkpt_v2_info_t` structure defines the layout of frame 1 in a version 2 workspace checkpoint. It contains metadata about the checkpoint, including identifiers for the application, thread, host, CPU, group, and user, as well as sizes for various strings related to the checkpoint. This structure is used to store and manage information necessary for reconstructing the state of a workspace at the time of the checkpoint.


---
### fd\_wksp\_checkpt\_v2\_cmd
- **Type**: `union`
- **Members**:
    - `meta`: Contains a tag greater than 0 and two ulong fields for low and high global addresses.
    - `data`: Contains a tag equal to 0, a cgroup count equal to ULONG_MAX, and a frame offset equal to ULONG_MAX.
    - `appendix`: Contains a tag equal to 0, a cgroup count less than ULONG_MAX, and a frame offset less than ULONG_MAX.
    - `volumes`: Contains a tag equal to 0, a cgroup count equal to ULONG_MAX, and a frame offset less than ULONG_MAX.
- **Description**: The `fd_wksp_checkpt_v2_cmd` union is a versatile data structure used in the context of workspace checkpointing, specifically for version 2 of the checkpointing process. It encapsulates four different command types, each represented by a struct with specific fields. The `meta` struct is used for metadata commands with a positive tag and global address range. The `data` struct is used for data commands, indicating the start of a data section with specific constraints on cgroup count and frame offset. The `appendix` struct is used for appendix commands, which provide information about cgroup frames and their offsets. Lastly, the `volumes` struct is used for volume commands, indicating the presence of volumes with specific constraints on cgroup count and frame offset. This union allows for efficient handling of different command types within the checkpointing process.


---
### fd\_wksp\_checkpt\_v2\_cmd\_t
- **Type**: `union`
- **Members**:
    - `meta`: Contains a tag greater than 0 and two ulong fields for address range.
    - `data`: Contains a tag of 0, a cgroup count of ULONG_MAX, and a frame offset of ULONG_MAX.
    - `appendix`: Contains a tag of 0, a cgroup count less than ULONG_MAX, and a frame offset less than ULONG_MAX.
    - `volumes`: Contains a tag of 0, a cgroup count of ULONG_MAX, and a frame offset less than ULONG_MAX.
- **Description**: The `fd_wksp_checkpt_v2_cmd_t` is a union data structure used in the context of workspace checkpointing in version 2. It supports different command types for handling metadata, data, appendix, and volume information during the checkpointing process. Each command type is distinguished by specific values in its fields, allowing the system to identify and process the command appropriately. This structure facilitates efficient management of large checkpoints by enabling streaming and parallel restoration of frames.


---
### fd\_wksp\_checkpt\_v2\_ftr
- **Type**: `struct`
- **Members**:
    - `alloc_cnt`: Total number of allocations in the checkpoint.
    - `cgroup_cnt`: Total number of cgroups in the checkpoint.
    - `volume_cnt`: Total number of volumes in the checkpoint.
    - `frame_off`: Byte offset of the volumes command relative to the header initial byte.
    - `checkpt_sz`: Byte size of the checkpoint from the header initial byte to the footer final byte inclusive.
    - `data_max`: Should match the header's data_max value.
    - `part_max`: Should match the header's part_max value.
    - `seed`: Should match the header's seed value.
    - `name`: Should match the header's name value.
    - `reserved`: Reserved field for future use.
    - `frame_style_compressed`: Should match the header's frame_style_compressed value.
    - `style`: Should match the header's style value.
    - `unmagic`: Should be the bitwise negation of FD_WKSP_MAGIC.
- **Description**: The `fd_wksp_checkpt_v2_ftr` structure represents the footer of a version 2 workspace checkpoint, containing metadata necessary for interpreting the checkpoint data. It includes counts of allocations, cgroups, and volumes, as well as offsets and sizes for navigating the checkpoint. The structure also ensures consistency with the header by matching several fields, and it includes a unique 'unmagic' value for validation purposes.


---
### fd\_wksp\_checkpt\_v2\_ftr\_t
- **Type**: `struct`
- **Members**:
    - `alloc_cnt`: Total number of allocations in the checkpoint.
    - `cgroup_cnt`: Total number of cgroups in the checkpoint.
    - `volume_cnt`: Total number of volumes in the checkpoint.
    - `frame_off`: Byte offset of the volumes command relative to the header initial byte.
    - `checkpt_sz`: Total byte size of the checkpoint from the header initial byte to the footer final byte inclusive.
    - `data_max`: Maximum data size, should match the header.
    - `part_max`: Maximum partition size, should match the header.
    - `seed`: Random seed used, should match the header.
    - `name`: Name of the shared memory region, should match the header.
    - `reserved`: Reserved for future use, should match the header.
    - `frame_style_compressed`: Compression style of the frame, should match the header.
    - `style`: Checkpoint style, should match the header.
    - `unmagic`: Inverse of the magic number, used for validation.
- **Description**: The `fd_wksp_checkpt_v2_ftr_t` structure defines the layout of the final frame of a workspace version 2 checkpoint. It contains metadata necessary for reconstructing the checkpoint, including counts of allocations, cgroups, and volumes, as well as offsets and sizes for navigating the checkpoint data. The structure also includes fields that should match the corresponding header values, ensuring consistency and integrity of the checkpoint data. The `unmagic` field is used for validation purposes, being the bitwise inverse of the magic number.


# Functions

---
### fd\_wksp\_private\_pinfo\_sz<!-- {{#callable:fd_wksp_private_pinfo_sz}} -->
The function `fd_wksp_private_pinfo_sz` calculates the size of a workspace partition in bytes by subtracting the lower address boundary from the upper address boundary.
- **Inputs**:
    - `pinfo`: A pointer to a `fd_wksp_private_pinfo_t` structure, which contains information about a partition in a workspace.
- **Control Flow**:
    - The function takes a single argument, `pinfo`, which is a pointer to a `fd_wksp_private_pinfo_t` structure.
    - It calculates the size of the partition by subtracting `gaddr_lo` from `gaddr_hi` within the `pinfo` structure.
- **Output**: The function returns an `ulong` representing the size of the partition in bytes, which is guaranteed to be positive.


---
### fd\_wksp\_private\_pinfo\_off<!-- {{#callable:fd_wksp_private_pinfo_off}} -->
The function `fd_wksp_private_pinfo_off` returns a constant offset value used for aligning workspace partition information.
- **Inputs**: None
- **Control Flow**:
    - The function is defined as a static inline function, indicating it is intended for use within the same translation unit and should be inlined by the compiler.
    - The function does not take any parameters.
    - It directly returns the constant value `128UL`, which is a pre-calculated aligned offset for workspace partition information.
- **Output**: The function returns an unsigned long integer (`ulong`) with the value `128UL`, representing the offset for workspace partition information alignment.


---
### fd\_wksp\_private\_data\_off<!-- {{#callable:fd_wksp_private_data_off}} -->
The function `fd_wksp_private_data_off` calculates the offset to the data region in a workspace based on the maximum number of partitions.
- **Inputs**:
    - `part_max`: The maximum number of partitions in the workspace, represented as an unsigned long integer.
- **Control Flow**:
    - Call `fd_wksp_private_pinfo_off()` to get the offset to the start of the partition info array.
    - Multiply `part_max` by the size of `fd_wksp_private_pinfo_t` to calculate the total size of the partition info array.
    - Add the result from the previous step to the offset obtained from `fd_wksp_private_pinfo_off()` to get the final offset to the data region.
- **Output**: The function returns an unsigned long integer representing the offset to the data region in the workspace.
- **Functions called**:
    - [`fd_wksp_private_pinfo_off`](#fd_wksp_private_pinfo_off)


---
### fd\_wksp\_private\_pinfo\_const<!-- {{#callable:fd_wksp_private_pinfo_const}} -->
The function `fd_wksp_private_pinfo_const` returns a constant pointer to the partition information array within a workspace structure.
- **Inputs**:
    - `wksp`: A constant pointer to a `fd_wksp_t` structure representing the workspace.
- **Control Flow**:
    - The function calculates the offset to the partition information array by calling `fd_wksp_private_pinfo_off()`.
    - It casts the workspace pointer `wksp` to an unsigned long, adds the offset, and then casts the result to a constant pointer of type `fd_wksp_private_pinfo_t`.
    - The function returns this constant pointer.
- **Output**: A constant pointer to the `fd_wksp_private_pinfo_t` structure, which represents the partition information array within the workspace.
- **Functions called**:
    - [`fd_wksp_private_pinfo_off`](#fd_wksp_private_pinfo_off)


---
### fd\_wksp\_private\_pinfo\_cidx<!-- {{#callable:fd_wksp_private_pinfo_cidx}} -->
The function `fd_wksp_private_pinfo_cidx` converts a `ulong` index to a `uint` compressed index.
- **Inputs**:
    - `idx`: A `ulong` index representing a partition index in the workspace.
- **Control Flow**:
    - The function takes a single input parameter `idx` of type `ulong`.
    - It casts the `ulong` index to a `uint` type.
    - The function returns the casted `uint` value.
- **Output**: The function returns a `uint` which is the compressed form of the input `ulong` index.


---
### fd\_wksp\_private\_pinfo\_idx<!-- {{#callable:fd_wksp_private_pinfo_idx}} -->
The function `fd_wksp_private_pinfo_idx` converts a compressed index of type `uint` to an uncompressed index of type `ulong`.
- **Inputs**:
    - `cidx`: A compressed index of type `uint` that needs to be converted to an uncompressed index.
- **Control Flow**:
    - The function takes a single input parameter `cidx` of type `uint`.
    - It performs a type cast of `cidx` to `ulong`.
    - The function returns the result of this type cast.
- **Output**: The function returns an uncompressed index of type `ulong`.


---
### fd\_wksp\_private\_pinfo\_idx\_is\_null<!-- {{#callable:fd_wksp_private_pinfo_idx_is_null}} -->
The function `fd_wksp_private_pinfo_idx_is_null` checks if a given index is equal to a predefined null index value.
- **Inputs**:
    - `idx`: An unsigned long integer representing the index to be checked against the null index value.
- **Control Flow**:
    - The function compares the input index `idx` with the constant `FD_WKSP_PRIVATE_PINFO_IDX_NULL`.
    - If `idx` is equal to `FD_WKSP_PRIVATE_PINFO_IDX_NULL`, the function returns 1.
    - If `idx` is not equal to `FD_WKSP_PRIVATE_PINFO_IDX_NULL`, the function returns 0.
- **Output**: The function returns an integer: 1 if the index is null, otherwise 0.


---
### fd\_wksp\_private\_idle\_stack\_is\_empty<!-- {{#callable:fd_wksp_private_idle_stack_is_empty}} -->
The function `fd_wksp_private_idle_stack_is_empty` checks if the idle stack of a workspace is empty or corrupted.
- **Inputs**:
    - `wksp`: A pointer to a `fd_wksp_t` structure representing the workspace to be checked.
- **Control Flow**:
    - The function retrieves the index of the top of the idle stack using [`fd_wksp_private_pinfo_idx`](#fd_wksp_private_pinfo_idx) on `wksp->idle_top_cidx`.
    - It compares this index to `wksp->part_max`.
    - If the index is greater than or equal to `wksp->part_max`, it returns 1, indicating the idle stack is empty or corrupted.
    - Otherwise, it returns 0, indicating the idle stack is not empty.
- **Output**: Returns 1 if the idle stack is empty or corrupted, and 0 otherwise.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](#fd_wksp_private_pinfo_idx)


---
### fd\_wksp\_private\_idle\_stack\_pop<!-- {{#callable:fd_wksp_private_idle_stack_pop}} -->
The function `fd_wksp_private_idle_stack_pop` removes and returns the top idle partition index from a workspace's idle stack.
- **Inputs**:
    - `wksp`: A pointer to an `fd_wksp_t` structure representing the workspace, assumed to be a current local join.
    - `pinfo`: A pointer to an array of `fd_wksp_private_pinfo_t` structures, representing partition information, assumed to be obtained from `fd_wksp_private_pinfo(wksp)`.
- **Control Flow**:
    - Retrieve the index `i` of the top idle partition from `wksp->idle_top_cidx` using [`fd_wksp_private_pinfo_idx`](#fd_wksp_private_pinfo_idx).
    - Update `wksp->idle_top_cidx` to the `parent_cidx` of the partition at index `i`, effectively removing it from the stack.
    - Set the `parent_cidx` of the partition at index `i` to `FD_WKSP_PRIVATE_PINFO_IDX_NULL`, indicating it is no longer in the idle stack.
    - Return the index `i` of the partition that was popped from the idle stack.
- **Output**: Returns the index of the partition that was popped from the idle stack, which is an unsigned long integer.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_cidx`](#fd_wksp_private_pinfo_cidx)


---
### fd\_wksp\_private\_idle\_stack\_push<!-- {{#callable:fd_wksp_private_idle_stack_push}} -->
The function `fd_wksp_private_idle_stack_push` pushes a partition index onto the idle stack of a workspace, initializing its metadata to indicate it is idle.
- **Inputs**:
    - `i`: An unsigned long integer representing the index of the partition to be pushed onto the idle stack, assumed to be within the range [0, part_max).
    - `wksp`: A pointer to an `fd_wksp_t` structure representing the workspace, assumed to be currently joined locally.
    - `pinfo`: A pointer to an array of `fd_wksp_private_pinfo_t` structures, representing the partition information of the workspace, assumed to be obtained from `fd_wksp_private_pinfo(wksp)`.
- **Control Flow**:
    - Set the `gaddr_lo` and `gaddr_hi` fields of the partition at index `i` in `pinfo` to 0, indicating it is idle.
    - Set the `tag` field of the partition at index `i` in `pinfo` to 0, indicating it is not allocated.
    - Set the `in_same` field of the partition at index `i` in `pinfo` to 0, indicating it is not in a list of same-sized partitions.
    - Set the `prev_cidx`, `next_cidx`, `left_cidx`, `right_cidx`, and `same_cidx` fields of the partition at index `i` in `pinfo` to `fd_wksp_private_pinfo_cidx(FD_WKSP_PRIVATE_PINFO_IDX_NULL)`, indicating no connections to other partitions.
    - Set the `parent_cidx` field of the partition at index `i` in `pinfo` to the current `idle_top_cidx` of `wksp`, linking it to the current top of the idle stack.
    - Update the `idle_top_cidx` of `wksp` to `fd_wksp_private_pinfo_cidx(i)`, making the partition at index `i` the new top of the idle stack.
- **Output**: The function does not return a value; it modifies the workspace and partition information in place.
- **Functions called**:
    - [`fd_wksp_private_pinfo_cidx`](#fd_wksp_private_pinfo_cidx)


---
### fd\_wksp\_private\_free\_treap\_same\_is\_empty<!-- {{#callable:fd_wksp_private_free_treap_same_is_empty}} -->
The function `fd_wksp_private_free_treap_same_is_empty` checks if the 'same' list for a given partition in a workspace's free treap is empty or if there is corruption.
- **Inputs**:
    - `d`: The index of the partition in the free treap to check.
    - `wksp`: A pointer to the workspace structure, assumed to be a current local join.
    - `pinfo`: A pointer to the array of partition information structures, equivalent to `fd_wksp_private_pinfo(wksp)`.
- **Control Flow**:
    - Retrieve the maximum number of partitions (`part_max`) from the workspace structure (`wksp`).
    - Get the index of the next partition in the 'same' list for the partition at index `d` using `pinfo[d].same_cidx`.
    - Convert the compressed index to an actual index using [`fd_wksp_private_pinfo_idx`](#fd_wksp_private_pinfo_idx).
    - Return 1 if the index is greater than or equal to `part_max`, indicating the 'same' list is empty or corrupted; otherwise, return 0.
- **Output**: Returns 1 if the 'same' list is empty or if corruption is detected, otherwise returns 0.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](#fd_wksp_private_pinfo_idx)


---
### fd\_wksp\_private\_free\_treap\_same\_remove<!-- {{#callable:fd_wksp_private_free_treap_same_remove}} -->
The function `fd_wksp_private_free_treap_same_remove` removes the first partition from a list of partitions with the same size in a free treap and updates the necessary pointers.
- **Inputs**:
    - `d`: The index of the partition in the free treap whose same-sized list is being modified.
    - `wksp`: A pointer to the workspace structure, assumed to be a current local join.
    - `pinfo`: A pointer to the array of partition information structures, equivalent to `fd_wksp_private_pinfo(wksp)`.
- **Control Flow**:
    - Retrieve the maximum number of partitions (`part_max`) from the workspace structure.
    - Get the index `i` of the first partition in the same-sized list of partition `d` using [`fd_wksp_private_pinfo_idx`](#fd_wksp_private_pinfo_idx).
    - Get the index `j` of the next partition in the same-sized list after `i`.
    - Update the `same_cidx` of partition `d` to point to `j`.
    - If `j` is a valid index (less than `part_max`), update the `parent_cidx` of partition `j` to point back to `d`.
    - Set the `in_same` flag of partition `i` to 0, indicating it is no longer in a same-sized list.
    - Set the `same_cidx` and `parent_cidx` of partition `i` to `FD_WKSP_PRIVATE_PINFO_IDX_NULL`, effectively removing it from the list.
- **Output**: Returns the index `i` of the removed partition from the same-sized list.
- **Functions called**:
    - [`fd_wksp_private_pinfo_idx`](#fd_wksp_private_pinfo_idx)
    - [`fd_wksp_private_pinfo_cidx`](#fd_wksp_private_pinfo_cidx)


---
### fd\_wksp\_private\_unlock<!-- {{#callable:fd_wksp_private_unlock}} -->
The `fd_wksp_private_unlock` function releases a lock on a workspace by setting its owner to `ULONG_MAX` with memory fence operations to ensure proper ordering.
- **Inputs**:
    - `wksp`: A pointer to an `fd_wksp_t` structure representing the workspace to be unlocked.
- **Control Flow**:
    - The function begins by executing a memory fence operation (`FD_COMPILER_MFENCE`) to ensure that all previous memory operations are completed before proceeding.
    - The `owner` field of the `wksp` structure is set to `ULONG_MAX`, indicating that the workspace is no longer owned by any thread or process.
    - Another memory fence operation is executed to ensure that the update to the `owner` field is visible to other threads or processes.
- **Output**: This function does not return any value; it performs an inline operation to unlock the workspace.


---
### fd\_wksp\_checkpt\_v2\_cmd\_is\_meta<!-- {{#callable:fd_wksp_checkpt_v2_cmd_is_meta}} -->
The function `fd_wksp_checkpt_v2_cmd_is_meta` checks if a given command is a meta command by evaluating its tag.
- **Inputs**:
    - `cmd`: A pointer to a `fd_wksp_checkpt_v2_cmd_t` structure, which represents a command in a workspace checkpoint version 2.
- **Control Flow**:
    - The function accesses the `meta` field of the `cmd` structure.
    - It checks if the `tag` field within the `meta` structure is greater than 0.
- **Output**: The function returns an integer value: 1 if the `tag` is greater than 0, indicating the command is a meta command, and 0 otherwise.


---
### fd\_wksp\_checkpt\_v2\_cmd\_is\_data<!-- {{#callable:fd_wksp_checkpt_v2_cmd_is_data}} -->
The function `fd_wksp_checkpt_v2_cmd_is_data` checks if a given command is a data command in a workspace checkpoint version 2.
- **Inputs**:
    - `cmd`: A pointer to a `fd_wksp_checkpt_v2_cmd_t` structure representing the command to be checked.
- **Control Flow**:
    - The function accesses the `data` member of the `cmd` structure.
    - It checks if `tag` is equal to 0, `cgroup_cnt` is equal to `ULONG_MAX`, and `frame_off` is equal to `ULONG_MAX`.
    - The function returns the result of a bitwise AND operation on these three conditions.
- **Output**: The function returns an integer value, which is 1 if the command is a data command (all conditions are true) and 0 otherwise.


---
### fd\_wksp\_checkpt\_v2\_cmd\_is\_appendix<!-- {{#callable:fd_wksp_checkpt_v2_cmd_is_appendix}} -->
The function `fd_wksp_checkpt_v2_cmd_is_appendix` checks if a given command is an appendix command in a workspace checkpoint version 2.
- **Inputs**:
    - `cmd`: A pointer to a `fd_wksp_checkpt_v2_cmd_t` structure, which represents a command in a workspace checkpoint version 2.
- **Control Flow**:
    - The function checks if the `tag` field of the `appendix` union member is equal to 0.
    - It checks if the `cgroup_cnt` field of the `appendix` union member is less than `ULONG_MAX`.
    - It checks if the `frame_off` field of the `appendix` union member is less than `ULONG_MAX`.
    - The function returns the result of a bitwise AND operation on the three conditions above.
- **Output**: The function returns an integer that is non-zero if the command is an appendix command, and zero otherwise.


---
### fd\_wksp\_checkpt\_v2\_cmd\_is\_volumes<!-- {{#callable:fd_wksp_checkpt_v2_cmd_is_volumes}} -->
The function `fd_wksp_checkpt_v2_cmd_is_volumes` checks if a given command is a 'volumes' command in a workspace checkpoint version 2.
- **Inputs**:
    - `cmd`: A pointer to a `fd_wksp_checkpt_v2_cmd_t` structure, which represents a command in a workspace checkpoint version 2.
- **Control Flow**:
    - The function checks if the `tag` field of the `volumes` structure within `cmd` is equal to 0.
    - It checks if the `cgroup_cnt` field of the `volumes` structure is equal to `ULONG_MAX`.
    - It checks if the `frame_off` field of the `volumes` structure is less than `ULONG_MAX`.
    - The function returns the result of a bitwise AND operation on the three conditions above.
- **Output**: The function returns an integer that is non-zero if the command is a 'volumes' command, and zero otherwise.


# Function Declarations (Public API)

---
### fd\_wksp\_private\_used\_treap\_query<!-- {{#callable_declaration:fd_wksp_private_used_treap_query}} -->
Queries the used treap for a partition containing a given address.
- **Description**: This function is used to find the index of a partition within a workspace's used treap that contains a specified global address. It should be called when you need to determine which partition a particular address belongs to within the used partitions of a workspace. The function requires that the address is within the valid range of the workspace's global address space. If the address is not within any used partition or if there is an internal error such as a cycle or bad index, the function will return a special null index value.
- **Inputs**:
    - `gaddr`: The global address to query within the workspace. It must be within the range [wksp->gaddr_lo, wksp->gaddr_hi). If it is not, the function returns FD_WKSP_PRIVATE_PINFO_IDX_NULL.
    - `wksp`: A pointer to the workspace structure. It must be a valid pointer to a workspace that is currently joined locally.
    - `pinfo`: A pointer to the array of partition information structures. It must be a valid pointer to the partition information array associated with the workspace.
- **Output**: Returns the index of the partition containing the address if successful, or FD_WKSP_PRIVATE_PINFO_IDX_NULL if the address is not found or an error occurs.
- **See also**: [`fd_wksp_private_used_treap_query`](fd_wksp_used_treap.c.driver.md#fd_wksp_private_used_treap_query)  (Implementation)


---
### fd\_wksp\_private\_used\_treap\_insert<!-- {{#callable_declaration:fd_wksp_private_used_treap_insert}} -->
Inserts a partition into the used treap of a workspace.
- **Description**: This function is used to insert a partition, identified by its index, into the used treap of a workspace. It should be called when a partition is to be marked as used, and it assumes that the partition is not currently in the idle stack, used treap, or free treap. The function requires that the partition's address range is within the workspace's data region and that the partition's heap priority is initialized. The caller is expected to set the partition's tag to a non-zero value after a successful insertion to officially mark it as used. The function returns success or an error code if the insertion fails due to invalid input or internal treap issues.
- **Inputs**:
    - `n`: The index of the partition to insert, which must be within the range [0, part_max). Invalid indices result in an error.
    - `wksp`: A pointer to the workspace structure, which must be a current local join. The caller retains ownership and must ensure it is not null.
    - `pinfo`: A pointer to the partition info array associated with the workspace. It must not be null and should be obtained via fd_wksp_private_pinfo(wksp).
- **Output**: Returns FD_WKSP_SUCCESS (zero) on success or a negative FD_WKSP_ERR_* code on failure, indicating issues such as invalid input or treap corruption.
- **See also**: [`fd_wksp_private_used_treap_insert`](fd_wksp_used_treap.c.driver.md#fd_wksp_private_used_treap_insert)  (Implementation)


---
### fd\_wksp\_private\_used\_treap\_remove<!-- {{#callable_declaration:fd_wksp_private_used_treap_remove}} -->
Removes a partition from the used treap in a workspace.
- **Description**: This function is used to remove a specified partition from the used treap of a workspace. It should be called when a partition, identified by its index, is no longer needed in the used treap. The function assumes that the partition is currently in the used treap and not in the free treap or idle stack. It operates efficiently with a time complexity of O(log N), where N is the number of used partitions. The function may consume a workspace cycle tag and modify certain internal fields of the partition. It returns a success code on successful removal or an error code if the operation fails due to user error or memory corruption.
- **Inputs**:
    - `d`: The index of the partition to be removed. It must be within the range [0, part_max) and currently in the used treap.
    - `wksp`: A pointer to the workspace structure. It must be a current local join and the caller retains ownership.
    - `pinfo`: A pointer to the partition information array associated with the workspace. It must not be null and should correspond to the workspace's partition information.
- **Output**: Returns FD_WKSP_SUCCESS (zero) on success or a negative error code on failure, indicating issues such as invalid index or treap connectivity problems.
- **See also**: [`fd_wksp_private_used_treap_remove`](fd_wksp_used_treap.c.driver.md#fd_wksp_private_used_treap_remove)  (Implementation)


---
### fd\_wksp\_private\_free\_treap\_query<!-- {{#callable_declaration:fd_wksp_private_free_treap_query}} -->
Finds the smallest free partition that can accommodate a given size.
- **Description**: This function searches the free treap of a workspace for the smallest partition that is at least as large as the specified size. It is used when allocating memory within a workspace to find a suitable free partition. The function should be called with a valid workspace and partition information array. If the size is zero or if no suitable partition is found, the function returns a special null index. The function may consume a cycle tag and modify partition cycle tags during its operation.
- **Inputs**:
    - `sz`: The size in bytes of the partition being queried. Must be greater than zero; otherwise, the function returns a null index.
    - `wksp`: A pointer to the workspace structure. Must not be null and should be a valid, currently joined workspace.
    - `pinfo`: A pointer to the array of partition information structures. Must not be null and should correspond to the workspace's partition information.
- **Output**: Returns the index of a suitable partition in the free treap, or a null index if no suitable partition is found or if the input size is zero.
- **See also**: [`fd_wksp_private_free_treap_query`](fd_wksp_free_treap.c.driver.md#fd_wksp_private_free_treap_query)  (Implementation)


---
### fd\_wksp\_private\_free\_treap\_insert<!-- {{#callable_declaration:fd_wksp_private_free_treap_insert}} -->
Inserts a partition into the free treap of a workspace.
- **Description**: This function is used to insert a partition, identified by its index, into the free treap of a workspace. It is intended for use when managing memory partitions within a workspace, specifically when a partition is being marked as free. The function assumes that the partition is not currently in the idle stack, used treap, or free treap, and that the workspace is in a valid state for local operations. The partition's address range and heap priority must be initialized before calling this function. The function will handle the initialization of various internal indices and may consume a workspace cycle tag. It returns a success code on successful insertion or an error code if the insertion fails due to invalid parameters or internal connectivity issues.
- **Inputs**:
    - `n`: The index of the partition to be inserted. Must be within the range [0, part_max) and not currently in the idle stack, used treap, or free treap.
    - `wksp`: A pointer to the workspace structure. Must be a valid, currently joined workspace.
    - `pinfo`: A pointer to the partition information array associated with the workspace. Must not be null and should correspond to the workspace's partition information.
- **Output**: Returns FD_WKSP_SUCCESS (zero) on success or a negative error code on failure, indicating issues such as invalid index, range errors, or internal connectivity problems.
- **See also**: [`fd_wksp_private_free_treap_insert`](fd_wksp_free_treap.c.driver.md#fd_wksp_private_free_treap_insert)  (Implementation)


---
### fd\_wksp\_private\_free\_treap\_remove<!-- {{#callable_declaration:fd_wksp_private_free_treap_remove}} -->
Removes a partition from the free treap in a workspace.
- **Description**: This function is used to remove a specified partition from the free treap of a workspace. It assumes that the partition is currently in the free treap and not in the used treap or idle stack. The function is efficient, operating in logarithmic time relative to the number of free partitions. It may consume a workspace cycle tag and modify certain internal fields of the partition. The function returns a success code if the operation is successful, and an error code if it fails due to user error or memory corruption. It is important to ensure that the partition index is within valid bounds and that the workspace is properly joined before calling this function.
- **Inputs**:
    - `d`: The index of the partition to be removed. It must be within the range [0, part_max) and currently in the free treap.
    - `wksp`: A pointer to the workspace from which the partition is to be removed. The workspace must be a current local join.
    - `pinfo`: A pointer to the array of partition information structures associated with the workspace. It must be obtained via fd_wksp_private_pinfo(wksp).
- **Output**: Returns FD_WKSP_SUCCESS (zero) on success, or a negative error code on failure, indicating issues such as invalid index or treap connectivity problems.
- **See also**: [`fd_wksp_private_free_treap_remove`](fd_wksp_free_treap.c.driver.md#fd_wksp_private_free_treap_remove)  (Implementation)


---
### fd\_wksp\_private\_lock<!-- {{#callable_declaration:fd_wksp_private_lock}} -->
Locks the workspace for exclusive access.
- **Description**: Use this function to acquire an exclusive lock on a workspace, ensuring that no other process or thread can access it concurrently. This function should be called when a workspace needs to be accessed or modified safely. If the workspace is already locked by another process, the function will wait until the lock is available. In cases where the previous lock holder has died, the function attempts to reclaim the lock and recover any incomplete operations. It returns an error if memory corruption is detected during recovery. This function assumes the workspace is a current local join.
- **Inputs**:
    - `wksp`: A pointer to the workspace to be locked. Must not be null and should point to a valid, currently joined workspace.
- **Output**: Returns FD_WKSP_SUCCESS (0) if the lock is successfully acquired, or FD_WKSP_ERR_CORRUPT if memory corruption is detected during lock recovery.
- **See also**: [`fd_wksp_private_lock`](fd_wksp_admin.c.driver.md#fd_wksp_private_lock)  (Implementation)


---
### fd\_wksp\_private\_checkpt\_v1<!-- {{#callable_declaration:fd_wksp_private_checkpt_v1}} -->
Creates a checkpoint of a workspace to a specified file path.
- **Description**: This function is used to create a version 1 checkpoint of a given workspace, saving its state to a specified file path. It should be called when a persistent snapshot of the workspace's current state is needed. The function requires a valid workspace and a file path where the checkpoint will be stored. The file is created with the specified mode, and the function will fail if the file already exists. The function does not support thread parallelism in this version, so the thread pool and thread range parameters are ignored. It returns an error code if the operation fails due to I/O errors or workspace corruption.
- **Inputs**:
    - `tpool`: A pointer to a thread pool, which is ignored in this version. Can be null.
    - `t0`: The starting index of the thread range, which is ignored in this version.
    - `t1`: The ending index of the thread range, which is ignored in this version.
    - `wksp`: A pointer to the workspace to be checkpointed. Must not be null and must be a valid, initialized workspace.
    - `path`: A string representing the file path where the checkpoint will be saved. Must not be null. The file must not already exist.
    - `mode`: The file mode for the new checkpoint file, specified as an unsigned long. Determines the permissions of the created file.
    - `uinfo`: A string containing user information to be included in the checkpoint. Must not be null.
- **Output**: Returns 0 on success, or a negative error code if the operation fails due to I/O errors or workspace corruption.
- **See also**: [`fd_wksp_private_checkpt_v1`](fd_wksp_checkpt_v1.c.driver.md#fd_wksp_private_checkpt_v1)  (Implementation)


---
### fd\_wksp\_private\_restore\_v1<!-- {{#callable_declaration:fd_wksp_private_restore_v1}} -->
Restores a version 1 checkpoint into a workspace.
- **Description**: This function restores a version 1 checkpoint from a specified file path into a given workspace. It is used to recover the state of a workspace from a previously saved checkpoint. The function must be called with a valid workspace and a path to a checkpoint file. It logs the restoration process and handles errors such as file access issues or format errors in the checkpoint. The function assumes that the workspace is in a state ready to accept the restored data and that the checkpoint file is correctly formatted for version 1.
- **Inputs**:
    - `tpool`: A pointer to a thread pool structure, which is currently unused in this version and can be NULL.
    - `t0`: An unsigned long representing the starting thread index, currently unused in this version.
    - `t1`: An unsigned long representing the ending thread index, currently unused in this version.
    - `wksp`: A pointer to the workspace structure where the checkpoint will be restored. Must not be NULL and should be properly initialized.
    - `path`: A constant character pointer to the file path of the checkpoint to be restored. Must not be NULL and should point to a valid file path.
    - `new_seed`: An unsigned integer representing the new seed for the workspace after restoration.
- **Output**: Returns an integer status code: 0 on success, or a negative error code on failure, indicating issues such as file access errors or format errors in the checkpoint.
- **See also**: [`fd_wksp_private_restore_v1`](fd_wksp_restore_v1.c.driver.md#fd_wksp_private_restore_v1)  (Implementation)


---
### fd\_wksp\_private\_printf\_v1<!-- {{#callable_declaration:fd_wksp_private_printf_v1}} -->
Prints detailed information about a workspace from a checkpoint file.
- **Description**: This function is used to print detailed information about a workspace stored in a checkpoint file specified by the path. It outputs the information to the specified file descriptor and can provide varying levels of verbosity based on the verbose parameter. The function assumes that the checkpoint file is in a specific format and that the verbose level is at least 1. It is typically used for debugging or inspecting the state of a workspace. The function must be called with a valid file descriptor and a non-null path to a valid checkpoint file.
- **Inputs**:
    - `out`: A file descriptor where the output will be written. Must be a valid, open file descriptor.
    - `path`: A string representing the path to the checkpoint file. Must not be null and should point to a valid file.
    - `verbose`: An integer specifying the verbosity level of the output. Must be at least 1 to produce output.
- **Output**: Returns an integer representing the total number of bytes written to the output file descriptor. Returns a negative value if an error occurs during processing.
- **See also**: [`fd_wksp_private_printf_v1`](fd_wksp_restore_v1.c.driver.md#fd_wksp_private_printf_v1)  (Implementation)


---
### fd\_wksp\_private\_checkpt\_v2<!-- {{#callable_declaration:fd_wksp_private_checkpt_v2}} -->
Creates a checkpoint of a workspace to a specified file path.
- **Description**: This function is used to create a checkpoint of a given workspace, saving its state to a specified file path. It is intended for use when you need to persist the current state of a workspace for later restoration or analysis. The function requires a valid workspace and a file path where the checkpoint will be saved. It supports different frame styles for compression, but not all styles may be supported on all targets. The function must be called with a valid workspace and a non-null path. If the frame style is unsupported, the function will return an error. The function also handles file creation and locking of the workspace to ensure consistency during the checkpoint process.
- **Inputs**:
    - `tpool`: A pointer to a thread pool structure. Currently unused, so it can be null.
    - `t0`: The starting index of threads in the thread pool. Currently unused.
    - `t1`: The ending index of threads in the thread pool. Currently unused.
    - `wksp`: A pointer to the workspace to be checkpointed. Must not be null and should be a valid, initialized workspace.
    - `path`: A constant character pointer to the file path where the checkpoint will be saved. Must not be null.
    - `mode`: The file mode for the checkpoint file, specifying permissions. Should be a valid mode value.
    - `uinfo`: A constant character pointer to user information to be included in the checkpoint. Can be null if no user information is needed.
    - `frame_style_compressed`: An integer specifying the frame style for compression. Must be a supported style; otherwise, the function will return an error.
- **Output**: Returns an integer indicating success or failure. A non-zero return value indicates an error, such as an unsupported frame style or file creation failure.
- **See also**: [`fd_wksp_private_checkpt_v2`](fd_wksp_checkpt_v2.c.driver.md#fd_wksp_private_checkpt_v2)  (Implementation)


---
### fd\_wksp\_private\_restore\_v2<!-- {{#callable_declaration:fd_wksp_private_restore_v2}} -->
Restores a workspace from a checkpoint file.
- **Description**: This function restores the state of a workspace from a specified checkpoint file, using either memory-mapped I/O or streaming, depending on the file's capabilities. It is typically used to recover a workspace to a known state, such as after a system restart or failure. The function requires a valid thread pool and workspace, and the checkpoint file must be accessible and correctly formatted. It logs the restoration process and handles errors by returning a failure code if any step fails.
- **Inputs**:
    - `tpool`: A pointer to a thread pool structure used for parallel processing. Must not be null.
    - `t0`: The starting index of the thread range to use for parallel processing. Must be less than or equal to t1.
    - `t1`: The ending index of the thread range to use for parallel processing. Must be greater than or equal to t0.
    - `wksp`: A pointer to the workspace structure where the checkpoint will be restored. Must not be null and should be properly initialized.
    - `path`: A constant character pointer to the file path of the checkpoint. Must not be null and should point to a valid, readable file.
    - `new_seed`: An unsigned integer used as a new seed for the workspace's random number generator.
- **Output**: Returns an integer status code: zero on success, or a negative error code on failure.
- **See also**: [`fd_wksp_private_restore_v2`](fd_wksp_restore_v2.c.driver.md#fd_wksp_private_restore_v2)  (Implementation)


---
### fd\_wksp\_private\_printf\_v2<!-- {{#callable_declaration:fd_wksp_private_printf_v2}} -->
Prints detailed information about a workspace checkpoint to a specified output.
- **Description**: This function is used to print detailed information about a workspace checkpoint from a specified file path to a given output file descriptor. It is useful for debugging or logging purposes when you need to inspect the metadata and structure of a workspace checkpoint. The function can print varying levels of detail based on the verbosity level provided. It should be called with a valid file descriptor for output and a valid path to a checkpoint file. The verbosity level controls the amount of information printed, with higher levels providing more detailed output. The function handles errors internally and logs warnings if any issues occur during file operations.
- **Inputs**:
    - `out`: An integer representing the file descriptor where the output will be written. It must be a valid, open file descriptor for writing.
    - `path`: A constant character pointer to the path of the checkpoint file to be read. It must not be null and should point to a valid file path.
    - `verbose`: An integer that specifies the verbosity level of the output. Valid values are 1 or higher, with higher values providing more detailed information. If the value is less than 1, the function will not print any output.
- **Output**: Returns an integer representing the total number of bytes written to the output file descriptor, or a negative value if an error occurred during the operation.
- **See also**: [`fd_wksp_private_printf_v2`](fd_wksp_restore_v2.c.driver.md#fd_wksp_private_printf_v2)  (Implementation)


