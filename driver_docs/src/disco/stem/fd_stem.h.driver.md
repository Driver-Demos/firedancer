# Purpose
This C header file defines structures and inline functions for managing and interacting with a data streaming context, likely within a larger framework for handling data fragments. The `fd_stem_context` structure holds metadata caches, sequence numbers, and other parameters necessary for managing data flow. The `fd_stem_tile_in` structure is aligned for performance and contains information about a specific data input, including its cache, sequence number, and diagnostic accumulators. The inline functions [`fd_stem_publish`](#fd_stem_publish) and [`fd_stem_advance`](#fd_stem_advance) are used to publish data fragments to a cache and advance the sequence number, respectively, while managing flow control credits. This file is part of a modular system, as indicated by the inclusion of a base header file, and it is designed to ensure efficient data handling and synchronization in a concurrent environment.
# Imports and Dependencies

---
- `../fd_disco_base.h`


# Data Structures

---
### fd\_stem\_context
- **Type**: `struct`
- **Members**:
    - `mcaches`: A pointer to an array of pointers to fd_frag_meta_t, representing metadata caches.
    - `seqs`: A pointer to an array of unsigned long integers, representing sequence numbers.
    - `depths`: A pointer to an array of unsigned long integers, representing the depths of caches.
    - `cr_avail`: A pointer to an unsigned long integer, representing available credits.
    - `cr_decrement_amount`: An unsigned long integer, representing the amount to decrement credits by.
- **Description**: The `fd_stem_context` structure is designed to manage and track metadata caches, sequence numbers, and cache depths for a set of operations. It includes pointers to arrays for metadata caches (`mcaches`), sequence numbers (`seqs`), and cache depths (`depths`). Additionally, it manages flow control through `cr_avail`, which tracks available credits, and `cr_decrement_amount`, which specifies how much to decrement the credits by during operations. This structure is integral to managing the state and flow control in a system that processes fragments of data.


---
### fd\_stem\_context\_t
- **Type**: `struct`
- **Members**:
    - `mcaches`: A pointer to an array of pointers to fd_frag_meta_t, representing multiple caches.
    - `seqs`: A pointer to an array of unsigned long integers, each representing a sequence number for a cache.
    - `depths`: A pointer to an array of unsigned long integers, each representing the depth of a cache.
    - `cr_avail`: A pointer to an unsigned long integer representing the available credit.
    - `cr_decrement_amount`: An unsigned long integer representing the amount to decrement the available credit by.
- **Description**: The `fd_stem_context_t` structure is designed to manage multiple caches, each with its own sequence number and depth, in a high-performance computing environment. It includes mechanisms for tracking available credits and decrementing them as operations are performed, facilitating efficient resource management and synchronization across different cache instances.


---
### fd\_stem\_tile\_in
- **Type**: `struct`
- **Members**:
    - `mcache`: Pointer to the local join of this input's mcache.
    - `depth`: Depth of this input's cache, equivalent to fd_mcache_depth(mcache).
    - `idx`: Index of this input in the list of providers, ranging from 0 to in_cnt.
    - `seq`: Sequence number of the next fragment expected from the upstream producer.
    - `mline`: Location to poll next, calculated as mcache + fd_mcache_line_idx(seq, depth).
    - `fseq`: Pointer to the local join of the fseq used for returning flow control credits.
    - `accum`: Array of local diagnostic accumulators drained during input housekeeping.
- **Description**: The `fd_stem_tile_in` structure is designed to manage the state and metadata associated with an input tile in a data processing pipeline. It includes pointers to cache metadata (`mcache` and `mline`), sequence numbers for tracking data fragments (`seq`), and diagnostic accumulators for monitoring performance and flow control (`accum`). The structure is aligned to 64 bytes for performance optimization, and it facilitates efficient data handling and flow control in a multi-provider environment.


---
### fd\_stem\_tile\_in\_t
- **Type**: `struct`
- **Members**:
    - `mcache`: A constant pointer to fd_frag_meta_t representing a local join to this input's mcache.
    - `depth`: An unsigned integer representing the depth of this input's cache, which is constant.
    - `idx`: An unsigned integer representing the index of this input in the list of providers.
    - `seq`: An unsigned long representing the sequence number of the next fragment expected from the upstream producer.
    - `mline`: A constant pointer to fd_frag_meta_t representing the location to poll next.
    - `fseq`: A pointer to an unsigned long used to return flow control credits to the input.
    - `accum`: An array of six unsigned integers used as local diagnostic accumulators.
- **Description**: The `fd_stem_tile_in_t` structure is designed to manage and track the state of an input tile in a data processing pipeline. It includes pointers to metadata caches and sequence numbers for managing data flow and synchronization. The structure also contains diagnostic accumulators for monitoring and debugging purposes, ensuring efficient data handling and flow control within the system.


# Functions

---
### fd\_stem\_publish<!-- {{#callable:fd_stem_publish}} -->
The `fd_stem_publish` function publishes a fragment to a specified output index in the stem context, updates the sequence number, and decrements the available credit.
- **Inputs**:
    - `stem`: A pointer to an `fd_stem_context_t` structure, which contains metadata caches, sequence numbers, depths, available credits, and decrement amounts.
    - `out_idx`: An unsigned long integer representing the index of the output in the stem context where the fragment will be published.
    - `sig`: An unsigned long integer representing the signature of the fragment to be published.
    - `chunk`: An unsigned long integer representing the chunk of data to be published.
    - `sz`: An unsigned long integer representing the size of the fragment to be published.
    - `ctl`: An unsigned long integer representing control information for the fragment.
    - `tsorig`: An unsigned long integer representing the original timestamp of the fragment.
    - `tspub`: An unsigned long integer representing the publication timestamp of the fragment.
- **Control Flow**:
    - Retrieve the sequence pointer for the specified output index from the stem context.
    - Store the current sequence number from the sequence pointer.
    - Call `fd_mcache_publish` with the metadata cache, depth, sequence number, and other fragment details to publish the fragment.
    - Decrement the available credit in the stem context by the decrement amount.
    - Increment the sequence number by 1 using `fd_seq_inc` and update the sequence pointer with the new sequence number.
- **Output**: The function does not return a value; it performs operations on the provided stem context and updates its state.


---
### fd\_stem\_advance<!-- {{#callable:fd_stem_advance}} -->
The `fd_stem_advance` function updates the sequence number for a given output index in a stem context and decrements the available credits by a specified amount.
- **Inputs**:
    - `stem`: A pointer to an `fd_stem_context_t` structure, which contains the sequence numbers and credit information for the stem.
    - `out_idx`: An unsigned long integer representing the index of the output for which the sequence number is to be advanced.
- **Control Flow**:
    - Retrieve the pointer to the sequence number for the specified output index from the `seqs` array in the `stem` context.
    - Store the current sequence number in a local variable `seq`.
    - Decrement the available credits (`cr_avail`) in the `stem` context by the `cr_decrement_amount`.
    - Increment the sequence number by 1 using the `fd_seq_inc` function and update the sequence number in the `seqs` array.
    - Return the original sequence number before incrementing.
- **Output**: The function returns the original sequence number (of type `ulong`) before it was incremented.


