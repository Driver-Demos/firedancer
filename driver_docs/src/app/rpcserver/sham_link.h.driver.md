# Purpose
This C source code file defines a structure and a set of functions related to a component named `SHAM_LINK`. The primary purpose of this code is to manage and interact with a shared memory link, which is likely used for inter-process communication or data synchronization. The code provides functionality to create a new `SHAM_LINK` instance, initialize it, and poll for data fragments in a memory cache. The `SHAM_LINK` structure includes pointers to a memory cache (`mcache`) and a workspace (`wksp`), as well as variables for tracking the depth and expected sequence number of data fragments.

The code is designed to be part of a larger system, as indicated by the use of macros for naming and the presence of external function calls such as `fd_wksp_attach`, `fd_mcache_join`, and `fd_frag_meta_seq_query`. These functions suggest that the code interfaces with a specific framework or library for memory management and data handling. The file does not define a public API but rather provides internal functionality that can be used by other components within the same system. The use of static inline functions and the absence of a `main` function indicate that this code is intended to be included and used within other C files rather than being compiled as a standalone executable.
# Global Variables

---
### SHAM\_LINK\_
- **Type**: `macro`
- **Description**: `SHAM_LINK_` is a macro used to concatenate the prefix `SHAM_LINK_NAME` with a given suffix, effectively creating unique identifiers for various components of the SHAM_LINK system. It is used to define and manage the naming of functions and types related to the SHAM_LINK structure.
- **Use**: This macro is used to generate unique names for functions and types associated with the SHAM_LINK structure by concatenating a specified suffix.


# Data Structures

---
### SHAM\_LINK\_NAME
- **Type**: `struct`
- **Members**:
    - `mcache`: A pointer to a fragment metadata cache.
    - `wksp`: A pointer to a workspace structure.
    - `depth`: An unsigned long integer representing the depth of the cache.
    - `seq_expect`: An unsigned long integer representing the expected sequence number.
- **Description**: The `SHAM_LINK_NAME` structure is designed to manage and interact with a fragment metadata cache and a workspace in a networked environment. It holds pointers to the cache and workspace, and maintains state information such as the depth of the cache and the expected sequence number for processing fragments. This structure is used in conjunction with various functions to initialize, start, and poll the cache for new fragments, ensuring that data is processed in the correct sequence and handling any overruns that may occur.


# Functions

---
### SHAM\_LINK\_<!-- {{#callable:SHAM_LINK_}} -->
The `SHAM_LINK_(new)` function initializes a new SHAM_LINK object by attaching it to a specified workspace and joining its mcache.
- **Inputs**:
    - `mem`: A pointer to memory where the SHAM_LINK object will be initialized.
    - `wksp_name`: A string representing the name of the workspace to attach to.
- **Control Flow**:
    - Cast the provided memory pointer to a SHAM_LINK object pointer.
    - Initialize the memory for the SHAM_LINK object to zero using `memset`.
    - Log a notice indicating the attempt to attach to the specified workspace.
    - Attempt to attach to the workspace using `fd_wksp_attach` and store the result in `self->wksp`.
    - If the workspace attachment fails, log an error and exit.
    - Calculate the offset for the mcache using `fd_ulong_align_up` and `fd_wksp_private_data_off`.
    - Join the mcache at the calculated offset using `fd_mcache_join` and store the result in `self->mcache`.
    - If joining the mcache fails, log an error and exit.
    - Return the initialized SHAM_LINK object.
- **Output**: Returns a pointer to the initialized SHAM_LINK object, or logs an error and exits if initialization fails.
- **Functions called**:
    - [`SHAM_LINK_`](#SHAM_LINK_)


