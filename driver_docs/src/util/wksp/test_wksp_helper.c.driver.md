# Purpose
This C source code file is a comprehensive test suite for a workspace management library, likely part of a larger system. The code is structured to test various functionalities related to workspace creation, attachment, allocation, and deletion, both for named and anonymous workspaces. It uses a series of assertions and logging to verify the correct behavior of the workspace functions, such as `fd_wksp_new_named`, `fd_wksp_attach`, `fd_wksp_alloc_laddr`, and others. The tests cover a wide range of scenarios, including edge cases and invalid inputs, ensuring robustness and reliability of the workspace management functions.

The file is designed to be executed as a standalone program, as indicated by the presence of a [`main`](#main) function. It does not define public APIs or external interfaces but rather serves as an internal validation tool for developers. The code makes extensive use of utility functions for command-line argument parsing and logging, suggesting it is part of a well-structured codebase with modular components. The use of macros like `FD_STATIC_ASSERT` and `FD_TEST` indicates a focus on compile-time checks and runtime assertions to catch errors early in the development process. Overall, this file is a critical component for ensuring the integrity and correctness of the workspace management features in the system.
# Imports and Dependencies

---
- `../fd_util.h`


# Functions

---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, parses command-line arguments, and performs a series of tests on workspace creation, attachment, allocation, and deletion functions for both named and anonymous workspaces.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Parse command-line arguments to extract parameters like `name`, `_page_sz`, `page_cnt`, `near_cpu`, `_mode`, `seed`, and `part_max`.
    - Convert `_page_sz` and `_mode` to `page_sz` and `mode` using helper functions.
    - Initialize variables `zero` and `big` for testing purposes.
    - Iterate twice to perform tests for named and anonymous workspaces.
    - In the first iteration, test named workspace creation with various invalid parameters and valid creation, followed by attachment and detachment tests.
    - In the second iteration, test anonymous workspace creation with various invalid parameters and valid creation, followed by attachment and detachment tests.
    - Perform allocation tests using `fd_wksp_alloc_laddr` and verify results.
    - Test workspace containing, string allocation, tagging, memset, mapping, and unmapping functions.
    - Test workspace deletion for both named and anonymous workspaces.
    - Log the success of tests and halt the program.
- **Output**: The function returns an integer `0` indicating successful execution after performing all tests.


