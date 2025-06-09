# Purpose
The provided C source code file is designed to execute and validate a series of text-based instruction tests for a virtual machine (VM) within the "flamenco" project. The code is structured to parse test instructions from input files, execute these instructions on a VM, and verify the results against expected outcomes. It includes a parser that interprets a minimal text-based grammar to define test inputs and expected effects, such as register values and execution status. The parser reads tokens from the input, which can include comments, new inputs, assertions, and assignments, and constructs test fixtures that are then executed on the VM.

The code is organized into several key components: parsing functions that handle the reading and interpretation of test files, execution functions that run the parsed instructions on a VM, and validation functions that compare the actual VM state against expected results. The main function orchestrates the execution of tests by iterating over input files specified as command-line arguments or default paths if no arguments are provided. The code is intended to be run as an executable, as indicated by the presence of a [`main`](#main) function, and it does not define public APIs or external interfaces. Instead, it focuses on internal testing of VM instruction handling, making it a specialized tool for developers working on the VM component of the "flamenco" project.
# Imports and Dependencies

---
- `fd_vm.h`
- `fd_vm_base.h`
- `fd_vm_private.h`
- `test_vm_util.h`
- `../runtime/context/fd_exec_epoch_ctx.h`
- `../runtime/context/fd_exec_slot_ctx.h`
- `assert.h`
- `ctype.h`
- `errno.h`
- `fcntl.h`
- `stdlib.h`
- `sys/stat.h`
- `unistd.h`


# Data Structures

---
### test\_input
- **Type**: `struct`
- **Members**:
    - `input`: A pointer to a heap-allocated array of unsigned characters representing the input data.
    - `input_sz`: An unsigned long representing the size of the input data.
    - `op`: An unsigned character representing the operation code.
    - `dst`: A 4-bit unsigned character representing the destination register.
    - `src`: A 4-bit unsigned character representing the source register.
    - `off`: An unsigned short representing an offset value.
    - `imm`: An unsigned long representing an immediate value.
    - `reg`: An array of unsigned longs representing the registers, with a size defined by REG_CNT.
    - `region_boundary`: An array of unsigned integers representing the boundaries of memory regions, with a maximum size of 16.
    - `region_boundary_cnt`: An unsigned integer representing the count of region boundaries.
- **Description**: The `test_input` structure is designed to encapsulate the input data and parameters for a virtual machine instruction test. It includes fields for the input data, operation code, destination and source registers, offset, immediate value, and an array of registers. Additionally, it manages memory region boundaries and their count, allowing for flexible configuration of memory regions during testing.


---
### test\_input\_t
- **Type**: `struct`
- **Members**:
    - `input`: Pointer to a heap-allocated array of unsigned characters representing the input data.
    - `input_sz`: Size of the input data in bytes.
    - `op`: Operation code represented as an unsigned character.
    - `dst`: Destination register index, using 4 bits.
    - `src`: Source register index, using 4 bits.
    - `off`: Offset value represented as an unsigned short.
    - `imm`: Immediate value represented as an unsigned long.
    - `reg`: Array of 12 unsigned long integers representing register values.
    - `region_boundary`: Array of 16 unsigned integers representing region boundaries.
    - `region_boundary_cnt`: Count of region boundaries used.
- **Description**: The `test_input_t` structure is designed to encapsulate the input data and parameters for executing a virtual machine instruction test. It includes fields for the input data, operation code, register indices, offset, immediate value, and register values. Additionally, it manages memory regions through region boundaries and their count, facilitating the setup of test scenarios for instruction execution.


---
### test\_effects
- **Type**: `struct`
- **Members**:
    - `status`: An integer representing the status of the test effects.
    - `force_exec`: An integer flag indicating whether to force execution despite verification failures.
    - `reg`: An array of unsigned long integers representing the register values, with a size defined by REG_CNT.
- **Description**: The `test_effects` structure is used to represent the expected outcomes of a test execution in a virtual machine environment. It includes a status field to indicate the result of the test, a force_exec flag to determine if execution should proceed despite verification issues, and an array of register values that capture the state of the machine's registers after execution. This structure is crucial for validating the correctness of instruction execution by comparing expected and actual outcomes.


---
### test\_effects\_t
- **Type**: `struct`
- **Members**:
    - `status`: An integer representing the status of the test effects.
    - `force_exec`: An integer flag indicating whether execution should be forced.
    - `reg`: An array of unsigned long integers representing the register values.
- **Description**: The `test_effects_t` structure is used to represent the effects of executing a test input in a virtual machine environment. It contains a status field to indicate the result of the execution, a force_exec flag to determine if execution should be forced despite validation failures, and an array of register values to capture the state of the registers after execution. This structure is crucial for verifying the correctness of instruction execution in test scenarios.


---
### test\_fixture
- **Type**: `struct`
- **Members**:
    - `line`: Stores the line number associated with the test fixture.
    - `input`: Holds the input data for the test, defined by the `test_input_t` structure.
    - `effects`: Contains the expected effects or outcomes of the test, defined by the `test_effects_t` structure.
- **Description**: The `test_fixture` structure is designed to encapsulate a single test case for a virtual machine instruction test. It includes the line number where the test is defined, the input data for the test, and the expected effects or outcomes after executing the test. This structure is used to manage and verify the correctness of instruction execution within a testing framework.


---
### test\_fixture\_t
- **Type**: `struct`
- **Members**:
    - `line`: Stores the line number in the source file where the test fixture is defined.
    - `input`: Holds the input data for the test, including operation, destination, source, and immediate values.
    - `effects`: Contains the expected effects of executing the test, such as status and register values.
- **Description**: The `test_fixture_t` structure is used to represent a single test case for a virtual machine instruction test. It encapsulates the line number of the test case, the input parameters required to execute the test, and the expected effects or outcomes after the test execution. This structure is crucial for organizing and running automated tests to verify the correctness of virtual machine instructions.


---
### test\_parser
- **Type**: `struct`
- **Members**:
    - `path`: Pointer to a constant character string representing the file path being parsed.
    - `cur`: Pointer to the current position in the input buffer being parsed.
    - `end`: Pointer to the end of the input buffer.
    - `line`: Current line number in the input buffer being parsed.
    - `test_line`: Line number where the current test case starts.
    - `state`: Current state of the parser, indicating whether it is parsing input or assertions.
    - `input`: Structure holding the input data for the test, including operation and register information.
    - `effects`: Structure holding the expected effects or results of the test, including status and register values.
- **Description**: The `test_parser` structure is designed to facilitate the parsing of text-based instruction tests, maintaining the current state of parsing, including the position in the input buffer, line numbers, and the current parsing state. It also holds the input data and expected effects for a test case, allowing the parser to process and validate instruction tests against expected outcomes.


---
### test\_parser\_t
- **Type**: `struct`
- **Members**:
    - `path`: A pointer to a constant character string representing the file path being parsed.
    - `cur`: A pointer to the current position in the input buffer being parsed.
    - `end`: A pointer to the end of the input buffer being parsed.
    - `line`: An unsigned long integer tracking the current line number in the input buffer.
    - `test_line`: An unsigned long integer tracking the line number where the current test started.
    - `state`: An integer representing the current state of the parser, such as input or assertion state.
    - `input`: A test_input_t structure holding the input data for the current test.
    - `effects`: A test_effects_t structure holding the expected effects or results of the current test.
- **Description**: The `test_parser_t` structure is designed to facilitate the parsing of text-based instruction tests for a virtual machine. It maintains the state of the parser, including the current position in the input buffer, the current line number, and the state of the parser (input or assertion). It also holds the input data and expected effects for the current test, allowing the parser to process and validate instruction tests effectively.


# Functions

---
### test\_status\_str<!-- {{#callable:test_status_str}} -->
The `test_status_str` function returns a string representation of a given status code.
- **Inputs**:
    - `status`: An integer representing the status code, which can be STATUS_OK, STATUS_FAULT, STATUS_VERIFY_FAIL, or any other integer.
- **Control Flow**:
    - The function uses a switch statement to check the value of the input status.
    - If the status is STATUS_OK, it returns the string "Ok".
    - If the status is STATUS_FAULT, it returns the string "Fault".
    - If the status is STATUS_VERIFY_FAIL, it returns the string "VerifyFail".
    - For any other status value, it returns the string "unknown (!!!)".
- **Output**: A constant character pointer to a string that describes the status.


---
### parse\_advance<!-- {{#callable:parse_advance}} -->
The `parse_advance` function advances the current position in a parser by a specified number of characters, updating the line count for any newline characters encountered.
- **Inputs**:
    - `p`: A pointer to a `test_parser_t` structure, which contains the current parsing state including the current position, end position, and line number.
    - `n`: An unsigned long integer representing the number of characters to advance the current position by.
- **Control Flow**:
    - The function asserts that advancing by `n` characters does not exceed the end of the parsing buffer.
    - It iterates over the next `n` characters from the current position.
    - For each character, it checks if the character is a newline ('\n').
    - If a newline is encountered, it increments the line count in the parser structure.
    - After processing `n` characters, it updates the current position in the parser by adding `n` to it.
- **Output**: The function does not return a value; it modifies the `test_parser_t` structure in place.


---
### parse\_assign\_sep<!-- {{#callable:parse_assign_sep}} -->
The `parse_assign_sep` function advances the parser's current position to the next '=' character, skipping any leading or trailing whitespace, and logs an error if '=' is not found.
- **Inputs**:
    - `p`: A pointer to a `test_parser_t` structure, which contains the current state of the parser, including the current position, end position, and other parsing context.
- **Control Flow**:
    - The function enters a loop to skip over any whitespace characters at the current position of the parser.
    - It checks if the current position has reached the end or if the current character is not '=', and logs an error if either condition is true.
    - If the '=' character is found, it advances the parser's position by one character.
    - The function enters another loop to skip over any whitespace characters following the '=' character.
- **Output**: The function does not return a value; it modifies the parser's current position in place and may log an error if the expected '=' character is not found.
- **Functions called**:
    - [`parse_advance`](#parse_advance)


---
### parse\_hex\_buf<!-- {{#callable:parse_hex_buf}} -->
The `parse_hex_buf` function reads a hexadecimal string from a parser, converts it into a binary buffer, and returns the buffer along with its size.
- **Inputs**:
    - `p`: A pointer to a `test_parser_t` structure, which contains the current position and end of the input string to be parsed.
    - `psz`: A pointer to an `ulong` where the size of the parsed binary buffer will be stored.
- **Control Flow**:
    - Initialize `sz` to 0 to count the number of bytes in the hexadecimal string.
    - Use a first pass to iterate over the input string in pairs of characters, checking if both are hexadecimal digits using `fd_isxdigit`.
    - For each valid pair, increment the size counter `sz` and move the pointer `peek` forward by two characters.
    - Allocate memory for the binary buffer `buf` based on the counted size `sz`.
    - Use a second pass to convert each pair of hexadecimal characters into a byte, storing the result in the buffer `buf`.
    - For each pair, calculate the high and low nibbles using `fd_isdigit` and `tolower` to handle both digit and letter characters.
    - Combine the high and low nibbles into a single byte and store it in the buffer, then advance the parser's current position by two characters using [`parse_advance`](#parse_advance).
    - Store the final size `sz` in the location pointed to by `psz`.
- **Output**: A pointer to a dynamically allocated buffer containing the binary representation of the parsed hexadecimal string.
- **Functions called**:
    - [`parse_advance`](#parse_advance)


---
### parse\_hex\_int<!-- {{#callable:parse_hex_int}} -->
The `parse_hex_int` function reads a hexadecimal string from a parser and converts it into an unsigned long integer.
- **Inputs**:
    - `p`: A pointer to a `test_parser_t` structure, which contains the current position in the input string, the end of the string, and other parsing state information.
- **Control Flow**:
    - Initialize `val` to 0 and `empty` to 1 to track if any valid digits are found.
    - Enter a loop that continues as long as the current position `p->cur` is not at the end `p->end`.
    - Retrieve the current character `c` from the parser's current position.
    - Check if `c` is a valid hexadecimal digit using `fd_isxdigit`; if not, break the loop.
    - Convert the character `c` to its numeric value, handling both digit and letter cases.
    - Shift `val` left by 4 bits to make room for the new digit and add the digit to `val`.
    - Set `empty` to 0 to indicate that at least one valid digit has been processed.
    - Advance the parser's current position by one character using [`parse_advance`](#parse_advance).
    - After the loop, if `empty` is still 1, log an error indicating that a hex integer was expected but not found.
    - Return the accumulated `val` as the result.
- **Output**: The function returns an `ulong` representing the parsed hexadecimal integer from the input string.
- **Functions called**:
    - [`parse_advance`](#parse_advance)


---
### parse\_token<!-- {{#callable:parse_token}} -->
The `parse_token` function processes the current token in a text-based instruction parser, updating the parser state and potentially returning a completed test fixture.
- **Inputs**:
    - `p`: A pointer to a `test_parser_t` structure representing the current state of the parser.
    - `out`: A pointer to a `test_fixture_t` structure where the parsed test fixture will be stored if completed.
- **Control Flow**:
    - The function skips any leading whitespace in the input stream.
    - If the end of the input is reached, it checks the parser state; if in assertion state, it finalizes the test fixture and returns it, otherwise returns NULL.
    - It checks the first character of the current token to determine the type of token ('$' for new input, '#' for comment, ':' for assertion, or a word for assignment).
    - For '$', it updates the parser state to input and may finalize the previous test fixture if in assertion state.
    - For '#', it skips the rest of the line as a comment.
    - For ':', it sets the parser state to assertion and copies input registers to effects registers.
    - For words, it identifies the keyword and performs the corresponding action (e.g., parsing hex values for 'input', 'op', 'dst', 'src', 'off', 'imm', setting status for 'ok', 'err', 'vfy', 'vfyub', or updating registers for 'rN').
    - If an unexpected token is encountered, it logs an error and aborts.
    - The function returns NULL if no complete test fixture is ready.
- **Output**: Returns a pointer to a `test_fixture_t` if a new test fixture is ready, otherwise returns NULL.
- **Functions called**:
    - [`parse_advance`](#parse_advance)
    - [`parse_assign_sep`](#parse_assign_sep)
    - [`parse_hex_buf`](#parse_hex_buf)
    - [`parse_hex_int`](#parse_hex_int)


---
### parse\_next<!-- {{#callable:parse_next}} -->
The `parse_next` function iterates through tokens in a parser until a complete test fixture is parsed or the end of input is reached.
- **Inputs**:
    - `p`: A pointer to a `test_parser_t` structure, which contains the current state of the parser, including the current position in the input and the end of the input.
    - `out`: A pointer to a `test_fixture_t` structure where the parsed test fixture will be stored if a complete fixture is found.
- **Control Flow**:
    - The function enters a do-while loop that continues as long as the current position in the parser (`p->cur`) is not equal to the end of the input (`p->end`).
    - Within the loop, it calls [`parse_token`](#parse_token) with the parser and output fixture pointers.
    - If [`parse_token`](#parse_token) returns a non-NULL value, indicating a complete test fixture has been parsed, `parse_next` returns this value immediately.
    - If the end of the input is reached without finding a complete fixture, the loop exits and the function returns NULL.
- **Output**: Returns a pointer to a `test_fixture_t` if a complete test fixture is parsed, otherwise returns NULL if the end of input is reached without completing a fixture.
- **Functions called**:
    - [`parse_token`](#parse_token)


---
### run\_input2<!-- {{#callable:run_input2}} -->
The `run_input2` function validates and executes a virtual machine (VM) and updates the test effects based on the execution results.
- **Inputs**:
    - `out`: A pointer to a `test_effects_t` structure where the function will store the results of the VM execution.
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine to be validated and executed.
    - `force_exec`: An integer flag indicating whether to force execution even if validation fails.
- **Control Flow**:
    - The function first validates the VM using [`fd_vm_validate`](fd_vm.c.driver.md#fd_vm_validate).
    - If validation fails, it sets the status in `out` to `STATUS_VERIFY_FAIL`.
    - If `force_exec` is true and [`fd_vm_exec_notrace`](fd_vm_interp.c.driver.md#fd_vm_exec_notrace) succeeds, it implies a forced execution despite validation failure.
    - If validation passes, it attempts to execute the VM using [`fd_vm_exec_notrace`](fd_vm_interp.c.driver.md#fd_vm_exec_notrace).
    - If execution fails, it sets the status in `out` to `STATUS_FAULT`.
    - If execution succeeds, it sets the status in `out` to `STATUS_OK` and copies the first 12 registers from the VM to `out`.
- **Output**: The function updates the `out` parameter with the status of the VM execution and the values of the first 12 registers if execution is successful.
- **Functions called**:
    - [`fd_vm_validate`](fd_vm.c.driver.md#fd_vm_validate)
    - [`fd_vm_exec_notrace`](fd_vm_interp.c.driver.md#fd_vm_exec_notrace)


---
### run\_input<!-- {{#callable:run_input}} -->
The `run_input` function sets up and executes a virtual machine (VM) with given test input instructions and configurations, then evaluates the execution effects.
- **Inputs**:
    - `input`: A pointer to a `test_input_t` structure containing the input data, operation code, destination and source registers, offset, immediate value, register values, region boundaries, and count of region boundaries.
    - `out`: A pointer to a `test_effects_t` structure where the results of the VM execution will be stored.
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine to be configured and executed.
    - `sbpf_version`: An unsigned long integer representing the version of the SBPF (Solana Berkeley Packet Filter) to be used.
    - `force_exec`: An integer flag indicating whether to force execution even if validation fails.
- **Control Flow**:
    - Initialize an array `text` to store the instructions and set `text_cnt` to 0.
    - Assemble the instructions using [`fd_vm_instr`](fd_vm_private.h.driver.md#fd_vm_instr) and store them in `text`, incrementing `text_cnt` accordingly.
    - Allocate memory for `input_copy` and copy the input data into it.
    - Set up the memory regions for the VM using `input_region` based on the input's region boundaries.
    - Create and join `fd_sbpf_calldests_t` and `fd_sbpf_syscalls_t` structures for call destinations and syscalls respectively.
    - Allocate virtual memory for execution contexts using `fd_valloc_t` and initialize them.
    - Initialize the VM with the prepared instructions, memory regions, and other configurations using [`fd_vm_init`](fd_vm.c.driver.md#fd_vm_init).
    - Copy the input register values into the VM's registers.
    - Call [`run_input2`](#run_input2) to execute the VM and store the results in `out`.
    - Free allocated resources and clean up.
- **Output**: The function does not return a value but modifies the `out` parameter to reflect the execution status and register values after running the VM.
- **Functions called**:
    - [`fd_vm_instr`](fd_vm_private.h.driver.md#fd_vm_instr)
    - [`test_vm_minimal_exec_instr_ctx`](test_vm_util.c.driver.md#test_vm_minimal_exec_instr_ctx)
    - [`fd_vm_init`](fd_vm.c.driver.md#fd_vm_init)
    - [`run_input2`](#run_input2)
    - [`test_vm_exec_instr_ctx_delete`](test_vm_util.c.driver.md#test_vm_exec_instr_ctx_delete)


---
### run\_fixture<!-- {{#callable:run_fixture}} -->
The `run_fixture` function executes a test fixture and compares the actual execution results with the expected results, logging any discrepancies.
- **Inputs**:
    - `f`: A pointer to a `test_fixture_t` structure containing the test input and expected effects.
    - `src_file`: A string representing the source file name where the test is defined.
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine instance to execute the test on.
    - `sbpf_version`: An unsigned long integer representing the version of the SBPF (Solana Berkeley Packet Filter) to use during execution.
- **Control Flow**:
    - Initialize a failure flag `fail` to 0.
    - Retrieve the expected effects from the test fixture `f`.
    - Initialize an `actual` effects structure to store the results of the test execution.
    - Call [`run_input`](#run_input) to execute the test input on the virtual machine `vm` and store the results in `actual`.
    - Compare the `status` field of the expected and actual effects; if they differ, log a warning and set `fail` to 1.
    - If either the expected or actual status is not `STATUS_OK`, return the `fail` flag.
    - Iterate over each register (0 to REG_CNT-1) and compare the expected and actual register values; log a warning and set `fail` to 1 if they differ.
    - Return the `fail` flag indicating whether the test passed or failed.
- **Output**: An integer indicating whether the test passed (0) or failed (1).
- **Functions called**:
    - [`run_input`](#run_input)
    - [`test_status_str`](#test_status_str)


---
### handle\_file<!-- {{#callable:handle_file}} -->
The `handle_file` function processes a file containing test instructions, executes them using a virtual machine, and returns the number of failed tests.
- **Inputs**:
    - `file_path`: A constant character pointer representing the path to the file containing test instructions.
    - `vm`: A pointer to an `fd_vm_t` structure representing the virtual machine instance used to execute the tests.
    - `sbpf_version`: An unsigned long integer representing the version of the SBPF (Solana Berkeley Packet Filter) to be used during execution.
- **Control Flow**:
    - Open the file specified by `file_path` in read-only mode and check for errors.
    - Retrieve file statistics using `fstat` and check for errors.
    - Allocate a buffer to read the entire file content and check for successful allocation.
    - Read the file content into the buffer and check for read errors.
    - Initialize a `test_parser_t` structure to parse the file content.
    - Enter a loop to parse and execute each test fixture using [`parse_next`](#parse_next) and [`run_fixture`](#run_fixture).
    - Accumulate the number of failed tests in the `fail` variable.
    - Close the file descriptor and check for errors.
    - Free the allocated memory for the input buffer and the parser's input.
    - Return the total number of failed tests.
- **Output**: The function returns an integer representing the number of test fixtures that failed during execution.
- **Functions called**:
    - [`parse_next`](#parse_next)
    - [`run_fixture`](#run_fixture)


---
### main<!-- {{#callable:main}} -->
The `main` function initializes the environment, processes command-line arguments, executes specified or default instruction test files, and logs the results.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of strings representing the command-line arguments.
- **Control Flow**:
    - Initialize the environment using `fd_boot` with command-line arguments.
    - Determine the CPU index and adjust if it exceeds the shared memory CPU count.
    - Parse command-line arguments for page size, page count, and NUMA index, with defaults if not provided.
    - Initialize a virtual machine instance using [`fd_vm_join`](fd_vm.c.driver.md#fd_vm_join) and [`fd_vm_new`](fd_vm.c.driver.md#fd_vm_new).
    - Iterate over command-line arguments to execute files that are not flags, using [`handle_file`](#handle_file).
    - If no files are executed, run default instruction test files for two versions (v0 and v2).
    - Log the results of the tests, indicating pass or fail for each version and overall.
    - Call `fd_halt` to clean up and terminate the program.
    - Return the total number of failed tests as the exit status.
- **Output**: The function returns an integer representing the number of failed tests, which is used as the program's exit status.
- **Functions called**:
    - [`fd_vm_join`](fd_vm.c.driver.md#fd_vm_join)
    - [`fd_vm_new`](fd_vm.c.driver.md#fd_vm_new)
    - [`handle_file`](#handle_file)


