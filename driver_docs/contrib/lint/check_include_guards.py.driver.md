# Purpose
This Python script is a specialized tool designed to verify that C/C++ header files within a project adhere to a specific naming convention for include guards, as per the Firedancer code style. It recursively searches for `.h` files starting from the `./src` directory and checks each file to ensure that the include guards are present and correctly named. The expected format for the include guard is derived from the file path, transforming it into a standardized string prefixed with "HEADER_fd_". If a file's include guard is missing or incorrectly named, the script outputs a message indicating the discrepancy. This script provides narrow functionality, focusing solely on enforcing a specific code style for include guards in header files.
# Imports and Dependencies

---
- `pathlib.Path`
- `os`


# Functions

---
### check\_file<!-- {{#callable:firedancer/contrib/lint/check_include_guards.check_file}} -->
The `check_file` function verifies if a C/C++ header file contains the correct include guard according to Firedancer code style.
- **Inputs**:
    - `path`: The file path to the C/C++ header file that needs to be checked for include guards.
- **Control Flow**:
    - Constructs the expected include guard name by replacing '.' and '/' in the file path with underscores and prefixing with 'HEADER_fd_'.
    - Opens the file at the given path in read mode.
    - Reads lines from the file, skipping lines that are comments or whitespace, until a non-comment, non-whitespace line is found.
    - Reads the next line after the first non-comment, non-whitespace line.
    - Checks if the first two lines are include guard directives ('#ifndef' and '#define').
    - If the include guard directives are missing, prints a message indicating the missing include guard.
    - Compares the text following '#ifndef' and '#define' to ensure they match; if not, the function returns early.
    - Checks if the include guard name matches the expected format and prints a message if it does not.
- **Output**: The function does not return any value but prints messages to the console if the include guard is missing or incorrect.


---
### main<!-- {{#callable:firedancer/contrib/lint/check_include_guards.main}} -->
The `main` function recursively searches for C/C++ header files in the './src' directory and checks each file for proper include guards using the [`check_file`](#check_file) function.
- **Inputs**: None
- **Control Flow**:
    - The function uses `Path('./src').rglob('*.h')` to recursively find all files with the '.h' extension in the './src' directory.
    - For each header file found, it attempts to call the [`check_file`](#check_file) function with the file path as an argument.
    - If an `IOError` occurs during the file check, it catches the exception and prints an error message indicating the file that could not be read.
- **Output**: The function does not return any value; it performs file checks and prints messages to the console.
- **Functions called**:
    - [`firedancer/contrib/lint/check_include_guards.check_file`](#check_file)


