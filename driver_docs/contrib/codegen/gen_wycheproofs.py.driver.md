# Purpose
This Python script is designed to automate the process of downloading cryptographic test vectors from external sources and generating corresponding C test code. It specifically targets test vectors for the EdDSA (Edwards-curve Digital Signature Algorithm) and XDH (Elliptic Curve Diffie-Hellman) algorithms, utilizing data from Google's Wycheproof project and the C2SP CCTV project. The script defines data structures using Python's `dataclass` to represent test cases for EdDSA and XDH, and it processes JSON data fetched from URLs to populate these structures. The script then generates C code that includes these test vectors, formatted as static arrays of structs, which can be used for testing cryptographic implementations in C.

The script is structured to be executed as a standalone program, with a [`main`](#main) function that orchestrates the generation of C test files. It writes the generated C code to specific files within a project directory, redirecting the standard output to these files. The script ensures that the generated C code is marked as auto-generated and includes a timestamp for reference. This automation facilitates the integration of up-to-date test vectors into a C-based cryptographic library, ensuring that the library can be tested against known test cases for correctness and security compliance.
# Imports and Dependencies

---
- `contextlib.redirect_stdout`
- `dataclasses.dataclass`
- `datetime`
- `requests`
- `os`
- `pathlib.Path`
- `sys`


# Classes

---
### EddsaVerify<!-- {{#class:firedancer/contrib/codegen/gen_wycheproofs.EddsaVerify}} -->
- **Decorators**: `@dataclass`
- **Members**:
    - `tcId`: An integer representing the test case ID.
    - `comment`: A string containing comments or descriptions for the test case.
    - `msg`: A byte sequence representing the message to be verified.
    - `sig`: A byte sequence representing the signature to be verified.
    - `pub`: A byte sequence representing the public key used for verification.
    - `ok`: A boolean indicating whether the test case is expected to pass (True) or fail (False).
- **Description**: The EddsaVerify class is a data structure used to represent test cases for verifying EdDSA signatures. It includes fields for the test case ID, a comment, the message, signature, public key, and a boolean indicating the expected result of the verification. This class is used in the context of generating test vectors for cryptographic verification processes.


---
### XDHVerify<!-- {{#class:firedancer/contrib/codegen/gen_wycheproofs.XDHVerify}} -->
- **Decorators**: `@dataclass`
- **Members**:
    - `tcId`: An integer representing the test case identifier.
    - `comment`: A string providing additional information or comments about the test case.
    - `shared`: A bytes object representing the shared secret in the test case.
    - `prv`: A bytes object representing the private key used in the test case.
    - `pub`: A bytes object representing the public key used in the test case.
    - `ok`: A boolean indicating whether the test case is expected to pass or fail.
- **Description**: The XDHVerify class is a data structure used to represent test cases for verifying XDH (Elliptic Curve Diffie-Hellman) operations. It includes fields for storing the test case ID, comments, shared secret, private key, public key, and a boolean indicating the expected result of the test. This class is part of a system that generates C test code from Wycheproof test vectors.


# Functions

---
### \_gen\_ed25519<!-- {{#callable:firedancer/contrib/codegen/gen_wycheproofs._gen_ed25519}} -->
The `_gen_ed25519` function fetches EDDSA test vectors from a remote JSON file, processes them, and generates corresponding C code for verification tests.
- **Inputs**: None
- **Control Flow**:
    - Send a GET request to the specified URL to fetch the EDDSA test vectors JSON file.
    - Assert that the HTTP response status code is 200, indicating a successful request.
    - Parse the JSON response and assert that it contains the expected algorithm and schema values.
    - Initialize an empty list `verify_tests` to store processed test cases.
    - Iterate over each test group in the JSON file, skipping any group that is not of type 'EddsaVerify'.
    - For each valid test group, extract the public key and iterate over its tests, converting each test's message and signature from hexadecimal to bytes and appending an [`EddsaVerify`](#EddsaVerify) instance to `verify_tests`.
    - Print a header comment indicating the code is auto-generated and include the current UTC timestamp.
    - Print the C structure definition for `fd_ed25519_verify_wycheproof` and its typedef.
    - Iterate over the `verify_tests` list, printing each test case in the C array format, ensuring the signature length is 64 bytes.
    - Print a terminating zero entry and closing brace for the C array.
- **Output**: The function outputs C code to the standard output, which includes a C array of test cases for EDDSA verification, formatted according to the `fd_ed25519_verify_wycheproof` structure.
- **Functions called**:
    - [`firedancer/contrib/codegen/gen_wycheproofs.EddsaVerify`](#EddsaVerify)


---
### \_gen\_x25519<!-- {{#callable:firedancer/contrib/codegen/gen_wycheproofs._gen_x25519}} -->
The `_gen_x25519` function fetches X25519 test vectors from a remote JSON file, processes them, and generates corresponding C code for verification tests.
- **Inputs**: None
- **Control Flow**:
    - Send a GET request to fetch the X25519 test vectors JSON file from a specified URL.
    - Check if the HTTP response status code is 200 to ensure the request was successful.
    - Parse the JSON response and verify the algorithm and schema fields to ensure they match expected values.
    - Iterate over each test group in the JSON file, skipping any group that is not of type 'XdhComp'.
    - For each test in the valid groups, create an [`XDHVerify`](#XDHVerify) object with test details and append it to the `verify_tests` list.
    - Print a header comment indicating the code is auto-generated and include a timestamp of generation.
    - Generate C code for each test in `verify_tests`, converting byte data to hexadecimal string format and outputting the test details in a structured format.
    - Print a closing brace to complete the C array definition.
- **Output**: The function outputs C code that defines an array of `fd_x25519_verify_wycheproof_t` structures, each representing a test case with its associated data and expected result.
- **Functions called**:
    - [`firedancer/contrib/codegen/gen_wycheproofs.XDHVerify`](#XDHVerify)


---
### \_gen\_cctv\_ed25519<!-- {{#callable:firedancer/contrib/codegen/gen_wycheproofs._gen_cctv_ed25519}} -->
The function `_gen_cctv_ed25519` fetches Ed25519 test vectors from a remote JSON file, processes them to determine their validity, and generates corresponding C test code for verification.
- **Inputs**: None
- **Control Flow**:
    - The function sends a GET request to a specified URL to fetch Ed25519 test vectors in JSON format.
    - It asserts that the HTTP response status code is 200, indicating a successful request.
    - The JSON response is parsed into a Python object, and an empty list `verify_tests` is initialized to store processed test cases.
    - The function iterates over each test case in the JSON file, extracting the `flags` field to determine the validity of the test case.
    - If `flags` are present, it checks specific conditions to set the `ok` variable, which indicates whether the test case should pass or fail.
    - If the `flags` contain 'non_canonical_R' without 'low_order_R', an exception is raised with the test case number.
    - Each test case is converted into an [`EddsaVerify`](#EddsaVerify) object with relevant fields and appended to the `verify_tests` list.
    - The function prints a header comment indicating the code is auto-generated and includes the current UTC timestamp.
    - It defines a C struct `fd_ed25519_verify_cctv` and a corresponding typedef for storing test case data.
    - The function iterates over the `verify_tests` list, printing each test case in a C-compatible format, ensuring the signature length is 64 bytes.
    - Finally, it prints a terminating zero entry for the C array.
- **Output**: The function outputs C code that defines a static array of `fd_ed25519_verify_cctv_t` structs, each representing a test case with fields for test case ID, comment, message, signature, public key, and a boolean indicating expected verification success.
- **Functions called**:
    - [`firedancer/contrib/codegen/gen_wycheproofs.EddsaVerify`](#EddsaVerify)


---
### main<!-- {{#callable:firedancer/contrib/codegen/gen_wycheproofs.main}} -->
The `main` function generates C test code files for ED25519 and X25519 cryptographic algorithms using Wycheproof and CCTV test vectors.
- **Inputs**: None
- **Control Flow**:
    - Opens a file 'src/ballet/ed25519/test_ed25519_wycheproof.c' for writing and redirects stdout to this file.
    - Calls the [`_gen_ed25519`](#_gen_ed25519) function to generate ED25519 test code and writes it to the opened file.
    - Opens a file 'src/ballet/ed25519/test_x25519_wycheproof.c' for writing and redirects stdout to this file.
    - Calls the [`_gen_x25519`](#_gen_x25519) function to generate X25519 test code and writes it to the opened file.
    - Opens a file 'src/ballet/ed25519/test_ed25519_cctv.c' for writing and redirects stdout to this file.
    - Calls the [`_gen_cctv_ed25519`](#_gen_cctv_ed25519) function to generate ED25519 test code using CCTV vectors and writes it to the opened file.
- **Output**: The function does not return any value; it writes generated C test code to specified files.
- **Functions called**:
    - [`firedancer/contrib/codegen/gen_wycheproofs._gen_ed25519`](#_gen_ed25519)
    - [`firedancer/contrib/codegen/gen_wycheproofs._gen_x25519`](#_gen_x25519)
    - [`firedancer/contrib/codegen/gen_wycheproofs._gen_cctv_ed25519`](#_gen_cctv_ed25519)


