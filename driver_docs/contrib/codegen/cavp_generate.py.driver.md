# Purpose
This Python script is designed to generate C include files containing test vectors for cryptographic hash functions, specifically those defined by the NIST Cryptographic Algorithm Validation Program (CAVP). The script processes CAVP response files, which contain test data for verifying cryptographic hash function implementations, and outputs C code that defines these test vectors as static constant arrays. The script is part of the Firedancer project and is intended to be executed as a standalone script, as indicated by the presence of the `__main__` block.

Key components of the script include functions for converting binary data into C string and array initializers ([`bin2cstr`](#bin2cstr) and [`bin2carr`](#bin2carr)), a `Msg` dataclass to represent message-digest pairs, and a `HashMsgGenerator` class that manages the generation of C test vector definitions. The script uses regular expressions to parse the response files and extract message and digest data, which are then formatted into C code. The script supports SHA-2 algorithms (SHA-256, SHA-384, and SHA-512) and allows users to specify the algorithm, test name, and output file via command-line arguments. The generated C code is output to either a specified file or standard output, making it suitable for integration into C projects that require cryptographic validation.
# Imports and Dependencies

---
- `argparse`
- `dataclasses.dataclass`
- `pathlib.Path`
- `re`
- `sys`
- `textwrap`
- `typing.Iterator`


# Classes

---
### Msg<!-- {{#class:firedancer/contrib/codegen/cavp_generate.Msg}} -->
- **Decorators**: `@dataclass`
- **Members**:
    - `msg`: A byte sequence representing the message.
    - `digest`: A byte sequence representing the message digest.
- **Description**: The Msg class is a simple data structure used to encapsulate a message and its corresponding digest, both represented as byte sequences. It is designed to facilitate the handling and processing of cryptographic test vectors, particularly in the context of parsing and generating CAVP response files for cryptographic hash function verification.


---
### HashMsgGenerator<!-- {{#class:firedancer/contrib/codegen/cavp_generate.HashMsgGenerator}} -->
- **Members**:
    - `name`: The name of the test vector.
    - `test_vector_type`: The type of the test vector, typically related to the hash algorithm.
    - `hashes`: A list of byte arrays representing the message digests.
- **Description**: The HashMsgGenerator class is responsible for generating C include files containing static const test vectors for cryptographic hash functions. It manages the creation of test vectors by storing message digests and formatting them into C array initializers. The class is initialized with a name and a test vector type, and it provides methods to write individual test vectors and finalize the output by printing the complete set of test vectors in a format suitable for inclusion in C source files.
- **Methods**:
    - [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator.__init__`](#HashMsgGenerator__init__)
    - [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator._test_vector_name`](#HashMsgGenerator_test_vector_name)
    - [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator.write_test`](#HashMsgGeneratorwrite_test)
    - [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator.finish`](#HashMsgGeneratorfinish)

**Methods**

---
#### HashMsgGenerator\.\_\_init\_\_<!-- {{#callable:firedancer/contrib/codegen/cavp_generate.HashMsgGenerator.__init__}} -->
The `__init__` method initializes a `HashMsgGenerator` object with a name, test vector type, and an empty list for storing hashes.
- **Inputs**:
    - `name`: A string representing the name of the test vector.
    - `test_vector_type`: A string representing the type of the test vector.
- **Control Flow**:
    - Assigns the input parameter `name` to the instance variable `self.name`.
    - Assigns the input parameter `test_vector_type` to the instance variable `self.test_vector_type`.
    - Initializes `self.hashes` as an empty list to store hash values.
- **Output**: This method does not return any value; it initializes the instance variables of the `HashMsgGenerator` class.
- **See also**: [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator`](#HashMsgGenerator)  (Base Class)


---
#### HashMsgGenerator\.\_test\_vector\_name<!-- {{#callable:firedancer/contrib/codegen/cavp_generate.HashMsgGenerator._test_vector_name}} -->
The `_test_vector_name` method generates a formatted string representing a test vector name using the instance's name and a given index.
- **Inputs**:
    - `i`: An integer index used to differentiate test vector names.
- **Control Flow**:
    - The method takes an integer `i` as input.
    - It returns a formatted string that combines the instance's `name` attribute with the string '_test_' and the integer `i`.
- **Output**: A string formatted as "{self.name}_test_{i}".
- **See also**: [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator`](#HashMsgGenerator)  (Base Class)


---
#### HashMsgGenerator\.write\_test<!-- {{#callable:firedancer/contrib/codegen/cavp_generate.HashMsgGenerator.write_test}} -->
The `write_test` method generates and prints a C static array declaration for a given message and its digest, appending the digest to an internal list.
- **Inputs**:
    - `msg`: An instance of the `Msg` class containing a message (`msg`) and its digest (`digest`).
- **Control Flow**:
    - Check if the message (`msg.msg`) is empty; if so, return immediately without doing anything.
    - Determine the current index `i` by getting the length of the `hashes` list.
    - Append the message digest (`msg.digest`) to the `hashes` list.
    - Print a C static array declaration using the [`_test_vector_name`](#HashMsgGenerator_test_vector_name) method to generate the array name based on the current index `i`.
    - Convert the message bytes to a C array initializer format using [`bin2carr`](#bin2carr) and print it with indentation.
    - Close the C array declaration with a closing brace and semicolon.
- **Output**: The method does not return any value; it outputs C code to the standard output.
- **Functions called**:
    - [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator._test_vector_name`](#HashMsgGenerator_test_vector_name)
    - [`firedancer/contrib/codegen/cavp_generate.bin2carr`](#bin2carr)
- **See also**: [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator`](#HashMsgGenerator)  (Base Class)


---
#### HashMsgGenerator\.finish<!-- {{#callable:firedancer/contrib/codegen/cavp_generate.HashMsgGenerator.finish}} -->
The `finish` method generates and prints a C array of test vectors from stored hash digests.
- **Inputs**: None
- **Control Flow**:
    - Prints the beginning of a C array declaration using the `test_vector_type` and `name` attributes.
    - Iterates over the `hashes` list, which contains hash digests, using an index and the digest value.
    - For each digest, it generates a test vector name using [`_test_vector_name`](#HashMsgGenerator_test_vector_name) and prints a C struct initializer with the test vector name and its size.
    - Converts each digest to a C string format using [`bin2cstr`](#bin2cstr) and prints it as part of the struct initializer.
    - Prints a terminating struct with null values to indicate the end of the array.
    - Prints the closing of the C array declaration.
- **Output**: The method outputs a formatted C array declaration to the standard output, representing the test vectors.
- **Functions called**:
    - [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator._test_vector_name`](#HashMsgGenerator_test_vector_name)
    - [`firedancer/contrib/codegen/cavp_generate.bin2cstr`](#bin2cstr)
- **See also**: [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator`](#HashMsgGenerator)  (Base Class)



# Functions

---
### bin2cstr<!-- {{#callable:firedancer/contrib/codegen/cavp_generate.bin2cstr}} -->
The `bin2cstr` function converts a byte sequence into a C-style string with hex-escaped characters, formatted for readability.
- **Inputs**:
    - `data`: A byte sequence that needs to be converted into a C-style string with hex-escaped characters.
- **Control Flow**:
    - Check if the input data is empty; if so, return 'NULL'.
    - Initialize the output string with a starting double quote.
    - Iterate over each byte in the input data, using its index and value.
    - For the first byte, do nothing special.
    - For every 32nd byte, add a newline and a starting double quote to the output string.
    - For every 8th byte (except the first), add a space and a starting double quote to the output string.
    - Convert each byte to a hex-escaped string and append it to the output string.
    - For every 8th byte, add a closing double quote to the output string.
    - After the loop, if the total number of bytes is not a multiple of 8, add a closing double quote to the output string.
    - Return the formatted C-style string.
- **Output**: A string representing the input byte sequence as a C-style string with hex-escaped characters, formatted for readability.


---
### bin2carr<!-- {{#callable:firedancer/contrib/codegen/cavp_generate.bin2carr}} -->
The `bin2carr` function converts a bytes object into a C array initializer string with formatted hexadecimal values.
- **Inputs**:
    - `data`: A bytes object containing the binary data to be converted into a C array initializer.
- **Control Flow**:
    - The function asserts that the input data is not empty.
    - An empty string `out` is initialized to accumulate the C array initializer.
    - The function iterates over each byte in the input data using `enumerate` to get both the index and the byte value.
    - For the first byte, no prefix is added to the output string.
    - For every 16th byte, a newline followed by a comma is added to the output string.
    - For every 8th byte that is not the 16th, a comma followed by a space is added to the output string.
    - For all other bytes, a comma is added to the output string.
    - Each byte is formatted as a two-digit hexadecimal number prefixed by `_()` and appended to the output string.
    - The function returns the accumulated string `out` as the C array initializer.
- **Output**: A string representing the C array initializer with each byte formatted as a two-digit hexadecimal number prefixed by `_()`.


---
### \_find\_line\_match<!-- {{#callable:firedancer/contrib/codegen/cavp_generate._find_line_match}} -->
The function `_find_line_match` searches through an iterator of lines to find and return the first line that matches a given regular expression pattern.
- **Inputs**:
    - `lines`: An iterator of strings, where each string represents a line to be checked against the pattern.
    - `pat`: A compiled regular expression pattern used to match against each line in the iterator.
- **Control Flow**:
    - Iterates over each line in the provided `lines` iterator.
    - For each line, attempts to match it against the provided regular expression pattern `pat`.
    - If a match is found, the function immediately returns the match object.
    - If no match is found after all lines have been checked, an `AssertionError` is raised with the message 'failed to parse file'.
- **Output**: The function returns a `re.Match` object representing the first successful match found in the lines, or raises an `AssertionError` if no match is found.


---
### parse\_msg\_rsp<!-- {{#callable:firedancer/contrib/codegen/cavp_generate.parse_msg_rsp}} -->
The `parse_msg_rsp` function parses a CAVP response file to extract message tests and returns a list of [`Msg`](#Msg) objects containing the message and its digest.
- **Inputs**:
    - `file`: An iterable file object representing a CAVP response file containing message tests.
- **Control Flow**:
    - Initialize an iterator over the lines of the input file.
    - Compile regular expressions to match message count, message size, message content, and message digest.
    - Initialize an empty list `msgs` to store parsed [`Msg`](#Msg) objects.
    - Extract the total number of messages (`msg_count`) from the file using the `_match_msg_count` pattern.
    - Enter a loop that continues until all messages are parsed (`msg_count` > 0).
    - Within the loop, extract the message size (`msg_sz`), message content (`msg`), and message digest (`md`) using the respective regular expressions.
    - Convert the message and digest from hexadecimal to bytes and truncate the message to its specified size.
    - Create a [`Msg`](#Msg) object with the parsed message and digest, and append it to the `msgs` list.
    - Decrement `msg_count` to process the next message.
    - Return the list of [`Msg`](#Msg) objects after all messages have been parsed.
- **Output**: A list of [`Msg`](#Msg) objects, each containing a message and its corresponding digest extracted from the CAVP response file.
- **Functions called**:
    - [`firedancer/contrib/codegen/cavp_generate._find_line_match`](#_find_line_match)
    - [`firedancer/contrib/codegen/cavp_generate.Msg`](#Msg)


---
### \_main<!-- {{#callable:firedancer/contrib/codegen/cavp_generate._main}} -->
The `_main` function parses command-line arguments to generate C include files containing SHA-2 test vectors from a CAVS response file, outputting the result to stdout or a specified file.
- **Inputs**: None
- **Control Flow**:
    - An `ArgumentParser` is created to handle command-line arguments, including `--rsp` for the response file path, `--alg` for the algorithm type, `--name` for the test name, and `--out` for the output file path.
    - The parsed arguments are stored in `args`, and if `args.out` is specified, `sys.stdout` is redirected to the specified file.
    - A header comment is printed to the output, indicating the file was auto-generated and specifying the response file name.
    - The response file specified by `args.rsp` is opened and parsed using [`parse_msg_rsp`](#parse_msg_rsp) to extract message test vectors.
    - A [`HashMsgGenerator`](#HashMsgGenerator) object is instantiated with the test name and test vector type derived from the algorithm argument.
    - For each message in the parsed response, [`write_test`](#HashMsgGeneratorwrite_test) is called on the [`HashMsgGenerator`](#HashMsgGenerator) to generate and print the test vector.
    - After processing all messages, `gen.finish()` is called to finalize and print the test vector array.
    - A macro definition `#define _(v)` is used to format bytes, and it is undefined at the end of the function.
- **Output**: The function outputs a C include file containing static const SHA-2 test vectors, either to stdout or to a specified file.
- **Functions called**:
    - [`firedancer/contrib/codegen/cavp_generate.parse_msg_rsp`](#parse_msg_rsp)
    - [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator`](#HashMsgGenerator)
    - [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator.write_test`](#HashMsgGeneratorwrite_test)
    - [`firedancer/contrib/codegen/cavp_generate.HashMsgGenerator.finish`](#HashMsgGeneratorfinish)


