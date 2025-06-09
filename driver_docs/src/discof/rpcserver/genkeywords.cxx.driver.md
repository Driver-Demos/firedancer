# Purpose
This C++ source code file is designed to generate keyword matching functionality for a web server, specifically for JSON keyword recognition. The code reads a list of keywords and their associated tokens from a file named "keywords.txt" and constructs a data structure to efficiently match these keywords. The primary components of the code include the `keyword` and `matchnode` structures, which are used to represent keywords and nodes in a keyword matching tree, respectively. The [`genmatchnode`](#genmatchnode) function recursively builds a tree of `matchnode` objects, which is then used to generate C code that can match keywords against input strings. This generated code is written to "keywords.h" and "keywords.c" files, which define macros for each keyword token and implement the keyword matching logic.

The file also includes a [`gentest`](#gentest) function that generates test code to verify the correctness of the keyword matching logic. This test code is written to "test_keywords.h". The main function orchestrates the reading of the keyword file, the generation of the matching logic, and the creation of the test code. The generated files are intended to be used as part of a larger project, providing a public API for keyword matching through the `fd_webserver_json_keyword` function and its associated macros. The code is structured to ensure that the generated files are not edited directly, as they are automatically produced by this source file.
# Imports and Dependencies

---
- `stdio.h`
- `stdlib.h`
- `string.h`
- `strings.h`
- `assert.h`
- `map`
- `vector`
- `set`
- `string`


# Data Structures

---
### keyword<!-- {{#data_structure:keyword}} -->
- **Type**: `struct`
- **Members**:
    - `text`: A pointer to a constant character string representing the text being matched.
    - `token`: A pointer to a constant character string representing the output token associated with the text.
- **Description**: The `keyword` struct is a simple data structure used to represent a keyword and its associated token in a text-matching context. It contains two members: `text`, which is a pointer to the character string of the keyword being matched, and `token`, which is a pointer to the character string of the output token that corresponds to the keyword. This struct is typically used in applications where keywords need to be identified and mapped to specific tokens for further processing or analysis.


---
### matchnode<!-- {{#data_structure:matchnode}} -->
- **Type**: `struct`
- **Members**:
    - `token`: A pointer to a constant character string representing the output token.
    - `text`: A pointer to a constant character string representing the text being matched.
    - `children`: A map where each key is a pointer to a matchnode and each value is a vector of characters, representing the children nodes and their associated characters.
- **Description**: The `matchnode` struct is a data structure used to represent nodes in a keyword matching tree. Each node contains pointers to a token and text, which are used to store the matched keyword and its associated token. The `children` map holds pointers to child nodes and the characters that lead to those nodes, allowing for the construction of a tree structure that can be used to efficiently match and identify keywords in a given input.


# Functions

---
### genmatchnode<!-- {{#callable:genmatchnode}} -->
The `genmatchnode` function constructs a trie-like structure of `matchnode` objects based on a given prefix and a table of keywords, identifying possible next characters and handling output tokens.
- **Inputs**:
    - `node`: A pointer to a `matchnode` object where the function will store the result of the trie construction.
    - `prefix`: A C-string representing the current prefix being matched against the keywords.
    - `textlen`: An integer representing the length of the text to be matched.
    - `table`: A pointer to an array of `keyword` structures, each containing a text and a token, representing the keywords to be matched.
- **Control Flow**:
    - Initialize variables for output token and text, and a map to store possible next characters.
    - Calculate the length of the prefix and assert it is not greater than the text length.
    - Iterate over the keyword table to find keywords matching the prefix and of the correct length.
    - If a complete match is found, set the output token and text, ensuring no redundancy.
    - If partial matches are found, populate the `nexts` map with possible next characters.
    - If an output token is set and `nexts` is not empty, report an error and exit.
    - If no output token is set, iterate over `nexts` to create child nodes, checking for duplicate states.
    - Recursively call `genmatchnode` for each new child node with an updated prefix.
    - Reverse the map of children to facilitate later analysis.
- **Output**: The function modifies the `node` parameter by setting its `token`, `text`, and `children` fields to represent the constructed trie structure.


---
### genchaincode<!-- {{#callable:genchaincode}} -->
The `genchaincode` function generates C code to match a sequence of characters from a chain of match nodes and writes it to a file.
- **Inputs**:
    - `chain`: A vector of pointers to `matchnode` objects representing a sequence of nodes to be processed.
    - `prefixlen`: An unsigned integer representing the length of the prefix to be used in the generated code.
    - `fd`: A file pointer to which the generated C code will be written.
- **Control Flow**:
    - Iterates over the `chain` vector using an index `j`.
    - For each node in the chain, checks if it is the first node and writes ' && ' to the file if not.
    - Retrieves the characters associated with the current node's children.
    - If there are multiple characters, writes a logical OR expression for each character to the file.
    - If there is only one character, attempts to optimize by matching up to 8 characters at once using bitwise operations.
    - Writes the appropriate C code to the file for each case, updating the index `j` accordingly.
- **Output**: The function does not return a value; it writes C code to the provided file pointer `fd`.


---
### gencode<!-- {{#callable:gencode}} -->
The `gencode` function generates C code for matching a sequence of characters against a tree of match nodes, optimizing for chains of single transitions and handling multiple children with switch-case statements.
- **Inputs**:
    - `node`: A pointer to the root matchnode from which code generation begins.
    - `indent`: An unsigned integer representing the current indentation level for the generated code.
    - `prefixlen`: An unsigned integer representing the length of the prefix already processed in the keyword.
    - `fd`: A file pointer to the output file where the generated code will be written.
- **Control Flow**:
    - Define a lambda function `doindent` to handle indentation in the output file.
    - Initialize a vector `chain` to store nodes with a single child, and traverse the tree to populate this chain until a node with multiple children is found.
    - If the chain is not empty, write an 'if' statement to the file and call [`genchaincode`](#genchaincode) to generate code for the chain, then increase the indentation.
    - Check if the current node `end` has a token; if so, write a return statement with the token and text to the file.
    - If the node does not have a token, write a 'switch' statement to the file based on the next character in the keyword, iterating over each child node and recursively calling `gencode` for each child.
    - After processing all children, write a 'break' statement for each case and close the switch statement.
    - If a chain was processed, decrease the indentation and close the 'if' block.
- **Output**: The function does not return a value; it writes generated C code to the specified file.
- **Functions called**:
    - [`genchaincode`](#genchaincode)


---
### genmacros<!-- {{#callable:genmacros}} -->
The `genmacros` function generates C preprocessor macros for a set of keywords and writes them to a specified file.
- **Inputs**:
    - `table`: A pointer to an array of `keyword` structures, each containing a `text` and a `token` string, representing the keywords and their associated tokens.
    - `funname`: A string representing the name of the function to be declared in the generated code.
    - `errtoken`: A string representing the error token to be used in the generated code if a keyword is not found.
    - `fd`: A file pointer to the file where the generated macros and function declarations will be written.
- **Control Flow**:
    - Initialize an unsigned integer `j` to 0 and a set `done` to keep track of processed tokens.
    - Iterate over the `keyword` array `table` until a `NULL` text is encountered.
    - For each keyword, check if its token is not already in the `done` set.
    - If the token is not in `done`, write a `#define` macro to the file `fd` with the token and the current value of `j`, then increment `j` and add the token to `done`.
    - Write a conditional `#ifndef` directive for the `errtoken` to the file `fd`, defining it as `-1L` if not already defined.
    - Write function declarations for a function named `funname` and another function prefixed with `un_` to the file `fd`.
- **Output**: The function does not return a value; it writes C preprocessor macros and function declarations to the specified file.


---
### genmatcher<!-- {{#callable:genmatcher}} -->
The `genmatcher` function generates C code for keyword matching and reverse lookup functions based on a given table of keywords and writes it to a specified file.
- **Inputs**:
    - `table`: A pointer to an array of `keyword` structures, each containing a `text` and `token`, representing the keywords and their associated tokens.
    - `funname`: A string representing the name of the function to be generated for keyword matching.
    - `errtoken`: A string representing the token to return in case of an error or unmatched keyword.
    - `fd`: A file pointer to which the generated C code will be written.
- **Control Flow**:
    - Initialize a map `rootsbylen` to store `matchnode` roots indexed by keyword length.
    - Iterate over the `table` to populate `rootsbylen` with `matchnode` roots for each unique keyword length.
    - For each keyword length in `rootsbylen`, generate C code for a switch-case structure to handle keyword matching based on length, using the [`gencode`](#gencode) function.
    - Write the generated C code for the keyword matching function, including a default return of `errtoken` for unmatched cases.
    - Generate and write C code for a reverse lookup function that maps tokens back to their keyword strings.
- **Output**: The function does not return a value; it writes generated C code to the specified file.
- **Functions called**:
    - [`genmatchnode`](#genmatchnode)
    - [`gencode`](#gencode)


---
### gentest<!-- {{#callable:gentest}} -->
The `gentest` function generates a C function that tests a keyword matching function by asserting expected outputs for various input scenarios.
- **Inputs**:
    - `table`: A pointer to an array of `keyword` structures, each containing a `text` and a `token`, representing the keywords and their corresponding tokens to be tested.
    - `funname`: A string representing the name of the function to be tested.
    - `errtoken`: A string representing the token to be returned when a test case is expected to fail.
    - `fd`: A file pointer to which the generated test function code will be written.
- **Control Flow**:
    - The function begins by writing the function signature for the test function to the file `fd`.
    - It iterates over each keyword in the `table` until a `NULL` text is encountered, indicating the end of the table.
    - For each keyword, it copies the keyword text into a buffer `scratch` and writes an assertion to check if the function `funname` returns the expected token for the exact keyword text.
    - It modifies the `scratch` buffer by appending an 'x' to the keyword text and writes an assertion to check if the function returns `errtoken` for this modified text.
    - It truncates the last character of the keyword text in `scratch` and checks if this truncated text matches any other keyword in the table; if not, it writes an assertion to check if the function returns `errtoken`.
    - For each character position in the keyword text, it replaces the character with '|' in `scratch` and writes an assertion to check if the function returns `errtoken` for these modified texts.
    - Finally, it writes the closing brace for the test function to the file `fd`.
- **Output**: The function outputs C code to the file `fd` that defines a test function for the specified keyword matching function, containing assertions for various test cases.


---
### main<!-- {{#callable:main}} -->
The `main` function reads keywords and tokens from a file, processes them into a table, and generates C header and source files for keyword matching and testing.
- **Inputs**:
    - `argc`: The number of command-line arguments passed to the program.
    - `argv`: An array of character pointers listing all the arguments.
- **Control Flow**:
    - Open the file 'keywords.txt' for reading and read its contents into a buffer.
    - Close the file after reading.
    - Initialize a keyword table to store up to 256 keywords and tokens.
    - Iterate over the buffer to parse each line into a keyword and a token, storing them in the keyword table.
    - Check for parsing errors and ensure each line contains exactly a keyword and a token.
    - Open 'keywords.h' for writing and generate macro definitions for the keywords using [`genmacros`](#genmacros).
    - Open 'keywords.c' for writing, include 'keywords.h', and generate keyword matching code using [`genmatcher`](#genmatcher).
    - Open 'test_keywords.h' for writing and generate test code for the keywords using [`gentest`](#gentest).
    - Close all opened files.
- **Output**: The function returns 0 on successful execution, or -1 if there is an error in the input file format.
- **Functions called**:
    - [`genmacros`](#genmacros)
    - [`genmatcher`](#genmatcher)
    - [`gentest`](#gentest)


