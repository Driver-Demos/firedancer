# Purpose
This C header file, `fd_toml.h`, provides an API for parsing TOML (Tom's Obvious, Minimal Language) configuration files into a structured format using a custom data structure called `fd_pod`. It defines several error codes to handle various parsing issues, such as running out of space or encountering duplicate keys, and specifies a maximum path length for the parsed data. The primary function, [`fd_toml_parse`](#fd_toml_parse), deserializes a TOML document into an `fd_pod` object, utilizing scratch memory for processing, and returns detailed error information if parsing fails. The file also includes a function, [`fd_toml_strerror`](#fd_toml_strerror), to convert error codes into human-readable strings. Notably, the implementation supports only a subset of the TOML specification, with several known limitations and deviations from the official TOML grammar.
# Imports and Dependencies

---
- `../../util/pod/fd_pod.h`


# Global Variables

---
### fd\_toml\_strerror
- **Type**: `function pointer`
- **Description**: `fd_toml_strerror` is a function that returns a constant character pointer to a human-readable error string. This string describes the error code provided as an argument, which corresponds to the negative return values from the `fd_toml_parse` function.
- **Use**: This function is used to translate error codes from `fd_toml_parse` into descriptive error messages for easier debugging and user feedback.


# Data Structures

---
### fd\_toml\_err\_info
- **Type**: `struct`
- **Members**:
    - `line`: 1-indexed line number indicating where the error occurred in the TOML file.
- **Description**: The `fd_toml_err_info` structure is designed to hold information about errors encountered during the parsing of a TOML file. Currently, it contains a single member, `line`, which records the line number where the error occurred, using a 1-based index. This structure is intended to be expanded with additional fields to provide more detailed error information in the future.


---
### fd\_toml\_err\_info\_t
- **Type**: `struct`
- **Members**:
    - `line`: 1-indexed line number indicating where the error occurred in the TOML file.
- **Description**: The `fd_toml_err_info_t` structure is designed to store information about errors encountered during the parsing of a TOML file. Currently, it contains a single member, `line`, which records the line number where the parsing error occurred. This structure can be expanded to include additional error details as needed, providing a mechanism for detailed error reporting in TOML parsing operations.


# Function Declarations (Public API)

---
### fd\_toml\_parse<!-- {{#callable_declaration:fd_toml_parse}} -->
Deserializes a TOML document into an fd_pod object tree.
- **Description**: Use this function to parse a TOML document and insert its object tree into an fd_pod. It requires a pointer to the TOML data, its size, a local join to an fd_pod, and a scratch memory area for temporary storage during parsing. The function is suitable for parsing TOML documents that do not require strict adherence to the TOML specification, as it allows certain deviations. It is not optimized for performance and should not be used with untrusted input. The function returns success or an error code, and optionally provides error details if parsing fails.
- **Inputs**:
    - `toml`: Pointer to the first byte of the TOML document. If toml_sz is 0, this pointer is ignored and may be invalid.
    - `toml_sz`: The byte length of the TOML document. If 0, the function does nothing and returns success.
    - `pod`: A local join to an fd_pod where the parsed object tree will be inserted. The caller retains ownership.
    - `scratch`: Pointer to a scratch memory area used during deserialization. Must be non-null and large enough to handle the parsing process.
    - `scratch_sz`: Size of the scratch memory area. Recommended to be at least 4kB. If too small, parsing may fail for long strings and sub-tables.
    - `opt_err`: Optional pointer to a fd_toml_err_info_t structure to receive error information. If null, error details are not provided.
- **Output**: Returns FD_TOML_SUCCESS on success or an appropriate FD_TOML_ERR_* code on failure. If opt_err is provided, it is initialized with error information.
- **See also**: [`fd_toml_parse`](fd_toml.c.driver.md#fd_toml_parse)  (Implementation)


---
### fd\_toml\_strerror<!-- {{#callable_declaration:fd_toml_strerror}} -->
Return a human-readable error string for a given TOML error code.
- **Description**: Use this function to obtain a descriptive error message corresponding to a specific TOML error code, which can be useful for logging or debugging purposes. It is particularly relevant for interpreting negative return values from the `fd_toml_parse` function. The function returns a static string, so there is no need to manage memory for the returned value. It handles all defined TOML error codes and returns "unknown error" for any unrecognized codes.
- **Inputs**:
    - `err`: An integer representing a TOML error code, typically a negative value returned by `fd_toml_parse`. Valid values include FD_TOML_SUCCESS, FD_TOML_ERR_POD, FD_TOML_ERR_SCRATCH, FD_TOML_ERR_KEY, FD_TOML_ERR_DUP, FD_TOML_ERR_RANGE, and FD_TOML_ERR_PARSE. If an unrecognized error code is provided, the function returns "unknown error".
- **Output**: A constant character pointer to a static string describing the error associated with the provided error code.
- **See also**: [`fd_toml_strerror`](fd_toml.c.driver.md#fd_toml_strerror)  (Implementation)


