# Purpose
This C source code file provides utility functions for querying and validating configuration data stored in a "pod" structure. The primary purpose of the code is to facilitate the extraction and validation of various data types from a configuration pod, which is a structured data container. The file includes functions to retrieve and validate strings, unsigned long integers, unsigned integers, unsigned short integers, boolean values, and floating-point numbers from the pod. Each function checks the type of the value stored in the pod and logs warnings if the value is of an unexpected type or if it exceeds specified bounds. This ensures that configuration data is correctly interpreted and any discrepancies are promptly reported.

The file also includes a function, [`fdctl_pod_find_leftover`](#fdctl_pod_find_leftover), which recursively descends through the pod to log warnings for any unrecognized configuration options, helping users identify unused or incorrect configuration entries. The code is designed to be part of a larger system, as indicated by the inclusion of external utility headers and the use of macros for logging and type checking. The functions are defined as static inline, suggesting they are intended for use within the same compilation unit, optimizing for performance by reducing function call overhead. Overall, this file is a specialized utility for managing and validating configuration data within a software system.
# Imports and Dependencies

---
- `../../util/fd_util.h`
- `../../util/pod/fd_pod.h`


# Functions

---
### fdctl\_cfg\_get\_cstr\_<!-- {{#callable:fdctl_cfg_get_cstr_}} -->
The function `fdctl_cfg_get_cstr_` copies a C-style string from a pod info structure to an output buffer if the value type is correct and the buffer is large enough.
- **Inputs**:
    - `out`: A pointer to a character array where the C-style string will be copied.
    - `out_sz`: The size of the output buffer `out`.
    - `info`: A pointer to a `fd_pod_info_t` structure containing the value to be copied.
    - `path`: A string representing the path to the value, used for logging purposes.
- **Control Flow**:
    - Check if the value type in `info` is `FD_POD_VAL_TYPE_CSTR`; if not, log a warning and return 0.
    - Retrieve the string from `info->val` and calculate its length including the null terminator.
    - Check if the string length exceeds `out_sz`; if so, log a warning and return 0.
    - Copy the string to the output buffer `out` using `fd_memcpy`.
    - Return 1 to indicate success.
- **Output**: Returns 1 if the string is successfully copied to the output buffer, otherwise returns 0.


---
### fdctl\_cfg\_get\_ulong<!-- {{#callable:fdctl_cfg_get_ulong}} -->
The `fdctl_cfg_get_ulong` function retrieves an unsigned long integer value from a pod configuration, ensuring it is valid and non-negative.
- **Inputs**:
    - `out`: A pointer to an unsigned long where the retrieved value will be stored.
    - `out_sz`: The size of the output buffer, marked as unused in this function.
    - `info`: A constant pointer to an `fd_pod_info_t` structure containing the value type and data.
    - `path`: A constant character pointer representing the path to the configuration value, used for logging purposes.
- **Control Flow**:
    - Initialize a variable `num` to store the decoded value.
    - Check the type of the value in `info->val_type`.
    - If the type is `FD_POD_VAL_TYPE_LONG`, decode the value as a signed long, check if it is negative, log a warning and return 0 if it is, otherwise cast it to unsigned long.
    - If the type is `FD_POD_VAL_TYPE_ULONG`, decode the value directly as an unsigned long.
    - If the type is neither, log a warning about the invalid value and return 0.
    - Store the decoded value in the location pointed to by `out`.
    - Return 1 to indicate success.
- **Output**: Returns 1 if the value is successfully retrieved and valid, otherwise returns 0.


---
### fdctl\_cfg\_get\_uint<!-- {{#callable:fdctl_cfg_get_uint}} -->
The `fdctl_cfg_get_uint` function retrieves an unsigned integer value from a configuration pod and checks if it is within the bounds of a `uint` type.
- **Inputs**:
    - `out`: A pointer to a `uint` where the retrieved value will be stored.
    - `out_sz`: An unused parameter, typically representing the size of the output buffer.
    - `info`: A pointer to a `fd_pod_info_t` structure containing the configuration data.
    - `path`: A string representing the path to the configuration value within the pod.
- **Control Flow**:
    - Call [`fdctl_cfg_get_ulong`](#fdctl_cfg_get_ulong) to retrieve a `ulong` value from the configuration pod using the provided `info` and `path`.
    - Check if the retrieved `ulong` value exceeds `UINT_MAX`; if so, log a warning and return 0.
    - If the value is within bounds, cast it to `uint` and store it in the location pointed to by `out`.
    - Return 1 to indicate success.
- **Output**: Returns 1 if the value is successfully retrieved and within bounds, otherwise returns 0.
- **Functions called**:
    - [`fdctl_cfg_get_ulong`](#fdctl_cfg_get_ulong)


---
### fdctl\_cfg\_get\_ushort<!-- {{#callable:fdctl_cfg_get_ushort}} -->
The function `fdctl_cfg_get_ushort` retrieves an unsigned short integer from a configuration pod, ensuring it is within valid bounds.
- **Inputs**:
    - `out`: A pointer to an unsigned short where the result will be stored.
    - `out_sz`: The size of the output buffer, marked as unused in this function.
    - `info`: A constant pointer to a `fd_pod_info_t` structure containing the configuration data.
    - `path`: A constant character pointer representing the path to the configuration value within the pod.
- **Control Flow**:
    - Call [`fdctl_cfg_get_ulong`](#fdctl_cfg_get_ulong) to retrieve a `ulong` value from the configuration pod using the provided `info` and `path`.
    - Check if the retrieval was unsuccessful; if so, return 0 indicating failure.
    - Verify if the retrieved `ulong` value exceeds `USHORT_MAX`; if it does, log a warning and return 0.
    - If the value is within bounds, cast it to `ushort` and store it in the location pointed to by `out`.
    - Return 1 to indicate successful retrieval and conversion.
- **Output**: Returns 1 if the unsigned short value is successfully retrieved and within bounds, otherwise returns 0.
- **Functions called**:
    - [`fdctl_cfg_get_ulong`](#fdctl_cfg_get_ulong)


---
### fdctl\_cfg\_get\_bool<!-- {{#callable:fdctl_cfg_get_bool}} -->
The `fdctl_cfg_get_bool` function retrieves a boolean value from a pod configuration, ensuring the value is of the correct type and decoding it appropriately.
- **Inputs**:
    - `out`: A pointer to an integer where the decoded boolean value will be stored.
    - `out_sz`: An unused parameter, typically representing the size of the output buffer.
    - `info`: A constant pointer to a `fd_pod_info_t` structure containing the value to be decoded.
    - `path`: A constant character pointer representing the path to the configuration value, used for logging purposes.
- **Control Flow**:
    - Check if the value type in `info` is `FD_POD_VAL_TYPE_INT`; if not, log a warning and return 0.
    - Decode the value from `info->val` using `fd_ulong_svw_dec` into a `ulong` variable `u`.
    - Convert the decoded `ulong` value `u` to an integer using `fd_int_zz_dec` and store it in the location pointed to by `out`.
    - Return 1 to indicate successful retrieval and decoding of the boolean value.
- **Output**: Returns 1 if the boolean value is successfully retrieved and decoded, otherwise returns 0 if the value type is incorrect.


---
### fdctl\_cfg\_get\_float<!-- {{#callable:fdctl_cfg_get_float}} -->
The `fdctl_cfg_get_float` function retrieves a floating-point value from a given configuration pod and stores it in the provided output variable.
- **Inputs**:
    - `out`: A pointer to a float where the retrieved value will be stored.
    - `out_sz`: An unused parameter, typically representing the size of the output buffer.
    - `info`: A pointer to a `fd_pod_info_t` structure containing the value type and data to be retrieved.
    - `path`: A string representing the path to the configuration value, used for logging purposes.
- **Control Flow**:
    - Initialize variables `unum` and `num` for processing the value.
    - Check the type of value stored in `info->val_type`.
    - If the type is `FD_POD_VAL_TYPE_LONG`, decode the value as a long integer, check if it is non-negative, and convert it to a float.
    - If the type is `FD_POD_VAL_TYPE_ULONG`, decode the value as an unsigned long integer and convert it to a float.
    - If the type is `FD_POD_VAL_TYPE_FLOAT`, directly load the float value from `info->val`.
    - If the value type is invalid, log a warning and return 0.
    - Store the converted float value in the location pointed to by `out`.
    - Return 1 to indicate success.
- **Output**: Returns 1 on successful retrieval and conversion of the value, or 0 if an error occurs (e.g., invalid type or negative value for long type).


# Function Declarations (Public API)

---
### fdctl\_pod\_find\_leftover<!-- {{#callable_declaration:fdctl_pod_find_leftover}} -->
Logs warnings for unrecognized configuration keys in a pod.
- **Description**: Use this function to identify and log warnings for any unrecognized configuration keys present in a pod after loading configuration files. It recursively traverses the pod structure and logs a warning for each leaf item that is not recognized. This function is useful for debugging and ensuring that all configuration options are correctly processed. It should be called after the configuration files have been loaded into the pod to verify that no extraneous or unexpected keys are present.
- **Inputs**:
    - `pod`: A pointer to the pod structure to be checked. Must not be null. The function assumes the pod is already populated with configuration data.
- **Output**: Returns 1 if no unrecognized keys are found, otherwise returns 0 and logs a warning for each unrecognized key.
- **See also**: [`fdctl_pod_find_leftover`](fd_config_extract.c.driver.md#fdctl_pod_find_leftover)  (Implementation)


