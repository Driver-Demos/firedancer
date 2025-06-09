# Purpose
The provided C header file, `fd_funk_val.h`, defines a set of APIs for managing the values associated with funk records. It is part of a larger system, as indicated by its inclusion of other headers like `fd_funk_rec.h`, and is not intended to be included directly by users; instead, users should include `fd_funk.h`. The file provides functionality to access, modify, and verify the values of records within a funk system, which appears to be a data management or database-like system. The key components include functions for retrieving the size and memory allocation of record values, accessing the values themselves, and modifying the size of these values. Additionally, it includes utility functions for initializing and flushing record values, as well as verifying the integrity of these values.

The header file defines several inline functions and a few non-inline functions, indicating a mix of performance optimization and more complex operations that might require external linkage. The functions are designed to handle memory management tasks such as resizing and freeing memory associated with record values, and they include error handling mechanisms to ensure robustness. The file also defines constants like `FD_FUNK_REC_VAL_MAX` and `FD_FUNK_VAL_ALIGN` to manage constraints and alignments for record values. Overall, this header file is a specialized component of a larger system, providing essential operations for managing the values of records in a structured and efficient manner.
# Imports and Dependencies

---
- `fd_funk_rec.h`


# Global Variables

---
### fd\_funk\_val\_truncate
- **Type**: `function`
- **Description**: The `fd_funk_val_truncate` function is designed to resize a record's value to a specified size, optimizing for minimal excess allocation. It returns a pointer to the resized value on success or NULL on failure, with an optional error code provided through `opt_err`. The function ensures that any existing pointers to the record's value storage are invalidated due to potential reallocation.
- **Use**: This function is used to adjust the size of a record's value, ensuring efficient memory usage by minimizing excess allocation.


# Functions

---
### fd\_funk\_val\_sz<!-- {{#callable:fd_funk_val_sz}} -->
The `fd_funk_val_sz` function returns the current size of the value associated with a given funk record.
- **Inputs**:
    - `rec`: A pointer to a `fd_funk_rec_t` structure, representing a live funk record in the caller's address space.
- **Control Flow**:
    - The function takes a single argument, `rec`, which is a pointer to a `fd_funk_rec_t` structure.
    - It accesses the `val_sz` field of the `rec` structure, which represents the current size of the record's value in bytes.
    - The function returns the value of `val_sz` cast to an `ulong` type.
- **Output**: The function returns an `ulong` representing the current size of the record's value in bytes.


---
### fd\_funk\_val\_max<!-- {{#callable:fd_funk_val_max}} -->
The `fd_funk_val_max` function returns the maximum size of the value allocation for a given funk record.
- **Inputs**:
    - `rec`: A pointer to a constant `fd_funk_rec_t` structure, representing a live funk record in the caller's address space.
- **Control Flow**:
    - The function takes a single input, a pointer to a constant `fd_funk_rec_t` structure.
    - It accesses the `val_max` field of the `fd_funk_rec_t` structure pointed to by `rec`.
    - The function returns the value of `val_max` cast to an `ulong`.
- **Output**: The function returns an `ulong` representing the maximum size of the value allocation in bytes for the given funk record.


---
### fd\_funk\_val<!-- {{#callable:fd_funk_val}} -->
The `fd_funk_val` function returns a pointer to the current value associated with a funk record, or NULL if the record is marked for erasure or has no value.
- **Inputs**:
    - `rec`: A pointer to a `fd_funk_rec_t` structure representing a live funk record in the caller's address space.
    - `wksp`: A pointer to a `fd_wksp_t` structure, which should be the workspace associated with the current local join of the funk.
- **Control Flow**:
    - Retrieve the global address of the value from the `rec` structure.
    - Check if the global address is zero; if so, return NULL, indicating the record is marked for erasure or has no value.
    - If the global address is non-zero, use `fd_wksp_laddr_fast` to convert the global address to a local address in the caller's address space and return it.
- **Output**: A pointer to the value associated with the record in the caller's address space, or NULL if the record has no value or is marked for erasure.


---
### fd\_funk\_val\_const<!-- {{#callable:fd_funk_val_const}} -->
The `fd_funk_val_const` function returns a constant pointer to the value associated with a given funk record, or NULL if the record's value is not present.
- **Inputs**:
    - `rec`: A pointer to a constant `fd_funk_rec_t` structure representing a live funk record in the caller's address space.
    - `wksp`: A pointer to a constant `fd_wksp_t` structure, which should be the workspace associated with the current local join of the funk.
- **Control Flow**:
    - Retrieve the global address of the value from the `rec` structure's `val_gaddr` field.
    - Check if `val_gaddr` is zero; if so, return NULL, indicating that the value is not present or the record is marked for erasure.
    - If `val_gaddr` is non-zero, use `fd_wksp_laddr_fast` to convert the global address to a local address in the workspace and return it.
- **Output**: A constant pointer to the value associated with the record, or NULL if the value is not present.


---
### fd\_funk\_val\_init<!-- {{#callable:fd_funk_val_init}} -->
The `fd_funk_val_init` function initializes a funk record's value metadata to represent a NULL value.
- **Inputs**:
    - `rec`: A pointer to a `fd_funk_rec_t` structure, assumed to be in the caller's address space with uninitialized value metadata.
- **Control Flow**:
    - Set the `val_sz` field of the `rec` structure to 0, indicating the size of the value is zero.
    - Set the `val_max` field of the `rec` structure to 0, indicating no workspace is allocated for the value.
    - Set the `val_gaddr` field of the `rec` structure to 0, indicating no global address is associated with the value.
    - Return the modified `rec` pointer.
- **Output**: Returns the pointer to the `fd_funk_rec_t` structure (`rec`) after initializing its value metadata.


---
### fd\_funk\_val\_flush<!-- {{#callable:fd_funk_val_flush}} -->
The `fd_funk_val_flush` function resets a funk record's value to NULL and frees any associated memory if it exists.
- **Inputs**:
    - `rec`: A pointer to a live funk record in the caller's address space.
    - `alloc`: A pointer to an allocator, which is the result of `fd_funk_alloc(funk, wksp)`.
    - `wksp`: A pointer to a workspace, which is the result of `fd_funk_wksp(funk)` where funk is a current local join.
- **Control Flow**:
    - Retrieve the global address of the record's value from `rec->val_gaddr`.
    - Call `fd_funk_val_init(rec)` to reset the record's value metadata to NULL.
    - If `val_gaddr` is non-zero, free the memory associated with the value using `fd_alloc_free` and `fd_wksp_laddr_fast` to convert the global address to a local address.
    - Return the modified record `rec`.
- **Output**: The function returns the modified funk record `rec`.
- **Functions called**:
    - [`fd_funk_val_init`](#fd_funk_val_init)


# Function Declarations (Public API)

---
### fd\_funk\_val\_truncate<!-- {{#callable_declaration:fd_funk_val_truncate}} -->
Resizes the value associated with a record to a specified size.
- **Description**: This function adjusts the size of the value associated with a given record to the specified size, potentially reallocating memory to accommodate the new size. It is designed for scenarios where the user knows the desired long-term size of the record's value. The function minimizes excess memory allocation, which may invalidate existing pointers to the record's value storage. It returns a pointer to the resized value on success or NULL on failure. If an error occurs and opt_err is provided, it will contain an error code indicating the type of failure. The function assumes no concurrent modifications to the record.
- **Inputs**:
    - `rec`: A pointer to a live funk record in the caller's address space. Must not be null, and the record must not be marked for erasure.
    - `alloc`: A pointer to the allocator associated with the workspace. Must not be null.
    - `wksp`: A pointer to the workspace associated with the funk. Must not be null.
    - `align`: The alignment for the allocation, which must be a power of 2. If 0, the default alignment is used.
    - `sz`: The desired size for the record's value, which must be between 0 and FD_FUNK_REC_VAL_MAX inclusive.
    - `opt_err`: An optional pointer to an integer where the error code will be stored if the operation fails. Can be null if error codes are not needed.
- **Output**: Returns a pointer to the resized value on success, or NULL on failure. If opt_err is provided, it will contain FD_FUNK_SUCCESS on success or an appropriate error code on failure.
- **See also**: [`fd_funk_val_truncate`](fd_funk_val.c.driver.md#fd_funk_val_truncate)  (Implementation)


---
### fd\_funk\_val\_verify<!-- {{#callable_declaration:fd_funk_val_verify}} -->
Verify the integrity of record values in a funk instance.
- **Description**: Use this function to ensure that all record values within a given funk instance are valid and consistent. It should be called when you need to verify the integrity of the data managed by the funk instance, typically as part of a broader verification process. The function assumes that the funk instance is non-NULL and that its workspace, record map, and workspace tag have been previously verified. It logs a warning and returns an error code if any inconsistencies are found in the record values.
- **Inputs**:
    - `funk`: A pointer to a fd_funk_t instance representing the funk whose record values are to be verified. Must not be NULL. The caller retains ownership and responsibility for ensuring the funk instance is valid and properly initialized.
- **Output**: Returns FD_FUNK_SUCCESS if all record values are valid, or FD_FUNK_ERR_INVAL if any inconsistencies are detected, with details logged as warnings.
- **See also**: [`fd_funk_val_verify`](fd_funk_val.c.driver.md#fd_funk_val_verify)  (Implementation)


