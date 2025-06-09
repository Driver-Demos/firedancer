# Purpose
This C source code file implements the Poseidon cryptographic hash function, which is designed for use in zero-knowledge proofs and other cryptographic applications. The file provides both the internal mechanics and the public interface for the Poseidon hash function. The internal functions, such as [`fd_poseidon_apply_ark`](#fd_poseidon_apply_ark), [`fd_poseidon_apply_sbox_full`](#fd_poseidon_apply_sbox_full), [`fd_poseidon_apply_sbox_partial`](#fd_poseidon_apply_sbox_partial), and [`fd_poseidon_apply_mds`](#fd_poseidon_apply_mds), are responsible for the core operations of the Poseidon algorithm, including the application of the round constants (ark), the S-box transformations, and the matrix multiplication (MDS). These operations are essential for the cryptographic strength and permutation properties of the Poseidon hash function.

The public interface consists of functions like [`fd_poseidon_init`](#fd_poseidon_init), [`fd_poseidon_append`](#fd_poseidon_append), and [`fd_poseidon_fini`](#fd_poseidon_fini), which manage the lifecycle of a Poseidon hash computation. [`fd_poseidon_init`](#fd_poseidon_init) initializes the hash state, [`fd_poseidon_append`](#fd_poseidon_append) allows data to be added to the hash computation, and [`fd_poseidon_fini`](#fd_poseidon_fini) finalizes the hash computation and produces the hash output. The code is structured to handle different input widths and endianness, ensuring flexibility and compatibility with various systems. The file also includes mechanisms for parameter retrieval, ensuring that the correct constants and matrices are used for different input sizes. Overall, this file provides a comprehensive implementation of the Poseidon hash function, suitable for integration into larger cryptographic systems.
# Imports and Dependencies

---
- `./fd_poseidon.h`
- `fd_poseidon_params.c`


# Functions

---
### fd\_poseidon\_apply\_ark<!-- {{#callable:fd_poseidon_apply_ark}} -->
The `fd_poseidon_apply_ark` function adds round-specific constants to each element of the state array in a Poseidon hash function.
- **Inputs**:
    - `state`: An array of `fd_bn254_scalar_t` representing the current state of the Poseidon hash.
    - `width`: An unsigned long integer representing the number of elements in the state array.
    - `params`: A pointer to a `fd_poseidon_par_t` structure containing the Poseidon parameters, including the round constants.
    - `round`: An unsigned long integer representing the current round number in the Poseidon hash function.
- **Control Flow**:
    - Iterates over each element of the state array from index 0 to `width-1`.
    - For each element, adds the corresponding round constant from `params->ark` to the state element using `fd_bn254_scalar_add`.
- **Output**: The function does not return a value; it modifies the `state` array in place.


---
### fd\_poseidon\_apply\_sbox\_full<!-- {{#callable:fd_poseidon_apply_sbox_full}} -->
The `fd_poseidon_apply_sbox_full` function applies a non-linear transformation to each element of a state array by raising each element to the power of five.
- **Inputs**:
    - `state`: An array of `fd_bn254_scalar_t` elements representing the state to be transformed.
    - `width`: An unsigned long integer representing the number of elements in the state array to be processed.
- **Control Flow**:
    - Iterates over each element in the state array up to the specified width.
    - For each element, computes its square and stores it in a temporary variable `t`.
    - Squares the temporary variable `t` again to get the fourth power of the original element.
    - Multiplies the original element by the fourth power stored in `t` to compute the fifth power, updating the element in the state array.
- **Output**: The function modifies the input `state` array in place, with each element raised to the power of five.


---
### fd\_poseidon\_apply\_sbox\_partial<!-- {{#callable:fd_poseidon_apply_sbox_partial}} -->
The `fd_poseidon_apply_sbox_partial` function applies a partial S-box transformation to the first element of the state array by raising it to the power of 5.
- **Inputs**:
    - `state`: An array of `fd_bn254_scalar_t` representing the state of the Poseidon hash function.
- **Control Flow**:
    - The function calls [`fd_poseidon_apply_sbox_full`](#fd_poseidon_apply_sbox_full) with the `state` array and a width of 1, which applies the S-box transformation to the first element of the state array.
    - The S-box transformation involves raising the first element of the state array to the power of 5.
- **Output**: The function does not return a value; it modifies the first element of the `state` array in place.
- **Functions called**:
    - [`fd_poseidon_apply_sbox_full`](#fd_poseidon_apply_sbox_full)


---
### fd\_poseidon\_apply\_mds<!-- {{#callable:fd_poseidon_apply_mds}} -->
The `fd_poseidon_apply_mds` function performs a vector-matrix multiplication between a state vector and an MDS matrix, updating the state vector with the result.
- **Inputs**:
    - `state`: An array of `fd_bn254_scalar_t` representing the state vector to be transformed.
    - `width`: An unsigned long integer representing the width of the state vector and MDS matrix.
    - `params`: A pointer to a `fd_poseidon_par_t` structure containing the MDS matrix used for the transformation.
- **Control Flow**:
    - Initialize a temporary array `x` to store intermediate results, with all elements set to zero.
    - Iterate over each element `i` of the state vector, from 0 to `width-1`.
    - For each element `i`, iterate over each element `j` of the state vector, from 0 to `width-1`.
    - Multiply the `j`-th element of the state vector by the corresponding element in the MDS matrix, storing the result in a temporary variable `t`.
    - Add the value of `t` to the `i`-th element of the temporary array `x`.
    - After completing the inner loop, assign the `i`-th element of `x` to the `i`-th element of the state vector.
- **Output**: The function updates the `state` array in place with the result of the vector-matrix multiplication.


---
### fd\_poseidon\_get\_params<!-- {{#callable:fd_poseidon_get_params}} -->
The `fd_poseidon_get_params` function assigns the appropriate Ark and MDS matrices to a `fd_poseidon_par_t` structure based on the specified width.
- **Inputs**:
    - `params`: A pointer to a `fd_poseidon_par_t` structure where the Ark and MDS matrices will be stored.
    - `width`: An unsigned long integer representing the width for which the parameters are to be retrieved.
- **Control Flow**:
    - The function uses a switch statement to determine the appropriate case based on the `width` value.
    - For each case, the macro `FD_POSEIDON_GET_PARAMS(w)` is invoked, which assigns the Ark and MDS matrices corresponding to the width `w` to the `params` structure.
    - The macro is defined to handle widths from 2 to 13, inclusive.
    - If the `width` does not match any of the defined cases, no action is taken.
- **Output**: The function does not return a value; it modifies the `params` structure in place.


---
### fd\_poseidon\_init<!-- {{#callable:fd_poseidon_init}} -->
The `fd_poseidon_init` function initializes a `fd_poseidon_t` structure with specified endianness and resets its state.
- **Inputs**:
    - `pos`: A pointer to a `fd_poseidon_t` structure that needs to be initialized.
    - `big_endian`: An integer indicating whether the data should be treated as big-endian (non-zero) or little-endian (zero).
- **Control Flow**:
    - Check if the `pos` pointer is NULL; if so, return NULL.
    - Set the `big_endian` field of the `pos` structure to the provided `big_endian` value.
    - Initialize the `cnt` field of the `pos` structure to 0.
    - Clear the `state` array of the `pos` structure using `fd_memset` to set all bytes to zero.
    - Return the initialized `pos` structure.
- **Output**: Returns the initialized `fd_poseidon_t` structure, or NULL if the input pointer `pos` is NULL.


---
### fd\_poseidon\_append<!-- {{#callable:fd_poseidon_append}} -->
The `fd_poseidon_append` function appends a data element to a Poseidon hash state, handling endianness and validating the input.
- **Inputs**:
    - `pos`: A pointer to an `fd_poseidon_t` structure representing the current state of the Poseidon hash.
    - `data`: A pointer to an array of unsigned characters representing the data to be appended.
    - `sz`: An unsigned long integer representing the size of the data to be appended, which must be between 1 and 32 bytes.
- **Control Flow**:
    - Check if the `pos` pointer is NULL and return NULL if true.
    - Check if the current count of elements in `pos` is greater than or equal to `FD_POSEIDON_MAX_WIDTH` and return NULL if true.
    - Check if the size `sz` is 0 or greater than 32 and return NULL if true.
    - Initialize a `fd_bn254_scalar_t` structure `cur` to zero.
    - Copy the input data into `cur`, adjusting for endianness if necessary.
    - If the data is in big-endian format, swap the byte order of `cur`.
    - Validate the `cur` scalar and return NULL if validation fails.
    - Increment the element count in `pos`.
    - Convert `cur` to Montgomery form and store it in the `state` array of `pos`.
    - Return the updated `pos` pointer.
- **Output**: Returns a pointer to the updated `fd_poseidon_t` structure, or NULL if an error occurs.


---
### fd\_poseidon\_fini<!-- {{#callable:fd_poseidon_fini}} -->
The `fd_poseidon_fini` function finalizes the Poseidon hash computation by applying a series of cryptographic transformations to the state and outputs the resulting hash.
- **Inputs**:
    - `pos`: A pointer to an `fd_poseidon_t` structure representing the current state of the Poseidon hash computation.
    - `hash`: An array of unsigned characters where the resulting hash will be stored; it must be aligned to `FD_UINT256_ALIGNED`.
- **Control Flow**:
    - Check if the `pos` pointer is NULL or if `pos->cnt` is zero, returning NULL if either condition is true.
    - Calculate the `width` as `pos->cnt + 1` and initialize Poseidon parameters using [`fd_poseidon_get_params`](#fd_poseidon_get_params).
    - Verify that the parameters `ark` and `mds` are valid, returning NULL if not.
    - Determine the number of partial rounds from a predefined array based on `pos->cnt`.
    - Perform a series of cryptographic transformations over three phases: half full rounds, partial rounds, and remaining full rounds, using functions [`fd_poseidon_apply_ark`](#fd_poseidon_apply_ark), [`fd_poseidon_apply_sbox_full`](#fd_poseidon_apply_sbox_full), [`fd_poseidon_apply_sbox_partial`](#fd_poseidon_apply_sbox_partial), and [`fd_poseidon_apply_mds`](#fd_poseidon_apply_mds).
    - Convert the first element of the state from Montgomery form to a scalar hash.
    - If `pos->big_endian` is true, swap the byte order of the scalar hash.
    - Copy the scalar hash to the `hash` output buffer.
- **Output**: The function returns a pointer to the `hash` array containing the final Poseidon hash, or NULL if an error occurs during processing.
- **Functions called**:
    - [`fd_poseidon_get_params`](#fd_poseidon_get_params)
    - [`fd_poseidon_apply_ark`](#fd_poseidon_apply_ark)
    - [`fd_poseidon_apply_sbox_full`](#fd_poseidon_apply_sbox_full)
    - [`fd_poseidon_apply_mds`](#fd_poseidon_apply_mds)
    - [`fd_poseidon_apply_sbox_partial`](#fd_poseidon_apply_sbox_partial)


