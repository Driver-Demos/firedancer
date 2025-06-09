# Purpose
This C header file, `fd_zksdk_batched_range_proofs.h`, is part of a cryptographic library focused on implementing batched range proofs, which are a type of zero-knowledge proof. The file defines data structures and functions necessary for handling range proofs for different bit lengths (64, 128, and 256 bits). These structures, such as `fd_zksdk_range_proof_u64_proof_t`, `fd_zksdk_range_proof_u128_proof_t`, and `fd_zksdk_range_proof_u256_proof_t`, encapsulate the components of a range proof, including the range proof itself, intermediate vector points, and scalar values. The header also defines a context structure, `fd_zksdk_batched_range_proof_context_t`, which holds commitments and bit lengths for a batch of proofs, facilitating the management of multiple proofs simultaneously.

The file provides inline functions for initializing and validating batched range proofs. The [`batched_range_proof_transcript_init`](#batched_range_proof_transcript_init) function initializes a cryptographic transcript with the context's commitments and bit lengths, while [`batched_range_proof_init_and_validate`](#batched_range_proof_init_and_validate) validates the context and determines the size of the batch by identifying the first all-zero commitment. This functionality is crucial for ensuring the integrity and correctness of the range proofs within the context of a larger cryptographic protocol. The header file is designed to be included in other C source files, providing a public API for managing batched range proofs in applications that require secure and efficient cryptographic operations.
# Imports and Dependencies

---
- `../../../../fd_flamenco_base.h`


# Data Structures

---
### fd\_zksdk\_range\_proof\_u64\_proof
- **Type**: `struct`
- **Members**:
    - `range_proof`: A field of type `fd_rangeproofs_range_proof_t` representing the range proof.
    - `ipp_lr_vec`: An array of 6 `fd_rangeproofs_ipp_vecs_t` elements representing log(bit_length) points.
    - `ipp_a`: A 32-byte unsigned character array representing a scalar.
    - `ipp_b`: A 32-byte unsigned character array representing a scalar.
- **Description**: The `fd_zksdk_range_proof_u64_proof` structure is a packed data structure used in zero-knowledge proofs to represent a range proof for 64-bit unsigned integers. It includes a range proof, an array of inner product proof vectors, and two scalar values. The structure is designed to efficiently store and process the necessary components for verifying that a value lies within a certain range without revealing the value itself.


---
### fd\_zksdk\_range\_proof\_u64\_proof\_t
- **Type**: `struct`
- **Members**:
    - `range_proof`: A field of type `fd_rangeproofs_range_proof_t` representing the range proof.
    - `ipp_lr_vec`: An array of 6 `fd_rangeproofs_ipp_vecs_t` elements representing log(bit_length) points.
    - `ipp_a`: A 32-byte array representing a scalar value.
    - `ipp_b`: A 32-byte array representing a scalar value.
- **Description**: The `fd_zksdk_range_proof_u64_proof_t` structure is a packed data structure used to represent a range proof for 64-bit unsigned integers. It includes a range proof field, an array of inner product proof vectors, and two scalar values. This structure is part of a zero-knowledge proof system, likely used in cryptographic applications to prove that a number lies within a certain range without revealing the number itself.


---
### fd\_zksdk\_range\_proof\_u128\_proof
- **Type**: `struct`
- **Members**:
    - `range_proof`: A field of type `fd_rangeproofs_range_proof_t` representing the range proof data.
    - `ipp_lr_vec`: An array of 7 elements of type `fd_rangeproofs_ipp_vecs_t`, representing log(bit_length) points.
    - `ipp_a`: A 32-byte unsigned character array representing a scalar value.
    - `ipp_b`: A 32-byte unsigned character array representing another scalar value.
- **Description**: The `fd_zksdk_range_proof_u128_proof` structure is a packed data structure used in zero-knowledge proofs to represent a range proof for 128-bit values. It includes a range proof field, an array of inner product proof vectors, and two scalar values, all of which are essential components for verifying the validity of the range proof in cryptographic protocols.


---
### fd\_zksdk\_range\_proof\_u128\_proof\_t
- **Type**: `struct`
- **Members**:
    - `range_proof`: A field of type `fd_rangeproofs_range_proof_t` representing the range proof.
    - `ipp_lr_vec`: An array of 7 `fd_rangeproofs_ipp_vecs_t` elements representing log(bit_length) points.
    - `ipp_a`: A 32-byte array representing a scalar value.
    - `ipp_b`: A 32-byte array representing another scalar value.
- **Description**: The `fd_zksdk_range_proof_u128_proof_t` structure is a packed data structure used to represent a range proof for 128-bit values. It includes a range proof field, an array of inner product proof vectors, and two scalar values. This structure is part of a zero-knowledge proof system, specifically designed to handle 128-bit range proofs, and is used in cryptographic protocols to prove that a secret value lies within a certain range without revealing the value itself.


---
### fd\_zksdk\_range\_proof\_u256\_proof
- **Type**: `struct`
- **Members**:
    - `range_proof`: A field of type `fd_rangeproofs_range_proof_t` representing the range proof.
    - `ipp_lr_vec`: An array of 8 `fd_rangeproofs_ipp_vecs_t` elements representing log(bit_length) points.
    - `ipp_a`: A 32-byte array representing a scalar value.
    - `ipp_b`: A 32-byte array representing another scalar value.
- **Description**: The `fd_zksdk_range_proof_u256_proof` structure is a packed data structure used in zero-knowledge proofs to represent a range proof for 256-bit values. It includes a range proof field, an array of inner product proof vectors, and two scalar values. This structure is part of a system designed to verify that a number lies within a certain range without revealing the number itself, leveraging cryptographic techniques to ensure privacy and security.


---
### fd\_zksdk\_range\_proof\_u256\_proof\_t
- **Type**: `struct`
- **Members**:
    - `range_proof`: A field of type `fd_rangeproofs_range_proof_t` representing the range proof.
    - `ipp_lr_vec`: An array of 8 `fd_rangeproofs_ipp_vecs_t` elements representing log(bit_length) points.
    - `ipp_a`: A 32-byte array representing a scalar value.
    - `ipp_b`: A 32-byte array representing another scalar value.
- **Description**: The `fd_zksdk_range_proof_u256_proof_t` structure is a packed data structure used to represent a range proof for 256-bit values. It includes a range proof field, an array of inner product proof vectors, and two scalar values. This structure is part of a zero-knowledge proof system, specifically designed to handle 256-bit range proofs, ensuring that a value lies within a certain range without revealing the value itself.


---
### fd\_zksdk\_batched\_range\_proof\_context
- **Type**: `struct`
- **Members**:
    - `commitments`: An array of uchar storing commitment points, with a maximum size defined by FD_ZKSDK_MAX_COMMITMENTS times 32.
    - `bit_lengths`: An array of uchar storing bit lengths, with a maximum size defined by FD_ZKSDK_MAX_COMMITMENTS.
- **Description**: The `fd_zksdk_batched_range_proof_context` structure is designed to hold data necessary for batched range proofs in zero-knowledge proof systems. It contains two main components: `commitments`, which is an array of commitment points, and `bit_lengths`, which stores the bit lengths associated with each commitment. The structure is packed to ensure efficient memory usage and is used in conjunction with functions that initialize and validate range proof contexts, facilitating the verification of proofs in a batched manner.


---
### fd\_zksdk\_batched\_range\_proof\_context\_t
- **Type**: `struct`
- **Members**:
    - `commitments`: An array of points, each 32 bytes long, with a maximum size defined by FD_ZKSDK_MAX_COMMITMENTS.
    - `bit_lengths`: An array of bit lengths corresponding to each commitment, with a maximum size defined by FD_ZKSDK_MAX_COMMITMENTS.
- **Description**: The `fd_zksdk_batched_range_proof_context_t` structure is designed to hold data necessary for batched range proofs in zero-knowledge proofs (ZKP). It contains arrays for commitments and their corresponding bit lengths, allowing for efficient handling of multiple proofs in a single batch. The structure is packed to ensure memory efficiency and is used in conjunction with functions that initialize and validate the proof context, ensuring compatibility with external systems like Agave.


# Functions

---
### batched\_range\_proof\_transcript\_init<!-- {{#callable:batched_range_proof_transcript_init}} -->
The function `batched_range_proof_transcript_init` initializes a transcript for a batched range proof by appending specific context data to it.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure that will be initialized and appended with messages.
    - `context`: A constant pointer to an `fd_zksdk_batched_range_proof_context_t` structure containing the commitments and bit lengths to be appended to the transcript.
- **Control Flow**:
    - Call `fd_zksdk_transcript_init` to initialize the transcript with a literal string 'batched-range-proof-instruction'.
    - Append the 'commitments' from the context to the transcript using `fd_merlin_transcript_append_message`.
    - Append the 'bit-lengths' from the context to the transcript using `fd_merlin_transcript_append_message`.
- **Output**: The function does not return a value; it modifies the `transcript` in place.


---
### batched\_range\_proof\_init\_and\_validate<!-- {{#callable:batched_range_proof_init_and_validate}} -->
The function `batched_range_proof_init_and_validate` initializes and validates a batched range proof by determining the length of valid commitments and initializing a transcript.
- **Inputs**:
    - `len`: A pointer to an unsigned char where the function will store the length of valid commitments.
    - `context`: A constant pointer to a `fd_zksdk_batched_range_proof_context_t` structure containing the commitments and bit lengths for the range proof.
    - `transcript`: A pointer to a `fd_zksdk_transcript_t` structure that will be initialized with the context data.
- **Control Flow**:
    - Initialize a loop counter `i` to 0.
    - Iterate over the maximum number of commitments defined by `FD_ZKSDK_MAX_COMMITMENTS`.
    - For each commitment, check if it is equal to a zeroed commitment using `fd_memeq`.
    - If a zeroed commitment is found, break the loop.
    - Store the current value of `i` in `len`, representing the number of valid commitments.
    - Call [`batched_range_proof_transcript_init`](#batched_range_proof_transcript_init) to initialize the transcript with the context data.
    - Return `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful execution.
- **Output**: The function returns an integer `FD_EXECUTOR_INSTR_SUCCESS` to indicate successful initialization and validation, and it updates `len` with the number of valid commitments.
- **Functions called**:
    - [`batched_range_proof_transcript_init`](#batched_range_proof_transcript_init)


