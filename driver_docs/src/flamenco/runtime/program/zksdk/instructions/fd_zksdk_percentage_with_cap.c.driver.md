# Purpose
This C source code file is part of a cryptographic library, specifically dealing with zero-knowledge proofs related to percentage calculations with a cap. The file provides functionality to verify cryptographic proofs that ensure certain properties about percentage values without revealing the actual values themselves. The main components of the code include functions for initializing a cryptographic transcript and verifying a proof related to percentage calculations with a cap. The [`percentage_with_cap_transcript_init`](#percentage_with_cap_transcript_init) function initializes a transcript with specific commitments and a maximum value, while the [`fd_zksdk_verify_proof_percentage_with_cap`](#fd_zksdk_verify_proof_percentage_with_cap) function performs the actual verification of the proof by validating inputs, computing necessary scalars, and performing a multi-scalar multiplication to ensure the proof's validity.

The code is designed to be part of a larger cryptographic system, likely used in privacy-preserving applications where zero-knowledge proofs are essential. It does not define a public API but rather provides internal functionality that can be used by other components of the system. The file includes references to external cryptographic functions and data structures, such as `fd_ristretto255_point_t` and `fd_curve25519_scalar_validate`, indicating its reliance on specific cryptographic primitives. The code is structured to ensure that the proof verification process is both efficient and secure, leveraging inline functions and careful validation of cryptographic elements.
# Imports and Dependencies

---
- `../fd_zksdk_private.h`


# Functions

---
### percentage\_with\_cap\_transcript\_init<!-- {{#callable:percentage_with_cap_transcript_init}} -->
The function `percentage_with_cap_transcript_init` initializes a transcript for a percentage-with-cap instruction by appending various commitments and a maximum value from the given context.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure that will be initialized and modified by the function.
    - `context`: A pointer to a constant `fd_zksdk_percentage_with_cap_context_t` structure containing the commitments and maximum value to be appended to the transcript.
- **Control Flow**:
    - Call `fd_zksdk_transcript_init` to initialize the transcript with a literal string 'percentage-with-cap-instruction'.
    - Append the 'percentage-commitment' from the context to the transcript using `fd_zksdk_transcript_append_commitment`.
    - Append the 'delta-commitment' from the context to the transcript using `fd_zksdk_transcript_append_commitment`.
    - Append the 'claimed-commitment' from the context to the transcript using `fd_zksdk_transcript_append_commitment`.
    - Append the 'max-value' from the context to the transcript using `fd_merlin_transcript_append_u64`.
- **Output**: The function does not return a value; it modifies the `transcript` in place.


---
### fd\_zksdk\_verify\_proof\_percentage\_with\_cap<!-- {{#callable:fd_zksdk_verify_proof_percentage_with_cap}} -->
The function `fd_zksdk_verify_proof_percentage_with_cap` verifies a zero-knowledge proof for a percentage with a cap using cryptographic commitments and a transcript.
- **Inputs**:
    - `proof`: A pointer to a `fd_zksdk_percentage_with_cap_proof_t` structure containing the proof data to be verified.
    - `percentage_commitment`: A 32-byte array representing the percentage commitment.
    - `delta_commitment`: A 32-byte array representing the delta commitment.
    - `claimed_commitment`: A 32-byte array representing the claimed commitment.
    - `max_value`: An unsigned long integer representing the maximum value for the percentage cap.
    - `transcript`: A pointer to a `fd_zksdk_transcript_t` structure used for managing the cryptographic transcript during verification.
- **Control Flow**:
    - Initialize arrays for scalars and points, and validate the scalar values in the proof using `fd_curve25519_scalar_validate`.
    - Set base points G and H, and decompress the commitments and proof points into the `points` array using `fd_ristretto255_point_decompress`.
    - Initialize the transcript with domain separation and append proof points to it, checking for success.
    - Generate challenge scalars `c` and `w` from the transcript, and compute `ww` as the square of `w`.
    - Calculate the scalar `m` from `max_value` and compute `c_eq` as the difference between `c` and `c_max`.
    - Compute the scalars for the multi-scalar multiplication (MSM) using the given formulas, involving operations like multiplication, addition, and subtraction of scalars.
    - Perform the MSM with the computed scalars and points, storing the result in `res`.
    - Check if the resulting point `res` is equal to the decompressed `y` point, returning success if they match, otherwise returning an error.
- **Output**: Returns `FD_EXECUTOR_INSTR_SUCCESS` if the proof is successfully verified, otherwise returns `FD_ZKSDK_VERIFY_PROOF_ERROR`.


---
### fd\_zksdk\_instr\_verify\_proof\_percentage\_with\_cap<!-- {{#callable:fd_zksdk_instr_verify_proof_percentage_with_cap}} -->
The function `fd_zksdk_instr_verify_proof_percentage_with_cap` initializes a transcript and verifies a proof against a percentage with cap context.
- **Inputs**:
    - `_context`: A pointer to a `fd_zksdk_percentage_with_cap_context_t` structure containing the context for the proof verification, including commitments and a maximum value.
    - `_proof`: A pointer to a `fd_zksdk_percentage_with_cap_proof_t` structure containing the proof data to be verified.
- **Control Flow**:
    - Initialize a `fd_zksdk_transcript_t` object to store the transcript data.
    - Cast the `_context` pointer to a `fd_zksdk_percentage_with_cap_context_t` pointer to access the context data.
    - Cast the `_proof` pointer to a `fd_zksdk_percentage_with_cap_proof_t` pointer to access the proof data.
    - Call [`percentage_with_cap_transcript_init`](#percentage_with_cap_transcript_init) to initialize the transcript with the context data.
    - Call [`fd_zksdk_verify_proof_percentage_with_cap`](#fd_zksdk_verify_proof_percentage_with_cap) with the proof, context commitments, maximum value, and the initialized transcript to verify the proof.
    - Return the result of the proof verification.
- **Output**: Returns an integer indicating the success or failure of the proof verification, where a specific success or error code is returned based on the verification result.
- **Functions called**:
    - [`percentage_with_cap_transcript_init`](#percentage_with_cap_transcript_init)
    - [`fd_zksdk_verify_proof_percentage_with_cap`](#fd_zksdk_verify_proof_percentage_with_cap)


