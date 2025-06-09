# Purpose
This C header file defines data structures and functions related to the verification of batched grouped ciphertext validity proofs, specifically within the context of zero-knowledge proofs (ZKPs). The file provides a set of packed structures that represent proofs and contexts for grouped ciphertexts with either two or three handles. These structures include arrays of unsigned characters (uchar) to store cryptographic points and scalars, which are essential components in cryptographic operations. The file also defines typedefs for these structures to facilitate their use in other parts of the program.

The header file includes two primary functions: [`fd_zksdk_verify_proof_batched_grouped_ciphertext_2_handles_validity`](#fd_zksdk_verify_proof_batched_grouped_ciphertext_2_handles_validity) and [`fd_zksdk_verify_proof_batched_grouped_ciphertext_3_handles_validity`](#fd_zksdk_verify_proof_batched_grouped_ciphertext_3_handles_validity). These functions are designed to verify the validity of proofs for grouped ciphertexts with two and three handles, respectively. They take as input the proof structure, public keys, commitments, handles, and a transcript, and they return an integer indicating the success or failure of the verification process. The inclusion of these functions suggests that the file is intended to be part of a larger cryptographic library or application, where it provides specific functionality for handling and verifying batched grouped ciphertext validity proofs in a zero-knowledge proof system.
# Imports and Dependencies

---
- `../../../../fd_flamenco_base.h`


# Data Structures

---
### fd\_zksdk\_grp\_ciph\_2h\_val\_proof
- **Type**: `struct`
- **Members**:
    - `y0`: An array of 32 unsigned characters representing a point.
    - `y1`: An array of 32 unsigned characters representing a point.
    - `y2`: An array of 32 unsigned characters representing a point.
    - `zr`: An array of 32 unsigned characters representing a scalar.
    - `zx`: An array of 32 unsigned characters representing a scalar.
- **Description**: The `fd_zksdk_grp_ciph_2h_val_proof` structure is a packed data structure used in zero-knowledge proofs for grouped ciphertext validity. It contains three 32-byte arrays (`y0`, `y1`, `y2`) that represent points, and two 32-byte arrays (`zr`, `zx`) that represent scalars. This structure is part of a cryptographic protocol to verify the validity of grouped ciphertexts with two handles, ensuring that the ciphertexts are correctly formed without revealing the underlying plaintext.


---
### fd\_zksdk\_grp\_ciph\_2h\_val\_proof\_t
- **Type**: `struct`
- **Members**:
    - `y0`: A 32-byte array representing a point.
    - `y1`: A 32-byte array representing a point.
    - `y2`: A 32-byte array representing a point.
    - `zr`: A 32-byte array representing a scalar.
    - `zx`: A 32-byte array representing a scalar.
- **Description**: The `fd_zksdk_grp_ciph_2h_val_proof_t` structure is a packed data structure used to represent a proof in the context of grouped ciphertext validity with two handles. It consists of three 32-byte arrays (`y0`, `y1`, `y2`) that represent points, and two 32-byte arrays (`zr`, `zx`) that represent scalars. This structure is part of a zero-knowledge proof system, likely used to verify the validity of grouped ciphertexts in cryptographic protocols.


---
### fd\_zksdk\_grp\_ciph\_3h\_val\_proof
- **Type**: `struct`
- **Members**:
    - `y0`: A 32-byte array representing a point.
    - `y1`: A 32-byte array representing a point.
    - `y2`: A 32-byte array representing a point.
    - `y3`: A 32-byte array representing a point.
    - `zr`: A 32-byte array representing a scalar.
    - `zx`: A 32-byte array representing a scalar.
- **Description**: The `fd_zksdk_grp_ciph_3h_val_proof` structure is a packed data structure used in zero-knowledge proofs for grouped ciphertext validity, specifically handling three points and two scalars. It contains four 32-byte arrays (`y0`, `y1`, `y2`, `y3`) representing points and two 32-byte arrays (`zr`, `zx`) representing scalars. This structure is part of a cryptographic protocol for verifying the validity of grouped ciphertexts with three handles, ensuring the integrity and confidentiality of the data involved.


---
### fd\_zksdk\_grp\_ciph\_3h\_val\_proof\_t
- **Type**: `struct`
- **Members**:
    - `y0`: A 32-byte array representing a point.
    - `y1`: A 32-byte array representing a point.
    - `y2`: A 32-byte array representing a point.
    - `y3`: A 32-byte array representing a point.
    - `zr`: A 32-byte array representing a scalar.
    - `zx`: A 32-byte array representing a scalar.
- **Description**: The `fd_zksdk_grp_ciph_3h_val_proof_t` structure is a packed data structure used in zero-knowledge proofs for grouped ciphertext validity with three handles. It contains four 32-byte arrays (`y0`, `y1`, `y2`, `y3`) representing points and two 32-byte arrays (`zr`, `zx`) representing scalars. This structure is part of a cryptographic protocol to verify the validity of grouped ciphertexts in a secure and efficient manner.


---
### grp\_ciph\_handle
- **Type**: `struct`
- **Members**:
    - `handle`: An array of 32 unsigned characters representing a point.
- **Description**: The `grp_ciph_handle` structure is a packed data structure that contains a single member, `handle`, which is an array of 32 unsigned characters. This array is used to represent a point, likely in the context of cryptographic operations. The structure is defined with the `packed` attribute to ensure that there is no padding between its members, which is important for maintaining a consistent memory layout, especially in cryptographic applications where precise control over data representation is crucial.


---
### grp\_ciph\_handle\_t
- **Type**: `struct`
- **Members**:
    - `handle`: A 32-byte array representing a point.
- **Description**: The `grp_ciph_handle_t` is a packed structure that contains a single member, `handle`, which is a 32-byte array. This structure is used to represent a cryptographic handle, likely a point on an elliptic curve or similar structure, within the context of grouped ciphertext validity proofs. It serves as a fundamental building block for more complex structures that handle multiple cryptographic points.


---
### grp\_ciph\_2h
- **Type**: `struct`
- **Members**:
    - `commitment`: An array of 32 unsigned characters representing a point.
    - `handles`: An array of two grp_ciph_handle_t structures, each representing a point.
- **Description**: The `grp_ciph_2h` structure is a packed data structure used to represent a grouped ciphertext with two handles. It contains a 32-byte commitment and an array of two handles, each of which is a 32-byte point. This structure is likely used in cryptographic contexts where grouped ciphertexts need to be validated or manipulated, particularly in zero-knowledge proof systems.


---
### grp\_ciph\_2h\_t
- **Type**: `struct`
- **Members**:
    - `commitment`: A 32-byte array representing a point.
    - `handles`: An array of two grp_ciph_handle_t structures, each representing a point.
- **Description**: The `grp_ciph_2h_t` structure is a packed data structure used to represent a grouped ciphertext with two handles. It contains a 32-byte commitment point and an array of two `grp_ciph_handle_t` structures, each of which is a 32-byte point. This structure is likely used in cryptographic contexts where grouped ciphertexts need to be validated or manipulated, particularly in zero-knowledge proof systems.


---
### grp\_ciph\_3h
- **Type**: `struct`
- **Members**:
    - `commitment`: An array of 32 unsigned characters representing a point.
    - `handles`: An array of 3 grp_ciph_handle_t structures, each representing a point.
- **Description**: The `grp_ciph_3h` structure is a packed data structure used to represent a grouped ciphertext with three handles. It contains a 32-byte commitment, which is a point, and an array of three `grp_ciph_handle_t` structures, each also representing a point. This structure is likely used in cryptographic contexts where multiple points need to be handled together, such as in zero-knowledge proofs or encryption schemes.


---
### grp\_ciph\_3h\_t
- **Type**: `struct`
- **Members**:
    - `commitment`: A 32-byte array representing a point, used as a commitment.
    - `handles`: An array of three grp_ciph_handle_t structures, each representing a point.
- **Description**: The `grp_ciph_3h_t` structure is a packed data structure used to represent a grouped ciphertext with three handles. It contains a 32-byte commitment point and an array of three `grp_ciph_handle_t` structures, each of which is a 32-byte point. This structure is likely used in cryptographic contexts where multiple handles are associated with a single commitment, facilitating operations such as zero-knowledge proofs or secure multi-party computations.


---
### fd\_zksdk\_grp\_ciph\_2h\_val\_context
- **Type**: `struct`
- **Members**:
    - `pubkey1`: An array of 32 unsigned characters representing a point.
    - `pubkey2`: An array of 32 unsigned characters representing a point.
    - `grouped_ciphertext`: A grp_ciph_2h_t structure representing grouped ciphertext with 3 points.
- **Description**: The `fd_zksdk_grp_ciph_2h_val_context` structure is a packed data structure used in the context of zero-knowledge proofs for grouped ciphertext validity. It contains two public keys, each represented as a 32-byte array, and a `grp_ciph_2h_t` structure that holds the grouped ciphertext, which consists of a commitment and two handles, each represented as points. This structure is part of a cryptographic protocol for verifying the validity of grouped ciphertexts with two handles.


---
### fd\_zksdk\_grp\_ciph\_2h\_val\_context\_t
- **Type**: `struct`
- **Members**:
    - `pubkey1`: A 32-byte array representing a public key point.
    - `pubkey2`: A 32-byte array representing a second public key point.
    - `grouped_ciphertext`: A `grp_ciph_2h_t` structure containing a commitment and two handle points.
- **Description**: The `fd_zksdk_grp_ciph_2h_val_context_t` structure is designed to hold cryptographic context information for validating grouped ciphertexts with two handles. It includes two public key points and a `grp_ciph_2h_t` structure, which itself contains a commitment and two handle points, facilitating the verification of cryptographic proofs in zero-knowledge protocols.


---
### fd\_zksdk\_batched\_grp\_ciph\_2h\_val\_context
- **Type**: `struct`
- **Members**:
    - `pubkey1`: An array of 32 unsigned characters representing a point, likely a public key.
    - `pubkey2`: An array of 32 unsigned characters representing a point, likely a second public key.
    - `grouped_ciphertext_lo`: A structure of type grp_ciph_2h_t representing a grouped ciphertext with lower handles, consisting of 3 points.
    - `grouped_ciphertext_hi`: A structure of type grp_ciph_2h_t representing a grouped ciphertext with higher handles, consisting of 3 points.
- **Description**: The `fd_zksdk_batched_grp_ciph_2h_val_context` structure is a packed data structure used in the context of batched grouped ciphertext validity proofs. It contains two public keys and two grouped ciphertexts, each represented by the `grp_ciph_2h_t` type, which includes a commitment and two handles. This structure is likely used in cryptographic operations where multiple ciphertexts are validated together, leveraging the public keys and the grouped ciphertexts for verification purposes.


---
### fd\_zksdk\_batched\_grp\_ciph\_2h\_val\_context\_t
- **Type**: `struct`
- **Members**:
    - `pubkey1`: A 32-byte array representing a public key point.
    - `pubkey2`: A 32-byte array representing a second public key point.
    - `grouped_ciphertext_lo`: A `grp_ciph_2h_t` structure representing the lower grouped ciphertext with two handles.
    - `grouped_ciphertext_hi`: A `grp_ciph_2h_t` structure representing the higher grouped ciphertext with two handles.
- **Description**: The `fd_zksdk_batched_grp_ciph_2h_val_context_t` structure is designed to hold context information for verifying the validity of batched grouped ciphertexts with two handles. It includes two public key points and two `grp_ciph_2h_t` structures, which represent the lower and higher grouped ciphertexts, each containing a commitment and two handle points. This structure is used in cryptographic operations to ensure the integrity and validity of grouped ciphertexts in a batched manner.


---
### fd\_zksdk\_grp\_ciph\_3h\_val\_context
- **Type**: `struct`
- **Members**:
    - `pubkey1`: An array of 32 unsigned characters representing a point.
    - `pubkey2`: An array of 32 unsigned characters representing a point.
    - `pubkey3`: An array of 32 unsigned characters representing a point.
    - `grouped_ciphertext`: A grp_ciph_3h_t structure representing grouped ciphertext with 4 points.
- **Description**: The `fd_zksdk_grp_ciph_3h_val_context` structure is a packed data structure used in the context of zero-knowledge proofs for grouped ciphertext validity. It contains three public keys, each represented as a 32-byte array, and a `grp_ciph_3h_t` structure that holds the grouped ciphertext, which consists of four points. This structure is part of a cryptographic protocol implementation, likely used to verify the validity of ciphertexts in a secure and efficient manner.


---
### fd\_zksdk\_grp\_ciph\_3h\_val\_context\_t
- **Type**: `struct`
- **Members**:
    - `pubkey1`: A 32-byte array representing the first public key point.
    - `pubkey2`: A 32-byte array representing the second public key point.
    - `pubkey3`: A 32-byte array representing the third public key point.
    - `grouped_ciphertext`: A `grp_ciph_3h_t` structure representing the grouped ciphertext with 4 points.
- **Description**: The `fd_zksdk_grp_ciph_3h_val_context_t` structure is designed to hold the context for verifying the validity of grouped ciphertexts with three handles. It includes three public key points and a `grp_ciph_3h_t` structure that encapsulates the grouped ciphertext, which is used in cryptographic proofs to ensure the integrity and validity of the ciphertexts in a zero-knowledge setting.


---
### fd\_zksdk\_batched\_grp\_ciph\_3h\_val\_context
- **Type**: `struct`
- **Members**:
    - `pubkey1`: An array of 32 unsigned characters representing a point.
    - `pubkey2`: An array of 32 unsigned characters representing a point.
    - `pubkey3`: An array of 32 unsigned characters representing a point.
    - `grouped_ciphertext_lo`: A grp_ciph_3h_t structure representing a lower grouped ciphertext with 4 points.
    - `grouped_ciphertext_hi`: A grp_ciph_3h_t structure representing a higher grouped ciphertext with 4 points.
- **Description**: The `fd_zksdk_batched_grp_ciph_3h_val_context` structure is a packed data structure used in the context of batched grouped ciphertext validity proofs. It contains three public keys, each represented as a 32-byte array, and two grouped ciphertexts, each represented by a `grp_ciph_3h_t` structure, which includes multiple points. This structure is likely used in cryptographic operations where multiple ciphertexts are validated together, leveraging the public keys and grouped ciphertexts for proof verification.


---
### fd\_zksdk\_batched\_grp\_ciph\_3h\_val\_context\_t
- **Type**: `struct`
- **Members**:
    - `pubkey1`: A 32-byte array representing the first public key point.
    - `pubkey2`: A 32-byte array representing the second public key point.
    - `pubkey3`: A 32-byte array representing the third public key point.
    - `grouped_ciphertext_lo`: A grp_ciph_3h_t structure representing the lower grouped ciphertext with 4 points.
    - `grouped_ciphertext_hi`: A grp_ciph_3h_t structure representing the higher grouped ciphertext with 4 points.
- **Description**: The `fd_zksdk_batched_grp_ciph_3h_val_context_t` structure is designed to hold the context for verifying the validity of batched grouped ciphertexts with three handles. It includes three public key points and two `grp_ciph_3h_t` structures, each containing a commitment and three handle points, representing the lower and higher grouped ciphertexts. This structure is used in cryptographic proofs to ensure the integrity and validity of the ciphertexts in a batched manner.


# Function Declarations (Public API)

---
### fd\_zksdk\_verify\_proof\_batched\_grouped\_ciphertext\_2\_handles\_validity<!-- {{#callable_declaration:fd_zksdk_verify_proof_batched_grouped_ciphertext_2_handles_validity}} -->
Verify the validity of a batched grouped ciphertext proof with two handles.
- **Description**: This function checks the validity of a zero-knowledge proof for a batched grouped ciphertext with two handles. It should be used when you need to verify that the provided proof correctly demonstrates the equivalence of certain cryptographic commitments and public keys. The function requires a valid proof structure, public keys, commitments, and handles as inputs. It supports both batched and non-batched modes, which affects how the commitments and handles are processed. The function must be called with a properly initialized transcript, and it will update the transcript as part of the verification process. If the second public key is zero, the corresponding proof and handles must also be zero. The function returns an integer indicating success or failure of the verification.
- **Inputs**:
    - `proof`: A pointer to a constant fd_zksdk_grp_ciph_2h_val_proof_t structure containing the proof data. Must not be null.
    - `pubkey1`: A 32-byte array representing the first public key. Must be a valid compressed point.
    - `pubkey2`: A 32-byte array representing the second public key. Must be a valid compressed point or all zeros if not used.
    - `comm`: A 32-byte array representing the commitment. Must be a valid compressed point.
    - `handle1`: A 32-byte array representing the first handle. Must be a valid compressed point.
    - `handle2`: A 32-byte array representing the second handle. Must be a valid compressed point or all zeros if pubkey2 is zero.
    - `comm_hi`: A 32-byte array representing the high commitment for batched mode. Must be a valid compressed point if batched is true.
    - `handle1_hi`: A 32-byte array representing the high first handle for batched mode. Must be a valid compressed point if batched is true.
    - `handle2_hi`: A 32-byte array representing the high second handle for batched mode. Must be a valid compressed point if batched is true and pubkey2 is not zero.
    - `batched`: A boolean indicating whether the proof is in batched mode. Affects how commitments and handles are processed.
    - `transcript`: A pointer to an fd_zksdk_transcript_t structure used for maintaining the cryptographic transcript. Must be initialized before calling and will be updated by the function.
- **Output**: Returns an integer indicating the success or failure of the proof verification. A specific success or error code is returned based on the verification result.
- **See also**: [`fd_zksdk_verify_proof_batched_grouped_ciphertext_2_handles_validity`](fd_zksdk_batched_grouped_ciphertext_2_handles_validity.c.driver.md#fd_zksdk_verify_proof_batched_grouped_ciphertext_2_handles_validity)  (Implementation)


---
### fd\_zksdk\_verify\_proof\_batched\_grouped\_ciphertext\_3\_handles\_validity<!-- {{#callable_declaration:fd_zksdk_verify_proof_batched_grouped_ciphertext_3_handles_validity}} -->
Verify the validity of a batched grouped ciphertext proof with three handles.
- **Description**: This function checks the validity of a zero-knowledge proof for a batched grouped ciphertext with three handles. It should be used when you need to verify that a given proof correctly demonstrates the validity of the ciphertexts under the provided public keys and handles. The function requires a proof structure, three public keys, a commitment, and three handles, with optional high-order terms if batched mode is enabled. The transcript is used to maintain the proof's context and must be initialized before calling this function. The function returns an integer indicating success or failure of the verification.
- **Inputs**:
    - `proof`: A pointer to a constant fd_zksdk_grp_ciph_3h_val_proof_t structure containing the proof data. Must not be null.
    - `pubkey1`: A 32-byte array representing the first public key. Must not be null.
    - `pubkey2`: A 32-byte array representing the second public key. Must not be null.
    - `pubkey3`: A 32-byte array representing the third public key. Must not be null.
    - `comm`: A 32-byte array representing the commitment. Must not be null.
    - `handle1`: A 32-byte array representing the first handle. Must not be null.
    - `handle2`: A 32-byte array representing the second handle. Must not be null.
    - `handle3`: A 32-byte array representing the third handle. Must not be null.
    - `comm_hi`: A 32-byte array representing the high-order term of the commitment, used only if batched is true. Can be null if batched is false.
    - `handle1_hi`: A 32-byte array representing the high-order term of the first handle, used only if batched is true. Can be null if batched is false.
    - `handle2_hi`: A 32-byte array representing the high-order term of the second handle, used only if batched is true. Can be null if batched is false.
    - `handle3_hi`: A 32-byte array representing the high-order term of the third handle, used only if batched is true. Can be null if batched is false.
    - `batched`: A boolean indicating whether the proof is batched. If true, high-order terms are used.
    - `transcript`: A pointer to an fd_zksdk_transcript_t structure used to maintain the proof's context. Must be initialized before calling this function.
- **Output**: Returns an integer indicating the success or failure of the proof verification. A specific success or error code is returned.
- **See also**: [`fd_zksdk_verify_proof_batched_grouped_ciphertext_3_handles_validity`](fd_zksdk_batched_grouped_ciphertext_3_handles_validity.c.driver.md#fd_zksdk_verify_proof_batched_grouped_ciphertext_3_handles_validity)  (Implementation)


