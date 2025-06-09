# Purpose
This C header file defines data structures and a function prototype for verifying the equality between a ciphertext and a commitment in a zero-knowledge proof context. It includes two packed structures: `fd_zksdk_ciph_comm_eq_proof`, which holds proof data including points and scalars, and `fd_zksdk_ciph_comm_eq_context`, which contains the public key, ciphertext, and commitment, all represented as byte arrays. The function [`fd_zksdk_verify_proof_ciphertext_commitment_equality`](#fd_zksdk_verify_proof_ciphertext_commitment_equality) is declared to verify the proof of equality between the given ciphertext and commitment using the provided public key and a transcript for the verification process. This file is part of a cryptographic library, likely used in secure communications or blockchain applications, where zero-knowledge proofs are essential for privacy-preserving verification.
# Imports and Dependencies

---
- `../../../../fd_flamenco_base.h`


# Data Structures

---
### fd\_zksdk\_ciph\_comm\_eq\_proof
- **Type**: `struct`
- **Members**:
    - `y0`: An array of 32 unsigned characters representing a point.
    - `y1`: An array of 32 unsigned characters representing a point.
    - `y2`: An array of 32 unsigned characters representing a point.
    - `zs`: An array of 32 unsigned characters representing a scalar.
    - `zx`: An array of 32 unsigned characters representing a scalar.
    - `zr`: An array of 32 unsigned characters representing a scalar.
- **Description**: The `fd_zksdk_ciph_comm_eq_proof` structure is a packed data structure used in zero-knowledge proofs for verifying the equality of ciphertext commitments. It contains three 32-byte arrays (`y0`, `y1`, `y2`) representing points and three 32-byte arrays (`zs`, `zx`, `zr`) representing scalars, which are likely used in cryptographic operations to ensure the integrity and validity of the proof.


---
### fd\_zksdk\_ciph\_comm\_eq\_proof\_t
- **Type**: `struct`
- **Members**:
    - `y0`: An array of 32 unsigned characters representing a point.
    - `y1`: An array of 32 unsigned characters representing a point.
    - `y2`: An array of 32 unsigned characters representing a point.
    - `zs`: An array of 32 unsigned characters representing a scalar.
    - `zx`: An array of 32 unsigned characters representing a scalar.
    - `zr`: An array of 32 unsigned characters representing a scalar.
- **Description**: The `fd_zksdk_ciph_comm_eq_proof_t` structure is a packed data structure used in cryptographic operations to represent a proof of equality between ciphertext and commitment. It contains three 32-byte arrays (`y0`, `y1`, `y2`) that represent points, and three 32-byte arrays (`zs`, `zx`, `zr`) that represent scalars. This structure is likely used in zero-knowledge proofs to verify that a given ciphertext corresponds to a specific commitment without revealing the underlying data.


---
### fd\_zksdk\_ciph\_comm\_eq\_context
- **Type**: `struct`
- **Members**:
    - `pubkey`: An array of 32 unsigned characters representing a public key point.
    - `ciphertext`: An array of 64 unsigned characters representing two points of ciphertext.
    - `commitment`: An array of 32 unsigned characters representing a commitment point.
- **Description**: The `fd_zksdk_ciph_comm_eq_context` structure is a packed data structure used in cryptographic operations to hold a public key, ciphertext, and commitment, each represented as arrays of unsigned characters. This structure is likely used in the context of verifying the equality of ciphertext and commitment in zero-knowledge proofs, where the public key, ciphertext, and commitment are essential components for the verification process.


---
### fd\_zksdk\_ciph\_comm\_eq\_context\_t
- **Type**: `struct`
- **Members**:
    - `pubkey`: A 32-byte array representing a public key point.
    - `ciphertext`: A 64-byte array representing two points of ciphertext.
    - `commitment`: A 32-byte array representing a commitment point.
- **Description**: The `fd_zksdk_ciph_comm_eq_context_t` structure is used to store cryptographic data related to the equality of ciphertext and commitment in a zero-knowledge proof context. It contains a public key, a ciphertext consisting of two points, and a commitment point, all of which are essential for verifying the proof of equality between the ciphertext and the commitment.


# Function Declarations (Public API)

---
### fd\_zksdk\_verify\_proof\_ciphertext\_commitment\_equality<!-- {{#callable_declaration:fd_zksdk_verify_proof_ciphertext_commitment_equality}} -->
Verify the equality of a ciphertext and commitment using a zero-knowledge proof.
- **Description**: This function is used to verify that a given zero-knowledge proof demonstrates the equality between a ciphertext and a commitment, based on a public key and a transcript. It should be called when you need to validate such a proof in cryptographic protocols. The function requires valid inputs for the proof, public key, ciphertext, and commitment, and it updates the transcript as part of the verification process. It returns an error code if any input is invalid or if the proof does not verify correctly.
- **Inputs**:
    - `proof`: A pointer to a `fd_zksdk_ciph_comm_eq_proof_t` structure containing the proof data. Must not be null and must contain valid scalar and point data.
    - `pubkey`: A 32-byte array representing the public key. Must not be null and must be a valid point.
    - `ciphertext`: A 64-byte array representing the ciphertext, consisting of two points. Must not be null and must contain valid point data.
    - `commitment`: A 32-byte array representing the commitment. Must not be null and must be a valid point.
    - `transcript`: A pointer to a `fd_zksdk_transcript_t` structure used to maintain the transcript of the proof verification process. Must not be null and is updated by the function.
- **Output**: Returns an integer indicating success or failure of the verification. Returns a specific error code if inputs are invalid or the proof does not verify.
- **See also**: [`fd_zksdk_verify_proof_ciphertext_commitment_equality`](fd_zksdk_ciphertext_commitment_equality.c.driver.md#fd_zksdk_verify_proof_ciphertext_commitment_equality)  (Implementation)


