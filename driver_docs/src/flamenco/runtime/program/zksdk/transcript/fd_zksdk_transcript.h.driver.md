# Purpose
This C header file, `fd_transcript.h`, is part of a larger software system related to cryptographic operations, specifically focusing on zero-knowledge proofs (ZKPs). The file provides a set of inline functions and macros that facilitate the creation and manipulation of cryptographic transcripts using the Merlin protocol. It acts as an interface layer that abstracts and extends the functionality of the underlying Merlin and rangeproofs libraries, allowing for the appending of various cryptographic elements such as public keys, ciphertexts, commitments, and handles to a transcript. Additionally, it defines domain separators for different types of cryptographic proofs, which are essential for ensuring the integrity and security of the ZKP processes.

The file is structured to be included in other C source files, providing a narrow but crucial functionality within the cryptographic domain. It leverages existing components from the Merlin and rangeproofs libraries, as well as the Ristretto255 curve from the Ed25519 library, to offer a cohesive API for managing cryptographic transcripts. The use of macros to alias functions from these libraries indicates a design choice to maintain consistency and ease of use across the system. This header file does not define a public API in the traditional sense but rather serves as an internal component that other parts of the system can utilize to perform specific cryptographic operations related to zero-knowledge proofs.
# Imports and Dependencies

---
- `../../../../fd_flamenco_base.h`
- `../merlin/fd_merlin.h`
- `../rangeproofs/fd_rangeproofs.h`
- `../../../../../ballet/ed25519/fd_ristretto255.h`


# Functions

---
### fd\_zksdk\_transcript\_append\_pubkey<!-- {{#callable:fd_zksdk_transcript_append_pubkey}} -->
The function `fd_zksdk_transcript_append_pubkey` appends a public key to a transcript with a specified label.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure where the public key will be appended.
    - `label`: A constant character pointer representing the label associated with the public key in the transcript.
    - `label_len`: An unsigned integer representing the length of the label.
    - `pubkey`: A constant unsigned character array of 32 bytes representing the public key to be appended.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` with the provided `transcript`, `label`, `label_len`, and `pubkey` along with a fixed size of 32 bytes for the public key.
- **Output**: The function does not return a value; it modifies the `transcript` in place by appending the public key.


---
### fd\_zksdk\_transcript\_append\_ciphertext<!-- {{#callable:fd_zksdk_transcript_append_ciphertext}} -->
The function `fd_zksdk_transcript_append_ciphertext` appends a 64-byte ciphertext to a transcript with a specified label.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure where the ciphertext will be appended.
    - `label`: A constant character pointer representing the label associated with the ciphertext.
    - `label_len`: An unsigned integer representing the length of the label.
    - `ciphertext`: A constant unsigned character array of 64 bytes representing the ciphertext to be appended.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` with the provided `transcript`, `label`, `label_len`, `ciphertext`, and a fixed size of 64 bytes.
    - The `fd_merlin_transcript_append_message` function handles the actual appending of the ciphertext to the transcript.
- **Output**: The function does not return a value; it modifies the transcript in place by appending the ciphertext.


---
### fd\_zksdk\_transcript\_append\_commitment<!-- {{#callable:fd_zksdk_transcript_append_commitment}} -->
The function `fd_zksdk_transcript_append_commitment` appends a 32-byte commitment to a transcript with a specified label.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure where the commitment will be appended.
    - `label`: A constant character pointer representing the label associated with the commitment.
    - `label_len`: An unsigned integer specifying the length of the label.
    - `commitment`: A constant unsigned character array of 32 bytes representing the commitment to be appended.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` with the provided `transcript`, `label`, `label_len`, and `commitment`, along with a fixed size of 32 for the commitment.
- **Output**: The function does not return a value; it modifies the `transcript` in place by appending the commitment.


---
### fd\_zksdk\_transcript\_append\_handle<!-- {{#callable:fd_zksdk_transcript_append_handle}} -->
The function `fd_zksdk_transcript_append_handle` appends a 32-byte handle to a transcript with a specified label.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure where the handle will be appended.
    - `label`: A constant character pointer representing the label associated with the handle.
    - `label_len`: An unsigned integer representing the length of the label.
    - `handle`: A constant unsigned character array of 32 bytes representing the handle to be appended.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` with the provided `transcript`, `label`, `label_len`, `handle`, and a fixed size of 32 bytes.
    - The `fd_merlin_transcript_append_message` function handles the actual appending of the handle to the transcript.
- **Output**: The function does not return a value; it modifies the `transcript` in place by appending the handle.


---
### fd\_zksdk\_transcript\_domsep\_ciph\_ciph\_eq\_proof<!-- {{#callable:fd_zksdk_transcript_domsep_ciph_ciph_eq_proof}} -->
The function `fd_zksdk_transcript_domsep_ciph_ciph_eq_proof` appends a domain separator message indicating a 'ciphertext-ciphertext-equality-proof' to a given transcript.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` object, which is used to record the domain separator message.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` with the `transcript`, a literal label 'dom-sep', and a message 'ciphertext-ciphertext-equality-proof'.
- **Output**: The function does not return any value; it modifies the `transcript` in place by appending the specified message.


---
### fd\_zksdk\_transcript\_domsep\_ciph\_comm\_eq\_proof<!-- {{#callable:fd_zksdk_transcript_domsep_ciph_comm_eq_proof}} -->
The function `fd_zksdk_transcript_domsep_ciph_comm_eq_proof` appends a domain separator message indicating a 'ciphertext-commitment-equality-proof' to a given transcript.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` object, which is a type alias for `fd_merlin_transcript_t`, representing the transcript to which the message will be appended.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` with the `transcript` pointer, a literal string 'dom-sep', and a literal string 'ciphertext-commitment-equality-proof' cast to `uchar *`.
- **Output**: The function does not return a value; it modifies the `transcript` in place by appending a specific domain separator message.


---
### fd\_zksdk\_transcript\_domsep\_zero\_ciphertext\_proof<!-- {{#callable:fd_zksdk_transcript_domsep_zero_ciphertext_proof}} -->
The function `fd_zksdk_transcript_domsep_zero_ciphertext_proof` appends a domain separator message for a zero-ciphertext proof to a given transcript.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` object, which is the transcript to which the domain separator message will be appended.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` with the `transcript` pointer, a literal string "dom-sep", and a literal string "zero-ciphertext-proof" cast to `uchar *`.
- **Output**: The function does not return any value; it modifies the `transcript` in place by appending a specific domain separator message.


---
### fd\_zksdk\_transcript\_domsep\_grp\_ciph\_val\_proof<!-- {{#callable:fd_zksdk_transcript_domsep_grp_ciph_val_proof}} -->
The function `fd_zksdk_transcript_domsep_grp_ciph_val_proof` appends a domain separator and a handle value to a transcript for a group ciphertext validity proof.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure, which is used to record the transcript of the cryptographic protocol.
    - `handles`: An unsigned long integer representing the handle value to be appended to the transcript.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` to append a domain separator labeled 'dom-sep' with the message 'validity-proof' to the transcript.
    - The function then calls `fd_merlin_transcript_append_u64` to append the handle value to the transcript with the label 'handles'.
- **Output**: The function does not return a value; it modifies the `transcript` in place by appending the specified domain separator and handle value.


---
### fd\_zksdk\_transcript\_domsep\_batched\_grp\_ciph\_val\_proof<!-- {{#callable:fd_zksdk_transcript_domsep_batched_grp_ciph_val_proof}} -->
The function `fd_zksdk_transcript_domsep_batched_grp_ciph_val_proof` appends a domain separator and a handle count to a transcript for a batched group cipher validity proof.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure, which is used to record the transcript of cryptographic operations.
    - `handles`: An unsigned long integer representing the number of handles involved in the batched group cipher validity proof.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` to append a domain separator labeled 'dom-sep' with the message 'batched-validity-proof' to the transcript.
    - It then calls `fd_merlin_transcript_append_u64` to append the number of handles to the transcript with the label 'handles'.
- **Output**: The function does not return a value; it modifies the transcript in place.


---
### fd\_zksdk\_transcript\_domsep\_percentage\_with\_cap\_proof<!-- {{#callable:fd_zksdk_transcript_domsep_percentage_with_cap_proof}} -->
The function `fd_zksdk_transcript_domsep_percentage_with_cap_proof` appends a domain separator message indicating a 'percentage-with-cap-proof' to a given transcript.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure, which is the transcript to which the domain separator message will be appended.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` with the `transcript`, a literal string 'dom-sep', and a literal string 'percentage-with-cap-proof' cast to `uchar *`.
- **Output**: The function does not return any value; it modifies the `transcript` in place by appending a specific domain separator message.


---
### fd\_zksdk\_transcript\_domsep\_pubkey\_proof<!-- {{#callable:fd_zksdk_transcript_domsep_pubkey_proof}} -->
The function `fd_zksdk_transcript_domsep_pubkey_proof` appends a domain separator message labeled 'pubkey-proof' to a given transcript.
- **Inputs**:
    - `transcript`: A pointer to an `fd_zksdk_transcript_t` structure, which is used to record the domain separator message.
- **Control Flow**:
    - The function calls `fd_merlin_transcript_append_message` with the `transcript`, a literal label 'dom-sep', and a message 'pubkey-proof'.
- **Output**: The function does not return a value; it modifies the `transcript` in place by appending a specific domain separator message.


