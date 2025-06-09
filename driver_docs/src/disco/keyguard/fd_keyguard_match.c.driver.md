# Purpose
The provided C source code file is part of a security module designed to protect against unauthorized signing requests, specifically targeting "fake signing" attacks. This module, `fd_keyguard_match`, is responsible for fingerprinting and verifying the authenticity of various types of signing requests to ensure they are legitimate and not subject to type confusion or key reuse vulnerabilities. The code implements a series of static functions that check if a given payload matches specific message types, such as transaction messages, gossip messages, repair messages, and others. Each function performs checks based on the message's structure and size, ensuring that only valid and expected message types are processed further.

The code is highly specialized and optimized for performance and security, with a focus on preventing false negatives in type detection. It uses constant-time operations to ensure compatibility with formal verification tools like CBMC, which are used to prove the absence of certain classes of vulnerabilities. The module is a critical component in securing the identity key of validators, as it forms the first line of defense against unauthorized signing requests. The functions are marked with `FD_FN_PURE`, indicating that they have no side effects and their return values depend only on their input parameters, which is crucial for the reliability and predictability of the security checks.
# Imports and Dependencies

---
- `fd_keyguard.h`
- `../../ballet/shred/fd_shred.h`
- `../../ballet/txn/fd_compact_u16.h`


# Functions

---
### fd\_keyguard\_payload\_matches\_txn\_msg<!-- {{#callable:fd_keyguard_payload_matches_txn_msg}} -->
The function `fd_keyguard_payload_matches_txn_msg` checks if a given data payload matches the expected format of a transaction message for a specific signing type.
- **Inputs**:
    - `data`: A pointer to the unsigned character array representing the data payload to be checked.
    - `sz`: The size of the data payload in bytes.
    - `sign_type`: An integer representing the type of signing used, expected to be `FD_KEYGUARD_SIGN_TYPE_ED25519` for this function to proceed.
- **Control Flow**:
    - Check if the signing type is `FD_KEYGUARD_SIGN_TYPE_ED25519`; if not, return 0.
    - Calculate the minimum size of a valid transaction message and return 0 if the provided size is smaller.
    - Initialize a cursor to traverse the data and extract the first byte to determine the message type (legacy or versioned).
    - For versioned messages, check if the version is recognized (v0) and extract the signature count; for legacy messages, use the first byte as the signature count.
    - Return 0 if the signature count is zero or if the calculated signature size exceeds the transaction size limit.
    - Skip over the readonly signed and unsigned counts in the data.
    - Decode the address count size and value from the data, returning 0 if decoding fails or if the signature count exceeds the address count.
    - Return 1 if all checks pass, indicating the data matches the expected transaction message format.
- **Output**: Returns 1 if the data payload matches the expected transaction message format for the specified signing type, otherwise returns 0.


---
### fd\_keyguard\_payload\_matches\_ping\_msg<!-- {{#callable:fd_keyguard_payload_matches_ping_msg}} -->
The function `fd_keyguard_payload_matches_ping_msg` checks if a given data payload matches the criteria for a 'ping' message, specifically for the SHA256_ED25519 signing type.
- **Inputs**:
    - `data`: A pointer to the data payload that needs to be checked.
    - `sz`: The size of the data payload in bytes.
    - `sign_type`: An integer representing the type of signing used for the data payload.
- **Control Flow**:
    - The function first checks if the `sign_type` is equal to `FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519`.
    - It then checks if the size `sz` of the data is exactly 48 bytes.
    - Finally, it compares the first 16 bytes of the data with the string "SOLANA_PING_PONG" using `memcmp`.
- **Output**: The function returns 1 if all conditions are met, indicating a match, otherwise it returns 0.


---
### fd\_keyguard\_payload\_matches\_prune\_data<!-- {{#callable:fd_keyguard_payload_matches_prune_data}} -->
The function `fd_keyguard_payload_matches_prune_data` checks if a given data payload matches the expected format and size for a prune data message with a specific signature type.
- **Inputs**:
    - `data`: A pointer to the unsigned character array representing the data payload to be checked.
    - `sz`: The size of the data payload in bytes.
    - `sign_type`: An integer representing the type of signature used for the data payload.
- **Control Flow**:
    - Check if the signature type is `FD_KEYGUARD_SIGN_TYPE_ED25519`; if not, return 0.
    - Define a constant `static_sz` with a value of 80 and check if `sz` is less than `static_sz`; if so, return 0.
    - Load a `ulong` value from the data at offset 32 into `prune_cnt`.
    - Calculate `expected_sz` by multiplying `prune_cnt` by 32 and adding `static_sz`, checking for overflow; if overflow occurs, return 0.
    - Check if `sz` equals `expected_sz`; if not, return 0.
    - If all checks pass, return 1.
- **Output**: Returns 1 if the data payload matches the expected prune data format and size, otherwise returns 0.


---
### fd\_keyguard\_payload\_matches\_gossip<!-- {{#callable:fd_keyguard_payload_matches_gossip}} -->
The function `fd_keyguard_payload_matches_gossip` checks if a given data payload matches the expected format for a gossip message with a specific signing type.
- **Inputs**:
    - `data`: A pointer to the unsigned character array representing the data payload to be checked.
    - `sz`: An unsigned long integer representing the size of the data payload.
    - `sign_type`: An integer representing the type of signing used for the data payload.
- **Control Flow**:
    - Check if the signing type is not `FD_KEYGUARD_SIGN_TYPE_ED25519`; if so, return 0 indicating no match.
    - Check if the size of the data payload is less than 36 bytes; if so, return 0 indicating no match.
    - Check if the first four bytes of the data payload match the expected pattern for a gossip message; if so, return 1 indicating a match.
    - If none of the above conditions are met, return 0 indicating no match.
- **Output**: Returns an integer, 1 if the data payload matches the expected format for a gossip message, otherwise 0.


---
### fd\_keyguard\_payload\_matches\_repair<!-- {{#callable:fd_keyguard_payload_matches_repair}} -->
The function `fd_keyguard_payload_matches_repair` checks if a given data payload matches the criteria for a repair message using raw signing with the Ed25519 signature type.
- **Inputs**:
    - `data`: A pointer to the unsigned character array representing the data payload to be checked.
    - `sz`: The size of the data payload in bytes.
    - `sign_type`: An integer representing the type of signature used for the data payload.
- **Control Flow**:
    - Check if the signature type is not `FD_KEYGUARD_SIGN_TYPE_ED25519`; if so, return 0 indicating no match.
    - Verify that the size of the data payload is at least 36 bytes; if not, return 0 indicating no match.
    - Check if the first four bytes of the data payload represent a valid repair message type by ensuring the first byte is less than 0x20 and the next three bytes are zero; if so, return 1 indicating a match.
    - If none of the conditions for a match are met, return 0.
- **Output**: The function returns 1 if the data payload matches the criteria for a repair message, otherwise it returns 0.


---
### fd\_keyguard\_payload\_matches\_shred<!-- {{#callable:fd_keyguard_payload_matches_shred}} -->
The function `fd_keyguard_payload_matches_shred` checks if a given payload matches the criteria for a shred message based on its size and signature type.
- **Inputs**:
    - `data`: A pointer to the payload data to be checked, though it is not used in the function.
    - `sz`: The size of the payload data, which must be exactly 32 bytes for a match.
    - `sign_type`: The type of signature used, which must be `FD_KEYGUARD_SIGN_TYPE_ED25519` for a match.
- **Control Flow**:
    - The function first checks if the `sign_type` is `FD_KEYGUARD_SIGN_TYPE_ED25519`; if not, it returns 0.
    - Next, it checks if the `sz` is equal to 32; if not, it returns 0.
    - If both conditions are met, the function returns 1, indicating a match.
- **Output**: The function returns an integer, 1 if the payload matches the criteria for a shred message, otherwise 0.


---
### fd\_keyguard\_payload\_matches\_tls\_cv<!-- {{#callable:fd_keyguard_payload_matches_tls_cv}} -->
The function `fd_keyguard_payload_matches_tls_cv` checks if a given payload matches the expected format for a TLS CertificateVerify message with a specific signing type and size.
- **Inputs**:
    - `data`: A pointer to the unsigned character array representing the payload data to be checked.
    - `sz`: The size of the payload data in bytes.
    - `sign_type`: An integer representing the type of signature used, expected to be `FD_KEYGUARD_SIGN_TYPE_ED25519` for this function to proceed.
- **Control Flow**:
    - Check if the `sign_type` is `FD_KEYGUARD_SIGN_TYPE_ED25519`; if not, return 0.
    - Use a switch statement to verify if `sz` matches one of the expected sizes (130, 146, or 162 bytes); if not, return 0.
    - Define static client and server prefix strings, each 98 characters long, with specific TLS 1.3 CertificateVerify patterns.
    - Compare the beginning of `data` with the client and server prefixes using `memcmp` to determine if it matches either pattern.
    - Return 1 if the data matches either the client or server prefix, otherwise return 0.
- **Output**: Returns 1 if the payload matches the expected TLS CertificateVerify format for either a client or server, otherwise returns 0.


---
### fd\_keyguard\_payload\_matches\_bundle<!-- {{#callable:fd_keyguard_payload_matches_bundle}} -->
The function `fd_keyguard_payload_matches_bundle` checks if a given payload matches the criteria for a bundle signature type.
- **Inputs**:
    - `data`: A pointer to the unsigned character array representing the payload data to be checked.
    - `sz`: An unsigned long integer representing the size of the payload data.
    - `sign_type`: An integer representing the type of signature used for the payload.
- **Control Flow**:
    - The function first ignores the `data` parameter as it is not used in the logic.
    - It checks if the `sign_type` is equal to `FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519`; if not, it returns 0.
    - It then checks if the size `sz` is equal to 9; if not, it returns 0.
    - If both conditions are met, it returns 1.
- **Output**: The function returns an integer, 1 if the payload matches the bundle criteria, otherwise 0.


---
### fd\_keyguard\_payload\_matches\_event<!-- {{#callable:fd_keyguard_payload_matches_event}} -->
The function `fd_keyguard_payload_matches_event` checks if a given payload matches the criteria for an FD_METRICS_REPORT_CONCAT_ED25519 event.
- **Inputs**:
    - `data`: A pointer to the payload data to be checked.
    - `sz`: The size of the payload data.
    - `sign_type`: The type of signature associated with the payload.
- **Control Flow**:
    - The function first ignores the `data` parameter as it is not used in the logic.
    - It checks if `sign_type` is equal to `FD_KEYGUARD_SIGN_TYPE_FD_METRICS_REPORT_CONCAT_ED25519`; if not, it returns 0.
    - It then checks if `sz` is equal to 32; if not, it returns 0.
    - If both conditions are met, it returns 1.
- **Output**: The function returns 1 if the payload matches the event criteria, otherwise it returns 0.


---
### fd\_keyguard\_payload\_match<!-- {{#callable:fd_keyguard_payload_match}} -->
The `fd_keyguard_payload_match` function determines the type of a given payload by checking it against various known message types and returns a bitmask indicating the matched types.
- **Inputs**:
    - `data`: A pointer to the unsigned character array representing the payload data to be checked.
    - `sz`: The size of the payload data in bytes.
    - `sign_type`: An integer representing the type of signature used for the payload.
- **Control Flow**:
    - Initialize a result variable `res` to 0.
    - For each known message type (transaction, gossip, repair, prune data, shred, TLS CV, ping, bundle, event), call the corresponding match function with `data`, `sz`, and `sign_type` as arguments.
    - Use `fd_ulong_if` to update `res` with a specific bitmask if the match function returns true for a message type.
    - Return the final value of `res`, which is a bitmask representing the matched message types.
- **Output**: The function returns an unsigned long integer that acts as a bitmask, indicating which message types the payload matches.
- **Functions called**:
    - [`fd_keyguard_payload_matches_txn_msg`](#fd_keyguard_payload_matches_txn_msg)
    - [`fd_keyguard_payload_matches_gossip`](#fd_keyguard_payload_matches_gossip)
    - [`fd_keyguard_payload_matches_repair`](#fd_keyguard_payload_matches_repair)
    - [`fd_keyguard_payload_matches_prune_data`](#fd_keyguard_payload_matches_prune_data)
    - [`fd_keyguard_payload_matches_shred`](#fd_keyguard_payload_matches_shred)
    - [`fd_keyguard_payload_matches_tls_cv`](#fd_keyguard_payload_matches_tls_cv)
    - [`fd_keyguard_payload_matches_ping_msg`](#fd_keyguard_payload_matches_ping_msg)
    - [`fd_keyguard_payload_matches_bundle`](#fd_keyguard_payload_matches_bundle)
    - [`fd_keyguard_payload_matches_event`](#fd_keyguard_payload_matches_event)


