# Purpose
This C header file, `fd_keyguard.h`, is part of a digital signature system designed to facilitate secure operations for validator components, likely within a blockchain or distributed ledger context. It defines constants and structures for managing digital signatures, including maximum payload sizes, role definitions, payload types, and signature types. The file provides function prototypes for matching payload types and authorizing signing requests, ensuring that only authorized entities can request signatures for specific roles and payloads. The header includes mechanisms for type checking and authorization, emphasizing security and role-based access control in the signing process.
# Imports and Dependencies

---
- `../fd_disco_base.h`


# Data Structures

---
### fd\_keyguard\_authority
- **Type**: `struct`
- **Members**:
    - `identity_pubkey`: An array of 32 unsigned characters representing a public key.
- **Description**: The `fd_keyguard_authority` structure is used to store a public key, which is essential for verifying digital signatures in the context of the keyguard system. This structure is likely used to identify and authorize entities that request digital signatures, ensuring that only authorized components can perform signing operations.


---
### fd\_keyguard\_authority\_t
- **Type**: `struct`
- **Members**:
    - `identity_pubkey`: An array of 32 unsigned characters representing the public key identity.
- **Description**: The `fd_keyguard_authority_t` structure is used to represent an authority in the keyguard system, specifically holding the public key identity necessary for authorizing signing requests. This structure is integral to the authorization process, ensuring that only entities with the correct public key can initiate signing operations, thereby maintaining the security and integrity of the digital signature process within the keyguard framework.


# Function Declarations (Public API)

---
### fd\_keyguard\_payload\_match<!-- {{#callable_declaration:fd_keyguard_payload_match}} -->
Determine the type of a payload based on its content and signing type.
- **Description**: Use this function to identify the type of a given payload by analyzing its content and the specified signing type. It is useful when you need to determine the nature of a payload before processing or signing it. The function examines the payload against various known types and returns a bitwise OR of matching payload type constants. It is important to ensure that the payload size does not exceed the maximum allowed size for signing requests. The function returns 0 if no type matches, and the result will have a single bit set if the payload unambiguously matches one type.
- **Inputs**:
    - `data`: A pointer to the payload data to be analyzed. It must not be null and should point to a valid memory region of at least 'sz' bytes.
    - `sz`: The size of the payload data in bytes. It should be a positive value and must not exceed FD_KEYGUARD_SIGN_REQ_MTU.
    - `sign_type`: An integer representing the signing type, which must be one of the defined FD_KEYGUARD_SIGN_TYPE_{...} constants.
- **Output**: Returns a bitwise OR of FD_KEYGUARD_PAYLOAD_{...} constants indicating the matching payload types, or 0 if none match.
- **See also**: [`fd_keyguard_payload_match`](fd_keyguard_match.c.driver.md#fd_keyguard_payload_match)  (Implementation)


---
### fd\_keyguard\_payload\_authorize<!-- {{#callable_declaration:fd_keyguard_payload_authorize}} -->
Authorize a signing request based on role and payload type.
- **Description**: This function determines if a signing request is authorized based on the specified role and the type of payload. It should be used when a component needs to verify if it can proceed with signing a given payload. The function requires that the payload size does not exceed the defined maximum and that the role is one of the predefined roles. It returns a boolean indicating authorization success or failure. The function is more restrictive than payload matching functions, ensuring that only valid and authorized requests are processed.
- **Inputs**:
    - `authority`: A pointer to a constant fd_keyguard_authority_t structure containing the identity public key. Must not be null.
    - `data`: A pointer to the payload data to be signed. The data is a byte array and must not be null.
    - `sz`: The size of the data in bytes. Must be less than or equal to FD_KEYGUARD_SIGN_REQ_MTU (2048 bytes). If the size exceeds this limit, the function returns 0.
    - `role`: An integer representing the role of the requester, which must be one of the predefined FD_KEYGUARD_ROLE_{...} constants. If the role is unsupported, the function returns 0.
    - `sign_type`: An integer representing the type of signing operation, which must be one of the FD_KEYGUARD_SIGN_TYPE_{...} constants.
- **Output**: Returns 1 if the signing request is authorized, otherwise returns 0.
- **See also**: [`fd_keyguard_payload_authorize`](fd_keyguard_authorize.c.driver.md#fd_keyguard_payload_authorize)  (Implementation)


