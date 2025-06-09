# Purpose
This C header file defines data structures related to cryptographic proofs, specifically for percentage calculations with a cap, likely used in a zero-knowledge proof (ZKP) system. The file includes definitions for three packed structures: `percentage_max_proof`, `percentage_equality_proof`, and `fd_zksdk_percentage_with_cap_proof`, each containing arrays of unsigned characters (likely representing cryptographic points and scalars) and a `ulong` for a maximum value. These structures are used to encapsulate data necessary for verifying percentage calculations under certain constraints, such as a maximum cap, without revealing the actual values involved. The inclusion of `fd_flamenco_base.h` suggests that these structures are part of a larger cryptographic framework or library.
# Imports and Dependencies

---
- `../../../../fd_flamenco_base.h`


# Data Structures

---
### percentage\_max\_proof
- **Type**: `struct`
- **Members**:
    - `y_max`: An array of 32 unsigned characters representing a point.
    - `z_max`: An array of 32 unsigned characters representing a scalar.
    - `c_max`: An array of 32 unsigned characters representing a scalar.
- **Description**: The `percentage_max_proof` structure is a packed data structure used to store cryptographic proof components related to a maximum percentage calculation. It contains three members: `y_max`, `z_max`, and `c_max`, each being an array of 32 unsigned characters. These arrays are likely used to represent cryptographic points and scalars in a zero-knowledge proof system, ensuring that the maximum percentage is correctly calculated and verified without revealing the actual values.


---
### percentage\_max\_proof\_t
- **Type**: `struct`
- **Members**:
    - `y_max`: An array of 32 unsigned characters representing a point.
    - `z_max`: An array of 32 unsigned characters representing a scalar.
    - `c_max`: An array of 32 unsigned characters representing a scalar.
- **Description**: The `percentage_max_proof_t` structure is a packed data structure used to store cryptographic proof elements related to a maximum percentage calculation. It contains three members: `y_max`, `z_max`, and `c_max`, each of which is an array of 32 unsigned characters. These members are likely used to represent cryptographic points and scalars in a zero-knowledge proof system, ensuring that certain percentage constraints are met without revealing the actual values involved.


---
### percentage\_equality\_proof
- **Type**: `struct`
- **Members**:
    - `y_delta`: An array of 32 unsigned characters representing a point.
    - `y_claimed`: An array of 32 unsigned characters representing a point.
    - `z_x`: An array of 32 unsigned characters representing a scalar.
    - `z_delta`: An array of 32 unsigned characters representing a scalar.
    - `z_claimed`: An array of 32 unsigned characters representing a scalar.
- **Description**: The `percentage_equality_proof` structure is a packed data structure used to store cryptographic proof elements related to percentage equality verification. It contains five fields, each consisting of an array of 32 unsigned characters, which are used to represent points and scalars in cryptographic operations. The fields `y_delta` and `y_claimed` are used to store point values, while `z_x`, `z_delta`, and `z_claimed` store scalar values, all of which are essential for the proof's integrity and verification process.


---
### percentage\_equality\_proof\_t
- **Type**: `struct`
- **Members**:
    - `y_delta`: A 32-byte array representing a point.
    - `y_claimed`: A 32-byte array representing a point.
    - `z_x`: A 32-byte array representing a scalar.
    - `z_delta`: A 32-byte array representing a scalar.
    - `z_claimed`: A 32-byte array representing a scalar.
- **Description**: The `percentage_equality_proof_t` structure is a packed data structure used to represent a proof of equality in percentage calculations. It contains arrays for points and scalars, which are likely used in cryptographic operations to verify the equality of certain percentage values. The structure is designed to be compact, with each member being a fixed-size array of 32 bytes, ensuring efficient storage and processing.


---
### fd\_zksdk\_percentage\_with\_cap\_proof
- **Type**: `struct`
- **Members**:
    - `percentage_max_proof`: A member of type `percentage_max_proof_t` that holds proof data related to the maximum percentage.
    - `percentage_equality_proof`: A member of type `percentage_equality_proof_t` that holds proof data related to percentage equality.
- **Description**: The `fd_zksdk_percentage_with_cap_proof` structure is a packed data structure that encapsulates two types of cryptographic proofs: `percentage_max_proof` and `percentage_equality_proof`. These proofs are used to verify certain properties of percentages, such as ensuring a percentage does not exceed a maximum value and verifying equality between percentage values, within a zero-knowledge proof system. The structure is designed to be compact and efficient for use in cryptographic operations.


---
### fd\_zksdk\_percentage\_with\_cap\_proof\_t
- **Type**: `struct`
- **Members**:
    - `percentage_max_proof`: A structure containing fields for maximum percentage proof, including y_max, z_max, and c_max.
    - `percentage_equality_proof`: A structure containing fields for percentage equality proof, including y_delta, y_claimed, z_x, z_delta, and z_claimed.
- **Description**: The `fd_zksdk_percentage_with_cap_proof_t` structure is a packed data structure that encapsulates two types of cryptographic proofs: `percentage_max_proof_t` and `percentage_equality_proof_t`. These proofs are used to verify percentage values with a cap, ensuring both the maximum percentage and equality conditions are met. The structure is designed to be used in zero-knowledge proofs, where the integrity of percentage calculations can be verified without revealing the actual values.


---
### fd\_zksdk\_percentage\_with\_cap\_context
- **Type**: `struct`
- **Members**:
    - `percentage_commitment`: A 32-byte array representing a point commitment for the percentage.
    - `delta_commitment`: A 32-byte array representing a point commitment for the delta.
    - `claimed_commitment`: A 32-byte array representing a point commitment for the claimed value.
    - `max_value`: An unsigned long integer representing the maximum value allowed.
- **Description**: The `fd_zksdk_percentage_with_cap_context` structure is a packed data structure used to store cryptographic commitments related to percentage calculations with a cap. It includes three 32-byte arrays for storing point commitments (`percentage_commitment`, `delta_commitment`, and `claimed_commitment`) and a `max_value` field to define the upper limit for the percentage value. This structure is likely used in zero-knowledge proofs or similar cryptographic protocols to ensure data integrity and confidentiality while enforcing a maximum cap on the percentage value.


---
### fd\_zksdk\_percentage\_with\_cap\_context\_t
- **Type**: `struct`
- **Members**:
    - `percentage_commitment`: A 32-byte array representing a point commitment for the percentage.
    - `delta_commitment`: A 32-byte array representing a point commitment for the delta.
    - `claimed_commitment`: A 32-byte array representing a point commitment for the claimed value.
    - `max_value`: An unsigned long integer representing the maximum allowable value.
- **Description**: The `fd_zksdk_percentage_with_cap_context_t` structure is designed to manage and store cryptographic commitments related to percentage calculations with an upper cap. It includes three 32-byte arrays for storing point commitments (`percentage_commitment`, `delta_commitment`, and `claimed_commitment`) and a `max_value` field to define the maximum permissible value in the context of these calculations. This structure is packed to ensure efficient memory usage and alignment.


