# Purpose
This C source code file is designed to handle mock X.509 certificates, specifically for testing or simulation purposes. It defines a static template for a mock X.509 certificate (`fd_x509_mock_tpl`) and provides functions to manipulate and extract information from these certificates. The primary functionality includes creating a mock certificate with a specified public key ([`fd_x509_mock_cert`](#fd_x509_mock_cert)) and extracting the public key from a given certificate ([`fd_x509_mock_pubkey`](#fd_x509_mock_pubkey)). The code supports two versions of the certificate format, as indicated by the functions [`fd_x509_mock_pubkey_v1`](#fd_x509_mock_pubkey_v1) and [`fd_x509_mock_pubkey_v2`](#fd_x509_mock_pubkey_v2), which handle different certificate structures. The use of `memmem` and `memcmp` functions suggests that the code performs byte-level operations to match and extract data from the certificate byte arrays.

The file is not intended to be an executable on its own but rather a component that can be included in larger projects, likely for testing cryptographic operations or systems that rely on X.509 certificates. It does not define public APIs or external interfaces but provides internal static functions to support its operations. The code is highly specialized, focusing on the manipulation of mock certificates, and is likely part of a broader testing framework or library that simulates certificate-based authentication or encryption processes.
# Imports and Dependencies

---
- `fd_x509_mock.h`
- `string.h`


# Global Variables

---
### fd\_x509\_mock\_tpl
- **Type**: `array of unsigned char`
- **Description**: The `fd_x509_mock_tpl` is a static constant array of unsigned characters that represents a mock X.509 certificate template. It includes various components of an X.509 certificate such as the version, serial number, signature algorithm, issuer name, validity period, subject name, subject public key info, and extensions. This template is used to generate mock certificates for testing purposes.
- **Use**: This variable is used as a template to create mock X.509 certificates by copying its contents and replacing the public key section with a specified public key.


---
### fd\_x509\_mock\_v1\_prefix
- **Type**: `uchar const[]`
- **Description**: The `fd_x509_mock_v1_prefix` is a static constant array of unsigned characters that represents a specific prefix pattern used in X.509 mock certificates. This prefix is part of the certificate structure and is used to identify and match a specific version of the certificate format, particularly for Agave v1.18, which uses a less deterministic template due to a variable length serial number.
- **Use**: This variable is used to match the prefix of a certificate before the public key in the `fd_x509_mock_pubkey_v1` function to identify and extract the public key from a version 1 certificate.


# Functions

---
### fd\_x509\_mock\_cert<!-- {{#callable:fd_x509_mock_cert}} -->
The `fd_x509_mock_cert` function creates a mock X.509 certificate by copying a template into a buffer and inserting a given public key at a specified offset.
- **Inputs**:
    - `buf`: A buffer of size `FD_X509_MOCK_CERT_SZ` where the mock certificate will be stored.
    - `public_key`: A 32-byte array representing the public key to be inserted into the certificate.
- **Control Flow**:
    - Copy the contents of `fd_x509_mock_tpl` into the `buf` buffer using `fd_memcpy`.
    - Copy the `public_key` into the `buf` at the offset `FD_X509_MOCK_PUBKEY_OFF` using `fd_memcpy`.
- **Output**: The function does not return a value; it modifies the `buf` in place to contain the mock certificate.


---
### fd\_x509\_mock\_pubkey\_v1<!-- {{#callable:fd_x509_mock_pubkey_v1}} -->
The function `fd_x509_mock_pubkey_v1` extracts a public key from a mock X.509 certificate if it matches a specific prefix pattern.
- **Inputs**:
    - `cert`: A pointer to the beginning of the certificate data.
    - `cert_sz`: The size of the certificate data in bytes.
- **Control Flow**:
    - Calculate the end of the certificate data by adding `cert_sz` to `cert`.
    - Search for the `fd_x509_mock_v1_prefix` within the certificate data using `memmem`.
    - If the prefix is not found, return `NULL`.
    - Calculate the position of the public key by adding the size of the prefix to the match position.
    - Check if the public key extends beyond the end of the certificate data; if so, return `NULL`.
    - Return the pointer to the start of the public key.
- **Output**: A pointer to the start of the public key within the certificate, or `NULL` if the prefix is not found or the public key is out of bounds.


---
### fd\_x509\_mock\_pubkey\_v2<!-- {{#callable:fd_x509_mock_pubkey_v2}} -->
The function `fd_x509_mock_pubkey_v2` extracts the public key from a mock X.509 certificate if the certificate matches a predefined template.
- **Inputs**:
    - `cert`: A pointer to the certificate data, represented as an array of unsigned characters.
    - `cert_sz`: The size of the certificate data, represented as an unsigned long integer.
- **Control Flow**:
    - Check if the certificate size `cert_sz` is equal to `FD_X509_MOCK_CERT_SZ`; if not, return NULL.
    - Initialize an offset `off` to 0.
    - Compare the initial part of the certificate with the template up to the public key offset `FD_X509_MOCK_PUBKEY_OFF`; store the result in `match0`.
    - Increment the offset by `FD_X509_MOCK_PUBKEY_OFF` and then by 32 (the size of the public key).
    - Compare the remaining part of the certificate with the template from the current offset to the end; store the result in `match1`.
    - If either `match0` or `match1` is false, return NULL.
    - Return a pointer to the public key within the certificate, located at `FD_X509_MOCK_PUBKEY_OFF`.
- **Output**: A pointer to the public key within the certificate if the certificate matches the template; otherwise, NULL.


---
### fd\_x509\_mock\_pubkey<!-- {{#callable:fd_x509_mock_pubkey}} -->
The `fd_x509_mock_pubkey` function attempts to extract a public key from a given certificate using two different mock methods.
- **Inputs**:
    - `cert`: A pointer to the certificate data from which the public key is to be extracted.
    - `cert_sz`: The size of the certificate data in bytes.
- **Control Flow**:
    - The function first calls [`fd_x509_mock_pubkey_v1`](#fd_x509_mock_pubkey_v1) with the provided certificate and its size to attempt to find the public key using the first mock method.
    - If [`fd_x509_mock_pubkey_v1`](#fd_x509_mock_pubkey_v1) returns a non-null pointer, indicating a successful match, the function returns this pointer as the public key.
    - If the first method fails (returns null), the function then calls [`fd_x509_mock_pubkey_v2`](#fd_x509_mock_pubkey_v2) with the same inputs to attempt to find the public key using the second mock method.
    - If [`fd_x509_mock_pubkey_v2`](#fd_x509_mock_pubkey_v2) returns a non-null pointer, the function returns this pointer as the public key.
    - If both methods fail to find a match, the function returns null, indicating that the public key could not be extracted.
- **Output**: A pointer to the location of the public key within the certificate if found, or NULL if no public key could be extracted using the mock methods.
- **Functions called**:
    - [`fd_x509_mock_pubkey_v1`](#fd_x509_mock_pubkey_v1)
    - [`fd_x509_mock_pubkey_v2`](#fd_x509_mock_pubkey_v2)


