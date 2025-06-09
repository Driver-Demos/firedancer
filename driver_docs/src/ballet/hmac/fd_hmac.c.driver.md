# Purpose
This C source code file is a configuration and implementation template for HMAC (Hash-based Message Authentication Code) using different SHA (Secure Hash Algorithm) variants. It includes header files for SHA-256, SHA-384, and SHA-512 algorithms, and defines macros to set the hash algorithm, block size, and hash size for each variant. The file then includes a template file, `fd_hmac_tmpl.c`, three times, each time with different macro definitions, effectively generating HMAC implementations for SHA-256, SHA-384, and SHA-512. This approach allows for code reuse and modularity by leveraging a single template to handle multiple hash algorithms with minimal redundancy.
# Imports and Dependencies

---
- `fd_hmac.h`
- `../sha256/fd_sha256.h`
- `../sha512/fd_sha512.h`
- `fd_hmac_tmpl.c`


