# Purpose
This code is a C header file that defines a macro for declaring functions used to decode QUIC packets and frames. The macro `FD_TEMPL_DEF_STRUCT_BEGIN(NAME)` is designed to generate function prototypes for decoding different QUIC structures, where `NAME` is a placeholder for the specific structure type. Each generated function, such as `fd_quic_decode_<NAME>`, takes a pointer to an output structure and a byte array as input, returning the number of bytes consumed during the decoding process. The use of `FD_WARN_UNUSED` suggests that the return value must be checked by the caller, ensuring that the function's result is not ignored. The inclusion of `"fd_quic_dft.h"` indicates that this file likely relies on definitions or additional macros provided in that header, which are necessary for the decoding operations.
# Imports and Dependencies

---
- `fd_quic_dft.h`


