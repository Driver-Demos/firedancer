# Purpose
This code is a C header file that serves as a wrapper for including compiler sanitizer APIs, specifically AddressSanitizer (ASan) and MemorySanitizer (MSan). The file begins with include guards to prevent multiple inclusions, ensuring that the header's contents are only processed once during compilation. The purpose of this header is to facilitate the integration of sanitizers, which are tools used to detect various types of runtime errors such as out-of-bounds memory accesses and undefined behavior. By including "fd_asan.h" and "fd_msan.h", this file provides a centralized way to incorporate these error detection capabilities into a C project, enhancing its robustness and reliability.
# Imports and Dependencies

---
- `fd_asan.h`
- `fd_msan.h`


