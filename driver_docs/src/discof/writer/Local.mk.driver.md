# Purpose
This snippet is from a Makefile, a build automation tool used to compile and link programs. It conditionally adds the object files `fd_writer_tile` and `fd_discof` to the build process if both `FD_HAS_INT128` and `FD_HAS_SSE` are defined, indicating that the build should include these components only when the system supports 128-bit integers and SSE (Streaming SIMD Extensions).
