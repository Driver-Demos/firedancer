# Purpose
This is a Makefile snippet used in a build system to conditionally add object files to the build process. It checks for the presence of two preprocessor macros, `FD_HAS_SSE` and `FD_HAS_ALLOCA`, and if both are defined, it invokes a function `add-objs` to include the `fd_sock_tile` and `fd_disco` object files in the build.
