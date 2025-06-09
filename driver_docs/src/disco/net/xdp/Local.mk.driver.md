# Purpose
This is a Makefile snippet used in a build system to conditionally add object files to a target. It checks for the presence of two preprocessor macros, `FD_HAS_SSE` and `FD_HAS_ALLOCA`. If both are defined, it invokes a function `add-objs` to include the object files `fd_xdp_tile` and `fd_disco` in the build process.
