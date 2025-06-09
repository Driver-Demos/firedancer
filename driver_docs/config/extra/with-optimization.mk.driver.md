# Purpose
This Makefile snippet conditionally sets compiler flags for C++ code based on the presence of the `FD_DISABLE_OPTIMIZATION` variable. If the variable is not set, it enables optimization with flags like `-O3` and defines `FD_HAS_OPTIMIZATION` as 1. If the variable is set, it disables optimization with `-O0`. Additionally, it sets the Rust build profile to `release-with-debug`.
