# Purpose
This file is a Makefile snippet used for conditional compilation. It checks if the macro `FD_HAS_INT128` is defined, and if so, it adds `fd_rewards.h` to the list of headers and `fd_rewards` and `fd_flamenco` to the list of object files to be compiled. This ensures that these components are only included in the build process when 128-bit integer support is available.
