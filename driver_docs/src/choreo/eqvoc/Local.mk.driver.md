# Purpose
This file is a Makefile snippet used for conditional compilation. It checks if the `FD_HAS_INT128` flag is defined, and if so, it adds headers and objects related to `fd_eqvoc` and `fd_choreo`. Additionally, if the `FD_HAS_HOSTED` flag is also defined, it sets up a unit test for `test_eqvoc` with dependencies on `fd_choreo`, `fd_flamenco`, `fd_ballet`, and `fd_util`.
