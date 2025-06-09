# Purpose
This file is a Makefile snippet used for conditional compilation. It checks for the presence of the `FD_HAS_INT128` flag to include headers and objects related to `fd_zksdk` and `fd_flamenco`. If the `FD_HAS_HOSTED` flag is also defined, it sets up a unit test for `test_zksdk` with dependencies on `fd_flamenco`, `fd_ballet`, and `fd_util`.
