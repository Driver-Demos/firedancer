# Purpose
This file is a Makefile snippet used for conditional compilation and testing in a software build process. It checks for the presence of the `FD_HAS_INT128` flag to include headers and objects related to `fd_genesis_create` and `fd_flamenco`. If the `FD_HAS_HOSTED` flag is also set, it defines and runs a unit test for `test_genesis_create` using specified dependencies.
