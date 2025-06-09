# Purpose
This file is a Makefile snippet used in a build system. It conditionally includes a header file and defines a unit test target if the macro `FD_HAS_INT128` is defined, indicating support for 128-bit integers. The unit test `test_log_collector` is configured to link against the `fd_flamenco`, `fd_ballet`, and `fd_util` libraries.
