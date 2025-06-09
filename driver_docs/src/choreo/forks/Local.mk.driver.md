# Purpose
This is a Makefile snippet used in a build system to conditionally include headers, objects, and unit tests if the macro `FD_HAS_INT128` is defined. It adds `fd_forks.h` to the headers, `fd_forks` and `fd_choreo` to the objects, and sets up a unit test named `test_forks` that depends on the `fd_choreo`, `fd_flamenco`, `fd_ballet`, and `fd_util` components.
