# Purpose
This file is a Makefile snippet used in a build system to conditionally include headers and objects based on the presence of a feature macro `FD_HAS_INT128`. If `FD_HAS_INT128` is defined, it adds `fd_epoch.h` to the headers and `fd_epoch` and `fd_choreo` to the objects for compilation.
