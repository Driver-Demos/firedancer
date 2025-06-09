# Purpose
This is a Makefile snippet used for conditional compilation and testing within a software project. It checks if the `FD_HAS_HOSTED` and `FD_HAS_LINUX` conditions are met, and if so, it compiles the `fd_fibre` library, adds its object files, creates a unit test named `test_fibre` that depends on `fd_fibre` and `fd_util`, and then runs the unit test `test_fibre`.
