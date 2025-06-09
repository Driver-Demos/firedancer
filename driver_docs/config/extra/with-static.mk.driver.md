# Purpose
This file is a Makefile snippet that sets a linker flag to produce a fully static build of a software application. By appending `-static` to the `LDFLAGS` variable, it instructs the linker to include all necessary libraries within the executable, resulting in a standalone binary that does not rely on shared libraries, specifically noting incompatibility with glibc.
