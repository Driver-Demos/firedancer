## Folders
- **[extra](config/extra.driver.md)**: The `extra` folder in the `firedancer` codebase contains a collection of makefile configurations that set up various build settings, including compiler and linker flags, for different environments, architectures, and tools such as fuzz testing, sanitizers, and specific libraries.
- **[machine](config/machine.driver.md)**: The `machine` folder in the `firedancer` codebase contains various makefile configurations for setting up build environments across different operating systems and architectures, including Linux, FreeBSD, macOS, and specific CPU architectures like Haswell, Ice Lake, Zen, ARM, Power9, RISC-V, and s390x, using both Clang and GCC compilers.

## Files
- **[base.mk](config/base.mk.driver.md)**: The `base.mk` file in the `firedancer` codebase sets up various build configurations and toolchain settings, including compiler flags, directory paths, and tool definitions for building the project.
- **[everything.mk](config/everything.mk.driver.md)**: The `everything.mk` file in the `firedancer` codebase is a comprehensive Makefile that defines build rules, targets, and auxiliary functions for compiling, testing, and generating reports for various components of the project, including binaries, libraries, unit tests, integration tests, and fuzz tests.
