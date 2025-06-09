# Purpose
This Makefile snippet checks for the presence of the `liblz4.a` library in a specified directory (`$(OPT)/lib`). If the library is found, it sets a flag (`FD_HAS_LZ4`) and updates the compiler (`CFLAGS`) and linker (`LDFLAGS`) flags to include LZ4 support. If the library is not found, it outputs a message indicating that LZ4 is not installed and skips the related configuration.
