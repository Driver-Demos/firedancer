# Purpose
This is a Makefile snippet used for conditional compilation. It checks if the `FD_HAS_HOSTED` variable is defined and, if so, adds headers and object files related to `fd_udpsock` and `fd_waltz` to the build process. Additionally, it sets up a unit test named `test_udpsock_echo` that depends on `fd_waltz` and `fd_util`.
