# Purpose
This is a Makefile snippet used in a build system to conditionally add object files to a build target. It checks for the presence of two features, `FD_HAS_INT128` and `FD_HAS_SSE`, and if both are defined, it adds the object files `fd_plugin_tile`, `fd_disco`, and `fd_flamenco` to the build process using the `add-objs` function.
