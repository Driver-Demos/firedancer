# Purpose
This is a Makefile used to automate the build process for generating `keywords.c` and `keywords.h` files. It specifies that these files depend on `genkeywords.cxx` and `keywords.txt`, and includes a rule to compile `genkeywords.cxx` into an executable named `genkeywords`, run this executable to generate the required files, and then remove the executable.
