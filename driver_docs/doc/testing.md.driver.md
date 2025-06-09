# Purpose
This document is a comprehensive guide for configuring and running tests for the Firedancer software, primarily focusing on system requirements, test execution, and best practices. It outlines the "Golden Configuration," which specifies the optimal system setup for testing, including kernel versions, operating systems, compilers, CPU types, and memory configurations. The document categorizes tests into unit tests and fuzz tests, providing detailed instructions on how to configure and execute them using Makefile commands. It also discusses the integration of fuzzing engines and sanitizers to enhance error detection and test reliability. The guide emphasizes best practices for test determinism, memory management, and the use of static variables, ensuring that tests are robust, repeatable, and efficient. This file is crucial for developers and testers within the Firedancer codebase, as it standardizes the testing process and helps maintain code quality across different environments.
# Content Summary
The provided document is a comprehensive guide for configuring and running tests for the Firedancer software. It outlines the optimal system configuration, test execution procedures, and best practices for developers working with the Firedancer codebase.

### Golden Configuration
The document specifies the most reliable system configuration for running tests, which includes using Linux kernel version 4.18 or newer, operating systems like RHEL 8 or Ubuntu 22.04, and compilers such as GCC 12 or Clang 15. It recommends using CPUs like Icelake Server or Epyc 2, with memory configured to reserve 2 gigantic pages per core via `fd_shmem_cfg`. This setup minimizes system noise and ensures consistent test results.

### Quick Start and Test Configuration
For a quick start, the document provides commands to allocate memory and run unit tests. It details the structure and execution of unit tests, which are C programs located in the `/src` directory. These tests are designed to run automatically without command-line parameters, using a single thread and completing within 5 minutes. The document also explains how to configure these tests in `Local.mk` files.

### Fuzz Tests
Fuzz tests are used to verify component behavior with arbitrary byte sequences, often combined with sanitizers for error detection. The document provides instructions for setting up fuzz tests using different engines like libFuzzer, AFL++, and Honggfuzz, each with specific compile commands and requirements. It also explains how to use a stub engine for regression testing when no fuzzing engine is available.

### Sanitizers
The document describes various sanitizers that can be used to perform runtime checks, such as AddressSanitizer, UndefinedBehaviorSanitizer, and MemorySanitizer. These tools help detect memory issues and undefined behavior, although they are not recommended for production environments.

### Best Practices
The document emphasizes best practices for testing, including ensuring test determinism, avoiding external inputs, and managing memory efficiently. It advises against using `malloc()` in tests and recommends using static variables or shared memory for memory allocation. Detailed instructions are provided for setting up memory workspaces using `fd_wksp_new_anonymous` and related functions.

Overall, this document serves as a detailed reference for developers to configure their systems, execute tests, and adhere to best practices when working with the Firedancer software.
