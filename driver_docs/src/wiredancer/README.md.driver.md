# Purpose
The provided content is a comprehensive documentation for configuring and utilizing the WireDancer (WD) functionalities within a software system, specifically targeting AWS-F1 series FPGA instances. This file serves a broad purpose, detailing the setup, building, and execution processes for integrating WD with the FD (presumably a larger framework or application). It includes specific instructions for initializing and freeing PCIe resources, building and running the WD on AWS-F1 instances, and configuring the FD system to support WD functionalities. A significant portion of the document is dedicated to the WD.SigVerify component, which is a hardware-accelerated solution for ED25519 signature verification, designed to achieve high throughput using FPGA technology. The document outlines the asynchronous API used by WD, the design principles behind WD.SigVerify, and the detailed pipeline architecture that enables efficient parallel processing without batching. This file is crucial for developers working with the WireDancer system, providing them with the necessary steps and technical details to effectively deploy and utilize the hardware acceleration capabilities offered by WD on AWS infrastructure.
# Content Summary
The provided document is a comprehensive guide for developers working with the WireDancer (WD) functionalities, specifically focusing on its integration with the FPGA-based AWS-F1 series and the SigVerify process. The document is structured into several sections, each detailing critical aspects of building, running, and utilizing WD within the FD (presumably a larger framework or system).

### Key Components and Functionalities:

1. **Supported Platforms and Functions:**
   - The document specifies that the WireDancer functionalities are designed for the AWS-F1 series, a type of FPGA-enabled EC2 instance.
   - It highlights the availability of the SigVerify function, which is crucial for signature verification processes.

2. **WD API:**
   - The API section outlines functions for initializing and freeing PCIe resources, which are essential for interfacing with FPGA cards. The `wd_init_pci` function allows for the initialization of multiple cards, while `wd_free_pci` is used to release these resources.

3. **Building and Running WD:**
   - Detailed instructions are provided for building WD on AWS-F1 series instances. This involves cloning the AWS-FPGA repository, replacing specific files, and rebuilding the project.
   - Running WD requires setting up an EC2 F1 machine, installing the necessary SDK, loading the WD image onto the FPGA, and configuring the FD system. The document provides step-by-step commands for these processes, ensuring that developers can replicate the setup accurately.

4. **WD-SigVerify:**
   - SigVerify is a critical component for verifying ED25519 signatures, a computationally intensive task. The document explains how WD uses hardware acceleration to achieve high throughput (1 million verifications per second) with a single FPGA, compared to traditional CPU architectures.
   - The SigVerify API is asynchronous, allowing for efficient request and response handling between software and the accelerator.

5. **Design and Optimization:**
   - The design of WD.SigVerify focuses on maximizing throughput while managing area and latency constraints. The document describes a pipeline design that leverages batchless parallelism, allowing independent processing of requests without batching.
   - A credit-based chain link system is used to manage pipeline throughput and latency, ensuring efficient data flow and processing.

6. **Algorithmic Details:**
   - The document provides a pseudocode breakdown of the ED25519 verification process, detailing each step from SHA-512 hashing to point equality checks. Each step is optimized for FPGA implementation, with specific latency and throughput metrics provided.

Overall, the document serves as a technical manual for developers looking to integrate and optimize WireDancer functionalities within their systems, particularly focusing on the high-performance requirements of signature verification using FPGA technology.
