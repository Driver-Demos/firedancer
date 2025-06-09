# Purpose
The provided Python script, `gen_features.py`, is designed to automate the generation of C header and source files (`fd_features_generated.h` and `fd_features_generated.c`) from a JSON file (`feature_map.json`). This script is a utility tool that reads feature definitions from the JSON file, processes them, and outputs C code that defines a union structure (`fd_features`) and an array of feature identifiers (`ids`). The script uses the `struct` and `base58` modules to decode public keys and convert them into a format suitable for C code, ensuring that each feature is represented with a unique identifier and associated metadata.

The script is structured as a command-line tool, utilizing the `argparse` module to handle input arguments for specifying the paths of the feature map, header, and body files. The main function orchestrates the process by parsing these arguments and invoking the [`generate`](#generate) function, which performs the core task of reading the JSON data, constructing the C code, and writing it to the specified files. This script is intended for developers who need to maintain a consistent and automated way of generating C code from feature definitions, ensuring that any changes in the feature map are accurately reflected in the generated C files.
# Imports and Dependencies

---
- `argparse`
- `json`
- `pathlib.Path`
- `struct`
- `base58`


# Functions

---
### generate<!-- {{#callable:firedancer/src/flamenco/features/gen_features.generate}} -->
The `generate` function reads a feature map from a JSON file and generates corresponding C header and source files with feature definitions and metadata.
- **Inputs**:
    - `feature_map_path`: The file path to the JSON file containing the feature map.
    - `header_path`: The file path where the generated C header file will be written.
    - `body_path`: The file path where the generated C source file will be written.
- **Control Flow**:
    - Open the JSON file at `feature_map_path` and load its content into `feature_map`.
    - Open the files at `header_path` and `body_path` for writing the generated C code.
    - Iterate over each feature in the `feature_map` to generate a short ID and append a formatted string to `fd_features_t_params`.
    - Write the C header file content, including the union definition for `fd_features` and the feature count macro, to the `header` file.
    - Define a helper function `pubkey_to_c_array` to convert a public key to a C array string representation.
    - Write the initial part of the C source file, including the array of feature IDs, to the `body` file.
    - Iterate over each feature in the `feature_map` to write its metadata, such as index, ID, name, and optional attributes like `cleaned_up`, `reverted`, and `activated_on_all_clusters`, to the `body` file.
    - Write a switch-case structure in the `body` file to map feature prefixes to their corresponding IDs.
    - Write static assertions to verify the correctness of offset calculations in the `body` file.
- **Output**: The function outputs two files: a C header file and a C source file, containing the generated feature definitions and metadata based on the input feature map.


---
### main<!-- {{#callable:firedancer/src/flamenco/features/gen_features.main}} -->
The `main` function parses command-line arguments to determine file paths and then calls the [`generate`](#generate) function to create feature-related header and body files.
- **Inputs**: None
- **Control Flow**:
    - The function starts by determining the directory of the current script using `Path(__file__).parent`.
    - An `ArgumentParser` object is created to handle command-line arguments.
    - Three arguments are added to the parser: `--feature_map`, `--header`, and `--body`, each with a default path based on the script's directory.
    - The parsed arguments are stored in the `args` variable.
    - The [`generate`](#generate) function is called with the paths specified in `args.feature_map`, `args.header`, and `args.body`.
- **Output**: The function does not return any value; it performs file generation as a side effect.
- **Functions called**:
    - [`firedancer/src/flamenco/features/gen_features.generate`](#generate)


