# Purpose
This Bash script is designed to automate the process of downloading specific files from a remote repository and modifying them for local use. It provides narrow functionality, focusing specifically on fetching a set of files from a specified version (tag) of the nanopb library hosted on GitHub. The script reads the desired repository tag from a local file named `nanopb_tag.txt`, then constructs URLs to download a predefined list of files, which include both header and source files related to nanopb. After downloading, it performs a text replacement in each file to change an `#include` directive, suggesting that these files are being adapted for integration into a different project environment. This script is not an executable or a library but rather a utility script intended to facilitate setup or maintenance tasks in a development workflow.
# Global Variables

---
### SCRIPT\_DIR
- **Type**: `string`
- **Description**: `SCRIPT_DIR` is a string variable that stores the absolute path of the directory where the script is located. It is determined by using the `dirname` command on the script's source path and resolving it to an absolute path with `pwd`. This ensures that any file operations within the script are relative to the script's location.
- **Use**: `SCRIPT_DIR` is used to construct file paths for downloading and saving files in the same directory as the script.


---
### REPO\_URL
- **Type**: `string`
- **Description**: The `REPO_URL` variable is a string that holds the base URL of the GitHub repository for the nanopb project. It is used to construct the full URL for downloading specific files from the repository.
- **Use**: This variable is used as the base URL to fetch files from the nanopb GitHub repository by appending the repository tag and file names to it.


---
### REPO\_TAG
- **Type**: `string`
- **Description**: The `REPO_TAG` variable is a string that holds the content of the file `nanopb_tag.txt`. This file is expected to contain a specific tag or version identifier for the nanopb repository.
- **Use**: `REPO_TAG` is used to construct URLs for downloading specific versions of files from the nanopb repository.


---
### FILES
- **Type**: `array of strings`
- **Description**: The `FILES` variable is a global array of strings that lists the filenames of source and header files related to the nanopb library. These files include both C source files and header files necessary for the nanopb library's functionality.
- **Use**: This variable is used to iterate over each filename in the array to download the corresponding file from a specified repository URL and perform a text replacement operation on each file.


