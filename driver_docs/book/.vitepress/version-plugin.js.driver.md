# Purpose
This code provides a specific functionality as a module intended to be imported and used elsewhere, likely within a build or documentation generation process. It defines a function `getLatestRelease` that fetches the latest release version of a specified GitHub repository using the GitHub API. The main exported function, `latestVersion`, utilizes `getLatestRelease` to obtain the latest version of the 'firedancer-io/firedancer' repository and returns a plugin object. This plugin object is designed to transform code, specifically replacing occurrences of `__FD_LATEST_VERSION__` in markdown files with the fetched version number. The code is narrowly focused on integrating version information into markdown files, suggesting its use in a documentation or build system where dynamic versioning is required.
# Functions

---
### getLatestRelease
The function `getLatestRelease` fetches the latest release tag name from a specified GitHub repository.
- **Inputs**:
    - `owner`: The GitHub username or organization name that owns the repository.
    - `repo`: The name of the repository from which to fetch the latest release.
- **Control Flow**:
    - Constructs a URL to access the latest release of the specified GitHub repository using the provided owner and repo parameters.
    - Performs a fetch request to the constructed URL with a header to accept GitHub's v3 API JSON format.
    - Checks if the response is not okay (i.e., not a successful HTTP status) and throws an error if so.
    - Parses the response as JSON if the fetch is successful.
    - Extracts and returns the 'tag_name' from the JSON data, which represents the latest release tag.
    - Catches any errors during the fetch or JSON parsing process and logs an error message to the console.
- **Output**: The function returns a promise that resolves to the tag name of the latest release from the specified GitHub repository.


---
### latestVersion
The `latestVersion` function retrieves the latest release version of the 'firedancer' repository and returns a plugin object that replaces a placeholder in markdown files with this version.
- **Inputs**: None
- **Control Flow**:
    - Calls `getLatestRelease` with 'firedancer-io' as the owner and 'firedancer' as the repository to fetch the latest release version.
    - Waits for the promise returned by `getLatestRelease` to resolve with the latest version tag.
    - Returns a plugin object with a `name` property set to 'version-plugin' and a `transform` method.
    - The `transform` method checks if the file ID ends with '.md'.
    - If the file is a markdown file, it replaces all occurrences of `__FD_LATEST_VERSION__` in the code with the fetched version.
    - If the file is not a markdown file, it returns the code unchanged.
- **Output**: A promise that resolves to a plugin object with a `name` and a `transform` method for processing markdown files.


