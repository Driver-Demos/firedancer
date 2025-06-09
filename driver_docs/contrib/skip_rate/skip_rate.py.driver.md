# Purpose
This Python script is designed to interact with the Solana blockchain's testnet API to analyze the performance of a specific validator, identified by the public key `fdVa1oF2FtLq4b5T4HFxTjsgeWSCztDCqwxFegjYbZH`, during a given epoch. The script retrieves epoch information and leader schedules, then determines which slots were successfully processed by the validator and which were missed. It further distinguishes between slots missed due to the validator being offline and those missed for other reasons. The script calculates and prints the skip rate and an adjusted skip rate that accounts for offline periods, providing insights into the validator's operational efficiency.

The script uses the `requests` library to send JSON-RPC requests to the Solana testnet API, retrieving data about the current epoch and the validator's leader schedule. It processes this data to identify missed and made leader slots, then checks surrounding slots to determine if missed slots were due to the validator being offline. The script outputs detailed statistics, including the skip rate, adjusted skip rate, and counts of made and truly skipped slots, offering a comprehensive view of the validator's performance. This script is a standalone utility, not intended for import as a library, and it does not define any public APIs or external interfaces.
# Imports and Dependencies

---
- `requests`
- `time`


# Global Variables

---
### api\_endpoint
- **Type**: `string`
- **Description**: The `api_endpoint` variable is a string that holds the URL of the Solana testnet API endpoint. It is used to make HTTP POST requests to interact with the Solana blockchain, specifically for retrieving epoch information and leader schedules.
- **Use**: This variable is used as the target URL for HTTP requests to the Solana testnet API.


---
### json\_data
- **Type**: `dict`
- **Description**: The `json_data` variable is a dictionary that represents a JSON-RPC request payload. It is used to interact with the Solana blockchain API, specifically to request information about the leader schedule for a given validator identity. The dictionary contains keys such as 'jsonrpc', 'id', 'method', and 'params', which are standard components of a JSON-RPC request.
- **Use**: This variable is used to send requests to the Solana API to retrieve leader schedule information and block data for specific slots.


---
### fd\_validator
- **Type**: `string`
- **Description**: The variable `fd_validator` is a string that represents the identity of a validator in the Solana blockchain network. It is used to identify the validator for which leader slots and block information are being queried.
- **Use**: This variable is used to specify the validator identity in API requests to the Solana network to retrieve leader schedule and block information.


---
### response
- **Type**: `requests.models.Response`
- **Description**: The `response` variable is an instance of the `Response` object from the `requests` library, which represents the HTTP response received from making a POST request to the specified API endpoint. It contains information such as the status code, response headers, and the response body, which can be accessed and processed to determine the outcome of the request.
- **Use**: This variable is used to store the HTTP response from the API requests made to the Solana testnet, allowing the program to check the status and content of the response for further processing.


---
### epoch\_json
- **Type**: `dict`
- **Description**: The `epoch_json` variable is a dictionary that stores the result of a JSON response from a POST request to the Solana API endpoint. This response contains information about the current epoch, including details such as the epoch number and slot indices.
- **Use**: This variable is used to extract and store epoch-related data from the API response for further processing and analysis in the script.


---
### cur\_epoch
- **Type**: `int`
- **Description**: The `cur_epoch` variable is an integer that represents the current epoch number retrieved from the Solana blockchain API response. It is extracted from the JSON response under the key 'epoch'.
- **Use**: This variable is used to store and print the current epoch number for further processing in the script.


---
### end\_slot
- **Type**: `int`
- **Description**: The `end_slot` variable is an integer that represents the absolute slot number at the end of the current epoch. It is derived from the 'absoluteSlot' key in the `epoch_json` dictionary, which is obtained from the response of a Solana API call.
- **Use**: This variable is used to determine the upper limit for the leader slots that have occurred in the current epoch.


---
### start\_slot
- **Type**: `int`
- **Description**: The `start_slot` variable is an integer that represents the starting slot number for the current epoch. It is calculated by subtracting the `slotIndex` from the `absoluteSlot` obtained from the `epoch_json` data.
- **Use**: This variable is used to adjust the leader slots to the correct slot numbers for the current epoch.


---
### leader\_slots
- **Type**: `list`
- **Description**: The `leader_slots` variable is a list that contains the adjusted slot numbers for a specific validator's leadership schedule within the current epoch. It is derived by adding the `start_slot` to each slot in the initial `leader_slots` list obtained from the API response, and filtering out any slots that are beyond the `end_slot`. This ensures that only slots that have already occurred are considered.
- **Use**: This variable is used to track the slots where the validator was scheduled to lead, allowing the program to determine which slots were missed and which were successfully led.


---
### missed\_leaders
- **Type**: `list`
- **Description**: The `missed_leaders` variable is a list that stores the slots that were missed by the validator during the current epoch. A slot is considered missed if the API response for that slot contains an error, indicating that the block was not produced or confirmed.
- **Use**: This variable is used to keep track of the slots that were not successfully processed by the validator, which is later used to calculate the skip rate and adjusted skip rate.


---
### made\_leaders
- **Type**: `list`
- **Description**: The `made_leaders` variable is a list that stores the slots for which the leader successfully produced a block. It is populated by iterating over the `leader_slots` and checking if a block was successfully retrieved for each slot.
- **Use**: This variable is used to keep track of the slots where the leader was able to produce a block, which is later used to calculate the adjusted skip rate.


---
### true\_skipped\_slots
- **Type**: `list`
- **Description**: The `true_skipped_slots` variable is a list that stores slots which were actually skipped by the validator due to reasons other than being offline. It is populated by checking surrounding slots for validator activity to determine if the validator was online but still missed the slot.
- **Use**: This variable is used to calculate the adjusted skip rate by identifying slots that were genuinely skipped by the validator.


---
### skip\_rate
- **Type**: `float`
- **Description**: The `skip_rate` variable is a floating-point number that represents the proportion of leader slots that were missed during a given epoch. It is calculated by dividing the number of missed leader slots (`missed_leaders`) by the total number of leader slots (`leader_slots`).
- **Use**: This variable is used to quantify the frequency of missed leader slots in the context of Solana's epoch leader schedule.


---
### adjusted\_skip\_rate
- **Type**: `float`
- **Description**: The `adjusted_skip_rate` is a floating-point number that represents the proportion of slots that were truly skipped by a validator, adjusted for periods when the validator was offline. It is calculated by dividing the number of truly skipped slots by the sum of made leaders and truly skipped slots.
- **Use**: This variable is used to provide a more accurate skip rate by accounting for offline periods, helping to assess the validator's performance more precisely.


