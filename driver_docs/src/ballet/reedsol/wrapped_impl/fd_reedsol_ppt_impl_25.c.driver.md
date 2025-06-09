# Purpose
This C source code file is an auto-generated implementation of a series of functions related to Reed-Solomon error correction, specifically for generating parity parts in a 32-symbol block with varying numbers of data symbols. Each function, named `fd_reedsol_ppt_32_N`, where `N` ranges from 25 to 31, is designed to handle a specific configuration of data and parity symbols. The functions take pointers to 32 Galois field elements (`gf_t`), which represent the input data symbols, and perform operations to generate the necessary parity symbols using the `FD_REEDSOL_GENERATE_PPT` macro. This macro is likely defined in the included header file `fd_reedsol_ppt.h`, which is not shown here but is crucial for the actual parity generation logic.

The file provides a narrow functionality focused on Reed-Solomon coding, a method widely used for error detection and correction in data transmission and storage. The functions are marked with `FD_FN_UNSANITIZED`, indicating that they may not perform input validation or error checking, which is typical for performance-critical code where inputs are assumed to be pre-validated. This file is part of a larger library or system, as suggested by the inclusion of a relative path header file, and is intended to be used as part of a Reed-Solomon encoding process. The functions do not define public APIs or external interfaces directly but are likely part of an internal implementation that supports higher-level error correction functionalities.
# Imports and Dependencies

---
- `../fd_reedsol_ppt.h`


# Functions

---
### fd\_reedsol\_ppt\_32\_25<!-- {{#callable:fd_reedsol_ppt_32_25}} -->
The function `fd_reedsol_ppt_32_25` performs a Reed-Solomon encoding operation on 32 input elements using a specific configuration and updates the input pointers with the results.
- **Inputs**:
    - `_in00`: Pointer to the first input element of type `gf_t`.
    - `_in01`: Pointer to the second input element of type `gf_t`.
    - `_in02`: Pointer to the third input element of type `gf_t`.
    - `_in03`: Pointer to the fourth input element of type `gf_t`.
    - `_in04`: Pointer to the fifth input element of type `gf_t`.
    - `_in05`: Pointer to the sixth input element of type `gf_t`.
    - `_in06`: Pointer to the seventh input element of type `gf_t`.
    - `_in07`: Pointer to the eighth input element of type `gf_t`.
    - `_in08`: Pointer to the ninth input element of type `gf_t`.
    - `_in09`: Pointer to the tenth input element of type `gf_t`.
    - `_in10`: Pointer to the eleventh input element of type `gf_t`.
    - `_in11`: Pointer to the twelfth input element of type `gf_t`.
    - `_in12`: Pointer to the thirteenth input element of type `gf_t`.
    - `_in13`: Pointer to the fourteenth input element of type `gf_t`.
    - `_in14`: Pointer to the fifteenth input element of type `gf_t`.
    - `_in15`: Pointer to the sixteenth input element of type `gf_t`.
    - `_in16`: Pointer to the seventeenth input element of type `gf_t`.
    - `_in17`: Pointer to the eighteenth input element of type `gf_t`.
    - `_in18`: Pointer to the nineteenth input element of type `gf_t`.
    - `_in19`: Pointer to the twentieth input element of type `gf_t`.
    - `_in20`: Pointer to the twenty-first input element of type `gf_t`.
    - `_in21`: Pointer to the twenty-second input element of type `gf_t`.
    - `_in22`: Pointer to the twenty-third input element of type `gf_t`.
    - `_in23`: Pointer to the twenty-fourth input element of type `gf_t`.
    - `_in24`: Pointer to the twenty-fifth input element of type `gf_t`.
    - `_in25`: Pointer to the twenty-sixth input element of type `gf_t`.
    - `_in26`: Pointer to the twenty-seventh input element of type `gf_t`.
    - `_in27`: Pointer to the twenty-eighth input element of type `gf_t`.
    - `_in28`: Pointer to the twenty-ninth input element of type `gf_t`.
    - `_in29`: Pointer to the thirtieth input element of type `gf_t`.
    - `_in30`: Pointer to the thirty-first input element of type `gf_t`.
    - `_in31`: Pointer to the thirty-second input element of type `gf_t`.
- **Control Flow**:
    - The function begins by dereferencing each of the 32 input pointers to obtain the actual `gf_t` values and assigns them to local variables `in00` to `in31`.
    - It then calls the macro `FD_REEDSOL_GENERATE_PPT` with the parameters 32, 25, and the local variables `in00` to `in31`, which performs the Reed-Solomon encoding operation.
    - After the macro call, the function updates the original input pointers with the potentially modified values from the local variables `in00` to `in31`.
- **Output**: The function does not return a value; it modifies the input data in place.


---
### fd\_reedsol\_ppt\_32\_26<!-- {{#callable:fd_reedsol_ppt_32_26}} -->
The function `fd_reedsol_ppt_32_26` performs a Reed-Solomon encoding operation on 32 input elements using a specific configuration and updates the input pointers with the results.
- **Inputs**:
    - `_in00`: Pointer to the first input element of type `gf_t`.
    - `_in01`: Pointer to the second input element of type `gf_t`.
    - `_in02`: Pointer to the third input element of type `gf_t`.
    - `_in03`: Pointer to the fourth input element of type `gf_t`.
    - `_in04`: Pointer to the fifth input element of type `gf_t`.
    - `_in05`: Pointer to the sixth input element of type `gf_t`.
    - `_in06`: Pointer to the seventh input element of type `gf_t`.
    - `_in07`: Pointer to the eighth input element of type `gf_t`.
    - `_in08`: Pointer to the ninth input element of type `gf_t`.
    - `_in09`: Pointer to the tenth input element of type `gf_t`.
    - `_in10`: Pointer to the eleventh input element of type `gf_t`.
    - `_in11`: Pointer to the twelfth input element of type `gf_t`.
    - `_in12`: Pointer to the thirteenth input element of type `gf_t`.
    - `_in13`: Pointer to the fourteenth input element of type `gf_t`.
    - `_in14`: Pointer to the fifteenth input element of type `gf_t`.
    - `_in15`: Pointer to the sixteenth input element of type `gf_t`.
    - `_in16`: Pointer to the seventeenth input element of type `gf_t`.
    - `_in17`: Pointer to the eighteenth input element of type `gf_t`.
    - `_in18`: Pointer to the nineteenth input element of type `gf_t`.
    - `_in19`: Pointer to the twentieth input element of type `gf_t`.
    - `_in20`: Pointer to the twenty-first input element of type `gf_t`.
    - `_in21`: Pointer to the twenty-second input element of type `gf_t`.
    - `_in22`: Pointer to the twenty-third input element of type `gf_t`.
    - `_in23`: Pointer to the twenty-fourth input element of type `gf_t`.
    - `_in24`: Pointer to the twenty-fifth input element of type `gf_t`.
    - `_in25`: Pointer to the twenty-sixth input element of type `gf_t`.
    - `_in26`: Pointer to the twenty-seventh input element of type `gf_t`.
    - `_in27`: Pointer to the twenty-eighth input element of type `gf_t`.
    - `_in28`: Pointer to the twenty-ninth input element of type `gf_t`.
    - `_in29`: Pointer to the thirtieth input element of type `gf_t`.
    - `_in30`: Pointer to the thirty-first input element of type `gf_t`.
    - `_in31`: Pointer to the thirty-second input element of type `gf_t`.
- **Control Flow**:
    - Each input pointer is dereferenced to obtain the corresponding `gf_t` value.
    - The `FD_REEDSOL_GENERATE_PPT` macro is called with 32 input values and the parameters 32 and 26, which likely performs the Reed-Solomon encoding operation.
    - The results of the encoding operation are stored back into the original input pointers.
- **Output**: The function does not return a value; it modifies the input pointers in place with the encoded results.


---
### fd\_reedsol\_ppt\_32\_27<!-- {{#callable:fd_reedsol_ppt_32_27}} -->
The function `fd_reedsol_ppt_32_27` processes 32 input elements using a Reed-Solomon error correction algorithm with 27 data elements and updates the input pointers with the processed values.
- **Inputs**:
    - `_in00`: Pointer to the first input element of type `gf_t`.
    - `_in01`: Pointer to the second input element of type `gf_t`.
    - `_in02`: Pointer to the third input element of type `gf_t`.
    - `_in03`: Pointer to the fourth input element of type `gf_t`.
    - `_in04`: Pointer to the fifth input element of type `gf_t`.
    - `_in05`: Pointer to the sixth input element of type `gf_t`.
    - `_in06`: Pointer to the seventh input element of type `gf_t`.
    - `_in07`: Pointer to the eighth input element of type `gf_t`.
    - `_in08`: Pointer to the ninth input element of type `gf_t`.
    - `_in09`: Pointer to the tenth input element of type `gf_t`.
    - `_in10`: Pointer to the eleventh input element of type `gf_t`.
    - `_in11`: Pointer to the twelfth input element of type `gf_t`.
    - `_in12`: Pointer to the thirteenth input element of type `gf_t`.
    - `_in13`: Pointer to the fourteenth input element of type `gf_t`.
    - `_in14`: Pointer to the fifteenth input element of type `gf_t`.
    - `_in15`: Pointer to the sixteenth input element of type `gf_t`.
    - `_in16`: Pointer to the seventeenth input element of type `gf_t`.
    - `_in17`: Pointer to the eighteenth input element of type `gf_t`.
    - `_in18`: Pointer to the nineteenth input element of type `gf_t`.
    - `_in19`: Pointer to the twentieth input element of type `gf_t`.
    - `_in20`: Pointer to the twenty-first input element of type `gf_t`.
    - `_in21`: Pointer to the twenty-second input element of type `gf_t`.
    - `_in22`: Pointer to the twenty-third input element of type `gf_t`.
    - `_in23`: Pointer to the twenty-fourth input element of type `gf_t`.
    - `_in24`: Pointer to the twenty-fifth input element of type `gf_t`.
    - `_in25`: Pointer to the twenty-sixth input element of type `gf_t`.
    - `_in26`: Pointer to the twenty-seventh input element of type `gf_t`.
    - `_in27`: Pointer to the twenty-eighth input element of type `gf_t`.
    - `_in28`: Pointer to the twenty-ninth input element of type `gf_t`.
    - `_in29`: Pointer to the thirtieth input element of type `gf_t`.
    - `_in30`: Pointer to the thirty-first input element of type `gf_t`.
    - `_in31`: Pointer to the thirty-second input element of type `gf_t`.
- **Control Flow**:
    - The function begins by dereferencing each of the 32 input pointers to obtain the actual `gf_t` values and stores them in local variables `in00` to `in31`.
    - It then calls the macro `FD_REEDSOL_GENERATE_PPT` with parameters `32` and `27`, along with the 32 local variables, to perform the Reed-Solomon error correction processing.
    - After the macro call, the function updates each of the original input pointers with the processed values from the local variables.
- **Output**: The function does not return a value; it modifies the input pointers in place with the processed data.


---
### fd\_reedsol\_ppt\_32\_28<!-- {{#callable:fd_reedsol_ppt_32_28}} -->
The function `fd_reedsol_ppt_32_28` performs a Reed-Solomon encoding operation on 32 input elements, generating 28 parity elements.
- **Inputs**:
    - `_in00`: Pointer to the first input element of type `gf_t`.
    - `_in01`: Pointer to the second input element of type `gf_t`.
    - `_in02`: Pointer to the third input element of type `gf_t`.
    - `_in03`: Pointer to the fourth input element of type `gf_t`.
    - `_in04`: Pointer to the fifth input element of type `gf_t`.
    - `_in05`: Pointer to the sixth input element of type `gf_t`.
    - `_in06`: Pointer to the seventh input element of type `gf_t`.
    - `_in07`: Pointer to the eighth input element of type `gf_t`.
    - `_in08`: Pointer to the ninth input element of type `gf_t`.
    - `_in09`: Pointer to the tenth input element of type `gf_t`.
    - `_in10`: Pointer to the eleventh input element of type `gf_t`.
    - `_in11`: Pointer to the twelfth input element of type `gf_t`.
    - `_in12`: Pointer to the thirteenth input element of type `gf_t`.
    - `_in13`: Pointer to the fourteenth input element of type `gf_t`.
    - `_in14`: Pointer to the fifteenth input element of type `gf_t`.
    - `_in15`: Pointer to the sixteenth input element of type `gf_t`.
    - `_in16`: Pointer to the seventeenth input element of type `gf_t`.
    - `_in17`: Pointer to the eighteenth input element of type `gf_t`.
    - `_in18`: Pointer to the nineteenth input element of type `gf_t`.
    - `_in19`: Pointer to the twentieth input element of type `gf_t`.
    - `_in20`: Pointer to the twenty-first input element of type `gf_t`.
    - `_in21`: Pointer to the twenty-second input element of type `gf_t`.
    - `_in22`: Pointer to the twenty-third input element of type `gf_t`.
    - `_in23`: Pointer to the twenty-fourth input element of type `gf_t`.
    - `_in24`: Pointer to the twenty-fifth input element of type `gf_t`.
    - `_in25`: Pointer to the twenty-sixth input element of type `gf_t`.
    - `_in26`: Pointer to the twenty-seventh input element of type `gf_t`.
    - `_in27`: Pointer to the twenty-eighth input element of type `gf_t`.
    - `_in28`: Pointer to the twenty-ninth input element of type `gf_t`.
    - `_in29`: Pointer to the thirtieth input element of type `gf_t`.
    - `_in30`: Pointer to the thirty-first input element of type `gf_t`.
    - `_in31`: Pointer to the thirty-second input element of type `gf_t`.
- **Control Flow**:
    - The function begins by dereferencing each of the 32 input pointers to obtain the actual `gf_t` values.
    - It then calls the macro `FD_REEDSOL_GENERATE_PPT` with the parameters 32, 28, and the 32 dereferenced input values.
    - The macro performs the Reed-Solomon encoding operation, generating 28 parity elements.
    - Finally, the function updates the original input pointers with the potentially modified values after the encoding operation.
- **Output**: The function does not return a value; it modifies the input pointers in place to reflect the results of the Reed-Solomon encoding operation.


---
### fd\_reedsol\_ppt\_32\_29<!-- {{#callable:fd_reedsol_ppt_32_29}} -->
The function `fd_reedsol_ppt_32_29` performs a Reed-Solomon encoding operation on 32 input elements using a specific configuration of 29 data elements.
- **Inputs**:
    - `_in00`: Pointer to the first input element of type `gf_t`.
    - `_in01`: Pointer to the second input element of type `gf_t`.
    - `_in02`: Pointer to the third input element of type `gf_t`.
    - `_in03`: Pointer to the fourth input element of type `gf_t`.
    - `_in04`: Pointer to the fifth input element of type `gf_t`.
    - `_in05`: Pointer to the sixth input element of type `gf_t`.
    - `_in06`: Pointer to the seventh input element of type `gf_t`.
    - `_in07`: Pointer to the eighth input element of type `gf_t`.
    - `_in08`: Pointer to the ninth input element of type `gf_t`.
    - `_in09`: Pointer to the tenth input element of type `gf_t`.
    - `_in10`: Pointer to the eleventh input element of type `gf_t`.
    - `_in11`: Pointer to the twelfth input element of type `gf_t`.
    - `_in12`: Pointer to the thirteenth input element of type `gf_t`.
    - `_in13`: Pointer to the fourteenth input element of type `gf_t`.
    - `_in14`: Pointer to the fifteenth input element of type `gf_t`.
    - `_in15`: Pointer to the sixteenth input element of type `gf_t`.
    - `_in16`: Pointer to the seventeenth input element of type `gf_t`.
    - `_in17`: Pointer to the eighteenth input element of type `gf_t`.
    - `_in18`: Pointer to the nineteenth input element of type `gf_t`.
    - `_in19`: Pointer to the twentieth input element of type `gf_t`.
    - `_in20`: Pointer to the twenty-first input element of type `gf_t`.
    - `_in21`: Pointer to the twenty-second input element of type `gf_t`.
    - `_in22`: Pointer to the twenty-third input element of type `gf_t`.
    - `_in23`: Pointer to the twenty-fourth input element of type `gf_t`.
    - `_in24`: Pointer to the twenty-fifth input element of type `gf_t`.
    - `_in25`: Pointer to the twenty-sixth input element of type `gf_t`.
    - `_in26`: Pointer to the twenty-seventh input element of type `gf_t`.
    - `_in27`: Pointer to the twenty-eighth input element of type `gf_t`.
    - `_in28`: Pointer to the twenty-ninth input element of type `gf_t`.
    - `_in29`: Pointer to the thirtieth input element of type `gf_t`.
    - `_in30`: Pointer to the thirty-first input element of type `gf_t`.
    - `_in31`: Pointer to the thirty-second input element of type `gf_t`.
- **Control Flow**:
    - The function begins by dereferencing each of the 32 input pointers to obtain the actual `gf_t` values.
    - It then calls the macro `FD_REEDSOL_GENERATE_PPT` with the parameters 32 and 29, along with the 32 dereferenced input values, to perform the Reed-Solomon encoding operation.
    - After the macro call, the function updates each of the original input pointers with the potentially modified `gf_t` values.
- **Output**: The function does not return a value; it modifies the input data in place.


---
### fd\_reedsol\_ppt\_32\_30<!-- {{#callable:fd_reedsol_ppt_32_30}} -->
The function `fd_reedsol_ppt_32_30` performs a Reed-Solomon error correction operation on 32 input elements, updating them in place.
- **Inputs**:
    - `_in00`: Pointer to the first input element of type `gf_t`.
    - `_in01`: Pointer to the second input element of type `gf_t`.
    - `_in02`: Pointer to the third input element of type `gf_t`.
    - `_in03`: Pointer to the fourth input element of type `gf_t`.
    - `_in04`: Pointer to the fifth input element of type `gf_t`.
    - `_in05`: Pointer to the sixth input element of type `gf_t`.
    - `_in06`: Pointer to the seventh input element of type `gf_t`.
    - `_in07`: Pointer to the eighth input element of type `gf_t`.
    - `_in08`: Pointer to the ninth input element of type `gf_t`.
    - `_in09`: Pointer to the tenth input element of type `gf_t`.
    - `_in10`: Pointer to the eleventh input element of type `gf_t`.
    - `_in11`: Pointer to the twelfth input element of type `gf_t`.
    - `_in12`: Pointer to the thirteenth input element of type `gf_t`.
    - `_in13`: Pointer to the fourteenth input element of type `gf_t`.
    - `_in14`: Pointer to the fifteenth input element of type `gf_t`.
    - `_in15`: Pointer to the sixteenth input element of type `gf_t`.
    - `_in16`: Pointer to the seventeenth input element of type `gf_t`.
    - `_in17`: Pointer to the eighteenth input element of type `gf_t`.
    - `_in18`: Pointer to the nineteenth input element of type `gf_t`.
    - `_in19`: Pointer to the twentieth input element of type `gf_t`.
    - `_in20`: Pointer to the twenty-first input element of type `gf_t`.
    - `_in21`: Pointer to the twenty-second input element of type `gf_t`.
    - `_in22`: Pointer to the twenty-third input element of type `gf_t`.
    - `_in23`: Pointer to the twenty-fourth input element of type `gf_t`.
    - `_in24`: Pointer to the twenty-fifth input element of type `gf_t`.
    - `_in25`: Pointer to the twenty-sixth input element of type `gf_t`.
    - `_in26`: Pointer to the twenty-seventh input element of type `gf_t`.
    - `_in27`: Pointer to the twenty-eighth input element of type `gf_t`.
    - `_in28`: Pointer to the twenty-ninth input element of type `gf_t`.
    - `_in29`: Pointer to the thirtieth input element of type `gf_t`.
    - `_in30`: Pointer to the thirty-first input element of type `gf_t`.
    - `_in31`: Pointer to the thirty-second input element of type `gf_t`.
- **Control Flow**:
    - The function begins by dereferencing each of the 32 input pointers to obtain the actual `gf_t` values.
    - It then calls the macro `FD_REEDSOL_GENERATE_PPT` with the parameters 32, 30, and the 32 dereferenced input values, which performs the Reed-Solomon error correction operation.
    - After the macro call, the function updates each of the original input pointers with the potentially modified `gf_t` values.
- **Output**: The function does not return a value; it modifies the input data in place.


---
### fd\_reedsol\_ppt\_32\_31<!-- {{#callable:fd_reedsol_ppt_32_31}} -->
The function `fd_reedsol_ppt_32_31` processes 32 input elements using a Reed-Solomon encoding operation and updates the input pointers with the processed values.
- **Inputs**:
    - `_in00`: Pointer to the first input element of type `gf_t`.
    - `_in01`: Pointer to the second input element of type `gf_t`.
    - `_in02`: Pointer to the third input element of type `gf_t`.
    - `_in03`: Pointer to the fourth input element of type `gf_t`.
    - `_in04`: Pointer to the fifth input element of type `gf_t`.
    - `_in05`: Pointer to the sixth input element of type `gf_t`.
    - `_in06`: Pointer to the seventh input element of type `gf_t`.
    - `_in07`: Pointer to the eighth input element of type `gf_t`.
    - `_in08`: Pointer to the ninth input element of type `gf_t`.
    - `_in09`: Pointer to the tenth input element of type `gf_t`.
    - `_in10`: Pointer to the eleventh input element of type `gf_t`.
    - `_in11`: Pointer to the twelfth input element of type `gf_t`.
    - `_in12`: Pointer to the thirteenth input element of type `gf_t`.
    - `_in13`: Pointer to the fourteenth input element of type `gf_t`.
    - `_in14`: Pointer to the fifteenth input element of type `gf_t`.
    - `_in15`: Pointer to the sixteenth input element of type `gf_t`.
    - `_in16`: Pointer to the seventeenth input element of type `gf_t`.
    - `_in17`: Pointer to the eighteenth input element of type `gf_t`.
    - `_in18`: Pointer to the nineteenth input element of type `gf_t`.
    - `_in19`: Pointer to the twentieth input element of type `gf_t`.
    - `_in20`: Pointer to the twenty-first input element of type `gf_t`.
    - `_in21`: Pointer to the twenty-second input element of type `gf_t`.
    - `_in22`: Pointer to the twenty-third input element of type `gf_t`.
    - `_in23`: Pointer to the twenty-fourth input element of type `gf_t`.
    - `_in24`: Pointer to the twenty-fifth input element of type `gf_t`.
    - `_in25`: Pointer to the twenty-sixth input element of type `gf_t`.
    - `_in26`: Pointer to the twenty-seventh input element of type `gf_t`.
    - `_in27`: Pointer to the twenty-eighth input element of type `gf_t`.
    - `_in28`: Pointer to the twenty-ninth input element of type `gf_t`.
    - `_in29`: Pointer to the thirtieth input element of type `gf_t`.
    - `_in30`: Pointer to the thirty-first input element of type `gf_t`.
    - `_in31`: Pointer to the thirty-second input element of type `gf_t`.
- **Control Flow**:
    - The function begins by dereferencing each of the 32 input pointers to obtain the actual `gf_t` values and stores them in local variables `in00` to `in31`.
    - It then calls the macro `FD_REEDSOL_GENERATE_PPT` with the parameters `32`, `31`, and the 32 local variables, which likely performs a Reed-Solomon encoding operation on these values.
    - After the macro call, the function updates each of the original input pointers with the potentially modified values from the local variables.
- **Output**: The function does not return a value; it modifies the input data in place.


