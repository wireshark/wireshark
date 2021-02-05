# Marine

## Motivation
Various tools like Tshark and Tfshark allow for easy filtering and parsing of packets.
However, they're limited by the fact that they only allow a single filter per cap file. So, if for example we want to apply two different filters to the same cap, we will have to split the cap into two (or run two filters on the same cap).
As we require more and more filters, we'll need to perform more IO operations just to fit ourselves to the requirements set by Tshark.

Streaming applications which have to apply different filters to packets can't use the default APIs exposed by Wireshark, as it will be CPU intensive and slow.
So, Marine offers an API which works per-packet and not per-file.

### So, what is Marine?
Marine allows to filter and parse packets directly from the memory, without requiring any additional IO.
For example, a streaming application can filter and parse every packet it receives in any way it wishes to without creating files, parsing complicated outputs, etc.

## Clients
[Python Client](https://github.com/tomlegkov/marine-python)

## Installation
Clone the repository under the "marine" branch, and compile it as you would compile Wireshark normally (make sure you have libpcap-dev installed). 
After the compilation you'll receive libmarine.so which you can then load using your favorite language. 

## Usage
The usage is described in C, however it can be applied to any language that will load libmarine.so and call its functions.

0. Initialize Marine with `marine_init()`. Possible return values are:
   
    | Const         | Value         | Condition     |
    |:-------------:|:-------------: |:-------------:|
    | - | 0 | Success |
    |`MARINE_INIT_INTERNAL_ERROR_CODE` | -1 | Internal error |
    |`MARINE_ALREADY_INITIALIZED_ERROR_CODE`| -2 | Marine was already initialized |


1. 
    Add a filter with `marine_add_filter`:
    ```c
    int marine_add_filter(char *bpf, char *dfilter, char **fields, int* macro_indices, unsigned int fields_len, int wtap_encap, char **err_msg);
   ```
    * `bpf`: Standard BPF (can be `NULL`)
    * `dfilter`: A wireshark-style display filter (can be `NULL`)
    * `fields`: An array of wireshark-style fields to parse from the packet, for example `ip.src` and `ip.dst` (can be `NULL`)
    * `macro_indices`: 
        Only for advanced usage, allows for the usage of "macros".
        For example, if we want to extract an IP address from a packet without knowing ahead of time if the packet is IPv4 or IPv6,
        we can define the macro (python-style): `{"macro.ip.src": ["ip.src", "ipv6.src"]}`.
        If we call `marine_add_filter` with `fields=["eth.src", "ip.src", "ipv6.src"]` and `macro_indices=[0, 1, 1]`,
        we specify to Marine that `ip.src` and `ipv6.src` should be mapped to the same field (i.e if both exist in the packet, only choose the first).
    * `fields_len`: Length of the `fields` parameter (`0` if `fields == NULL`)
    * `wtap_encap`: Encapsulation of the packet. Marine exports the consts `ETHERNET_ENCAP` and `WIFI_ENCAP` (but all encapsulation types are supported). 
    * `err_msg`: If an error occurs, it will be written to the pointer supplied by this argument (remember to free it later).

At least one of the fields `bpf`, `dfilter`, `fields` must be given as a valid argument to the function.   

Example usage:
```c
char *err_msg;
char *bpf = "ip host 1.1.1.1"; // can be NULL
char *display_filter = "tcp.port == 123"; // can be NULL
char *fields[] = {"ip.src", "frame.number"}; // can be NULL (and pass fields_len=0 instead of 2)
int filter_id = marine_add_filter(bpf, display_filter, fields, NULL, 2, ETHERNET_ENCAP, &err_msg);

if (filter_id < 0) {
    fprintf(stderr, "Error while creating filter: %s", err_msg);
    marine_free_err_msg(err_msg); // err_msg is allocated when an error occurs
}
```

On success, a `filter_id >= 0` will be returned. Else, an error code will be returned and `err_msg` will be allocated with an error message.

The possible error codes:

| Const         | Value         | Condition     |
|:-------------:|:-------------: |:-------------:|
| - | `>= 0` | Success |
|`BAD_BPF_ERROR_CODE` | -1 | Bad BPF |
|`BAD_DISPLAY_FILTER_ERROR_CODE`| -2 | Bad display filter |
|`INVALID_FIELD_ERROR_CODE`| -3 | One or more of the output fields isn't valid |


2. 
    Define your packet (without the pcap header!) and its length:
    ```c
    unsigned char packet[] = { ... };
    int len = ...;
    ```

3. 
    Call `marine_dissect_packet`:
    ```c
    marine_result *result = marine_dissect_packet(filter_id, packet, len);
    ```
   
4.
    `marine_result` contains three fields:
    ```c
    typedef struct {
        char **output;
        unsigned int len;
        int result;
    } marine_result;
    ```
   
    `result` can be one of the following values:
    
    | Value         | Condition     |
    | ------------- |:-------------:|
    | -1 | `filter_id` doesn't exist                                     |
    | 0  | The packet didn't pass the filter                             |
    | 1  | The packet passed the filter (or a filter wasn't supplied)    |
    
    `output` is an array of the parsed fields. The order is the same as the `fields` array. 
    `len` is the length of the `output` array.    

    If `macro_indices` were used, the `i` slot will contain the first field that was parsed successfully from the given macro index `i`.

5. Free the result with `marine_free(result)`.

### Other API
Since Wireshark stores a lot of internal state, we need to clear it every once in a while so that applications can run for a long time while using Marine.

The API supplied by Marine allows to specify how many packets to parse before clearing the internal state with:
`void set_epan_auto_reset_count(guint32 auto_reset_count);`
