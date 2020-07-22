# Marine

## Motivation
Various tools like Tshark and Tfshark allow for easy filtering and parsing of packets. However, they're limited by the fact that they only allow a single filter per cap file. So, if for example I want to apply two different filters to the same cap, I'll have to split the cap into two. As I require more and more filters, I'll need to perform more IO operations just to fit myself to the requirements set by Tshark.

This is very tedious and very CPU-intensive. Streaming applications which have to deal with thousands of packets per second can't afford to maintain files for every filter they want to apply, which is where Marine comes in.

### So, what is Marine?
Marine allows to filter and parse packets directly from the memory, without requiring any additional IO.
For example, a streaming application can filter and parse every packet it receives in any way it wishes to without creating files, parsing complicated outputs, etc.

### How it Works
libwireshark has a close-knit relationship with the filesystem; almost every internal struct is affected by and tied to the IO methods. 
Marine "fakes" many of these relationships with the filesystem, to allow a simple input of byte array and output as a struct to the memory. Using various clients (under my profile), you can use these features to parse and filter packets as you wish.

## Clients
[Python Client](https://github.com/tomlegkov/marine-python)

## Installation
Clone the repository under the "marine" branch, and compile it as you would compile Wireshark normally (make sure you have libpcap-dev installed). 
After the compilation you'll receive libmarine.so which you can then load using your favorite language. 

## Usage
The usage is described in C, however it can be applied to any language that will load libmarine.so and call its functions.

0. Possible errors for initializing Marine (calling init_marine()):

    | Value         | Condition     |
    | ------------- |:-------------:|
    | -1    | Internal Error      			   |
    | -2    | Marine was already initialized               |


1. 
    Add a filter (or many as you'd like). A filter contains a BPF, a display filter and output fields.
    Every parameter is optional. If it's passed as NULL, it won't be applied to the packet.

    So for example, if you pass output fields without BPF or display filter, the packet will be parsed without any filtering.
    If you only pass a filter (BPF/display filter) without output fields, the packet will be filtered without any parsing.
    
    The result is a filter id (id >= 0). If the id is smaller than 0, it's an error (bad filter / bad output fields).
    ```c
    char err_msg[512];
    char *fields[] = {"ip.src", "frame.number"}; // If you don't want fields set it to NULL and pass 0 instead of 2
    int filter_id = marine_add_filter("a bpf or NULL", "a display filter or NULL", fields, 2, err_msg);
    ```
   
    Possible errors (`err_msg` will be filled with an error message):
    
    | Value         | Condition     |
    | ------------- |:-------------:|
    | -1    | bad BPF                                       |
    | -2    | bad display filter                            |
    | -3    | one or more of the output fields isn't valid  |

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
    `marine_result` contains two fields:
    ```c
    typedef struct {
        char *output;
        int result;
    } marine_result;
    ```
   
    `result` can be one of the following values:
    
    | Value         | Condition     |
    | ------------- |:-------------:|
    | -1 | `filter_id` doesn't exist                                     |
    | 0  | The packet didn't pass the filter                             |
    | 1  | The packet passed the filter (or a filter wasn't supplied)    |
    
    `output` will contain the requested `fields` in a CSV format (without headers - the order is the same as the provided array), separated by `\t` with double quotes (`"`).

5. Free the result with `marine_free(result)`.

---

Tom Legkov <tom.legkov@outlook.com>

