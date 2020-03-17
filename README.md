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

## Installation
Clone the repository under the "marine" branch, and compile it as you would compile Wireshark normally. 
After the compilation you'll receive libmarine.so which you can then load using your favorite language. 

Tom Legkov <tom.legkov@outlook.com>

