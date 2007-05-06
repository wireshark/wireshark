$Id$

utest.exe is a UUID generator based on the example code provided in RFC4122 and using the gcrypt libraries for the MD5/SHA1 algorithms. It has only been tested on Windows to date.

A Wireshark namespace UUID has been defined (94630be0-e031-11db-974d-0002a5d5c51b) which allows UUIDs to be generated from a simple string. Supplying a single string parameters to utest.exe will result in a sed expression being output. The expression is designed to be used with the manifest.tmpl to generate the manifest.u3i file. For example,

utest.exe "0.99.6" => s/$(UUID)/c84e2059-6e2f-54dd-9af7-646f91327cce/

The U3 packaging uses this UUID to identify separate versions, which includes the automated builds.

Graeme Lunt 1/4/2007