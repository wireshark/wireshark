# Falco Bridge

This plugin is a bridge between [Falco plugins](https://github.com/falcosecurity/plugins/) and Wireshark, so that Falco plugins can be used as dissectors.
It requires [libsinsp and libscap](https://github.com/falcosecurity/libs/).

## Building the Falco Bridge plugin

1. Download and compile [libsinsp and libscap](https://github.com/falcosecurity/libs/).
   You will probably want to pass `-DMINIMAL_BUILD=ON -DCREATE_TEST_TARGETS=OFF` to cmake.

1. Configure Wireshark with `cmake ... -DSINSP_INCLUDEDIR=/path/to/falcosecurity-libs -DSINSP_LIBDIR=/path/to/falcosecurity-libs/build ...`

## Quick Start

1. Create a directory named "falco" at the same level as the "epan" plugin folder.
You can find the global and per-user plugin folder locations on your system in About → Folders or in the [User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).

1. Build your desired [Falco plugin](https://github.com/falcosecurity/plugins/) and place it in the "falco" plugin directory.

## Licensing

libsinsp and libscap are released under the Apache 2.0 license.

- b64: MIT
- c-ares: MIT
- curl: MIT
- GRPC: Apache 2.0
- jq: MIT
- JsonCpp: MIT
- LuaJIT: MIT
- OpenSSL < 3.0: SSLeay
- OpenSSL >= 3.0 : Apache 2.0
- Protobuf: BSD-3-Clause
- oneTBB: Apache 2.0
- zlib: zlib

Wireshark is released under the GPL version 2 (GPL-2.0-or-later). It and the Apache-2.0 license are compatible via the "any later version" provision in the GPL version 2.
No version of the GPL is compatible with the SSLeay license; you must ensure that libsinsp+libscap is linked with OpenSSL 3.0 or later.
