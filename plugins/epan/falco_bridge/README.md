# Falco Bridge

This plugin is a bridge between [Falco plugins](https://github.com/falcosecurity/plugins/) and Wireshark, so that Falco plugins can be used as dissectors.
It requires [libsinsp and libscap](https://github.com/falcosecurity/libs/).

## Building the Falco Bridge plugin

1. Download and compile [libsinsp and libscap](https://github.com/falcosecurity/libs/).

1. Configure Wireshark with `cmake ... -DSINSP_INCLUDE_DIR=/path/to/falcosecurity-libs -DSINSP_LIBDIR=/path/to/falcosecurity-libs/build ...`

## Quick Start

1. Create a directory named "falco" at the same level as the "epan" plugin folder.
You can find the global and per-user plugin folder locations on your system in About → Folders or in the [User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).

1. Build your desired [Falco plugin](https://github.com/falcosecurity/plugins/) and place it in the "falco" plugin directory.
