Wireshark supports several different types of binary plugins. See the relevant
developer documentation for details on those and guidance on how to develop the
code. This document just provides some pointers on how to build and distribute
your plugin for Wireshark.

This source tree contains plugins built and bundled with the entire Wireshark
application. If you are developing one or more plugins and don't mind or prefer
to distribute your own custom build of Wireshark you can add your plugin code
to this project tree, using any method of your liking. You can follow existing
CMake patterns and edit CMake code directly or explore the various CMake custom
plugin variables and default includes that exist to try to make this more
convenient. Bear in mind that upstream contributions to the project (for
example in the form of new dissectors) are usually not accepted as plugins,
unless an exception is granted for some reason.

However one advantage of using plugins is that they can be compiled and
distributed independently of the Wireshark application code. Building Wireshark
can be slow and has specific dependency requirements you must meet and hitting
compilation warnings or errors compiling off the master branch unrelated to
your code is not unusual.

If developing your plugin separately from the main repository is something that
interests you you may also want to check out the recipe provided in
doc/plugins.example to do that instead.
