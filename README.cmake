          Explain the cmake build system for wireshark

                           Notice

   To find out the current state of the cmake implementation for
   Wireshark, please take a look at "What needs to be done?" below.
   Basically this is an experiment and if we find out that it works
   and we like cmake more than autofoo we might switch one day.

Table of contents
=================

How to get started with cmake (Unix/Linux and Win32/64)?
Why cmake?
Why not cmake?
What needs to be done?
Links regarding cmake

How to get started with cmake (Unix/Linux and Win32/64)?
========================================================

You can find documentation on cmake at: http://www.cmake.org/

cmake is designed to support out of tree builds. So much so, that
in tree builds do not work properly in all cases.

How to do out of tree build (Unix/Linux):
1) Install cmake.
2) Assuming, you are in the top directory of the wireshark source
   cd ..
3) mkdir build
4) cd build
5) cmake ../<Name_of_WS_source_dir>
6) make (or cmake --build .)
7) (as root) umask 0022 && make install

Note 1:
in step 5), you may override the defaults for features:
 cmake -DENABLE_CAP=OFF ../<Name_of_WS_source_dir>
 will disable the capabilities check.

Note 2:
 On OS X, you may want to run cmake like this:
 cmake -DENABLE_CAP=OFF -G "Unix Makefiles"

Note 3:
  After running cmake, you can always run "make help" to see
  a list of all possible make targets.

Note 4:
  Cmake honors user umask for creating directories as of now:
  http://public.kitware.com/Bug/view.php?id=9620
  To get predictable results please set umask explicitly.

How to do out of tree build (Win32/64):
[This is advanced alpha and should build all executables except the GTK3
 Wireshark for 32-bit.]
1) Follow http://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html
   Steps 1-9
1a) Set WIRESHARK_BASE_DIR=c:\wireshark (the parent directory of the
   library directory).
1b) set WIRESHARK_TARGET_PLATFORM=win32 (or win64)
1c) set QT5_BASE_DIR=c:\Qt\Qt5.1.1\5.1.1\msvc2010 (or whatever)
1d) In case you want to use Visual Studio, make sure that the paths
    to python and cygwin are available to GUI applications.
2) Install cmake
2a) Build the zlib library, e.g.
    cd %WIRESHARK_BASE_DIR%\wireshark-%WIRESHARK_TARGET_PLATFORM%-libs\zlib125
    cmake -G "NMake Makefiles" . # msbuild will not do because of configuration path
    cmake --build .
3) mkdir c:\wireshark\build
4) cd c:\wireshark\build
5) cmake -G "NMake Makefiles" path\to\sources
  (i.e. in case your sources are located at c:\wireshark\trunk, use "..\trunk")
5a) cmake path\to\sources (this will build for the latest Visual Studio version found)
5b) cmake -G "Visual Studio xx" where xx = 10 for VS2010, 11 for VS2012 and 12 for VS2013
    will build a solution for a specfic version of VS (it must still be installed).
6) nmake /X- VERBOSE=1 (or cmake --build . -- VERBOSE=1 )
6a) Wireshark.sln (this will run up Visual Studio with the cmake built solution
   (or using msbuild: msbuild wireshark.sln /m /p:Configuration=RelWithDebInfo)
7) In case you want to test the executable(s) inside the build tree:
   Run setpath.bat whenever it gets updated (there is a message in each cmake
   run whether it is necessary or not).

Why cmake?
==========
- Can create project files for some MS and Apple IDEs.
- Fast
- Easier to understand/learn
- Doesn't create any files in the source tree in case
  of out of tree builds
- One build infrastructure even including Windows
...

Why not cmake?
==============
- Lots of work to do
- Everyone who wants to build from source needs cmake
- Current state of documentation isn't really better than
  autofoo documentation, in some respect it's even worse
  (you need to buy a book to get an explanation as to how
  cmake really works).
...

What works?
===========

All the executables now build from clean source on:
* 32bit openSUSE 11.3: (gnu)make and gcc
* 64bit FedoraXXX
* 32bit Ubuntu 9.04
* 32bit Ubuntu 10.04
* 64bit Debian Wheezy

What needs to be done?
======================

- Add back platform specific objects.
- Fix places in the cmake files marked as todo.
- Guides are not installed.
- Build source package (using CPack).
  This is obsolete if we decide to release VCS snapshots instead
- Build rpm package (using CPack).
- Add back checkAPI target.
- Test and add support for other platforms (BSDs, OSX,
  Solaris, Win32, Win64, ...)
- Add support for cmake configurations.
- Get plugins loading when running *shark from the build directory.
- Automatically figure out if *shark is running from the build directory
  (making WIRESHARK_RUN_FROM_BUILD_DIRECTORY unnecessary like it is with
  autofoo).
- Get cross-compilation working (or ensure it does). It works with autofoo.
...

Links regarding cmake
=====================
The home page of the cmake project
	http://www.cmake.org/

The home page of the cmake project documentation
	http://www.cmake.org/Wiki/CMake

About cmake in general and why KDE4 uses it
	http://lwn.net/Articles/188693/

Introductory/tutorial presentation
	http://ait.web.psi.ch/services/linux/hpc/hpc_user_cookbook/tools/cmake/docs/Cmake_VM_2007.pdf

Introductory article in Linux Journal
	http://www.linuxjournal.com/node/6700/print

Useful variables
	http://www.cmake.org/Wiki/CMake_Useful_Variables

cmake FAQ
	http://www.cmake.org/Wiki/CMake_FAQ

Additional cmake modules
	http://code.google.com/p/cmake-modules/
