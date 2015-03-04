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
5) cmake [options] ../<Name_of_WS_source_dir>
6) make (or cmake --build .)
7) (as root) umask 0022 && make install

Note 1:
  In step 5) you may need to override the defaults for features. Common
  options include:

  # Disable the POSIX capbabilities check
  -DENABLE_CAP=OFF

  # Enable debugging symbols
  -DCMAKE_BUILD_TYPE=Debug

  # Disable GTK+ 3
  -DENABLE_GTK3=OFF

  # Build documentation
  -DENABLE_HTML_GUIDES=ON
  -DENABLE_PDF_GUIDES=ON

  # Make ccache and clang work together
  -DCMAKE_C_FLAGS='-Qunused-arguments'

  # Force Python path on Windows. May be needed if Cygwin's
  # /usr/bin/python is present and is a symlink
  # http://public.kitware.com/Bug/view.php?id=13818
  -DPYTHON_EXECUTABLE=c:/Python27/python

  # Disable building an application bundle (Wireshark.app) on Mac OS X
  -DENABLE_APPLICATION_BUNDLE=OFF

Note 2:
  After running cmake, you can always run "make help" to see
  a list of all possible make targets.

Note 3:
  Cmake honors user umask for creating directories as of now:
  http://public.kitware.com/Bug/view.php?id=9620
  To get predictable results please set umask explicitly.

How to do an out of tree build using Visual C++ 2013:
[This is advanced alpha and should build all executables except the GTK3
 Wireshark for 32-bit.]
1) Follow https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html
   Steps 1-9
1a) Set the library search path.
    If you set WIRESHARK_LIB_DIR, it will be used as the top-level library
    directory.
    If you set WIRESHARK_BASE_DIR,
    %WIRESHARK_BASE_DIR%\wireshark-%WIRESHARK_TARGET_PLATFORM%-libs will
    be used as the top-level library directory.
1b) set WIRESHARK_TARGET_PLATFORM=win32 (or win64)
1c) set QT5_BASE_DIR=C:\Qt\5.3\msvc2013_opengl (must match the Qt component path
    on your system)
1d) If you want to use Visual Studio make sure that the paths to Python and
    Cygwin are available to GUI applications. The Python path MUST come first.
2) Install cmake
2a) Build the zlib library, e.g.
    cd %WIRESHARK_BASE_DIR%\wireshark-%WIRESHARK_TARGET_PLATFORM%-libs\zlib125
    cmake -G "NMake Makefiles" . # msbuild will not do because of configuration path
    cmake --build .
3) mkdir c:\wireshark\build
4) cd c:\wireshark\build
5) Run one of the following to create the build environment:
   cmake -G "NMake Makefiles" path\to\sources  (i.e. in case your sources are located at c:\wireshark\trunk, use "..\trunk")
   cmake path\to\sources (this will build for the latest Visual Studio version found)
   cmake -G "Visual Studio 12" ("12" builds for VS2103. Use "11" for VS2012 or "10" for VS2010.)
   cmake -G "Visual Studio 12 Win64" (Win32 is the default)
6) Run one of the following to build Wireshark:
   nmake /X- VERBOSE=1 (or cmake --build . -- VERBOSE=1 )
   Open Wireshark.sln in Windows Explorer to build in Visual Studio
   msbuild wireshark.sln /m /p:Configuration=RelWithDebInfo
7) In case you want to test the executable(s) inside the build tree:
   Run setpath.bat whenever it gets updated (there is a message in each cmake
   run whether it is necessary or not).

Why cmake?
==========
- Can create project files for many IDEs including Qt Creator, Visual Studio,
  and XCode.
- Fast
- Easier to understand/learn
- Doesn't create any files in the source tree in case of out of tree builds
- One build infrastructure for all of our tier 1 platforms (including Windows)

Why not cmake?
==============
- Lots of work to do
- Everyone who wants to build from source needs cmake
- Current state of documentation isn't really better than
  Autotools documentation. In some respects it's even worse
  (you need to buy a book to get an explanation as to how
  cmake really works).
...

What works?
===========

All the executables now build from clean source on:
* 32 bit openSUSE 11.3: (gnu)make and gcc
* 64 bit FedoraXXX
* 32 bit Ubuntu 9.04
* 32 bit Ubuntu 10.04
* 64 bit Ubuntu 14.04
* 64 bit Debian Wheezy
* 32 bit OS X
* 64 bit OS X
* 32 bit Windows using Visual C++ 2013
* 64 bit Windows using Visual C++ 2013
* 64 bit Solaris 10

The Buildbot runs CMake steps on Ubuntu, Win32, Win64, OS X, and Solaris.

What needs to be done?
======================

- Add back platform specific objects.
- Fix places in the cmake files marked as todo.
- Guides are not installed.
- Build source package (using CPack).
  This is obsolete if we decide to release VCS snapshots instead
- Build packages using CPack: tarball, Windows installer + PortableApps, OS X
  installer dmg, RPM, SVR4. This includes setting OS target version stuff
  appropriately for OS X. We currently use NSIS for the Windows installer but
  should probably use WiX instead.
- Add back checkAPI target.
- Add support for cmake configurations.
- Automatically figure out if *shark is running from the build directory
  (making WIRESHARK_RUN_FROM_BUILD_DIRECTORY unnecessary like it is with
  autofoo).
  Sadly:

      $ file run/qtshark
      run/qtshark: Mach-O 64-bit x86_64 executable

  so what you're running from the build directory is the executable
  itself.  autofoo includes libtool in our case, so what you're running
  from the build directory is a script that then runs the executable,
  and the executable is in a .libs directory; the code that checks for
  "running from the build directory?" checks for that.  The actual
  executable isn't supposed to be run directly - it's expected to be run
  by the wrapper script and might not even work if run directly, as it
  won't find the relevant shared libraries.

  We could perhaps check for the executable being in a "run" directory
  instead, if the build drops it there.  However, it's possible, at
  least on OS X, to copy the executable to another directory and have
  it run, so the guarantee that it's in a "run" directory is not as
  strong.
- Get plugins loading when running *shark from the build directory.
  That might involve handling ".libs" and "run" differently.  The chance
  that a random directory the executable was ultimately placed in would
  be named "run" might also be a bit bigger than the chance that it's
  named ".libs".
- Get the test suite running in a cmake build.  Currently at least the Lua
  parts fail.
- Get cross-compilation working (or ensure it does). It works with autofoo--and
  people use it.
- Handle -DFORTIFY_SOURCE=2 appropriately.  (Do a Web search for
  "cmake fortify" for some information.)
- Add support for Visual Studio code anlaysis similar to ENABLE_CODE_ANALYSIS in
  config.nmake.
- Define the GTK_DISABLE_ and GDK_DISABLE_ values as appropriate if we
  care about supporting the GTK+ version.
- Install the freedesktop integration files (wireshark.desktop,
  wireshark-mime-package.xml, etc.).
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
