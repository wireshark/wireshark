          Explain the cmake build system for wireshark

                           Notice

   To find out the current state of the cmake implementation for
   Wireshark, please take a look at "What needs to be done?" below.

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

  # Disable the POSIX capabilities check
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

  # Disable building an application bundle (Wireshark.app) on OS X
  -DENABLE_APPLICATION_BUNDLE=OFF

  # Qt Creator expects .cbp files when used with CMake.
  -G "CodeBlocks - Unix Makefiles"
  -G "CodeBlocks - NMake Makefiles"

  # We call try_compile many times, particularly via ConfigureChecks.cmake.
  # Setting a lightweight try_compile configuration can speed up cmake,
  # particularly for MSBuild.
  -DCMAKE_TRY_COMPILE_CONFIGURATION=Release

Note 2:
  After running cmake, you can always run "make help" to see
  a list of all possible make targets.

Note 3:
  Cmake honors user umask for creating directories as of now:
  http://public.kitware.com/Bug/view.php?id=9620
  To get predictable results please set umask explicitly.

How to do an out of tree build using Visual C++ 2013:
[This is used for the 2.x release builds, support for VS2010 and VS2012
 is included, but hasn't been tested.]
0) Install cmake (currently 3.1.3 or later is recommended).  You can use chocolatey,
   choco inst cmake.
1) Follow https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html
   Steps 1-9
1a) Set the library search path.
    If you set WIRESHARK_BASE_DIR,
    %WIRESHARK_BASE_DIR%\wireshark-%WIRESHARK_TARGET_PLATFORM%-libs-2.2 will
    be used as the top-level library directory.
    If you set WIRESHARK_LIB_DIR, it will be used as the top-level library
    directory.  This definition will require changing for different builds (x86 & x64).
1b) set WIRESHARK_TARGET_PLATFORM=win32 (or win64)
1c) set QT5_BASE_DIR=C:\Qt\5.4.1\5.4\msvc2013_opengl (must match the Qt component path
    on your system)
1d) If you want to use Visual Studio to build rather than msbuild from the command line,
    make sure that the path to Cygwin is available to GUI applications.
2) mkdir c:\wireshark\build or as appropriate for you.
   You will need one build directory for each bitness (win32, win64) you wish to build.
3) cd into the directory from 2) above.
4) Run the following to generate the build files:
   cmake -DENABLE_CHM_GUIDES=on xxx path\to\sources
   where path\to\sources is the absolute or relative path to the wireshark source tree
   and xxx is replaced with one of the following:
       nothing - This will build a VS solution for win32 using the latest version of VS found (preferred).
       -G "Visual Studio 12" ("12" builds for VS2013. Use "11" for VS2012 or "10" for VS2010.)
       -G "NMake Makefiles" - to build an nmake makefile.
       -G "Visual Studio 12 Win64" (to build an x64 version you must add the "Win64", Win32 is the default)
5) Run one of the following to build Wireshark:
   msbuild /m /p:Configuration=RelWithDebInfo wireshark.sln (preferred).
   Open Wireshark.sln in Windows Explorer to build in Visual Studio
   nmake /X- VERBOSE=1 (or cmake --build . -- VERBOSE=1 ) (if you generated nmake files).
   Subsequent changes to source files and CMakeLists.txt will be automagically detected
   and new build files generated, i.e. step 4) doesn't need to be run again.
   Changes to the build environment, e.g. QT_BASE_DIR aren't detected so you must delete the
   build dir and start form step 2) again.
6) The executables can be run from the appropriate directory, e.g. run\RelWithDebInfo for VS solutions
   or run\ for NMake files.
   On macOS CMake creates an application bundle by default and places executables in
   run/Wireshark.app/Contents/MacOS. It also creates a convenience wrapper script
   (run/wireshark) which will run the Wireshark executable in the bundle.
7) To build an installer, build the nsis_package_prep and then the nsis_package projects, e.g.
   msbuild /m /p:Configuration=RelWithDebInfo nsis_package_prep.vcxproj
   msbuild /m /p:Configuration=RelWithDebInfo nsis_package.vcxproj
   nmake ???

Why cmake?
==========
- Can create project files for many IDEs including Qt Creator, Visual Studio,
  and XCode.
- Fast, builds in parallel in Visual Studio or msbuild with the /m flag
- Easier to understand/learn
- Doesn't create any files in the source tree in case of out of tree builds
- One build infrastructure for all of our tier 1 platforms (including Windows)
- Out of tree builds permits both Win32 and Win64 builds without requiring a "clean" when swapping.

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
Windows packages are built using CMake steps.

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
- Add support for cmake configurations.
- Get cross-compilation working (or ensure it does). It works with autofoo--and
  people use it.
- Handle -DFORTIFY_SOURCE=2 appropriately.  (Do a Web search for
  "cmake fortify" for some information.)
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
