Placeholder for cmake development stuff :-)

                           Notice 

   The CMake build system for Wireshark is not yet ready for
   building the whole system. You'll still need autofoo to buld it.
   The only thing that can be build is dumpcap, and even that one
   requires that you successfully ran autofoo prior to running cmake
   (e.g. config.h is not yet build, lex and yacc are not run).
   Basically this is an experiment and if we find out that it works
   and we like cmake more than autofoo we might switch one day.

Table of contents
=================

How to get started with cmake?
Why cmake?
Why not cmake?
What needs to be done?

How to get started with cmake?
==============================

You can find documentation on cmake at: http://www.cmake.org/

cmake is designed to support out of tree builds. So much so, that
in tree builds do not work properly in all cases.

How to do out of tree build (Unix/Linux):
1) Install cmake.
2) Build the project with the old build system once (to generate
   config.h and run bison and flex to generate some c-files).
3) Assuming, you are in the top directory of the wireshark source
   cd ..
4) mkdir build
5) cd build
6) cmake ../<Name_of_WS_source_dir>
7) make

Why cmake?
==========
- Can create project files for some MS and Apple IDEs.
- Fast
- Easier to understand/learn
- One build infrastructure even including Windows?
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

What needs to be done?
======================

only dumpcap and libwiretap have been done, and even those rely on
autofoo having been run before:

- Add proper GTK1/GLIB2/GLIB1 detection (currently links against gtk2
  to pull in glib2).
- Create config.h
- Autocreated source files in wiretap need to be build from .l, .y files.

All other tools and libs still need to be built.

