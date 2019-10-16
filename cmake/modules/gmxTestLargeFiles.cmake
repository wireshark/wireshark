# This code was copied from http://www.gromacs.org/
# and its toplevel COPYING file starts with:
#
# GROMACS is free software, distributed under the GNU General Public License
# (GPL) Version 2.

# - Define macro to check large file support
#
#  GMX_TEST_LARGE_FILES(VARIABLE)
#
#  VARIABLE will be set to true if 64-bit file support is available.
#  This macro will also set defines as necessary to enable large file
# support, for instance:
#  _LARGE_FILES
#  _LARGEFILE_SOURCE
#  _FILE_OFFSET_BITS=64
#
#  However, it is YOUR job to make sure these defines are set in a cmakedefine so they
#  end up in a config.h file that is included in your source if necessary!

MACRO(GMX_TEST_LARGE_FILES VARIABLE)
    IF(NOT DEFINED ${VARIABLE})
        if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
            #
            # This is Visual Studio; Visual Studio has supported
            # _fseeki64 and _ftelli64 since Visual Studio 2005 / MSVCR80,
            # and we require newer versions, so we know we have them.
            #
            MESSAGE(STATUS "_fseeki64 and _ftelli64 are present")
        else(CMAKE_C_COMPILER_ID MATCHES "MSVC")
            #
            # This is UN*X, or some other Windows compiler.
            #
            # For UN*X, we do the Large File Support tests, to see
            # whether it's present and, if so what we need to define
            # to enable it.
            #
            # XXX - what's the right thing to do on Windows with,
            # for example, MinGW?
            #
            # On most platforms it is probably overkill to first test
            # the flags for 64-bit off_t, and then separately fseeko.
            # However, in the future we might have 128-bit seek offsets
            # to support 128-bit filesystems that allow 128-bit offsets
            # (ZFS), so it might be dangerous to indiscriminately set
            # e.g. _FILE_OFFSET_BITS=64.
            #
            MESSAGE(STATUS "Checking for 64-bit off_t")

            # First check without any special flags
            TRY_COMPILE(FILE64_OK "${CMAKE_BINARY_DIR}"
                        "${CMAKE_SOURCE_DIR}/cmake/TestFileOffsetBits.c")
            if(FILE64_OK)
                MESSAGE(STATUS "64-bit off_t is present with no special flags")
            endif(FILE64_OK)

            if(NOT FILE64_OK)
                # Test with _FILE_OFFSET_BITS=64
                TRY_COMPILE(FILE64_OK "${CMAKE_BINARY_DIR}"
                            "${CMAKE_SOURCE_DIR}/cmake/TestFileOffsetBits.c"
                            COMPILE_DEFINITIONS "-D_FILE_OFFSET_BITS=64" )
                if(FILE64_OK)
                    MESSAGE(STATUS "64-bit off_t is present with _FILE_OFFSET_BITS=64")
                    set(_FILE_OFFSET_BITS 64 CACHE INTERNAL "64-bit off_t requires _FILE_OFFSET_BITS=64")
                endif(FILE64_OK)
            endif(NOT FILE64_OK)

            if(NOT FILE64_OK)
                # Test with _LARGE_FILES
                TRY_COMPILE(FILE64_OK "${CMAKE_BINARY_DIR}"
                            "${CMAKE_SOURCE_DIR}/cmake/TestFileOffsetBits.c"
                            COMPILE_DEFINITIONS "-D_LARGE_FILES" )
                if(FILE64_OK)
                    MESSAGE(STATUS "64-bit off_t is present with _LARGE_FILES")
                    set(_LARGE_FILES 1 CACHE INTERNAL "64-bit off_t requires _LARGE_FILES")
                endif(FILE64_OK)
            endif(NOT FILE64_OK)

            if(NOT FILE64_OK)
                # Test with _LARGEFILE_SOURCE
                TRY_COMPILE(FILE64_OK "${CMAKE_BINARY_DIR}"
                            "${CMAKE_SOURCE_DIR}/cmake/TestFileOffsetBits.c"
                            COMPILE_DEFINITIONS "-D_LARGEFILE_SOURCE" )
                if(FILE64_OK)
                    MESSAGE(STATUS "64-bit off_t is present with _LARGEFILE_SOURCE")
                    set(_LARGEFILE_SOURCE 1 CACHE INTERNAL "64-bit off_t requires _LARGEFILE_SOURCE")
                endif(FILE64_OK)
            endif(NOT FILE64_OK)

            if(NOT FILE64_OK)
                MESSAGE(STATUS "64-bit file offset support not available")
            else(NOT FILE64_OK)
                # Set the flags we might have determined to be required above
                configure_file("${CMAKE_SOURCE_DIR}/cmake/TestLargeFiles.c.cmakein"
                               "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/TestLargeFiles.c")

                #
                # If this is Windows, assume we have _fseeki64/_ftelli64
                # available.  If this is UN*X, check for fseeko/ftello.
                #
                if(NOT WIN32)
                    MESSAGE(STATUS "Checking for fseeko/ftello")
                    # Test if ftello/fseeko are available
                    TRY_COMPILE(FSEEKO_COMPILE_OK "${CMAKE_BINARY_DIR}"
                                "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/TestLargeFiles.c")
                    if(FSEEKO_COMPILE_OK)
                        MESSAGE(STATUS "Checking for fseeko/ftello - present")
                    endif(FSEEKO_COMPILE_OK)

                    if(NOT FSEEKO_COMPILE_OK)
                        # glibc 2.2 neds _LARGEFILE_SOURCE for fseeko (but not 64-bit off_t...)
                        TRY_COMPILE(FSEEKO_COMPILE_OK "${CMAKE_BINARY_DIR}"
                                    "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/TestLargeFiles.c"
                                    COMPILE_DEFINITIONS "-D_LARGEFILE_SOURCE" )
                        if(FSEEKO_COMPILE_OK)
                            MESSAGE(STATUS "Checking for fseeko/ftello - present with _LARGEFILE_SOURCE")
                            set(_LARGEFILE_SOURCE 1 CACHE INTERNAL "64-bit fseeko requires _LARGEFILE_SOURCE")
                        endif(FSEEKO_COMPILE_OK)
                    endif(NOT FSEEKO_COMPILE_OK)
                    if(FSEEKO_COMPILE_OK)
                        SET(${VARIABLE} 1 CACHE INTERNAL "Result of test for large file support" FORCE)
                        set(HAVE_FSEEKO 1 CACHE INTERNAL "64-bit fseeko is available" FORCE)
                    else(FSEEKO_COMPILE_OK)
                        MESSAGE(STATUS "Checking for fseeko/ftello - not found")
                        SET(${VARIABLE} 0 CACHE INTERNAL "Result of test for large file support" FORCE)
                    endif(FSEEKO_COMPILE_OK)
                endif(NOT WIN32)
            endif(NOT FILE64_OK)
        endif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    ENDIF(NOT DEFINED ${VARIABLE})
ENDMACRO(GMX_TEST_LARGE_FILES VARIABLE)



