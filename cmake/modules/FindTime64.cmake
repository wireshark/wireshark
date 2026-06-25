# CMake support for 64-bit time_t
#
# Based on FindLFS.cmake by
# Copyright (C) 2016 Julian Andres Klode <jak@debian.org>.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# This defines the following variables
#
# TIME64_DEFINITIONS - List of definitions to pass to add_definitions()
# TIME64_FOUND - If there is 64-bit time_t support
#

include(FindPackageHandleStandardArgs)
include(CMakePushCheckState)
include(CheckTypeSize)

function(_time64_smallest_size size_variable out_variable)
    set(smallest_size 8)
    foreach(arch_key in LISTS "${size_variable}_KEYS")
	set(arch_size ${size_variable-${arch_key}})

	if(arch_size LESS smallest_size)
	    set(smallest_size ${arch_size})
	endif()
    endforeach()
    set(${out_variable} ${smallest_size} PARENT_SCOPE)
endfunction()

function(_time64_check_compiler_option var definitions)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_QUIET 1)
    set(CMAKE_REQUIRED_DEFINITIONS ${LFS_DEFINITIONS} ${definitions})

    message(CHECK_START "Looking for 64-bit time_t support using ${definitions}")
    check_type_size(time_t ${var})
    cmake_pop_check_state()

    if (${var} EQUAL 0)
        # Universal/multiarch (e.g., CMAKE_OSX_ARCHITECTURES)
        _time64_smallest_size(${var} SMALLEST_TIME_T)
        if(SMALLEST_TIME_T GREATER_EQUAL 8)
            message(CHECK_PASS "multiple archs, all at least 64-bit")
            set(_time64_definitions ${definitions} PARENT_SCOPE)
            set(TIME64_FOUND TRUE PARENT_SCOPE)
        else()
            message(CHECK_FAIL "multiple archs, smallest time_t ${SMALLEST_TIME_T} bytes")
        endif()
    elseif (${var} GREATER_EQUAL 8)
	message(CHECK_PASS "found")
	set(_time64_definitions ${definitions} PARENT_SCOPE)
	set(TIME64_FOUND TRUE PARENT_SCOPE)
    else()
	message(CHECK_FAIL "not found")
    endif()
endfunction()

# Check for the availability of 64-bit time_t()
# The cases handled are:
#
#  * Native 64-bit time_t()
#  * Preprocessor flag -D_TIME_BITS=64
#
function(_time64_check)
    include(FindLFS)

    set(_time64_cppflags)
    cmake_push_check_state()
    message(CHECK_START "Looking for native 64-bit time_t support")
    set(CMAKE_REQUIRED_QUIET 1)
    set(CMAKE_REQUIRED_DEFINITIONS ${LFS_DEFINITIONS})
    # check_type_size includes sys/types.h which is good enough for POSIX.
    # If this were used on Windows CMAKE_EXTRA_INCLUDE_FILES "time.h" might
    # be needed.
    check_type_size(time_t SIZEOF_TIME_T)
    cmake_pop_check_state()
    if (SIZEOF_TIME_T EQUAL 0)
        # Universal/multiarch (e.g., CMAKE_OSX_ARCHITECTURES)
	_time64_smallest_size(SIZEOF_TIME_T SMALLEST_TIME_T)
        if(SMALLEST_TIME_T GREATER_EQUAL 8)
            message(CHECK_PASS "multiple archs, all at least 64-bit")
            set(TIME64_FOUND TRUE)
        else()
            message(CHECK_FAIL "multiple archs, smallest time_t ${SMALLEST_TIME_T} bytes")
        endif()
    elseif (SIZEOF_TIME_T GREATER_EQUAL 8)
        message(CHECK_PASS "found")
        set(TIME64_FOUND TRUE)
    else()
        message(CHECK_FAIL "not found")
    endif()

    if (NOT TIME64_FOUND)
        # See if it's available with _TIME_BITS=64. (glibc >= 2.34)
	_time64_check_compiler_option(SIZEOF_TIME_T_WITH_TIME_BITS "-D_TIME_BITS=64")
    endif()

    set(TIME64_DEFINITIONS ${_time64_definitions} CACHE STRING "Extra definitions for 64-bit time_t support")
    set(TIME64_FOUND ${TIME64_FOUND} CACHE INTERNAL "Found 64-bit time_t")
endfunction()

if (NOT TIME64_FOUND)
    _time64_check()
endif()

find_package_handle_standard_args(TIME64 "Could not force 64-bit time_t. Set TIME64_DEFINITIONS." TIME64_FOUND)
