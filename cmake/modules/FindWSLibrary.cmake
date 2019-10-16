#
# - Find WS Library
#  This function is a wrapper for find_library() that does handle vcpkg exported
#  library directory structure

function(FindWSLibrary OUTPUT_LIBRARY)
    cmake_parse_arguments(
        WS_LIB
        ""
        "WIN32_HINTS"
        "NAMES;HINTS;PATHS"
        ${ARGN}
    )

    if (WIN32)
        find_library(${OUTPUT_LIBRARY}_DEBUG
            NAMES ${WS_LIB_NAMES}
            HINTS "${WS_LIB_WIN32_HINTS}/debug/lib"
            PATHS ${WS_LIB_PATHS}
        )
        find_library(${OUTPUT_LIBRARY}_RELEASE
            NAMES ${WS_LIB_NAMES}
            HINTS "${WS_LIB_WIN32_HINTS}/lib"
            PATHS ${WS_LIB_PATHS}
        )

        if (${OUTPUT_LIBRARY}_DEBUG AND ${OUTPUT_LIBRARY}_RELEASE)
            set(${OUTPUT_LIBRARY} debug ${${OUTPUT_LIBRARY}_DEBUG} optimized ${${OUTPUT_LIBRARY}_RELEASE} PARENT_SCOPE)
        endif()
    else()
        find_library(${OUTPUT_LIBRARY}
            NAMES ${WS_LIB_NAMES}
            HINTS ${WS_LIB_HINTS}
            PATHS ${WS_LIB_PATHS}
        )
    endif()
endfunction()
