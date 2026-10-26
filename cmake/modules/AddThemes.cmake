# AddTheme.cmake — Handles capsulating themes into Qt resource files
# This module provides a simple interface for adding themes to the Qt resource file.
# It requires QrcBuilder.cmake to be included before it.
#
# add_theme(<disk_name> [<alias>])
# 	Adds a theme to the list of themes to be included in the Qt resource file.
# 	The disk_name is the name of the theme directory under resources/themes,
# 	and alias is an optional name to use in the resource file instead of the disk name.
#
# add_bundled_themes([TARGET <target>])
# 	Adds every directory under resources/themes that holds a theme.jsonc,
# 	so the theme directories are the only list of bundled themes.
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(NOT COMMAND qrc_add_file)
    message(FATAL_ERROR
        "AddThemes.cmake requires QrcBuilder.cmake to be included first. "
        "Add 'include(QrcBuilder)' before 'include(AddThemes)'.")
endif()

function(add_theme)
    cmake_parse_arguments(ARG "" "NAME;ALIAS;TARGET" "" ${ARGN})
    if(NOT ARG_NAME)
        message(FATAL_ERROR "add_theme: NAME is required")
    endif()

    set(_theme_name "${ARG_NAME}")
    set(_alias_name "${ARG_NAME}")
    if(ARG_ALIAS)
        set(_alias_name "${ARG_ALIAS}")
    endif()

    qrc_add_file(NAME themes
                 FILE "${CMAKE_SOURCE_DIR}/resources/themes/${_theme_name}/theme.jsonc"
                 ALIAS "${_alias_name}/theme.jsonc"
		 TARGET "${ARG_TARGET}")

endfunction()

function(add_bundled_themes)
    cmake_parse_arguments(ARG "" "TARGET" "" ${ARGN})
    file(GLOB _theme_files CONFIGURE_DEPENDS
         "${CMAKE_SOURCE_DIR}/resources/themes/*/theme.jsonc")
    list(SORT _theme_files)
    foreach(_theme_file IN LISTS _theme_files)
        get_filename_component(_theme_dir "${_theme_file}" DIRECTORY)
        get_filename_component(_theme_name "${_theme_dir}" NAME)
        add_theme(NAME "${_theme_name}" TARGET "${ARG_TARGET}")
    endforeach()
endfunction()
