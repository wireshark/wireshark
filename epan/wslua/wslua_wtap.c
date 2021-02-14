/*
 * wslua_wtap.c
 *
 * Wireshark's interface to the Lua Programming Language
 * for various libwiretap utility functions.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

/* WSLUA_MODULE Wtap Wtap Functions For Handling Capture File Types */

#include <limits.h>

#include "wslua.h"
#include <wiretap/wtap.h>

WSLUA_FUNCTION wslua_wtap_file_type_subtype_description(lua_State* LS) {
    /*
    Get a string describing a capture file type, given a filetype
    value for that file type.

    @since 3.2.12, 3.4.4
    */
#define WSLUA_ARG_file_type_subtype_description_FILETYPE 1 /* The type for which the description is to be fetched - a number returned by `wtap_name_to_file_type_subtype()`. */
    lua_Number filetype = luaL_checknumber(LS,WSLUA_ARG_file_type_subtype_description_FILETYPE);
    /* wtap_file_type_subtype_string()'s name isn't really descriptive. */
    if (filetype > INT_MAX) {
        /* Too big. */
        lua_pushnil(LS);
    } else {
        const gchar* str = wtap_file_type_subtype_string((int)filetype);
        if (str == NULL)
            lua_pushnil(LS);
        else
            lua_pushstring(LS,str);
    }
    WSLUA_RETURN(1); /* The description of the file type with that filetype value, or nil if there is no such file type. */
}

WSLUA_FUNCTION wslua_wtap_file_type_subtype_name(lua_State* LS) {
    /*
    Get a string giving the name for a capture file type, given a filetype
    value for that file type.

    @since 3.2.12, 3.4.4
    */
#define WSLUA_ARG_file_type_subtype_name_FILETYPE 1 /* The type for which the name is to be fetched - a number returned by `wtap_name_to_file_type_subtype()`. */
    lua_Number filetype = luaL_checknumber(LS,WSLUA_ARG_file_type_subtype_name_FILETYPE);
    /* wtap_file_type_subtype_string()'s name isn't really descriptive. */
    if (filetype > INT_MAX) {
        /* Too big. */
        lua_pushnil(LS);
    } else {
        const gchar* str = wtap_file_type_subtype_short_string((int)filetype);
        if (str == NULL)
            lua_pushnil(LS);
        else
           lua_pushstring(LS,str);
    }
    WSLUA_RETURN(1); /* The name of the file type with that filetype value, or nil if there is no such file type. */
}

WSLUA_FUNCTION wslua_wtap_name_to_file_type_subtype(lua_State* LS) {
    /*
    Get a filetype value for a file type, given the name for that
    file type.

    @since 3.2.12, 3.4.4
    */
#define WSLUA_ARG_name_to_file_type_subtype_NAME 1 /* The name of a file type. */
    const char* name = luaL_checkstring(LS,WSLUA_ARG_name_to_file_type_subtype_NAME);
    /* wtap_short_string_to_file_type_subtype()'s name isn't really descriptive. */
    lua_Number filetype = wtap_short_string_to_file_type_subtype(name);
    if (filetype == -1)
        lua_pushnil(LS);
    else
        lua_pushnumber(LS,filetype);
    WSLUA_RETURN(1); /* The filetype value for the file type with that name, or nil if there is no such file type. */
}
