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

/*
 * Solely for the function that gets the table of backwards-compatibility
 * Lua names for file types/subtypes.
 */
#include <wiretap/wtap-int.h>

WSLUA_FUNCTION wslua_wtap_file_type_subtype_description(lua_State* LS) {
    /*
    Get a string describing a capture file type, given a filetype
    value for that file type.

    @since 3.2.12, 3.4.4
    */
#define WSLUA_ARG_wtap_file_type_subtype_description_FILETYPE 1 /* The type for which the description is to be fetched - a number returned by `wtap_name_to_file_type_subtype()`. */
    lua_Number filetype = luaL_checknumber(LS,WSLUA_ARG_wtap_file_type_subtype_description_FILETYPE);
    /* wtap_file_type_subtype_description()'s name isn't really descriptive. */
    if (filetype > INT_MAX) {
        /* Too big. */
        lua_pushnil(LS);
    } else {
        const gchar* str = wtap_file_type_subtype_description((int)filetype);
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
#define WSLUA_ARG_wtap_file_type_subtype_name_FILETYPE 1 /* The type for which the name is to be fetched - a number returned by `wtap_name_to_file_type_subtype()`. */
    lua_Number filetype = luaL_checknumber(LS,WSLUA_ARG_wtap_file_type_subtype_name_FILETYPE);
    /* wtap_file_type_subtype_description()'s name isn't really descriptive. */
    if (filetype > INT_MAX) {
        /* Too big. */
        lua_pushnil(LS);
    } else {
        const gchar* str = wtap_file_type_subtype_name((int)filetype);
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
#define WSLUA_ARG_wtap_name_to_file_type_subtype_NAME 1 /* The name of a file type. */
    const char* name = luaL_checkstring(LS,WSLUA_ARG_wtap_name_to_file_type_subtype_NAME);
    lua_Number filetype = wtap_name_to_file_type_subtype(name);
    if (filetype == -1)
        lua_pushnil(LS);
    else
        lua_pushnumber(LS,filetype);
    WSLUA_RETURN(1); /* The filetype value for the file type with that name, or nil if there is no such file type. */
}

WSLUA_FUNCTION wslua_wtap_pcap_file_type_subtype(lua_State* LS) {
    /*
    Get the filetype value for pcap files.

    @since 3.2.12, 3.4.4
    */
    lua_Number filetype = wtap_pcap_file_type_subtype();
    lua_pushnumber(LS,filetype);
    WSLUA_RETURN(1); /* The filetype value for pcap files. */
}

WSLUA_FUNCTION wslua_wtap_pcap_nsec_file_type_subtype(lua_State* LS) {
    /*
    Get the filetype value for nanosecond-resolution pcap files.

    @since 3.2.12, 3.4.4
    */
    lua_Number filetype = wtap_pcap_nsec_file_type_subtype();
    lua_pushnumber(LS,filetype);
    WSLUA_RETURN(1); /* The filetype value for nanosecond-resolution pcap files. */
}

WSLUA_FUNCTION wslua_wtap_pcapng_file_type_subtype(lua_State* LS) {
    /*
    Get the filetype value for pcapng files.

    @since 3.2.12, 3.4.4
    */
    lua_Number filetype = wtap_pcapng_file_type_subtype();
    lua_pushnumber(LS,filetype);
    WSLUA_RETURN(1); /* The filetype value for pcapng files. */
}

/*
 * init.wslua-only function to return a table to assign to
 * wtap_filetypes.
 */
WSLUA_INTERNAL_FUNCTION wslua_get_wtap_filetypes(lua_State* LS) {
    /* Get the GArray from which we initialize this. */
    const GArray *table = get_backwards_compatibility_lua_table();

    /*
     * Create the table; it's indexted by strings, not numbers,
     * so none of the entries will be in a sequence.
     */
    lua_createtable(LS,0,table->len);
    for (guint i = 0; i < table->len; i++) {
        struct backwards_compatibiliity_lua_name *entry;

        entry = &g_array_index(table,
            struct backwards_compatibiliity_lua_name, i);
        /*
         * Push the name and the ft, in order, so that the ft,
         * which should be the value at the top of the stack,
         * is at the top of the stack, and the name, which should
         * be the value just below that, is the value just below
         * it.
         */
        lua_pushstring(LS, entry->name);
        lua_pushnumber(LS, entry->ft);
        /*
         * The -3 is the index, relative to the top of the stack, of
         * the table; the two elements on top of it are the ft and
         * the name, so it's -3.
         */
        lua_settable(LS, -3);
    }
    WSLUA_RETURN(1); /* The table. */
}
