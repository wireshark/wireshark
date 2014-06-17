/*
 *  wslua_util.c
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

/* WSLUA_MODULE Utility Utility Functions */

#include "wslua.h"
#include <math.h>
#include <epan/stat_cmd_args.h>


WSLUA_FUNCTION wslua_get_version(lua_State* L) { /* Gets a string of the Wireshark version. */
    const gchar* str = VERSION;
    lua_pushstring(L,str);
    WSLUA_RETURN(1); /* version string */
}

WSLUA_FUNCTION wslua_format_date(lua_State* LS) { /* Formats an absolute timestamp into a human readable date. */
#define WSLUA_ARG_format_date_TIMESTAMP 1 /* A timestamp value to convert. */
    lua_Number timestamp = luaL_checknumber(LS,WSLUA_ARG_format_date_TIMESTAMP);
    nstime_t then;
    gchar* str;

    then.secs = (guint32)(floor(timestamp));
    then.nsecs = (guint32) ( (timestamp-(double)(then.secs))*1000000000);
    str = abs_time_to_str(NULL, &then, ABSOLUTE_TIME_LOCAL, TRUE);
    lua_pushstring(LS,str);
    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* A string with the formated date */
}

WSLUA_FUNCTION wslua_format_time(lua_State* LS) { /* Formats a relative timestamp in a human readable form. */
#define WSLUA_ARG_format_time_TIMESTAMP 1 /* A timestamp value to convert. */
    lua_Number timestamp = luaL_checknumber(LS,WSLUA_ARG_format_time_TIMESTAMP);
    nstime_t then;
    gchar* str;

    then.secs = (guint32)(floor(timestamp));
    then.nsecs = (guint32) ( (timestamp-(double)(then.secs))*1000000000);
    str = rel_time_to_str(NULL, &then);
    lua_pushstring(LS,str);
    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* A string with the formated time */
}

WSLUA_FUNCTION wslua_report_failure(lua_State* LS) { /* Reports a failure to the user. */
#define WSLUA_ARG_report_failure_TEXT 1 /* Message text to report. */
    const gchar* s = luaL_checkstring(LS,WSLUA_ARG_report_failure_TEXT);
    report_failure("%s",s);
    return 0;
}

static int wslua_log(lua_State* L, GLogLevelFlags log_level) {
    GString* str = g_string_new("");
    int n = lua_gettop(L);  /* Number of arguments */
    int i;

    lua_getglobal(L, "tostring");
    for (i=1; i<=n; i++) {
        const char *s;
        lua_pushvalue(L, -1);  /* function to be called */
        lua_pushvalue(L, i);   /* value to print */
        lua_call(L, 1, 1);
        s = lua_tostring(L, -1);  /* get result */
        if (s == NULL)
            return luaL_error(L, "`tostring' must return a string");

        if (i>1) g_string_append(str,"\t");
        g_string_append(str,s);

        lua_pop(L, 1);  /* pop result */
    }

    g_log(LOG_DOMAIN_LUA, log_level, "%s\n", str->str);
    g_string_free(str,TRUE);

    return 0;
}

WSLUA_FUNCTION wslua_critical( lua_State* L ) { /* Will add a log entry with critical severity. */
/* WSLUA_MOREARGS critical objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_CRITICAL);
    return 0;
}
WSLUA_FUNCTION wslua_warn( lua_State* L ) { /* Will add a log entry with warn severity. */
/* WSLUA_MOREARGS warn objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_WARNING);
    return 0;
}
WSLUA_FUNCTION wslua_message( lua_State* L ) { /* Will add a log entry with message severity. */
/* WSLUA_MOREARGS message objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_MESSAGE);
    return 0;
}
WSLUA_FUNCTION wslua_info( lua_State* L ) { /* Will add a log entry with info severity. */
/* WSLUA_MOREARGS info objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_INFO);
    return 0;
}
WSLUA_FUNCTION wslua_debug( lua_State* L ) { /* Will add a log entry with debug severity. */
/* WSLUA_MOREARGS debug objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_DEBUG);
    return 0;
}

/* The returned filename is g_malloc()'d so the caller must free it */
/* except when NULL is returned if file doesn't exist               */
char* wslua_get_actual_filename(const char* fname) {
    char fname_clean[256];
    char* f;
    char* filename;

    g_strlcpy(fname_clean,fname,255);
    fname_clean[255] = '\0';

    for(f = fname_clean; *f; f++) {
        switch(*f) {
            case '/': case '\\':
                *f = *(G_DIR_SEPARATOR_S);
                break;
            default:
                break;
        }
    }

    if ( file_exists(fname_clean) ) {
        return g_strdup(fname_clean);
    }

    filename = get_persconffile_path(fname_clean,FALSE);

    if ( file_exists(filename) ) {
        return filename;
    }
    g_free(filename);

    filename = get_datafile_path(fname_clean);
    if ( file_exists(filename) ) {
        return filename;
    }
    g_free(filename);

    if (running_in_build_directory()) {
        /* Running in build directory, try wslua source directory */
        filename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "epan" G_DIR_SEPARATOR_S "wslua"
                                   G_DIR_SEPARATOR_S "%s", get_datafile_dir(), fname_clean);
        if ( file_exists(filename) ) {
            return filename;
        }
        g_free(filename);
    }

    return NULL;
}

WSLUA_FUNCTION wslua_loadfile(lua_State* L) {
    /* Lua's loadfile() has been modified so that if a file does not exist
    in the current directory it will look for it in wireshark's user and system directories. */
#define WSLUA_ARG_loadfile_FILENAME 1 /* Name of the file to be loaded. */
    const char *given_fname = luaL_checkstring(L, WSLUA_ARG_loadfile_FILENAME);
    char* filename;

    filename = wslua_get_actual_filename(given_fname);

    if (!filename) {
        WSLUA_ARG_ERROR(loadfile,FILENAME,"file does not exist");
        return 0;
    }

    if (luaL_loadfile(L, filename) == 0) {
        g_free(filename);
        return 1;
    } else {
        g_free(filename);
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }
}

WSLUA_FUNCTION wslua_dofile(lua_State* L) {
    /* Lua's dofile() has been modified so that if a file does not exist
    in the current directory it will look for it in wireshark's user and system directories. */
#define WSLUA_ARG_dofile_FILENAME 1 /* Name of the file to be run. */
    const char *given_fname = luaL_checkstring(L, WSLUA_ARG_dofile_FILENAME);
    char* filename;
    int n;

    if (!given_fname) {
        WSLUA_ARG_ERROR(dofile,FILENAME,"must be a string");
        return 0;
    }

    filename = wslua_get_actual_filename(given_fname);

    if (!filename) {
        WSLUA_ARG_ERROR(dofile,FILENAME,"file does not exist");
        return 0;
    }

    n = lua_gettop(L);
    if (luaL_loadfile(L, filename) != 0) lua_error(L);
    g_free(filename);
    lua_call(L, 0, LUA_MULTRET);
    return lua_gettop(L) - n;
}


typedef struct _statcmd_t {
    lua_State* L;
    int func_ref;
} statcmd_t;

static int statcmd_init_cb_error_handler(lua_State* L _U_) {
    return 0;
}

static void statcmd_init(const char *opt_arg, void* userdata) {
    statcmd_t* sc = (statcmd_t *)userdata;
    lua_State* L = sc->L;

    lua_settop(L,0);
    lua_pushcfunction(L,statcmd_init_cb_error_handler);
    lua_rawgeti(L, LUA_REGISTRYINDEX, sc->func_ref);

    lua_pushstring(L,opt_arg);

    switch ( lua_pcall(L,1,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            g_warning("Runtime error while calling statcmd callback");
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling statcmd callback");
            break;
        default:
            g_assert_not_reached();
            break;
    }

}

WSLUA_FUNCTION wslua_register_stat_cmd_arg(lua_State* L) {
    /*  Register a function to handle a `-z` option */
#define WSLUA_ARG_register_stat_cmd_arg_ARGUMENT 1 /* Argument */
#define WSLUA_OPTARG_register_stat_cmd_arg_ACTION 2 /* Action */
    const char* arg = luaL_checkstring(L,WSLUA_ARG_register_stat_cmd_arg_ARGUMENT);
    statcmd_t* sc = (statcmd_t *)g_malloc0(sizeof(statcmd_t)); /* XXX leaked */

    sc->L = L;
    lua_pushvalue(L, WSLUA_OPTARG_register_stat_cmd_arg_ACTION);
    sc->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,1);

    register_stat_cmd_arg(arg, statcmd_init, sc);
    return 0;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
