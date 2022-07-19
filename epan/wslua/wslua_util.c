/*
 *  wslua_util.c
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

/* WSLUA_MODULE Utility Utility Functions */

#include "wslua.h"
#include <math.h>
#include <epan/stat_tap_ui.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>


WSLUA_FUNCTION wslua_get_version(lua_State* L) { /* Gets the Wireshark version as a string. */
    const gchar* str = VERSION;
    lua_pushstring(L,str);
    WSLUA_RETURN(1); /* The version string, e.g. "3.2.5". */
}


static gchar* current_plugin_version = NULL;

const gchar* get_current_plugin_version(void) {
    return current_plugin_version ? current_plugin_version : "";
}

void clear_current_plugin_version(void) {
    if (current_plugin_version != NULL) {
        g_free(current_plugin_version);
        current_plugin_version = NULL;
    }
}

WSLUA_FUNCTION wslua_set_plugin_info(lua_State* L) {
    /*
    Set a Lua table with meta-data about the plugin, such as version.

    The passed-in Lua table entries need to be keyed/indexed by the following:

     * "version" with a string value identifying the plugin version (required)
     * "description" with a string value describing the plugin (optional)
     * "author" with a string value of the author's name(s) (optional)
     * "repository" with a string value of a URL to a repository (optional)

    Not all of the above key entries need to be in the table. The 'version'
    entry is required, however. The others are not currently used for anything, but
    might be in the future and thus using them might be useful. Table entries keyed
    by other strings are ignored, and do not cause an error.

    ===== Example

    [source,lua]
    ----
    local my_info = {
        version = "1.0.1",
        author = "Jane Doe",
        repository = "https://github.com/octocat/Spoon-Knife"
    }

    set_plugin_info(my_info)
    ----

    @since 1.99.8
    */
#define WSLUA_ARG_set_plugin_info_TABLE 1 /* The Lua table of information. */

    if ( lua_istable(L,WSLUA_ARG_set_plugin_info_TABLE) ) {
        int top;
        lua_getfield(L, WSLUA_ARG_set_plugin_info_TABLE, "version");
        top = lua_gettop(L);
        if (lua_isstring(L, top)) {
            clear_current_plugin_version();
            current_plugin_version = g_strdup( luaL_checkstring(L, top) );
            /* pop the string */
            lua_pop(L, 1);
        }
        else {
            return luaL_error(L,"the Lua table must have a 'version' key entry with a string value");
        }
    } else {
        return luaL_error(L,"a Lua table with at least a 'version' string entry");
    }

    return 0;
}


WSLUA_FUNCTION wslua_format_date(lua_State* LS) { /* Formats an absolute timestamp into a human readable date. */
#define WSLUA_ARG_format_date_TIMESTAMP 1 /* A timestamp value to convert. */
    lua_Number timestamp = luaL_checknumber(LS,WSLUA_ARG_format_date_TIMESTAMP);
    nstime_t then;
    gchar* str;

    then.secs = (time_t)(floor(timestamp));
    then.nsecs = (guint32) ( (timestamp-(double)(then.secs))*1000000000);
    str = abs_time_to_str(NULL, &then, ABSOLUTE_TIME_LOCAL, TRUE);
    lua_pushstring(LS,str);
    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* A string with the formated date */
}

WSLUA_FUNCTION wslua_format_time(lua_State* LS) { /* Formats a relative timestamp in a human readable time. */
#define WSLUA_ARG_format_time_TIMESTAMP 1 /* A timestamp value to convert. */
    lua_Number timestamp = luaL_checknumber(LS,WSLUA_ARG_format_time_TIMESTAMP);
    nstime_t then;
    gchar* str;

    then.secs = (time_t)(floor(timestamp));
    then.nsecs = (guint32) ( (timestamp-(double)(then.secs))*1000000000);
    str = rel_time_to_str(NULL, &then);
    lua_pushstring(LS,str);
    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* A string with the formated time */
}

WSLUA_FUNCTION wslua_get_preference(lua_State *L) {
    /* Get a preference value. @since 3.5.0 */
#define WSLUA_ARG_get_preference_PREFERENCE 1 /* The name of the preference. */
    const gchar* preference = luaL_checkstring(L,WSLUA_ARG_get_preference_PREFERENCE);

    /* Split preference from module.preference */
    gchar *module_name = g_strdup(preference);
    gchar *preference_name = strchr(module_name, '.');
    pref_t *pref = NULL;

    if (preference_name) {
        *preference_name = '\0';
        preference_name++;

        module_t *module = prefs_find_module(module_name);
        pref = prefs_find_preference(module, preference_name);
    }
    g_free (module_name);

    if (pref) {
        switch (prefs_get_type(pref)) {
            case PREF_UINT:
            {
                guint uint_value = prefs_get_uint_value_real(pref, pref_current);
                lua_pushinteger(L, uint_value);
                break;
            }
            case PREF_BOOL:
            {
                gboolean bool_value = prefs_get_bool_value(pref, pref_current);
                lua_pushboolean(L, bool_value);
                break;
            }
            case PREF_ENUM:
            {
                const enum_val_t *enums;
                gint enum_value = prefs_get_enum_value(pref, pref_current);

                for (enums = prefs_get_enumvals(pref); enums->name; enums++) {
                    if (enums->value == enum_value) {
                        lua_pushstring(L,enums->name);
                        break;
                    }
                }

                if (!enums || !enums->name) {
                    /* Enum preference has an unknown value. */
                    lua_pushstring(L,"");
                }
                break;
            }
            case PREF_STRING:
            case PREF_SAVE_FILENAME:
            case PREF_OPEN_FILENAME:
            case PREF_DIRNAME:
            {
                const gchar *string_value = prefs_get_string_value(pref, pref_current);
                lua_pushstring(L,string_value);
                break;
            }
            case PREF_RANGE:
            {
                char *range_value = range_convert_range(NULL, prefs_get_range_value_real(pref, pref_current));
                lua_pushstring(L,range_value);
                wmem_free(NULL, range_value);
                break;
            }
            default:
                /* Get not supported for this type. */
                return luaL_error(L, "preference type %d is not supported.", prefs_get_type(pref));
        }
    } else {
        /* No such preference. */
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The preference value, or nil if not found. */
}

WSLUA_FUNCTION wslua_set_preference(lua_State *L) {
    /* Set a preference value. @since 3.5.0 */
#define WSLUA_ARG_set_preference_PREFERENCE 1 /* The name of the preference. */
#define WSLUA_ARG_set_preference_VALUE 2 /* The preference value to set. */
    const gchar* preference = luaL_checkstring(L,WSLUA_ARG_set_preference_PREFERENCE);

    /* Split preference from module.preference */
    gchar *module_name = g_strdup(preference);
    gchar *preference_name = strchr(module_name, '.');
    module_t *module = NULL;
    pref_t *pref = NULL;

    if (preference_name) {
        *preference_name = '\0';
        preference_name++;

        module = prefs_find_module(module_name);
        pref = prefs_find_preference(module, preference_name);
    }
    g_free (module_name);

    if (pref) {
        unsigned int changed = 0;
        switch (prefs_get_type(pref)) {
            case PREF_UINT:
            {
                guint uint_value = (guint)luaL_checkinteger(L,WSLUA_ARG_set_preference_VALUE);
                changed = prefs_set_uint_value(pref, uint_value, pref_current);
                module->prefs_changed_flags |= changed;
                lua_pushboolean(L, changed);
                break;
            }
            case PREF_BOOL:
            {
                gboolean bool_value = wslua_checkboolean(L, WSLUA_ARG_set_preference_VALUE);
                changed = prefs_set_bool_value(pref, bool_value, pref_current);
                module->prefs_changed_flags |= changed;
                lua_pushboolean(L, changed);
                break;
            }
            case PREF_ENUM:
            {
                const gchar *enum_value = luaL_checkstring(L,WSLUA_ARG_set_preference_VALUE);
                changed = prefs_set_enum_string_value(pref, enum_value, pref_current);
                module->prefs_changed_flags |= changed;
                lua_pushboolean(L, changed);
                break;
            }
            case PREF_STRING:
            case PREF_SAVE_FILENAME:
            case PREF_OPEN_FILENAME:
            case PREF_DIRNAME:
            {
                const gchar *string_value = luaL_checkstring(L,WSLUA_ARG_set_preference_VALUE);
                changed = prefs_set_string_value(pref, string_value, pref_current);
                module->prefs_changed_flags |= changed;
                lua_pushboolean(L, changed);
                break;
            }
            case PREF_RANGE:
            {
                const gchar *range_value = luaL_checkstring(L,WSLUA_ARG_set_preference_VALUE);
                range_t *range = NULL;
                convert_ret_t ret = range_convert_str(NULL, &range, range_value, prefs_get_max_value(pref));
                if (ret == CVT_NUMBER_TOO_BIG) {
                    return luaL_error(L, "illegal range (number too big)");
                } else if (ret != CVT_NO_ERROR) {
                    return luaL_error(L, "illegal range (syntax error)");
                }
                changed = prefs_set_range_value(pref, range, pref_current);
                wmem_free(NULL, range);
                module->prefs_changed_flags |= changed;
                lua_pushboolean(L, changed);
                break;
            }
            default:
                /* Set not supported for this type. */
                return luaL_error(L, "preference type %d is not supported.", prefs_get_type(pref));
        }
    } else {
        /* No such preference. */
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* true if changed, false if unchanged or nil if not found. */
}

WSLUA_FUNCTION wslua_reset_preference(lua_State *L) {
    /* Reset a preference to default value. @since 3.5.0 */
#define WSLUA_ARG_reset_preference_PREFERENCE 1 /* The name of the preference. */
    const gchar* preference = luaL_checkstring(L,WSLUA_ARG_reset_preference_PREFERENCE);

    // Split preference from module.preference
    gchar *module_name = g_strdup(preference);
    gchar *preference_name = strchr(module_name, '.');
    pref_t *pref = NULL;

    if (preference_name) {
        *preference_name = '\0';
        preference_name++;

        module_t *module = prefs_find_module(module_name);
        pref = prefs_find_preference(module, preference_name);
    }

    if (pref) {
        reset_pref(pref);
        lua_pushboolean(L, TRUE);
    } else {
        /* No such preference. */
        lua_pushnil(L);
    }

    g_free(module_name);
    WSLUA_RETURN(1); /* true if valid preference */
}

WSLUA_FUNCTION wslua_apply_preferences(lua_State *L) {
    /* Write preferences to file and apply changes. @since 3.5.0 */
    char *pf_path = NULL;
    int err = write_prefs(&pf_path);

    if (err) {
        /* Make a copy of pf_path because luaL_error() will return */
        gchar pf_path_copy[256];
        (void) g_strlcpy(pf_path_copy, pf_path, sizeof pf_path_copy);
        g_free(pf_path);

        return luaL_error(L, "can't open preferences file\n\"%s\": %s.",
                          pf_path_copy, g_strerror(err));
    } else {
        prefs_apply_all();
    }

    return 0;
}

WSLUA_FUNCTION wslua_report_failure(lua_State* LS) { /* Reports a failure to the user. */
#define WSLUA_ARG_report_failure_TEXT 1 /* Message text to report. */
    const gchar* s = luaL_checkstring(LS,WSLUA_ARG_report_failure_TEXT);
    report_failure("%s",s);
    return 0;
}

/* The returned filename is g_malloc()'d so the caller must free it */
/* except when NULL is returned if file doesn't exist               */
char* wslua_get_actual_filename(const char* fname) {
    char fname_clean[256];
    char* f;
    char* filename;

    (void) g_strlcpy(fname_clean,fname,255);
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

    /*
     * Try to look in global data directory, nothing extraordinary for normal
     * installations. For executions from the build dir, it will look for files
     * copied to DATAFILE_DIR.
     */
    filename = get_datafile_path(fname_clean);
    if ( file_exists(filename) ) {
        return filename;
    }
    g_free(filename);

    return NULL;
}

WSLUA_FUNCTION wslua_loadfile(lua_State* L) {
    /*
    Loads a Lua file and compiles it into a Lua chunk, similar to the standard
    https://www.lua.org/manual/5.1/manual.html#pdf-loadfile[loadfile]
    but searches additional directories.
    The search order is the current directory, followed by the user's
    https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html[personal configuration]
    directory, and finally the
    https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html[global configuration]
    directory.

    ===== Example

    [source,lua]
    ----
    -- Assume foo.lua contains definition for foo(a,b). Load the chunk
    -- from the file and execute it to add foo(a,b) to the global table.
    -- These two lines are effectively the same as dofile('foo.lua').
    local loaded_chunk = assert(loadfile('foo.lua'))
    loaded_chunk()

    -- ok to call foo at this point
    foo(1,2)
    ----
    */
#define WSLUA_ARG_loadfile_FILENAME 1 /* Name of the file to be loaded. If the file does not exist in the current directory, the user and system directories are searched. */
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
    /*
    Loads a Lua file and executes it as a Lua chunk, similar to the standard
    https://www.lua.org/manual/5.1/manual.html#pdf-dofile[dofile]
    but searches additional directories.
    The search order is the current directory, followed by the user's
    https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html[personal configuration]
    directory, and finally the
    https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html[global configuration]
    directory.
    */
#define WSLUA_ARG_dofile_FILENAME 1 /* Name of the file to be run. If the file does not exist in the current directory, the user and system directories are searched. */
    const char *given_fname = luaL_checkstring(L, WSLUA_ARG_dofile_FILENAME);
    char* filename = wslua_get_actual_filename(given_fname);
    int n;

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
            ws_warning("Runtime error while calling statcmd callback");
            break;
        case LUA_ERRMEM:
            ws_warning("Memory alloc error while calling statcmd callback");
            break;
        case LUA_ERRERR:
            ws_warning("Error while running the error handler function for statcmd callback");
            break;
        default:
            ws_assert_not_reached();
            break;
    }

}

WSLUA_FUNCTION wslua_register_stat_cmd_arg(lua_State* L) {
    /* Register a function to handle a `-z` option */
#define WSLUA_ARG_register_stat_cmd_arg_ARGUMENT 1 /* The name of the option argument. */
#define WSLUA_OPTARG_register_stat_cmd_arg_ACTION 2 /* The function to be called when the command is invoked. */
    const char* arg = luaL_checkstring(L,WSLUA_ARG_register_stat_cmd_arg_ARGUMENT);
    statcmd_t* sc = g_new0(statcmd_t, 1); /* XXX leaked */
    stat_tap_ui ui_info;

    sc->L = L;
    lua_pushvalue(L, WSLUA_OPTARG_register_stat_cmd_arg_ACTION);
    sc->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,1);

    ui_info.group = REGISTER_PACKET_STAT_GROUP_UNSORTED; /* XXX - need an argument? */
    ui_info.title = NULL;
    ui_info.cli_string = arg;
    ui_info.tap_init_cb = statcmd_init;
    ui_info.nparams = 0;
    ui_info.params = NULL;
    register_stat_tap_ui(&ui_info, sc);
    return 0;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
