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
#include <wsutil/file_util.h>


WSLUA_FUNCTION wslua_get_version(lua_State* L) { /* Gets a string of the Wireshark version. */
    const gchar* str = VERSION;
    lua_pushstring(L,str);
    WSLUA_RETURN(1); /* version string */
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
    /*  Set a Lua table with meta-data about the plugin, such as version.

        The passed-in Lua table entries need to be keyed/indexed by the following:
         * "version" with a string value identifying the plugin version (required)
         * "description" with a string value describing the plugin (optional)
         * "author" with a string value of the author's name(s) (optional)
         * "repository" with a string value of a URL to a repository (optional)

        Not all of the above key entries need to be in the table. The 'version'
        entry is required, however. The others are not currently used for anything, but
        might be in the future and thus using them might be useful. Table entries keyed
        by other strings are ignored, and do not cause an error.

        Example:

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

/*
 * These routines here are based on code from:
 * lbaselib.c,v 1.276.1.1 2013/04/12 18:48:47 roberto
 * lauxlib.c,v 1.248.1.1 2013/04/12 18:48:47 roberto
 * See Copyright Notice in lua.h
 *
 * All we did was 1) rename luaL_loadfilex to loadfilex, 2) make it
 * static, and 3) make it call ws_fopen() so that, on Windows, it takes
 * a UTF-8 pathname, rather than a pathname in the local code page, as
 * the file name argument.
 */

typedef struct LoadF {
    int n;  /* number of pre-read characters */
    FILE *f;  /* file being read */
    char buff[LUAL_BUFFERSIZE];  /* area for reading file */
} LoadF;

static const char *getF(lua_State *L, void *ud, size_t *size) {
    LoadF *lf = (LoadF *)ud;
    (void)L;  /* not used */
    if (lf->n > 0) {  /* are there pre-read characters to be read? */
        *size = lf->n;  /* return them (chars already in buffer) */
        lf->n = 0;  /* no more pre-read characters */
    }
    else {  /* read a block from file */
        /* 'fread' can return > 0 *and* set the EOF flag. If next call to
           'getF' called 'fread', it might still wait for user input.
           The next check avoids this problem. */
        if (feof(lf->f)) return NULL;
        *size = fread(lf->buff, 1, sizeof(lf->buff), lf->f);  /* read block */
    }
    return lf->buff;
}

static int errfile(lua_State *L, const char *what, int fnameindex) {
    const char *serr = g_strerror(errno);
    const char *filename = lua_tostring(L, fnameindex) + 1;
    lua_pushfstring(L, "cannot %s %s: %s", what, filename, serr);
    lua_remove(L, fnameindex);
    return LUA_ERRFILE;
}

static int skipBOM(LoadF *lf) {
    const char *p = "\xEF\xBB\xBF";  /* Utf8 BOM mark */
    int c;
    lf->n = 0;
    do {
        c = getc(lf->f);
        if (c == EOF || c != *(const unsigned char *)p++) return c;
        lf->buff[lf->n++] = c;  /* to be read by the parser */
    } while (*p != '\0');
    lf->n = 0;  /* prefix matched; discard it */
    return getc(lf->f);  /* return next character */
}

/*
** reads the first character of file 'f' and skips an optional BOM mark
** in its beginning plus its first line if it starts with '#'. Returns
** true if it skipped the first line.  In any case, '*cp' has the
** first "valid" character of the file (after the optional BOM and
** a first-line comment).
*/
static int skipcomment(LoadF *lf, int *cp) {
    int c = *cp = skipBOM(lf);
    if (c == '#') {  /* first line is a comment (Unix exec. file)? */
        do {  /* skip first line */
            c = getc(lf->f);
        } while (c != EOF && c != '\n') ;
        *cp = getc(lf->f);  /* skip end-of-line, if present */
        return 1;  /* there was a comment */
    }
    else return 0;  /* no comment */
}

static int our_loadfilex(lua_State *L, const char *filename, const char *mode) {
    LoadF lf;
    int status, readstatus;
    int c;
    int fnameindex = lua_gettop(L) + 1;  /* index of filename on the stack */
    if (filename == NULL) {
        lua_pushliteral(L, "=stdin");
        lf.f = stdin;
    }
    else {
        lua_pushfstring(L, "@%s", filename);
        lf.f = ws_fopen(filename, "r");
        if (lf.f == NULL) return errfile(L, "open", fnameindex);
    }
    if (skipcomment(&lf, &c))  /* read initial portion */
        lf.buff[lf.n++] = '\n';  /* add line to correct line numbers */
    if (c == LUA_SIGNATURE[0] && filename) {  /* binary file? */
        lf.f = ws_freopen(filename, "rb", lf.f);  /* reopen in binary mode */
        if (lf.f == NULL) return errfile(L, "reopen", fnameindex);
        skipcomment(&lf, &c);  /* re-read initial portion */
    }
    if (c != EOF)
        lf.buff[lf.n++] = c;  /* 'c' is the first character of the stream */
    status = lua_load(L, getF, &lf, lua_tostring(L, -1), mode);
    readstatus = ferror(lf.f);
    if (filename) fclose(lf.f);  /* close file (even in case of errors) */
    if (readstatus) {
        lua_settop(L, fnameindex);  /* ignore results from `lua_load' */
        return errfile(L, "read", fnameindex);
    }
    lua_remove(L, fnameindex);
    return status;
}

#define our_loadfile(L,f)  our_loadfilex(L,f,NULL)

WSLUA_FUNCTION wslua_ws_loadfile(lua_State* L) {
    /* This is like Lua's loadfile(), except that 1) if a file does not
    exist in the current directory it will look for it in Wireshark's
    user and system directories and 2) pathnames are, on Windows, treated
    as UTF-8 strings rather than strings in the current code page. */
#define WSLUA_ARG_loadfile_FILENAME 1 /* Name of the file to be loaded. */
    const char *given_fname = luaL_checkstring(L, WSLUA_ARG_loadfile_FILENAME);
    char* filename;

    filename = wslua_get_actual_filename(given_fname);

    if (!filename) {
        WSLUA_ARG_ERROR(loadfile,FILENAME,"file does not exist");
        return 0;
    }

    /* Use our loadfile, so that, on Windows, we handle UTF-8 file names. */
    if (our_loadfile(L, filename) == 0) {
        g_free(filename);
        return 1;
    } else {
        g_free(filename);
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }
}

WSLUA_FUNCTION wslua_ws_dofile(lua_State* L) {
    /* This is like Lua's dofile(), except that 1) if a file does not
    exist in the current directory it will look for it in Wireshark's
    user and system directories and 2) pathnames are, on Windows, treated
    as UTF-8 strings rather than strings in the current code page. */
#define WSLUA_ARG_dofile_FILENAME 1 /* Name of the file to be run. */
    const char *given_fname = luaL_checkstring(L, WSLUA_ARG_dofile_FILENAME);
    char* filename = wslua_get_actual_filename(given_fname);
    int n;

    if (!filename) {
        WSLUA_ARG_ERROR(dofile,FILENAME,"file does not exist");
        return 0;
    }

    n = lua_gettop(L);
    /* Use our loadfile, so that, on Windows, we handle UTF-8 file names. */
    if (our_loadfile(L, filename) != 0) lua_error(L);
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
    stat_tap_ui ui_info;

    sc->L = L;
    lua_pushvalue(L, WSLUA_OPTARG_register_stat_cmd_arg_ACTION);
    sc->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,1);

    ui_info.group = REGISTER_STAT_GROUP_UNSORTED;  /* XXX - need group for CLI-only? */
    ui_info.title = NULL;
    ui_info.cli_string = arg;
    ui_info.tap_init_cb = statcmd_init;
    ui_info.nparams = 0;
    ui_info.params = NULL;
    register_stat_tap_ui(&ui_info, sc);
    return 0;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
