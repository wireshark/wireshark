/*
 *  wslua_util.c
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * $Id$
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


WSLUA_FUNCTION wslua_get_version(lua_State* L) { /* Get Wireshark version */
    const gchar* str = VERSION;
    lua_pushstring(L,str);
    WSLUA_RETURN(1); /* version string */
}

WSLUA_FUNCTION wslua_format_date(lua_State* LS) { /* Formats an absolute timestamp into a human readable date */
#define WSLUA_ARG_format_date_TIMESTAMP 1 /* A timestamp value to convert. */
    lua_Number timestamp = luaL_checknumber(LS,WSLUA_ARG_format_date_TIMESTAMP);
    nstime_t then;
    gchar* str;

    then.secs = (guint32)(floor(timestamp));
    then.nsecs = (guint32) ( (timestamp-(double)(then.secs))*1000000000);
    str = abs_time_to_ep_str(&then, ABSOLUTE_TIME_LOCAL, TRUE);
    lua_pushstring(LS,str);

    WSLUA_RETURN(1); /* A string with the formated date */
}

WSLUA_FUNCTION wslua_format_time(lua_State* LS) { /* Formats a relative timestamp in a human readable form */
#define WSLUA_ARG_format_time_TIMESTAMP 1 /* A timestamp value to convert */
    lua_Number timestamp = luaL_checknumber(LS,WSLUA_ARG_format_time_TIMESTAMP);
    nstime_t then;
    gchar* str;

    then.secs = (guint32)(floor(timestamp));
    then.nsecs = (guint32) ( (timestamp-(double)(then.secs))*1000000000);
    str = rel_time_to_ep_str(&then);
    lua_pushstring(LS,str);

    WSLUA_RETURN(1); /* A string with the formated time */
}

WSLUA_FUNCTION wslua_report_failure(lua_State* LS) { /* Reports a failure to the user */
#define WSLUA_ARG_report_failure_TEXT 1 /* Message */
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

WSLUA_FUNCTION wslua_critical( lua_State* L ) { /* Will add a log entry with critical severity*/
/* WSLUA_MOREARGS critical objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_CRITICAL);
    return 0;
}
WSLUA_FUNCTION wslua_warn( lua_State* L ) { /* Will add a log entry with warn severity */
/* WSLUA_MOREARGS warn objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_WARNING);
    return 0;
}
WSLUA_FUNCTION wslua_message( lua_State* L ) { /* Will add a log entry with message severity */
/* WSLUA_MOREARGS message objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_MESSAGE);
    return 0;
}
WSLUA_FUNCTION wslua_info( lua_State* L ) { /* Will add a log entry with info severity */
/* WSLUA_MOREARGS info objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_INFO);
    return 0;
}
WSLUA_FUNCTION wslua_debug( lua_State* L ) { /* Will add a log entry with debug severity */
/* WSLUA_MOREARGS debug objects to be printed    */
    wslua_log(L,G_LOG_LEVEL_DEBUG);
    return 0;
}

/* The returned filename is g_malloc()'d so the caller must free it */
/* except when NULL is returned if file doesn't exist               */
static char* wslua_get_actual_filename(const char* fname) {
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
    in the current directory it will look for it in wireshark's user and system directories */
#define WSLUA_ARG_loadfile_FILENAME 1 /* Name of the file to be loaded */
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
    in the current directory it will look for it in wireshark's user and system directories */
#define WSLUA_ARG_dofile_FILENAME 1 /* Name of the file to be run */
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


WSLUA_FUNCTION wslua_persconffile_path(lua_State* L) {
#define WSLUA_OPTARG_persconffile_path_FILENAME 1 /* A filename */
    const char *fname = luaL_optstring(L, WSLUA_OPTARG_persconffile_path_FILENAME,"");
    char* filename = get_persconffile_path(fname,FALSE);

    lua_pushstring(L,filename);
    g_free(filename);
    WSLUA_RETURN(1); /* The full pathname for a file in the personal configuration directory */
}

WSLUA_FUNCTION wslua_datafile_path(lua_State* L) {
#define WSLUA_OPTARG_datafile_path_FILENAME 1 /* A filename */
    const char *fname = luaL_optstring(L, WSLUA_OPTARG_datafile_path_FILENAME,"");
    char* filename;

    if (running_in_build_directory()) {
        /* Running in build directory, set datafile_path to wslua source directory */
        filename = g_strdup_printf("%s" G_DIR_SEPARATOR_S "epan" G_DIR_SEPARATOR_S "wslua"
                                   G_DIR_SEPARATOR_S "%s", get_datafile_dir(), fname);
    } else {
        filename = get_datafile_path(fname);
    }

    lua_pushstring(L,filename);
    g_free(filename);
    WSLUA_RETURN(1); /* The full pathname for a file in wireshark's configuration directory */
}


WSLUA_CLASS_DEFINE(Dir,FAIL_ON_NULL("Dir"),NOP); /* A Directory */

WSLUA_CONSTRUCTOR Dir_open(lua_State* L) {
    /* Usage: for filename in Dir.open(path) do ... end */
#define WSLUA_ARG_Dir_open_PATHNAME 1 /* The pathname of the directory */
#define WSLUA_OPTARG_Dir_open_EXTENSION 2 /* If given, only file with this extension will be returned */

    const char* dirname = luaL_checkstring(L,WSLUA_ARG_Dir_open_PATHNAME);
    const char* extension = luaL_optstring(L,WSLUA_OPTARG_Dir_open_EXTENSION,NULL);
    Dir dir;
    char* dirname_clean;

    if (!dirname) {
        WSLUA_ARG_ERROR(Dir_open,PATHNAME,"must be a string");
        return 0;
    }

    dirname_clean = wslua_get_actual_filename(dirname);
    if (!dirname_clean) {
        WSLUA_ARG_ERROR(Dir_open,PATHNAME,"directory does not exist");
        return 0;
    }

    if (!test_for_directory(dirname_clean))  {
        g_free(dirname_clean);
        WSLUA_ARG_ERROR(Dir_open,PATHNAME, "must be a directory");
        return 0;
    }

    dir = (Dir)g_malloc(sizeof(struct _wslua_dir));
    dir->dir = OPENDIR_OP(dirname_clean);
    g_free(dirname_clean);
    dir->ext = extension ? g_strdup(extension) : NULL;
    dir->dummy = (GError **)g_malloc(sizeof(GError *));
    *(dir->dummy) = NULL;

    if (dir->dir == NULL) {
        g_free(dir->dummy);
        g_free(dir);

        WSLUA_ARG_ERROR(Dir_open,PATHNAME,"could not open directory");
        return 0;
    }

    pushDir(L,dir);
    WSLUA_RETURN(1); /* the Dir object */
}

WSLUA_METAMETHOD Dir__call(lua_State* L) {
    /* At every invocation will return one file (nil when done) */

    Dir dir = checkDir(L,1);
    const FILE_T* file;
    const gchar* filename;
    const char* ext;

    if (!dir->dir) {
        return 0;
    }

    if ( ! ( file = DIRGETNEXT_OP(dir->dir ) )) {
        CLOSEDIR_OP(dir->dir);
        dir->dir = NULL;
        return 0;
    }


    if ( ! dir->ext ) {
        filename = GETFNAME_OP(file);
        lua_pushstring(L,filename);
        return 1;
    }

    do {
        filename = GETFNAME_OP(file);

        /* XXX strstr returns ptr to first match,
            this fails ext=".xxx" filename="aaa.xxxz.xxx"  */
        if ( ( ext = strstr(filename,dir->ext)) && g_str_equal(ext,dir->ext) ) {
            lua_pushstring(L,filename);
            return 1;
        }
    } while(( file = DIRGETNEXT_OP(dir->dir) ));

    CLOSEDIR_OP(dir->dir);
    dir->dir = NULL;
    return 0;
}

WSLUA_METHOD Dir_close(lua_State* L) {
    /* Closes the directory */
    Dir dir = checkDir(L,1);

    if (dir->dir) {
        CLOSEDIR_OP(dir->dir);
        dir->dir = NULL;
    }

    return 0;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Dir__gc(lua_State* L) {
    Dir dir = toDir(L,1);

    if(!dir) return 0;

    if (dir->dir) {
        CLOSEDIR_OP(dir->dir);
    }

    g_free(dir->dummy);

    if (dir->ext) g_free(dir->ext);

    g_free(dir);

    return 0;
}

static const luaL_Reg Dir_methods[] = {
    {"open", Dir_open},
    {"close", Dir_close},
    { NULL, NULL }
};

static const luaL_Reg Dir_meta[] = {
    {"__call", Dir__call},
    { NULL, NULL }
};

int Dir_register(lua_State* L) {

    WSLUA_REGISTER_CLASS(Dir);

    return 0;
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
    /*  Register a function to handle a -z option */
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

/* Pushes a hex string of the binary data argument. */
int wslua_bin2hex(lua_State* L, const guint8* data, const guint len, const gboolean lowercase, const gchar* sep) {
    luaL_Buffer b;
    guint i = 0;
    static const char byte_to_str_upper[256][3] = {
        "00","01","02","03","04","05","06","07","08","09","0A","0B","0C","0D","0E","0F",
        "10","11","12","13","14","15","16","17","18","19","1A","1B","1C","1D","1E","1F",
        "20","21","22","23","24","25","26","27","28","29","2A","2B","2C","2D","2E","2F",
        "30","31","32","33","34","35","36","37","38","39","3A","3B","3C","3D","3E","3F",
        "40","41","42","43","44","45","46","47","48","49","4A","4B","4C","4D","4E","4F",
        "50","51","52","53","54","55","56","57","58","59","5A","5B","5C","5D","5E","5F",
        "60","61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F",
        "70","71","72","73","74","75","76","77","78","79","7A","7B","7C","7D","7E","7F",
        "80","81","82","83","84","85","86","87","88","89","8A","8B","8C","8D","8E","8F",
        "90","91","92","93","94","95","96","97","98","99","9A","9B","9C","9D","9E","9F",
        "A0","A1","A2","A3","A4","A5","A6","A7","A8","A9","AA","AB","AC","AD","AE","AF",
        "B0","B1","B2","B3","B4","B5","B6","B7","B8","B9","BA","BB","BC","BD","BE","BF",
        "C0","C1","C2","C3","C4","C5","C6","C7","C8","C9","CA","CB","CC","CD","CE","CF",
        "D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","DA","DB","DC","DD","DE","DF",
        "E0","E1","E2","E3","E4","E5","E6","E7","E8","E9","EA","EB","EC","ED","EE","EF",
        "F0","F1","F2","F3","F4","F5","F6","F7","F8","F9","FA","FB","FC","FD","FE","FF"
    };
    static const char byte_to_str_lower[256][3] = {
        "00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f",
        "10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f",
        "20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f",
        "30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f",
        "40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f",
        "50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f",
        "60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f",
        "70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f",
        "80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f",
        "90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f",
        "a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af",
        "b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf",
        "c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf",
        "d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df",
        "e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef",
        "f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"
    };
    const char (*byte_to_str)[3] = byte_to_str_upper;
    const guint last = len - 1;

    if (lowercase) byte_to_str = byte_to_str_lower;

    luaL_buffinit(L, &b);

    for (i = 0; i < len; i++) {
        luaL_addlstring(&b, &(*byte_to_str[data[i]]), 2);
        if (sep && i < last) luaL_addstring(&b, sep);
    }

    luaL_pushresult(&b);

    return 1;
}

/* Pushes a binary string of the hex-ascii data argument. */
int wslua_hex2bin(lua_State* L, const char* data, const guint len, const gchar* sep) {
    luaL_Buffer b;
    guint i = 0;
    guint seplen = 0;
    char c, d;

    static const char str_to_nibble[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    if (sep) seplen = (guint) strlen(sep);

    luaL_buffinit(L, &b);

    for (i = 0; i < len;) {
        c = str_to_nibble[(int)data[i]];
        if (c < 0) {
            if (seplen && strncmp(&data[i], sep, seplen) == 0) {
                i += seplen;
                continue;
            } else {
                break;
            }
        }
        d = str_to_nibble[(int)data[++i]];
        if (d < 0) break;
        luaL_addchar(&b, (c * 16) + d);
        i++;
    }

    luaL_pushresult(&b);

    return 1;
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
