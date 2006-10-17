/*
 *  wslua_util.c
 *  
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 * 
 * $Id: wslua_util.c 18197 2006-05-21 05:12:17Z sahlberg $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "wslua.h"
#include <math.h>

WSLUA_API const gchar* lua_shiftstring(lua_State* L, int i) {
    const gchar* p = luaL_checkstring(L, i);
	
    if (p) {
        lua_remove(L,i);
        return p;
    } else {
        return NULL;
    }
}

WSLUA_FUNCTION wslua_format_date(lua_State* LS) { /* Formats an absolute timestamp into a human readable date */ 
#define WSLUA_ARG_format_date_TIMESTAMP 1 /* A timestamp value to convert. */
	lua_Number time = luaL_checknumber(LS,WSLUA_ARG_format_date_TIMESTAMP);
	nstime_t then;
	gchar* str;

	then.secs = (guint32)floor(time);
	then.nsecs = (guint32) ( (time-(double)(then.secs))*1000000000);
	str = abs_time_to_str(&then);    
	lua_pushstring(LS,str);

	WSLUA_RETURN(1); /* a string with the formated date */
}

WSLUA_FUNCTION wslua_format_time(lua_State* LS) { /* Formats an absolute timestamp in a human readable form */
#define WSLUA_ARG_format_time_TIMESTAMP 1 /* a timestamp value to convert */
	lua_Number time = luaL_checknumber(LS,WSLUA_ARG_format_time_TIMESTAMP);
	nstime_t then;
	gchar* str;

	then.secs = (guint32)floor(time);
	then.nsecs = (guint32) ( (time-(double)(then.secs))*1000000000);
	str = rel_time_to_str(&then);    
	lua_pushstring(LS,str);

	WSLUA_RETURN(1); /* a string with the formated time */
}

WSLUA_FUNCTION wslua_report_failure(lua_State* LS) { /* reports a failure to the user */
#define WSLUA_ARG_report_failure_TEXT 1 /* message */
	const gchar* s = luaL_checkstring(LS,WSLUA_ARG_report_failure_TEXT);
	report_failure("%s",s);
	return 0;
}

static int wslua_log(lua_State* L, GLogLevelFlags log_level) {
    GString* str = g_string_new("");
    int n = lua_gettop(L);  /* number of arguments */
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
/* WSLUA_MOREARGS critical objects to be printed	*/
	wslua_log(L,G_LOG_LEVEL_CRITICAL);
	return 0;
}
WSLUA_FUNCTION wslua_warn( lua_State* L ) { /* Will add a log entry with warn severity */
/* WSLUA_MOREARGS warn objects to be printed	*/
	wslua_log(L,G_LOG_LEVEL_WARNING);
	return 0;
}
WSLUA_FUNCTION wslua_message( lua_State* L ) { /* Will add a log entry with message severity */
/* WSLUA_MOREARGS message objects to be printed	*/
	wslua_log(L,G_LOG_LEVEL_MESSAGE);
	return 0;
}
WSLUA_FUNCTION wslua_info( lua_State* L ) { /* Will add a log entry with info severity */
/* WSLUA_MOREARGS info objects to be printed	*/
	wslua_log(L,G_LOG_LEVEL_INFO);
	return 0;
}
WSLUA_FUNCTION wslua_debug( lua_State* L ) { /* Will add a log entry with debug severity */
/* WSLUA_MOREARGS debug objects to be printed	*/
	wslua_log(L,G_LOG_LEVEL_DEBUG);
	return 0;
}

const char* get_actual_filename(const char* fname) {
	const char* filename;
	
	if ( file_exists(fname) ) {
		return fname;
	}
	
	filename = get_persconffile_path(fname,FALSE);
	
	if ( file_exists(filename) ) {
		return filename;
	}
	
	filename = get_datafile_path(fname);

	return filename;
}

WSLUA_FUNCTION wslua_loadfile(lua_State* L) {
#define WSLUA_ARG_loadfile_FILENAME 1
	const char *given_fname = luaL_checkstring(L, WSLUA_ARG_loadfile_FILENAME);
	const char* filename;
	
	filename = get_actual_filename(given_fname);
	
	if (!filename) WSLUA_ARG_ERROR(loadfile,FILENAME,"file does not exist");
	
	if (luaL_loadfile(L, filename) == 0) {
		return 1;
	} else {
		lua_pushnil(L);
		lua_insert(L, -2);
		return 2;
	}
}

WSLUA_FUNCTION wslua_dofile(lua_State* L) {
#define WSLUA_ARG_dofile_FILENAME 1
	const char *given_fname = luaL_checkstring(L, WSLUA_ARG_dofile_FILENAME);
	const char* filename;
	int n;
	
	if (!given_fname) WSLUA_ARG_ERROR(dofile,FILENAME,"must be a string");
	
	filename = get_actual_filename(given_fname);
	
	if (!filename)  WSLUA_ARG_ERROR(dofile,FILENAME,"file does not exist");
	
	n = lua_gettop(L);
	if (luaL_loadfile(L, filename) != 0) lua_error(L);
	lua_call(L, 0, LUA_MULTRET);
	return lua_gettop(L) - n;
}


WSLUA_FUNCTION wslua_persconffile_path(lua_State* L) {
#define WSLUA_OPTARG_persconffile_path_FILENAME 1
	const char *fname = luaL_optstring(L, WSLUA_OPTARG_persconffile_path_FILENAME,"");
	const char* filename = get_persconffile_path(fname,FALSE);
	
	lua_pushstring(L,filename);
	return 1;
}

WSLUA_FUNCTION wslua_datafile_path(lua_State* L) {
#define WSLUA_OPTARG_datafile_path_FILENAME 1
	const char *fname = luaL_optstring(L, WSLUA_OPTARG_datafile_path_FILENAME,"");
	const char* filename = get_datafile_path(fname);

	lua_pushstring(L,filename);
	return 1;
}


WSLUA_CLASS_DEFINE(Dir,NOP,NOP); /* A Directory */

WSLUA_CONSTRUCTOR wslua_Dir_open(lua_State* L) {
#define WSLUA_ARG_Dir_open_PATHNAME 1
#define WSLUA_OPTARG_Dir_open_EXTENSION 2
	
	const char* dirname = luaL_checkstring(L,WSLUA_ARG_Dir_open_PATHNAME);
	const char* extension = luaL_optstring(L,WSLUA_OPTARG_Dir_open_EXTENSION,NULL);
	Dir dir;

	if (!dirname) WSLUA_ARG_ERROR(Dir_open,PATHNAME,"must be a string");
	if (!test_for_directory(dirname))  WSLUA_ARG_ERROR(Dir_open, PATHNAME, "must be a directory");

	dir = g_malloc(sizeof(struct _wslua_dir));
	dir->dir = OPENDIR_OP(dirname);
	dir->ext = extension ? g_strdup(extension) : NULL;
#if GLIB_MAJOR_VERSION >= 2
	dir->dummy = g_malloc(sizeof(GError *));
	*(dir->dummy) = NULL;
#endif
	
	if (dir->dir == NULL) {
#if GLIB_MAJOR_VERSION >= 2
		g_free(dir->dummy);
#endif
		g_free(dir);

		WSLUA_ARG_ERROR(Dir_open,PATHNAME,"could not open directory");
		return 0;
	}
	
	pushDir(L,dir);
	return 1;
}

WSLUA_METAMETHOD wslua_Dir__call(lua_State* L) {
#define WSLUA_ARG_Dir__call_DIR 1
	Dir dir = checkDir(L,1);
	const FILE_T* file;
	const gchar* filename;
	const char* ext;
	
	if (!dir) 
		WSLUA_ARG_ERROR(Dir__call,DIR,"must be a Dir");

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

WSLUA_METHOD wslua_Dir_close(lua_State* L) {
#define WSLUA_ARG_Dir_close_DIR 1
	Dir dir = checkDir(L,1);

	if (dir->dir) {
		CLOSEDIR_OP(dir->dir);
		dir->dir = NULL;
	}

	return 0;
}

WSLUA_METAMETHOD wslua_Dir__gc(lua_State* L) {
#define WSLUA_ARG_Dir__gc_DIR 1
	Dir dir = checkDir(L,1);
	
	if (dir->dir) {
		CLOSEDIR_OP(dir->dir);
	}
	
#if GLIB_MAJOR_VERSION >= 2
	g_free(dir->dummy);
#endif
	
	if (dir->ext) g_free(dir->ext);

	g_free(dir);
	
	return 0;
}

static const luaL_reg Dir_methods[] = {
    {"open", wslua_Dir_open},
    {"close", wslua_Dir_close},
    {0, 0}
};

static const luaL_reg Dir_meta[] = {
    {"__call", wslua_Dir__call},
    {"__gc", wslua_Dir__gc},
    {0, 0}
};

int Dir_register(lua_State* L) {
	
    WSLUA_REGISTER_CLASS(Dir);
	
    return 1;
}
