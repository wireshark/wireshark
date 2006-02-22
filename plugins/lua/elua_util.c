/*
 *  elua_util.c
 *  
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 * 
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "elua.h"
#include <math.h>

ELUA_API const gchar* lua_shiftstring(lua_State* L, int i) {
    const gchar* p = luaL_checkstring(L, i);
	
    if (p) {
        lua_remove(L,i);
        return p;
    } else {
        return NULL;
    }
}

ELUA_FUNCTION elua_format_date(lua_State* LS) { /* Formats an absolute timestamp into a human readable date */ 
#define ELUA_ARG_format_date_TIMESTAMP 1 /* A timestamp value to convert. */
lua_Number time = luaL_checknumber(LS,ELUA_ARG_format_date_TIMESTAMP);
nstime_t then;
gchar* str;

then.secs = (guint32)floor(time);
then.nsecs = (guint32) ( (time-(double)(then.secs))*1000000000);
str = abs_time_to_str(&then);    
lua_pushstring(LS,str);

ELUA_RETURN(1); /* a string with the formated date */
}

ELUA_FUNCTION elua_format_time(lua_State* LS) { /* Formats an absolute timestamp in a human readable form */
#define ELUA_ARG_format_time_TIMESTAMP 1 /* a timestamp value to convert */
lua_Number time = luaL_checknumber(LS,ELUA_ARG_format_time_TIMESTAMP);
nstime_t then;
gchar* str;

then.secs = (guint32)floor(time);
then.nsecs = (guint32) ( (time-(double)(then.secs))*1000000000);
str = rel_time_to_str(&then);    
lua_pushstring(LS,str);

ELUA_RETURN(1); /* a string with the formated time */
}

ELUA_FUNCTION elua_report_failure(lua_State* LS) { /* reports a failure to the user */
#define ELUA_ARG_report_failure_TEXT 1 /* message */
const gchar* s = luaL_checkstring(LS,ELUA_ARG_report_failure_TEXT);
report_failure("%s",s);
return 0;
}

static int elua_log(lua_State* L, GLogLevelFlags log_level) {
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
            return luaL_error(L, "`tostring' must return a string to `print'");
        
        if (i>1) g_string_append(str,"\t");
        g_string_append(str,s);
        
        lua_pop(L, 1);  /* pop result */
    }
    
    g_log(LOG_DOMAIN_LUA, log_level, "%s\n", str->str);
    g_string_free(str,TRUE);
    
    return 0;
}

ELUA_FUNCTION elua_critical( lua_State* L ) { /* Will add a log entry with critical severity*/
/* ELUA_MOREARGS critical objects to be printed	*/
elua_log(L,G_LOG_LEVEL_CRITICAL);
return 0;
}
ELUA_FUNCTION elua_warn( lua_State* L ) { /* Will add a log entry with warn severity */
/* ELUA_MOREARGS critical objects to be printed	*/
elua_log(L,G_LOG_LEVEL_WARNING);
return 0;
}
ELUA_FUNCTION elua_message( lua_State* L ) { /* Will add a log entry with message severity */
/* ELUA_MOREARGS critical objects to be printed	*/
elua_log(L,G_LOG_LEVEL_MESSAGE);
return 0;
}
ELUA_FUNCTION elua_info( lua_State* L ) { /* Will add a log entry with info severity */
/* ELUA_MOREARGS critical objects to be printed	*/
elua_log(L,G_LOG_LEVEL_INFO);
return 0;
}
ELUA_FUNCTION elua_debug( lua_State* L ) { /* Will add a log entry with debug severity */
/* ELUA_MOREARGS critical objects to be printed	*/
elua_log(L,G_LOG_LEVEL_DEBUG);
return 0;
}

