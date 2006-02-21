/*
 * packet-lua.c
 *
 * Ethereal's interface to the Lua Programming Language
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
#include <epan/nstime.h>
#include <math.h>
#include <epan/expert.h>
#include <epan/ex-opt.h>
#include <epan/privileges.h>

static lua_State* L = NULL;

packet_info* lua_pinfo;
proto_tree* lua_tree;
tvbuff_t* lua_tvb;
int lua_malformed;
int lua_dissectors_table_ref;

dissector_handle_t lua_data_handle;


const gchar* lua_shiftstring(lua_State* L, int i) {
    const gchar* p = luaL_checkstring(L, i);

    if (p) {
        lua_remove(L,i);
        return p;
    } else {
        return NULL;
    }
}

static int elua_format_date(lua_State* LS) {
    lua_Number time = luaL_checknumber(LS,1);
    nstime_t then;
    gchar* str;
    
    then.secs = (guint32)floor(time);
    then.nsecs = (guint32) ( (time-(double)(then.secs))*1000000000);
    str = abs_time_to_str(&then);    
    lua_pushstring(LS,str);
    
    return 1;
}

static int elua_format_time(lua_State* LS) {
    lua_Number time = luaL_checknumber(LS,1);
    nstime_t then;
    gchar* str;
    
    then.secs = (guint32)floor(time);
    then.nsecs = (guint32) ( (time-(double)(then.secs))*1000000000);
    str = rel_time_to_str(&then);    
    lua_pushstring(LS,str);
    
    return 1;
}

static int elua_report_failure(lua_State* LS) {
    const gchar* s = luaL_checkstring(LS,1);
    report_failure("%s",s);
    return 0;
}

static int elua_not_register_menu(lua_State* L) {
    luaL_error(L,"too late to register a menu");
    return 0;    
}

static int elua_not_print(lua_State* L) {
    luaL_error(L,"do not use print use either a TextWindow or critical(),\n"
               "warn(), message(), info() or debug()");
    return 0;        
}

int elua_log(lua_State* L, GLogLevelFlags log_level) {
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

int elua_critical( lua_State* L ) { elua_log(L,G_LOG_LEVEL_CRITICAL); return 0; }
int elua_warn( lua_State* L ) { elua_log(L,G_LOG_LEVEL_WARNING); return 0; }
int elua_message( lua_State* L ) { elua_log(L,G_LOG_LEVEL_MESSAGE); return 0; }
int elua_info( lua_State* L ) { elua_log(L,G_LOG_LEVEL_INFO); return 0; }
int elua_debug( lua_State* L ) { elua_log(L,G_LOG_LEVEL_DEBUG); return 0; }


void dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {
    lua_pinfo = pinfo;
    lua_tree = tree;
    lua_tvb = tvb;

    /*
     * almost equivalent to Lua:
     * dissectors[current_proto](tvb,pinfo,tree)
     */
    
    lua_settop(L,0);

    lua_rawgeti(L, LUA_REGISTRYINDEX, lua_dissectors_table_ref);    
    
    lua_pushstring(L, pinfo->current_proto);
    lua_gettable(L, -2);  

    lua_remove(L,1);

    
    if (lua_isfunction(L,1)) {
        
        push_Tvb(L,tvb);
        push_Pinfo(L,pinfo);
        push_ProtoTree(L,tree);
        
        if  ( lua_pcall(L,3,0,0) ) {
            const gchar* error = lua_tostring(L,-1);

            proto_item* pi = proto_tree_add_text(tree,tvb,0,0,"Lua Error: %s",error);
            expert_add_info_format(pinfo, pi, PI_DEBUG, PI_ERROR ,"Lua Error");
        }
    } else {
        proto_item* pi = proto_tree_add_text(tree,tvb,0,0,"Lua Error: did not find the %s dissector"
                                             " in the dissectors table",pinfo->current_proto);
        
        expert_add_info_format(pinfo, pi, PI_DEBUG, PI_ERROR ,"Lua Error");
    }
    
    clear_outstanding_tvbs();
    clear_outstanding_pinfos();
    clear_outstanding_trees();

    
    lua_pinfo = NULL;
    lua_tree = NULL;
    lua_tvb = NULL;

}

static void iter_table_and_call(lua_State* LS, int env, const gchar* table_name, lua_CFunction error_handler) {
    lua_settop(LS,0);
    
    lua_pushcfunction(LS,error_handler);
    lua_pushstring(LS, table_name);
    lua_gettable(LS, env);
    
    if (!lua_istable(LS, 2)) {
        report_failure("Lua: either `%s' does not exist or it is not a table!\n",table_name);
        lua_close(LS);
        L = NULL;
        return;
    }

    lua_pushnil(LS);
    
    while (lua_next(LS, 2)) {
        const gchar* name = lua_tostring(L,-2);

        if (lua_isfunction(LS,-1)) {

            if ( lua_pcall(LS,0,0,1) ) {
                    lua_pop(LS,1);
            }
            
        } else {
            report_failure("Lua: Something not a function got its way into the %s.%s",table_name,name);
            lua_close(LS);
            L = NULL;
            return;
        }
    }

    lua_settop(LS,0);
}

gboolean lua_initialized = FALSE;

static int init_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of Initialization:\n %s",error);
    return 0;
}

static void init_lua(void) {
    if ( ! lua_initialized ) {

        lua_prime_all_fields(NULL);
        
        lua_register_subtrees();
            
        lua_initialized = TRUE;
    }
    
    if (L) {
        iter_table_and_call(L, LUA_GLOBALSINDEX, LUA_INIT_ROUTINES,init_error_handler);
    }

}

static const char *getF(lua_State *L _U_, void *ud, size_t *size)
{
    FILE *f=(FILE *)ud;
    static char buff[512];
    if (feof(f)) return NULL;
    *size=fread(buff,1,sizeof(buff),f);
    return (*size>0) ? buff : NULL;
}

static int lua_main_error_handler(lua_State* LS) {
    const gchar* error =  lua_tostring(LS,1);
    report_failure("Lua: Error during loading:\n %s",error);
    return 0;
}

void lua_load_script(const gchar* filename) {
    FILE* file;

    if (! ( file = fopen(filename,"r")) ) {
        report_open_failure(filename,errno,FALSE);
        return;
    }

    lua_settop(L,0);
    
    lua_pushcfunction(L,lua_main_error_handler);
    
    switch (lua_load(L,getF,file,filename)) {
        case 0:
            lua_pcall(L,0,0,1);
            fclose(file);
            return;
        case LUA_ERRSYNTAX: {
            report_failure("Lua: syntax error during precompilation of `%s':\n%s",filename,lua_tostring(L,-1));
            fclose(file);
            return;
        }
        case LUA_ERRMEM:
            report_failure("Lua: memory allocation error during execution of %s",filename);
            fclose(file);
            return;
    }
    
}

static void basic_logger(const gchar *log_domain _U_,
                          GLogLevelFlags log_level _U_,
                          const gchar *message,
                          gpointer user_data _U_) {
    fputs(message,stderr);
}

void register_lua(void) {
    const gchar* filename;
    const funnel_ops_t* ops = funnel_get_funnel_ops();
    gboolean run_anyway = FALSE;
    
    /* set up the logger */
    g_log_set_handler(LOG_DOMAIN_LUA, G_LOG_LEVEL_CRITICAL|
                      G_LOG_LEVEL_WARNING|
                      G_LOG_LEVEL_MESSAGE|
                      G_LOG_LEVEL_INFO|
                      G_LOG_LEVEL_DEBUG,
                      ops ? ops->logger : basic_logger, NULL);
    
	ELUA_INIT(L);
    
    /* load ethereal's API */
	ELUA_REGISTER_CLASSES(L);    
    
    /* print has been changed to yield an error if used */
    lua_pushstring(L, "print");
    lua_pushcfunction(L, elua_not_print);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    /* logger functions */
	ELUA_REGISTER_FUNCTION(critical);
	ELUA_REGISTER_FUNCTION(warn);
	ELUA_REGISTER_FUNCTION(info);
	ELUA_REGISTER_FUNCTION(message);
	ELUA_REGISTER_FUNCTION(debug);
	
	/* Utility functions */
	ELUA_REGISTER_FUNCTION(format_date);
	ELUA_REGISTER_FUNCTION(format_time);
	ELUA_REGISTER_FUNCTION(report_failure);

	/* Functions declared in  modules */
	ELUA_REGISTER_FUNCTIONS();
    
    /* the init_routines table (accessible by the user) */
    lua_pushstring(L, LUA_INIT_ROUTINES);
    lua_newtable (L);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    /* the dissectors table goes in the registry (not accessible) */
    lua_newtable (L);
    lua_dissectors_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    /* set running_superuser variable to it's propper value */
    lua_pushstring(L,"running_superuser");
    lua_pushboolean(L,started_with_special_privs());
    lua_settable(L, LUA_GLOBALSINDEX);    

    /* load system's init.lua */
    filename = get_datafile_path("init.lua");
    
    if (( file_exists(filename))) {
        lua_load_script(filename);
    }
    
    /* check if lua is to be disabled */
    lua_pushstring(L,"lua_disabled");
    lua_gettable(L, LUA_GLOBALSINDEX);
    
    if (lua_isboolean(L,-1) && lua_toboolean(L,-1)) {
        /* disable lua */
        lua_close(L);
        L = NULL;
        return;
    }
    
    /* check whether we should run other scripts even if running superuser */
    lua_pushstring(L,"run_user_scripts_when_superuser");
    lua_gettable(L, LUA_GLOBALSINDEX);
    
    if (lua_isboolean(L,-1) && lua_toboolean(L,-1)) {
        run_anyway = TRUE;
    }


    /* if we are indeed superuser run user scripts only if told to do so */
    if ( (!started_with_special_privs()) || run_anyway ) {
        filename = get_persconffile_path("init.lua", FALSE);
        
        if (( file_exists(filename))) {
            lua_load_script(filename);
        }
        
        while((filename = ex_opt_get_next("lua_script"))) {
            lua_load_script(filename);
        }
    }
    
    /* at this point we're set up so register the init routine */
    register_init_routine(init_lua);    
    
    /*
     * after this point it is too late to register a menu
     * disable the function to avoid weirdness
     */
    lua_pushstring(L, "register_menu");
    lua_pushcfunction(L, elua_not_register_menu);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    /* set up some essential globals */
    lua_pinfo = NULL;
    lua_tree = NULL;
    lua_tvb = NULL;
    
    lua_data_handle = find_dissector("data");
    lua_malformed = proto_get_id_by_filter_name("malformed");
    
    return;
}

void proto_register_lua(void)
{
    register_final_registration_routine(register_lua);
}
