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

#include "packet-lua.h"
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

static int lua_format_date(lua_State* LS) {
    lua_Number time = luaL_checknumber(LS,1);
    nstime_t then;
    gchar* str;
    
    then.secs = (guint32)floor(time);
    then.nsecs = (guint32) ( (time-(double)(then.secs))*1000000000);
    str = abs_time_to_str(&then);    
    lua_pushstring(LS,str);
    
    return 1;
}

static int lua_format_time(lua_State* LS) {
    lua_Number time = luaL_checknumber(LS,1);
    nstime_t then;
    gchar* str;
    
    then.secs = (guint32)floor(time);
    then.nsecs = (guint32) ( (time-(double)(then.secs))*1000000000);
    str = rel_time_to_str(&then);    
    lua_pushstring(LS,str);
    
    return 1;
}

static int lua_report_failure(lua_State* LS) {
    const gchar* s = luaL_checkstring(LS,1);
    report_failure("%s",s);
    return 0;
}

static int lua_not_register_menu(lua_State* L) {
    luaL_error(L,"too late to register a menu");
    return 0;    
}


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
        
        pushTvb(L,tvb);
        pushPinfo(L,pinfo);
        pushProtoTree(L,tree);
        
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

void register_lua(void) {
    const gchar* filename;
    GPtrArray* filenames = g_ptr_array_new();
    guint i;
    
    filename = get_datafile_path("init.lua");
    
    if (( file_exists(filename))) {
        g_ptr_array_add(filenames,(void*)filename);
    }
    

    if (! started_with_special_privs() ) {
        filename = get_persconffile_path("init.lua", FALSE);
        
        if (( file_exists(filename))) {
            g_ptr_array_add(filenames,(void*)filename);
        }
        
        while((filename = ex_opt_get_next("lua_script"))) {
            g_ptr_array_add(filenames,(void*)filename);
        }
    }
    
    if (! filenames->len) {
        g_ptr_array_free(filenames,TRUE);
        return;
    }
    
    register_init_routine(init_lua);    
    
    L = lua_open();
    
    luaopen_base(L);
    luaopen_table(L);
    luaopen_io(L);
    luaopen_string(L);

    ProtoField_register(L);
    ProtoFieldArray_register(L);
    SubTree_register(L);
    ByteArray_register(L);
    Tvb_register(L);
    TvbRange_register(L);
    Proto_register(L);
    Column_register(L);
    Pinfo_register(L);
    ProtoTree_register(L);
    ProtoItem_register(L);
    Dissector_register(L);
    DissectorTable_register(L);
    Field_register(L);
    Columns_register(L);
    Tap_register(L);
    Address_register(L);
    TextWindow_register(L);

    lua_pushstring(L, "format_date");
    lua_pushcfunction(L, lua_format_date);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "format_time");
    lua_pushcfunction(L, lua_format_time);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "report_failure");
    lua_pushcfunction(L, lua_report_failure);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "register_menu");
    lua_pushcfunction(L, lua_register_menu);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "gui_enabled");
    lua_pushcfunction(L, lua_gui_enabled);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "dialog");
    lua_pushcfunction(L, lua_new_dialog);
    lua_settable(L, LUA_GLOBALSINDEX);

    lua_pushstring(L, LUA_INIT_ROUTINES);
    lua_newtable (L);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_newtable (L);
    lua_dissectors_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    for (i=0 ; i < filenames->len ; i++) {
        filename = g_ptr_array_index(filenames,i);
        lua_load_script(filename);
    }
    
    g_ptr_array_free(filenames,TRUE);
    
    /* after the body it is too late to register a menu */
    lua_pushstring(L, "register_menu");
    lua_pushcfunction(L, lua_not_register_menu);
    lua_settable(L, LUA_GLOBALSINDEX);
    
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
