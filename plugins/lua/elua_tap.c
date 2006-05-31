/*
 * lua_tap.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "elua.h"

ELUA_CLASS_DEFINE(Tap,NOP)
/*
    A Tap Listener, is once for called every packet that matches a certain filter.
    It can read the tree and the packet's buffer but it cannot add elements to the tree. 
 */
struct _eth_tap {
    gchar* name;
    gchar* filter;
    lua_State* L;
    int packet_ref;
    int draw_ref;
    int init_ref;
    int data_ref;
};


int tap_packet_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    static gchar* last_error = NULL;
    static int repeated = 0;
    static int next = 2;
	const gchar* where =  (lua_pinfo) ?
		ep_strdup_printf("Lua: on packet %i Error During execution of Tap Packet Callback",lua_pinfo->fd->num) :
		ep_strdup_printf("Lua: Error During execution of Tap Packet Callback") ;
	
    /* show the error the 1st, 3rd, 5th, 9th, 17th, 33th... time it appears to avoid window flooding */ 
    /* XXX the last series of identical errors won't be shown (the user however gets at least one message) */
    
    if (! last_error) {
        report_failure("%s:\n%s",where,error);
        last_error = g_strdup(error);
        repeated = 0;
        next = 2;
        return 0;
    }
    
    if (g_str_equal(last_error,error) ) {
        repeated++;
        if ( repeated == next ) {
            report_failure("%s happened %i times:\n %s",where,repeated,error);
            next *= 2;
        }
    } else {
        report_failure("%s happened %i times:\n %s",where,repeated,last_error);
        g_free(last_error);
        last_error = g_strdup(error);
        repeated = 0;
        next = 2;
        report_failure("%s:\n %s",where,error);
    }
    
    return 0;    
}


int lua_tap_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data _U_) {
    Tap tap = tapdata;
    int retval = 0;

    if (tap->packet_ref == LUA_NOREF) return 0;

    lua_settop(tap->L,0);
    
    lua_pushcfunction(tap->L,tap_packet_cb_error_handler);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->packet_ref);
    
    push_Pinfo(tap->L, pinfo);
    push_Tvb(tap->L, edt->tvb);
    
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->data_ref);
    
    lua_pinfo = pinfo; 
    lua_tvb = edt->tvb;
    lua_tree = ep_alloc(sizeof(struct _eth_treeitem));
	lua_tree->tree = edt->tree;
	lua_tree->item = NULL;
    
    switch ( lua_pcall(tap->L,3,1,1) ) {
        case 0:
            
            if (lua_gettop(tap->L) == 1)
                retval = luaL_checkint(tap->L,1);
            else 
                retval = 1;
            
            break;
        case LUA_ERRRUN:
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling %s.packet() ",tap->name);
            break;
        default:
            g_assert_not_reached();
            break;
    }
    
    clear_outstanding_pinfos();
    clear_outstanding_tvbs();
    
    lua_pinfo = NULL; 
    lua_tvb = NULL;
    lua_tree = NULL;
    
    return retval;
}

int tap_reset_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of Tap init Callback:\n %s",error);
    return 1;
}

void lua_tap_reset(void *tapdata) {
    Tap tap = tapdata;
    
    if (tap->init_ref == LUA_NOREF) return;
    
    lua_pushcfunction(tap->L,tap_reset_cb_error_handler);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->init_ref);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->data_ref);
    
    switch ( lua_pcall(tap->L,1,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            g_warning("Runtime error while calling %s.init() ",tap->name);
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling %s.init() ",tap->name);
            break;
        default:
            g_assert_not_reached();
            break;
    }
}

int tap_draw_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of Tap Draw Callback:\n %s",error);
    return 1;
}

void lua_tap_draw(void *tapdata) {
    Tap tap = tapdata;
    const gchar* error;
    if (tap->draw_ref == LUA_NOREF) return;
    
    lua_pushcfunction(tap->L,tap_reset_cb_error_handler);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->draw_ref);
    lua_rawgeti(tap->L, LUA_REGISTRYINDEX, tap->data_ref);
    
    switch ( lua_pcall(tap->L,1,0,1) ) {
        case 0:
            /* OK */
            break;
        case LUA_ERRRUN:
            error = lua_tostring(tap->L,-1);
            g_warning("Runtime error while calling %s.draw(): %s",tap->name,error);
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling %s.draw() ",tap->name);
            break;
        default:
            g_assert_not_reached();
            break;
    }
}

ELUA_CONSTRUCTOR Tap_new(lua_State* L) {
	/* Creates a new Tap listener */
#define ELUA_ARG_Tap_new_NAME 1 /* the name of the tap */
#define ELUA_ARG_Tap_new_FILTER 2 /* a filter that when matches the tap.packet function gets called (use nil to be called for every packet) */
#define ELUA_OPTARG_Tap_new_USERDATA 3 /* a datum that will be passed as last argument to all tap functions when they get called */

    const gchar* name = luaL_checkstring(L,ELUA_ARG_Tap_new_NAME);
    const gchar* filter = luaL_optstring(L,ELUA_ARG_Tap_new_FILTER,NULL);
    Tap tap;
    GString* error;

    if (!name) ELUA_ARG_ERROR(Tap_new,NAME,"must be a string");
    
    tap = g_malloc(sizeof(struct _eth_tap));
    
    tap->name = g_strdup(name);
    tap->filter = filter ? g_strdup(filter) : NULL;
    tap->L = L;
    tap->packet_ref = LUA_NOREF;
    tap->draw_ref = LUA_NOREF;
    tap->init_ref = LUA_NOREF;

    if (lua_gettop(L) > 2) {
        lua_pushvalue(L, ELUA_OPTARG_Tap_new_USERDATA);
        tap->data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        tap->data_ref = LUA_NOREF;
    }
    
    error = register_tap_listener("frame", tap, tap->filter, lua_tap_reset, lua_tap_packet, lua_tap_draw);

    if (error) {
		/* ELUA_ERROR(new_tap,"tap registration error"); */
        luaL_error(L,"Error while registering tap:\n%s",error->str);
        g_string_free(error,TRUE);
        if (tap->filter) g_free(tap->filter);
        g_free(tap->name);
        luaL_unref(L, LUA_REGISTRYINDEX, tap->data_ref);
        g_free(tap);
    }
    
    pushTap(L,tap);
    ELUA_RETURN(1); /* The newly created Tap listener object */
}

ELUA_METHOD Tap_remove(lua_State* L) {
	/* Removes a tap listener */
    Tap tap = checkTap(L,1);
    
    if (!tap) return 0;
    
    remove_tap_listener(tap);
    
    return 0;
}

static int Tap_tostring(lua_State* L) {
    Tap tap = checkTap(L,1);
    gchar* str;
    
    if (!tap) return 0;
    
    str = g_strdup_printf("Tap->%s filter: %s",tap->name, tap->filter ? tap->filter : "NONE");
    lua_pushstring(L,str);
    g_free(str);
    
    return 1;
}


static int Tap_newindex(lua_State* L) { 
	/* ELUA_ATTRIBUTE Tap_packet WO A function that will be called once every packet matches the Tap listener filter.
	
		function tap.packet(pinfo,tvb,userdata) ... end
	*/
	/* ELUA_ATTRIBUTE Tap_draw WO A function that will be called once every few seconds to redraw the gui objects
				in tshark this funtion is called oly at the very end of the capture file.
	
		function tap.draw(userdata) ... end
	*/
	/* ELUA_ATTRIBUTE Tap_reset WO A function that will be called at the end of the capture run.
	
		function tap.reset(userdata) ... end
	*/
    Tap tap = shiftTap(L,1);
    const gchar* index = lua_shiftstring(L,1);
    int* refp = NULL;
    
    if (!index) return 0;
    
    if (g_str_equal(index,"packet")) {
        refp = &(tap->packet_ref);
    } else if (g_str_equal(index,"draw")) {
        refp = &(tap->draw_ref);
    } else if (g_str_equal(index,"reset")) {
        refp = &(tap->init_ref);
    } else {
        luaL_error(L,"No such attribute `%s' for a tap",index);
        return 0;
    }
    
    if (! lua_isfunction(L,1)) {
        luaL_error(L,"Tap's attribute `%s' must be a function");
        return 0;
    }
    
    lua_pushvalue(L, 1);
    *refp = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}


static const luaL_reg Tap_methods[] = {
    {"new", Tap_new},
    {"remove", Tap_remove},
    {0, 0}
};

static const luaL_reg Tap_meta[] = {
    {"__tostring", Tap_tostring},
    {"__newindex", Tap_newindex},
    {0, 0}
};

int Tap_register(lua_State* L) {
    ELUA_REGISTER_CLASS(Tap);
	return 1;
}

