/*
 *  lua_gui.c
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

LUA_CLASS_DEFINE(TextWindow,TEXT_WINDOW,NOP)

static const funnel_ops_t* ops = NULL;

struct _lua_menu_data {
    lua_State* L;
    int cb_ref;
    int data_ref;
};

static int menu_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of Menu Callback:\n %s",error);
    return 0;    
}

void lua_menu_callback(gpointer data) {
    struct _lua_menu_data* md = data;
    int i;

    lua_pushcfunction(md->L,menu_cb_error_handler);
    lua_rawgeti(md->L, LUA_REGISTRYINDEX, md->cb_ref);
    lua_rawgeti(md->L, LUA_REGISTRYINDEX, md->data_ref);
        
    lua_pcall(md->L,1,0,1);
    
    return;
}

extern int lua_register_menu(lua_State* L) {
    const gchar* name = luaL_checkstring(L,1);
    struct _lua_menu_data* md;
    
    if (ops) {
        luaL_error(L,"to late to register_menu");
        return 0;
    }
    
    if (!lua_isfunction(L,2)) {
        luaL_error(L,"register_menu takes a string, a function and another optional datum");
        return 0;
    }
    
    md = g_malloc(sizeof(struct _lua_menu_data));
    md->L = L;
    
    lua_pushvalue(L, 2);
    md->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    if ( lua_gettop(L) > 2) {
        lua_pushvalue(L, 3);
        md->data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        md->data_ref = LUA_NOREF;
    }

    funnel_register_menu(name,
                         REGISTER_STAT_GROUP_GENERIC,
                         lua_menu_callback,
                         md);
}


/*
 * TextWindow
 */

static int TextWindow_new(lua_State* L) {
    const gchar* title;
    TextWindow tw;
    
    if (!ops) {
        luaL_error(L,"GUI system not available");
        return 0;
    }
    
    title = luaL_optstring(L,1,"Untitled Window");
    tw = ops->new_text_window(title);
    pushTextWindow(L,tw);
    
    return 1;
}

static int TextWindow_set_text(lua_State* L) {
    TextWindow tw = shiftTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,1);

    if (!text) return 0;
    
    ops->set_text(tw,text);
    
    pushTextWindow(L,tw);
    return 1;
}

static int TextWindow_append_text(lua_State* L) {
    TextWindow tw = shiftTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,1);
    
    if (!text) return 0;
    
    ops->append_text(tw,text);
    
    pushTextWindow(L,tw);
    return 1;
}

static int TextWindow_prepend_text(lua_State* L) {
    TextWindow tw = shiftTextWindow(L,1);
    const gchar* text = luaL_checkstring(L,1);
    
    if (!text) return 0;
    
    ops->prepend_text(tw,text);
    
    pushTextWindow(L,tw);
    return 1;
}

static int TextWindow_clear_text(lua_State* L) {
    TextWindow tw = shiftTextWindow(L,1);
    
    ops->clear_text(tw);
    
    pushTextWindow(L,tw);
    return 1;
}

static int TextWindow_get_text(lua_State* L) {
    TextWindow tw = shiftTextWindow(L,1);
    const gchar* text = ops->get_text(tw);
    
    lua_pushstring(L,text);
    return 1;
}

static int TextWindow_gc(lua_State* L) {
    TextWindow tw = shiftTextWindow(L,1);
    
    ops->destroy_text_window(tw);
    return 1;
}


static const luaL_reg TextWindow_methods[] = {
    {"new", TextWindow_new},
    {"set", TextWindow_set_text},
    {"append", TextWindow_append_text},
    {"prepend", TextWindow_prepend_text},
    {"clear", TextWindow_clear_text},
    {0, 0}
};

static const luaL_reg TextWindow_meta[] = {
    {"__tostring", TextWindow_get_text},
    {"__gc", TextWindow_gc},
    {0, 0}
};

int TextWindow_register(lua_State* L) {
    
    ops = funnel_get_funnel_ops();
    
    luaL_openlib(L, TEXT_WINDOW, TextWindow_methods, 0);
    luaL_newmetatable(L, TEXT_WINDOW);
    luaL_openlib(L, 0, TextWindow_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}


