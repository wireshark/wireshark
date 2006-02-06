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

int lua_gui_enabled(lua_State* L) {
    lua_pushboolean(L,GPOINTER_TO_INT(ops));
    return 1;
}

void lua_menu_callback(gpointer data) {
    struct _lua_menu_data* md = data;

    lua_pushcfunction(md->L,menu_cb_error_handler);
    lua_rawgeti(md->L, LUA_REGISTRYINDEX, md->cb_ref);
    lua_rawgeti(md->L, LUA_REGISTRYINDEX, md->data_ref);
        
    lua_pcall(md->L,1,0,1);
    
    return;
}

extern int lua_register_menu(lua_State* L) {
    const gchar* name = luaL_checkstring(L,1);
    struct _lua_menu_data* md;
    gboolean retap = FALSE;
    
    if (!lua_isfunction(L,2)) {
        luaL_error(L,"register_menu takes a string, a function and another optional datum");
        return 0;
    }
    
    md = g_malloc(sizeof(struct _lua_menu_data));
    md->L = L;
    
    lua_pushvalue(L, 2);
    md->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    if ( lua_gettop(L) > 2) {
        retap = lua_toboolean(L,3);
    }

    if ( lua_gettop(L) > 3) {
        lua_pushvalue(L, 4);
        md->data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        md->data_ref = LUA_NOREF;
    }

    funnel_register_menu(name,
                         REGISTER_STAT_GROUP_GENERIC,
                         lua_menu_callback,
                         md,
                         retap);
    return 0;
}




struct _dlg_cb_data {
    lua_State* L;
    int func_ref;
    int data_ref;
};

static int dlg_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of dialog callback:\n %s",error);
    return 0;
}

static void lua_dialog_cb(gchar** user_input, void* data) {
    struct _dlg_cb_data* dcbd = data;
    int i = 0;
    gchar* input;
    lua_State* L = dcbd->L;
    
    lua_settop(L,0);
    lua_pushcfunction(L,dlg_cb_error_handler);
    lua_rawgeti(L, LUA_REGISTRYINDEX, dcbd->func_ref);
    lua_rawgeti(L, LUA_REGISTRYINDEX, dcbd->data_ref);
    
    for (i = 0; (input = user_input[i]) ; i++) {
        lua_pushstring(L,input);
        g_free(input);
    }
    
    g_free(user_input);
    
    switch ( lua_pcall(L,i+1,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            g_warning("Runtime error while calling dialog callback");
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error while calling dialog callback");
            break;
        default:
            g_assert_not_reached();
            break;
    }
    
}

extern int lua_new_dialog(lua_State* L) {
    const gchar* title;
    int top = lua_gettop(L);
    int i;
    GPtrArray* labels;
    struct _dlg_cb_data* dcbd;
    
    if (! ops) {
        luaL_error(L,"GUI not available");
        return 0;
    }
    
    if (! (title  = luaL_checkstring(L,1)) ) {
        luaL_argerror(L,1,"the title must be a string");
        return 0;
    }
    
    if (! lua_isfunction(L,2)) {
        luaL_argerror(L,2,"must be a function");
        return 0;
    }
    
    if (top < 3) {
        luaL_error(L,"too few arguments");
        return 0;
    }
    
    
    dcbd = g_malloc(sizeof(struct _dlg_cb_data));
    dcbd->L = L;
    
    lua_remove(L,1);
    
    lua_pushvalue(L, 1);
    dcbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,1);
    
    lua_pushvalue(L, 1);
    dcbd->data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_remove(L,1);
    
    labels = g_ptr_array_new();
    
    top -= 3;
    
    for (i = 1; i <= top; i++) {
        gchar* label = (void*)luaL_checkstring(L,i);
        g_ptr_array_add(labels,label);
    }
    
    g_ptr_array_add(labels,NULL);
    
    ops->new_dialog(title, (const gchar**)labels->pdata, lua_dialog_cb, dcbd);
    
    g_ptr_array_free(labels,TRUE);
    
    return 0;
}


/*
 * TextWindow
 */

static int TextWindow_new(lua_State* L) {
    const gchar* title;
    TextWindow tw;
    
    if (!ops) {
        luaL_error(L,"GUI not available");
        return 0;
    }
    
    title = luaL_optstring(L,1,"Untitled Window");
    tw = ops->new_text_window(title);
    pushTextWindow(L,tw);
    
    return 1;
}

struct _close_cb_data {
    lua_State* L;
    int func_ref;
    int data_ref;
};

int text_win_close_cb_error_handler(lua_State* L) {
    const gchar* error =  lua_tostring(L,1);
    report_failure("Lua: Error During execution of TextWindow close callback:\n %s",error);
    return 0;    
}

static void text_win_close_cb(void* data) {
    struct _close_cb_data* cbd = data;
    lua_State* L = cbd->L;

    lua_pushcfunction(L,text_win_close_cb_error_handler);
    lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->func_ref);
    lua_rawgeti(L, LUA_REGISTRYINDEX, cbd->data_ref);
    
    switch ( lua_pcall(L,1,0,1) ) {
        case 0:
            break;
        case LUA_ERRRUN:
            g_warning("Runtime error during execution of TextWindow close callback");
            break;
        case LUA_ERRMEM:
            g_warning("Memory alloc error during execution of TextWindow close callback");
            break;
        default:
            g_assert_not_reached();
            break;
    }
}

static int TextWindow_at_close(lua_State* L) {
    TextWindow tw = shiftTextWindow(L,1);
    struct _close_cb_data* cbd;

    lua_settop(L,2);

    if (! lua_isfunction(L,1)) {
        luaL_error(L,"Window's close callback must be a function");
        return 0;
    }
    
    cbd = g_malloc(sizeof(struct _close_cb_data));

    cbd->L = L;
    cbd->data_ref = luaL_ref(L,  LUA_REGISTRYINDEX);
    cbd->func_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    
    ops->set_close_cb(tw,text_win_close_cb,cbd);
    
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
    {"at_close", TextWindow_at_close},
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


