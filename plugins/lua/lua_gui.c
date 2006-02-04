/*
 *  lua_gui.c
 *  
 *
 *  Created by L. E. G. O. on 2006/02/04.
 *  Copyright 2006 __MyCompanyName__. All rights reserved.
 *
 */

#include "packet-lua.h"

LUA_CLASS_DEFINE(TextWindow,TEXT_WINDOW,NOP)

static const funnel_ops_t* ops = NULL;

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
    {"__GC", TextWindow_gc},
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

