/*
 * lua_tap.c
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

LUA_CLASS_DEFINE(Tap,TAP,NOP);
LUA_CLASS_DEFINE(Interesting,INTERESTING,NOP);

static int Interesting_get (lua_State *L) {
    const gchar* name = luaL_checkstring(L,1);
    Interesting i;
    
    if (!name) return 0;
    
    i = proto_registrar_get_byname(name);
    
    if (!i) {
        luaL_error(L,"Could not find field `%s'",name);
        return 0;
    }
    
    pushInteresting(L,i);
    return 1;
}    

static int Interesting_fetch (lua_State* L) {
    Interesting in = checkInteresting(L,1);
    int items_found = 0;
    
    for (;in;in = in->same_name_next) {
        GPtrArray* found = proto_find_finfo(lua_tree, in->id);
        guint i;
        
        for (i=0; i<found->len; i++) {
            field_info* fi = g_ptr_array_index(found,i);
            switch(fi->hfinfo->type) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                case FT_FRAMENUM:
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    lua_pushnumber(L,(lua_Number)fvalue_get_integer(&(fi->value)));
                    items_found++;
                    break;
                case FT_FLOAT:
                case FT_DOUBLE:
                    lua_pushnumber(L,(lua_Number)fvalue_get_floating(&(fi->value)));
                    items_found++;
                    break;
                case FT_UINT64:
                case FT_INT64:
                    /* XXX: get them as strings for now */
                case FT_STRING:
                case FT_STRINGZ:
                case FT_ETHER:
                case FT_BYTES:
                case FT_UINT_BYTES:
                case FT_IPv4:
                case FT_IPv6:
                case FT_IPXNET:
                case FT_GUID:
                case FT_OID:
                    lua_pushstring(L,fvalue_to_string_repr(&fi->value,FTREPR_DISPLAY,NULL));
                    items_found++;
                    break;
                default:
                    luaL_error(L,"FT_ not yet supported");
                    return items_found;
            }
        }
    }
    
    return items_found;
    
}

static int Interesting_tostring (lua_State* L) {
    Interesting in = checkInteresting(L,1);
    
    lua_pushfstring(L,"Interesting: %s",in->abbrev);
    return 1;
}

static const luaL_reg Interesting_methods[] = {
    {"get", Interesting_get},
    {"fetch", Interesting_fetch },
    {0,0}
};

static const luaL_reg Interesting_meta[] = {
    {"__tostring", Interesting_tostring},
    {0, 0}
};

int Interesting_register(lua_State* L) {
    luaL_openlib(L, INTERESTING, Interesting_methods, 0);
    luaL_newmetatable(L, INTERESTING);
    luaL_openlib(L, 0, Interesting_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
};


static int Tap_new(lua_State* L) {
    const gchar* name = luaL_checkstring(L,1);
    Tap tap;
    
    if (!name) return 0;
    
    if( find_tap_id(name) ) {
        luaL_error(L,"a tap with this name exists already");
        return 0;
    }

    tap = g_malloc(sizeof(struct _eth_tap));
    
    tap->name = g_strdup(name);
    tap->interesting_fields = g_ptr_array_new();
    tap->filter = NULL;
    
    pushTap(L,tap);
    return 1;
}

static int Tap_add(lua_State* L) {
    Tap tap = checkTap(L,1);
    Interesting in = checkInteresting(L,2);
    
    if (!(tap && in)) return 0;
    
    g_ptr_array_add(tap->interesting_fields,in);
    
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

static int Tap_set_filter(lua_State* L) {
    Tap tap = checkTap(L,1);
    const gchar* filter = luaL_checkstring(L,2);
    
    if (!(tap && filter)) return 0;
    
    if (tap->filter) {
        luaL_error(L,"tap has filter already");
        return 0;
    }

    tap->filter = g_strdup(filter);
    
    return 0;
}

static int Tap_register_to_ethereal(lua_State*L) {
    Tap tap = checkTap(L,1);
    GString* filter_s;
    GString* error;
    GPtrArray* ins;
    guint i;

    if (!tap) return 0;

    filter_s = g_string_new("");
    
    if (tap->filter)
        g_string_sprintfa(filter_s,"( %s ) && frame ",tap->filter);
    
    g_free(tap->filter);

    ins = tap->interesting_fields;

    for (i=0; i < ins->len; i++) {
        Interesting in = g_ptr_array_index(ins,i);
        g_string_sprintfa(filter_s," ||%s",in->abbrev);
    }

    tap->filter = filter_s->str;
    g_string_free(filter_s,FALSE);

    error = register_tap_listener("frame", tap, tap->filter, lua_tap_reset, lua_tap_packet, lua_tap_draw);

    if (error) {
        luaL_error(L,"tap registration error: %s",error);
        g_string_free(error,TRUE);
    }
    
    return 0;
}

static const luaL_reg Tap_methods[] = {
    {"new", Tap_new},
    {"add", Tap_add},
    {"set_filter", Tap_set_filter},
    {"register", Tap_register_to_ethereal},
    {0,0}
};

static const luaL_reg Tap_meta[] = {
    {"__tostring", Tap_tostring},
    {0, 0}
};

int Tap_register(lua_State* L) {
    luaL_openlib(L, TAP, Tap_methods, 0);
    luaL_newmetatable(L, TAP);
    luaL_openlib(L, 0, Tap_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
};

