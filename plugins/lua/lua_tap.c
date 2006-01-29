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

LUA_CLASS_DEFINE(Tap,TAP,NOP)
LUA_CLASS_DEFINE(Field,FIELD,NOP)

static GPtrArray* wanted_fields = NULL;
static GPtrArray* lua_taps = NULL;
static gboolean taps_registered = FALSE;

/* XXX this will be used in the future, called from somewhere in packet.c */
#if 0
void lua_prime_all_fields(proto_tree* tree) {
    guint i;
    
    for(i=0; i < wanted_fields->len; i++) {
        Field f = g_ptr_array_index(wanted_fields,i);
        for (;f;f = f->same_name_next) {
            proto_tree_prime_hfid(tree,f->id);
        }
    }
}
#else
/* XXX - this will be used while we are a plugin */

void lua_prime_all_fields(proto_tree* tree _U_) {
    GString* fake_tap_filter = g_string_new("frame");
    guint i;
    static gboolean fake_tap;
    
    
    if ( !wanted_fields || fake_tap ) return;

    fake_tap = FALSE;
    
    for(i=0; i < wanted_fields->len; i++) {
        Field f = g_ptr_array_index(wanted_fields,i);
        g_string_sprintfa(fake_tap_filter," || %s",f->abbrev);
        fake_tap = TRUE;
    }
    
    if (fake_tap) {
        /* a boring tap :-) */
        GString* error = register_tap_listener("frame",
                                      &fake_tap,
                                      fake_tap_filter->str,
                                      NULL, NULL, NULL);
        
        if (error) {
            report_failure("while regitering lua_fake_tap:\n%s",error->str);
            g_string_free(error,TRUE);
        }
    }
    
}
#endif

static int Field_get (lua_State *L) {
    const gchar* name = luaL_checkstring(L,1);
    Field f;
    
    if (!name) return 0;
    
    f = proto_registrar_get_byname(name);
    
    if (!f) {
        luaL_error(L,"Could not find field `%s'",name);
        return 0;
    }
    
    if (!wanted_fields)
        wanted_fields = g_ptr_array_new();
    
    g_ptr_array_add(wanted_fields,f);
    
    pushField(L,f);
    return 1;
}    

static int Field_fetch (lua_State* L) {
    Field in = checkField(L,1);
    int items_found = 0;
    
    for (;in;in = in->same_name_next) {
        GPtrArray* found = proto_find_finfo(lua_tree, in->id);
        guint i;
        if (found) {
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
                    case FT_ETHER:
                    case FT_IPv4:
                    case FT_IPv6:
                    case FT_IPXNET:
                        /* XXX -> Address */
                    case FT_STRING:
                    case FT_STRINGZ:
                    case FT_BYTES:
                    case FT_UINT_BYTES:
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
    }
    return items_found;
    
}

static int Field_tostring (lua_State* L) {
    Field in = checkField(L,1);
    
    lua_pushfstring(L,"Field: %s",in->abbrev);
    return 1;
}

static const luaL_reg Field_methods[] = {
    {"get", Field_get},
    {"fetch", Field_fetch },
    {0,0}
};

static const luaL_reg Field_meta[] = {
    {"__tostring", Field_tostring},
    {0, 0}
};

int Field_register(lua_State* L) {
    luaL_openlib(L, FIELD, Field_methods, 0);
    luaL_newmetatable(L, FIELD);
    luaL_openlib(L, 0, Field_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}


static int Tap_new(lua_State* L) {
    const gchar* name = luaL_checkstring(L,1);
    const gchar* filter = luaL_optstring(L,2,NULL);
    Tap tap;
    
    if (!name) return 0;
    
    tap = g_malloc(sizeof(struct _eth_tap));
    
    tap->name = g_strdup(name);
    tap->filter = g_strdup(filter);

    if (!lua_taps)
        lua_taps = g_ptr_array_new();
    
    g_ptr_array_add(lua_taps,tap);
    
    
    pushTap(L,tap);
    return 1;
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

GString* lua_register_all_taps(void) {
    
    if (!lua_taps || taps_registered) return NULL;

    while (lua_taps->len) {
        Tap tap = g_ptr_array_remove_index(lua_taps,0);
        GString* error;

        error = register_tap_listener("frame", tap, tap->filter, lua_tap_reset, lua_tap_packet, lua_tap_draw);
    
        if (error) {
            return error;
        }
        
        taps_registered = TRUE;
    }
    
    
    return NULL;
    
}

static const luaL_reg Tap_methods[] = {
    {"new", Tap_new},
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
}

