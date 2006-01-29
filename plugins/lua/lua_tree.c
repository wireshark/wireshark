/*
 * lua_tree.c
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
#include <epan/expert.h>

LUA_CLASS_DEFINE(ProtoTree,PROTO_TREE,NOP)
LUA_CLASS_DEFINE(ProtoItem,ITEM,NOP)
LUA_CLASS_DEFINE(SubTree,SUBTREE,NOP)


/*
 * SubTree class
 */


static GArray* lua_etts = NULL;
static gint lua_ett = -1;

void lua_register_subtrees(void) {
    gint* ettp = &lua_ett;

    if (!lua_etts) 
        lua_etts = g_array_new(FALSE,FALSE,sizeof(gint*));

    g_array_append_val(lua_etts,ettp);
    
    proto_register_subtree_array((gint**)lua_etts->data,lua_etts->len);
}

static int SubTree_new(lua_State* L) {
    SubTree e;
    
    if (lua_initialized)
        luaL_error(L,"a SubTree can be created only before initialization");
    
    e = g_malloc(sizeof(gint));
    *e = -1;
    
    if (!lua_etts) 
        lua_etts = g_array_new(FALSE,FALSE,sizeof(gint*));
    
    g_array_append_val(lua_etts,e);
    
    pushSubTree(L,e);
    
    return 1;
}

static int SubTree_tostring(lua_State* L) {
    SubTree e = checkSubTree(L,1);
    gchar* s = g_strdup_printf("SubTree: %i",*e);
    
    lua_pushstring(L,s);
    g_free(s);
    
    return 1;
}


static const luaL_reg SubTree_methods[] = {
    {"new",   SubTree_new},
    {0,0}
};

static const luaL_reg SubTree_meta[] = {
    {"__tostring", SubTree_tostring},
    {0, 0}
};

int SubTree_register(lua_State* L) {
    luaL_openlib(L, SUBTREE, SubTree_methods, 0);
    luaL_newmetatable(L, SUBTREE);
    luaL_openlib(L, 0, SubTree_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}


/* ProtoTree class */

static int ProtoTree_add_item_any(lua_State *L, gboolean little_endian) {
    /*
     called with:
     tree,field,tvb,offset,len,datum
     tree,field,tvb,offset,len
     tree,tvb,offset,len,text
     tree,tvb,text
     */
    ProtoTree tree = checkProtoTree(L,1);
    ProtoItem item = NULL;
    Tvb tvb;
    
    if (!tree) {
        pushProtoItem(L,NULL);
        return 1;
    }
    
    if (( luaL_checkudata (L, 2, TVB) )) {
        tvb = checkTvb(L,2);

        TRY {
            const char* str;
            int offset;
            int len;

            if (lua_isnumber(L,3)) {
                offset = luaL_checkint(L,3);
                len = luaL_checkint(L,4);
                str = lua_tostring(L,5);
            } else if (lua_isstring(L,3)) {
                offset = 0;
                len = 0;
                str = lua_tostring(L,3);
            } else {
                luaL_error(L,"First arg must be either TVB or ProtoField");
                return 0;
            }
        
            item = proto_tree_add_text(tree,tvb,offset,len,"%s",str);
        } CATCH(ReportedBoundsError) {
            proto_tree_add_protocol_format(lua_tree, lua_malformed, lua_tvb, 0, 0, "[Malformed Frame: Packet Length]" );
            luaL_error(L,"Malformed Frame");
            return 0;
        } ENDTRY;
            
    } else if (( luaL_checkudata (L, 2, PROTO_FIELD) )) {
        ProtoField field = checkProtoField(L,2);
        tvb = checkTvb(L,3);

        TRY {
            int offset = luaL_checkint(L,4);
            int len = luaL_checkint(L,5);

            if ( lua_gettop(L) == 6 ) {
                switch(field->type) {
                    case FT_UINT8:
                    case FT_UINT16:
                    case FT_UINT24:
                    case FT_UINT32:
                    case FT_FRAMENUM:
                        item = proto_tree_add_uint(tree,field->hfid,tvb,offset,len,(guint32)luaL_checknumber(L,6));
                        break;
                    case FT_INT8:
                    case FT_INT16:
                    case FT_INT24:
                    case FT_INT32:
                        item = proto_tree_add_int(tree,field->hfid,tvb,offset,len,(gint32)luaL_checknumber(L,6));
                        break;
                    case FT_FLOAT:
                        item = proto_tree_add_float(tree,field->hfid,tvb,offset,len,(float)luaL_checknumber(L,6));
                        break;
                    case FT_DOUBLE:
                        item = proto_tree_add_double(tree,field->hfid,tvb,offset,len,(double)luaL_checknumber(L,6));
                        break;
                    case FT_STRING:
                    case FT_STRINGZ:
                        item = proto_tree_add_string(tree,field->hfid,tvb,offset,len,luaL_checkstring(L,6));
                        break;
                    case FT_UINT64:
                    case FT_INT64:
                    case FT_ETHER:
                    case FT_BYTES:
                    case FT_UINT_BYTES:
                    case FT_IPv4:
                    case FT_IPv6:
                    case FT_IPXNET:
                    case FT_GUID:
                    case FT_OID:
                    default:
                        luaL_error(L,"FT_ not yet supported");
                        return 0;
                }
            } else {
                item = proto_tree_add_item(tree,field->hfid,tvb,offset,len,little_endian);
            }
        } CATCH(ReportedBoundsError) {
            proto_tree_add_protocol_format(lua_tree, lua_malformed, lua_tvb, 0, 0, "[Malformed Frame: Packet Length]" );
            luaL_error(L,"Malformed Frame");
            return 0;
        } ENDTRY;
        
    } else if (( luaL_checkudata (L, 2, PROTO) )) {
        Proto proto = checkProto(L,2);
        tvb = checkTvb(L,3);
        
        TRY {
            int offset = luaL_checkint(L,4);
            int len = luaL_checkint(L,5);
            
            item = proto_tree_add_item(tree,proto->hfid,tvb,offset,len,little_endian);
        } CATCH(ReportedBoundsError) {
            proto_tree_add_protocol_format(lua_tree, lua_malformed, lua_tvb, 0, 0, "[Malformed Frame: Packet Length]" );
            luaL_error(L,"Malformed Frame");
            return 0;
        } ENDTRY;
    } else {
        luaL_error(L,"First arg must be either TVB or ProtoField");
        return 0;
    }
    
    pushProtoItem(L,item);
    return 1;
}

static int ProtoTree_add_item(lua_State *L) { return ProtoTree_add_item_any(L,FALSE); }
static int ProtoTree_add_item_le(lua_State *L) { return ProtoTree_add_item_any(L,TRUE); }

static int ProtoTree_tostring(lua_State *L) {
    ProtoTree tree = checkProtoTree(L,1);
    lua_pushstring(L,ep_strdup_printf("ProtoTree %p",tree));
    return 1;
}


static int ProtoTree_get_parent(lua_State *L) {
    ProtoTree tree = checkProtoTree(L,1);
    proto_item* item = NULL;
    
    if (tree) {
        item = proto_tree_get_parent(tree);
    }
    
    pushProtoItem(L,item);
    
    return 1;
}

static const luaL_reg ProtoTree_methods[] = {
    {"add_item",       ProtoTree_add_item},
    {"add_item_le",       ProtoTree_add_item_le},
    {"get_parent",       ProtoTree_get_parent},
    {0, 0}
};

static const luaL_reg ProtoTree_meta[] = {
    {"__tostring", ProtoTree_tostring},
    {0, 0}
};

int ProtoTree_register(lua_State* L) {
    luaL_openlib(L, PROTO_TREE, ProtoTree_methods, 0);
    luaL_newmetatable(L, PROTO_TREE);
    luaL_openlib(L, 0, ProtoTree_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}

/* ProtoItem class */
static int ProtoItem_tostring(lua_State *L) {
    ProtoItem item = checkProtoItem(L,1);
    lua_pushstring(L,ep_strdup_printf("ProtoItem %p",item));
    return 1;
}

static int ProtoItem_add_subtree(lua_State *L) {
    ProtoItem item = checkProtoItem(L,1);
    ProtoTree tree = NULL;
    
    if (item) {
        SubTree ett = luaL_checkudata(L,2,SUBTREE);
        
        if (ett) {
            tree = proto_item_add_subtree(item,*ett);
        } else {
            tree = proto_item_add_subtree(item,lua_ett);
        }
    }
    
    pushProtoTree(L,tree);
    return 1;
}

static int ProtoItem_set_text(lua_State *L) {
    ProtoItem item = checkProtoItem(L,1);
    
    if (!item) {
        const gchar* s = luaL_checkstring(L,2);
        proto_item_set_text(item,"%s",s);
    }
    
    return 0;
}

static int ProtoItem_append_text(lua_State *L) {
    ProtoItem item = checkProtoItem(L,1);
    const gchar* s;
    
    if (item) {
        s = luaL_checkstring(L,2);
        proto_item_append_text(item,"%s",s);
    }
    return 0;
}

static int ProtoItem_set_len(lua_State *L) {
    ProtoItem item = checkProtoItem(L,1);
    int len;

    if (item) {
        len = luaL_checkint(L,2);
        proto_item_set_len(item,len);
    }
    
    return 0;
}

struct _expert_severity {
    const gchar* str;
    int val;
};

static const struct _expert_severity severities[] = {
    {"PI_CHAT",PI_CHAT},
    {"PI_NOTE",PI_NOTE},
    {"PI_WARN",PI_WARN},
    {"PI_ERROR",PI_ERROR},
    {"PI_CHECKSUM",PI_CHECKSUM},
    {"PI_SEQUENCE",PI_SEQUENCE},
    {"PI_RESPONSE_CODE",PI_RESPONSE_CODE},
    {"PI_UNDECODED",PI_UNDECODED},
    {"PI_REASSEMBLE",PI_REASSEMBLE},
    {"PI_MALFORMED",PI_MALFORMED},
    {"PI_DEBUG",PI_DEBUG},
    {NULL,0}
};

static int str_to_expert(const gchar* str) {
    const struct _expert_severity* s;

    if (!str) return 0;
    
    for(s = severities; s->str; s++) {
        if (g_str_equal(str,s->str)) {
            return s->val;
        }
    }
    return 0;
}

#if 0
static const gchar* expert_to_str(int val) {
    const struct _expert_severity* s;
    for(s = severities; s->str; s++) {
        if (s->val == val) {
            return s->str;
        }
    }
    return NULL;
}
#endif

static int ProtoItem_set_expert_flags(lua_State *L) {
    ProtoItem item = checkProtoItem(L,1);
    int group;
    int severity;

    if (item) {
        group = str_to_expert(luaL_checkstring(L,2));
        severity = str_to_expert(luaL_checkstring(L,3));

        if (group && severity) {
            proto_item_set_expert_flags(item,group,severity);
        }
    }

    return 0;
}

static int ProtoItem_add_expert_info(lua_State *L) {
    ProtoItem item = checkProtoItem(L,1);

    if (item) {
        int group = str_to_expert(luaL_checkstring(L,2));
        int severity = str_to_expert(luaL_checkstring(L,3));
        const gchar* str = luaL_optstring(L,4,"Expert Info");
        
        expert_add_info_format(lua_pinfo, item, group, severity, "%s", str);
    }
    
    return 0;
}

static int ProtoItem_set_generated(lua_State *L) {
    ProtoItem item = checkProtoItem(L,1);
    if (item) {
        PROTO_ITEM_SET_GENERATED(item);
    }
    return 0;
}


static int ProtoItem_set_hidden(lua_State *L) {
    ProtoItem item = checkProtoItem(L,1);
    if (item) {
        PROTO_ITEM_SET_HIDDEN(item);
    }
    return 0;
}

static const luaL_reg ProtoItem_methods[] = {
    {"add_subtree",       ProtoItem_add_subtree},
    {"set_text",       ProtoItem_set_text},
    {"append_text",       ProtoItem_append_text},
    {"set_len",       ProtoItem_set_len},
    {"set_expert_flags",       ProtoItem_set_expert_flags},
    {"add_expert_info",       ProtoItem_add_expert_info},
    {"set_generated",       ProtoItem_set_generated},
    {"set_hidden",       ProtoItem_set_hidden},
    {0, 0}
};

static const luaL_reg ProtoItem_meta[] = {
    {"__tostring", ProtoItem_tostring},
    {0, 0}
};



int ProtoItem_register(lua_State *L) {
   const struct _expert_severity* s;
    
    luaL_openlib(L, ITEM, ProtoItem_methods, 0);
    luaL_newmetatable(L, ITEM);
    luaL_openlib(L, 0, ProtoItem_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    for(s = severities; s->str; s++) {
        lua_pushstring(L, s->str);
        lua_pushstring(L, s->str);
        lua_settable(L, LUA_GLOBALSINDEX);
    }
    
    return 1;
}
