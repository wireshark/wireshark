/*
 * elua_tree.c
 *
 * Ethereal's interface to the Lua Programming Language
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
#include <epan/expert.h>

static gint elua_ett = -1;

static GPtrArray* outstanding_stuff = NULL;

#define PUSH_TREEITEM(L,i) g_ptr_array_add(outstanding_stuff,push_TreeItem(L,i))

void* push_TreeItem(lua_State*L, TreeItem t) {
    void** p = (void**)pushTreeItem(L,t);
    g_ptr_array_add(outstanding_stuff,p);
	return p;
}

void clear_outstanding_trees(void) {
    while (outstanding_stuff->len) {
        void** p = (void**)g_ptr_array_remove_index_fast(outstanding_stuff,0);
        *p = NULL;
    }
}

ELUA_CLASS_DEFINE(TreeItem,NOP)

/* ProtoTree class */
static int TreeItem_add_item_any(lua_State *L, gboolean little_endian) {
    TvbRange tvbr;
    Proto proto;
    ProtoField field;
    int hfid = -1;
    int ett = -1;
    ftenum_t type = FT_NONE;
	TreeItem tree_item  = shiftTreeItem(L,1);
	proto_item* item = NULL;
	
    if (!tree_item) {
        return luaL_error(L,"not a TreeItem!");
    }
    if (! ( field = shiftProtoField(L,1) ) ) {
        if (( proto = shiftProto(L,1) )) {
            hfid = proto->hfid;
            type = FT_PROTOCOL;
			ett = proto->ett;
        }
    } else {
        hfid = field->hfid;
        type = field->type;
        ett = field->ett;
    }

    tvbr = shiftTvbRange(L,1);

    if (!tvbr) {
        tvbr = ep_alloc(sizeof(struct _eth_tvbrange));
        tvbr->tvb = lua_tvb;
        tvbr->offset = 0;
        tvbr->len = 0;
    }
    
    if (hfid > 0 ) {
        if (lua_gettop(L)) {
            switch(type) {
                case FT_PROTOCOL:
                    item = proto_tree_add_item(tree_item->tree,hfid,tvbr->tvb,tvbr->offset,tvbr->len,FALSE);
                    lua_pushnumber(L,0);
                    lua_insert(L,1);
                    break;
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                case FT_FRAMENUM:
                    item = proto_tree_add_uint(tree_item->tree,hfid,tvbr->tvb,tvbr->offset,tvbr->len,(guint32)luaL_checknumber(L,1));
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    item = proto_tree_add_int(tree_item->tree,hfid,tvbr->tvb,tvbr->offset,tvbr->len,(gint32)luaL_checknumber(L,1));
                    break;
                case FT_FLOAT:
                    item = proto_tree_add_float(tree_item->tree,hfid,tvbr->tvb,tvbr->offset,tvbr->len,(float)luaL_checknumber(L,1));
                    break;
                case FT_DOUBLE:
                    item = proto_tree_add_double(tree_item->tree,hfid,tvbr->tvb,tvbr->offset,tvbr->len,(double)luaL_checknumber(L,1));
                    break;
                case FT_STRING:
                case FT_STRINGZ:
                    item = proto_tree_add_string(tree_item->tree,hfid,tvbr->tvb,tvbr->offset,tvbr->len,luaL_checkstring(L,1));
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
            
            lua_remove(L,1);

        } else {
            item = proto_tree_add_item(tree_item->tree, hfid, tvbr->tvb, tvbr->offset, tvbr->len, little_endian);
        }
        
        if ( lua_gettop(L) ) {
            const gchar* s = lua_tostring(L,1);
            
            if (s) proto_item_set_text(item,"%s",s);

            lua_remove(L,1);

        }        
    
    } else if (tvbr) {
        if (lua_gettop(L)) {
            const gchar* s = lua_tostring(L,1);

            item = proto_tree_add_text(tree_item->tree, tvbr->tvb, tvbr->offset, tvbr->len,"%s",s);
            lua_remove(L,1);
        }
    } else {
        if (lua_gettop(L)) {
            const gchar* s = lua_tostring(L,1);
            item = proto_tree_add_text(tree_item->tree, lua_tvb, 0, 0,"%s",s);
            lua_remove(L,1);
        }
    }

    while(lua_gettop(L)) {
        const gchar* s = lua_tostring(L,1);

        if (s) proto_item_append_text(item, " %s", s);

        lua_remove(L,1);

    }
    

	tree_item = ep_alloc(sizeof(struct _eth_treeitem));
	tree_item->item = item;
	tree_item->tree = proto_item_add_subtree(item,ett > 0 ? ett : elua_ett);

    PUSH_TREEITEM(L,tree_item);
    
    return 1;
}


ELUA_METHOD TreeItem_add(lua_State *L) { return TreeItem_add_item_any(L,FALSE); }
ELUA_METHOD TreeItem_add_le(lua_State *L) { return TreeItem_add_item_any(L,TRUE); }

ELUA_METHOD TreeItem_set_text(lua_State *L) {
    TreeItem ti = checkTreeItem(L,1);
    
    if (ti) {
        const gchar* s = luaL_checkstring(L,2);
        proto_item_set_text(ti->item,"%s",s);
    }
    
    return 0;
}

ELUA_METHOD TreeItem_append_text(lua_State *L) {
    TreeItem ti = checkTreeItem(L,1);
    const gchar* s;
    
    if (ti) {
        s = luaL_checkstring(L,2);
        proto_item_append_text(ti->item,"%s",s);
    }
    return 0;
}

ELUA_METHOD TreeItem_set_len(lua_State *L) {
    TreeItem ti = checkTreeItem(L,1);
    int len;

    if (ti) {
        len = luaL_checkint(L,2);
        proto_item_set_len(ti->item,len);
    }
    
    return 0;
}

ELUA_METHOD TreeItem_set_expert_flags(lua_State *L) {
    TreeItem ti = checkTreeItem(L,1);
	int group = luaL_checkint(L,2);
	int severity = luaL_checkint(L,3);

    if ( ti && ti->item ) {
            proto_item_set_expert_flags(ti->item,group,severity);
    }

    return 0;
}

ELUA_METHOD TreeItem_add_expert_info(lua_State *L) {
    TreeItem ti = checkTreeItem(L,1);
	int group = luaL_checkint(L,2);
	int severity = luaL_checkint(L,3);
	const gchar* str = luaL_optstring(L,4,"Expert Info");
	
    if ( ti && ti->item ) {
        expert_add_info_format(lua_pinfo, ti->item, group, severity, "%s", str);
    }
    
    return 0;
}

ELUA_METHOD TreeItem_set_generated(lua_State *L) {
    TreeItem ti = checkTreeItem(L,1);
    if (ti) {
        PROTO_ITEM_SET_GENERATED(ti->item);
    }
    return 0;
}


ELUA_METHOD TreeItem_set_hidden(lua_State *L) {
    TreeItem ti = checkTreeItem(L,1);
    if (ti) {
        PROTO_ITEM_SET_HIDDEN(ti->item);
    }
    return 0;
}

static const luaL_reg TreeItem_methods[] = {
    {"add",       TreeItem_add},
    {"add_le",       TreeItem_add_le},
    {"set_text",       TreeItem_set_text},
    {"append_text",       TreeItem_append_text},
    {"set_len",       TreeItem_set_len},
    {"set_expert_flags",       TreeItem_set_expert_flags},
    {"add_expert_info",       TreeItem_add_expert_info},
    {"set_generated",       TreeItem_set_generated},
    {"set_hidden",       TreeItem_set_hidden},
    {0, 0}
};
static const luaL_reg TreeItem_meta[] = {
    {0, 0}
};



int TreeItem_register(lua_State *L) {
	gint* etts[] = { &elua_ett };
	
	ELUA_REGISTER_CLASS(TreeItem);    
    outstanding_stuff = g_ptr_array_new();
	
	proto_register_subtree_array(etts,1);

    return 1;
}
