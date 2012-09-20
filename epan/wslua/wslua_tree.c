/*
 * wslua_tree.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

/* WSLUA_MODULE Tree Adding information to the dissection tree */

#include "wslua.h"
#include <epan/expert.h>

static gint wslua_ett = -1;

static GPtrArray* outstanding_TreeItem = NULL;

#define PUSH_TREEITEM(L,i) {g_ptr_array_add(outstanding_TreeItem,i);pushTreeItem(L,i);}

TreeItem* push_TreeItem(lua_State*L, TreeItem t) {
    g_ptr_array_add(outstanding_TreeItem,t);
    return pushTreeItem(L,t);
}

CLEAR_OUTSTANDING(TreeItem, expired, TRUE)

WSLUA_CLASS_DEFINE(TreeItem,NOP,NOP);
/* TreeItems represent information in the packet-details pane.
   A root TreeItem is passed to dissectors as first argument. */

WSLUA_METHOD TreeItem_add_packet_field(lua_State *L) {
    /*
     Adds an child item to a given item, returning the child.
     tree_item:add_packet_field([proto_field], [tvbrange], [encoding], ...)
    */
    TvbRange tvbr;
    ProtoField field;
    int hfid;
    int ett;
    ftenum_t type;
    TreeItem tree_item  = shiftTreeItem(L,1);
    guint encoding;
    proto_item* item = NULL;

    if (!tree_item) {
        return luaL_error(L,"not a TreeItem!");
    }
    if (tree_item->expired) {
        luaL_error(L,"expired TreeItem");
        return 0;
    }

    if (! ( field = shiftProtoField(L,1) ) ) {
        luaL_error(L,"TreeField:add_packet_field not passed a ProtoField");
        return 0;
    }
    hfid = field->hfid;
    type = field->type;
    ett = field->ett;

    tvbr = shiftTvbRange(L,1);
    if (!tvbr) {
        /* No TvbRange specified */
        tvbr = ep_alloc(sizeof(struct _wslua_tvbrange));
        tvbr->tvb = ep_alloc(sizeof(struct _wslua_tvb));
        tvbr->tvb->ws_tvb = lua_tvb;
        tvbr->offset = 0;
        tvbr->len = 0;
    }

    encoding = (guint)luaL_checknumber(L,1);
    lua_remove(L,1);
    if (type == FT_STRINGZ) {
        switch (encoding & ENC_CHARENCODING_MASK) {

        case ENC_UTF_16:
        case ENC_UCS_2:
            tvbr->len = tvb_unicode_strsize (tvbr->tvb->ws_tvb, tvbr->offset);
            break;

        default:
            tvbr->len = tvb_strsize (tvbr->tvb->ws_tvb, tvbr->offset);
            break;
        }
    }
    item = proto_tree_add_item(tree_item->tree, hfid, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len, encoding);

    while(lua_gettop(L)) {
        const gchar* s;
        s = lua_tostring(L,1);
        if (s) proto_item_append_text(item, " %s", s);
        lua_remove(L,1);
    }

    tree_item = g_malloc(sizeof(struct _wslua_treeitem));
    tree_item->item = item;
    tree_item->tree = proto_item_add_subtree(item,ett > 0 ? ett : wslua_ett);
    tree_item->expired = FALSE;

    PUSH_TREEITEM(L,tree_item);

    return 1;
}

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
    if (tree_item->expired) {
        luaL_error(L,"expired TreeItem");
        return 0;
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
        tvbr = ep_alloc(sizeof(struct _wslua_tvbrange));
        tvbr->tvb = ep_alloc(sizeof(struct _wslua_tvb));
        tvbr->tvb->ws_tvb = lua_tvb;
        tvbr->offset = 0;
        tvbr->len = 0;
    }

    if (hfid > 0 ) {
        if (lua_gettop(L)) {
            switch(type) {
                case FT_PROTOCOL:
                    item = proto_tree_add_item(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,ENC_NA);
                    lua_pushnumber(L,0);
                    lua_insert(L,1);
                    break;
                case FT_BOOLEAN:
                    item = proto_tree_add_boolean(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,(guint32)luaL_checknumber(L,1));
                    break;
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                case FT_FRAMENUM:
                    item = proto_tree_add_uint(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,(guint32)luaL_checknumber(L,1));
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    item = proto_tree_add_int(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,(gint32)luaL_checknumber(L,1));
                    break;
                case FT_FLOAT:
                    item = proto_tree_add_float(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,(float)luaL_checknumber(L,1));
                    break;
                case FT_DOUBLE:
                    item = proto_tree_add_double(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,(double)luaL_checknumber(L,1));
                    break;
                case FT_ABSOLUTE_TIME:
                case FT_RELATIVE_TIME:
                    item = proto_tree_add_time(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,checkNSTime(L,1));
                    break;
                case FT_STRING:
                    item = proto_tree_add_string(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,luaL_checkstring(L,1));
                    break;
                case FT_STRINGZ:
                    item = proto_tree_add_string(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvb_strsize (tvbr->tvb->ws_tvb, tvbr->offset),luaL_checkstring(L,1));
                    break;
                case FT_BYTES:
                    item = proto_tree_add_bytes(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len, (const guint8*) luaL_checkstring(L,1));
                    break;
                case FT_UINT64:
                    item = proto_tree_add_uint64(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,*(UInt64)checkUInt64(L,1));
                    break;
                case FT_INT64:
                    item = proto_tree_add_int64(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,*(Int64)checkInt64(L,1));
                    break;
                case FT_IPv4:
                    item = proto_tree_add_ipv4(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,*((guint32*)(checkAddress(L,1)->data)));
                    break;
                case FT_ETHER:
                case FT_UINT_BYTES:
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
            if (type == FT_STRINGZ) tvbr->len = tvb_strsize (tvbr->tvb->ws_tvb, tvbr->offset);
            item = proto_tree_add_item(tree_item->tree, hfid, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
        }

        if ( lua_gettop(L) ) {
            const gchar* s = lua_tostring(L,1);
            if (s) proto_item_set_text(item,"%s",s);
            lua_remove(L,1);
        }

    } else {
        if (lua_gettop(L)) {
            const gchar* s = lua_tostring(L,1);
            item = proto_tree_add_text(tree_item->tree, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len,"%s",s);
            lua_remove(L,1);
        }
    }

    while(lua_gettop(L)) {
        const gchar* s = lua_tostring(L,1);
        if (s) proto_item_append_text(item, " %s", s);
        lua_remove(L,1);
    }

    tree_item = g_malloc(sizeof(struct _wslua_treeitem));
    tree_item->item = item;
    tree_item->tree = proto_item_add_subtree(item,ett > 0 ? ett : wslua_ett);
    tree_item->expired = FALSE;

    PUSH_TREEITEM(L,tree_item);

    return 1;
}


WSLUA_METHOD TreeItem_add(lua_State *L) {
    /*
     Adds an child item to a given item, returning the child.
     tree_item:add([proto_field | proto], [tvbrange], [label], ...)
     if the proto_field represents a numeric value (int, uint or float) is to be treated as a Big Endian (network order) Value.
    */
    WSLUA_RETURN(TreeItem_add_item_any(L,FALSE)); /* The child item */
}

WSLUA_METHOD TreeItem_add_le(lua_State *L) {
    /*
     Adds (and returns) an child item to a given item, returning the child.
     tree_item:add([proto_field | proto], [tvbrange], [label], ...)
     if the proto_field represents a numeric value (int, uint or float) is to be treated as a Little Endian Value.
     */
    WSLUA_RETURN(TreeItem_add_item_any(L,TRUE)); /* The child item */
}

WSLUA_METHOD TreeItem_set_text(lua_State *L) {
    /* Sets the text of the label */
#define WSLUA_ARG_TreeItem_set_text_TEXT 2 /* The text to be used. */
    TreeItem ti = checkTreeItem(L,1);
    const gchar* s;

    if (ti) {
        if (ti->expired) {
            luaL_error(L,"expired TreeItem");
            return 0;
        }

        s = luaL_checkstring(L,WSLUA_ARG_TreeItem_set_text_TEXT);
        proto_item_set_text(ti->item,"%s",s);
    }

    return 0;
}

WSLUA_METHOD TreeItem_append_text(lua_State *L) {
    /* Appends text to the label */
#define WSLUA_ARG_TreeItem_append_text_TEXT 2 /* The text to be appended. */
    TreeItem ti = checkTreeItem(L,1);
    const gchar* s;

    if (ti) {
        if (ti->expired) {
            luaL_error(L,"expired TreeItem");
            return 0;
        }

        s = luaL_checkstring(L,WSLUA_ARG_TreeItem_append_text_TEXT);
        proto_item_append_text(ti->item,"%s",s);
    }
    return 0;
}

WSLUA_METHOD TreeItem_set_expert_flags(lua_State *L) {
    /* Sets the expert flags of the item. */
#define WSLUA_OPTARG_TreeItem_set_expert_flags_GROUP 2 /* One of PI_CHECKSUM, PI_SEQUENCE, PI_RESPONSE_CODE, PI_REQUEST_CODE, PI_UNDECODED, PI_REASSEMBLE, PI_MALFORMED or PI_DEBUG */
#define WSLUA_OPTARG_TreeItem_set_expert_flags_SEVERITY 3 /* One of PI_CHAT, PI_NOTE, PI_WARN, PI_ERROR */
    TreeItem ti = checkTreeItem(L,1);
    int group = luaL_optint(L,WSLUA_OPTARG_TreeItem_set_expert_flags_GROUP,PI_DEBUG);
    int severity = luaL_optint(L,WSLUA_OPTARG_TreeItem_set_expert_flags_SEVERITY,PI_CHAT);

    if ( ti && ti->item ) {
        if (ti->expired) {
            luaL_error(L,"expired TreeItem");
            return 0;
        }
        proto_item_set_expert_flags(ti->item,group,severity);
    }

    return 0;
}

WSLUA_METHOD TreeItem_add_expert_info(lua_State *L) {
    /* Sets the expert flags of the item and adds expert info to the packet. */
#define WSLUA_OPTARG_TreeItem_add_expert_info_GROUP 2 /* One of PI_CHECKSUM, PI_SEQUENCE, PI_RESPONSE_CODE, PI_REQUEST_CODE, PI_UNDECODED, PI_REASSEMBLE, PI_MALFORMED or PI_DEBUG */
#define WSLUA_OPTARG_TreeItem_add_expert_info_SEVERITY 3 /* One of PI_CHAT, PI_NOTE, PI_WARN, PI_ERROR */
#define WSLUA_OPTARG_TreeItem_add_expert_info_TEXT 4 /* The text for the expert info */
    TreeItem ti = checkTreeItem(L,1);
    int group = luaL_optint(L,WSLUA_OPTARG_TreeItem_add_expert_info_GROUP,PI_DEBUG);
    int severity = luaL_optint(L,WSLUA_OPTARG_TreeItem_add_expert_info_SEVERITY,PI_CHAT);
    const gchar* str = luaL_optstring(L,WSLUA_OPTARG_TreeItem_add_expert_info_TEXT,"Expert Info");

    if ( ti && ti->item ) {
        if (ti->expired) {
            luaL_error(L,"expired TreeItem");
            return 0;
        }
        expert_add_info_format(lua_pinfo, ti->item, group, severity, "%s", str);
    }

    return 0;
}

WSLUA_METHOD TreeItem_set_generated(lua_State *L) {
    /* Marks the TreeItem as a generated field (with data infered but not contained in the packet). */
    TreeItem ti = checkTreeItem(L,1);
    if (ti) {
        if (ti->expired) {
            luaL_error(L,"expired TreeItem");
            return 0;
        }
        PROTO_ITEM_SET_GENERATED(ti->item);
    }
    return 0;
}


WSLUA_METHOD TreeItem_set_hidden(lua_State *L) {
    /* Should not be used */
    TreeItem ti = checkTreeItem(L,1);
    if (ti) {
        if (ti->expired) {
            luaL_error(L,"expired TreeItem");
            return 0;
        }
        PROTO_ITEM_SET_HIDDEN(ti->item);
    }
    return 0;
}

WSLUA_METHOD TreeItem_set_len(lua_State *L) {
    /* Set TreeItem's length inside tvb, after it has already been created. */
#define WSLUA_ARG_TreeItem_set_len_LEN 2 /* The length to be used. */
    TreeItem ti = checkTreeItem(L,1);
    gint len;

    if (ti) {
        if (ti->expired) {
            luaL_error(L,"expired TreeItem");
            return 0;
        }

        len = luaL_checkint(L,WSLUA_ARG_TreeItem_set_len_LEN);
        proto_item_set_len(ti->item, len);
    }

    return 0;
}

static int TreeItem_gc(lua_State* L) {
    TreeItem ti = checkTreeItem(L,1);
    if (!ti) return 0;
    if (!ti->expired)
        ti->expired = TRUE;
    else
        g_free(ti);
    return 0;
}

static const luaL_Reg TreeItem_methods[] = {
    {"add_packet_field", TreeItem_add_packet_field},
    {"add",              TreeItem_add},
    {"add_le",           TreeItem_add_le},
    {"set_text",         TreeItem_set_text},
    {"append_text",      TreeItem_append_text},
    {"set_expert_flags", TreeItem_set_expert_flags},
    {"add_expert_info",  TreeItem_add_expert_info},
    {"set_generated",    TreeItem_set_generated},
    {"set_hidden",       TreeItem_set_hidden},
    {"set_len",          TreeItem_set_len},
    { NULL, NULL }
};

static const luaL_Reg TreeItem_meta[] = {
    {"__gc", TreeItem_gc},
    { NULL, NULL }
};

int TreeItem_register(lua_State *L) {
    gint* etts[] = { &wslua_ett };
    WSLUA_REGISTER_CLASS(TreeItem);
    outstanding_TreeItem = g_ptr_array_new();
    proto_register_subtree_array(etts,1);
    return 1;
}
