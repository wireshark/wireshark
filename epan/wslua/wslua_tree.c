/*
 * wslua_tree.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
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

#include <epan/emem.h>

/* WSLUA_MODULE Tree Adding information to the dissection tree */

#include "wslua.h"
#include <epan/exceptions.h>
#include <epan/show_exception.h>

static gint wslua_ett = -1;

static GPtrArray* outstanding_TreeItem = NULL;

#define PUSH_TREEITEM(L,i) {g_ptr_array_add(outstanding_TreeItem,i);pushTreeItem(L,i);}

TreeItem* push_TreeItem(lua_State*L, TreeItem t) {
    g_ptr_array_add(outstanding_TreeItem,t);
    return pushTreeItem(L,t);
}

CLEAR_OUTSTANDING(TreeItem, expired, TRUE)

WSLUA_CLASS_DEFINE(TreeItem,FAIL_ON_NULL_OR_EXPIRED("TreeItem"),NOP);
/* `TreeItem`s represent information in the packet-details pane.
   A root `TreeItem` is passed to dissectors as the third argument. */

/* the following is used by TreeItem_add_packet_field() - this can THROW errors */
static proto_item *
try_add_packet_field(lua_State *L, TreeItem tree_item, TvbRange tvbr, const int hfid,
                     const ftenum_t type, const guint encoding, gint *ret_err)
{
    gint err = 0;
    proto_item* item = NULL;
    gint endoff = 0;

    switch(type) {
        /* these all generate ByteArrays */
        case FT_BYTES:
        case FT_UINT_BYTES:
        case FT_OID:
        case FT_REL_OID:
        case FT_SYSTEM_ID:
            {
                /* GByteArray and its data will be g_free'd by Lua */
                GByteArray *gba = g_byte_array_new();
                item = proto_tree_add_bytes_item(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                   tvbr->offset, tvbr->len, encoding,
                                                   gba, &endoff, &err);
                if (err == 0) {
                    pushByteArray(L, gba);
                    lua_pushinteger(L, endoff);
                }
            }
            break;

        case FT_ABSOLUTE_TIME:
        case FT_RELATIVE_TIME:
            {
               /* nstime_t will be g_free'd by Lua */
                nstime_t *nstime = (nstime_t *) g_malloc0(sizeof(nstime_t));
                item = proto_tree_add_time_item(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                   tvbr->offset, tvbr->len, encoding,
                                                   nstime, &endoff, &err);
                if (err == 0) {
                    pushNSTime(L,nstime);
                    lua_pushinteger(L, endoff);
                }
            }
            break;

        /* XXX: what about these? */
        case FT_NONE:
        case FT_PROTOCOL:
        /* anything else just needs to be done the old fashioned way */
        default:
            item = proto_tree_add_item(tree_item->tree, hfid, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len, encoding);
            lua_pushnil(L);
            lua_pushnil(L);
            break;
    }

    if (ret_err) *ret_err = err;

    return item;
}

WSLUA_METHOD TreeItem_add_packet_field(lua_State *L) {
    /*
     Adds a new child tree for the given `ProtoField` object to this tree item,
     returning the new child `TreeItem`.

     Unlike `TreeItem:add()` and `TreeItem:add_le()`, the `ProtoField` argument
     is not optional, and cannot be a `Proto` object. Instead, this function always
     uses the `ProtoField` to determine the type of field to extract from the
     passed-in `TvbRange`, highlighting the relevant bytes in the Packet Bytes pane
     of the GUI (if there is a GUI), etc.  If no `TvbRange` is given, no bytes are
     highlighted and the field's value cannot be determined; the `ProtoField` must
     have been defined/created not to have a length in such a case, or an error will
     occur.  For backwards-compatibility reasons the `encoding` argument, however,
     must still be given.

     Unlike `TreeItem:add()` and `TreeItem:add_le()`, this function performs both
     big-endian and little-endian decoding, by setting the `encoding` argument to
     be `ENC_BIG_ENDIAN` or `ENC_LITTLE_ENDIAN`.

     The signature of this function:
     @code
     tree_item:add_packet_field(proto_field [,tvbrange], encoding, ...)
     @endcode

     In Wireshark version 1.11.3, this function was changed to return more than
     just the new child `TreeItem`. The child is the first return value, so that
     function chaining will still work as before; but it now also returns the value
     of the extracted field (i.e., a number, `UInt64`, `Address`, etc.). If the
     value could not be extracted from the `TvbRange`, the child `TreeItem` is still
     returned, but the second returned value is `nil`.

     Another new feature added to this function in Wireshark version 1.11.3 is the
     ability to extract native number `ProtoField`s from string encoding in the
     `TvbRange`, for ASCII-based and similar string encodings. For example, a
     `ProtoField` of as `ftypes.UINT32` type can be extracted from a `TvbRange`
     containing the ASCII string "123", and it will correctly decode the ASCII to
     the number `123`, both in the tree as well as for the second return value of
     this function. To do so, you must set the `encoding` argument of this function
     to the appropriate string `ENC_*` value, bitwise-or'd with the `ENC_STRING`
     value (see `init.lua`). `ENC_STRING` is guaranteed to be a unique bit flag, and
     thus it can added instead of bitwise-or'ed as well. Only single-byte ASCII digit
     string encoding types can be used for this, such as `ENC_ASCII` and `ENC_UTF_8`.

     For example, assuming the `Tvb` named "`tvb`" contains the string "123":
     @code
     -- this is done earlier in the script
     local myfield = ProtoField.new("Transaction ID", "myproto.trans_id", ftypes.UINT16)

     -- this is done inside a dissector, post-dissector, or heuristic function
     -- child will be the created child tree, and value will be the number 123 or nil on failure
     local child, value = tree:add_packet_field(myfield, tvb:range(0,3), ENC_UTF_8 + ENC_STRING)
     @endcode

    */
#define WSLUA_ARG_TreeItem_add_packet_field_PROTOFIELD 2 /* The ProtoField field object to add to the tree. */
#define WSLUA_OPTARG_TreeItem_add_packet_field_TVBRANGE 3 /* The `TvbRange` of bytes in the packet this tree item covers/represents. */
#define WSLUA_ARG_TreeItem_add_packet_field_ENCODING 4 /* The field's encoding in the `TvbRange`. */
#define WSLUA_OPTARG_TreeItem_add_packet_field_LABEL 5 /* One or more strings to append to the created `TreeItem`. */
    volatile TvbRange tvbr;
    ProtoField field;
    int hfid;
    volatile int ett;
    ftenum_t type;
    TreeItem tree_item = shiftTreeItem(L,1);
    guint encoding;
    proto_item* item = NULL;
    volatile int nargs;
    volatile gint err = 0;
    const char *volatile error = NULL;

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
        tvbr = ep_new(struct _wslua_tvbrange);
        tvbr->tvb = ep_new(struct _wslua_tvb);
        tvbr->tvb->ws_tvb = lua_tvb;
        tvbr->offset = 0;
        tvbr->len = 0;
    }

    encoding = wslua_checkguint(L,1);
    lua_remove(L,1);

    /* get the number of additional args before we add more to the stack */
    nargs = lua_gettop(L);

    /* XXX: why is this being done? If the length was -1, FT_STRINGZ figures out
     * the right length in tvb_get_stringz_enc(); if it was 0, it should remain zero;
     * if it was greater than zero, then it's the length the caller wanted.
     */
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

    TRY {
        gint errx = 0;
        item = try_add_packet_field(L, tree_item, tvbr, hfid, type, encoding, &errx);
        err = errx;
    } CATCH_ALL {
        show_exception(tvbr->tvb->ws_tvb, lua_pinfo, tree_item->tree, EXCEPT_CODE, GET_MESSAGE);
        error = "Lua programming error";
    } ENDTRY;

    if (error) { WSLUA_ERROR(TreeItem_add_packet_field,error); }

    if (err != 0) {
        lua_pushnil(L);
        lua_pushnil(L);
    }

    while(nargs) {
        const gchar* s;
        s = lua_tostring(L,1);
        if (s) proto_item_append_text(item, " %s", s);
        lua_remove(L,1);
        nargs--;
    }

    tree_item = (TreeItem)g_malloc(sizeof(struct _wslua_treeitem));
    tree_item->item = item;
    tree_item->tree = proto_item_add_subtree(item,ett > 0 ? ett : wslua_ett);
    tree_item->expired = FALSE;

    PUSH_TREEITEM(L,tree_item);

    /* move the tree object before the field value */
    lua_insert(L, 1);

    WSLUA_RETURN(3); /* The new child `TreeItem`, the field's extracted value or nil, and offset or nil. */
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
        tvbr = ep_new(struct _wslua_tvbrange);
        tvbr->tvb = ep_new(struct _wslua_tvb);
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
                    {
                        /* this needs to use checkinteger so that it can accept a Lua boolean and coerce it to an int */
                        guint32 val = (guint32) (wslua_tointeger(L,1));
                        item = proto_tree_add_boolean(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,val);
                    }
                    break;
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                case FT_FRAMENUM:
                    item = proto_tree_add_uint(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,wslua_checkguint32(L,1));
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    item = proto_tree_add_int(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,wslua_checkguint32(L,1));
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
                    item = proto_tree_add_uint64(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,checkUInt64(L,1));
                    break;
                case FT_INT64:
                    item = proto_tree_add_int64(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,checkInt64(L,1));
                    break;
                case FT_IPv4:
                    item = proto_tree_add_ipv4(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,*((const guint32*)(checkAddress(L,1)->data)));
                    break;
                case FT_ETHER:
                case FT_UINT_BYTES:
                case FT_IPv6:
                case FT_IPXNET:
                case FT_GUID:
                case FT_OID:
                case FT_REL_OID:
                case FT_SYSTEM_ID:
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
        } else {
            luaL_error(L,"Tree item ProtoField/Protocol handle is invalid (ProtoField/Proto not registered?)");
        }
    }

    while(lua_gettop(L)) {
        const gchar* s = lua_tostring(L,1);
        if (s) proto_item_append_text(item, " %s", s);
        lua_remove(L,1);
    }

    tree_item = (TreeItem)g_malloc(sizeof(struct _wslua_treeitem));
    tree_item->item = item;
    tree_item->tree = proto_item_add_subtree(item,ett > 0 ? ett : wslua_ett);
    tree_item->expired = FALSE;

    PUSH_TREEITEM(L,tree_item);

    return 1;
}


WSLUA_METHOD TreeItem_add(lua_State *L) {
    /*
     Adds a child item to this tree item, returning the new child `TreeItem`.

     If the `ProtoField` represents a numeric value (int, uint or float), then it's treated as a Big Endian (network order) value.

     This function has a complicated form: 'treeitem:add(protofield, [tvbrange,] [[value], label]])', such that if the second
     argument is a `TvbRange`, and a third argument is given, it's a value; but if the second argument is a non-`TvbRange` type, then
     it is the value (as opposed to filling that argument with 'nil', which is invalid for this function).
    */
#define WSLUA_ARG_TreeItem_add_PROTOFIELD 2 /* The ProtoField field or Proto protocol object to add to the tree. */
#define WSLUA_OPTARG_TreeItem_add_TVBRANGE 3 /* The TvbRange of bytes in the packet this tree item covers/represents. */
#define WSLUA_OPTARG_TreeItem_add_VALUE 4 /* The field's value, instead of the ProtoField/Proto one. */
#define WSLUA_OPTARG_TreeItem_add_LABEL 5 /* One or more strings to use for the tree item label, instead of the ProtoField/Proto one. */
    WSLUA_RETURN(TreeItem_add_item_any(L,FALSE)); /* The new child TreeItem. */
}

WSLUA_METHOD TreeItem_add_le(lua_State *L) {
    /*
     Adds a child item to this tree item, returning the new child `TreeItem`.

     If the `ProtoField` represents a numeric value (int, uint or float), then it's treated as a Little Endian value.

     This function has a complicated form: 'treeitem:add_le(protofield, [tvbrange,] [[value], label]])', such that if the second
     argument is a `TvbRange`, and a third argument is given, it's a value; but if the second argument is a non-`TvbRange` type, then
     it is the value (as opposed to filling that argument with 'nil', which is invalid for this function).
     */
#define WSLUA_ARG_TreeItem_add_le_PROTOFIELD 2 /* The ProtoField field or Proto protocol object to add to the tree. */
#define WSLUA_OPTARG_TreeItem_add_le_TVBRANGE 3 /* The TvbRange of bytes in the packet this tree item covers/represents. */
#define WSLUA_OPTARG_TreeItem_add_le_VALUE 4 /* The field's value, instead of the ProtoField/Proto one. */
#define WSLUA_OPTARG_TreeItem_add_le_LABEL 5 /* One or more strings to use for the tree item label, instead of the ProtoField/Proto one. */
    WSLUA_RETURN(TreeItem_add_item_any(L,TRUE)); /* The new child TreeItem. */
}

WSLUA_METHOD TreeItem_set_text(lua_State *L) {
    /* Sets the text of the label.

       This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
    */
#define WSLUA_ARG_TreeItem_set_text_TEXT 2 /* The text to be used. */
    TreeItem ti = checkTreeItem(L,1);
    const gchar* s = luaL_checkstring(L,WSLUA_ARG_TreeItem_set_text_TEXT);

    proto_item_set_text(ti->item,"%s",s);

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

WSLUA_METHOD TreeItem_append_text(lua_State *L) {
    /* Appends text to the label.

       This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
    */
#define WSLUA_ARG_TreeItem_append_text_TEXT 2 /* The text to be appended. */
    TreeItem ti = checkTreeItem(L,1);
    const gchar* s = luaL_checkstring(L,WSLUA_ARG_TreeItem_append_text_TEXT);

    proto_item_append_text(ti->item,"%s",s);

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

WSLUA_METHOD TreeItem_prepend_text(lua_State *L) {
    /* Prepends text to the label.

       This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
    */
#define WSLUA_ARG_TreeItem_prepend_text_TEXT 2 /* The text to be prepended. */
    TreeItem ti = checkTreeItem(L,1);
    const gchar* s = luaL_checkstring(L,WSLUA_ARG_TreeItem_prepend_text_TEXT);

    proto_item_prepend_text(ti->item,"%s",s);

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

WSLUA_METHOD TreeItem_add_expert_info(lua_State *L) {
    /* Sets the expert flags of the item and adds expert info to the packet.

       This function does *not* create a truly filterable expert info for a protocol.
       Instead you should use `TreeItem.add_proto_expert_info()`.

       Note: This function is provided for backwards compatibility only, and should not
       be used in new Lua code. It may be removed in the future. You should only
       use `TreeItem.add_proto_expert_info()`.
     */
#define WSLUA_OPTARG_TreeItem_add_expert_info_GROUP 2 /* One of `PI_CHECKSUM`, `PI_SEQUENCE`,
                                                         `PI_RESPONSE_CODE`, `PI_REQUEST_CODE`,
                                                         `PI_UNDECODED`, `PI_REASSEMBLE`,
                                                         `PI_MALFORMED` or `PI_DEBUG`. */
#define WSLUA_OPTARG_TreeItem_add_expert_info_SEVERITY 3 /* One of `PI_CHAT`, `PI_NOTE`,
                                                            `PI_WARN`, or `PI_ERROR`. */
#define WSLUA_OPTARG_TreeItem_add_expert_info_TEXT 4 /* The text for the expert info display. */
    TreeItem ti           = checkTreeItem(L,1);
    int group             = luaL_optint(L,WSLUA_OPTARG_TreeItem_add_expert_info_GROUP,PI_DEBUG);
    int severity          = luaL_optint(L,WSLUA_OPTARG_TreeItem_add_expert_info_SEVERITY,PI_CHAT);
    expert_field* ei_info = wslua_get_expert_field(group, severity);
    const gchar* str;

    if (lua_gettop(L) >= WSLUA_OPTARG_TreeItem_add_expert_info_TEXT) {
        str = wslua_checkstring_only(L, WSLUA_OPTARG_TreeItem_add_expert_info_TEXT);
        expert_add_info_format(lua_pinfo, ti->item, ei_info, "%s", str);
    } else {
        expert_add_info(lua_pinfo, ti->item, ei_info);
    }

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

WSLUA_METHOD TreeItem_add_proto_expert_info(lua_State *L) {
    /* Sets the expert flags of the tree item and adds expert info to the packet.

       @since 1.11.3
     */
#define WSLUA_ARG_TreeItem_add_proto_expert_info_EXPERT 2 /* The `ProtoExpert` object to add to the tree. */
#define WSLUA_OPTARG_TreeItem_add_proto_expert_info_TEXT 3 /* Text for the expert info display
                                                              (default is to use the registered
                                                              text). */
    TreeItem ti = checkTreeItem(L,1);
    ProtoExpert expert = checkProtoExpert(L,WSLUA_ARG_TreeItem_add_proto_expert_info_EXPERT);
    const gchar* str;

    if (expert->ids.ei == EI_INIT_EI || expert->ids.hf == EI_INIT_HF) {
        luaL_error(L, "ProtoExpert is not registered");
        return 0;
    }

    if (lua_gettop(L) >= WSLUA_OPTARG_TreeItem_add_proto_expert_info_TEXT) {
        str = wslua_checkstring_only(L, WSLUA_OPTARG_TreeItem_add_proto_expert_info_TEXT);
        expert_add_info_format(lua_pinfo, ti->item, &expert->ids, "%s", str);
    } else {
        expert_add_info(lua_pinfo, ti->item, &expert->ids);
    }

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

WSLUA_METHOD TreeItem_add_tvb_expert_info(lua_State *L) {
    /* Sets the expert flags of the tree item and adds expert info to the packet
       associated with the `Tvb` or `TvbRange` bytes in the packet.

       @since 1.11.3
     */
#define WSLUA_ARG_TreeItem_add_tvb_expert_info_EXPERT 2 /* The `ProtoExpert` object to add to the tree. */
#define WSLUA_ARG_TreeItem_add_tvb_expert_info_TVB 3 /* The `Tvb` or `TvbRange` object bytes to associate
                                                        the expert info with. */
#define WSLUA_OPTARG_TreeItem_add_tvb_expert_info_TEXT 4 /* Text for the expert info display
                                                              (default is to use the registered
                                                              text). */
    TreeItem ti = checkTreeItem(L,1);
    ProtoExpert expert = checkProtoExpert(L,WSLUA_ARG_TreeItem_add_proto_expert_info_EXPERT);
    TvbRange tvbr;
    const gchar* str;

    if (expert->ids.ei == EI_INIT_EI || expert->ids.hf == EI_INIT_HF) {
        luaL_error(L, "ProtoExpert is not registered");
        return 0;
    }

    tvbr = shiftTvbRange(L,WSLUA_ARG_TreeItem_add_tvb_expert_info_TVB);

    if (!tvbr) {
        tvbr = ep_new(struct _wslua_tvbrange);
        tvbr->tvb = shiftTvb(L,WSLUA_ARG_TreeItem_add_tvb_expert_info_TVB);
        if (!tvbr->tvb) {
            tvbr->tvb = ep_new(struct _wslua_tvb);
        }
        tvbr->tvb->ws_tvb = lua_tvb;
        tvbr->offset = 0;
        tvbr->len = 0;
    }

    if (lua_gettop(L) >= WSLUA_OPTARG_TreeItem_add_proto_expert_info_TEXT) {
        str = wslua_checkstring_only(L, WSLUA_OPTARG_TreeItem_add_proto_expert_info_TEXT);
        proto_tree_add_expert_format(ti->tree, lua_pinfo, &expert->ids,
                                     tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len,
                                     "%s", str);
    } else {
        proto_tree_add_expert(ti->tree, lua_pinfo, &expert->ids,
                              tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    }

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

WSLUA_METHOD TreeItem_set_generated(lua_State *L) {
    /* Marks the `TreeItem` as a generated field (with data inferred but not contained in the packet).

       This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
    */
    TreeItem ti = checkTreeItem(L,1);

    PROTO_ITEM_SET_GENERATED(ti->item);

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}


WSLUA_METHOD TreeItem_set_hidden(lua_State *L) {
    /* This function should not be used, and is provided for backwards-compatibility only. */
    TreeItem ti = checkTreeItem(L,1);

    PROTO_ITEM_SET_HIDDEN(ti->item);

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

WSLUA_METHOD TreeItem_set_len(lua_State *L) {
    /* Set `TreeItem`'s length inside tvb, after it has already been created.

       This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
    */
#define WSLUA_ARG_TreeItem_set_len_LEN 2 /* The length to be used. */
    TreeItem ti = checkTreeItem(L,1);
    gint len = luaL_checkint(L,WSLUA_ARG_TreeItem_set_len_LEN);

    proto_item_set_len(ti->item, len);

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int TreeItem__gc(lua_State* L) {
    TreeItem ti = toTreeItem(L,1);
    if (!ti) return 0;
    if (!ti->expired)
        ti->expired = TRUE;
    else
        g_free(ti);
    return 0;
}

WSLUA_METHODS TreeItem_methods[] = {
    WSLUA_CLASS_FNREG(TreeItem,add_packet_field),
    WSLUA_CLASS_FNREG(TreeItem,add),
    WSLUA_CLASS_FNREG(TreeItem,add_le),
    WSLUA_CLASS_FNREG(TreeItem,set_text),
    WSLUA_CLASS_FNREG(TreeItem,append_text),
    WSLUA_CLASS_FNREG(TreeItem,prepend_text),
    WSLUA_CLASS_FNREG(TreeItem,add_expert_info),
    WSLUA_CLASS_FNREG(TreeItem,add_proto_expert_info),
    WSLUA_CLASS_FNREG(TreeItem,add_tvb_expert_info),
    WSLUA_CLASS_FNREG(TreeItem,set_generated),
    WSLUA_CLASS_FNREG(TreeItem,set_hidden),
    WSLUA_CLASS_FNREG(TreeItem,set_len),
    { NULL, NULL }
};

WSLUA_META TreeItem_meta[] = {
    { NULL, NULL }
};

int TreeItem_register(lua_State *L) {
    gint* etts[] = { &wslua_ett };
    WSLUA_REGISTER_CLASS(TreeItem);
    outstanding_TreeItem = g_ptr_array_new();
    proto_register_subtree_array(etts,1);
    return 0;
}
