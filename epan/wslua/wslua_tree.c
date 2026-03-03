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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

/* WSLUA_MODULE Tree Adding Information To The Dissection Tree */

#include "wslua.h"
#include <epan/exceptions.h>
#include <epan/show_exception.h>

static int wslua_ett = -1;

static GPtrArray* outstanding_TreeItem;


/* pushing a TreeItem with a NULL item or subtree is completely valid for this function */
TreeItem push_TreeItem(lua_State *L, proto_tree *tree, proto_item *item) {
    TreeItem ti = g_new(struct _wslua_treeitem, 1);

    ti->tree = tree;
    ti->item = item;
    ti->expired = false;

    g_ptr_array_add(outstanding_TreeItem, ti);

    return *(pushTreeItem(L,ti));
}

/* creates the TreeItem but does NOT push it into Lua */
TreeItem create_TreeItem(proto_tree* tree, proto_item* item)
{
    TreeItem tree_item = (TreeItem)g_malloc(sizeof(struct _wslua_treeitem));
    tree_item->tree = tree;
    tree_item->item = item;
    tree_item->expired = false;

    return tree_item;
}

CLEAR_OUTSTANDING(TreeItem, expired, true)

WSLUA_CLASS_DEFINE(TreeItem,FAIL_ON_NULL_OR_EXPIRED("TreeItem"));
/* <<lua_class_TreeItem,`TreeItem`>>s represent information in the https://www.wireshark.org/docs/wsug_html_chunked/ChUsePacketDetailsPaneSection.html[packet details] pane of Wireshark, and the packet details view of TShark.
   A <<lua_class_TreeItem,`TreeItem`>> represents a node in the tree, which might also be a subtree and have a list of children.
   The children of a subtree have zero or more siblings which are other children of the same <<lua_class_TreeItem,`TreeItem`>> subtree.

   During dissection, heuristic-dissection, and post-dissection, a root <<lua_class_TreeItem,`TreeItem`>> is passed to dissectors as the third argument of the function
   callback (e.g., `myproto.dissector(tvbuf,pktinfo,root)`).

   In some cases the tree is not truly added to, in order to improve performance.
   For example for packets not currently displayed/selected in Wireshark's visible
   window pane, or if TShark isn't invoked with the `-V` switch. However the
   "add" type <<lua_class_TreeItem,`TreeItem`>> functions can still be called, and still return <<lua_class_TreeItem,`TreeItem`>>
   objects - but the info isn't really added to the tree. Therefore you do not
   typically need to worry about whether there's a real tree or not. If, for some
   reason, you need to know it, you can use the <<lua_class_attrib_treeitem_visible,`TreeItem.visible`>> attribute getter
   to retrieve the state.
 */

/* the following is used by TreeItem_add_packet_field() - this can THROW errors */
static proto_item *
try_add_packet_field(lua_State *L, TreeItem tree_item, TvbRange tvbr, const int hfid,
                     const ftenum_t type, const unsigned encoding, int *ret_err)
{
    int err = 0;
    proto_item *volatile item = NULL;
    unsigned endoff = 0;

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
                nstime_t *nstime = g_new0(nstime_t, 1);
                item = proto_tree_add_time_item(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                   tvbr->offset, tvbr->len, encoding,
                                                   nstime, &endoff, &err);
                if (err == 0) {
                    pushNSTime(L,nstime);
                    lua_pushinteger(L, endoff);
                }
            }
            break;

        case FT_INT8:
        case FT_INT16:
        case FT_INT24:
        case FT_INT32:
            {
                int32_t ret;
                item = proto_tree_add_item_ret_int(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                tvbr->offset, tvbr->len, encoding,
                                                &ret);
                lua_pushinteger(L, (lua_Integer)ret);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

        case FT_INT40:
        case FT_INT48:
        case FT_INT56:
        case FT_INT64:
            {
                int64_t ret;
                item = proto_tree_add_item_ret_int64(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                tvbr->offset, tvbr->len, encoding,
                                                &ret);
                pushInt64(L, ret);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

        case FT_CHAR:
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
            {
                uint32_t ret;
                item = proto_tree_add_item_ret_uint(tree_item-> tree, hfid, tvbr->tvb->ws_tvb,
                                                    tvbr->offset, tvbr->len, encoding,
                                                    &ret);
                lua_pushinteger(L, (lua_Integer)ret);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

        case FT_UINT40:
        case FT_UINT48:
        case FT_UINT56:
        case FT_UINT64:
            {
                uint64_t ret;
                item = proto_tree_add_item_ret_uint64(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                    tvbr->offset, tvbr->len, encoding,
                                                    &ret);
                pushUInt64(L, ret);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

        case FT_BOOLEAN:
            {
                bool ret;
                item = proto_tree_add_item_ret_boolean(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                    tvbr->offset, tvbr->len, encoding,
                                                    &ret);
                lua_pushboolean(L, ret);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

        case FT_STRING:
        case FT_STRINGZ:
        case FT_STRINGZPAD:
        case FT_STRINGZTRUNC:
        case FT_UINT_STRING:
            {
                const uint8_t *ret;
                int len;
                item = proto_tree_add_item_ret_string_and_length(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                    tvbr->offset, tvbr->len, encoding,
                                                    NULL, &ret, &len);
                lua_pushstring(L, (const char*)ret);
                lua_pushinteger(L, tvbr->offset + len);
                wmem_free(NULL, (void*)ret);
            }
            break;

        case FT_FLOAT:
            {
                float ret;
                item = proto_tree_add_item_ret_float(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                    tvbr->offset, tvbr->len, encoding,
                                                    &ret);
                lua_pushnumber(L, (lua_Number)ret);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

        case FT_DOUBLE:
            {
                double ret;
                item = proto_tree_add_item_ret_double(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                    tvbr->offset, tvbr->len, encoding,
                                                    &ret);
                lua_pushnumber(L, (lua_Number)ret);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

        case FT_IPv4:
            {
                Address addr = g_new(address,1);
                ws_in4_addr ret;
                item = proto_tree_add_item_ret_ipv4(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                    tvbr->offset, tvbr->len, encoding,
                                                    &ret);
                alloc_address_wmem(NULL, addr, AT_IPv4, sizeof(ret), &ret);
                pushAddress(L, addr);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

        case FT_IPv6:
            {
                Address addr = g_new(address, 1);
                ws_in6_addr ret;
                item = proto_tree_add_item_ret_ipv6(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                    tvbr->offset, tvbr->len, encoding,
                                                    &ret);
                alloc_address_wmem(NULL, addr, AT_IPv6, sizeof(ret), &ret);
                pushAddress(L, addr);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

        case FT_ETHER:
            {
                Address addr = g_new(address, 1);
                uint8_t bytes[FT_ETHER_LEN];

                item = proto_tree_add_item_ret_ether(tree_item->tree, hfid, tvbr->tvb->ws_tvb,
                                                    tvbr->offset, tvbr->len, encoding,
                                                    bytes);
                alloc_address_wmem(NULL, addr, AT_ETHER, sizeof(bytes), bytes);
                pushAddress(L, addr);
                lua_pushinteger(L, tvbr->offset + tvbr->len);
            }
            break;

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
     Adds a new child tree for the given <<lua_class_ProtoField,`ProtoField`>> object to this tree item,
     returning the new child <<lua_class_TreeItem,`TreeItem`>>.

     Unlike `TreeItem:add()` and `TreeItem:add_le()`, the <<lua_class_ProtoField,`ProtoField`>> argument
     is not optional, and cannot be a `Proto` object. Instead, this function always
     uses the <<lua_class_ProtoField,`ProtoField`>> to determine the type of field to extract from the
     passed-in `TvbRange`, highlighting the relevant bytes in the Packet Bytes pane
     of the GUI (if there is a GUI), etc.  If no <<lua_class_TvbRange,`TvbRange`>>is given, no bytes are
     highlighted and the field's value cannot be determined; the <<lua_class_ProtoField,`ProtoField`>> must
     have been defined/created not to have a length in such a case, or an error will
     occur.  For backwards-compatibility reasons the `encoding` argument, however,
     must still be given.

     Unlike `TreeItem:add()` and `TreeItem:add_le()`, this function performs both
     big-endian and little-endian decoding, by setting the `encoding` argument to
     be `ENC_BIG_ENDIAN` or `ENC_LITTLE_ENDIAN`.

     The signature of this function:

     [source,lua]
     ----
     tree_item:add_packet_field(proto_field [,tvbrange], encoding, ...)
     ----

     This function returns more than just the new child <<lua_class_TreeItem,`TreeItem`>>.
     The child is the first return value, so that function chaining will still work; but it
     also returns more information. The second return is the value of the extracted field
     (i.e., a number, `UInt64`, `Address`, etc.). The third return is is the offset where
     data should be read next. This is useful when the length of the field is not known in
     advance. The additional return values may be null if the field type is not well supported
     in the Lua API.

     This function can extract a <<lua_class_ProtoField,`ProtoField`>> of type `ftypes.BYTES`
     or `ftypes.ABSOLUTE_TIME` from a string in the `TvbRange` in ASCII-based and similar
     encodings. For example, a `ProtoField` of `ftypes.BYTES` can be extracted from a `TvbRange`
     containing the ASCII string "a1b2c3d4e5f6", and it will correctly decode the ASCII both in the
     tree as well as for the second return value, which will be a <<lua_class_ByteArray,`ByteArray`>>.
     To do so, you must set the `encoding` argument of this function to the appropriate string `ENC_*`
     value, bitwise-or'd (or added) with the `ENC_STR_HEX` value and one or more `ENC_SEP_XXX` values
     indicating which encodings are allowed. For `ftypes.ABSOLUTE_TIME`, one of the `ENC_ISO_8601_*`
     encodings or `ENC_IMF_DATE_TIME` must be used, and the second return value is a <<lua_class_NSTime,`NSTime`>>.
     Only single-byte ASCII digit string encodings such as `ENC_ASCII` and `ENC_UTF_8` can be used for this.

     For example, assuming the <<lua_class_Tvb,`Tvb`>> named "`tvb`" contains the string "abcdef"
     (61 62 63 64 65 66 in hex):

     [source,lua]
     ----
     -- this is done earlier in the script
     local myfield = ProtoField.new("Transaction ID", "myproto.trans_id", ftypes.BYTES)
     myproto.fields = { myfield }

     -- this is done inside a dissector, post-dissector, or heuristic function
     -- child will be the created child tree, and value will be the ByteArray "abcdef" or nil on failure
     local child, value = tree:add_packet_field(myfield, tvb:range(0,6), ENC_UTF_8 + ENC_STR_HEX + ENC_SEP_NONE)
     ----

    */
#define WSLUA_ARG_TreeItem_add_packet_field_PROTOFIELD 2 /* The ProtoField field object to add to the tree. */
#define WSLUA_OPTARG_TreeItem_add_packet_field_TVBRANGE 3 /* The <<lua_class_TvbRange,`TvbRange`>> of bytes in the packet this tree item covers/represents. */
#define WSLUA_ARG_TreeItem_add_packet_field_ENCODING 4 /* The field's encoding in the `TvbRange`. */
#define WSLUA_OPTARG_TreeItem_add_packet_field_LABEL 5 /* One or more strings to append to the created <<lua_class_TreeItem,`TreeItem`>>. */
    volatile TvbRange tvbr;
    ProtoField field;
    int hfid;
    volatile int ett;
    ftenum_t type;
    TreeItem tree_item = shiftTreeItem(L,1);
    unsigned encoding;
    proto_item* item = NULL;
    volatile int nargs;
    volatile int err = 0;
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
    if (field->hfid == -2) {
        luaL_error(L, "ProtoField %s unregistered (not added to a Proto.fields attribute)", field->abbrev);
    }
    hfid = field->hfid;
    type = field->type;
    ett = field->ett;

    tvbr = shiftTvbRange(L,1);
    if (!tvbr) {
        /* No TvbRange specified */
        tvbr = wmem_new(lua_pinfo->pool, struct _wslua_tvbrange);
        tvbr->tvb = wmem_new(lua_pinfo->pool, struct _wslua_tvb);
        tvbr->tvb->ws_tvb = lua_tvb;
        tvbr->offset = 0;
        tvbr->len = 0;
    }

    encoding = wslua_checkuint(L,1);
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
            if (!tvb_find_uint8_remaining(tvbr->tvb->ws_tvb, tvbr->offset, 0, NULL)) {
                luaL_error(L,"out of bounds");
                return 0;
            }
            tvbr->len = tvb_strsize (tvbr->tvb->ws_tvb, tvbr->offset);
            break;
        }
    }

    TRY {
        int errx = 0;
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
        const char* s;
        s = lua_tostring(L,1);
        if (s) proto_item_append_text(item, " %s", s);
        lua_remove(L,1);
        nargs--;
    }

    push_TreeItem(L, proto_item_add_subtree(item,ett > 0 ? ett : wslua_ett), item);

    /* move the tree object before the field value */
    lua_insert(L, 1);

    WSLUA_RETURN(3); /* The new child <<lua_class_TreeItem,`TreeItem`>>, the field's extracted value or nil, and offset or nil. */
}

/* The following is used by TreeItem_add() and TreeItem_le() and can THROW.
 * It should be called inside a TRY (e.g. WRAP_NON_LUA_EXCEPTIONS) block and
 * THROW_LUA_ERROR should be used insteadof lua[L]_error.
 */
static int TreeItem_add_item_any(lua_State *L, bool little_endian) {
    TvbRange tvbr;
    Proto proto;
    ProtoField field;
    int hfid = -1;
    int ett = -1;
    ftenum_t type = FT_NONE;
    TreeItem tree_item  = shiftTreeItem(L,1);
    proto_item* item = NULL;

    if (!tree_item) {
        THROW_LUA_ERROR("not a TreeItem!");
    }
    if (tree_item->expired) {
        THROW_LUA_ERROR("expired TreeItem");
        return 0;
    }

    if (! ( field = shiftProtoField(L,1) ) ) {
        if (( proto = shiftProto(L,1) )) {
            hfid = proto->hfid;
            type = FT_PROTOCOL;
            ett = proto->ett;
        } else if (lua_isnil(L, 1)) {
            THROW_LUA_ERROR("first argument to TreeItem:add is nil!");
        }
    } else {
        hfid = field->hfid;
        type = field->type;
        ett = field->ett;
    }

    tvbr = shiftTvbRange(L,1);

    if (!tvbr) {
        tvbr = wmem_new(lua_pinfo->pool, struct _wslua_tvbrange);
        tvbr->tvb = wmem_new(lua_pinfo->pool, struct _wslua_tvb);
        tvbr->tvb->ws_tvb = lua_tvb;
        tvbr->offset = 0;
        tvbr->len = 0;
    }

    if (hfid > 0 ) {
        /* hfid is > 0 when the first arg was a ProtoField or Proto */

        if (type == FT_STRINGZ) {
            if (!tvb_find_uint8_remaining(tvbr->tvb->ws_tvb, tvbr->offset, 0, NULL)) {
                THROW_LUA_ERROR("out of bounds");
                return 0;
            }
            tvbr->len = tvb_strsize (tvbr->tvb->ws_tvb, tvbr->offset);
        }

        if (lua_gettop(L)) {
            /* if we got here, the (L,1) index is the value to add, instead of decoding from the Tvb */

            /* It's invalid for it to be nil (which has been documented for
             * a long time). Make sure we throw our error instead of an
             * internal Lua error (due to nested setjmp/longjmp).
             */
            if (lua_isnil(L, 1)) {
                THROW_LUA_ERROR("TreeItem:add value argument is nil!");
            }

            switch(type) {
                case FT_PROTOCOL:
                    item = proto_tree_add_item(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,ENC_NA);
                    lua_pushinteger(L,0);
                    lua_insert(L,1);
                    break;
                case FT_BOOLEAN:
                    {
                        uint64_t val;
                        switch(lua_type(L, 1)) {

                        case LUA_TUSERDATA:
                            val = checkUInt64(L, 1);
                            break;

                        default:
                            /* this needs to use checkinteger so that it can accept a Lua boolean and coerce it to an int */
                            val = (uint64_t) (wslua_tointeger(L,1));
                        }
                        item = proto_tree_add_boolean(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,val);
                    }
                    break;
                case FT_CHAR:
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                case FT_FRAMENUM:
                    item = proto_tree_add_uint(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,wslua_checkuint32(L,1));
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    item = proto_tree_add_int(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,wslua_checkint32(L,1));
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
                case FT_STRINGZ:
                    item = proto_tree_add_string(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,luaL_checkstring(L,1));
                    break;
                case FT_BYTES:
                    item = proto_tree_add_bytes(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len, (const uint8_t*) luaL_checkstring(L,1));
                    break;
                case FT_UINT64:
                    item = proto_tree_add_uint64(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,checkUInt64(L,1));
                    break;
                case FT_INT64:
                    item = proto_tree_add_int64(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,checkInt64(L,1));
                    break;
                case FT_IPv4:
                    {
                        Address addr = checkAddress(L,1);
                        uint32_t addr_value;

                        if (addr->type != AT_IPv4) {
                            THROW_LUA_ERROR("Expected IPv4 address for FT_IPv4 field");
                            return 0;
                        }

                        /*
                         * The address is not guaranteed to be aligned on a
                         * 32-bit boundary, so we can't safely dereference
                         * the pointer as if it were so aligned.
                         */
                        memcpy(&addr_value, addr->data, sizeof addr_value);
                        item = proto_tree_add_ipv4(tree_item->tree,hfid,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,addr_value);
                    }
                    break;
                case FT_IPv6:
                    {
                        Address addr = checkAddress(L,1);
                        if (addr->type != AT_IPv6) {
                            THROW_LUA_ERROR("Expected IPv6 address for FT_IPv6 field");
                            return 0;
                        }

                        item = proto_tree_add_ipv6(tree_item->tree, hfid, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len, (const ws_in6_addr *)addr->data);
                    }
                    break;
                case FT_ETHER:
                    {
                        Address addr = checkAddress(L,1);
                        if (addr->type != AT_ETHER) {
                            THROW_LUA_ERROR("Expected MAC address for FT_ETHER field");
                            return 0;
                        }

                        item = proto_tree_add_ether(tree_item->tree, hfid, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len, (const uint8_t *)addr->data);
                    }
                    break;
                case FT_UINT_BYTES:
                case FT_IPXNET:
                case FT_GUID:
                case FT_OID:
                case FT_REL_OID:
                case FT_SYSTEM_ID:
                case FT_VINES:
                case FT_FCWWN:
                default:
                    THROW_LUA_ERROR("%s not yet supported", ftype_name(type));
                    return 0;
            }

            lua_remove(L,1);

        } else {
            if (type == FT_FRAMENUM) {
                THROW_LUA_ERROR("ProtoField FRAMENUM cannot fetch value from Tvb");
                return 0;
            }
            /* the Lua stack is empty - no value was given - so decode the value from the tvb */
            item = proto_tree_add_item(tree_item->tree, hfid, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len, little_endian ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
        }

        if ( lua_gettop(L) ) {
            /* if there was a value, it was removed earlier, so what's left is the display string to set */
            const char* s = lua_tostring(L,1);
            if (s) proto_item_set_text(item,"%s",s);
            lua_remove(L,1);
        }

    } else {
        /* no ProtoField or Proto was given - we're adding a text-only field,
         * any remaining parameters are parts of the text label. */
        if (lua_gettop(L)) {
            const char* s = lua_tostring(L,1);
            const int hf = get_hf_wslua_text();
            if (hf > -1) {
                /* use proto_tree_add_none_format() instead? */
                item = proto_tree_add_item(tree_item->tree, hf, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len, ENC_NA);
                proto_item_set_text(item, "%s", s);
            } else {
                THROW_LUA_ERROR("Internal error: hf_wslua_text not registered");
            }
            lua_remove(L,1);
        } else {
            THROW_LUA_ERROR("Tree item ProtoField/Protocol handle is invalid (ProtoField/Proto not registered?)");
        }
    }

    while(lua_gettop(L)) {
        /* keep appending more text */
        const char* s = lua_tostring(L,1);
        if (s) proto_item_append_text(item, " %s", s);
        lua_remove(L,1);
    }

    push_TreeItem(L, proto_item_add_subtree(item,ett > 0 ? ett : wslua_ett), item);

    return 1;
}


WSLUA_METHOD TreeItem_add(lua_State *L) {
    /*
    Adds a child item to this tree item, returning the new child <<lua_class_TreeItem,`TreeItem`>>.

    If the <<lua_class_ProtoField,`ProtoField`>> represents a numeric value (int, uint or float), then it's treated as a Big Endian (network order) value.

    This function has a complicated form: 'treeitem:add([protofield,] [tvbrange,] [[value], label]])', such that if the first
    argument is a <<lua_class_ProtoField,`ProtoField`>> or a <<lua_class_Proto,`Proto`>>, the second argument is a <<lua_class_TvbRange,`TvbRange`>>, and a third argument is given, it's a value;
    but if the second argument is a non-<<lua_class_TvbRange,`TvbRange`>>, then it's the value (as opposed to filling that argument with 'nil',
    which is invalid for this function).  If the first argument is a non-<<lua_class_ProtoField,`ProtoField`>> and a non-<<lua_class_Proto,`Proto`>> then this argument can
    be either a <<lua_class_TvbRange,`TvbRange`>> or a label, and the value is not in use.

    [discrete]
    ====== Example

    [source,lua]
    ----
    local proto_foo = Proto("foo", "Foo Protocol")
    proto_foo.fields.bytes = ProtoField.bytes("foo.bytes", "Byte array")
    proto_foo.fields.u16 = ProtoField.uint16("foo.u16", "Unsigned short", base.HEX)

    function proto_foo.dissector(buf, pinfo, tree)
            -- ignore packets less than 4 bytes long
            if buf:len() < 4 then return end

            -- ##############################################
            -- # Assume buf(0,4) == {0x00, 0x01, 0x00, 0x02}
            -- ##############################################

            local t = tree:add( proto_foo, buf() )

            -- Adds a byte array that shows as: "Byte array: 00010002"
            t:add( proto_foo.fields.bytes, buf(0,4) )

            -- Adds a byte array that shows as "Byte array: 313233"
            -- (the ASCII char code of each character in "123")
            t:add( proto_foo.fields.bytes, buf(0,4), "123" )

            -- Adds a tree item that shows as: "Unsigned short: 0x0001"
            t:add( proto_foo.fields.u16, buf(0,2) )

            -- Adds a tree item that shows as: "Unsigned short: 0x0064"
            t:add( proto_foo.fields.u16, buf(0,2), 100 )

            -- Adds a tree item that shows as: "Unsigned short: 0x0064 ( big endian )"
            t:add( proto_foo.fields.u16, buf(1,2), 100, nil, "(", nil, "big", 999, nil, "endian", nil, ")" )

            -- LITTLE ENDIAN: Adds a tree item that shows as: "Unsigned short: 0x0100"
            t:add_le( proto_foo.fields.u16, buf(0,2) )

            -- LITTLE ENDIAN: Adds a tree item that shows as: "Unsigned short: 0x6400"
            t:add_le( proto_foo.fields.u16, buf(0,2), 100 )

            -- LITTLE ENDIAN: Adds a tree item that shows as: "Unsigned short: 0x6400 ( little endian )"
            t:add_le( proto_foo.fields.u16, buf(1,2), 100, nil, "(", nil, "little", 999, nil, "endian", nil, ")" )
    end

    udp_table = DissectorTable.get("udp.port")
    udp_table:add(7777, proto_foo)
    ----
    */
#define WSLUA_OPTARG_TreeItem_add_PROTOFIELD 2 /* The <<lua_class_ProtoField,`ProtoField`>> field or <<lua_class_Proto,`Proto`>> protocol object to add to the tree. */
#define WSLUA_OPTARG_TreeItem_add_TVBRANGE 3 /* The <<lua_class_TvbRange,`TvbRange`>> of bytes in the packet this tree item covers/represents. */
#define WSLUA_OPTARG_TreeItem_add_VALUE 4 /* The field's value, instead of the ProtoField/Proto one. */
#define WSLUA_OPTARG_TreeItem_add_LABEL 5 /* One or more strings to use for the tree item label, instead of the ProtoField/Proto one. */

    volatile int ret;
    WRAP_NON_LUA_EXCEPTIONS(
        ret = TreeItem_add_item_any(L,false);
    )
    WSLUA_RETURN(ret); /* The new child TreeItem. */
}

WSLUA_METHOD TreeItem_add_le(lua_State *L) {
    /*
     Adds a child item to this tree item, returning the new child <<lua_class_TreeItem,`TreeItem`>>.

     If the <<lua_class_ProtoField,`ProtoField`>> represents a numeric value (int, uint or float), then it's treated as a Little Endian value.

     This function has a complicated form: 'treeitem:add_le([protofield,] [tvbrange,] [[value], label]])', such that if the first
     argument is a <<lua_class_ProtoField,`ProtoField`>> or a <<lua_class_Proto,`Proto`>>, the second argument is a <<lua_class_TvbRange,`TvbRange`>>, and a third argument is given, it's a value;
     but if the second argument is a non-<<lua_class_TvbRange,`TvbRange`>>, then it's the value (as opposed to filling that argument with 'nil',
     which is invalid for this function).  If the first argument is a non-<<lua_class_ProtoField,`ProtoField`>> and a non-<<lua_class_Proto,`Proto`>> then this argument can
     be either a <<lua_class_TvbRange,`TvbRange`>> or a label, and the value is not in use.
     */
#define WSLUA_OPTARG_TreeItem_add_le_PROTOFIELD 2 /* The ProtoField field or Proto protocol object to add to the tree. */
#define WSLUA_OPTARG_TreeItem_add_le_TVBRANGE 3 /* The TvbRange of bytes in the packet this tree item covers/represents. */
#define WSLUA_OPTARG_TreeItem_add_le_VALUE 4 /* The field's value, instead of the ProtoField/Proto one. */
#define WSLUA_OPTARG_TreeItem_add_le_LABEL 5 /* One or more strings to use for the tree item label, instead of the ProtoField/Proto one. */
    volatile int ret;
    WRAP_NON_LUA_EXCEPTIONS(
        ret = TreeItem_add_item_any(L,true);
    )
    WSLUA_RETURN(ret); /* The new child TreeItem. */
}

/* WSLUA_ATTRIBUTE TreeItem_text RW Set/get the <<lua_class_TreeItem,`TreeItem`>>'s display string (string).

    For the getter, if the TreeItem has no display string, then nil is returned.
 */
static int TreeItem_get_text(lua_State* L) {
    TreeItem ti = checkTreeItem(L,1);
    char label_str[ITEM_LABEL_LENGTH+1];
    char *label_ptr;

    if (ti->item && PITEM_FINFO(ti->item)) {
        field_info *fi = PITEM_FINFO(ti->item);

        if (!fi->rep) {
            label_ptr = label_str;
            proto_item_fill_label(fi, label_str, NULL);
        } else
            label_ptr = fi->rep->representation;

        if (label_ptr) {
            lua_pushstring(L, label_ptr);
        } else {
            lua_pushnil(L);
        }
    } else {
        lua_pushnil(L);
    }

    return 1;
}

/* the following is used as both a method and attribute */
WSLUA_METHOD TreeItem_set_text(lua_State *L) {
    /* Sets the text of the label.

       This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
    */
#define WSLUA_ARG_TreeItem_set_text_TEXT 2 /* The text to be used. */
    TreeItem ti = checkTreeItem(L,1);
    const char* s = luaL_checkstring(L,WSLUA_ARG_TreeItem_set_text_TEXT);

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
    const char* s = luaL_checkstring(L,WSLUA_ARG_TreeItem_append_text_TEXT);

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
    const char* s = luaL_checkstring(L,WSLUA_ARG_TreeItem_prepend_text_TEXT);

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
#define WSLUA_OPTARG_TreeItem_add_expert_info_GROUP 2 /* One of:
                                                         `PI_CHECKSUM`,
                                                         `PI_SEQUENCE`,
                                                         `PI_RESPONSE_CODE`,
                                                         `PI_REQUEST_CODE`,
                                                         `PI_UNDECODED`,
                                                         `PI_REASSEMBLE`,
                                                         `PI_MALFORMED`,
                                                         `PI_DEBUG`,
                                                         `PI_PROTOCOL`,
                                                         `PI_SECURITY`,
                                                         `PI_COMMENTS_GROUP`,
                                                         `PI_DECRYPTION`,
                                                         `PI_ASSUMPTION`,
                                                         `PI_DEPRECATED`,
                                                         `PI_RECEIVE`,
                                                         `PI_INTERFACE`,
                                                         or `PI_DISSECTOR_BUG`. */
#define WSLUA_OPTARG_TreeItem_add_expert_info_SEVERITY 3 /* One of:
                                                            `PI_COMMENT`,
                                                            `PI_CHAT`,
                                                            `PI_NOTE`,
                                                            `PI_WARN`,
                                                            or `PI_ERROR`. */
#define WSLUA_OPTARG_TreeItem_add_expert_info_TEXT 4 /* The text for the expert info display. */
    TreeItem ti           = checkTreeItem(L,1);
    int group             = (int)luaL_optinteger(L,WSLUA_OPTARG_TreeItem_add_expert_info_GROUP,PI_DEBUG);
    int severity          = (int)luaL_optinteger(L,WSLUA_OPTARG_TreeItem_add_expert_info_SEVERITY,PI_CHAT);
    expert_field* ei_info = wslua_get_expert_field(group, severity);
    const char* str;

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
    /* Sets the expert flags of the tree item and adds expert info to the packet. */
#define WSLUA_ARG_TreeItem_add_proto_expert_info_EXPERT 2 /* The <<lua_class_ProtoExpert,`ProtoExpert`>> object to add to the tree. */
#define WSLUA_OPTARG_TreeItem_add_proto_expert_info_TEXT 3 /* Text for the expert info display
                                                              (default is to use the registered
                                                              text). */
    TreeItem ti = checkTreeItem(L,1);
    ProtoExpert expert = checkProtoExpert(L,WSLUA_ARG_TreeItem_add_proto_expert_info_EXPERT);
    const char* str;

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
       associated with the <<lua_class_Tvb,`Tvb`>> or <<lua_class_TvbRange,`TvbRange`>> bytes in the packet. */
#define WSLUA_ARG_TreeItem_add_tvb_expert_info_EXPERT 2 /* The <<lua_class_ProtoExpert,`ProtoExpert`>> object to add to the tree. */
#define WSLUA_ARG_TreeItem_add_tvb_expert_info_TVB 3 /* The <<lua_class_Tvb,`Tvb`>> or <<lua_class_TvbRange,`TvbRange`>> object bytes to associate
                                                        the expert info with. */
#define WSLUA_OPTARG_TreeItem_add_tvb_expert_info_TEXT 4 /* Text for the expert info display
                                                              (default is to use the registered
                                                              text). */
    TreeItem ti = checkTreeItem(L,1);
    ProtoExpert expert = checkProtoExpert(L,WSLUA_ARG_TreeItem_add_proto_expert_info_EXPERT);
    TvbRange tvbr;
    const char* str;

    if (expert->ids.ei == EI_INIT_EI || expert->ids.hf == EI_INIT_HF) {
        luaL_error(L, "ProtoExpert is not registered");
        return 0;
    }

    tvbr = shiftTvbRange(L,WSLUA_ARG_TreeItem_add_tvb_expert_info_TVB);

    if (!tvbr) {
        tvbr = wmem_new(lua_pinfo->pool, struct _wslua_tvbrange);
        tvbr->tvb = shiftTvb(L,WSLUA_ARG_TreeItem_add_tvb_expert_info_TVB);
        if (!tvbr->tvb) {
            tvbr->tvb = wmem_new(lua_pinfo->pool, struct _wslua_tvb);
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


/* WSLUA_ATTRIBUTE TreeItem_visible RO Get the <<lua_class_TreeItem,`TreeItem`>>'s subtree visibility status (boolean). */
static int TreeItem_get_visible(lua_State* L) {
    TreeItem ti = checkTreeItem(L,1);

    if (ti->tree) {
        lua_pushboolean(L, PTREE_DATA(ti->tree)->visible);
    }
    else {
        lua_pushboolean(L, false);
    }

    return 1;
}


/* WSLUA_ATTRIBUTE TreeItem_generated RW Set/get the <<lua_class_TreeItem,`TreeItem`>>'s generated state (boolean). */
static int TreeItem_get_generated(lua_State* L) {
    TreeItem ti = checkTreeItem(L,1);

    lua_pushboolean(L, proto_item_is_generated(ti->item));

    return 1;
}

/* the following is used as both a method and attribute. As a method it defaults
   to setting the value, because that's what it used to do before. */
WSLUA_METHOD TreeItem_set_generated(lua_State *L) {
    /* Marks the <<lua_class_TreeItem,`TreeItem`>> as a generated field (with data inferred but not contained in the packet).

       This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
    */
#define WSLUA_OPTARG_TreeItem_set_generated_BOOL 2 /* A Lua boolean, which if `true` sets the <<lua_class_TreeItem,`TreeItem`>>
                                                      generated flag, else clears it (default=true) */
    TreeItem ti = checkTreeItem(L,1);
    bool set = wslua_optbool(L, WSLUA_OPTARG_TreeItem_set_generated_BOOL, true);

    if (set) {
        proto_item_set_generated(ti->item);
    } else {
        if (ti->item)
            FI_RESET_FLAG(PITEM_FINFO(ti->item), FI_GENERATED);
    }

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

/* WSLUA_ATTRIBUTE TreeItem_hidden RW Set/get <<lua_class_TreeItem,`TreeItem`>>'s hidden state (boolean). */
static int TreeItem_get_hidden(lua_State* L) {
    TreeItem ti = checkTreeItem(L,1);

    lua_pushboolean(L, proto_item_is_hidden(ti->item));

    return 1;
}

/* the following is used as both a method and attribute. As a method it defaults
   to setting the value, because that's what it used to do before. */
WSLUA_METHOD TreeItem_set_hidden(lua_State *L) {
    /*
    Marks the <<lua_class_TreeItem,`TreeItem`>> as a hidden field (neither displayed nor used in filters).
    Deprecated

    This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
    */
#define WSLUA_OPTARG_TreeItem_set_hidden_BOOL 2 /* A Lua boolean, which if `true` sets the <<lua_class_TreeItem,`TreeItem`>>
                                                      hidden flag, else clears it. Default is `true`. */
    TreeItem ti = checkTreeItem(L,1);
    bool set = wslua_optbool(L, WSLUA_OPTARG_TreeItem_set_hidden_BOOL, true);

    if (set) {
        proto_item_set_hidden(ti->item);
    } else {
        proto_item_set_visible(ti->item);
    }

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

/* WSLUA_ATTRIBUTE TreeItem_len RW Set/get <<lua_class_TreeItem,`TreeItem`>>'s length inside tvb, after it has already been created. */
static int TreeItem_get_len(lua_State* L) {
    TreeItem ti = checkTreeItem(L,1);
    int len = 0;

    /* XXX - this is *NOT* guaranteed to return a correct value! */
    len = proto_item_get_len(ti->item);

    lua_pushinteger(L, len > 0 ? len : 0);

    return 1;
}

WSLUA_METHOD TreeItem_set_len(lua_State *L) {
    /* Set <<lua_class_TreeItem,`TreeItem`>>'s length inside tvb, after it has already been created.

       This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
    */
#define WSLUA_ARG_TreeItem_set_len_LEN 2 /* The length to be used. */
    TreeItem ti = checkTreeItem(L,1);
    int len = (int)luaL_checkinteger(L,WSLUA_ARG_TreeItem_set_len_LEN);

    if (len < 0) {
        luaL_argerror(L,WSLUA_ARG_TreeItem_set_len_LEN,"must be a positive value");
        return 0;
    }

    proto_item_set_len(ti->item, len);

    /* copy the TreeItem userdata so we give it back */
    lua_pushvalue(L, 1);

    WSLUA_RETURN(1); /* The same TreeItem. */
}

WSLUA_METHOD TreeItem_referenced(lua_State *L) {
    /* Checks if a <<lua_class_ProtoField,`ProtoField`>> or <<lua_class_Dissector,`Dissector`>> is referenced by a filter/tap/UI.

    If this function returns `false`, it means that the field (or dissector) does not need to be dissected
    and can be safely skipped. By skipping a field rather than dissecting it, the dissector will
    usually run faster since Wireshark will not do extra dissection work when it doesn't need the field.

    You can use this in conjunction with the TreeItem.visible attribute. This function will always return
    true when the TreeItem is visible. When it is not visible and the field is not referenced, you can
    speed up the dissection by not dissecting the field as it is not needed for display or filtering.

    This function takes one parameter that can be a <<lua_class_ProtoField,`ProtoField`>> or <<lua_class_Dissector,`Dissector`>>.
    The <<lua_class_Dissector,`Dissector`>> form is useful when you need to decide whether to call a sub-dissector.
    */
#define WSLUA_ARG_TreeItem_referenced_PROTOFIELD 2 /* The <<lua_class_ProtoField,`ProtoField`>> or <<lua_class_Dissector,`Dissector`>> to check if referenced. */
    TreeItem ti = checkTreeItem(L, 1);
    if (!ti) return 0;
    ProtoField f = shiftProtoField(L, WSLUA_ARG_TreeItem_referenced_PROTOFIELD);
    if (f) {
        lua_pushboolean(L, proto_field_is_referenced(ti->tree, f->hfid));
    }
    else {
        Dissector d = checkDissector(L, WSLUA_ARG_TreeItem_referenced_PROTOFIELD);
        if (!d) return 0;
        lua_pushboolean(L, proto_field_is_referenced(ti->tree, dissector_handle_get_protocol_index(d)));
    }
    WSLUA_RETURN(1); /* A boolean indicating if the ProtoField/Dissector is referenced */
}

WSLUA_METHOD TreeItem_get_child_count(lua_State *L) {
    /* Returns the number of direct child tree items.

    This method counts and returns the number of direct children of this tree item.
    Only immediate children are counted; grandchildren and deeper descendants are not included.

    [source,lua]
    ----
    local tree = root:add(myproto, tvbuf())
    tree:add("Child 1")
    tree:add("Child 2")

    local count = tree:get_child_count()
    -- count is now 2
    ----

    @since 4.7.0
    */

    /* Retrieve and validate the TreeItem from Lua stack position 1 */
    TreeItem ti = checkTreeItem(L, 1);
    if (!ti) {
        return 0;
    }

    int count = 0;
    proto_tree *tree = ti->tree;

    if (tree) {
        /* Get the first child node from the proto_tree structure */
        proto_node *current = ((proto_node *)tree)->first_child;

        /* Iterate through the linked list of children using the 'next' pointer */
        while (current) {
            count++;
            current = current->next;  /* Move to next sibling */
        }
    }

    /* Push the count as an integer onto the Lua stack */
    lua_pushinteger(L, count);
    WSLUA_RETURN(1); /* The number of child tree items. */
}

WSLUA_METHOD TreeItem_get_parent(lua_State *L) {
    /* Returns the parent tree item.

    Returns the parent tree item of this item, or nil if this is a root item
    (i.e., a top-level tree item added directly to the protocol tree).

    [source,lua]
    ----
    local parent_tree = root:add(myproto, tvbuf())
    local child_tree = parent_tree:add("Child")

    local parent = child_tree:get_parent()
    -- parent is the same as parent_tree

    local root_parent = parent_tree:get_parent()
    -- root_parent is nil (assuming parent_tree is a root item)
    ----
    @since 4.7.0
    */

    /* Retrieve and validate the TreeItem from Lua stack */
    TreeItem ti = checkTreeItem(L, 1);
    if (!ti) {
        return 0;
    }

    proto_item *parent = NULL;

    if (ti->item) {
        /* Use Wireshark's built-in function to get the parent proto_item */
        parent = proto_item_get_parent(ti->item);
    }

    if (parent) {
        /* Parent exists - get its subtree (may be NULL if parent has no children) */
        proto_tree *parent_tree = proto_item_get_subtree(parent);

        /* Create a new Lua TreeItem object wrapping the parent and push it to Lua */
        push_TreeItem(L, parent_tree, parent);
    } else {
        /* No parent exists - this is a root item, return nil */
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The parent TreeItem, or nil if this is a root item. */
}

WSLUA_METHOD TreeItem_get_child(lua_State *L) {
    /* Returns the child tree item at the specified index.

    Returns the direct child TreeItem at the given index using 0-based indexing.
    This provides random access to child items by their position.

    [source,lua]
    ----
    local tree = root:add(myproto, tvbuf())
    tree:add("First child")   -- index 0
    tree:add("Second child")  -- index 1
    tree:add("Third child")   -- index 2

    local first = tree:get_child(0)   -- Returns first child
    local second = tree:get_child(1)  -- Returns second child
    local invalid = tree:get_child(5) -- Returns nil (out of range)
    ----
    @since 4.7.0
    */

#define WSLUA_ARG_TreeItem_get_child_INDEX 2 /* The index of the child (0-based). */
    /* Retrieve and validate the TreeItem */
    TreeItem ti = checkTreeItem(L, 1);
    if (!ti)
        return 0;

    /* Get the index parameter from Lua (must be an integer) */
    lua_Integer index = luaL_checkinteger(L, WSLUA_ARG_TreeItem_get_child_INDEX);

    /* Validate index - must be non-negative for 0-based indexing */
    if (index < 0) {
        WSLUA_ARG_ERROR(TreeItem_get_child, INDEX, "index must be non-negative");
    }

    proto_node *current = NULL;

    if (ti->tree) {
        /* Get the first child in the linked list */
        current = ((proto_node *)ti->tree)->first_child;
    }

    /* Navigate to the index-th child by following the 'next' pointers */
    lua_Integer current_index = 0;
    while (current && current_index < index) {
        current = current->next;  /* Move to next sibling */
        current_index++;
    }

    if (current) {
        /* Child found at the specified index */
        /* Get the subtree (may be NULL if this node has no children) */
        proto_tree *child_tree = proto_item_get_subtree((proto_item *)current);

        /* Create and push the TreeItem to Lua */
        push_TreeItem(L, child_tree, (proto_item *)current);
    } else {
        /* Index out of range - no child exists at this position */
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The child TreeItem at the specified index, or nil if out of range. */
}

/* Structure to hold iterator state with optional field name filters and recursion */
typedef struct
{
    proto_node *current_node;  /* Current node being processed in iteration */
    char **field_filters;      /* Array of field name strings to match (e.g., "tcp.port") */
    int num_filters;           /* Number of filter strings in the array */
    bool recursive;            /* If true, iterate through entire subtree depth-first */
    proto_node **stack;        /* Stack for recursive depth-first traversal */
    int stack_size;            /* Number of nodes currently on the stack */
    int stack_capacity;        /* Maximum capacity of stack (grows dynamically) */
} TreeItem_iterator_state;

/* Helper function to push a node onto the stack for recursive iteration */
static void push_node_to_stack(TreeItem_iterator_state *state, proto_node *node) {
    if (!node)
        return;

    /* Dynamically expand stack capacity if needed */
    if (state->stack_size >= state->stack_capacity) {
        /* Double capacity plus initial buffer to reduce reallocation frequency */
        state->stack_capacity = state->stack_capacity * 2 + 10;
        state->stack = (proto_node **)g_realloc(state->stack,
                                                state->stack_capacity * sizeof(proto_node *));
    }

    /* Add node to top of stack and increment size */
    state->stack[state->stack_size++] = node;
}

/* Helper function to pop a node from the stack */
static proto_node *pop_node_from_stack(TreeItem_iterator_state *state) {
    /* Check if stack is empty */
    if (state->stack_size <= 0)
        return NULL;

    /* Return top element and decrement stack size */
    return state->stack[--state->stack_size];
}

/* Helper function for the children iterator with optional filtering and recursion */
static int TreeItem_children_iterator(lua_State *L) {
    /* Retrieve the iterator state from the closure's upvalue */
    TreeItem_iterator_state *state = (TreeItem_iterator_state *)lua_touserdata(L, lua_upvalueindex(1));

    /* Continue iterating while we have nodes to process */
    /* Either from current sibling chain OR from recursive stack */
    while (state->current_node || (state->recursive && state->stack_size > 0)) {
        proto_node *node = NULL;

        if (state->current_node) {
            /* Process next node in current sibling chain */
            node = state->current_node;
            state->current_node = node->next;  /* Advance to next sibling for next iteration */
        } else if (state->recursive && state->stack_size > 0) {
            /* No more siblings - pop from stack for recursive traversal */
            node = pop_node_from_stack(state);
            if (!node)
                continue;  /* Stack had invalid entry, skip */

            /* Set current_node to first child of popped node */
            /* This allows iteration through all siblings before going deeper */
            proto_tree *subtree = proto_item_get_subtree((proto_item *)node);
            if (subtree) {
                state->current_node = ((proto_node *)subtree)->first_child;
            }
        }

        if (!node)
            continue;  /* Safety check - should not happen */

        /* IMPORTANT: For recursive mode, always add children to stack regardless of filter match
         * This ensures that even if the current node doesn't match the filter,
         * its children are still searched recursively (depth-first traversal)
         *
         * Example: If we filter for "tcp.port" but current node is "tcp.flags",
         * we still need to check if "tcp.flags" has "tcp.port" children
         */
        if (state->recursive) {
            proto_tree *subtree = proto_item_get_subtree((proto_item *)node);
            if (subtree) {
                /* Collect all children first (needed for reverse-order pushing) */
                proto_node *child = ((proto_node *)subtree)->first_child;
                proto_node **children = NULL;
                int child_count = 0;

                /* Count and collect all children in forward order */
                while (child) {
                    child_count++;
                    children = (proto_node **)g_realloc(children, child_count * sizeof(proto_node *));
                    children[child_count - 1] = child;
                    child = child->next;
                }

                /* Push children in REVERSE order to stack */
                /* This ensures depth-first left-to-right traversal */
                /* (first child is on top of stack, gets popped first) */
                for (int i = child_count - 1; i >= 0; i--) {
                    push_node_to_stack(state, children[i]);
                }

                /* Free temporary children array */
                if (children)
                    g_free(children);
            }
        }

        /* Check if this node matches the filter criteria */
        bool matches = false;
        if (state->num_filters > 0) {
            /* Filters are specified - check if node's field name matches any filter */
            field_info *finfo = node->finfo;

            /* Ensure node has valid field_info with abbreviated name */
            if (finfo && finfo->hfinfo && finfo->hfinfo->abbrev) {
                /* Check against all filter strings (OR logic) */
                for (int i = 0; i < state->num_filters; i++) {
                    if (strcmp(finfo->hfinfo->abbrev, state->field_filters[i]) == 0) {
                        matches = true;
                        break;  /* Found match, no need to check remaining filters */
                    }
                }
            }
            /* If finfo is NULL or has no abbrev, matches remains false */
        } else {
            /* No filters specified - return all children/descendants */
            matches = true;
        }

        /* Only return matching nodes to Lua, but continue processing regardless
         * (children were already added to stack above for recursive mode) */
        if (matches) {
            /* Get the subtree for this matching node (may be NULL) */
            proto_tree *child_tree = proto_item_get_subtree((proto_item *)node);

            /* Push matching TreeItem to Lua stack */
            push_TreeItem(L, child_tree, (proto_item *)node);
            return 1;  /* Return 1 value to Lua iterator */
        }

        /* If no match, continue to next node
         * Children are already on stack for recursive mode,
         * ensuring we don't miss matching descendants */
    }

    /* No more nodes to process - iteration complete */
    return 0;  /* Return no values - signals end of iteration to Lua */
}

/* Garbage collector for the iterator state */
static int TreeItem_iterator_state_gc(lua_State *L) {
    /* Retrieve the iterator state userdata */
    TreeItem_iterator_state *state = (TreeItem_iterator_state *)lua_touserdata(L, 1);

    /* Free the filter strings array */
    if (state->field_filters) {
        /* Free each individual filter string */
        for (int i = 0; i < state->num_filters; i++) {
            g_free(state->field_filters[i]);
        }
        /* Free the array itself */
        g_free(state->field_filters);
    }

    /* Free the recursion stack */
    if (state->stack) {
        g_free(state->stack);
    }

    /* Note: The state struct itself is freed by Lua's GC */
    return 0;
}

WSLUA_METHOD TreeItem_children(lua_State *L) {
    /* Returns an iterator function to iterate over child tree items.

    Returns an iterator function that can be used in a Lua for loop to iterate
    over children of this tree item. Supports optional filtering and recursive traversal.

    The basic usage iterates over direct children only:
    [source,lua]
    ----
    for child in tree:children() do
        print("Child: " .. tostring(child))
    end
    ----

    You can filter by field names to only get children with specific fields:
    [source,lua]
    ----
    -- Single field filter
    for child in tree:children("tcp.flags") do
        print("TCP flags child: " .. tostring(child))
    end

    -- Multiple field filters
    for child in tree:children({"tcp.port", "tcp.srcport", "tcp.dstport"}) do
        print("TCP port child: " .. tostring(child))
    end
    ----

    Enable recursive iteration to traverse the entire subtree in depth-first order:
    [source,lua]
    ----
    -- Recursive iteration without filter
    for child in tree:children(nil, true) do
        print("Descendant: " .. tostring(child))
    end

    -- Recursive iteration with field filter
    for child in tree:children("tcp.flags", true) do
        print("TCP flags anywhere in subtree: " .. tostring(child))
    end
    ----

    When using recursive mode with filters, the iterator searches through all descendants
    even if parent nodes don't match the filter, ensuring no matching children are missed.

    IMPORTANT: Field extractors must still be created for the fields you want to iterate over.
    Wireshark optimizes dissection by only creating tree items for fields that are explicitly
    requested through field extractors, display filters, or taps. Without proper field extractors,
    the fields may not exist in the dissection tree and will not be found by this iterator.

    Example of proper field extractor setup:
    [source,lua]
    ----
    -- Define field extractors first
    local tcp_flags_extractor = Field.new("tcp.flags")
    local tcp_port_extractor = Field.new("tcp.port")

    -- Then use tree navigation (extractors ensure fields exist in tree)
    for child in tree:children("tcp.flags") do
        local field_info = child:get_field_info()
        print("TCP Flags:", field_info.value)
    end
    ----
    @since 4.7.0
    */

#define WSLUA_OPTARG_TreeItem_children_FIELD_FILTER 2 /* Optional field name(s) to filter by (string or table of strings). */
#define WSLUA_OPTARG_TreeItem_children_RECURSIVE 3    /* Optional boolean to enable recursive (depth-first) iteration. Default is false. */

    /* Retrieve and validate the TreeItem */
    TreeItem ti = checkTreeItem(L, 1);
    if (!ti)
        return 0;

    if (lua_gettop(L) >= WSLUA_OPTARG_TreeItem_children_RECURSIVE &&
        !lua_isnil(L, WSLUA_OPTARG_TreeItem_children_RECURSIVE) &&
        !lua_isboolean(L, WSLUA_OPTARG_TreeItem_children_RECURSIVE)) {
        luaL_error(L, "TreeItem:children() recursive argument must be a boolean");
        return 0;
    }

    if (lua_gettop(L) >= WSLUA_OPTARG_TreeItem_children_FIELD_FILTER &&
        !lua_isnil(L, WSLUA_OPTARG_TreeItem_children_FIELD_FILTER)) {
        int filter_arg = WSLUA_OPTARG_TreeItem_children_FIELD_FILTER;

        if (lua_type(L, filter_arg) != LUA_TSTRING && !lua_istable(L, filter_arg)) {
            luaL_error(L, "TreeItem:children() field filter must be a string or table of strings");
            return 0;
        }

        if (lua_istable(L, filter_arg)) {
            int table_len = (int)lua_rawlen(L, filter_arg);
            for (int i = 0; i < table_len; i++) {
                lua_rawgeti(L, filter_arg, i + 1);
                if (lua_type(L, -1) != LUA_TSTRING) {
                    luaL_error(L, "TreeItem:children() field filter table entries must be strings");
                    return 0;
                }
                lua_pop(L, 1);
            }
        }
    }

    proto_node *first_child = NULL;

    if (ti->tree) {
        /* Get the first child from the tree's linked list */
        first_child = ((proto_node *)ti->tree)->first_child;
    }

    /* Create the iterator state userdata that will be used by the iterator closure */
    /* This userdata will be garbage collected when the iterator is no longer referenced */
    TreeItem_iterator_state *state = (TreeItem_iterator_state *)lua_newuserdata(L, sizeof(TreeItem_iterator_state));

    /* Initialize all state fields to safe defaults */
    state->current_node = first_child;     /* Start with first child */
    state->field_filters = NULL;           /* No filters by default */
    state->num_filters = 0;
    state->recursive = false;              /* Non-recursive by default */
    state->stack = NULL;                   /* Stack only allocated if recursive */
    state->stack_size = 0;
    state->stack_capacity = 0;

    /* Set up garbage collection metatable for the state userdata */
    /* This ensures proper cleanup when iterator is no longer referenced */
    lua_newtable(L);                       /* Create metatable */
    lua_pushcfunction(L, TreeItem_iterator_state_gc);
    lua_setfield(L, -2, "__gc");          /* Set __gc metamethod */
    lua_setmetatable(L, -2);              /* Apply metatable to userdata */

    /* Check for recursive parameter (argument 3) */
    if (lua_gettop(L) >= WSLUA_OPTARG_TreeItem_children_RECURSIVE &&
        !lua_isnil(L, WSLUA_OPTARG_TreeItem_children_RECURSIVE)) {
        /* Convert Lua boolean to C bool */
        state->recursive = lua_toboolean(L, WSLUA_OPTARG_TreeItem_children_RECURSIVE);
    }

    /* Check if filter argument (argument 2) is provided */
    if (lua_gettop(L) >= WSLUA_OPTARG_TreeItem_children_FIELD_FILTER &&
        !lua_isnil(L, WSLUA_OPTARG_TreeItem_children_FIELD_FILTER)) {
        int filter_arg = WSLUA_OPTARG_TreeItem_children_FIELD_FILTER;

        if (lua_type(L, filter_arg) == LUA_TSTRING) {
            /* Single filter string - allocate array of size 1 */
            state->num_filters = 1;
            state->field_filters = (char **)g_malloc(sizeof(char *));
            /* Duplicate the string (Lua string becomes C string copy) */
            state->field_filters[0] = g_strdup(lua_tostring(L, filter_arg));
        } else if (lua_istable(L, filter_arg)) {
            /* Table of filter strings - extract all strings from table */
            int table_len = (int)lua_rawlen(L, filter_arg);
            state->num_filters = table_len;
            state->field_filters = (char **)g_malloc(sizeof(char *) * table_len);

            /* Iterate through Lua table (1-based indexing) */
            for (int i = 0; i < table_len; i++) {
                lua_rawgeti(L, filter_arg, i + 1);  /* Get table[i+1] */
                /* Valid string entry - duplicate it */
                state->field_filters[i] = g_strdup(lua_tostring(L, -1));
                lua_pop(L, 1);  /* Remove the value from stack */
            }
        }
        /* If neither string nor table, filters remain NULL (no filtering) */
    }

    /* Push the iterator function as a closure with state as upvalue */
    /* The state userdata is kept alive as long as the closure exists */
    lua_pushcclosure(L, TreeItem_children_iterator, 1);

    WSLUA_RETURN(1); /* An iterator function for use in Lua for loops. */
}

WSLUA_METHOD TreeItem_get_field_info(lua_State *L) {
    /* Returns the FieldInfo object associated with this tree item.

    Returns a FieldInfo object that provides access to the underlying field
    information including name, abbreviated name, type, value, data offset,
    length, and other protocol field properties.

    This is particularly useful for extracting actual field values and
    metadata from tree items during packet analysis.

    [source,lua]
    ----
    for child in tree:children() do
        local field_info = child:get_field_info()
        if field_info then
            print("Field name: " .. field_info.name)
            print("Field abbrev: " .. field_info.abbrev)
            print("Field type: " .. field_info.type)
            print("Field value: " .. tostring(field_info.value))
            print("Field offset: " .. field_info.offset)
            print("Field len: " .. field_info.len)
        else
            print("No field info (text-only or generated item)")
        end
    end
    ----

    NOTE: Field extractors are still required to ensure fields exist in the dissection tree.
    This method only provides access to field information for tree items that already exist.

    @since 4.7.0
    */

    /* Retrieve and validate the TreeItem */
    TreeItem ti = checkTreeItem(L, 1);
    if (!ti)
        return 0;

    field_info *finfo = NULL;

    /* Get field_info from the proto_item */
    if (ti->item) {
        /* Cast proto_item to proto_node to access finfo member */
        proto_node *node = (proto_node *)ti->item;
        finfo = node->finfo;  /* May be NULL for text-only tree items */
    }

    if (finfo) {
        /* Valid field_info exists - create and push FieldInfo Lua object */
        /* This makes all field properties accessible from Lua */
        push_FieldInfo(L, finfo);
    } else {
        /* No field_info - this is a text-only tree item or generated content */
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The FieldInfo object, or nil if not available. */
}

WSLUA_METAMETHOD TreeItem__tostring(lua_State* L) {
    /* Returns string debug information about the <<lua_class_TreeItem,`TreeItem`>>. */
    TreeItem ti = toTreeItem(L,1);

    if (ti) {
        lua_pushfstring(L,
            "TreeItem: expired=%s, has item=%s, has subtree=%s, they are %sthe same",
            ti->expired ? "true" : "false",
            ti->item ? "true" : "false",
            ti->tree ? "true" : "false",
            (ti->tree == ti->item) ? "" : "not ");
    }
    else {
        lua_pushstring(L, "No TreeItem object!");
    }

    return 1;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int TreeItem__gc(lua_State* L) {
    TreeItem ti = toTreeItem(L,1);
    if (!ti) return 0;
    if (!ti->expired)
        ti->expired = true;
    else
        g_free(ti);
    return 0;
}

WSLUA_ATTRIBUTES TreeItem_attributes[] = {
    WSLUA_ATTRIBUTE_RWREG(TreeItem,generated),
    WSLUA_ATTRIBUTE_RWREG(TreeItem,hidden),
    WSLUA_ATTRIBUTE_RWREG(TreeItem,len),
    WSLUA_ATTRIBUTE_RWREG(TreeItem,text),
    WSLUA_ATTRIBUTE_ROREG(TreeItem,visible),
    { NULL, NULL, NULL }
};

WSLUA_METHODS TreeItem_methods[] = {
    WSLUA_CLASS_FNREG(TreeItem, add_packet_field),
    WSLUA_CLASS_FNREG(TreeItem, add),
    WSLUA_CLASS_FNREG(TreeItem, add_le),
    WSLUA_CLASS_FNREG(TreeItem, set_text),
    WSLUA_CLASS_FNREG(TreeItem, append_text),
    WSLUA_CLASS_FNREG(TreeItem, prepend_text),
    WSLUA_CLASS_FNREG(TreeItem, add_expert_info),
    WSLUA_CLASS_FNREG(TreeItem, add_proto_expert_info),
    WSLUA_CLASS_FNREG(TreeItem, add_tvb_expert_info),
    WSLUA_CLASS_FNREG(TreeItem, set_generated),
    WSLUA_CLASS_FNREG(TreeItem, set_hidden),
    WSLUA_CLASS_FNREG(TreeItem, set_len),
    WSLUA_CLASS_FNREG(TreeItem, referenced),
    WSLUA_CLASS_FNREG(TreeItem, get_child_count),
    WSLUA_CLASS_FNREG(TreeItem, get_parent),
    WSLUA_CLASS_FNREG(TreeItem, get_child),
    WSLUA_CLASS_FNREG(TreeItem, children),
    WSLUA_CLASS_FNREG(TreeItem, get_field_info),
    {NULL, NULL}};

WSLUA_META TreeItem_meta[] = {
    WSLUA_CLASS_MTREG(TreeItem,tostring),
    { NULL, NULL }
};

int TreeItem_register(lua_State *L) {
    int* etts[] = { &wslua_ett };
    wslua_ett = -1; /* Reset to support reload Lua plugins */
    WSLUA_REGISTER_CLASS_WITH_ATTRS(TreeItem);
    if (outstanding_TreeItem != NULL) {
        g_ptr_array_unref(outstanding_TreeItem);
    }
    outstanding_TreeItem = g_ptr_array_new();
    proto_register_subtree_array(etts,1);
    return 0;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
