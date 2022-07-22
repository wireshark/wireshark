/*
 * wslua_byte_array.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 * (c) 2011, Stig Bjorlykke <stig@bjorlykke.org>
 * (c) 2014, Hadriel Kaplan <hadrielk@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wslua.h"

/* WSLUA_CONTINUE_MODULE Tvb */


WSLUA_CLASS_DEFINE(ByteArray,FAIL_ON_NULL("ByteArray"));

WSLUA_CONSTRUCTOR ByteArray_new(lua_State* L) {
    /*
    Creates a new <<lua_class_ByteArray,`ByteArray`>> object.

    Starting in version 1.11.3, if the second argument is a boolean `true`,
    then the first argument is treated as a raw Lua string of bytes to use,
    instead of a hexadecimal string.

    ===== Example

    [source,lua]
    ----
    local empty = ByteArray.new()
    local b1 = ByteArray.new("a1 b2 c3 d4")
    local b2 = ByteArray.new("112233")
    ----
    */
#define WSLUA_OPTARG_ByteArray_new_HEXBYTES 1 /* A string consisting of hexadecimal bytes like "00 B1 A2" or "1a2b3c4d". */
#define WSLUA_OPTARG_ByteArray_new_SEPARATOR 2 /* A string separator between hex bytes/words (default=" "),
                                                  or if the boolean value `true` is used, then the first argument
                                                  is treated as raw binary data */
    GByteArray* ba = g_byte_array_new();
    const gchar* s;
    size_t len = 0;
    const gchar* sep = " ";
    gboolean ishex = TRUE;

    if (lua_gettop(L) >= 1) {
        s = luaL_checklstring(L,WSLUA_OPTARG_ByteArray_new_HEXBYTES,&len);

        if (lua_gettop(L) >= 2) {
            if (lua_type(L,2) == LUA_TBOOLEAN && lua_toboolean(L,2)) {
                ishex = FALSE;
            } else {
                sep = luaL_optstring(L,WSLUA_OPTARG_ByteArray_new_SEPARATOR," ");
            }
        }

        if (ishex) {
            wslua_hex2bin(L, s, (guint)len, sep);   /* this pushes a new string on top of stack */
            s = luaL_checklstring(L, -1, &len);     /* get the new binary string */
            g_byte_array_append(ba,s,(guint)len);   /* copy it into ByteArray */
            lua_pop(L,1);                           /* pop the newly created string */
        } else {
            g_byte_array_append(ba,s,(guint)len);
        }
    }

    pushByteArray(L,ba);

    WSLUA_RETURN(1); /* The new ByteArray object. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int ByteArray__gc(lua_State* L) {
    ByteArray ba = toByteArray(L,1);

    if (!ba) return 0;

    g_byte_array_free(ba,TRUE);
    return 0;
}

WSLUA_METAMETHOD ByteArray__concat(lua_State* L) {
    /* Concatenate two <<lua_class_ByteArray,`ByteArray`>>s. */
#define WSLUA_ARG_ByteArray__concat_FIRST 1 /* First array. */
#define WSLUA_ARG_ByteArray__concat_SECOND 2 /* Second array. */

    ByteArray ba1 = checkByteArray(L,WSLUA_ARG_ByteArray__concat_FIRST);
    ByteArray ba2 = checkByteArray(L,WSLUA_ARG_ByteArray__concat_SECOND);
    ByteArray ba;

    ba = g_byte_array_new();
    g_byte_array_append(ba,ba1->data,ba1->len);
    g_byte_array_append(ba,ba2->data,ba2->len);

    pushByteArray(L,ba);
    WSLUA_RETURN(1); /* The new composite <<lua_class_ByteArray,`ByteArray`>>. */
}

WSLUA_METAMETHOD ByteArray__eq(lua_State* L) {
    /* Compares two ByteArray values.

       @since 1.11.4
     */
#define WSLUA_ARG_ByteArray__eq_FIRST 1 /* First array. */
#define WSLUA_ARG_ByteArray__eq_SECOND 2 /* Second array. */
    ByteArray ba1 = checkByteArray(L,WSLUA_ARG_ByteArray__eq_FIRST);
    ByteArray ba2 = checkByteArray(L,WSLUA_ARG_ByteArray__eq_SECOND);
    gboolean result = FALSE;

    if (ba1->len == ba2->len) {
        if (memcmp(ba1->data, ba2->data, ba1->len) == 0)
            result = TRUE;
    }

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_METHOD ByteArray_prepend(lua_State* L) {
    /* Prepend a <<lua_class_ByteArray,`ByteArray`>> to this <<lua_class_ByteArray,`ByteArray`>>. */
#define WSLUA_ARG_ByteArray_prepend_PREPENDED 2 /* <<lua_class_ByteArray,`ByteArray`>> to be prepended. */
    ByteArray ba = checkByteArray(L,1);
    ByteArray ba2 = checkByteArray(L,WSLUA_ARG_ByteArray_prepend_PREPENDED);

    g_byte_array_prepend(ba,ba2->data,ba2->len);

    return 0;
}

WSLUA_METHOD ByteArray_append(lua_State* L) {
    /* Append a <<lua_class_ByteArray,`ByteArray`>> to this <<lua_class_ByteArray,`ByteArray`>>. */
#define WSLUA_ARG_ByteArray_append_APPENDED 2 /* <<lua_class_ByteArray,`ByteArray`>> to be appended. */
    ByteArray ba = checkByteArray(L,1);
    ByteArray ba2 = checkByteArray(L,WSLUA_ARG_ByteArray_append_APPENDED);

    g_byte_array_append(ba,ba2->data,ba2->len);

    return 0;
}

WSLUA_METHOD ByteArray_set_size(lua_State* L) {
    /* Sets the size of a <<lua_class_ByteArray,`ByteArray`>>, either truncating it or filling it with zeros. */
#define WSLUA_ARG_ByteArray_set_size_SIZE 2 /* New size of the array. */

    ByteArray ba = checkByteArray(L,1);
    int siz = (int)luaL_checkinteger(L,WSLUA_ARG_ByteArray_set_size_SIZE);
    guint8* padding;

    if (siz < 0) {
        WSLUA_ERROR(ByteArray_set_size,"ByteArray size must be non-negative");
        return 0;
    }

    if (ba->len >= (guint)siz) { /* truncate */
        g_byte_array_set_size(ba,siz);
    } else { /* fill */
        padding = (guint8 *)g_malloc0(sizeof(guint8)*(siz - ba->len));
        g_byte_array_append(ba,padding,siz - ba->len);
        g_free(padding);
    }
    return 0;
}

WSLUA_METHOD ByteArray_set_index(lua_State* L) {
    /* Sets the value of an index of a <<lua_class_ByteArray,`ByteArray`>>. */
#define WSLUA_ARG_ByteArray_set_index_INDEX 2 /* The position of the byte to be set. */
#define WSLUA_ARG_ByteArray_set_index_VALUE 3 /* The char value to set [0-255]. */
    ByteArray ba = checkByteArray(L,1);
    int idx = (int)luaL_checkinteger(L,WSLUA_ARG_ByteArray_set_index_INDEX);
    int v = (int)luaL_checkinteger(L,WSLUA_ARG_ByteArray_set_index_VALUE);

    if (idx == 0 && ! g_str_equal(luaL_optstring(L,2,""),"0") ) {
        luaL_argerror(L,2,"bad index");
        return 0;
    }

    if (idx < 0 || (guint)idx >= ba->len) {
            luaL_argerror(L,2,"index out of range");
            return 0;
    }

    if (v < 0 || v > 255) {
        luaL_argerror(L,3,"Byte out of range");
        return 0;
    }

    ba->data[idx] = (guint8)v;

    return 0;
}


WSLUA_METHOD ByteArray_get_index(lua_State* L) {
    /* Get the value of a byte in a <<lua_class_ByteArray,`ByteArray`>>. */
#define WSLUA_ARG_ByteArray_get_index_INDEX 2 /* The position of the byte to get. */
    ByteArray ba = checkByteArray(L,1);
    int idx = (int)luaL_checkinteger(L,WSLUA_ARG_ByteArray_get_index_INDEX);

    if (idx == 0 && ! g_str_equal(luaL_optstring(L,2,""),"0") ) {
        luaL_argerror(L,2,"bad index");
        return 0;
    }

    if (idx < 0 || (guint)idx >= ba->len) {
        luaL_argerror(L,2,"index out of range");
        return 0;
    }
    lua_pushnumber(L,ba->data[idx]);

    WSLUA_RETURN(1); /* The value [0-255] of the byte. */
}

WSLUA_METHOD ByteArray_len(lua_State* L) {
    /* Obtain the length of a <<lua_class_ByteArray,`ByteArray`>>. */
    ByteArray ba = checkByteArray(L,1);

    lua_pushnumber(L,(lua_Number)ba->len);

    WSLUA_RETURN(1); /* The length of the <<lua_class_ByteArray,`ByteArray`>>. */
}

WSLUA_METHOD ByteArray_subset(lua_State* L) {
    /* Obtain a segment of a <<lua_class_ByteArray,`ByteArray`>>, as a new <<lua_class_ByteArray,`ByteArray`>>. */
#define WSLUA_ARG_ByteArray_subset_OFFSET 2 /* The position of the first byte (0=first). */
#define WSLUA_ARG_ByteArray_subset_LENGTH 3 /* The length of the segment. */
    ByteArray ba = checkByteArray(L,1);
    int offset = (int)luaL_checkinteger(L,WSLUA_ARG_ByteArray_subset_OFFSET);
    int len = (int)luaL_checkinteger(L,WSLUA_ARG_ByteArray_subset_LENGTH);
    ByteArray sub;

    if ((offset + len) > (int)ba->len || offset < 0 || len < 1) {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }

    sub = g_byte_array_new();
    g_byte_array_append(sub,ba->data + offset,len);

    pushByteArray(L,sub);

    WSLUA_RETURN(1); /* A <<lua_class_ByteArray,`ByteArray`>> containing the requested segment. */
}

WSLUA_METHOD ByteArray_base64_decode(lua_State* L) {
    /* Obtain a Base64 decoded <<lua_class_ByteArray,`ByteArray`>>.

       @since 1.11.3
     */
    ByteArray ba = checkByteArray(L,1);
    ByteArray ba2;
    gchar *data;
    gsize len = ba->len;

    if ((len % 4) != 0) {
        len += 4 - (len % 4);
    }

    ba2 = g_byte_array_new();
    if (ba->len > 1) {
        data = (gchar*)g_malloc(len + 1);
        memcpy(data, ba->data, ba->len);
        if (len > ba->len) {
            memcpy(data + ba->len, "====", len - ba->len);
        }
        data[len] = '\0';

        g_base64_decode_inplace(data, &len);
        g_byte_array_append(ba2, data, (int)len);
        g_free(data);
    }

    pushByteArray(L,ba2);
    WSLUA_RETURN(1); /* The created <<lua_class_ByteArray,`ByteArray`>>. */
}

WSLUA_METHOD ByteArray_raw(lua_State* L) {
    /* Obtain a Lua string of the binary bytes in a <<lua_class_ByteArray,`ByteArray`>>.

       @since 1.11.3
     */
#define WSLUA_OPTARG_ByteArray_raw_OFFSET 2 /* The position of the first byte (default=0/first). */
#define WSLUA_OPTARG_ByteArray_raw_LENGTH 3 /* The length of the segment to get (default=all). */
    ByteArray ba = checkByteArray(L,1);
    guint offset = (guint) luaL_optinteger(L,WSLUA_OPTARG_ByteArray_raw_OFFSET,0);
    int len;

    if (!ba) return 0;
    if (offset > ba->len) {
        WSLUA_OPTARG_ERROR(ByteArray_raw,OFFSET,"offset beyond end of byte array");
        return 0;
    }

    len = (int) luaL_optinteger(L,WSLUA_OPTARG_ByteArray_raw_LENGTH, ba->len - offset);
    if ((len < 0) || ((guint)len > (ba->len - offset)))
        len = ba->len - offset;

    lua_pushlstring(L, &(ba->data[offset]), len);

    WSLUA_RETURN(1); /* A Lua string of the binary bytes in the ByteArray. */
}

WSLUA_METHOD ByteArray_tohex(lua_State* L) {
    /* Obtain a Lua string of the bytes in a <<lua_class_ByteArray,`ByteArray`>> as hex-ascii, with given separator

       @since 1.11.3
     */
#define WSLUA_OPTARG_ByteArray_tohex_LOWERCASE 2 /* True to use lower-case hex characters (default=false). */
#define WSLUA_OPTARG_ByteArray_tohex_SEPARATOR 3 /* A string separator to insert between hex bytes (default=nil). */
    ByteArray ba = checkByteArray(L,1);
    gboolean lowercase = FALSE;
    const gchar* sep = NULL;

    if (!ba) return 0;

    lowercase = wslua_optbool(L,WSLUA_OPTARG_ByteArray_tohex_LOWERCASE,FALSE);
    sep = luaL_optstring(L,WSLUA_OPTARG_ByteArray_tohex_SEPARATOR,NULL);

    wslua_bin2hex(L, ba->data, ba->len, lowercase, sep);

    WSLUA_RETURN(1); /* A hex-ascii string representation of the <<lua_class_ByteArray,`ByteArray`>>. */
}

WSLUA_METAMETHOD ByteArray__tostring(lua_State* L) {
    /* Obtain a Lua string containing the bytes in a <<lua_class_ByteArray,`ByteArray`>> so that it can be used in
       display filters (e.g. "01FE456789AB"). */
    ByteArray ba = checkByteArray(L,1);

    if (!ba) return 0;

    wslua_bin2hex(L, ba->data, ba->len, FALSE, NULL);

    WSLUA_RETURN(1); /* A hex-ascii string representation of the <<lua_class_ByteArray,`ByteArray`>>. */
}

WSLUA_METHOD ByteArray_tvb (lua_State *L) {
    /*
    Creates a new <<lua_class_Tvb,`Tvb`>> from a <<lua_class_ByteArray,`ByteArray`>>.
    The <<lua_class_Tvb,`Tvb`>> will be added to the current frame.

    ===== Example

    [source,lua]
    ----
    function proto_foo.dissector(buf, pinfo, tree)
            -- Create a new tab named "My Tvb" and add some data to it
            local b = ByteArray.new("11223344")
            local tvb = ByteArray.tvb(b, "My Tvb")

            -- Create a tree item that, when clicked, automatically shows the tab we just created
            tree:add( tvb(1,2), "Foo" )
    end
    ----
    */
#define WSLUA_ARG_ByteArray_tvb_NAME 2 /* The name to be given to the new data source. */
    ByteArray ba = checkByteArray(L,1);
    const gchar* name = luaL_optstring(L,WSLUA_ARG_ByteArray_tvb_NAME,"Unnamed") ;
    guint8* data;
    Tvb tvb;

    if (!lua_tvb) {
        luaL_error(L,"Tvbs can only be created and used in dissectors");
        return 0;
    }

    data = (guint8 *)g_memdup2(ba->data, ba->len);

    tvb = (Tvb)g_malloc(sizeof(struct _wslua_tvb));
    tvb->ws_tvb = tvb_new_child_real_data(lua_tvb, data, ba->len,ba->len);
    tvb->expired = FALSE;
    tvb->need_free = FALSE;
    tvb_set_free_cb(tvb->ws_tvb, g_free);

    add_new_data_source(lua_pinfo, tvb->ws_tvb, name);
    push_wsluaTvb(L,tvb);
    WSLUA_RETURN(1); /* The created <<lua_class_Tvb,`Tvb`>>. */
}


WSLUA_METHODS ByteArray_methods[] = {
    WSLUA_CLASS_FNREG(ByteArray,new),
    WSLUA_CLASS_FNREG(ByteArray,len),
    WSLUA_CLASS_FNREG(ByteArray,prepend),
    WSLUA_CLASS_FNREG(ByteArray,append),
    WSLUA_CLASS_FNREG(ByteArray,subset),
    WSLUA_CLASS_FNREG(ByteArray,set_size),
    WSLUA_CLASS_FNREG(ByteArray,tvb),
    WSLUA_CLASS_FNREG(ByteArray,base64_decode),
    WSLUA_CLASS_FNREG(ByteArray,get_index),
    WSLUA_CLASS_FNREG(ByteArray,set_index),
    WSLUA_CLASS_FNREG(ByteArray,tohex),
    WSLUA_CLASS_FNREG(ByteArray,raw),
    { NULL, NULL }
};

WSLUA_META ByteArray_meta[] = {
    WSLUA_CLASS_MTREG(ByteArray,tostring),
    WSLUA_CLASS_MTREG(ByteArray,concat),
    WSLUA_CLASS_MTREG(ByteArray,eq),
    {"__call",ByteArray_subset},
    { NULL, NULL }
};

int ByteArray_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(ByteArray);
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
