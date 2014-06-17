/*
 * wslua_tvb.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 * (c) 2009, Stig Bjorlykke <stig@bjorlykke.org>
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

#include <epan/wmem/wmem.h>

/* WSLUA_MODULE Tvb Functions for handling packet data */

#include "wslua.h"
#include "wsutil/base64.h"

WSLUA_CLASS_DEFINE(ByteArray,FAIL_ON_NULL("ByteArray"),NOP);

WSLUA_CONSTRUCTOR ByteArray_new(lua_State* L) { /* Creates a `ByteArray` object. */
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

        if (!s) {
            WSLUA_OPTARG_ERROR(ByteArray_new,HEXBYTES,"must be a string");
            return 0;
        }

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
	/* Concatenate two `ByteArrays`. */
#define WSLUA_ARG_ByteArray__cat_FIRST 1 /* First array. */
#define WSLUA_ARG_ByteArray__cat_SECOND 2 /* Second array. */

    ByteArray ba1 = checkByteArray(L,WSLUA_ARG_ByteArray__cat_FIRST);
    ByteArray ba2 = checkByteArray(L,WSLUA_ARG_ByteArray__cat_SECOND);
    ByteArray ba;

    ba = g_byte_array_new();
    g_byte_array_append(ba,ba1->data,ba1->len);
    g_byte_array_append(ba,ba2->data,ba2->len);

    pushByteArray(L,ba);
    WSLUA_RETURN(1); /* The new composite `ByteArray`. */
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
	/* Prepend a `ByteArray` to this `ByteArray`. */
#define WSLUA_ARG_ByteArray_prepend_PREPENDED 2 /* `ByteArray` to be prepended. */
    ByteArray ba = checkByteArray(L,1);
    ByteArray ba2 = checkByteArray(L,WSLUA_ARG_ByteArray_prepend_PREPENDED);

    g_byte_array_prepend(ba,ba2->data,ba2->len);

    return 0;
}

WSLUA_METHOD ByteArray_append(lua_State* L) {
	/* Append a `ByteArray` to this `ByteArray`. */
#define WSLUA_ARG_ByteArray_append_APPENDED 2 /* `ByteArray` to be appended. */
    ByteArray ba = checkByteArray(L,1);
    ByteArray ba2 = checkByteArray(L,WSLUA_ARG_ByteArray_append_APPENDED);

    g_byte_array_append(ba,ba2->data,ba2->len);

    return 0;
}

WSLUA_METHOD ByteArray_set_size(lua_State* L) {
	/* Sets the size of a `ByteArray`, either truncating it or filling it with zeros. */
#define WSLUA_ARG_ByteArray_set_size_SIZE 2 /* New size of the array. */

    ByteArray ba = checkByteArray(L,1);
    int siz = luaL_checkint(L,WSLUA_ARG_ByteArray_set_size_SIZE);
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
	/* Sets the value of an index of a `ByteArray`. */
#define WSLUA_ARG_ByteArray_set_index_INDEX 2 /* The position of the byte to be set. */
#define WSLUA_ARG_ByteArray_set_index_VALUE 3 /* The char value to set [0-255]. */
    ByteArray ba = checkByteArray(L,1);
    int idx = luaL_checkint(L,WSLUA_ARG_ByteArray_set_index_INDEX);
    int v = luaL_checkint(L,WSLUA_ARG_ByteArray_set_index_VALUE);

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
	/* Get the value of a byte in a `ByteArray`. */
#define WSLUA_ARG_ByteArray_get_index_INDEX 2 /* The position of the byte to get. */
    ByteArray ba = checkByteArray(L,1);
    int idx = luaL_checkint(L,WSLUA_ARG_ByteArray_get_index_INDEX);

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
	/* Obtain the length of a `ByteArray`. */
    ByteArray ba = checkByteArray(L,1);

    lua_pushnumber(L,(lua_Number)ba->len);

    WSLUA_RETURN(1); /* The length of the `ByteArray`. */
}

WSLUA_METHOD ByteArray_subset(lua_State* L) {
	/* Obtain a segment of a `ByteArray`, as a new `ByteArray`. */
#define WSLUA_ARG_ByteArray_set_index_OFFSET 2 /* The position of the first byte (0=first). */
#define WSLUA_ARG_ByteArray_set_index_LENGTH 3 /* The length of the segment. */
    ByteArray ba = checkByteArray(L,1);
    int offset = luaL_checkint(L,WSLUA_ARG_ByteArray_set_index_OFFSET);
    int len = luaL_checkint(L,WSLUA_ARG_ByteArray_set_index_LENGTH);
    ByteArray sub;

    if ((offset + len) > (int)ba->len || offset < 0 || len < 1) {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }

    sub = g_byte_array_new();
    g_byte_array_append(sub,ba->data + offset,len);

    pushByteArray(L,sub);

    WSLUA_RETURN(1); /* A `ByteArray` containing the requested segment. */
}

WSLUA_METHOD ByteArray_base64_decode(lua_State* L) {
	/* Obtain a base64 decoded `ByteArray`. */
    ByteArray ba = checkByteArray(L,1);
    ByteArray ba2;
    gchar *data;
    size_t len;

    ba2 = g_byte_array_new();
    data = (gchar*)g_malloc (ba->len + 1);
    memcpy(data, ba->data, ba->len);
    data[ba->len] = '\0';

    len = ws_base64_decode_inplace(data);
    g_byte_array_append(ba2,data,(int)len);
    g_free(data);

    pushByteArray(L,ba2);
    WSLUA_RETURN(1); /* The created `ByteArray`. */
}

WSLUA_METHOD ByteArray_raw(lua_State* L) {
    /* Obtain a Lua string of the binary bytes in a `ByteArray`. */
#define WSLUA_OPTARG_ByteArray_raw_OFFSET 2 /* The position of the first byte (default=0/first). */
#define WSLUA_OPTARG_ByteArray_raw_LENGTH 3 /* The length of the segment to get (default=all). */
    ByteArray ba = checkByteArray(L,1);
    guint offset = (guint) luaL_optint(L,WSLUA_OPTARG_ByteArray_raw_OFFSET,0);
    int len;

    if (!ba) return 0;
    if (offset > ba->len) {
        WSLUA_OPTARG_ERROR(ByteArray_raw,OFFSET,"offset beyond end of byte array");
        return 0;
    }

    len = luaL_optint(L,WSLUA_OPTARG_ByteArray_raw_LENGTH, ba->len - offset);
    if ((len < 0) || ((guint)len > (ba->len - offset)))
        len = ba->len - offset;

    lua_pushlstring(L, &(ba->data[offset]), len);

    WSLUA_RETURN(1); /* A Lua string of the binary bytes in the ByteArray. */
}

WSLUA_METHOD ByteArray_tohex(lua_State* L) {
    /* Obtain a Lua string of the bytes in a `ByteArray` as hex-ascii, with given separator */
#define WSLUA_OPTARG_ByteArray_tohex_LOWERCASE 2 /* True to use lower-case hex characters (default=false). */
#define WSLUA_OPTARG_ByteArray_tohex_SEPARATOR 3 /* A string separator to insert between hex bytes (default=nil). */
    ByteArray ba = checkByteArray(L,1);
    gboolean lowercase = FALSE;
    const gchar* sep = NULL;

    if (!ba) return 0;

    lowercase = wslua_optbool(L,WSLUA_OPTARG_ByteArray_tohex_LOWERCASE,FALSE);
    sep = luaL_optstring(L,WSLUA_OPTARG_ByteArray_tohex_SEPARATOR,NULL);

    wslua_bin2hex(L, ba->data, ba->len, lowercase, sep);

    WSLUA_RETURN(1); /* A hex-ascii string representation of the `ByteArray`. */
}

WSLUA_METAMETHOD ByteArray__tostring(lua_State* L) {
	/* Obtain a Lua string containing the bytes in a `ByteArray` so that it can be used in
       display filters (e.g. "01FE456789AB"). */
    ByteArray ba = checkByteArray(L,1);

    if (!ba) return 0;

    wslua_bin2hex(L, ba->data, ba->len, FALSE, NULL);

    WSLUA_RETURN(1); /* A hex-ascii string representation of the `ByteArray`. */
}

static int ByteArray_tvb (lua_State *L);

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
 * Tvb & TvbRange
 *
 * a Tvb represents a tvbuff_t in Lua.
 * a TvbRange represents a range in a tvb (tvb,offset,length) its main purpose is to do bounds checking,
 *            It helps, too, simplifying argument passing to Tree. In wireshark terms this is worthless nothing
 *            not already done by the TVB itself. In lua's terms it's necessary to avoid abusing TRY{}CATCH(){}
 *            via preemptive bounds checking.
 *
 * These lua objects refer to structures in wireshark that are freed independently from Lua's garbage collector.
 * To avoid using pointers from Lua to Wireshark structures that are already freed, we maintain a list of the
 * pointers each with a marker that tracks its expiry.
 *
 * All pointers are marked as expired when the dissection of the current frame is finished or when the garbage
 * collector tries to free the object referring to the pointer, whichever comes first.
 *
 * All allocated memory chunks used for tracking the pointers' state are freed after marking the pointer as expired
 * by the garbage collector or by the end of the dissection of the current frame, whichever comes second.
 *
 * We check the expiry state of the pointer before each access.
 *
 */

WSLUA_CLASS_DEFINE(Tvb,FAIL_ON_NULL_OR_EXPIRED("Tvb"),NOP);
/* A `Tvb` represents the packet's buffer. It is passed as an argument to listeners and dissectors,
   and can be used to extract information (via `TvbRange`) from the packet's data.

   To create a `TvbRange` the `Tvb` must be called with offset and length as optional arguments;
   the offset defaults to 0 and the length to `tvb:len()`.

   @warning `Tvb`s are usable only by the current listener or dissector call and are destroyed
   as soon as the listener/dissector returns, so references to them are unusable once the function
   has returned.
*/

static GPtrArray* outstanding_Tvb = NULL;
static GPtrArray* outstanding_TvbRange = NULL;

#define PUSH_TVB(L,t) {g_ptr_array_add(outstanding_Tvb,t);pushTvb(L,t);}
#define PUSH_TVBRANGE(L,t) {g_ptr_array_add(outstanding_TvbRange,t);pushTvbRange(L,t);}

static void free_Tvb(Tvb tvb) {
    if (!tvb) return;

    if (!tvb->expired) {
        tvb->expired = TRUE;
    } else {
        if (tvb->need_free)
            tvb_free(tvb->ws_tvb);
        g_free(tvb);
    }
}

void clear_outstanding_Tvb(void) {
    while (outstanding_Tvb->len) {
        Tvb tvb = (Tvb)g_ptr_array_remove_index_fast(outstanding_Tvb,0);
        free_Tvb(tvb);
    }
}

static void free_TvbRange(TvbRange tvbr) {
    if (!(tvbr && tvbr->tvb)) return;

    if (!tvbr->tvb->expired) {
        tvbr->tvb->expired = TRUE;
    } else {
        free_Tvb(tvbr->tvb);
        g_free(tvbr);
    }
}

void clear_outstanding_TvbRange(void) {
    while (outstanding_TvbRange->len) {
        TvbRange tvbr = (TvbRange)g_ptr_array_remove_index_fast(outstanding_TvbRange,0);
        free_TvbRange(tvbr);
    }
}


Tvb* push_Tvb(lua_State* L, tvbuff_t* ws_tvb) {
    Tvb tvb = (Tvb)g_malloc(sizeof(struct _wslua_tvb));
    tvb->ws_tvb = ws_tvb;
    tvb->expired = FALSE;
    tvb->need_free = FALSE;
    g_ptr_array_add(outstanding_Tvb,tvb);
    return pushTvb(L,tvb);
}



/*
 * ByteArray_tvb(name)
 */
WSLUA_CONSTRUCTOR ByteArray_tvb (lua_State *L) {
	/* Creates a new `Tvb` from a `ByteArray` (it gets added to the current frame too). */
#define WSLUA_ARG_ByteArray_tvb_NAME 2 /* The name to be given to the new data-source. */
    ByteArray ba = checkByteArray(L,1);
    const gchar* name = luaL_optstring(L,WSLUA_ARG_ByteArray_tvb_NAME,"Unnamed") ;
    guint8* data;
    Tvb tvb;

    if (!lua_tvb) {
        luaL_error(L,"Tvbs can only be created and used in dissectors");
        return 0;
    }

    data = (guint8 *)g_memdup(ba->data, ba->len);

    tvb = (Tvb)g_malloc(sizeof(struct _wslua_tvb));
    tvb->ws_tvb = tvb_new_real_data(data, ba->len,ba->len);
    tvb->expired = FALSE;
    tvb->need_free = TRUE;
    tvb_set_free_cb(tvb->ws_tvb, g_free);

    add_new_data_source(lua_pinfo, tvb->ws_tvb, name);
    PUSH_TVB(L,tvb);
    WSLUA_RETURN(1); /* The created `Tvb`. */
}

WSLUA_CONSTRUCTOR TvbRange_tvb (lua_State *L) {
	/* Creates a (sub)`Tvb` from a `TvbRange`. */
#define WSLUA_ARG_Tvb_new_subset_RANGE 1 /* The `TvbRange` from which to create the new `Tvb`. */

    TvbRange tvbr = checkTvbRange(L,WSLUA_ARG_Tvb_new_subset_RANGE);
    Tvb tvb;

    if (! (tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvb_offset_exists(tvbr->tvb->ws_tvb,  tvbr->offset + tvbr->len -1 )) {
        tvb = (Tvb)g_malloc(sizeof(struct _wslua_tvb));
        tvb->expired = FALSE;
        tvb->need_free = FALSE;
        tvb->ws_tvb = tvb_new_subset(tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len, tvbr->len);
        PUSH_TVB(L, tvb);
        return 1;
    } else {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }
}

WSLUA_METAMETHOD Tvb__tostring(lua_State* L) {
	/* Convert the bytes of a `Tvb` into a string, to be used for debugging purposes as '...'
       will be appended in case the string is too long. */
    Tvb tvb = checkTvb(L,1);
    int len;
    gchar* str;

    len = tvb_length(tvb->ws_tvb);
    str = wmem_strdup_printf(NULL, "TVB(%i) : %s",len,tvb_bytes_to_ep_str(tvb->ws_tvb,0,len));
    lua_pushstring(L,str);
    wmem_free(NULL, str);
    WSLUA_RETURN(1); /* The string. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Tvb__gc(lua_State* L) {
    Tvb tvb = toTvb(L,1);

    free_Tvb(tvb);

    return 0;

}

WSLUA_METHOD Tvb_reported_len(lua_State* L) {
	/* Obtain the reported (not captured) length of a `Tvb`. */
    Tvb tvb = checkTvb(L,1);

    lua_pushnumber(L,tvb_reported_length(tvb->ws_tvb));
    WSLUA_RETURN(1); /* The reported length of the `Tvb`. */
}

WSLUA_METHOD Tvb_len(lua_State* L) {
	/* Obtain the actual (captured) length of a `Tvb`. */
    Tvb tvb = checkTvb(L,1);

    lua_pushnumber(L,tvb_length(tvb->ws_tvb));
    WSLUA_RETURN(1); /* The captured length of the `Tvb`. */
}

WSLUA_METHOD Tvb_reported_length_remaining(lua_State* L) {
	/* Obtain the reported (not captured) length of packet data to end of a `Tvb` or -1 if the
       offset is beyond the end of the `Tvb`. */
#define Tvb_reported_length_remaining_OFFSET 2 /* offset */
    Tvb tvb = checkTvb(L,1);
    int offset = luaL_optint(L, Tvb_reported_length_remaining_OFFSET, 0);

    lua_pushnumber(L,tvb_reported_length_remaining(tvb->ws_tvb, offset));
    WSLUA_RETURN(1); /* The captured length of the `Tvb`. */
}

WSLUA_METHOD Tvb_offset(lua_State* L) {
	/* Returns the raw offset (from the beginning of the source `Tvb`) of a sub `Tvb`. */
    Tvb tvb = checkTvb(L,1);

    lua_pushnumber(L,tvb_raw_offset(tvb->ws_tvb));
    WSLUA_RETURN(1); /* The raw offset of the `Tvb`. */
}


#if USED_FOR_DOC_PURPOSES
WSLUA_METAMETHOD Tvb__call(lua_State* L) {
	/* Equivalent to tvb:range(...) */
	return 0;
}
#endif

WSLUA_CLASS_DEFINE(TvbRange,FAIL_ON_NULL("TvbRange"),NOP);
/*
  A `TvbRange` represents a usable range of a `Tvb` and is used to extract data from the `Tvb` that generated it.

  `TvbRange`s are created by calling a `Tvb` (e.g. 'tvb(offset,length)'). If the `TvbRange` span is outside the
  `Tvb`'s range the creation will cause a runtime error.
 */

gboolean push_TvbRange(lua_State* L, tvbuff_t* ws_tvb, int offset, int len) {
    TvbRange tvbr;

    if (!ws_tvb) {
        luaL_error(L,"expired tvb");
        return FALSE;
    }

    if (len == -1) {
        len = tvb_length_remaining(ws_tvb,offset);
        if (len < 0) {
            luaL_error(L,"out of bounds");
            return FALSE;
        }
    } else if ( (guint)(len + offset) > tvb_length(ws_tvb)) {
        luaL_error(L,"Range is out of bounds");
        return FALSE;
    }

    tvbr = (TvbRange)g_malloc(sizeof(struct _wslua_tvbrange));
    tvbr->tvb = (Tvb)g_malloc(sizeof(struct _wslua_tvb));
    tvbr->tvb->ws_tvb = ws_tvb;
    tvbr->tvb->expired = FALSE;
    tvbr->tvb->need_free = FALSE;
    tvbr->offset = offset;
    tvbr->len = len;

    PUSH_TVBRANGE(L,tvbr);

    return TRUE;
}


WSLUA_METHOD Tvb_range(lua_State* L) {
	/* Creates a `TvbRange` from this `Tvb`. */
#define WSLUA_OPTARG_Tvb_range_OFFSET 2 /* The offset (in octets) from the beginning of the `Tvb`. Defaults to 0. */
#define WSLUA_OPTARG_Tvb_range_LENGTH 3 /* The length (in octets) of the range. Defaults to until the end of the `Tvb`. */

    Tvb tvb = checkTvb(L,1);
    int offset = luaL_optint(L,WSLUA_OPTARG_Tvb_range_OFFSET,0);
    int len = luaL_optint(L,WSLUA_OPTARG_Tvb_range_LENGTH,-1);

    if (push_TvbRange(L,tvb->ws_tvb,offset,len)) {
        WSLUA_RETURN(1); /* The TvbRange */
    }

    return 0;
}

WSLUA_METHOD Tvb_raw(lua_State* L) {
    /* Obtain a Lua string of the binary bytes in a `Tvb`. */
#define WSLUA_OPTARG_Tvb_raw_OFFSET 2 /* The position of the first byte (default=0/first). */
#define WSLUA_OPTARG_Tvb_raw_LENGTH 3 /* The length of the segment to get (default=all). */
    Tvb tvb = checkTvb(L,1);
    int offset = luaL_optint(L,WSLUA_OPTARG_Tvb_raw_OFFSET,0);
    int len = luaL_optint(L,WSLUA_OPTARG_Tvb_raw_LENGTH,-1);

    if (!tvb) return 0;
    if (tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if ((guint)offset > tvb_length(tvb->ws_tvb)) {
        WSLUA_OPTARG_ERROR(Tvb_raw,OFFSET,"offset beyond end of Tvb");
        return 0;
    }

    if (len == -1) {
        len = tvb_length_remaining(tvb->ws_tvb,offset);
        if (len < 0) {
            luaL_error(L,"out of bounds");
            return FALSE;
        }
    } else if ( (guint)(len + offset) > tvb_length(tvb->ws_tvb)) {
        luaL_error(L,"Range is out of bounds");
        return FALSE;
    }

    lua_pushlstring(L, tvb_get_ptr(tvb->ws_tvb, offset, len), len);

    WSLUA_RETURN(1); /* A Lua string of the binary bytes in the `Tvb`. */
}

WSLUA_METHODS Tvb_methods[] = {
    WSLUA_CLASS_FNREG(Tvb,range),
    WSLUA_CLASS_FNREG(Tvb,len),
    WSLUA_CLASS_FNREG(Tvb,offset),
    WSLUA_CLASS_FNREG(Tvb,reported_len),
    WSLUA_CLASS_FNREG(Tvb,reported_length_remaining),
    WSLUA_CLASS_FNREG(Tvb,raw),
    { NULL, NULL }
};

WSLUA_META Tvb_meta[] = {
    WSLUA_CLASS_MTREG(Tvb,tostring),
    {"__call", Tvb_range},
    { NULL, NULL }
};

int Tvb_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(Tvb);
    return 0;
}


/*
 *  get a Blefuscuoan unsigned integer from a tvb
 */
WSLUA_METHOD TvbRange_uint(lua_State* L) {
	/* Get a Big Endian (network order) unsigned integer from a `TvbRange`.
       The range must be 1, 2, 3 or 4 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            lua_pushnumber(L,tvb_get_guint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushnumber(L,tvb_get_ntohs(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushnumber(L,tvb_get_ntoh24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushnumber(L,tvb_get_ntohl(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The unsigned integer value. */
            /*
             * XXX:
             *    lua uses double so we have 52 bits to play with
             *    we are missing 5 and 6 byte integers within lua's range
             *    and 64 bit integers are not supported (there's a lib for
             *    lua that does).
             */
        default:
            luaL_error(L,"TvbRange:uint() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Lilliputian unsigned integer from a tvb
 */
WSLUA_METHOD TvbRange_le_uint(lua_State* L) {
	/* Get a Little Endian unsigned integer from a `TvbRange`.
       The range must be 1, 2, 3 or 4 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            /* XXX unsigned anyway */
            lua_pushnumber(L,(lua_Number)(guint)tvb_get_guint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushnumber(L,tvb_get_letohs(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushnumber(L,tvb_get_letoh24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushnumber(L,tvb_get_letohl(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The unsigned integer value */
        default:
            luaL_error(L,"TvbRange:le_uint() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Blefuscuoan unsigned 64 bit integer from a tvb
 */
WSLUA_METHOD TvbRange_uint64(lua_State* L) {
	/* Get a Big Endian (network order) unsigned 64 bit integer from a `TvbRange`, as a `UInt64` object.
       The range must be 1-8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8: {
            pushUInt64(L,tvb_get_ntoh64(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The `UInt64` object. */
        }
        default:
            luaL_error(L,"TvbRange:uint64() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Lilliputian unsigned 64 bit integer from a tvb
 */
WSLUA_METHOD TvbRange_le_uint64(lua_State* L) {
	/* Get a Little Endian unsigned 64 bit integer from a `TvbRange`, as a `UInt64` object.
       The range must be 1-8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8: {
            pushUInt64(L,tvb_get_letoh64(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The `UInt64` object. */
        }
        default:
            luaL_error(L,"TvbRange:le_uint64() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Blefuscuoan signed integer from a tvb
 */
WSLUA_METHOD TvbRange_int(lua_State* L) {
	/* Get a Big Endian (network order) signed integer from a `TvbRange`.
       The range must be 1, 2 or 4 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            lua_pushnumber(L,(gchar)tvb_get_guint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushnumber(L,(gshort)tvb_get_ntohs(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushnumber(L,(gint)tvb_get_ntohl(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The signed integer value */
            /*
             * XXX:
             *    lua uses double so we have 52 bits to play with
             *    we are missing 5 and 6 byte integers within lua's range
             *    and 64 bit integers are not supported (there's a lib for
             *    lua that does).
             */
        default:
            luaL_error(L,"TvbRange:int() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Lilliputian signed integer from a tvb
 */
WSLUA_METHOD TvbRange_le_int(lua_State* L) {
	/* Get a Little Endian signed integer from a `TvbRange`.
       The range must be 1, 2 or 4 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            lua_pushnumber(L,(gchar)tvb_get_guint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushnumber(L,(gshort)tvb_get_letohs(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushnumber(L,(gint)tvb_get_letohl(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The signed integer value. */
        default:
            luaL_error(L,"TvbRange:le_int() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Blefuscuoan signed 64 bit integer from a tvb
 */
WSLUA_METHOD TvbRange_int64(lua_State* L) {
	/* Get a Big Endian (network order) signed 64 bit integer from a `TvbRange`, as an `Int64` object.
       The range must be 1-8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8: {
            pushInt64(L,(gint64)tvb_get_ntoh64(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The `Int64` object. */
        }
        default:
            luaL_error(L,"TvbRange:int64() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Lilliputian signed 64 bit integer from a tvb
 */
WSLUA_METHOD TvbRange_le_int64(lua_State* L) {
	/* Get a Little Endian signed 64 bit integer from a `TvbRange`, as an `Int64` object.
       The range must be 1-8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8: {
            pushInt64(L,(gint64)tvb_get_letoh64(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The `Int64` object. */
        }
        default:
            luaL_error(L,"TvbRange:le_int64() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Blefuscuoan float
 */
WSLUA_METHOD TvbRange_float(lua_State* L) {
	/* Get a Big Endian (network order) floating point number from a `TvbRange`.
       The range must be 4 or 8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 4:
            lua_pushnumber(L,(double)tvb_get_ntohieee_float(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 8:
            lua_pushnumber(L,tvb_get_ntohieee_double(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The floating point value. */
        default:
            luaL_error(L,"TvbRange:float() does not handle %d byte floating numbers",tvbr->len);
            return 0;
    }
}

/*
 * get a Lilliputian float
 */
WSLUA_METHOD TvbRange_le_float(lua_State* L) {
	/* Get a Little Endian floating point number from a `TvbRange`.
       The range must be 4 or 8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;

    switch (tvbr->len) {
        case 4:
            lua_pushnumber(L,tvb_get_letohieee_float(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 8:
            lua_pushnumber(L,tvb_get_letohieee_double(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The floating point value. */
        default:
            luaL_error(L,"TvbRange:le_float() does not handle %d byte floating numbers",tvbr->len);
            return 0;
    }
}

WSLUA_METHOD TvbRange_ipv4(lua_State* L) {
	/* Get an IPv4 Address from a `TvbRange`, as an `Address` object. */
    TvbRange tvbr = checkTvbRange(L,1);
    Address addr;
    guint32* ip_addr;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 4) {
        WSLUA_ERROR(TvbRange_ipv4,"The range must be 4 octets long");
        return 0;
    }

    addr = (address *)g_malloc(sizeof(address));

    ip_addr = (guint32 *)g_malloc(sizeof(guint32));
    *ip_addr = tvb_get_ipv4(tvbr->tvb->ws_tvb,tvbr->offset);

    SET_ADDRESS(addr, AT_IPv4, 4, ip_addr);
    pushAddress(L,addr);

    WSLUA_RETURN(1); /* The IPv4 `Address` object. */
}

WSLUA_METHOD TvbRange_le_ipv4(lua_State* L) {
	/* Get an Little Endian IPv4 Address from a `TvbRange`, as an `Address` object. */
    TvbRange tvbr = checkTvbRange(L,1);
    Address addr;
    guint32* ip_addr;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 4) {
        WSLUA_ERROR(TvbRange_ipv4,"The range must be 4 octets long");
        return 0;
    }

    addr = (address *)g_malloc(sizeof(address));

    ip_addr = (guint32 *)g_malloc(sizeof(guint32));
    *ip_addr = tvb_get_ipv4(tvbr->tvb->ws_tvb,tvbr->offset);
    *((guint32 *)ip_addr) = GUINT32_SWAP_LE_BE(*((guint32 *)ip_addr));

    SET_ADDRESS(addr, AT_IPv4, 4, ip_addr);
    pushAddress(L,addr);

    WSLUA_RETURN(1); /* The IPv4 `Address` object. */
}

WSLUA_METHOD TvbRange_ether(lua_State* L) {
	/* Get an Ethernet Address from a `TvbRange`, as an `Address` object. */
    TvbRange tvbr = checkTvbRange(L,1);
    Address addr;
    guint8* buff;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 6) {
        WSLUA_ERROR(TvbRange_ether,"The range must be 6 bytes long");
        return 0;
    }

    addr = g_new(address,1);

    buff = (guint8 *)tvb_memdup(NULL,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len);

    SET_ADDRESS(addr, AT_ETHER, 6, buff);
    pushAddress(L,addr);

    WSLUA_RETURN(1); /* The Ethernet `Address` object. */
}

WSLUA_METHOD TvbRange_nstime(lua_State* L) {
	/* Obtain a time_t structure from a `TvbRange`, as an `NSTime` object. */
#define WSLUA_OPTARG_TvbRange_nstime_ENCODING 2 /* An optional ENC_* encoding value to use */
    TvbRange tvbr = checkTvbRange(L,1);
    NSTime nstime;
    const guint encoding = luaL_optint(L, WSLUA_OPTARG_TvbRange_nstime_ENCODING, 0);

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    nstime = g_new(nstime_t,1);

    if (encoding == 0) {
        if (tvbr->len == 4) {
          nstime->secs = tvb_get_ntohl(tvbr->tvb->ws_tvb, tvbr->offset);
          nstime->nsecs = 0;
        } else if (tvbr->len == 8) {
          nstime->secs = tvb_get_ntohl(tvbr->tvb->ws_tvb, tvbr->offset);
          nstime->nsecs = tvb_get_ntohl(tvbr->tvb->ws_tvb, tvbr->offset + 4);
        } else {
          g_free(nstime);
          WSLUA_ERROR(TvbRange_nstime,"The range must be 4 or 8 bytes long");
          return 0;
        }
        pushNSTime(L, nstime);
        lua_pushinteger(L, tvbr->len);
    }
    else if (encoding & ~ENC_STR_TIME_MASK) {
        WSLUA_OPTARG_ERROR(TvbRange_nstime, ENCODING, "invalid encoding value");
    }
    else {
        gint endoff = 0;
        nstime_t *retval = tvb_get_string_time(tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len,
                                               encoding, nstime, &endoff);
        if (!retval || endoff == 0) {
            g_free(nstime);
            /* push nil nstime and offset */
            lua_pushnil(L);
            lua_pushnil(L);
        }
        else {
            pushNSTime(L, nstime);
            lua_pushinteger(L, endoff);
        }
    }

    WSLUA_RETURN(2); /* The `NSTime` object and number of bytes used, or nil on failure. */
}

WSLUA_METHOD TvbRange_le_nstime(lua_State* L) {
	/* Obtain a nstime from a `TvbRange`, as an `NSTime` object. */
    TvbRange tvbr = checkTvbRange(L,1);
    NSTime nstime;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    nstime = g_new(nstime_t,1);

    if (tvbr->len == 4) {
      nstime->secs = tvb_get_letohl(tvbr->tvb->ws_tvb, tvbr->offset);
      nstime->nsecs = 0;
    } else if (tvbr->len == 8) {
      nstime->secs = tvb_get_letohl(tvbr->tvb->ws_tvb, tvbr->offset);
      nstime->nsecs = tvb_get_letohl(tvbr->tvb->ws_tvb, tvbr->offset + 4);
    } else {
      g_free(nstime);
      WSLUA_ERROR(TvbRange_nstime,"The range must be 4 or 8 bytes long");
      return 0;
    }

    pushNSTime(L, nstime);

    WSLUA_RETURN(1); /* The `NSTime` object. */
}

WSLUA_METHOD TvbRange_string(lua_State* L) {
	/* Obtain a string from a `TvbRange`. */
#define WSLUA_OPTARG_TvbRange_string_ENCODING 2 /* The encoding to use. Defaults to ENC_ASCII. */
    TvbRange tvbr = checkTvbRange(L,1);
    guint encoding = (guint)luaL_optint(L,WSLUA_OPTARG_TvbRange_string_ENCODING, ENC_ASCII|ENC_NA);

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    lua_pushlstring(L, (gchar*)tvb_get_string_enc(wmem_packet_scope(),tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,encoding), tvbr->len);

    WSLUA_RETURN(1); /* The string */
}

static int TvbRange_ustring_any(lua_State* L, gboolean little_endian) {
	/* Obtain a UTF-16 encoded string from a `TvbRange`. */
    TvbRange tvbr = checkTvbRange(L,1);
    gchar * str;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    str = (gchar*)tvb_get_string_enc(wmem_packet_scope(),tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,(little_endian ? ENC_UTF_16|ENC_LITTLE_ENDIAN : ENC_UTF_16|ENC_BIG_ENDIAN));
    lua_pushlstring(L, str, strlen(str));

    return 1; /* The string */
}

WSLUA_METHOD TvbRange_ustring(lua_State* L) {
	/* Obtain a Big Endian (network order) UTF-16 encoded string from a `TvbRange`. */
    WSLUA_RETURN(TvbRange_ustring_any(L, FALSE)); /* The string. */
}

WSLUA_METHOD TvbRange_le_ustring(lua_State* L) {
	/* Obtain a Little Endian UTF-16 encoded string from a `TvbRange`. */
    WSLUA_RETURN(TvbRange_ustring_any(L, TRUE)); /* The string. */
}

WSLUA_METHOD TvbRange_stringz(lua_State* L) {
	/* Obtain a zero terminated string from a `TvbRange`. */
#define WSLUA_OPTARG_TvbRange_stringz_ENCODING 2 /* The encoding to use. Defaults to ENC_ASCII. */
    TvbRange tvbr = checkTvbRange(L,1);
    guint encoding = (guint)luaL_optint(L,WSLUA_OPTARG_TvbRange_stringz_ENCODING, ENC_ASCII|ENC_NA);
    gint offset;
    gunichar2 uchar;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (encoding & ENC_CHARENCODING_MASK) {

    case ENC_UTF_16:
    case ENC_UCS_2:
        offset = tvbr->offset;
        do {
            if (!tvb_bytes_exist (tvbr->tvb->ws_tvb, offset, 2)) {
                luaL_error(L,"out of bounds");
                return 0;
            }
            /* Endianness doesn't matter when looking for null */
            uchar = tvb_get_ntohs (tvbr->tvb->ws_tvb, offset);
            offset += 2;
        } while(uchar != 0);
        break;

    default:
        if (tvb_find_guint8 (tvbr->tvb->ws_tvb, tvbr->offset, -1, 0) == -1) {
            luaL_error(L,"out of bounds");
            return 0;
        }
        break;
    }

    lua_pushstring(L, (gchar*)tvb_get_stringz_enc(wmem_packet_scope(),tvbr->tvb->ws_tvb,tvbr->offset,NULL,encoding));

    WSLUA_RETURN(1); /* The zero terminated string. */
}

WSLUA_METHOD TvbRange_strsize(lua_State* L) {
        /* Find the size of a zero terminated string from a `TvbRange`.
           The size of the string includes the terminating zero. */
#define WSLUA_OPTARG_TvbRange_strsize_ENCODING 2 /* The encoding to use. Defaults to ENC_ASCII. */
    TvbRange tvbr = checkTvbRange(L,1);
    guint encoding = (guint)luaL_optint(L,WSLUA_OPTARG_TvbRange_strsize_ENCODING, ENC_ASCII|ENC_NA);
    gint offset;
    gunichar2 uchar;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (encoding & ENC_CHARENCODING_MASK) {

    case ENC_UTF_16:
    case ENC_UCS_2:
        offset = tvbr->offset;
        do {
            if (!tvb_bytes_exist (tvbr->tvb->ws_tvb, offset, 2)) {
                luaL_error(L,"out of bounds");
                return 0;
            }
            /* Endianness doesn't matter when looking for null */
            uchar = tvb_get_ntohs (tvbr->tvb->ws_tvb, offset);
            offset += 2;
        } while (uchar != 0);
        lua_pushinteger(L, tvb_unicode_strsize(tvbr->tvb->ws_tvb, tvbr->offset));
        break;

    default:
        if (tvb_find_guint8 (tvbr->tvb->ws_tvb, tvbr->offset, -1, 0) == -1) {
            luaL_error(L,"out of bounds");
            return 0;
        }
        lua_pushinteger(L, tvb_strsize(tvbr->tvb->ws_tvb, tvbr->offset));
        break;
    }

    WSLUA_RETURN(1); /* Length of the zero terminated string. */
}


static int TvbRange_ustringz_any(lua_State* L, gboolean little_endian) {
	/* Obtain a zero terminated string from a TvbRange */
    gint count;
    TvbRange tvbr = checkTvbRange(L,1);
    gint offset;
    gunichar2 uchar;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    offset = tvbr->offset;
    do {
      if (!tvb_bytes_exist (tvbr->tvb->ws_tvb, offset, 2)) {
        luaL_error(L,"out of bounds");
        return 0;
      }
      /* Endianness doesn't matter when looking for null */
      uchar = tvb_get_ntohs (tvbr->tvb->ws_tvb, offset);
      offset += 2;
    } while (uchar != 0);

    lua_pushstring(L, (gchar*)tvb_get_stringz_enc(wmem_packet_scope(),tvbr->tvb->ws_tvb,tvbr->offset,&count,
                                (little_endian ? ENC_UTF_16|ENC_LITTLE_ENDIAN : ENC_UTF_16|ENC_BIG_ENDIAN)) );
    lua_pushinteger(L,count);

    return 2; /* The zero terminated string, the length found in tvbr */
}

WSLUA_METHOD TvbRange_ustringz(lua_State* L) {
	/* Obtain a Big Endian (network order) UTF-16 encoded zero terminated string from a `TvbRange`. */
    WSLUA_RETURN(TvbRange_ustringz_any(L, FALSE)); /* Two return values: the zero terminated string, and the length. */
}

WSLUA_METHOD TvbRange_le_ustringz(lua_State* L) {
	/* Obtain a Little Endian UTF-16 encoded zero terminated string from a TvbRange */
    WSLUA_RETURN(TvbRange_ustringz_any(L, TRUE)); /* Two return values: the zero terminated string, and the length. */
}

WSLUA_METHOD TvbRange_bytes(lua_State* L) {
	/* Obtain a `ByteArray` from a `TvbRange`.

       Starting in 1.11.4, this function also takes an optional `encoding` argument,
       which can be set to `ENC_STR_HEX` to decode a hex-string from the `TvbRange`
       into the returned `ByteArray`. The `encoding` can be bitwise-or'ed with one
       or more separator encodings, such as `ENC_SEP_COLON`, to allow separators
       to occur between each pair of hex characters.

       The return value also now returns the number of bytes used as a second return value.

       On failure or error, nil is returned for both return values.

       @note The encoding type of the hex string should also be set, for example
       `ENC_ASCII` or `ENC_UTF_8`, along with `ENC_STR_HEX`.
     */
#define WSLUA_OPTARG_TvbRange_bytes_ENCODING 2 /* An optional ENC_* encoding value to use */
    TvbRange tvbr = checkTvbRange(L,1);
    GByteArray* ba;
    const guint encoding = luaL_optint(L, WSLUA_OPTARG_TvbRange_bytes_ENCODING, 0);

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    ba = g_byte_array_new();

    if (encoding == 0) {
        g_byte_array_append(ba,(const guint8 *)tvb_memdup(wmem_packet_scope(),tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len),tvbr->len);
        pushByteArray(L,ba);
        lua_pushinteger(L, tvbr->len);
    }
    else if ((encoding & ENC_STR_HEX) == 0) {
        WSLUA_OPTARG_ERROR(TvbRange_nstime, ENCODING, "invalid encoding value");
    }
    else {
        gint endoff = 0;
        GByteArray* retval = tvb_get_string_bytes(tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len,
                                                  encoding, ba, &endoff);
        if (!retval || endoff == 0) {
            g_byte_array_free(ba, TRUE);
            /* push nil nstime and offset */
            lua_pushnil(L);
            lua_pushnil(L);
        }
        else {
            pushByteArray(L,ba);
            lua_pushinteger(L, endoff);
        }
    }

    WSLUA_RETURN(2); /* The `ByteArray` object or nil, and number of bytes consumed or nil. */
}

WSLUA_METHOD TvbRange_bitfield(lua_State* L) {
	/* Get a bitfield from a `TvbRange`. */
#define WSLUA_OPTARG_TvbRange_bitfield_POSITION 2 /* The bit offset from the beginning of the `TvbRange`. Defaults to 0. */
#define WSLUA_OPTARG_TvbRange_bitfield_LENGTH 3 /* The length (in bits) of the field. Defaults to 1. */

    TvbRange tvbr = checkTvbRange(L,1);
    int pos = luaL_optint(L,WSLUA_OPTARG_TvbRange_bitfield_POSITION,0);
    int len = luaL_optint(L,WSLUA_OPTARG_TvbRange_bitfield_LENGTH,1);

    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if ((pos+len) > (tvbr->len<<3)) {
        luaL_error(L, "Requested bitfield out of range");
        return 0;
    }

    if (len <= 8) {
        lua_pushnumber(L,(lua_Number)(guint)tvb_get_bits8(tvbr->tvb->ws_tvb,tvbr->offset*8 + pos, len));
        return 1;
    } else if (len <= 16) {
        lua_pushnumber(L,tvb_get_bits16(tvbr->tvb->ws_tvb,tvbr->offset*8 + pos, len, FALSE));
        return 1;
    } else if (len <= 32) {
        lua_pushnumber(L,tvb_get_bits32(tvbr->tvb->ws_tvb,tvbr->offset*8 + pos, len, FALSE));
        return 1;
    } else if (len <= 64) {
        pushUInt64(L,tvb_get_bits64(tvbr->tvb->ws_tvb,tvbr->offset*8 + pos, len, FALSE));
        WSLUA_RETURN(1); /* The bitfield value */
    } else {
        luaL_error(L,"TvbRange:bitfield() does not handle %d bits",len);
        return 0;
    }
}

WSLUA_METHOD TvbRange_range(lua_State* L) {
	/* Creates a sub-`TvbRange` from this `TvbRange`. */
#define WSLUA_OPTARG_TvbRange_range_OFFSET 2 /* The offset (in octets) from the beginning of the `TvbRange`. Defaults to 0. */
#define WSLUA_OPTARG_TvbRange_range_LENGTH 3 /* The length (in octets) of the range. Defaults to until the end of the `TvbRange`. */

    TvbRange tvbr = checkTvbRange(L,1);
    int offset = luaL_optint(L,WSLUA_OPTARG_TvbRange_range_OFFSET,0);
    int len;

    if (!(tvbr && tvbr->tvb)) return 0;

    len = luaL_optint(L,WSLUA_OPTARG_TvbRange_range_LENGTH,tvbr->len-offset);

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (offset >= tvbr->len || (len + offset) > tvbr->len) {
        luaL_error(L,"Range is out of bounds");
        return 0;
    }

    if (push_TvbRange(L,tvbr->tvb->ws_tvb,tvbr->offset+offset,len)) {
        WSLUA_RETURN(1); /* The TvbRange */
    }

    return 0;
}

static int TvbRange_uncompress(lua_State* L) {
	/* Obtain a uncompressed TvbRange from a TvbRange */
#define WSLUA_ARG_TvbRange_uncompress_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
#ifdef HAVE_LIBZ
    const gchar* name = luaL_optstring(L,WSLUA_ARG_TvbRange_uncompress_NAME,"Uncompressed");
    tvbuff_t *uncompr_tvb;
#endif

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

#ifdef HAVE_LIBZ
    uncompr_tvb = tvb_child_uncompress(tvbr->tvb->ws_tvb, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (uncompr_tvb) {
       add_new_data_source (lua_pinfo, uncompr_tvb, name);
       if (push_TvbRange(L,uncompr_tvb,0,tvb_length(uncompr_tvb))) {
          WSLUA_RETURN(1); /* The TvbRange */
       }
    }
#else
    luaL_error(L,"Missing support for ZLIB");
#endif

    return 0;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int TvbRange__gc(lua_State* L) {
    TvbRange tvbr = checkTvbRange(L,1);

    free_TvbRange(tvbr);

    return 0;

}

WSLUA_METHOD TvbRange_len(lua_State* L) {
	/* Obtain the length of a `TvbRange`. */
    TvbRange tvbr = checkTvbRange(L,1);

    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }
    lua_pushnumber(L,(lua_Number)tvbr->len);
    return 1;
}

WSLUA_METHOD TvbRange_offset(lua_State* L) {
	/* Obtain the offset in a `TvbRange`. */
    TvbRange tvbr = checkTvbRange(L,1);

    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }
    lua_pushnumber(L,(lua_Number)tvbr->offset);
    return 1;
}

WSLUA_METHOD TvbRange_raw(lua_State* L) {
    /* Obtain a Lua string of the binary bytes in a `TvbRange`. */
#define WSLUA_OPTARG_TvbRange_raw_OFFSET 2 /* The position of the first byte (default=0/first). */
#define WSLUA_OPTARG_TvbRange_raw_LENGTH 3 /* The length of the segment to get (default=all). */
    TvbRange tvbr = checkTvbRange(L,1);
    int offset = luaL_optint(L,WSLUA_OPTARG_TvbRange_raw_OFFSET,0);
    int len = luaL_optint(L,WSLUA_OPTARG_TvbRange_raw_LENGTH,-1);

    if (!tvbr || !tvbr->tvb) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if ((guint)offset > tvb_length(tvbr->tvb->ws_tvb)) {
        WSLUA_OPTARG_ERROR(Tvb_raw,OFFSET,"offset beyond end of Tvb");
        return 0;
    }

    if (len == -1) {
        len = tvb_length_remaining(tvbr->tvb->ws_tvb,offset);
        if (len < 0) {
            luaL_error(L,"out of bounds");
            return FALSE;
        }
    } else if ( (guint)(len + offset) > tvb_length(tvbr->tvb->ws_tvb)) {
        luaL_error(L,"Range is out of bounds");
        return FALSE;
    }

    lua_pushlstring(L, tvb_get_ptr(tvbr->tvb->ws_tvb, offset, len), len);

    WSLUA_RETURN(1); /* A Lua string of the binary bytes in the `TvbRange`. */
}


WSLUA_METAMETHOD TvbRange__tostring(lua_State* L) {
	/* Converts the `TvbRange` into a string. As the string gets truncated
	   you should use this only for debugging purposes
	   or if what you want is to have a truncated string in the format 67:89:AB:... */
    TvbRange tvbr = checkTvbRange(L,1);

    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    lua_pushstring(L,tvb_bytes_to_ep_str(tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len));
    return 1;
}

WSLUA_METHODS TvbRange_methods[] = {
    WSLUA_CLASS_FNREG(TvbRange,uint),
    WSLUA_CLASS_FNREG(TvbRange,le_uint),
    WSLUA_CLASS_FNREG(TvbRange,int),
    WSLUA_CLASS_FNREG(TvbRange,le_int),
    WSLUA_CLASS_FNREG(TvbRange,uint64),
    WSLUA_CLASS_FNREG(TvbRange,le_uint64),
    WSLUA_CLASS_FNREG(TvbRange,int64),
    WSLUA_CLASS_FNREG(TvbRange,le_int64),
    WSLUA_CLASS_FNREG(TvbRange,float),
    WSLUA_CLASS_FNREG(TvbRange,le_float),
    WSLUA_CLASS_FNREG(TvbRange,ether),
    WSLUA_CLASS_FNREG(TvbRange,ipv4),
    WSLUA_CLASS_FNREG(TvbRange,le_ipv4),
    WSLUA_CLASS_FNREG(TvbRange,nstime),
    WSLUA_CLASS_FNREG(TvbRange,le_nstime),
    WSLUA_CLASS_FNREG(TvbRange,string),
    WSLUA_CLASS_FNREG(TvbRange,stringz),
    WSLUA_CLASS_FNREG(TvbRange,strsize),
    WSLUA_CLASS_FNREG(TvbRange,bytes),
    WSLUA_CLASS_FNREG(TvbRange,bitfield),
    WSLUA_CLASS_FNREG(TvbRange,range),
    WSLUA_CLASS_FNREG(TvbRange,len),
    WSLUA_CLASS_FNREG(TvbRange,offset),
    WSLUA_CLASS_FNREG(TvbRange,tvb),
    WSLUA_CLASS_FNREG(TvbRange,le_ustring),
    WSLUA_CLASS_FNREG(TvbRange,ustring),
    WSLUA_CLASS_FNREG(TvbRange,le_ustringz),
    WSLUA_CLASS_FNREG(TvbRange,ustringz),
    WSLUA_CLASS_FNREG(TvbRange,uncompress),
    WSLUA_CLASS_FNREG(TvbRange,raw),
    { NULL, NULL }
};

WSLUA_META TvbRange_meta[] = {
    WSLUA_CLASS_MTREG(TvbRange,tostring),
    WSLUA_CLASS_MTREG(wslua,concat),
    {"__call", TvbRange_range},
    { NULL, NULL }
};

int TvbRange_register(lua_State* L) {
    outstanding_Tvb = g_ptr_array_new();
    outstanding_TvbRange = g_ptr_array_new();
    WSLUA_REGISTER_CLASS(TvbRange);
    return 0;
}

