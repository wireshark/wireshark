/*
 * wslua_tvb.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 * (c) 2009, Stig Bjorlykke <stig@bjorlykke.org>
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
#include <epan/wmem_scopes.h>


/* WSLUA_MODULE Tvb Functions For Handling Packet Data */


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

WSLUA_CLASS_DEFINE(Tvb,FAIL_ON_NULL_OR_EXPIRED("Tvb"));
/* A <<lua_class_Tvb,`Tvb`>> represents the packet's buffer. It is passed as an argument to listeners and dissectors,
   and can be used to extract information (via <<lua_class_TvbRange,`TvbRange`>>) from the packet's data.

   To create a <<lua_class_TvbRange,`TvbRange`>> the <<lua_class_Tvb,`Tvb`>> must be called with offset and length as optional arguments;
   the offset defaults to 0 and the length to `tvb:captured_len()`.

   [WARNING]
   ====
   Tvbs are usable only by the current listener or dissector call and are destroyed
   as soon as the listener or dissector returns, so references to them are unusable once the function
   has returned.
   ====
*/

static GPtrArray* outstanding_Tvb;
static GPtrArray* outstanding_TvbRange;

/* this is used to push Tvbs that were created brand new by wslua code */
int push_wsluaTvb(lua_State* L, Tvb t) {
    g_ptr_array_add(outstanding_Tvb,t);
    pushTvb(L,t);
    return 1;
}

#define PUSH_TVBRANGE(L,t) {g_ptr_array_add(outstanding_TvbRange,t);pushTvbRange(L,t);}


static void free_Tvb(Tvb tvb) {
    if (!tvb) return;

    if (!tvb->expired) {
        tvb->expired = true;
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

/* this is used to push Tvbs that just point to pre-existing C-code Tvbs */
Tvb* push_Tvb(lua_State* L, tvbuff_t* ws_tvb) {
    Tvb tvb = (Tvb)g_malloc(sizeof(struct _wslua_tvb));
    tvb->ws_tvb = ws_tvb;
    tvb->expired = false;
    tvb->need_free = false;
    g_ptr_array_add(outstanding_Tvb,tvb);
    return pushTvb(L,tvb);
}


WSLUA_METAMETHOD Tvb__tostring(lua_State* L) {
    /*
    Convert the bytes of a <<lua_class_Tvb,`Tvb`>> into a string.
    This is primarily useful for debugging purposes since the string will be truncated if it is too long.
    */
    Tvb tvb = checkTvb(L,1);
    int len = tvb_captured_length(tvb->ws_tvb);
    char* str = tvb_bytes_to_str(NULL,tvb->ws_tvb,0,len);

    lua_pushfstring(L, "TVB(%d) : %s", len, str);

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
    /* Obtain the reported length (length on the network) of a <<lua_class_Tvb,`Tvb`>>. */
    Tvb tvb = checkTvb(L,1);

    lua_pushinteger(L,tvb_reported_length(tvb->ws_tvb));
    WSLUA_RETURN(1); /* The reported length of the <<lua_class_Tvb,`Tvb`>>. */
}

WSLUA_METHOD Tvb_captured_len(lua_State* L) {
    /* Obtain the captured length (amount saved in the capture process) of a <<lua_class_Tvb,`Tvb`>>. */
    Tvb tvb = checkTvb(L,1);

    lua_pushinteger(L,tvb_captured_length(tvb->ws_tvb));
    WSLUA_RETURN(1); /* The captured length of the <<lua_class_Tvb,`Tvb`>>. */
}

WSLUA_METHOD Tvb_len(lua_State* L) {
    /* Obtain the captured length (amount saved in the capture process) of a <<lua_class_Tvb,`Tvb`>>.
       Same as captured_len; kept only for backwards compatibility */
    Tvb tvb = checkTvb(L,1);

    lua_pushinteger(L,tvb_captured_length(tvb->ws_tvb));
    WSLUA_RETURN(1); /* The captured length of the <<lua_class_Tvb,`Tvb`>>. */
}

WSLUA_METHOD Tvb_reported_length_remaining(lua_State* L) {
    /* Obtain the reported (not captured) length of packet data to end of a <<lua_class_Tvb,`Tvb`>> or 0 if the
       offset is beyond the end of the <<lua_class_Tvb,`Tvb`>>. */
#define WSLUA_OPTARG_Tvb_reported_length_remaining_OFFSET 2 /* The offset (in octets) from the beginning of the <<lua_class_Tvb,`Tvb`>>. Defaults to 0. */
    Tvb tvb = checkTvb(L,1);
    int offset = (int) luaL_optinteger(L, WSLUA_OPTARG_Tvb_reported_length_remaining_OFFSET, 0);

    lua_pushinteger(L,tvb_reported_length_remaining(tvb->ws_tvb, offset));
    WSLUA_RETURN(1); /* The remaining reported length of the <<lua_class_Tvb,`Tvb`>>. */
}

WSLUA_METHOD Tvb_bytes(lua_State* L) {
    /* Obtain a <<lua_class_ByteArray,`ByteArray`>> from a <<lua_class_Tvb,`Tvb`>>. */
#define WSLUA_OPTARG_Tvb_bytes_OFFSET 2 /* The offset (in octets) from the beginning of the <<lua_class_Tvb,`Tvb`>>. Defaults to 0. */
#define WSLUA_OPTARG_Tvb_bytes_LENGTH 3 /* The length (in octets) of the range. Defaults to until the end of the <<lua_class_Tvb,`Tvb`>>. */
    Tvb tvb = checkTvb(L,1);
    GByteArray* ba;
#if LUA_VERSION_NUM >= 503
    int offset = (int)luaL_optinteger(L, WSLUA_OPTARG_Tvb_bytes_OFFSET, 0);
    int len = (int)luaL_optinteger(L, WSLUA_OPTARG_Tvb_bytes_LENGTH, -1);
#else
    int offset = luaL_optint(L, WSLUA_OPTARG_Tvb_bytes_OFFSET, 0);
    int len = luaL_optint(L,WSLUA_OPTARG_Tvb_bytes_LENGTH,-1);
#endif
    if (tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (len < 0) {
        len = tvb_captured_length_remaining(tvb->ws_tvb,offset);
        if (len < 0) {
            luaL_error(L,"out of bounds");
            return 0;
        }
    } else if ( (unsigned)(len + offset) > tvb_captured_length(tvb->ws_tvb)) {
        luaL_error(L,"Range is out of bounds");
        return 0;
    }

    ba = g_byte_array_new();
    g_byte_array_append(ba, tvb_get_ptr(tvb->ws_tvb, offset, len), len);
    pushByteArray(L,ba);

    WSLUA_RETURN(1); /* The <<lua_class_ByteArray,`ByteArray`>> object or nil. */
}

WSLUA_METHOD Tvb_offset(lua_State* L) {
    /* Returns the raw offset (from the beginning of the source <<lua_class_Tvb,`Tvb`>>) of a sub <<lua_class_Tvb,`Tvb`>>. */
    Tvb tvb = checkTvb(L,1);

    lua_pushinteger(L,tvb_raw_offset(tvb->ws_tvb));
    WSLUA_RETURN(1); /* The raw offset of the <<lua_class_Tvb,`Tvb`>>. */
}


#if USED_FOR_DOC_PURPOSES
WSLUA_METAMETHOD Tvb__call(lua_State* L) {
    /* Equivalent to tvb:range(...) */
    return 0;
}
#endif


WSLUA_METHOD Tvb_range(lua_State* L) {
    /* Creates a <<lua_class_TvbRange,`TvbRange`>> from this <<lua_class_Tvb,`Tvb`>>. */
#define WSLUA_OPTARG_Tvb_range_OFFSET 2 /* The offset (in octets) from the beginning of the <<lua_class_Tvb,`Tvb`>>. Defaults to 0. */
#define WSLUA_OPTARG_Tvb_range_LENGTH 3 /* The length (in octets) of the range. Defaults to -1, which specifies the remaining bytes in the <<lua_class_Tvb,`Tvb`>>. */

    Tvb tvb = checkTvb(L,1);
    int offset = (int) luaL_optinteger(L,WSLUA_OPTARG_Tvb_range_OFFSET,0);
    int len = (int) luaL_optinteger(L,WSLUA_OPTARG_Tvb_range_LENGTH,-1);

    if (push_TvbRange(L,tvb->ws_tvb,offset,len)) {
        WSLUA_RETURN(1); /* The TvbRange */
    }

    return 0;
}

WSLUA_METHOD Tvb_raw(lua_State* L) {
    /* Obtain a Lua string of the binary bytes in a <<lua_class_Tvb,`Tvb`>>. */
#define WSLUA_OPTARG_Tvb_raw_OFFSET 2 /* The position of the first byte. Default is 0, or the first byte. */
#define WSLUA_OPTARG_Tvb_raw_LENGTH 3 /* The length of the segment to get. Default is -1, or the remaining bytes in the <<lua_class_Tvb,`Tvb`>>. */
    Tvb tvb = checkTvb(L,1);
    int offset = (int) luaL_optinteger(L,WSLUA_OPTARG_Tvb_raw_OFFSET,0);
    int len = (int) luaL_optinteger(L,WSLUA_OPTARG_Tvb_raw_LENGTH,-1);

    if (!tvb) return 0;
    if (tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if ((unsigned)offset > tvb_captured_length(tvb->ws_tvb)) {
        WSLUA_OPTARG_ERROR(Tvb_raw,OFFSET,"offset beyond end of Tvb");
        return 0;
    }

    if (len == -1) {
        len = tvb_captured_length_remaining(tvb->ws_tvb,offset);
        if (len < 0) {
            luaL_error(L,"out of bounds");
            return false;
        }
    } else if ( (unsigned)(len + offset) > tvb_captured_length(tvb->ws_tvb)) {
        luaL_error(L,"Range is out of bounds");
        return false;
    }

    lua_pushlstring(L, tvb_get_ptr(tvb->ws_tvb, offset, len), len);

    WSLUA_RETURN(1); /* A Lua string of the binary bytes in the <<lua_class_Tvb,`Tvb`>>. */
}

WSLUA_METAMETHOD Tvb__eq(lua_State* L) {
    /* Checks whether contents of two <<lua_class_Tvb,`Tvb`>>s are equal. */
    Tvb tvb_l = checkTvb(L,1);
    Tvb tvb_r = checkTvb(L,2);

    int len_l = tvb_captured_length(tvb_l->ws_tvb);
    int len_r = tvb_captured_length(tvb_r->ws_tvb);

    /* it is not an error if their ds_tvb are different... they're just not equal */
    if (len_l == len_r)
    {
        const char* lp = tvb_get_ptr(tvb_l->ws_tvb, 0, len_l);
        const char* rp = tvb_get_ptr(tvb_r->ws_tvb, 0, len_r);
        int i = 0;

        for (; i < len_l; ++i) {
            if (lp[i] != rp[i]) {
                lua_pushboolean(L,0);
                return 1;
            }
        }
        lua_pushboolean(L,1);
    } else {
        lua_pushboolean(L,0);
    }

    return 1;
}

WSLUA_METHODS Tvb_methods[] = {
    WSLUA_CLASS_FNREG(Tvb,bytes),
    WSLUA_CLASS_FNREG(Tvb,range),
    WSLUA_CLASS_FNREG(Tvb,offset),
    WSLUA_CLASS_FNREG(Tvb,reported_len),
    WSLUA_CLASS_FNREG(Tvb,reported_length_remaining),
    WSLUA_CLASS_FNREG(Tvb,captured_len),
    WSLUA_CLASS_FNREG(Tvb,len),
    WSLUA_CLASS_FNREG(Tvb,raw),
    { NULL, NULL }
};

WSLUA_META Tvb_meta[] = {
    WSLUA_CLASS_MTREG(Tvb,eq),
    WSLUA_CLASS_MTREG(Tvb,tostring),
    {"__call", Tvb_range},
    { NULL, NULL }
};

int Tvb_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(Tvb);
    if (outstanding_Tvb != NULL) {
        g_ptr_array_unref(outstanding_Tvb);
    }
    outstanding_Tvb = g_ptr_array_new();
    return 0;
}




WSLUA_CLASS_DEFINE(TvbRange,FAIL_ON_NULL("TvbRange"));
    /*
    A <<lua_class_TvbRange,`TvbRange`>> represents a usable range of a <<lua_class_Tvb,`Tvb`>> and is used to extract data from the <<lua_class_Tvb,`Tvb`>> that generated it.

    <<lua_class_TvbRange,`TvbRange`>>s are created by calling a <<lua_class_Tvb,`Tvb`>> (e.g. 'tvb(offset,length)').
    A length of -1, which is the default, means to use the bytes up to the end of the <<lua_class_Tvb,`Tvb`>>.
    If the <<lua_class_TvbRange,`TvbRange`>> span is outside the <<lua_class_Tvb,`Tvb`>>'s range the creation will cause a runtime error.
    */

static void free_TvbRange(TvbRange tvbr) {
    if (!(tvbr && tvbr->tvb)) return;

    if (!tvbr->tvb->expired) {
        tvbr->tvb->expired = true;
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


bool push_TvbRange(lua_State* L, tvbuff_t* ws_tvb, int offset, int len) {
    TvbRange tvbr;

    if (!ws_tvb) {
        luaL_error(L,"expired tvb");
        return false;
    }

    if (len == -1) {
        len = tvb_captured_length_remaining(ws_tvb,offset);
        if (len < 0) {
            luaL_error(L,"out of bounds");
            return false;
        }
    } else if (len < -1) {
        luaL_error(L, "negative length in tvb range");
        return false;
    } else if ( (unsigned)(len + offset) > tvb_captured_length(ws_tvb)) {
        luaL_error(L,"Range is out of bounds");
        return false;
    }

    tvbr = (TvbRange)g_malloc(sizeof(struct _wslua_tvbrange));
    tvbr->tvb = (Tvb)g_malloc(sizeof(struct _wslua_tvb));
    tvbr->tvb->ws_tvb = ws_tvb;
    tvbr->tvb->expired = false;
    tvbr->tvb->need_free = false;
    tvbr->offset = offset;
    tvbr->len = len;

    PUSH_TVBRANGE(L,tvbr);

    return true;
}


WSLUA_METHOD TvbRange_tvb(lua_State *L) {
    /* Creates a  new <<lua_class_Tvb,`Tvb`>> from a <<lua_class_TvbRange,`TvbRange`>>. */

    TvbRange tvbr = checkTvbRange(L,1);
    Tvb tvb;

    if (! (tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvb_offset_exists(tvbr->tvb->ws_tvb,  tvbr->offset + tvbr->len -1 )) {
        tvb = (Tvb)g_malloc(sizeof(struct _wslua_tvb));
        tvb->expired = false;
        tvb->need_free = false;
        tvb->ws_tvb = tvb_new_subset_length(tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len);
        return push_wsluaTvb(L, tvb);
    } else {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }
}


/*
 *  get a Blefuscuoan unsigned integer from a tvb
 */
WSLUA_METHOD TvbRange_uint(lua_State* L) {
    /* Get a Big Endian (network order) unsigned integer from a <<lua_class_TvbRange,`TvbRange`>>.
       The range must be 1-4 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            lua_pushinteger(L,tvb_get_guint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushinteger(L,tvb_get_ntohs(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushinteger(L,tvb_get_ntoh24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushinteger(L,tvb_get_ntohl(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The unsigned integer value. */
        default:
            luaL_error(L,"TvbRange:uint() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Lilliputian unsigned integer from a tvb
 */
WSLUA_METHOD TvbRange_le_uint(lua_State* L) {
    /* Get a Little Endian unsigned integer from a <<lua_class_TvbRange,`TvbRange`>>.
       The range must be 1-4 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            /* XXX unsigned anyway */
            lua_pushinteger(L,(lua_Integer)(unsigned)tvb_get_guint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushinteger(L,tvb_get_letohs(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushinteger(L,tvb_get_letoh24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushinteger(L,tvb_get_letohl(tvbr->tvb->ws_tvb,tvbr->offset));
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
    /* Get a Big Endian (network order) unsigned 64 bit integer from a <<lua_class_TvbRange,`TvbRange`>>, as a <<lua_class_UInt64,`UInt64`>> object.
       The range must be 1-8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            pushUInt64(L,tvb_get_guint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            pushUInt64(L,tvb_get_ntohs(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            pushUInt64(L,tvb_get_ntoh24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            pushUInt64(L,tvb_get_ntohl(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 5:
            pushUInt64(L,tvb_get_ntoh40(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 6:
            pushUInt64(L,tvb_get_ntoh48(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 7:
            pushUInt64(L,tvb_get_ntoh56(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 8:
            pushUInt64(L,tvb_get_ntoh64(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
        default:
            luaL_error(L,"TvbRange:uint64() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Lilliputian unsigned 64 bit integer from a tvb
 */
WSLUA_METHOD TvbRange_le_uint64(lua_State* L) {
    /* Get a Little Endian unsigned 64 bit integer from a <<lua_class_TvbRange,`TvbRange`>>, as a <<lua_class_UInt64,`UInt64`>> object.
       The range must be 1-8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            pushUInt64(L,tvb_get_guint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            pushUInt64(L,tvb_get_letohs(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            pushUInt64(L,tvb_get_letoh24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            pushUInt64(L,tvb_get_letohl(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 5:
            pushUInt64(L,tvb_get_letoh40(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 6:
            pushUInt64(L,tvb_get_letoh48(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 7:
            pushUInt64(L,tvb_get_letoh56(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 8:
            pushUInt64(L,tvb_get_letoh64(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The <<lua_class_UInt64,`UInt64`>> object. */
        default:
            luaL_error(L,"TvbRange:le_uint64() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Blefuscuoan signed integer from a tvb
 */
WSLUA_METHOD TvbRange_int(lua_State* L) {
    /* Get a Big Endian (network order) signed integer from a <<lua_class_TvbRange,`TvbRange`>>.
       The range must be 1-4 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            lua_pushinteger(L,tvb_get_gint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushinteger(L,tvb_get_ntohis(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushinteger(L,tvb_get_ntohi24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushinteger(L,tvb_get_ntohil(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The signed integer value. */
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
    /* Get a Little Endian signed integer from a <<lua_class_TvbRange,`TvbRange`>>.
       The range must be 1-4 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            lua_pushinteger(L,tvb_get_gint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushinteger(L,tvb_get_letohis(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushinteger(L,tvb_get_letohi24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushinteger(L,tvb_get_letohil(tvbr->tvb->ws_tvb,tvbr->offset));
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
    /* Get a Big Endian (network order) signed 64 bit integer from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Int64,`Int64`>> object.
       The range must be 1-8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            pushInt64(L,tvb_get_gint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            pushInt64(L,tvb_get_ntohis(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            pushInt64(L,tvb_get_ntohi24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            pushInt64(L,tvb_get_ntohil(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 5:
            pushInt64(L,tvb_get_ntohi40(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 6:
            pushInt64(L,tvb_get_ntohi48(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 7:
            pushInt64(L,tvb_get_ntohi56(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 8:
            pushInt64(L,tvb_get_ntohi64(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
        default:
            luaL_error(L,"TvbRange:int64() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Lilliputian signed 64 bit integer from a tvb
 */
WSLUA_METHOD TvbRange_le_int64(lua_State* L) {
    /* Get a Little Endian signed 64 bit integer from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Int64,`Int64`>> object.
       The range must be 1-8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            pushInt64(L,tvb_get_gint8(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 2:
            pushInt64(L,tvb_get_letohis(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 3:
            pushInt64(L,tvb_get_letohi24(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 4:
            pushInt64(L,tvb_get_letohil(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 5:
            pushInt64(L,tvb_get_letohi40(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 6:
            pushInt64(L,tvb_get_letohi48(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 7:
            pushInt64(L,tvb_get_letohi56(tvbr->tvb->ws_tvb,tvbr->offset));
            return 1;
        case 8:
            pushInt64(L,tvb_get_letohi64(tvbr->tvb->ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The <<lua_class_Int64,`Int64`>> object. */
        default:
            luaL_error(L,"TvbRange:le_int64() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Blefuscuoan float
 */
WSLUA_METHOD TvbRange_float(lua_State* L) {
    /* Get a Big Endian (network order) floating point number from a <<lua_class_TvbRange,`TvbRange`>>.
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
    /* Get a Little Endian floating point number from a <<lua_class_TvbRange,`TvbRange`>>.
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
    /* Get an IPv4 Address from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Address,`Address`>> object. */
    TvbRange tvbr = checkTvbRange(L,1);
    Address addr;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 4) {
        WSLUA_ERROR(TvbRange_ipv4,"The range must be 4 octets long");
        return 0;
    }

    addr = g_new(address,1);
    alloc_address_tvb(NULL,addr,AT_IPv4,sizeof(uint32_t),tvbr->tvb->ws_tvb,tvbr->offset);
    pushAddress(L,addr);

    WSLUA_RETURN(1); /* The IPv4 <<lua_class_Address,`Address`>> object. */
}

WSLUA_METHOD TvbRange_le_ipv4(lua_State* L) {
    /* Get an Little Endian IPv4 Address from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Address,`Address`>> object. */
    TvbRange tvbr = checkTvbRange(L,1);
    Address addr;
    uint32_t ip_addr;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 4) {
        WSLUA_ERROR(TvbRange_ipv4,"The range must be 4 octets long");
        return 0;
    }

    addr = g_new(address,1);
    ip_addr = GUINT32_SWAP_LE_BE(tvb_get_ipv4(tvbr->tvb->ws_tvb,tvbr->offset));
    alloc_address_wmem(NULL, addr, AT_IPv4, sizeof(ip_addr), &ip_addr);
    pushAddress(L,addr);

    WSLUA_RETURN(1); /* The IPv4 <<lua_class_Address,`Address`>> object. */
}

WSLUA_METHOD TvbRange_ipv6(lua_State* L) {
    /* Get an IPv6 Address from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Address,`Address`>> object. */
    TvbRange tvbr = checkTvbRange(L,1);
    Address addr;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 16) {
        WSLUA_ERROR(TvbRange_ipv6,"The range must be 16 octets long");
        return 0;
    }

    addr = g_new(address,1);
    alloc_address_tvb(NULL,addr,AT_IPv6,16,tvbr->tvb->ws_tvb,tvbr->offset);
    pushAddress(L,addr);

    WSLUA_RETURN(1); /* The IPv6 <<lua_class_Address,`Address`>> object. */
}

WSLUA_METHOD TvbRange_ether(lua_State* L) {
    /* Get an Ethernet Address from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Address,`Address`>> object. */
    TvbRange tvbr = checkTvbRange(L,1);
    Address addr;

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
    alloc_address_tvb(NULL,addr,AT_ETHER,6,tvbr->tvb->ws_tvb,tvbr->offset);
    pushAddress(L,addr);

    WSLUA_RETURN(1); /* The Ethernet <<lua_class_Address,`Address`>> object. */
}

WSLUA_METHOD TvbRange_nstime(lua_State* L) {
    /* Obtain a time_t structure from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_NSTime,`NSTime`>> object. */
#define WSLUA_OPTARG_TvbRange_nstime_ENCODING 2 /* An optional ENC_* encoding value to use */
    TvbRange tvbr = checkTvbRange(L,1);
    NSTime nstime;
    const unsigned encoding = (unsigned) luaL_optinteger(L, WSLUA_OPTARG_TvbRange_nstime_ENCODING, 0);

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (encoding & ~ENC_STR_TIME_MASK) {
        WSLUA_OPTARG_ERROR(TvbRange_nstime, ENCODING, "invalid encoding value");
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
    else {
        int endoff = 0;
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

    WSLUA_RETURN(2); /* The <<lua_class_NSTime,`NSTime`>> object and number of bytes used, or nil on failure. */
}

WSLUA_METHOD TvbRange_le_nstime(lua_State* L) {
    /* Obtain a nstime from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_NSTime,`NSTime`>> object. */
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

    WSLUA_RETURN(1); /* The <<lua_class_NSTime,`NSTime`>> object. */
}

WSLUA_METHOD TvbRange_string(lua_State* L) {
    /* Obtain a string from a <<lua_class_TvbRange,`TvbRange`>>. */
#define WSLUA_OPTARG_TvbRange_string_ENCODING 2 /* The encoding to use. Defaults to ENC_ASCII. */
    TvbRange tvbr = checkTvbRange(L,1);
    unsigned encoding = (unsigned)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_string_ENCODING, ENC_ASCII|ENC_NA);
    char * str;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    str = (char*)tvb_get_string_enc(NULL,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,encoding);
    lua_pushlstring(L, str, strlen(str));
    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* A string containing all bytes in the <<lua_class_TvbRange,`TvbRange`>> including all zeroes (e.g., "a\000bc\000"). */
}

static int TvbRange_ustring_any(lua_State* L, bool little_endian) {
    /* Obtain a UTF-16 encoded string from a <<lua_class_TvbRange,`TvbRange`>>. */
    TvbRange tvbr = checkTvbRange(L,1);
    char * str;

    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    str = (char*)tvb_get_string_enc(NULL,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len,(little_endian ? ENC_UTF_16|ENC_LITTLE_ENDIAN : ENC_UTF_16|ENC_BIG_ENDIAN));
    lua_pushlstring(L, str, strlen(str));
    wmem_free(NULL, str);

    return 1; /* The string */
}

WSLUA_METHOD TvbRange_ustring(lua_State* L) {
    /* Obtain a Big Endian (network order) UTF-16 encoded string from a <<lua_class_TvbRange,`TvbRange`>>. */
    WSLUA_RETURN(TvbRange_ustring_any(L, false)); /* A string containing all bytes in the <<lua_class_TvbRange,`TvbRange`>> including all zeroes (e.g., "a\000bc\000"). */
}

WSLUA_METHOD TvbRange_le_ustring(lua_State* L) {
    /* Obtain a Little Endian UTF-16 encoded string from a <<lua_class_TvbRange,`TvbRange`>>. */
    WSLUA_RETURN(TvbRange_ustring_any(L, true)); /* A string containing all bytes in the <<lua_class_TvbRange,`TvbRange`>> including all zeroes (e.g., "a\000bc\000"). */
}

WSLUA_METHOD TvbRange_stringz(lua_State* L) {
    /* Obtain a zero terminated string from a <<lua_class_TvbRange,`TvbRange`>>. */
#define WSLUA_OPTARG_TvbRange_stringz_ENCODING 2 /* The encoding to use. Defaults to ENC_ASCII. */
    TvbRange tvbr = checkTvbRange(L,1);
    unsigned encoding = (unsigned)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_stringz_ENCODING, ENC_ASCII|ENC_NA);
    int offset;
    gunichar2 uchar;
    char *str;

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

    str = (char*)tvb_get_stringz_enc(NULL,tvbr->tvb->ws_tvb,tvbr->offset,NULL,encoding);
    lua_pushstring(L, str);
    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* The string containing all bytes in the <<lua_class_TvbRange,`TvbRange`>> up to the first terminating zero. */
}

WSLUA_METHOD TvbRange_strsize(lua_State* L) {
    /*
    Find the size of a zero terminated string from a <<lua_class_TvbRange,`TvbRange`>>.
    The size of the string includes the terminating zero. */
#define WSLUA_OPTARG_TvbRange_strsize_ENCODING 2 /* The encoding to use. Defaults to ENC_ASCII. */
    TvbRange tvbr = checkTvbRange(L,1);
    unsigned encoding = (unsigned)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_strsize_ENCODING, ENC_ASCII|ENC_NA);
    int offset;
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


static int TvbRange_ustringz_any(lua_State* L, bool little_endian) {
    /* Obtain a zero terminated string from a TvbRange */
    int count;
    TvbRange tvbr = checkTvbRange(L,1);
    int offset;
    gunichar2 uchar;
    char *str;

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

    str = (char*)tvb_get_stringz_enc(NULL,tvbr->tvb->ws_tvb,tvbr->offset,&count,
                                (little_endian ? ENC_UTF_16|ENC_LITTLE_ENDIAN : ENC_UTF_16|ENC_BIG_ENDIAN));
    lua_pushstring(L, str);
    lua_pushinteger(L,count);
    wmem_free(NULL, str);

    return 2; /* The zero terminated string, the length found in tvbr */
}

WSLUA_METHOD TvbRange_ustringz(lua_State* L) {
    /* Obtain a Big Endian (network order) UTF-16 encoded zero terminated string from a <<lua_class_TvbRange,`TvbRange`>>. */
    WSLUA_RETURN(TvbRange_ustringz_any(L, false)); /* Two return values: the zero terminated string, and the length. */
}

WSLUA_METHOD TvbRange_le_ustringz(lua_State* L) {
    /* Obtain a Little Endian UTF-16 encoded zero terminated string from a TvbRange */
    WSLUA_RETURN(TvbRange_ustringz_any(L, true)); /* Two return values: the zero terminated string, and the length. */
}

WSLUA_METHOD TvbRange_bytes(lua_State* L) {
    /* Obtain a <<lua_class_ByteArray,`ByteArray`>> from a <<lua_class_TvbRange,`TvbRange`>>.

       Starting in 1.11.4, this function also takes an optional `encoding` argument,
       which can be set to `ENC_STR_HEX` to decode a hex-string from the <<lua_class_TvbRange,`TvbRange`>>
       into the returned <<lua_class_ByteArray,`ByteArray`>>. The `encoding` can be bitwise-or'ed with one
       or more separator encodings, such as `ENC_SEP_COLON`, to allow separators
       to occur between each pair of hex characters.

       The return value also now returns the number of bytes used as a second return value.

       On failure or error, nil is returned for both return values.

       [NOTE]
       ====
       The encoding type of the hex string should also be set, for example
       `ENC_ASCII` or `ENC_UTF_8`, along with `ENC_STR_HEX`.
       ====
     */
#define WSLUA_OPTARG_TvbRange_bytes_ENCODING 2 /* An optional ENC_* encoding value to use */
    TvbRange tvbr = checkTvbRange(L,1);
    GByteArray* ba;
    uint8_t* raw;
    const unsigned encoding = (unsigned)luaL_optinteger(L, WSLUA_OPTARG_TvbRange_bytes_ENCODING, 0);


    if ( !(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (encoding == 0) {
        ba = g_byte_array_new();
        raw = (uint8_t *)tvb_memdup(NULL,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len);
        g_byte_array_append(ba,raw,tvbr->len);
        wmem_free(NULL, raw);
        pushByteArray(L,ba);
        lua_pushinteger(L, tvbr->len);
    }
    else if ((encoding & ENC_STR_HEX) == 0) {
        WSLUA_OPTARG_ERROR(TvbRange_nstime, ENCODING, "invalid encoding value");
    }
    else {
        int endoff = 0;
        GByteArray* retval;

        ba = g_byte_array_new();
        retval = tvb_get_string_bytes(tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len,
                                                  encoding, ba, &endoff);
        if (!retval || endoff == 0) {
            g_byte_array_free(ba, true);
            /* push nil nstime and offset */
            lua_pushnil(L);
            lua_pushnil(L);
        }
        else {
            pushByteArray(L,ba);
            lua_pushinteger(L, endoff);
        }
    }

    WSLUA_RETURN(2); /* The <<lua_class_ByteArray,`ByteArray`>> object or nil, and number of bytes consumed or nil. */
}

WSLUA_METHOD TvbRange_bitfield(lua_State* L) {
    /* Get a bitfield from a <<lua_class_TvbRange,`TvbRange`>>. */
#define WSLUA_OPTARG_TvbRange_bitfield_POSITION 2 /* The bit offset (link:https://en.wikipedia.org/wiki/Bit_numbering#MSB_0_bit_numbering[MSB 0 bit numbering]) from the beginning of the <<lua_class_TvbRange,`TvbRange`>>. Defaults to 0. */
#define WSLUA_OPTARG_TvbRange_bitfield_LENGTH 3 /* The length in bits of the field. Defaults to 1. */

    TvbRange tvbr = checkTvbRange(L,1);
    int pos = (int)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_bitfield_POSITION,0);
    int len = (int)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_bitfield_LENGTH,1);

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
        lua_pushinteger(L,(lua_Integer)(unsigned)tvb_get_bits8(tvbr->tvb->ws_tvb,tvbr->offset*8 + pos, len));
        return 1;
    } else if (len <= 16) {
        lua_pushinteger(L,tvb_get_bits16(tvbr->tvb->ws_tvb,tvbr->offset*8 + pos, len, false));
        return 1;
    } else if (len <= 32) {
        lua_pushinteger(L,tvb_get_bits32(tvbr->tvb->ws_tvb,tvbr->offset*8 + pos, len, false));
        return 1;
    } else if (len <= 64) {
        pushUInt64(L,tvb_get_bits64(tvbr->tvb->ws_tvb,tvbr->offset*8 + pos, len, false));
        WSLUA_RETURN(1); /* The bitfield value */
    } else {
        luaL_error(L,"TvbRange:bitfield() does not handle %d bits",len);
        return 0;
    }
}

WSLUA_METHOD TvbRange_range(lua_State* L) {
    /* Creates a sub-<<lua_class_TvbRange,`TvbRange`>> from this <<lua_class_TvbRange,`TvbRange`>>. */
#define WSLUA_OPTARG_TvbRange_range_OFFSET 2 /* The offset (in octets) from the beginning of the <<lua_class_TvbRange,`TvbRange`>>. Defaults to 0. */
#define WSLUA_OPTARG_TvbRange_range_LENGTH 3 /* The length (in octets) of the range. Defaults to until the end of the <<lua_class_TvbRange,`TvbRange`>>. */

    TvbRange tvbr = checkTvbRange(L,1);
    int offset = (int)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_range_OFFSET,0);
    int len;

    if (!(tvbr && tvbr->tvb)) return 0;

    len = (int)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_range_LENGTH,tvbr->len-offset);

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (offset >= tvbr->len || (len + offset) > tvbr->len) {
        luaL_error(L,"Range is out of bounds");
        return 0;
    }

    if (push_TvbRange(L,tvbr->tvb->ws_tvb,tvbr->offset+offset,len)) {
        WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
    }

    return 0;
}

WSLUA_METHOD TvbRange_uncompress_zlib(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing zlib compressed data, decompresses the data and returns a new <<lua_class_TvbRange,`TvbRange`>> containing the uncompressed data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_uncompress_zlib_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_uncompress_zlib_NAME,"Uncompressed");
    tvbuff_t *uncompr_tvb;
#endif

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
    uncompr_tvb = tvb_child_uncompress_zlib(tvbr->tvb->ws_tvb, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (uncompr_tvb) {
       add_new_data_source (lua_pinfo, uncompr_tvb, name);
       if (push_TvbRange(L,uncompr_tvb,0,tvb_captured_length(uncompr_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }
#else
    luaL_error(L,"Missing support for ZLIB");
#endif

    return 0;
}

WSLUA_METHOD TvbRange_uncompress(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing zlib compressed data, decompresses the data and returns a new <<lua_class_TvbRange,`TvbRange`>> containing the uncompressed data. Deprecated; use tvbrange:uncompress_zlib() instead. */
#define WSLUA_ARG_TvbRange_uncompress_NAME 2 /* The name to be given to the new data-source. */
    return TvbRange_uncompress_zlib(L);
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int TvbRange__gc(lua_State* L) {
    TvbRange tvbr = checkTvbRange(L,1);

    free_TvbRange(tvbr);

    return 0;

}

WSLUA_METHOD TvbRange_uncompress_brotli(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing Brotli compressed data, decompresses the data and returns a new <<lua_class_TvbRange,`TvbRange`>> containing the uncompressed data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_uncompress_brotli_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
#ifdef HAVE_BROTLI
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_uncompress_brotli_NAME,"Uncompressed");
    tvbuff_t *uncompr_tvb;
#endif

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

#ifdef HAVE_BROTLI
    uncompr_tvb = tvb_child_uncompress_brotli(tvbr->tvb->ws_tvb, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (uncompr_tvb) {
       add_new_data_source (lua_pinfo, uncompr_tvb, name);
       if (push_TvbRange(L,uncompr_tvb,0,tvb_captured_length(uncompr_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }
#else
    luaL_error(L,"Missing support for Brotli");
#endif

    return 0;
}

WSLUA_METHOD TvbRange_uncompress_hpack_huff(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing data compressed using the Huffman encoding in HTTP/2 HPACK and HTTP/3 QPACK, decompresses the data and returns a new <<lua_class_TvbRange,`TvbRange`>> containing the uncompressed data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_uncompress_hpack_huff_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_uncompress_hpack_huff_NAME,"Uncompressed");
    tvbuff_t *uncompr_tvb;

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    uncompr_tvb = tvb_child_uncompress_hpack_huff(tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (uncompr_tvb) {
       add_new_data_source (lua_pinfo, uncompr_tvb, name);
       if (push_TvbRange(L,uncompr_tvb,0,tvb_captured_length(uncompr_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }

    return 0;
}

WSLUA_METHOD TvbRange_uncompress_lz77(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing Microsoft Plain LZ77 compressed data, decompresses the data and returns a new <<lua_class_TvbRange,`TvbRange`>> containing the uncompressed data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_uncompress_lz77_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_uncompress_lz77_NAME,"Uncompressed");
    tvbuff_t *uncompr_tvb;

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    uncompr_tvb = tvb_child_uncompress_lz77(tvbr->tvb->ws_tvb, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (uncompr_tvb) {
       add_new_data_source (lua_pinfo, uncompr_tvb, name);
       if (push_TvbRange(L,uncompr_tvb,0,tvb_captured_length(uncompr_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }

    return 0;
}

WSLUA_METHOD TvbRange_uncompress_lz77huff(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing Microsoft LZ77+Huffman compressed data, decompresses the data and returns a new <<lua_class_TvbRange,`TvbRange`>> containing the uncompressed data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_uncompress_lz77huff_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_uncompress_lz77huff_NAME,"Uncompressed");
    tvbuff_t *uncompr_tvb;

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    uncompr_tvb = tvb_child_uncompress_lz77huff(tvbr->tvb->ws_tvb, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (uncompr_tvb) {
       add_new_data_source (lua_pinfo, uncompr_tvb, name);
       if (push_TvbRange(L,uncompr_tvb,0,tvb_captured_length(uncompr_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }

    return 0;
}

WSLUA_METHOD TvbRange_uncompress_lznt1(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing Microsoft LZNT1 compressed data, decompresses the data and returns a new <<lua_class_TvbRange,`TvbRange`>> containing the uncompressed data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_uncompress_lznt1_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_uncompress_lznt1_NAME,"Uncompressed");
    tvbuff_t *uncompr_tvb;

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    uncompr_tvb = tvb_child_uncompress_lznt1(tvbr->tvb->ws_tvb, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (uncompr_tvb) {
       add_new_data_source (lua_pinfo, uncompr_tvb, name);
       if (push_TvbRange(L,uncompr_tvb,0,tvb_captured_length(uncompr_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }

    return 0;
}

WSLUA_METHOD TvbRange_uncompress_snappy(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing Snappy compressed data, decompresses the data and returns a new <<lua_class_TvbRange,`TvbRange`>> containing the uncompressed data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_uncompress_snappy_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
#ifdef HAVE_SNAPPY
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_uncompress_snappy_NAME,"Uncompressed");
    tvbuff_t *uncompr_tvb;
#endif

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

#ifdef HAVE_SNAPPY
    uncompr_tvb = tvb_child_uncompress_snappy(tvbr->tvb->ws_tvb, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (uncompr_tvb) {
       add_new_data_source (lua_pinfo, uncompr_tvb, name);
       if (push_TvbRange(L,uncompr_tvb,0,tvb_captured_length(uncompr_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }
#else
    luaL_error(L,"Missing support for Snappy");
#endif

    return 0;
}

WSLUA_METHOD TvbRange_uncompress_zstd(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing Zstandard compressed data, decompresses the data and returns a new <<lua_class_TvbRange,`TvbRange`>> containing the uncompressed data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_uncompress_zstd_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
#ifdef HAVE_ZSTD
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_uncompress_zstd_NAME,"Uncompressed");
    tvbuff_t *uncompr_tvb;
#endif

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

#ifdef HAVE_ZSTD
    uncompr_tvb = tvb_child_uncompress_zstd(tvbr->tvb->ws_tvb, tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (uncompr_tvb) {
       add_new_data_source (lua_pinfo, uncompr_tvb, name);
       if (push_TvbRange(L,uncompr_tvb,0,tvb_captured_length(uncompr_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }
#else
    luaL_error(L,"Missing support for ZStandard");
#endif

    return 0;
}

WSLUA_METHOD TvbRange_decode_base64(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing Base64 encoded data, return a new <<lua_class_TvbRange,`TvbRange`>> containing the decoded data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_decode_base64_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_decode_base64_NAME,"Decoded");
    tvbuff_t *decoded_tvb;

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    decoded_tvb = base64_tvb_to_new_tvb(tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (decoded_tvb) {
       add_new_data_source (lua_pinfo, decoded_tvb, name);
       if (push_TvbRange(L,decoded_tvb,0,tvb_captured_length(decoded_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }

    return 0;
}

WSLUA_METHOD TvbRange_decode_base64url(lua_State* L) {
    /* Given a <<lua_class_TvbRange,`TvbRange`>> containing base64url encoded data, return a new <<lua_class_TvbRange,`TvbRange`>> containing the decoded data.
     @since 4.3.0
     */
#define WSLUA_ARG_TvbRange_decode_base64url_NAME 2 /* The name to be given to the new data-source. */
    TvbRange tvbr = checkTvbRange(L,1);
    const char* name = luaL_optstring(L,WSLUA_ARG_TvbRange_decode_base64url_NAME,"Decoded");
    tvbuff_t *decoded_tvb;

    if (!(tvbr && tvbr->tvb)) return 0;

    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    decoded_tvb = base64uri_tvb_to_new_tvb(tvbr->tvb->ws_tvb, tvbr->offset, tvbr->len);
    if (decoded_tvb) {
       add_new_data_source (lua_pinfo, decoded_tvb, name);
       if (push_TvbRange(L,decoded_tvb,0,tvb_captured_length(decoded_tvb))) {
          WSLUA_RETURN(1); /* The <<lua_class_TvbRange,`TvbRange`>>. */
       }
    }

    return 0;
}

WSLUA_METHOD TvbRange_len(lua_State* L) {
    /* Obtain the length of a <<lua_class_TvbRange,`TvbRange`>>. */
    TvbRange tvbr = checkTvbRange(L,1);

    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }
    lua_pushinteger(L,(lua_Integer)tvbr->len);
    return 1;
}

WSLUA_METHOD TvbRange_offset(lua_State* L) {
    /* Obtain the offset in a <<lua_class_TvbRange,`TvbRange`>>. */
    TvbRange tvbr = checkTvbRange(L,1);

    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }
    lua_pushinteger(L,(lua_Integer)tvbr->offset);
    return 1;
}

WSLUA_METHOD TvbRange_raw(lua_State* L) {
    /* Obtain a Lua string of the binary bytes in a <<lua_class_TvbRange,`TvbRange`>>. */
#define WSLUA_OPTARG_TvbRange_raw_OFFSET 2 /* The position of the first byte within the range. Default is 0, or first byte. */
#define WSLUA_OPTARG_TvbRange_raw_LENGTH 3 /* The length of the segment to get. Default is -1, or the remaining bytes in the range. */
    TvbRange tvbr = checkTvbRange(L,1);
    int offset = (int)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_raw_OFFSET,0);
    int len = (int)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_raw_LENGTH,-1);

    if (!tvbr || !tvbr->tvb) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (offset < 0) {
        WSLUA_OPTARG_ERROR(TvbRange_raw,OFFSET,"offset before start of TvbRange");
        return 0;
    }
    if (offset > tvbr->len) {
        WSLUA_OPTARG_ERROR(TvbRange_raw,OFFSET,"offset beyond end of TvbRange");
        return 0;
    }

    if (len == -1) {
        len = tvbr->len - offset;
    }
    if (len < 0) {
        luaL_error(L,"out of bounds");
        return false;
    } else if ( (len + offset) > tvbr->len) {
        luaL_error(L,"Range is out of bounds");
        return false;
    }

    lua_pushlstring(L, tvb_get_ptr(tvbr->tvb->ws_tvb, tvbr->offset+offset, len), len);

    WSLUA_RETURN(1); /* A Lua string of the binary bytes in the <<lua_class_TvbRange,`TvbRange`>>. */
}

WSLUA_METAMETHOD TvbRange__eq(lua_State* L) {
    /* Checks whether the contents of two <<lua_class_TvbRange,`TvbRange`>>s are equal. */
    TvbRange tvb_l = checkTvbRange(L,1);
    TvbRange tvb_r = checkTvbRange(L,2);

    /* it is not an error if their ds_tvb are different... they're just not equal */
    if (tvb_l->len == tvb_r->len &&
        tvb_l->len <= tvb_captured_length_remaining(tvb_l->tvb->ws_tvb, tvb_l->offset) &&
        tvb_r->len <= tvb_captured_length_remaining(tvb_r->tvb->ws_tvb, tvb_r->offset))
    {
        const char* lp = tvb_get_ptr(tvb_l->tvb->ws_tvb, tvb_l->offset, tvb_l->len);
        const char* rp = tvb_get_ptr(tvb_r->tvb->ws_tvb, tvb_r->offset, tvb_r->len);
        int i = 0;

        for (; i < tvb_r->len; ++i) {
            if (lp[i] != rp[i]) {
                lua_pushboolean(L,0);
                return 1;
            }
        }
        lua_pushboolean(L,1);
    } else {
        lua_pushboolean(L,0);
    }

    return 1;
}

WSLUA_METAMETHOD TvbRange__tostring(lua_State* L) {
    /*
    Converts the <<lua_class_TvbRange,`TvbRange`>> into a string.
    The string can be truncated, so this is primarily useful for debugging or in cases where truncation is preferred, e.g. "67:89:AB:...".
    */
    TvbRange tvbr = checkTvbRange(L,1);
    char* str = NULL;

    if (!(tvbr && tvbr->tvb)) return 0;
    if (tvbr->tvb->expired) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len == 0) {
        lua_pushstring(L, "<EMPTY>");
    } else {
        str = tvb_bytes_to_str(NULL,tvbr->tvb->ws_tvb,tvbr->offset,tvbr->len);
        lua_pushstring(L,str);
        wmem_free(NULL, str);
    }

    WSLUA_RETURN(1); /* A Lua hex string of the <<lua_class_TvbRange,`TvbRange`>> truncated to 24 bytes. */
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
    WSLUA_CLASS_FNREG(TvbRange,ipv6),
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
    WSLUA_CLASS_FNREG(TvbRange,uncompress_zlib),
    WSLUA_CLASS_FNREG(TvbRange,uncompress_brotli),
    WSLUA_CLASS_FNREG(TvbRange,uncompress_hpack_huff),
    WSLUA_CLASS_FNREG(TvbRange,uncompress_lz77),
    WSLUA_CLASS_FNREG(TvbRange,uncompress_lz77huff),
    WSLUA_CLASS_FNREG(TvbRange,uncompress_lznt1),
    WSLUA_CLASS_FNREG(TvbRange,uncompress_snappy),
    WSLUA_CLASS_FNREG(TvbRange,uncompress_zstd),
    WSLUA_CLASS_FNREG(TvbRange,decode_base64),
    WSLUA_CLASS_FNREG(TvbRange,decode_base64url),
    WSLUA_CLASS_FNREG(TvbRange,raw),
    { NULL, NULL }
};

WSLUA_META TvbRange_meta[] = {
    WSLUA_CLASS_MTREG(TvbRange,tostring),
    WSLUA_CLASS_MTREG(wslua,concat),
    WSLUA_CLASS_MTREG(TvbRange,eq),
    {"__call", TvbRange_range},
    { NULL, NULL }
};

int TvbRange_register(lua_State* L) {
    if (outstanding_TvbRange != NULL) {
        g_ptr_array_unref(outstanding_TvbRange);
    }
    outstanding_TvbRange = g_ptr_array_new();
    WSLUA_REGISTER_CLASS(TvbRange);
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
