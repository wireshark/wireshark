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
 * It helps, too, simplifying argument passing to Tree.
 *
 * Normally in Wireshark explicit bounds checking is unnecessary as the tvbuff
 * functions throw appropriate exceptions depending on why data wasn't present.
 * In Lua, the interaction between the exception handling in epan and Lua's error
 * handling, both of which use setjmp/longjmp, requires careful programming to
 * avoid longjmp'ing down to the stack to a location that has already exited,
 * particularly when Lua dissector calls are nested. TvbRange reduces the amount
 * of possible exceptions (and TRY/CATCH to deal with them) by doing preemptive
 * bounds checking - at a cost of making it impossible to support truncated
 * captures where captured length < reported length (#15655).
 *
 * These lua objects refer to structures in wireshark that are freed independently from Lua's garbage collector.
 * To avoid using pointers from Lua to Wireshark structures that are already freed, each object records the
 * wslua_packet_generation in which it was created, and is expired once that changes, which happens when the
 * dissection of the current frame is finished.
 *
 * We check the expiry state of the pointer before each access.
 *
 * The objects are stored in the Lua userdata itself and have no __gc metamethod, so that they are freed
 * promptly by the garbage collector; see WSLUA_CLASS_DEFINE_INLINE.
 *
 */

WSLUA_CLASS_DEFINE_INLINE(Tvb,FAIL_ON_EXPIRED("Tvb"));
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

/* The tvbuff is not owned by the Tvb; it must be freed (if necessary)
 * by the end of the dissection of the current frame, e.g. by being
 * a child of the frame's tvbuff, or added as a new data source. */
Tvb push_Tvb(lua_State* L, tvbuff_t* ws_tvb) {
    struct _wslua_tvb tvb = {
        .ws_tvb = ws_tvb,
        .generation = wslua_packet_generation,
    };
    return pushTvb(L,&tvb);
}


/* WSLUA_ATTRIBUTE Tvb_captured_length RO The captured length of the Tvb
   (amount saved in the capture process). Mirrors `tvb:captured_len()`. */
WSLUA_ATTRIBUTE_GET(Tvb,captured_length, {
    lua_pushinteger(L, tvb_captured_length(obj->ws_tvb));
});

/* WSLUA_ATTRIBUTE Tvb_reported_length RO The reported length of the Tvb
   (length on the network). Mirrors `tvb:reported_len()`. */
WSLUA_ATTRIBUTE_GET(Tvb,reported_length, {
    lua_pushinteger(L, tvb_reported_length(obj->ws_tvb));
});

/* WSLUA_ATTRIBUTE Tvb_raw_offset RO The raw offset of this (sub) Tvb in its
   source Tvb. Mirrors `tvb:offset()`. */
WSLUA_ATTRIBUTE_GET(Tvb,raw_offset, {
    lua_pushinteger(L, tvb_raw_offset(obj->ws_tvb));
});

WSLUA_METAMETHOD Tvb__tostring(lua_State* L) {
    /*
    Convert the bytes of a <<lua_class_Tvb,`Tvb`>> into a string of
    the form `Tvb: captured=<C> reported=<R> bytes=<hex>`.
    The hex preview is automatically truncated by `tvb_bytes_to_str`
    to a small number of bytes (currently 36) so the rendering stays
    useful in the debugger Variables view and in `print()` for large
    packets.
    */
    Tvb tvb = checkTvb(L,1);
    int captured = tvb_captured_length(tvb->ws_tvb);
    int reported = tvb_reported_length(tvb->ws_tvb);
    char* str = tvb_bytes_to_str(NULL, tvb->ws_tvb, 0, captured);

    lua_pushfstring(L, "Tvb: captured=%d reported=%d bytes=%s",
                    captured, reported, str ? str : "");

    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* The string. */
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
    if (WSLUA_EXPIRED(tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    /* XXX - Why is *any* negative value allowed here to mean "to the
     * end of the Tvb" instead of just -1 as elsewhere?
     */
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
    if (WSLUA_EXPIRED(tvb)) {
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

    lua_pushlstring(L, (const char*)tvb_get_ptr(tvb->ws_tvb, offset, len), len);

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
        const uint8_t* lp = tvb_get_ptr(tvb_l->ws_tvb, 0, len_l);
        const uint8_t* rp = tvb_get_ptr(tvb_r->ws_tvb, 0, len_r);

        int ret = memcmp(lp, rp, len_l) == 0 ? 1 : 0;

        lua_pushboolean(L,ret);
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

/* Read-only attributes. Registered so the Lua debugger can expand a Tvb
 * in the Variables view without having to invoke methods. The attribute
 * names intentionally differ from the corresponding method names to
 * avoid the attribute/method collision check performed by
 * wslua_push_attributes. */
WSLUA_ATTRIBUTES Tvb_attributes[] = {
    WSLUA_ATTRIBUTE_ROREG(Tvb,captured_length),
    WSLUA_ATTRIBUTE_ROREG(Tvb,reported_length),
    WSLUA_ATTRIBUTE_ROREG(Tvb,raw_offset),
    { NULL, NULL, NULL }
};

int Tvb_register(lua_State* L) {
    WSLUA_REGISTER_CLASS_WITH_ATTRS_NOGC(Tvb);
    return 0;
}




WSLUA_CLASS_DEFINE_INLINE(TvbRange,NOP);
    /*
    A <<lua_class_TvbRange,`TvbRange`>> represents a usable range of a <<lua_class_Tvb,`Tvb`>> and is used to extract data from the <<lua_class_Tvb,`Tvb`>> that generated it.

    <<lua_class_TvbRange,`TvbRange`>>s are created by calling a <<lua_class_Tvb,`Tvb`>> (e.g. 'tvb(offset,length)').
    A length of -1, which is the default, means to use the bytes up to the end of the <<lua_class_Tvb,`Tvb`>>.
    If the <<lua_class_TvbRange,`TvbRange`>> span is outside the <<lua_class_Tvb,`Tvb`>>'s range the creation will cause a runtime error.
    */

bool push_TvbRange(lua_State* L, tvbuff_t* ws_tvb, int offset, int len) {
    struct _wslua_tvbrange tvbr;

    if (!ws_tvb) {
        luaL_error(L,"expired tvb");
        return false;
    }

    /* XXX - What if offset is negative? In epan/tvbuff.h functions, a negative
     * offset means "the offset from the end of the backing tvbuff at which
     * the new tvbuff's data begins", but that's not done consistently in this
     * code when taking ranges and passing an offset. And maybe we don't want
     * to support negative offsets at all in the future (#20103).
     */
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

    tvbr.tvb.ws_tvb = ws_tvb;
    tvbr.tvb.generation = wslua_packet_generation;
    tvbr.offset = offset;
    tvbr.len = len;

    pushTvbRange(L,&tvbr);

    return true;
}


WSLUA_METHOD TvbRange_tvb(lua_State *L) {
    /* Creates a  new <<lua_class_Tvb,`Tvb`>> from a <<lua_class_TvbRange,`TvbRange`>>. */

    TvbRange tvbr = checkTvbRange(L,1);

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvb_bytes_exist(tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len)) {
        push_Tvb(L, tvb_new_subset_length(tvbr->tvb.ws_tvb,tvbr->offset,tvbr->len));
        return 1;
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            lua_pushinteger(L,tvb_get_uint8(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushinteger(L,tvb_get_ntohs(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushinteger(L,tvb_get_ntoh24(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushinteger(L,tvb_get_ntohl(tvbr->tvb.ws_tvb,tvbr->offset));
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            /* XXX unsigned anyway */
            lua_pushinteger(L,(lua_Integer)(unsigned)tvb_get_uint8(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushinteger(L,tvb_get_letohs(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushinteger(L,tvb_get_letoh24(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushinteger(L,tvb_get_letohl(tvbr->tvb.ws_tvb,tvbr->offset));
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            pushUInt64(L,tvb_get_uint8(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 2:
            pushUInt64(L,tvb_get_ntohs(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 3:
            pushUInt64(L,tvb_get_ntoh24(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 4:
            pushUInt64(L,tvb_get_ntohl(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 5:
            pushUInt64(L,tvb_get_ntoh40(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 6:
            pushUInt64(L,tvb_get_ntoh48(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 7:
            pushUInt64(L,tvb_get_ntoh56(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 8:
            pushUInt64(L,tvb_get_ntoh64(tvbr->tvb.ws_tvb,tvbr->offset));
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            pushUInt64(L,tvb_get_uint8(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 2:
            pushUInt64(L,tvb_get_letohs(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 3:
            pushUInt64(L,tvb_get_letoh24(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 4:
            pushUInt64(L,tvb_get_letohl(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 5:
            pushUInt64(L,tvb_get_letoh40(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 6:
            pushUInt64(L,tvb_get_letoh48(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 7:
            pushUInt64(L,tvb_get_letoh56(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 8:
            pushUInt64(L,tvb_get_letoh64(tvbr->tvb.ws_tvb,tvbr->offset));
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            lua_pushinteger(L,tvb_get_int8(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushinteger(L,tvb_get_ntohis(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushinteger(L,tvb_get_ntohi24(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushinteger(L,tvb_get_ntohil(tvbr->tvb.ws_tvb,tvbr->offset));
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            lua_pushinteger(L,tvb_get_int8(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushinteger(L,tvb_get_letohis(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushinteger(L,tvb_get_letohi24(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushinteger(L,tvb_get_letohil(tvbr->tvb.ws_tvb,tvbr->offset));
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            pushInt64(L,tvb_get_int8(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 2:
            pushInt64(L,tvb_get_ntohis(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 3:
            pushInt64(L,tvb_get_ntohi24(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 4:
            pushInt64(L,tvb_get_ntohil(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 5:
            pushInt64(L,tvb_get_ntohi40(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 6:
            pushInt64(L,tvb_get_ntohi48(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 7:
            pushInt64(L,tvb_get_ntohi56(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 8:
            pushInt64(L,tvb_get_ntohi64(tvbr->tvb.ws_tvb,tvbr->offset));
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 1:
            pushInt64(L,tvb_get_int8(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 2:
            pushInt64(L,tvb_get_letohis(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 3:
            pushInt64(L,tvb_get_letohi24(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 4:
            pushInt64(L,tvb_get_letohil(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 5:
            pushInt64(L,tvb_get_letohi40(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 6:
            pushInt64(L,tvb_get_letohi48(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 7:
            pushInt64(L,tvb_get_letohi56(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 8:
            pushInt64(L,tvb_get_letohi64(tvbr->tvb.ws_tvb,tvbr->offset));
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 4:
            lua_pushnumber(L,(double)tvb_get_ntohieee_float(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 8:
            lua_pushnumber(L,tvb_get_ntohieee_double(tvbr->tvb.ws_tvb,tvbr->offset));
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
    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    switch (tvbr->len) {
        case 4:
            lua_pushnumber(L,tvb_get_letohieee_float(tvbr->tvb.ws_tvb,tvbr->offset));
            return 1;
        case 8:
            lua_pushnumber(L,tvb_get_letohieee_double(tvbr->tvb.ws_tvb,tvbr->offset));
            WSLUA_RETURN(1); /* The floating point value. */
        default:
            luaL_error(L,"TvbRange:le_float() does not handle %d byte floating numbers",tvbr->len);
            return 0;
    }
}

WSLUA_METHOD TvbRange_ipv4(lua_State* L) {
    /* Get an IPv4 Address from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Address,`Address`>> object. */
    TvbRange tvbr = checkTvbRange(L,1);
    address addr;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 4) {
        WSLUA_ERROR(TvbRange_ipv4,"The range must be 4 octets long");
        return 0;
    }

    set_address_tvb(&addr,AT_IPv4,sizeof(uint32_t),tvbr->tvb.ws_tvb,tvbr->offset);
    pushAddress(L,&addr);

    WSLUA_RETURN(1); /* The IPv4 <<lua_class_Address,`Address`>> object. */
}

WSLUA_METHOD TvbRange_le_ipv4(lua_State* L) {
    /* Get an Little Endian IPv4 Address from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Address,`Address`>> object. */
    TvbRange tvbr = checkTvbRange(L,1);
    address addr;
    uint32_t ip_addr;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 4) {
        WSLUA_ERROR(TvbRange_ipv4,"The range must be 4 octets long");
        return 0;
    }

    ip_addr = GUINT32_SWAP_LE_BE(tvb_get_ipv4(tvbr->tvb.ws_tvb,tvbr->offset));
    set_address(&addr, AT_IPv4, sizeof(ip_addr), &ip_addr);
    pushAddress(L,&addr);

    WSLUA_RETURN(1); /* The IPv4 <<lua_class_Address,`Address`>> object. */
}

WSLUA_METHOD TvbRange_ipv6(lua_State* L) {
    /* Get an IPv6 Address from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Address,`Address`>> object. */
    TvbRange tvbr = checkTvbRange(L,1);
    address addr;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 16) {
        WSLUA_ERROR(TvbRange_ipv6,"The range must be 16 octets long");
        return 0;
    }

    set_address_tvb(&addr,AT_IPv6,16,tvbr->tvb.ws_tvb,tvbr->offset);
    pushAddress(L,&addr);

    WSLUA_RETURN(1); /* The IPv6 <<lua_class_Address,`Address`>> object. */
}

WSLUA_METHOD TvbRange_ether(lua_State* L) {
    /* Get an Ethernet Address from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_Address,`Address`>> object. */
    TvbRange tvbr = checkTvbRange(L,1);
    address addr;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len != 6) {
        WSLUA_ERROR(TvbRange_ether,"The range must be 6 bytes long");
        return 0;
    }

    set_address_tvb(&addr,AT_ETHER,6,tvbr->tvb.ws_tvb,tvbr->offset);
    pushAddress(L,&addr);

    WSLUA_RETURN(1); /* The Ethernet <<lua_class_Address,`Address`>> object. */
}

WSLUA_METHOD TvbRange_nstime(lua_State* L) {
    /* Obtain a time_t structure from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_NSTime,`NSTime`>> object. */
#define WSLUA_OPTARG_TvbRange_nstime_ENCODING 2 /* An optional ENC_* encoding value to use */
    TvbRange tvbr = checkTvbRange(L,1);
    nstime_t nstime;
    const unsigned encoding = (unsigned) luaL_optinteger(L, WSLUA_OPTARG_TvbRange_nstime_ENCODING, 0);

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (encoding & ~ENC_STR_TIME_MASK) {
        WSLUA_OPTARG_ERROR(TvbRange_nstime, ENCODING, "invalid encoding value");
        return 0;
    }

    if (encoding == 0) {
        if (tvbr->len == 4) {
          nstime.secs = tvb_get_ntohl(tvbr->tvb.ws_tvb, tvbr->offset);
          nstime.nsecs = 0;
        } else if (tvbr->len == 8) {
          nstime.secs = tvb_get_ntohl(tvbr->tvb.ws_tvb, tvbr->offset);
          nstime.nsecs = tvb_get_ntohl(tvbr->tvb.ws_tvb, tvbr->offset + 4);
        } else {
          WSLUA_ERROR(TvbRange_nstime,"The range must be 4 or 8 bytes long");
          return 0;
        }
        pushNSTime(L, &nstime);
        lua_pushinteger(L, tvbr->len);
    }
    else {
        unsigned endoff = 0;
        nstime_t *retval = tvb_get_string_time(tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len,
                                               encoding, &nstime, &endoff);
        if (!retval || endoff == 0) {
            /* push nil nstime and offset */
            lua_pushnil(L);
            lua_pushnil(L);
        }
        else {
            pushNSTime(L, &nstime);
            lua_pushinteger(L, endoff);
        }
    }

    WSLUA_RETURN(2); /* The <<lua_class_NSTime,`NSTime`>> object and number of bytes used, or nil on failure. */
}

WSLUA_METHOD TvbRange_le_nstime(lua_State* L) {
    /* Obtain a nstime from a <<lua_class_TvbRange,`TvbRange`>>, as an <<lua_class_NSTime,`NSTime`>> object. */
    TvbRange tvbr = checkTvbRange(L,1);
    nstime_t nstime;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len == 4) {
      nstime.secs = tvb_get_letohl(tvbr->tvb.ws_tvb, tvbr->offset);
      nstime.nsecs = 0;
    } else if (tvbr->len == 8) {
      nstime.secs = tvb_get_letohl(tvbr->tvb.ws_tvb, tvbr->offset);
      nstime.nsecs = tvb_get_letohl(tvbr->tvb.ws_tvb, tvbr->offset + 4);
    } else {
      WSLUA_ERROR(TvbRange_nstime,"The range must be 4 or 8 bytes long");
      return 0;
    }

    pushNSTime(L, &nstime);

    WSLUA_RETURN(1); /* The <<lua_class_NSTime,`NSTime`>> object. */
}

WSLUA_METHOD TvbRange_string(lua_State* L) {
    /* Obtain a string from a <<lua_class_TvbRange,`TvbRange`>>. */
#define WSLUA_OPTARG_TvbRange_string_ENCODING 2 /* The encoding to use. Defaults to ENC_ASCII. */
    TvbRange tvbr = checkTvbRange(L,1);
    unsigned encoding = (unsigned)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_string_ENCODING, ENC_ASCII|ENC_NA);
    char * str;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    str = (char*)tvb_get_string_enc(NULL,tvbr->tvb.ws_tvb,tvbr->offset,tvbr->len,encoding);
    lua_pushlstring(L, str, strlen(str));
    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* A string containing all bytes in the <<lua_class_TvbRange,`TvbRange`>> including all zeroes (e.g., "a\000bc\000"). */
}

static int TvbRange_ustring_any(lua_State* L, bool little_endian) {
    /* Obtain a UTF-16 encoded string from a <<lua_class_TvbRange,`TvbRange`>>. */
    TvbRange tvbr = checkTvbRange(L,1);
    char * str;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    str = (char*)tvb_get_string_enc(NULL,tvbr->tvb.ws_tvb,tvbr->offset,tvbr->len,(little_endian ? ENC_UTF_16|ENC_LITTLE_ENDIAN : ENC_UTF_16|ENC_BIG_ENDIAN));
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
    char *str = NULL;
    unsigned length;
    const char* error = NULL;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    /* XXX - This leaks outside the length of the TvbRange to scan the entire
     * underlying tvbuffer. It has always done that, but that does seem odd. */
    TRY {
        str = (char*)tvb_get_stringz_enc(NULL,tvbr->tvb.ws_tvb,tvbr->offset,&length,encoding);
    } CATCH(DissectorError) {
        /* Presumably an unsupported encoding */
        error = lua_pushstring(L, GET_MESSAGE);
    } CATCH_BOUNDS_ERRORS {
        error = lua_pushstring(L, "Out of bounds");
    } ENDTRY;

    if (error) {
        /* By converting the exceptions into Lua errors, we also add
         * the Lua traceback. */
        WSLUA_ERROR(TvbRange_stringz, lua_tostring(L, 1));
        return 0;
    }

    lua_pushstring(L, str);
    wmem_free(NULL, str);
    lua_pushinteger(L, length);

    WSLUA_RETURN(2); /* The string containing all bytes in the <<lua_class_TvbRange,`TvbRange`>> up to the first terminating zero, and the length of that string. */
}

WSLUA_METHOD TvbRange_strsize(lua_State* L) {
    /*
    Find the size of a zero terminated string from a <<lua_class_TvbRange,`TvbRange`>>.
    The size of the string includes the terminating zero. */
#define WSLUA_OPTARG_TvbRange_strsize_ENCODING 2 /* The encoding to use. Defaults to ENC_ASCII. */
    TvbRange tvbr = checkTvbRange(L,1);
    unsigned encoding = (unsigned)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_strsize_ENCODING, ENC_ASCII|ENC_NA);
    const char* error = NULL;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    /* XXX - This leaks outside the length of the TvbRange to scan the entire
     * underlying tvbuffer. It has always done that, but that does seem odd. */
    TRY {
        lua_pushinteger(L, tvb_strsize_enc(tvbr->tvb.ws_tvb, tvbr->offset, encoding));
    } CATCH(DissectorError) {
        /* Presumably an unsupported encoding */
        error = lua_pushstring(L, GET_MESSAGE);
    } CATCH_BOUNDS_ERRORS {
        error = lua_pushstring(L, "Out of bounds");
    } ENDTRY;

    if (error) {
        /* By converting the exceptions into Lua errors, we also add
         * the Lua traceback. */
        WSLUA_ERROR(TvbRange_strsize, lua_tostring(L, 1));
        return 0;
    }

    WSLUA_RETURN(1); /* Length of the zero terminated string. */
}


static int TvbRange_ustringz_any(lua_State* L, bool little_endian) {
    /* Obtain a zero terminated string from a TvbRange */
    unsigned count;
    TvbRange tvbr = checkTvbRange(L,1);
    int offset;
    gunichar2 uchar;
    char *str;

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    offset = tvbr->offset;
    do {
      if (!tvb_bytes_exist (tvbr->tvb.ws_tvb, offset, 2)) {
        luaL_error(L,"out of bounds");
        return 0;
      }
      /* Endianness doesn't matter when looking for null */
      uchar = tvb_get_ntohs (tvbr->tvb.ws_tvb, offset);
      offset += 2;
    } while (uchar != 0);

    str = (char*)tvb_get_stringz_enc(NULL,tvbr->tvb.ws_tvb,tvbr->offset,&count,
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


    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (encoding == 0) {
        ba = g_byte_array_new();
        raw = (uint8_t *)tvb_memdup(NULL,tvbr->tvb.ws_tvb,tvbr->offset,tvbr->len);
        g_byte_array_append(ba,raw,tvbr->len);
        wmem_free(NULL, raw);
        pushByteArray(L,ba);
        lua_pushinteger(L, tvbr->len);
    }
    else if ((encoding & ENC_STR_HEX) == 0) {
        WSLUA_OPTARG_ERROR(TvbRange_nstime, ENCODING, "invalid encoding value");
    }
    else {
        unsigned endoff = 0;
        GByteArray* retval;

        ba = g_byte_array_new();
        retval = tvb_get_string_bytes(tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len,
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
    unsigned pos = (unsigned)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_bitfield_POSITION,0);
    unsigned len = (unsigned)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_bitfield_LENGTH,1);

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if ((pos+len) > (tvbr->len<<3)) {
        luaL_error(L, "Requested bitfield out of range");
        return 0;
    }

    if (len <= 32) {
        /* XXX - If LUA_INTEGER_SIZE is 4 (on Lua 5.3/5.4 it's usually 8), then
         * for len == 32 an unsigned won't necessarily fit in a lua_Integer.
         * Should we use a UInt64 then?
         */
        WRAP_NON_LUA_EXCEPTIONS(
            lua_pushinteger(L,tvb_get_bits32(tvbr->tvb.ws_tvb,tvbr->offset*8 + pos, len, false));
        )
    } else if (len <= 64) {
        WRAP_NON_LUA_EXCEPTIONS(
            pushUInt64(L,tvb_get_bits64(tvbr->tvb.ws_tvb,tvbr->offset*8 + pos, len, false));
        )
    } else {
        luaL_error(L,"TvbRange:bitfield() does not handle %d bits",len);
        return 0;
    }

    WSLUA_RETURN(1); /* The bitfield value */
}

WSLUA_METHOD TvbRange_range(lua_State* L) {
    /* Creates a sub-<<lua_class_TvbRange,`TvbRange`>> from this <<lua_class_TvbRange,`TvbRange`>>. */
#define WSLUA_OPTARG_TvbRange_range_OFFSET 2 /* The offset (in octets) from the beginning of the <<lua_class_TvbRange,`TvbRange`>>. Defaults to 0. */
#define WSLUA_OPTARG_TvbRange_range_LENGTH 3 /* The length (in octets) of the range. Defaults to until the end of the <<lua_class_TvbRange,`TvbRange`>>. */

    TvbRange tvbr = checkTvbRange(L,1);
    int offset = (int)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_range_OFFSET,0);
    int len = (int)luaL_optinteger(L,WSLUA_OPTARG_TvbRange_range_LENGTH,-1);

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (offset < 0) {
        WSLUA_OPTARG_ERROR(TvbRange_range,OFFSET,"offset before start of TvbRange");
        return 0;
    }
    if ((unsigned)offset > tvbr->len) {
        WSLUA_OPTARG_ERROR(TvbRange_range,OFFSET,"offset beyond end of TvbRange");
        return 0;
    }

    if (len == -1) {
        len = tvbr->len - offset;
    }
    if (len < 0) {
        luaL_error(L,"out of bounds");
        return 0;
    } else if ( (unsigned)(len + offset) > tvbr->len) {
        luaL_error(L,"Range is out of bounds");
        return 0;
    }

    if (push_TvbRange(L,tvbr->tvb.ws_tvb,tvbr->offset+offset,len)) {
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
    uncompr_tvb = tvb_child_uncompress_zlib(tvbr->tvb.ws_tvb, tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

#ifdef HAVE_BROTLI
    uncompr_tvb = tvb_child_uncompress_brotli(tvbr->tvb.ws_tvb, tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    uncompr_tvb = tvb_child_uncompress_hpack_huff(tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    uncompr_tvb = tvb_child_uncompress_lz77(tvbr->tvb.ws_tvb, tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    uncompr_tvb = tvb_child_uncompress_lz77huff(tvbr->tvb.ws_tvb, tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    uncompr_tvb = tvb_child_uncompress_lznt1(tvbr->tvb.ws_tvb, tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

#ifdef HAVE_SNAPPY
    uncompr_tvb = tvb_child_uncompress_snappy(tvbr->tvb.ws_tvb, tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

#ifdef HAVE_ZSTD
    uncompr_tvb = tvb_child_uncompress_zstd(tvbr->tvb.ws_tvb, tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    decoded_tvb = base64_tvb_to_new_tvb(tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;

    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    decoded_tvb = base64uri_tvb_to_new_tvb(tvbr->tvb.ws_tvb, tvbr->offset, tvbr->len);
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

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }
    lua_pushinteger(L,(lua_Integer)tvbr->len);
    return 1;
}

WSLUA_METHOD TvbRange_offset(lua_State* L) {
    /* Obtain the offset in a <<lua_class_TvbRange,`TvbRange`>>. */
    TvbRange tvbr = checkTvbRange(L,1);

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
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

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (offset < 0) {
        WSLUA_OPTARG_ERROR(TvbRange_raw,OFFSET,"offset before start of TvbRange");
        return 0;
    }
    if ((unsigned)offset > tvbr->len) {
        WSLUA_OPTARG_ERROR(TvbRange_raw,OFFSET,"offset beyond end of TvbRange");
        return 0;
    }

    if (len == -1) {
        len = tvbr->len - offset;
    }
    if (len < 0) {
        luaL_error(L,"out of bounds");
        return false;
    } else if ( (unsigned)(len + offset) > tvbr->len) {
        luaL_error(L,"Range is out of bounds");
        return false;
    }

    lua_pushlstring(L, (const char*)tvb_get_ptr(tvbr->tvb.ws_tvb, tvbr->offset+offset, len), len);

    WSLUA_RETURN(1); /* A Lua string of the binary bytes in the <<lua_class_TvbRange,`TvbRange`>>. */
}

/* WSLUA_ATTRIBUTE TvbRange_length RO The length (in bytes) of the range.
   Mirrors `range:len()`. */
WSLUA_ATTRIBUTE_GET(TvbRange,length, {
    lua_pushinteger(L, (lua_Integer)obj->len);
});

/* WSLUA_ATTRIBUTE TvbRange_position RO The offset within the parent Tvb at
   which the range starts. Mirrors `range:offset()`. */
WSLUA_ATTRIBUTE_GET(TvbRange,position, {
    lua_pushinteger(L, (lua_Integer)obj->offset);
});

WSLUA_METAMETHOD TvbRange__eq(lua_State* L) {
    /* Checks whether the contents of two <<lua_class_TvbRange,`TvbRange`>>s are equal. */
    TvbRange tvb_l = checkTvbRange(L,1);
    TvbRange tvb_r = checkTvbRange(L,2);

    if (WSLUA_EXPIRED(&tvb_l->tvb) || WSLUA_EXPIRED(&tvb_r->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    /* it is not an error if their ds_tvb are different... they're just not equal */
    if (tvb_l->len == tvb_r->len &&
        tvb_l->len <= tvb_captured_length_remaining(tvb_l->tvb.ws_tvb, tvb_l->offset) &&
        tvb_r->len <= tvb_captured_length_remaining(tvb_r->tvb.ws_tvb, tvb_r->offset))
    {
        const char* lp = (const char*)tvb_get_ptr(tvb_l->tvb.ws_tvb, tvb_l->offset, tvb_l->len);
        const char* rp = (const char*)tvb_get_ptr(tvb_r->tvb.ws_tvb, tvb_r->offset, tvb_r->len);
        unsigned i = 0;

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
    Converts the <<lua_class_TvbRange,`TvbRange`>> into a string of
    the form `TvbRange: offset=<O> length=<L> bytes=<hex>`. The hex
    preview is truncated by `tvb_bytes_to_str` to a small number of
    bytes so the rendering stays useful in the debugger Variables
    view and in `print()` for large ranges. Empty ranges render as
    `TvbRange: offset=<O> length=0 (empty)`.
    */
    TvbRange tvbr = checkTvbRange(L,1);

    if (!tvbr) return 0;
    if (WSLUA_EXPIRED(&tvbr->tvb)) {
        luaL_error(L,"expired tvb");
        return 0;
    }

    if (tvbr->len == 0) {
        lua_pushfstring(L, "TvbRange: offset=%d length=0 (empty)",
                        tvbr->offset);
    } else {
        char *str = tvb_bytes_to_str(NULL, tvbr->tvb.ws_tvb,
                                     tvbr->offset, tvbr->len);
        lua_pushfstring(L, "TvbRange: offset=%d length=%d bytes=%s",
                        tvbr->offset, tvbr->len, str ? str : "");
        wmem_free(NULL, str);
    }

    WSLUA_RETURN(1); /* A short label including the offset, length,
                        and a truncated hex preview. */
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

/* Read-only attributes for debugger introspection; see the comment on
 * Tvb_attributes for the naming rationale. */
WSLUA_ATTRIBUTES TvbRange_attributes[] = {
    WSLUA_ATTRIBUTE_ROREG(TvbRange,length),
    WSLUA_ATTRIBUTE_ROREG(TvbRange,position),
    { NULL, NULL, NULL }
};

int TvbRange_register(lua_State* L) {
    WSLUA_REGISTER_CLASS_WITH_ATTRS_NOGC(TvbRange);
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
