/*
 * A Lua userdata object for 64-bit signed/unsigned integers.
 *
 * I, Hadriel Kaplan, the author of wslua_int6464.c, wish to put it in
 * the Public Domain.  That is not universally accepted, however,
 * so you may license it under the FreeBSD License instead, which is an open
 * source license approved for GPL use as well as commercial etc.
 * It's even less restrictive than the MIT license, because it requires
 * no attribution anywhere - I don't *want* attribution.

Copyright (C) 2013 Hadriel Kaplan <hadrielk@yahoo.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the FreeBSD Project.
*/

#include "config.h"

#include "wslua.h"

/* WSLUA_MODULE Int64 Handling 64-bit Integers

  Lua uses one single number representation which can be chosen at compile time and since
  it is often set to IEEE 754 double precision floating point, one cannot store a 64 bit integer
  with full precision.

  For details, see [[http://wiki.wireshark.org/LuaAPI/Int64]].
 */

#define LUATYPE64_STRING_SIZE 21  /* string to hold 18446744073709551615 */


WSLUA_CLASS_DEFINE_BASE(Int64,NOP,NOP,0);
/*
  `Int64` represents a 64 bit signed integer.

  For details, see [[http://wiki.wireshark.org/LuaAPI/Int64]].
 */

/* A checkInt64 but that also auto-converts numbers, strings, and UINT64 to a gint64 */
static gint64 getInt64(lua_State *L, int i)
{
    gchar *end = NULL;
    (void) end;
    switch (lua_type(L,i))
    {
        case LUA_TNUMBER:
            return wslua_checkgint64(L,i);
        case LUA_TSTRING:
            return g_ascii_strtoll(luaL_checkstring(L,i),&end,10);
        case LUA_TUSERDATA:
            if (isUInt64(L, i)) {
                return (Int64) toUInt64(L, i);
            }
            /* fall through */
        default:
            return checkInt64(L,i);
        }
}


/* Encodes Int64 userdata into Lua string struct with given endianness */
void Int64_pack(lua_State* L, luaL_Buffer *b, gint idx, gboolean asLittleEndian) {
    gint64 value = checkInt64(L,idx);
    gint8 buff[sizeof(gint64)];

    if (asLittleEndian) {
        guint i;
        for (i = 0; i < sizeof(gint64); i++) {
            buff[i] = (value & 0xff);
            value >>= 8;
        }
    }
    else {
        gint i;
        for (i = sizeof(gint64) - 1; i >= 0; i--) {
            buff[i] = (value & 0xff);
            value >>= 8;
        }
    }
    luaL_addlstring(b, (char*)buff, sizeof(gint64));
}

WSLUA_METHOD Int64_encode(lua_State* L) {
    /* Encodes the `Int64` number into an 8-byte Lua string, using given endianness.
       @since 1.11.3
     */
#define WSLUA_OPTARG_Int64_encode_ENDIAN 2 /* If set to true then little-endian is used,
                                              if false then big-endian; if missing/nil,
                                              native host endian. */
    luaL_Buffer b;
    gboolean asLittleEndian = (G_BYTE_ORDER == G_LITTLE_ENDIAN)? TRUE : FALSE;

    if (lua_gettop(L) >= WSLUA_OPTARG_Int64_encode_ENDIAN) {
        if (lua_type(L,WSLUA_OPTARG_Int64_encode_ENDIAN) == LUA_TBOOLEAN)
            asLittleEndian = lua_toboolean(L,WSLUA_OPTARG_Int64_encode_ENDIAN);
    }

    luaL_buffinit(L, &b);

    Int64_pack(L, &b, 1, asLittleEndian);

    luaL_pushresult(&b);
    WSLUA_RETURN(1); /* The Lua string. */
}

/* Decodes from string buffer struct into Int64 userdata, with given endianness */
int Int64_unpack(lua_State* L, const gchar *buff, gboolean asLittleEndian) {
    gint64 value = 0;
    gint i;

    if (asLittleEndian) {
        for (i = sizeof(gint64) - 1; i >= 0; i--) {
            value <<= 8;
            value |= (gint64)(guchar)buff[i];
        }
    }
    else {
        for (i = 0; i < (gint) sizeof(gint64); i++) {
            value <<= 8;
            value |= (gint64)(guchar)buff[i];
        }
    }

    pushInt64(L,value);
    return 1;
}

WSLUA_CONSTRUCTOR Int64_decode(lua_State* L) {
    /* Decodes an 8-byte Lua string, using given endianness, into a new `Int64` object.
       @since 1.11.3
     */
#define WSLUA_ARG_Int64_decode_STRING 1 /* The Lua string containing a binary 64-bit integer. */
#define WSLUA_OPTARG_Int64_decode_ENDIAN 2 /* If set to true then little-endian is used,
                                              if false then big-endian; if missing/nil, native
                                              host endian. */
    gboolean asLittleEndian = (G_BYTE_ORDER == G_LITTLE_ENDIAN)? TRUE : FALSE;
    size_t len = 0;
    const gchar *s = luaL_checklstring(L, WSLUA_ARG_Int64_decode_STRING, &len);

    if (lua_gettop(L) >= WSLUA_OPTARG_Int64_decode_ENDIAN) {
        if (lua_type(L,WSLUA_OPTARG_Int64_decode_ENDIAN) == LUA_TBOOLEAN)
            asLittleEndian = lua_toboolean(L,WSLUA_OPTARG_Int64_decode_ENDIAN);
    }

    if (len == sizeof(gint64)) {
        Int64_unpack(L, s, asLittleEndian);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The `Int64` object created, or nil on failure. */
}

WSLUA_CONSTRUCTOR Int64_new(lua_State* L) {
    /* Creates a `Int64` Object.
       @since 1.11.3
     */
#define WSLUA_OPTARG_Int64_new_VALUE 1 /* A number, `UInt64`, `Int64`, or string of ASCII digits
                                          to assign the value of the new `Int64` (default=0). */
#define WSLUA_OPTARG_Int64_new_HIGHVALUE 2 /* If this is a number and the first argument was
                                              a number, then the first will be treated as a
                                              lower 32-bits, and this is the high-order 32
                                              bit number. */
    gint64 value = 0;

    if (lua_gettop(L) >= 1) {
        switch(lua_type(L, WSLUA_OPTARG_Int64_new_VALUE)) {
            case LUA_TNUMBER:
                value = wslua_togint64(L, WSLUA_OPTARG_Int64_new_VALUE);
                if (lua_gettop(L) == 2 &&
                    lua_type(L, WSLUA_OPTARG_Int64_new_HIGHVALUE) == LUA_TNUMBER) {
                    gint64 h = wslua_togint64(L, WSLUA_OPTARG_Int64_new_HIGHVALUE);
                    value &= G_GUINT64_CONSTANT(0x00000000FFFFFFFF);
                    h <<= 32; h &= G_GUINT64_CONSTANT(0xFFFFFFFF00000000);
                    value += h;
                }
                break;
            case LUA_TSTRING:
            case LUA_TUSERDATA:
                value = getInt64(L,WSLUA_OPTARG_Int64_new_VALUE);
                break;
            default:
                WSLUA_OPTARG_ERROR(Int64_new,VALUE,"must be a number, UInt64, Int64, or string");
                break;
        }
    }

    pushInt64(L,value);

    WSLUA_RETURN(1); /* The new `Int64` object. */
}

WSLUA_METAMETHOD Int64__call(lua_State* L) {
    /* Creates a `Int64` Object.
       @since 1.11.3
     */
    lua_remove(L,1); /* remove the table */
    WSLUA_RETURN(Int64_new(L)); /* The new `Int64` object. */
}

WSLUA_CONSTRUCTOR Int64_max(lua_State* L) {
    /* Gets the max possible value.
       @since 1.11.3
     */
    pushInt64(L, G_MAXINT64);
    WSLUA_RETURN(1); /* The new `Int64` object of the max value. */
}

WSLUA_CONSTRUCTOR Int64_min(lua_State* L) {
    /* Gets the min possible value.
       @since 1.11.3
     */
    pushInt64(L, G_MININT64);
    WSLUA_RETURN(1); /* The new `Int64` object of the min value. */
}


WSLUA_METHOD Int64_tonumber(lua_State* L) {
    /* Returns a Lua number of the `Int64` value - this may lose precision.
       @since 1.11.3
     */
    lua_pushnumber(L, (lua_Number)(checkInt64(L,1)));
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_CONSTRUCTOR Int64_fromhex(lua_State* L) {
    /* Creates an `Int64` object from the given hex string.
       @since 1.11.3
     */
#define WSLUA_ARG_Int64_fromhex_HEX 1 /* The hex-ascii Lua string. */
    guint64 result = 0;
    size_t len = 0;
    const gchar *s = luaL_checklstring(L,WSLUA_ARG_Int64_fromhex_HEX,&len);

    if (s && len > 0) {
        sscanf(s, "%" G_GINT64_MODIFIER "x", &result);
    }
    pushInt64(L,(gint64)result);
    WSLUA_RETURN(1); /* The new `Int64` object. */
}

WSLUA_METHOD Int64_tohex(lua_State* L) {
    /* Returns a hex string of the `Int64` value.
       @since 1.11.3
     */
#define WSLUA_OPTARG_Int64_new_NUMBYTES 2 /* The number of hex-chars/nibbles to generate,
                                             negative means uppercase (default=16). */
    gint64 b = getInt64(L,1);
    gint n = luaL_optint(L, WSLUA_OPTARG_Int64_new_NUMBYTES, 16);
    const gchar *hexdigits = "0123456789abcdef";
    gchar buf[16];
    gint i;
    if (n < 0) { n = -n; hexdigits = "0123456789ABCDEF"; }
    if (n > 16) n = 16;
    for (i = n-1; i >= 0; --i) { buf[i] = hexdigits[b & 15]; b >>= 4; }
    lua_pushlstring(L, buf, (size_t)n);
    WSLUA_RETURN(1); /* The string hex. */
}

WSLUA_METHOD Int64_higher(lua_State* L) {
    /* Returns a Lua number of the higher 32-bits of the `Int64` value. (negative `Int64`
       will return a negative Lua number).
       @since 1.11.3
     */
    gint64 num = getInt64(L,1);
    gint64 b = num;
    lua_Number n = 0;
    if (b < 0) b = -b; /* masking/shifting negative int64 isn't working on some platforms */
    b &= G_GUINT64_CONSTANT(0x7FFFFFFF00000000);
    b >>= 32;
    n = (lua_Number)(guint32)(b & G_GUINT64_CONSTANT(0x00000000FFFFFFFFF));
    if (num < 0) n = -n;
    lua_pushnumber(L,n);
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METHOD Int64_lower(lua_State* L) {
    /* Returns a Lua number of the lower 32-bits of the `Int64` value. (always positive).
       @since 1.11.3
     */
    gint64 b = getInt64(L,1);
    if (b < 0) b = -b; /* masking/shifting negative int64 isn't working on some platforms */
    lua_pushnumber(L,(guint32)(b & G_GUINT64_CONSTANT(0x00000000FFFFFFFFF)));
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METAMETHOD Int64__tostring(lua_State* L) {
    /* Converts the `Int64` into a string of decimal digits. */
    gint64 num = getInt64(L,1);
    gchar s[LUATYPE64_STRING_SIZE];
    if (g_snprintf(s, LUATYPE64_STRING_SIZE, "%" G_GINT64_MODIFIER "d", num) < 0) {
        return luaL_error(L, "Error writing Int64 to a string");
    }
    lua_pushstring(L,s);
    WSLUA_RETURN(1); /* The Lua string. */
}

WSLUA_METAMETHOD Int64__unm(lua_State* L) {
    /* Returns the negative of the `Int64`, in a new `Int64`.
       @since 1.11.3
     */
    pushInt64(L,-(getInt64(L,1)));
    WSLUA_RETURN(1); /* The new `Int64`. */
}

#define WSLUA_MATH_OP_FUNC(obj,op) \
    /* use the 'get' form so we can accept numbers as well */ \
    obj num1 = get##obj(L,1); \
    obj num2 = get##obj(L,2); \
    push##obj(L,(num1) op (num2)); \
    return 1

WSLUA_METAMETHOD Int64__add(lua_State* L) {
    /* Adds two `Int64` together and returns a new one (this may wrap the value).
       @since 1.11.3
     */
    WSLUA_MATH_OP_FUNC(Int64,+);
}

WSLUA_METAMETHOD Int64__sub(lua_State* L) {
    /* Subtracts two `Int64` and returns a new one (this may wrap the value).
       @since 1.11.3
     */
    WSLUA_MATH_OP_FUNC(Int64,-);
}

WSLUA_METAMETHOD Int64__mul(lua_State* L) {
    /* Multiplies two `Int64` and returns a new one (this may truncate the value).
       @since 1.11.3
     */
    WSLUA_MATH_OP_FUNC(Int64,*);
}

WSLUA_METAMETHOD Int64__div(lua_State* L) {
    /* Divides two `Int64` and returns a new one (integer divide, no remainder).
       Trying to divide by zero results in a Lua error.
       @since 1.11.3
     */
    Int64 num1 = getInt64(L,1);
    Int64 num2 = getInt64(L,2);
    if (num2 == 0) {
        return luaL_error(L, "Trying to divide Int64 by zero");
    }
    pushInt64(L, num1 / num2);
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METAMETHOD Int64__mod(lua_State* L) {
    /* Divides two `Int64` and returns a new one of the remainder.
       Trying to modulo by zero results in a Lua error.
       @since 1.11.3
     */
    Int64 num1 = getInt64(L,1);
    Int64 num2 = getInt64(L,2);
    if (num2 == 0) {
        return luaL_error(L, "Trying to modulo Int64 by zero");
    }
    pushInt64(L, num1 % num2);
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METAMETHOD Int64__pow(lua_State* L) {
    /* The first `Int64` is taken to the power of the second `Int64`, returning a new
       one (this may truncate the value).
       @since 1.11.3
     */
    gint64 num1 = getInt64(L,1);
    gint64 num2 = getInt64(L,2);
    gint64 result;
    if (num1 == 2) {
        result = (num2 >= 8 * (gint64) sizeof(gint64)) ? 0 : ((gint64)1 << num2);
    }
    else {
        for (result = 1; num2 > 0; num2 >>= 1) {
            if (num2 & 1) result *= num1;
            num1 *= num1;
        }
    }
    pushInt64(L,result);
    WSLUA_RETURN(1); /* The `Int64` object. */
}

#define WSLUA_COMP_OP_FUNC(obj,op) \
    obj num1 = get##obj(L,1); \
    obj num2 = get##obj(L,2); \
    lua_pushboolean(L,(num1) op (num2)); \
    return 1

WSLUA_METAMETHOD Int64__eq(lua_State* L) {
    /* Returns true if both `Int64` are equal.
       @since 1.11.3
     */
    WSLUA_COMP_OP_FUNC(Int64,==);
}

WSLUA_METAMETHOD Int64__lt(lua_State* L) {
    /* Returns true if first `Int64` < second.
       @since 1.11.3
     */
    WSLUA_COMP_OP_FUNC(Int64,<);
}

WSLUA_METAMETHOD Int64__le(lua_State* L) {
    /* Returns true if first `Int64` <= second.
       @since 1.11.3
     */
    WSLUA_COMP_OP_FUNC(Int64,<=);
}

WSLUA_METHOD Int64_bnot(lua_State* L) {
    /* Returns a `Int64` of the bitwise 'not' operation.
       @since 1.11.3
     */
    pushInt64(L,~(getInt64(L,1)));
    WSLUA_RETURN(1); /* The `Int64` object. */
}

#define WSLUA_BIT_OP_FUNC(obj,op) \
    gint32 i; \
    obj num = get##obj(L,1); \
    for (i = lua_gettop(L); i > 1; i--) { \
        num op get##obj(L,i); \
    } \
    push##obj(L,num); \
    return 1

WSLUA_METHOD Int64_band(lua_State* L) {
    /* Returns a `Int64` of the bitwise 'and' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
       @since 1.11.3
     */
    WSLUA_BIT_OP_FUNC(Int64,&=);
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METHOD Int64_bor(lua_State* L) {
    /* Returns a `Int64` of the bitwise 'or' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
       @since 1.11.3
     */
    WSLUA_BIT_OP_FUNC(Int64,|=);
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METHOD Int64_bxor(lua_State* L) {
    /* Returns a `Int64` of the bitwise 'xor' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
       @since 1.11.3
     */
    WSLUA_BIT_OP_FUNC(Int64,^=);
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METHOD Int64_lshift(lua_State* L) {
    /* Returns a `Int64` of the bitwise logical left-shift operation, by the given
       number of bits.
       @since 1.11.3
     */
#define WSLUA_ARG_Int64_lshift_NUMBITS 2 /* The number of bits to left-shift by. */
    guint64 b = (guint64) getInt64(L,1);
    guint32 n = wslua_checkguint32(L,WSLUA_ARG_Int64_lshift_NUMBITS);
    pushInt64(L,(gint64)(b << n));
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METHOD Int64_rshift(lua_State* L) {
    /* Returns a `Int64` of the bitwise logical right-shift operation, by the
       given number of bits.
       @since 1.11.3
     */
#define WSLUA_ARG_Int64_rshift_NUMBITS 2 /* The number of bits to right-shift by. */
    guint64 b = (guint64) getInt64(L,1);
    guint32 n = wslua_checkguint32(L,WSLUA_ARG_Int64_rshift_NUMBITS);
    pushInt64(L,(gint64)(b >> n));
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METHOD Int64_arshift(lua_State* L) {
    /* Returns a `Int64` of the bitwise arithmetic right-shift operation, by the
       given number of bits.
       @since 1.11.3
     */
#define WSLUA_ARG_Int64_arshift_NUMBITS 2 /* The number of bits to right-shift by. */
    gint64 b = getInt64(L,1);
    gint32 n = wslua_checkgint32(L,WSLUA_ARG_Int64_arshift_NUMBITS);
    pushInt64(L,(b >> n));
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METHOD Int64_rol(lua_State* L) {
    /* Returns a `Int64` of the bitwise left rotation operation, by the given number of
       bits (up to 63).
       @since 1.11.3
     */
#define WSLUA_ARG_Int64_rol_NUMBITS 2 /* The number of bits to roll left by. */
    guint64 b = (guint64) getInt64(L,1);
    guint32 n = wslua_checkguint32(L,WSLUA_ARG_Int64_rol_NUMBITS);
    pushInt64(L,(gint64)((b << n) | (b >> (64-n))));
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METHOD Int64_ror(lua_State* L) {
    /* Returns a `Int64` of the bitwise right rotation operation, by the given number of
       bits (up to 63).
       @since 1.11.3
     */
#define WSLUA_ARG_Int64_ror_NUMBITS 2 /* The number of bits to roll right by. */
    guint64 b = (guint64) getInt64(L,1);
    guint32 n = wslua_checkguint32(L,WSLUA_ARG_Int64_ror_NUMBITS);
    pushInt64(L,(gint64)((b << (64-n)) | (b >> n)));
    WSLUA_RETURN(1); /* The `Int64` object. */
}

WSLUA_METHOD Int64_bswap(lua_State* L) {
    /* Returns a `Int64` of the bytes swapped. This can be used to convert little-endian
       64-bit numbers to big-endian 64 bit numbers or vice versa.
       @since 1.11.3
     */
    guint64 b = (guint64) getInt64(L,1);
    guint64 result = 0;
    size_t i;
    for (i = 0; i < sizeof(gint64); i++) {
        result <<= 8;
        result |= (b & G_GUINT64_CONSTANT(0x00000000000000FF));
        b >>= 8;
    }
    pushInt64(L,(gint64)result);
    WSLUA_RETURN(1); /* The `Int64` object. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META. */
static int Int64__gc(lua_State* L _U_) {
    return 0;
}

WSLUA_METHODS Int64_methods[] = {
    WSLUA_CLASS_FNREG(Int64,new),
    WSLUA_CLASS_FNREG(Int64,max),
    WSLUA_CLASS_FNREG(Int64,min),
    WSLUA_CLASS_FNREG(Int64,tonumber),
    WSLUA_CLASS_FNREG(Int64,fromhex),
    WSLUA_CLASS_FNREG(Int64,tohex),
    WSLUA_CLASS_FNREG(Int64,higher),
    WSLUA_CLASS_FNREG(Int64,lower),
    WSLUA_CLASS_FNREG(Int64,encode),
    WSLUA_CLASS_FNREG(Int64,decode),
    WSLUA_CLASS_FNREG(Int64,bnot),
    WSLUA_CLASS_FNREG(Int64,band),
    WSLUA_CLASS_FNREG(Int64,bor),
    WSLUA_CLASS_FNREG(Int64,bxor),
    WSLUA_CLASS_FNREG(Int64,lshift),
    WSLUA_CLASS_FNREG(Int64,rshift),
    WSLUA_CLASS_FNREG(Int64,arshift),
    WSLUA_CLASS_FNREG(Int64,rol),
    WSLUA_CLASS_FNREG(Int64,ror),
    WSLUA_CLASS_FNREG(Int64,bswap),
    { NULL, NULL }
};

WSLUA_META Int64_meta[] = {
    WSLUA_CLASS_MTREG(Int64,tostring),
    WSLUA_CLASS_MTREG(Int64,call),
    WSLUA_CLASS_MTREG(wslua,concat),
    WSLUA_CLASS_MTREG(Int64,unm),
    WSLUA_CLASS_MTREG(Int64,add),
    WSLUA_CLASS_MTREG(Int64,sub),
    WSLUA_CLASS_MTREG(Int64,mul),
    WSLUA_CLASS_MTREG(Int64,div),
    WSLUA_CLASS_MTREG(Int64,mod),
    WSLUA_CLASS_MTREG(Int64,pow),
    WSLUA_CLASS_MTREG(Int64,eq),
    WSLUA_CLASS_MTREG(Int64,lt),
    WSLUA_CLASS_MTREG(Int64,le),
    { NULL, NULL }
};

LUALIB_API int Int64_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(Int64);
    return 0;
}



WSLUA_CLASS_DEFINE_BASE(UInt64,NOP,NOP,0);
/* `UInt64` represents a 64 bit unsigned integer, similar to `Int64`.

   For details, see: http://wiki.wireshark.org/LuaAPI/`Int64`.
*/

/* A checkUInt64 but that also auto-converts numbers, strings, and `Int64` to a guint64. */
static guint64 getUInt64(lua_State *L, int i)
{
    gchar *end = NULL;
    (void) end;
    switch (lua_type(L,i))
    {
        case LUA_TNUMBER:
            return wslua_checkguint64(L,i);
        case LUA_TSTRING:
            return g_ascii_strtoull(luaL_checkstring(L,i), &end, 10);
        case LUA_TUSERDATA:
            if (isInt64(L, i)) {
                return (UInt64) toInt64(L, i);
            }
            /* fall through */
        default:
            return checkUInt64(L,i);
        }
}

/* Encodes `UInt64` userdata into Lua string struct with given endianness */
void UInt64_pack(lua_State* L, luaL_Buffer *b, gint idx, gboolean asLittleEndian) {
    guint64 value = checkUInt64(L,idx);
    gint8 buff[sizeof(guint64)];

    if (asLittleEndian) {
        guint i;
        for (i = 0; i < sizeof(guint64); i++) {
            buff[i] = (value & 0xff);
            value >>= 8;
        }
    }
    else {
        gint i;
        for (i = sizeof(guint64) - 1; i >= 0; i--) {
            buff[i] = (value & 0xff);
            value >>= 8;
        }
    }
    luaL_addlstring(b, (char*)buff, sizeof(guint64));
}

WSLUA_METHOD UInt64_encode(lua_State* L) {
    /* Encodes the `UInt64` number into an 8-byte Lua binary string, using given endianness.
       @since 1.11.3
     */
#define WSLUA_OPTARG_UInt64_encode_ENDIAN 2 /* If set to true then little-endian is used,
                                               if false then big-endian; if missing/nil,
                                               native host endian. */
    luaL_Buffer b;
    gboolean asLittleEndian = (G_BYTE_ORDER == G_LITTLE_ENDIAN)? TRUE : FALSE;

    if (lua_gettop(L) >= 2) {
        if (lua_type(L,2) == LUA_TBOOLEAN)
            asLittleEndian = lua_toboolean(L,2);
    }

    luaL_buffinit(L, &b);

    UInt64_pack(L, &b, 1, asLittleEndian);

    luaL_pushresult(&b);
    WSLUA_RETURN(1); /* The Lua binary string. */
}

/* Decodes from string buffer struct into `UInt64` userdata, with given endianness. */
int UInt64_unpack(lua_State* L, const gchar *buff, gboolean asLittleEndian) {
    guint64 value = 0;
    gint i;

    if (asLittleEndian) {
        for (i = sizeof(guint64) - 1; i >= 0; i--) {
            value <<= 8;
            value |= (guint64)(guchar)buff[i];
        }
    }
    else {
        for (i = 0; i < (gint) sizeof(guint64); i++) {
            value <<= 8;
            value |= (guint64)(guchar)buff[i];
        }
    }

    pushUInt64(L,value);
    return 1;
}

WSLUA_CONSTRUCTOR UInt64_decode(lua_State* L) {
    /* Decodes an 8-byte Lua binary string, using given endianness, into a new `UInt64` object.
       @since 1.11.3
     */
#define WSLUA_ARG_UInt64_decode_STRING 1 /* The Lua string containing a binary 64-bit integer. */
#define WSLUA_OPTARG_UInt64_decode_ENDIAN 2 /* If set to true then little-endian is used,
                                               if false then big-endian; if missing/nil,
                                               native host endian. */
    gboolean asLittleEndian = (G_BYTE_ORDER == G_LITTLE_ENDIAN)? TRUE : FALSE;
    size_t len = 0;
    const gchar *s = luaL_checklstring(L, WSLUA_ARG_UInt64_decode_STRING, &len);

    if (lua_gettop(L) >= WSLUA_OPTARG_UInt64_decode_ENDIAN) {
        if (lua_type(L,WSLUA_OPTARG_UInt64_decode_ENDIAN) == LUA_TBOOLEAN)
            asLittleEndian = lua_toboolean(L,WSLUA_OPTARG_UInt64_decode_ENDIAN);
    }

    if (len == sizeof(guint64)) {
        UInt64_unpack(L, s, asLittleEndian);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The `UInt64` object created, or nil on failure. */
}

WSLUA_CONSTRUCTOR UInt64_new(lua_State* L) {
    /* Creates a `UInt64` Object.
       @since 1.11.3
     */
#define WSLUA_OPTARG_UInt64_new_VALUE 1 /* A number, `UInt64`, `Int64`, or string of digits
                                           to assign the value of the new `UInt64` (default=0). */
#define WSLUA_OPTARG_UInt64_new_HIGHVALUE 2 /* If this is a number and the first argument was
                                               a number, then the first will be treated as a
                                               lower 32-bits, and this is the high-order
                                               32-bit number. */
    guint64 value = 0;

    if (lua_gettop(L) >= 1) {
        switch(lua_type(L, WSLUA_OPTARG_UInt64_new_VALUE)) {
            case LUA_TNUMBER:
                value = wslua_toguint64(L, WSLUA_OPTARG_UInt64_new_VALUE);
                 if (lua_gettop(L) == 2 &&
                     lua_type(L, WSLUA_OPTARG_UInt64_new_HIGHVALUE) == LUA_TNUMBER) {
                    guint64 h = wslua_toguint64(L, WSLUA_OPTARG_UInt64_new_HIGHVALUE);
                    value &= G_GUINT64_CONSTANT(0x00000000FFFFFFFF);
                    h <<= 32; h &= G_GUINT64_CONSTANT(0xFFFFFFFF00000000);
                    value += h;
                }
               break;
            case LUA_TSTRING:
            case LUA_TUSERDATA:
                value = getUInt64(L, WSLUA_OPTARG_UInt64_new_VALUE);
                break;
            default:
                WSLUA_OPTARG_ERROR(UInt64_new,VALUE,"must be a number, UInt64, Int64, or string");
                break;
        }
    }

    pushUInt64(L,value);

    WSLUA_RETURN(1); /* The new `UInt64` object. */
}

WSLUA_METAMETHOD UInt64__call(lua_State* L) {
    /* Creates a `UInt64` Object.
       @since 1.11.3
     */
    lua_remove(L,1); /* remove the table */
    WSLUA_RETURN(UInt64_new(L)); /* The new `UInt64` object. */
}

WSLUA_CONSTRUCTOR UInt64_max(lua_State* L) {
    /* Gets the max possible value.
       @since 1.11.3
     */
    pushUInt64(L,G_MAXUINT64);
    WSLUA_RETURN(1); /* The max value. */
}

WSLUA_CONSTRUCTOR UInt64_min(lua_State* L) {
    /* Gets the min possible value (i.e., 0).
       @since 1.11.3
     */
    pushUInt64(L,0);
    WSLUA_RETURN(1); /* The min value. */
}

WSLUA_METHOD UInt64_tonumber(lua_State* L) {
    /* Returns a Lua number of the `UInt64` value - this may lose precision.
       @since 1.11.3
     */
    lua_pushnumber(L,(lua_Number)(checkUInt64(L,1)));
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METAMETHOD UInt64__tostring(lua_State* L) {
    /* Converts the `UInt64` into a string. */
    guint64 num = getUInt64(L,1);
    gchar s[LUATYPE64_STRING_SIZE];
    if (g_snprintf(s, LUATYPE64_STRING_SIZE, "%" G_GINT64_MODIFIER "u",(guint64)num) < 0) {
        return luaL_error(L, "Error writing UInt64 to a string");
    }
    lua_pushstring(L,s);
    WSLUA_RETURN(1); /* The Lua string. */
}

WSLUA_CONSTRUCTOR UInt64_fromhex(lua_State* L) {
    /* Creates a `UInt64` object from the given hex string.
       @since 1.11.3
     */
#define WSLUA_ARG_UInt64_fromhex_HEX 1 /* The hex-ascii Lua string. */
    guint64 result = 0;
    size_t len = 0;
    const gchar *s = luaL_checklstring(L,WSLUA_ARG_UInt64_fromhex_HEX,&len);

    if (s && len > 0) {
        sscanf(s, "%" G_GINT64_MODIFIER "x", &result);
    }
    pushUInt64(L,result);
    WSLUA_RETURN(1); /* The new `UInt64` object. */
}

WSLUA_METHOD UInt64_tohex(lua_State* L) {
    /* Returns a hex string of the `UInt64` value.
       @since 1.11.3
     */
#define WSLUA_OPTARG_UInt64_new_NUMBYTES 2 /* The number of hex-chars/nibbles to generate,
                                              negative means uppercase (default=16). */
    guint64 b = getUInt64(L,1);
    gint n = luaL_optint(L, WSLUA_OPTARG_UInt64_new_NUMBYTES, 16);
    const gchar *hexdigits = "0123456789abcdef";
    gchar buf[16];
    gint i;
    if (n < 0) { n = -n; hexdigits = "0123456789ABCDEF"; }
    if (n > 16) n = 16;
    for (i = n-1; i >= 0; --i) { buf[i] = hexdigits[b & 15]; b >>= 4; }
    lua_pushlstring(L, buf, (size_t)n);
    WSLUA_RETURN(1); /* The string hex. */
}

WSLUA_METHOD UInt64_higher(lua_State* L) {
    /* Returns a Lua number of the higher 32-bits of the `UInt64` value. */
    guint64 num = getUInt64(L,1);
    guint64 b = num;
    lua_Number n = 0;
    b &= G_GUINT64_CONSTANT(0xFFFFFFFF00000000);
    b >>= 32;
    n = (lua_Number)(guint32)(b & G_GUINT64_CONSTANT(0x00000000FFFFFFFFF));
    lua_pushnumber(L,n);
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METHOD UInt64_lower(lua_State* L) {
    /* Returns a Lua number of the lower 32-bits of the `UInt64` value. */
    guint64 b = getUInt64(L,1);
    lua_pushnumber(L,(guint32)(b & G_GUINT64_CONSTANT(0x00000000FFFFFFFFF)));
    WSLUA_RETURN(1); /* The Lua number. */
}

WSLUA_METAMETHOD UInt64__unm(lua_State* L) {
    /* Returns the `UInt64`, in a new `UInt64`, since unsigned integers can't be negated.
       @since 1.11.3
     */
    pushUInt64(L,getUInt64(L,1));
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METAMETHOD UInt64__add(lua_State* L) {
    /* Adds two `UInt64` together and returns a new one (this may wrap the value).
       @since 1.11.3
     */
    WSLUA_MATH_OP_FUNC(UInt64,+);
}

WSLUA_METAMETHOD UInt64__sub(lua_State* L) {
    /* Subtracts two `UInt64` and returns a new one (this may wrap the value).
       @since 1.11.3
     */
    WSLUA_MATH_OP_FUNC(UInt64,-);
}

WSLUA_METAMETHOD UInt64__mul(lua_State* L) {
    /* Multiplies two `UInt64` and returns a new one (this may truncate the value).
       @since 1.11.3
     */
    WSLUA_MATH_OP_FUNC(UInt64,*);
}

WSLUA_METAMETHOD UInt64__div(lua_State* L) {
    /* Divides two `UInt64` and returns a new one (integer divide, no remainder).
       Trying to divide by zero results in a Lua error.
       @since 1.11.3
     */
    UInt64 num1 = getUInt64(L,1);
    UInt64 num2 = getUInt64(L,2);
    if (num2 == 0) {
        return luaL_error(L, "Trying to divide UInt64 by zero");
    }
    pushUInt64(L, num1 / num2);
    WSLUA_RETURN(1); /* The `UInt64` result. */
}

WSLUA_METAMETHOD UInt64__mod(lua_State* L) {
    /* Divides two `UInt64` and returns a new one of the remainder.
       Trying to modulo by zero results in a Lua error.
       @since 1.11.3
     */
    UInt64 num1 = getUInt64(L,1);
    UInt64 num2 = getUInt64(L,2);
    if (num2 == 0) {
        return luaL_error(L, "Trying to modulo UInt64 by zero");
    }
    pushUInt64(L, num1 % num2);
    WSLUA_RETURN(1); /* The `UInt64` result. */
}

WSLUA_METAMETHOD UInt64__pow(lua_State* L) {
    /* The first `UInt64` is taken to the power of the second `UInt64`/number,
       returning a new one (this may truncate the value).
       @since 1.11.3
     */
    guint64 num1 = getUInt64(L,1);
    guint64 num2 = getUInt64(L,2);
    guint64 result;
    if (num1 == 2) {
        result = (num2 >= 8 * (guint64) sizeof(guint64)) ? 0 : ((guint64)1 << num2);
    }
    else {
        for (result = 1; num2 > 0; num2 >>= 1) {
            if (num2 & 1) result *= num1;
            num1 *= num1;
        }
    }
    pushUInt64(L,result);
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METAMETHOD UInt64__eq(lua_State* L) {
    /* Returns true if both `UInt64` are equal.
       @since 1.11.3
     */
    WSLUA_COMP_OP_FUNC(UInt64,==);
}

WSLUA_METAMETHOD UInt64__lt(lua_State* L) {
    /* Returns true if first `UInt64` < second.
       @since 1.11.3
     */
    WSLUA_COMP_OP_FUNC(UInt64,<);
}

WSLUA_METAMETHOD UInt64__le(lua_State* L) {
    /* Returns true if first `UInt64` <= second.
       @since 1.11.3
     */
    WSLUA_COMP_OP_FUNC(UInt64,<=);
}

WSLUA_METHOD UInt64_bnot(lua_State* L) {
    /* Returns a `UInt64` of the bitwise 'not' operation.
       @since 1.11.3
     */
    pushUInt64(L,~(getUInt64(L,1)));
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METHOD UInt64_band(lua_State* L) {
    /* Returns a `UInt64` of the bitwise 'and' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
       @since 1.11.3
     */
    WSLUA_BIT_OP_FUNC(UInt64,&=);
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METHOD UInt64_bor(lua_State* L) {
    /* Returns a `UInt64` of the bitwise 'or' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
       @since 1.11.3
     */
    WSLUA_BIT_OP_FUNC(UInt64,|=);
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METHOD UInt64_bxor(lua_State* L) {
    /* Returns a `UInt64` of the bitwise 'xor' operation, with the given number/`Int64`/`UInt64`.
       Note that multiple arguments are allowed.
       @since 1.11.3
     */
    WSLUA_BIT_OP_FUNC(UInt64,^=);
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METHOD UInt64_lshift(lua_State* L) {
    /* Returns a `UInt64` of the bitwise logical left-shift operation, by the
       given number of bits.
       @since 1.11.3
     */
#define WSLUA_ARG_UInt64_lshift_NUMBITS 2 /* The number of bits to left-shift by. */
    guint64 b = getUInt64(L,1);
    guint32 n = wslua_checkguint32(L,WSLUA_ARG_UInt64_lshift_NUMBITS);
    pushUInt64(L,(b << n));
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METHOD UInt64_rshift(lua_State* L) {
    /* Returns a `UInt64` of the bitwise logical right-shift operation, by the
       given number of bits.
       @since 1.11.3
     */
#define WSLUA_ARG_UInt64_rshift_NUMBITS 2 /* The number of bits to right-shift by. */
    guint64 b = getUInt64(L,1);
    guint32 n = wslua_checkguint32(L,WSLUA_ARG_UInt64_rshift_NUMBITS);
    pushUInt64(L,(b >> n));
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METHOD UInt64_arshift(lua_State* L) {
    /* Returns a `UInt64` of the bitwise arithmetic right-shift operation, by the
       given number of bits.
       @since 1.11.3
     */
#define WSLUA_ARG_UInt64_arshift_NUMBITS 2 /* The number of bits to right-shift by. */
    guint64 b = getUInt64(L,1);
    guint32 n = wslua_checkguint32(L,WSLUA_ARG_UInt64_arshift_NUMBITS);
    pushUInt64(L,(b >> n));
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METHOD UInt64_rol(lua_State* L) {
    /* Returns a `UInt64` of the bitwise left rotation operation, by the
       given number of bits (up to 63).
       @since 1.11.3
     */
#define WSLUA_ARG_UInt64_rol_NUMBITS 2 /* The number of bits to roll left by. */
    guint64 b = getUInt64(L,1);
    guint32 n = wslua_checkguint32(L,WSLUA_ARG_UInt64_rol_NUMBITS);
    pushUInt64(L,((b << n) | (b >> (64-n))));
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METHOD UInt64_ror(lua_State* L) {
    /* Returns a `UInt64` of the bitwise right rotation operation, by the
       given number of bits (up to 63).
       @since 1.11.3
     */
#define WSLUA_ARG_UInt64_ror_NUMBITS 2 /* The number of bits to roll right by. */
    guint64 b = getUInt64(L,1);
    guint32 n = wslua_checkguint32(L,WSLUA_ARG_UInt64_ror_NUMBITS);
    pushUInt64(L,((b << (64-n)) | (b >> n)));
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

WSLUA_METHOD UInt64_bswap(lua_State* L) {
    /* Returns a `UInt64` of the bytes swapped. This can be used to convert little-endian
       64-bit numbers to big-endian 64 bit numbers or vice versa.
       @since 1.11.3
     */
    guint64 b = getUInt64(L,1);
    guint64 result = 0;
    size_t i;
    for (i = 0; i < sizeof(guint64); i++) {
        result <<= 8;
        result |= (b & G_GUINT64_CONSTANT(0x00000000000000FF));
        b >>= 8;
    }
    pushUInt64(L,result);
    WSLUA_RETURN(1); /* The `UInt64` object. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int UInt64__gc(lua_State* L _U_) {
    return 0;
}

WSLUA_METHODS UInt64_methods[] = {
    WSLUA_CLASS_FNREG(UInt64,new),
    WSLUA_CLASS_FNREG(UInt64,max),
    WSLUA_CLASS_FNREG(UInt64,min),
    WSLUA_CLASS_FNREG(UInt64,tonumber),
    WSLUA_CLASS_FNREG(UInt64,fromhex),
    WSLUA_CLASS_FNREG(UInt64,tohex),
    WSLUA_CLASS_FNREG(UInt64,higher),
    WSLUA_CLASS_FNREG(UInt64,lower),
    WSLUA_CLASS_FNREG(UInt64,encode),
    WSLUA_CLASS_FNREG(UInt64,decode),
    WSLUA_CLASS_FNREG(UInt64,bnot),
    WSLUA_CLASS_FNREG(UInt64,band),
    WSLUA_CLASS_FNREG(UInt64,bor),
    WSLUA_CLASS_FNREG(UInt64,bxor),
    WSLUA_CLASS_FNREG(UInt64,lshift),
    WSLUA_CLASS_FNREG(UInt64,rshift),
    WSLUA_CLASS_FNREG(UInt64,arshift),
    WSLUA_CLASS_FNREG(UInt64,rol),
    WSLUA_CLASS_FNREG(UInt64,ror),
    WSLUA_CLASS_FNREG(UInt64,bswap),
    { NULL, NULL }
};

WSLUA_META UInt64_meta[] = {
    WSLUA_CLASS_MTREG(UInt64,tostring),
    WSLUA_CLASS_MTREG(UInt64,call),
    WSLUA_CLASS_MTREG(wslua,concat),
    WSLUA_CLASS_MTREG(UInt64,unm),
    WSLUA_CLASS_MTREG(UInt64,add),
    WSLUA_CLASS_MTREG(UInt64,sub),
    WSLUA_CLASS_MTREG(UInt64,mul),
    WSLUA_CLASS_MTREG(UInt64,div),
    WSLUA_CLASS_MTREG(UInt64,mod),
    WSLUA_CLASS_MTREG(UInt64,pow),
    WSLUA_CLASS_MTREG(UInt64,eq),
    WSLUA_CLASS_MTREG(UInt64,lt),
    WSLUA_CLASS_MTREG(UInt64,le),
    { NULL, NULL }
};

LUALIB_API int UInt64_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(UInt64);
    return 0;
}
