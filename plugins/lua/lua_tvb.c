/*
 * lua_tvb.c
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

LUA_CLASS_DEFINE(Tvb,TVB,if (! *p) luaL_error(L,"null tvb"));
LUA_CLASS_DEFINE(ByteArray,BYTE_ARRAY,if (! *p) luaL_argerror(L,index,"null bytearray"));

static int ByteArray_new(lua_State* L) {
    GByteArray* ba = g_byte_array_new();

    if (lua_gettop(L) == 1) {
        const gchar* s = luaL_checkstring(L,1);
        
        if (!s) {
            luaL_argerror(L,1,"not a string");
            return 0;
        }
        
        /* XXX: slow! */
        int nibble[2];
        int i = 0;
        gchar c;
        
        for (; (c = *s); s++) {
            switch(c) {
                case '0': case '1': case '2': case '3': case '4': case '5' : case '6' : case '7': case '8' : case '9' :
                    nibble[(i++)%2] = c - '0';
                    break;
                case 'a': case 'b': case 'c': case 'd': case 'e': case 'f' :
                    nibble[(i++)%2] = c - 'a' + 0xa;
                    break;
                case 'A': case 'B': case 'C': case 'D': case 'E': case 'F' :
                    nibble[(i++)%2] = c - 'A' + 0xa;
                    break;
                default:
                    break;
            }

            if ( i == 2 ) {
                guint8 b = (guint8)(nibble[0] * 16 + nibble[1]);
                g_byte_array_append(ba,&b,1);
                i = 0;
            }
        }
    } 
    
    pushByteArray(L,ba);

    return 1;
}

static int ByteArray_gc(lua_State* L) {
    ByteArray ba = checkByteArray(L,1);

    if (!ba) return 0;
    
    g_byte_array_free(ba,TRUE);
    return 0;
}

static int ByteArray_append(lua_State* L) {
    ByteArray ba = checkByteArray(L,1);
    
    if (luaL_checkudata (L, 2, BYTE_ARRAY)) {
        ByteArray ba2 = checkByteArray(L,2);
        g_byte_array_append(ba,ba2->data,ba2->len);
    } else if (( lua_gettop(L) == 2 )) {
        int i = luaL_checkint(L,2);
        guint8 d;
        
        if (i < 0 || i > 255) {
            luaL_error(L,"Byte out of range");
            return 0;
        }
        
        d = (guint8)i;
        g_byte_array_append(ba,&d,1);
    } else {
        luaL_error(L,"ByteArray:append takes two arguments");
    }
    return 0;
}

static int ByteArray_preppend(lua_State* L) {
    ByteArray ba = checkByteArray(L,1);
    
    if (!ba) return 0;
    
    if (luaL_checkudata (L, 2, BYTE_ARRAY)) {
        ByteArray ba2 = checkByteArray(L,2);
        g_byte_array_prepend(ba,ba2->data,ba2->len);
    } else if (( lua_gettop(L) == 2 )) {
        int i = luaL_checkint(L,2);
        guint8 d;
        
        if (i < 0 || i > 255) luaL_error(L,"Byte out of range");
        
        d = (guint8)i;
        g_byte_array_prepend(ba,&d,1);
    } else {
        luaL_error(L,"ByteArray:preppend takes two arguments");
    }
    return 0;
}

static int ByteArray_set_size(lua_State* L) {
    ByteArray ba = checkByteArray(L,1);
    int siz = luaL_checkint(L,2);

    if (!ba) return 0;

    g_byte_array_set_size(ba,siz);
    return 0;
}

static int ByteArray_set_index(lua_State* L) {
    ByteArray ba = checkByteArray(L,1);
    int idx = luaL_checkint(L,2);
    int v = luaL_checkint(L,3);
    
    if (!ba) return 0;

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


static int ByteArray_get_index(lua_State* L) {
    ByteArray ba = checkByteArray(L,1);
    int idx = luaL_checkint(L,2);
    
    if (!ba) return 0;

    if (idx < 0 || (guint)idx >= ba->len) {
        luaL_argerror(L,2,"index out of range");
        return 0;
    }
    
    lua_pushnumber(L,(lua_Number)ba->data[idx]);
    
    return 1;
}

static int ByteArray_len(lua_State* L) {
    ByteArray ba = checkByteArray(L,1);
    
    if (!ba) return 0;
    
    lua_pushnumber(L,(lua_Number)ba->len);

    return 1;
}

static int ByteArray_subset(lua_State* L) {
    ByteArray ba = checkByteArray(L,1);
    int offset = luaL_checkint(L,2);
    int len = luaL_checkint(L,3);
    ByteArray ret;
    guint i;
    
    if (!ba) return 0;
    
    if ((offset + len) > (int)ba->len) {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }
    
    ret = g_byte_array_sized_new(len);
    
    for ( i=0 ; i < ba->len ; i++) {
        (ret->data)[i] =  (ba->data)[offset+i];
    }
    
    pushByteArray(L,ba);
    return 1;
}

static int ByteArray_tostring(lua_State* L) {
    static const gchar* byte_to_str[] = {
        "00","01","02","03","04","05","06","07","08","09","0A","0B","0C","0D","0E","0F",
        "10","11","12","13","14","15","16","17","18","19","1A","1B","1C","1D","1E","1F",
        "20","21","22","23","24","25","26","27","28","29","2A","2B","2C","2D","2E","2F",
        "30","31","32","33","34","35","36","37","38","39","3A","3B","3C","3D","3E","3F",
        "40","41","42","43","44","45","46","47","48","49","4A","4B","4C","4D","4E","4F",
        "50","51","52","53","54","55","56","57","58","59","5A","5B","5C","5D","5E","5F",
        "60","61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F",
        "70","71","72","73","74","75","76","77","78","79","7A","7B","7C","7D","7E","7F",
        "80","81","82","83","84","85","86","87","88","89","8A","8B","8C","8D","8E","8F",
        "90","91","92","93","94","95","96","97","98","99","9A","9B","9C","9D","9E","9F",
        "A0","A1","A2","A3","A4","A5","A6","A7","A8","A9","AA","AB","AC","AD","AE","AF",
        "B0","B1","B2","B3","B4","B5","B6","B7","B8","B9","BA","BB","BC","BD","BE","BF",
        "C0","C1","C2","C3","C4","C5","C6","C7","C8","C9","CA","CB","CC","CD","CE","CF",
        "D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","DA","DB","DC","DD","DE","DF",
        "E0","E1","E2","E3","E4","E5","E6","E7","E8","E9","EA","EB","EC","ED","EE","EF",
        "F0","F1","F2","F3","F4","F5","F6","F7","F8","F9","FA","FB","FC","FD","FE","FF"
    };
    ByteArray ba = checkByteArray(L,1);
    int i;
    GString* s;
    
    if (!ba) return 0;
    
    s = g_string_new("");
    
    for (i = 0; i < (int)ba->len; i++) {
        g_string_append(s,byte_to_str[(ba->data)[i]]);
    }
    
    lua_pushstring(L,s->str);
    g_string_free(s,TRUE);
    
    return 1;
}

static const luaL_reg ByteArray_methods[] = {
    {"new",           ByteArray_new},
    {"get_index", ByteArray_get_index},
    {"len", ByteArray_len},
    {"preppend", ByteArray_preppend},
    {"append", ByteArray_append},
    {"subset", ByteArray_subset},
    {"set", ByteArray_set_index},
    {"set_size", ByteArray_set_size},
    {0,0}
};

static const luaL_reg ByteArray_meta[] = {
    {"__gc",       ByteArray_gc},
    {"__tostring", ByteArray_tostring},
    {"__concat", ByteArray_append},
    {0, 0}
};

int ByteArray_register(lua_State* L) {
    luaL_openlib(L, BYTE_ARRAY, ByteArray_methods, 0);
    luaL_newmetatable(L, BYTE_ARRAY);
    luaL_openlib(L, 0, ByteArray_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
};


/*
 * Tvb class
 */


static int Tvb_new (lua_State *L) {
    ByteArray ba;

    if (!lua_tvb) {
        /* XXX: incomplete check, a tvb should only be used in the frame that created it */
        luaL_error(L,"Tvb can only be used in dissectors");
        return 0;
    }
        
    if (( luaL_checkudata(L,1,BYTE_ARRAY) )) {
        ba = toByteArray(L,1);
        const gchar* name = luaL_optstring(L,2,"Unnamed") ;
        guint8* data;
        
        if (! ba) return  0;
        
        data = g_memdup(ba->data, ba->len);
        
        Tvb tvb = tvb_new_real_data(data, ba->len,ba->len);
        tvb_set_free_cb(tvb, g_free);
        
        add_new_data_source(lua_pinfo, tvb, name);
        pushTvb(L,tvb);
        return 1;
    } else {
        Tvb tvb = checkTvb(L,1);
        int offset = luaL_optint(L, 2, 0);
        int len = luaL_optint(L, 3, -1);
        
        if (tvb_offset_exists(tvb, offset+len)) {
            pushTvb(L, tvb_new_subset(tvb,offset,len, len) );
            return 1;
        } else {
            luaL_error(L,"Out Of Bounds");
            return 0;
        }
    }
}



#define TVBGET_FN(type) Tvb_get_ ## type

#define DEFINE_TVBGET(type,len)  static int TVBGET_FN(type) (lua_State *L) { \
    tvbuff_t* tvb = checkTvb(L,1); \
    int offset = luaL_checkint(L,2); \
    if (!tvb) return 0; \
    if (!lua_pinfo) { luaL_error(L,"Tvb can only be used in dissectors"); return 0; } \
    if (tvb_offset_exists(tvb, offset+len)) { \
        lua_pushnumber(L, (lua_Number) tvb_get_ ## type(tvb,offset)); \
        return 1; \
    } else { \
        luaL_error(L,"Out Of Bounds"); \
        return 0; \
    } \
}


DEFINE_TVBGET(guint8,1);
DEFINE_TVBGET(ntohs,2);
DEFINE_TVBGET(ntoh24,3);
DEFINE_TVBGET(ntohl,4);
DEFINE_TVBGET(ntohieee_float,4);
DEFINE_TVBGET(ntohieee_double,8);

DEFINE_TVBGET(letohs,1);
DEFINE_TVBGET(letoh24,2);
DEFINE_TVBGET(letohl,3);
DEFINE_TVBGET(letohieee_float,4);
DEFINE_TVBGET(letohieee_double,8);

static int Tvb_get_bytearray(lua_State* L) {
    Tvb tvb = checkTvb(L,1);
    int offset = 0;
    int o_len;
    int len;
    ByteArray ba;
    
    if (!tvb) return 0;
    
    o_len = tvb_length(tvb);
    len = o_len;
    
    if (!lua_pinfo) {
        luaL_error(L,"Tvb can only be used in dissectors");
        return 0;
    }
    
    
    switch( lua_gettop(L) ) {
        case 3:
            offset = luaL_checkint(L,2);
            len = luaL_checkint(L,3);
            break;
        case 2:
            offset = luaL_checkint(L,2);
            len -= offset;
            break;
        case 1:
            break;
        default:
            luaL_error(L,"too many arguments");
            return 0;
    }
    
    if (len <  1 || offset+len > o_len) {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }
    
    ba = g_byte_array_new();
    g_byte_array_append(ba,ep_tvb_memdup(tvb,offset,len),len);
    
    pushByteArray(L,ba);
    
    return 1;
}

static int Tvb_get_stringz(lua_State* L) {
    Tvb tvb = checkTvb(L,1);
    int offset;
    int len;
    guint8* buf;
    
    if (!tvb) return 0;
    
    offset = luaL_checkint(L,2);
    
    if (!tvb_offset_exists(tvb, offset)) {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }
        
    len = tvb_length(tvb) - offset;
    buf = ep_alloc0(len+1);
    
    if (!lua_pinfo) {
        luaL_error(L,"Tvb can only be used in dissectors");
        return 0;
    }
    
    len = tvb_get_nstringz(tvb, offset, len, buf);
    
    lua_pushstring(L,(gchar*)buf);
    lua_pushnumber(L,(lua_Number)len);
    
    return 2;
}

static int Tvb_get_string(lua_State* L) {
    Tvb tvb = checkTvb(L,1);
    int offset;
    int len;

    if (!tvb) return 0;

    if (!lua_tvb) {
        luaL_error(L,"Tvb can only be used in dissectors");
        return 0;
    }
    
    offset = luaL_checkint(L,2);
    len = luaL_checkint(L,3);
    
    if ( ! tvb_offset_exists(tvb, offset+len)) {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }
    
    lua_pushstring(L,(gchar*)tvb_get_ephemeral_string(tvb,offset,len));
    
   return 1;
}

static int Tvb_tostring(lua_State* L) {
    Tvb tvb = checkTvb(L,1);
    int len;
    
    if (!tvb) return 0;

    len = tvb_length(tvb);
    gchar* str = ep_strdup_printf("TVB(%i) : %s",len,tvb_bytes_to_str(tvb,0,len));
    lua_pushstring(L,str);
    return 1;
}



static int Tvb_len(lua_State* L) {
    Tvb tvb = checkTvb(L,1);

    if (!tvb) return 0;
    
    if (!lua_pinfo) {
        luaL_error(L,"Tvb can only be used in dissectors");
        return 0;
    }
    
    lua_pushnumber(L,tvb_length(tvb));
    return 1;
}

static int Tvb_get_eth(lua_State* L) {
    Tvb tvb = checkTvb(L,1);
    int offset = luaL_checkint(L,2);
    Address addr;
    guint8* eth_addr;
    
    if (!tvb) return 0;
    
    if (tvb_offset_exists(tvb, offset+6)) {
        eth_addr = ep_tvb_memdup(tvb,offset,6);
        addr = g_malloc(sizeof(address));
        SET_ADDRESS(addr, AT_ETHER, 4, eth_addr);
        pushAddress(L,addr);
        return 1;
    } else {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }
    
}

static int Tvb_get_ipv4(lua_State* L) {
    Tvb tvb = checkTvb(L,1);
    int offset = luaL_checkint(L,2);
    Address addr;
    guint32 ip_addr;
    
    if (!tvb) return 0;

    if (tvb_offset_exists(tvb, offset+4)) {
        ip_addr = tvb_get_ipv4(tvb,offset);
        addr = g_malloc(sizeof(address));
        SET_ADDRESS(addr, AT_IPv4, 4, ip_addr);
        pushAddress(L,addr);
        return 1;
    } else {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }
    
}


static const luaL_reg Tvb_methods[] = {
    {"new",           Tvb_new},
    {"get_char", TVBGET_FN(guint8)},
    {"get_ntohs", TVBGET_FN(ntohs)},
    {"get_ntoh24", TVBGET_FN(ntoh24)},
    {"get_ntohl", TVBGET_FN(ntohl)},
    {"get_ntohfloat", TVBGET_FN(ntohieee_float)},
    {"get_ntohdouble", TVBGET_FN(ntohieee_double)},
    {"get_letohs", TVBGET_FN(letohs)},
    {"get_letoh24", TVBGET_FN(letoh24)},
    {"get_letohl", TVBGET_FN(letohl)},
    {"get_letohl", TVBGET_FN(letohl)},
    {"get_letohfloat", TVBGET_FN(letohieee_float)},
    {"get_letohdouble", TVBGET_FN(letohieee_double)},
    {"get_stringz", Tvb_get_stringz },
    {"get_string", Tvb_get_string },
    {"get_bytearray",Tvb_get_bytearray},
    {"get_ipv4", Tvb_get_ipv4 },
    {"get_eth",Tvb_get_eth },    
#if 0
    {"get_ipv6",Tvb_get_ipv6 },
#endif
    {"len", Tvb_len},
    {0,0}
};

static const luaL_reg Tvb_meta[] = {
    {"__tostring", Tvb_tostring},
    {0, 0}
};

int Tvb_register(lua_State* L) {
    luaL_openlib(L, TVB, Tvb_methods, 0);
    luaL_newmetatable(L, TVB);
    luaL_openlib(L, 0, Tvb_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
};

