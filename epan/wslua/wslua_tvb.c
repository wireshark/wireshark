/*
 * wslua_tvb.c
 *
 * Wireshark's interface to the Lua Programming Language
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

/* WSLUA_MODULE Tvb functions for handling packet data */

#include "wslua.h"

WSLUA_CLASS_DEFINE(ByteArray,FAIL_ON_NULL("null bytearray"),NOP);

WSLUA_CONSTRUCTOR ByteArray_new(lua_State* L) { /* creates a ByteArray Object */
#define WSLUA_OPTARG_ByteArray_new_HEXBYTES 1 /* A string consisting of hexadecimal bytes like "00 B1 A2" or "1a2b3c4d" */
    GByteArray* ba = g_byte_array_new();
    const gchar* s;
    int nibble[2];
    int i = 0;
    gchar c;

    if (lua_gettop(L) == 1) {
        s = luaL_checkstring(L,WSLUA_OPTARG_ByteArray_new_HEXBYTES);
        
        if (!s) {
            WSLUA_OPTARG_ERROR(ByteArray_new,HEXBYTES,"must be a string");
            return 0;
        }
        
        /* XXX: slow! */
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

    WSLUA_RETURN(1); /* The new ByteArray object. */
}

static int ByteArray_gc(lua_State* L) {
    ByteArray ba = checkByteArray(L,1);

    if (!ba) return 0;
    
    g_byte_array_free(ba,TRUE);
    return 0;
}

WSLUA_METAMETHOD ByteArray__concat(lua_State* L) {
	/* concatenate two ByteArrays */
#define WSLUA_ARG_ByteArray__cat_FIRST 1
#define WSLUA_ARG_ByteArray__cat_SECOND 1
	
    ByteArray ba = checkByteArray(L,1);
    ByteArray ba2 = checkByteArray(L,2);

	if (! (ba  && ba2) )
		WSLUA_ERROR(ByteArray__cat,"both arguments must be ByteArrays");
	
    g_byte_array_append(ba,ba2->data,ba2->len);

    pushByteArray(L,ba);
    WSLUA_RETURN(1); /* The new composite ByteArray. */
}

WSLUA_METHOD ByteArray_prepend(lua_State* L) {
	/* prepend a ByteArray to this ByteArray */
#define WSLUA_ARG_ByteArray_prepend_PREPENDED 2
    ByteArray ba = checkByteArray(L,1);
    ByteArray ba2 = checkByteArray(L,2);
    
	if (! (ba  && ba2) )
		WSLUA_ERROR(ByteArray_prepend,"both arguments must be ByteArrays");

    g_byte_array_prepend(ba,ba2->data,ba2->len);
    
    pushByteArray(L,ba);
    return 1;
}

WSLUA_METHOD ByteArray_append(lua_State* L) {
	/* append a ByteArray to this ByteArray */
#define WSLUA_ARG_ByteArray_append_APPENDED 2
    ByteArray ba = checkByteArray(L,1);
    ByteArray ba2 = checkByteArray(L,2);
    
	if (! (ba  && ba2) )
		WSLUA_ERROR(ByteArray_prepend,"both arguments must be ByteArrays");
	
    g_byte_array_prepend(ba,ba2->data,ba2->len);
    
    pushByteArray(L,ba);
    return 1;
}

WSLUA_METHOD ByteArray_set_size(lua_State* L) {
	/* Sets the size of a ByteArray, either truncating it or filling it with zeros. */
#define WSLUA_ARG_ByteArray_set_size_SIZE 2

    ByteArray ba = checkByteArray(L,1);
    int siz = luaL_checkint(L,2);

    if (!ba) return 0;

    g_byte_array_set_size(ba,siz);
    return 0;
}

WSLUA_METHOD ByteArray_set_index(lua_State* L) {
	/* sets the value of an index of a ByteArray. */
#define WSLUA_ARG_ByteArray_set_index_INDEX 2 /* the position of the byte to be set */
#define WSLUA_ARG_ByteArray_set_index_VALUE 3 /* the char value to set [0-255] */
    ByteArray ba = checkByteArray(L,1);
    int idx = luaL_checkint(L,2);
    int v = luaL_checkint(L,3);
    
    if (!ba) return 0;

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
	/* get the value of a byte in a ByteArray */
#define WSLUA_ARG_ByteArray_set_index_INDEX 2 /* the position of the byte to be set */
    ByteArray ba = checkByteArray(L,1);
    int idx = luaL_checkint(L,2);
    
    if (!ba) return 0;
    
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
	/* obtain the length of a ByteArray */
    ByteArray ba = checkByteArray(L,1);
    
    if (!ba) return 0;
    
    lua_pushnumber(L,(lua_Number)ba->len);

    WSLUA_RETURN(1); /* The length of the ByteArray. */
}

WSLUA_METHOD ByteArray_subset(lua_State* L) {
	/* obtain a segment of a ByteArray */
#define WSLUA_ARG_ByteArray_set_index_OFFSET 2 /* the position of the first byte */
#define WSLUA_ARG_ByteArray_set_index_LENGTH 2 /* the lenght of the segment */
    ByteArray ba = checkByteArray(L,1);
    int offset = luaL_checkint(L,2);
    int len = luaL_checkint(L,3);
    ByteArray sub;

    if (!ba) return 0;
    
    if ((offset + len) > (int)ba->len || offset < 0 || len < 1) {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }

    sub = g_byte_array_new();
    g_byte_array_append(sub,ba->data + offset,len);
    
    pushByteArray(L,sub);
    
    WSLUA_RETURN(1); /* a ByteArray contaning the requested segment. */
}

static int ByteArray_tostring(lua_State* L) {
	/* obtain a string containing the bytes in a ByteArray so that it can be used in display filters (e.g. "01:23:45:67:89:AB") */
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
    
    WSLUA_RETURN(1); /* a string contaning a representaion of the ByteArray. */
}

static int Tvb_new_real (lua_State *L);

static const luaL_reg ByteArray_methods[] = {
    {"new", ByteArray_new},
    {"len", ByteArray_len},
    {"prepend", ByteArray_prepend},
    {"append", ByteArray_append},
    {"subset", ByteArray_subset},
    {"set_size", ByteArray_set_size},
    {"tvb", Tvb_new_real},
    {"get_index", ByteArray_get_index},
    {"set_index", ByteArray_set_index},
    {0,0}
};

static const luaL_reg ByteArray_meta[] = {
    {"__tostring", ByteArray_tostring},
    {"__gc",       ByteArray_gc},
    {"__concat", ByteArray__concat},
    {"__call",ByteArray_subset},
    {0, 0}
};

int ByteArray_register(lua_State* L) {
	WSLUA_REGISTER_CLASS(ByteArray);
    return 1;
}


/*
 * Tvb & TvbRange
 *
 * a Tvb represents a tvbuff_t in Lua. 
 * a TvbRange represents a range in a tvb (tvb,offset,lenght) it's main purpose is to do bounds checking, 
 *            it helps too simplifing argument passing to Tree. In wireshark terms this is worthless nothing
 *            not already done by the TVB itself. In lua's terms is necessary to avoid abusing TRY{}CATCH(){}
 *            via preemptive bounds checking. 
 *
 * These lua objects have to be "NULLified after use", that is, we cannot leave pointers in the
 * lua machine to a tvb or a tvbr that might exist anymore. 
 *
 * To do so we are going to keep a pointer to every "box" in which lua has placed a pointer to our object 
 * and then NULLify the object lua points to.
 *
 * Other than that we are going to check every instance of a potentialy NULLified object before using it
 * and report an error to the lua machine if it happens to be NULLified.
 */

WSLUA_CLASS_DEFINE(Tvb,FAIL_ON_NULL("expired tvb"),NOP);
/* a Tvb represents the packet's buffer. It is passed as an argument to listeners and dissectors,
and can be used to extract information (via TvbRange) from the packet's data. Beware that Tvbs are usable only by the current
listener or dissector call and are destroyed as soon as the listener/dissector returns, so references
to them are unusable once the function has returned. 
To create a tvbrange the tvb must be called with offset and length as optional arguments ( the offset defaults to 0 and the length to tvb:len() )*/

static GPtrArray* outstanding_stuff = NULL;

#define PUSH_TVB(L,t) g_ptr_array_add(outstanding_stuff,pushTvb(L,t))
#define PUSH_TVBRANGE(L,t) g_ptr_array_add(outstanding_stuff,pushTvbRange(L,t))

void clear_outstanding_tvbs(void) {
    while (outstanding_stuff->len) {
        void** p = (void**)g_ptr_array_remove_index_fast(outstanding_stuff,0);
        *p = NULL;
    }
}

void* push_Tvb(lua_State* L, Tvb tvb) {
    void** p = (void**)pushTvb(L,tvb);
    g_ptr_array_add(outstanding_stuff,p);
	return p;
}



/*
 * Tvb_new_real(bytearray,name)
 */
WSLUA_CONSTRUCTOR Tvb_new_real (lua_State *L) {
	/* Creates a new Tvb from a bytearray (it gets added to the current frame too) */
#define WSLUA_ARG_Tvb_new_real_BYTEARRAY 1 /* The data source for this Tvb. */
#define WSLUA_ARG_Tvb_new_real_NAME 2 /* The name to be given to the new data-source. */
    ByteArray ba = checkByteArray(L,1);
    const gchar* name = luaL_optstring(L,2,"Unnamed") ;
    guint8* data;
    Tvb tvb;
    
    if (!ba) return 0;
    
    if (!lua_tvb) {
        luaL_error(L,"Tvbs can only be created and used in dissectors");
        return 0;
    }
    
    data = g_memdup(ba->data, ba->len);
    
    tvb = tvb_new_real_data(data, ba->len,ba->len);
    tvb_set_free_cb(tvb, g_free);
    
    add_new_data_source(lua_pinfo, tvb, name);
    PUSH_TVB(L,tvb);
    WSLUA_RETURN(1); /* the created Tvb. */
}

WSLUA_CONSTRUCTOR Tvb_new_subset (lua_State *L) {
	/* creates a (sub)Tvb from using a TvbRange */
#define WSLUA_ARG_Tvb_new_subset_RANGE 2 /* the TvbRange from which to create the new Tvb. */

    TvbRange tvbr = checkTvbRange(L,1);
    
    if (! tvbr) return 0;
        
    if (tvb_offset_exists(tvbr->tvb,  tvbr->offset + tvbr->len -1 )) {
        PUSH_TVB(L, tvb_new_subset(tvbr->tvb,tvbr->offset,tvbr->len, tvbr->len) );
        return 1;
    } else {
        luaL_error(L,"Out Of Bounds");
        return 0;
    }
}

WSLUA_METAMETHOD Tvb__tostring(lua_State* L) {
	/* convert the bytes of a Tvb into a string, to be used for debugging purposes as '...' will be appended in case the string is too long. */
    Tvb tvb = checkTvb(L,1);
    int len;
    gchar* str;
    
    if (!tvb) return 0;

    len = tvb_length(tvb);
    str = ep_strdup_printf("TVB(%i) : %s",len,tvb_bytes_to_str(tvb,0,len));
    lua_pushstring(L,str);
    WSLUA_RETURN(1); /* the string. */
}


WSLUA_METHOD Tvb_len(lua_State* L) {
	/* obtain the length of a TVB */
    Tvb tvb = checkTvb(L,1);
    
    if (!tvb) return 0;
    
    lua_pushnumber(L,tvb_length(tvb));
    WSLUA_RETURN(1); /* the lenght of the Tvb. */
}

WSLUA_METHOD Tvb_offset(lua_State* L) {
	/* returns the raw offset (from the beginning of the source Tvb) of a sub Tvb. */
    Tvb tvb = checkTvb(L,1);
    
    if (!tvb) return 0;
        
    lua_pushnumber(L,TVB_RAW_OFFSET(tvb));
    WSLUA_RETURN(1); /* the raw offset of the Tvb. */
}


static const luaL_reg Tvb_methods[] = {
    {"len", Tvb_len},
    {"offset", Tvb_offset},
    {0,0}
};

static int Tvb_range(lua_State* L);
#if USED_FOR_DOC_PURPOSES
WSLUA_METAMETHOD Tvb__call(lua_State* L) {
	/* equivalent to tvb:range(...) */
	return 0
}
#endif

static const luaL_reg Tvb_meta[] = {
    {"__call", Tvb_range},
    {"__tostring", Tvb__tostring},
    {0, 0}
};

int Tvb_register(lua_State* L) {
	WSLUA_REGISTER_CLASS(Tvb);
    return 1;
}

WSLUA_CLASS_DEFINE(TvbRange,FAIL_ON_NULL("expired tvbrange"),NOP);
/*
 *  a TvbRange represents an usable range of a Tvb and is used to extract data from the Tvb that generated it
 * TvbRanges are created by calling a tvb (e.g. tvb(offset,lenght)). If the TvbRange span is outside the Tvb's range the creation will cause a runtime error.
 */

TvbRange new_TvbRange(lua_State* L, tvbuff_t* tvb, int offset, int len) {
    TvbRange tvbr;
    
    if (len == -1) {
        len = tvb_length_remaining(tvb,offset);
        if (len < 0) {
            luaL_error(L,"out of bounds");
            return 0;
        }        
    } else if ( (guint)(len + offset) > tvb_length(tvb)) {
        luaL_error(L,"Range is out of bounds");
        return NULL;
    }
    
    tvbr = ep_alloc(sizeof(struct _wslua_tvbrange));
    tvbr->tvb = tvb;
    tvbr->offset = offset;
    tvbr->len = len;
    
    return tvbr;
}

WSLUA_METHOD Tvb_range(lua_State* L) {
	/* creates a tvbr from this Tvb. This is used also as the Tvb:__call() metamethod. */
#define WSLUA_OPTARG_Tvb_range_OFFSET 2 /* The offset (in octets) from the begining of the Tvb. Defaults to 0. */
#define WSLUA_OPTARG_Tvb_range_LENGTH 2 /* The length (in octets) of the range. Defaults to until the end of the Tvb. */
	
    Tvb tvb = checkTvb(L,1);
    int offset = luaL_optint(L,2,0);
    int len = luaL_optint(L,3,-1);
    TvbRange tvbr;

    if (!tvb) return 0;

    if ((tvbr = new_TvbRange(L,tvb,offset,len))) {
        PUSH_TVBRANGE(L,tvbr);
		WSLUA_RETURN(1); /* the TvbRange */
    }
    
    return 0;
}


/*
 *  read access to tvbr's data
 */
static int TvbRange_get_index(lua_State* L) {
	/* WSLUA_ATTRIBUTE TvbRange_tvb RO The Tvb from which this TvbRange was generated */	
	/* WSLUA_ATTRIBUTE TvbRange_len RW The lenght (in octets) of this TvbRange */	
	/* WSLUA_ATTRIBUTE TvbRange_offset RW The offset (in octets) of this TvbRange */

    TvbRange tvbr = checkTvbRange(L,1);
    const gchar* index = luaL_checkstring(L,2);
    
    if (!(tvbr && index)) return 0;
    
    if (g_str_equal(index,"offset")) {
        lua_pushnumber(L,(lua_Number)tvbr->offset);
        return 1;
    } else if (g_str_equal(index,"len")) {
        lua_pushnumber(L,(lua_Number)tvbr->len);
        return 1;
    } else if (g_str_equal(index,"tvb")) {
        PUSH_TVB(L,tvbr->tvb);
        return 1;
    } else {
        luaL_error(L,"TvbRange has no `%s' attribute",index);
    }
    
    return 0;
}

/*
 *  write access to tvbr's data
 */
static int TvbRange_set_index(lua_State* L) {
    TvbRange tvbr = checkTvbRange(L,1);
    const gchar* index = luaL_checkstring(L,2);

    if (!tvbr) return 0;
    
    if (g_str_equal(index,"offset")) {
        int offset = (int)lua_tonumber(L,3);
    
        if ( (guint)(tvbr->len + offset) > tvb_length(tvbr->tvb)) {
            luaL_error(L,"out of bounds");
            return 0;
        } else {
            tvbr->offset = offset;
            PUSH_TVBRANGE(L,tvbr);
            return 1;
        }
    } else if (g_str_equal(index,"len")) {
        int len = (int)lua_tonumber(L,3);
        
        if ( (guint)(tvbr->offset + len) > tvb_length(tvbr->tvb)) {
            luaL_error(L,"out of bounds");
            return 0;
        } else {
            tvbr->len = len;
            PUSH_TVBRANGE(L,tvbr);
            return 1;
        }
    } else {
        luaL_error(L,"cannot set `%s' attribute on TvbRange",index);
        return 0;
    }
    
    return 0;
}

/*
 *  get a Blefuscuoan unsigned integer from a tvb
 */
WSLUA_METHOD TvbRange_get_uint(lua_State* L) {
	/* get a Big Endian (network order) unsigned integer from a TvbRange. The range must be 1, 2, 3 or 4 octets long.
	There's no support yet for 64 bit integers*/
    TvbRange tvbr = checkTvbRange(L,1);
    if (!tvbr) return 0;
    
    switch (tvbr->len) {
        case 1:
            lua_pushnumber(L,tvb_get_guint8(tvbr->tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushnumber(L,tvb_get_ntohs(tvbr->tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushnumber(L,tvb_get_ntoh24(tvbr->tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushnumber(L,tvb_get_ntohl(tvbr->tvb,tvbr->offset));
			WSLUA_RETURN(1); /* the unsigned integer value */
            /*
             * XXX:
             *    lua uses double so we have 52 bits to play with
             *    we are missing 5 and 6 byte integers within lua's range
             *    and 64 bit integers are not supported (there's a lib for
             *    lua that does).
             */
        default:
            luaL_error(L,"TvbRange:get_uint() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Lilliputian unsigned integer from a tvb
 */
WSLUA_METHOD TvbRange_get_le_uint(lua_State* L) {
	/* get a Little Endian unsigned integer from a TvbRange. The range must be 1, 2, 3 or 4 octets long.
	There's no support yet for 64 bit integers*/
    TvbRange tvbr = checkTvbRange(L,1);
    if (!tvbr) return 0;
    
    switch (tvbr->len) {
        case 1:
            /* XXX unsigned anyway */
            lua_pushnumber(L,(lua_Number)tvb_get_guint8(tvbr->tvb,tvbr->offset));
            return 1;
        case 2:
            lua_pushnumber(L,tvb_get_letohs(tvbr->tvb,tvbr->offset));
            return 1;
        case 3:
            lua_pushnumber(L,tvb_get_letoh24(tvbr->tvb,tvbr->offset));
            return 1;
        case 4:
            lua_pushnumber(L,tvb_get_letohl(tvbr->tvb,tvbr->offset));
			WSLUA_RETURN(1); /* the unsigned integer value */
        default:
            luaL_error(L,"TvbRange:get_le_uint() does not handle %d byte integers",tvbr->len);
            return 0;
    }
}

/*
 *  get a Blefuscuoan float
 */
WSLUA_METHOD TvbRange_get_float(lua_State* L) {
	/* get a Big Endian (network order) floating point number from a TvbRange. The range must be 4 or 8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!tvbr) return 0;
    
    switch (tvbr->len) {
        case 4:
            lua_pushnumber(L,(double)tvb_get_ntohieee_float(tvbr->tvb,tvbr->offset));
            return 1;
        case 8:
            lua_pushnumber(L,tvb_get_ntohieee_double(tvbr->tvb,tvbr->offset));
			WSLUA_RETURN(1); /* the flaoting point value */
        default:
            luaL_error(L,"TvbRange:get_float() does not handle %d byte floating numbers",tvbr->len);
            return 0;
    }
}

/*
 * get a Lilliputian float
 */
WSLUA_METHOD TvbRange_get_le_float(lua_State* L) {
	/* get a Little Endian floating point number from a TvbRange. The range must be 4 or 8 octets long. */
    TvbRange tvbr = checkTvbRange(L,1);
    if (!tvbr) return 0;
    
    switch (tvbr->len) {
        case 4:
            lua_pushnumber(L,tvb_get_letohieee_float(tvbr->tvb,tvbr->offset));
            return 1;
        case 8:
            lua_pushnumber(L,tvb_get_letohieee_double(tvbr->tvb,tvbr->offset));
			WSLUA_RETURN(1); /* the flaoting point value */
        default:
            luaL_error(L,"TvbRange:get_float() does not handle %d byte floating numbers",tvbr->len);
            return 0;
    }
}

WSLUA_METHOD TvbRange_get_ipv4(lua_State* L) {
	/* get an IPv4 Address from a TvbRange. */

    TvbRange tvbr = checkTvbRange(L,1);
    Address addr;
    guint32* ip_addr;
    
    if ( !tvbr ) return 0;
    
	if (tvbr->len != 4) 
		WSLUA_ERROR(TvbRange_get_ipv4,"The range must be 4 octets long");
	
    addr = g_malloc(sizeof(address));

    ip_addr = g_malloc(sizeof(guint32));
    *ip_addr = tvb_get_ntohl(tvbr->tvb,tvbr->offset);
    
    SET_ADDRESS(addr, AT_IPv4, 4, ip_addr); 
    pushAddress(L,addr);

	WSLUA_RETURN(1); /* the IPv4 Address */
}

WSLUA_METHOD TvbRange_get_ether(lua_State* L) {
	/* get an Ethernet Address from a TvbRange. */
    TvbRange tvbr = checkTvbRange(L,1);
    Address addr;
    guint8* buff;
    
    if ( !tvbr ) return 0;
    
    addr = g_malloc(sizeof(address));
    
	if (tvbr->len != 6)
		WSLUA_ERROR(TvbRange_get_ether,"The range must be 6 bytes long");
	
    buff = tvb_memdup(tvbr->tvb,tvbr->offset,tvbr->len);
    
    SET_ADDRESS(addr, AT_ETHER, 6, buff); 
    pushAddress(L,addr);
    
	WSLUA_RETURN(1); /* the Ethernet Address */
}


WSLUA_METHOD TvbRange_get_string(lua_State* L) {
	/* obtain a string from a TvbRange */
    TvbRange tvbr = checkTvbRange(L,1);
    
    if ( !tvbr ) return 0;
    
    lua_pushstring(L, (gchar*)tvb_get_ephemeral_string(tvbr->tvb,tvbr->offset,tvbr->len) );
    
	WSLUA_RETURN(1); /* the string */
}

WSLUA_METHOD TvbRange_get_bytes(lua_State* L) {
	/* obtain a ByteArray */
    TvbRange tvbr = checkTvbRange(L,1);
    GByteArray* ba;
    
    if ( !tvbr ) return 0;
    
    ba = g_byte_array_new();
    g_byte_array_append(ba,ep_tvb_memdup(tvbr->tvb,tvbr->offset,tvbr->len),tvbr->len);
    
    pushByteArray(L,ba);
    
	WSLUA_RETURN(1); /* the ByteArray */
}

WSLUA_METAMETHOD TvbRange__tostring(lua_State* L) {
	/* converts the TvbRange into a string. As the string gets truncated
	   you should use this only for debugging purposes
	   or if what you want is to have a truncated string in the format 67:89:AB:... */
    TvbRange tvbr = checkTvbRange(L,1);

    if (!tvbr) return 0;
    
    lua_pushstring(L,tvb_bytes_to_str(tvbr->tvb,tvbr->offset,tvbr->len));
    return 1;
}

static const luaL_reg TvbRange_methods[] = {
    {"uint", TvbRange_get_uint},
    {"le_uint", TvbRange_get_le_uint},
    {"float", TvbRange_get_float},
    {"le_float", TvbRange_get_le_float},
    {"ether", TvbRange_get_ether},
    {"ipv4", TvbRange_get_ipv4},
    {"string", TvbRange_get_string},
    {"bytes", TvbRange_get_bytes},
    {"tvb", Tvb_new_subset},
    {0, 0}
};

static const luaL_reg TvbRange_meta[] = {
    {"__index", TvbRange_get_index},
    {"__newindex", TvbRange_set_index},
    {"__tostring", TvbRange__tostring},
    {0, 0}
};

int TvbRange_register(lua_State* L) {
    outstanding_stuff = g_ptr_array_new();
    WSLUA_REGISTER_CLASS(TvbRange);
    return 1;
}
