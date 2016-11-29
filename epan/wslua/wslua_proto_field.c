/*
 * wslua_proto_field.c
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

#include "wslua.h"


/* WSLUA_CONTINUE_MODULE Proto */


WSLUA_CLASS_DEFINE(ProtoField,FAIL_ON_NULL("null ProtoField"));
    /* A Protocol field (to be used when adding items to the dissection tree). */

static const wslua_ft_types_t ftenums[] = {
    {"ftypes.NONE", FT_NONE},
    {"ftypes.BOOLEAN", FT_BOOLEAN},
    {"ftypes.UINT8", FT_UINT8},
    {"ftypes.UINT16", FT_UINT16},
    {"ftypes.UINT24", FT_UINT24},
    {"ftypes.UINT32", FT_UINT32},
    {"ftypes.UINT64", FT_UINT64},
    {"ftypes.INT8", FT_INT8},
    {"ftypes.INT16", FT_INT16},
    {"ftypes.INT24", FT_INT24},
    {"ftypes.INT32", FT_INT32},
    {"ftypes.INT64", FT_INT64},
    {"ftypes.FLOAT", FT_FLOAT},
    {"ftypes.DOUBLE", FT_DOUBLE},
    {"ftypes.ABSOLUTE_TIME", FT_ABSOLUTE_TIME},
    {"ftypes.RELATIVE_TIME", FT_RELATIVE_TIME},
    {"ftypes.STRING", FT_STRING},
    {"ftypes.STRINGZ", FT_STRINGZ},
    {"ftypes.ETHER", FT_ETHER},
    {"ftypes.BYTES", FT_BYTES},
    {"ftypes.UINT_BYTES", FT_UINT_BYTES},
    {"ftypes.IPv4", FT_IPv4},
    {"ftypes.IPv6", FT_IPv6},
    {"ftypes.IPXNET", FT_IPXNET},
    {"ftypes.FRAMENUM", FT_FRAMENUM},
    {"ftypes.GUID", FT_GUID},
    {"ftypes.OID", FT_OID},
    {"ftypes.SYSTEM_ID", FT_SYSTEM_ID},
    {"ftypes.REL_OID", FT_REL_OID},
    {"ftypes.EUI64", FT_EUI64},
    {"ftypes.FCWWN", FT_FCWWN},
    {NULL, FT_NONE}
};

static enum ftenum get_ftenum(const gchar* type) {
    const wslua_ft_types_t* ts;
    for (ts = ftenums; ts->str; ts++) {
        if ( g_str_equal(ts->str,type) ) {
            return ts->id;
        }
    }
    return FT_NONE;
}

static const gchar* ftenum_to_string(enum ftenum ft) {
    const wslua_ft_types_t* ts;
    for (ts = ftenums; ts->str; ts++) {
        if ( ts->id == ft ) {
            return ts->str;
        }
    }
    return NULL;
}

struct field_display_string_t {
    const gchar* str;
    unsigned base;
};

static const struct field_display_string_t base_displays[] = {
    {"base.NONE", BASE_NONE},
    {"base.DEC", BASE_DEC},
    {"base.HEX", BASE_HEX},
    {"base.OCT", BASE_OCT},
    {"base.DEC_HEX", BASE_DEC_HEX},
    {"base.HEX_DEC", BASE_HEX_DEC},
    /* for FT_BOOLEAN, how wide the parent bitfield is */
    {"8",8},
    {"16",16},
    {"24",24},
    {"32",32},
    /* for FT_ABSOLUTE_TIME use values in absolute_time_display_e */
    {"LOCAL", ABSOLUTE_TIME_LOCAL},
    {"UTC", ABSOLUTE_TIME_UTC},
    {"DOY_UTC", ABSOLUTE_TIME_DOY_UTC},
    {NULL,0}
};

static const gchar* base_to_string(unsigned base) {
    const struct field_display_string_t* b;
    for (b=base_displays;b->str;b++) {
        if ( base == b->base)
            return b->str;
    }
    return NULL;
}

static unsigned string_to_base(const gchar* str) {
    const struct field_display_string_t* b;
    for (b=base_displays;b->str;b++) {
        if ( g_str_equal(str,b->str))
            return b->base;
    }
    return BASE_NONE;
}

static value_string* value_string_from_table(lua_State* L, int idx) {
    GArray* vs = g_array_new(TRUE,TRUE,sizeof(value_string));
    value_string* ret;

    if(lua_isnil(L,idx)) {
        return NULL;
    } else if (!lua_istable(L,idx)) {
        luaL_argerror(L,idx,"must be a table");
        g_array_free(vs,TRUE);
        return NULL;
    }

    lua_pushnil(L);

    while (lua_next(L, idx) != 0) {
        value_string v = {0,NULL};

        if (! lua_isnumber(L,-2)) {
            luaL_argerror(L,idx,"All keys of a table used as value_string must be integers");
            g_array_free(vs,TRUE);
            return NULL;
        }

        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"All values of a table used as value_string must be strings");
            g_array_free(vs,TRUE);
            return NULL;
        }

        v.value = wslua_toguint32(L,-2);
        v.strptr = g_strdup(lua_tostring(L,-1));

        g_array_append_val(vs,v);

        lua_pop(L, 1);
    }

    ret = (value_string*)(void*)vs->data;

    g_array_free(vs,FALSE);

    return ret;
}

static val64_string* val64_string_from_table(lua_State* L, int idx) {
    GArray* vs = g_array_new(TRUE,TRUE,sizeof(val64_string));
    val64_string* ret;

    if(lua_isnil(L,idx)) {
        return NULL;
    } else if (!lua_istable(L,idx)) {
        luaL_argerror(L,idx,"must be a table");
        g_array_free(vs,TRUE);
        return NULL;
    }

    lua_pushnil(L);

    while (lua_next(L, idx) != 0) {
        val64_string v = {0,NULL};

        if (! lua_isnumber(L,-2)) {
            luaL_argerror(L,idx,"All keys of a table used as value string must be integers");
            g_array_free(vs,TRUE);
            return NULL;
        }

        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"All values of a table used as value string must be strings");
            g_array_free(vs,TRUE);
            return NULL;
        }

        v.value = wslua_toguint64(L, -2);
        v.strptr = g_strdup(lua_tostring(L,-1));

        g_array_append_val(vs,v);

        lua_pop(L, 1);
    }

    ret = (val64_string*)(void*)vs->data;

    g_array_free(vs,FALSE);

    return ret;
}

static true_false_string* true_false_string_from_table(lua_State* L, int idx) {
    GArray* tfs = g_array_new(TRUE,TRUE,sizeof(true_false_string));
    true_false_string* ret;
    true_false_string tf = { g_strdup("True"), g_strdup("False") };

    if (lua_isnil(L,idx)) {
        return NULL;
    } else if (!lua_istable(L,idx)) {
        luaL_argerror(L,idx,"must be a table");
        g_array_free(tfs,TRUE);
        return NULL;
    }

    lua_pushnil(L);

    while (lua_next(L, idx)) {

        if (! lua_isnumber(L,-2)) {
            luaL_argerror(L,idx,"All keys of a table used as true_false_string must be integers");
            g_array_free(tfs,TRUE);
            return NULL;
        }

        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"All values of a table used as true_false_string must be strings");
            g_array_free(tfs,TRUE);
            return NULL;
        }

        /* arrays in LUA start with index number 1 */
        if (lua_tointeger(L,-2) == 1) {
            g_free((gchar *)tf.true_string);
            tf.true_string = g_strdup(lua_tostring(L,-1));
        }

        if (lua_tointeger(L,-2) == 2) {
            g_free((gchar *)tf.false_string);
            tf.false_string = g_strdup(lua_tostring(L,-1));
        }

        lua_pop(L, 1);
    }

    g_array_append_val(tfs,tf);

    ret = (true_false_string*)(void*)tfs->data;

    g_array_free(tfs,FALSE);

    return ret;
}

static const gchar* check_field_name(lua_State* L, const int abbr_idx, const enum ftenum type) {
    const gchar* abbr = luaL_checkstring(L,abbr_idx);
    const header_field_info* hfinfo = NULL;

    if (!abbr[0]) {
        luaL_argerror(L, abbr_idx, "Empty field name abbreviation");
        return NULL;
    }

    if (proto_check_field_name(abbr)) {
        luaL_argerror(L, abbr_idx, "Invalid char in abbrev");
        return NULL;
    }

    hfinfo = proto_registrar_get_byname(abbr);

    if (hfinfo && !ftype_similar_types(type, hfinfo->type)) {
        luaL_argerror(L, abbr_idx, "A field of an incompatible ftype with this abbrev already exists");
        return NULL;
    }

    return abbr;
}

WSLUA_CONSTRUCTOR ProtoField_new(lua_State* L) {
    /* Creates a new `ProtoField` object to be used for a protocol field. */
#define WSLUA_ARG_ProtoField_new_NAME 1 /* Actual name of the field (the string that
                                           appears in the tree). */
#define WSLUA_ARG_ProtoField_new_ABBR 2 /* Filter name of the field (the string that
                                           is used in filters). */
#define WSLUA_ARG_ProtoField_new_TYPE 3 /* Field Type: one of: `ftypes.BOOLEAN`, `ftypes.UINT8`,
        `ftypes.UINT16`, `ftypes.UINT24`, `ftypes.UINT32`, `ftypes.UINT64`, `ftypes.INT8`,
        `ftypes.INT16`, `ftypes.INT24`, `ftypes.INT32`, `ftypes.INT64`, `ftypes.FLOAT`,
        `ftypes.DOUBLE` , `ftypes.ABSOLUTE_TIME`, `ftypes.RELATIVE_TIME`, `ftypes.STRING`,
        `ftypes.STRINGZ`, `ftypes.UINT_STRING`, `ftypes.ETHER`, `ftypes.BYTES`,
        `ftypes.UINT_BYTES`, `ftypes.IPv4`, `ftypes.IPv6`, `ftypes.IPXNET`, `ftypes.FRAMENUM`,
        `ftypes.PCRE`, `ftypes.GUID`, `ftypes.OID`, `ftypes.PROTOCOL`, `ftypes.REL_OID`,
        `ftypes.SYSTEM_ID`, `ftypes.EUI64` or `ftypes.NONE`.
    */
#define WSLUA_OPTARG_ProtoField_new_VALUESTRING 4 /* A table containing the text that
        corresponds to the values, or one of `frametype.NONE`, `frametype.REQUEST`, `frametype.RESPONSE`,
        `frametype.ACK` or `frametype.DUP_ACK` if field type is ftypes.FRAMENUM. */
#define WSLUA_OPTARG_ProtoField_new_BASE 5 /* The representation, one of: `base.NONE`, `base.DEC`,
                                              `base.HEX`, `base.OCT`, `base.DEC_HEX`, or
                                              `base.HEX_DEC`. */
#define WSLUA_OPTARG_ProtoField_new_MASK 6 /* The bitmask to be used. */
#define WSLUA_OPTARG_ProtoField_new_DESCR 7 /* The description of the field. */

    ProtoField f;
    int nargs = lua_gettop(L);
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_ProtoField_new_NAME);
    const gchar* abbr = NULL;
    enum ftenum type;
    enum ft_framenum_type framenum_type = FT_FRAMENUM_NONE;
    value_string *vs32 = NULL;
    val64_string *vs64 = NULL;
    true_false_string *tfs = NULL;
    unsigned base;
    guint32 mask = wslua_optguint32(L, WSLUA_OPTARG_ProtoField_new_MASK, 0x0);
    const gchar *blob = luaL_optstring(L,WSLUA_OPTARG_ProtoField_new_DESCR,NULL);

    if (!name[0]) {
        WSLUA_ARG_ERROR(ProtoField_new,NAME,"cannot be an empty string");
        return 0;
    }

    if (lua_isnumber(L,WSLUA_ARG_ProtoField_new_TYPE)) {
        type = (enum ftenum)luaL_checkinteger(L,WSLUA_ARG_ProtoField_new_TYPE);
    } else {
        type = get_ftenum(luaL_checkstring(L,WSLUA_ARG_ProtoField_new_TYPE));
    }

    abbr = check_field_name(L,WSLUA_ARG_ProtoField_new_ABBR,type);

    if (lua_isnumber(L, WSLUA_OPTARG_ProtoField_new_BASE)) {
        base = (unsigned)luaL_optinteger(L, WSLUA_OPTARG_ProtoField_new_BASE, BASE_NONE);
    } else {
        base = string_to_base(luaL_optstring(L, WSLUA_OPTARG_ProtoField_new_BASE, "BASE_NONE"));
    }

    switch (type) {
    case FT_FRAMENUM:
        if (base != BASE_NONE) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"FRAMENUM must use base.NONE");
            return 0;
        }
        if (mask) {
            WSLUA_OPTARG_ERROR(ProtoField_new,MASK,"FRAMENUM can not have a bitmask");
            return 0;
        }
        if (nargs >= WSLUA_OPTARG_ProtoField_new_VALUESTRING && !lua_isnil(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING)) {
            framenum_type = (enum ft_framenum_type) luaL_checkinteger(L, 4);
            if (framenum_type >= FT_FRAMENUM_NUM_TYPES) {
                WSLUA_OPTARG_ERROR(ProtoField_new,VALUESTRING,"Invalid frametype");
                return 0;
            }
        }
        break;
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    case FT_UINT64:
    case FT_INT8:
    case FT_INT16:
    case FT_INT24:
    case FT_INT32:
    case FT_INT64:
        if (base == BASE_NONE) {
            base = BASE_DEC;  /* Default base for integer */
        } else if (base < BASE_DEC || base > BASE_HEX_DEC) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Base must be either base.DEC, base.HEX, base.OCT,"
                               " base.DEC_HEX, base.DEC_HEX or base.HEX_DEC");
            return 0;
        }
        if ((base == BASE_HEX || base == BASE_OCT) &&
            (type == FT_INT8 || type == FT_INT16 || type == FT_INT24 || type == FT_INT32 || type == FT_INT64))
        {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"This type does not display as hexadecimal");
            return 0;
        }
        if (nargs >= WSLUA_OPTARG_ProtoField_new_VALUESTRING && !lua_isnil(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING)) {
            if (type == FT_UINT64 || type == FT_INT64) {
                vs64 = val64_string_from_table(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING);
            } else {
                vs32 = value_string_from_table(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING);
            }
        }
        break;
    case FT_BOOLEAN:
        if (mask == 0x0 && base != BASE_NONE) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Base must be base.NONE if bitmask is zero.");
            return 0;
        }
        if (mask != 0x0 && (base < 1 || base > 64)) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Base must be between 1 and 64 if bitmask is non-zero.");
            return 0;
        }
        if (nargs >= WSLUA_OPTARG_ProtoField_new_VALUESTRING && !lua_isnil(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING)) {
            tfs = true_false_string_from_table(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING);
        }
        break;
    case FT_ABSOLUTE_TIME:
        if (base == BASE_NONE) {
            base = ABSOLUTE_TIME_LOCAL;  /* Default base for FT_ABSOLUTE_TIME */
        } else if (base < ABSOLUTE_TIME_LOCAL || base > ABSOLUTE_TIME_DOY_UTC) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Base must be either LOCAL, UTC, or DOY_UTC");
            return 0;
        }
        if (mask) {
            WSLUA_OPTARG_ERROR(ProtoField_new,MASK,"ABSOLUTE_TIME can not have a bitmask");
            return 0;
        }
        break;
    case FT_NONE:
    case FT_IPv4:
    case FT_IPv6:
    case FT_IPXNET:
    case FT_ETHER:
    case FT_FLOAT:
    case FT_DOUBLE:
    case FT_RELATIVE_TIME:
    case FT_STRING:
    case FT_STRINGZ:
    case FT_BYTES:
    case FT_UINT_BYTES:
    case FT_GUID:
    case FT_OID:
    case FT_PROTOCOL:
    case FT_SYSTEM_ID:
    case FT_REL_OID:
    case FT_EUI64:
    case FT_VINES:
    case FT_FCWWN:
        if (base != BASE_NONE) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Base must be base.NONE");
            return 0;
        }
        if (mask) {
            WSLUA_OPTARG_ERROR(ProtoField_new,MASK,"This type can not have a bitmask");
            return 0;
        }
        break;
    /* TODO: not handled yet */
    case FT_UINT40:
    case FT_UINT48:
    case FT_UINT56:
    case FT_INT40:
    case FT_INT48:
    case FT_INT56:
    case FT_IEEE_11073_SFLOAT:
    case FT_IEEE_11073_FLOAT:
    case FT_UINT_STRING:
    case FT_AX25:
    case FT_STRINGZPAD:
        WSLUA_ARG_ERROR(ProtoField_new,TYPE,"Unsupported ProtoField field type");
        break;
    /* FT_PCRE isn't a valid field type. */
    case FT_PCRE:
    default:
        WSLUA_ARG_ERROR(ProtoField_new,TYPE,"Invalid ProtoField field type");
        break;
    }

    f = g_new(wslua_field_t,1);

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbrev = g_strdup(abbr);
    f->type = type;
    f->base = base;
    if (tfs) {
        f->vs = TFS(tfs);
    } else if (vs32) {
        f->vs = VALS(vs32);
    } else if (vs64) {
        /* Indicate that we are using val64_string */
        f->base |= BASE_VAL64_STRING;
        f->vs = VALS(vs64);
    } else if (framenum_type) {
        f->vs = FRAMENUM_TYPE(framenum_type);
    } else {
        f->vs = NULL;
    }
    f->mask = mask;
    if (blob && strcmp(blob, f->name) != 0) {
        f->blob = g_strdup(blob);
    } else {
        f->blob = NULL;
    }

    pushProtoField(L,f);

    WSLUA_RETURN(1); /* The newly created `ProtoField` object. */
}

static int ProtoField_integer(lua_State* L, enum ftenum type) {
    ProtoField f;
    const gchar* abbr = check_field_name(L,1,type);
    const gchar* name = luaL_optstring(L,2,abbr);
    unsigned default_base = (type == FT_FRAMENUM) ? BASE_NONE : BASE_DEC;
    unsigned base = (unsigned)luaL_optinteger(L, 3, default_base);
    enum ft_framenum_type framenum_type = FT_FRAMENUM_NONE;
    value_string* vs32 = NULL;
    val64_string* vs64 = NULL;
    guint32 mask = wslua_optguint32(L,5,0);
    const gchar* blob = luaL_optstring(L,6,NULL);

    if (!name[0]) {
        luaL_argerror(L, 2, "cannot be an empty string");
        return 0;
    }

    if (lua_gettop(L) > 3 && !lua_isnil(L, 4)) {
        if (type == FT_FRAMENUM) {
            framenum_type = (enum ft_framenum_type) luaL_checkinteger(L, 4);
            if (framenum_type >= FT_FRAMENUM_NUM_TYPES) {
                luaL_argerror(L, 4, "Invalid frametype");
                return 0;
            }
        } else if (type == FT_UINT64 || type == FT_INT64) {
            vs64 = val64_string_from_table(L,4);
        } else {
            vs32 = value_string_from_table(L,4);
        }
    }

    if (type == FT_FRAMENUM) {
        if (base != BASE_NONE)
            luaL_argerror(L, 3, "FRAMENUM must use base.NONE");
        else if (mask)
            luaL_argerror(L, 5, "FRAMENUM can not have a bitmask");
    } else if (base < BASE_DEC || base > BASE_HEX_DEC) {
        luaL_argerror(L, 3, "Base must be either base.DEC, base.HEX, base.OCT,"
                      " base.DEC_HEX, base.DEC_HEX or base.HEX_DEC");
        return 0;
    } else if ((base == BASE_HEX || base == BASE_OCT) &&
               (type == FT_INT8 || type == FT_INT16 || type == FT_INT24 || type == FT_INT32 || type == FT_INT64)) {
      luaL_argerror(L, 3, "This type does not display as hexadecimal");
      return 0;
    }

    f = g_new(wslua_field_t,1);

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbrev = g_strdup(abbr);
    f->type = type;
    f->base = base;
    if (vs64) {
        /* Indicate that we are using val64_string */
        f->base |= BASE_VAL64_STRING;
        f->vs = VALS(vs64);
    } else if (vs32) {
        f->vs = VALS(vs32);
    } else if (framenum_type) {
        f->vs = FRAMENUM_TYPE(framenum_type);
    } else {
        f->vs = NULL;
    }
    f->mask = mask;
    if (blob && strcmp(blob, f->name) != 0) {
        f->blob = g_strdup(blob);
    } else {
        f->blob = NULL;
    }

    pushProtoField(L,f);

    return 1;
}

#define PROTOFIELD_INTEGER(lower,FT) static int ProtoField_##lower(lua_State* L) { return ProtoField_integer(L,FT); }
/* _WSLUA_CONSTRUCTOR_ ProtoField_uint8 Creates a `ProtoField` of an unsigned 8-bit integer (i.e., a byte). */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint16 Creates a `ProtoField` of an unsigned 16-bit integer. */
/* WSLUA_ARG_Protofield_uint16_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_uint16_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_uint16_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_uint16_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_uint16_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_uint16_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint24 Creates a `ProtoField` of an unsigned 24-bit integer. */
/* WSLUA_ARG_Protofield_uint24_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_uint24_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_uint24_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_uint24_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_uint24_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_uint24_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint32 Creates a `ProtoField` of an unsigned 32-bit integer. */
/* WSLUA_ARG_Protofield_uint32_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_uint32_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_uint32_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_uint32_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_uint32_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_uint32_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint64 Creates a `ProtoField` of an unsigned 64-bit integer. */
/* WSLUA_ARG_Protofield_uint64_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_uint64_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_uint64_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_uint64_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_uint64_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_uint64_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int8 Creates a `ProtoField` of a signed 8-bit integer (i.e., a byte). */
/* WSLUA_ARG_Protofield_int8_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_int8_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_int8_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_int8_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_int8_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_int8_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int16 Creates a `ProtoField` of a signed 16-bit integer. */
/* WSLUA_ARG_Protofield_int16_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_int16_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_int16_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_int16_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_int16_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_int16_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int24 Creates a `ProtoField` of a signed 24-bit integer. */
/* WSLUA_ARG_Protofield_int24_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_int24_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_int24_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_int24_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_int24_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_int24_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int32 Creates a `ProtoField` of a signed 32-bit integer. */
/* WSLUA_ARG_Protofield_int32_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_int32_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_int32_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_int32_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_int32_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_int32_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int64 Creates a `ProtoField` of a signed 64-bit integer. */
/* WSLUA_ARG_Protofield_int64_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_int64_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_int64_BASE One of `base.DEC`, `base.HEX` or `base.OCT`. */
/* WSLUA_OPTARG_Protofield_int64_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_int64_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_int64_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_framenum Creates a `ProtoField` for a frame number (for hyperlinks between frames). */
/* WSLUA_ARG_Protofield_framenum_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_framenum_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_framenum_BASE Only `base.NONE` is supported for framenum. */
/* WSLUA_OPTARG_Protofield_framenum_FRAMETYPE One of `frametype.NONE`, `frametype.REQUEST`, `frametype.RESPONSE`, `frametype.ACK` or `frametype.DUP_ACK`. */
/* WSLUA_OPTARG_Protofield_framenum_MASK Integer mask of this field, which must be 0 for framenum. */
/* WSLUA_OPTARG_Protofield_framenum_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

PROTOFIELD_INTEGER(uint8,FT_UINT8)
PROTOFIELD_INTEGER(uint16,FT_UINT16)
PROTOFIELD_INTEGER(uint24,FT_UINT24)
PROTOFIELD_INTEGER(uint32,FT_UINT32)
PROTOFIELD_INTEGER(uint64,FT_UINT64)
PROTOFIELD_INTEGER(int8,FT_INT8)
PROTOFIELD_INTEGER(int16,FT_INT16)
PROTOFIELD_INTEGER(int24,FT_INT24)
PROTOFIELD_INTEGER(int32,FT_INT32)
PROTOFIELD_INTEGER(int64,FT_INT64)
PROTOFIELD_INTEGER(framenum,FT_FRAMENUM)

static int ProtoField_boolean(lua_State* L, enum ftenum type) {
    ProtoField f;
    const gchar* abbr = check_field_name(L,1,type);
    const gchar* name = luaL_optstring(L,2,abbr);
    unsigned base = (unsigned)luaL_optinteger(L, 3, BASE_NONE);
    true_false_string* tfs = NULL;
    guint32 mask = wslua_optguint32(L,5,0);
    const gchar* blob = luaL_optstring(L,6,NULL);

    if (!name[0]) {
        luaL_argerror(L, 2, "cannot be an empty string");
        return 0;
    }

    if (mask == 0x0 && base != BASE_NONE) {
        luaL_argerror(L,3,"Fieldbase (fielddisplay) must be base.NONE"
                      " if bitmask is zero.");
        return 0;
    }

    if (mask != 0x0 && (base < 1 || base > 64)) {
        luaL_argerror(L,3,"Fieldbase (fielddisplay) must be between 1 and 64"
                      " if bitmask is non-zero.");
        return 0;
    }

    if (lua_gettop(L) > 3 && !lua_isnil(L,4)) {
        tfs = true_false_string_from_table(L,4);
    }

    f = g_new(wslua_field_t,1);

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbrev = g_strdup(abbr);
    f->type = type;
    f->vs = TFS(tfs);
    f->base = base;
    f->mask = mask;
    if (blob && strcmp(blob, f->name) != 0) {
        f->blob = g_strdup(blob);
    } else {
        f->blob = NULL;
    }

    pushProtoField(L,f);

    return 1;
}

#define PROTOFIELD_BOOL(lower,FT) static int ProtoField_##lower(lua_State* L) { return ProtoField_boolean(L,FT); }
/* _WSLUA_CONSTRUCTOR_ ProtoField_bool Creates a `ProtoField` for a boolean true/false value. */
/* WSLUA_ARG_Protofield_bool_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_bool_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_bool_DISPLAY how wide the parent bitfield is (`base.NONE` is used for NULL-value). */
/* WSLUA_OPTARG_Protofield_bool_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_Protofield_bool_MASK Integer mask of this field. */
/* WSLUA_OPTARG_Protofield_bool_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* XXX: T/F strings */
PROTOFIELD_BOOL(bool,FT_BOOLEAN)

static int ProtoField_time(lua_State* L,enum ftenum type) {
    ProtoField f;
    const gchar* abbr = check_field_name(L,1,type);
    const gchar* name = luaL_optstring(L,2,abbr);
    unsigned base = (unsigned)luaL_optinteger(L,3,ABSOLUTE_TIME_LOCAL);
    const gchar* blob = luaL_optstring(L,4,NULL);

    if (!name[0]) {
        luaL_argerror(L, 2, "cannot be an empty string");
        return 0;
    }

    if (type == FT_ABSOLUTE_TIME) {
        if (base < ABSOLUTE_TIME_LOCAL || base > ABSOLUTE_TIME_DOY_UTC) {
            luaL_argerror(L, 3, "Base must be either LOCAL, UTC, or DOY_UTC");
            return 0;
        }
    }

    f = g_new(wslua_field_t,1);

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbrev = g_strdup(abbr);
    f->type = type;
    f->vs = NULL;
    f->base = base;
    f->mask = 0;
    if (blob && strcmp(blob, f->name) != 0) {
        f->blob = g_strdup(blob);
    } else {
        f->blob = NULL;
    }

    pushProtoField(L,f);

    return 1;
}

#define PROTOFIELD_TIME(lower,FT) static int ProtoField_##lower(lua_State* L) { return ProtoField_time(L,FT); }
/* _WSLUA_CONSTRUCTOR_ ProtoField_absolute_time Creates a `ProtoField` of a time_t structure value. */
/* WSLUA_ARG_Protofield_absolute_time_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_absolute_time_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_absolute_time_BASE One of `base.LOCAL`, `base.UTC` or `base.DOY_UTC`. */
/* WSLUA_OPTARG_Protofield_absolute_time_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_relative_time Creates a `ProtoField` of a time_t structure value. */
/* WSLUA_ARG_Protofield_relative_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_relative_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_relative_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */


PROTOFIELD_TIME(absolute_time,FT_ABSOLUTE_TIME)

static int ProtoField_other(lua_State* L,enum ftenum type) {
    ProtoField f;
    const gchar* abbr = check_field_name(L,1,type);
    const gchar* name = luaL_optstring(L,2,abbr);
    const gchar* blob = luaL_optstring(L,3,NULL);

    if (!name[0]) {
        luaL_argerror(L, 2, "cannot be an empty string");
        return 0;
    }

    f = g_new(wslua_field_t,1);

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbrev = g_strdup(abbr);
    f->type = type;
    f->vs = NULL;
    f->base = BASE_NONE;
    f->mask = 0;
    if (blob && strcmp(blob, f->name) != 0) {
        f->blob = g_strdup(blob);
    } else {
        f->blob = NULL;
    }

    pushProtoField(L,f);

    return 1;
}

#define PROTOFIELD_OTHER(lower,FT) static int ProtoField_##lower(lua_State* L) { return ProtoField_other(L,FT); }
/* _WSLUA_CONSTRUCTOR_ ProtoField_none Creates a `ProtoField` of an unstructured type. */
/* WSLUA_ARG_Protofield_none_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_none_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_none_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ipv4 Creates a `ProtoField` of an IPv4 address (4 bytes). */
/* WSLUA_ARG_Protofield_ipv4_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_ipv4_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_ipv4_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ipv6 Creates a `ProtoField` of an IPv6 address (16 bytes). */
/* WSLUA_ARG_Protofield_ipv6_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_ipv6_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_ipv6_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ether Creates a `ProtoField` of an Ethernet address (6 bytes). */
/* WSLUA_ARG_Protofield_ether_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_ether_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_ether_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_float Creates a `ProtoField` of a floating point number (4 bytes). */
/* WSLUA_ARG_Protofield_float_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_float_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_float_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_double Creates a `ProtoField` of a double-precision floating point (8 bytes). */
/* WSLUA_ARG_Protofield_double_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_double_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_double_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_string Creates a `ProtoField` of a string value. */
/* WSLUA_ARG_Protofield_string_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_string_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_string_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_stringz Creates a `ProtoField` of a zero-terminated string value. */
/* WSLUA_ARG_Protofield_stringz_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_stringz_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_stringz_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_bytes Creates a `ProtoField` for an arbitrary number of bytes. */
/* WSLUA_ARG_Protofield_bytes_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_bytes_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_bytes_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ubytes Creates a `ProtoField` for an arbitrary number of unsigned bytes. */
/* WSLUA_ARG_Protofield_ubytes_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_ubytes_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_ubytes_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_guid Creates a `ProtoField` for a Globally Unique IDentifier (GUID). */
/* WSLUA_ARG_Protofield_guid_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_guid_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_guid_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_oid Creates a `ProtoField` for an ASN.1 Organizational IDentified (OID). */
/* WSLUA_ARG_Protofield_oid_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_oid_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_oid_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_protocol Creates a `ProtoField` for a sub-protocol. Since 1.99.9. */
/* WSLUA_ARG_Protofield_protocol_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_protocol_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_protocol_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_rel_oid Creates a `ProtoField` for an ASN.1 Relative-OID. */
/* WSLUA_ARG_Protofield_rel_oid_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_rel_oid_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_rel_oid_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_systemid Creates a `ProtoField` for an OSI System ID. */
/* WSLUA_ARG_Protofield_systemid_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_systemid_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_systemid_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_eui64 Creates a `ProtoField` for an EUI64. */
/* WSLUA_ARG_Protofield_eui64_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_Protofield_eui64_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_Protofield_eui64_DESC Description of the field. */
/* _WSLUA_RETURNS_ A `ProtoField` object to be added to a table set to the `Proto.fields` attribute. */

PROTOFIELD_OTHER(none,FT_NONE)
PROTOFIELD_OTHER(ipv4,FT_IPv4)
PROTOFIELD_OTHER(ipv6,FT_IPv6)
PROTOFIELD_OTHER(ipx,FT_IPXNET)
PROTOFIELD_OTHER(ether,FT_ETHER)
PROTOFIELD_OTHER(float,FT_FLOAT)
PROTOFIELD_OTHER(double,FT_DOUBLE)
PROTOFIELD_OTHER(relative_time,FT_RELATIVE_TIME)
PROTOFIELD_OTHER(string,FT_STRING)
PROTOFIELD_OTHER(stringz,FT_STRINGZ)
PROTOFIELD_OTHER(bytes,FT_BYTES)
PROTOFIELD_OTHER(ubytes,FT_UINT_BYTES)
PROTOFIELD_OTHER(guid,FT_GUID)
PROTOFIELD_OTHER(oid,FT_OID)
PROTOFIELD_OTHER(protocol,FT_PROTOCOL)
PROTOFIELD_OTHER(rel_oid,FT_REL_OID)
PROTOFIELD_OTHER(systemid,FT_SYSTEM_ID)
PROTOFIELD_OTHER(eui64,FT_EUI64)

WSLUA_METAMETHOD ProtoField__tostring(lua_State* L) {
    /* Returns a string with info about a protofield (for debugging purposes). */
    ProtoField f = checkProtoField(L,1);
    gchar* s = g_strdup_printf("ProtoField(%i): %s %s %s %s %p %.8x %s",
                                         f->hfid,f->name,f->abbrev,
                                         ftenum_to_string(f->type),
                                         base_to_string(f->base),
                                         f->vs,f->mask,f->blob);
    lua_pushstring(L,s);
    g_free(s);
    return 1;
}

static int ProtoField__gc(lua_State* L) {
    ProtoField f = toProtoField(L,1);

    if (f->hfid == -2) {
        /* Only free unregistered and deregistered ProtoField */
        g_free(f);
    }

    return 0;
}

WSLUA_METHODS ProtoField_methods[] = {
    WSLUA_CLASS_FNREG(ProtoField,new),
    WSLUA_CLASS_FNREG(ProtoField,none),
    WSLUA_CLASS_FNREG(ProtoField,uint8),
    WSLUA_CLASS_FNREG(ProtoField,uint16),
    WSLUA_CLASS_FNREG(ProtoField,uint24),
    WSLUA_CLASS_FNREG(ProtoField,uint32),
    WSLUA_CLASS_FNREG(ProtoField,uint64),
    WSLUA_CLASS_FNREG(ProtoField,int8),
    WSLUA_CLASS_FNREG(ProtoField,int16),
    WSLUA_CLASS_FNREG(ProtoField,int24),
    WSLUA_CLASS_FNREG(ProtoField,int32),
    WSLUA_CLASS_FNREG(ProtoField,int64),
    WSLUA_CLASS_FNREG(ProtoField,framenum),
    WSLUA_CLASS_FNREG(ProtoField,ipv4),
    WSLUA_CLASS_FNREG(ProtoField,ipv6),
    WSLUA_CLASS_FNREG(ProtoField,ipx),
    WSLUA_CLASS_FNREG(ProtoField,ether),
    WSLUA_CLASS_FNREG(ProtoField,bool),
    WSLUA_CLASS_FNREG(ProtoField,float),
    WSLUA_CLASS_FNREG(ProtoField,double),
    WSLUA_CLASS_FNREG(ProtoField,absolute_time),
    WSLUA_CLASS_FNREG(ProtoField,relative_time),
    WSLUA_CLASS_FNREG(ProtoField,string),
    WSLUA_CLASS_FNREG(ProtoField,stringz),
    WSLUA_CLASS_FNREG(ProtoField,bytes),
    WSLUA_CLASS_FNREG(ProtoField,ubytes),
    WSLUA_CLASS_FNREG(ProtoField,guid),
    WSLUA_CLASS_FNREG(ProtoField,oid),
    WSLUA_CLASS_FNREG(ProtoField,protocol),
    WSLUA_CLASS_FNREG(ProtoField,rel_oid),
    WSLUA_CLASS_FNREG(ProtoField,systemid),
    WSLUA_CLASS_FNREG(ProtoField,eui64),
    { NULL, NULL }
};

WSLUA_META ProtoField_meta[] = {
    WSLUA_CLASS_MTREG(ProtoField,tostring),
    { NULL, NULL }
};

int ProtoField_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(ProtoField);
    return 0;
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
