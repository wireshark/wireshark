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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wslua.h"

/* WSLUA_CONTINUE_MODULE Proto */


WSLUA_CLASS_DEFINE(ProtoField,FAIL_ON_NULL("null ProtoField"));
    /* A Protocol field (to be used when adding items to the dissection tree). */

static const wslua_ft_types_t ftenums[] = {
    {"ftypes.NONE", FT_NONE},
    {"ftypes.BOOLEAN", FT_BOOLEAN},
    {"ftypes.CHAR", FT_CHAR},
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

/*
 * This table is primarily used to convert from string representation
 * to int representation in string_to_base().
 * Some string values are added for backward compatibility.
 */
static const struct field_display_string_t base_displays[] = {
    {"base.NONE", BASE_NONE},
    {"base.DEC", BASE_DEC},
    {"base.HEX", BASE_HEX},
    {"base.OCT", BASE_OCT},
    {"base.DEC_HEX", BASE_DEC_HEX},
    {"base.HEX_DEC", BASE_HEX_DEC},
    {"base.UNIT_STRING", BASE_UNIT_STRING},
    /* Byte separators */
    {"base.DOT", SEP_DOT},
    {"base.DASH", SEP_DASH},
    {"base.COLON", SEP_COLON},
    {"base.SPACE", SEP_SPACE},
    /* for FT_BOOLEAN, how wide the parent bitfield is */
    {"8",8},
    {"16",16},
    {"24",24},
    {"32",32},
    /* FT_ABSOLUTE_TIME */
    {"base.LOCAL", ABSOLUTE_TIME_LOCAL},
    {"base.UTC", ABSOLUTE_TIME_UTC},
    {"base.DOY_UTC", ABSOLUTE_TIME_DOY_UTC},
    {"LOCAL", ABSOLUTE_TIME_LOCAL},        /* for backward compatibility */
    {"UTC", ABSOLUTE_TIME_UTC},            /* for backward compatibility */
    {"DOY_UTC", ABSOLUTE_TIME_DOY_UTC},    /* for backward compatibility */
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

static void cleanup_range_string(GArray *rs) {
    range_string *rs32 = (range_string *)(void *)(rs->data);

    while (rs32->strptr) {
        g_free((gchar *)rs32->strptr);
        rs32++;
    }
    g_array_free(rs, TRUE);
}

static range_string * range_string_from_table(lua_State* L, int idx) {
    GArray* rs;
    range_string* rs32;

    if (lua_isnil(L,idx)) {
        return NULL;
    } else if (!lua_istable(L,idx)) {
        luaL_argerror(L,idx,"must be a table");
        return NULL;
    }

    /*
     * The first parameter set to TRUE means give us a zero-filled
     * terminal entry.
     */
    rs = g_array_new(TRUE,TRUE,sizeof(range_string));

    lua_pushnil(L);

    while (lua_next(L, idx) != 0) {
        int inner_idx;
        int key_count = 0;
        range_string r = {0,0,NULL};

        if (!lua_istable(L, -1)) {
            cleanup_range_string(rs);
            luaL_argerror(L, idx, "All values of a table used as a range_string must be tables");
            return NULL;
        }

        /*
         * Now process the table ... it must have three elements,
         * the min value, the max, both integers and a string.
         *
         * However, they are each separate items in the table and we
         * ignore their keys.
         */
        inner_idx = lua_gettop(L);
        lua_pushnil(L);

        /*
         * First two elements must be numbers, third is a string
         */
        while (lua_next(L, inner_idx) != 0) {
            if (++key_count > 3) {
                break;
            }

            switch (key_count) {
            case 1:
            case 2:
                if (!lua_isnumber(L, -1)) {
                    cleanup_range_string(rs);
                    luaL_argerror(L, idx, "First two elements of a range string value must be integers");
                    return NULL;
                }
                if (key_count == 1) /* We incremented it above */
                    r.value_min = wslua_toguint64(L, -1);
                else
                    r.value_max = wslua_toguint64(L, -1);
                break;

            case 3:
                if (lua_type(L, -1) != LUA_TSTRING) {
                    cleanup_range_string(rs);
                    luaL_argerror(L, idx, "Third element of a range string value must be a string");
                    return NULL;
                }
                r.strptr = g_strdup(lua_tostring(L,-1));
                /*
                 * We append the value here to avoid a mem leak if there
                 * are more than three entries in the table.
                 */
                g_array_append_val(rs,r);
                break;
            }

            lua_pop(L, 1);
        }

        if (key_count != 3) {
            cleanup_range_string(rs);
            luaL_argerror(L, idx, "Values of a range string must be tables with exactly three elements");
            return NULL;
        }

        lua_pop(L, 1);
    }

    rs32 = (range_string*)(void*)g_array_free(rs, FALSE);

    return rs32;
}

static value_string* value_string_from_table(lua_State* L, int idx) {
    GArray* vs;
    value_string* vs32;

    if (lua_isnil(L,idx)) {
        return NULL;
    } else if (!lua_istable(L,idx)) {
        luaL_argerror(L,idx,"must be a table");
        return NULL;
    }

    /*
     * The first parameter set to TRUE means give us a zero-filled
     * terminal entry.
     */
    vs = g_array_new(TRUE,TRUE,sizeof(value_string));

    lua_pushnil(L);

    while (lua_next(L, idx) != 0) {
        value_string v = {0,NULL};

        if (! lua_isnumber(L,-2)) {
            vs32 = (value_string *)(void *)vs->data;
            while (vs32->strptr) {
                g_free((gchar *)vs32->strptr);
                vs32++;
            }
            g_array_free(vs,TRUE);
            luaL_argerror(L,idx,"All keys of a table used as value_string must be integers");
            return NULL;
        }

        if (! lua_isstring(L,-1)) {
            vs32 = (value_string *)(void *)vs->data;
            while (vs32->strptr) {
                g_free((gchar *)vs32->strptr);
                vs32++;
            }
            g_array_free(vs,TRUE);
            luaL_argerror(L,idx,"All values of a table used as value_string must be strings");
            return NULL;
        }

        v.value = wslua_toguint32(L,-2);
        v.strptr = g_strdup(lua_tostring(L,-1));

        g_array_append_val(vs,v);

        lua_pop(L, 1);
    }

    vs32 = (value_string*)(void*)g_array_free(vs, FALSE);

    return vs32;
}

static val64_string* val64_string_from_table(lua_State* L, int idx) {
    GArray* vs;
    val64_string* vs64;

    if (lua_isnil(L,idx)) {
        return NULL;
    } else if (!lua_istable(L,idx)) {
        luaL_argerror(L,idx,"must be a table");
        return NULL;
    }

    /*
     * The first parameter set to TRUE means give us a zero-filled
     * terminal entry.
     */
    vs = g_array_new(TRUE,TRUE,sizeof(val64_string));

    lua_pushnil(L);

    while (lua_next(L, idx) != 0) {
        val64_string v = {0,NULL};

        if (! lua_isnumber(L,-2)) {
            vs64 = (val64_string *)(void *)vs->data;
            while (vs64->strptr) {
                g_free((gchar *)vs64->strptr);
                vs64++;
            }
            g_array_free(vs,TRUE);
            luaL_argerror(L,idx,"All keys of a table used as value string must be integers");
            return NULL;
        }

        if (! lua_isstring(L,-1)) {
            vs64 = (val64_string *)(void *)vs->data;
            while (vs64->strptr) {
                g_free((gchar *)vs64->strptr);
                vs64++;
            }
            g_array_free(vs,TRUE);
            luaL_argerror(L,idx,"All values of a table used as value string must be strings");
            return NULL;
        }

        v.value = wslua_toguint64(L, -2);
        v.strptr = g_strdup(lua_tostring(L,-1));

        g_array_append_val(vs,v);

        lua_pop(L, 1);
    }

    vs64 = (val64_string*)(void*)g_array_free(vs, FALSE);

    return vs64;
}

static true_false_string* true_false_string_from_table(lua_State* L, int idx) {
    true_false_string* tfs;
    gchar *true_string;
    gchar *false_string;

    if (lua_isnil(L,idx)) {
        return NULL;
    } else if (!lua_istable(L,idx)) {
        luaL_argerror(L,idx,"must be a table");
        return NULL;
    }

    true_string = g_strdup("True");
    false_string = g_strdup("False");

    lua_pushnil(L);

    while (lua_next(L, idx)) {

        if (! lua_isnumber(L,-2)) {
            g_free (true_string);
            g_free (false_string);
            luaL_argerror(L,idx,"All keys of a table used as true_false_string must be integers");
            return NULL;
        }

        if (! lua_isstring(L,-1)) {
            g_free (true_string);
            g_free (false_string);
            luaL_argerror(L,idx,"All values of a table used as true_false_string must be strings");
            return NULL;
        }

        /* Arrays in Lua start with index number 1 */
        switch (lua_tointeger(L,-2)) {
        case 1:
            g_free(true_string);
            true_string = g_strdup(lua_tostring(L,-1));
            break;
        case 2:
            g_free(false_string);
            false_string = g_strdup(lua_tostring(L,-1));
            break;
        default:
            g_free (true_string);
            g_free (false_string);
            luaL_argerror(L,idx,"The true_false_string table can have maximum two strings with key value 1 and 2");
            return NULL;
        }

        lua_pop(L, 1);
    }

    tfs = g_new(true_false_string, 1);
    tfs->true_string = true_string;
    tfs->false_string = false_string;

    return tfs;
}

static unit_name_string* unit_name_string_from_table(lua_State* L, int idx) {
    unit_name_string* units;

    if (lua_isnil(L,idx)) {
        return NULL;
    } else if (!lua_istable(L,idx)) {
        luaL_argerror(L,idx,"must be a table");
        return NULL;
    }

    units = g_new0(unit_name_string, 1);

    lua_pushnil(L);

    while (lua_next(L, idx)) {

        if (! lua_isnumber(L,-2)) {
            g_free(units->singular);
            g_free(units->plural);
            g_free(units);
            luaL_argerror(L,idx,"All keys of a table used as unit name must be integers");
            return NULL;
        }

        if (! lua_isstring(L,-1)) {
            g_free(units->singular);
            g_free(units->plural);
            g_free(units);
            luaL_argerror(L,idx,"All values of a table used as unit name must be strings");
            return NULL;
        }

        /* Arrays in Lua start with index number 1 */
        switch (lua_tointeger(L,-2)) {
        case 1:
            g_free((gchar *)units->singular);
            units->singular = g_strdup(lua_tostring(L,-1));
            break;
        case 2:
            g_free((gchar *)units->plural);
            units->plural = g_strdup(lua_tostring(L,-1));
            break;
        default:
            g_free(units->singular);
            g_free(units->plural);
            g_free(units);
            luaL_argerror(L,idx,"The unit name table can have maximum two strings with key value 1 and 2");
            return NULL;
        }

        lua_pop(L, 1);
    }

    if (!units->singular) {
        g_free(units->plural);
        g_free(units);
        luaL_argerror(L,idx,"The unit name table must have a singular entry (key value 1)");
        return NULL;
    }

    return units;
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
    /* Creates a new <<lua_class_ProtoField,`ProtoField`>> object to be used for a protocol field. */
#define WSLUA_ARG_ProtoField_new_NAME 1 /* Actual name of the field (the string that
                                           appears in the tree). */
#define WSLUA_ARG_ProtoField_new_ABBR 2 /* Filter name of the field (the string that
                                           is used in filters). */
#define WSLUA_ARG_ProtoField_new_TYPE 3 /* Field Type: one of: `ftypes.BOOLEAN`, `ftypes.CHAR`, `ftypes.UINT8`,
        `ftypes.UINT16`, `ftypes.UINT24`, `ftypes.UINT32`, `ftypes.UINT64`, `ftypes.INT8`,
        `ftypes.INT16`, `ftypes.INT24`, `ftypes.INT32`, `ftypes.INT64`, `ftypes.FLOAT`,
        `ftypes.DOUBLE` , `ftypes.ABSOLUTE_TIME`, `ftypes.RELATIVE_TIME`, `ftypes.STRING`,
        `ftypes.STRINGZ`, `ftypes.UINT_STRING`, `ftypes.ETHER`, `ftypes.BYTES`,
        `ftypes.UINT_BYTES`, `ftypes.IPv4`, `ftypes.IPv6`, `ftypes.IPXNET`, `ftypes.FRAMENUM`,
        `ftypes.PCRE`, `ftypes.GUID`, `ftypes.OID`, `ftypes.PROTOCOL`, `ftypes.REL_OID`,
        `ftypes.SYSTEM_ID`, `ftypes.EUI64` or `ftypes.NONE`.
    */
#define WSLUA_OPTARG_ProtoField_new_VALUESTRING 4 /* A table containing the text that
        corresponds to the values, or a table containing tables of range string values that
        corresponds to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing unit name
        for the values if base is `base.UNIT_STRING`, or one of `frametype.NONE`, `frametype.REQUEST`,
        `frametype.RESPONSE`, `frametype.ACK` or `frametype.DUP_ACK` if field type is ftypes.FRAMENUM. */
#define WSLUA_OPTARG_ProtoField_new_BASE 5 /* The representation, one of: `base.NONE`, `base.DEC`,
                                              `base.HEX`, `base.OCT`, `base.DEC_HEX`,
                                              `base.HEX_DEC`, `base.UNIT_STRING` or
                                              `base.RANGE_STRING`. */
#define WSLUA_OPTARG_ProtoField_new_MASK 6 /* The bitmask to be used. */
#define WSLUA_OPTARG_ProtoField_new_DESCR 7 /* The description of the field. */

    ProtoField f;
    int nargs = lua_gettop(L);
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_ProtoField_new_NAME);
    const gchar* abbr = NULL;
    enum ftenum type;
    enum ft_framenum_type framenum_type = FT_FRAMENUM_NONE;
    range_string *rs32 = NULL;
    value_string *vs32 = NULL;
    val64_string *vs64 = NULL;
    true_false_string *tfs = NULL;
    unit_name_string *uns = NULL;
    unsigned base;
    guint32 mask = wslua_optguint32(L, WSLUA_OPTARG_ProtoField_new_MASK, 0x0);
    const gchar *blob = luaL_optstring(L,WSLUA_OPTARG_ProtoField_new_DESCR,NULL);
    gboolean base_unit_string = FALSE;
    gboolean base_range_string = FALSE;

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
    case FT_CHAR:
        if (nargs < WSLUA_OPTARG_ProtoField_new_BASE || lua_isnil(L, WSLUA_OPTARG_ProtoField_new_BASE)) {
            base = BASE_OCT; /* Default base for characters (BASE_HEX instead?) */
        }
        if (base & BASE_UNIT_STRING) {
            WSLUA_OPTARG_ERROR(ProtoField_new, BASE, "Character type can not use base.UNIT_STRING");
            return 0;
        }
        /* FALLTHRU */
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
        if (base & BASE_UNIT_STRING) {
            base_unit_string = TRUE;
            base &= ~BASE_UNIT_STRING;
        }
        if (base & BASE_RANGE_STRING) {
            base_range_string = TRUE;
            base &= ~BASE_RANGE_STRING;
        }
        if (base_unit_string && base_range_string) {
                WSLUA_OPTARG_ERROR(ProtoField_new, BASE, "Only one of base.UNIT_STRING and base.RANGE_STRING can be specified");
                return 0;
        }
        if (type != FT_CHAR && base == BASE_NONE) {
            base = BASE_DEC;  /* Default base for integer */
        }
        if (type == FT_CHAR) {
            if (base != BASE_NONE && base != BASE_HEX && base != BASE_OCT) {
                luaL_argerror(L, 3, "Base must be either base.NONE, base.HEX or base.OCT");
                return 0;
            }
        } else if ((base != BASE_DEC) &&
            (type == FT_INT8 || type == FT_INT16 || type == FT_INT24 || type == FT_INT32 || type == FT_INT64))
        {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Base must be either base.DEC or base.UNIT_STRING");
            return 0;
        } else if (base < BASE_DEC || base > BASE_HEX_DEC) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Base must be either base.DEC, base.HEX, base.OCT,"
                               " base.DEC_HEX, base.HEX_DEC or base.UNIT_STRING");
            return 0;
        }
        if (nargs >= WSLUA_OPTARG_ProtoField_new_VALUESTRING) {
            if (base_unit_string) {
                uns = unit_name_string_from_table(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING);
            } else if (base_range_string) {
                rs32 = range_string_from_table(L, WSLUA_OPTARG_ProtoField_new_VALUESTRING);
            } else if (type == FT_UINT64 || type == FT_INT64) {
                vs64 = val64_string_from_table(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING);
            } else {
                vs32 = value_string_from_table(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING);
            }
        }
        if (type == FT_CHAR && base == BASE_NONE && rs32 == NULL && vs32 == NULL) {
            luaL_argerror(L, 3, "Base base.NONE must be used with a valuestring");
            return 0;
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
        } else if (!FIELD_DISPLAY_IS_ABSOLUTE_TIME(base)) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Base must be either base.LOCAL, base.UTC, or base.DOY_UTC");
            return 0;
        }
        if (mask) {
            WSLUA_OPTARG_ERROR(ProtoField_new,MASK,"ABSOLUTE_TIME can not have a bitmask");
            return 0;
        }
        break;
    case FT_STRING:
    case FT_STRINGZ:
        if (base != BASE_NONE) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Display must be base.NONE");
            return 0;
        }
        if (mask) {
            WSLUA_OPTARG_ERROR(ProtoField_new,MASK,"This type can not have a bitmask");
            return 0;
        }
        break;
    case FT_BYTES:
    case FT_UINT_BYTES:
        if (base != BASE_NONE && (base < SEP_DOT || base > SEP_SPACE)) {
            WSLUA_OPTARG_ERROR(ProtoField_new,BASE,"Display must be either base.NONE, base.DOT, base.DASH, base.COLON or base.SPACE");
            return 0;
        }
        if (mask) {
            WSLUA_OPTARG_ERROR(ProtoField_new,MASK,"This type can not have a bitmask");
            return 0;
        }
        break;
    case FT_FLOAT:
    case FT_DOUBLE:
        if (base & BASE_UNIT_STRING) {
            base_unit_string = TRUE;
            base &= ~BASE_UNIT_STRING;
        }
        if (nargs >= WSLUA_OPTARG_ProtoField_new_VALUESTRING) {
            uns = unit_name_string_from_table(L,WSLUA_OPTARG_ProtoField_new_VALUESTRING);
        }
        /* FALLTHRU */
    case FT_NONE:
    case FT_IPv4:
    case FT_IPv6:
    case FT_IPXNET:
    case FT_ETHER:
    case FT_RELATIVE_TIME:
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
    case FT_STRINGZTRUNC:
        WSLUA_ARG_ERROR(ProtoField_new,TYPE,"Unsupported ProtoField field type");
        break;
    default:
        WSLUA_ARG_ERROR(ProtoField_new,TYPE,"Invalid ProtoField field type");
        break;
    }

    if (base_unit_string && !uns) {
        WSLUA_OPTARG_ERROR(ProtoField_new,VALUESTRING, "Base contains base.UNIT_STRING but no table was provided");
        return 0;
    }

    if (base_range_string && !rs32) {
        WSLUA_OPTARG_ERROR(ProtoField_new, VALUESTRING, "Base contains bas.RANGE_STRING but no table was provided")
        return 0;
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
    } else if (rs32) {
        f->base |= BASE_RANGE_STRING;
        f->vs = RVALS(rs32);
    } else if (vs64) {
        /* Indicate that we are using val64_string */
        f->base |= BASE_VAL64_STRING;
        f->vs = VALS64(vs64);
    } else if (uns) {
        f->base |= BASE_UNIT_STRING;
        f->vs = uns;
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

    WSLUA_RETURN(1); /* The newly created <<lua_class_ProtoField,`ProtoField`>> object. */
}

static int ProtoField_integer(lua_State* L, enum ftenum type) {
    ProtoField f;
    const gchar* abbr = check_field_name(L,1,type);
    const gchar* name = luaL_optstring(L,2,abbr);
    unsigned default_base = (type == FT_FRAMENUM) ? BASE_NONE : ((type == FT_CHAR) ? BASE_OCT : BASE_DEC);
    unsigned base = (unsigned)luaL_optinteger(L, 3, default_base);
    enum ft_framenum_type framenum_type = FT_FRAMENUM_NONE;
    value_string* vs32 = NULL;
    range_string* rs32 = NULL;
    val64_string* vs64 = NULL;
    unit_name_string* uns = NULL;
    guint32 mask = wslua_optguint32(L,5,0);
    const gchar* blob = luaL_optstring(L,6,NULL);
    gboolean base_unit_string = FALSE;
    gboolean base_range_string = FALSE;

    if (!name[0]) {
        luaL_argerror(L, 2, "cannot be an empty string");
        return 0;
    }

    if (type == FT_CHAR && base & BASE_UNIT_STRING) {
        luaL_argerror(L, 3, "Character type can not use base.UNIT_STRING");
        return 0;
    }

    if (base & BASE_UNIT_STRING) {
        base_unit_string = TRUE;
        base &= ~BASE_UNIT_STRING;
        if (base == BASE_NONE) {
            base = BASE_DEC;
        }
    }

    if (base & BASE_RANGE_STRING) {
        base_range_string = TRUE;
        base &= ~BASE_RANGE_STRING;
        if (type != FT_CHAR && base == BASE_NONE) {
            base = BASE_DEC;
        }
    }

    if (base_unit_string && base_range_string) {
        luaL_argerror(L, 3, "Only one of base.RANGE_STRING and base.UNIT_STRING can be specified");
        return 0;
    }

    if (lua_gettop(L) > 3 && !lua_isnil(L, 4)) {
        if (type == FT_FRAMENUM) {
            framenum_type = (enum ft_framenum_type) luaL_checkinteger(L, 4);
            if (framenum_type >= FT_FRAMENUM_NUM_TYPES) {
                luaL_argerror(L, 4, "Invalid frametype");
                return 0;
            }
        } else if (base_unit_string) {
            uns = unit_name_string_from_table(L,4);
        } else if (base_range_string) {
            rs32 = range_string_from_table(L, 4);
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
    } else if (type == FT_CHAR) {
        if (base != BASE_NONE && base != BASE_HEX && base != BASE_OCT) {
            luaL_argerror(L, 3, "Base must be either base.NONE, base.HEX or base.OCT");
            return 0;
        }
        if (base == BASE_NONE && rs32 == NULL && vs32 == NULL) {
            luaL_argerror(L, 3, "Base base.NONE must be used with a valuestring");
            return 0;
        }
    } else if ((base != BASE_DEC) &&
               (type == FT_INT8 || type == FT_INT16 || type == FT_INT24 || type == FT_INT32 || type == FT_INT64)) {
        luaL_argerror(L, 3, "Base must be either base.DEC or base.UNIT_STRING");
        return 0;
    } else if (base < BASE_DEC || base > BASE_HEX_DEC) {
        luaL_argerror(L, 3, "Base must be either base.DEC, base.HEX, base.OCT,"
                      " base.DEC_HEX, base.HEX_DEC or base.UNIT_STRING");
        return 0;
    }

    if (base_unit_string && !uns) {
        luaL_argerror(L, 4, "Base contains base.UNIT_STRING but no table was given");
        return 0;
    }

    if (base_range_string && !rs32) {
        luaL_argerror(L, 4, "Base contains base.RANGE_STRING but no table was given");
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
        f->vs = VALS64(vs64);
    } else if (rs32) {
        f->base |= BASE_RANGE_STRING;
        f->vs = rs32;
    } else if (vs32) {
        f->vs = VALS(vs32);
    } else if (uns) {
        f->base |= BASE_UNIT_STRING;
        f->vs = uns;
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
/* _WSLUA_CONSTRUCTOR_ ProtoField_char Creates a <<lua_class_ProtoField,`ProtoField`>> of an 8-bit ASCII character. */
/* WSLUA_ARG_ProtoField_char_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_char_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_char_BASE One of `base.NONE`, `base.HEX`, `base.OCT` or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_char_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_char_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_char_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint8 Creates a <<lua_class_ProtoField,`ProtoField`>> of an unsigned 8-bit integer (i.e., a byte). */
/* WSLUA_ARG_ProtoField_uint8_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_uint8_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_uint8_BASE One of `base.DEC`, `base.HEX` or `base.OCT`, `base.DEC_HEX`, `base.HEX_DEC`, `base.UNIT_STRING` or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint8_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing the unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint8_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_uint8_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint16 Creates a <<lua_class_ProtoField,`ProtoField`>> of an unsigned 16-bit integer. */
/* WSLUA_ARG_ProtoField_uint16_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_uint16_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_uint16_BASE One of `base.DEC`, `base.HEX`, `base.OCT`, `base.DEC_HEX`, `base.HEX_DEC`, `base.UNIT_STRING` or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint16_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint16_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_uint16_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint24 Creates a <<lua_class_ProtoField,`ProtoField`>> of an unsigned 24-bit integer. */
/* WSLUA_ARG_ProtoField_uint24_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_uint24_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_uint24_BASE One of `base.DEC`, `base.HEX`, `base.OCT`, `base.DEC_HEX`, `base.HEX_DEC`, `base.UNIT_STRING`, or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint24_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing the unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint24_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_uint24_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint32 Creates a <<lua_class_ProtoField,`ProtoField`>> of an unsigned 32-bit integer. */
/* WSLUA_ARG_ProtoField_uint32_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_uint32_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_uint32_BASE One of `base.DEC`, `base.HEX`, `base.OCT`, `base.DEC_HEX`, `base.HEX_DEC`, `base.UNIT_STRING`, or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint32_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing the unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint32_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_uint32_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint64 Creates a <<lua_class_ProtoField,`ProtoField`>> of an unsigned 64-bit integer. */
/* WSLUA_ARG_ProtoField_uint64_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_uint64_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_uint64_BASE One of `base.DEC`, `base.HEX`, `base.OCT`, `base.DEC_HEX`, `base.HEX_DEC`, `base.UNIT_STRING`, or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint64_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing the unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_uint64_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_uint64_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int8 Creates a <<lua_class_ProtoField,`ProtoField`>> of a signed 8-bit integer (i.e., a byte). */
/* WSLUA_ARG_ProtoField_int8_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_int8_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_int8_BASE One of `base.DEC`, `base.UNIT_STRING`, or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_int8_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_int8_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_int8_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int16 Creates a <<lua_class_ProtoField,`ProtoField`>> of a signed 16-bit integer. */
/* WSLUA_ARG_ProtoField_int16_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_int16_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_int16_BASE One of `base.DEC`, `base.UNIT_STRING`, or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_int16_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_int16_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_int16_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int24 Creates a <<lua_class_ProtoField,`ProtoField`>> of a signed 24-bit integer. */
/* WSLUA_ARG_ProtoField_int24_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_int24_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_int24_BASE One of `base.DEC`, `base.UNIT_STRING`, or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_int24_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_int24_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_int24_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int32 Creates a <<lua_class_ProtoField,`ProtoField`>> of a signed 32-bit integer. */
/* WSLUA_ARG_ProtoField_int32_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_int32_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_int32_BASE One of `base.DEC`, `base.UNIT_STRING`, or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_int32_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_int32_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_int32_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int64 Creates a <<lua_class_ProtoField,`ProtoField`>> of a signed 64-bit integer. */
/* WSLUA_ARG_ProtoField_int64_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_int64_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_int64_BASE One of `base.DEC`, `base.UNIT_STRING`, or `base.RANGE_STRING`. */
/* WSLUA_OPTARG_ProtoField_int64_VALUESTRING A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is `base.RANGE_STRING`, or a table containing unit name for the values if base is `base.UNIT_STRING`. */
/* WSLUA_OPTARG_ProtoField_int64_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_int64_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_framenum Creates a <<lua_class_ProtoField,`ProtoField`>> for a frame number (for hyperlinks between frames). */
/* WSLUA_ARG_ProtoField_framenum_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_framenum_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_framenum_BASE Only `base.NONE` is supported for framenum. */
/* WSLUA_OPTARG_ProtoField_framenum_FRAMETYPE One of `frametype.NONE`, `frametype.REQUEST`, `frametype.RESPONSE`, `frametype.ACK` or `frametype.DUP_ACK`. */
/* WSLUA_OPTARG_ProtoField_framenum_MASK Integer mask of this field, which must be 0 for framenum. */
/* WSLUA_OPTARG_ProtoField_framenum_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

PROTOFIELD_INTEGER(char,FT_CHAR)
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
/* _WSLUA_CONSTRUCTOR_ ProtoField_bool Creates a <<lua_class_ProtoField,`ProtoField`>> for a boolean true/false value. */
/* WSLUA_ARG_ProtoField_bool_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_bool_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_bool_DISPLAY How wide the parent bitfield is (`base.NONE` is used for NULL-value). */
/* WSLUA_OPTARG_ProtoField_bool_VALUESTRING A table containing the text that corresponds to the values. */
/* WSLUA_OPTARG_ProtoField_bool_MASK Integer mask of this field. */
/* WSLUA_OPTARG_ProtoField_bool_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

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
        if (!FIELD_DISPLAY_IS_ABSOLUTE_TIME(base)) {
            luaL_argerror(L, 3, "Base must be either base.LOCAL, base.UTC, or base.DOY_UTC");
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
/* _WSLUA_CONSTRUCTOR_ ProtoField_absolute_time Creates a <<lua_class_ProtoField,`ProtoField`>> of a time_t structure value. */
/* WSLUA_ARG_ProtoField_absolute_time_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_absolute_time_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_absolute_time_BASE One of `base.LOCAL`, `base.UTC` or `base.DOY_UTC`. */
/* WSLUA_OPTARG_ProtoField_absolute_time_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_relative_time Creates a <<lua_class_ProtoField,`ProtoField`>> of a time_t structure value. */
/* WSLUA_ARG_ProtoField_relative_time_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_relative_time_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_relative_time_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */


PROTOFIELD_TIME(absolute_time,FT_ABSOLUTE_TIME)

static int ProtoField_floating(lua_State* L,enum ftenum type) {
    ProtoField f;
    const gchar* abbr = check_field_name(L,1,type);
    const gchar* name = luaL_optstring(L,2,abbr);
    unit_name_string* uns = NULL;
    const gchar* blob;

    if (!name[0]) {
        luaL_argerror(L, 2, "cannot be an empty string");
        return 0;
    }

    if (lua_istable(L, 3)) {
        uns = unit_name_string_from_table(L,3);
        blob = luaL_optstring(L,4,NULL);
    } else {
        blob = luaL_optstring(L,3,NULL);
    }

    f = g_new(wslua_field_t,1);

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbrev = g_strdup(abbr);
    f->type = type;
    if (uns) {
        f->vs = uns;
        f->base = BASE_NONE | BASE_UNIT_STRING;
    } else {
        f->vs = NULL;
        f->base = BASE_NONE;
    }
    f->mask = 0;
    if (blob && strcmp(blob, f->name) != 0) {
        f->blob = g_strdup(blob);
    } else {
        f->blob = NULL;
    }

    pushProtoField(L,f);

    return 1;
}

#define PROTOFIELD_FLOATING(lower,FT) static int ProtoField_##lower(lua_State* L) { return ProtoField_floating(L,FT); }
/* _WSLUA_CONSTRUCTOR_ ProtoField_float Creates a <<lua_class_ProtoField,`ProtoField`>> of a floating point number (4 bytes). */
/* WSLUA_ARG_ProtoField_float_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_float_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_float_VALUESTRING A table containing unit name for the values. */
/* WSLUA_OPTARG_ProtoField_float_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_double Creates a <<lua_class_ProtoField,`ProtoField`>> of a double-precision floating point (8 bytes). */
/* WSLUA_ARG_ProtoField_double_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_double_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_double_VALUESTRING A table containing unit name for the values. */
/* WSLUA_OPTARG_ProtoField_double_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

PROTOFIELD_FLOATING(float,FT_FLOAT)
PROTOFIELD_FLOATING(double,FT_DOUBLE)

static int ProtoField_other_display(lua_State* L,enum ftenum type) {
    ProtoField f;
    const gchar* abbr = check_field_name(L,1,type);
    const gchar* name = luaL_optstring(L,2,abbr);
    unsigned base = BASE_NONE;
    const gchar* blob;

    if (!name[0]) {
        luaL_argerror(L, 2, "cannot be an empty string");
        return 0;
    }

    if (lua_isnumber(L, 3)) {
        base = (unsigned)luaL_optinteger(L,3,BASE_NONE);
        if (type == FT_STRING || type == FT_STRINGZ) {
            if (base != BASE_NONE) {
                luaL_argerror(L, 3, "Display must be base.NONE");
                return 0;
            }
        } else if (type == FT_BYTES || type == FT_UINT_BYTES) {
            if (base != BASE_NONE && (base < SEP_DOT || base > SEP_SPACE)) {
                luaL_argerror(L, 3, "Display must be either base.NONE, base.DOT, base.DASH, base.COLON or base.SPACE");
                return 0;
            }
        }

        blob = luaL_optstring(L,4,NULL);
    } else {
        blob = luaL_optstring(L,3,NULL);
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

#define PROTOFIELD_OTHER_DISPLAY(lower,FT) static int ProtoField_##lower(lua_State* L) { return ProtoField_other_display(L,FT); }
/* _WSLUA_CONSTRUCTOR_ ProtoField_string Creates a <<lua_class_ProtoField,`ProtoField`>> of a string value. */
/* WSLUA_ARG_ProtoField_string_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_string_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_string_DISPLAY One of `base.ASCII` or `base.UNICODE`. */
/* WSLUA_OPTARG_ProtoField_string_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_stringz Creates a <<lua_class_ProtoField,`ProtoField`>> of a zero-terminated string value. */
/* WSLUA_ARG_ProtoField_stringz_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_stringz_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_stringz_DISPLAY One of `base.ASCII` or `base.UNICODE`. */
/* WSLUA_OPTARG_ProtoField_stringz_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_bytes Creates a <<lua_class_ProtoField,`ProtoField`>> for an arbitrary number of bytes. */
/* WSLUA_ARG_ProtoField_bytes_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_bytes_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_bytes_DISPLAY One of `base.NONE`, `base.DOT`, `base.DASH`, `base.COLON` or `base.SPACE`. */
/* WSLUA_OPTARG_ProtoField_bytes_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ubytes Creates a <<lua_class_ProtoField,`ProtoField`>> for an arbitrary number of unsigned bytes. */
/* WSLUA_ARG_ProtoField_ubytes_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_ubytes_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_ubytes_DISPLAY One of `base.NONE`, `base.DOT`, `base.DASH`, `base.COLON` or `base.SPACE`. */
/* WSLUA_OPTARG_ProtoField_ubytes_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */


PROTOFIELD_OTHER_DISPLAY(string,FT_STRING)
PROTOFIELD_OTHER_DISPLAY(stringz,FT_STRINGZ)
PROTOFIELD_OTHER_DISPLAY(bytes,FT_BYTES)
PROTOFIELD_OTHER_DISPLAY(ubytes,FT_UINT_BYTES)

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
/* _WSLUA_CONSTRUCTOR_ ProtoField_none Creates a <<lua_class_ProtoField,`ProtoField`>> of an unstructured type. */
/* WSLUA_ARG_ProtoField_none_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_none_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_none_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ipv4 Creates a <<lua_class_ProtoField,`ProtoField`>> of an IPv4 address (4 bytes). */
/* WSLUA_ARG_ProtoField_ipv4_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_ipv4_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_ipv4_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ipv6 Creates a <<lua_class_ProtoField,`ProtoField`>> of an IPv6 address (16 bytes). */
/* WSLUA_ARG_ProtoField_ipv6_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_ipv6_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_ipv6_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ether Creates a <<lua_class_ProtoField,`ProtoField`>> of an Ethernet address (6 bytes). */
/* WSLUA_ARG_ProtoField_ether_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_ether_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_ether_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_guid Creates a <<lua_class_ProtoField,`ProtoField`>> for a Globally Unique IDentifier (GUID). */
/* WSLUA_ARG_ProtoField_guid_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_guid_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_guid_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_oid Creates a <<lua_class_ProtoField,`ProtoField`>> for an ASN.1 Organizational IDentified (OID). */
/* WSLUA_ARG_ProtoField_oid_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_oid_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_oid_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_protocol Creates a <<lua_class_ProtoField,`ProtoField`>> for a sub-protocol. Since 1.99.9. */
/* WSLUA_ARG_ProtoField_protocol_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_protocol_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_protocol_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_rel_oid Creates a <<lua_class_ProtoField,`ProtoField`>> for an ASN.1 Relative-OID. */
/* WSLUA_ARG_ProtoField_rel_oid_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_rel_oid_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_rel_oid_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_systemid Creates a <<lua_class_ProtoField,`ProtoField`>> for an OSI System ID. */
/* WSLUA_ARG_ProtoField_systemid_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_systemid_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_systemid_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

/* _WSLUA_CONSTRUCTOR_ ProtoField_eui64 Creates a <<lua_class_ProtoField,`ProtoField`>> for an EUI64. */
/* WSLUA_ARG_ProtoField_eui64_ABBR Abbreviated name of the field (the string used in filters). */
/* WSLUA_OPTARG_ProtoField_eui64_NAME Actual name of the field (the string that appears in the tree). */
/* WSLUA_OPTARG_ProtoField_eui64_DESC Description of the field. */
/* _WSLUA_RETURNS_ A <<lua_class_ProtoField,`ProtoField`>> object to be added to a table set to the <<lua_class_attrib_proto_fields,`Proto.fields`>> attribute. */

PROTOFIELD_OTHER(none,FT_NONE)
PROTOFIELD_OTHER(ipv4,FT_IPv4)
PROTOFIELD_OTHER(ipv6,FT_IPv6)
PROTOFIELD_OTHER(ipx,FT_IPXNET)
PROTOFIELD_OTHER(ether,FT_ETHER)
PROTOFIELD_OTHER(relative_time,FT_RELATIVE_TIME)
PROTOFIELD_OTHER(guid,FT_GUID)
PROTOFIELD_OTHER(oid,FT_OID)
PROTOFIELD_OTHER(protocol,FT_PROTOCOL)
PROTOFIELD_OTHER(rel_oid,FT_REL_OID)
PROTOFIELD_OTHER(systemid,FT_SYSTEM_ID)
PROTOFIELD_OTHER(eui64,FT_EUI64)

WSLUA_METAMETHOD ProtoField__tostring(lua_State* L) {
    /* Returns a string with info about a protofield (for debugging purposes). */
    ProtoField f = checkProtoField(L,1);
    gchar* s = ws_strdup_printf("ProtoField(%i): %s %s %s %s %p %.8x %s",
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

    /*
     * Initialized to -2 in ProtoField_new,
     * changed to -1 in Proto_commit and subsequently replaced by
     * an allocated number in proto_register_field_array.
     * Reset to -2 again in wslua_deregister_protocols.
     */
    if (f->hfid != -2) {
        /* Only free unregistered and deregistered ProtoField */
        return 0;
    }

    /* Note: name, abbrev, blob and vs will be NULL after Proto deregistration. */
    g_free(f->name);
    g_free(f->abbrev);
    g_free(f->blob);
    proto_free_field_strings(f->type, f->base, f->vs);
    g_free(f);

    return 0;
}

WSLUA_METHODS ProtoField_methods[] = {
    WSLUA_CLASS_FNREG(ProtoField,new),
    WSLUA_CLASS_FNREG(ProtoField,none),
    WSLUA_CLASS_FNREG(ProtoField,char),
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
