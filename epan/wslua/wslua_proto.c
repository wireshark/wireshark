/*
 * lua_proto.c
 *
 * wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2007, Tamas Regos <tamas.regos@ericsson.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* WSLUA_MODULE Proto Functions for writing dissectors */

#include "wslua.h"

WSLUA_CLASS_DEFINE(Pref,NOP,NOP); /* A preference of a Protocol. */

static range_t* get_range(lua_State *L, int idx_r, int idx_m)
{
    static range_t *ret;
    range_convert_str(&ret,g_strdup(luaL_checkstring(L, idx_r)),(guint32)lua_tonumber(L, idx_m));
    return ret;
}

static enum_val_t* get_enum(lua_State *L, int idx)
{
    double seq;
    const gchar *str1, *str2;
    enum_val_t *ret, last = {NULL, NULL, -1};
    GArray* es = g_array_new(TRUE,TRUE,sizeof(enum_val_t));

    luaL_checktype(L, idx, LUA_TTABLE);
    lua_pushnil(L);  /* first key */

    while (lua_next(L, idx)) {
        enum_val_t e = {NULL, NULL, -1};

        luaL_checktype(L, -1, LUA_TTABLE);
        lua_pushnil(L);
        lua_next(L, -2);
        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"First value of an enum table must be string");
            g_array_free(es,TRUE);
            return NULL;
        }
        str1 = lua_tostring(L, -1);

        lua_pop(L, 1);
        lua_next(L, -2);
        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"Second value of an enum table must be string");
            g_array_free(es,TRUE);
            return NULL;
        }
        str2 = lua_tostring(L, -1);

        lua_pop(L, 1);
        lua_next(L, -2);
        if (! lua_isnumber(L,-1)) {
            luaL_argerror(L,idx,"Third value of an enum table must be an integer");
            g_array_free(es,TRUE);
            return NULL;
        }
        seq = lua_tonumber(L, -1);

        e.name = g_strdup(str1);
        e.description = g_strdup(str2);
        e.value = (guint32)seq;

        g_array_append_val(es,e);

        lua_pop(L, 3);  /* removes 'value'; keeps 'key' for next iteration */
    }

    g_array_append_val(es,last);

    ret = (enum_val_t*)es->data;

    g_array_free(es,FALSE);

    return ret;
}

static int new_pref(lua_State* L, pref_type_t type) {
    const gchar* label = luaL_optstring(L,1,NULL);
    const gchar* descr = luaL_optstring(L,3,"");

    Pref pref = g_malloc(sizeof(wslua_pref_t));
    pref->name = NULL;
    pref->label = label ? g_strdup(label) : NULL;
    pref->desc = g_strdup(descr);
    pref->type = type;
    pref->next = NULL;
    pref->proto = NULL;

    switch(type) {
        case PREF_BOOL: {
            gboolean def = lua_toboolean(L,2);
            pref->value.b = def;
            break;
        }
        case PREF_UINT: {
            guint32 def = (guint32)luaL_optnumber(L,2,0);
            pref->value.u = def;
            break;
        }
        case PREF_STRING: {
            gchar* def = g_strdup(luaL_optstring(L,2,""));
            pref->value.s = def;
            break;
        }
        case PREF_ENUM: {
            guint32 def = (guint32)luaL_optnumber(L,2,0);
            enum_val_t *enum_val = get_enum(L,4);
            gboolean radio = lua_toboolean(L,5);
            pref->value.e = def;
            pref->info.enum_info.enumvals = enum_val;
            pref->info.enum_info.radio_buttons = radio;
            break;
        }
        case PREF_RANGE: {
            range_t *range = get_range(L,2,4);
            guint32 max = (guint32)luaL_optnumber(L,4,0);
            pref->value.r = range;
            pref->info.max_value = max;
            break;
        }
        case PREF_STATIC_TEXT: {
            /* This is just a static text. */
            break;
        }
        default:
            g_assert_not_reached();
            break;

    }

    pushPref(L,pref);
    return 1;
}

WSLUA_CONSTRUCTOR Pref_bool(lua_State* L) {
    /* Creates a boolean preference to be added to a Protocol's prefs table. */
#define WSLUA_ARG_Pref_bool_LABEL 1 /* The Label (text in the right side of the preference input) for this preference */
#define WSLUA_ARG_Pref_bool_DEFAULT 2 /* The default value for this preference */
#define WSLUA_ARG_Pref_bool_DESCR 3 /* A description of what this preference is */
    return new_pref(L,PREF_BOOL);
}

WSLUA_CONSTRUCTOR Pref_uint(lua_State* L) {
    /* Creates an (unsigned) integer preference to be added to a Protocol's prefs table. */
#define WSLUA_ARG_Pref_uint_LABEL 1 /* The Label (text in the right side of the preference input) for this preference */
#define WSLUA_ARG_Pref_uint_DEFAULT 2 /* The default value for this preference */
#define WSLUA_ARG_Pref_uint_DESCR 3 /* A description of what this preference is */
    return new_pref(L,PREF_UINT);
}

WSLUA_CONSTRUCTOR Pref_string(lua_State* L) {
    /* Creates a string preference to be added to a Protocol's prefs table. */
#define WSLUA_ARG_Pref_string_LABEL 1 /* The Label (text in the right side of the preference input) for this preference */
#define WSLUA_ARG_Pref_string_DEFAULT 2 /* The default value for this preference */
#define WSLUA_ARG_Pref_string_DESCR 3 /* A description of what this preference is */
    return new_pref(L,PREF_STRING);
}

WSLUA_CONSTRUCTOR Pref_enum(lua_State* L) {
    /* Creates an enum preference to be added to a Protocol's prefs table. */
#define WSLUA_ARG_Pref_enum_LABEL 1 /* The Label (text in the right side of the preference input) for this preference */
#define WSLUA_ARG_Pref_enum_DEFAULT 2 /* The default value for this preference */
#define WSLUA_ARG_Pref_enum_DESCR 3 /* A description of what this preference is */
#define WSLUA_ARG_Pref_enum_ENUM 4 /* A enum table */
#define WSLUA_ARG_Pref_enum_RADIO 5 /* Radio button (true) or Combobox (false) */
    return new_pref(L,PREF_ENUM);
}

WSLUA_CONSTRUCTOR Pref_range(lua_State* L) {
    /* Creates a range preference to be added to a Protocol's prefs table. */
#define WSLUA_ARG_Pref_range_LABEL 1 /* The Label (text in the right side of the preference input) for this preference */
#define WSLUA_ARG_Pref_range_DEFAULT 2 /* The default value for this preference, e.g., "53", "10-30", or "10-30,53,55,100-120" */
#define WSLUA_ARG_Pref_range_DESCR 3 /* A description of what this preference is */
#define WSLUA_ARG_Pref_range_MAX 4 /* The maximum value */
    return new_pref(L,PREF_RANGE);
}

WSLUA_CONSTRUCTOR Pref_statictext(lua_State* L) {
    /* Creates a static text preference to be added to a Protocol's prefs table.  */
#define WSLUA_ARG_Pref_statictext_LABEL 1 /* The static text */
#define WSLUA_ARG_Pref_statictext_DESCR 2 /* The static text description */
    return new_pref(L,PREF_STATIC_TEXT);
}

static int Pref_gc(lua_State* L) {
    Pref pref = checkPref(L,1);

    if (pref && ! pref->name) {
        g_free(pref->label);
        g_free(pref->desc);
        if (pref->type == PREF_STRING)
            g_free((void*)pref->value.s);
        g_free(pref);
    }

    return 0;
}

WSLUA_METHODS Pref_methods[] = {
    {"bool",   Pref_bool},
    {"uint",   Pref_uint},
    {"string", Pref_string},
    {"enum",   Pref_enum},
    {"range",  Pref_range},
    {"statictext",  Pref_statictext},
    {0,0}
};

WSLUA_META Pref_meta[] = {
    {"__gc",   Pref_gc},
    {0,0}
};


WSLUA_REGISTER Pref_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(Pref);
    return 1;
}

WSLUA_CLASS_DEFINE(Prefs,NOP,NOP); /* The table of preferences of a protocol */

WSLUA_METAMETHOD Prefs__newindex(lua_State* L) {
    /* Creates a new preference */
#define WSLUA_ARG_Prefs__newindex_NAME 2 /* The abbreviation of this preference */
#define WSLUA_ARG_Prefs__newindex_PREF 3 /* A valid but still unassigned Pref object */

    Pref prefs_p = checkPrefs(L,1);
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_Prefs__newindex_NAME);
    Pref pref = checkPref(L,WSLUA_ARG_Prefs__newindex_PREF);
    Pref p;
    const gchar *c;

    if (! prefs_p ) return 0;

    if (! name )
        WSLUA_ARG_ERROR(Prefs__newindex,NAME,"must be a string");

    if (! pref )
        WSLUA_ARG_ERROR(Prefs__newindex,PREF,"must be a valid Pref");

    if (pref->name)
        WSLUA_ARG_ERROR(Prefs__newindex,NAME,"cannot change existing preference");

    if (pref->proto)
        WSLUA_ARG_ERROR(Prefs__newindex,PREF,"cannot be added to more than one protocol");

    p = prefs_p;

    do {
        if ( p->name && g_str_equal(p->name,name) ) {
            luaL_error(L,"a preference named %s exists already",name);
            return 0;
        }
    /*
         * Make sure that only lower-case ASCII letters, numbers,
         * underscores, and dots appear in the preference name.
     */
    for (c = name; *c != '\0'; c++) {
        if (!isascii((guchar)*c) ||
           (!islower((guchar)*c) && !isdigit((guchar)*c) && *c != '_' && *c != '.'))
        {
            luaL_error(L,"illegal preference name \"%s\", only lower-case ASCII letters, numbers, underscores and dots may be used",name);
            return 0;
        }
    }

        if ( ! p->next) {
            p->next = pref;
            pref->name = g_strdup(name);

            if (!pref->label)
                pref->label = g_strdup(name);

            if (!prefs_p->proto->prefs_module) {
                prefs_p->proto->prefs_module = prefs_register_protocol(prefs_p->proto->hfid, NULL);
            }

            switch(pref->type) {
                case PREF_BOOL:
                    prefs_register_bool_preference(prefs_p->proto->prefs_module,
                                                   pref->name,
                                                   pref->label,
                                                   pref->desc,
                                                   &(pref->value.b));
                    break;
                case PREF_UINT:
                    prefs_register_uint_preference(prefs_p->proto->prefs_module,
                                                   pref->name,
                                                   pref->label,
                                                   pref->desc,
                                                   10,
                                                   &(pref->value.u));
                    break;
                case PREF_STRING:
                    prefs_register_string_preference(prefs_p->proto->prefs_module,
                                                     pref->name,
                                                     pref->label,
                                                     pref->desc,
                                                     &(pref->value.s));
                    break;
                case PREF_ENUM:
                    prefs_register_enum_preference(prefs_p->proto->prefs_module,
                                                     pref->name,
                                                     pref->label,
                                                     pref->desc,
                                                     &(pref->value.e),
                                                     pref->info.enum_info.enumvals,
                                                     pref->info.enum_info.radio_buttons);
                    break;
                case PREF_RANGE:
                    prefs_register_range_preference(prefs_p->proto->prefs_module,
                                                     pref->name,
                                                     pref->label,
                                                     pref->desc,
                                                     &(pref->value.r),
                                                     pref->info.max_value);
                    break;
                case PREF_STATIC_TEXT:
                    prefs_register_static_text_preference(prefs_p->proto->prefs_module,
                                                     pref->name,
                                                     pref->label,
                                                     pref->desc);
                    break;
                default:
                    WSLUA_ERROR(Prefs__newindex,"Unknow Pref type");
            }

            pref->proto = p->proto;

            WSLUA_RETURN(0);
        }
    } while (( p = p->next ));

    luaL_error(L,"this should not happen!");

    WSLUA_RETURN(0);
}

WSLUA_METAMETHOD Prefs__index(lua_State* L) {
    /* Get the value of a preference setting */
#define WSLUA_ARG_Prefs__index_NAME 2 /* The abbreviation of this preference  */

    Pref prefs_p = checkPrefs(L,1);
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_Prefs__index_NAME);

    if (! ( name && prefs_p ) ) return 0;

    prefs_p = prefs_p->next;

    do {
        if ( g_str_equal(prefs_p->name,name) ) {
            switch (prefs_p->type) {
                case PREF_BOOL: lua_pushboolean(L, prefs_p->value.b); break;
                case PREF_UINT: lua_pushnumber(L,(lua_Number)prefs_p->value.u); break;
                case PREF_STRING: lua_pushstring(L,prefs_p->value.s); break;
                case PREF_ENUM: lua_pushnumber(L,(lua_Number)prefs_p->value.e); break;
                case PREF_RANGE: lua_pushstring(L,range_convert_range(prefs_p->value.r)); break;
                default: WSLUA_ERROR(Prefs__index,"Unknow Pref type");
            }
            WSLUA_RETURN(1); /* The current value of the preference */
        }
    } while (( prefs_p = prefs_p->next ));

    WSLUA_ARG_ERROR(Prefs__index,NAME,"no preference named like this");
}

WSLUA_META Prefs_meta[] = {
    {"__newindex",   Prefs__newindex},
    {"__index",   Prefs__index},
    {0,0}
};

WSLUA_REGISTER Prefs_register(lua_State* L) {
    WSLUA_REGISTER_META(Prefs);
    return 1;
}

WSLUA_CLASS_DEFINE(ProtoField,FAIL_ON_NULL("null ProtoField"),NOP);
    /* A Protocol field (to be used when adding items to the dissection tree) */

static const wslua_ft_types_t ftenums[] = {
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

struct base_display_string_t {
    const gchar* str;
    base_display_e base;
};

static const struct base_display_string_t base_displays[] = {
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

static const gchar* base_to_string(base_display_e base) {
    const struct base_display_string_t* b;
    for (b=base_displays;b->str;b++) {
        if ( base == b->base)
            return b->str;
    }
    return NULL;
}

static base_display_e string_to_base(const gchar* str) {
    const struct base_display_string_t* b;
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

        v.value = (guint32)lua_tonumber(L,-2);
        v.strptr = g_strdup(lua_tostring(L,-1));

        g_array_append_val(vs,v);

        lua_pop(L, 1);
    }

    ret = (value_string*)vs->data;

    g_array_free(vs,FALSE);

    return ret;
}

static true_false_string* true_false_string_from_table(lua_State* L, int idx) {
    GArray* tfs = g_array_new(TRUE,TRUE,sizeof(true_false_string));
    true_false_string* ret;
    true_false_string tf = { "True", "False" };

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
        if ((guint32)lua_tonumber(L,-2) == 1)
            tf.true_string = g_strdup(lua_tostring(L,-1));

        if ((guint32)lua_tonumber(L,-2) == 2)
            tf.false_string = g_strdup(lua_tostring(L,-1));

        lua_pop(L, 1);
    }

    g_array_append_val(tfs,tf);

    ret = (true_false_string*)tfs->data;

    g_array_free(tfs,FALSE);

    return ret;
}

WSLUA_CONSTRUCTOR ProtoField_new(lua_State* L) { /* Creates a new field to be used in a protocol. */
#define WSLUA_ARG_ProtoField_new_NAME 1 /* Actual name of the field (the string that appears in the tree).  */
#define WSLUA_ARG_ProtoField_new_ABBR 2 /* Filter name of the field (the string that is used in filters).  */
#define WSLUA_ARG_ProtoField_new_TYPE 3 /* Field Type: one of ftypes.NONE, ftypes.PROTOCOL, ftypes.BOOLEAN,
	ftypes.UINT8, ftypes.UINT16, ftypes.UINT24, ftypes.UINT32, ftypes.UINT64, ftypes.INT8, ftypes.INT16
	ftypes.INT24, ftypes.INT32, ftypes.INT64, ftypes.FLOAT, ftypes.DOUBLE, ftypes.ABSOLUTE_TIME
	ftypes.RELATIVE_TIME, ftypes.STRING, ftypes.STRINGZ, ftypes.UINT_STRING, ftypes.ETHER, ftypes.BYTES
	ftypes.UINT_BYTES, ftypes.IPv4, ftypes.IPv6, ftypes.IPXNET, ftypes.FRAMENUM, ftypes.PCRE, ftypes.GUID
	ftypes.OID, ftypes.EUI64 */
#define WSLUA_OPTARG_ProtoField_new_VOIDSTRING 4 /* A VoidString object. */
#define WSLUA_OPTARG_ProtoField_new_BASE 5 /* The representation: one of base.NONE, base.DEC, base.HEX, base.OCT, base.DEC_HEX, base.HEX_DEC */
#define WSLUA_OPTARG_ProtoField_new_MASK 6 /* The bitmask to be used.  */
#define WSLUA_OPTARG_ProtoField_new_DESCR 7 /* The description of the field.  */

    ProtoField f = g_malloc(sizeof(wslua_field_t));
    value_string* vs = NULL;
    true_false_string* tfs = NULL;
    const gchar *blob;

    /* will be using -2 as far as the field has not been added to an array then it will turn -1 */
    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(luaL_checkstring(L,WSLUA_ARG_ProtoField_new_NAME));
    f->abbr = g_strdup(luaL_checkstring(L,WSLUA_ARG_ProtoField_new_ABBR));
    f->type = get_ftenum(luaL_checkstring(L,WSLUA_ARG_ProtoField_new_TYPE));

    /*XXX do it better*/
    if (f->type == FT_NONE)
        WSLUA_ARG_ERROR(ProtoField_new,TYPE,"invalid ftypes");

    if (proto_check_field_name(f->abbr)) {
      WSLUA_ARG_ERROR(ProtoField_new,ABBR,"Invalid char in abbrev");
      return 0;
    }

    if (! lua_isnil(L,WSLUA_OPTARG_ProtoField_new_VOIDSTRING) ) {
        if (f->type == FT_BOOLEAN) {
            tfs = true_false_string_from_table(L,WSLUA_OPTARG_ProtoField_new_VOIDSTRING);
        }
        else {
            vs = value_string_from_table(L,WSLUA_OPTARG_ProtoField_new_VOIDSTRING);
        }

        if (vs) {
            f->vs = VALS(vs);
        } else if (tfs) {
            f->vs = TFS(tfs);
        } else {
            g_free(f);
            return 0;
        }

    } else {
        f->vs = NULL;
    }

    /* XXX: need BASE_ERROR */
    f->base = string_to_base(luaL_optstring(L, WSLUA_OPTARG_ProtoField_new_BASE, "BASE_NONE"));
    f->mask = luaL_optint(L, WSLUA_OPTARG_ProtoField_new_MASK, 0x0);
    blob = luaL_optstring(L,WSLUA_OPTARG_ProtoField_new_DESCR,NULL);
    if (blob && strcmp(blob, f->name) != 0) {
        f->blob = g_strdup(blob);
    } else {
        f->blob = NULL;
    }

    pushProtoField(L,f);

    WSLUA_RETURN(1); /* The newly created ProtoField object */
}

static int ProtoField_integer(lua_State* L, enum ftenum type) {
    ProtoField f = g_malloc(sizeof(wslua_field_t));
    const gchar* abbr = luaL_checkstring(L,1);
    const gchar* name = luaL_optstring(L,2,abbr);
    base_display_e base = luaL_optint(L, 3, BASE_DEC);
    value_string* vs = (lua_gettop(L) > 3) ? value_string_from_table(L,4) : NULL;
    guint32 mask = luaL_optint(L, 5, 0x0);
    const gchar* blob = luaL_optstring(L,6,NULL);

    if (type == FT_FRAMENUM) {
	if (base != BASE_NONE)
	    luaL_argerror(L, 3, "ftypes.FRAMENUMs must use base.NONE");
	else if (mask)
	    luaL_argerror(L, 3, "ftypes.FRAMENUMs can not have a bitmask");
    } else if (base < BASE_DEC || base > BASE_HEX_DEC) {
        luaL_argerror(L, 3, "Base must be either base.DEC, base.HEX, base.OCT,"
                      " base.DEC_HEX, base.DEC_HEX or base.HEX_DEC");
        return 0;
    } else if (vs && (type == FT_INT64 || type == FT_UINT64)) {
      luaL_argerror(L, 4, "This type does not support value string");
      return 0;
    } else if ((base == BASE_HEX || base == BASE_OCT) &&
	       (type == FT_INT8 || type == FT_INT16 || type == FT_INT24 || type == FT_INT32 || type == FT_INT64)) {
      luaL_argerror(L, 3, "This type does not display as hexadecimal");
      return 0;
    }

    if (proto_check_field_name(abbr)) {
      luaL_argerror(L, 1, "Invalid char in abbrev");
      return 0;
    }

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbr = g_strdup(abbr);
    f->type = type;
    f->vs = VALS(vs);
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

#define PROTOFIELD_INTEGER(lower,FT) static int ProtoField_##lower(lua_State* L) { return ProtoField_integer(L,FT); }
/* _WSLUA_CONSTRUCTOR_ ProtoField_uint8 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint16 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint24 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint32 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_uint64 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int8 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int16 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int24 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int32 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_int64 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_framenum A frame number (for hyperlinks between frames) */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_BASE One of base.DEC, base.HEX or base.OCT */
/* WSLUA_OPTARG_Protofield_uint8_VALUESTRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_uint8_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

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
    ProtoField f = g_malloc(sizeof(wslua_field_t));
    const gchar* abbr = luaL_checkstring(L,1);
    const gchar* name = luaL_optstring(L,2,abbr);
    base_display_e base = luaL_optint(L, 3, BASE_NONE);
    true_false_string* tfs = (lua_gettop(L) > 3) ? true_false_string_from_table(L,4) : NULL;
    int mask = luaL_optint(L, 5, 0x0);
    const gchar* blob = luaL_optstring(L,6,NULL);

    if (mask == 0x0 && base != BASE_NONE) {
        luaL_argerror(L,2,"Fieldbase (fielddisplay) must be base.NONE"
                      " if bitmask is zero.");
        return 0;
    }

    if (mask != 0x0 && (base < 1 || base > 64)) {
        luaL_argerror(L,2,"Fieldbase (fielddisplay) must be between 1 and 64"
                      " if bitmask is non-zero.");
        return 0;
    }

    if (proto_check_field_name(abbr)) {
      luaL_argerror(L,1,"Invalid char in abbrev");
      return 0;
    }

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbr = g_strdup(abbr);
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
/* _WSLUA_CONSTRUCTOR_ ProtoField_bool */
/* WSLUA_ARG_Protofield_bool_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_bool_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_bool_DISPLAY how wide the parent bitfield is (base.NONE is used for NULL-value) */
/* WSLUA_OPTARG_Protofield_bool_TRUE_FALSE_STRING A table containing the text that corresponds to the values  */
/* WSLUA_OPTARG_Protofield_bool_MASK Integer mask of this field  */
/* WSLUA_OPTARG_Protofield_bool_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* XXX: T/F strings */
PROTOFIELD_BOOL(bool,FT_BOOLEAN)

static int ProtoField_time(lua_State* L,enum ftenum type) {
    ProtoField f = g_malloc(sizeof(wslua_field_t));
    const gchar* abbr = luaL_checkstring(L,1);
    const gchar* name = luaL_optstring(L,2,abbr);
    absolute_time_display_e base = luaL_optint(L,3,ABSOLUTE_TIME_LOCAL);
    const gchar* blob = luaL_optstring(L,4,NULL);

    if (proto_check_field_name(abbr)) {
      luaL_argerror(L,1,"Invalid char in abbrev");
      return 0;
    }

    if (type == FT_ABSOLUTE_TIME) {
      if (base < ABSOLUTE_TIME_LOCAL || base > ABSOLUTE_TIME_DOY_UTC) {
        luaL_argerror(L, 3, "Base must be either LOCAL, UTC, or DOY_UTC");
        return 0;
      }
    }

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbr = g_strdup(abbr);
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
/* _WSLUA_CONSTRUCTOR_ ProtoField_absolute_time */
/* WSLUA_ARG_Protofield_absolute_time_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_absolute_time_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_absolute_time_BASE One of base.LOCAL, base.UTC or base.DOY_UTC */
/* WSLUA_OPTARG_Protofield_absolute_time_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_relative_time */
/* WSLUA_ARG_Protofield_relative_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_relative_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_relative_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */


PROTOFIELD_TIME(absolute_time,FT_ABSOLUTE_TIME)

static int ProtoField_other(lua_State* L,enum ftenum type) {
    ProtoField f = g_malloc(sizeof(wslua_field_t));
    const gchar* abbr = luaL_checkstring(L,1);
    const gchar* name = luaL_optstring(L,2,abbr);
    const gchar* blob = luaL_optstring(L,3,NULL);

    if (proto_check_field_name(abbr)) {
      luaL_argerror(L,1,"Invalid char in abbrev");
      return 0;
    }

    f->hfid = -2;
    f->ett = -1;
    f->name = g_strdup(name);
    f->abbr = g_strdup(abbr);
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
/* _WSLUA_CONSTRUCTOR_ ProtoField_ipv4 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ipv6 */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ether */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_float */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_double */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_string */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_stringz */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_bytes */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_ubytes */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_guid */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_oid */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

/* _WSLUA_CONSTRUCTOR_ ProtoField_bool */
/* WSLUA_ARG_Protofield_uint8_ABBR Abbreviated name of the field (the string used in filters)  */
/* WSLUA_OPTARG_Protofield_uint8_NAME Actual name of the field (the string that appears in the tree)  */
/* WSLUA_OPTARG_Protofield_uint8_DESC Description of the field  */
/* _WSLUA_RETURNS_ A protofield item to be added to a ProtoFieldArray */

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

WSLUA_METAMETHOD ProtoField__tostring(lua_State* L) {
    /* Returns a string with info about a protofield (for debugging purposes) */
    ProtoField f = checkProtoField(L,1);
    gchar* s = ep_strdup_printf("ProtoField(%i): %s %s %s %s %p %.8x %s",f->hfid,f->name,f->abbr,ftenum_to_string(f->type),base_to_string(f->base),f->vs,f->mask,f->blob);
    lua_pushstring(L,s);
    return 1;
}

static int ProtoField_gc(lua_State* L) {
    ProtoField f = checkProtoField(L,1);

    /*
     * A garbage collector for ProtoFields makes little sense.
     * Even if This cannot be used anymore because it has gone out of scope,
     * we can destroy the ProtoField only if it is not part of a ProtoFieldArray,
     * if it actualy belongs to one we need to preserve it as it is pointed by
     * a field array that may be registered afterwards causing a crash or memory corruption.
     */

    if (!f) {
        luaL_argerror(L,1,"BUG: ProtoField_gc called for something not ProtoField");
        /* g_assert() ?? */
    } else if (f->hfid == -2) {
        g_free(f->name);
        g_free(f->abbr);
        g_free(f->blob);
        g_free(f);
    }

    return 0;
}

static const luaL_reg ProtoField_methods[] = {
    {"new",   ProtoField_new},
    {"uint8",ProtoField_uint8},
    {"uint16",ProtoField_uint16},
    {"uint24",ProtoField_uint24},
    {"uint32",ProtoField_uint32},
    {"uint64",ProtoField_uint64},
    {"int8",ProtoField_int8},
    {"int16",ProtoField_int16},
    {"int24",ProtoField_int24},
    {"int32",ProtoField_int32},
    {"int64",ProtoField_int64},
    {"framenum",ProtoField_framenum},
    {"ipv4",ProtoField_ipv4},
    {"ipv6",ProtoField_ipv6},
    {"ipx",ProtoField_ipx},
    {"ether",ProtoField_ether},
    {"bool",ProtoField_bool},
    {"float",ProtoField_float},
    {"double",ProtoField_double},
    {"absolute_time",ProtoField_absolute_time},
    {"relative_time",ProtoField_relative_time},
    {"string",ProtoField_string},
    {"stringz",ProtoField_stringz},
    {"bytes",ProtoField_bytes},
    {"ubytes",ProtoField_ubytes},
    {"guid",ProtoField_guid},
    {"oid",ProtoField_oid},
    { NULL, NULL }
};

static const luaL_reg ProtoField_meta[] = {
    {"__tostring", ProtoField__tostring },
    {"__gc", ProtoField_gc },
    { NULL, NULL }
};

int ProtoField_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(ProtoField);
    return 1;
}

WSLUA_CLASS_DEFINE(Proto,NOP,NOP);
/*
  A new protocol in wireshark. Protocols have more uses, the main one is to dissect
  a protocol. But they can be just dummies used to register preferences for
  other purposes.
 */

static int protocols_table_ref = LUA_NOREF;

WSLUA_CONSTRUCTOR Proto_new(lua_State* L) {
#define WSLUA_ARG_Proto_new_NAME 1 /* The name of the protocol */
#define WSLUA_ARG_Proto_new_DESC 2 /* A Long Text description of the protocol (usually lowercase) */
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_Proto_new_NAME);
    const gchar* desc = luaL_checkstring(L,WSLUA_ARG_Proto_new_DESC);

    if ( name ) {
        gchar* loname_a;
        int proto_id;

        loname_a = g_ascii_strdown(name, -1);
        proto_id = proto_get_id_by_filter_name(loname_a);
        g_free(loname_a);
        if ( proto_id > 0 ) {
            WSLUA_ARG_ERROR(Proto_new,NAME,"there cannot be two protocols with the same name");
        } else {
            Proto proto = g_malloc(sizeof(wslua_proto_t));
            gchar* loname = g_ascii_strdown(name, -1);
            gchar* hiname = g_ascii_strup(name, -1);

            proto->name = hiname;
            proto->desc = g_strdup(desc);
            proto->hfid = proto_register_protocol(proto->desc,hiname,loname);
            proto->ett = -1;
            proto->is_postdissector = FALSE;

            lua_newtable (L);
            proto->fields = luaL_ref(L, LUA_REGISTRYINDEX);

            proto->prefs.name = NULL;
            proto->prefs.label = NULL;
            proto->prefs.desc = NULL;
            proto->prefs.value.u = 0;
            proto->prefs.next = NULL;
            proto->prefs.proto = proto;

            proto->prefs_module = NULL;
            proto->handle = NULL;

            lua_rawgeti(L, LUA_REGISTRYINDEX, protocols_table_ref);

            lua_pushstring(L,loname);
            pushProto(L,proto);

            lua_settable(L, -3);

            pushProto(L,proto);

            WSLUA_RETURN(1); /* The newly created protocol */
        }
    } else
        WSLUA_ARG_ERROR(Proto_new,NAME,"must be a string");

    return 0;
}

static int Proto_tostring(lua_State* L) {
    Proto proto = checkProto(L,1);
    gchar* s;

    if (!proto) return 0;

    s = ep_strdup_printf("Proto: %s",proto->name);
    lua_pushstring(L,s);

    return 1;
}

WSLUA_FUNCTION wslua_register_postdissector(lua_State* L) {
    /* Make a protocol (with a dissector) a postdissector. It will be called for every frame after dissection */
#define WSLUA_ARG_register_postdissector_PROTO 1 /* the protocol to be used as postdissector */
    Proto proto = checkProto(L,WSLUA_ARG_register_postdissector_PROTO);
    if (!proto) return 0;

    if(!proto->is_postdissector) {
        if (! proto->handle) {
            proto->handle = new_create_dissector_handle(dissect_lua, proto->hfid);
        }

        register_postdissector(proto->handle);
    } else {
        luaL_argerror(L,1,"this protocol is already registered as postdissector");
    }

    return 0;
}

static int Proto_get_dissector(lua_State* L) {
    Proto proto = toProto(L,1);

    if (proto->handle) {
        pushDissector(L,proto->handle);
        return 1;
    } else {
        luaL_error(L,"The protocol hasn't been registered yet");
        return 0;
    }
}

static int Proto_set_dissector(lua_State* L) {
    Proto proto = toProto(L,1);

    if (lua_isfunction(L,3)) {
        /* insert the dissector into the dissectors table */
        gchar* loname = g_ascii_strdown(proto->name, -1);

        lua_rawgeti(L, LUA_REGISTRYINDEX, lua_dissectors_table_ref);
        lua_replace(L, 1);
        lua_pushstring(L,proto->name);
        lua_replace(L, 2);
        lua_settable(L,1);

        proto->handle = new_create_dissector_handle(dissect_lua, proto->hfid);

        new_register_dissector(loname, dissect_lua, proto->hfid);

        return 0;
    } else {
        luaL_argerror(L,3,"The dissector of a protocol must be a function");
        return 0;
    }
}

static int Proto_get_prefs(lua_State* L) {
    Proto proto = toProto(L,1);
    pushPrefs(L,&proto->prefs);
    return 1;
}

static int Proto_set_init(lua_State* L) {
    Proto proto = toProto(L,1);

    if (lua_isfunction(L,3)) {
        /* insert the dissector into the dissectors table */
        lua_pushstring(L, WSLUA_INIT_ROUTINES);
        lua_gettable(L, LUA_GLOBALSINDEX);
        lua_replace(L, 1);
        lua_pushstring(L,proto->name);
        lua_replace(L, 2);
        lua_settable(L,1);

        return 0;
    }  else {
        luaL_argerror(L,3,"The initializer of a protocol must be a function");
        return 0;
    }
}

static int Proto_get_name(lua_State* L) {
    Proto proto = toProto(L,1);
    lua_pushstring(L,proto->name);
    return 1;
}

static int Proto_get_description(lua_State* L) {
    Proto proto = toProto(L,1);
    lua_pushstring(L,proto->desc);
    return 1;
}

static int Proto_get_fields(lua_State* L) {
    Proto proto = toProto(L,1);
    lua_rawgeti(L, LUA_REGISTRYINDEX, proto->fields);
    return 1;
}

void wslua_print_stack(char* s, lua_State* L) {
    int i;

    for (i=1;i<=lua_gettop(L);i++) {
        printf("%s-%i: %s\n",s,i,lua_typename (L,lua_type(L, i)));
    }
    printf("\n");
}

static int Proto_set_fields(lua_State* L) {
    Proto proto = toProto(L,1);
#define FIELDS_TABLE 2
#define NEW_TABLE 3
#define NEW_FIELD 3

    lua_rawgeti(L, LUA_REGISTRYINDEX, proto->fields);
    lua_replace(L,FIELDS_TABLE);

    if( lua_istable(L,NEW_TABLE)) {
        for (lua_pushnil(L); lua_next(L, NEW_TABLE); ) {
            if (isProtoField(L,5)) {
                luaL_ref(L,FIELDS_TABLE);
            } else if (! lua_isnil(L,5) ) {
                return luaL_error(L,"only ProtoFields should be in the table");
            }
        }
    } else if (isProtoField(L,NEW_FIELD)){
        lua_pushvalue(L, NEW_FIELD);
        luaL_ref(L,FIELDS_TABLE);

    } else {
        return luaL_error(L,"either a ProtoField or an array of protofields");
    }

    lua_pushvalue(L, 3);

    return 1;
}

typedef struct {
    gchar* name;
    lua_CFunction get;
    lua_CFunction set;
} proto_actions_t;

static const proto_actions_t proto_actions[] = {
    /* WSLUA_ATTRIBUTE Proto_dissector RW The protocol's dissector, a function you define */
    {"dissector",Proto_get_dissector, Proto_set_dissector},

    /* WSLUA_ATTRIBUTE Proto_fields RO The Fields Table of this dissector */
    {"fields" ,Proto_get_fields, Proto_set_fields},

    /* WSLUA_ATTRIBUTE Proto_prefs RO The preferences of this dissector */
    {"prefs",Proto_get_prefs,NULL},

    /* WSLUA_ATTRIBUTE Proto_init WO The init routine of this dissector, a function you define */
    {"init",NULL,Proto_set_init},

    /* WSLUA_ATTRIBUTE Proto_name RO The name given to this dissector */
    {"name",Proto_get_name,NULL},

    /* WSLUA_ATTRIBUTE Proto_description RO The description given to this dissector */
    {"description",Proto_get_description,NULL},

    {NULL,NULL,NULL}
};

static int Proto_index(lua_State* L) {
    Proto proto = checkProto(L,1);
    const gchar* name = luaL_checkstring(L,2);
    const proto_actions_t* pa;

    if (! (proto && name) ) return 0;

    for (pa = proto_actions; pa->name; pa++) {
        if ( g_str_equal(name,pa->name) ) {
            if (pa->get) {
                return pa->get(L);
            } else {
                luaL_error(L,"You cannot get the `%s' attribute of a protocol",name);
                return 0;
            }
        }
    }

    luaL_error(L,"A protocol doesn't have a `%s' attribute",name);
    return 0;
}

static int Proto_newindex(lua_State* L) {
    Proto proto = checkProto(L,1);
    const gchar* name = luaL_checkstring(L,2);
    const proto_actions_t* pa;

    if (! (proto && name) ) return 0;

    for (pa = proto_actions; pa->name; pa++) {
        if ( g_str_equal(name,pa->name) ) {
            if (pa->set) {
                return pa->set(L);
            } else {
                luaL_error(L,"You cannot set the `%s' attribute of a protocol",name);
                return 0;
            }
        }
    }

    luaL_error(L,"A protocol doesn't have a `%s' attribute",name);
    return 0;
}

static const luaL_reg Proto_meta[] = {
    {"__tostring", Proto_tostring},
    {"__index", Proto_index},
    {"__newindex", Proto_newindex},
    { NULL, NULL }
};

int Proto_register(lua_State* L) {

    WSLUA_REGISTER_META(Proto);

    lua_newtable(L);
    protocols_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    lua_pushstring(L, "Proto");
    lua_pushcfunction(L, Proto_new);
    lua_settable(L, LUA_GLOBALSINDEX);

    Pref_register(L);
    Prefs_register(L);

    return 1;
}

int Proto_commit(lua_State* L) {
    lua_settop(L,0);
    lua_rawgeti(L, LUA_REGISTRYINDEX, protocols_table_ref);

    for (lua_pushnil(L); lua_next(L, 1); lua_pop(L, 2)) {
        GArray* hfa = g_array_new(TRUE,TRUE,sizeof(hf_register_info));
        GArray* etta = g_array_new(TRUE,TRUE,sizeof(gint*));
        Proto proto;
        /* const gchar* proto_name = lua_tostring(L,2); */
        proto = checkProto(L,3);

        lua_rawgeti(L, LUA_REGISTRYINDEX, proto->fields);

        for (lua_pushnil(L); lua_next(L, 4); lua_pop(L, 1)) {
            ProtoField f = checkProtoField(L,6);
            hf_register_info hfri = { &(f->hfid), {f->name,f->abbr,f->type,f->base,VALS(f->vs),f->mask,f->blob,HFILL}};
            gint* ettp = &(f->ett);

            if (f->hfid != -2) {
                return luaL_error(L,"fields can be registered only once");
            }

            f->hfid = -1;
            g_array_append_val(hfa,hfri);
            g_array_append_val(etta,ettp);
        }

        proto_register_field_array(proto->hfid,(hf_register_info*)hfa->data,hfa->len);
        proto_register_subtree_array((gint**)etta->data,etta->len);

        g_array_free(hfa,FALSE);
        g_array_free(etta,FALSE);
    }

    return 0;
}

WSLUA_CLASS_DEFINE(Dissector,NOP,NOP);
/*
   A refererence to a dissector, used to call a dissector against a packet or a part of it.
 */

WSLUA_CONSTRUCTOR Dissector_get (lua_State *L) {
    /* Obtains a dissector reference by name */
#define WSLUA_ARG_Dissector_get_NAME 1 /* The name of the dissector */
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_Dissector_get_NAME);
    Dissector d;

    if (!name)
        WSLUA_ARG_ERROR(Dissector_get,NAME,"must be a string");

    if ((d = find_dissector(name))) {
        pushDissector(L, d);
        WSLUA_RETURN(1); /* The Dissector reference */
    } else
        WSLUA_ARG_ERROR(Dissector_get,NAME,"No such dissector");
}

WSLUA_METHOD Dissector_call(lua_State* L) {
    /* Calls a dissector against a given packet (or part of it) */
#define WSLUA_ARG_Dissector_call_TVB 2 /* The buffer to dissect */
#define WSLUA_ARG_Dissector_call_PINFO 3 /* The packet info */
#define WSLUA_ARG_Dissector_call_TREE 4 /* The tree on which to add the protocol items */

    Dissector d = checkDissector(L,1);
    Tvb tvb = checkTvb(L,WSLUA_ARG_Dissector_call_TVB);
    Pinfo pinfo = checkPinfo(L,WSLUA_ARG_Dissector_call_PINFO);
    TreeItem ti = checkTreeItem(L,WSLUA_ARG_Dissector_call_TREE);
    char *volatile error = NULL;

    if (! ( d && tvb && pinfo) ) return 0;

    TRY {
        call_dissector(d, tvb->ws_tvb, pinfo->ws_pinfo, ti->tree);
        /* XXX Are we sure about this??? is this the right/only thing to catch */
    } CATCH(ReportedBoundsError) {
        proto_tree_add_protocol_format(lua_tree->tree, lua_malformed, lua_tvb, 0, 0, "[Malformed Frame: Packet Length]" );
        error = "Malformed frame";
    } ENDTRY;

     if (error) { WSLUA_ERROR(Dissector_call,error); }

    return 0;
}

WSLUA_METAMETHOD Dissector_tostring(lua_State* L) {
    Dissector d = checkDissector(L,1);
    if (!d) return 0;
    lua_pushstring(L,dissector_handle_get_short_name(d));
    return 1;
}

static const luaL_reg Dissector_methods[] = {
    {"get", Dissector_get },
    {"call", Dissector_call },
    { NULL, NULL }
};

static const luaL_reg Dissector_meta[] = {
    {"__tostring", Dissector_tostring},
    { NULL, NULL }
};

int Dissector_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(Dissector);
    return 1;
}

WSLUA_CLASS_DEFINE(DissectorTable,NOP,NOP);
/*
 A table of subdissectors of a particular protocol (e.g. TCP subdissectors like http, smtp, sip are added to table "tcp.port").
 Useful to add more dissectors to a table so that they appear in the Decode As... dialog.
 */

WSLUA_CONSTRUCTOR DissectorTable_new (lua_State *L) {
    /* Creates a new DissectorTable for your dissector's use. */
#define WSLUA_ARG_DissectorTable_new_TABLENAME 1 /* The short name of the table. */
#define WSLUA_OPTARG_DissectorTable_new_UINAME 2 /* The name of the table in the User Interface (defaults to the name given). */
#define WSLUA_OPTARG_DissectorTable_new_TYPE 3 /* Either ftypes.UINT{8,16,24,32} or ftypes.STRING (defaults to ftypes.UINT32) */
#define WSLUA_OPTARG_DissectorTable_new_BASE 4 /* Either base.NONE, base.DEC, base.HEX, base.OCT, base.DEC_HEX or base.HEX_DEC (defaults to base.DEC) */
    gchar* name = (void*)luaL_checkstring(L,WSLUA_ARG_DissectorTable_new_TABLENAME);
    gchar* ui_name = (void*)luaL_optstring(L,WSLUA_OPTARG_DissectorTable_new_UINAME,name);
    enum ftenum type = luaL_optint(L,WSLUA_OPTARG_DissectorTable_new_TYPE,FT_UINT32);
    base_display_e base = luaL_optint(L,WSLUA_OPTARG_DissectorTable_new_BASE,BASE_DEC);

    if(!(name && ui_name)) return 0;

    name = g_strdup(name);
    ui_name = g_strdup(ui_name);

    switch(type) {
        case FT_STRING:
            base = BASE_NONE;
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
        {
            DissectorTable dt = g_malloc(sizeof(struct _wslua_distbl_t));

            dt->table = register_dissector_table(name, ui_name, type, base);
            dt->name = name;
            pushDissectorTable(L, dt);
        }
            WSLUA_RETURN(1); /* The newly created DissectorTable */
        default:
            WSLUA_OPTARG_ERROR(DissectorTable_new,TYPE,"must be ftypes.UINT{8,16,24,32} or ftypes.STRING");
    }
    return 0;
}

WSLUA_CONSTRUCTOR DissectorTable_get (lua_State *L) {
    /*
     Obtain a reference to an existing dissector table.
     */
#define WSLUA_ARG_DissectorTable_get_TABLENAME 1 /* The short name of the table. */
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_DissectorTable_get_TABLENAME);
    dissector_table_t table;

    if(!name) return 0;

    table = find_dissector_table(name);

    if (table) {
        DissectorTable dt = g_malloc(sizeof(struct _wslua_distbl_t));
        dt->table = table;
        dt->name = g_strdup(name);

        pushDissectorTable(L, dt);

        WSLUA_RETURN(1); /* The DissectorTable */
    } else
        WSLUA_ARG_ERROR(DissectorTable_get,TABLENAME,"no such dissector_table");

}

WSLUA_METHOD DissectorTable_add (lua_State *L) {
    /*
     Add a dissector to a table.
     */
#define WSLUA_ARG_DissectorTable_add_PATTERN 2 /* The pattern to match (either an integer or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_add_DISSECTOR 3 /* The dissector to add (either an Proto or a Dissector). */

    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    Dissector handle;

    if (!dt) return 0;

    if( isProto(L,WSLUA_ARG_DissectorTable_add_DISSECTOR) ) {
        Proto p;
        p = toProto(L,WSLUA_ARG_DissectorTable_add_DISSECTOR);
        handle = p->handle;

        if (! handle)
            WSLUA_ARG_ERROR(DissectorTable_add,DISSECTOR,"a Protocol that does not have a dissector cannot be added to a table");

    } else if ( isDissector(L,WSLUA_ARG_DissectorTable_add_DISSECTOR) ) {
        handle = toDissector(L,WSLUA_ARG_DissectorTable_add_DISSECTOR);
    } else
        WSLUA_ARG_ERROR(DissectorTable_add,DISSECTOR,"must be either Proto or Dissector");

    type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        gchar* pattern = g_strdup(luaL_checkstring(L,WSLUA_ARG_DissectorTable_add_PATTERN));
        dissector_add_string(dt->name, pattern,handle);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        int port = luaL_checkint(L, WSLUA_ARG_DissectorTable_add_PATTERN);
        dissector_add_uint(dt->name, port, handle);
    } else {
        luaL_error(L,"Strange type %d for a DissectorTable",type);
    }

    return 0;
}

WSLUA_METHOD DissectorTable_remove (lua_State *L) {
    /*
     Remove a dissector from a table
     */
#define WSLUA_ARG_DissectorTable_remove_PATTERN 2 /* The pattern to match (either an integer or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_remove_DISSECTOR 3 /* The dissector to add (either an Proto or a Dissector). */
    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    Dissector handle;

    if (!dt) return 0;

    if( isProto(L,WSLUA_ARG_DissectorTable_remove_DISSECTOR) ) {
        Proto p;
        p = toProto(L,WSLUA_ARG_DissectorTable_remove_DISSECTOR);
        handle = p->handle;

    } else if ( isDissector(L,WSLUA_ARG_DissectorTable_remove_DISSECTOR) ) {
        handle = toDissector(L,WSLUA_ARG_DissectorTable_remove_DISSECTOR);
    } else
        WSLUA_ARG_ERROR(DissectorTable_add,DISSECTOR,"must be either Proto or Dissector");

    type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        gchar* pattern = g_strdup(luaL_checkstring(L,2));
        dissector_delete_string(dt->name, pattern,handle);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        int port = luaL_checkint(L, 2);
        dissector_delete_uint(dt->name, port, handle);
    }

    return 0;
}

WSLUA_METHOD DissectorTable_try (lua_State *L) {
    /*
     Try to call a dissector from a table
     */
#define WSLUA_ARG_DissectorTable_try_PATTERN 2 /* The pattern to be matched (either an integer or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_try_TVB 3 /* The buffer to dissect */
#define WSLUA_ARG_DissectorTable_try_PINFO 4 /* The packet info */
#define WSLUA_ARG_DissectorTable_try_TREE 5 /* The tree on which to add the protocol items */
    DissectorTable dt = checkDissectorTable(L,1);
    Tvb tvb = checkTvb(L,3);
    Pinfo pinfo = checkPinfo(L,4);
    TreeItem ti = checkTreeItem(L,5);
    ftenum_t type;
    gboolean handled = FALSE;
    gchar *volatile error = NULL;

    if (! (dt && tvb && tvb->ws_tvb && pinfo && ti) ) return 0;

    type = get_dissector_table_selector_type(dt->name);

    TRY {

        if (type == FT_STRING) {
            const gchar* pattern = luaL_checkstring(L,2);

            if (!pattern)
                handled = TRUE;

            else if (dissector_try_string(dt->table,pattern,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree))
                handled = TRUE;

        } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
            int port = luaL_checkint(L, 2);

            if (dissector_try_uint(dt->table,port,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree))
                handled = TRUE;

        } else {
            luaL_error(L,"No such type of dissector_table");
        }

        if (!handled)
            call_dissector(lua_data_handle,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree);

        /* XXX Are we sure about this??? is this the right/only thing to catch */
    } CATCH(ReportedBoundsError) {
        proto_tree_add_protocol_format(lua_tree->tree, lua_malformed, lua_tvb, 0, 0, "[Malformed Frame: Packet Length]" );
        error = "Malformed frame";
    } ENDTRY;

    if (error) { WSLUA_ERROR(DissectorTable_try,error); }

    return 0;
}

WSLUA_METHOD DissectorTable_get_dissector (lua_State *L) {
    /*
     Try to obtain a dissector from a table.
     */
#define WSLUA_ARG_DissectorTable_try_PATTERN 2 /* The pattern to be matched (either an integer or a string depending on the table's type). */

    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    dissector_handle_t handle = lua_data_handle;

    if (!dt) return 0;

    type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        const gchar* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_try_PATTERN);

        if (!pattern) WSLUA_ARG_ERROR(DissectorTable_try,PATTERN,"must be a string");

        handle = dissector_get_string_handle(dt->table,pattern);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        int port = luaL_checkint(L, WSLUA_ARG_DissectorTable_try_PATTERN);
        handle = dissector_get_uint_handle(dt->table,port);
    }

    if (handle) {
        pushDissector(L,handle);
        WSLUA_RETURN(1); /* The dissector handle if found */
    } else {
        lua_pushnil(L);
        WSLUA_RETURN(1); /* nil if not found */
    }
}

WSLUA_METAMETHOD DissectorTable_tostring(lua_State* L) {
/**/
    /* XXX It would be nice to iterate and print which dissectors it has */
    DissectorTable dt = checkDissectorTable(L,1);
    GString* s;
    ftenum_t type;

    if (!dt) return 0;

    type =  get_dissector_table_selector_type(dt->name);
    s = g_string_new("DissectorTable ");

    switch(type) {
        case FT_STRING:
        {
            g_string_append_printf(s,"%s String:\n",dt->name);
            break;
        }
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
        {
            int base = get_dissector_table_base(dt->name);
            g_string_append_printf(s,"%s Integer(%i):\n",dt->name,base);
            break;
        }
        default:
            luaL_error(L,"Strange table type");
    }

    lua_pushstring(L,s->str);
    g_string_free(s,TRUE);
    return 1;
}

static const luaL_reg DissectorTable_methods[] = {
    {"new", DissectorTable_new },
    {"get", DissectorTable_get },
    {"add", DissectorTable_add },
    {"remove", DissectorTable_remove },
    {"try", DissectorTable_try },
    {"get_dissector", DissectorTable_get_dissector },
    { NULL, NULL }
};

static const luaL_reg DissectorTable_meta[] = {
    {"__tostring", DissectorTable_tostring},
    { NULL, NULL }
};

int DissectorTable_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(DissectorTable);
    return 1;
}
