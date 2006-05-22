/*
 * lua_proto.c
 *
 * Ethereal's interface to the Lua Programming Language
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

#include "elua.h"

ELUA_CLASS_DEFINE(Pref,NOP) /* A preference of a Protocol. */

static int new_pref(lua_State* L, pref_type_t type) {
    const gchar* label = luaL_optstring(L,1,NULL);
    const gchar* descr = luaL_optstring(L,3,"");
    
    Pref pref = g_malloc(sizeof(eth_pref_t));
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
        default:
            g_assert_not_reached();
            break;

    }

    pushPref(L,pref);
    return 1;
    
}

ELUA_CONSTRUCTOR Pref_bool(lua_State* L) {
	/*
	 * Creates a boolean preference to be added to a Protocol's prefs table.
	 */
#define ELUA_ATTR_Pref_bool_LABEL 1 /* The Label (text in the right side of the preference input) for this preference */
#define ELUA_ATTR_Pref_bool_DEFAULT 2 /* The default value for this preference */
#define ELUA_ATTR_Pref_bool_DESCR 3 /* A description of what this preference is */
    return new_pref(L,PREF_BOOL);
}

ELUA_CONSTRUCTOR Pref_uint(lua_State* L) {
	/*
	 * Creates an (unsigned) integer preference to be added to a Protocol's prefs table.
	 */
#define ELUA_ATTR_Pref_uint_LABEL 1 /* The Label (text in the right side of the preference input) for this preference */
#define ELUA_ATTR_Pref_uint_DEFAULT 2 /* The default value for this preference */
#define ELUA_ATTR_Pref_uint_DESCR 3 /* A description of what this preference is */
    return new_pref(L,PREF_UINT);
}

ELUA_CONSTRUCTOR Pref_string(lua_State* L) {
	/*
	 * Creates a string preference to be added to a Protocol's prefs table.
	 */
#define ELUA_ATTR_Pref_string_LABEL 1 /* The Label (text in the right side of the preference input) for this preference */
#define ELUA_ATTR_Pref_string_DEFAULT 2 /* The default value for this preference */
#define ELUA_ATTR_Pref_string_DESCR 3 /* A description of what this preference is */
    return new_pref(L,PREF_STRING);
}

static int Pref_gc(lua_State* L) {
    Pref pref = checkPref(L,1);
    
    if (pref && ! pref->name) {
        if (pref->label) g_free(pref->label);
        if (pref->desc) g_free(pref->desc);
        if (pref->type == PREF_STRING) g_free((void*)pref->value.s);
        g_free(pref);
    }
    
    return 0;
}

ELUA_METHODS Pref_methods[] = {
    {"bool",   Pref_bool},
    {"uint",   Pref_uint},
    {"string",   Pref_string},
    {0,0}
};

ELUA_META Pref_meta[] = {
    {"__gc",   Pref_gc},
    {0,0}
};


ELUA_REGISTER Pref_register(lua_State* L) {
	ELUA_REGISTER_CLASS(Pref);
    return 1;
}

ELUA_CLASS_DEFINE(Prefs,NOP) /* The table of preferences of a protocol */

ELUA_METAMETHOD Prefs__newindex(lua_State* L) {
	/* creates a new preference */
#define ELUA_ARG_Prefs__newindex_NAME 2 /* The abbreviation of this preference */
#define ELUA_ARG_Prefs__newindex_PREF 3 /* A valid still unassigned Pref object */

    Pref prefs = checkPrefs(L,1);
    const gchar* name = luaL_checkstring(L,ELUA_ARG_Prefs__newindex_NAME);
    Pref pref = checkPref(L,ELUA_ARG_Prefs__newindex_PREF);
    Pref p;

	if (! prefs ) return 0;

	if (! name ) 
		ELUA_ARG_ERROR(Prefs__newindex,NAME,"must be a string");

	if (! pref )
		ELUA_ARG_ERROR(Prefs__newindex,PREF,"must be a valid Pref");
    
    if (pref->name)
        ELUA_ARG_ERROR(Prefs__newindex,NAME,"cannot change existing preference");

	if (pref->proto)
		ELUA_ARG_ERROR(Prefs__newindex,PREF,"cannot be added to more than one protocol");

    p = prefs;
    
    do {
        if ( p->name && g_str_equal(p->name,name) ) {
            luaL_error(L,"a preference named %s exists already",name);
            return 0;
        }
        
        if ( ! p->next) {
            p->next = pref;
            
            pref->name = g_strdup(name);
            
            if (!pref->label)
                pref->label = g_strdup(name);

            if (!prefs->proto->prefs_module) {
                prefs->proto->prefs_module = prefs_register_protocol(prefs->proto->hfid, NULL);
   
            }
            
            switch(pref->type) {
                case PREF_BOOL: 
                    prefs_register_bool_preference(prefs->proto->prefs_module,
                                                   pref->name,
                                                   pref->label,
                                                   pref->desc,
                                                   &(pref->value.b));
                    break;
                case PREF_UINT:
                    prefs_register_uint_preference(prefs->proto->prefs_module,
                                                   pref->name,
                                                   pref->label,
                                                   pref->desc,
                                                   10,
                                                   &(pref->value.u));
                    break;
                case PREF_STRING:
                    prefs_register_string_preference(prefs->proto->prefs_module, 
                                                     pref->name,
                                                     pref->label,
                                                     pref->desc,
                                                     &(pref->value.s));
                    break;
                default:
                    ELUA_ERROR(Prefs__newindex,"unknow Pref type");
            }
            
            pref->proto = p->proto;
            
            ELUA_RETURN(0);
        }
    } while (( p = p->next ));

	luaL_error(L,"this should not happen!");
    
    ELUA_RETURN(0);
}

ELUA_METAMETHOD Prefs__index(lua_State* L) {
	/* get the value of a preference setting */
#define ELUA_ARG_Prefs__index_NAME 2 /* The abbreviation of this preference  */

    Pref prefs = checkPrefs(L,1);
    const gchar* name = luaL_checkstring(L,2);
    
    if (! ( name && prefs ) ) return 0;
    
    prefs = prefs->next;
    
    do {
        if ( g_str_equal(prefs->name,name) ) {
            switch (prefs->type) {
                case PREF_BOOL: lua_pushboolean(L, prefs->value.b); break;
                case PREF_UINT: lua_pushnumber(L,(lua_Number)prefs->value.u); break;
                case PREF_STRING: lua_pushstring(L,prefs->value.s); break;
                default: ELUA_ERROR(Prefs__index,"unknow Pref type");
            }
            ELUA_RETURN(1); /* the current value of the preference */
        }
    } while (( prefs = prefs->next ));

    ELUA_ARG_ERROR(Prefs__index,NAME,"no preference named like this");
    ELUA_RETURN(0);
}

ELUA_META Prefs_meta[] = {
    {"__newindex",   Prefs__newindex},
    {"__index",   Prefs__index},
    {0,0}
};

ELUA_REGISTER Prefs_register(lua_State* L) {
	ELUA_REGISTER_META(Prefs);
    return 1;
}


ELUA_CLASS_DEFINE(ProtoField,FAIL_ON_NULL("null ProtoField"))
/*
 * A Protocol field (to be used when adding items to the dissection tree)
 */

static const eth_ft_types_t ftenums[] = {
{"FT_BOOLEAN",FT_BOOLEAN},
{"FT_UINT8",FT_UINT8},
{"FT_UINT16",FT_UINT16},
{"FT_UINT24",FT_UINT24},
{"FT_UINT32",FT_UINT32},
{"FT_UINT64",FT_UINT64},
{"FT_INT8",FT_INT8},
{"FT_INT16",FT_INT16},
{"FT_INT24",FT_INT24},
{"FT_INT32",FT_INT32},
{"FT_INT64",FT_INT64},
{"FT_FLOAT",FT_FLOAT},
{"FT_DOUBLE",FT_DOUBLE},
{"FT_STRING",FT_STRING},
{"FT_STRINGZ",FT_STRINGZ},
{"FT_ETHER",FT_ETHER},
{"FT_BYTES",FT_BYTES},
{"FT_UINT_BYTES",FT_UINT_BYTES},
{"FT_IPv4",FT_IPv4},
{"FT_IPv6",FT_IPv6},
{"FT_IPXNET",FT_IPXNET},
{"FT_FRAMENUM",FT_FRAMENUM},
{"FT_GUID",FT_GUID},
{"FT_OID",FT_OID},
{NULL,FT_NONE}
};

#if 0
static enum ftenum get_ftenum(const gchar* type) {
    const eth_ft_types_t* ts;
    for (ts = ftenums; ts->str; ts++) {
        if ( g_str_equal(ts->str,type) ) {
            return ts->id;
        }
    }
    
    return FT_NONE;
}
#endif

static const gchar* ftenum_to_string(enum ftenum ft) {
    const eth_ft_types_t* ts;
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
	{ "BASE_NONE", BASE_NONE},
	{"BASE_DEC", BASE_DEC},
	{"BASE_HEX", BASE_HEX},
	{"BASE_OCT", BASE_OCT},
	{"BASE_DEC_HEX", BASE_DEC_HEX},
	{"BASE_HEX_DEC", BASE_HEX_DEC},
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

#if 0
static base_display_e string_to_base(const gchar* str) {
    const struct base_display_string_t* b;
    for (b=base_displays;b->str;b++) {
        if ( g_str_equal(str,b->str))
            return b->base;
    }
    return BASE_NONE;
}
#endif

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
            luaL_argerror(L,idx,"All keys of a table used as vaalue_string must be integers");
            g_array_free(vs,TRUE);
            return NULL;
        }
        
        if (! lua_isstring(L,-1)) {
            luaL_argerror(L,idx,"All values of a table used as vaalue_string must be strings");
            g_array_free(vs,TRUE);
            return NULL;
        }
        
        v.value = (guint32)lua_tonumber(L,-2);
        v.strptr = g_strdup(lua_tostring(L,-1));
        
        g_array_append_val(vs,v);
        
        lua_pop(L, 1);
    }
    
    lua_pop(L, 1);
    
    ret = (value_string*)vs->data;
    
    g_array_free(vs,FALSE);

    return ret;
    
}    

ELUA_CONSTRUCTOR ProtoField_new(lua_State* L) { /* Creates a new field to be used in a protocol. */
#define ELUA_ARG_ProtoField_new_NAME 1 /* Actual name of the field (the string that appears in the tree).  */
#define ELUA_ARG_ProtoField_new_ABBR 2 /* Filter name of the field (the string that is used in filters).  */
#define ELUA_ARG_ProtoField_new_TYPE 3 /* Field Type (FT_*).  */
#define ELUA_OPTARG_ProtoField_new_VALUESTRING 3 /* a ValueString object. */
#define ELUA_OPTARG_ProtoField_new_BASE 4 /* The representation BASE_*. */
#define ELUA_OPTARG_ProtoField_new_MASK 5 /* the bitmask to be used.  */
#define ELUA_OPTARG_ProtoField_new_DESCR 6 /* The description of the field.  */
	
    ProtoField f = g_malloc(sizeof(eth_field_t));
    value_string* vs;
    
    /* will be using -2 as far as the field has not been added to an array then it will turn -1 */
    f->hfid = -2;
	f->ett = -1;
    f->name = g_strdup(luaL_checkstring(L,ELUA_ARG_ProtoField_new_NAME));
    f->abbr = g_strdup(luaL_checkstring(L,ELUA_ARG_ProtoField_new_ABBR));
    f->type = luaL_checkint(L,ELUA_ARG_ProtoField_new_TYPE);
    
	/*XXX do it better*/
    if (f->type == FT_NONE) { 
        ELUA_ARG_ERROR(ProtoField_new,TYPE,"invalid FT_type");
        return 0;
    }
    
    if (! lua_isnil(L,4) ) {
        vs = value_string_from_table(L,4);
        
        if (vs) {
            f->vs = vs;
        } else {
            g_free(f);
            return 0;
        }
        
        
    } else {
        f->vs = NULL;
    }
    
    /* XXX: need BASE_ERROR */
    f->base = luaL_optint(L, ELUA_OPTARG_ProtoField_new_BASE, BASE_NONE);
    f->mask = luaL_optint(L, ELUA_OPTARG_ProtoField_new_MASK, 0x0);
    f->blob = g_strdup(luaL_optstring(L,ELUA_OPTARG_ProtoField_new_DESCR,""));
    
    pushProtoField(L,f);
    
    ELUA_RETURN(1); /* The newly created ProtoField object */ 
}


static int ProtoField_integer(lua_State* L, enum ftenum type) {
    ProtoField f = g_malloc(sizeof(eth_field_t));
	const gchar* abbr = luaL_checkstring(L,1);
    const gchar* name = luaL_optstring(L,2,abbr);
    base_display_e base = luaL_optint(L, 3, BASE_DEC);
    value_string* vs = (lua_gettop(L) > 3) ? value_string_from_table(L,4) : NULL;
    int mask = luaL_optint(L, 5, 0x0);
    const gchar* blob = luaL_optstring(L,6,"");

    if (base < BASE_DEC || base > BASE_HEX_DEC) {
        luaL_argerror(L,2,"Base must be either BASE_DEC, BASE_HEX, BASE_OCT,"
                      " BASE_DEC_HEX, BASE_DEC_HEX or BASE_HEX_DEC");
        return 0;
    }

    f->hfid = -2;
	f->ett = -1;
    f->name = g_strdup(name);
    f->abbr = g_strdup(abbr);
    f->type = type;
    f->vs = vs;
    f->base = base;
    f->mask = mask;
    f->blob = g_strdup(blob);
    
    
    pushProtoField(L,f);
    
    return 1;
}

#define PROTOFIELD_INTEGER(lower,FT) static int ProtoField_##lower(lua_State* L) { return ProtoField_integer(L,FT); }
/* ELUA_SECTION Protofield integer constructors */
/* ELUA_TEXT integer type ProtoField constructors use the following arguments */
/* ELUA_ARG_DESC Protofield_integer ABBR abbreviated name of the field (the string used in filters)  */
/* ELUA_OPTARG_DESC Protofield_integer NAME Actual name of the field (the string that appears in the tree)  */
/* ELUA_ARGDESC Protofield_integer DESC description of the field  */
/* _ELUA_RETURNS_ Protofield_integer a protofiled item to be added to a ProtoFieldArray */
/* _ELUA_CONSTRUCTOR_ ProtoField_uint8 */
/* _ELUA_CONSTRUCTOR_ ProtoField_uint16 */
/* _ELUA_CONSTRUCTOR_ ProtoField_uint24 */
/* _ELUA_CONSTRUCTOR_ ProtoField_uint32 */
/* _ELUA_CONSTRUCTOR_ ProtoField_uint64 */
/* _ELUA_CONSTRUCTOR_ ProtoField_int8 */
/* _ELUA_CONSTRUCTOR_ ProtoField_int16 */
/* _ELUA_CONSTRUCTOR_ ProtoField_int24 */
/* _ELUA_CONSTRUCTOR_ ProtoField_int32 */
/* _ELUA_CONSTRUCTOR_ ProtoField_int64 */
/* _ELUA_CONSTRUCTOR_ ProtoField_framenum */
PROTOFIELD_INTEGER(uint8,FT_UINT8)
PROTOFIELD_INTEGER(uint16,FT_UINT16)
PROTOFIELD_INTEGER(uint24,FT_UINT24)
PROTOFIELD_INTEGER(uint32,FT_UINT32)
PROTOFIELD_INTEGER(uint64,FT_UINT64)
PROTOFIELD_INTEGER(int8,FT_INT8)
PROTOFIELD_INTEGER(int16,FT_INT8)
PROTOFIELD_INTEGER(int24,FT_INT8)
PROTOFIELD_INTEGER(int32,FT_INT8)
PROTOFIELD_INTEGER(int64,FT_INT8)
PROTOFIELD_INTEGER(framenum,FT_FRAMENUM)

static int ProtoField_other(lua_State* L,enum ftenum type) {
    ProtoField f = g_malloc(sizeof(eth_field_t));
    const gchar* abbr = luaL_checkstring(L,1);
    const gchar* name = luaL_optstring(L,2,abbr);
    const gchar* blob = luaL_optstring(L,3,"");
    
    f->hfid = -2;
	f->ett = -1;
    f->name = g_strdup(name);
    f->abbr = g_strdup(abbr);
    f->type = type;
    f->vs = NULL;
    f->base = ( type == FT_FLOAT || type == FT_DOUBLE) ? BASE_DEC : BASE_NONE;
    f->mask = 0;
    f->blob = g_strdup(blob);
    
    pushProtoField(L,f);
    
    return 1;
}

#define PROTOFIELD_OTHER(lower,FT) static int ProtoField_##lower(lua_State* L) { return ProtoField_other(L,FT); }
/* ELUA_SECTION Protofield integer constructors */
/* ELUA_TEXT integer type ProtoField constructors use the following arguments */
/* ELUA_ARG_DESC Protofield_integer ABBR abbreviated name of the field (the string used in filters)  */
/* ELUA_OPTARG_DESC Protofield_integer NAME Actual name of the field (the string that appears in the tree)  */
/* ELUA_ARGDESC Protofield_integer DESC : description of the field  */
/* _ELUA_RETURNS_ Protofield non integer : a protofiled item to be added to a ProtoFieldArray */
/* _ELUA_CONSTRUCTOR_ ProtoField_ipv4 */
/* _ELUA_CONSTRUCTOR_ ProtoField_ipv6 */
/* _ELUA_CONSTRUCTOR_ ProtoField_ether */
/* _ELUA_CONSTRUCTOR_ ProtoField_float */
/* _ELUA_CONSTRUCTOR_ ProtoField_double */
/* _ELUA_CONSTRUCTOR_ ProtoField_string */
/* _ELUA_CONSTRUCTOR_ ProtoField_strigz */
/* _ELUA_CONSTRUCTOR_ ProtoField_bytes */
/* _ELUA_CONSTRUCTOR_ ProtoField_ubytes */
/* _ELUA_CONSTRUCTOR_ ProtoField_guid */
/* _ELUA_CONSTRUCTOR_ ProtoField_oid */
/* _ELUA_CONSTRUCTOR_ ProtoField_bool */
PROTOFIELD_OTHER(ipv4,FT_IPv4)
PROTOFIELD_OTHER(ipv6,FT_IPv6)
PROTOFIELD_OTHER(ipx,FT_IPXNET)
PROTOFIELD_OTHER(ether,FT_ETHER)
PROTOFIELD_OTHER(float,FT_FLOAT)
PROTOFIELD_OTHER(double,FT_DOUBLE)
PROTOFIELD_OTHER(string,FT_STRING)
PROTOFIELD_OTHER(stringz,FT_STRINGZ)
PROTOFIELD_OTHER(bytes,FT_BYTES)
PROTOFIELD_OTHER(ubytes,FT_UINT_BYTES)
PROTOFIELD_OTHER(guid,FT_GUID)
PROTOFIELD_OTHER(oid,FT_OID)

/* XXX: T/F strings */
PROTOFIELD_OTHER(bool,FT_BOOLEAN)


static int ProtoField_tostring(lua_State* L) {
    ProtoField f = checkProtoField(L,1);
    gchar* s = g_strdup_printf("ProtoField(%i): %s %s %s %s %p %.8x %s",f->hfid,f->name,f->abbr,ftenum_to_string(f->type),base_to_string(f->base),f->vs,f->mask,f->blob);
    
    lua_pushstring(L,s);
    g_free(s);
    
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
    {"string",ProtoField_string},
    {"stringz",ProtoField_stringz},
    {"bytes",ProtoField_bytes},
    {"ubytes",ProtoField_ubytes},
    {"guid",ProtoField_guid},
    {"oid",ProtoField_oid},
    {0,0}
};

static const luaL_reg ProtoField_meta[] = {
    {"__gc", ProtoField_gc },
    {"__tostring", ProtoField_tostring },
    {0, 0}
};

int ProtoField_register(lua_State* L) {
    
	ELUA_REGISTER_CLASS(ProtoField);
        
    return 1;
}

ELUA_CLASS_DEFINE(Proto,NOP)
/*
  A new protocol in wireshark. Protocols have more uses, the main one is to dissect
  a protocol. But they can be just dummies used to register preferences for
  other purposes.
 */

static int protocols_table_ref = LUA_NOREF;

ELUA_CONSTRUCTOR Proto_new(lua_State* L) {
#define ELUA_ARG_Proto_new_NAME 1 /* The name of the protocol */
#define ELUA_ARG_Proto_new_DESC 1 /* A Long Text description of the protocol (usually lowercase) */
    const gchar* name = luaL_checkstring(L,1);
    const gchar* desc = luaL_checkstring(L,2);
    
    if ( name ) {
		gchar* loname = ep_strdup(name);
		g_strdown(loname);
        if ( proto_get_id_by_filter_name(loname) > 0 ) { 
            ELUA_ARG_ERROR(Proto_new,NAME,"there cannot be two protocols with the same name");
        } else {
            Proto proto = g_malloc(sizeof(eth_proto_t));
			gchar* loname = g_strdup(name);
			gchar* hiname = g_strdup(name);
			
			g_strdown(loname);
			g_strup(hiname);

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
			
			ELUA_RETURN(1); /* The newly created protocol */
        }
     } else {
        ELUA_ARG_ERROR(Proto_new,NAME,"must be a string");
     }

	return 0;
}



static int Proto_tostring(lua_State* L) { 
    Proto proto = checkProto(L,1);
    gchar* s;
    
    if (!proto) return 0;
    
    s = g_strdup_printf("Proto: %s",proto->name);
    lua_pushstring(L,s);
    g_free(s);
    
    return 1;
}

ELUA_FUNCTION elua_register_postdissector(lua_State* L) { 
    Proto proto = checkProto(L,1);
    if (!proto) return 0;
    
    if(!proto->is_postdissector) {
        if (! proto->handle) {
            proto->handle = create_dissector_handle(dissect_lua, proto->hfid);
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
       
        lua_rawgeti(L, LUA_REGISTRYINDEX, lua_dissectors_table_ref);
        lua_replace(L, 1);
        lua_pushstring(L,proto->name);
        lua_replace(L, 2);
        lua_settable(L,1);
        
        proto->handle = create_dissector_handle(dissect_lua, proto->hfid);
        
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
        lua_pushstring(L, ELUA_INIT_ROUTINES);
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


static int Proto_get_fields(lua_State* L) { 
    Proto proto = toProto(L,1);
    lua_rawgeti(L, LUA_REGISTRYINDEX, proto->fields);
    return 1;
}

void elua_print_stack(char* s, lua_State* L) {
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
	/* ELUA_ATTRIBUTE Pinfo_dissector RW the protocol's dissector, a function you define */
    {"dissector",Proto_get_dissector, Proto_set_dissector},

	/* ELUA_ATTRIBUTE Pinfo_fields RO the Fields Table of this dissector */
    {"fields" ,Proto_get_fields, Proto_set_fields},
	
	/* ELUA_ATTRIBUTE Proto_get_prefs RO the preferences of this dissector */
    {"prefs",Proto_get_prefs,NULL},

	/* ELUA_ATTRIBUTE Proto_init WO the init routine of this dissector, a function you define */
    {"init",NULL,Proto_set_init},

	/* ELUA_ATTRIBUTE Proto_init RO the name given to this dissector */
    {"name",Proto_get_name,NULL},
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
    {0, 0}
};

int Proto_register(lua_State* L) {

	ELUA_REGISTER_META(Proto);

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
		const gchar* proto_name;
		proto_name = lua_tostring(L,2);
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



ELUA_CLASS_DEFINE(Dissector,NOP)
/*
   A refererence to a dissector, used to call a dissector against a packet or a part of it.
 */


ELUA_CONSTRUCTOR Dissector_get (lua_State *L) {
	/*
	 *  Obtains a dissector reference by name
	 */
#define ELUA_ARG_Dissector_get_NAME 1 /* The name of the dissector */
    const gchar* name = luaL_checkstring(L,1);
    Dissector d;
    
    if (!name)
        ELUA_ARG_ERROR(Dissector_get,NAME,"must be a string");
    
    if ((d = find_dissector(name))) {
        pushDissector(L, d);
        ELUA_RETURN(1); /* The Dissector reference */
    } else
        ELUA_ARG_ERROR(Dissector_get,NAME,"No such dissector");
    
}

ELUA_METHOD Dissector_call(lua_State* L) {
	/*
	 *  Calls a dissector against a given packet (or part of it)
	 */
#define ELUA_ARG_Dissector_call_TVB 2 /* The buffer to dissect */
#define ELUA_ARG_Dissector_call_PINFO 3 /* The packet info */
#define ELUA_ARG_Dissector_call_TREE 4 /* The tree on which to add the protocol items */
	
    Dissector d = checkDissector(L,1);
    Tvb tvb = checkTvb(L,ELUA_ARG_Dissector_call_TVB);
    Pinfo pinfo = checkPinfo(L,ELUA_ARG_Dissector_call_PINFO);
    TreeItem ti = checkTreeItem(L,ELUA_ARG_Dissector_call_TREE);
    
    if (! ( d && tvb && pinfo) ) return 0;
    
    TRY {
        call_dissector(d, tvb, pinfo, ti->tree);
		/* XXX Are we sure about this??? is this the right/only thing to catch */
    } CATCH(ReportedBoundsError) {
        proto_tree_add_protocol_format(lua_tree->tree, lua_malformed, lua_tvb, 0, 0, "[Malformed Frame: Packet Length]" );
        ELUA_ERROR(Dissector_call,"malformed frame");
        return 0;
    } ENDTRY;
    
    return 0;
}


static int Dissector_tostring(lua_State* L) {
    Dissector d = checkDissector(L,1);
    if (!d) return 0;
    lua_pushstring(L,dissector_handle_get_short_name(d));
    return 1;
}

static const luaL_reg Dissector_methods[] = {
    {"get", Dissector_get },
    {"call", Dissector_call },
    {0,0}
};

static const luaL_reg Dissector_meta[] = {
    {"__tostring", Dissector_tostring},
    {0, 0}
};

int Dissector_register(lua_State* L) {
	ELUA_REGISTER_CLASS(Dissector);
    return 1;
}


ELUA_CLASS_DEFINE(DissectorTable,NOP)
/*
 A table of subdissectors of a particular protocol (e.g. TCP subdissectors like http, smtp, sip are added to table "tcp.port").
 Useful to add more dissectors to a table so that they appear in the Decode As... dialog. 
 */

ELUA_CONSTRUCTOR DissectorTable_new (lua_State *L) {
	/*
	 Creates a new DissectorTable for your dissector's use .
	 */
#define ELUA_ARG_DissectorTable_new_TABLENAME 1 /* The short name of the table. */
#define ELUA_OPTARG_DissectorTable_new_UINAME 2 /* The name of the table in the User Interface (defaults to the name given). */
#define ELUA_OPTARG_DissectorTable_new_TYPE 3 /* either FT_UINT* or FT_STRING (defaults to FT_UINT32) */
    gchar* name = (void*)luaL_checkstring(L,ELUA_ARG_DissectorTable_new_TABLENAME);
    gchar* ui_name = (void*)luaL_optstring(L,ELUA_OPTARG_DissectorTable_new_UINAME,name);
    enum ftenum type = luaL_optint(L,ELUA_OPTARG_DissectorTable_new_TYPE,FT_UINT32);
    base_display_e base = luaL_optint(L,4,BASE_DEC);
    
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
            DissectorTable dt = g_malloc(sizeof(struct _eth_distbl_t));
            
            dt->table = register_dissector_table(name, ui_name, type, base);
            dt->name = name;
            pushDissectorTable(L, dt);
        }
            ELUA_RETURN(1); /* The newly created DissectorTable */
        default:
            ELUA_OPTARG_ERROR(DissectorTable_new,TYPE,"must be FTUINT* or FT_STRING");
    }
	return 0;    
}

ELUA_CONSTRUCTOR DissectorTable_get (lua_State *L) {
	/*
	 Obtain a reference to an existing dissector table.
	 */
#define ELUA_ARG_DissectorTable_get_TABLENAME 1 /* The short name of the table. */
    const gchar* name = luaL_checkstring(L,ELUA_ARG_DissectorTable_get_TABLENAME);
    dissector_table_t table;
    
    if(!name) return 0;
    
    table = find_dissector_table(name);
    
    if (table) {
        DissectorTable dt = g_malloc(sizeof(struct _eth_distbl_t));
        dt->table = table;
        dt->name = g_strdup(name);
        
        pushDissectorTable(L, dt);
        
		ELUA_RETURN(1); /* The DissectorTable */
    } else
        ELUA_ARG_ERROR(DissectorTable_get,TABLENAME,"no such dissector_table");
    
}


ELUA_METHOD DissectorTable_add (lua_State *L) {
	/*
	 Add a dissector to a table.
	 */
#define ELUA_ARG_DissectorTable_add_PATTERN 2 /* The pattern to match (either an integer or a string depending on the table's type). */
#define ELUA_ARG_DissectorTable_add_DISSECTOR 3 /* The dissector to add (either an Proto or a Dissector). */
	
    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    Dissector handle;

    if (!dt) return 0;

    if( isProto(L,ELUA_ARG_DissectorTable_add_DISSECTOR) ) {
        Proto p;
        p = toProto(L,ELUA_ARG_DissectorTable_add_DISSECTOR);
        handle = p->handle;
        
        if (! handle)
            ELUA_ARG_ERROR(DissectorTable_add,DISSECTOR,"a Protocol that does not have a dissector cannot be added to a table");
        
    } else if ( isDissector(L,ELUA_ARG_DissectorTable_add_DISSECTOR) ) {
        handle = toDissector(L,ELUA_ARG_DissectorTable_add_DISSECTOR);
    } else
		ELUA_ARG_ERROR(DissectorTable_add,DISSECTOR,"must be either Proto or Dissector");
    
    type = get_dissector_table_selector_type(dt->name);
    
    if (type == FT_STRING) {
        gchar* pattern = g_strdup(luaL_checkstring(L,ELUA_ARG_DissectorTable_add_PATTERN));
        dissector_add_string(dt->name, pattern,handle);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        int port = luaL_checkint(L, ELUA_ARG_DissectorTable_add_PATTERN);
        dissector_add(dt->name, port, handle);
    } else {
        luaL_error(L,"Strange type %d for a DissectorTable",type);
    }
    
    return 0;
}

ELUA_METHOD DissectorTable_remove (lua_State *L) {
	/*
	 Remove a dissector from a table
	 */
#define ELUA_ARG_DissectorTable_remove_PATTERN 2 /* The pattern to match (either an integer or a string depending on the table's type). */
#define ELUA_ARG_DissectorTable_remove_DISSECTOR 3 /* The dissector to add (either an Proto or a Dissector). */
    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    Dissector handle;
    
    if (!dt) return 0;
    
    if( isProto(L,ELUA_ARG_DissectorTable_remove_DISSECTOR) ) {
        Proto p;
        p = toProto(L,ELUA_ARG_DissectorTable_remove_DISSECTOR);
        handle = p->handle;
        
    } else if ( isDissector(L,ELUA_ARG_DissectorTable_remove_DISSECTOR) ) {
        handle = toDissector(L,ELUA_ARG_DissectorTable_remove_DISSECTOR);
	} else
		ELUA_ARG_ERROR(DissectorTable_add,DISSECTOR,"must be either Proto or Dissector");
    
    type = get_dissector_table_selector_type(dt->name);
    
    if (type == FT_STRING) {
        gchar* pattern = g_strdup(luaL_checkstring(L,2));
        dissector_delete_string(dt->name, pattern,handle);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        int port = luaL_checkint(L, 2);
        dissector_delete(dt->name, port, handle);
    }
    
    return 0;
}


ELUA_METHOD DissectorTable_try (lua_State *L) {
	/*
	 Try to call a dissector from a table
	 */
#define ELUA_ARG_DissectorTable_try_PATTERN 2 /* The pattern to be matched (either an integer or a string depending on the table's type). */
#define ELUA_ARG_DissectorTable_try_TVB 3 /* The buffer to dissect */
#define ELUA_ARG_DissectorTable_try_PINFO 4 /* The packet info */
#define ELUA_ARG_DissectorTable_try_TREE 5 /* The tree on which to add the protocol items */
    DissectorTable dt = checkDissectorTable(L,1);
    Tvb tvb = checkTvb(L,3);
    Pinfo pinfo = checkPinfo(L,4);
    TreeItem ti = checkTreeItem(L,5);
    ftenum_t type;
    
    if (! (dt && tvb && pinfo && ti) ) return 0;
    
    type = get_dissector_table_selector_type(dt->name);
    
	TRY {
		
		if (type == FT_STRING) {
			const gchar* pattern = luaL_checkstring(L,2);
			
			if (!pattern) return 0;
			
			if (dissector_try_string(dt->table,pattern,tvb,pinfo,ti->tree))
				return 0;
			
		} else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
			int port = luaL_checkint(L, 2);
		
			if (dissector_try_port(dt->table,port,tvb,pinfo,ti->tree)) 
				return 0;
			
		} else {
			luaL_error(L,"No such type of dissector_table");
		}
		
		call_dissector(lua_data_handle,tvb,pinfo,ti->tree);
	
		/* XXX Are we sure about this??? is this the right/only thing to catch */
	} CATCH(ReportedBoundsError) {
		proto_tree_add_protocol_format(lua_tree->tree, lua_malformed, lua_tvb, 0, 0, "[Malformed Frame: Packet Length]" );
		ELUA_ERROR(DissectorTable_try,"malformed frame");
	} ENDTRY;

	return 0;
	
}

ELUA_METHOD DissectorTable_get_dissector (lua_State *L) {
	/*
	 Try to obtain a dissector from a table.
	 */
#define ELUA_ARG_DissectorTable_try_PATTERN 2 /* The pattern to be matched (either an integer or a string depending on the table's type). */

    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    dissector_handle_t handle = lua_data_handle;
    
    if (!dt) return 0;
    
    type = get_dissector_table_selector_type(dt->name);
    
    if (type == FT_STRING) {
        const gchar* pattern = luaL_checkstring(L,ELUA_ARG_DissectorTable_try_PATTERN);
		
		if (!pattern) ELUA_ARG_ERROR(DissectorTable_try,PATTERN,"must be a string");
		
        handle = dissector_get_string_handle(dt->table,pattern);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        int port = luaL_checkint(L, ELUA_ARG_DissectorTable_try_PATTERN);
        handle = dissector_get_port_handle(dt->table,port);
    }
    
	if (handle) {
		pushDissector(L,handle);
		ELUA_RETURN(1); /* The dissector handle if found */
	} else {
		lua_pushnil(L);
		ELUA_RETURN(1); /* nil if not found */
	}
}


static int DissectorTable_tostring(lua_State* L) {
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
            g_string_sprintfa(s,"%s String:\n",dt->name);
            break;
        }
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
        {
            int base = get_dissector_table_base(dt->name);
            g_string_sprintfa(s,"%s Integer(%i):\n",dt->name,base);
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
    {0,0}
};

static const luaL_reg DissectorTable_meta[] = {
    {"__tostring", DissectorTable_tostring},
    {0, 0}
};

int DissectorTable_register(lua_State* L) {
	ELUA_REGISTER_CLASS(DissectorTable);
    return 1;
}



