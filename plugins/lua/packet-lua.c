/*
 * packet-lua.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <errno.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/filesystem.h>
#include <epan/report_err.h>
#include <epan/emem.h>

#define VALUE_STRING "ValueString"
typedef GArray* ValueString;

#define FIELD "Field"
typedef struct _eth_field_t* Field;

#define FIELD_ARRAY "FieldArray"
typedef GArray* FieldArray;

#define ETT "Ett"
typedef int* Ett;

#define ETT_ARRAY "EttArray"
typedef GArray* EttArray;

#define PROTO "Proto"
typedef struct _eth_proto_t* Proto;

#define DISSECTOR_TABLE "DissectorTable"
typedef struct _eth_distbl_t {
    dissector_table_t table;
    gchar* name;
}* DissectorTable;

#define DISSECTOR "Dissector"
typedef dissector_handle_t Dissector;

#define TVB "Tvb"
typedef tvbuff_t* Tvb;

#define COLUMN "Column"
typedef struct _eth_col_info {
    column_info* cinfo;
    gint col;
}* Column;

#define PINFO "Pinfo"
typedef packet_info* Pinfo;

#define TREE "Tree"
typedef proto_tree* Tree;

#define ITEM "Item"
typedef proto_item* Item;

#define ADDRESS "Address"
typedef address* Address;

static lua_State* L = NULL;
static dissector_handle_t data_handle = NULL;

typedef struct _eth_field_t {
    int hfid;
    char* name;
    char* abbr;
    char* blob;
    enum ftenum type;
    base_display_e base;
    value_string* vs;
    guint32 mask;
} eth_field_t;

typedef enum {PREF_BOOL,PREF_UINT,PREF_STRING} pref_type_t;

typedef struct _eth_pref_t {
    gchar* name;
    pref_type_t type;
    union {
        gboolean b;
        guint32 u;
        gint32 i;
        const gchar* s;
    } value;
    struct _eth_pref_t* next;
} eth_pref_t;

typedef struct _eth_proto_t {
    int hfid;
    char* name;
    char* filter;
    char* desc;
    hf_register_info* hfarray;
    gboolean hf_registered;
    module_t *prefs_module;
    eth_pref_t* prefs;
    dissector_handle_t handle;
} eth_proto_t;

typedef struct {const gchar* str; enum ftenum id; } eth_ft_types_t;

#define NOP

#define LUA_CLASS_OPS(C,CN,check_code) \
static  C to##C(lua_State* L, int index) { \
    C* v = (C*)lua_touserdata (L, index); \
    if (!v) luaL_typerror(L,index,CN); \
    return *v; \
} \
static  C check##C(lua_State* L, int index) { \
    C* p; \
    luaL_checktype(L,index,LUA_TUSERDATA); \
    p = (C*)luaL_checkudata(L, index, CN); \
    check_code; \
    return *p; \
} \
static  C* push##C(lua_State* L, C v) { \
    C* p = lua_newuserdata(L,sizeof(C)); *p = v; \
    luaL_getmetatable(L, CN); lua_setmetatable(L, -2); \
    return p; \
}

static int No_gc(lua_State *L _U_) { return 0; }

/*
 * ValueString class
 */
LUA_CLASS_OPS(ValueString,VALUE_STRING,if ( !p )  luaL_error(L,"null value_string"););

static int ValueString_new(lua_State* L) {
    ValueString vs = g_array_new(TRUE,TRUE,sizeof(value_string));
    pushValueString(L,vs);
    return 1;
}


static int ValueString_add(lua_State* L) {
    ValueString vs = checkValueString(L,1);
    value_string v = {0,NULL};
    
    v.value = luaL_checkint(L,2);
    v.strptr = g_strdup(luaL_checkstring(L,3));
    
    g_array_append_val(vs,v);
    
    return 0;
}

static int ValueString_match(lua_State* L) {
    ValueString vs = checkValueString(L,1);
    guint32 val = (guint32)luaL_checkint(L,2);
    const gchar* def = luaL_optstring(L,8,"Unknown");
    
    lua_pushstring(L,val_to_str(val, (value_string*)(vs->data), def));
    
    return 1;
}

static int ValueString_gc(lua_State* L) {
    ValueString vs = checkValueString(L,1);
    
    g_array_free(vs,TRUE);
    
    return 0;
}

static int ValueString_tostring(lua_State* L) {
    ValueString vs = checkValueString(L,1);
    value_string* c = (value_string*)vs->data;
    GString* s = g_string_new("");
    
    for(;c->strptr;c++) {
        g_string_sprintfa(s,"\t%u\t%s\n",c->value,c->strptr);
    }
    
    lua_pushstring(L,s->str);
    
    g_string_free(s,TRUE);
    
    return 1;
}

static const luaL_reg ValueString_methods[] = {
    {"new",   ValueString_new},
    {"add",   ValueString_add},
    {"match", ValueString_match},
    {0,0}
};


static const luaL_reg ValueString_meta[] = {
    {"__gc",       ValueString_gc},
    {"__tostring", ValueString_tostring},
    {0, 0}
};


static  int ValueString_register(lua_State* L) {
    luaL_openlib(L, VALUE_STRING, ValueString_methods, 0);
    luaL_newmetatable(L, VALUE_STRING);
    luaL_openlib(L, 0, ValueString_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}




/*
 * Field class
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

static enum ftenum get_ftenum(const gchar* type) {
    const eth_ft_types_t* ts;
    for (ts = ftenums; ts->str; ts++) {
        if ( g_str_equal(ts->str,type) ) {
            return ts->id;
        }
    }
    
    return FT_NONE;
}

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

static base_display_e string_to_base(const gchar* str) {
    const struct base_display_string_t* b;
    for (b=base_displays;b->str;b++) {
        if ( g_str_equal(str,b->str))
            return b->base;
    }
    return BASE_NONE;
}


LUA_CLASS_OPS(Field,FIELD,if (! *p) luaL_error(L,"null Field"));

static int Field_new(lua_State* L) {
    Field f = g_malloc(sizeof(eth_field_t));
    GArray* vs;
    
    f->hfid = -1;
    f->name = g_strdup(luaL_checkstring(L,1));
    f->abbr = g_strdup(luaL_checkstring(L,2));
    f->type = get_ftenum(luaL_checkstring(L,3));
    
    if (f->type == FT_NONE) {
        luaL_error(L,"invalid FT_type");
        return 0;
    }
    
    if (! lua_isnil(L,4) ) {
        vs = checkValueString(L,4);
        
        if (vs) {
            f->vs = (value_string*)vs->data;
        }
    } else {
        f->vs = NULL;
    }
    
    f->base = string_to_base(luaL_optstring(L, 5, "BASE_NONE"));
    f->mask = luaL_optint(L, 6, 0x0);
    f->blob = g_strdup(luaL_optstring(L,7,""));
    
    pushField(L,f);
    
    return 1;
}

static int Field_tostring(lua_State* L) {
    Field f = checkField(L,1);
    gchar* s = g_strdup_printf("Field: %s %s %s %s %p %.8x %s\n",f->name,f->abbr,ftenum_to_string(f->type),base_to_string(f->base),f->vs,f->mask,f->blob);
    
    lua_pushstring(L,s);
    g_free(s);
    
    return 1;
}



static const luaL_reg Field_methods[] = {
    {"new",   Field_new},
    {0,0}
};

static const luaL_reg Field_meta[] = {
    {"__gc",       No_gc},
    {"__tostring", Field_tostring},
    {0, 0}
};

static int Field_register(lua_State* L) {
    const eth_ft_types_t* ts;
    const struct base_display_string_t* b;

    luaL_openlib(L, FIELD, Field_methods, 0);
    luaL_newmetatable(L, FIELD);
    luaL_openlib(L, 0, Field_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    for (ts = ftenums; ts->str; ts++) {
        lua_pushstring(L, ts->str);
        lua_pushstring(L, ts->str);
        lua_settable(L, LUA_GLOBALSINDEX);
    }
    
    for (b=base_displays;b->str;b++) {
        lua_pushstring(L, b->str);
        lua_pushstring(L, b->str);
        lua_settable(L, LUA_GLOBALSINDEX);
    }
    
    return 1;
}




/*
 * FieldArray class
 */

LUA_CLASS_OPS(FieldArray,FIELD_ARRAY,if (! *p) luaL_error(L,"null FieldArray"));

static int FieldArray_new(lua_State* L) {
    FieldArray fa = g_array_new(TRUE,TRUE,sizeof(hf_register_info));
    pushFieldArray(L,fa);
    return 1;
}


static int FieldArray_add(lua_State* L) {
    FieldArray fa = checkFieldArray(L,1);
    Field f = checkField(L,2);
    hf_register_info hfri = { &(f->hfid), {f->name,f->abbr,f->type,f->base,VALS(f->vs),f->mask,f->blob,HFILL}};
    
    g_array_append_val(fa,hfri);
    
    return 0;
}

static int FieldArray_tostring(lua_State* L) {
    GString* s = g_string_new("FieldArray:\n");
    hf_register_info* f;
    FieldArray fa = checkFieldArray(L,1);
    unsigned i;
    
    for(i = 0; i< fa->len; i++) {
        f = &(((hf_register_info*)(fa->data))[i]);
        g_string_sprintfa(s,"%i %s %s %s %u %p %.8x %s\n",*(f->p_id),f->hfinfo.name,f->hfinfo.abbrev,ftenum_to_string(f->hfinfo.type),f->hfinfo.display,f->hfinfo.strings,f->hfinfo.bitmask,f->hfinfo.blurb);
    };
    
    lua_pushstring(L,s->str);
    g_string_free(s,TRUE);
    
    return 1;
}

static int FieldArray_gc(lua_State* L) {
    FieldArray vs = checkValueString(L,1);
    
    g_array_free(vs,TRUE);
    
    return 0;
}


static const luaL_reg FieldArray_methods[] = {
    {"new",   FieldArray_new},
    {"add",   FieldArray_add},
    {0,0}
};

static const luaL_reg FieldArray_meta[] = {
    {"__gc",       FieldArray_gc},
    {"__tostring", FieldArray_tostring},
    {0, 0}
};

static int FieldArray_register(lua_State* L) {
    luaL_openlib(L, FIELD_ARRAY, FieldArray_methods, 0);
    luaL_newmetatable(L, FIELD_ARRAY);
    luaL_openlib(L, 0, FieldArray_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}




/*
 * Ett class
 */

LUA_CLASS_OPS(Ett,ETT,NOP);

static int Ett_new(lua_State* L) {
    Ett e = g_malloc(sizeof(int));
    *e = -1;
    pushEtt(L,e);
    
    return 1;
}

static int Ett_tostring(lua_State* L) {
    Ett e = checkEtt(L,1);
    gchar* s = g_strdup_printf("Ett: %i",*e);
    
    lua_pushstring(L,s);
    g_free(s);
    
    return 1;
}


static const luaL_reg Ett_methods[] = {
    {"new",   Ett_new},
    {0,0}
};

static const luaL_reg Ett_meta[] = {
    {"__gc",       No_gc},
    {"__tostring", Ett_tostring},
    {0, 0}
};

static int Ett_register(lua_State* L) {
    luaL_openlib(L, ETT, Ett_methods, 0);
    luaL_newmetatable(L, ETT);
    luaL_openlib(L, 0, Ett_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}





/*
 * EttArray class
 */
LUA_CLASS_OPS(EttArray,ETT_ARRAY,if (! *p) luaL_error(L,"null EttArray"));


static int EttArray_new(lua_State* L) {
    EttArray ea = g_array_new(TRUE,TRUE,sizeof(gint*));
    pushEttArray(L,ea);
    return 1;
}


static int EttArray_add(lua_State* L) {
    EttArray ea = checkEttArray(L,1);
    Ett e = checkEtt(L,2);
    
    g_array_append_val(ea,e);
    
    return 0;
}

static int EttArray_tostring(lua_State* L) {
    GString* s = g_string_new("EttArray:\n");
    EttArray ea = checkEttArray(L,1);
    unsigned i;
    
    for(i = 0; i< ea->len; i++) {
        gint ett = *(((gint**)(ea->data))[i]);
        g_string_sprintfa(s,"%i\n",ett);
    };
    
    lua_pushstring(L,s->str);
    g_string_free(s,TRUE);
    
    return 1;
}

static int EttArray_register_to_ethereal(lua_State* L) {
    EttArray ea = checkEttArray(L,1);
    proto_register_subtree_array((gint *const *)ea->data, ea->len);
    return 0;
}

static int EttArray_gc(lua_State* L) {
    EttArray ea = checkEttArray(L,1);
    
    g_array_free(ea,FALSE);
    
    return 0;
}


static const luaL_reg EttArray_methods[] = {
    {"new",   EttArray_new},
    {"add",   EttArray_add},
    {"register",   EttArray_register_to_ethereal},
    {0,0}
};

static const luaL_reg EttArray_meta[] = {
    {"__gc",       EttArray_gc},
    {"__tostring", EttArray_tostring},
    {0, 0}
};

static int EttArray_register(lua_State* L) {
    luaL_openlib(L, ETT_ARRAY, EttArray_methods, 0);
    luaL_newmetatable(L, ETT_ARRAY);
    luaL_openlib(L, 0, EttArray_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}


/*
 * Proto class
 */
LUA_CLASS_OPS(Proto,PROTO,if (! *p) luaL_error(L,"null Proto"));

static void dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree);

static int Proto_new(lua_State* L) {
    Proto proto = g_malloc(sizeof(eth_proto_t));
    
    proto->hfid = -1;
    proto->name = g_strdup(luaL_checkstring(L,1));
    proto->filter = g_strdup(luaL_checkstring(L,2));
    proto->desc = g_strdup(luaL_checkstring(L,3));
    proto->hfarray = NULL;
    proto->prefs_module = NULL;
    proto->prefs = NULL;
    proto->handle = NULL;
    
    if (proto->name && proto->filter && proto->desc) {
        if ( proto_get_id_by_filter_name(proto->filter) > 0 ) { 
            g_free(proto);
            luaL_error(L,"Protocol exists already");
            return 0;
        } else {
            proto->hfid = proto_register_protocol(proto->desc,proto->name,proto->filter);
            proto->handle = create_dissector_handle(dissect_lua,proto->hfid);
            pushProto(L,proto);
            return 1;
        }
     } else {
         g_free(proto);
         luaL_error(L,"Missing Parameters");
         return 0;
     }

}

static int Proto_register_field_array(lua_State* L) {
    Proto proto = checkProto(L,1);
    FieldArray fa = checkFieldArray(L,2);
    
    if (proto && fa && fa->len) {
        if (proto->hfarray) {
            luaL_error(L,"field array already registered");
        }
        
        proto->hfarray = (hf_register_info*)(fa->data);
        proto_register_field_array(proto->hfid,proto->hfarray,fa->len);
        
    } else {
        luaL_error(L,"not a good field array");
    }
    
    return 0;
}

static int Proto_add_uint_pref(lua_State* L) {
    Proto proto = checkProto(L,1);
    gchar* abbr = g_strdup(luaL_checkstring(L,2));
    guint def = (guint)luaL_optint(L,3,0);
    guint base = (guint)luaL_optint(L,4,10);
    gchar* name = g_strdup(luaL_optstring (L, 5, ""));
    gchar* desc = g_strdup(luaL_optstring (L, 6, ""));
    
    if (proto && abbr) {
        eth_pref_t* pref = g_malloc(sizeof(eth_pref_t));
        pref->name = abbr;
        pref->type = PREF_UINT;
        pref->value.u = def;
        pref->next = NULL;
        
        if (! proto->prefs_module)
            proto->prefs_module = prefs_register_protocol(proto->hfid, NULL);
        
        if (! proto->prefs) {
            proto->prefs = pref;
        } else {
            eth_pref_t* p;
            for (p = proto->prefs; p->next; p = p->next) ;
            p->next = pref;
        }
        
        prefs_register_uint_preference(proto->prefs_module, abbr,name,
                                       desc, base, &(pref->value.u));
        
    } else {
        luaL_error(L,"missing a mandatory parameter");
    }
    
    return 0;
}

static int Proto_add_bool_pref(lua_State* L) {
    Proto proto = checkProto(L,1);
    gchar* abbr = g_strdup(luaL_checkstring(L,2));
    gboolean def = (gboolean)luaL_optint(L,3,FALSE);
    gchar* name = g_strdup(luaL_optstring (L, 4, ""));
    gchar* desc = g_strdup(luaL_optstring (L, 5, ""));
    
    if (proto && abbr) {
        eth_pref_t* pref = g_malloc(sizeof(eth_pref_t));
        pref->name = abbr;
        pref->type = PREF_BOOL;
        pref->value.b = def;
        pref->next = NULL;
        
        if (! proto->prefs_module)
            proto->prefs_module = prefs_register_protocol(proto->hfid, NULL);
        
        if (! proto->prefs) {
            proto->prefs = pref;
        } else {
            eth_pref_t* p;
            for (p = proto->prefs; p->next; p = p->next) ;
            p->next = pref;
        }
        
        prefs_register_bool_preference(proto->prefs_module, abbr,name,
                                       desc, &(pref->value.b));
        
    } else {
        luaL_error(L,"missing a mandatory parameter");
    }
    
    return 0;
}

static int Proto_add_string_pref(lua_State* L) {
    Proto proto = checkProto(L,1);
    gchar* abbr = g_strdup(luaL_checkstring(L,2));
    gchar* def = g_strdup(luaL_optstring (L, 3, ""));
    gchar* name = g_strdup(luaL_optstring (L, 4, ""));
    gchar* desc = g_strdup(luaL_optstring (L, 5, ""));
    
    if (proto && abbr) {
        eth_pref_t* pref = g_malloc(sizeof(eth_pref_t));
        pref->name = abbr;
        pref->type = PREF_STRING;
        pref->value.s = def;
        pref->next = NULL;
        
        if (! proto->prefs_module)
            proto->prefs_module = prefs_register_protocol(proto->hfid, NULL);
        
        if (! proto->prefs) {
            proto->prefs = pref;
        } else {
            eth_pref_t* p;
            for (p = proto->prefs; p->next; p = p->next) ;
            p->next = pref;
        }
        
        prefs_register_string_preference(proto->prefs_module, abbr,name,
                                         desc, &(pref->value.s));
        
    } else {
        luaL_error(L,"missing a mandatory parameter");
    }
    
    return 0;
}


static int Proto_get_pref(lua_State* L) {
    Proto proto = checkProto(L,1);
    gchar* abbr = g_strdup(luaL_checkstring(L,2));
    
    if (! proto || ! abbr) {
        return 0;
    }
    
    if (proto->prefs) {
        eth_pref_t* p;
        for (p = proto->prefs; p; p = p->next) {
            if (g_str_equal(p->name,abbr)) {
                switch(p->type) {
                    case PREF_BOOL:
                        lua_pushboolean(L, p->value.b);
                        break;
                    case PREF_UINT:
                        lua_pushnumber(L, (lua_Number)(p->value.u));
                        break;
                    case PREF_STRING:
                        lua_pushstring(L, p->value.s);
                        break;
                }
                return 1;
            }
        }
        
        luaL_error(L,"no such preference");
        return 0;
        
    } else {
        luaL_error(L,"no preferences");
        return 0;
    }
}


static int Proto_set_pref(lua_State* L) {
    Proto proto = checkProto(L,1);
    gchar* abbr = g_strdup(luaL_checkstring(L,2));
    
    if (! proto || ! abbr) {
        return 0;
    }
    
    if (proto->prefs) {
        eth_pref_t* p;
        for (p = proto->prefs; p; p = p->next) {
            if (g_str_equal(p->name,abbr)) {
                switch(p->type) {
                    case PREF_BOOL:
                        if (lua_isnumber(L, 3)) {
                            p->value.b  = lua_toboolean(L, 3);
                        } else {
                            p->value.b = TRUE;
                        }
                        break;
                    case PREF_UINT:
                        p->value.u = (guint32)luaL_checkint(L, 3);
                        break;
                    case PREF_STRING:
                        g_free((void*)p->value.s);
                        p->value.s = lua_isstring(L, 3) ? g_strdup(lua_tostring(L,3)): g_strdup("");
                        break;
                }
                return 0;
            }
        }
        
        luaL_error(L,"no such preference");
        return 0;
        
    } else {
        luaL_error(L,"no preferences");
        return 0;
    }
}

static int Proto_tostring(lua_State* L) { 
    Proto proto = checkProto(L,1);
    gchar* s = g_strdup_printf("a Proto: %s",proto->name);
    lua_pushstring(L,s);
    g_free(s);
    
    return 1;
}

static const luaL_reg Proto_methods[] = {
    {"new",   Proto_new},
    {"register_field_array",   Proto_register_field_array},
    {"add_uint_pref",   Proto_add_uint_pref},
    {"add_bool_pref",   Proto_add_bool_pref},
    {"add_string_pref",   Proto_add_string_pref},
    {"get_pref",   Proto_get_pref},
    {"set_pref",   Proto_set_pref},
    {0,0}
};

static const luaL_reg Proto_meta[] = {
    {"__gc",       No_gc},
    {"__tostring", Proto_tostring},
    {0, 0}
};

static int Proto_register(lua_State* L) {
    luaL_openlib(L, PROTO, Proto_methods, 0);
    luaL_newmetatable(L, PROTO);
    luaL_openlib(L, 0, Proto_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}



/*
 * Tvb class
 */


LUA_CLASS_OPS(Tvb,TVB,if (! *p) luaL_error(L,"null tvb"));

static int Tvb_new (lua_State *L) {
    int len = luaL_optint(L, 3, -1);
    pushTvb(L, tvb_new_subset( checkTvb(L,1),luaL_optint(L, 2, 0),len, len) );
    return 1;
}



#define TVBGET_FN(type) Tvb_get_ ## type

#define DEFINE_TVBGET(type,len)  static int TVBGET_FN(type) (lua_State *L) { \
    tvbuff_t* tvb = checkTvb(L,1); \
    int offset = luaL_checkint(L,2); \
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


static int Tvb_get_stringz(lua_State* L) {
    lua_pushstring(L,(gchar*)tvb_get_ephemeral_stringz(checkTvb(L,1),luaL_checkint(L,2),NULL));
    return 1;
}

static int Tvb_get_string(lua_State* L) {
    lua_pushstring(L,(gchar*)tvb_get_ephemeral_string(checkTvb(L,1),luaL_checkint(L,2),luaL_checkint(L,3)));
   return 1;
}

static int Tvb_tostring(lua_State* L) {
    Tvb tvb = checkTvb(L,1);
    int len = tvb_length(tvb);
    gchar* str = g_strdup_printf("TVB(%i) : %s",len,tvb_bytes_to_str(tvb,0,len));
    lua_pushstring(L,str);
    return 1;
}



static int Tvb_len(lua_State* L) {
    Tvb tvb = checkTvb(L,1);
    lua_pushnumber(L,tvb_length(tvb));
    return 1;
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
    {"len", Tvb_len},
    {0,0}
};

static const luaL_reg Tvb_meta[] = {
    {"__gc",       No_gc},
    {"__tostring", Tvb_tostring},
    {0, 0}
};

static int Tvb_register(lua_State* L) {
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

/* Address class */

/* Column class */
struct col_names_t {
    const gchar* name;
    int id;
};

static const struct col_names_t colnames[] = {
    {"COL_NUMBER",COL_NUMBER},
    {"COL_CLS_TIME",COL_CLS_TIME},
    {"COL_REL_TIME",COL_REL_TIME},
    {"COL_ABS_TIME",COL_ABS_TIME},
    {"COL_ABS_DATE_TIME",COL_ABS_DATE_TIME},
    {"COL_DELTA_TIME",COL_DELTA_TIME},
    {"COL_DEF_SRC",COL_DEF_SRC},
    {"COL_RES_SRC",COL_RES_SRC},
    {"COL_UNRES_SRC",COL_UNRES_SRC},
    {"COL_DEF_DL_SRC",COL_DEF_DL_SRC},
    {"COL_RES_DL_SRC",COL_RES_DL_SRC},
    {"COL_UNRES_DL_SRC",COL_UNRES_DL_SRC},
    {"COL_DEF_NET_SRC",COL_DEF_NET_SRC},
    {"COL_RES_NET_SRC",COL_RES_NET_SRC},
    {"COL_UNRES_NET_SRC",COL_UNRES_NET_SRC},
    {"COL_DEF_DST",COL_DEF_DST},
    {"COL_RES_DST",COL_RES_DST},
    {"COL_UNRES_DST",COL_UNRES_DST},
    {"COL_DEF_DL_DST",COL_DEF_DL_DST},
    {"COL_RES_DL_DST",COL_RES_DL_DST},
    {"COL_UNRES_DL_DST",COL_UNRES_DL_DST},
    {"COL_DEF_NET_DST",COL_DEF_NET_DST},
    {"COL_RES_NET_DST",COL_RES_NET_DST},
    {"COL_UNRES_NET_DST",COL_UNRES_NET_DST},
    {"COL_DEF_SRC_PORT",COL_DEF_SRC_PORT},
    {"COL_RES_SRC_PORT",COL_RES_SRC_PORT},
    {"COL_UNRES_SRC_PORT",COL_UNRES_SRC_PORT},
    {"COL_DEF_DST_PORT",COL_DEF_DST_PORT},
    {"COL_RES_DST_PORT",COL_RES_DST_PORT},
    {"COL_UNRES_DST_PORT",COL_UNRES_DST_PORT},
    {"COL_PROTOCOL",COL_PROTOCOL},
    {"COL_INFO",COL_INFO},
    {"COL_PACKET_LENGTH",COL_PACKET_LENGTH},
    {"COL_CUMULATIVE_BYTES",COL_CUMULATIVE_BYTES},
    {"COL_OXID",COL_OXID},
    {"COL_RXID",COL_RXID},
    {"COL_IF_DIR",COL_IF_DIR},
    {"COL_CIRCUIT_ID",COL_CIRCUIT_ID},
    {"COL_SRCIDX",COL_SRCIDX},
    {"COL_DSTIDX",COL_DSTIDX},
    {"COL_VSAN",COL_VSAN},
    {"COL_TX_RATE",COL_TX_RATE},
    {"COL_RSSI",COL_RSSI},
    {"COL_HPUX_SUBSYS",COL_HPUX_SUBSYS},
    {"COL_HPUX_DEVID",COL_HPUX_DEVID},
    {"COL_DCE_CALL",COL_DCE_CALL},
    {NULL,0}
};

static gint col_name_to_id(const gchar* name) {
    const struct col_names_t* cn;    
    for(cn = colnames; cn->name; cn++) {
        if (g_str_equal(cn->name,name)) {
            return cn->id;
        }
    }
    
    return 0;
}

static const gchar*  col_id_to_name(gint id) {
    const struct col_names_t* cn;    
    for(cn = colnames; cn->name; cn++) {
        if ( cn->id == id ) {
            return cn->name;
        }
    }
    return NULL;
}

LUA_CLASS_OPS(Column,COLUMN,if (! *p) luaL_error(L,"null column"));

static int Column_tostring(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* name = col_id_to_name(c->col);
    lua_pushstring(L,name ? name : "Unknown Column");
    return 1;
}

static int Column_clear(lua_State *L) {
    Column c = checkColumn(L,1);
    if (check_col(c->cinfo, c->col))
        col_clear(c->cinfo, c->col);
    return 0;
}

static int Column_set(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,2);
    
    if (check_col(c->cinfo, c->col))
        col_set_str(c->cinfo, c->col, s);
    
    return 0;
}

static int Column_append(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,2);
    
    if (check_col(c->cinfo, c->col))
        col_append_str(c->cinfo, c->col, s);
    
    return 0;
}
static int Column_preppend(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,2);
    
    if (check_col(c->cinfo, c->col))
        col_prepend_fstr(c->cinfo, c->col, "%s",s);
    
    return 0;
}

static int Column_gc(lua_State *L) {
    Column c = checkColumn(L,1);
    g_free(c);
    return 0;
}

static const luaL_reg Column_methods[] = {
    {"clear", Column_clear },
    {"set", Column_set },
    {"append", Column_append },
    {"preppend", Column_preppend },
    {0,0}
};


static const luaL_reg Column_meta[] = {
    {"__gc", Column_gc },
    {"__tostring", Column_tostring },
    {0,0}
};


static int Column_register(lua_State *L) {
    const struct col_names_t* cn;    

    luaL_openlib(L, COLUMN, Column_methods, 0);
    luaL_newmetatable(L, COLUMN);
    luaL_openlib(L, 0, Column_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    for(cn = colnames; cn->name; cn++) {
        lua_pushstring(L, cn->name);
        lua_pushstring(L, cn->name);
        lua_settable(L, LUA_GLOBALSINDEX);
    }

    return 1;
}

/* Pinfo class */
LUA_CLASS_OPS(Pinfo,PINFO,if (! *p) luaL_error(L,"null pinfo"));
static int Pinfo_tostring(lua_State *L) { lua_pushstring(L,"a Pinfo"); return 1; }

#define PINFO_GET_NUMBER(name,val) static int name(lua_State *L) {  Pinfo pinfo = checkPinfo(L,1); lua_pushnumber(L,(lua_Number)(val)); return 1; }
#define PINFO_GET_STRING(name,val) static int name(lua_State *L) {  Pinfo pinfo = checkPinfo(L,1); if (val) lua_pushstring(L,(const char*)(val)); else lua_pushnil(L); return 1; }

PINFO_GET_NUMBER(Pinfo_number,pinfo->fd->num);
PINFO_GET_NUMBER(Pinfo_len,pinfo->fd->pkt_len);
PINFO_GET_NUMBER(Pinfo_caplen,pinfo->fd->cap_len);
PINFO_GET_NUMBER(Pinfo_abs_ts,(((double)pinfo->fd->abs_ts.secs) + (((double)pinfo->fd->abs_ts.nsecs) / 1000000000.0) ));
PINFO_GET_NUMBER(Pinfo_rel_ts,(((double)pinfo->fd->rel_ts.secs) + (((double)pinfo->fd->rel_ts.nsecs) / 1000000000.0) ));
PINFO_GET_NUMBER(Pinfo_delta_ts,(((double)pinfo->fd->del_ts.secs) + (((double)pinfo->fd->del_ts.nsecs) / 1000000000.0) ));
PINFO_GET_NUMBER(Pinfo_visited,pinfo->fd->flags.visited);
PINFO_GET_NUMBER(Pinfo_ipproto,pinfo->ipproto);
PINFO_GET_NUMBER(Pinfo_circuit_id,pinfo->circuit_id);
PINFO_GET_NUMBER(Pinfo_ptype,pinfo->ptype);
PINFO_GET_NUMBER(Pinfo_match_port,pinfo->match_port);


PINFO_GET_STRING(Pinfo_src,address_to_str(&(pinfo->src)));
PINFO_GET_STRING(Pinfo_dst,address_to_str(&(pinfo->dst)));
PINFO_GET_STRING(Pinfo_net_src,address_to_str(&(pinfo->net_src)));
PINFO_GET_STRING(Pinfo_net_dst,address_to_str(&(pinfo->net_dst)));
PINFO_GET_STRING(Pinfo_dl_src,address_to_str(&(pinfo->dl_src)));
PINFO_GET_STRING(Pinfo_dl_dst,address_to_str(&(pinfo->dl_dst)));
PINFO_GET_STRING(Pinfo_match_string,pinfo->match_string);
PINFO_GET_STRING(Pinfo_curr_proto,pinfo->current_proto);

static int Pinfo_column(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
    Column c = g_malloc(sizeof(*c));
    
    c->cinfo = pinfo->cinfo;
    c->col = col_name_to_id(luaL_checkstring(L,2));
    
    pushColumn(L,c);
    return 1;
}

static const luaL_reg Pinfo_methods[] = {
    {"number", Pinfo_number },
    {"len", Pinfo_len },
    {"caplen", Pinfo_caplen },
    {"abs_ts",Pinfo_abs_ts },
    {"rel_ts",Pinfo_rel_ts },
    {"delta_ts",Pinfo_delta_ts },
    {"visited",Pinfo_visited },
    {"src_address", Pinfo_src },
    {"dst_address", Pinfo_dst },
    {"dl_src", Pinfo_dl_src },
    {"dl_dst", Pinfo_dl_dst },
    {"net_src", Pinfo_net_src },
    {"net_dst", Pinfo_net_dst },
    {"ipproto", Pinfo_ipproto },
    {"circuit_id", Pinfo_circuit_id },
    {"ptype", Pinfo_ptype },
    {"match_port", Pinfo_match_port },
    {"match_string", Pinfo_match_string },
    {"curr_proto", Pinfo_curr_proto },
    {"col", Pinfo_column },
    {0,0}
};

static const luaL_reg Pinfo_meta[] = {
    {"__gc",       No_gc},
    {"__tostring", Pinfo_tostring},
    {0, 0}
};

static int Pinfo_register(lua_State* L) {
    luaL_openlib(L, PINFO, Pinfo_methods, 0);
    luaL_newmetatable(L, PINFO);
    luaL_openlib(L, 0, Pinfo_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
};

/* Tree class */
LUA_CLASS_OPS(Tree,TREE,NOP);
LUA_CLASS_OPS(Item,ITEM,NOP);

static int Tree_add_item_any(lua_State *L, gboolean little_endian) {
    /*
     called with:
     tree,field,tvb,offset,len,datum
     tree,field,tvb,offset,len
     tree,tvb,offset,len,text
     tree,tvb,text
     */
    Tree tree = checkTree(L,1);
    Field field;
    Item item;
    Tvb tvb;
    int offset;
    int len;
    
    if (!tree) {
        pushItem(L,NULL);
        return 1;
    }
    
    if (( luaL_checkudata (L, 2, TVB) )) {
        tvb = checkTvb(L,2);
        const char* str;
        
        if (lua_isnumber(L,3)) {
            offset = luaL_checkint(L,3);
            len = luaL_checkint(L,4);
            str = lua_tostring(L,5);
        } else if (lua_isstring(L,3)) {
            offset = 0;
            len = 0;
            str = lua_tostring(L,3);
        } else {
            luaL_error(L,"First arg must be either TVB or Field");
            return 0;
        }
        
        item = proto_tree_add_text(tree,tvb,offset,len,"%s",str);
        
    } else if (( luaL_checkudata (L, 2, FIELD) )) {
        field = checkField(L,2);
        tvb = checkTvb(L,3);
        offset = luaL_checkint(L,4);
        len = luaL_checkint(L,5);
        
        if ( lua_gettop(L) == 6 ) {
            switch(field->type) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                case FT_FRAMENUM:
                    item = proto_tree_add_uint(tree,field->hfid,tvb,offset,len,(guint32)luaL_checknumber(L,6));
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    item = proto_tree_add_int(tree,field->hfid,tvb,offset,len,(gint32)luaL_checknumber(L,6));
                    break;
                case FT_FLOAT:
                    item = proto_tree_add_float(tree,field->hfid,tvb,offset,len,(float)luaL_checknumber(L,6));
                    break;
                case FT_DOUBLE:
                    item = proto_tree_add_double(tree,field->hfid,tvb,offset,len,(double)luaL_checknumber(L,6));
                    break;
                case FT_STRING:
                case FT_STRINGZ:
                    item = proto_tree_add_string(tree,field->hfid,tvb,offset,len,luaL_checkstring(L,6));
                    break;
                case FT_UINT64:
                case FT_INT64:
                case FT_ETHER:
                case FT_BYTES:
                case FT_UINT_BYTES:
                case FT_IPv4:
                case FT_IPv6:
                case FT_IPXNET:
                case FT_GUID:
                case FT_OID:
                default:
                    luaL_error(L,"FT_ not yet supported");
                    return 0;
            }
        } else {
            item = proto_tree_add_item(tree,field->hfid,tvb,offset,len,little_endian);
        }
    } else {
        luaL_error(L,"First arg must be either TVB or Field");
        return 0;
    }
    
    pushItem(L,item);
    return 1;
}

static int Tree_add_item(lua_State *L) { return Tree_add_item_any(L,FALSE); }
static int Tree_add_item_le(lua_State *L) { return Tree_add_item_any(L,TRUE); }

static int Tree_tostring(lua_State *L) {
    Tree tree = checkTree(L,1);
    lua_pushstring(L,ep_strdup_printf("a Tree %p",tree));
    return 1;
}


static int Tree_get_parent(lua_State *L) {
    Tree tree = checkTree(L,1);
    proto_item* item = NULL;
    
    if (tree) {
        item = proto_tree_get_parent(tree);
    }
    
    pushItem(L,item);
    
    return 1;
}

static const luaL_reg Tree_methods[] = {
    {"add_item",       Tree_add_item},
    {"add_item_le",       Tree_add_item_le},
    {"get_parent",       Tree_get_parent},
    {0, 0}
};

static const luaL_reg Tree_meta[] = {
    {"__gc",       No_gc},
    {"__tostring", Tree_tostring},
    {0, 0}
};

static int Tree_register(lua_State* L) {
    luaL_openlib(L, TREE, Tree_methods, 0);
    luaL_newmetatable(L, TREE);
    luaL_openlib(L, 0, Tree_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}

/* Item class */
static int Item_tostring(lua_State *L) {
    Item item = checkItem(L,1);
    lua_pushstring(L,ep_strdup_printf("an Item %p",item));
    return 1;
}

static int Item_add_subtree(lua_State *L) {
    Item item = checkItem(L,1);
    Ett ett;
    
    if (!item) {
        pushTree(L,NULL);
        return 1;
    }
    
    ett = checkEtt(L,2);
    
    Tree tree = proto_item_add_subtree(item,*ett);
    
    pushTree(L,tree);
    return 1;
}

static int Item_set_text(lua_State *L) {
    Item item = checkItem(L,1);
    
    if (!item) {
        const gchar* s = luaL_checkstring(L,2);
        proto_item_set_text(item,"%s",s);
    }
    
    return 0;
}

static int Item_append_text(lua_State *L) {
    Item item = checkItem(L,1);
    const gchar* s;
    
    if (item) {
        s = luaL_checkstring(L,2);
        proto_item_append_text(item,"%s",s);
    }
    return 0;
}

static int Item_set_len(lua_State *L) {
    Item item = checkItem(L,1);
    int len;

    if (item) {
        len = luaL_checkint(L,2);
        proto_item_set_len(item,len);
    }
    
    return 0;
}

struct _expert_severity {
    const gchar* str;
    int val;
};

static const struct _expert_severity severities[] = {
    {"PI_CHAT",PI_CHAT},
    {"PI_NOTE",PI_NOTE},
    {"PI_WARN",PI_WARN},
    {"PI_ERROR",PI_ERROR},
    {"PI_CHECKSUM",PI_CHECKSUM},
    {"PI_SEQUENCE",PI_SEQUENCE},
    {"PI_RESPONSE_CODE",PI_RESPONSE_CODE},
    {"PI_UNDECODED",PI_UNDECODED},
    {"PI_REASSEMBLE",PI_REASSEMBLE},
    {"PI_MALFORMED",PI_MALFORMED},
    {"PI_DEBUG",PI_DEBUG},
    {NULL,0}
};

static int str_to_expert(const gchar* str) {
    const struct _expert_severity* s;

    if (!str) return 0;
    
    for(s = severities; s->str; s++) {
        if (g_str_equal(str,s->str)) {
            return s->val;
        }
    }
    return 0;
}

#if 0
static const gchar* expert_to_str(int val) {
    const struct _expert_severity* s;
    for(s = severities; s->str; s++) {
        if (s->val == val) {
            return s->str;
        }
    }
    return NULL;
}
#endif

static int Item_set_expert_flags(lua_State *L) {
    Item item = checkItem(L,1);
    int group;
    int severity;

    if (item) {
        group = str_to_expert(luaL_checkstring(L,2));
        severity = str_to_expert(luaL_checkstring(L,3));

        if (group && severity) {
            proto_item_set_expert_flags(item,group,severity);
        }
    }

    return 0;
}


static int Item_set_generated(lua_State *L) {
    Item item = checkItem(L,1);
    if (item) {
        PROTO_ITEM_SET_GENERATED(item);
    }
    return 0;
}


static int Item_set_hidden(lua_State *L) {
    Item item = checkItem(L,1);
    if (item) {
        PROTO_ITEM_SET_HIDDEN(item);
    }
    return 0;
}

static const luaL_reg Item_methods[] = {
    {"add_subtree",       Item_add_subtree},
    {"set_text",       Item_set_text},
    {"append_text",       Item_append_text},
    {"set_len",       Item_set_len},
    {"set_expert_flags",       Item_set_expert_flags},
    {"set_generated",       Item_set_generated},
    {"set_hidden",       Item_set_hidden},
    {0, 0}
};

static const luaL_reg Item_meta[] = {
    {"__gc",       No_gc},
    {"__tostring", Item_tostring},
    {0, 0}
};



static int Item_register(lua_State *L) {
   const struct _expert_severity* s;
    
    luaL_openlib(L, ITEM, Item_methods, 0);
    luaL_newmetatable(L, ITEM);
    luaL_openlib(L, 0, Item_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    for(s = severities; s->str; s++) {
        lua_pushstring(L, s->str);
        lua_pushstring(L, s->str);
        lua_settable(L, LUA_GLOBALSINDEX);
    }
    
    return 1;
}


/*
 * Dissector class
 */
LUA_CLASS_OPS(Dissector,DISSECTOR,NOP);

static int Dissector_get (lua_State *L) {
    const gchar* name = luaL_checkstring(L,1);
    Dissector d = find_dissector(name);
    
    if (d) {
        pushDissector(L, d);
        return 1;
    } else {
        luaL_error(L,"No such dissector");
        return 0;
    }
    
}


static int Dissector_call(lua_State* L) {
    Dissector d = checkDissector(L,1);
    Tvb tvb = checkTvb(L,2);
    Pinfo pinfo = checkPinfo(L,3);
    Tree tree = checkTree(L,4);
    
    call_dissector(d, tvb, pinfo, tree);
    return 0;
}


static int Dissector_tostring(lua_State* L) {
    Dissector d = checkDissector(L,1);
    lua_pushstring(L,dissector_handle_get_short_name(d));
    return 1;
}


static const luaL_reg Dissector_methods[] = {
    {"get", Dissector_get },
    {"call", Dissector_call },
    {0,0}
};

static const luaL_reg Dissector_meta[] = {
    {"__gc",       No_gc},
    {"__tostring", Dissector_tostring},
    {0, 0}
};

static int Dissector_register(lua_State* L) {
    luaL_openlib(L, DISSECTOR, Dissector_methods, 0);
    luaL_newmetatable(L, DISSECTOR);
    luaL_openlib(L, 0, Dissector_meta, 0);
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
 * DissectorTable class
 */
LUA_CLASS_OPS(DissectorTable,DISSECTOR_TABLE,NOP);

static int DissectorTable_new (lua_State *L) {
    gchar* name = g_strdup(luaL_checkstring(L,1));
    gchar* ui_name = g_strdup(luaL_optstring(L,2,name));
    enum ftenum type = get_ftenum(luaL_optstring(L,3,"FT_UINT32"));
    int base = luaL_optint(L,3,10);
    
    switch(type) {
        case FT_STRING:
            base = 0;
        case FT_UINT32:
        {
            DissectorTable dt = g_malloc(sizeof(struct _eth_distbl_t));

            dt->table = register_dissector_table(name, ui_name, type, base);
            dt->name = name;
            pushDissectorTable(L, dt);
        }
            return 1;
        default:
            luaL_error(L,"Invalid ft_type");
            return 0;
    }
    
}

static int DissectorTable_get (lua_State *L) {
    const gchar* name = luaL_checkstring(L,1);
    dissector_table_t table = find_dissector_table(name);
        
    if (table) {
        DissectorTable dt = g_malloc(sizeof(struct _eth_distbl_t));
        dt->table = table;
        dt->name = g_strdup(name);
        
        pushDissectorTable(L, dt);
        
        return 1;
    } else {
        luaL_error(L,"No such dissector_table");
        return 0;
    }
    
}


static int DissectorTable_add (lua_State *L) {
    DissectorTable dt = checkDissectorTable(L,1);
    Proto p = checkProto(L,3);
    ftenum_t type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        gchar* pattern = g_strdup(luaL_checkstring(L,2));
        dissector_add_string(dt->name, pattern,p->handle);
    } else if ( type == FT_UINT32 ) {
        int port = luaL_checkint(L, 2);
        dissector_add(dt->name, port, p->handle);
    }
    
    return 0;
}


static int DissectorTable_try (lua_State *L) {
    DissectorTable dt = checkDissectorTable(L,1);
    Tvb tvb = checkTvb(L,3);
    Pinfo pinfo = checkPinfo(L,4);
    Tree tree = checkTree(L,5);
    ftenum_t type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        const gchar* pattern = luaL_checkstring(L,2);
        if (dissector_try_string(dt->table,pattern,tvb,pinfo,tree))
            return 0;
    } else if ( type == FT_UINT32 ) {
        int port = luaL_checkint(L, 2);
        if (dissector_try_port(dt->table,port,tvb,pinfo,tree))
            return 0;
    } else {
        luaL_error(L,"No such type of dissector_table");
    }
    
    call_dissector(data_handle,tvb,pinfo,tree);
    return 0;
}


static int DissectorTable_get_dissector (lua_State *L) {
    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type = get_dissector_table_selector_type(dt->name);
    dissector_handle_t handle = data_handle;
    
    if (type == FT_STRING) {
        const gchar* pattern = luaL_checkstring(L,2);
        handle = dissector_get_string_handle(dt->table,pattern);
    } else if ( type == FT_UINT32 ) {
        int port = luaL_checkint(L, 2);
        handle = dissector_get_port_handle(dt->table,port);
    }
    
    pushDissector(L,handle);

    return 1;

}


static int DissectorTable_tostring(lua_State* L) {
    DissectorTable dt = checkDissectorTable(L,1);
    GString* s = g_string_new("DissectorTable ");
    ftenum_t type =  get_dissector_table_selector_type(dt->name);
    
    switch(type) {
        case FT_STRING:
        {
            g_string_sprintfa(s,"%s String:\n",dt->name);
            break;
        }
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
    {"new", DissectorTable_new},
    {"get", DissectorTable_get},
    {"add", DissectorTable_add },
    {"try", DissectorTable_try },
    {"get_dissector", DissectorTable_get_dissector },
    {0,0}
};

static const luaL_reg DissectorTable_meta[] = {
    {"__gc",       No_gc},
    {"__tostring", DissectorTable_tostring},
    {0, 0}
};

static int DissectorTable_register(lua_State* L) {
    luaL_openlib(L, DISSECTOR_TABLE, DissectorTable_methods, 0);
    luaL_newmetatable(L, DISSECTOR_TABLE);
    luaL_openlib(L, 0, DissectorTable_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
};



/* ethereal uses lua */

static void dissect_lua(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree) {

    lua_pushstring(L, "_ethereal_tvb");
    pushTvb(L, tvb);
    lua_settable(L, LUA_GLOBALSINDEX);

    lua_pushstring(L, "_ethereal_pinfo");
    pushPinfo(L, pinfo);
    lua_settable(L, LUA_GLOBALSINDEX);

    lua_pushstring(L, "_ethereal_tree");
    pushTree(L, tree);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_dostring(L,ep_strdup_printf("dissectors.%s(_ethereal_tvb,_ethereal_pinfo,_ethereal_tree);",pinfo->current_proto));
    
}

static void init_lua(void) {
    if (L)
        lua_dostring(L, "for k in init_routines do init_routines[k]() end;");
}

void proto_reg_handoff_lua(void) {
    data_handle = find_dissector("data");
    
    if (L)
        lua_dostring(L, "for k in handoff_routines do handoff_routines[k]() end ;");
}

static const char *getF(lua_State *L _U_, void *ud, size_t *size)
{
    FILE *f=(FILE *)ud;
    static char buff[512];
    if (feof(f)) return NULL;
    *size=fread(buff,1,sizeof(buff),f);
    return (*size>0) ? buff : NULL;
}

static void functions_defined_but_unused(void) {
    toValueString(L,1);
    toField(L,1);
    toFieldArray(L,1);
    toEtt(L,1);
    toEttArray(L,1);
    toProto(L,1);
    toTvb(L,1);
    toColumn(L,1);
    toPinfo(L,1);
    toTree(L,1);
    toItem(L,1);
    toDissector(L,1);
    toDissectorTable(L,1);
}

void proto_register_lua(void)
{
    FILE* file;
    gchar* filename = getenv("ETHEREAL_LUA_INIT");
    
    if (!filename) filename = get_persconffile_path("init.lua", FALSE);

    file = fopen(filename,"r");

    if (! file) return;
    
    register_init_routine(init_lua);    
    
    L = lua_open();
    luaopen_base(L);
    luaopen_table(L);
    luaopen_io(L);
    luaopen_string(L);
    ValueString_register(L);
    Field_register(L);
    FieldArray_register(L);
    Ett_register(L);
    EttArray_register(L);
    Tvb_register(L);
    Proto_register(L);
    Column_register(L);
    Pinfo_register(L);
    Tree_register(L);
    Item_register(L);
    Dissector_register(L);
    DissectorTable_register(L);
    
    lua_pushstring(L, "handoff_routines");
    lua_newtable (L);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "init_routines");
    lua_newtable (L);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "dissectors");
    lua_newtable (L);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    if (lua_load(L,getF,file,filename) || lua_pcall(L,0,0,0))
        fprintf(stderr,"%s\n",lua_tostring(L,-1));
    
    fclose(file);
    
}

