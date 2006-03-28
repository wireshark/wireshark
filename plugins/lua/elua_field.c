/*
 *  elua_field.c
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

#include "elua.h"

ELUA_CLASS_DEFINE(FieldInfo,NOP)
/*
 An extracted Field
 */

ELUA_METAMETHOD FieldInfo__len(lua_State* L) {
	/*
	 The Length of the field
	 */
	FieldInfo fi = checkFieldInfo(L,1);
	lua_pushnumber(L,fi->length);
	return 1;
}

ELUA_METAMETHOD FieldInfo__unm(lua_State* L) {
	/*
	 The Offset of the field
	 */
	FieldInfo fi = checkFieldInfo(L,1);
	lua_pushnumber(L,fi->start);
	return 1;
}

ELUA_METAMETHOD FieldInfo__call(lua_State* L) {
	/*
	 The Value of the field
	 */
	FieldInfo fi = checkFieldInfo(L,1);

	switch(fi->hfinfo->type) {
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_FRAMENUM:
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			lua_pushnumber(L,(lua_Number)fvalue_get_integer(&(fi->value)));
			return 1;
		case FT_FLOAT:
		case FT_DOUBLE:
			lua_pushnumber(L,(lua_Number)fvalue_get_floating(&(fi->value)));
			return 1;
		case FT_INT64:
		case FT_UINT64:
			/*
			 * XXX: double has 53 bits integer precision, n > 2^22 will cause a loss in precision
			 */
			lua_pushnumber(L,(lua_Number)(gint64)fvalue_get_integer64(&(fi->value)));
			return 1;
		case FT_ETHER:
		case FT_IPv4:
		case FT_IPv6:
		case FT_IPXNET:
			/* XXX: use Address ??? */

		case FT_STRING:
		case FT_STRINGZ:
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_GUID:
		case FT_OID:
			lua_pushstring(L,fvalue_to_string_repr(&fi->value,FTREPR_DISPLAY,NULL));
			return 1;
		default:
			luaL_error(L,"FT_ not yet supported");
			return 1;
	}

}

ELUA_METAMETHOD FieldInfo__tostring(lua_State* L) {
	FieldInfo fi = checkFieldInfo(L,1);
	lua_pushstring(L,fi->rep->representation);
	return 1;
}

ELUA_ATTR_GET FieldInfo_get_data_source(lua_State* L) {
	FieldInfo fi = checkFieldInfo(L,1);
	pushTvb(L,fi->ds_tvb);
	return 1;
}

ELUA_ATTR_GET FieldInfo_get_range(lua_State* L) {
	FieldInfo fi = checkFieldInfo(L,1);
	TvbRange r = ep_alloc(sizeof(struct _eth_tvbrange));

	r->tvb = fi->ds_tvb;
	r->offset = fi->start;
	r->len = fi->length;

	pushTvbRange(L,r);
	return 1;
}


ELUA_ATTR_GET FieldInfo_get_hidden(lua_State* L) {
	FieldInfo fi = checkFieldInfo(L,1);
	lua_pushboolean(L,FI_GET_FLAG(fi, FI_HIDDEN));
	return 1;
}

ELUA_ATTR_GET FieldInfo_get_generated(lua_State* L) {
	FieldInfo fi = checkFieldInfo(L,1);
	lua_pushboolean(L,FI_GET_FLAG(fi, FI_GENERATED));
	return 1;
}

static const luaL_reg FieldInfo_get[] = {
    {"data_source", FieldInfo_get_data_source },
    {"range", FieldInfo_get_range},
    {"hidden", FieldInfo_get_hidden},
    {"generated", FieldInfo_get_generated},
    {"label", FieldInfo__tostring},
    {"value", FieldInfo__call},
    {"len", FieldInfo__len},
    {"offset", FieldInfo__unm},
    {0, 0}
};

ELUA_METAMETHOD FieldInfo__index(lua_State* L) {
	/*
	 Other attributes:
	 */
	const gchar* index = luaL_checkstring(L,2);
	const luaL_reg* r;

	checkFieldInfo(L,1);

	for (r = FieldInfo_get; r->name; r++) {
		if (g_str_equal(r->name, index)) {
			return r->func(L);
		}
	}

	return 0;
}

ELUA_METAMETHOD FieldInfo__eq(lua_State* L) {
	FieldInfo l = checkFieldInfo(L,1);
	FieldInfo r = checkFieldInfo(L,2);

	if (l->ds_tvb != r->ds_tvb)
		ELUA_ERROR(FieldInfo__eq,"data source must be the same for both fields");

	if (l->start <= r->start && r->start + r->length <= l->start + r->length) {
		lua_pushboolean(L,1);
		return 1;
	} else {
		return 0;
	}
}

ELUA_METAMETHOD FieldInfo__le(lua_State* L) {
	FieldInfo l = checkFieldInfo(L,1);
	FieldInfo r = checkFieldInfo(L,2);

	if (l->ds_tvb != r->ds_tvb)
		ELUA_ERROR(FieldInfo__eq,"data source must be the same for both fields");

	if (r->start + r->length <= l->start + r->length) {
		lua_pushboolean(L,1);
		return 1;
	} else {
		return 0;
	}
}

ELUA_METAMETHOD FieldInfo__lt(lua_State* L) {
	FieldInfo l = checkFieldInfo(L,1);
	FieldInfo r = checkFieldInfo(L,2);

	if (l->ds_tvb != r->ds_tvb)
		ELUA_ERROR(FieldInfo__eq,"data source must be the same for both fields");

	if ( r->start + r->length < l->start ) {
		lua_pushboolean(L,1);
		return 1;
	} else {
		return 0;
	}
}


static const luaL_reg FieldInfo_meta[] = {
    {"__tostring", FieldInfo__tostring},
    {"__call", FieldInfo__call},
    {"__index", FieldInfo__index},
    {"__len", FieldInfo__len},
    {"__unm", FieldInfo__unm},
    {"__eq", FieldInfo__eq},
    {"__le", FieldInfo__le},
    {"__lt", FieldInfo__lt},
    {0, 0}
};

int FieldInfo_register(lua_State* L) {
    ELUA_REGISTER_META(FieldInfo);
    return 1;
}


ELUA_FUNCTION elua_all_field_infos(lua_State* L) {
	GPtrArray* found = proto_all_finfos(lua_tree->tree);
	int items_found = 0;
	guint i;

	if (found) {
		for (i=0; i<found->len; i++) {
			pushFieldInfo(L,g_ptr_array_index(found,i));
			items_found++;
		}
	}
	return items_found;
}

ELUA_CLASS_DEFINE(Field,NOP)
/*
 A Field extractor to to obtain field values.
 */

static GPtrArray* wanted_fields = NULL;

/*
 * field extractor registartion is tricky, In order to allow
 * the user to define them in the body of the script we will
 * populate the Field value with a pointer of the abbrev of it
 * to later replace it with the hfi.
 *
 * This will be added to the wanted_fields array that will
 * exists only while they can be defined, and be cleared right
 * after the fields are primed.
 */

void lua_prime_all_fields(proto_tree* tree _U_) {
    GString* fake_tap_filter = g_string_new("frame");
    guint i;
    static gboolean fake_tap = FALSE;

    for(i=0; i < wanted_fields->len; i++) {
        Field f = g_ptr_array_index(wanted_fields,i);
        gchar* name = *((gchar**)f);

        *f = proto_registrar_get_byname(name);

        if (!*f) {
            report_failure("Could not find field `%s'",name);
            *f = NULL;
            g_free(name);
            continue;
        }

        g_free(name);

        g_string_sprintfa(fake_tap_filter," || %s",(*f)->abbrev);
        fake_tap = TRUE;
    }

    g_ptr_array_free(wanted_fields,TRUE);
    wanted_fields = NULL;

    if (fake_tap) {
        /* a boring tap :-) */
        GString* error = register_tap_listener("frame",
											   &fake_tap,
											   fake_tap_filter->str,
											   NULL, NULL, NULL);

        if (error) {
            report_failure("while registering lua_fake_tap:\n%s",error->str);
            g_string_free(error,TRUE);
        }
    }

}

ELUA_CONSTRUCTOR Field_new(lua_State *L) {
	/*
	 Create a Field extractor
	 */
#define ELUA_ARG_Field_new_FIELDNAME 1 /* The filter name of the field (e.g. ip.addr) */
    const gchar* name = luaL_checkstring(L,ELUA_ARG_Field_new_FIELDNAME);
    Field f;

    if (!name) return 0;

	if (!proto_registrar_get_byname(name))
		ELUA_ARG_ERROR(Field_new,FIELDNAME,"a field with this name must exist");

    if (!wanted_fields)
		ELUA_ERROR(Field_get,"a Field extractor must be defined before Taps or Dissectors get called");

    f = g_malloc(sizeof(void*));
    *f = (header_field_info*)g_strdup(name); /* cheating */

    g_ptr_array_add(wanted_fields,f);

    pushField(L,f);
    ELUA_RETURN(1); /* The field extractor */
}

ELUA_METAMETHOD Field__call (lua_State* L) {
    Field f = checkField(L,1);
    header_field_info* in = *f;
	int items_found = 0;

    if (! in) {
        luaL_error(L,"invalid field");
        return 0;
    }

    if (! lua_pinfo ) {
        ELUA_ERROR(Field__call,"fields cannot be used outside dissectors or taps");
        return 0;
    }

    for (;in;in = in->same_name_next) {
        GPtrArray* found = proto_get_finfo_ptr_array(lua_tree->tree, in->id);
        guint i;
        if (found) {
            for (i=0; i<found->len; i++) {
				pushFieldInfo(L,g_ptr_array_index(found,i));
				items_found++;
			}
        }

		g_ptr_array_free(found,TRUE);
    }

    ELUA_RETURN(items_found); /* All the values of this field */
}

static int Field_tostring(lua_State* L) {
    Field f = checkField(L,1);

    if ( !(f && *f) ) {
        luaL_error(L,"invalid Field");
        return 0;
    }

    if (wanted_fields) {
        lua_pushstring(L,*((gchar**)f));
    } else {
        lua_pushstring(L,(*f)->abbrev);
    }

    return 1;
}

static const luaL_reg Field_methods[] = {
    {"new", Field_new},
    {0, 0}
};

static const luaL_reg Field_meta[] = {
    {"__tostring", Field_tostring},
    {"__call", Field__call},
    {0, 0}
};

int Field_register(lua_State* L) {

    wanted_fields = g_ptr_array_new();

    ELUA_REGISTER_CLASS(Field);

    return 1;
}


