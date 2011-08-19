/*
 *  wslua_field.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
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

/* WSLUA_MODULE Field Obtaining dissection data */

#include "wslua.h"

WSLUA_CLASS_DEFINE(FieldInfo,NOP,NOP);
/*
 An extracted Field
 */

WSLUA_METAMETHOD FieldInfo__len(lua_State* L) {
	/*
	 Obtain the Length of the field
	 */
	FieldInfo fi = checkFieldInfo(L,1);
	lua_pushnumber(L,fi->length);
	return 1;
}

WSLUA_METAMETHOD FieldInfo__unm(lua_State* L) {
	/*
	 Obtain the Offset of the field
	 */
	FieldInfo fi = checkFieldInfo(L,1);
	lua_pushnumber(L,fi->start);
	return 1;
}

WSLUA_METAMETHOD FieldInfo__call(lua_State* L) {
	/*
	 Obtain the Value of the field
	 */
	FieldInfo fi = checkFieldInfo(L,1);

	switch(fi->hfinfo->type) {
		case FT_NONE:
			lua_pushnil(L);
			return 1;
		case FT_BOOLEAN:
			lua_pushboolean(L,(int)fvalue_get_uinteger(&(fi->value)));
			return 1;
		case FT_UINT8:
		case FT_UINT16:
		case FT_UINT24:
		case FT_UINT32:
		case FT_FRAMENUM:
			lua_pushnumber(L,(lua_Number)fvalue_get_uinteger(&(fi->value)));
			return 1;
		case FT_INT8:
		case FT_INT16:
		case FT_INT24:
		case FT_INT32:
			lua_pushnumber(L,(lua_Number)fvalue_get_sinteger(&(fi->value)));
			return 1;
		case FT_FLOAT:
		case FT_DOUBLE:
			lua_pushnumber(L,(lua_Number)fvalue_get_floating(&(fi->value)));
			return 1;
		case FT_INT64: {
			Int64 num = g_malloc(sizeof(gint64));
			*num = fvalue_get_integer64(&(fi->value));
			pushInt64(L,num);
			return 1;
		}
		case FT_UINT64: {
			UInt64 num = g_malloc(sizeof(guint64));
			*num = fvalue_get_integer64(&(fi->value));
			pushUInt64(L,num);
			return 1;
		}
		case FT_ETHER: {
			Address eth = g_malloc(sizeof(address));
			eth->type = AT_ETHER;
			eth->len = fi->length;
			eth->data = tvb_memdup(fi->ds_tvb,fi->start,fi->length);
			pushAddress(L,eth);
			return 1;
		}
		case FT_IPv4:{
			Address ipv4 = g_malloc(sizeof(address));
			ipv4->type = AT_IPv4;
			ipv4->len = fi->length;
			ipv4->data = tvb_memdup(fi->ds_tvb,fi->start,fi->length);
			pushAddress(L,ipv4);
			return 1;
		}
		case FT_IPv6: {
			Address ipv6 = g_malloc(sizeof(address));
			ipv6->type = AT_IPv6;
			ipv6->len = fi->length;
			ipv6->data = tvb_memdup(fi->ds_tvb,fi->start,fi->length);
			pushAddress(L,ipv6);
			return 1;
		}
		case FT_IPXNET:{
			Address ipx = g_malloc(sizeof(address));
			ipx->type = AT_IPX;
			ipx->len = fi->length;
			ipx->data = tvb_memdup(fi->ds_tvb,fi->start,fi->length);
			pushAddress(L,ipx);
			return 1;
		}
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME: {
			NSTime nstime = g_malloc(sizeof(nstime_t));
			*nstime = *(NSTime)fvalue_get(&(fi->value));
			pushNSTime(L,nstime);
			return 1;
		}
		case FT_STRING:
		case FT_STRINGZ: {
			gchar* repr = fvalue_to_string_repr(&fi->value,FTREPR_DISPLAY,NULL);
			if (repr)
				lua_pushstring(L,repr);
			else
				luaL_error(L,"field cannot be represented as string because it may contain invalid characters");

			return 1;
		}
		case FT_BYTES:
		case FT_UINT_BYTES:
		case FT_GUID:
		case FT_PROTOCOL:
		case FT_OID: {
			ByteArray ba = g_byte_array_new();
			g_byte_array_append(ba, ep_tvb_memdup(fi->ds_tvb,fi->start,fi->length),fi->length);
			pushByteArray(L,ba);
			return 1;
		}
		default:
			luaL_error(L,"FT_ not yet supported");
			return 1;
	}
}

WSLUA_METAMETHOD FieldInfo__tostring(lua_State* L) {
	/* The string representation of the field */
	FieldInfo fi = checkFieldInfo(L,1);
	if (fi) {
		if (fi->value.ftype->val_to_string_repr) {
			gchar* repr = fvalue_to_string_repr(&fi->value,FTREPR_DISPLAY,NULL);
			if (repr)
				lua_pushstring(L,repr);
			else
				luaL_error(L,"field cannot be represented as string because it may contain invalid characters");
		} else
			luaL_error(L,"field has no string representation");
	}
	return 1;
}

static int FieldInfo_get_range(lua_State* L) {
	/* The TvbRange covering this field */
	FieldInfo fi = checkFieldInfo(L,1);
	TvbRange r = ep_alloc(sizeof(struct _wslua_tvbrange));
	r->tvb = ep_alloc(sizeof(struct _wslua_tvb));

	r->tvb->ws_tvb = fi->ds_tvb;
	r->offset = fi->start;
	r->len = fi->length;

	pushTvbRange(L,r);
	return 1;
}

static int FieldInfo_get_generated(lua_State* L) {
	/* Whether this field was marked as generated. */
	FieldInfo fi = checkFieldInfo(L,1);
	lua_pushboolean(L,FI_GET_FLAG(fi, FI_GENERATED));
	return 1;
}

static int FieldInfo_get_name(lua_State* L) {
	/* The filter name of this field. */
	FieldInfo fi = checkFieldInfo(L,1);
	lua_pushstring(L,fi->hfinfo->abbrev);
	return 1;
}

static const luaL_reg FieldInfo_get[] = {
/*    {"data_source", FieldInfo_get_data_source }, */
    {"range", FieldInfo_get_range},
/*    {"hidden", FieldInfo_get_hidden}, */
    {"generated", FieldInfo_get_generated},

	/* WSLUA_ATTRIBUTE FieldInfo_name RO The name of this field */
    {"name", FieldInfo_get_name},
	/* WSLUA_ATTRIBUTE FieldInfo_label RO The string representing this field */
    {"label", FieldInfo__tostring},
	/* WSLUA_ATTRIBUTE FieldInfo_value RO The value of this field */
    {"value", FieldInfo__call},
	/* WSLUA_ATTRIBUTE FieldInfo_len RO The length of this field */
    {"len", FieldInfo__len},
	/* WSLUA_ATTRIBUTE FieldInfo_offset RO The offset of this field */
    {"offset", FieldInfo__unm},
    { NULL, NULL }
};

static int FieldInfo__index(lua_State* L) {
	/*
	 Other attributes:
	 */
	const gchar* idx = luaL_checkstring(L,2);
	const luaL_reg* r;

	checkFieldInfo(L,1);

	for (r = FieldInfo_get; r->name; r++) {
		if (g_str_equal(r->name, idx)) {
			return r->func(L);
		}
	}

	return 0;
}

WSLUA_METAMETHOD FieldInfo__eq(lua_State* L) {
	/* Checks whether lhs is within rhs */
	FieldInfo l = checkFieldInfo(L,1);
	FieldInfo r = checkFieldInfo(L,2);

	if (l->ds_tvb != r->ds_tvb)
		WSLUA_ERROR(FieldInfo__eq,"Data source must be the same for both fields");

	if (l->start <= r->start && r->start + r->length <= l->start + r->length) {
		lua_pushboolean(L,1);
		return 1;
	} else {
		return 0;
	}
}

WSLUA_METAMETHOD FieldInfo__le(lua_State* L) {
	/* Checks whether the end byte of lhs is before the end of rhs */
	FieldInfo l = checkFieldInfo(L,1);
	FieldInfo r = checkFieldInfo(L,2);

	if (l->ds_tvb != r->ds_tvb)
		return 0;

	if (r->start + r->length <= l->start + r->length) {
		lua_pushboolean(L,1);
		return 1;
	} else {
		return 0;
	}
}

WSLUA_METAMETHOD FieldInfo__lt(lua_State* L) {
	/* Checks whether the end byte of rhs is before the beginning of rhs */
	FieldInfo l = checkFieldInfo(L,1);
	FieldInfo r = checkFieldInfo(L,2);

	if (l->ds_tvb != r->ds_tvb)
		WSLUA_ERROR(FieldInfo__eq,"Data source must be the same for both fields");

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
    { NULL, NULL }
};

int FieldInfo_register(lua_State* L) {
    WSLUA_REGISTER_META(FieldInfo);
    return 1;
}


WSLUA_FUNCTION wslua_all_field_infos(lua_State* L) {
	/* Obtain all fields from the current tree */
	GPtrArray* found;
	int items_found = 0;
	guint i;

	if (! lua_tree || ! lua_tree->tree ) {
		WSLUA_ERROR(wslua_all_field_infos,"Cannot be called outside a listener or dissector");
	}

	found = proto_all_finfos(lua_tree->tree);

	if (found) {
		for (i=0; i<found->len; i++) {
			pushFieldInfo(L,g_ptr_array_index(found,i));
			items_found++;
		}

		g_ptr_array_free(found,TRUE);
	}

	return items_found;
}

WSLUA_CLASS_DEFINE(Field,NOP,NOP);
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

        g_string_append_printf(fake_tap_filter," || %s",(*f)->abbrev);
        fake_tap = TRUE;
    }

    g_ptr_array_free(wanted_fields,TRUE);
    wanted_fields = NULL;

    if (fake_tap) {
        /* a boring tap :-) */
        GString* error = register_tap_listener("frame",
                                               &fake_tap,
                                               fake_tap_filter->str,
                                               0, /* XXX - do we need the protocol tree or columns? */
                                               NULL, NULL, NULL);

        if (error) {
            report_failure("while registering lua_fake_tap:\n%s",error->str);
            g_string_free(error,TRUE);
        }
    }

}

WSLUA_CONSTRUCTOR Field_new(lua_State *L) {
	/*
	 Create a Field extractor
	 */
#define WSLUA_ARG_Field_new_FIELDNAME 1 /* The filter name of the field (e.g. ip.addr) */
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_Field_new_FIELDNAME);
    Field f;

    if (!name) return 0;

	if (!proto_registrar_get_byname(name))
		WSLUA_ARG_ERROR(Field_new,FIELDNAME,"a field with this name must exist");

    if (!wanted_fields)
		WSLUA_ERROR(Field_get,"A Field extractor must be defined before Taps or Dissectors get called");

    f = g_malloc(sizeof(void*));
    *f = (header_field_info*)g_strdup(name); /* cheating */

    g_ptr_array_add(wanted_fields,f);

    pushField(L,f);
    WSLUA_RETURN(1); /* The field extractor */
}

WSLUA_METAMETHOD Field__call (lua_State* L) {
	/* Obtain all values (see FieldInfo) for this field. */
    Field f = checkField(L,1);
    header_field_info* in = *f;
	int items_found = 0;

    if (! in) {
        luaL_error(L,"invalid field");
        return 0;
    }

    if (! lua_pinfo ) {
        WSLUA_ERROR(Field__call,"Fields cannot be used outside dissectors or taps");
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
    }

    WSLUA_RETURN(items_found); /* All the values of this field */
}

WSLUA_METAMETHOD Field_tostring(lua_State* L) {
	/* Obtain a srting with the field name */
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
    { NULL, NULL }
};

static const luaL_reg Field_meta[] = {
    {"__tostring", Field_tostring},
    {"__call", Field__call},
    { NULL, NULL }
};

int Field_register(lua_State* L) {

    wanted_fields = g_ptr_array_new();

    WSLUA_REGISTER_CLASS(Field);

    return 1;
}


