/*
 * wslua_dissector.c
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

#include "epan/guid-utils.h"
#include "epan/proto.h"
#include "wslua.h"

#include <epan/decode_as.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <string.h>


/* WSLUA_CONTINUE_MODULE Proto */


WSLUA_CLASS_DEFINE(Dissector,NOP);
/*
   A refererence to a dissector, used to call a dissector against a packet or a part of it.
 */

WSLUA_CONSTRUCTOR Dissector_get (lua_State *L) {
    /* Obtains a dissector reference by name. */
#define WSLUA_ARG_Dissector_get_NAME 1 /* The name of the dissector. */
    const char* name = luaL_checkstring(L,WSLUA_ARG_Dissector_get_NAME);
    Dissector d;

    if ((d = find_dissector(name))) {
        pushDissector(L, d);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The <<lua_class_Dissector,`Dissector`>> reference if found, otherwise `nil`. */
}

/* Allow dissector key names to be sorted alphabetically. */
static int
compare_dissector_key_name(const void *dissector_a, const void *dissector_b)
{
  return strcmp((const char*)dissector_a, (const char*)dissector_b);
}

WSLUA_CONSTRUCTOR Dissector_list (lua_State *L) {
    /* Gets a Lua array table of all registered Dissector names.

       Note: This is an expensive operation, and should only be used for troubleshooting.
     */
    GList* list = get_dissector_names();
    GList* elist = NULL;
    int i = 1;

    if (!list) return luaL_error(L,"Cannot retrieve Dissector name list");

    list = g_list_sort(list, (GCompareFunc)compare_dissector_key_name);
    elist = g_list_first(list);

    lua_newtable(L);
    for (i=1; elist; i++, elist = g_list_next(elist)) {
        lua_pushstring(L,(const char *) elist->data);
        lua_rawseti(L,-2,i);
    }

    g_list_free(list);
    WSLUA_RETURN(1); /* The array table of registered dissector names. */
}

WSLUA_METHOD Dissector_call(lua_State* L) {
    /* Calls a dissector against a given packet (or part of it). */
#define WSLUA_ARG_Dissector_call_TVB 2 /* The buffer to dissect. */
#define WSLUA_ARG_Dissector_call_PINFO 3 /* The packet info. */
#define WSLUA_ARG_Dissector_call_TREE 4 /* The tree on which to add the protocol items. */

    Dissector volatile d = checkDissector(L,1);
    Tvb tvb = checkTvb(L,WSLUA_ARG_Dissector_call_TVB);
    Pinfo pinfo = checkPinfo(L,WSLUA_ARG_Dissector_call_PINFO);
    TreeItem ti = checkTreeItem(L,WSLUA_ARG_Dissector_call_TREE);
    const char *volatile error = NULL;
    int len = 0;

    if (! ( d && tvb && pinfo) ) return 0;

    TRY {
        len = call_dissector(d, tvb->ws_tvb, pinfo->ws_pinfo, ti->tree);
        /* XXX Are we sure about this??? is this the right/only thing to catch */
    } CATCH_BOUNDS_AND_DISSECTOR_ERRORS {
        show_exception(tvb->ws_tvb, pinfo->ws_pinfo, ti->tree, EXCEPT_CODE, GET_MESSAGE);
        error = GET_MESSAGE ? GET_MESSAGE : "Malformed frame";
    } ENDTRY;

    /* XXX: Some exceptions, like FragmentBoundsError and ScsiBoundsError,
       are normal conditions and possibly don't need the Lua traceback. */
    if (error) { WSLUA_ERROR(Dissector_call,error); }

    lua_pushinteger(L,(lua_Integer)len);
    WSLUA_RETURN(1); /* Number of bytes dissected.  Note that some dissectors always return number of bytes in incoming buffer, so be aware. */
}

WSLUA_METAMETHOD Dissector__call(lua_State* L) {
    /* Calls a dissector against a given packet (or part of it). */
#define WSLUA_ARG_Dissector__call_TVB 2 /* The buffer to dissect. */
#define WSLUA_ARG_Dissector__call_PINFO 3 /* The packet info. */
#define WSLUA_ARG_Dissector__call_TREE 4 /* The tree on which to add the protocol items. */
    return Dissector_call(L);
}

WSLUA_METAMETHOD Dissector__tostring(lua_State* L) {
    /* Gets the Dissector's description. */
    Dissector d = checkDissector(L,1);
    if (!d) return 0;
    lua_pushstring(L,dissector_handle_get_description(d));
    WSLUA_RETURN(1); /* A string of the Dissector's description. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Dissector__gc(lua_State* L _U_) {
    /* do NOT free Dissector */
    return 0;
}

WSLUA_METHODS Dissector_methods[] = {
    WSLUA_CLASS_FNREG(Dissector,get),
    WSLUA_CLASS_FNREG(Dissector,call),
    WSLUA_CLASS_FNREG(Dissector,list),
    { NULL, NULL }
};

WSLUA_META Dissector_meta[] = {
    WSLUA_CLASS_MTREG(Dissector,tostring),
    WSLUA_CLASS_MTREG(Dissector,call),
    { NULL, NULL }
};

int Dissector_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(Dissector);
    return 0;
}

WSLUA_CLASS_DEFINE(DissectorTable,NOP);
/*
    A table of subdissectors of a particular protocol (e.g. TCP subdissectors like http, smtp, sip are added to table "tcp.port").

    Useful to add more dissectors to a table so that they appear in the “Decode As...” dialog.
 */

static int dissectortable_table_ref = LUA_NOREF;

WSLUA_CONSTRUCTOR DissectorTable_new (lua_State *L) {
    /* Creates a new `DissectorTable` for your dissector's use. */
#define WSLUA_ARG_DissectorTable_new_TABLENAME 1 /* The short name of the table. Use lower-case alphanumeric, dot, and/or underscores (e.g., "ansi_map.tele_id" or "udp.port"). */
#define WSLUA_OPTARG_DissectorTable_new_UINAME 2 /* The name of the table in the user interface.
                                                    Defaults to the name given in `tablename`, but can be any string. */
#define WSLUA_OPTARG_DissectorTable_new_TYPE 3 /* One of `ftypes.UINT8`, `ftypes.UINT16`,
                                                  `ftypes.UINT24`, `ftypes.UINT32`,
                                                  `ftypes.STRING`, `ftypes.NONE`,
                                                  or `ftypes.GUID`.
                                                  Defaults to `ftypes.UINT32`. */
#define WSLUA_OPTARG_DissectorTable_new_BASE 4 /* One of `base.NONE`, `base.DEC`, `base.HEX`,
                                                  `base.OCT`, `base.DEC_HEX` or `base.HEX_DEC`.
                                                  Defaults to `base.DEC`. */
#define WSLUA_OPTARG_DissectorTable_new_PROTO 5 /* The <<lua_class_Proto,`Proto`>> object that uses this dissector table. */
    const char* name = (const char*)luaL_checkstring(L,WSLUA_ARG_DissectorTable_new_TABLENAME);
    const char* ui_name = (const char*)luaL_optstring(L,WSLUA_OPTARG_DissectorTable_new_UINAME,name);
    enum ftenum type = (enum ftenum)luaL_optinteger(L,WSLUA_OPTARG_DissectorTable_new_TYPE,FT_UINT32);
    unsigned base = (unsigned)luaL_optinteger(L,WSLUA_OPTARG_DissectorTable_new_BASE,BASE_DEC);
    DissectorTable dt;
    int proto_id = -1;

    switch(type) {
        case FT_STRING:
            base = BASE_NONE;
            break;

        case FT_NONE:
            break;

        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
            break;

        case FT_GUID:
            base = BASE_HEX;
            break;

        default:
            /* Calling WSLUA_OPTARG_ERROR raises a Lua error and
               returns from this function. */
            WSLUA_OPTARG_ERROR(
                    DissectorTable_new, TYPE,
                    "must be ftypes.UINT{8,16,24,32}, ftypes.STRING, ftypes.GUID or ftypes.NONE");
            break;
    }

    dt = (DissectorTable)g_malloc(sizeof(struct _wslua_distbl_t));

    if (isProto(L, WSLUA_OPTARG_DissectorTable_new_PROTO)) {
        Proto proto = checkProto(L, WSLUA_OPTARG_DissectorTable_new_PROTO);
        proto_id = proto_get_id_by_short_name(proto->name);
    }

    dt->table = (type == FT_NONE) ?
        register_decode_as_next_proto(proto_id, name, ui_name, NULL) :
        register_dissector_table(name, ui_name, proto_id, type, base);
    dt->heur_list = NULL;
    dt->name = g_strdup(name);
    dt->ui_name = g_strdup(ui_name);
    dt->created = true;
    dt->expired = false;

    lua_rawgeti(L, LUA_REGISTRYINDEX, dissectortable_table_ref);
    lua_pushstring(L, name);
    pushDissectorTable(L, dt);
    lua_settable(L, -3);

    pushDissectorTable(L, dt);
    WSLUA_RETURN(1); /* The newly created DissectorTable. */
}

WSLUA_CONSTRUCTOR DissectorTable_heuristic_new(lua_State *L) {
    /* Creates a new heuristic `DissectorTable` for your dissector's use. Returns true if table was created successfully.
     * XXX - Currently it always returns nil.

       @since 4.2.0
     */
#define WSLUA_ARG_DissectorTable_heuristic_new_TABLENAME 1 /* The short name of the table. Use lower-case alphanumeric, dot, and/or underscores. */
#define WSLUA_OPTARG_DissectorTable_heuristic_new_UINAME 2 /* The name of the table in the user interface.
                                                    Defaults to the name given in `tablename`, but can be any string. */
#define WSLUA_ARG_DissectorTable_heuristic_new_PROTO 3 /* The <<lua_class_Proto,`Proto`>> object that uses this dissector table. */
    const char* name = (const char*)luaL_checkstring(L,WSLUA_ARG_DissectorTable_heuristic_new_TABLENAME);
    const char* ui_name = NULL;
    Proto proto = NULL;
    int proto_id = -1;
    heur_dissector_list_t list;
    int idx = WSLUA_OPTARG_DissectorTable_heuristic_new_UINAME;

    if (lua_isstring(L, idx)) {
        ui_name = luaL_checkstring(L, idx);
        idx++;
    }

    proto = checkProto(L, idx);
    proto_id = proto_get_id_by_short_name(proto->name);

    list = find_heur_dissector_list(name);
    if (list) {
        luaL_error(L, "Heuristic list '%s' already exists", name);
        return 0;
    }


    DissectorTable dt;
    dt = (DissectorTable)g_malloc(sizeof(struct _wslua_distbl_t));
    dt->table = NULL;
    dt->heur_list = register_heur_dissector_list_with_description(name, ui_name, proto_id);
    dt->name = g_strdup(name);
    dt->ui_name = g_strdup(ui_name);
    dt->created = true;
    dt->expired = false;

    lua_rawgeti(L, LUA_REGISTRYINDEX, dissectortable_table_ref);
    lua_pushstring(L, name);
    pushDissectorTable(L, dt);
    lua_settable(L, -3);

#if 0
    /* Return nil because this is not a regular DissectorTable that could
     * be used with _try, _set, _add, etc., and so we need to build checks
     * into the functions similar to File and CaptureInfo so that it
     * doesn't get used as one. However, not returning it means that it
     * doesn't get properly garbage collected. */
    pushDissectorTable(L, dt);
    WSLUA_RETURN(1); /* The newly created DissectorTable. */
#endif
    return 0;
}

/* this struct is used for passing ourselves user_data through dissector_all_tables_foreach_table(). */
typedef struct dissector_tables_foreach_table_info {
    int num;
    lua_State *L;
} dissector_tables_foreach_table_info_t;

/* this is the DATFunc_table function used for dissector_all_tables_foreach_table()
   so we can get all dissector_table names. This pushes the name into a table at stack index 1 */
static void
dissector_tables_list_func(const char *table_name, const char *ui_name _U_, void *user_data) {
    dissector_tables_foreach_table_info_t *data = (dissector_tables_foreach_table_info_t*) user_data;
    lua_pushstring(data->L, table_name);
    lua_rawseti(data->L, 1, data->num);
    data->num = data->num + 1;
}

WSLUA_CONSTRUCTOR DissectorTable_list (lua_State *L) {
    /* Gets a Lua array table of all DissectorTable names - i.e., the string names you can
       use for the first argument to DissectorTable.get().

       Note: This is an expensive operation, and should only be used for troubleshooting.
     */
    dissector_tables_foreach_table_info_t data = { 1, L };

    lua_newtable(L);

    dissector_all_tables_foreach_table(dissector_tables_list_func, (void *)&data,
                                       (GCompareFunc)compare_dissector_key_name);

    WSLUA_RETURN(1); /* The array table of registered DissectorTable names. */
}

/* this is the DATFunc_heur_table function used for dissector_all_heur_tables_foreach_table()
   so we can get all heuristic dissector list names. This pushes the name into a table at stack index 1 */
static void
heur_dissector_tables_list_func(const char *table_name, struct heur_dissector_list *table _U_, void *user_data) {
    dissector_tables_foreach_table_info_t *data = (dissector_tables_foreach_table_info_t*) user_data;
    lua_pushstring(data->L, table_name);
    lua_rawseti(data->L, 1, data->num);
    data->num = data->num + 1;
}

WSLUA_CONSTRUCTOR DissectorTable_heuristic_list (lua_State *L) {
    /* Gets a Lua array table of all heuristic list names - i.e., the string names you can
       use for the first argument in Proto:register_heuristic().

       Note: This is an expensive operation, and should only be used for troubleshooting.
     */
    dissector_tables_foreach_table_info_t data = { 1, L };

    lua_newtable(L);

    dissector_all_heur_tables_foreach_table(heur_dissector_tables_list_func, (void *)&data, NULL);

    WSLUA_RETURN(1); /* The array table of registered heuristic list names */
}

WSLUA_CONSTRUCTOR DissectorTable_try_heuristics (lua_State *L) {
    /*
     Try all the dissectors in a given heuristic dissector table.
     */
#define WSLUA_ARG_DissectorTable_try_heuristics_LISTNAME 1 /* The name of the heuristic dissector. */
#define WSLUA_ARG_DissectorTable_try_heuristics_TVB 2 /* The buffer to dissect. */
#define WSLUA_ARG_DissectorTable_try_heuristics_PINFO 3 /* The packet info. */
#define WSLUA_ARG_DissectorTable_try_heuristics_TREE 4 /* The tree on which to add the protocol items. */

    const char* name = luaL_checkstring(L,WSLUA_ARG_DissectorTable_try_heuristics_LISTNAME);
    Tvb tvb = checkTvb(L,WSLUA_ARG_DissectorTable_try_heuristics_TVB);
    Pinfo pinfo = checkPinfo(L,WSLUA_ARG_DissectorTable_try_heuristics_PINFO);
    TreeItem tree = checkTreeItem(L,WSLUA_ARG_DissectorTable_try_heuristics_TREE);
    heur_dissector_list_t list;
    heur_dtbl_entry_t *entry;

    if (!(name && tvb && pinfo && tree)) return 0;

    list = find_heur_dissector_list(name);
    if (!list) {
        luaL_error(L, "Heuristic list '%s' does not exist", name);
        return 0;
    }

    lua_pushboolean(L, dissector_try_heuristic(list, tvb->ws_tvb, pinfo->ws_pinfo, tree->tree, &entry, NULL));

    WSLUA_RETURN(1); /* True if the packet was recognized by the sub-dissector (stop dissection here). */
}

WSLUA_CONSTRUCTOR DissectorTable_get (lua_State *L) {
    /*
     Obtain a reference to an existing dissector table.
     */
#define WSLUA_ARG_DissectorTable_get_TABLENAME 1 /* The short name of the table. */
    const char* name = luaL_checkstring(L,WSLUA_ARG_DissectorTable_get_TABLENAME);
    dissector_table_t table = find_dissector_table(name);

    if (table) {
        DissectorTable dt = (DissectorTable)g_malloc(sizeof(struct _wslua_distbl_t));
        dt->table = table;
        dt->heur_list = NULL;
        dt->name = g_strdup(name);
        dt->ui_name = NULL;
        dt->created = false;
        dt->expired = false;

        pushDissectorTable(L, dt);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The <<lua_class_DissectorTable,`DissectorTable`>> reference if found, otherwise `nil`. */
}

WSLUA_METHOD DissectorTable_add (lua_State *L) {
    /*
     Add a <<lua_class_Proto,`Proto`>> with a dissector function or a <<lua_class_Dissector,`Dissector`>> object to the dissector table.
     */
#define WSLUA_ARG_DissectorTable_add_PATTERN 2 /* The pattern to match (either an integer, a
                                                  integer range or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_add_DISSECTOR 3 /* The dissector to add (either a <<lua_class_Proto,`Proto`>> or a <<lua_class_Dissector,`Dissector`>>). */

    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    Dissector handle;

    if (!dt) return 0;

    if( isProto(L,WSLUA_ARG_DissectorTable_add_DISSECTOR) ) {
        Proto p;
        p = checkProto(L,WSLUA_ARG_DissectorTable_add_DISSECTOR);
        handle = p->handle;

        if (! handle) {
            WSLUA_ARG_ERROR(DissectorTable_add,DISSECTOR,"a Protocol that does not have a dissector cannot be added to a table");
            return 0;
        }

    } else if ( isDissector(L,WSLUA_ARG_DissectorTable_add_DISSECTOR) ) {
        handle = toDissector(L,WSLUA_ARG_DissectorTable_add_DISSECTOR);
    } else {
        WSLUA_ARG_ERROR(DissectorTable_add,DISSECTOR,"must be either Proto or Dissector");
        return 0;
    }

    type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        char* pattern = g_strdup(luaL_checkstring(L,WSLUA_ARG_DissectorTable_add_PATTERN));
        dissector_add_string(dt->name, pattern,handle);
        g_free (pattern);
    } else if (type == FT_GUID) {
        /* Handle GUID type (assuming it is represented as a string in Lua) */
        const char* guid_str = luaL_checkstring(L,WSLUA_ARG_DissectorTable_add_PATTERN);
        fvalue_t* fval = fvalue_from_literal(type, guid_str, 0, NULL);
        const e_guid_t* guid = fvalue_get_guid(fval);
        guid_key gk = {*guid, 0};
        /* The dcerpc.uuid table requires its own initializer */
        if(strcmp(DCERPC_TABLE_NAME, dt->name) == 0) {
            e_guid_t uuid;
            memcpy(&uuid, guid, sizeof(e_guid_t));
            dcerpc_init_from_handle(dissector_handle_get_protocol_index(handle), &uuid, 0, handle);
        } else {
            dissector_add_guid(dt->name, &gk, handle);
            guids_add_uuid(guid, dissector_handle_get_protocol_short_name(handle));
        }
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        if (lua_isnumber(L, WSLUA_ARG_DissectorTable_add_PATTERN)) {
            uint32_t port = wslua_checkuint32(L, WSLUA_ARG_DissectorTable_add_PATTERN);
            dissector_add_uint(dt->name, port, handle);
        } else {
            /* Not a number, try as range */
            const char* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_add_PATTERN);
            range_t *range = NULL;
            if (range_convert_str(NULL, &range, pattern, UINT32_MAX) == CVT_NO_ERROR) {
                dissector_add_uint_range(dt->name, range, handle);
            } else {
                wmem_free (NULL, range);
                WSLUA_ARG_ERROR(DissectorTable_add,PATTERN,"invalid integer or range");
                return  0;
            }
            wmem_free (NULL, range);
        }
    } else {
        luaL_error(L,"Strange type %d for a DissectorTable",type);
    }

    return 0;
}

WSLUA_METHOD DissectorTable_set (lua_State *L) {
    /* Clear all existing dissectors from a table and add a new dissector or a range of new dissectors. */
#define WSLUA_ARG_DissectorTable_set_PATTERN 2 /* The pattern to match (either an integer, a integer range or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_set_DISSECTOR 3 /* The dissector to add (either a <<lua_class_Proto,`Proto`>> or a <<lua_class_Dissector,`Dissector`>>). */

    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    Dissector handle;

    if (!dt) return 0;

    if( isProto(L,WSLUA_ARG_DissectorTable_set_DISSECTOR) ) {
        Proto p;
        p = checkProto(L,WSLUA_ARG_DissectorTable_set_DISSECTOR);
        handle = p->handle;

        if (! handle) {
            WSLUA_ARG_ERROR(DissectorTable_set,DISSECTOR,"a Protocol that does not have a dissector cannot be set to a table");
            return 0;
        }

    } else if ( isDissector(L,WSLUA_ARG_DissectorTable_set_DISSECTOR) ) {
        handle = toDissector(L,WSLUA_ARG_DissectorTable_set_DISSECTOR);
    } else {
        WSLUA_ARG_ERROR(DissectorTable_set,DISSECTOR,"must be either Proto or Dissector");
        return 0;
    }

    type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        const char* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_set_PATTERN);
        dissector_delete_all(dt->name, handle);
        dissector_add_string(dt->name, pattern,handle);
    } else if (type == FT_GUID) {
        /* Handle GUID type (assuming it is represented as a string in Lua) */
        const char* guid_str = luaL_checkstring(L,WSLUA_ARG_DissectorTable_set_PATTERN);
        fvalue_t* fval = fvalue_from_literal(type, guid_str, 0, NULL);
        const e_guid_t* guid = fvalue_get_guid(fval);
        guid_key gk = {*guid, 0};
        /* The dcerpc.uuid table requires its own initializer */
        if(strcmp(DCERPC_TABLE_NAME, dt->name) == 0) {
            e_guid_t uuid;
            memcpy(&uuid, guid, sizeof(e_guid_t));
            dcerpc_init_from_handle(dissector_handle_get_protocol_index(handle), &uuid, 0, handle);
        } else {
            dissector_add_guid(dt->name, &gk, handle);
            guids_add_uuid(guid, dissector_handle_get_protocol_short_name(handle));
        }
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        if (lua_isnumber(L, WSLUA_ARG_DissectorTable_set_PATTERN)) {
            uint32_t port = wslua_checkuint32(L, WSLUA_ARG_DissectorTable_set_PATTERN);
            dissector_delete_all(dt->name, handle);
            dissector_add_uint(dt->name, port, handle);
        } else {
            /* Not a number, try as range */
            const char* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_set_PATTERN);
            range_t *range = NULL;
            if (range_convert_str(NULL, &range, pattern, UINT32_MAX) == CVT_NO_ERROR) {
                dissector_delete_all(dt->name, handle);
                dissector_add_uint_range(dt->name, range, handle);
            } else {
                wmem_free (NULL, range);
                WSLUA_ARG_ERROR(DissectorTable_set,PATTERN,"invalid integer or range");
                return 0;
            }
            wmem_free (NULL, range);
        }
    } else {
        luaL_error(L,"Strange type %d for a DissectorTable",type);
    }

    return 0;
}

WSLUA_METHOD DissectorTable_remove (lua_State *L) {
    /*
     Remove a dissector or a range of dissectors from a table.
     */
#define WSLUA_ARG_DissectorTable_remove_PATTERN 2 /* The pattern to match (either an integer, a integer range or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_remove_DISSECTOR 3 /* The dissector to remove (either a <<lua_class_Proto,`Proto`>> or a <<lua_class_Dissector,`Dissector`>>). */
    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    Dissector handle;

    if (!dt) return 0;

    if( isProto(L,WSLUA_ARG_DissectorTable_remove_DISSECTOR) ) {
        Proto p;
        p = checkProto(L,WSLUA_ARG_DissectorTable_remove_DISSECTOR);
        handle = p->handle;

    } else if ( isDissector(L,WSLUA_ARG_DissectorTable_remove_DISSECTOR) ) {
        handle = toDissector(L,WSLUA_ARG_DissectorTable_remove_DISSECTOR);
    } else {
        WSLUA_ARG_ERROR(DissectorTable_remove,DISSECTOR,"must be either Proto or Dissector");
        return 0;
    }

    type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        char* pattern = g_strdup(luaL_checkstring(L,WSLUA_ARG_DissectorTable_remove_PATTERN));
        dissector_delete_string(dt->name, pattern,handle);
        g_free (pattern);
    } else if (type == FT_GUID) {
        // Handle GUID type (assuming it is represented as a string in Lua)
        const char* guid_str = luaL_checkstring(L,WSLUA_ARG_DissectorTable_remove_PATTERN);
        fvalue_t* fval = fvalue_from_literal(type, guid_str, 0, NULL);
        const e_guid_t* guid = fvalue_get_guid(fval);
        guid_key gk = {*guid, 0};
        guids_delete_guid(guid);
        dissector_delete_guid(dt->name, &gk, handle);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        if (lua_isnumber(L, WSLUA_ARG_DissectorTable_remove_PATTERN)) {
          uint32_t port = wslua_checkuint32(L, WSLUA_ARG_DissectorTable_remove_PATTERN);
          dissector_delete_uint(dt->name, port, handle);
        } else {
            /* Not a number, try as range */
            const char* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_remove_PATTERN);
            range_t *range = NULL;
            if (range_convert_str(NULL, &range, pattern, UINT32_MAX) == CVT_NO_ERROR)
                dissector_delete_uint_range(dt->name, range, handle);
            else {
                wmem_free (NULL, range);
                WSLUA_ARG_ERROR(DissectorTable_remove,PATTERN,"invalid integer or range");
                return 0;
            }
            wmem_free (NULL, range);
        }
    }

    return 0;
}

WSLUA_METHOD DissectorTable_remove_all (lua_State *L) {
    /* Remove all dissectors from a table. */
#define WSLUA_ARG_DissectorTable_remove_all_DISSECTOR 2 /* The dissector to remove (either a <<lua_class_Proto,`Proto`>> or a <<lua_class_Dissector,`Dissector`>>). */
    DissectorTable dt = checkDissectorTable(L,1);
    Dissector handle;

    if (!dt) return 0;

    if( isProto(L,WSLUA_ARG_DissectorTable_remove_all_DISSECTOR) ) {
        Proto p;
        p = checkProto(L,WSLUA_ARG_DissectorTable_remove_all_DISSECTOR);
        handle = p->handle;

    } else if ( isDissector(L,WSLUA_ARG_DissectorTable_remove_all_DISSECTOR) ) {
        handle = toDissector(L,WSLUA_ARG_DissectorTable_remove_all_DISSECTOR);
    } else {
        WSLUA_ARG_ERROR(DissectorTable_remove_all,DISSECTOR,"must be either Proto or Dissector");
        return 0;
    }

    dissector_delete_all (dt->name, handle);

    return 0;
}

WSLUA_METHOD DissectorTable_try (lua_State *L) {
    /*
     Try to call a dissector from a table.
     */
#define WSLUA_ARG_DissectorTable_try_PATTERN 2 /* The pattern to be matched (either an integer or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_try_TVB 3 /* The <<lua_class_Tvb,`Tvb`>> to dissect. */
#define WSLUA_ARG_DissectorTable_try_PINFO 4 /* The packet's <<lua_class_Pinfo,`Pinfo`>>. */
#define WSLUA_ARG_DissectorTable_try_TREE 5 /* The <<lua_class_TreeItem,`TreeItem`>> on which to add the protocol items. */
    DissectorTable volatile dt = checkDissectorTable(L,1);
    Tvb tvb = checkTvb(L,WSLUA_ARG_DissectorTable_try_TVB);
    Pinfo pinfo = checkPinfo(L,WSLUA_ARG_DissectorTable_try_PINFO);
    TreeItem ti = checkTreeItem(L,WSLUA_ARG_DissectorTable_try_TREE);
    ftenum_t type;
    bool handled = false;
    const char *volatile error = NULL;
    int len = 0;

    if (! (dt && tvb && tvb->ws_tvb && pinfo && ti) ) return 0;

    type = get_dissector_table_selector_type(dt->name);

    TRY {

        if (type == FT_STRING) {
            const char* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_try_PATTERN);

            len = dissector_try_string(dt->table,pattern,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree, NULL);
            if (len > 0) {
                handled = true;
            }
        } else if ( type == FT_GUID ) {
            const char* guid_str = luaL_checkstring(L,WSLUA_ARG_DissectorTable_try_PATTERN);
            fvalue_t* fval = fvalue_from_literal(type, guid_str, 0, NULL);
            const e_guid_t* guid = fvalue_get_guid(fval);
            guid_key gk = {*guid, 0};

            len = dissector_try_guid(dt->table, &gk,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree);
            if (len > 0) {
                handled = true;
            }
        } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
            uint32_t port = wslua_checkuint32(L, WSLUA_ARG_DissectorTable_try_PATTERN);

            len = dissector_try_uint(dt->table,port,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree);
            if (len > 0) {
                handled = true;
            }
	} else if ( type == FT_NONE ) {
	    len = dissector_try_payload(dt->table,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree);
	    if (len > 0) {
	        handled = true;
            }
        } else {
            error = "No such type of dissector table";
        }

        if (!handled) {
            len = call_data_dissector(tvb->ws_tvb, pinfo->ws_pinfo, ti->tree);
        }
        /* XXX Are we sure about this??? is this the right/only thing to catch */
    } CATCH_NONFATAL_ERRORS {
        show_exception(tvb->ws_tvb, pinfo->ws_pinfo, ti->tree, EXCEPT_CODE, GET_MESSAGE);
        error = "Malformed frame";
    } ENDTRY;

    if (error) { WSLUA_ERROR(DissectorTable_try,error); }

    lua_pushinteger(L,(lua_Integer)len);
    WSLUA_RETURN(1); /* Number of bytes dissected.  Note that some dissectors always return number of bytes in incoming buffer, so be aware. */
}

WSLUA_METHOD DissectorTable_get_dissector (lua_State *L) {
    /*
     Try to obtain a dissector from a table.
     */
#define WSLUA_ARG_DissectorTable_get_dissector_PATTERN 2 /* The pattern to be matched (either an integer or a string depending on the table's type). */

    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    dissector_handle_t handle = NULL;

    if (!dt) return 0;

    type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        const char* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_get_dissector_PATTERN);
        handle = dissector_get_string_handle(dt->table,pattern);
    } else if ( type == FT_GUID ) {
        const char* guid_str = luaL_checkstring(L,WSLUA_ARG_DissectorTable_get_dissector_PATTERN);
        fvalue_t* fval = fvalue_from_literal(type, guid_str, 0, NULL);
        const e_guid_t* guid = fvalue_get_guid(fval);
        guid_key gk = {*guid, 0};
        handle = dissector_get_guid_handle(dt->table,&gk);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        uint32_t port = wslua_checkuint32(L, WSLUA_ARG_DissectorTable_get_dissector_PATTERN);
        handle = dissector_get_uint_handle(dt->table,port);
    }

    if (handle) {
        pushDissector(L,handle);
    } else {
        lua_pushnil(L);
    }

    WSLUA_RETURN(1); /* The <<lua_class_Dissector,`Dissector`>> handle if found, otherwise `nil` */
}

WSLUA_METHOD DissectorTable_add_for_decode_as (lua_State *L) {
    /*
     Add the given <<lua_class_Proto,`Proto`>> to the “Decode as...” list for this DissectorTable.
     The passed-in <<lua_class_Proto,`Proto`>> object's `dissector()` function is used for dissecting.
     */
#define WSLUA_ARG_DissectorTable_add_for_decode_as_PROTO 2 /* The <<lua_class_Proto,`Proto`>> to add. */
    DissectorTable dt = checkDissectorTable(L,1);
    Proto proto = checkProto(L, WSLUA_ARG_DissectorTable_add_for_decode_as_PROTO);
    dissector_handle_t handle = NULL;

    if (! proto->handle) {
        proto->handle = register_dissector(proto->loname, dissect_lua, proto->hfid);
    }

    handle = proto->handle;

    dissector_add_for_decode_as(dt->name, handle);

    return 0;
}

/* XXX It would be nice to iterate and print which dissectors it has */
WSLUA_METAMETHOD DissectorTable__tostring(lua_State* L) {
    /* Gets some debug information about the <<lua_class_DissectorTable,`DissectorTable`>>. */
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
            int base = get_dissector_table_param(dt->name);
            g_string_append_printf(s,"%s Integer(%i):\n",dt->name,base);
            break;
        }
        case FT_GUID:
        {
            g_string_append_printf(s,"%s GUID:\n",dt->name);
            break;
        }
        case FT_NONE:
        {
            g_string_append_printf(s,"%s only for Decode As:\n",dt->name);
            break;
        }
        default:
            luaL_error(L,"Strange table type");
    }

    lua_pushstring(L,s->str);
    g_string_free(s,TRUE);
    WSLUA_RETURN(1); /* A string of debug information about the <<lua_class_DissectorTable,`DissectorTable`>>. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int DissectorTable__gc(lua_State* L) {
    DissectorTable dt = toDissectorTable(L,1);

    if (dt->created && !dt->expired) {
        /* Created DissectorTable will pass GC two times */
        dt->expired = true;
    } else {
        g_free((char *)dt->name);
        g_free((char *)dt->ui_name);
        g_free(dt);
    }

    return 0;
}

WSLUA_METHODS DissectorTable_methods[] = {
    WSLUA_CLASS_FNREG(DissectorTable,new),
    WSLUA_CLASS_FNREG(DissectorTable,heuristic_new),
    WSLUA_CLASS_FNREG(DissectorTable,get),
    WSLUA_CLASS_FNREG(DissectorTable,list),
    WSLUA_CLASS_FNREG(DissectorTable,heuristic_list),
    WSLUA_CLASS_FNREG(DissectorTable,try_heuristics),
    WSLUA_CLASS_FNREG(DissectorTable,add),
    WSLUA_CLASS_FNREG(DissectorTable,set),
    WSLUA_CLASS_FNREG(DissectorTable,remove),
    WSLUA_CLASS_FNREG(DissectorTable,remove_all),
    WSLUA_CLASS_FNREG(DissectorTable,try),
    WSLUA_CLASS_FNREG(DissectorTable,get_dissector),
    WSLUA_CLASS_FNREG(DissectorTable,add_for_decode_as),
    { NULL, NULL }
};

WSLUA_META DissectorTable_meta[] = {
    WSLUA_CLASS_MTREG(DissectorTable,tostring),
    { NULL, NULL }
};

int DissectorTable_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(DissectorTable);

    lua_newtable (L);
    dissectortable_table_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

int wslua_deregister_dissector_tables(lua_State* L) {
    /* for each registered DissectorTable do... */
    lua_rawgeti(L, LUA_REGISTRYINDEX, dissectortable_table_ref);
    for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
        DissectorTable dt = checkDissectorTable(L, -1);
        if (dt->created) {
            if (dt->table) {
                deregister_dissector_table(dt->name);
            }
            if (dt->heur_list) {
                deregister_heur_dissector_list(dt->name);
            }
        }
    }

    lua_pop(L, 1); /* dissector_table_ref */

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
