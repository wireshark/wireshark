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

#include <epan/exceptions.h>
#include <epan/show_exception.h>


/* WSLUA_CONTINUE_MODULE Proto */


WSLUA_CLASS_DEFINE(Dissector,NOP);
/*
   A refererence to a dissector, used to call a dissector against a packet or a part of it.
 */

WSLUA_CONSTRUCTOR Dissector_get (lua_State *L) {
    /* Obtains a dissector reference by name. */
#define WSLUA_ARG_Dissector_get_NAME 1 /* The name of the dissector. */
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_Dissector_get_NAME);
    Dissector d;

    if ((d = find_dissector(name))) {
        pushDissector(L, d);
        WSLUA_RETURN(1); /* The Dissector reference. */
    }

    WSLUA_ARG_ERROR(Dissector_get,NAME,"No such dissector");
    return 0;
}

/* Allow dissector key names to be sorted alphabetically. */
static gint
compare_dissector_key_name(gconstpointer dissector_a, gconstpointer dissector_b)
{
  return strcmp((const char*)dissector_a, (const char*)dissector_b);
}

WSLUA_CONSTRUCTOR Dissector_list (lua_State *L) {
    /* Gets a Lua array table of all registered Dissector names.

       Note: this is an expensive operation, and should only be used for troubleshooting.

       @since 1.11.3
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
        lua_rawseti(L,1,i);
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
    } CATCH_NONFATAL_ERRORS {
        show_exception(tvb->ws_tvb, pinfo->ws_pinfo, ti->tree, EXCEPT_CODE, GET_MESSAGE);
        error = "Malformed frame";
    } ENDTRY;

    if (error) { WSLUA_ERROR(Dissector_call,error); }

    lua_pushnumber(L,(lua_Number)len);
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
    /* Gets the Dissector's protocol short name. */
    Dissector d = checkDissector(L,1);
    if (!d) return 0;
    lua_pushstring(L,dissector_handle_get_short_name(d));
    WSLUA_RETURN(1); /* A string of the protocol's short name. */
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
 A table of subdissectors of a particular protocol (e.g. TCP subdissectors like http, smtp,
 sip are added to table "tcp.port").

 Useful to add more dissectors to a table so that they appear in the Decode As... dialog.
 */

static int dissectortable_table_ref = LUA_NOREF;

WSLUA_CONSTRUCTOR DissectorTable_new (lua_State *L) {
    /* Creates a new DissectorTable for your dissector's use. */
#define WSLUA_ARG_DissectorTable_new_TABLENAME 1 /* The short name of the table. */
#define WSLUA_OPTARG_DissectorTable_new_UINAME 2 /* The name of the table in the User Interface
                                                    (defaults to the name given). */
#define WSLUA_OPTARG_DissectorTable_new_TYPE 3 /* Either `ftypes.UINT8`, `ftypes.UINT16`,
                                                  `ftypes.UINT24`, `ftypes.UINT32`, or
                                                  `ftypes.STRING`
                                                  (defaults to `ftypes.UINT32`). */
#define WSLUA_OPTARG_DissectorTable_new_BASE 4 /* Either `base.NONE`, `base.DEC`, `base.HEX`,
                                                  `base.OCT`, `base.DEC_HEX` or `base.HEX_DEC`
                                                  (defaults to `base.DEC`). */
    const gchar* name = (const gchar*)luaL_checkstring(L,WSLUA_ARG_DissectorTable_new_TABLENAME);
    const gchar* ui_name = (const gchar*)luaL_optstring(L,WSLUA_OPTARG_DissectorTable_new_UINAME,name);
    enum ftenum type = (enum ftenum)luaL_optinteger(L,WSLUA_OPTARG_DissectorTable_new_TYPE,FT_UINT32);
    unsigned base = (unsigned)luaL_optinteger(L,WSLUA_OPTARG_DissectorTable_new_BASE,BASE_DEC);

    switch(type) {
        case FT_STRING:
            base = BASE_NONE;
            /* fallthrough */
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
        {
            DissectorTable dt = (DissectorTable)g_malloc(sizeof(struct _wslua_distbl_t));

            name = g_strdup(name);
            ui_name = g_strdup(ui_name);

            /* XXX - can't determine dependencies of Lua protocols if they don't provide protocol name */
            dt->table = register_dissector_table(name, ui_name, -1, type, base);
            dt->name = name;
            dt->ui_name = ui_name;
            dt->created = TRUE;
            dt->expired = FALSE;

            lua_rawgeti(L, LUA_REGISTRYINDEX, dissectortable_table_ref);
            lua_pushstring(L, name);
            pushDissectorTable(L, dt);
            lua_settable(L, -3);

            pushDissectorTable(L, dt);
        }
            WSLUA_RETURN(1); /* The newly created DissectorTable. */
        default:
            WSLUA_OPTARG_ERROR(DissectorTable_new,TYPE,"must be ftypes.UINT{8,16,24,32} or ftypes.STRING");
            break;
    }
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
dissector_tables_list_func(const gchar *table_name, const gchar *ui_name _U_, gpointer user_data) {
    dissector_tables_foreach_table_info_t *data = (dissector_tables_foreach_table_info_t*) user_data;
    lua_pushstring(data->L, table_name);
    lua_rawseti(data->L, 1, data->num);
    data->num = data->num + 1;
}

WSLUA_CONSTRUCTOR DissectorTable_list (lua_State *L) {
    /* Gets a Lua array table of all DissectorTable names - i.e., the string names you can
       use for the first argument to DissectorTable.get().

       Note: this is an expensive operation, and should only be used for troubleshooting.

       @since 1.11.3
     */
    dissector_tables_foreach_table_info_t data = { 1, L };

    lua_newtable(L);

    dissector_all_tables_foreach_table(dissector_tables_list_func, (gpointer)&data,
                                       (GCompareFunc)compare_dissector_key_name);

    WSLUA_RETURN(1); /* The array table of registered DissectorTable names. */
}

/* this is the DATFunc_heur_table function used for dissector_all_heur_tables_foreach_table()
   so we can get all heuristic dissector list names. This pushes the name into a table at stack index 1 */
static void
heur_dissector_tables_list_func(const gchar *table_name, struct heur_dissector_list *table _U_, gpointer user_data) {
    dissector_tables_foreach_table_info_t *data = (dissector_tables_foreach_table_info_t*) user_data;
    lua_pushstring(data->L, table_name);
    lua_rawseti(data->L, 1, data->num);
    data->num = data->num + 1;
}

WSLUA_CONSTRUCTOR DissectorTable_heuristic_list (lua_State *L) {
    /* Gets a Lua array table of all heuristic list names - i.e., the string names you can
       use for the first argument in Proto:register_heuristic().

       Note: this is an expensive operation, and should only be used for troubleshooting.

       @since 1.11.3
     */
    dissector_tables_foreach_table_info_t data = { 1, L };

    lua_newtable(L);

    dissector_all_heur_tables_foreach_table(heur_dissector_tables_list_func, (gpointer)&data, NULL);

    WSLUA_RETURN(1); /* The array table of registered heuristic list names */
}

WSLUA_CONSTRUCTOR DissectorTable_get (lua_State *L) {
    /*
     Obtain a reference to an existing dissector table.
     */
#define WSLUA_ARG_DissectorTable_get_TABLENAME 1 /* The short name of the table. */
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_DissectorTable_get_TABLENAME);
    dissector_table_t table = find_dissector_table(name);

    if (table) {
        DissectorTable dt = (DissectorTable)g_malloc(sizeof(struct _wslua_distbl_t));
        dt->table = table;
        dt->name = g_strdup(name);
        dt->ui_name = NULL;
        dt->created = FALSE;
        dt->expired = FALSE;

        pushDissectorTable(L, dt);

        WSLUA_RETURN(1); /* The DissectorTable. */
    }

    WSLUA_ARG_ERROR(DissectorTable_get,TABLENAME,"no such dissector_table");
    return 0;
}

WSLUA_METHOD DissectorTable_add (lua_State *L) {
    /*
     Add a `Proto` with a dissector function, or a `Dissector` object, to the dissector table.
     */
#define WSLUA_ARG_DissectorTable_add_PATTERN 2 /* The pattern to match (either an integer, a
                                                  integer range or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_add_DISSECTOR 3 /* The dissector to add (either a `Proto` or a `Dissector`). */

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
        gchar* pattern = g_strdup(luaL_checkstring(L,WSLUA_ARG_DissectorTable_add_PATTERN));
        dissector_add_string(dt->name, pattern,handle);
        g_free (pattern);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        if (lua_isnumber(L, WSLUA_ARG_DissectorTable_add_PATTERN)) {
            int port = (int)luaL_checkinteger(L, WSLUA_ARG_DissectorTable_add_PATTERN);
            dissector_add_uint(dt->name, port, handle);
        } else {
            /* Not a number, try as range */
            const gchar* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_add_PATTERN);
            range_t *range = NULL;
            if (range_convert_str(&range, pattern, G_MAXUINT32) == CVT_NO_ERROR) {
                dissector_add_uint_range(dt->name, range, handle);
            } else {
                g_free (range);
                WSLUA_ARG_ERROR(DissectorTable_add,PATTERN,"invalid integer or range");
                return  0;
            }
            g_free (range);
        }
    } else {
        luaL_error(L,"Strange type %d for a DissectorTable",type);
    }

    return 0;
}

WSLUA_METHOD DissectorTable_set (lua_State *L) {
    /*
     Remove existing dissectors from a table and add a new or a range of new dissectors.

     @since 1.11.3
     */
#define WSLUA_ARG_DissectorTable_set_PATTERN 2 /* The pattern to match (either an integer, a integer range or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_set_DISSECTOR 3 /* The dissector to add (either a `Proto` or a `Dissector`). */

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
        const gchar* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_set_PATTERN);
        dissector_delete_all(dt->name, handle);
        dissector_add_string(dt->name, pattern,handle);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        if (lua_isnumber(L, WSLUA_ARG_DissectorTable_set_PATTERN)) {
            int port = (int)luaL_checkinteger(L, WSLUA_ARG_DissectorTable_set_PATTERN);
            dissector_delete_all(dt->name, handle);
            dissector_add_uint(dt->name, port, handle);
        } else {
            /* Not a number, try as range */
            const gchar* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_set_PATTERN);
            range_t *range = NULL;
            if (range_convert_str(&range, pattern, G_MAXUINT32) == CVT_NO_ERROR) {
                dissector_delete_all(dt->name, handle);
                dissector_add_uint_range(dt->name, range, handle);
            } else {
                g_free (range);
                WSLUA_ARG_ERROR(DissectorTable_set,PATTERN,"invalid integer or range");
                return 0;
            }
            g_free (range);
        }
    } else {
        luaL_error(L,"Strange type %d for a DissectorTable",type);
    }

    return 0;
}

WSLUA_METHOD DissectorTable_remove (lua_State *L) {
    /*
     Remove a dissector or a range of dissectors from a table
     */
#define WSLUA_ARG_DissectorTable_remove_PATTERN 2 /* The pattern to match (either an integer, a integer range or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_remove_DISSECTOR 3 /* The dissector to remove (either a `Proto` or a `Dissector`). */
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
        gchar* pattern = g_strdup(luaL_checkstring(L,WSLUA_ARG_DissectorTable_remove_PATTERN));
        dissector_delete_string(dt->name, pattern,handle);
        g_free (pattern);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        if (lua_isnumber(L, WSLUA_ARG_DissectorTable_remove_PATTERN)) {
          int port = (int)luaL_checkinteger(L, WSLUA_ARG_DissectorTable_remove_PATTERN);
          dissector_delete_uint(dt->name, port, handle);
        } else {
            /* Not a number, try as range */
            const gchar* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_remove_PATTERN);
            range_t *range = NULL;
            if (range_convert_str(&range, pattern, G_MAXUINT32) == CVT_NO_ERROR)
                dissector_delete_uint_range(dt->name, range, handle);
            else {
                g_free (range);
                WSLUA_ARG_ERROR(DissectorTable_remove,PATTERN,"invalid integer or range");
                return 0;
            }
            g_free (range);
        }
    }

    return 0;
}

WSLUA_METHOD DissectorTable_remove_all (lua_State *L) {
    /*
     Remove all dissectors from a table.

     @since 1.11.3
     */
#define WSLUA_ARG_DissectorTable_remove_all_DISSECTOR 2 /* The dissector to remove (either a `Proto` or a `Dissector`). */
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
     Try to call a dissector from a table
     */
#define WSLUA_ARG_DissectorTable_try_PATTERN 2 /* The pattern to be matched (either an integer or a string depending on the table's type). */
#define WSLUA_ARG_DissectorTable_try_TVB 3 /* The buffer to dissect. */
#define WSLUA_ARG_DissectorTable_try_PINFO 4 /* The packet info. */
#define WSLUA_ARG_DissectorTable_try_TREE 5 /* The tree on which to add the protocol items. */
    DissectorTable volatile dt = checkDissectorTable(L,1);
    Tvb tvb = checkTvb(L,WSLUA_ARG_DissectorTable_try_TVB);
    Pinfo pinfo = checkPinfo(L,WSLUA_ARG_DissectorTable_try_PINFO);
    TreeItem ti = checkTreeItem(L,WSLUA_ARG_DissectorTable_try_TREE);
    ftenum_t type;
    gboolean handled = FALSE;
    const gchar *volatile error = NULL;
    int len = 0;

    if (! (dt && tvb && tvb->ws_tvb && pinfo && ti) ) return 0;

    type = get_dissector_table_selector_type(dt->name);

    TRY {

        if (type == FT_STRING) {
            const gchar* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_try_PATTERN);

            len = dissector_try_string(dt->table,pattern,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree, NULL);
            if (len > 0) {
                handled = TRUE;
            }
        } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
            int port = (int)luaL_checkinteger(L, WSLUA_ARG_DissectorTable_try_PATTERN);

            len = dissector_try_uint(dt->table,port,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree);
            if (len > 0) {
                handled = TRUE;
            }
        } else {
            luaL_error(L,"No such type of dissector_table");
        }

        if (!handled) {
            len = call_dissector(lua_data_handle,tvb->ws_tvb,pinfo->ws_pinfo,ti->tree);
        }
        /* XXX Are we sure about this??? is this the right/only thing to catch */
    } CATCH_NONFATAL_ERRORS {
        show_exception(tvb->ws_tvb, pinfo->ws_pinfo, ti->tree, EXCEPT_CODE, GET_MESSAGE);
        error = "Malformed frame";
    } ENDTRY;

    if (error) { WSLUA_ERROR(DissectorTable_try,error); }

    lua_pushnumber(L,(lua_Number)len);
    WSLUA_RETURN(1); /* Number of bytes dissected.  Note that some dissectors always return number of bytes in incoming buffer, so be aware. */
}

WSLUA_METHOD DissectorTable_get_dissector (lua_State *L) {
    /*
     Try to obtain a dissector from a table.
     */
#define WSLUA_ARG_DissectorTable_get_dissector_PATTERN 2 /* The pattern to be matched (either an integer or a string depending on the table's type). */

    DissectorTable dt = checkDissectorTable(L,1);
    ftenum_t type;
    dissector_handle_t handle = lua_data_handle;

    if (!dt) return 0;

    type = get_dissector_table_selector_type(dt->name);

    if (type == FT_STRING) {
        const gchar* pattern = luaL_checkstring(L,WSLUA_ARG_DissectorTable_get_dissector_PATTERN);
        handle = dissector_get_string_handle(dt->table,pattern);
    } else if ( type == FT_UINT32 || type == FT_UINT16 || type ==  FT_UINT8 || type ==  FT_UINT24 ) {
        int port = (int)luaL_checkinteger(L, WSLUA_ARG_DissectorTable_get_dissector_PATTERN);
        handle = dissector_get_uint_handle(dt->table,port);
    }

    if (handle) {
        pushDissector(L,handle);
        WSLUA_RETURN(1); /* The dissector handle if found. */
    } else {
        lua_pushnil(L);
        WSLUA_RETURN(1); /* nil if not found. */
    }
}

WSLUA_METHOD DissectorTable_add_for_decode_as (lua_State *L) {
    /*
     Add the given `Proto` to the "Decode as..." list for this DissectorTable.
     The passed-in `Proto` object's `dissector()` function is used for dissecting.

     @since 1.99.1
     */
#define WSLUA_ARG_DissectorTable_add_for_decode_as_PROTO 2 /* The `Proto` to add. */
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
    /* Gets some debug information about the DissectorTable. */
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
        default:
            luaL_error(L,"Strange table type");
    }

    lua_pushstring(L,s->str);
    g_string_free(s,TRUE);
    WSLUA_RETURN(1); /* A string of debug information about the DissectorTable. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int DissectorTable__gc(lua_State* L) {
    DissectorTable dt = toDissectorTable(L,1);

    if (dt->created && !dt->expired) {
        /* Created DissectorTable will pass GC two times */
        dt->expired = TRUE;
    } else {
        g_free((char *)dt->name);
        g_free((char *)dt->ui_name);
        g_free(dt);
    }

    return 0;
}

WSLUA_METHODS DissectorTable_methods[] = {
    WSLUA_CLASS_FNREG(DissectorTable,new),
    WSLUA_CLASS_FNREG(DissectorTable,get),
    WSLUA_CLASS_FNREG(DissectorTable,list),
    WSLUA_CLASS_FNREG(DissectorTable,heuristic_list),
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
            deregister_dissector_table(dt->name);
        }
    }

    lua_pop(L, 1); /* dissector_table_ref */

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
