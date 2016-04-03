/*
 * wslua_column.c
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

#include "wslua_pinfo_common.h"


/* WSLUA_CONTINUE_MODULE Pinfo */


static GPtrArray* outstanding_Column = NULL;
static GPtrArray* outstanding_Columns = NULL;

CLEAR_OUTSTANDING(Column,expired, TRUE)
CLEAR_OUTSTANDING(Columns,expired, TRUE)

#define PUSH_COLUMN(L,c) {g_ptr_array_add(outstanding_Column,c);pushColumn(L,c);}

void Push_Columns(lua_State *L, Columns c)
{
    g_ptr_array_add(outstanding_Columns, c);
    pushColumns(L, c);
}


WSLUA_CLASS_DEFINE(Column,FAIL_ON_NULL("Column")); /* A Column in the packet list. */

struct col_names_t {
    const gchar* name;
    int id;
};

static const struct col_names_t colnames[] = {
    {"number",COL_NUMBER},
    {"abs_time",COL_ABS_TIME},
    {"utc_time",COL_UTC_TIME},
    {"cls_time",COL_CLS_TIME},
    {"rel_time",COL_REL_TIME},
    {"date",COL_ABS_YMD_TIME},
    {"date_doy",COL_ABS_YDOY_TIME},
    {"utc_date",COL_UTC_YMD_TIME},
    {"utc_date_doy",COL_UTC_YDOY_TIME},
    {"delta_time",COL_DELTA_TIME},
    {"delta_time_displayed",COL_DELTA_TIME_DIS},
    {"src",COL_DEF_SRC},
    {"src_res",COL_RES_SRC},
    {"src_unres",COL_UNRES_SRC},
    {"dl_src",COL_DEF_DL_SRC},
    {"dl_src_res",COL_RES_DL_SRC},
    {"dl_src_unres",COL_UNRES_DL_SRC},
    {"net_src",COL_DEF_NET_SRC},
    {"net_src_res",COL_RES_NET_SRC},
    {"net_src_unres",COL_UNRES_NET_SRC},
    {"dst",COL_DEF_DST},
    {"dst_res",COL_RES_DST},
    {"dst_unres",COL_UNRES_DST},
    {"dl_dst",COL_DEF_DL_DST},
    {"dl_dst_res",COL_RES_DL_DST},
    {"dl_dst_unres",COL_UNRES_DL_DST},
    {"net_dst",COL_DEF_NET_DST},
    {"net_dst_res",COL_RES_NET_DST},
    {"net_dst_unres",COL_UNRES_NET_DST},
    {"src_port",COL_DEF_SRC_PORT},
    {"src_port_res",COL_RES_SRC_PORT},
    {"src_port_unres",COL_UNRES_SRC_PORT},
    {"dst_port",COL_DEF_DST_PORT},
    {"dst_port_res",COL_RES_DST_PORT},
    {"dst_port_unres",COL_UNRES_DST_PORT},
    {"protocol",COL_PROTOCOL},
    {"info",COL_INFO},
    {"packet_len",COL_PACKET_LENGTH},
    {"cumulative_bytes",COL_CUMULATIVE_BYTES},
    {"direction",COL_IF_DIR},
    {"vsan",COL_VSAN},
    {"tx_rate",COL_TX_RATE},
    {"rssi",COL_RSSI},
    {"dce_call",COL_DCE_CALL},
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


WSLUA_METAMETHOD Column__tostring(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* text;

    if (!c->cinfo) {
        text = col_id_to_name(c->col);
        lua_pushfstring(L, "(%s)", text ? text : "unknown");
    }
    else {
        text = col_get_text(c->cinfo, c->col);
        lua_pushstring(L, text ? text : "(nil)");
    }

    WSLUA_RETURN(1); /* The column's string text (in parenthesis if not available). */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS */
static int Column__gc(lua_State* L) {
    Column col = toColumn(L,1);

    if (!col) return 0;

    if (!col->expired)
        col->expired = TRUE;
    else
        g_free(col);

    return 0;

}

WSLUA_METHOD Column_clear(lua_State *L) {
    /* Clears a Column. */
    Column c = checkColumn(L,1);

    if (!(c->cinfo)) return 0;

    col_clear(c->cinfo, c->col);

    return 0;
}

WSLUA_METHOD Column_set(lua_State *L) {
    /* Sets the text of a Column. */
#define WSLUA_ARG_Column_set_TEXT 2 /* The text to which to set the Column. */
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,WSLUA_ARG_Column_set_TEXT);

    if (!(c->cinfo))
        return 0;

    col_add_str(c->cinfo, c->col, s);

    return 0;
}

WSLUA_METHOD Column_append(lua_State *L) {
    /* Appends text to a Column. */
#define WSLUA_ARG_Column_append_TEXT 2 /* The text to append to the Column. */
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,WSLUA_ARG_Column_append_TEXT);

    if (!(c->cinfo))
        return 0;

    col_append_str(c->cinfo, c->col, s);

    return 0;
}

WSLUA_METHOD Column_prepend(lua_State *L) {
    /* Prepends text to a Column. */
#define WSLUA_ARG_Column_prepend_TEXT 2 /* The text to prepend to the Column. */
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,WSLUA_ARG_Column_prepend_TEXT);

    if (!(c->cinfo))
        return 0;

    col_prepend_fstr(c->cinfo, c->col, "%s",s);

    return 0;
}

WSLUA_METHOD Column_fence(lua_State *L) {
    /* Sets Column text fence, to prevent overwriting.

       @since 1.10.6
     */
    Column c = checkColumn(L,1);

    if (c->cinfo)
        col_set_fence(c->cinfo, c->col);

    return 0;
}

WSLUA_METHOD Column_clear_fence(lua_State *L) {
    /* Clear Column text fence.

       @since 1.11.3
     */
    Column c = checkColumn(L,1);

    if (c->cinfo)
        col_clear_fence(c->cinfo, c->col);

    return 0;
}


WSLUA_METHODS Column_methods[] = {
    WSLUA_CLASS_FNREG(Column,clear),
    WSLUA_CLASS_FNREG(Column,set),
    WSLUA_CLASS_FNREG(Column,append),
    WSLUA_CLASS_FNREG(Column,prepend),
    WSLUA_CLASS_FNREG_ALIAS(Column,preppend,prepend),
    WSLUA_CLASS_FNREG(Column,fence),
    WSLUA_CLASS_FNREG(Column,clear_fence),
    { NULL, NULL }
};


WSLUA_META Column_meta[] = {
    WSLUA_CLASS_MTREG(Column,tostring),
    { NULL, NULL }
};


int Column_register(lua_State *L) {
    WSLUA_REGISTER_CLASS(Column);
    outstanding_Column = g_ptr_array_new();
    return 0;
}


WSLUA_CLASS_DEFINE(Columns,NOP);
/* The Columns of the packet list. */

WSLUA_METAMETHOD Columns__tostring(lua_State *L) {
    lua_pushstring(L,"Columns");
    WSLUA_RETURN(1);
    /* The string "Columns", no real use, just for debugging purposes. */
}

/*
 * To document this is very odd - it won't make sense to a person reading the
 * API docs to see this metamethod as a method, but oh well.
 */
WSLUA_METAMETHOD Columns__newindex(lua_State *L) {
    /* Sets the text of a specific column. */
#define WSLUA_ARG_Columns__newindex_COLUMN 2 /* The name of the column to set. */
#define WSLUA_ARG_Columns__newindex_TEXT 3 /* The text for the column. */
    Columns cols = checkColumns(L,1);
    const struct col_names_t* cn;
    const char* colname;
    const char* text;

    if (!cols) return 0;
    if (cols->expired) {
        luaL_error(L,"expired column");
        return 0;
    }

    colname = luaL_checkstring(L,WSLUA_ARG_Columns__newindex_COLUMN);
    text = luaL_checkstring(L,WSLUA_ARG_Columns__newindex_TEXT);

    for(cn = colnames; cn->name; cn++) {
        if( g_str_equal(cn->name,colname) ) {
            col_add_str(cols->cinfo, cn->id, text);
            return 0;
        }
    }

    WSLUA_ARG_ERROR(Columns__newindex,COLUMN,"the column name must be a valid column");
    return 0;
}

WSLUA_METAMETHOD Columns__index(lua_State *L) {
    /* Gets a specific Column. */
    Columns cols = checkColumns(L,1);
    const struct col_names_t* cn;
    const char* colname = luaL_checkstring(L,2);

    if (!cols) {
        Column c = (Column)g_malloc(sizeof(struct _wslua_col_info));
        c->cinfo = NULL;
        c->col = col_name_to_id(colname);
        c->expired = FALSE;

        PUSH_COLUMN(L,c);
        return 1;
    }


    if (cols->expired) {
        luaL_error(L,"expired column");
        return 0;
    }

    for(cn = colnames; cn->name; cn++) {
        if( g_str_equal(cn->name,colname) ) {
            Column c = (Column)g_malloc(sizeof(struct _wslua_col_info));
            c->cinfo = cols->cinfo;
            c->col = col_name_to_id(colname);
            c->expired = FALSE;

            PUSH_COLUMN(L,c);
            return 1;
        }
    }

    return 0;
}

/* for internal use - used by Pinfo */
int get_Columns_index(lua_State *L)
{
    return Columns__index(L);
}


/* Gets registered as metamethod automatically by WSLUA_REGISTER_META */
static int Columns__gc(lua_State* L) {
    Columns cols = toColumns(L,1);

    if (!cols) return 0;

    if (!cols->expired)
        cols->expired = TRUE;
    else
        g_free(cols);

    return 0;

}


WSLUA_META Columns_meta[] = {
    WSLUA_CLASS_MTREG(Columns,tostring),
    WSLUA_CLASS_MTREG(Columns,newindex),
    WSLUA_CLASS_MTREG(Columns,index),
    { NULL, NULL }
};


int Columns_register(lua_State *L) {
    WSLUA_REGISTER_META(Columns);
    outstanding_Columns = g_ptr_array_new();
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
