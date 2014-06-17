/*
 * wslua_pinfo.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 * (c) 2008, Balint Reczey <balint.reczey@ericsson.com>
 * (c) 2011, Stig Bjorlykke <stig@bjorlykke.org>
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

#include <epan/wmem/wmem.h>

/* WSLUA_MODULE Pinfo Obtaining packet information */


#include "wslua.h"

#include <epan/addr_resolv.h>
#include <epan/conversation.h>
#include <string.h>


/*
 * Track pointers to wireshark's structures.
 * see comment on wslua_tvb.c
 */

static GPtrArray* outstanding_Pinfo = NULL;
static GPtrArray* outstanding_Column = NULL;
static GPtrArray* outstanding_Columns = NULL;
static GPtrArray* outstanding_PrivateTable = NULL;

CLEAR_OUTSTANDING(Pinfo,expired, TRUE)
CLEAR_OUTSTANDING(Column,expired, TRUE)
CLEAR_OUTSTANDING(Columns,expired, TRUE)
CLEAR_OUTSTANDING(PrivateTable,expired, TRUE)

Pinfo* push_Pinfo(lua_State* L, packet_info* ws_pinfo) {
    Pinfo pinfo = NULL;
    if (ws_pinfo) {
        pinfo = (Pinfo)g_malloc(sizeof(struct _wslua_pinfo));
        pinfo->ws_pinfo = ws_pinfo;
        pinfo->expired = FALSE;
        g_ptr_array_add(outstanding_Pinfo,pinfo);
    }
    return pushPinfo(L,pinfo);
}

#define PUSH_COLUMN(L,c) {g_ptr_array_add(outstanding_Column,c);pushColumn(L,c);}
#define PUSH_COLUMNS(L,c) {g_ptr_array_add(outstanding_Columns,c);pushColumns(L,c);}
#define PUSH_PRIVATE_TABLE(L,c) {g_ptr_array_add(outstanding_PrivateTable,c);pushPrivateTable(L,c);}

WSLUA_CLASS_DEFINE(NSTime,FAIL_ON_NULL("NSTime"),NOP);
	/* NSTime represents a nstime_t.  This is an object with seconds and nanoseconds. */

WSLUA_CONSTRUCTOR NSTime_new(lua_State *L) {
	/* Creates a new NSTime object. */
#define WSLUA_OPTARG_NSTime_new_SECONDS 1 /* Seconds. */
#define WSLUA_OPTARG_NSTime_new_NSECONDS 2 /* Nano seconds. */
    NSTime nstime = (NSTime)g_malloc(sizeof(nstime_t));

    if (!nstime) return 0;

    nstime->secs = (time_t) luaL_optint(L,WSLUA_OPTARG_NSTime_new_SECONDS,0);
    nstime->nsecs = luaL_optint(L,WSLUA_OPTARG_NSTime_new_NSECONDS,0);

    pushNSTime(L,nstime);

    WSLUA_RETURN(1); /* The new NSTime object. */
}

WSLUA_METAMETHOD NSTime__call(lua_State* L) { /* Creates a NSTime object. */
#define WSLUA_OPTARG_NSTime__call_SECONDS 1 /* Seconds. */
#define WSLUA_OPTARG_NSTime__call_NSECONDS 2 /* Nanoseconds. */
    lua_remove(L,1); /* remove the table */
    WSLUA_RETURN(NSTime_new(L)); /* The new NSTime object. */
}

WSLUA_METAMETHOD NSTime__tostring(lua_State* L) {
    NSTime nstime = checkNSTime(L,1);
    gchar *str;

    str = wmem_strdup_printf(NULL, "%ld.%09d", (long)nstime->secs, nstime->nsecs);
    lua_pushstring(L, str);
    wmem_free(NULL, str);

    WSLUA_RETURN(1); /* The string representing the nstime. */
}
WSLUA_METAMETHOD NSTime__add(lua_State* L) { /* Calculates the sum of two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    NSTime time3 = (NSTime)g_malloc (sizeof (nstime_t));

    nstime_sum (time3, time1, time2);
    pushNSTime (L, time3);

    return 1;
}

WSLUA_METAMETHOD NSTime__sub(lua_State* L) { /* Calculates the diff of two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    NSTime time3 = (NSTime)g_malloc (sizeof (nstime_t));

    nstime_delta (time3, time1, time2);
    pushNSTime (L, time3);

    return 1;
}

WSLUA_METAMETHOD NSTime__unm(lua_State* L) { /* Calculates the negative NSTime. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = (NSTime)g_malloc (sizeof (nstime_t));

    nstime_set_zero (time2);
    nstime_subtract (time2, time1);
    pushNSTime (L, time2);

    return 1;
}

WSLUA_METAMETHOD NSTime__eq(lua_State* L) { /* Compares two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    gboolean result = FALSE;

    if (nstime_cmp(time1, time2) == 0)
        result = TRUE;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_METAMETHOD NSTime__le(lua_State* L) { /* Compares two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    gboolean result = FALSE;

    if (nstime_cmp(time1, time2) <= 0)
        result = TRUE;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_METAMETHOD NSTime__lt(lua_State* L) { /* Compares two NSTimes. */
    NSTime time1 = checkNSTime(L,1);
    NSTime time2 = checkNSTime(L,2);
    gboolean result = FALSE;

    if (nstime_cmp(time1, time2) < 0)
        result = TRUE;

    lua_pushboolean(L,result);

    return 1;
}


/* WSLUA_ATTRIBUTE NSTime_secs RW The NSTime seconds. */
WSLUA_ATTRIBUTE_NUMBER_GETTER(NSTime,secs);
WSLUA_ATTRIBUTE_NUMBER_SETTER(NSTime,secs,time_t);

/* WSLUA_ATTRIBUTE NSTime_nsecs RW The NSTime nano seconds. */
WSLUA_ATTRIBUTE_NUMBER_GETTER(NSTime,nsecs);
WSLUA_ATTRIBUTE_NUMBER_SETTER(NSTime,nsecs,int);

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int NSTime__gc(lua_State* L) {
    NSTime nstime = toNSTime(L,1);

    if (!nstime) return 0;

    g_free (nstime);
    return 0;
}

/* This table is ultimately registered as a sub-table of the class' metatable,
 * and if __index/__newindex is invoked then it calls the appropriate function
 * from this table for getting/setting the members.
 */
WSLUA_ATTRIBUTES NSTime_attributes[] = {
    WSLUA_ATTRIBUTE_RWREG(NSTime,secs),
    WSLUA_ATTRIBUTE_RWREG(NSTime,nsecs),
    { NULL, NULL, NULL }
};

WSLUA_METHODS NSTime_methods[] = {
    WSLUA_CLASS_FNREG(NSTime,new),
    { NULL, NULL }
};

WSLUA_META NSTime_meta[] = {
    WSLUA_CLASS_MTREG(NSTime,tostring),
    WSLUA_CLASS_MTREG(NSTime,add),
    WSLUA_CLASS_MTREG(NSTime,sub),
    WSLUA_CLASS_MTREG(NSTime,unm),
    WSLUA_CLASS_MTREG(NSTime,eq),
    WSLUA_CLASS_MTREG(NSTime,le),
    WSLUA_CLASS_MTREG(NSTime,lt),
    WSLUA_CLASS_MTREG(NSTime,call),
   { NULL, NULL }
};

int NSTime_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(NSTime);
    WSLUA_REGISTER_ATTRIBUTES(NSTime);
    return 0;
}

WSLUA_CLASS_DEFINE(Address,FAIL_ON_NULL("Address"),NOP); /* Represents an address. */

WSLUA_CONSTRUCTOR Address_ip(lua_State* L) {
	/* Creates an Address Object representing an IP address. */

#define WSLUA_ARG_Address_ip_HOSTNAME 1 /* The address or name of the IP host. */
    Address addr = (Address)g_malloc(sizeof(address));
    guint32* ip_addr = (guint32 *)g_malloc(sizeof(guint32));
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_Address_ip_HOSTNAME);

    if (! get_host_ipaddr(name, (guint32*)ip_addr)) {
        *ip_addr = 0;
    }

    SET_ADDRESS(addr, AT_IPv4, 4, ip_addr);
    pushAddress(L,addr);
    WSLUA_RETURN(1); /* The Address object. */
}

#if 0
/* TODO */
static int Address_ipv6(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_ss7(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_eth(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_sna(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_atalk(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_vines(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_osi(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_arcnet(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_fc(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_string(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_eui64(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_uri(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
static int Address_tipc(lua_State* L) {
    Address addr = g_malloc(sizeof(address));

    SET_ADDRESS(addr, AT_NONE, 4, g_malloc(4));

    pushAddress(L,addr);
    return 1;
}
#endif

WSLUA_METHODS Address_methods[] = {
    WSLUA_CLASS_FNREG(Address,ip),
    WSLUA_CLASS_FNREG_ALIAS(Address,ipv4,ip),
#if 0
    WSLUA_CLASS_FNREG(Address,ipv6),
    WSLUA_CLASS_FNREG_ALIAS(Address,ss7pc,ss7),
    WSLUA_CLASS_FNREG(Address,eth),
    WSLUA_CLASS_FNREG(Address,sna},
    WSLUA_CLASS_FNREG(Address,atalk),
    WSLUA_CLASS_FNREG(Address,vines),
    WSLUA_CLASS_FNREG(Address,osi),
    WSLUA_CLASS_FNREG(Address,arcnet),
    WSLUA_CLASS_FNREG(Address,fc),
    WSLUA_CLASS_FNREG(Address,string),
    WSLUA_CLASS_FNREG(Address,eui64),
    WSLUA_CLASS_FNREG(Address,uri),
    WSLUA_CLASS_FNREG(Address,tipc),
#endif
    { NULL, NULL }
};

WSLUA_METAMETHOD Address__tostring(lua_State* L) {
    Address addr = checkAddress(L,1);

    lua_pushstring(L,ep_address_to_display(addr));

    WSLUA_RETURN(1); /* The string representing the address. */
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Address__gc(lua_State* L) {
    Address addr = toAddress(L,1);

    if (addr) {
        g_free((void*)(addr->data));
        g_free((void*)(addr));
    }

    return 0;
}

WSLUA_METAMETHOD Address__eq(lua_State* L) { /* Compares two Addresses. */
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;

    if (ADDRESSES_EQUAL(addr1, addr2))
        result = TRUE;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_METAMETHOD Address__le(lua_State* L) { /* Compares two Addresses. */
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;

    if (CMP_ADDRESS(addr1, addr2) <= 0)
        result = TRUE;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_METAMETHOD Address__lt(lua_State* L) { /* Compares two Addresses. */
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;

    if (CMP_ADDRESS(addr1, addr2) < 0)
        result = TRUE;

    lua_pushboolean(L,result);

    return 1;
}

WSLUA_META Address_meta[] = {
    WSLUA_CLASS_MTREG(Address,tostring),
    WSLUA_CLASS_MTREG(Address,eq),
    WSLUA_CLASS_MTREG(Address,le),
    WSLUA_CLASS_MTREG(Address,lt),
    { NULL, NULL }
};


int Address_register(lua_State *L) {
    WSLUA_REGISTER_CLASS(Address);
    return 0;
}


WSLUA_CLASS_DEFINE(Column,FAIL_ON_NULL("Column"),NOP); /* A Column in the packet list. */

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

    if (!s) {
        WSLUA_ARG_ERROR(Column_set,TEXT,"must be a string");
        return 0;
    }

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

    if (!s) {
        WSLUA_ARG_ERROR(Column_append,TEXT,"must be a string");
        return 0;
    }

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

    if (!s) {
        WSLUA_ARG_ERROR(Column_prepend,TEXT,"must be a string");
        return 0;
    }

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
    return 0;
}


WSLUA_CLASS_DEFINE(Columns,NOP,NOP);
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

    if (!colname) return 0;

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
    return 0;
}

WSLUA_CLASS_DEFINE(PrivateTable,FAIL_ON_NULL_OR_EXPIRED("PrivateTable"),NOP);
	/* PrivateTable represents the pinfo->private_table. */

WSLUA_METAMETHOD PrivateTable__tostring(lua_State* L) {
    /* Gets debugging type information about the private table. */
    PrivateTable priv = toPrivateTable(L,1);
    GString *key_string;
    GList *keys, *key;

    if (!priv) return 0;

    key_string = g_string_new ("");
    keys = g_hash_table_get_keys (priv->table);
    key = g_list_first (keys);
    while (key) {
        key_string = g_string_append (key_string, (const gchar *)key->data);
        key = g_list_next (key);
        if (key) {
            key_string = g_string_append_c (key_string, ',');
        }
    }

    lua_pushstring(L,key_string->str);

    g_string_free (key_string, TRUE);
    g_list_free (keys);

    WSLUA_RETURN(1); /* A string with all keys in the table, mostly for debugging. */
}

static int PrivateTable__index(lua_State* L) {
	/* Gets the text of a specific entry. */
    PrivateTable priv = checkPrivateTable(L,1);
    const gchar* name = luaL_checkstring(L,2);
    const gchar* string;

    string = (const gchar *)(g_hash_table_lookup (priv->table, (gpointer) name));

    if (string) {
        lua_pushstring(L, string);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static int PrivateTable__newindex(lua_State* L) {
	/* Sets the text of a specific entry. */
    PrivateTable priv = checkPrivateTable(L,1);
    const gchar* name = luaL_checkstring(L,2);
    const gchar* string = NULL;

    if (lua_isstring(L,3)) {
        /* This also catches numbers, which is converted to string */
        string = luaL_checkstring(L,3);
    } else if (lua_isboolean(L,3)) {
        /* We support boolean by setting a empty string if true and NULL if false */
        string = lua_toboolean(L,3) ? "" : NULL;
    } else if (!lua_isnil(L,3)) {
        luaL_error(L,"unsupported type: %s", lua_typename(L,3));
        return 0;
    }

    if (string) {
      g_hash_table_replace (priv->table, (gpointer) ep_strdup(name), (gpointer) ep_strdup(string));
    } else {
      g_hash_table_remove (priv->table, (gconstpointer) name);
    }

    return 1;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int PrivateTable__gc(lua_State* L) {
    PrivateTable priv = toPrivateTable(L,1);

    if (!priv) return 0;

    if (!priv->expired) {
        priv->expired = TRUE;
    } else {
        if (priv->is_allocated) {
            g_hash_table_destroy (priv->table);
        }
        g_free(priv);
    }

    return 0;
}

WSLUA_META PrivateTable_meta[] = {
    WSLUA_CLASS_MTREG(PrivateTable,index),
    WSLUA_CLASS_MTREG(PrivateTable,newindex),
    WSLUA_CLASS_MTREG(PrivateTable,tostring),
    { NULL, NULL }
};

int PrivateTable_register(lua_State* L) {
    WSLUA_REGISTER_META(PrivateTable);
    return 0;
}


WSLUA_CLASS_DEFINE(Pinfo,FAIL_ON_NULL_OR_EXPIRED("Pinfo"),NOP);
/* Packet information. */

static int Pinfo__tostring(lua_State *L) { lua_pushstring(L,"a Pinfo"); return 1; }

#define PINFO_ADDRESS_GETTER(name) \
    WSLUA_ATTRIBUTE_GET(Pinfo,name, { \
      Address addr = g_new(address,1); \
      COPY_ADDRESS(addr, &(obj->ws_pinfo->name)); \
      pushAddress(L,addr); \
    })

#define PINFO_ADDRESS_SETTER(name) \
    WSLUA_ATTRIBUTE_SET(Pinfo,name, { \
      const address* from = checkAddress(L,-1); \
      COPY_ADDRESS(&(obj->ws_pinfo->name),from); \
    })

#define PINFO_NAMED_BOOLEAN_GETTER(name,member) \
    WSLUA_ATTRIBUTE_NAMED_BOOLEAN_GETTER(Pinfo,name,ws_pinfo->member)

#define PINFO_NUMBER_GETTER(name) \
    WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(Pinfo,name,ws_pinfo->name)

#define PINFO_NAMED_NUMBER_GETTER(name,member) \
    WSLUA_ATTRIBUTE_NAMED_NUMBER_GETTER(Pinfo,name,ws_pinfo->member)

#define PINFO_NUMBER_SETTER(name,cast) \
    WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(Pinfo,name,ws_pinfo->name,cast)

#define PINFO_NAMED_NUMBER_SETTER(name,member,cast) \
    WSLUA_ATTRIBUTE_NAMED_NUMBER_SETTER(Pinfo,name,ws_pinfo->member,cast)

static double
lua_nstime_to_sec(const nstime_t *nstime)
{
    return (((double)nstime->secs) + (((double)nstime->nsecs) / 1000000000.0));
}

static double
lua_delta_nstime_to_sec(const Pinfo pinfo, const frame_data *fd, guint32 prev_num)
{
	nstime_t del;

	frame_delta_abs_time(pinfo->ws_pinfo->epan, fd, prev_num, &del);
	return lua_nstime_to_sec(&del);
}


/* WSLUA_ATTRIBUTE Pinfo_visited RO Whether this packet has been already visited. */
PINFO_NAMED_BOOLEAN_GETTER(visited,fd->flags.visited);

/* WSLUA_ATTRIBUTE Pinfo_number RO The number of this packet in the current file. */
PINFO_NAMED_NUMBER_GETTER(number,fd->num);

/* WSLUA_ATTRIBUTE Pinfo_len  RO The length of the frame. */
PINFO_NAMED_NUMBER_GETTER(len,fd->pkt_len);

/* WSLUA_ATTRIBUTE Pinfo_caplen RO The captured length of the frame. */
PINFO_NAMED_NUMBER_GETTER(caplen,fd->cap_len);

/* WSLUA_ATTRIBUTE Pinfo_abs_ts RO When the packet was captured. */
WSLUA_ATTRIBUTE_BLOCK_NUMBER_GETTER(Pinfo,abs_ts,lua_nstime_to_sec(&obj->ws_pinfo->fd->abs_ts));

/* WSLUA_ATTRIBUTE Pinfo_rel_ts RO Number of seconds passed since beginning of capture. */
WSLUA_ATTRIBUTE_BLOCK_NUMBER_GETTER(Pinfo,rel_ts,lua_nstime_to_sec(&obj->ws_pinfo->rel_ts));

/* WSLUA_ATTRIBUTE Pinfo_delta_ts RO Number of seconds passed since the last captured packet. */
WSLUA_ATTRIBUTE_BLOCK_NUMBER_GETTER(Pinfo,delta_ts,lua_delta_nstime_to_sec(obj, obj->ws_pinfo->fd, obj->ws_pinfo->fd->num - 1));

/* WSLUA_ATTRIBUTE Pinfo_delta_dis_ts RO Number of seconds passed since the last displayed packet. */
WSLUA_ATTRIBUTE_BLOCK_NUMBER_GETTER(Pinfo,delta_dis_ts,lua_delta_nstime_to_sec(obj, obj->ws_pinfo->fd, obj->ws_pinfo->fd->prev_dis_num));

/* WSLUA_ATTRIBUTE Pinfo_ipproto RO IP Protocol id. */
PINFO_NUMBER_GETTER(ipproto);

/* WSLUA_ATTRIBUTE Pinfo_circuit_id RW For circuit based protocols. */
PINFO_NUMBER_GETTER(circuit_id);
PINFO_NUMBER_SETTER(circuit_id,guint32);

/* WSLUA_ATTRIBUTE Pinfo_curr_proto RO Which Protocol are we dissecting. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(Pinfo,curr_proto,ws_pinfo->current_proto);

/* WSLUA_ATTRIBUTE Pinfo_can_desegment RW Set if this segment could be desegmented. */
PINFO_NUMBER_GETTER(can_desegment);
PINFO_NUMBER_SETTER(can_desegment,guint16);

/* WSLUA_ATTRIBUTE Pinfo_desegment_len RW Estimated number of additional bytes required for completing the PDU. */
PINFO_NUMBER_GETTER(desegment_len);
PINFO_NUMBER_SETTER(desegment_len,guint32);

/* WSLUA_ATTRIBUTE Pinfo_desegment_offset RW Offset in the tvbuff at which the dissector will continue processing when next called. */
PINFO_NUMBER_GETTER(desegment_offset);
PINFO_NUMBER_SETTER(desegment_offset,int);

/* WSLUA_ATTRIBUTE Pinfo_private_data RO Access to private data. */
WSLUA_ATTRIBUTE_GET(Pinfo,private_data, {lua_pushlightuserdata(L,(void *)(obj->ws_pinfo->private_data));});

/* WSLUA_ATTRIBUTE Pinfo_fragmented RO If the protocol is only a fragment. */
PINFO_NAMED_BOOLEAN_GETTER(fragmented,fragmented);

/* WSLUA_ATTRIBUTE Pinfo_in_error_pkt RO If we're inside an error packet. */
PINFO_NAMED_BOOLEAN_GETTER(in_error_pkt,flags.in_error_pkt);

/* WSLUA_ATTRIBUTE Pinfo_match_uint RO Matched uint for calling subdissector from table. */
PINFO_NUMBER_GETTER(match_uint);

/* WSLUA_ATTRIBUTE Pinfo_match_string RO Matched string for calling subdissector from table. */
WSLUA_ATTRIBUTE_NAMED_STRING_GETTER(Pinfo,match_string,ws_pinfo->match_string);

/* WSLUA_ATTRIBUTE Pinfo_port_type RW Type of Port of .src_port and .dst_port. */
PINFO_NAMED_NUMBER_GETTER(port_type,ptype);

/* WSLUA_ATTRIBUTE Pinfo_src_port RW Source Port of this Packet. */
PINFO_NAMED_NUMBER_GETTER(src_port,srcport);
PINFO_NAMED_NUMBER_SETTER(src_port,srcport,guint32);

/* WSLUA_ATTRIBUTE Pinfo_dst_port RW Source Address of this Packet. */
PINFO_NAMED_NUMBER_GETTER(dst_port,destport);
PINFO_NAMED_NUMBER_SETTER(dst_port,destport,guint32);

/* WSLUA_ATTRIBUTE Pinfo_dl_src RW Data Link Source Address of this Packet. */
PINFO_ADDRESS_GETTER(dl_src);
PINFO_ADDRESS_SETTER(dl_src);

/* WSLUA_ATTRIBUTE Pinfo_dl_dst RW Data Link Destination Address of this Packet. */
PINFO_ADDRESS_GETTER(dl_dst);
PINFO_ADDRESS_SETTER(dl_dst);

/* WSLUA_ATTRIBUTE Pinfo_net_src RW Network Layer Source Address of this Packet. */
PINFO_ADDRESS_GETTER(net_src);
PINFO_ADDRESS_SETTER(net_src);

/* WSLUA_ATTRIBUTE Pinfo_net_dst RW Network Layer Destination Address of this Packet. */
PINFO_ADDRESS_GETTER(net_dst);
PINFO_ADDRESS_SETTER(net_dst);

/* WSLUA_ATTRIBUTE Pinfo_src RW Source Address of this Packet. */
PINFO_ADDRESS_GETTER(src);
PINFO_ADDRESS_SETTER(src);

/* WSLUA_ATTRIBUTE Pinfo_dst RW Destination Address of this Packet. */
PINFO_ADDRESS_GETTER(dst);
PINFO_ADDRESS_SETTER(dst);


/* WSLUA_ATTRIBUTE Pinfo_match RO Port/Data we are matching. */
static int Pinfo_get_match(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);

    if (pinfo->ws_pinfo->match_string) {
        lua_pushstring(L,pinfo->ws_pinfo->match_string);
    } else {
        lua_pushnumber(L,(lua_Number)(pinfo->ws_pinfo->match_uint));
    }

    return 1;
}

/* WSLUA_ATTRIBUTE Pinfo_columns RO Accesss to the packet list columns. */
/* WSLUA_ATTRIBUTE Pinfo_cols RO Accesss to the packet list columns (equivalent to pinfo.columns). */
static int Pinfo_get_columns(lua_State *L) {
    Columns cols = NULL;
    Pinfo pinfo = checkPinfo(L,1);
    const gchar* colname = luaL_optstring(L,2,NULL);

    cols = (Columns)g_malloc(sizeof(struct _wslua_cols));
    cols->cinfo = pinfo->ws_pinfo->cinfo;
    cols->expired = FALSE;

    if (!colname) {
        PUSH_COLUMNS(L,cols);
    } else {
        lua_settop(L,0);
        PUSH_COLUMNS(L,cols);
        lua_pushstring(L,colname);
        return Columns__index(L);
    }
    return 1;
}

/* WSLUA_ATTRIBUTE Pinfo_private RO Access to the private table entries. */
static int Pinfo_get_private(lua_State *L) {
    PrivateTable priv = NULL;
    Pinfo pinfo = checkPinfo(L,1);
    const gchar* privname = luaL_optstring(L,2,NULL);
    gboolean is_allocated = FALSE;

    if (!pinfo->ws_pinfo->private_table) {
        pinfo->ws_pinfo->private_table = g_hash_table_new(g_str_hash,g_str_equal);
        is_allocated = TRUE;
    }

    priv = (PrivateTable)g_malloc(sizeof(struct _wslua_private_table));
    priv->table = pinfo->ws_pinfo->private_table;
    priv->is_allocated = is_allocated;
    priv->expired = FALSE;

    if (!privname) {
        PUSH_PRIVATE_TABLE(L,priv);
    } else {
        lua_settop(L,0);
        PUSH_PRIVATE_TABLE(L,priv);
        lua_pushstring(L,privname);
        return PrivateTable__index(L);
    }
    return 1;
}

/* WSLUA_ATTRIBUTE Pinfo_hi RW higher Address of this Packet. */
static int Pinfo_get_hi(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
    Address addr;

    addr = (Address)g_malloc(sizeof(address));
    if (CMP_ADDRESS(&(pinfo->ws_pinfo->src), &(pinfo->ws_pinfo->dst) ) >= 0) {
        COPY_ADDRESS(addr, &(pinfo->ws_pinfo->src));
    } else {
        COPY_ADDRESS(addr, &(pinfo->ws_pinfo->dst));
    }

    pushAddress(L,addr);
    return 1;
}

/* WSLUA_ATTRIBUTE Pinfo_lo RO lower Address of this Packet. */
static int Pinfo_get_lo(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
    Address addr;

    addr = (Address)g_malloc(sizeof(address));
    if (CMP_ADDRESS(&(pinfo->ws_pinfo->src), &(pinfo->ws_pinfo->dst) ) < 0) {
        COPY_ADDRESS(addr, &(pinfo->ws_pinfo->src));
    } else {
        COPY_ADDRESS(addr, &(pinfo->ws_pinfo->dst));
    }

    pushAddress(L,addr);
    return 1;
}

/* WSLUA_ATTRIBUTE Pinfo_conversation WO sets the packet conversation to the given Proto object. */
static int Pinfo_set_conversation(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
    Proto proto = checkProto(L,2);
    conversation_t  *conversation;

    if (!proto->handle) {
        luaL_error(L,"Proto %s has no registered dissector", proto->name? proto->name:"<UKNOWN>");
        return 0;
    }

    conversation = find_or_create_conversation(pinfo->ws_pinfo);
    conversation_set_dissector(conversation,proto->handle);

    return 0;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Pinfo__gc(lua_State* L) {
    Pinfo pinfo = toPinfo(L,1);

    if (!pinfo) return 0;

    if (!pinfo->expired)
        pinfo->expired = TRUE;
    else
        g_free(pinfo);

    return 0;

}

/* This table is ultimately registered as a sub-table of the class' metatable,
 * and if __index/__newindex is invoked then it calls the appropriate function
 * from this table for getting/setting the members.
 */
WSLUA_ATTRIBUTES Pinfo_attributes[] = {
    WSLUA_ATTRIBUTE_ROREG(Pinfo,number),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,len),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,caplen),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,abs_ts),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,rel_ts),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,delta_ts),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,delta_dis_ts),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,visited),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,src),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,dst),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,lo),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,hi),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,dl_src),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,dl_dst),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,net_src),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,net_dst),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,port_type),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,src_port),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,dst_port),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,ipproto),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,circuit_id),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,match),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,curr_proto),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,columns),
    { "cols", Pinfo_get_columns, NULL },
    WSLUA_ATTRIBUTE_RWREG(Pinfo,can_desegment),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,desegment_len),
    WSLUA_ATTRIBUTE_RWREG(Pinfo,desegment_offset),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,private_data),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,private),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,fragmented),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,in_error_pkt),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,fragmented),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,match_uint),
    WSLUA_ATTRIBUTE_ROREG(Pinfo,match_string),
    WSLUA_ATTRIBUTE_WOREG(Pinfo,conversation),
    { NULL, NULL, NULL }
};

WSLUA_META Pinfo_meta[] = {
    WSLUA_CLASS_MTREG(Pinfo,tostring),
    { NULL, NULL }
};

int Pinfo_register(lua_State* L) {
    WSLUA_REGISTER_META(Pinfo);
    WSLUA_REGISTER_ATTRIBUTES(Pinfo);
    outstanding_Pinfo = g_ptr_array_new();
    outstanding_Column = g_ptr_array_new();
    outstanding_Columns = g_ptr_array_new();
    outstanding_PrivateTable = g_ptr_array_new();
    return 0;
}
