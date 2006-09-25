/*
 * wslua_pinfo.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id: wslua_pinfo.c 18231 2006-05-28 16:32:49Z etxrab $
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

#include "wslua.h"

#include <epan/addr_resolv.h>
#include <string.h>


/*
 * NULLify lua userdata to avoid crashing when trying to
 * access saved copies of invalid stuff.
 *
 * see comment on lua_tvb.c
 */

static GPtrArray* outstanding_stuff = NULL;

void clear_outstanding_pinfos(void) {
    while (outstanding_stuff->len) {
        void** p = (void**)g_ptr_array_remove_index_fast(outstanding_stuff,0);
        *p = NULL;
    }
}

void* push_Pinfo(lua_State* L, Pinfo pinfo) {
    void** p = (void**)pushPinfo(L,pinfo);
    g_ptr_array_add(outstanding_stuff,p);
	return p;
}

#define PUSH_COLUMN(L,c) g_ptr_array_add(outstanding_stuff,pushColumn(L,c))
#define PUSH_COLUMNS(L,c) g_ptr_array_add(outstanding_stuff,pushColumns(L,c))

WSLUA_CLASS_DEFINE(Address,NOP,NOP);

WSLUA_CONSTRUCTOR Address_ip(lua_State* L) { /* Creates an Address Object representing an IP address. */
#define WSLUA_ARG_Address_ip_HOSTNAME 1 /* The address or name of the IP host. */
    Address addr = g_malloc(sizeof(address));
    guint32* ip_addr = g_malloc(sizeof(guint32));
    const gchar* name = luaL_checkstring(L,WSLUA_ARG_Address_ip_HOSTNAME);
    
    if (! get_host_ipaddr(name, (guint32*)ip_addr)) {
        *ip_addr = 0;
    }
        
    SET_ADDRESS(addr, AT_IPv4, 4, ip_addr); 
    pushAddress(L,addr);
    WSLUA_RETURN(1); /* the Address object */
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
	{"ip", Address_ip },
	{"ipv4", Address_ip },
#if 0
    {"ipv6", Address_ipv6 },
    {"ss7pc", Address_ss7 },
    {"eth", Address_eth },
    {"sna", Address_sna },
    {"atalk", Address_atalk },
    {"vines", Address_vines },
    {"osi", Address_osi },
    {"arcnet", Address_arcnet },
    {"fc", Address_fc },
    {"string", Address_string },
    {"eui64", Address_eui64 },
    {"uri", Address_uri },
    {"tipc", Address_tipc },
#endif
    {0,0}
};

WSLUA_METAMETHOD Address__tostring(lua_State* L) {
    Address addr = checkAddress(L,1);
    
    lua_pushstring(L,get_addr_name(addr));
    
    WSLUA_RETURN(1); /* The string representing the address. */
}

static int Address__gc(lua_State* L) {
    Address addr = checkAddress(L,1);
    
    if (addr) {
        if (addr->data) g_free((void*)addr->data);
        g_free((void*)addr);
    }

    return 0;
}

WSLUA_METAMETHOD Address__eq(lua_State* L) { /* compares two Addresses */
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;
    
    if (ADDRESSES_EQUAL(addr1, addr2))
        result = TRUE;
    
    lua_pushboolean(L,result);
    
    return 1;
}

WSLUA_METAMETHOD Address__le(lua_State* L) { /* compares two Addresses */
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;
    
    if (CMP_ADDRESS(addr1, addr2) <= 0)
        result = TRUE;
    
    lua_pushboolean(L,result);
    
    return 1;
}

WSLUA_METAMETHOD Address__lt(lua_State* L) { /* compares two Addresses */
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;
    
    if (CMP_ADDRESS(addr1, addr2) < 0)
        result = TRUE;
    
    lua_pushboolean(L,result);
    
    return 1;
}

WSLUA_META Address_meta[] = {
    {"__gc", Address__gc },
    {"__tostring", Address__tostring },
    {"__eq",Address__eq},
    {"__le",Address__le},
    {"__lt",Address__lt},
    {0,0}
};


int Address_register(lua_State *L) {
	WSLUA_REGISTER_CLASS(Address);
    return 1;
}


WSLUA_CLASS_DEFINE(Column,FAIL_ON_NULL("expired column"),NOP); /* A Column in the packet list */

struct col_names_t {
    const gchar* name;
    int id;
};

static const struct col_names_t colnames[] = {
    {"number",COL_NUMBER},
    {"abs_time",COL_ABS_TIME},
    {"cls_time",COL_CLS_TIME},
    {"rel_time",COL_REL_TIME},
    {"date",COL_ABS_DATE_TIME},
    {"delta_time",COL_DELTA_TIME},
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
    {"oxid",COL_OXID},
    {"rxid",COL_RXID},
    {"direction",COL_IF_DIR},
    {"circuit_id",COL_CIRCUIT_ID},
    {"src_idx",COL_SRCIDX},
    {"dst_idx",COL_DSTIDX},
    {"vsan",COL_VSAN},
    {"tx_rate",COL_TX_RATE},
    {"rssi",COL_RSSI},
    {"hpux_subsys",COL_HPUX_SUBSYS},
    {"hpux_devid",COL_HPUX_DEVID},
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
    const gchar* name;
    
    if (!(c)) {
        return 0;
    }
    
    /* XXX: should return the column's text ! */
    name = col_id_to_name(c->col);
    lua_pushstring(L,name ? name : "Unknown Column");
    
    WSLUA_RETURN(1); /* A string representing the column */
}

WSLUA_METHOD Column_clear(lua_State *L) {
	/* Clears a Column */
    Column c = checkColumn(L,1);
    
    if (!(c && c->cinfo)) return 0;
    
    if (check_col(c->cinfo, c->col))
        col_clear(c->cinfo, c->col);
    
    return 0;
}

WSLUA_METHOD Column_set(lua_State *L) {
	/* Sets the text of a Column */
#define WSLUA_ARG_Column_set_TEXT 2 /* The text to which to set the Column */
	Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,WSLUA_ARG_Column_set_TEXT);
    
    if (!(c && c->cinfo))
		return 0;

	if (!s) WSLUA_ARG_ERROR(Column_set,TEXT,"must be a string");

    if (check_col(c->cinfo, c->col))
        col_set_str(c->cinfo, c->col, s);
    
    return 0;
}

WSLUA_METHOD Column_append(lua_State *L) {
	/* Appends text to a Column */
#define WSLUA_ARG_Column_append_TEXT 2 /* The text to append to the Column */
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,WSLUA_ARG_Column_append_TEXT);
    
	if (!(c && c->cinfo))
		return 0;

	if (!s) WSLUA_ARG_ERROR(Column_append,TEXT,"must be a string");


    if (check_col(c->cinfo, c->col))
        col_append_str(c->cinfo, c->col, s);
    
    return 0;
}

WSLUA_METHOD Column_preppend(lua_State *L) {
	/* Prepends text to a Column */
#define WSLUA_ARG_Column_prepend_TEXT 2 /* The text to prepend to the Column */
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,WSLUA_ARG_Column_prepend_TEXT);
    
	if (!(c && c->cinfo))
		return 0;

	if (!s) WSLUA_ARG_ERROR(Column_prepend,TEXT,"must be a string");

    if (check_col(c->cinfo, c->col))
        col_prepend_fstr(c->cinfo, c->col, "%s",s);
    
    return 0;
}

WSLUA_METHODS Column_methods[] = {
    {"clear", Column_clear },
    {"set", Column_set },
    {"append", Column_append },
    {"preppend", Column_preppend },
    {0,0}
};


WSLUA_META Column_meta[] = {
    {"__tostring", Column__tostring },
    {0,0}
};


int Column_register(lua_State *L) {
	WSLUA_REGISTER_CLASS(Column);
    return 1;
}






WSLUA_CLASS_DEFINE(Columns,NOP,NOP);
/* The Columns of the packet list. */

WSLUA_METAMETHOD Columns__tostring(lua_State *L) {
    lua_pushstring(L,"Columns");
    WSLUA_RETURN(1);
	/* The string "Columns", no real use, just for debugging purposes. */
}

WSLUA_METAMETHOD Columns__newindex(lua_State *L) {
	/* Sets the text of a specific column */
#define WSLUA_ARG_Columns__newindex_COLUMN 2 /* the name of the column to set */
#define WSLUA_ARG_Columns__newindex_TEXT 3 /* the text for the column */
    Columns cols = checkColumns(L,1);
    const struct col_names_t* cn;    
    const char* colname;
    const char* text;
    
    if (!cols) return 0;
    
    colname = luaL_checkstring(L,WSLUA_ARG_Columns__newindex_COLUMN);
    text = luaL_checkstring(L,WSLUA_ARG_Columns__newindex_TEXT);
    
    for(cn = colnames; cn->name; cn++) {
        if( g_str_equal(cn->name,colname) ) {
            if (check_col(cols, cn->id))
                col_set_str(cols, cn->id, text);
            return 0;
        }
    }

	WSLUA_ARG_ERROR(Columns__newindex,COLUMN,"the column name must be a valid column");
    
    return 0;
}

WSLUA_METAMETHOD Columns_index(lua_State *L) {
    Columns cols = checkColumns(L,1);
    const struct col_names_t* cn;    
    const char* colname = luaL_checkstring(L,2);

    if (!cols) {
        Column c = ep_alloc(sizeof(struct _wslua_col_info));
        c->cinfo = NULL;
        c->col = col_name_to_id(colname);
        
        PUSH_COLUMN(L,c);
        return 1;
    }
    
    
    
    if (!colname) return 0;

    for(cn = colnames; cn->name; cn++) {
        if( g_str_equal(cn->name,colname) ) {
            Column c = ep_alloc(sizeof(struct _wslua_col_info));
            c->cinfo = cols;
            c->col = col_name_to_id(colname);

            PUSH_COLUMN(L,c);
            return 1;
        }
    }

    return 0;
}


static const luaL_reg Columns_meta[] = {
    {"__tostring", Columns__tostring },
    {"__newindex", Columns__newindex },
    {"__index",  Columns_index},
    {0,0}
};


int Columns_register(lua_State *L) {
	WSLUA_REGISTER_META(Columns);
    return 1;
}


WSLUA_CLASS_DEFINE(Pinfo,FAIL_ON_NULL("expired pinfo"),NOP);
/* Packet information */

static int Pinfo_tostring(lua_State *L) { lua_pushstring(L,"a Pinfo"); return 1; }

#define PINFO_GET_NUMBER(name,val) static int name(lua_State *L) {  \
    Pinfo pinfo = checkPinfo(L,1); \
    if (!pinfo) return 0;\
    lua_pushnumber(L,(lua_Number)(val));\
    return 1;\
}

#define PINFO_GET_STRING(name,val) static int name(lua_State *L) { \
    Pinfo pinfo = checkPinfo(L,1); \
    const gchar* value; \
    if (!pinfo) return 0; \
    value = val; \
    if (value) lua_pushstring(L,(const char*)(value)); else lua_pushnil(L); \
    return 1; \
}

#define PINFO_GET_ADDRESS(name,role) static int name(lua_State *L) { \
    Pinfo pinfo = checkPinfo(L,1); \
    Address addr = g_malloc(sizeof(address)); \
    if (!pinfo) return 0; \
    COPY_ADDRESS(addr, &(pinfo->role)); \
    pushAddress(L,addr); \
    return 1; \
}

PINFO_GET_NUMBER(Pinfo_number,pinfo->fd->num)
PINFO_GET_NUMBER(Pinfo_len,pinfo->fd->pkt_len)
PINFO_GET_NUMBER(Pinfo_caplen,pinfo->fd->cap_len)
PINFO_GET_NUMBER(Pinfo_abs_ts,(((double)pinfo->fd->abs_ts.secs) + (((double)pinfo->fd->abs_ts.nsecs) / 1000000000.0) ))
PINFO_GET_NUMBER(Pinfo_rel_ts,(((double)pinfo->fd->rel_ts.secs) + (((double)pinfo->fd->rel_ts.nsecs) / 1000000000.0) ))
PINFO_GET_NUMBER(Pinfo_delta_ts,(((double)pinfo->fd->del_ts.secs) + (((double)pinfo->fd->del_ts.nsecs) / 1000000000.0) ))
PINFO_GET_NUMBER(Pinfo_ipproto,pinfo->ipproto)
PINFO_GET_NUMBER(Pinfo_circuit_id,pinfo->circuit_id)
PINFO_GET_NUMBER(Pinfo_ptype,pinfo->ptype)
PINFO_GET_NUMBER(Pinfo_src_port,pinfo->srcport)
PINFO_GET_NUMBER(Pinfo_dst_port,pinfo->destport)

PINFO_GET_STRING(Pinfo_curr_proto,pinfo->current_proto)

PINFO_GET_ADDRESS(Pinfo_net_src,net_src)
PINFO_GET_ADDRESS(Pinfo_net_dst,net_dst)
PINFO_GET_ADDRESS(Pinfo_dl_src,dl_src)
PINFO_GET_ADDRESS(Pinfo_dl_dst,dl_dst)
PINFO_GET_ADDRESS(Pinfo_src,src)
PINFO_GET_ADDRESS(Pinfo_dst,dst)

static int Pinfo_visited(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
    if (!pinfo) return 0;
    lua_pushboolean(L,pinfo->fd->flags.visited);
    return 1;
}


static int Pinfo_match(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
    
    if (!pinfo) return 0;
    
    if (pinfo->match_string) {
        lua_pushstring(L,pinfo->match_string);
    } else {
        lua_pushnumber(L,(lua_Number)(pinfo->match_port));
    }
    
    return 1;
}

static int Pinfo_columns(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
    const gchar* colname = luaL_optstring(L,2,NULL);

    if (!colname) {
        PUSH_COLUMNS(L,pinfo->cinfo);
    } else {
        lua_settop(L,0);
        PUSH_COLUMNS(L,pinfo->cinfo);
        lua_pushstring(L,colname);
        return Columns_index(L);
    }
    return 1;
}


typedef enum {
    PARAM_NONE,
    PARAM_ADDR_SRC,
    PARAM_ADDR_DST,
    PARAM_ADDR_DL_SRC,
    PARAM_ADDR_DL_DST,
    PARAM_ADDR_NET_SRC,
    PARAM_ADDR_NET_DST,
    PARAM_PORT_SRC,
    PARAM_PORT_DST,
    PARAM_CIRCUIT_ID,
    PARAM_PORT_TYPE,
} pinfo_param_type_t;

static int pushnil_param(lua_State* L, packet_info* pinfo _U_, pinfo_param_type_t pt _U_ ) {
    lua_pushnil(L);
    return 1;
}

int Pinfo_set_addr(lua_State* L, packet_info* pinfo, pinfo_param_type_t pt) {
    const address* from = checkAddress(L,1);
    address* to;
    
    if (! from ) {
        luaL_error(L,"Not an OK address");
        return 0;
    }
    
    switch(pt) {
        case PARAM_ADDR_SRC:
            to = &(pinfo->src);
            break;
        case PARAM_ADDR_DST:
            to = &(pinfo->dst);
            break;
        case PARAM_ADDR_DL_SRC:
            to = &(pinfo->dl_src);
            break;
        case PARAM_ADDR_DL_DST:
            to = &(pinfo->dl_dst);
            break;
        case PARAM_ADDR_NET_SRC:
            to = &(pinfo->net_src);
            break;
        case PARAM_ADDR_NET_DST:
            to = &(pinfo->net_dst);
            break;
        default:
            g_assert(!"BUG: A bad parameter");
    }
    
    COPY_ADDRESS(to,from);
    return 0;
}

int Pinfo_set_int(lua_State* L, packet_info* pinfo, pinfo_param_type_t pt) {
    guint v = luaL_checkint(L,1);
    
    switch(pt) {
        case PARAM_PORT_SRC:
            pinfo->srcport = v;
            return 0;
        case PARAM_PORT_DST:
            pinfo->destport = v;
            return 0;
        case PARAM_CIRCUIT_ID:
            pinfo->circuit_id = v;
            return 0;
        default:
            g_assert(!"BUG: A bad parameter");
    }
    
    return 0;
}

typedef struct _pinfo_method_t {
    const gchar* name;
    lua_CFunction get;
    int (*set)(lua_State*, packet_info*, pinfo_param_type_t);
    pinfo_param_type_t param;
} pinfo_method_t;

static int Pinfo_hi(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
	Address addr = g_malloc(sizeof(address));

	if (!pinfo) return 0;
	
	if (CMP_ADDRESS(&(pinfo->src), &(pinfo->dst) ) >= 0) {
		COPY_ADDRESS(addr, &(pinfo->src));
	} else {
		COPY_ADDRESS(addr, &(pinfo->dst));
	}
	
	pushAddress(L,addr);
	return 1;
}

static int Pinfo_lo(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
	Address addr = g_malloc(sizeof(address));
	
	if (!pinfo) return 0;
	
	if (CMP_ADDRESS(&(pinfo->src), &(pinfo->dst) ) < 0) {
		COPY_ADDRESS(addr, &(pinfo->src));
	} else {
		COPY_ADDRESS(addr, &(pinfo->dst));
	}
	
	pushAddress(L,addr);
	return 1;
}


static const pinfo_method_t Pinfo_methods[] = {
	
	/* WSLUA_ATTRIBUTE Pinfo_number RO The number of this packet in the current file */
    {"number", Pinfo_number, pushnil_param, PARAM_NONE},

  	/* WSLUA_ATTRIBUTE Pinfo_len  RO The length of the frame */
    {"len", Pinfo_len, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_caplen RO The captured length of the frame */
    {"caplen", Pinfo_caplen, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_abs_ts RO When the packet was captured */
    {"abs_ts",Pinfo_abs_ts, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_rel_ts RO Number of seconds passed since beginning of capture */
    {"rel_ts",Pinfo_rel_ts, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_delta_ts RO Number of seconds passed since the last packet */
    {"delta_ts",Pinfo_delta_ts, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_visited RO Whether this packet hass been already visited */
    {"visited",Pinfo_visited, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_src RW Source Address of this Packet */
    {"src", Pinfo_src, Pinfo_set_addr, PARAM_ADDR_SRC },
	
	/* WSLUA_ATTRIBUTE Pinfo_dst RW Destination Address of this Packet */
    {"dst", Pinfo_dst, Pinfo_set_addr, PARAM_ADDR_DST },
	
	/* WSLUA_ATTRIBUTE Pinfo_lo RO lower Address of this Packet */
    {"lo", Pinfo_lo, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_hi RW higher Address of this Packet */
    {"hi", Pinfo_hi, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_dl_src RW Data Link Source Address of this Packet */
    {"dl_src", Pinfo_dl_src, Pinfo_set_addr, PARAM_ADDR_DL_SRC },
	
	/* WSLUA_ATTRIBUTE Pinfo_dl_dst RW Data Link Destination Address of this Packet */
    {"dl_dst", Pinfo_dl_dst, Pinfo_set_addr, PARAM_ADDR_DL_DST },
	
	/* WSLUA_ATTRIBUTE Pinfo_net_src RW Network Layer Source Address of this Packet */
    {"net_src", Pinfo_net_src, Pinfo_set_addr, PARAM_ADDR_NET_SRC },
	
	/* WSLUA_ATTRIBUTE Pinfo_net_dst RW Network Layer Destination Address of this Packet */
    {"net_dst", Pinfo_net_dst, Pinfo_set_addr, PARAM_ADDR_NET_DST },

	/* WSLUA_ATTRIBUTE Pinfo_ptype RW Type of Port of .src_port and .dst_port */
    {"port_type", Pinfo_ptype, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_src_port RW Source Port of this Packet */
    {"src_port", Pinfo_src_port, Pinfo_set_int,  PARAM_PORT_SRC },
	
	/* WSLUA_ATTRIBUTE Pinfo_dst_port RW Source Address of this Packet */
    {"dst_port", Pinfo_dst_port, Pinfo_set_int,  PARAM_PORT_SRC },
	
	/* WSLUA_ATTRIBUTE Pinfo_ipproto RO IP Protocol id */
    {"ipproto", Pinfo_ipproto, pushnil_param,  PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_circuit_id RO For circuit based protocols */
    {"circuit_id", Pinfo_circuit_id, Pinfo_set_int, PARAM_CIRCUIT_ID },
	
	/* WSLUA_ATTRIBUTE Pinfo_match RO Port/Data we are matching */	
    {"match", Pinfo_match, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_match RO Which Protocol are we dissecting */	
    {"curr_proto", Pinfo_curr_proto, pushnil_param, PARAM_NONE },
	
	/* WSLUA_ATTRIBUTE Pinfo_columns RO Accesss to the packet list columns */	
    {"cols", Pinfo_columns, pushnil_param, PARAM_NONE },
    
	{NULL,NULL,NULL,PARAM_NONE}
};


static int pushnil(lua_State* L) {
    lua_pushnil(L);
    return 1;
}

static int Pinfo_index(lua_State* L) {
    Pinfo pinfo = checkPinfo(L,1);
    const gchar* name = luaL_checkstring(L,2);
    lua_CFunction method = pushnil;
    const pinfo_method_t* curr;
    
    if (! (pinfo && name) ) {
        lua_pushnil(L);
        return 1;
    }
    
    for (curr = Pinfo_methods ; curr->name ; curr++) {
        if (g_str_equal(curr->name,name)) {
            method = curr->get;
            break;
        }
    }
    
    lua_settop(L,1);
    return method(L);
}

static int Pinfo_setindex(lua_State* L) {
    Pinfo pinfo = checkPinfo(L,1);
    const gchar* name = luaL_checkstring(L,2);
    int (*method)(lua_State*, packet_info* pinfo, pinfo_param_type_t) = pushnil_param;
    const pinfo_method_t* curr;
    pinfo_param_type_t param_type = PARAM_NONE;
    
    if (! (pinfo && name) ) {
        return 0;
    }
    
    for (curr = Pinfo_methods ; curr->name ; curr++) {
        if (g_str_equal(curr->name,name)) {
            method = curr->set;
            param_type = curr->param;
            break;
        }
    }
    
    lua_remove(L,1);
    lua_remove(L,1);    
    return method(L,pinfo,param_type);
}

static const luaL_reg Pinfo_meta[] = {
    {"__index", Pinfo_index},
    {"__newindex",Pinfo_setindex},
    {"__tostring", Pinfo_tostring},
    {0, 0}
};

int Pinfo_register(lua_State* L) {
	WSLUA_REGISTER_META(Pinfo);
    outstanding_stuff = g_ptr_array_new();
    return 1;
}

