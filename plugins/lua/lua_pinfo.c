/*
 * lua_pinfo.c
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

#include "packet-lua.h"
#include <epan/addr_resolv.h>
#include <string.h>

LUA_CLASS_DEFINE(Column,COLUMN,NOP)
LUA_CLASS_DEFINE(Columns,COLUMNS,NOP)
LUA_CLASS_DEFINE(Pinfo,PINFO,if (! *p) luaL_error(L,"null pinfo"))
LUA_CLASS_DEFINE(Address,ADDRESS,NOP)

static int Address_ip(lua_State* L) {
    Address addr = g_malloc(sizeof(address));
    guint32* ip_addr = g_malloc(sizeof(guint32));
    const gchar* name = luaL_checkstring(L,1);
    
    if (! get_host_ipaddr(name, (guint32*)ip_addr)) {
        *ip_addr = 0;
    }
        
    SET_ADDRESS(addr, AT_IPv4, 4, ip_addr); 
    pushAddress(L,addr);
    return 1;
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

static const luaL_reg Address_methods[] = {
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

static int Address_tostring(lua_State* L) {
    Address addr = checkAddress(L,1);
    
    lua_pushstring(L,get_addr_name(addr));
    
    return 1;
}

static int Address_gc(lua_State* L) {
    Address addr = checkAddress(L,1);
    
    if (addr) {
        if (addr->data) g_free((void*)addr->data);
        g_free((void*)addr);
    }

    return 0;
}

static int Address_gt(lua_State* L) {
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;
    
    if (CMP_ADDRESS(addr1, addr2) > 0)
        result = TRUE;

    lua_pushboolean(L,result);
    
    return 1;
}

static int Address_ge(lua_State* L) {
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;
    
    if (CMP_ADDRESS(addr1, addr2) >= 0)
        result = TRUE;
    
    lua_pushboolean(L,result);
    
    return 1;
}

static int Address_eq(lua_State* L) {
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;
    
    if (ADDRESSES_EQUAL(addr1, addr2))
        result = TRUE;
    
    lua_pushboolean(L,result);
    
    return 1;
}

static int Address_le(lua_State* L) {
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;
    
    if (CMP_ADDRESS(addr1, addr2) <= 0)
        result = TRUE;
    
    lua_pushboolean(L,result);
    
    return 1;
}

static int Address_lt(lua_State* L) {
    Address addr1 = checkAddress(L,1);
    Address addr2 = checkAddress(L,2);
    gboolean result = FALSE;
    
    if (CMP_ADDRESS(addr1, addr2) < 0)
        result = TRUE;
    
    lua_pushboolean(L,result);
    
    return 1;
}

static const luaL_reg Address_meta[] = {
    {"__gc", Address_gc },
    {"__tostring", Address_tostring },
    {"__gt",Address_gt},
    {"__ge",Address_ge},
    {"__eq",Address_eq},
    {"__le",Address_le},
    {"__lt",Address_lt},
    {0,0}
};


int Address_register(lua_State *L) {
    luaL_openlib(L, ADDRESS, Address_methods, 0);
    luaL_newmetatable(L, ADDRESS);
    luaL_openlib(L, 0, Address_meta, 0);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushvalue(L, -3);
    lua_rawset(L, -3);
    lua_pop(L, 1);
    
    return 1;
}

/* Column class */
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


static int Column_tostring(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* name;
    
    if (!(c)) {
        luaL_error(L,"Bad column");
        return 0;
    } else {
        /* TODO: format the column */
        name = col_id_to_name(c->col);
        lua_pushstring(L,name ? name : "Unknown Column");
    }
    
    return 1;
}

static int Column_clear(lua_State *L) {
    Column c = checkColumn(L,1);
    
    if (!(c && c->cinfo)) return 0;
    
    if (check_col(c->cinfo, c->col))
        col_clear(c->cinfo, c->col);
    
    return 0;
}

static int Column_set(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,2);
    
    if (!(c && c->cinfo && s)) return 0;

    if (check_col(c->cinfo, c->col))
        col_set_str(c->cinfo, c->col, s);
    
    return 0;
}

static int Column_append(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,2);
    
    if (!(c && c->cinfo && s)) return 0;
    
    if (check_col(c->cinfo, c->col))
        col_append_str(c->cinfo, c->col, s);
    
    return 0;
}
static int Column_preppend(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,2);
    
    if (!(c && c->cinfo && s)) return 0;
    
    if (check_col(c->cinfo, c->col))
        col_prepend_fstr(c->cinfo, c->col, "%s",s);
    
    return 0;
}

static int Column_gc(lua_State *L) {
    Column c = checkColumn(L,1);
    if (!c) return 0;
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


int Column_register(lua_State *L) {
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

    return 1;
}








static int Columns_tostring(lua_State *L) {
    lua_pushstring(L,"Columns");
    return 1;
}

static int Columns_newindex(lua_State *L) {
    Columns cols = checkColumns(L,1);
    const struct col_names_t* cn;    
    const char* colname;
    const char* text;
    
    if (!cols) return 0;
    
    colname = luaL_checkstring(L,2);
    text = luaL_checkstring(L,3);
    
    
    for(cn = colnames; cn->name; cn++) {
        if( g_str_equal(cn->name,colname) ) {
            if (check_col(cols, cn->id))
                col_set_str(cols, cn->id, text);
            return 0;
        }
    }
    
    return 0;
}

static int Columns_index(lua_State *L) {
    Columns cols = checkColumns(L,1);
    const struct col_names_t* cn;    
    const char* colname = luaL_checkstring(L,2);

    if (!cols) {
        Column c = g_malloc(sizeof(struct _eth_col_info));
        c->cinfo = NULL;
        c->col = col_name_to_id(colname);
        
        pushColumn(L,c);
        return 1;
    }
    
    
    
    if (!colname) return 0;

    for(cn = colnames; cn->name; cn++) {
        if( g_str_equal(cn->name,colname) ) {
            Column c = g_malloc(sizeof(struct _eth_col_info));
            c->cinfo = cols;
            c->col = col_name_to_id(colname);

            pushColumn(L,c);
            return 1;
        }
    }

    return 0;
}


static const luaL_reg Columns_meta[] = {
    {"__tostring", Columns_tostring },
    {"__newindex", Columns_newindex },
    {"__index",  Columns_index},
    {0,0}
};


int Columns_register(lua_State *L) {
    luaL_newmetatable(L, COLUMNS);
    luaL_openlib(L, NULL, Columns_meta, 0);
    
    return 1;
}


/* Pinfo class */
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
        pushColumns(L,pinfo->cinfo);
    } else {
        lua_settop(L,0);
        pushColumns(L,pinfo->cinfo);
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


static const pinfo_method_t Pinfo_methods[] = {
    {"number", Pinfo_number, pushnil_param, PARAM_NONE},
    {"len", Pinfo_len, pushnil_param, PARAM_NONE },
    {"caplen", Pinfo_caplen, pushnil_param, PARAM_NONE },
    {"abs_ts",Pinfo_abs_ts, pushnil_param, PARAM_NONE },
    {"rel_ts",Pinfo_rel_ts, pushnil_param, PARAM_NONE },
    {"delta_ts",Pinfo_delta_ts, pushnil_param, PARAM_NONE },
    {"visited",Pinfo_visited, pushnil_param, PARAM_NONE },
    {"src", Pinfo_src, Pinfo_set_addr, PARAM_ADDR_SRC },
    {"dst", Pinfo_dst, Pinfo_set_addr, PARAM_ADDR_DST },
    {"dl_src", Pinfo_dl_src, Pinfo_set_addr, PARAM_ADDR_DL_SRC },
    {"dl_dst", Pinfo_dl_dst, Pinfo_set_addr, PARAM_ADDR_DL_DST },
    {"net_src", Pinfo_net_src, Pinfo_set_addr, PARAM_ADDR_NET_SRC },
    {"net_dst", Pinfo_net_dst, Pinfo_set_addr, PARAM_ADDR_NET_DST },
    {"src_port", Pinfo_src_port, Pinfo_set_int,  PARAM_PORT_SRC },
    {"dst_port", Pinfo_dst_port, Pinfo_set_int,  PARAM_PORT_SRC },
    {"ipproto", Pinfo_ipproto, pushnil_param,  PARAM_NONE },
    {"circuit_id", Pinfo_circuit_id, Pinfo_set_int, PARAM_CIRCUIT_ID },
    {"port_type", Pinfo_ptype, pushnil_param, PARAM_NONE },
    {"match", Pinfo_match, pushnil_param, PARAM_NONE },
    {"curr_proto", Pinfo_curr_proto, pushnil_param, PARAM_NONE },
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
    luaL_newmetatable(L, PINFO);
    luaL_openlib(L, NULL, Pinfo_meta, 0);

    return 1;
}

