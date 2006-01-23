#include "packet-lua.h"

LUA_CLASS_DEFINE(Column,COLUMN,if (! *p) luaL_error(L,"null column"));
LUA_CLASS_DEFINE(Columns,COLUMNS,NOP);
LUA_CLASS_DEFINE(Pinfo,PINFO,if (! *p) luaL_error(L,"null pinfo"));

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
    
    if (!c) return 0;

    name = col_id_to_name(c->col);
    
    lua_pushstring(L,name ? name : "Unknown Column");
    return 1;
}

static int Column_clear(lua_State *L) {
    Column c = checkColumn(L,1);
    
    if (!c) return 0;
    
    if (check_col(c->cinfo, c->col))
        col_clear(c->cinfo, c->col);
    
    return 0;
}

static int Column_set(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,2);
    
    if (!c) return 0;

    if (check_col(c->cinfo, c->col))
        col_set_str(c->cinfo, c->col, s);
    
    return 0;
}

static int Column_append(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,2);
    
    if (!(c && s)) return 0;
    
    if (check_col(c->cinfo, c->col))
        col_append_str(c->cinfo, c->col, s);
    
    return 0;
}
static int Column_preppend(lua_State *L) {
    Column c = checkColumn(L,1);
    const gchar* s = luaL_checkstring(L,2);
    
    if (!(c && s)) return 0;
    
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
            return 1;
        }
    }
    
    return 0;
}

static int Columns_index(lua_State *L) {
    Columns cols = checkColumns(L,1);
    const struct col_names_t* cn;    
    const char* colname;

    if (!cols) return 0;
    
    colname = luaL_checkstring(L,2);
    
    if (!colname) return 0;

    for(cn = colnames; cn->name; cn++) {
        if( g_str_equal(cn->name,colname) ) {
            Column c = g_malloc(sizeof(struct _eth_col_info));
            c->cinfo = cols;
            c->col = col_name_to_id(colname);
            
            pushColumn(L,c);
            return 0;
        }
    }
    
    return 0;
}


static const luaL_reg Columns_meta[] = {
    {"__tostring", Columns_tostring },
    {"__newindex", Columns_index },
    {"__index", Columns_newindex },
    {0,0}
};


int Columns_register(lua_State *L) {
    luaL_newmetatable(L, COLUMN);
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
    if (!pinfo) return 0; \
    if (val) lua_pushstring(L,(const char*)(val)); else lua_pushnil(L); \
    return 1; \
}

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

static int Pinfo_columns(lua_State *L) {
    Pinfo pinfo = checkPinfo(L,1);
    if (!pinfo) return 0;
    pushColumns(L,pinfo->cinfo);
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
    {"col", Pinfo_columns },
    {0,0}
};

static const luaL_reg Pinfo_meta[] = {
    {"__tostring", Pinfo_tostring},
    {0, 0}
};

int Pinfo_register(lua_State* L) {
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

