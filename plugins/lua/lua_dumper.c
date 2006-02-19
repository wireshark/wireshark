/*
 *  lua_dumper.c
 *
 * Ethereal's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * $Id: lua_tvb.c 17307 2006-02-15 02:10:07Z lego $
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
#include <math.h>

LUA_CLASS_DEFINE(Dumper,DUMPER,NOP)
LUA_CLASS_DEFINE(PseudoHeader,PSEUDOHEADER,NOP)

enum lua_pseudoheader_type {
    PHDR_NONE,
    PHDR_ETH,
    PHDR_X25,
    PHDR_ISDN,
    PHDR_ATM,
    PHDR_ASCEND,
    PHDR_P2P,
    PHDR_WIFI,
    PHDR_COSINE,
    PHDR_IRDA,
    PHDR_NETTL,
    PHDR_MTP2,
    PHDR_K12
};

struct lua_pseudo_header {
    enum lua_pseudoheader_type type;
    union wtap_pseudo_header* wph;   
};

static int PseudoHeader_none(lua_State* L) {
    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_NONE;
    ph->wph = NULL;
    
    pushPseudoHeader(L,ph);
    return 1;
}

static int PseudoHeader_eth(lua_State* L) {
    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_ETH;
    ph->wph = g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->eth.fcs_len = luaL_optint(L,1,-1);
    
    pushPseudoHeader(L,ph);
    return 1;
}

static int PseudoHeader_atm(lua_State* L) { 
    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_ATM;
    ph->wph = g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->atm.aal = luaL_optint(L,1,5);
    ph->wph->atm.vpi = luaL_optint(L,2,1);
    ph->wph->atm.vci = luaL_optint(L,3,1);
    ph->wph->atm.channel = luaL_optint(L,4,0);
    ph->wph->atm.cells = luaL_optint(L,5,1);
    ph->wph->atm.aal5t_u2u = luaL_optint(L,6,1);
    ph->wph->atm.aal5t_len = luaL_optint(L,7,0);
    
    pushPseudoHeader(L,ph);
    return 1;
}

static int PseudoHeader_mtp2(lua_State* L) {
    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_MTP2;
    ph->wph = g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->mtp2.sent = luaL_optint(L,1,0);
    ph->wph->mtp2.annex_a_used = luaL_optint(L,2,0);
    ph->wph->mtp2.link_number = luaL_optint(L,3,0);

    pushPseudoHeader(L,ph);
    return 1;
}

#if 0
static int PseudoHeader_x25(lua_State* L) { luaL_error(L,"not implemented"); return 0; }
static int PseudoHeader_isdn(lua_State* L) { luaL_error(L,"not implemented"); return 0; }
static int PseudoHeader_ascend(lua_State* L) { luaL_error(L,"not implemented"); return 0; }
static int PseudoHeader_wifi(lua_State* L) { luaL_error(L,"not implemented"); return 0; }
static int PseudoHeader_cosine(lua_State* L) { luaL_error(L,"not implemented"); return 0; }
static int PseudoHeader_irda(lua_State* L) { luaL_error(L,"not implemented"); return 0; }
static int PseudoHeader_nettl(lua_State* L) { luaL_error(L,"not implemented"); return 0; }
static int PseudoHeader_k12(lua_State* L) { luaL_error(L,"not implemented"); return 0; }
#endif

int PseudoHeader_register(lua_State* L) {
    luaL_newmetatable(L, PSEUDOHEADER);
    
    lua_pushstring(L, "PH_MTP2");
    lua_pushcfunction(L, PseudoHeader_mtp2);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "PH_ATM");
    lua_pushcfunction(L, PseudoHeader_atm);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "PH_ETH");
    lua_pushcfunction(L, PseudoHeader_eth);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    lua_pushstring(L, "PH_NONE");
    lua_pushcfunction(L, PseudoHeader_none);
    lua_settable(L, LUA_GLOBALSINDEX);
    
    return 0;
}

static GHashTable* dumper_encaps = NULL;
#define DUMPER_ENCAP(d) GPOINTER_TO_INT(g_hash_table_lookup(dumper_encaps,d))

static int Dumper_new(lua_State* L) {
    Dumper d;
    const char* filename = luaL_checkstring(L,1);
    int filetype = luaL_optint(L,2,WTAP_FILE_PCAP);
    int encap  = luaL_optint(L,3,WTAP_ENCAP_ETHERNET);
    int err = 0;
    
    if (! filename) return 0;
    
    if (!wtap_dump_can_write_encap(filetype, encap)) {
        luaL_error(L,"Cannot write encap %s in filetype %s",
                   wtap_encap_short_string(encap),
                   wtap_file_type_string(filetype));
        return 0;
    }
    
    d = wtap_dump_open(filename, filetype, encap,0 , FALSE, &err);
    
    if (! d ) {
        luaL_error(L,"error while opening `%s': %s",
                   filename,
                   wtap_strerror(err));
        return 0;
    }
    
    g_hash_table_insert(dumper_encaps,d,GINT_TO_POINTER(encap));
    
    pushDumper(L,d);
    return 1;
}

static int Dumper_close(lua_State* L) {
    Dumper d = checkDumper(L,1);
    int err;
    
    if (!d) return 0;

    g_hash_table_remove(dumper_encaps,d);

    if (!wtap_dump_close(d, &err)) {
        luaL_error(L,"error closing: %s",
                   wtap_strerror(err));
    }

    return 0;
   
}

static int Dumper_flush(lua_State* L) {
    Dumper d = checkDumper(L,1);

    if (!d) return 0;
    
    wtap_dump_flush(d);
    
    return 0;
}

static int Dumper_dump(lua_State* L) {
    Dumper d = checkDumper(L,1);
    PseudoHeader ph;
    ByteArray ba;
    struct wtap_pkthdr pkthdr;
    double ts;
    int err;
    
    if (!d) return 0;
    
    ts = luaL_checknumber(L,2);
    ph = checkPseudoHeader(L,3);
    
    if (!ph) {
        luaL_error(L,"Cannot do without a Pseudo Header");
        return 0;
    }
    
    ba = checkByteArray(L,4);
    
    if (! ba) {
        luaL_error(L,"No data to dump!");
        return 0;
    }
    
    pkthdr.ts.secs = floor(ts);
    pkthdr.ts.nsecs = floor(ts - pkthdr.ts.secs) * 1000000000;
    pkthdr.len  = ba->len;
    pkthdr.caplen  = ba->len;    
    pkthdr.pkt_encap = DUMPER_ENCAP(d);
    
    if (! wtap_dump(d, &pkthdr, ph->wph, ba->data, &err)) {
        luaL_error(L,"error while dumping: %s",
                   wtap_strerror(err));        
    }
    
    return 0;
    
}

static int Dumper_new_for_current(lua_State* L) {
    Dumper d;
    const char* filename = luaL_checkstring(L,1);
    int filetype = luaL_optint(L,2,WTAP_FILE_PCAP);
    int encap;
    int err = 0;
    
    if (!d) return 0;
    
    if (! lua_pinfo ) {
        luaL_error(L,"Dumper.new_for_current cannot be used outside a tap or a dissector");
        return 0;
    }
    
    encap = lua_pinfo->fd->lnk_t;
    
    if (!wtap_dump_can_write_encap(filetype, encap)) {
        luaL_error(L,"Cannot write encap %s in filetype %s",
                   wtap_encap_short_string(encap),
                   wtap_file_type_string(filetype));
        return 0;
    }
    
    d = wtap_dump_open(filename, filetype, encap, 0 , FALSE, &err);

    if (! d ) {
        luaL_error(L,"error while opening `%s': %s",
                   filename,
                   wtap_strerror(err));
        return 0;
    }
    
    pushDumper(L,d);
    return 1;
    
}

static int Dumper_dump_current(lua_State* L) {
    Dumper d = checkDumper(L,1);
    struct wtap_pkthdr pkthdr;
    const guchar* data;
    tvbuff_t* data_src;
    int err = 0;
    
    if (!d) return 0;
    
    if (! lua_pinfo ) {
        luaL_error(L,"dump_current cannot be used outside a tap or a dissector");
        return 0;
    }

    data_src = ((data_source*)(lua_pinfo->data_src->data))->tvb;

    pkthdr.ts.secs = lua_pinfo->fd->abs_ts.secs;
    pkthdr.ts.nsecs = lua_pinfo->fd->abs_ts.nsecs;
    pkthdr.len  = tvb_reported_length(data_src);
    pkthdr.caplen  = tvb_length(data_src);    
    pkthdr.pkt_encap = lua_pinfo->fd->lnk_t;

    data = ep_tvb_memdup(data_src,0,pkthdr.caplen);
    
    if (! wtap_dump(d, &pkthdr, lua_pinfo->pseudo_header, data, &err)) {
        luaL_error(L,"error while dumping: %s",
                   wtap_strerror(err));        
    }

    return 0;
}

static const luaL_reg Dumper_methods[] = 
{
    {"new",       Dumper_new},
    {"new_for_current",       Dumper_new_for_current},
    {"close",       Dumper_close},
    {"flush",       Dumper_flush},
    {"dump",       Dumper_dump},
    {"dump_current",       Dumper_dump_current},
    {0, 0}
};

static const luaL_reg Dumper_meta[] = 
{
    {0, 0}
};

int Dumper_register(lua_State* L) {
    dumper_encaps = g_hash_table_new(g_direct_hash,g_direct_equal);
    REGISTER_FULL_CLASS(DUMPER, Dumper_methods, Dumper_meta)
    return 1;
}
