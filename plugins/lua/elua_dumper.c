/*
 *  lua_dumper.c
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
#include <math.h>

ELUA_CLASS_DEFINE(PseudoHeader,NOP)
/*
 A pseudoheader to be used to save captured frames.
 */ 

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

ELUA_CONSTRUCTOR PseudoHeader_none(lua_State* L) {
	/*
	 Creates a "no" pseudoheader.
	
	*/
    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_NONE;
    ph->wph = NULL;
    
    pushPseudoHeader(L,ph);
	
    ELUA_RETURN(1);
	/* A null pseudoheader */
}

ELUA_CONSTRUCTOR PseudoHeader_eth(lua_State* L) {
	/*
	 Creates an ethernet pseudoheader
	 */

#define ELUA_OPTARG_PseudoHeader_eth_FCSLEN 1 /* the fcs lenght */
	
    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_ETH;
    ph->wph = g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->eth.fcs_len = luaL_optint(L,1,-1);
    
    pushPseudoHeader(L,ph);
	
	ELUA_RETURN(1); /* The ethernet pseudoheader */
}

ELUA_CONSTRUCTOR PseudoHeader_atm(lua_State* L) {
	/*
	 Creates an ATM pseudoheader
	 */
#define ELUA_OPTARG_PseudoHeader_atm_AAL 1 /* AAL number */
#define ELUA_OPTARG_PseudoHeader_atm_VPI 2 /* VPI */
#define ELUA_OPTARG_PseudoHeader_atm_VCI 3 /* VCI */
#define ELUA_OPTARG_PseudoHeader_atm_CHANNEL 4 /* Channel */
#define ELUA_OPTARG_PseudoHeader_atm_CELLS 5 /* Number of cells in the PDU */
#define ELUA_OPTARG_PseudoHeader_atm_AAL5U2U 6 /* AAL5 User to User indicator */
#define ELUA_OPTARG_PseudoHeader_atm_AAL5LEN 7 /* AAL5 Len */

    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_ATM;
    ph->wph = g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->atm.aal = luaL_optint(L,ELUA_OPTARG_PseudoHeader_atm_AAL,5);
    ph->wph->atm.vpi = luaL_optint(L,ELUA_OPTARG_PseudoHeader_atm_VPI,1);
    ph->wph->atm.vci = luaL_optint(L,ELUA_OPTARG_PseudoHeader_atm_VCI,1);
    ph->wph->atm.channel = luaL_optint(L,ELUA_OPTARG_PseudoHeader_atm_CHANNEL,0);
    ph->wph->atm.cells = luaL_optint(L,ELUA_OPTARG_PseudoHeader_atm_CELLS,1);
    ph->wph->atm.aal5t_u2u = luaL_optint(L,ELUA_OPTARG_PseudoHeader_atm_AAL5U2U,1);
    ph->wph->atm.aal5t_len = luaL_optint(L,ELUA_OPTARG_PseudoHeader_atm_AAL5LEN,0);
    
    pushPseudoHeader(L,ph);
	ELUA_RETURN(1);
	/* The ATM pseudoheader */
}

ELUA_CONSTRUCTOR PseudoHeader_mtp2(lua_State* L) {
	/* Creates an MTP2 PseudoHeader */
#define ELUA_OPTARG_PseudoHeader_mtp2_SENT /* True if the packet is sent, False if received. */
#define ELUA_OPTARG_PseudoHeader_mtp2_ANNEXA /* True if annex A is used  */
#define ELUA_OPTARG_PseudoHeader_mtp2_LINKNUM /* Link Number */
    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_MTP2;
    ph->wph = g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->mtp2.sent = luaL_optint(L,1,0);
    ph->wph->mtp2.annex_a_used = luaL_optint(L,2,0);
    ph->wph->mtp2.link_number = luaL_optint(L,3,0);

    pushPseudoHeader(L,ph);
	ELUA_RETURN(1); /* The MTP2 pseudoheader */
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

ELUA_METHODS PseudoHeader_methods[] = {
	ELUA_CLASS_FNREG(PseudoHeader,mtp2),
	ELUA_CLASS_FNREG(PseudoHeader,atm),
	ELUA_CLASS_FNREG(PseudoHeader,eth),
	ELUA_CLASS_FNREG(PseudoHeader,none),
	{0,0}
};

ELUA_META PseudoHeader_meta[] = {
	{0,0}
};

int PseudoHeader_register(lua_State* L) {
	ELUA_REGISTER_CLASS(PseudoHeader)
    return 0;
}


ELUA_CLASS_DEFINE(Dumper,FAIL_ON_NULL("Dumper already closed"))

static GHashTable* dumper_encaps = NULL;
#define DUMPER_ENCAP(d) GPOINTER_TO_INT(g_hash_table_lookup(dumper_encaps,d))

ELUA_CONSTRUCTOR Dumper_new(lua_State* L) {
	/*
	 Creates a file to write packets.
	 Dumper:new_for_current() will probably be a better choice. 
	*/
#define ELUA_ARG_Dumper_new_FILENAME 1 /* The name of the capture file to be created */
#define ELUA_OPTARG_Dumper_new_FILETYPE 3 /* The type of the file to be created */
#define ELUA_OPTARG_Dumper_new_ENCAP 3 /* The encapsulation to be used in the file to be created */
    Dumper d;
    const char* filename = luaL_checkstring(L,1);
    int filetype = luaL_optint(L,2,WTAP_FILE_PCAP);
    int encap  = luaL_optint(L,3,WTAP_ENCAP_ETHERNET);
    int err = 0;
    
    if (! filename) return 0;
    
    if (!wtap_dump_can_write_encap(filetype, encap))
        ELUA_ERROR(Dumper_new,"not every filetype handles every encap");
    
    d = wtap_dump_open(filename, filetype, encap,0 , FALSE, &err);
    
    if (! d ) {
		/* ELUA_ERROR("error while opening file for writing"); */
        luaL_error(L,"error while opening `%s': %s",
                   filename,
                   wtap_strerror(err));
        return 0;
    }
    
    g_hash_table_insert(dumper_encaps,d,GINT_TO_POINTER(encap));
    
    pushDumper(L,d);
    ELUA_RETURN(1);
	/* The newly created Dumper object */
}

ELUA_METHOD Dumper_close(lua_State* L) {
	/* Closes a dumper */
	Dumper* dp = (Dumper*)luaL_checkudata(L, 1, "Dumper");
    int err;
    
    if (! *dp)
		ELUA_ERROR(Dumper_close,"Cannot operate on a closed dumper");

    g_hash_table_remove(dumper_encaps,*dp);

    if (!wtap_dump_close(*dp, &err)) {
        luaL_error(L,"error closing: %s",
                   wtap_strerror(err));
    }

	/* this way if we close a dumper any attempt to use it (for everything but GC) will yield an error */
	dp = NULL;

    return 0;
}

ELUA_METHOD Dumper_flush(lua_State* L) {
	/*
	 Writes all unsaved data of a dumper to the disk.
	 */
    Dumper d = checkDumper(L,1);

    if (!d) return 0;
    
    wtap_dump_flush(d);
    
    return 0;
}

ELUA_METHOD Dumper_dump(lua_State* L) {
	/*
	 Dumps an arbitrary packet.
	 Note: Dumper:dump_current() will fit best in most cases.
	 */
#define ELUA_ARG_Dumper_dump_TIMESTAMP 2 /* The absolute timestamp the packet will have */
#define ELUA_ARG_Dumper_dump_PSEUDOHEADER 3 /* The Pseudoheader to use. */
#define ELUA_ARG_Dumper_dump_BYTEARRAY 4 /* the data to be saved */

	Dumper d = checkDumper(L,1);
    PseudoHeader ph;
    ByteArray ba;
    struct wtap_pkthdr pkthdr;
    double ts;
    int err;
    
    if (!d) return 0;
    
    ts = luaL_checknumber(L,ELUA_ARG_Dumper_dump_TIMESTAMP);
    ph = checkPseudoHeader(L,ELUA_ARG_Dumper_dump_PSEUDOHEADER);
    
    if (!ph) ELUA_ARG_ERROR(Dumper_dump,TIMESTAMP,"need a PseudoHeader");
    
    ba = checkByteArray(L,ELUA_ARG_Dumper_dump_BYTEARRAY);
    
	if (! ba) ELUA_ARG_ERROR(Dumper_dump,BYTEARRAY,"must be a ByteArray");
    
    pkthdr.ts.secs = (int)floor(ts);
    pkthdr.ts.nsecs = (int)floor(ts - pkthdr.ts.secs) * 1000000000;
    pkthdr.len  = ba->len;
    pkthdr.caplen  = ba->len;    
    pkthdr.pkt_encap = DUMPER_ENCAP(d);
    
    if (! wtap_dump(d, &pkthdr, ph->wph, ba->data, &err)) {
        luaL_error(L,"error while dumping: %s",
                   wtap_strerror(err));        
    }
    
    return 0;
    
}

ELUA_METHOD Dumper_new_for_current(lua_State* L) {
	/*
	 Creates a capture file using the same encapsulation as the one of the cuurrent packet
	 */
#define ELUA_OPTARG_Dumper_new_for_current_FILETYPE 2 /* The file type. Defaults to pcap. */
	Dumper d;
    const char* filename = luaL_checkstring(L,1);
    int filetype = luaL_optint(L,2,WTAP_FILE_PCAP);
    int encap;
    int err = 0;
    
    if (! lua_pinfo )
		ELUA_ERROR(Dumper_new_for_current,"cannot be used outside a tap or a dissector");
    
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
    ELUA_RETURN(1); /* The newly created Dumper Object */
    
}

ELUA_METHOD Dumper_dump_current(lua_State* L) {
	/*
	 Dumps the current packet as it is.
	 */
    Dumper d = checkDumper(L,1);
    struct wtap_pkthdr pkthdr;
    const guchar* data;
    tvbuff_t* data_src;
    int err = 0;
    
    if (!d) return 0;
    
	if (! lua_pinfo ) ELUA_ERROR(Dumper_new_for_current,"cannot be used outside a tap or a dissector");

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

static int Dumper__gc(lua_State* L) {
	Dumper* dp = (Dumper*)luaL_checkudata(L, 1, "Dumper");
	int err;

	/* If we are Garbage Collected it means the Dumper is no longer usable. Close it */ 
	
	if (! *dp)
		return 0; /* already closed, nothing to do! */

	g_hash_table_remove(dumper_encaps,*dp);

	if (!wtap_dump_close(*dp, &err)) {
		luaL_error(L,"error closing: %s",
				   wtap_strerror(err));
	}

	return 0;
}


ELUA_METHODS Dumper_methods[] = {
    {"new",       Dumper_new},
    {"new_for_current",       Dumper_new_for_current},
    {"close",       Dumper_close},
    {"flush",       Dumper_flush},
    {"dump",       Dumper_dump},
    {"dump_current",       Dumper_dump_current},
    {0, 0}
};

ELUA_META Dumper_meta[] = {
	{"__gc", Dumper__gc},
    {0, 0}
};

int Dumper_register(lua_State* L) {
    dumper_encaps = g_hash_table_new(g_direct_hash,g_direct_equal);
    ELUA_REGISTER_CLASS(Dumper);
    return 1;
}

