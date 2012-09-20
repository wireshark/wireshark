/*
 *  wslua_dumper.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

/* WSLUA_MODULE Dumper Saving capture files */

#include "wslua.h"
#include <math.h>

WSLUA_CLASS_DEFINE(PseudoHeader,NOP,NOP);
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

WSLUA_CONSTRUCTOR PseudoHeader_none(lua_State* L) {
    /*
     Creates a "no" pseudoheader.

    */
    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_NONE;
    ph->wph = NULL;

    pushPseudoHeader(L,ph);

    WSLUA_RETURN(1);
    /* A null pseudoheader */
}

WSLUA_CONSTRUCTOR PseudoHeader_eth(lua_State* L) {
    /*
     Creates an ethernet pseudoheader
     */

#define WSLUA_OPTARG_PseudoHeader_eth_FCSLEN 1 /* The fcs length */

    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_ETH;
    ph->wph = g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->eth.fcs_len = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_eth_FCSLEN,-1);

    pushPseudoHeader(L,ph);

    WSLUA_RETURN(1); /* The ethernet pseudoheader */
}

WSLUA_CONSTRUCTOR PseudoHeader_atm(lua_State* L) {
    /*
     Creates an ATM pseudoheader
     */
#define WSLUA_OPTARG_PseudoHeader_atm_AAL 1 /* AAL number */
#define WSLUA_OPTARG_PseudoHeader_atm_VPI 2 /* VPI */
#define WSLUA_OPTARG_PseudoHeader_atm_VCI 3 /* VCI */
#define WSLUA_OPTARG_PseudoHeader_atm_CHANNEL 4 /* Channel */
#define WSLUA_OPTARG_PseudoHeader_atm_CELLS 5 /* Number of cells in the PDU */
#define WSLUA_OPTARG_PseudoHeader_atm_AAL5U2U 6 /* AAL5 User to User indicator */
#define WSLUA_OPTARG_PseudoHeader_atm_AAL5LEN 7 /* AAL5 Len */

    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_ATM;
    ph->wph = g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->atm.aal = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_atm_AAL,5);
    ph->wph->atm.vpi = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_atm_VPI,1);
    ph->wph->atm.vci = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_atm_VCI,1);
    ph->wph->atm.channel = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_atm_CHANNEL,0);
    ph->wph->atm.cells = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_atm_CELLS,1);
    ph->wph->atm.aal5t_u2u = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_atm_AAL5U2U,1);
    ph->wph->atm.aal5t_len = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_atm_AAL5LEN,0);

    pushPseudoHeader(L,ph);
    WSLUA_RETURN(1);
    /* The ATM pseudoheader */
}

WSLUA_CONSTRUCTOR PseudoHeader_mtp2(lua_State* L) {
    /* Creates an MTP2 PseudoHeader */
#define WSLUA_OPTARG_PseudoHeader_mtp2_SENT 1 /* True if the packet is sent, False if received. */
#define WSLUA_OPTARG_PseudoHeader_mtp2_ANNEXA 2 /* True if annex A is used  */
#define WSLUA_OPTARG_PseudoHeader_mtp2_LINKNUM 3 /* Link Number */
    PseudoHeader ph = g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_MTP2;
    ph->wph = g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->mtp2.sent = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_mtp2_SENT,0);
    ph->wph->mtp2.annex_a_used = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_mtp2_ANNEXA,0);
    ph->wph->mtp2.link_number = luaL_optint(L,WSLUA_OPTARG_PseudoHeader_mtp2_LINKNUM,0);

    pushPseudoHeader(L,ph);
    WSLUA_RETURN(1); /* The MTP2 pseudoheader */
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

WSLUA_METHODS PseudoHeader_methods[] = {
    WSLUA_CLASS_FNREG(PseudoHeader,mtp2),
    WSLUA_CLASS_FNREG(PseudoHeader,atm),
    WSLUA_CLASS_FNREG(PseudoHeader,eth),
    WSLUA_CLASS_FNREG(PseudoHeader,none),
    {0,0}
};

WSLUA_META PseudoHeader_meta[] = {
    {0,0}
};

int PseudoHeader_register(lua_State* L) {
    WSLUA_REGISTER_CLASS(PseudoHeader)
    return 0;
}


WSLUA_CLASS_DEFINE(Dumper,FAIL_ON_NULL("Dumper already closed"),NOP);

static GHashTable* dumper_encaps = NULL;
#define DUMPER_ENCAP(d) GPOINTER_TO_INT(g_hash_table_lookup(dumper_encaps,d))

static const char* cross_plat_fname(const char* fname) {
    static char fname_clean[256];
    char* f;

    g_strlcpy(fname_clean,fname,255);
    fname_clean[255] = '\0';

    for(f = fname_clean; *f; f++) {
        switch(*f) {
            case '/': case '\\':
                *f = *(G_DIR_SEPARATOR_S);
                break;
            default:
                break;
        }
    }

    return fname_clean;
}

WSLUA_CONSTRUCTOR Dumper_new(lua_State* L) {
    /*
     Creates a file to write packets.
     Dumper:new_for_current() will probably be a better choice.
    */
#define WSLUA_ARG_Dumper_new_FILENAME 1 /* The name of the capture file to be created */
#define WSLUA_OPTARG_Dumper_new_FILETYPE 2 /* The type of the file to be created */
#define WSLUA_OPTARG_Dumper_new_ENCAP 3 /* The encapsulation to be used in the file to be created */
    Dumper d;
    const char* fname = luaL_checkstring(L,WSLUA_ARG_Dumper_new_FILENAME);
    int filetype = luaL_optint(L,WSLUA_OPTARG_Dumper_new_FILETYPE,WTAP_FILE_PCAP);
    int encap  = luaL_optint(L,WSLUA_OPTARG_Dumper_new_ENCAP,WTAP_ENCAP_ETHERNET);
    int err = 0;
    const char* filename;

    if (! fname) return 0;

    filename = cross_plat_fname(fname);

    if (!wtap_dump_can_write_encap(filetype, encap))
        WSLUA_ERROR(Dumper_new,"Not every filetype handles every encap");

    d = wtap_dump_open(filename, filetype, encap,0 , FALSE, &err);

    if (! d ) {
        /* WSLUA_ERROR("Error while opening file for writing"); */
        luaL_error(L,"error while opening `%s': %s",
                   filename,
                   wtap_strerror(err));
        return 0;
    }

    g_hash_table_insert(dumper_encaps,d,GINT_TO_POINTER(encap));

    pushDumper(L,d);
    WSLUA_RETURN(1);
    /* The newly created Dumper object */
}

WSLUA_METHOD Dumper_close(lua_State* L) {
    /* Closes a dumper */
    Dumper* dp = (Dumper*)luaL_checkudata(L, 1, "Dumper");
    int err;

    if (! *dp)
        WSLUA_ERROR(Dumper_close,"Cannot operate on a closed dumper");

    g_hash_table_remove(dumper_encaps,*dp);

    if (!wtap_dump_close(*dp, &err)) {
        luaL_error(L,"error closing: %s",
                   wtap_strerror(err));
    }

    /* this way if we close a dumper any attempt to use it (for everything but GC) will yield an error */
    *dp = NULL;

    return 0;
}

WSLUA_METHOD Dumper_flush(lua_State* L) {
    /*
     Writes all unsaved data of a dumper to the disk.
     */
    Dumper d = checkDumper(L,1);

    if (!d) return 0;

    wtap_dump_flush(d);

    return 0;
}

WSLUA_METHOD Dumper_dump(lua_State* L) {
    /*
     Dumps an arbitrary packet.
     Note: Dumper:dump_current() will fit best in most cases.
     */
#define WSLUA_ARG_Dumper_dump_TIMESTAMP 2 /* The absolute timestamp the packet will have */
#define WSLUA_ARG_Dumper_dump_PSEUDOHEADER 3 /* The Pseudoheader to use. */
#define WSLUA_ARG_Dumper_dump_BYTEARRAY 4 /* the data to be saved */

    Dumper d = checkDumper(L,1);
    PseudoHeader ph;
    ByteArray ba;
    struct wtap_pkthdr pkthdr;
    double ts;
    int err;

    if (!d) return 0;

    ts = luaL_checknumber(L,WSLUA_ARG_Dumper_dump_TIMESTAMP);
    ph = checkPseudoHeader(L,WSLUA_ARG_Dumper_dump_PSEUDOHEADER);

    if (!ph) WSLUA_ARG_ERROR(Dumper_dump,TIMESTAMP,"need a PseudoHeader");

    ba = checkByteArray(L,WSLUA_ARG_Dumper_dump_BYTEARRAY);

    if (! ba) WSLUA_ARG_ERROR(Dumper_dump,BYTEARRAY,"must be a ByteArray");

    memset(&pkthdr, 0, sizeof(pkthdr));

    pkthdr.ts.secs  = (unsigned)floor(ts);
    pkthdr.ts.nsecs = (unsigned)floor((ts - (double)pkthdr.ts.secs) * 1000000000);

    pkthdr.len       = ba->len;
    pkthdr.caplen    = ba->len;
    pkthdr.pkt_encap = DUMPER_ENCAP(d);

    /* TODO: Can we get access to pinfo->fd->opt_comment here somehow? We
     * should be copying it to pkthdr.opt_comment if we can. */

    if (! wtap_dump(d, &pkthdr, ph->wph, ba->data, &err)) {
        luaL_error(L,"error while dumping: %s",
                   wtap_strerror(err));
    }

    return 0;

}

WSLUA_METHOD Dumper_new_for_current(lua_State* L) {
    /*
     Creates a capture file using the same encapsulation as the one of the cuurrent packet
     */
#define WSLUA_OPTARG_Dumper_new_for_current_FILETYPE 2 /* The file type. Defaults to pcap. */
    Dumper d;
    const char* fname = luaL_checkstring(L,1);
    int filetype = luaL_optint(L,WSLUA_OPTARG_Dumper_new_for_current_FILETYPE,WTAP_FILE_PCAP);
    int encap;
    int err = 0;
    const char* filename;

    if (! fname) return 0;

    filename = cross_plat_fname(fname);

    if (! lua_pinfo )
        WSLUA_ERROR(Dumper_new_for_current,"Cannot be used outside a tap or a dissector");

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
    WSLUA_RETURN(1); /* The newly created Dumper Object */

}

WSLUA_METHOD Dumper_dump_current(lua_State* L) {
    /*
     Dumps the current packet as it is.
     */
    Dumper d = checkDumper(L,1);
    struct wtap_pkthdr pkthdr;
    const guchar* data;
    tvbuff_t* tvb;
    data_source *data_src;
    int err = 0;

    if (!d) return 0;

    if (! lua_pinfo ) WSLUA_ERROR(Dumper_new_for_current,"Cannot be used outside a tap or a dissector");

    data_src = (data_source*) (lua_pinfo->data_src->data);
    if (!data_src)
        return 0;

    tvb = data_src->tvb;

    memset(&pkthdr, 0, sizeof(pkthdr));

    pkthdr.ts.secs   = lua_pinfo->fd->abs_ts.secs;
    pkthdr.ts.nsecs  = lua_pinfo->fd->abs_ts.nsecs;
    pkthdr.len       = tvb_reported_length(tvb);
    pkthdr.caplen    = tvb_length(tvb);
    pkthdr.pkt_encap = lua_pinfo->fd->lnk_t;

    if (lua_pinfo->fd->opt_comment)
        pkthdr.opt_comment = ep_strdup(lua_pinfo->fd->opt_comment);

    data = ep_tvb_memdup(tvb,0,pkthdr.caplen);

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


WSLUA_METHODS Dumper_methods[] = {
    {"new",       Dumper_new},
    {"new_for_current",       Dumper_new_for_current},
    {"close",       Dumper_close},
    {"flush",       Dumper_flush},
    {"dump",       Dumper_dump},
    {"dump_current",       Dumper_dump_current},
    {0, 0}
};

WSLUA_META Dumper_meta[] = {
    {"__gc", Dumper__gc},
    {0, 0}
};

int Dumper_register(lua_State* L) {
    dumper_encaps = g_hash_table_new(g_direct_hash,g_direct_equal);
    WSLUA_REGISTER_CLASS(Dumper);
    return 1;
}

