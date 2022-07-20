/*
 *  wslua_dumper.c
 *
 * Wireshark's interface to the Lua Programming Language
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wiretap/wtap_opttypes.h>
#include <epan/wmem_scopes.h>

/* WSLUA_MODULE Dumper Saving Capture Files

   The classes/functions defined in this module are for using a `Dumper` object to
   make Wireshark save a capture file to disk. `Dumper` represents Wireshark's built-in
   file format writers (see the `wtap_name_to_file_type_subtype` function).

   (The `wtap_filetypes` table in `init.lua` is deprecated, and should
   only be used in code that must run on Wireshark 3.4.3 and earlier 3.4
   releases or in Wireshark 3.2.11 and earlier 3.2.x releases.)

   To have a Lua script create its own file format writer, see the chapter titled
   "Custom file format reading/writing".
*/

#include "wslua.h"
#include <math.h>

WSLUA_CLASS_DEFINE(PseudoHeader,NOP);
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
    PseudoHeader ph = (PseudoHeader)g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_NONE;
    ph->wph = NULL;

    pushPseudoHeader(L,ph);

    WSLUA_RETURN(1);
    /* A null pseudoheader */
}

WSLUA_CONSTRUCTOR PseudoHeader_eth(lua_State* L) {
    /*
     Creates an ethernet pseudoheader.
     */

#define WSLUA_OPTARG_PseudoHeader_eth_FCSLEN 1 /* The fcs length */

    PseudoHeader ph = (PseudoHeader)g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_ETH;
    ph->wph = (union wtap_pseudo_header *)g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->eth.fcs_len = (gint)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_eth_FCSLEN,-1);

    pushPseudoHeader(L,ph);

    WSLUA_RETURN(1); /* The ethernet pseudoheader */
}

WSLUA_CONSTRUCTOR PseudoHeader_atm(lua_State* L) {
    /*
     Creates an ATM pseudoheader.
     */
#define WSLUA_OPTARG_PseudoHeader_atm_AAL 1 /* AAL number */
#define WSLUA_OPTARG_PseudoHeader_atm_VPI 2 /* VPI */
#define WSLUA_OPTARG_PseudoHeader_atm_VCI 3 /* VCI */
#define WSLUA_OPTARG_PseudoHeader_atm_CHANNEL 4 /* Channel */
#define WSLUA_OPTARG_PseudoHeader_atm_CELLS 5 /* Number of cells in the PDU */
#define WSLUA_OPTARG_PseudoHeader_atm_AAL5U2U 6 /* AAL5 User to User indicator */
#define WSLUA_OPTARG_PseudoHeader_atm_AAL5LEN 7 /* AAL5 Len */

    PseudoHeader ph = (PseudoHeader)g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_ATM;
    ph->wph = (union wtap_pseudo_header *)g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->atm.aal = (guint8)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_AAL,5);
    ph->wph->atm.vpi = (guint16)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_VPI,1);
    ph->wph->atm.vci = (guint16)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_VCI,1);
    ph->wph->atm.channel = (guint16)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_CHANNEL,0);
    ph->wph->atm.cells = (guint16)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_CELLS,1);
    ph->wph->atm.aal5t_u2u = (guint16)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_AAL5U2U,1);
    ph->wph->atm.aal5t_len = (guint16)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_AAL5LEN,0);

    pushPseudoHeader(L,ph);
    WSLUA_RETURN(1);
    /* The ATM pseudoheader */
}

WSLUA_CONSTRUCTOR PseudoHeader_mtp2(lua_State* L) {
    /* Creates an MTP2 PseudoHeader. */
#define WSLUA_OPTARG_PseudoHeader_mtp2_SENT 1 /* True if the packet is sent, False if received. */
#define WSLUA_OPTARG_PseudoHeader_mtp2_ANNEXA 2 /* True if annex A is used.  */
#define WSLUA_OPTARG_PseudoHeader_mtp2_LINKNUM 3 /* Link Number. */
    PseudoHeader ph = (PseudoHeader)g_malloc(sizeof(struct lua_pseudo_header));
    ph->type = PHDR_MTP2;
    ph->wph = (union wtap_pseudo_header *)g_malloc(sizeof(union wtap_pseudo_header));
    ph->wph->mtp2.sent = (guint8)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_mtp2_SENT,0);
    ph->wph->mtp2.annex_a_used = (guint8)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_mtp2_ANNEXA,0);
    ph->wph->mtp2.link_number = (guint16)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_mtp2_LINKNUM,0);

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

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int PseudoHeader__gc(lua_State* L _U_) {
    /* do NOT free PseudoHeader */
    return 0;
}

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


WSLUA_CLASS_DEFINE(Dumper,FAIL_ON_NULL("Dumper already closed"));

static GHashTable* dumper_encaps = NULL;
#define DUMPER_ENCAP(d) GPOINTER_TO_INT(g_hash_table_lookup(dumper_encaps,d))

static const char* cross_plat_fname(const char* fname) {
    static char fname_clean[256];
    char* f;

    (void) g_strlcpy(fname_clean,fname,255);
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
     `Dumper:new_for_current()` will probably be a better choice.
    */
#define WSLUA_ARG_Dumper_new_FILENAME 1 /* The name of the capture file to be created. */
#define WSLUA_OPTARG_Dumper_new_FILETYPE 2 /* The type of the file to be created - a number returned by `wtap_name_to_file_type_subtype()`.
                                              (The `wtap_filetypes` table in `init.lua`
                                              is deprecated, and should only be used
                                              in code that must run on Wireshark 3.4.3 and earlier 3.4 releases
                                              or in Wireshark 3.2.11 and earlier
                                              3.2.x releases.) */
#define WSLUA_OPTARG_Dumper_new_ENCAP 3 /* The encapsulation to be used in the file to be created - a number entry from the `wtap_encaps` table in `init.lua`. */
    Dumper d;
    const char* fname = luaL_checkstring(L,WSLUA_ARG_Dumper_new_FILENAME);
    int filetype = (int)luaL_optinteger(L,WSLUA_OPTARG_Dumper_new_FILETYPE,wtap_pcap_file_type_subtype());
    int encap  = (int)luaL_optinteger(L,WSLUA_OPTARG_Dumper_new_ENCAP,WTAP_ENCAP_ETHERNET);
    int err = 0;
    gchar *err_info = NULL;
    const char* filename = cross_plat_fname(fname);
    wtap_dump_params params = WTAP_DUMP_PARAMS_INIT;

    params.encap = encap;
    d = wtap_dump_open(filename, filetype, WTAP_UNCOMPRESSED, &params, &err,
                       &err_info);

    if (! d ) {
        /* WSLUA_ERROR("Error while opening file for writing"); */
        switch (err) {
        case WTAP_ERR_NOT_REGULAR_FILE:
            luaL_error(L,"The file \"%s\" is a \"special file\" or socket or other non-regular file",
                       filename);
            break;

        case WTAP_ERR_CANT_WRITE_TO_PIPE:
            luaL_error(L,"The file \"%s\" is a pipe, and %s capture files can't be written to a pipe",
                       filename, wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_UNWRITABLE_FILE_TYPE:
            luaL_error(L,"Files of file type %s cannot be written",
                       wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_UNWRITABLE_ENCAP:
            luaL_error(L,"Files of file type %s don't support encapsulation %s",
                       wtap_file_type_subtype_description(filetype),
                       wtap_encap_name(encap));
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            luaL_error(L,"Files of file type %s don't support per-packet encapsulation",
                       wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_CANT_OPEN:
            luaL_error(L,"The file \"%s\" could not be created for some unknown reason",
                       filename);
            break;

        case WTAP_ERR_SHORT_WRITE:
            luaL_error(L,"A full header couldn't be written to the file \"%s\".",
                       filename);
            break;

        case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
            luaL_error(L,"Files of file type %s cannot be written as a compressed file",
                       wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_INTERNAL:
             luaL_error(L,"An internal error occurred creating the file \"%s\" (%s)",
                        filename,
                        err_info != NULL ? err_info : "no information supplied");
             g_free(err_info);
             break;

        default:
            luaL_error(L,"error while opening \"%s\": %s",
                       filename,
                       wtap_strerror(err));
            break;
        }
        return 0;
    }

    g_hash_table_insert(dumper_encaps,d,GINT_TO_POINTER(encap));

    pushDumper(L,d);
    WSLUA_RETURN(1);
    /* The newly created Dumper object */
}

WSLUA_METHOD Dumper_close(lua_State* L) {
    /* Closes a dumper. */
    Dumper* dp = (Dumper*)luaL_checkudata(L, 1, "Dumper");
    int err;
    gchar *err_info;

    if (! *dp) {
        WSLUA_ERROR(Dumper_close,"Cannot operate on a closed dumper");
        return 0;
    }

    g_hash_table_remove(dumper_encaps,*dp);

    if (!wtap_dump_close(*dp, NULL, &err, &err_info)) {
        if (err_info != NULL) {
            luaL_error(L,"error closing: %s (%s)",
                       wtap_strerror(err), err_info);
            g_free(err_info);
        } else {
            luaL_error(L,"error closing: %s",
                       wtap_strerror(err));
        }
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
    int err;

    if (!d) return 0;

    if (!wtap_dump_flush(d, &err)) {
        luaL_error(L,"error while dumping: %s",
                   wtap_strerror(err));
    }

    return 0;
}

WSLUA_METHOD Dumper_dump(lua_State* L) {
    /*
     Dumps an arbitrary packet.
     Note: Dumper:dump_current() will fit best in most cases.
     */
#define WSLUA_ARG_Dumper_dump_TIMESTAMP 2 /* The absolute timestamp the packet will have. */
#define WSLUA_ARG_Dumper_dump_PSEUDOHEADER 3 /* The `PseudoHeader` to use. */
#define WSLUA_ARG_Dumper_dump_BYTEARRAY 4 /* The data to be saved */

    Dumper d = checkDumper(L,1);
    PseudoHeader ph;
    ByteArray ba;
    wtap_rec rec;
    double ts;
    int err;
    gchar *err_info;

    if (!d) return 0;

    ts = luaL_checknumber(L,WSLUA_ARG_Dumper_dump_TIMESTAMP);
    ph = checkPseudoHeader(L,WSLUA_ARG_Dumper_dump_PSEUDOHEADER);

    if (!ph) {
        WSLUA_ARG_ERROR(Dumper_dump,PSEUDOHEADER,"need a PseudoHeader");
        return 0;
    }

    ba = checkByteArray(L,WSLUA_ARG_Dumper_dump_BYTEARRAY);

    if (! ba) {
        WSLUA_ARG_ERROR(Dumper_dump,BYTEARRAY,"must be a ByteArray");
        return 0;
    }

    memset(&rec, 0, sizeof rec);

    rec.rec_type = REC_TYPE_PACKET;

    rec.presence_flags = WTAP_HAS_TS;
    rec.ts.secs  = (unsigned int)(floor(ts));
    rec.ts.nsecs = (unsigned int)(floor((ts - (double)rec.ts.secs) * 1000000000));

    rec.rec_header.packet_header.len       = ba->len;
    rec.rec_header.packet_header.caplen    = ba->len;
    rec.rec_header.packet_header.pkt_encap = DUMPER_ENCAP(d);
    if (ph->wph) {
        rec.rec_header.packet_header.pseudo_header = *ph->wph;
    }

    /* TODO: Can we get access to pinfo->rec->block here somehow? We
     * should be copying it to pkthdr.pkt_block if we can. */

    if (! wtap_dump(d, &rec, ba->data, &err, &err_info)) {
        switch (err) {

        case WTAP_ERR_UNWRITABLE_REC_DATA:
            luaL_error(L,"error while dumping: %s (%s)",
                       wtap_strerror(err), err_info);
            g_free(err_info);
            break;

        default:
            luaL_error(L,"error while dumping: %s",
                       wtap_strerror(err));
            break;
        }
    }

    return 0;

}

WSLUA_METHOD Dumper_new_for_current(lua_State* L) {
    /*
     Creates a capture file using the same encapsulation as the one of the current packet.
     */
#define WSLUA_OPTARG_Dumper_new_for_current_FILETYPE 2 /* The file type. Defaults to pcap. */
    Dumper d;
    const char* fname = luaL_checkstring(L,1);
    int filetype = (int)luaL_optinteger(L,WSLUA_OPTARG_Dumper_new_for_current_FILETYPE,wtap_pcap_file_type_subtype());
    int encap;
    int err = 0;
    gchar *err_info = NULL;
    const char* filename = cross_plat_fname(fname);
    wtap_dump_params params = WTAP_DUMP_PARAMS_INIT;

    if (! lua_pinfo ) {
        WSLUA_ERROR(Dumper_new_for_current,"Cannot be used outside a tap or a dissector");
        return 0;
    }

    if (lua_pinfo->rec->rec_type != REC_TYPE_PACKET) {
        return 0;
    }

    encap = lua_pinfo->rec->rec_header.packet_header.pkt_encap;
    params.encap = encap;
    d = wtap_dump_open(filename, filetype, WTAP_UNCOMPRESSED, &params, &err,
                       &err_info);

    if (! d ) {
        switch (err) {
        case WTAP_ERR_NOT_REGULAR_FILE:
            luaL_error(L,"The file \"%s\" is a \"special file\" or socket or other non-regular file",
                       filename);
            break;

        case WTAP_ERR_CANT_WRITE_TO_PIPE:
            luaL_error(L,"The file \"%s\" is a pipe, and %s capture files can't be written to a pipe",
                       filename, wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_UNWRITABLE_FILE_TYPE:
            luaL_error(L,"Files of file type %s cannot be written",
                       wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_UNWRITABLE_ENCAP:
            luaL_error(L,"Files of file type %s don't support encapsulation %s",
                       wtap_file_type_subtype_description(filetype),
                       wtap_encap_name(encap));
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            luaL_error(L,"Files of file type %s don't support per-packet encapsulation",
                       wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_CANT_OPEN:
            luaL_error(L,"The file \"%s\" could not be created for some unknown reason",
                       filename);
            break;

        case WTAP_ERR_SHORT_WRITE:
            luaL_error(L,"A full header couldn't be written to the file \"%s\".",
                       filename);
            break;

        case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
            luaL_error(L,"Files of file type %s cannot be written as a compressed file",
                       wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_INTERNAL:
             luaL_error(L,"An internal error occurred creating the file \"%s\" (%s)",
                        filename,
                        err_info != NULL ? err_info : "no information supplied");
             g_free(err_info);
             break;

        default:
            luaL_error(L,"error while opening \"%s\": %s",
                       filename,
                       wtap_strerror(err));
            break;
        }
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
    wtap_rec rec;
    const guchar* data;
    tvbuff_t* tvb;
    struct data_source *data_src;
    int err = 0;
    gchar *err_info;

    if (!d) return 0;

    if (! lua_pinfo ) {
        WSLUA_ERROR(Dumper_new_for_current,"Cannot be used outside a tap or a dissector");
        return 0;
    }

    if (lua_pinfo->rec->rec_type != REC_TYPE_PACKET) {
        return 0;
    }

    data_src = (struct data_source*) (lua_pinfo->data_src->data);
    if (!data_src)
        return 0;

    tvb = get_data_source_tvb(data_src);

    memset(&rec, 0, sizeof rec);

    rec.rec_type                           = REC_TYPE_PACKET;
    rec.presence_flags                     = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    rec.ts                                 = lua_pinfo->abs_ts;
    rec.rec_header.packet_header.len       = tvb_reported_length(tvb);
    rec.rec_header.packet_header.caplen    = tvb_captured_length(tvb);
    rec.rec_header.packet_header.pkt_encap = lua_pinfo->rec->rec_header.packet_header.pkt_encap;
    rec.rec_header.packet_header.pseudo_header = *lua_pinfo->pseudo_header;

    /*
     * wtap_dump does not modify rec.block, so it should be possible to
     * pass epan_get_modified_block() or lua_pinfo->rec->block directly.
     * Temporarily duplicating the memory should not hurt though.
     */
    if (lua_pinfo->fd->has_modified_block) {
        rec.block = epan_get_modified_block(lua_pinfo->epan, lua_pinfo->fd);
        rec.block_was_modified = TRUE;
    } else {
        rec.block = lua_pinfo->rec->block;
    }

    data = (const guchar *)tvb_memdup(lua_pinfo->pool,tvb,0,rec.rec_header.packet_header.caplen);

    if (! wtap_dump(d, &rec, data, &err, &err_info)) {
        switch (err) {

        case WTAP_ERR_UNWRITABLE_REC_DATA:
            luaL_error(L,"error while dumping: %s (%s)",
                       wtap_strerror(err), err_info);
            g_free(err_info);
            break;

        default:
            luaL_error(L,"error while dumping: %s",
                       wtap_strerror(err));
            break;
        }
    }

    return 0;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Dumper__gc(lua_State* L) {
    Dumper* dp = (Dumper*)luaL_checkudata(L, 1, "Dumper");
    int err;
    gchar *err_info;

    /* If we are Garbage Collected it means the Dumper is no longer usable. Close it */

    if (! *dp)
        return 0; /* already closed, nothing to do! */

    g_hash_table_remove(dumper_encaps,*dp);

    if (!wtap_dump_close(*dp, NULL, &err, &err_info)) {
        if (err_info != NULL) {
            luaL_error(L,"error closing: %s (%s)",
                       wtap_strerror(err), err_info);
            g_free(err_info);
        } else {
            luaL_error(L,"error closing: %s",
                       wtap_strerror(err));
        }
    }

    return 0;
}


WSLUA_METHODS Dumper_methods[] = {
    WSLUA_CLASS_FNREG(Dumper,new),
    WSLUA_CLASS_FNREG(Dumper,new_for_current),
    WSLUA_CLASS_FNREG(Dumper,close),
    WSLUA_CLASS_FNREG(Dumper,flush),
    WSLUA_CLASS_FNREG(Dumper,dump),
    WSLUA_CLASS_FNREG(Dumper,dump_current),
    { NULL, NULL }
};

WSLUA_META Dumper_meta[] = {
    { NULL, NULL }
};

int Dumper_register(lua_State* L) {
    dumper_encaps = g_hash_table_new(g_direct_hash,g_direct_equal);
    WSLUA_REGISTER_CLASS(Dumper);
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
