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

   (The `wtap_filetypes` table is deprecated, and should
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
    ph->wph->eth.fcs_len = (int)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_eth_FCSLEN,-1);

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
    ph->wph->atm.aal = (uint8_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_AAL,5);
    ph->wph->atm.vpi = (uint16_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_VPI,1);
    ph->wph->atm.vci = (uint16_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_VCI,1);
    ph->wph->atm.channel = (uint16_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_CHANNEL,0);
    ph->wph->atm.cells = (uint16_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_CELLS,1);
    ph->wph->atm.aal5t_u2u = (uint16_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_AAL5U2U,1);
    ph->wph->atm.aal5t_len = (uint16_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_atm_AAL5LEN,0);

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
    ph->wph->mtp2.sent = (uint8_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_mtp2_SENT,0);
    ph->wph->mtp2.annex_a_used = (uint8_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_mtp2_ANNEXA,0);
    ph->wph->mtp2.link_number = (uint16_t)luaL_optinteger(L,WSLUA_OPTARG_PseudoHeader_mtp2_LINKNUM,0);

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

/* Short, stable names for the lua_pseudoheader_type enum. Indexed by enum
 * value so PseudoHeader.type_name stays aligned with PseudoHeader.type. */
static const char *pseudoheader_type_name(enum lua_pseudoheader_type t) {
    switch (t) {
        case PHDR_NONE:   return "none";
        case PHDR_ETH:    return "eth";
        case PHDR_X25:    return "x25";
        case PHDR_ISDN:   return "isdn";
        case PHDR_ATM:    return "atm";
        case PHDR_ASCEND: return "ascend";
        case PHDR_P2P:    return "p2p";
        case PHDR_WIFI:   return "wifi";
        case PHDR_COSINE: return "cosine";
        case PHDR_IRDA:   return "irda";
        case PHDR_NETTL:  return "nettl";
        case PHDR_MTP2:   return "mtp2";
        case PHDR_K12:    return "k12";
        default:          return "unknown";
    }
}

/* Keys exposed by __pairs for a given variant. Kept NULL-terminated so
 * the iterator can walk them without a size argument. Only variants
 * that Lua can actually construct need entries; anything else resolves
 * to an empty list (type only). */
static const char *pseudoheader_keys_for(enum lua_pseudoheader_type t) {
    /* NOLINTBEGIN - Return an opaque list; the iterator knows the
     * termination sentinel. */
    static const char *none_keys[] = { NULL };
    static const char *eth_keys[]  = { "fcs_len", NULL };
    static const char *atm_keys[]  = {
        "aal", "vpi", "vci", "channel", "cells",
        "aal5t_u2u", "aal5t_len", NULL
    };
    static const char *mtp2_keys[] = {
        "sent", "annex_a_used", "link_number", NULL
    };
    /* NOLINTEND */
    switch (t) {
        case PHDR_ETH:  return (const char *)eth_keys;
        case PHDR_ATM:  return (const char *)atm_keys;
        case PHDR_MTP2: return (const char *)mtp2_keys;
        case PHDR_NONE:
        default:        return (const char *)none_keys;
    }
}

/* Push a variant-specific field as a Lua value, mirroring the field
 * layout used by the constructors. Returns false if the key is not
 * valid for this variant. */
static bool pseudoheader_push_value(lua_State *L, PseudoHeader ph,
                                    const char *key) {
    if (!ph || !ph->wph || !key) return false;
    switch (ph->type) {
        case PHDR_ETH:
            if (g_strcmp0(key, "fcs_len") == 0) {
                lua_pushinteger(L, ph->wph->eth.fcs_len);
                return true;
            }
            break;
        case PHDR_ATM:
            if (g_strcmp0(key, "aal") == 0) {
                lua_pushinteger(L, ph->wph->atm.aal); return true;
            }
            if (g_strcmp0(key, "vpi") == 0) {
                lua_pushinteger(L, ph->wph->atm.vpi); return true;
            }
            if (g_strcmp0(key, "vci") == 0) {
                lua_pushinteger(L, ph->wph->atm.vci); return true;
            }
            if (g_strcmp0(key, "channel") == 0) {
                lua_pushinteger(L, ph->wph->atm.channel); return true;
            }
            if (g_strcmp0(key, "cells") == 0) {
                lua_pushinteger(L, ph->wph->atm.cells); return true;
            }
            if (g_strcmp0(key, "aal5t_u2u") == 0) {
                lua_pushinteger(L, ph->wph->atm.aal5t_u2u); return true;
            }
            if (g_strcmp0(key, "aal5t_len") == 0) {
                lua_pushinteger(L, ph->wph->atm.aal5t_len); return true;
            }
            break;
        case PHDR_MTP2:
            if (g_strcmp0(key, "sent") == 0) {
                lua_pushinteger(L, ph->wph->mtp2.sent); return true;
            }
            if (g_strcmp0(key, "annex_a_used") == 0) {
                lua_pushinteger(L, ph->wph->mtp2.annex_a_used); return true;
            }
            if (g_strcmp0(key, "link_number") == 0) {
                lua_pushinteger(L, ph->wph->mtp2.link_number); return true;
            }
            break;
        default:
            break;
    }
    return false;
}

/* Read-only attributes exposing the discriminant. */

/* WSLUA_ATTRIBUTE PseudoHeader_type RO The pseudoheader variant as the
   internal lua_pseudoheader_type enum value (integer). Use
   `PseudoHeader.type_name` for the short string form ("none", "eth",
   "atm", ...). */
WSLUA_ATTRIBUTE_GET(PseudoHeader,type, {
    lua_pushinteger(L, obj ? (lua_Integer)obj->type : (lua_Integer)PHDR_NONE);
});

/* WSLUA_ATTRIBUTE PseudoHeader_type_name RO Short string identifying the
   variant: "none", "eth", "atm", "mtp2", etc. */
WSLUA_ATTRIBUTE_GET(PseudoHeader,type_name, {
    lua_pushstring(L,
        pseudoheader_type_name(obj ? obj->type : PHDR_NONE));
});

/* __tostring returns a compact tag so the debugger/print show what kind
 * of pseudoheader this is without dumping the full variant struct.
 * Shape matches the shared convention: `Class: key=value` pairs. */
static int PseudoHeader__tostring(lua_State *L) {
    PseudoHeader ph = checkPseudoHeader(L, 1);
    lua_pushfstring(L, "PseudoHeader: type=%s",
                    pseudoheader_type_name(ph ? ph->type : PHDR_NONE));
    return 1;
}

/* Stateless __pairs iterator. Uses the variant's key list as the walk
 * order and the provided `prev` key for resume. Only non-nil
 * variant-specific fields are yielded. */
static int PseudoHeader_pairs_iter(lua_State *L) {
    PseudoHeader ph = checkPseudoHeader(L, 1);
    const char *prev = lua_isnoneornil(L, 2) ? NULL : luaL_checkstring(L, 2);
    if (!ph) { lua_pushnil(L); return 1; }

    const char **keys = (const char **)pseudoheader_keys_for(ph->type);
    /* Skip past prev, if any. */
    const char **p = keys;
    if (prev) {
        while (*p && g_strcmp0(*p, prev) != 0) ++p;
        if (*p) ++p;   /* move to the next key */
    }
    if (!*p) { lua_pushnil(L); return 1; }

    lua_pushstring(L, *p);
    if (!pseudoheader_push_value(L, ph, *p)) {
        lua_pushnil(L);
    }
    return 2;
}

WSLUA_METAMETHOD PseudoHeader__pairs(lua_State *L) {
    /*
    Iterate over the variant-specific fields of the pseudoheader (for
    example `fcs_len` on Ethernet pseudoheaders or `aal`/`vpi`/`vci`
    on ATM ones). Nothing is yielded for `PseudoHeader.none`.
    */
    WSLUA_STATELESS_PAIRS_BODY(PseudoHeader);
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int PseudoHeader__gc(lua_State* L _U_) {
    /* do NOT free PseudoHeader */
    return 0;
}

WSLUA_ATTRIBUTES PseudoHeader_attributes[] = {
    WSLUA_ATTRIBUTE_ROREG(PseudoHeader,type),
    WSLUA_ATTRIBUTE_ROREG(PseudoHeader,type_name),
    { NULL, NULL, NULL }
};

WSLUA_METHODS PseudoHeader_methods[] = {
    WSLUA_CLASS_FNREG(PseudoHeader,mtp2),
    WSLUA_CLASS_FNREG(PseudoHeader,atm),
    WSLUA_CLASS_FNREG(PseudoHeader,eth),
    WSLUA_CLASS_FNREG(PseudoHeader,none),
    {0,0}
};

WSLUA_META PseudoHeader_meta[] = {
    WSLUA_CLASS_MTREG(PseudoHeader,tostring),
    WSLUA_CLASS_MTREG(PseudoHeader,pairs),
    {0,0}
};

int PseudoHeader_register(lua_State* L) {
    WSLUA_REGISTER_CLASS_WITH_ATTRS(PseudoHeader);
    return 0;
}


WSLUA_CLASS_DEFINE(Dumper,FAIL_ON_NULL("Dumper already closed"));

static GHashTable* dumper_encaps;
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
     `Dumper:new_for_current()` will probably be a better choice, especially for file types other than pcapng.
    */
#define WSLUA_ARG_Dumper_new_FILENAME 1 /* The name of the capture file to be created. */
#define WSLUA_OPTARG_Dumper_new_FILETYPE 2 /* The type of the file to be created - a number returned by `wtap_name_to_file_type_subtype()`. Defaults to pcapng.
                                              (The `wtap_filetypes` table
                                              is deprecated, and should only be used
                                              in code that must run on Wireshark 3.4.3 and earlier 3.4.x releases
                                              or in Wireshark 3.2.11 and earlier
                                              3.2.x releases.) */
#define WSLUA_OPTARG_Dumper_new_ENCAP 3 /* The encapsulation to be used in the file to be created - a number entry from the `wtap_encaps` table.
                                              Defaults to per-packet encapsulation for pcapng
                                              (which doesn't have file-level encapsulation;
                                              this will create IDBs on demand as necessary)
                                              and Ethernet encapsulation for other file types. */
    Dumper d;
    const char* fname = luaL_checkstring(L,WSLUA_ARG_Dumper_new_FILENAME);
    int filetype = (int)luaL_optinteger(L,WSLUA_OPTARG_Dumper_new_FILETYPE,wtap_pcapng_file_type_subtype());
    /* If we're writing pcapng, then WTAP_ENCAP_NONE and WTAP_ENCAP_PER_PACKET
     * generate a fake IDB on demand when the first packet for an encapsulation
     * type is written. Specifying any other encapsulation will generate a fake
     * IDB for that encapsulation upon opening even if there are no packets of
     * that type.
     * XXX - Default to PER_PACKET for any file type that supports it? */
    int encap  = (int)luaL_optinteger(L,WSLUA_OPTARG_Dumper_new_ENCAP, filetype == wtap_pcapng_file_type_subtype() ? WTAP_ENCAP_PER_PACKET : WTAP_ENCAP_ETHERNET);
    int err = 0;
    char *err_info = NULL;
    const char* filename = cross_plat_fname(fname);
    wtap_dump_params params = WTAP_DUMP_PARAMS_INIT;

    params.encap = encap;
    /* XXX - Check for an existing file, or the same file name as the current
     * capture file?
     */
    d = wtap_dump_open(filename, filetype, WS_FILE_UNCOMPRESSED, &params, &err,
                       &err_info);

    if (! d ) {
        /* WSLUA_ERROR("Error while opening file for writing"); */

        /* Push an appropriate error message, and free the err_info string
           if necessary. */
        switch (err) {
        case WTAP_ERR_NOT_REGULAR_FILE:
            lua_pushfstring(L,"The file \"%s\" is a \"special file\" or socket or other non-regular file",
                            filename);
            break;

        case WTAP_ERR_CANT_WRITE_TO_PIPE:
            lua_pushfstring(L,"The file \"%s\" is a pipe, and %s capture files can't be written to a pipe",
                            filename,
                            wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_UNWRITABLE_FILE_TYPE:
            lua_pushfstring(L,"Files of file type %s cannot be written",
                            wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_UNWRITABLE_ENCAP:
            lua_pushfstring(L,"Files of file type %s don't support encapsulation %s",
                            wtap_file_type_subtype_description(filetype),
                            wtap_encap_name(encap));
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            lua_pushfstring(L,"Files of file type %s don't support per-packet encapsulation",
                            wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_CANT_OPEN:
            lua_pushfstring(L,"The file \"%s\" could not be created for some unknown reason",
                            filename);
            break;

        case WTAP_ERR_SHORT_WRITE:
            lua_pushfstring(L,"A full header couldn't be written to the file \"%s\".",
                            filename);
            break;

        case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
            lua_pushfstring(L,"Files of file type %s cannot be written as a compressed file",
                            wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_INTERNAL:
            lua_pushfstring(L,"An internal error occurred creating the file \"%s\" (%s)",
                            filename,
                            err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        default:
            lua_pushfstring(L,"error while opening \"%s\": %s",
                            filename,
                            wtap_strerror(err));
            break;
        }

        /* Now throw the error. */
        return lua_error(L);
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
    char *err_info;

    if (! *dp) {
        WSLUA_ERROR(Dumper_close,"Cannot operate on a closed dumper");
        return 0;
    }

    g_hash_table_remove(dumper_encaps,*dp);

    if (!wtap_dump_close(*dp, NULL, &err, &err_info)) {
        /* Push an appropriate error message, and free the err_info string
           if necessary. */
        if (err_info != NULL) {
            lua_pushfstring(L,"error closing: %s (%s)",
                            wtap_strerror(err), err_info);
            g_free(err_info);
        } else {
            lua_pushfstring(L,"error closing: %s",
                            wtap_strerror(err));
        }

        /* Now throw the error. */
        return lua_error(L);
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
    char *err_info;

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

    wtap_rec_init(&rec, ba->len);

    wtap_setup_packet_rec(&rec, DUMPER_ENCAP(d));

    rec.presence_flags = WTAP_HAS_TS;
    rec.ts.secs  = (unsigned int)(floor(ts));
    rec.ts.nsecs = (unsigned int)(floor((ts - (double)rec.ts.secs) * 1000000000));

    rec.rec_header.packet_header.len       = ba->len;
    rec.rec_header.packet_header.caplen    = ba->len;
    if (ph->wph) {
        rec.rec_header.packet_header.pseudo_header = *ph->wph;
    }

    ws_buffer_append(&rec.data, ba->data, ba->len);

    /* TODO: Can we get access to pinfo->rec->block here somehow? We
     * should be copying it to pkthdr.pkt_block if we can. */

    if (! wtap_dump(d, &rec, &err, &err_info)) {
        wtap_rec_cleanup(&rec);

        /* Push an appropriate error message, and free the err_info string
           if necessary. */
        switch (err) {

        case WTAP_ERR_UNWRITABLE_REC_DATA:
            lua_pushfstring(L,"error while dumping: %s (%s)",
                            wtap_strerror(err), err_info);
            g_free(err_info);
            break;

        default:
            lua_pushfstring(L,"error while dumping: %s",
                            wtap_strerror(err));
            break;
        }

        /* Now throw the error. */
        return lua_error(L);
    }

    wtap_rec_cleanup(&rec);

    return 0;
}

WSLUA_METHOD Dumper_new_for_current(lua_State* L) {
    /*
     Creates a capture file using the same encapsulation as the one of the current packet.
     */
#define WSLUA_OPTARG_Dumper_new_for_current_FILETYPE 2 /* The file type. Defaults to pcapng. */
    Dumper d;
    const char* fname = luaL_checkstring(L,1);
    int filetype = (int)luaL_optinteger(L,WSLUA_OPTARG_Dumper_new_for_current_FILETYPE,wtap_pcapng_file_type_subtype());
    int encap;
    int err = 0;
    char *err_info = NULL;
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
    d = wtap_dump_open(filename, filetype, WS_FILE_UNCOMPRESSED, &params, &err,
                       &err_info);

    if (! d ) {
        /* Push an appropriate error message, and free the err_info string
           if necessary. */
        switch (err) {
        case WTAP_ERR_NOT_REGULAR_FILE:
            lua_pushfstring(L,"The file \"%s\" is a \"special file\" or socket or other non-regular file",
                            filename);
            break;

        case WTAP_ERR_CANT_WRITE_TO_PIPE:
            lua_pushfstring(L,"The file \"%s\" is a pipe, and %s capture files can't be written to a pipe",
                            filename,
                            wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_UNWRITABLE_FILE_TYPE:
            lua_pushfstring(L,"Files of file type %s cannot be written",
                            wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_UNWRITABLE_ENCAP:
            lua_pushfstring(L,"Files of file type %s don't support encapsulation %s",
                            wtap_file_type_subtype_description(filetype),
                            wtap_encap_name(encap));
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            lua_pushfstring(L,"Files of file type %s don't support per-packet encapsulation",
                            wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_CANT_OPEN:
            lua_pushfstring(L,"The file \"%s\" could not be created for some unknown reason",
                            filename);
            break;

        case WTAP_ERR_SHORT_WRITE:
            lua_pushfstring(L,"A full header couldn't be written to the file \"%s\".",
                            filename);
            break;

        case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
            lua_pushfstring(L,"Files of file type %s cannot be written as a compressed file",
                            wtap_file_type_subtype_description(filetype));
            break;

        case WTAP_ERR_INTERNAL:
             lua_pushfstring(L,"An internal error occurred creating the file \"%s\" (%s)",
                             filename,
                             err_info != NULL ? err_info : "no information supplied");
             g_free(err_info);
             break;

        default:
            lua_pushfstring(L,"error while opening \"%s\": %s",
                            filename,
                            wtap_strerror(err));
            break;
        }

        /* Now throw the error. */
        return lua_error(L);
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
    tvbuff_t* tvb;
    struct data_source *data_src;
    int err = 0;
    char *err_info;

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

    wtap_rec_init(&rec, tvb_captured_length(tvb));

    wtap_setup_packet_rec(&rec, lua_pinfo->rec->rec_header.packet_header.pkt_encap);
    rec.presence_flags                     = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    rec.ts                                 = lua_pinfo->abs_ts;
    rec.rec_header.packet_header.len       = tvb_reported_length(tvb);
    rec.rec_header.packet_header.caplen    = tvb_captured_length(tvb);
    rec.rec_header.packet_header.pseudo_header = *lua_pinfo->pseudo_header;

    /*
     * wtap_dump does not modify rec.block, so it should be possible to
     * pass epan_get_modified_block() or lua_pinfo->rec->block directly.
     * Temporarily duplicating the memory should not hurt though.
     */
    if (lua_pinfo->fd->has_modified_block) {
        rec.block = epan_get_modified_block(lua_pinfo->epan, lua_pinfo->fd);
        rec.block_was_modified = true;
    } else {
        rec.block = lua_pinfo->rec->block;
    }

    tvb_memcpy(tvb,ws_buffer_start_ptr(&rec.data),0,rec.rec_header.packet_header.caplen);

    if (! wtap_dump(d, &rec, &err, &err_info)) {
        wtap_rec_cleanup(&rec);

        /* Push an appropriate error message, and free the err_info string
           if necessary. */
        switch (err) {

        case WTAP_ERR_UNWRITABLE_REC_DATA:
            lua_pushfstring(L,"error while dumping: %s (%s)",
                            wtap_strerror(err), err_info);
            g_free(err_info);
            break;

        default:
            lua_pushfstring(L,"error while dumping: %s",
                            wtap_strerror(err));
            break;
        }

        /* Now throw the error. */
        return lua_error(L);
    }

    wtap_rec_cleanup(&rec);

    return 0;
}

/* Gets registered as metamethod automatically by WSLUA_REGISTER_CLASS/META */
static int Dumper__gc(lua_State* L) {
    Dumper* dp = (Dumper*)luaL_checkudata(L, 1, "Dumper");
    int err;
    char *err_info;

    /* If we are Garbage Collected it means the Dumper is no longer usable. Close it */

    if (! *dp)
        return 0; /* already closed, nothing to do! */

    g_hash_table_remove(dumper_encaps,*dp);

    if (!wtap_dump_close(*dp, NULL, &err, &err_info)) {
        /* Push an appropriate error message, and free the err_info string
           if necessary. */
        if (err_info != NULL) {
            lua_pushfstring(L,"error closing: %s (%s)",
                            wtap_strerror(err), err_info);
            g_free(err_info);
        } else {
            lua_pushfstring(L,"error closing: %s",
                            wtap_strerror(err));
        }

        /* Now throw the error. */
        return lua_error(L);
    }

    return 0;
}


/* Read-only attributes. These intentionally do not go through
 * checkDumper() because that raises "Dumper already closed" for a
 * closed handle (FAIL_ON_NULL). A closed Dumper is still reachable
 * from the Variables view via its binding name, and it is convenient
 * to inspect metadata such as the chosen file type even after close.
 * Each getter therefore uses luaL_checkudata directly, treats
 * *dp == NULL as "closed", and returns nil for metadata it cannot
 * compute in that state. */

/* WSLUA_ATTRIBUTE Dumper_is_open RO True while the dumper is open,
   false once Dumper:close() has run. */
static int Dumper_get_is_open(lua_State* L) {
    Dumper *dp = (Dumper *)luaL_checkudata(L, 1, "Dumper");
    lua_pushboolean(L, dp && *dp ? 1 : 0);
    return 1;
}

/* WSLUA_ATTRIBUTE Dumper_file_type RO The numeric wiretap file-type-
   subtype (as returned by wtap_name_to_file_type_subtype()), or nil if
   the dumper is closed. */
static int Dumper_get_file_type(lua_State* L) {
    Dumper *dp = (Dumper *)luaL_checkudata(L, 1, "Dumper");
    if (!dp || !*dp) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, wtap_dump_file_type_subtype(*dp));
    return 1;
}

/* WSLUA_ATTRIBUTE Dumper_file_type_name RO Short wiretap name of the
   file type (e.g. "pcapng"), or nil if the dumper is closed. */
static int Dumper_get_file_type_name(lua_State* L) {
    Dumper *dp = (Dumper *)luaL_checkudata(L, 1, "Dumper");
    if (!dp || !*dp) { lua_pushnil(L); return 1; }
    const char *name = wtap_file_type_subtype_name(
        wtap_dump_file_type_subtype(*dp));
    if (name) lua_pushstring(L, name); else lua_pushnil(L);
    return 1;
}

/* WSLUA_ATTRIBUTE Dumper_file_type_description RO Human-readable
   description of the file type (e.g. "Wireshark/... - pcapng"), or nil
   if the dumper is closed. */
static int Dumper_get_file_type_description(lua_State* L) {
    Dumper *dp = (Dumper *)luaL_checkudata(L, 1, "Dumper");
    if (!dp || !*dp) { lua_pushnil(L); return 1; }
    const char *desc = wtap_file_type_subtype_description(
        wtap_dump_file_type_subtype(*dp));
    if (desc) lua_pushstring(L, desc); else lua_pushnil(L);
    return 1;
}

/* WSLUA_ATTRIBUTE Dumper_encap RO The numeric WTAP_ENCAP_* chosen at
   open time, or nil if the dumper is closed. */
static int Dumper_get_encap(lua_State* L) {
    Dumper *dp = (Dumper *)luaL_checkudata(L, 1, "Dumper");
    if (!dp || !*dp) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, DUMPER_ENCAP(*dp));
    return 1;
}

/* WSLUA_ATTRIBUTE Dumper_encap_name RO Short wiretap name of the
   encapsulation (e.g. "ETHERNET"), or nil if the dumper is closed. */
static int Dumper_get_encap_name(lua_State* L) {
    Dumper *dp = (Dumper *)luaL_checkudata(L, 1, "Dumper");
    if (!dp || !*dp) { lua_pushnil(L); return 1; }
    const char *name = wtap_encap_name(DUMPER_ENCAP(*dp));
    if (name) lua_pushstring(L, name); else lua_pushnil(L);
    return 1;
}

/* WSLUA_ATTRIBUTE Dumper_encap_description RO Human-readable description
   of the encapsulation (e.g. "Ethernet"), or nil if the dumper is
   closed. */
static int Dumper_get_encap_description(lua_State* L) {
    Dumper *dp = (Dumper *)luaL_checkudata(L, 1, "Dumper");
    if (!dp || !*dp) { lua_pushnil(L); return 1; }
    const char *desc = wtap_encap_description(DUMPER_ENCAP(*dp));
    if (desc) lua_pushstring(L, desc); else lua_pushnil(L);
    return 1;
}

WSLUA_METAMETHOD Dumper__tostring(lua_State* L) {
    /* Returns a short label of the form
       `Dumper: file_type=<name> encap=<name>` while open, or
       `Dumper: (closed)` once `Dumper:close()` has run. Like the
       read-only attributes above, this deliberately bypasses
       checkDumper so a closed dumper is still inspectable from the
       debugger's Variables view. */
    Dumper *dp = (Dumper *)luaL_checkudata(L, 1, "Dumper");
    if (!dp || !*dp) {
        lua_pushstring(L, "Dumper: (closed)");
        WSLUA_RETURN(1);
    }
    const char *ftype = wtap_file_type_subtype_name(
        wtap_dump_file_type_subtype(*dp));
    const char *encap = wtap_encap_name(DUMPER_ENCAP(*dp));
    lua_pushfstring(L, "Dumper: file_type=%s encap=%s",
                    ftype ? ftype : "?",
                    encap ? encap : "?");
    WSLUA_RETURN(1); /* The string. */
}

WSLUA_ATTRIBUTES Dumper_attributes[] = {
    WSLUA_ATTRIBUTE_ROREG(Dumper,is_open),
    WSLUA_ATTRIBUTE_ROREG(Dumper,file_type),
    WSLUA_ATTRIBUTE_ROREG(Dumper,file_type_name),
    WSLUA_ATTRIBUTE_ROREG(Dumper,file_type_description),
    WSLUA_ATTRIBUTE_ROREG(Dumper,encap),
    WSLUA_ATTRIBUTE_ROREG(Dumper,encap_name),
    WSLUA_ATTRIBUTE_ROREG(Dumper,encap_description),
    { NULL, NULL, NULL }
};

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
    WSLUA_CLASS_MTREG(Dumper,tostring),
    { NULL, NULL }
};

int Dumper_register(lua_State* L) {
    if (dumper_encaps != NULL) {
        g_hash_table_unref(dumper_encaps);
    }
    dumper_encaps = g_hash_table_new(g_direct_hash,g_direct_equal);
    WSLUA_REGISTER_CLASS_WITH_ATTRS(Dumper);
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
