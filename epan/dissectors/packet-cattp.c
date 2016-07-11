/* packet-cattp.c
 * Routines for packet dissection of
 *      ETSI TS 102 127 v6.13.0  (Release 6 / 2009-0r45)
 *      Card Application Toolkit - Transport Protocol over UDP
 *
 * Copyright 2014-2014 by Sebastian Kloeppel <sk [at] nakedape.net>
 *                        Cristina E. Vintila <cristina.vintila [at] gmail.com>
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/in_cksum.h>

#define CATTP_SHORTNAME "CAT-TP"
#define CATTP_HBLEN 18

#define F_SYN 0x80
#define F_ACK 0x40
#define F_EAK 0x20
#define F_RST 0x10
#define F_NUL 0x08
#define F_SEG 0x04

/* bit masks for the first header byte. */
#define M_FLAGS   0xFC  /* flags only, no version */
#define M_PDU_SYN 0xB8  /* SYN (ACK, SEG dont care) without version */
#define M_PDU_ACK 0xD0  /* ACK (EAK, SEG, NUL dont care) without version */
#define M_PDU_RST 0xBC  /* RST (ACK dont care) without version */
#define M_VERSION 0x03  /* only Version */

#define ICCID_PREFIX 0x98

static int proto_cattp = -1;

static gint ett_cattp = -1;
static gint ett_cattp_id = -1;
static gint ett_cattp_flags = -1;
static gint ett_cattp_eaks = -1;

static int hf_cattp_flags = -1;

/* flag components */
static int hf_cattp_flag_syn = -1;
static int hf_cattp_flag_ack = -1;
static int hf_cattp_flag_eak = -1;
static int hf_cattp_flag_rst = -1;
static int hf_cattp_flag_nul = -1;
static int hf_cattp_flag_seg = -1;
static int hf_cattp_version = -1;

/* structure of flag components */
static const int *cattp_flags[] = {
    &hf_cattp_flag_syn,
    &hf_cattp_flag_ack,
    &hf_cattp_flag_eak,
    &hf_cattp_flag_rst,
    &hf_cattp_flag_nul,
    &hf_cattp_flag_seg,
    &hf_cattp_version,
    NULL
};

static int hf_cattp_hlen = -1;
static int hf_cattp_srcport = -1;
static int hf_cattp_dstport = -1;
static int hf_cattp_datalen = -1;
static int hf_cattp_seq = -1;
static int hf_cattp_ack = -1;
static int hf_cattp_windowsize = -1;
static int hf_cattp_checksum = -1;
static int hf_cattp_checksum_status = -1;
static int hf_cattp_identification = -1;
static int hf_cattp_iccid = -1;
static int hf_cattp_idlen = -1;
static int hf_cattp_maxpdu = -1;
static int hf_cattp_maxsdu = -1;
static int hf_cattp_rc = -1;
static int hf_cattp_eaklen = -1;
static int hf_cattp_eaks = -1;

/* Preference to control whether to check the CATTP checksum */
static gboolean cattp_check_checksum = TRUE;

/* Reason code mapping */
static const value_string cattp_reset_reason[] = {
    { 0, "Normal Ending" },
    { 1, "Connection set-up failed, illegal parameters" },
    { 2, "Temporarily unable to set up this connection" },
    { 3, "Requested Port not available" },
    { 4, "Unexpected PDU received" },
    { 5, "Maximum retries exceeded" },
    { 6, "Version not supported" },
    { 7, "RFU" },
    { 0, NULL }
};

/* Forward declartion due to use of heuristic dissection preference. */
void proto_reg_handoff_cattp(void);
void proto_register_cattp(void);

/* Dissection of SYN PDUs */
static guint32
dissect_cattp_synpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cattp_tree, guint32 offset)
{
    proto_item *idi, *id_tree;
    guint8      idlen;

    proto_tree_add_item(cattp_tree, hf_cattp_maxpdu, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(cattp_tree, hf_cattp_maxsdu, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    idlen = tvb_get_guint8(tvb, offset);
    idi = proto_tree_add_uint(cattp_tree, hf_cattp_idlen, tvb, offset, 1, idlen);
    offset += 1;

    col_append_fstr(pinfo->cinfo, COL_INFO, " IdLen=%u ", idlen);

    id_tree = proto_item_add_subtree(idi, ett_cattp_id);

    if (idlen > 0) {
        guint8 first_id_byte;

        first_id_byte = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(id_tree, hf_cattp_identification, tvb, offset, idlen, ENC_NA);

        /* Optional code. Checks whether identification field may be an ICCID.
         * It has to be considered to move this logic to another layer / dissector.
         * However it is common to send ICCID as Identification for OTA download. */
        if (idlen <= 10 && idlen >= 9 && ICCID_PREFIX == first_id_byte) {
            wmem_strbuf_t *buf;
            int i;

            buf = wmem_strbuf_new(wmem_packet_scope(), "");

            /* switch nibbles */
            for (i = 0; i < idlen; i++) {
                guint8 c, n;

                c = tvb_get_guint8(tvb, offset + i);
                n = ((c & 0xF0) >> 4) + ((c & 0x0F) << 4);
                wmem_strbuf_append_printf(buf, "%02X", n);
            }

            proto_tree_add_string(id_tree, hf_cattp_iccid, tvb, offset,
                                 idlen, wmem_strbuf_get_str(buf));
        }
        offset += idlen;
    }
    return offset;
}

/* Dissection of Extended Acknowledgement PDUs */
static guint32
dissect_cattp_eakpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cattp_tree, guint32 offset, guint8 hlen)
{
    proto_item *eaki;
    guint8      eak_count;

    eak_count = (hlen - offset) >> 1;
    eaki = proto_tree_add_uint_format_value(cattp_tree, hf_cattp_eaklen, tvb, offset, eak_count * 2,
                                            eak_count, "%u PDUs", eak_count);

    if (eak_count > 0) {
        proto_item *eak_tree;
        int i;

        col_append_fstr(pinfo->cinfo, COL_INFO, " EAKs=%u", eak_count);
        eak_tree = proto_item_add_subtree(eaki, ett_cattp_eaks);

        for (i = 0; i < eak_count; i++) {
            proto_tree_add_item(eak_tree, hf_cattp_eaks, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }

    return offset;
}

/* Dissection of Extended Acknowledgement PDUs */
static guint32
dissect_cattp_rstpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *cattp_tree, guint32 offset)
{
    guint8       rc;
    const gchar *rc_str;

    rc = tvb_get_guint8(tvb, offset); /* reason code of RST */
    rc_str = val_to_str(rc, cattp_reset_reason, "Unknown reason code: 0x%02x");
    col_append_fstr(pinfo->cinfo, COL_INFO, " Reason=\"%s\" ", rc_str);

    proto_tree_add_item(cattp_tree, hf_cattp_rc, tvb, offset, 1, ENC_BIG_ENDIAN);
    return ++offset;
}

/* Dissection of the base header */
static int
dissect_cattp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    const char *pdutype = "[Unknown PDU]";
    proto_item *ti, *cattp_tree;
    guint32     offset;
    vec_t       cksum_vec[1];
    int         header_offset;
    guint       cksum_data_len;
    guint8      flags, first_byte, hlen, ver;
    guint16     plen, ackno, seqno, wsize, sport, dport;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, CATTP_SHORTNAME);

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    hlen = tvb_get_guint8(tvb, 3); /* lookahead header len. */

    offset = 0;
    ti = proto_tree_add_protocol_format(tree, proto_cattp, tvb, offset, hlen,
                                        "Card Application Toolkit Transport Protocol");

    cattp_tree = proto_item_add_subtree(ti, ett_cattp);

    /* render flags tree */
    first_byte = tvb_get_guint8(tvb, offset);
    flags = first_byte & M_FLAGS; /* discard version from first byte for flags */
    ver   = first_byte & M_VERSION; /* discard flags for version */
    proto_tree_add_bitmask(cattp_tree, tvb, offset, hf_cattp_flags, ett_cattp_flags, cattp_flags, ENC_BIG_ENDIAN);
    offset += 3; /* skip RFU and header len */

    /* Header length, varies for SYN(identification) and EAKs */
    proto_tree_add_uint(cattp_tree, hf_cattp_hlen, tvb, offset, 1, hlen);
    offset += 1;

    /* Parse cattp source port. */
    sport = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(cattp_tree, hf_cattp_srcport, tvb, offset, 2, sport);
    offset += 2;

    /* Parse cattp destination port. */
    dport = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(cattp_tree, hf_cattp_dstport, tvb, offset, 2, dport);
    offset += 2;

    proto_item_append_text(ti, " (v%u, Src Port: %u, Dst Port: %u)", ver, sport, dport);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%u > %u ", sport, dport);

    /* Parse length of payload. */
    plen = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(cattp_tree, hf_cattp_datalen, tvb, offset, 2, plen);
    offset += 2;

    /* Parse sequence number. */
    seqno = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(cattp_tree, hf_cattp_seq, tvb, offset, 2, seqno);
    offset += 2;

    /* Parse acknowledgement number. */
    ackno = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(cattp_tree, hf_cattp_ack, tvb, offset, 2, ackno);
    offset += 2;

    /* Parse window size. */
    wsize = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(cattp_tree, hf_cattp_windowsize, tvb, offset, 2, wsize);
    offset += 2;

    if (flags & F_SYN)
           pdutype = "[SYN PDU]";
    else if (flags & F_ACK)
           pdutype = "[ACK PDU]";
    else if (flags & F_RST)
           pdutype = "[RST PDU]";

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s Flags=0x%02X Ack=%u Seq=%u WSize=%u", pdutype, flags, ackno, seqno, wsize);

    /* Parse and verify checksum */
    header_offset  = 0;
    cksum_data_len = hlen + plen;
    if (!cattp_check_checksum) {
        /* We have turned checksum checking off; we do NOT checksum it. */
        proto_tree_add_checksum(cattp_tree, tvb, offset, hf_cattp_checksum, hf_cattp_checksum_status, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    } else {
        /* We haven't turned checksum checking off; checksum it. */

        /* Unlike TCP, CATTP does not make use of a pseudo-header for checksum */
        SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, header_offset, cksum_data_len);
        proto_tree_add_checksum(cattp_tree, tvb, offset, hf_cattp_checksum, hf_cattp_checksum_status, NULL, pinfo, in_cksum(cksum_vec, 1),
                                ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
    } /* End of checksum code */
    offset += 2;

    if (flags & F_SYN)
        offset = dissect_cattp_synpdu(tvb, pinfo, cattp_tree, offset);
    else if (flags & F_EAK)
        offset = dissect_cattp_eakpdu(tvb, pinfo, cattp_tree, offset, hlen);
    else if (flags & F_RST)
        offset = dissect_cattp_rstpdu(tvb, pinfo, cattp_tree, offset);
    /* for other PDU types nothing special to be displayed in detail tree. */

    if (plen > 0) { /* Call generic data handle if data exists. */
       col_append_fstr(pinfo->cinfo, COL_INFO, " DataLen=%u", plen);
       tvb = tvb_new_subset_remaining(tvb, offset);
       call_data_dissector(tvb, pinfo, tree);
    }
    return tvb_captured_length(tvb);
}

/* The heuristic dissector function checks if the UDP packet may be a cattp packet */
static gboolean
dissect_cattp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) >= CATTP_HBLEN) { /* check of data is big enough for base header. */
        guint8  flags, hlen;
        guint16 plen;

        hlen = tvb_get_guint8(tvb, 3); /* header len  */
        plen = tvb_get_ntohs(tvb, 8);  /* payload len */

        if (hlen+plen != tvb_reported_length(tvb)) /* check if data length is ok. */
            return FALSE;

        flags = tvb_get_guint8(tvb, 0) & M_FLAGS;
        if ( (flags & M_PDU_SYN) == F_SYN ||
             (flags & M_PDU_RST) == F_RST ||
             (flags & M_PDU_ACK) == F_ACK ) { /* check if flag combi is valid */
            dissect_cattp(tvb, pinfo, tree, data);
            return TRUE;
        }
    }
    return FALSE;
}

/* Function to register the dissector, called by infrastructure. */
void
proto_register_cattp(void)
{
    static hf_register_info hf[] = {
        {
            &hf_cattp_flags,
            {
                "Flags", "cattp.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_syn,
            {
                "Synchronize Flag", "cattp.flags.syn", FT_UINT8, BASE_DEC, NULL, F_SYN,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_ack,
            {
                "Acknowledge Flag", "cattp.flags.ack", FT_UINT8, BASE_DEC, NULL, F_ACK,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_eak,
            {
                "Extended Acknowledge Flag", "cattp.flags.eak", FT_UINT8, BASE_DEC, NULL, F_EAK,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_rst,
            {
                "Reset Flag", "cattp.flags.rst", FT_UINT8, BASE_DEC, NULL, F_RST,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_nul,
            {
                "NULL Flag", "cattp.flags.nul", FT_UINT8, BASE_DEC, NULL, F_NUL,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_seg,
            {
                "Segmentation Flag", "cattp.flags.seg", FT_UINT8, BASE_DEC, NULL, F_SEG,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_version,
            {
                "Version", "cattp.version", FT_UINT8, BASE_HEX, NULL, M_VERSION,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_hlen,
            {
                "Header Length", "cattp.hlen", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_srcport,
            {
                "Source Port", "cattp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_dstport,
            {
                "Destination Port", "cattp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_datalen,
            {
                "Data Length", "cattp.datalen", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_seq,
            {
                "Sequence Number", "cattp.seq", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_ack,
            {
                "Acknowledgement Number", "cattp.ack", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_windowsize,
            {
                "Window Size", "cattp.windowsize", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_checksum,
            {
                "Checksum", "cattp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_checksum_status,
            {
                "Checksum Status", "cattp.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_identification,
            {
                "Identification", "cattp.identification", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_iccid,
            {
                "ICCID", "cattp.iccid", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_maxpdu,
            {
                "Maxpdu", "cattp.maxpdu", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_maxsdu,
            {
                "Maxsdu", "cattp.maxsdu", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_rc,
            {
                "Reason Code", "cattp.rc", FT_UINT8, BASE_DEC, VALS(cattp_reset_reason), 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_idlen,
            {
                "Identification Length", "cattp.idlen", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_eaks,
            {
                "Acknowledgement Number", "cattp.eak", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_eaklen,
            {
                "Extended Acknowledgement Numbers", "cattp.eaks", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_cattp,
        &ett_cattp_flags,
        &ett_cattp_id,
        &ett_cattp_eaks
    };

    module_t *cattp_module;

    proto_cattp = proto_register_protocol (
                      "ETSI Card Application Toolkit Transport Protocol",    /* name */
                      CATTP_SHORTNAME, /* short name */
                      "cattp"          /* abbrev */
                  );

    proto_register_field_array(proto_cattp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    cattp_module = prefs_register_protocol(proto_cattp, proto_reg_handoff_cattp);
    prefs_register_bool_preference(cattp_module, "checksum",
                                   "Validate checksum of all messages",
                                   "Whether the checksum of all messages should be validated or not",
                                   &cattp_check_checksum);

    prefs_register_obsolete_preference(cattp_module, "enable");
}

/* Handoff */
void
proto_reg_handoff_cattp(void)
{
    static gboolean initialized = FALSE;

    if (!initialized) {
        dissector_handle_t cattp_handle;

        /* Create dissector handle */
        cattp_handle = create_dissector_handle(dissect_cattp, proto_cattp);

        heur_dissector_add("udp", dissect_cattp_heur, "CAT-TP over UDP", "cattp_udp", proto_cattp, HEURISTIC_ENABLE);
        dissector_add_for_decode_as("udp.port", cattp_handle);
        initialized = TRUE;
    }
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
