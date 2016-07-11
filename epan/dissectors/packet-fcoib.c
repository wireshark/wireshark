/*
 * packet-fcoib.c
 * Routines for FCoIB dissection - Fibre Channel over Infiniband
 * Copyright (c) 2010 Mellanox Technologies Ltd. (slavak@mellanox.co.il)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on packet-fcoe.c, Copyright (c) 2006 Nuova Systems, Inc. (jre@nuovasystems.com)
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

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include "packet-infiniband.h"
#include "packet-fc.h"

void proto_register_fcoib(void);
void proto_reg_handoff_fcoib(void);

#define FCOIB_HEADER_LEN   16        /* header: encap. header, SOF, and padding */
#define FCOIB_TRAILER_LEN   8        /* trailer: FC-CRC, EOF and padding */
#define FCOIB_VER_OFFSET    2        /* offset of ver field (in bytes) inside FCoIB Encap. header */

typedef enum {
    FCOIB_EOFn    = 0x41,
    FCOIB_EOFt    = 0x42,
    FCOIB_EOFrt   = 0x44,
    FCOIB_EOFdt   = 0x46,
    FCOIB_EOFni   = 0x49,
    FCOIB_EOFdti  = 0x4E,
    FCOIB_EOFrti  = 0x4F,
    FCOIB_EOFa    = 0x50
} fcoib_eof_t;

typedef enum {
    FCOIB_SOFf    = 0x28,
    FCOIB_SOFi4   = 0x29,
    FCOIB_SOFi2   = 0x2D,
    FCOIB_SOFi3   = 0x2E,
    FCOIB_SOFn4   = 0x31,
    FCOIB_SOFn2   = 0x35,
    FCOIB_SOFn3   = 0x36,
    FCOIB_SOFc4   = 0x39
} fcoib_sof_t;

static const value_string fcoib_eof_vals[] = {
    {FCOIB_EOFn,    "EOFn" },
    {FCOIB_EOFt,    "EOFt" },
    {FCOIB_EOFrt,   "EOFrt" },
    {FCOIB_EOFdt,   "EOFdt" },
    {FCOIB_EOFni,   "EOFni" },
    {FCOIB_EOFdti,  "EOFdti" },
    {FCOIB_EOFrti,  "EOFrti" },
    {FCOIB_EOFa,    "EOFa" },
    {0, NULL}
};

static const value_string fcoib_sof_vals[] = {
    {FCOIB_SOFf,    "SOFf" },
    {FCOIB_SOFi4,   "SOFi4" },
    {FCOIB_SOFi2,   "SOFi2" },
    {FCOIB_SOFi3,   "SOFi3" },
    {FCOIB_SOFn4,   "SOFn4" },
    {FCOIB_SOFn2,   "SOFn2" },
    {FCOIB_SOFn3,   "SOFn3" },
    {FCOIB_SOFc4,   "SOFc4" },
    {0, NULL}
};

static int proto_fcoib          = -1;
static int hf_fcoib_ver         = -1;
static int hf_fcoib_sig         = -1;
static int hf_fcoib_sof         = -1;
static int hf_fcoib_eof         = -1;
static int hf_fcoib_crc         = -1;
static int hf_fcoib_crc_status  = -1;

static int ett_fcoib            = -1;

static expert_field ei_fcoib_crc = EI_INIT;

static dissector_handle_t fc_handle;

/* global preferences */
static gboolean    gPREF_HEUR_EN = TRUE;
static gboolean    gPREF_MAN_EN  = FALSE;
static gint        gPREF_TYPE[2] = {0};
static const char *gPREF_ID[2]   = {NULL};
static guint       gPREF_QP[2]   = {0};

/* source/destination addresses from preferences menu (parsed from gPREF_TYPE[?], gPREF_ID[?]) */
static address  manual_addr[2];
static void    *manual_addr_data[2];

static const enum_val_t pref_address_types[] = {
    {"lid", "LID", 0},
    {"gid", "GID", 1},
    {NULL, NULL, -1}
};

/* checks if a packet matches the source/destination manually-configured in preferences */
static gboolean
manual_addr_match(packet_info *pinfo) {
    if (gPREF_MAN_EN) {
        /* If the manual settings are enabled see if this fits - in which case we can skip
           the following checks entirely and go straight to dissecting */
        if (    (addresses_equal(&pinfo->src, &manual_addr[0]) &&
                 addresses_equal(&pinfo->dst, &manual_addr[1]) &&
                 (pinfo->srcport == 0xffffffff /* is unknown */ || pinfo->srcport == gPREF_QP[0]) &&
                 (pinfo->destport == 0xffffffff /* is unknown */ || pinfo->destport == gPREF_QP[1]))    ||
                (addresses_equal(&pinfo->src, &manual_addr[1]) &&
                 addresses_equal(&pinfo->dst, &manual_addr[0]) &&
                 (pinfo->srcport == 0xffffffff /* is unknown */ || pinfo->srcport == gPREF_QP[1]) &&
                 (pinfo->destport == 0xffffffff /* is unknown */ || pinfo->destport == gPREF_QP[0]))    )
            return TRUE;
    }

    return FALSE;
}

static gboolean
dissect_fcoib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        crc_offset;
    gint        eof_offset;
    gint        sof_offset;
    gint        frame_len;
    guint       version;
    const char *ver;
    gint        bytes_remaining;
    guint8      sof          = 0;
    guint8      eof          = 0;
    guint8      sig          = 0;
    const char *eof_str;
    const char *sof_str;
    const char *crc_msg;
    const char *len_msg;
    proto_item *ti;
    proto_tree *fcoib_tree;
    tvbuff_t   *next_tvb;
    gboolean    crc_exists;
    guint32     crc_computed = 0;
    guint32     crc          = 0;
    gboolean    packet_match_manual;
    fc_data_t   fc_data;

    tree = proto_tree_get_root(tree);   /* we don't want to add FCoIB under the Infiniband tree */

    frame_len = tvb_reported_length_remaining(tvb, 0) -
      FCOIB_HEADER_LEN - FCOIB_TRAILER_LEN;
    crc_offset = FCOIB_HEADER_LEN + frame_len;
    eof_offset = crc_offset + 4;
    sof_offset = FCOIB_HEADER_LEN - 1;

    if (frame_len <= 0)
        return FALSE;   /* this packet isn't even long enough to contain the header+trailer w/o FC payload! */

    packet_match_manual = manual_addr_match(pinfo);

    if (!packet_match_manual && !gPREF_HEUR_EN)
        return FALSE;   /* user doesn't want us trying to automatically identify FCoIB packets */

    /* we start off with some basic heuristics checks to make sure this could be a FCoIB packet */

    if (tvb_bytes_exist(tvb, 0, 1))
        sig = tvb_get_guint8(tvb, 0) >> 6;
    if (tvb_bytes_exist(tvb, eof_offset, 1))
        eof = tvb_get_guint8(tvb, eof_offset);
    if (tvb_bytes_exist(tvb, sof_offset, 1))
        sof = tvb_get_guint8(tvb, sof_offset);

    if (!packet_match_manual) {
        if (sig != 1)
            return FALSE;   /* the sig field in the FCoIB Encap. header MUST be 2'b01*/
        if (!tvb_bytes_exist(tvb, eof_offset + 1, 3) || tvb_get_ntoh24(tvb, eof_offset + 1) != 0)
            return FALSE;   /* 3 bytes of RESERVED field immediately after eEOF MUST be 0 */
        if (!try_val_to_str(sof, fcoib_sof_vals))
            return FALSE;   /* invalid value for SOF */
        if (!try_val_to_str(eof, fcoib_eof_vals))
            return FALSE;   /* invalid value for EOF */
    }


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FCoIB");
    bytes_remaining = tvb_captured_length_remaining(tvb, FCOIB_HEADER_LEN);
    if (bytes_remaining > frame_len)
        bytes_remaining = frame_len;        /* backing length */
    next_tvb = tvb_new_subset(tvb, FCOIB_HEADER_LEN, bytes_remaining, frame_len);

    /*
     * Only version 0 is defined at this point.
     * Don't print the version in the short summary if it is zero.
     */
    ver = "";
    version = tvb_get_guint8(tvb, 0 + FCOIB_VER_OFFSET) >> 4;
    if (version != 0)
        ver = wmem_strdup_printf(wmem_packet_scope(), ver, "ver %d ", version);

    eof_str = "none";
    if (tvb_bytes_exist(tvb, eof_offset, 1)) {
        eof_str = val_to_str(eof, fcoib_eof_vals, "0x%x");
    }

    sof_str = "none";
    if (tvb_bytes_exist(tvb, sof_offset, 1)) {
        sof_str = val_to_str(sof, fcoib_sof_vals, "0x%x");
    }

    /*
     * Check the CRC.
     */
    crc_msg = "";
    crc_exists = tvb_bytes_exist(tvb, crc_offset, 4);
    if (crc_exists) {
        crc = tvb_get_ntohl(tvb, crc_offset);
        crc_computed = crc32_802_tvb(next_tvb, frame_len);
        if (crc != crc_computed) {
            crc_msg = " [bad FC CRC]";
        }
    }
    len_msg = "";
    if ((frame_len % 4) != 0 || frame_len < 24) {
        len_msg = " [invalid length]";
    }

    ti = proto_tree_add_protocol_format(tree, proto_fcoib, tvb, 0,
                                        FCOIB_HEADER_LEN,
                                        "FCoIB %s(%s/%s) %d bytes%s%s", ver,
                                        sof_str, eof_str,
                                        frame_len, crc_msg,
                                        len_msg);

    /* Dissect the FCoIB Encapsulation header */

    fcoib_tree = proto_item_add_subtree(ti, ett_fcoib);
    proto_tree_add_uint(fcoib_tree, hf_fcoib_sig, tvb, 0, 1, sig);
    proto_tree_add_uint(fcoib_tree, hf_fcoib_ver, tvb, FCOIB_VER_OFFSET, 1, version);
    proto_tree_add_uint(fcoib_tree, hf_fcoib_sof, tvb, sof_offset, 1, sof);

    /*
     * Create the CRC information.
     */
    if (crc_exists) {
        proto_tree_add_checksum(fcoib_tree, tvb, crc_offset, hf_fcoib_crc, hf_fcoib_crc_status, &ei_fcoib_crc, pinfo, crc_computed, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
        proto_tree_set_appendix(fcoib_tree, tvb, crc_offset,
                                tvb_captured_length_remaining (tvb, crc_offset));
    } else {
        proto_tree_add_checksum(fcoib_tree, tvb, crc_offset, hf_fcoib_crc, hf_fcoib_crc_status, &ei_fcoib_crc, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NOT_PRESENT);
    }

    /*
     * Interpret the EOF.
     */
    if (tvb_bytes_exist(tvb, eof_offset, 1)) {
        proto_tree_add_item(fcoib_tree, hf_fcoib_eof, tvb, eof_offset, 1, ENC_BIG_ENDIAN);
    }

    /* Set the SOF/EOF flags in the packet_info header */
    fc_data.sof_eof = 0;
    if (sof == FCOIB_SOFi3 || sof == FCOIB_SOFi2 || sof == FCOIB_SOFi4) {
        fc_data.sof_eof = FC_DATA_SOF_FIRST_FRAME;
    } else if (sof == FCOIB_SOFf) {
        fc_data.sof_eof = FC_DATA_SOF_SOFF;
    }

    if (eof != FCOIB_EOFn) {
        fc_data.sof_eof |= FC_DATA_EOF_LAST_FRAME;
    } else if (eof != FCOIB_EOFt) {
        fc_data.sof_eof |= FC_DATA_EOF_INVALID;
    }

    /* Call the FC Dissector if this is carrying an FC frame */
    fc_data.ethertype = 0;

    if (fc_handle) {
        call_dissector_with_data(fc_handle, next_tvb, pinfo, tree, &fc_data);
    } else {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return TRUE;
}

void
proto_register_fcoib(void)
{
    module_t *fcoib_module;

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_fcoib_sof,
          {"SOF", "fcoib.sof", FT_UINT8, BASE_HEX, VALS(fcoib_sof_vals), 0,
           NULL, HFILL}},
        { &hf_fcoib_eof,
          {"EOF", "fcoib.eof", FT_UINT8, BASE_HEX, VALS(fcoib_eof_vals), 0,
           NULL, HFILL}},
        { &hf_fcoib_sig,
          {"Signature", "fcoib.sig", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},
        { &hf_fcoib_ver,
          {"Version", "fcoib.ver", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_fcoib_crc,
          {"CRC", "fcoib.crc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},
        { &hf_fcoib_crc_status,
          {"CRC Status", "fcoib.crc.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
           NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_fcoib,
    };

    static ei_register_info ei[] = {
        { &ei_fcoib_crc, { "fcoib.crc.bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    };

    expert_module_t* expert_fcoib;

    /* Register the protocol name and description */
    proto_fcoib = proto_register_protocol("Fibre Channel over Infiniband",
        "FCoIB", "fcoib");

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_fcoib, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_fcoib = expert_register_protocol(proto_fcoib);
    expert_register_field_array(expert_fcoib, ei, array_length(ei));

    fcoib_module = prefs_register_protocol(proto_fcoib, proto_reg_handoff_fcoib);

    prefs_register_bool_preference(fcoib_module, "heur_en", "Enable heuristic identification of FCoIB packets",
        "When this option is enabled Wireshark will attempt to identify FCoIB packets automatically "
        "based on some common features (may generate false positives)",
        &gPREF_HEUR_EN);

    prefs_register_bool_preference(fcoib_module, "manual_en", "Enable manual settings",
        "Enables dissecting packets between the manually configured source/destination as FCoIB traffic",
        &gPREF_MAN_EN);

    prefs_register_static_text_preference(fcoib_module, "addr_a", "Address A",
        "Side A of the manually-configured connection");
    prefs_register_enum_preference(fcoib_module, "addr_a_type", "Address Type",
        "Type of address specified", &gPREF_TYPE[0], pref_address_types, FALSE);
    prefs_register_string_preference(fcoib_module, "addr_a_id", "ID",
        "LID/GID of address A", &gPREF_ID[0]);
    prefs_register_uint_preference(fcoib_module, "addr_a_qp", "QP Number",
        "QP Number for address A", 10, &gPREF_QP[0]);

    prefs_register_static_text_preference(fcoib_module, "addr_b", "Address B",
        "Side B of the manually-configured connection");
    prefs_register_enum_preference(fcoib_module, "addr_b_type", "Address Type",
        "Type of address specified", &gPREF_TYPE[1], pref_address_types, FALSE);
    prefs_register_string_preference(fcoib_module, "addr_b_id", "ID",
        "LID/GID of address B", &gPREF_ID[1]);
    prefs_register_uint_preference(fcoib_module, "addr_b_qp", "QP Number",
        "QP Number for address B", 10, &gPREF_QP[1]);
}

void
proto_reg_handoff_fcoib(void)
{
    static gboolean initialized = FALSE;

    if (!initialized) {
        heur_dissector_add("infiniband.payload", dissect_fcoib, "Fibre Channel over Infiniband", "fc_infiniband", proto_fcoib, HEURISTIC_ENABLE);

        fc_handle = find_dissector_add_dependency("fc", proto_fcoib);

        initialized = TRUE;
    }

    if (gPREF_MAN_EN) {
        /* the manual setting is enabled, so parse the settings into the address type */
        gboolean error_occured = FALSE;
        char *not_parsed;
        int i;

        for (i = 0; i < 2; i++) {
            if (gPREF_ID[i][0] == '\0') {
                error_occured = TRUE;
            } else if (gPREF_TYPE[i] == 0) {   /* LID */
                errno = 0;  /* reset any previous error indicators */
                *((guint16*)manual_addr_data[i]) = (guint16)strtoul(gPREF_ID[i], &not_parsed, 0);
                if (errno || *not_parsed != '\0') {
                    error_occured = TRUE;
                } else {
                    set_address(&manual_addr[i], AT_IB, sizeof(guint16), manual_addr_data[i]);
                }
            } else {    /* GID */
                if (!str_to_ip6( gPREF_ID[i], manual_addr_data[i])) {
                    error_occured = TRUE;
                } else {
                    set_address(&manual_addr[i], AT_IB, GID_SIZE, manual_addr_data[i]);
                }
            }

            if (error_occured) {
                /* an invalid id was specified - disable manual settings until it's fixed */
                gPREF_MAN_EN = FALSE;
                break;
            }
        }

    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
