/* packet-quic.c
 * Routines for Quick UDP Internet Connections dissection
 * Copyright 2013, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
QUIC Wire Layout Specification : https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/

QUIC source code in Chromium : https://code.google.com/p/chromium/codesearch#chromium/src/net/quic/quic_utils.h&sq=package:chromium

*/
#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_quic(void);
void proto_reg_handoff_quic(void);

static int proto_quic = -1;
static int hf_quic_puflags = -1;
static int hf_quic_puflags_vrsn = -1;
static int hf_quic_puflags_rst = -1;
static int hf_quic_puflags_cid = -1;
static int hf_quic_puflags_seq = -1;
static int hf_quic_puflags_rsv = -1;
static int hf_quic_cid = -1;
static int hf_quic_version = -1;
static int hf_quic_sequence = -1;
#if 0 /* Decode Private Flags is not yet ready... */
static int hf_quic_prflags = -1;
static int hf_quic_prflags_entropy = -1;
static int hf_quic_prflags_fecg = -1;
static int hf_quic_prflags_fec = -1;
static int hf_quic_prflags_rsv = -1;
#endif
static int hf_quic_payload = -1;

static guint g_quic_port = 80;
static guint g_quics_port = 443;

static gint ett_quic = -1;
static gint ett_quic_puflags = -1;
static gint ett_quic_prflags = -1;

#define QUIC_MIN_LENGTH 3

/**************************************************************************/
/*                      Public Flags                                      */
/**************************************************************************/
#define PUFLAGS_VRSN    0x01
#define PUFLAGS_RST     0x02
#define PUFLAGS_CID    0x0C
#define PUFLAGS_SEQ     0x30
#define PUFLAGS_RSV     0xC0

static const value_string puflags_cid_vals[] = {
    { 0, "0 Byte" },
    { 1, "1 Bytes" },
    { 2, "4 Bytes" },
    { 3, "8 Bytes" },
    { 0, NULL }
};

static const value_string puflags_seq_vals[] = {
    { 0, "1 Byte" },
    { 1, "2 Bytes" },
    { 2, "4 Bytes" },
    { 3, "6 Bytes" },
    { 0, NULL }
};

/**************************************************************************/
/*                      Private Flags                                     */
/**************************************************************************/
#define PRFLAGS_ENTROPY 0x01
#define PRFLAGS_FECG    0x02
#define PRFLAGS_FEC     0x04
#define PRFLAGS_RSV     0xF8

static int
dissect_quic_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti, *ti_puflags/*, *ti_prflags, *expert_ti*/;
    proto_tree *quic_tree, *puflags_tree/*, *prflags_tree*/;
    guint offset = 0;
    guint8 puflags, len_cid, len_seq;
    guint64 cid, seq;

    if (tvb_length(tvb) < QUIC_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUIC");

    ti = proto_tree_add_item(tree, proto_quic, tvb, 0, -1, ENC_NA);
    quic_tree = proto_item_add_subtree(ti, ett_quic);

    /* Public Flags */
    ti_puflags = proto_tree_add_item(quic_tree, hf_quic_puflags, tvb, offset, 1, ENC_NA);
    puflags_tree = proto_item_add_subtree(ti_puflags, ett_quic_puflags);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_vrsn, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_rst, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_cid, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_seq, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(puflags_tree, hf_quic_puflags_rsv, tvb, offset, 1, ENC_NA);

    puflags = tvb_get_guint8(tvb, offset);

    offset += 1;

    /* CID */

    /* Get len of CID (and CID), may be a more easy function to get the length... */
    switch((puflags & PUFLAGS_CID) >> 2){
        case 0:
            len_cid = 0;
            cid = 0;
        break;
        case 1:
            len_cid = 1;
            cid = tvb_get_guint8(tvb, offset);
        break;
        case 2:
            len_cid = 4;
            cid = tvb_get_letohl(tvb, offset);
        break;
        case 3:
            len_cid = 8;
            cid = tvb_get_letoh64(tvb, offset);
        break;
        default: /* It is only between 0..3 but Clang(Analyser) i don't like this... ;-) */
            len_cid = 8;
            cid = tvb_get_letoh64(tvb, offset);
        break;
    }

    if (len_cid) {
        proto_tree_add_item(quic_tree, hf_quic_cid, tvb, offset, len_cid, ENC_LITTLE_ENDIAN);
        offset += len_cid;
    }

    /* Version */
    if(puflags & PUFLAGS_VRSN){
        proto_tree_add_item(quic_tree, hf_quic_version, tvb, offset, 4, ENC_ASCII||ENC_NA);
        offset += 4;
    }

    /* Sequence */

    /* Get len of sequence (and sequence), may be a more easy function to get the length... */
    switch((puflags & PUFLAGS_SEQ) >> 4){
        case 0:
            len_seq = 1;
            seq = tvb_get_guint8(tvb, offset);
        break;
        case 1:
            len_seq = 2;
            seq = tvb_get_letohs(tvb, offset);
        break;
        case 2:
            len_seq = 4;
            seq = tvb_get_letohl(tvb, offset);
        break;
        case 3:
            len_seq = 6;
            seq = tvb_get_letoh48(tvb, offset);
        break;
        default: /* It is only between 0..3 but Clang(Analyser) i don't like this... ;-) */
            len_seq = 6;
            seq = tvb_get_letoh48(tvb, offset);
        break;
    }
    proto_tree_add_item(quic_tree, hf_quic_sequence, tvb, offset, len_seq, ENC_LITTLE_ENDIAN);
    offset += len_seq;

    col_add_fstr(pinfo->cinfo, COL_INFO, "CID: %" G_GINT64_MODIFIER "u, Seq: %" G_GINT64_MODIFIER "u", cid, seq);

#if 0 /* Decode Private Flags is not yet ready... */
    /* Private Flags */
    ti_prflags = proto_tree_add_item(quic_tree, hf_quic_prflags, tvb, offset, 1, ENC_NA);
    prflags_tree = proto_item_add_subtree(ti_prflags, ett_quic_prflags);
    proto_tree_add_item(prflags_tree, hf_quic_prflags_entropy, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(prflags_tree, hf_quic_prflags_fecg, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(prflags_tree, hf_quic_prflags_fec, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(prflags_tree, hf_quic_prflags_rsv, tvb, offset, 1, ENC_NA);
    offset +=1;
#endif

    /* Payload... (encrypted... TODO FIX !) */
    proto_tree_add_item(quic_tree, hf_quic_payload, tvb, offset, -1, ENC_NA);

    return offset;
}

static int
dissect_quic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data _U_)
{
    return dissect_quic_common(tvb, pinfo, tree, NULL);
}

static int
dissect_quics(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data _U_)
{
    return dissect_quic_common(tvb, pinfo, tree, NULL);
}

void
proto_register_quic(void)
{
    module_t *quic_module;

    static hf_register_info hf[] = {
        { &hf_quic_puflags,
            { "Public Flags", "quic.puflags",
               FT_UINT8, BASE_HEX, NULL, 0x0,
              "Specifying per-packet public flags", HFILL }
        },
        { &hf_quic_puflags_vrsn,
            { "Version", "quic.puflags.version",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PUFLAGS_VRSN,
              "Signifies that this packet also contains the version of the QUIC protocol", HFILL }
        },
        { &hf_quic_puflags_rst,
            { "Reset", "quic.puflags.reset",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PUFLAGS_RST,
              "Signifies that this packet is a public reset packet", HFILL }
        },
        { &hf_quic_puflags_cid,
            { "CID Length", "quic.puflags.cid",
               FT_UINT8, BASE_HEX, VALS(puflags_cid_vals), PUFLAGS_CID,
              "Signifies the Length of CID", HFILL }
        },
        { &hf_quic_puflags_seq,
            { "Sequence Length", "quic.puflags.seq",
               FT_UINT8, BASE_HEX, VALS(puflags_seq_vals), PUFLAGS_SEQ,
              "Signifies the Length of Sequence", HFILL }
        },
        { &hf_quic_puflags_rsv,
            { "Reserved", "quic.puflags.rsv",
               FT_UINT8, BASE_HEX, NULL, PUFLAGS_RSV,
              "Must be Zero", HFILL }
        },
        { &hf_quic_cid,
            { "CID", "quic.cid",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "Connection ID 64 bit pseudo random number", HFILL }
        },
        { &hf_quic_version,
            { "Version", "quic.version",
               FT_STRING, BASE_NONE, NULL, 0x0,
              "32 bit opaque tag that represents the version of the QUIC", HFILL }
        },
        { &hf_quic_sequence,
            { "Sequence", "quic.sequence",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              "The lower 8, 16, 32, or 48 bits of the sequence number", HFILL }
        },
#if 0 /* Decode Private Flags is not yet ready... */
        { &hf_quic_prflags,
            { "Private Flags", "quic.prflags",
               FT_UINT8, BASE_HEX, NULL, 0x0,
              "Specifying per-packet Private flags", HFILL }
        },
        { &hf_quic_prflags_entropy,
            { "Entropy", "quic.prflags.entropy",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PRFLAGS_ENTROPY,
              "For data packets, signifies that this packet contains the 1 bit of entropy, for fec packets, contains the xor of the entropy of protected packets", HFILL }
        },
        { &hf_quic_prflags_fecg,
            { "FEC Group", "quic.prflags.fecg",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PRFLAGS_FECG,
              "Indicates whether the fec byte is present.", HFILL }
        },
        { &hf_quic_prflags_fec,
            { "FEC", "quic.prflags.fec",
               FT_BOOLEAN, 8, TFS(&tfs_yes_no), PRFLAGS_FEC,
              "Signifies that this packet represents an FEC packet", HFILL }
        },
        { &hf_quic_prflags_rsv,
            { "Reserved", "quic.prflags.rsv",
               FT_UINT8, BASE_HEX, NULL, PRFLAGS_RSV,
              "Must be Zero", HFILL }
        },
#endif

        { &hf_quic_payload,
            { "Payload", "quic.payload",
               FT_BYTES, BASE_NONE, NULL, 0x0,
              "Quic Payload..", HFILL }
        },

    };


    static gint *ett[] = {
        &ett_quic,
        &ett_quic_puflags,
        &ett_quic_prflags
    };

    proto_quic = proto_register_protocol("QUIC (Quick UDP Internet Connections)",
            "QUIC", "quic");

    proto_register_field_array(proto_quic, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    quic_module = prefs_register_protocol(proto_quic, proto_reg_handoff_quic);


    prefs_register_uint_preference(quic_module, "udp.quic.port", "QUIC UDP Port",
            "QUIC UDP port if other than the default",
            10, &g_quic_port);

    prefs_register_uint_preference(quic_module, "udp.quics.port", "QUICS UDP Port",
            "QUICS (Secure) UDP port if other than the default",
            10, &g_quics_port);
}

void
proto_reg_handoff_quic(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t quic_handle;
    static dissector_handle_t quics_handle;
    static int current_quic_port;
    static int current_quics_port;

    if (!initialized) {
        quic_handle = new_create_dissector_handle(dissect_quic,
                proto_quic);
        quics_handle = new_create_dissector_handle(dissect_quics,
                proto_quic);
        initialized = TRUE;

    } else {
        dissector_delete_uint("udp.port", current_quic_port, quic_handle);
        dissector_delete_uint("udp.port", current_quics_port, quics_handle);
    }

    current_quic_port = g_quic_port;
    current_quics_port = g_quics_port;


    dissector_add_uint("udp.port", current_quic_port, quic_handle);
    dissector_add_uint("udp.port", current_quics_port, quics_handle);
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
