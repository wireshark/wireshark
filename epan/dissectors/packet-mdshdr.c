/* packet-mdshdr.c
 * Routines for dissection of Cisco MDS Switch Internal Header
 * Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
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
#include <epan/etypes.h>
#include <epan/prefs.h>
#include "packet-fc.h"

void proto_register_mdshdr(void);
void proto_reg_handoff_mdshdr(void);

#define MDSHDR_VERSION_OFFSET             0

/* Mdshdr Control bits */
#define MDSHDR_CTL_IDXDIRECT              1
#define MDSHDR_CTL_IGNACLO                2
#define MDSHDR_CTL_DRP                    4

/* OFFSETS OF FIELDS */
#define MDSHDR_VER_OFFSET                 0
#define MDSHDR_SOF_OFFSET                 1
#define MDSHDR_PKTLEN_OFFSET              2
#define MDSHDR_DIDX_OFFSET                5
#define MDSHDR_SIDX_OFFSET                6
#define MDSHDR_VSAN_OFFSET               13

/* Two size definitions are sufficient */
#define MDSHDR_SIZE_BYTE                 sizeof(gchar)
#define MDSHDR_SIZE_INT16                sizeof(guint16)
#define MDSHDR_SIZE_INT32                sizeof(guint32)

/* Other miscellaneous defines; can't rely on sizeof structs */
#define MDSHDR_MAX_VERSION                0
#define MDSHDR_HEADER_SIZE               16
#define MDSHDR_TRAILER_SIZE               6

/* SOF Encodings */
#define MDSHDR_SOFc1                     0x1
#define MDSHDR_SOFi1                     0x2
#define MDSHDR_SOFn1                     0x3
#define MDSHDR_SOFi2                     0x4
#define MDSHDR_SOFn2                     0x5
#define MDSHDR_SOFi3                     0x6
#define MDSHDR_SOFn3                     0x7
#define MDSHDR_SOFf                      0x8
#define MDSHDR_SOFc4                     0x9
#define MDSHDR_SOFi4                     0xa
#define MDSHDR_SOFn4                     0xb

/* EOF Encodings */
#define MDSHDR_EOFt                      0x1
#define MDSHDR_EOFdt                     0x2
#define MDSHDR_EOFa                      0x4
#define MDSHDR_EOFn                      0x3
#define MDSHDR_EOFdti                    0x6
#define MDSHDR_EOFni                     0x7
#define MDSHDR_EOFrt                     0xa
#define MDSHDR_EOFrti                    0xe
#define MDSHDR_EOF_UNKNOWN               0xb

/* Initialize the protocol and registered fields */
static int proto_mdshdr = -1;
static int hf_mdshdr_sof = -1;
static int hf_mdshdr_pkt_len = -1;
static int hf_mdshdr_dstidx = -1;
static int hf_mdshdr_srcidx = -1;
static int hf_mdshdr_vsan = -1;
static int hf_mdshdr_eof = -1;
static int hf_mdshdr_no_trailer = -1;
static int hf_mdshdr_span = -1;
static int hf_mdshdr_fccrc = -1;

/* Initialize the subtree pointers */
static gint ett_mdshdr = -1;
static gint ett_mdshdr_hdr = -1;
static gint ett_mdshdr_trlr = -1;

static dissector_handle_t fc_dissector_handle;

static gboolean decode_if_zero_etype = FALSE;

static const value_string sof_vals[] = {
    {MDSHDR_SOFc1,               "SOFc1"},
    {MDSHDR_SOFi1,               "SOFi1"},
    {MDSHDR_SOFn1,               "SOFn1"},
    {MDSHDR_SOFi2,               "SOFi2"},
    {MDSHDR_SOFn2,               "SOFn2"},
    {MDSHDR_SOFi3,               "SOFi3"},
    {MDSHDR_SOFn3,               "SOFn3"},
    {MDSHDR_SOFc4,               "SOFc4"},
    {MDSHDR_SOFi4,               "SOFi4"},
    {MDSHDR_SOFn4,               "SOFn4"},
    {MDSHDR_SOFf,                "SOFf"},
    {0,                         NULL},
};

static const value_string eof_vals[] = {
    {MDSHDR_EOFt,                "EOFt"},
    {MDSHDR_EOFdt,               "EOFdt"},
    {MDSHDR_EOFa,                "EOFa"},
    {MDSHDR_EOFn,                "EOFn"},
    {MDSHDR_EOFdti,              "EOFdti"},
    {MDSHDR_EOFni,               "EOFni"},
    {MDSHDR_EOFrt,               "EOFrt"},
    {MDSHDR_EOFrti,              "EOFrti"},
    /*{MDSHDR_EOF_UNKNOWN,         ""}, intentionally removed*/
    {0,                          NULL},
};

static int
dissect_mdshdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti_main;
    proto_item *hidden_item;
    proto_tree *mdshdr_tree_main, *mdshdr_tree_hdr, *mdshdr_tree_trlr;
    int         offset        = 0;
    guint       pktlen;
    tvbuff_t   *next_tvb;
    guint8      sof, eof;
    int         trailer_start = 0; /*0 means "no trailer found"*/
    fc_data_t fc_data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MDS Header");

    col_clear(pinfo->cinfo, COL_INFO);

    sof     = tvb_get_guint8(tvb, offset+MDSHDR_SOF_OFFSET) & 0x0F;
    pktlen  = tvb_get_ntohs(tvb, offset+MDSHDR_PKTLEN_OFFSET) & 0x1FFF;

    /* The Mdshdr trailer is at the end of the frame */
    if ((tvb_captured_length(tvb) >= (MDSHDR_HEADER_SIZE + pktlen))
        /* Avoid header/trailer overlap if something wrong */
        && (pktlen >= MDSHDR_TRAILER_SIZE))  {
        trailer_start = MDSHDR_HEADER_SIZE + pktlen - MDSHDR_TRAILER_SIZE;

        eof = tvb_get_guint8(tvb, trailer_start);
        tvb_set_reported_length(tvb, MDSHDR_HEADER_SIZE+pktlen);
    }
    else {
        eof = MDSHDR_EOF_UNKNOWN;
    }

    fc_data.sof_eof = 0;

    if ((sof == MDSHDR_SOFi3) || (sof == MDSHDR_SOFi2) || (sof == MDSHDR_SOFi1)
        || (sof == MDSHDR_SOFi4)) {
        fc_data.sof_eof = FC_DATA_SOF_FIRST_FRAME;
    }
    else if (sof == MDSHDR_SOFf) {
        fc_data.sof_eof = FC_DATA_SOF_SOFF;
    }

    if (eof != MDSHDR_EOFn) {
        fc_data.sof_eof |= FC_DATA_EOF_LAST_FRAME;
    }
    else if (eof != MDSHDR_EOFt) {
        fc_data.sof_eof |= FC_DATA_EOF_INVALID;
    }

    if (tree) {
        ti_main = proto_tree_add_protocol_format(tree, proto_mdshdr, tvb, 0,
                                                 MDSHDR_HEADER_SIZE+pktlen,
                                                 "MDS Header(%s/%s)",
                                                 val_to_str(sof, sof_vals, "Unknown(%u)"),
                                                 val_to_str(eof, eof_vals, "Unknown(%u)"));

        mdshdr_tree_main = proto_item_add_subtree(ti_main, ett_mdshdr);

        /* Add Header part as subtree first */
        mdshdr_tree_hdr = proto_tree_add_subtree(mdshdr_tree_main, tvb, MDSHDR_VER_OFFSET,
                                     MDSHDR_HEADER_SIZE, ett_mdshdr_hdr, NULL, "MDS Header");

        hidden_item = proto_tree_add_item(mdshdr_tree_hdr, hf_mdshdr_sof, tvb, MDSHDR_SOF_OFFSET,
                                          MDSHDR_SIZE_BYTE, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(hidden_item);
        proto_tree_add_item(mdshdr_tree_hdr, hf_mdshdr_pkt_len, tvb, MDSHDR_PKTLEN_OFFSET,
                            MDSHDR_SIZE_INT16, ENC_BIG_ENDIAN);
        proto_tree_add_item(mdshdr_tree_hdr, hf_mdshdr_dstidx, tvb, MDSHDR_DIDX_OFFSET,
                            MDSHDR_SIZE_INT16, ENC_BIG_ENDIAN);
        proto_tree_add_item(mdshdr_tree_hdr, hf_mdshdr_srcidx, tvb, MDSHDR_SIDX_OFFSET,
                            MDSHDR_SIZE_INT16, ENC_BIG_ENDIAN);
        proto_tree_add_item(mdshdr_tree_hdr, hf_mdshdr_vsan, tvb, MDSHDR_VSAN_OFFSET,
                            MDSHDR_SIZE_INT16, ENC_BIG_ENDIAN);
        hidden_item = proto_tree_add_item(mdshdr_tree_hdr, hf_mdshdr_span,
                                          tvb, MDSHDR_VSAN_OFFSET,
                                          MDSHDR_SIZE_INT16, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_HIDDEN(hidden_item);

        /* Add Mdshdr Trailer part */
        if (tvb_reported_length(tvb) >= MDSHDR_HEADER_SIZE + pktlen
            && 0 != trailer_start) {
            mdshdr_tree_trlr = proto_tree_add_subtree(mdshdr_tree_main, tvb, trailer_start,
                                          MDSHDR_TRAILER_SIZE,
                                          ett_mdshdr_trlr, NULL, "MDS Trailer");

            proto_tree_add_item(mdshdr_tree_trlr, hf_mdshdr_eof, tvb,
                                trailer_start, MDSHDR_SIZE_BYTE, ENC_BIG_ENDIAN);
            proto_tree_add_item(mdshdr_tree_trlr, hf_mdshdr_fccrc, tvb,
                                trailer_start+2, MDSHDR_SIZE_INT32, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(mdshdr_tree_main, hf_mdshdr_no_trailer, tvb, 0, 0, ENC_NA);
        }
    }

    if (tvb_reported_length(tvb) >= MDSHDR_HEADER_SIZE + pktlen
        && 0 != pktlen /*if something wrong*/) {
        next_tvb = tvb_new_subset_length(tvb, MDSHDR_HEADER_SIZE, pktlen);
        /* XXX what to do with the rest of this frame? --ArtemTamazov */
    }
    else {
        next_tvb = tvb_new_subset_remaining(tvb, MDSHDR_HEADER_SIZE);
    }

    /* Call the Fibre Channel dissector */
    if (fc_dissector_handle) {
        fc_data.ethertype = ETHERTYPE_FCFT;
        call_dissector_with_data(fc_dissector_handle, next_tvb, pinfo, tree, &fc_data);
    }
    else {
        call_data_dissector(next_tvb, pinfo, tree);
    }
    return tvb_captured_length(tvb);
}


void
proto_register_mdshdr(void)
{

    static hf_register_info hf[] = {
        { &hf_mdshdr_sof,
          {"SOF", "mdshdr.sof", FT_UINT8, BASE_DEC, VALS(sof_vals), 0x0, NULL, HFILL}},

        { &hf_mdshdr_pkt_len,
          {"Packet Len", "mdshdr.plen", FT_UINT16, BASE_DEC, NULL, 0x1FFF, NULL, HFILL}},

        { &hf_mdshdr_dstidx,
          {"Dst Index", "mdshdr.dstidx", FT_UINT16, BASE_HEX, NULL, 0xFFC, NULL, HFILL}},

        { &hf_mdshdr_srcidx,
          {"Src Index", "mdshdr.srcidx", FT_UINT16, BASE_HEX, NULL, 0x3FF, NULL, HFILL}},

        { &hf_mdshdr_vsan,
          {"VSAN", "mdshdr.vsan", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL}},

        { &hf_mdshdr_eof,
          {"EOF", "mdshdr.eof", FT_UINT8, BASE_DEC, VALS(eof_vals), 0x0, NULL, HFILL}},

        { &hf_mdshdr_no_trailer,
          {"MDS Trailer: Not Found", "mdshdr.no_trailer", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        { &hf_mdshdr_span,
          {"SPAN Frame", "mdshdr.span", FT_UINT16, BASE_DEC, NULL, 0xF000, NULL, HFILL}},

        { &hf_mdshdr_fccrc,
          {"CRC", "mdshdr.crc", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mdshdr,
        &ett_mdshdr_hdr,
        &ett_mdshdr_trlr
    };
    module_t *mdshdr_module;

/* Register the protocol name and description */
    proto_mdshdr = proto_register_protocol("MDS Header", "MDS Header", "mdshdr");

    proto_register_field_array(proto_mdshdr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    mdshdr_module = prefs_register_protocol(proto_mdshdr, proto_reg_handoff_mdshdr);
    prefs_register_bool_preference(mdshdr_module, "decode_if_etype_zero",
                                   "Decode as MDS Header if Ethertype == 0",
                                   "A frame is considered for decoding as MDSHDR if either "
                                   "ethertype is 0xFCFC or zero. Turn this flag off if you "
                                   "don't want ethertype zero to be decoded as MDSHDR. "
                                   "This might be useful to avoid problems with test frames.",
                                   &decode_if_zero_etype);
}

void
proto_reg_handoff_mdshdr(void)
{
    static dissector_handle_t mdshdr_handle;
    static gboolean           registered_for_zero_etype = FALSE;
    static gboolean           mdshdr_prefs_initialized  = FALSE;

    if (!mdshdr_prefs_initialized) {
        /*
         * This is the first time this has been called (i.e.,
         * Wireshark/TShark is starting up), so create a handle for
         * the MDS Header dissector, register the dissector for
         * ethertype ETHERTYPE_FCFT, and fetch the data and Fibre
         * Channel handles.
         */
        mdshdr_handle = create_dissector_handle(dissect_mdshdr, proto_mdshdr);
        dissector_add_uint("ethertype", ETHERTYPE_FCFT, mdshdr_handle);
        fc_dissector_handle = find_dissector_add_dependency("fc", proto_mdshdr);
        mdshdr_prefs_initialized = TRUE;
    }

    /*
     * Only register the dissector for ethertype 0 if the preference
     * is set to do so.
     */
    if (decode_if_zero_etype) {
        /*
         * The preference to register for ethertype ETHERTYPE_UNK (0)
         * is set; if we're not registered for ethertype ETHERTYPE_UNK,
         * do so.
         */
        if (!registered_for_zero_etype) {
            dissector_add_uint("ethertype", ETHERTYPE_UNK, mdshdr_handle);
            registered_for_zero_etype = TRUE;
        }
    } else {
        /*
         * The preference to register for ethertype ETHERTYPE_UNK (0)
         * is not set; if we're registered for ethertype ETHERTYPE_UNK,
         * undo that registration.
         */
        if (registered_for_zero_etype) {
            dissector_delete_uint("ethertype", ETHERTYPE_UNK, mdshdr_handle);
            registered_for_zero_etype = FALSE;
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
