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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
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

static int
dissect_fcoib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        crc_offset;
    gint        eof_offset;
    gint        sof_offset;
    gint        frame_len;
    guint       version;
    const char *ver;
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
    fc_data_t   fc_data;

    frame_len = tvb_reported_length_remaining(tvb, 0) -
      FCOIB_HEADER_LEN - FCOIB_TRAILER_LEN;
    crc_offset = FCOIB_HEADER_LEN + frame_len;
    eof_offset = crc_offset + 4;
    sof_offset = FCOIB_HEADER_LEN - 1;

    if (frame_len <= 0)
        return 0;   /* this packet isn't even long enough to contain the header+trailer w/o FC payload! */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FCoIB");
    next_tvb = tvb_new_subset_length(tvb, FCOIB_HEADER_LEN, frame_len);

    /*
     * Only version 0 is defined at this point.
     * Don't print the version in the short summary if it is zero.
     */
    ver = "";
    version = tvb_get_guint8(tvb, 0 + FCOIB_VER_OFFSET) >> 4;
    if (version != 0)
        ver = wmem_strdup_printf(pinfo->pool, ver, "ver %d ", version);

    if (tvb_bytes_exist(tvb, 0, 1))
        sig = tvb_get_guint8(tvb, 0) >> 6;

    eof_str = "none";
    if (tvb_bytes_exist(tvb, eof_offset, 1)) {
        eof = tvb_get_guint8(tvb, eof_offset);
        eof_str = val_to_str(eof, fcoib_eof_vals, "0x%x");
    }

    sof_str = "none";
    if (tvb_bytes_exist(tvb, sof_offset, 1)) {
        sof = tvb_get_guint8(tvb, sof_offset);
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
        if (eof != FCOIB_EOFt) {
            fc_data.sof_eof |= FC_DATA_EOF_INVALID;
        }
    }

    /* Call the FC Dissector if this is carrying an FC frame */
    fc_data.ethertype = ETHERTYPE_UNK;

    if (fc_handle) {
        call_dissector_with_data(fc_handle, next_tvb, pinfo, tree, &fc_data);
    } else {
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

static gboolean
dissect_fcoib_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint        crc_offset;
    gint        eof_offset;
    gint        sof_offset;
    gint        frame_len;
    guint8      sof          = 0;
    guint8      eof          = 0;
    guint8      sig          = 0;

    frame_len = tvb_reported_length_remaining(tvb, 0) -
      FCOIB_HEADER_LEN - FCOIB_TRAILER_LEN;
    crc_offset = FCOIB_HEADER_LEN + frame_len;
    eof_offset = crc_offset + 4;
    sof_offset = FCOIB_HEADER_LEN - 1;

    if (frame_len <= 0)
        return FALSE;   /* this packet isn't even long enough to contain the header+trailer w/o FC payload! */

    /* we start off with some basic heuristics checks to make sure this could be a FCoIB packet */

    if (tvb_bytes_exist(tvb, 0, 1))
        sig = tvb_get_guint8(tvb, 0) >> 6;
    if (tvb_bytes_exist(tvb, eof_offset, 1))
        eof = tvb_get_guint8(tvb, eof_offset);
    if (tvb_bytes_exist(tvb, sof_offset, 1))
        sof = tvb_get_guint8(tvb, sof_offset);

    if (sig != 1)
        return FALSE;   /* the sig field in the FCoIB Encap. header MUST be 2'b01*/
    if (!tvb_bytes_exist(tvb, eof_offset + 1, 3) || tvb_get_ntoh24(tvb, eof_offset + 1) != 0)
        return FALSE;   /* 3 bytes of RESERVED field immediately after eEOF MUST be 0 */
    if (!try_val_to_str(sof, fcoib_sof_vals))
        return FALSE;   /* invalid value for SOF */
    if (!try_val_to_str(eof, fcoib_eof_vals))
        return FALSE;   /* invalid value for EOF */

    dissect_fcoib(tvb, pinfo, tree, data);
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

    fcoib_module = prefs_register_protocol(proto_fcoib, NULL);

    prefs_register_static_text_preference(fcoib_module, "use_decode_as",
        "Heuristic matching preferences removed.  Use Infiniband protocol preferences or Decode As.",
        "Simple heuristics can still be enable (may generate false positives) through Infiniband protocol preferences."
        "To force FCoIB dissection use Decode As");

    prefs_register_obsolete_preference(fcoib_module, "heur_en");
    prefs_register_obsolete_preference(fcoib_module, "manual_en");

    prefs_register_obsolete_preference(fcoib_module, "addr_a");
    prefs_register_obsolete_preference(fcoib_module, "addr_a_type");
    prefs_register_obsolete_preference(fcoib_module, "addr_a_id");
    prefs_register_obsolete_preference(fcoib_module, "addr_a_qp");

    prefs_register_obsolete_preference(fcoib_module, "addr_b");
    prefs_register_obsolete_preference(fcoib_module, "addr_b_type");
    prefs_register_obsolete_preference(fcoib_module, "addr_b_id");
    prefs_register_obsolete_preference(fcoib_module, "addr_b_qp");
}

void
proto_reg_handoff_fcoib(void)
{
    heur_dissector_add("infiniband.payload", dissect_fcoib_heur, "Fibre Channel over Infiniband", "fc_infiniband", proto_fcoib, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("infiniband", create_dissector_handle( dissect_fcoib, proto_fcoib ) );

    fc_handle = find_dissector_add_dependency("fc", proto_fcoib);
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
