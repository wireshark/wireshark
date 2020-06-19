/* packet-smp.c
 * Routines for Session Multiplex Protocol (SMP) dissection
 * January 2017 Uli Heilmeier with the help of Michael Mann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * References:
 *
 *    MC-SMP - https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-smp
 *    MS-TDS - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds
 *    https://docs.microsoft.com/en-us/sql/relational-databases/native-client/features/using-multiple-active-result-sets-mars
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |       SMID    |     FLAGS     |               SID             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           LENGTH                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           SEQNUM                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                            WNDW                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    /                         DATA (variable)                       /
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>

#include "packet-tcp.h"

void proto_reg_handoff_smp(void);
void proto_register_smp(void);

static int proto_smp = -1;

static int hf_smp_smid = -1;
static int hf_smp_flags = -1;
static int hf_smp_flags_syn = -1;
static int hf_smp_flags_ack = -1;
static int hf_smp_flags_fin = -1;
static int hf_smp_flags_data = -1;
static int hf_smp_sid = -1;
static int hf_smp_length = -1;
static int hf_smp_seqnum = -1;
static int hf_smp_wndw = -1;
static int hf_smp_data = -1;

static gint ett_smp = -1;
static gint ett_smp_flags = -1;

#define SMP_FLAGS_SYN  0x01
#define SMP_FLAGS_ACK  0x02
#define SMP_FLAGS_FIN  0x04
#define SMP_FLAGS_DATA 0x08

#define SMP_MIN_LENGTH 16

static dissector_handle_t tds_handle;
static dissector_table_t smp_payload_table;

static gboolean reassemble_smp = TRUE;

static void smp_prompt(packet_info *pinfo _U_, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Payload as");
}

/* Code to actually dissect the packets */
static int
dissect_smp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean tds_payload)
{
    guint offset = 0;
    guint remaining_bytes;
    proto_item *ti;
    proto_tree *smp_tree;
    guint32 flags, sid, smp_length;
    tvbuff_t* next_tvb;
    int parsed_bytes;
    static int * const flag_fields[] = {
        &hf_smp_flags_syn,
        &hf_smp_flags_ack,
        &hf_smp_flags_fin,
        &hf_smp_flags_data,
        NULL
    };

    if (tvb_reported_length(tvb) < SMP_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_smp, tvb, 0, -1, ENC_NA);
    smp_tree = proto_item_add_subtree(ti, ett_smp);

    proto_tree_add_item(smp_tree, hf_smp_smid, tvb, offset, 1, ENC_NA);
    offset+=1;

    proto_tree_add_bitmask(smp_tree, tvb, offset, hf_smp_flags, ett_smp_flags, flag_fields, ENC_NA);
    flags = tvb_get_guint8(tvb, offset);
    offset += 1;

    proto_tree_add_item_ret_uint(smp_tree, hf_smp_sid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sid);
    col_append_fstr(pinfo->cinfo, COL_INFO, "SID: %u", sid);
    offset += 2;

    if (flags & SMP_FLAGS_SYN)
        col_append_str(pinfo->cinfo, COL_INFO, ", Syn");
    if (flags & SMP_FLAGS_ACK)
        col_append_str(pinfo->cinfo, COL_INFO, ", Ack");
    if (flags & SMP_FLAGS_FIN)
        col_append_str(pinfo->cinfo, COL_INFO, ", Fin");
    if (flags & SMP_FLAGS_DATA)
        col_append_str(pinfo->cinfo, COL_INFO, ", Data");

    proto_tree_add_item_ret_uint(smp_tree, hf_smp_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &smp_length);
    offset += 4;

    proto_tree_add_item(smp_tree, hf_smp_seqnum, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(smp_tree, hf_smp_wndw, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    if ((flags & SMP_FLAGS_DATA) && (tvb_reported_length(tvb) > SMP_MIN_LENGTH)) {

        next_tvb = tvb_new_subset_remaining(tvb, offset);
        if (tds_payload) {
            parsed_bytes = call_dissector(tds_handle, next_tvb, pinfo, tree);
        } else {
            parsed_bytes = dissector_try_payload(smp_payload_table, next_tvb, pinfo, tree);
        }
        if (parsed_bytes <= 0)
        {
            remaining_bytes = tvb_reported_length_remaining(tvb, offset);
            if ( remaining_bytes < (smp_length - SMP_MIN_LENGTH)) {
                // Fragmented
                proto_tree_add_item(smp_tree, hf_smp_data, tvb, offset, remaining_bytes, ENC_NA);
                offset += remaining_bytes;
            }
            else {
                proto_tree_add_item(smp_tree, hf_smp_data, tvb, offset, smp_length - SMP_MIN_LENGTH, ENC_NA);
                offset += (smp_length - SMP_MIN_LENGTH);
            }
        }
        else {
            offset += parsed_bytes;
        }
    }

    return offset;
}

static guint get_smp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return tvb_get_letohl(tvb, offset + 4);
}

static int
dissect_smp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_smp_common(tvb, pinfo, tree, FALSE);
}

static int dissect_smp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    if ((tvb_reported_length(tvb) > 0) && (tvb_get_guint8(tvb, 0) == 0x53)) {
        tcp_dissect_pdus(tvb, pinfo, tree, reassemble_smp, SMP_MIN_LENGTH,
                     get_smp_pdu_len, dissect_smp_pdu, data);

        return tvb_captured_length(tvb);
    }

    return 0;
}

static int
dissect_smp_tds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_smp_common(tvb, pinfo, tree, TRUE);
}

void
proto_register_smp(void)
{
    static hf_register_info hf[] = {
        { &hf_smp_smid,
          { "Smid", "smp.smid", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_smp_flags,
          { "Flags", "smp.flags", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_smp_flags_syn,
          { "Syn", "smp.flags.syn", FT_BOOLEAN, 8, TFS(&tfs_set_notset), SMP_FLAGS_SYN, NULL, HFILL }},
        { &hf_smp_flags_ack,
          { "Ack", "smp.flags.ack", FT_BOOLEAN, 8, TFS(&tfs_set_notset), SMP_FLAGS_ACK, NULL, HFILL }},
        { &hf_smp_flags_fin,
          { "Fin", "smp.flags.fin", FT_BOOLEAN, 8, TFS(&tfs_set_notset), SMP_FLAGS_FIN, NULL, HFILL }},
        { &hf_smp_flags_data,
          { "Data", "smp.flags.data", FT_BOOLEAN, 8, TFS(&tfs_set_notset), SMP_FLAGS_DATA, NULL, HFILL }},
        { &hf_smp_sid,
          { "SID", "smp.sid", FT_UINT16, BASE_DEC, NULL, 0, "Session ID", HFILL }},
        { &hf_smp_length,
          { "Length", "smp.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_smp_seqnum,
          { "SeqNum", "smp.seqnum", FT_UINT32, BASE_HEX, NULL, 0, "Sequence Number", HFILL }},
        { &hf_smp_wndw,
          { "Wndw", "smp.wndw", FT_UINT32, BASE_HEX, NULL, 0, "Window Size", HFILL }},
        { &hf_smp_data,
          { "Data", "smp.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_smp,
        &ett_smp_flags,
    };

    module_t *smp_module;

    proto_smp = proto_register_protocol("Session Multiplex Protocol", "SMP", "smp");

    proto_register_field_array(proto_smp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("smp_tds", dissect_smp_tds, proto_smp);

    smp_payload_table = register_decode_as_next_proto(proto_smp, "smp.payload", "SMP Payload", smp_prompt);

    smp_module = prefs_register_protocol(proto_smp, NULL);
    prefs_register_bool_preference(smp_module, "desegment",
          "Reassemble SMP messages spanning multiple TCP segments",
          "Whether the SMP dissector should reassemble messages spanning multiple TCP segments."
          " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
          &reassemble_smp);
}

void
proto_reg_handoff_smp(void)
{
    dissector_handle_t smp_handle;
    smp_handle = create_dissector_handle(dissect_smp, proto_smp);
    dissector_add_for_decode_as_with_preference("tcp.port", smp_handle);

    tds_handle = find_dissector_add_dependency("tds", proto_smp);
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
