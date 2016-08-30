/* packet-pcli.c
 * Routines for Packet Cable Lawful Intercept packet disassembly
 *
 * Packet Cable Lawful Intercept is described by various PacketCable/CableLabs
 * specs.
 *
 * One spec is PacketCable(TM) Electronic Surveillance Specification
 * PKT-SP-ESP-I01-991229, the front page of which speaks of it as
 * being "Interim".  It does not appear to be available from the
 * CableLabs Web site, but is available through the Wayback Machine
 * at
 *
 *     http://web.archive.org/web/20030428211154/http://www.packetcable.com/downloads/specs/pkt-sp-esp-I01-991229.pdf
 *
 * See Section 4 "Call Content Connection Interface".  In that spec, the
 * packets have a 4-octet Call Content Connection (CCC) Identifier, followed
 * by the Intercepted Information.  The Intercepted Information is an IP
 * datagram, starting with an IP header.
 *
 * However, later specifications, such as PacketCable(TM) 1.5 Specifications,
 * Electronic Surveillance, PKT-SP-ESP1.5-I02-070412, at
 *
 *    http://www.cablelabs.com/wp-content/uploads/specdocs/PKT-SP-ESP1.5-I02-070412.pdf
 *
 * the front page of which speaks of it as being "ISSUED", in Section 5 "Call
 * Content Connection Interface", gives a header with a 4-octet CCC
 * Identifier followed by an 8-byte NTP-format timestamp.
 *
 * The PacketCable(TM) 2.0, PacketCable Electronic Surveillance Delivery
 * Function to Collection Function Interface Specification,
 * PKT-SP-ES-DCI-C01-140314, at
 *
 *     http://www.cablelabs.com/wp-content/uploads/specdocs/PKT-SP-ES-DCI-C01-140314.pdf
 *
 * which speaks of it as being "CLOSED" ("A static document, reviewed,
 * tested, validated, and closed to further engineering change requests to
 * the specification through CableLabs."), shows in section 7 "CALL CONTENT
 * CONNECTION (CCC) INTERFACE", a header with the 4-octet CCC Identifier,
 * the 8-byte NTP-format timestamp, and an 8-octet Case ID.
 *
 * So we may need a preference for the version.
 *
 * Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#include "config.h"

#include <epan/decode_as.h>
#include <epan/packet.h>
#include <epan/prefs.h>

void proto_register_pcli(void);
void proto_reg_handoff_pcli(void);

/* Define the pcli proto */

static int proto_pcli = -1;
static int proto_pcli8 = -1;
static int proto_pcli12 = -1;
static int proto_pcli20 = -1;

/* Define headers for pcli */

static int hf_pcli_cccid = -1;
static int hf_pcli_header = -1;
static int hf_pcli_timestamp = -1;
static int hf_pcli_case_id = -1;

/* Define the tree for pcli */

static int ett_pcli = -1;

/*
 * Here are the global variables associated with the preferences
 * for pcli
 */

static gboolean pcli_summary_in_tree = TRUE;

static dissector_table_t    pcli_subdissector_table;

static proto_tree *
dissect_pcli_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int* offset)
{
    guint32 cccid;
    proto_tree *pcli_tree;
    proto_item *pcli_item;

    /* Set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCLI");

    /*
     *If we have a non-null tree (ie we are building the proto_tree
     * instead of just filling out the columns ), then add a PLCI
     * tree node and put a CCCID header element under it.
     */
    pcli_item = proto_tree_add_item(tree, proto_pcli, tvb, *offset, 4, ENC_NA);
    pcli_tree = proto_item_add_subtree(pcli_item, ett_pcli);
    proto_tree_add_item_ret_uint(pcli_tree, hf_pcli_cccid, tvb, *offset, 4, ENC_BIG_ENDIAN, &cccid);
    (*offset) += 4;
    if (pcli_summary_in_tree) {
        proto_item_append_text(pcli_item, ", CCCID: %u", cccid);
    }

    /* Set the info column */
    col_add_fstr(pinfo->cinfo, COL_INFO, "CCCID: %u", cccid);

    return pcli_tree;
}

static void
dissect_pcli_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    tvbuff_t * next_tvb;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    /*
     * Implement "Decode As", as PCLI doesn't
     * have a unique identifier to determine subdissector
     */
    if (!dissector_try_uint(pcli_subdissector_table, 0, next_tvb, pinfo, tree)) {
        call_data_dissector(next_tvb, pinfo, tree);
    }
}

static int
dissect_pcli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;

    dissect_pcli_common(tvb, pinfo, tree, &offset);

    dissect_pcli_payload(tvb, pinfo, tree, offset);
    return tvb_captured_length(tvb);
}

static int
dissect_pcli8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *pcli_tree;
    int offset = 0;

    pcli_tree = dissect_pcli_common(tvb, pinfo, tree, &offset);

    proto_tree_add_item(pcli_tree, hf_pcli_header, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    dissect_pcli_payload(tvb, pinfo, tree, offset);
    return tvb_captured_length(tvb);
}

static int
dissect_pcli12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *pcli_tree;
    int offset = 0;

    pcli_tree = dissect_pcli_common(tvb, pinfo, tree, &offset);

    proto_tree_add_item(pcli_tree, hf_pcli_timestamp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
    offset += 8;

    dissect_pcli_payload(tvb, pinfo, tree, offset);
    return tvb_captured_length(tvb);
}

static int
dissect_pcli20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *pcli_tree;
    int offset = 0;

    pcli_tree = dissect_pcli_common(tvb, pinfo, tree, &offset);

    proto_tree_add_item(pcli_tree, hf_pcli_timestamp, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(pcli_tree, hf_pcli_case_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    dissect_pcli_payload(tvb, pinfo, tree, offset);
    return tvb_captured_length(tvb);
}

static void
pcli_prompt(packet_info *pinfo _U_, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "PCLI payload as");
}

static gpointer
pcli_value(packet_info *pinfo _U_)
{
    return NULL;
}

void
proto_register_pcli(void)
{
    static hf_register_info hf[] = {
        { &hf_pcli_cccid,
            { "CCCID", "pcli.cccid", FT_UINT32, BASE_DEC, NULL, 0x0,
              "Call Content Connection Identifier", HFILL }},
        { &hf_pcli_header,
            { "CCCID", "pcli.header", FT_UINT32, BASE_HEX, NULL, 0x0,
              "Part of 8 byte header (including CCCID?)", HFILL }},
        { &hf_pcli_timestamp,
            { "Timestamp", "pcli.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
              NULL, HFILL }},
        { &hf_pcli_case_id,
            { "Case ID", "pcli.case_id", FT_UINT64, BASE_HEX, NULL, 0x0,
              NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_pcli,
    };

    module_t *pcli_module;

    /* Decode As handling */
    static build_valid_func pcli_payload_da_build_value[1] = {pcli_value};
    static decode_as_value_t pcli_payload_da_values = {pcli_prompt, 1, pcli_payload_da_build_value};
    static decode_as_t pcli_payload_da = {
        "pcli", "PCLI payload", "pcli.payload", 1, 0,
        &pcli_payload_da_values, NULL, NULL,
        decode_as_default_populate_list,
        decode_as_default_reset,
        decode_as_default_change,
        NULL,
    };

    proto_pcli = proto_register_protocol("Packet Cable Lawful Intercept", "PCLI", "pcli");
    /* Create "placeholders" to remove confusion with Decode As" */
    proto_pcli8 = proto_register_protocol("Packet Cable Lawful Intercept (8 byte CCCID)", "PCLI8 (8 byte CCCID)", "pcli8");
    proto_pcli12 = proto_register_protocol("Packet Cable Lawful Intercept (timestamp)", "PCLI12 (timestamp)", "pcli12");
    proto_pcli20 = proto_register_protocol("Packet Cable Lawful Intercept (timestamp, case ID)", "PCLI20 (timestamp, case ID)", "pcli20");

    proto_register_field_array(proto_pcli,hf,array_length(hf));
    proto_register_subtree_array(ett,array_length(ett));

    pcli_module = prefs_register_protocol(proto_pcli, proto_reg_handoff_pcli);
    prefs_register_obsolete_preference(pcli_module, "udp_port");

    prefs_register_bool_preference(pcli_module, "summary_in_tree",
        "Show PCLI summary in protocol tree",
        "Whether the PCLI summary line should be shown in the protocol tree",
        &pcli_summary_in_tree);

    pcli_subdissector_table = register_dissector_table(
        "pcli.payload", "PCLI payload dissector",
        proto_pcli, FT_UINT32, BASE_DEC);

    register_decode_as(&pcli_payload_da);
}

/* The registration hand-off routing */

void
proto_reg_handoff_pcli(void)
{
    static gboolean pcli_initialized = FALSE;
    static dissector_handle_t pcli_handle, pcli_handle8, pcli_handle12, pcli_handle20;

    if(!pcli_initialized) {
        pcli_handle = create_dissector_handle(dissect_pcli, proto_pcli);
        pcli_handle8 = create_dissector_handle(dissect_pcli8, proto_pcli8);
        pcli_handle12 = create_dissector_handle(dissect_pcli12, proto_pcli12);
        pcli_handle20 = create_dissector_handle(dissect_pcli20, proto_pcli20);
        pcli_initialized = TRUE;
    }

    dissector_add_for_decode_as("udp.port", pcli_handle);
    dissector_add_for_decode_as("udp.port", pcli_handle8);
    dissector_add_for_decode_as("udp.port", pcli_handle12);
    dissector_add_for_decode_as("udp.port", pcli_handle20);
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
