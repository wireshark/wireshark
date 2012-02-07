/*
 * Dissector for the Sony FeliCa Protocol
 *
 * References:
 * http://www.sony.net/Products/felica/business/tech-support/data/fl_usmnl_1.2.pdf
 * http://www.sony.net/Products/felica/business/tech-support/data/format_sequence_guidelines_1.1.pdf
 * http://code.google.com/u/101410204121169118393/updates
 * https://github.com/codebutler/farebot/wiki/Suica
 *
 * Copyright 2012, Tyson Key <tyson.key@gmail.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <ctype.h>
#include <stdio.h>

static int proto_felica = -1;

/* Commmand and response */
static int hf_felica_command = -1;
static int hf_felica_response = -1;

/* System Code */
static int hf_felica_sys_code = -1;

/* Timeslot */
static int hf_felica_timeslot = -1;

/* Manufacture ID/NFCID2 */
static int hf_felica_idm = -1;

/* Request Code */
static int hf_felica_req_code = -1;

/* Manufacture Parameter/PAD */
static int hf_felica_pnm = -1;

/* Number of Services */

static int hf_felica_nbr_of_svcs = -1;

static int hf_felica_svc_code = -1;

static int hf_felica_nbr_of_blocks = -1;
static int hf_felica_block_nbr = -1;

/* Status flag 1 */
static int hf_felica_status_flag1 = -1;

/* Status flag 2 */
static int hf_felica_status_flag2 = -1;

/* - Commands - */
#define CMD_POLLING 0x00
#define CMD_READ_WO_ENCRYPTION 0x06
#define CMD_WRITE_WO_ENCRYPTION 0x08

/* - Responses - */
#define RES_POLLING 0x01
#define RES_READ_WO_ENCRYPTION 0x07
#define RES_WRITE_WO_ENCRYPTION 0x09

/* - Request Codes - */
#define RC_NO_REQ 0x00
#define RC_SYS_REQ 0x01
#define RC_COM_PERF_REQ 0x02

/* - System Codes - */

/* FeliCa Lite/DFC */
#define SC_FELICA_LITE 0x88b4

/* NFC Forum NDEF */
#define SC_NFC_FORUM   0x12fc

/* Felica Networks' Common Area */
#define SC_FELICA_NW_COMMON_AREA 0xfe00

/* Japanese transit card */
#define SC_IRUCA       0xde80

/* "...return a response to the Polling command, regardless
     of its System Code" */

#define SC_DOUBLE_WILDCARD 0xffff

/* TODO: Since commands and responses do not have any overlapping values,
 * consider a single felica_opcodes[] value_string array encompassing both.
 * This would simplify the column update by only calling it in one place, i.e.:
 *      col_set_str(pinfo->cinfo, COL_INFO,
 *          val_to_str_const(opcode, felica_opcodes, "Unknown"));
 */
static const value_string felica_commands[] = {
    {CMD_POLLING, "Polling"},
    {CMD_READ_WO_ENCRYPTION, "Read Without Encryption"},
    {CMD_WRITE_WO_ENCRYPTION, "Write Without Encryption"},

    /* End of commands */
    {0x00, NULL}
};

static const value_string felica_responses[] = {
    {RES_POLLING, "Polling"},
    {RES_READ_WO_ENCRYPTION, "Read Without Encryption"},
    {RES_WRITE_WO_ENCRYPTION, "Write Without Encryption"},

    /* End of responses */
    {0x00, NULL}
};

static const value_string felica_req_codes[] = {
    {RC_NO_REQ, "No Request"},
    {RC_SYS_REQ, "System Code Request"},
    {RC_COM_PERF_REQ, "Communication Performance Request"},

    /* Others are reserved for future use */

    /* End of request codes */
    {0x00, NULL}
};

static const value_string felica_sys_codes[] = {
    {SC_FELICA_LITE, "FeliCa Lite"},
    {SC_NFC_FORUM, "NFC Forum (NDEF)"},
    {SC_FELICA_NW_COMMON_AREA, "FeliCa Networks Common Area"},
    {SC_IRUCA, "IruCa"},
    {SC_DOUBLE_WILDCARD, "Wildcard"},

    /* End of system codes */
    {0x00, NULL}
};

static dissector_handle_t data_handle=NULL;

/* Forward-declare the dissector functions */
static void dissect_felica(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Subtree handles: set by register_subtree_array */
static gint ett_felica = -1;

static void dissect_felica(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item;
    proto_tree *felica_tree = NULL;
    guint8 opcode;
    guint8 rwe_pos = 0;
    tvbuff_t *rwe_resp_data_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FeliCa");
    col_set_str(pinfo->cinfo, COL_INFO, "FeliCa Packet");

    if (tree) {
        /* Start with a top-level item to add everything else to */
        item = proto_tree_add_item(tree, proto_felica, tvb, 0, -1, ENC_NA);
        felica_tree = proto_item_add_subtree(item, ett_felica);
    }
    opcode = tvb_get_guint8(tvb, 0);

    switch (opcode) {

    case CMD_POLLING:
        col_set_str(pinfo->cinfo, COL_INFO, "Polling Request");
        if (tree) {
            proto_tree_add_item(felica_tree, hf_felica_command, tvb, 0, 1, ENC_NA);
            proto_tree_add_item(felica_tree, hf_felica_sys_code, tvb, 1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_req_code, tvb, 3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_timeslot, tvb, 4, 1, ENC_BIG_ENDIAN);
        }
        break;

    case RES_POLLING:
        col_set_str(pinfo->cinfo, COL_INFO, "Polling Response");
        if (tree) {
            proto_tree_add_item(felica_tree, hf_felica_response, tvb, 0, 1, ENC_NA);
            proto_tree_add_item(felica_tree, hf_felica_idm, tvb, 1, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_pnm, tvb, 9, 8, ENC_BIG_ENDIAN);

            if (tvb_reported_length(tvb) == 19)
                proto_tree_add_item(felica_tree, hf_felica_sys_code, tvb, 17, 2, ENC_BIG_ENDIAN);

            /*
             * Request data - 0 or 2 bytes long; data corresponding to request
             * code; only if request code of command packet is not 00 and
             * corresponds to request data
             */
        }
        break;

    case CMD_READ_WO_ENCRYPTION:
        col_set_str(pinfo->cinfo, COL_INFO, "Read Without Encryption Request");
        if (tree) {
            proto_tree_add_item(felica_tree, hf_felica_command, tvb, 0, 1, ENC_NA);
            proto_tree_add_item(felica_tree, hf_felica_idm, tvb, 1, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_nbr_of_svcs, tvb, 9, 1, ENC_BIG_ENDIAN);

            /* Service codes are always 2 bytes in length */

            /* There can technically be multiple Service Codes - although my traces only contain 1 */
            proto_tree_add_item(felica_tree, hf_felica_svc_code, tvb, 10, 2, ENC_BIG_ENDIAN);

            /* Number of Blocks - 1byte */
            proto_tree_add_item(felica_tree, hf_felica_nbr_of_blocks, tvb, 12, 1, ENC_BIG_ENDIAN);

            /* Iterate through the block list, and update the tree */
            for (rwe_pos = 0; rwe_pos < tvb_get_guint8(tvb, 12); rwe_pos++) {
                proto_tree_add_uint(felica_tree, hf_felica_block_nbr, tvb,
                    13 + 2 * rwe_pos, 2, tvb_get_guint8(tvb, 14 + 2 * rwe_pos));
            }
        }
        break;

    case RES_READ_WO_ENCRYPTION:
        col_set_str(pinfo->cinfo, COL_INFO, "Read Without Encryption Response");
        if (tree) {
            proto_tree_add_item(felica_tree, hf_felica_response, tvb, 0, 1, ENC_NA);
            proto_tree_add_item(felica_tree, hf_felica_idm, tvb, 1, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_status_flag1, tvb, 9, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_status_flag2, tvb, 10, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_nbr_of_blocks, tvb, 11, 1, ENC_BIG_ENDIAN);
        }
        rwe_resp_data_tvb = tvb_new_subset_remaining(tvb, 12);
        call_dissector(data_handle, rwe_resp_data_tvb, pinfo, tree);
        break;

    case CMD_WRITE_WO_ENCRYPTION:
        col_set_str(pinfo->cinfo, COL_INFO, "Write Without Encryption Request");
        /* TODO */
        break;

    case RES_WRITE_WO_ENCRYPTION:
        col_set_str(pinfo->cinfo, COL_INFO, "Write Without Encryption Response");
        /* TODO */
        break;

    default:
        col_set_str(pinfo->cinfo, COL_INFO, "Unknown");
        break;
    }
}

void
proto_register_felica(void)
{
    static hf_register_info hf[] = {

    {&hf_felica_command,
        { "Command", "felica.cmd", FT_UINT8, BASE_HEX,
        VALS(felica_commands), 0x0, NULL, HFILL }},
    {&hf_felica_response,
        { "Response", "felica.res", FT_UINT8, BASE_HEX,
        VALS(felica_responses), 0x0, NULL, HFILL }},

    /* Request Code */
    {&hf_felica_req_code,
        { "Request Code", "felica.req.code", FT_UINT8, BASE_HEX,
        VALS(felica_req_codes), 0x0, NULL, HFILL }},

    {&hf_felica_idm,
        { "IDm (Manufacture ID)/NFCID2", "felica.idm", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

    /* System Code */
    {&hf_felica_sys_code,
        { "System Code", "felica.sys_code", FT_UINT16, BASE_HEX,
        VALS(felica_sys_codes), 0x0, NULL, HFILL }},

    /* Service Code */
    {&hf_felica_svc_code,
        { "Service Code", "felica.svc_code", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

      /* Parameter/PAD */
    {&hf_felica_pnm,
        { "PNm (Manufacture Parameter)/PAD", "felica.pnm", FT_UINT64, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

    /* Number of Services */
    {&hf_felica_nbr_of_svcs,
        { "Number of Services", "felica.svcs", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    /* Number of Blocks */
    {&hf_felica_nbr_of_blocks,
        { "Number of Blocks", "felica.blocks", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    /* Block ID */
    {&hf_felica_block_nbr,
        { "Block Number", "felica.block.nbr", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    /* Status Flag 1 */
    {&hf_felica_status_flag1,
        { "Status Flag 1", "felica.status.flag1", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

    /* Status Flag 2 */
    {&hf_felica_status_flag2,
        { "Status Flag 2", "felica.status.flag2", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

    /* Timeslot */
    {&hf_felica_timeslot,
        { "Timeslot", "felica.timeslot", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_felica
    };

    proto_felica = proto_register_protocol("Sony FeliCa", "FeliCa", "felica");
    proto_register_field_array(proto_felica, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("felica", dissect_felica, proto_felica);
}

/* Handler registration */
void
proto_reg_handoff_felica(void)
{
    data_handle = find_dissector("data");
}
/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
