/*
 * Dissector for the Sony FeliCa Protocol
 *
 * References:
 * http://www.sony.net/Products/felica/business/tech-support/data/fl_usmnl_1.2.pdf
 * http://www.sony.net/Products/felica/business/tech-support/data/fp_usmnl_1.11.pdf
 * http://www.sony.net/Products/felica/business/tech-support/data/format_sequence_guidelines_1.1.pdf
 * http://www.sony.net/Products/felica/business/tech-support/data/card_usersmanual_2.0.pdf
 * http://code.google.com/u/101410204121169118393/updates
 * https://github.com/codebutler/farebot/wiki/Suica
 *
 * Copyright 2012, Tyson Key <tyson.key@gmail.com>
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
 *
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_felica(void);

static int proto_felica = -1;

/* Opcodes */
static int hf_felica_opcode = -1;

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
#define CMD_REQ_SVC 0x02
#define CMD_REQ_RES 0x04
#define CMD_READ_WO_ENCRYPTION 0x06
#define CMD_WRITE_WO_ENCRYPTION 0x08
#define CMD_SEARCH_SVC_CODE 0x0A
#define CMD_REQ_SYS_CODE 0x0C
#define CMD_AUTH_1 0x10
#define CMD_AUTH_2 0x12
#define CMD_READ 0x14
#define CMD_WRITE 0x16
#define CMD_REQ_SVC_V2 0x32
#define CMD_REQ_SYS_STATUS 0x38
#define CMD_REQ_SPEC_VER 0x3C
#define CMD_RESET_MODE 0x3E
#define CMD_AUTH1_V2 0x40
#define CMD_AUTH2_V2 0x42
#define CMD_READ_V2 0x44
#define CMD_WRITE_V2 0x46
#define CMD_REQ_UPDATE_RAND_ID 0x4C

/* - Responses - */
#define RES_POLLING 0x01
#define RES_REQ_SVC 0x03
#define RES_REQ_RES 0x05
#define RES_READ_WO_ENCRYPTION 0x07
#define RES_WRITE_WO_ENCRYPTION 0x09
#define RES_SEARCH_SVC_CODE 0x0B
#define RES_REQ_SYS_CODE 0x0D
#define RES_AUTH_1 0x11
#define RES_AUTH_2 0x13
#define RES_READ 0x15
#define RES_WRITE 0x17
#define RES_REQ_SVC_V2 0x33
#define RES_REQ_SYS_STATUS 0x39
#define RES_REQ_SPEC_VER 0x3D
#define RES_RESET_MODE 0x3F
#define RES_AUTH1_V2 0x41
#define RES_AUTH2_V2 0x43
#define RES_READ_V2 0x45
#define RES_WRITE_V2 0x47
#define RES_REQ_UPDATE_RAND_ID 0x4D

/* - Request Codes - */
#define RC_NO_REQ 0x00
#define RC_SYS_REQ 0x01
#define RC_COM_PERF_REQ 0x02

/* - System Codes - */

/* FeliCa Lite/DFC */
#define SC_FELICA_LITE 0x88b4

/* NFC Forum NDEF */
#define SC_NFC_FORUM   0x12fc

/* FeliCa Networks' Common Area */
#define SC_FELICA_NW_COMMON_AREA 0xfe00

/* FeliCa Plug (NFC Dynamic Tag) */
#define SC_FELICA_PLUG 0xfee1

/* Japanese transit card */
#define SC_IRUCA       0xde80

/* "...return a response to the Polling command, regardless
     of its System Code" */

#define SC_DOUBLE_WILDCARD 0xffff

static const value_string felica_opcodes[] = {
    /* Commands */
    {CMD_POLLING,             "Polling"},
    {CMD_REQ_SVC,             "Request Service"},
    {CMD_REQ_RES,             "Request Response"},
    {CMD_READ_WO_ENCRYPTION,  "Read Without Encryption"},
    {CMD_WRITE_WO_ENCRYPTION, "Write Without Encryption"},
    {CMD_SEARCH_SVC_CODE,     "Search Service Code"},
    {CMD_REQ_SYS_CODE,        "Request System Code"},
    {CMD_AUTH_1, "Authentication1"},
    {CMD_AUTH_2, "Authentication2"},
    {CMD_READ, "Read"},
    {CMD_WRITE, "Write"},
    {CMD_REQ_SVC_V2, "Request Service v2"},
    {CMD_REQ_SYS_STATUS, "Get System Status"},
    {CMD_REQ_SPEC_VER, "Request Specification Version"},
    {CMD_RESET_MODE, "Reset Mode"},
    {CMD_AUTH1_V2, "Authentication1 v2"},
    {CMD_AUTH2_V2, "Authentication2 v2"},
    {CMD_READ_V2, "Read v2"},
    {CMD_WRITE_V2, "Write v2"},
    {CMD_REQ_UPDATE_RAND_ID, "Update Random ID"},
    /* End of commands */

    /* Responses */
    {RES_POLLING,             "Polling (Response)"},
    {RES_REQ_SVC,             "Request Service (Response)"},
    {RES_REQ_RES,             "Request Response (Response)"},
    {RES_READ_WO_ENCRYPTION,  "Read Without Encryption (Response)"},
    {RES_WRITE_WO_ENCRYPTION, "Write Without Encryption (Response)"},
    {RES_SEARCH_SVC_CODE,     "Search Service Code (Response)"},
    {RES_REQ_SYS_CODE,        "Request System Code (Response)"},
    {RES_AUTH_1, "Authentication1 (Response)"},
    {RES_AUTH_2, "Authentication2 (Response)"},
    {RES_READ, "Read (Response)"},
    {RES_WRITE, "Write (Response)"},
    {RES_REQ_SVC_V2, "Request Service v2 (Response)"},
    {RES_REQ_SYS_STATUS, "Get System Status (Response)"},
    {RES_REQ_SPEC_VER, "Request Specification Version (Response)"},
    {RES_RESET_MODE, "Reset Mode (Response)"},
    {RES_AUTH1_V2, "Authentication1 v2 (Response)"},
    {RES_AUTH2_V2, "Authentication2 v2 (Response)"},
    {RES_READ_V2, "Read v2 (Response)"},
    {RES_WRITE_V2, "Write v2 (Response)"},
    {RES_REQ_UPDATE_RAND_ID, "Update Random ID"},
    /* End of responses */

    {0x00, NULL}
};

static const value_string felica_req_codes[] = {
    {RC_NO_REQ,       "No Request"},
    {RC_SYS_REQ,      "System Code Request"},
    {RC_COM_PERF_REQ, "Communication Performance Request"},

    /* Others are reserved for future use */

    /* End of request codes */
    {0x00, NULL}
};

static const value_string felica_sys_codes[] = {
    {SC_FELICA_LITE,           "FeliCa Lite"},
    {SC_FELICA_PLUG,           "FeliCa Plug (NFC Dynamic Tag)"},
    {SC_NFC_FORUM,             "NFC Forum (NDEF)"},
    {SC_FELICA_NW_COMMON_AREA, "FeliCa Networks Common Area"},
    {SC_IRUCA,                 "IruCa"},
    {SC_DOUBLE_WILDCARD,       "Wildcard"},

    /* End of system codes */
    {0x00, NULL}
};

/* Subtree handles: set by register_subtree_array */
static gint ett_felica = -1;

static int dissect_felica(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *item;
    proto_tree *felica_tree;
    guint8      opcode;
    guint8      rwe_pos     = 0;
    tvbuff_t   *rwe_resp_data_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FeliCa");

    /* Start with a top-level item to add everything else to */
    item = proto_tree_add_item(tree, proto_felica, tvb, 0, -1, ENC_NA);
    felica_tree = proto_item_add_subtree(item, ett_felica);

    opcode = tvb_get_guint8(tvb, 0);
    col_set_str(pinfo->cinfo, COL_INFO,
      val_to_str_const(opcode, felica_opcodes, "Unknown"));

    proto_tree_add_item(felica_tree, hf_felica_opcode,  tvb, 0, 1, ENC_BIG_ENDIAN);

    switch (opcode) {

    case CMD_POLLING:
        if (tree) {
            proto_tree_add_item(felica_tree, hf_felica_sys_code, tvb, 1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_req_code, tvb, 3, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_timeslot, tvb, 4, 1, ENC_BIG_ENDIAN);
        }
        break;

    case RES_POLLING:
        if (tree) {
            proto_tree_add_item(felica_tree, hf_felica_idm,      tvb, 1, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_pnm,      tvb, 9, 8, ENC_BIG_ENDIAN);

            if (tvb_reported_length(tvb) == 19)
                proto_tree_add_item(felica_tree, hf_felica_sys_code, tvb, 17, 2, ENC_BIG_ENDIAN);

            /*
             * Request data - 0 or 2 bytes long; data corresponding to request
             * code; only if request code of command packet is not 00 and
             * corresponds to request data
             */
        }
        break;

    case CMD_REQ_SVC:
        /* TODO */
        break;

    case RES_REQ_SVC:
        /* TODO */
        break;

    case CMD_REQ_RES:
        /* TODO */
        break;

    case RES_REQ_RES:
        /* TODO */
        break;

    case CMD_READ_WO_ENCRYPTION:
        if (tree) {
            proto_tree_add_item(felica_tree, hf_felica_idm,         tvb, 1, 8, ENC_BIG_ENDIAN);
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
        if (tree) {
            proto_tree_add_item(felica_tree, hf_felica_idm,           tvb,  1, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_status_flag1,  tvb,  9, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_status_flag2,  tvb, 10, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(felica_tree, hf_felica_nbr_of_blocks, tvb, 11, 1, ENC_BIG_ENDIAN);
        }
        rwe_resp_data_tvb = tvb_new_subset_remaining(tvb, 12);
        call_data_dissector(rwe_resp_data_tvb, pinfo, tree);
        break;

    case CMD_WRITE_WO_ENCRYPTION:
        /* TODO */
        break;

    case RES_WRITE_WO_ENCRYPTION:
        /* TODO */
        break;

    case CMD_SEARCH_SVC_CODE:
        /* TODO */
        break;

    case RES_SEARCH_SVC_CODE:
        /* TODO */
        break;

    case CMD_REQ_SYS_CODE:
        /* TODO */
        break;

    case RES_REQ_SYS_CODE:
        /* TODO */
        break;

    case CMD_AUTH_1:
        /* TODO */
        break;

    case RES_AUTH_1:
        /* TODO */
        break;

    case CMD_AUTH_2:
        /* TODO */
        break;

    case RES_AUTH_2:
        /* TODO */
        break;

    case CMD_READ:
        /* TODO */
        break;

    case RES_READ:
        /* TODO */
        break;

    case CMD_WRITE:
        /* TODO */
        break;

    case RES_WRITE:
        /* TODO */
        break;

    case CMD_REQ_SVC_V2:
        /* TODO */
        break;

    case RES_REQ_SVC_V2:
        /* TODO */
        break;

    case CMD_REQ_SYS_STATUS:
        /* TODO */
        break;

    case RES_REQ_SYS_STATUS:
        /* TODO */
        break;

    case CMD_REQ_SPEC_VER:
        /* TODO */
        break;

    case RES_REQ_SPEC_VER:
        /* TODO */
        break;

    case CMD_RESET_MODE:
        /* TODO */
        break;

    case RES_RESET_MODE:
        /* TODO */
        break;

    case CMD_AUTH1_V2:
        /* TODO */
        break;

    case RES_AUTH1_V2:
        /* TODO */
        break;

    case CMD_AUTH2_V2:
        /* TODO */
        break;

    case RES_AUTH2_V2:
        /* TODO */
        break;

    case CMD_READ_V2:
        /* TODO */
        break;

    case RES_READ_V2:
        /* TODO */
        break;

    case CMD_WRITE_V2:
        /* TODO */
        break;

    case RES_WRITE_V2:
        /* TODO */
        break;

    case CMD_REQ_UPDATE_RAND_ID:
        /* TODO */
        break;

    case RES_REQ_UPDATE_RAND_ID:
        /* TODO */
        break;

    default:
        break;
    }
    return tvb_captured_length(tvb);
}

void
proto_register_felica(void)
{
    static hf_register_info hf[] = {

    {&hf_felica_opcode,
     { "Opcode", "felica.opcode",
       FT_UINT8, BASE_HEX, VALS(felica_opcodes), 0x0,
       NULL, HFILL }
    },

    /* Request Code */
    {&hf_felica_req_code,
     { "Request Code", "felica.req.code",
       FT_UINT8, BASE_HEX, VALS(felica_req_codes), 0x0,
       NULL, HFILL }
    },

    {&hf_felica_idm,
     { "IDm (Manufacture ID)/NFCID2", "felica.idm",
       FT_UINT64, BASE_HEX, NULL, 0x0,
       NULL, HFILL }
    },

    /* System Code */
    {&hf_felica_sys_code,
     { "System Code", "felica.sys_code",
       FT_UINT16, BASE_HEX, VALS(felica_sys_codes), 0x0,
       NULL, HFILL }
    },

    /* Service Code */
    {&hf_felica_svc_code,
     { "Service Code", "felica.svc_code",
       FT_UINT16, BASE_HEX, NULL, 0x0,
       NULL, HFILL }
    },

      /* Parameter/PAD */
    {&hf_felica_pnm,
     { "PNm (Manufacture Parameter)/PAD", "felica.pnm",
       FT_UINT64, BASE_HEX, NULL, 0x0,
       NULL, HFILL }
    },

    /* Number of Services */
    {&hf_felica_nbr_of_svcs,
     { "Number of Services", "felica.svcs",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL, HFILL }
    },

    /* Number of Blocks */
    {&hf_felica_nbr_of_blocks,
     { "Number of Blocks", "felica.blocks",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL, HFILL }
    },

    /* Block ID */
    {&hf_felica_block_nbr,
     { "Block Number", "felica.block.nbr",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL, HFILL }
    },

    /* Status Flag 1 */
    {&hf_felica_status_flag1,
     { "Status Flag 1", "felica.status.flag1",
       FT_UINT8, BASE_HEX, NULL, 0x0,
       NULL, HFILL }
    },

    /* Status Flag 2 */
    {&hf_felica_status_flag2,
     { "Status Flag 2", "felica.status.flag2",
       FT_UINT8, BASE_HEX, NULL, 0x0,
       NULL, HFILL }
    },

    /* Timeslot */
    {&hf_felica_timeslot,
     { "Timeslot", "felica.timeslot",
       FT_UINT8, BASE_HEX, NULL, 0x0,
       NULL, HFILL }
    }
    };

    static gint *ett[] = {
        &ett_felica
    };

    proto_felica = proto_register_protocol("Sony FeliCa", "FeliCa", "felica");
    proto_register_field_array(proto_felica, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("felica", dissect_felica, proto_felica);
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
