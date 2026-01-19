/* packet-epmd.c
 * dissector for EPMD (Erlang Port Mapper Daemon) messages;
 * this are the messages sent between Erlang nodes and
 * the empd process.
 * The message formats are derived from the
 * lib/kernel/src/erl_epmd.* files as part of the Erlang
 * distribution available from http://www.erlang.org/
 *
 * (c) 2007 Joost Yervante Damad <joost[AT]teluna.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-time.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/conversation.h>

#include <wsutil/strtoi.h>

#define PNAME  "Erlang Port Mapper Daemon"
#define PSNAME "EPMD"
#define PFNAME "epmd"

void proto_register_epmd(void);
void proto_reg_handoff_epmd(void);

static int proto_epmd;
static int hf_epmd_len;
static int hf_epmd_type;
static int hf_epmd_port_no;
static int hf_epmd_node_type;
static int hf_epmd_protocol;
static int hf_epmd_dist_high;
static int hf_epmd_dist_low;
static int hf_epmd_name_len;
static int hf_epmd_name;
static int hf_epmd_elen;
static int hf_epmd_edata;
static int hf_epmd_node_container;
static int hf_epmd_node_name;
static int hf_epmd_node_port;
static int hf_epmd_result;
static int hf_epmd_creation;
static int hf_epmd_creation2;

static int ett_epmd;
static int ett_epmd_node;

static expert_module_t* expert_epmd;
static expert_field ei_epmd_malformed_names_line;

static dissector_handle_t epmd_handle;

/* Other dissectors */
static dissector_handle_t edp_handle;

#define EPMD_PORT 4369

/* Definitions of message codes */
#define EPMD_ALIVE_REQ     'a'
#define EPMD_ALIVE_OK_RESP 'Y'
#define EPMD_PORT_REQ      'p'
#define EPMD_NAMES_REQ     'n'
#define EPMD_DUMP_REQ      'd'
#define EPMD_KILL_REQ      'k'
#define EPMD_STOP_REQ      's'
/* New epmd messages */
#define EPMD_ALIVE2_REQ    'x' /* 120 */
#define EPMD_PORT2_REQ     'z' /* 122 */
#define EPMD_ALIVE2_RESP   'y' /* 121 */
#define EPMD_PORT2_RESP    'w' /* 119 */
#define EPMD_ALIVE2_X_RESP 'v' /* 118 - Extended response for highvsn >= 6 */

static const value_string message_types[] = {
    { EPMD_ALIVE_REQ    , "EPMD_ALIVE_REQ"     },
    { EPMD_ALIVE_OK_RESP, "EPMD_ALIVE_OK_RESP" },
    { EPMD_PORT_REQ     , "EPMD_PORT_REQ"      },
    { EPMD_NAMES_REQ    , "EPMD_NAMES_REQ"     },
    { EPMD_DUMP_REQ     , "EPMD_DUMP_REQ"      },
    { EPMD_KILL_REQ     , "EPMD_KILL_REQ"      },
    { EPMD_STOP_REQ     , "EPMD_STOP_REQ"      },
    { EPMD_ALIVE2_REQ   , "EPMD_ALIVE2_REQ"    },
    { EPMD_PORT2_REQ    , "EPMD_PORT2_REQ"     },
    { EPMD_ALIVE2_RESP  , "EPMD_ALIVE2_RESP"   },
    { EPMD_PORT2_RESP   , "EPMD_PORT2_RESP"    },
    { EPMD_ALIVE2_X_RESP, "EPMD_ALIVE2_X_RESP" },
    {  0, NULL }
};

static const value_string node_type_vals[] = {
    {  72 , "R3 hidden node" },
    {  77 , "R3 erlang node" },
    { 104 , "R4 hidden node" },
    { 109 , "R4 erlang node" },
    { 110 , "R6 nodes" },
    {  0, NULL }
};

static const value_string protocol_vals[] = {
    {  0 , "tcp/ip-v4" },
    {  0, NULL }
};

const value_string epmd_version_vals[] = {
    {  0 , "R3"     },
    {  1 , "R4"     },
    {  2 , "R5"     },
    {  3 , "R5C"    },
    {  4 , "R6 dev" },
    {  5 , "R6"     },
    {  0, NULL }
};

static void
dissect_epmd_request(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree) {
    uint8_t       type;
    uint16_t      name_length = 0;
    const uint8_t *name        = NULL;

    proto_tree_add_item(tree, hf_epmd_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_epmd_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(pinfo->pool, type, VALS(message_types), "unknown (0x%02X)"));

    switch (type) {
        case EPMD_ALIVE2_REQ:
            proto_tree_add_item(tree, hf_epmd_port_no, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_epmd_node_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_epmd_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_epmd_dist_high, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_epmd_dist_low, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint16(tree, hf_epmd_name_len, tvb, offset, 2, ENC_BIG_ENDIAN, &name_length);
            proto_tree_add_item_ret_string(tree, hf_epmd_name, tvb, offset + 2, name_length, ENC_ASCII|ENC_NA, pinfo->pool, &name);
            offset += 2 + name_length;
            if (tvb_reported_length_remaining(tvb, offset) >= 2) {
                uint16_t elen=0;
                proto_tree_add_item_ret_uint16(tree, hf_epmd_elen, tvb, offset, 2, ENC_BIG_ENDIAN, &elen);
                if (elen > 0)
                    proto_tree_add_item(tree, hf_epmd_edata, tvb, offset + 2, elen, ENC_NA);
                /*offset += 2 + elen;*/
            }
            break;

        case EPMD_PORT_REQ:
        case EPMD_PORT2_REQ:
            name_length = tvb_captured_length_remaining(tvb, offset);
            proto_tree_add_item_ret_string(tree, hf_epmd_name, tvb, offset, name_length, ENC_ASCII|ENC_NA, pinfo->pool, &name);
            break;

        case EPMD_ALIVE_REQ:
            proto_tree_add_item(tree, hf_epmd_port_no, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            name_length = tvb_captured_length_remaining(tvb, offset);
            proto_tree_add_item_ret_string(tree, hf_epmd_name, tvb, offset, name_length, ENC_ASCII|ENC_NA, pinfo->pool, &name);
            break;

        case EPMD_NAMES_REQ:
            break;

    }

    if (name) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
    }

}

static void
dissect_epmd_response_names(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, proto_tree *tree)
{
    int reported_len = tvb_reported_length(tvb);
    int off = offset;

    int next_off;
    while (off < reported_len) {
        int linelen = tvb_find_line_end(tvb, off, -1, &next_off, FALSE);
        proto_item *node_ti = proto_tree_add_item(tree,hf_epmd_node_container, tvb, off, linelen, ENC_NA);
        proto_tree *node_tree = proto_item_add_subtree(node_ti, ett_epmd_node);

        if (tvb_strneql(tvb, off, "name ", 5) != 0) {
            off = next_off;
            expert_add_info_format(pinfo, node_tree, &ei_epmd_malformed_names_line, "Malformed line: expected 'name ' at start");
            continue;
        }
        int name_start = off + 5;

        int name_end = tvb_find_uint8(tvb, name_start, linelen - (name_start - off), ' ');
        if (name_end == -1){
            off = next_off;
            expert_add_info_format(pinfo, node_tree, &ei_epmd_malformed_names_line, "Malformed line: missing space after node name");
            continue;
        }

        if (tvb_strneql(tvb, name_end, " at port ", 9) != 0) {
            off = next_off;
            expert_add_info_format(pinfo, node_tree, &ei_epmd_malformed_names_line, "Malformed line: expected ' at port '");
            continue;
        }

        proto_tree_add_item(node_tree, hf_epmd_node_name, tvb, name_start, name_end-name_start, ENC_ASCII);
        int pos_port = name_end + 9;
        int port_len = (off + linelen) - pos_port;

        off = next_off; // skip '\n'
        if (port_len <= 0) {
            continue;
        }
        uint16_t portnum;
        char *port_str = (char*)tvb_get_string_enc(pinfo->pool, tvb, pos_port, port_len, ENC_ASCII);
        if (!ws_strtou16(port_str, NULL, &portnum)){
            expert_add_info_format(pinfo, node_tree, &ei_epmd_malformed_names_line, "Invalid or missing port number");
            continue;
        }
        proto_tree_add_uint(node_tree, hf_epmd_node_port, tvb, pos_port, 2, portnum);
    }
}

static int
dissect_epmd_response(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree) {
    uint8_t         type, result;
    uint32_t        port;
    uint16_t        name_length = 0;
    const uint8_t  *name        = NULL;
    conversation_t *conv        = NULL;

    port = tvb_get_ntohl(tvb, offset);
    if (port == EPMD_PORT) {
        dissect_epmd_response_names(pinfo, tvb, offset + 4, tree);
        return 0;
    }

    proto_tree_add_item_ret_uint8(tree, hf_epmd_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
    offset++;
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(pinfo->pool, type, VALS(message_types), "unknown (0x%02X)"));

    switch (type) {
        case EPMD_ALIVE_OK_RESP:
            proto_tree_add_item_ret_uint8(tree, hf_epmd_result, tvb, offset, 1, ENC_BIG_ENDIAN, &result);
            offset++;
            proto_tree_add_item(tree, hf_epmd_creation, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            if (!result) {
                col_append_str(pinfo->cinfo, COL_INFO, " OK");
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, " ERROR 0x%02X", result);
            }
            break;

        case EPMD_ALIVE2_RESP:
            proto_tree_add_item_ret_uint8(tree, hf_epmd_result, tvb, offset, 1, ENC_BIG_ENDIAN, &result);
            offset++;
            if (!result) {
                proto_tree_add_item(tree, hf_epmd_creation, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                col_append_str(pinfo->cinfo, COL_INFO, " OK");
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, " ERROR 0x%02X", result);
            }
            break;

        case EPMD_ALIVE2_X_RESP:
            proto_tree_add_item_ret_uint8(tree, hf_epmd_result, tvb, offset, 1, ENC_BIG_ENDIAN, &result);
            offset++;
            if (!result) {
                /* Check remaining length to determine creation field size */
                int remaining = tvb_reported_length_remaining(tvb, offset);
                if (remaining >= 4) {
                    proto_tree_add_item(tree, hf_epmd_creation2, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                } else if (remaining >= 2) {
                    proto_tree_add_item(tree, hf_epmd_creation, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                }
                col_append_str(pinfo->cinfo, COL_INFO, " OK");
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, " ERROR 0x%02X", result);
            }
            break;

        case EPMD_PORT2_RESP:
            proto_tree_add_item_ret_uint8(tree, hf_epmd_result, tvb, offset, 1, ENC_BIG_ENDIAN, &result);
            offset++;
            if (!result) {
                col_append_str(pinfo->cinfo, COL_INFO, " OK");
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, " ERROR 0x%02X", result);
                break;
            }
            proto_tree_add_item_ret_uint(tree, hf_epmd_port_no, tvb, offset, 2, ENC_BIG_ENDIAN, &port);
            offset += 2;
            proto_tree_add_item(tree, hf_epmd_node_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_epmd_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_epmd_dist_high, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(tree, hf_epmd_dist_low, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint16(tree, hf_epmd_name_len, tvb, offset, 2, ENC_BIG_ENDIAN, &name_length);
            proto_tree_add_item_ret_string(tree, hf_epmd_name, tvb, offset + 2, name_length, ENC_ASCII|ENC_NA, pinfo->pool, &name);
            offset += 2 + name_length;
            if (tvb_reported_length_remaining(tvb, offset) >= 2) {
                uint16_t elen;
                proto_tree_add_item_ret_uint16(tree, hf_epmd_elen, tvb, offset, 2, ENC_BIG_ENDIAN, &elen);
                if (elen > 0)
                    proto_tree_add_item(tree, hf_epmd_edata, tvb, offset + 2, elen, ENC_NA);
                offset += 2 + elen;
            }
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s port=%d", name, port);
            if (!pinfo->fd->visited) {
                conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_TCP, port, 0, NO_PORT2);
                conversation_set_dissector(conv, edp_handle);
            }
            break;
    }
    return offset;
}

static bool
check_epmd(tvbuff_t *tvb) {
    uint8_t type;

    /* simple heuristic:
     *
     * just check if the type is one of the EPMD
     * command types
     *
     * It's possible to start checking lengths but imho that
     * doesn't bring very much.
     */
    if (tvb_captured_length(tvb) < 3)
        return false;

    /* If the first 4 bytes interpreted as uint32_be equal EPMD port (0x00001111),
     * this is the 'names' style response that begins with 0x00001111.
     * Accept it as EPMD.
     */
    if (tvb_get_ntohl(tvb, 0) == EPMD_PORT)
        return true;

    type = tvb_get_uint8(tvb, 0);
    switch (type) {
        case EPMD_ALIVE_OK_RESP:
        case EPMD_ALIVE2_RESP:
        case EPMD_ALIVE2_X_RESP:
        case EPMD_PORT2_RESP:
            return true;
        default:
            break;
    }

    type = tvb_get_uint8(tvb, 2);
    switch (type) {
        case EPMD_ALIVE_REQ:
        case EPMD_ALIVE2_REQ:
        case EPMD_PORT_REQ:
        case EPMD_PORT2_REQ:
        case EPMD_NAMES_REQ:
            return true;
        default:
            break;
    }

    return false;
}

static int
dissect_epmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_tree *epmd_tree;
    proto_item *ti;

    if (!check_epmd(tvb))
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

    ti = proto_tree_add_item(tree, proto_epmd, tvb, 0, -1, ENC_NA);
    epmd_tree = proto_item_add_subtree(ti, ett_epmd);

    if (pinfo->match_uint == pinfo->destport) {
        dissect_epmd_request(pinfo, tvb, 0, epmd_tree);
    } else {
        dissect_epmd_response(pinfo, tvb, 0, epmd_tree);
    }

    return (tvb_captured_length(tvb));
}

void
proto_register_epmd(void)
{
    static hf_register_info hf[] = {
        { &hf_epmd_len,
          { "Length", "epmd.len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Message Length", HFILL }},

        { &hf_epmd_type,
          { "Type", "epmd.type",
            FT_UINT8, BASE_DEC, VALS(message_types), 0x0,
            "Message Type", HFILL }},

        { &hf_epmd_result,
          { "Result", "epmd.result",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_epmd_port_no,
          { "Port No", "epmd.port_no",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_epmd_node_type,
          { "Node Type", "epmd.node_type",
            FT_UINT8, BASE_DEC, VALS(node_type_vals), 0x0,
            NULL, HFILL }},

        { &hf_epmd_protocol,
          { "Protocol", "epmd.protocol",
            FT_UINT8, BASE_DEC, VALS(protocol_vals), 0x0,
            NULL, HFILL }},

        { &hf_epmd_creation,
          { "Creation", "epmd.creation",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_epmd_creation2,
          { "Creation", "epmd.creation2",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Creation (4 bytes)", HFILL }},

        { &hf_epmd_dist_high,
          { "Highest Version", "epmd.dist_high",
            FT_UINT16, BASE_DEC, VALS(epmd_version_vals), 0x0,
            NULL, HFILL }},

        { &hf_epmd_dist_low,
          { "Lowest Version", "epmd.dist_low",
            FT_UINT16, BASE_DEC, VALS(epmd_version_vals), 0x0,
            NULL, HFILL }},

        { &hf_epmd_name_len,
          { "Name Length", "epmd.name_len",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_epmd_name,
          { "Node Name", "epmd.name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_epmd_node_container,
            { "Node", "epmd.node",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Single EPMD node entry", HFILL }},

        { &hf_epmd_node_name,
            { "Name", "epmd.node_name",
                FT_STRING, BASE_NONE, NULL, 0x0,
                "Name of the Erlang node", HFILL }},

        { &hf_epmd_node_port,
            { "Port", "epmd.node_port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Port where the node is listening", HFILL }},

        { &hf_epmd_elen,
          { "Elen", "epmd.elen",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Extra Length", HFILL }},

        { &hf_epmd_edata,
          { "Edata", "epmd.edata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Extra Data", HFILL }},
    };

    static ei_register_info ei[] = {
        { &ei_epmd_malformed_names_line,
        { "epmd.malformed_names_line", PI_MALFORMED, PI_ERROR,
            "Malformed line in EPMD names response", EXPFILL }},
    };

    static int *ett[] = {
        &ett_epmd,
        &ett_epmd_node,
    };

    proto_epmd = proto_register_protocol(PNAME, PSNAME, PFNAME);
    proto_register_field_array(proto_epmd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    epmd_handle = register_dissector(PFNAME, dissect_epmd, proto_epmd);

    expert_epmd = expert_register_protocol(proto_epmd);
    expert_register_field_array(expert_epmd, ei, array_length(ei));
}

void
proto_reg_handoff_epmd(void) {
    edp_handle = find_dissector("erldp");

    dissector_add_uint_with_preference("tcp.port", EPMD_PORT, epmd_handle);
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
