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
#include <epan/conversation.h>

#define PNAME  "Erlang Port Mapper Daemon"
#define PSNAME "EPMD"
#define PFNAME "epmd"

void proto_register_epmd(void);
void proto_reg_handoff_epmd(void);

static int proto_epmd = -1;
static int hf_epmd_len = -1;
static int hf_epmd_type = -1;
static int hf_epmd_port_no = -1;
static int hf_epmd_node_type = -1;
static int hf_epmd_protocol = -1;
static int hf_epmd_dist_high = -1;
static int hf_epmd_dist_low = -1;
static int hf_epmd_name_len = -1;
static int hf_epmd_name = -1;
static int hf_epmd_elen = -1;
static int hf_epmd_edata = -1;
static int hf_epmd_names = -1;
static int hf_epmd_result = -1;
static int hf_epmd_creation = -1;

static gint ett_epmd = -1;

/* Other dissectors */
static dissector_handle_t edp_handle = NULL;

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
dissect_epmd_request(packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree) {
    guint8        type;
    guint16       name_length = 0;
    const guint8 *name        = NULL;

    proto_tree_add_item(tree, hf_epmd_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_epmd_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type, VALS(message_types), "unknown (0x%02X)"));

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
            name_length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_epmd_name_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_string(tree, hf_epmd_name, tvb, offset + 2, name_length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &name);
            offset += 2 + name_length;
            if (tvb_reported_length_remaining(tvb, offset) >= 2) {
                guint16 elen=0;
                elen = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(tree, hf_epmd_elen, tvb, offset, 2, ENC_BIG_ENDIAN);
                if (elen > 0)
                    proto_tree_add_item(tree, hf_epmd_edata, tvb, offset + 2, elen, ENC_NA);
                /*offset += 2 + elen;*/
            }
            break;

        case EPMD_PORT_REQ:
        case EPMD_PORT2_REQ:
            name_length = tvb_captured_length_remaining(tvb, offset);
            proto_tree_add_item_ret_string(tree, hf_epmd_name, tvb, offset, name_length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &name);
            break;

        case EPMD_ALIVE_REQ:
            proto_tree_add_item(tree, hf_epmd_port_no, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            name_length = tvb_captured_length_remaining(tvb, offset);
            proto_tree_add_item_ret_string(tree, hf_epmd_name, tvb, offset, name_length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &name);
            break;

        case EPMD_NAMES_REQ:
            break;

    }

    if (name) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
    }

}

static void
dissect_epmd_response_names(packet_info *pinfo _U_, tvbuff_t *tvb, gint offset, proto_tree *tree) {
    proto_tree_add_item(tree, hf_epmd_port_no, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_epmd_names, tvb, offset, -1, ENC_NA);
}

static int
dissect_epmd_response(packet_info *pinfo, tvbuff_t *tvb, gint offset, proto_tree *tree) {
    guint8          type, result;
    guint32         port;
    guint16         name_length = 0;
    const guint8   *name        = NULL;
    conversation_t *conv        = NULL;

    port = tvb_get_ntohl(tvb, offset);
    if (port == EPMD_PORT) {
        dissect_epmd_response_names(pinfo, tvb, offset, tree);
        return 0;
    }

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_epmd_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type, VALS(message_types), "unknown (0x%02X)"));

    switch (type) {
        case EPMD_ALIVE_OK_RESP:
        case EPMD_ALIVE2_RESP:
            result = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_epmd_result, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(tree, hf_epmd_creation, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            if (!result) {
                col_append_str(pinfo->cinfo, COL_INFO, " OK");
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, " ERROR 0x%02X", result);
            }
            break;

        case EPMD_PORT2_RESP:
            result = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_epmd_result, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (!result) {
                col_append_str(pinfo->cinfo, COL_INFO, " OK");
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, " ERROR 0x%02X", result);
                break;
            }
            port = tvb_get_ntohs(tvb, offset);
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
            name_length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_epmd_name_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_string(tree, hf_epmd_name, tvb, offset + 2, name_length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &name);
            offset += 2 + name_length;
            if (tvb_reported_length_remaining(tvb, offset) >= 2) {
                guint16 elen=0;
                elen = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(tree, hf_epmd_elen, tvb, offset, 2, ENC_BIG_ENDIAN);
                if (elen > 0)
                    proto_tree_add_item(tree, hf_epmd_edata, tvb, offset + 2, elen, ENC_NA);
                offset += 2 + elen;
            }
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s port=%d", name, port);
            if (!pinfo->fd->flags.visited) {
                conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, PT_TCP, port, 0, NO_PORT2);
                conversation_set_dissector(conv, edp_handle);
            }
            break;
    }
    return offset;
}

static gboolean
check_epmd(tvbuff_t *tvb) {
    guint8 type;

    /* simple heuristic:
     *
     * just check if the type is one of the EPMD
     * command types
     *
     * It's possible to start checking lengths but imho that
     * doesn't bring very much.
     */
    if (tvb_captured_length(tvb) < 3)
        return (FALSE);

    type = tvb_get_guint8(tvb, 0);
    switch (type) {
        case EPMD_ALIVE_OK_RESP:
        case EPMD_ALIVE2_RESP:
        case EPMD_PORT2_RESP:
            return (TRUE);
        default:
            break;
    }

    type = tvb_get_guint8(tvb, 2);
    switch (type) {
        case EPMD_ALIVE_REQ:
        case EPMD_ALIVE2_REQ:
        case EPMD_PORT_REQ:
        case EPMD_PORT2_REQ:
        case EPMD_NAMES_REQ:
            return (TRUE);
        default:
            break;
    }

    return (FALSE);
}

static int
dissect_epmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_tree *epmd_tree;
    proto_item *ti;

    if (!check_epmd(tvb))
        return (0);

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

        { &hf_epmd_elen,
          { "Elen", "epmd.elen",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Extra Length", HFILL }},

        { &hf_epmd_edata,
          { "Edata", "epmd.edata",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Extra Data", HFILL }},

        { &hf_epmd_names,
          { "Names", "epmd.names",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "List of names", HFILL }}
    };

    static gint *ett[] = {
        &ett_epmd,
    };

    proto_epmd = proto_register_protocol(PNAME, PSNAME, PFNAME);
    proto_register_field_array(proto_epmd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector(PFNAME, dissect_epmd, proto_epmd);
}

void
proto_reg_handoff_epmd(void) {
    dissector_handle_t epmd_handle;

    epmd_handle = find_dissector("epmd");
    edp_handle = find_dissector("erldp");

    dissector_add_uint("tcp.port", EPMD_PORT, epmd_handle);
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
