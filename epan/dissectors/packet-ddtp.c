/* packet-ddtp.c
 * Routines for DDTP (Dynamic DNS Tools Protocol) packet disassembly
 * see http://ddt.sourceforge.net/
 * Olivier Abad <oabad@noos.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000
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
#include <epan/expert.h>

#define DDTP_VERSION_ERROR      0
#define DDTP_VERSION_4          1
#define DDTP_VERSION_5          2

#define DDTP_ENCRYPT_ERROR      0
#define DDTP_ENCRYPT_PLAINTEXT  1
#define DDTP_ENCRYPT_BLOWFISH   2

#define DDTP_MESSAGE_ERROR      0
#define DDTP_UPDATE_QUERY       1
#define DDTP_UPDATE_REPLY       2
#define DDTP_ALIVE_QUERY        3
#define DDTP_ALIVE_REPLY        4

#define DDTP_MARK_ONLINE        0
#define DDTP_MARK_OFFLINE       1

#define DDTP_UPDATE_SUCCEEDED   0
#define DDTP_UPDATE_FAILED      1
#define DDTP_INVALID_PASSWORD   2
#define DDTP_INVALID_ACCOUNT    3
#define DDTP_INVALID_OPCODE     4

void proto_register_ddtp (void);
void proto_reg_handoff_ddtp (void);

static int proto_ddtp = -1;
static int hf_ddtp_version = -1;
static int hf_ddtp_encrypt = -1;
static int hf_ddtp_hostid = -1;
static int hf_ddtp_msgtype = -1;
static int hf_ddtp_opcode = -1;
static int hf_ddtp_ipaddr = -1;
static int hf_ddtp_status = -1;
static int hf_ddtp_alive = -1;

static int ett_ddtp = -1;

static expert_field ei_ddtp_msgtype = EI_INIT;

#define UDP_PORT_DDTP   1052

/*
 * XXX - is 0 an invalid value?  If so, should we remove it from this
 * list, so that putative DDNS packets with a version number of 0 are
 * rejected?
 */
static const value_string vals_ddtp_version[] = {
    { DDTP_VERSION_ERROR, "Protocol Error" },
    { DDTP_VERSION_4,     "4" },
    { DDTP_VERSION_5,     "5" },
    { 0, NULL}
};

static const value_string vals_ddtp_encrypt[] = {
    { DDTP_ENCRYPT_ERROR,     "Encryption Error" },
    { DDTP_ENCRYPT_PLAINTEXT, "Plain text" },
    { DDTP_ENCRYPT_BLOWFISH,  "Blowfish" },
    { 0, NULL}
};

static const value_string vals_ddtp_msgtype[] = {
    { DDTP_MESSAGE_ERROR, "Message Error" },
    { DDTP_UPDATE_QUERY,  "Update Query" },
    { DDTP_UPDATE_REPLY,  "Update Reply" },
    { DDTP_ALIVE_QUERY,   "Alive Query" },
    { DDTP_ALIVE_REPLY,   "Alive Reply" },
    { 0, NULL}
};

static const value_string vals_ddtp_opcode[] = {
    { DDTP_MARK_ONLINE,  "Mark online" },
    { DDTP_MARK_OFFLINE, "Mark offline" },
    { 0, NULL}
};

static const value_string vals_ddtp_status[] = {
    { DDTP_UPDATE_SUCCEEDED, "Update succeeded" },
    { DDTP_UPDATE_FAILED,    "Update failed" },
    { DDTP_INVALID_PASSWORD, "Invalid password" },
    { DDTP_INVALID_ACCOUNT,  "Invalid account" },
    { DDTP_INVALID_OPCODE,   "Invalid opcode" },
    { 0, NULL}
};

static int
dissect_ddtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *ddtp_tree;
    proto_item *ti;

    /*
     * If we don't recognize the version number, don't dissect this.
     */
    if (tvb_reported_length(tvb) < 4)
        return 0;

    if (try_val_to_str(tvb_get_ntohl(tvb, 0), vals_ddtp_version) == NULL)
            return 0;

    /* Indicate what kind of message this is. */
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "DDTP");
    /* In case we throw an exception below. */
    col_clear (pinfo->cinfo, COL_INFO);

        ti = proto_tree_add_item(tree, proto_ddtp, tvb, 0, -1, ENC_NA);
        ddtp_tree = proto_item_add_subtree(ti, ett_ddtp);

        proto_tree_add_item(ddtp_tree, hf_ddtp_version, tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ddtp_tree, hf_ddtp_encrypt, tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ddtp_tree, hf_ddtp_hostid, tvb, 8, 4, ENC_BIG_ENDIAN);

    if (tvb_get_ntohl(tvb, 4) == DDTP_ENCRYPT_PLAINTEXT) {
            ti = proto_tree_add_item(ddtp_tree, hf_ddtp_msgtype, tvb, 12, 4, ENC_BIG_ENDIAN);
        switch (tvb_get_ntohl(tvb, 12)) {
        case DDTP_MESSAGE_ERROR :
            col_set_str(pinfo->cinfo, COL_INFO, "Message Error");
            break;
        case DDTP_UPDATE_QUERY :
            col_set_str(pinfo->cinfo, COL_INFO, "Update Query");
                proto_tree_add_item(ddtp_tree, hf_ddtp_opcode, tvb, 16, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(ddtp_tree, hf_ddtp_ipaddr, tvb, 20, 4, ENC_BIG_ENDIAN);
            break;
        case DDTP_UPDATE_REPLY :
            col_set_str(pinfo->cinfo, COL_INFO, "Update Reply");
                proto_tree_add_item(ddtp_tree, hf_ddtp_status, tvb, 16, 4, ENC_BIG_ENDIAN);
            break;
        case DDTP_ALIVE_QUERY :
            col_set_str(pinfo->cinfo, COL_INFO, "Alive Query");
                proto_tree_add_item(ddtp_tree, hf_ddtp_alive, tvb, 16, 4, ENC_BIG_ENDIAN);
            break;
        case DDTP_ALIVE_REPLY :
            col_set_str(pinfo->cinfo, COL_INFO, "Alive Reply");
                proto_tree_add_item(ddtp_tree, hf_ddtp_alive, tvb, 16, 4, ENC_BIG_ENDIAN);
            break;
        default :
            col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
                expert_add_info(pinfo, ti, &ei_ddtp_msgtype);
        }
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Encrypted payload");
    }
    return tvb_reported_length(tvb);
}

void
proto_register_ddtp(void)
{
    static hf_register_info hf_ddtp[] = {
        { &hf_ddtp_version,
          { "Version", "ddtp.version", FT_UINT32, BASE_DEC, VALS(vals_ddtp_version), 0x0,
            NULL, HFILL }},
        { &hf_ddtp_encrypt,
          { "Encryption", "ddtp.encrypt", FT_UINT32, BASE_DEC, VALS(vals_ddtp_encrypt), 0x0,
            "Encryption type", HFILL }},
        { &hf_ddtp_hostid,
          { "Hostid", "ddtp.hostid", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Host ID", HFILL }},
        { &hf_ddtp_msgtype,
          { "Message type", "ddtp.msgtype", FT_UINT32, BASE_DEC, VALS(vals_ddtp_msgtype), 0x0,
            NULL, HFILL }},
        { &hf_ddtp_opcode,
          { "Opcode", "ddtp.opcode", FT_UINT32, BASE_DEC, VALS(vals_ddtp_opcode), 0x0,
            "Update query opcode", HFILL }},
        { &hf_ddtp_ipaddr,
          { "IP address", "ddtp.ipaddr", FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_ddtp_status,
          { "Status", "ddtp.status", FT_UINT32, BASE_DEC, VALS(vals_ddtp_status), 0x0,
            "Update reply status", HFILL }},
        { &hf_ddtp_alive,
          { "Dummy", "ddtp.alive", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
    };

    static gint *ett[] = { &ett_ddtp };

    static ei_register_info ei[] = {
        { &ei_ddtp_msgtype, { "ddtp.msgtype.unknown", PI_PROTOCOL, PI_WARN, "Unknown type", EXPFILL }},
    };

    expert_module_t* expert_ddtp;

    proto_ddtp = proto_register_protocol("Dynamic DNS Tools Protocol",
                                         "DDTP", "ddtp");
    proto_register_field_array(proto_ddtp, hf_ddtp, array_length(hf_ddtp));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ddtp = expert_register_protocol(proto_ddtp);
    expert_register_field_array(expert_ddtp, ei, array_length(ei));
}

void
proto_reg_handoff_ddtp(void)
{
    dissector_handle_t ddtp_handle;

    ddtp_handle = create_dissector_handle(dissect_ddtp, proto_ddtp);
    dissector_add_uint("udp.port", UDP_PORT_DDTP, ddtp_handle);
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
