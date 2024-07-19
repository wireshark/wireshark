/* packet-shicp.c
 * Routines for Secure Host IP Configuration Protocol dissection
 * Copyright 2021, Filip Kågesson <exfik@hms.se>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include "packet-udp.h"

void proto_reg_handoff_shicp(void);
void proto_register_shicp(void);

/* Protocols and header fields */
static int proto_shicp;
static int hf_shicp_header;
static int hf_shicp_protocol_version;
static int hf_shicp_dst;
static int hf_shicp_src;
static int hf_shicp_flags;
static int hf_shicp_msgclass_flag;
static int hf_shicp_error_flag;
static int hf_shicp_reserved_flag;
static int hf_shicp_msgtype;
static int hf_shicp_error;
static int hf_shicp_error_string;
static int hf_shicp_auth_req;
static int hf_shicp_module_version;
static int hf_shicp_module_desc;
static int hf_shicp_supported_msg;
static int hf_shicp_ip;
static int hf_shicp_sn;
static int hf_shicp_gw;
static int hf_shicp_dns1;
static int hf_shicp_dns2;
static int hf_shicp_dhcp;
static int hf_shicp_hn;
static int hf_shicp_hn_max_len;
static int hf_shicp_pswd_max_len;
static int hf_shicp_challenge;
static int hf_shicp_validity_period;
static int hf_shicp_token;
static int hf_shicp_pswd;
static int hf_shicp_wink_type;
static int hf_shicp_restart_mode;

static int ett_shicp;
static int ett_shicp_flags;

static expert_field ei_shicp_error;
static expert_field ei_shicp_malformed;

#define SHICP_UDP_PORT 3250

#define SHICP_MIN_LENGTH 2
#define SHICP_MAX_LENGTH 548
#define SHICP_HEADER_SIZE 2
#define SHICP_ADDRESS_SIZE 6
#define SHICP_FLAGS_SIZE 1
#define SHICP_MSG_TYPE_SIZE 1
#define SHICP_ERROR_SIZE 1
#define SHICP_CHALLENGE_SIZE 4
#define SHICP_VALIDITY_PERIOD_SIZE 1
#define SHICP_TOKEN_SIZE 36
#define SHICP_WINK_TYPE_SIZE 1
#define SHICP_RESTART_MODE_SIZE 1
#define SHICP_FIXED_LEN 18
#define SHICP_MSG_CLASS_FLAG 0x01
#define SHICP_ERROR_FLAG 0x02
#define SHICP_RESERVED_FLAG 0xFC

/* Values of the supported message types. */
#define SHICP_DISCOVER_MSG_TYPE 0x00
#define SHICP_AUTH_CHALLENGE_MSG_TYPE 0x01
#define SHICP_CONFIG_MSG_TYPE 0x02
#define SHICP_WINK_MSG_TYPE 0x03
#define SHICP_RESTART_MSG_TYPE 0x04
#define SHICP_MASS_RESTART_MSG_TYPE 0x05

/* Keys of the parameters associated with discover messages. */
#define SHICP_DISCOVER_AUTH_REQ_KEY 0x00
#define SHICP_DISCOVER_MODULE_VERSION_KEY 0x01
#define SHICP_DISCOVER_MODULE_DESC_KEY 0x02
#define SHICP_DISCOVER_SUPPORTED_MSG_KEY 0x03
#define SHICP_DISCOVER_IP_KEY 0x04
#define SHICP_DISCOVER_SN_KEY 0x05
#define SHICP_DISCOVER_GW_KEY 0x06
#define SHICP_DISCOVER_DNS1_KEY 0x07
#define SHICP_DISCOVER_DNS2_KEY 0x08
#define SHICP_DISCOVER_DHCP_KEY 0x09
#define SHICP_DISCOVER_HN_KEY 0x0A
#define SHICP_DISCOVER_HN_MAX_LEN_KEY 0x0B
#define SHICP_DISCOVER_PSWD_MAX_LEN_KEY 0x0C

/* Keys of the parameters associated with configuration messages. */
#define SHICP_CONFIG_IP_KEY 0x00
#define SHICP_CONFIG_SN_KEY 0x01
#define SHICP_CONFIG_GW_KEY 0x02
#define SHICP_CONFIG_DNS1_KEY 0x03
#define SHICP_CONFIG_DNS2_KEY 0x04
#define SHICP_CONFIG_DHCP_KEY 0x05
#define SHICP_CONFIG_HN_KEY 0x06
#define SHICP_CONFIG_PSWD_KEY 0x07

/* The types of messages supported. */
static const value_string message_types[] = {
    {SHICP_DISCOVER_MSG_TYPE, "Discover"},
    {SHICP_AUTH_CHALLENGE_MSG_TYPE, "Authentication challenge"},
    {SHICP_CONFIG_MSG_TYPE, "Configuration"},
    {SHICP_WINK_MSG_TYPE, "Wink"},
    {SHICP_RESTART_MSG_TYPE, "Restart"},
    {SHICP_MASS_RESTART_MSG_TYPE, "Mass-restart"},
    {0, NULL}
};
/* The error codes that are supported. */
static const value_string error_types[] = {
    {0x00, "Request was rejected"},
    {0x01, "Authentication failed"},
    {0x02, "Authentication required"},
    {0x03, "Unsupported message type"},
    {0x1F, "Hostname too long"},
    {0x20, "Password too long"},
    {0x21, "Bad config"},
    {0, NULL}
};
/* The types of restart mode that are supported. */
static const value_string restart_mode_types[] = {
    {0x00, "Immediate restart"},
    {0x01, "Delayed restart"},
    {0, NULL}
};

static bool
test_shicp(packet_info* pinfo, tvbuff_t* tvb, int offset, void* data _U_)
{
    /* Check that the port matches the port used by SHICP. */
    if (pinfo->destport != SHICP_UDP_PORT) {
        return false;
    }

    /* Check that the length of the message is within allowed boundaries. */
    if (tvb_reported_length(tvb) < SHICP_MIN_LENGTH || tvb_reported_length(tvb) > SHICP_MAX_LENGTH) {
        return false;
    }

    /* Check that the header tag starts with 0xABC0. */
    if ((tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN) & 0xFFF8) != 0xABC0) {
        return false;
    }

    return true;
}

static int
dissect_shicp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item* ti;
    proto_item* flags_pi;
    proto_item* error_pi;
    proto_tree* shicp_tree;
    unsigned offset = 0;
    unsigned payload_end;
    unsigned keyvalue_key = 0;
    unsigned keyvalue_length = 0;
    unsigned keyvalue_offset = 0;
    unsigned keyvalue_end = 0;
    uint8_t supported_message_value = 0;
    uint16_t payload_length = 0;
    uint32_t version = 0;
    uint32_t msgtype_value = 0;
    uint32_t error_value = 0;
    uint64_t flags_value = 0;

    wmem_strbuf_t* supported_messages = wmem_strbuf_new(pinfo->pool, "");
    wmem_strbuf_t* module_addr_strbuf = wmem_strbuf_new(pinfo->pool, "");

    static int* flags[] = {
        &hf_shicp_reserved_flag,
        &hf_shicp_error_flag,
        &hf_shicp_msgclass_flag,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SHICP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_shicp, tvb, offset, -1, ENC_NA);

    shicp_tree = proto_item_add_subtree(ti, ett_shicp);
    proto_item_append_text(ti,
        ", Src:%s, Dst:%s",
        address_with_resolution_to_str(pinfo->pool, &pinfo->dl_src),
        address_with_resolution_to_str(pinfo->pool, &pinfo->dl_dst));
    proto_tree_add_item_ret_uint(shicp_tree, hf_shicp_header, tvb, offset, SHICP_HEADER_SIZE, ENC_LITTLE_ENDIAN, &version);
    proto_tree_add_uint(shicp_tree, hf_shicp_protocol_version, tvb, offset, SHICP_HEADER_SIZE, version & 0x07);
    offset += SHICP_HEADER_SIZE;
    proto_tree_add_item(shicp_tree, hf_shicp_dst, tvb, offset, SHICP_ADDRESS_SIZE, ENC_NA);
    char* dst = tvb_address_to_str(pinfo->pool, tvb, AT_ETHER, offset);
    offset += SHICP_ADDRESS_SIZE;
    proto_tree_add_item(shicp_tree, hf_shicp_src, tvb, offset, SHICP_ADDRESS_SIZE, ENC_NA);
    char* src = tvb_address_to_str(pinfo->pool, tvb, AT_ETHER, offset);
    offset += SHICP_ADDRESS_SIZE;
    flags_pi = proto_tree_add_bitmask_ret_uint64(shicp_tree, tvb, offset, hf_shicp_flags, ett_shicp_flags, flags, ENC_LITTLE_ENDIAN, &flags_value);
    offset += SHICP_FLAGS_SIZE;
    proto_tree_add_item_ret_uint(shicp_tree, hf_shicp_msgtype, tvb, offset, SHICP_MSG_TYPE_SIZE, ENC_LITTLE_ENDIAN, &msgtype_value);
    offset += SHICP_MSG_TYPE_SIZE;
    payload_length = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 1;
    if (flags_value & SHICP_ERROR_FLAG) {
        proto_item_set_text(flags_pi,
            "Message flags: 0x%02x (%s, %s)",
            (unsigned)flags_value,
            tfs_get_string(flags_value & SHICP_MSG_CLASS_FLAG, &tfs_response_request), "Error");
        if (payload_length != 1) {
            error_pi = proto_tree_add_string(shicp_tree, hf_shicp_error_string, tvb, offset, 0, "Malformed message");
            expert_add_info(pinfo, error_pi, &ei_shicp_malformed);
            col_append_str(pinfo->cinfo, COL_INFO, "Error: Malformed message");
        }
        else {
            error_pi = proto_tree_add_item_ret_uint(shicp_tree, hf_shicp_error, tvb, offset, SHICP_ERROR_SIZE, ENC_LITTLE_ENDIAN, &error_value);
            expert_add_info(pinfo, error_pi, &ei_shicp_error);
            col_append_fstr(pinfo->cinfo, COL_INFO, "Error: %s", val_to_str(error_value, error_types, "%d"));
        }
    }
    else {
        proto_item_set_text(flags_pi,
            "Message flags: 0x%02x (%s)",
            (unsigned)flags_value,
            tfs_get_string(flags_value & SHICP_MSG_CLASS_FLAG, &tfs_response_request));
        col_append_fstr(pinfo->cinfo,
            COL_INFO,
            "%s, Type: %s",
            tfs_get_string(flags_value & SHICP_MSG_CLASS_FLAG, &tfs_response_request),
            val_to_str(msgtype_value, message_types, "%d"));
        payload_end = offset + payload_length;
        switch (msgtype_value)
        {
        case SHICP_DISCOVER_MSG_TYPE:
            while (offset < payload_end) {
                keyvalue_key = tvb_get_uint8(tvb, offset);
                offset += 1;
                keyvalue_length = tvb_get_uint8(tvb, offset);
                offset += 1;
                switch (keyvalue_key)
                {
                case SHICP_DISCOVER_AUTH_REQ_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_auth_req, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_DISCOVER_MODULE_VERSION_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_module_version, tvb, offset, keyvalue_length, ENC_ASCII | ENC_NA);
                    break;
                case SHICP_DISCOVER_MODULE_DESC_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_module_desc, tvb, offset, keyvalue_length, ENC_ASCII | ENC_NA);
                    break;
                case SHICP_DISCOVER_SUPPORTED_MSG_KEY:
                    keyvalue_end = offset + keyvalue_length;
                    keyvalue_offset = offset;
                    supported_message_value = tvb_get_uint8(tvb, keyvalue_offset);
                    wmem_strbuf_append(supported_messages, val_to_str(supported_message_value, message_types, "%d"));
                    keyvalue_offset += 1;
                    while (keyvalue_offset < keyvalue_end) {
                        supported_message_value = tvb_get_uint8(tvb, keyvalue_offset);
                        wmem_strbuf_append_printf(supported_messages, ", %s", val_to_str(supported_message_value, message_types, "%d"));
                        keyvalue_offset += 1;
                    }
                    proto_tree_add_string(shicp_tree, hf_shicp_supported_msg, tvb, offset, keyvalue_length, wmem_strbuf_get_str(supported_messages));
                    break;
                case SHICP_DISCOVER_IP_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_ip, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_DISCOVER_SN_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_sn, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_DISCOVER_GW_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_gw, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_DISCOVER_DNS1_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_dns1, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_DISCOVER_DNS2_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_dns2, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_DISCOVER_DHCP_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_dhcp, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_DISCOVER_HN_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_hn, tvb, offset, keyvalue_length, ENC_ASCII | ENC_NA);
                    break;
                case SHICP_DISCOVER_HN_MAX_LEN_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_hn_max_len, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_DISCOVER_PSWD_MAX_LEN_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_pswd_max_len, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                default:
                    break;
                }
                offset += keyvalue_length;
            }
            break;
        case SHICP_AUTH_CHALLENGE_MSG_TYPE:
            if (payload_length >= 5) {
                proto_tree_add_item(shicp_tree, hf_shicp_challenge, tvb, offset, SHICP_CHALLENGE_SIZE, ENC_LITTLE_ENDIAN);
                offset += SHICP_CHALLENGE_SIZE;
                proto_tree_add_item(shicp_tree, hf_shicp_validity_period, tvb, offset, SHICP_VALIDITY_PERIOD_SIZE, ENC_LITTLE_ENDIAN);
            }
            break;
        case SHICP_CONFIG_MSG_TYPE:
            if (payload_length >= SHICP_TOKEN_SIZE) {
                proto_tree_add_item(shicp_tree, hf_shicp_token, tvb, offset, SHICP_TOKEN_SIZE, ENC_NA);
                offset += SHICP_TOKEN_SIZE;
            }
            else if (payload_length == SHICP_ERROR_SIZE) {
                proto_tree_add_item(shicp_tree, hf_shicp_error, tvb, offset, SHICP_ERROR_SIZE, ENC_ASCII | ENC_NA);
                break;
            }
            while (offset < payload_end) {
                keyvalue_key = tvb_get_uint8(tvb, offset);
                offset += 1;
                keyvalue_length = tvb_get_uint8(tvb, offset);
                offset += 1;
                switch (keyvalue_key)
                {
                case SHICP_CONFIG_IP_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_ip, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_CONFIG_SN_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_sn, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_CONFIG_GW_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_gw, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_CONFIG_DNS1_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_dns1, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_CONFIG_DNS2_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_dns2, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_CONFIG_DHCP_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_dhcp, tvb, offset, keyvalue_length, ENC_LITTLE_ENDIAN);
                    break;
                case SHICP_CONFIG_HN_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_hn, tvb, offset, keyvalue_length, ENC_ASCII | ENC_NA);
                    break;
                case SHICP_CONFIG_PSWD_KEY:
                    proto_tree_add_item(shicp_tree, hf_shicp_pswd, tvb, offset, keyvalue_length, ENC_ASCII | ENC_NA);
                    break;
                default:
                    break;
                }
                offset += keyvalue_length;
            }
            break;
        case SHICP_WINK_MSG_TYPE:
            if (payload_length >= SHICP_TOKEN_SIZE + SHICP_WINK_TYPE_SIZE) {
                proto_tree_add_item(shicp_tree, hf_shicp_token, tvb, offset, SHICP_TOKEN_SIZE, ENC_NA);
                offset += SHICP_TOKEN_SIZE;
                proto_tree_add_item(shicp_tree, hf_shicp_wink_type, tvb, offset, SHICP_WINK_TYPE_SIZE, ENC_LITTLE_ENDIAN);
            }
            break;
        case SHICP_RESTART_MSG_TYPE:
            if (payload_length >= SHICP_TOKEN_SIZE + SHICP_RESTART_MODE_SIZE) {
                proto_tree_add_item(shicp_tree, hf_shicp_token, tvb, offset, SHICP_TOKEN_SIZE, ENC_NA);
                offset += SHICP_TOKEN_SIZE;
                proto_tree_add_item(shicp_tree, hf_shicp_restart_mode, tvb, offset, SHICP_RESTART_MODE_SIZE, ENC_LITTLE_ENDIAN);
            }
            break;
        default:
            break;
        }
    }

    wmem_strbuf_append(module_addr_strbuf, (flags_value & SHICP_MSG_CLASS_FLAG) ? src : dst);
    if (strcmp(wmem_strbuf_get_str(module_addr_strbuf), "ff:ff:ff:ff:ff:ff") != 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", wmem_strbuf_get_str(module_addr_strbuf));
    }

    return tvb_captured_length(tvb);
}

static unsigned
get_shicp_len(packet_info* pinfo _U_, tvbuff_t* tvb, int offset _U_, void* data _U_)
{
    return (unsigned)tvb_reported_length(tvb);
}

static bool
dissect_shicp_heur_udp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
        return (udp_dissect_pdus(tvb, pinfo, tree, SHICP_FIXED_LEN, test_shicp,
            get_shicp_len, dissect_shicp, data) != 0);
}

void
proto_register_shicp(void)
{
    expert_module_t* expert_shicp;

    static hf_register_info hf[] = {
        { &hf_shicp_header,
          { "Header", "shicp.header",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_protocol_version,
          { "Protocol version", "shicp.protocolversion",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_dst,
          { "Destination", "shicp.dst",
            FT_ETHER, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_src,
          { "Source", "shicp.src",
            FT_ETHER, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_flags,
          { "Message flags", "shicp.flags",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_reserved_flag,
          { "Reserved", "shicp.flags.reserved",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0xFC,
            NULL, HFILL }
        },
        { &hf_shicp_error_flag,
          { "Error", "shicp.flags.error",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x02,
            NULL, HFILL }
        },
        { &hf_shicp_msgclass_flag,
          { "Class", "shicp.flags.msgclass",
            FT_BOOLEAN, 8,
            TFS(&tfs_response_request), 0x01,
            NULL, HFILL }
        },
        { &hf_shicp_msgtype,
          { "Message type", "shicp.msgtype",
            FT_UINT8, BASE_HEX,
            VALS(message_types), 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_error,
          { "Error", "shicp.error",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_error_string,
          { "Error", "shicp.error.string",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_auth_req,
          { "Authentication required", "shicp.authreq",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_module_version,
          { "Module version", "shicp.moduleversion",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_module_desc,
          { "Module description", "shicp.moduledesc",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_supported_msg,
          { "Supported messages", "shicp.supportedmsg",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_ip,
          { "IP address", "shicp.ip",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_sn,
          { "Subnet mask", "shicp.sn",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_gw,
          { "Gateway address", "shicp.gw",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_dns1,
          { "Primary DNS address", "shicp.dns1",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_dns2,
          { "Secondary DNS address", "shicp.dns2",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_dhcp,
          { "DHCP", "shicp.dhcp",
            FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_enabled_disabled), 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_hn,
          { "Hostname", "shicp.hn",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_hn_max_len,
          { "Hostname max length", "shicp.hnmaxlen",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_pswd_max_len,
          { "Password max length", "shicp.pswdmaxlen",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_challenge,
          { "Challenge", "shicp.challenge",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_validity_period,
          { "Validity period (seconds)", "shicp.validityperiod",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_token,
          { "Authentication token", "shicp.token",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_pswd,
          { "Password", "shicp.pswd",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_wink_type,
          { "Wink type", "shicp.winktype",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_shicp_restart_mode,
          { "Restart mode", "shicp.restartmode",
            FT_UINT8, BASE_HEX,
            VALS(restart_mode_types), 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_shicp,
        &ett_shicp_flags
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_shicp_error,
          { "shicp.expert.error", PI_RESPONSE_CODE, PI_NOTE,
            "Message contains an error code", EXPFILL }
        },
        { &ei_shicp_malformed,
          { "shicp.malformed", PI_MALFORMED, PI_WARN,
            "Malformed message", EXPFILL }
        }
    };

    proto_shicp = proto_register_protocol("Secure Host IP Configuration Protocol", "SHICP", "shicp");

    proto_register_field_array(proto_shicp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_shicp = expert_register_protocol(proto_shicp);
    expert_register_field_array(expert_shicp, ei, array_length(ei));
}

void
proto_reg_handoff_shicp(void)
{
    heur_dissector_add("udp", dissect_shicp_heur_udp, "SHICP over UDP", "shicp_udp", proto_shicp, HEURISTIC_ENABLE);
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
