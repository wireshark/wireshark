/* packet-hicp.c
 * Routines for Host IP Configuration Protocol dissection
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
#include <epan/strutil.h>

void proto_reg_handoff_hicp(void);
void proto_register_hicp(void);

static dissector_handle_t hicp_handle;

/* Protocols and header fields. */
static int proto_hicp;
static int hf_hicp_cmd;
static int hf_hicp_proto_version;
static int hf_hicp_fb_type;
static int hf_hicp_module_version;
static int hf_hicp_mac;
static int hf_hicp_ip;
static int hf_hicp_sn;
static int hf_hicp_gw;
static int hf_hicp_dhcp;
static int hf_hicp_pswd_required;
static int hf_hicp_hn;
static int hf_hicp_dns1;
static int hf_hicp_dns2;
static int hf_hicp_ext;
static int hf_hicp_pswd;
static int hf_hicp_new_pswd;
static int hf_hicp_new_mac;
static int hf_hicp_status;
static int hf_hicp_error;
static int hf_hicp_target;
static int hf_hicp_src;

static expert_field ei_hicp_error;

static int ett_hicp;

#define HICP_PORT 3250
#define HICP_MIN_LENGTH 2
#define HICP_DELIMITER ";"

/* Values of the supported commands. */
#define HICP_MODULE_SCAN_COMMAND "Module scan"
#define HICP_CONFIG_COMMAND "Configure"
#define HICP_WINK_COMMAND "Wink"

/* Values of the supported parameters. */
#define HICP_PROTOCOL_VERSION "Protocol version"
#define HICP_FB_TYPE "FB type"
#define HICP_MODULE_VERSION "Module version"
#define HICP_MAC "MAC"
#define HICP_IP "IP"
#define HICP_SN "SN"
#define HICP_GW "GW"
#define HICP_DHCP "DHCP"
#define HICP_PSWD_REQUIRED "PSWD"
#define HICP_HN "HN"
#define HICP_DNS1 "DNS1"
#define HICP_DNS2 "DNS2"
#define HICP_EXT "EXT"
#define HICP_PSWD "Password"
#define HICP_NEW_PSWD "New Password"
#define HICP_NEW_MAC "New MAC"
#define HICP_RECONFIGURED "Reconfigured"
#define HICP_INVALID_PSWD "Invalid Password"
#define HICP_INVALID_CONFIG "Invalid Configuration"
#define HICP_TO "To"
#define HICP_EXECUTED "Executed"

static int
dissect_hicp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item* ti;
    proto_item* error_pi;
    proto_tree* hicp_tree;

    unsigned offset = 0;
    int lengthp = 0;
    double ext_value = 0;

    const char* parameters_ptr = NULL;
    char** parameters = NULL;
    char* parameter_value = NULL;

	/* Check that the packet does not start with the header of Secure Host IP Configuration Protocol (SHICP). */
    if ((tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN) & 0xFFFE) == 0xABC0) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HICP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_hicp, tvb, offset, -1, ENC_NA);

    hicp_tree = proto_item_add_subtree(ti, ett_hicp);

    parameters_ptr = tvb_get_stringz_enc(pinfo->pool, tvb, offset, &lengthp, ENC_ASCII);
    parameters = wmem_strsplit(pinfo->pool, (const char*)parameters_ptr, HICP_DELIMITER, -1);
    for (unsigned i = 0; i < g_strv_length(parameters); i++) {
        if (g_strrstr(parameters[i], " = ") != NULL) {
            parameter_value = &(g_strrstr(parameters[i], " = "))[3];
        }
        else if (g_strrstr(parameters[i], ": ") != NULL) {
            parameter_value = &(g_strrstr(parameters[i], ": "))[2];
        }
        else {
            parameter_value = "";
        }
        if (g_ascii_strncasecmp(parameters[i], HICP_MODULE_SCAN_COMMAND, (size_t)strlen(HICP_MODULE_SCAN_COMMAND)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_cmd, tvb, offset, (int)strlen(parameters[i]), HICP_MODULE_SCAN_COMMAND);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Request message, Command: %s", HICP_MODULE_SCAN_COMMAND);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_CONFIG_COMMAND, (size_t)strlen(HICP_CONFIG_COMMAND)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_cmd, tvb, offset, (int)strlen(parameters[i]), HICP_CONFIG_COMMAND);
            proto_tree_add_string(hicp_tree, hf_hicp_target, tvb, offset, (int)strlen(parameters[i]), parameter_value);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Request message, Command: %s", HICP_CONFIG_COMMAND);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_WINK_COMMAND, (size_t)strlen(HICP_WINK_COMMAND)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_cmd, tvb, offset, (int)strlen(parameters[i]), HICP_WINK_COMMAND);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Request message, Command: %s", HICP_WINK_COMMAND);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_PROTOCOL_VERSION, (size_t)strlen(HICP_PROTOCOL_VERSION)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_cmd, tvb, offset, (int)strlen(parameters[i]), HICP_MODULE_SCAN_COMMAND);
            proto_tree_add_string(hicp_tree, hf_hicp_proto_version, tvb, offset, (int)strlen(parameters[i]), parameter_value);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Response message, Command: %s", HICP_MODULE_SCAN_COMMAND);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_FB_TYPE, (size_t)strlen(HICP_FB_TYPE)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_fb_type, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_MODULE_VERSION, (size_t)strlen(HICP_MODULE_VERSION)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_module_version, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_MAC, (size_t)strlen(HICP_MAC)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_mac, tvb, offset, (int)strlen(parameters[i]), parameter_value);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_IP, (size_t)strlen(HICP_IP)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_ip, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_SN, (size_t)strlen(HICP_SN)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_sn, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_GW, (size_t)strlen(HICP_GW)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_gw, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_DHCP, (size_t)strlen(HICP_DHCP)) == 0) {
            proto_tree_add_string(hicp_tree,
                hf_hicp_dhcp,
                tvb,
                offset,
                (int)strlen(parameters[i]),
                g_ascii_strcasecmp(parameter_value, "ON") == 0 ? "Enabled" : "Disabled");
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_PSWD_REQUIRED, (size_t)strlen(HICP_PSWD_REQUIRED)) == 0) {
            proto_tree_add_string(hicp_tree,
                hf_hicp_pswd_required,
                tvb,
                offset,
                (int)strlen(parameters[i]),
                g_ascii_strcasecmp(parameter_value, "ON") == 0 ? "Required" : "Not required");
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_HN, (size_t)strlen(HICP_HN)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_hn, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_DNS1, (size_t)strlen(HICP_DNS1)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_dns1, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_DNS2, (size_t)strlen(HICP_DNS2)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_dns2, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_EXT, (size_t)strlen(HICP_EXT)) == 0) {
            ext_value = g_ascii_strtod(parameter_value, NULL);
            if (ext_value == 1) {
                parameter_value = HICP_WINK_COMMAND;
            }
            else if (ext_value == 0) {
                parameter_value = "None";
            }
            proto_tree_add_string(hicp_tree, hf_hicp_ext, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_PSWD, (size_t)strlen(HICP_PSWD)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_pswd, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_NEW_PSWD, (size_t)strlen(HICP_NEW_PSWD)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_new_pswd, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_NEW_MAC, (size_t)strlen(HICP_NEW_MAC)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_new_mac, tvb, offset, (int)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_RECONFIGURED, (size_t)strlen(HICP_RECONFIGURED)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_status, tvb, offset, (int)strlen(parameters[i]), HICP_RECONFIGURED);
            proto_tree_add_string(hicp_tree, hf_hicp_src, tvb, offset, (int)strlen(parameters[i]), parameter_value);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Respond message, Command: %s", HICP_CONFIG_COMMAND);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_INVALID_PSWD, (size_t)strlen(HICP_INVALID_PSWD)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_src, tvb, offset, (int)strlen(parameters[i]), parameter_value);
            error_pi = proto_tree_add_string(hicp_tree, hf_hicp_error, tvb, offset, (int)strlen(parameters[i]), HICP_INVALID_PSWD);
            expert_add_info(pinfo, error_pi, &ei_hicp_error);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Error: %s", HICP_INVALID_PSWD);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: %s, Module MAC address: %s", HICP_CONFIG_COMMAND, parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_INVALID_CONFIG, (size_t)strlen(HICP_INVALID_CONFIG)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_src, tvb, offset, (int)strlen(parameters[i]), parameter_value);
            error_pi = proto_tree_add_string(hicp_tree, hf_hicp_error, tvb, offset, (int)strlen(parameters[i]), HICP_INVALID_CONFIG);
            expert_add_info(pinfo, error_pi, &ei_hicp_error);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Error: %s", HICP_INVALID_CONFIG);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: %s, Module MAC address: %s", HICP_CONFIG_COMMAND, parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_EXECUTED, (size_t)strlen(HICP_EXECUTED)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_status, tvb, offset, (int)strlen(parameters[i]), HICP_EXECUTED);
            proto_tree_add_string(hicp_tree, hf_hicp_src, tvb, offset, (int)strlen(parameters[i]), parameter_value);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Respond message, Command: %s", HICP_WINK_COMMAND);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_TO, (size_t)strlen(HICP_TO)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_target, tvb, offset, (int)strlen(parameters[i]), parameter_value);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        offset += (unsigned)strlen(parameters[i]) + (unsigned)strlen(HICP_DELIMITER);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_hicp(void)
{
    expert_module_t* expert_hicp;

    static hf_register_info hf[] = {
        { &hf_hicp_cmd,
          { "Command", "hicp.cmd",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_proto_version,
          { "Protocol version", "hicp.protoversion",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_fb_type,
          { "Fieldbus type", "hicp.fbtype",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_module_version,
          { "Module version", "hicp.moduleversion",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_mac,
          { "MAC address", "hicp.mac",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_ip,
          { "IP address", "hicp.ip",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_sn,
          { "Subnet mask", "hicp.sn",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_gw,
          { "Gateway address", "hicp.gw",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_dhcp,
          { "DHCP", "hicp.dhcp",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_pswd_required,
          { "Password", "hicp.pswdrequired",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_hn,
          { "Hostname", "hicp.hn",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_dns1,
          { "Primary DNS address", "hicp.dns1",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_dns2,
          { "Secondary DNS", "hicp.dns2",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_ext,
          { "Extended commands supported", "hicp.ext",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_pswd,
          { "Password", "hicp.pswd",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_new_pswd,
          { "New password", "hicp.newpswd",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_new_mac,
          { "New MAC address", "hicp.newmac",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_status,
          { "Status", "hicp.status",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_error,
          { "Error", "hicp.error",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_target,
          { "Target", "hicp.target",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hicp_src,
          { "Source", "hicp.src",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] = {
        &ett_hicp
    };

    static ei_register_info ei[] = {
        { &ei_hicp_error,
          { "hicp.error", PI_RESPONSE_CODE, PI_NOTE,
            "Message contains an error message.", EXPFILL }
        }
    };

    proto_hicp = proto_register_protocol("Host IP Configuration Protocol", "HICP", "hicp");

    proto_register_field_array(proto_hicp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_hicp = expert_register_protocol(proto_hicp);
    expert_register_field_array(expert_hicp, ei, array_length(ei));

    hicp_handle = register_dissector("hicp", dissect_hicp, proto_hicp);
}

void
proto_reg_handoff_hicp(void)
{
    dissector_add_uint("udp.port", HICP_PORT, hicp_handle);
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
