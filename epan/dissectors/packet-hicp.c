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

void proto_reg_handoff_hicp(void);
void proto_register_hicp(void);

/* Protocols and header fields. */
static int proto_hicp = -1;
static int hf_hicp_cmd = -1;
static int hf_hicp_proto_version = -1;
static int hf_hicp_fb_type = -1;
static int hf_hicp_module_version = -1;
static int hf_hicp_mac = -1;
static int hf_hicp_ip = -1;
static int hf_hicp_sn = -1;
static int hf_hicp_gw = -1;
static int hf_hicp_dhcp = -1;
static int hf_hicp_pswd_required = -1;
static int hf_hicp_hn = -1;
static int hf_hicp_dns1 = -1;
static int hf_hicp_dns2 = -1;
static int hf_hicp_ext = -1;
static int hf_hicp_pswd = -1;
static int hf_hicp_new_pswd = -1;
static int hf_hicp_new_mac = -1;
static int hf_hicp_status = -1;
static int hf_hicp_error = -1;
static int hf_hicp_target = -1;
static int hf_hicp_src = -1;

static expert_field ei_hicp_error = EI_INIT;

static gint ett_hicp = -1;

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

    guint offset = 0;
    gint lengthp = 0;
    gdouble ext_value = 0;

    const guint8* parameters_ptr = NULL;
    gchar** parameters = NULL;
    gchar* parameter_value = NULL;

	/* Check that the packet does not start with the header of Secure Host IP Configuration Protocol (SHICP). */
    if ((tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN) & 0xFFFE) == 0xABC0) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HICP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_hicp, tvb, offset, -1, ENC_NA);

    hicp_tree = proto_item_add_subtree(ti, ett_hicp);

    parameters_ptr = tvb_get_const_stringz(tvb, offset, &lengthp);
    parameters = wmem_strsplit(pinfo->pool, (const gchar*)parameters_ptr, HICP_DELIMITER, -1);
    for (guint i = 0; i < g_strv_length(parameters); i++) {
        if (g_strrstr(parameters[i], " = ") != NULL) {
            parameter_value = &(g_strrstr(parameters[i], " = "))[3];
        }
        else if (g_strrstr(parameters[i], ": ") != NULL) {
            parameter_value = &(g_strrstr(parameters[i], ": "))[2];
        }
        else {
            parameter_value = "";
        }
        if (g_ascii_strncasecmp(parameters[i], HICP_MODULE_SCAN_COMMAND, (gsize)strlen(HICP_MODULE_SCAN_COMMAND)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_cmd, tvb, offset, (gint)strlen(parameters[i]), HICP_MODULE_SCAN_COMMAND);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Request message, Command: %s", HICP_MODULE_SCAN_COMMAND);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_CONFIG_COMMAND, (gsize)strlen(HICP_CONFIG_COMMAND)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_cmd, tvb, offset, (gint)strlen(parameters[i]), HICP_CONFIG_COMMAND);
            proto_tree_add_string(hicp_tree, hf_hicp_target, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Request message, Command: %s", HICP_CONFIG_COMMAND);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_WINK_COMMAND, (gsize)strlen(HICP_WINK_COMMAND)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_cmd, tvb, offset, (gint)strlen(parameters[i]), HICP_WINK_COMMAND);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Request message, Command: %s", HICP_WINK_COMMAND);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_PROTOCOL_VERSION, (gsize)strlen(HICP_PROTOCOL_VERSION)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_cmd, tvb, offset, (gint)strlen(parameters[i]), HICP_MODULE_SCAN_COMMAND);
            proto_tree_add_string(hicp_tree, hf_hicp_proto_version, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Response message, Command: %s", HICP_MODULE_SCAN_COMMAND);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_FB_TYPE, (gsize)strlen(HICP_FB_TYPE)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_fb_type, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_MODULE_VERSION, (gsize)strlen(HICP_MODULE_VERSION)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_module_version, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_MAC, (gsize)strlen(HICP_MAC)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_mac, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_IP, (gsize)strlen(HICP_IP)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_ip, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_SN, (gsize)strlen(HICP_SN)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_sn, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_GW, (gsize)strlen(HICP_GW)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_gw, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_DHCP, (gsize)strlen(HICP_DHCP)) == 0) {
            proto_tree_add_string(hicp_tree,
                hf_hicp_dhcp,
                tvb,
                offset,
                (gint)strlen(parameters[i]),
                g_ascii_strcasecmp(parameter_value, "ON") == 0 ? "Enabled" : "Disabled");
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_PSWD_REQUIRED, (gsize)strlen(HICP_PSWD_REQUIRED)) == 0) {
            proto_tree_add_string(hicp_tree,
                hf_hicp_pswd_required,
                tvb,
                offset,
                (gint)strlen(parameters[i]),
                g_ascii_strcasecmp(parameter_value, "ON") == 0 ? "Required" : "Not required");
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_HN, (gsize)strlen(HICP_HN)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_hn, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_DNS1, (gsize)strlen(HICP_DNS1)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_dns1, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_DNS2, (gsize)strlen(HICP_DNS2)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_dns2, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_EXT, (gsize)strlen(HICP_EXT)) == 0) {
            ext_value = g_ascii_strtod(parameter_value, NULL);
            if (ext_value == 1) {
                parameter_value = HICP_WINK_COMMAND;
            }
            else if (ext_value == 0) {
                parameter_value = "None";
            }
            proto_tree_add_string(hicp_tree, hf_hicp_ext, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_PSWD, (gsize)strlen(HICP_PSWD)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_pswd, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_NEW_PSWD, (gsize)strlen(HICP_NEW_PSWD)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_new_pswd, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_NEW_MAC, (gsize)strlen(HICP_NEW_MAC)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_new_mac, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_RECONFIGURED, (gsize)strlen(HICP_RECONFIGURED)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_status, tvb, offset, (gint)strlen(parameters[i]), HICP_RECONFIGURED);
            proto_tree_add_string(hicp_tree, hf_hicp_src, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Respond message, Command: %s", HICP_CONFIG_COMMAND);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_INVALID_PSWD, (gsize)strlen(HICP_INVALID_PSWD)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_src, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
            error_pi = proto_tree_add_string(hicp_tree, hf_hicp_error, tvb, offset, (gint)strlen(parameters[i]), HICP_INVALID_PSWD);
            expert_add_info(pinfo, error_pi, &ei_hicp_error);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Error: %s", HICP_INVALID_PSWD);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: %s, Module MAC address: %s", HICP_CONFIG_COMMAND, parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_INVALID_CONFIG, (gsize)strlen(HICP_INVALID_CONFIG)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_src, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
            error_pi = proto_tree_add_string(hicp_tree, hf_hicp_error, tvb, offset, (gint)strlen(parameters[i]), HICP_INVALID_CONFIG);
            expert_add_info(pinfo, error_pi, &ei_hicp_error);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Error: %s", HICP_INVALID_CONFIG);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Command: %s, Module MAC address: %s", HICP_CONFIG_COMMAND, parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_EXECUTED, (gsize)strlen(HICP_EXECUTED)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_status, tvb, offset, (gint)strlen(parameters[i]), HICP_EXECUTED);
            proto_tree_add_string(hicp_tree, hf_hicp_src, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "Respond message, Command: %s", HICP_WINK_COMMAND);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        else if (g_ascii_strncasecmp(parameters[i], HICP_TO, (gsize)strlen(HICP_TO)) == 0) {
            proto_tree_add_string(hicp_tree, hf_hicp_target, tvb, offset, (gint)strlen(parameters[i]), parameter_value);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Module MAC address: %s", parameter_value);
        }
        offset += (guint)strlen(parameters[i]) + (guint)strlen(HICP_DELIMITER);
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

    static gint *ett[] = {
        &ett_hicp
    };

    static ei_register_info ei[] = {
        { &ei_hicp_error,
          { "hicp.error", PI_RESPONSE_CODE, PI_NOTE,
            "Message contains an error message.", EXPFILL }
        }
    };

    proto_hicp = proto_register_protocol(
        "Host IP Configuration Protocol",
        "HICP",
        "hicp");

    proto_register_field_array(proto_hicp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_hicp = expert_register_protocol(proto_hicp);
    expert_register_field_array(expert_hicp, ei, array_length(ei));
}

void
proto_reg_handoff_hicp(void)
{
    static dissector_handle_t hicp_handle;

    hicp_handle = create_dissector_handle(dissect_hicp, proto_hicp);

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
