/* packet-uaudp.c
 * Routines for UA/UDP (Universal Alcatel over UDP) packet dissection.
 * Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
 * Copyright 2018, Alcatel-Lucent Enterprise <nicolas.bertin@al-enterprise.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wsutil/report_message.h>

#include "packet-uaudp.h"

void proto_register_uaudp(void);
void proto_reg_handoff_uaudp(void);

/* GLOBALS */

static dissector_handle_t uaudp_handle;

static int proto_uaudp              = -1;

static int hf_uaudp_opcode          = -1;
static int hf_uaudp_version         = -1;
static int hf_uaudp_window_size     = -1;
static int hf_uaudp_mtu             = -1;
static int hf_uaudp_udp_lost        = -1;
static int hf_uaudp_udp_lost_reinit = -1;
static int hf_uaudp_keepalive       = -1;
static int hf_uaudp_qos_ip_tos      = -1;
static int hf_uaudp_qos_8021_vlid   = -1;
static int hf_uaudp_qos_8021_pri    = -1;
static int hf_uaudp_superfast_connect = -1;
static int hf_uaudp_expseq          = -1;
static int hf_uaudp_sntseq          = -1;
static int hf_uaudp_type            = -1;
static int hf_uaudp_length          = -1;
static int hf_uaudp_startsig_reserved = -1;
static int hf_uaudp_startsig_filename = -1;

static gint ett_uaudp               = -1;
static gint ett_uaudp_tlv           = -1;

static expert_field ei_uaudp_tlv_length = EI_INIT;

/* pref */
#define UAUDP_PORT_RANGE "32000,32512" /* Not IANA registered */
static range_t *ua_udp_range = NULL;
static address cs_address = ADDRESS_INIT_NONE;
static ws_in4_addr cs_ipv4;
static ws_in6_addr cs_ipv6;
static const char* pref_sys_ip_s = "";

static gboolean use_sys_ip = FALSE;

static const value_string uaudp_opcode_str[] =
{
    { UAUDP_CONNECT,        "Connect" },
    { UAUDP_CONNECT_ACK,    "Connect ACK" },
    { UAUDP_RELEASE,        "Release" },
    { UAUDP_RELEASE_ACK,    "Release ACK" },
    { UAUDP_KEEPALIVE,      "Keepalive" },
    { UAUDP_KEEPALIVE_ACK,  "Keepalive ACK" },
    { UAUDP_NACK,           "NACK" },
    { UAUDP_DATA,           "Data" },
    { UAUDP_START_SIG,      "StartSig" },
    { UAUDP_START_SIG_ACK,  "StartSig ACK" },
    { 0, NULL }
};
value_string_ext uaudp_opcode_str_ext = VALUE_STRING_EXT_INIT(uaudp_opcode_str);

static const value_string uaudp_connect_vals[] =
{
    { UAUDP_CONNECT_VERSION,        "Version" },
    { UAUDP_CONNECT_WINDOW_SIZE,    "Window Size" },
    { UAUDP_CONNECT_MTU,            "MTU" },
    { UAUDP_CONNECT_UDP_LOST,       "UDP lost" },
    { UAUDP_CONNECT_UDP_LOST_REINIT,"UDP lost reinit" },
    { UAUDP_CONNECT_KEEPALIVE,      "Keepalive" },
    { UAUDP_CONNECT_QOS_IP_TOS,     "QoS IP TOS" },
    { UAUDP_CONNECT_QOS_8021_VLID,  "QoS 802.1 VLID" },
    { UAUDP_CONNECT_QOS_8021_PRI,   "QoS 802.1 PRI"},
    { UAUDP_CONNECT_SUPERFAST_CONNECT, "SuperFast Connect"},
    { 0, NULL }
};
value_string_ext uaudp_connect_vals_ext = VALUE_STRING_EXT_INIT(uaudp_connect_vals);

static dissector_handle_t ua_sys_to_term_handle;
static dissector_handle_t ua_term_to_sys_handle;

/* UA/UDP DISSECTOR */
static void _dissect_uaudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           e_ua_direction direction)
{
    gint        offset = 0;
    guint32     type, length;
    guint8      opcode;
    proto_item *uaudp_item, *tlv_item, *tlv_len_item;
    proto_tree *uaudp_tree, *connect_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UAUDP");

    /* get the identifier; it means operation code */
    opcode = tvb_get_guint8(tvb, offset);
    offset += 1;

    /* print in "INFO" column the type of UAUDP message */
    col_add_fstr(pinfo->cinfo,
                COL_INFO,
                "%s",
                val_to_str_ext(opcode, &uaudp_opcode_str_ext, "unknown (0x%02x)"));

    uaudp_item = proto_tree_add_protocol_format(tree, proto_uaudp, tvb, 0, tvb_reported_length(tvb),
                            "Universal Alcatel/UDP Encapsulation Protocol, %s",
                            val_to_str_ext(opcode, &uaudp_opcode_str_ext, "unknown (0x%02x)"));

    uaudp_tree = proto_item_add_subtree(uaudp_item, ett_uaudp);

    /* print the identifier */
    proto_tree_add_uint(uaudp_tree, hf_uaudp_opcode, tvb, 0, 1, opcode);

    switch(opcode)
    {
    case UAUDP_CONNECT:
    {
        while(tvb_reported_length_remaining(tvb, offset) > 0)
        {
            type = tvb_get_guint8(tvb, offset+0);
            connect_tree = proto_tree_add_subtree(uaudp_tree, tvb, offset, 0, ett_uaudp_tlv, &tlv_item,
                                                    val_to_str_ext(type, &uaudp_connect_vals_ext, "Unknown %d"));
            proto_tree_add_uint(connect_tree, hf_uaudp_type, tvb, offset, 1, type);
            offset++;
            tlv_len_item = proto_tree_add_item_ret_uint(connect_tree, hf_uaudp_length, tvb, offset, 1, ENC_NA, &length);
            proto_item_set_len(tlv_item, length+2);
            offset++;

            if ((length >= 1) && (length <= 4))
            {
                switch(type)
                {
                    case UAUDP_CONNECT_VERSION:
                        proto_tree_add_item(connect_tree, hf_uaudp_version, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case UAUDP_CONNECT_WINDOW_SIZE:
                        proto_tree_add_item(connect_tree, hf_uaudp_window_size, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case UAUDP_CONNECT_MTU:
                        proto_tree_add_item(connect_tree, hf_uaudp_mtu, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case UAUDP_CONNECT_UDP_LOST:
                        proto_tree_add_item(connect_tree, hf_uaudp_udp_lost, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case UAUDP_CONNECT_UDP_LOST_REINIT:
                        proto_tree_add_item(connect_tree, hf_uaudp_udp_lost_reinit, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case UAUDP_CONNECT_KEEPALIVE:
                        proto_tree_add_item(connect_tree, hf_uaudp_keepalive, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case UAUDP_CONNECT_QOS_IP_TOS:
                        proto_tree_add_item(connect_tree, hf_uaudp_qos_ip_tos, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case UAUDP_CONNECT_QOS_8021_VLID:
                        proto_tree_add_item(connect_tree, hf_uaudp_qos_8021_vlid, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case UAUDP_CONNECT_QOS_8021_PRI:
                        proto_tree_add_item(connect_tree, hf_uaudp_qos_8021_pri, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                    case UAUDP_CONNECT_SUPERFAST_CONNECT:
                        proto_tree_add_item(connect_tree, hf_uaudp_superfast_connect, tvb, offset, length, ENC_BIG_ENDIAN);
                        break;
                }
            }
            else
            {
                expert_add_info_format(pinfo, tlv_len_item, &ei_uaudp_tlv_length, "Invalid length %d", length);
            }
            offset += length;
        }
        break;
    }

    case UAUDP_NACK:
    {
        proto_tree_add_item(uaudp_tree,
                    hf_uaudp_expseq,
                    tvb,
                    offset,
                    2,
                    ENC_BIG_ENDIAN);
        break;
    }

    case UAUDP_DATA:
    {
        int datalen;

        proto_tree_add_item(uaudp_tree,
                    hf_uaudp_expseq,
                    tvb,
                    offset+0,
                    2,
                    ENC_BIG_ENDIAN);

        proto_tree_add_item(uaudp_tree,
                    hf_uaudp_sntseq,
                    tvb,
                    offset+2,
                    2,
                    ENC_BIG_ENDIAN);

        offset  += 4;
        datalen  = tvb_reported_length(tvb) - offset;

        /* if there is remaining data, call the UA dissector */
        if (datalen > 0)
        {
            if (direction == SYS_TO_TERM)
                call_dissector(ua_sys_to_term_handle,
                           tvb_new_subset_length(tvb, offset, datalen),
                           pinfo,
                           tree);
            else if (direction == TERM_TO_SYS)
                call_dissector(ua_term_to_sys_handle,
                           tvb_new_subset_length(tvb, offset, datalen),
                           pinfo,
                           tree);
            else {
                /* XXX: expert ?? */
                col_set_str(pinfo->cinfo,
                            COL_INFO,
                            "Data - Couldn't resolve direction. Check UAUDP Preferences.");
            }
        }
        else {
            /* print in "INFO" column */
            col_set_str(pinfo->cinfo,
                        COL_INFO,
                        "Data ACK");
        }
        break;
    }

    case UAUDP_START_SIG:
    {
        proto_tree_add_item(uaudp_tree, hf_uaudp_startsig_reserved, tvb, offset, 6, ENC_NA);
        offset += 6;
        proto_tree_add_item(uaudp_tree, hf_uaudp_startsig_filename, tvb, offset, tvb_strsize(tvb, offset)-1, ENC_ASCII|ENC_NA);
        break;
    }

    default:
        break;
    }
}

/*
 * UA/UDP DISSECTOR
 Wireshark packet dissector entry point
*/
static int dissect_uaudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* server address, if present, has precedence on ports */
    if (use_sys_ip) {
        /* use server address to find direction*/
        if (addresses_equal((address *)&pinfo->src, (address *)&cs_address))
        {
            _dissect_uaudp(tvb, pinfo, tree, SYS_TO_TERM);
            return tvb_captured_length(tvb);
        }
        else if (addresses_equal((address *)&pinfo->dst, (address *)&cs_address))
        {
            _dissect_uaudp(tvb, pinfo, tree, TERM_TO_SYS);
            return tvb_captured_length(tvb);
        }
    }

    /* use ports to find direction */
    if (value_is_in_range(ua_udp_range, pinfo->srcport))
    {
        _dissect_uaudp(tvb, pinfo, tree, TERM_TO_SYS);
        return tvb_captured_length(tvb);
    }
    else if (value_is_in_range(ua_udp_range, pinfo->destport))
    {
        _dissect_uaudp(tvb, pinfo, tree, SYS_TO_TERM);
        return tvb_captured_length(tvb);
    }

    _dissect_uaudp(tvb, pinfo, tree, DIR_UNKNOWN);
    return tvb_captured_length(tvb);
}

static void
apply_uaudp_prefs(void) {
    ua_udp_range = prefs_get_range_value("uaudp", "udp.port");

    use_sys_ip = FALSE;
    if (*pref_sys_ip_s) {
        use_sys_ip = ws_inet_pton4(pref_sys_ip_s, &cs_ipv4);
        if (use_sys_ip) {
            set_address((address *)&cs_address, AT_IPv4, sizeof(ws_in4_addr), &cs_ipv4);
            return;
        }
        use_sys_ip = ws_inet_pton6(pref_sys_ip_s, &cs_ipv6);
        if (use_sys_ip) {
            set_address((address *)&cs_address, AT_IPv6, sizeof(ws_in6_addr), &cs_ipv6);
            return;
        }
        report_failure("Invalid value for pref uaudp.system_ip: %s", pref_sys_ip_s);
    }
}

void proto_register_uaudp(void)
{
    module_t *uaudp_module;

    /* Setup list of header fields. See Section 1.6.1 for details */
    static hf_register_info hf_uaudp[] = {
        {
            &hf_uaudp_opcode,
            {
                "Opcode",
                "uaudp.opcode",
                FT_UINT8,
                BASE_DEC | BASE_EXT_STRING,
                &uaudp_opcode_str_ext,
                0x0,
                "UA/UDP Opcode",
                HFILL
            }
        },
        {
            &hf_uaudp_version,
            {
                "Version",
                "uaudp.version",
                FT_UINT8,
                BASE_DEC,
                NULL, 0x0,
                "UA/UDP Version",
                HFILL
            }
        },
        {
            &hf_uaudp_window_size,
            {
                "Window Size",
                "uaudp.window_size",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP Window Size",
                HFILL
            }
        },
        {
            &hf_uaudp_mtu,
            {
                "MTU",
                "uaudp.mtu",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP MTU",
                HFILL
            }
        },
        {
            &hf_uaudp_udp_lost,
            {
                "UDP Lost",
                "uaudp.udp_lost",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP Lost",
                HFILL
            }
        },
        {
            &hf_uaudp_udp_lost_reinit,
            {
                "UDP lost reinit",
                "uaudp.udp_lost_reinit",
                FT_UINT8,
                BASE_DEC,
                NULL, 0x0,
                "UA/UDP Lost Re-Init",
                HFILL
            }
        },
        {
            &hf_uaudp_keepalive,
            {
                "Keepalive",
                "uaudp.keepalive",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP Keepalive",
                HFILL
            }
        },
        {
            &hf_uaudp_qos_ip_tos,
            {
                "QoS IP TOS",
                "uaudp.qos_ip_tos",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP QoS IP TOS",
                HFILL
            }
        },
        {
            &hf_uaudp_qos_8021_vlid,
            {
                "QoS 802.1 VLID",
                "uaudp.qos_8021_vlid",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP QoS 802.1 VLID",
                HFILL
            }
        },
        {
            &hf_uaudp_qos_8021_pri,
            {
                "QoS 802.1 PRI",
                "uaudp.qos_8021_pri",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP QoS 802.1 PRI",
                HFILL
            }
        },
        {
            &hf_uaudp_superfast_connect,
            {
                "SuperFast Connect",
                "uaudp.superfast_connect",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP SuperFast Connect",
                HFILL
            }
        },
        {
            &hf_uaudp_expseq,
            {
                "Sequence Number (expected)",
                "uaudp.expseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP Expected Sequence Number",
                HFILL
            }
        },
        {
            &hf_uaudp_sntseq,
            {
                "Sequence Number (sent)",
                "uaudp.sntseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "UA/UDP Sent Sequence Number",
                HFILL
            }
        },
        {
            &hf_uaudp_type,
            {
                "Type",
                "uaudp.type",
                FT_UINT8,
                BASE_DEC|BASE_EXT_STRING,
                &uaudp_connect_vals_ext,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_uaudp_length,
            {
                "Length",
                "uaudp.length",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_uaudp_startsig_reserved,
            {
                "Reserved",
                "uaudp.startsig.reserved",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_uaudp_startsig_filename,
            {
                "Filename",
                "uaudp.startsig.filename",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },

    };

    /* Setup protocol subtree array */
    static gint *ett[] =
        {
            &ett_uaudp,
            &ett_uaudp_tlv,
        };

    static ei_register_info ei[] = {
        { &ei_uaudp_tlv_length, { "uaudp.tlv_length_invalid", PI_PROTOCOL, PI_WARN, "Invalid length", EXPFILL }},
    };
    expert_module_t* expert_uaudp;

    /* Register the protocol name and description */
    proto_uaudp = proto_register_protocol("UA/UDP Encapsulation Protocol", "UAUDP", "uaudp");

    uaudp_handle = register_dissector("uaudp", dissect_uaudp, proto_uaudp);

    proto_register_field_array(proto_uaudp, hf_uaudp, array_length(hf_uaudp));
    proto_register_subtree_array(ett, array_length(ett));
    expert_uaudp = expert_register_protocol(proto_uaudp);
    expert_register_field_array(expert_uaudp, ei, array_length(ei));

    /* Register preferences */
    uaudp_module = prefs_register_protocol(proto_uaudp, apply_uaudp_prefs);

    prefs_register_string_preference(uaudp_module, "system_ip",
                     "Call Server IP Address (optional)",
                     "IPv4 (or IPv6) address of the call server."
                     " (Used only in case of identical source and destination ports)",
                     &pref_sys_ip_s);
}

void proto_reg_handoff_uaudp(void)
{
    ua_sys_to_term_handle = find_dissector_add_dependency("ua_sys_to_term", proto_uaudp);
    ua_term_to_sys_handle = find_dissector_add_dependency("ua_term_to_sys", proto_uaudp);

    dissector_add_uint_range_with_preference("udp.port", UAUDP_PORT_RANGE, uaudp_handle);
    apply_uaudp_prefs();
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
