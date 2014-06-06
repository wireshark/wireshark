/* packet-uasip.c
 * Routines for UA/UDP (Universal Alcatel over UDP) and NOE/SIP packet dissection.
 * Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include "epan/packet.h"
#include "epan/prefs.h"
#include "epan/tap.h"
#include <epan/addr_resolv.h>

#include "packet-uaudp.h"

void proto_register_uasip(void);
void proto_reg_handoff_uasip(void);

static tap_struct_uaudp ua_tap_info;
#if 0
static int uasip_tap                = -1;
#endif

static int proto_uasip              = -1;
static int hf_uasip_opcode          = -1;
static int hf_uasip_version         = -1;
static int hf_uasip_window_size     = -1;
static int hf_uasip_mtu             = -1;
static int hf_uasip_udp_lost        = -1;
static int hf_uasip_udp_lost_reinit = -1;
static int hf_uasip_keepalive       = -1;
static int hf_uasip_qos_ip_tos      = -1;
static int hf_uasip_qos_8021_vlid   = -1;
static int hf_uasip_qos_8021_pri    = -1;
static int hf_uasip_expseq          = -1;
static int hf_uasip_sntseq          = -1;
static gint ett_uasip               = -1;

static guint8      proxy_ipaddr[4];
static const char *pref_proxy_ipaddr_s = NULL;

static gboolean uasip_enabled = FALSE;
static gboolean use_proxy_ipaddr = FALSE;
static gboolean noesip_enabled   = FALSE;

static dissector_handle_t uasip_handle;

static dissector_handle_t ua_sys_to_term_handle;
static dissector_handle_t ua_term_to_sys_handle;

static void rTLV(proto_tree *tree, int *V, tvbuff_t *tvb, gint offset, gint8 L)
{
    switch (L)
    {
        case 1:
            proto_tree_add_uint(tree, *V, tvb, offset, L+2, tvb_get_guint8(tvb, offset+2));
        break;

        case 2:
            proto_tree_add_uint(tree, *V, tvb, offset, L+2, tvb_get_ntohs(tvb, offset+2));
        break;

        case 3:
            proto_tree_add_uint(tree, *V, tvb, offset, L+2, tvb_get_ntoh24(tvb, offset+2));
        break;

        case 4:
            proto_tree_add_uint(tree, *V, tvb, offset, L+2, tvb_get_ntohl(tvb, offset+2));
        break;

        default:
        break;
    }
}


static void _dissect_uasip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, e_ua_direction direction)
{
    proto_item *uasip_item;
    proto_tree *uasip_tree;
    guint8      opcode;
    gint        offset = 0;

    if (noesip_enabled)
    {
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "/NOE");
    }
    else
    {
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "/DL");
    }

    opcode = tvb_get_guint8(tvb, offset);
    offset++;

    ua_tap_info.opcode = opcode;
    ua_tap_info.expseq = 0;
    ua_tap_info.sntseq = 0;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_ext(opcode, &uaudp_opcode_str_ext, "unknown (0x%02x)"));

    uasip_item = proto_tree_add_protocol_format(tree, proto_uasip, tvb, 0, 5,
                                                "SIP/NOE Protocol, %s",
                                                val_to_str_ext(opcode, &uaudp_opcode_str_ext, "unknown (0x%02x)"));
    uasip_tree = proto_item_add_subtree(uasip_item, ett_uasip);
    proto_tree_add_uint(uasip_tree, hf_uasip_opcode, tvb, 0, 1, opcode);

    switch(opcode)
    {
        case UAUDP_CONNECT:
        {
            if (!tree)
                break;
            while(tvb_offset_exists(tvb, offset))
            {
                guint8 T = tvb_get_guint8(tvb, offset+0);
                guint8 L = tvb_get_guint8(tvb, offset+1);

                switch(T)
                {
                    case UAUDP_CONNECT_VERSION:
                        rTLV(uasip_tree, &hf_uasip_version, tvb, offset, L);
                    break;

                    case UAUDP_CONNECT_WINDOW_SIZE:
                        rTLV(uasip_tree, &hf_uasip_window_size, tvb, offset, L);
                    break;

                    case UAUDP_CONNECT_MTU:
                        rTLV(uasip_tree, &hf_uasip_mtu, tvb, offset, L);
                    break;

                    case UAUDP_CONNECT_UDP_LOST:
                        rTLV(uasip_tree, &hf_uasip_udp_lost, tvb, offset, L);
                    break;

                    case UAUDP_CONNECT_UDP_LOST_REINIT:
                        rTLV(uasip_tree, &hf_uasip_udp_lost_reinit, tvb, offset, L);
                    break;

                    case UAUDP_CONNECT_KEEPALIVE:
                        rTLV(uasip_tree, &hf_uasip_keepalive, tvb, offset, L);
                    break;

                    case UAUDP_CONNECT_QOS_IP_TOS:
                        rTLV(uasip_tree, &hf_uasip_qos_ip_tos, tvb, offset, L);
                    break;

                    case UAUDP_CONNECT_QOS_8021_VLID:
                        rTLV(uasip_tree, &hf_uasip_qos_8021_vlid, tvb, offset, L);
                    break;

                    case UAUDP_CONNECT_QOS_8021_PRI:
                        rTLV(uasip_tree, &hf_uasip_qos_8021_pri, tvb, offset, L);
                    break;

                    default:
                    break;
                }
                offset += (2 + L);
            }
        }
        break;

        case UAUDP_NACK:
        {
            proto_tree_add_uint(uasip_tree, hf_uasip_expseq, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
            ua_tap_info.expseq = tvb_get_ntohs(tvb, offset+0);

            /*offset += 2;*/

            if (noesip_enabled)
            {
                col_add_fstr(pinfo->cinfo, COL_INFO, "NACK");
            }
            else
            {
                col_add_fstr(pinfo->cinfo, COL_INFO, "NACK exp:%d", ua_tap_info.expseq);
            }
        }
        break;

        case UAUDP_DATA:
        {
            int datalen;

            proto_tree_add_uint(uasip_tree, hf_uasip_expseq, tvb, offset+0, 2, tvb_get_ntohs(tvb, offset+0));
            proto_tree_add_uint(uasip_tree, hf_uasip_sntseq, tvb, offset+2, 2, tvb_get_ntohs(tvb, offset+2));
            ua_tap_info.expseq = tvb_get_ntohs(tvb, offset+0);
            ua_tap_info.sntseq = tvb_get_ntohs(tvb, offset+2);
            offset += 4;
            datalen  = (tvb_length(tvb) - offset);

            if (noesip_enabled)
            {
                if (datalen > 0)
                {
                    if (direction == SYS_TO_TERM)
                    {
                        call_dissector(ua_sys_to_term_handle, tvb_new_subset_length(tvb, offset, datalen), pinfo, tree);
                    }
                    else if (direction == TERM_TO_SYS)
                    {
                        call_dissector(ua_term_to_sys_handle, tvb_new_subset_length(tvb, offset, datalen), pinfo, tree);
                    }
                    else
                    {
                        col_add_str(pinfo->cinfo, COL_INFO, "DATA - Couldn't resolve direction.");
                    }
                }
                else
                {
                    col_add_str(pinfo->cinfo, COL_INFO, "ACK");
                }
            }
            else
            {
                if (datalen > 0)
                {
                    col_add_fstr(pinfo->cinfo, COL_INFO, "DATA exp:%d", ua_tap_info.expseq);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " snt:%d", ua_tap_info.sntseq);
                }
                else
                {
                    col_add_fstr(pinfo->cinfo, COL_INFO, "ACK  exp:%d", ua_tap_info.expseq);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " snt:%d", ua_tap_info.sntseq);
                }
            }
        }
        break;

        default:
        break;
    }
#if 0
    tap_queue_packet(uasip_tap, pinfo, &ua_tap_info);
#endif
}

static void dissect_uasip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (use_proxy_ipaddr)
    {
        if (memcmp((pinfo->src).data, proxy_ipaddr, sizeof(proxy_ipaddr)) == 0)
        {
            _dissect_uasip(tvb, pinfo, tree, SYS_TO_TERM);
            return;
        }
        else if (memcmp((pinfo->dst).data, proxy_ipaddr, sizeof(proxy_ipaddr)) == 0)
        {
            _dissect_uasip(tvb, pinfo, tree, TERM_TO_SYS);
            return;
        }
    }
    _dissect_uasip(tvb, pinfo, tree, DIR_UNKNOWN);
}

void proto_register_uasip(void)
{
    module_t *uasip_module;

    static hf_register_info hf_uasip[] = {
        {
            &hf_uasip_opcode,
            {
                "Opcode",
                "uasip.opcode",
                FT_UINT8,
                BASE_DEC | BASE_EXT_STRING,
                &uaudp_opcode_str_ext,
                0x0,
                "UA/SIP Opcode",
                HFILL
            }
        },
        {
            &hf_uasip_version,
            {
                "Version",
                "uasip.version",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP Version",
                HFILL
            }
        },
        {
            &hf_uasip_window_size,
            {
                "Window Size",
                "uasip.window_size",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP Window Size",
                HFILL
            }
        },
        {
            &hf_uasip_mtu,
            {
                "MTU",
                "uasip.mtu",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP MTU",
                HFILL
            }
        },
        {
            &hf_uasip_udp_lost,
            {
                "UDP Lost",
                "uasip.udp_lost",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP Lost",
                HFILL
            }
        },
        {
            &hf_uasip_udp_lost_reinit,
            {
                "UDP lost reinit",
                "uasip.udp_lost_reinit",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP Lost Re-Init",
                HFILL
            }
        },
        {
            &hf_uasip_keepalive,
            {
                "Keepalive",
                "uasip.keepalive",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP Keepalive",
                HFILL
            }
        },
        {
            &hf_uasip_qos_ip_tos,
            {
                "QoS IP TOS",
                "uasip.qos_ip_tos",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP QoS IP TOS",
                HFILL
            }
        },
        {
            &hf_uasip_qos_8021_vlid,
            {
                "QoS 802.1 VLID",
                "uasip.qos_8021_vlid",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP QoS 802.1 VLID",
                HFILL
            }
        },
        {
            &hf_uasip_qos_8021_pri,
            {
                "QoS 802.1 PRI",
                "uasip.qos_8021_pri",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP QoS 802.1 PRI",
                HFILL
            }
        },
        {
            &hf_uasip_expseq,
            {
                "Sequence Number (expected)",
                "uasip.expseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP Expected Sequence Number",
                HFILL
            }
        },
        {
            &hf_uasip_sntseq,
            {
                "Sequence Number (sent)",
                "uasip.sntseq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                "UA/SIP Sent Sequence Number",
                HFILL
            }
        },
    };

    static gint *ett[] =
    {
        &ett_uasip,
    };

    proto_uasip = proto_register_protocol("UA/SIP Protocol", "UASIP", "uasip");
    uasip_handle = register_dissector("uasip", dissect_uasip, proto_uasip);

    proto_register_field_array(proto_uasip, hf_uasip, array_length(hf_uasip));
    proto_register_subtree_array(ett, array_length(ett));

    uasip_module = prefs_register_protocol(proto_uasip, proto_reg_handoff_uasip);
    prefs_register_bool_preference(uasip_module, "aplication_octet_stream", "Try to decode application/octet-stream as UASIP", "UA SIP Protocol enabled", &uasip_enabled);
    prefs_register_bool_preference(uasip_module, "noesip", "Try to decode SIP NOE", "NOE SIP Protocol", &noesip_enabled);
    prefs_register_string_preference(uasip_module, "proxy_ipaddr", "Proxy IP Address",
                                     "IPv4 address of the proxy (Invalid values will be ignored)",
                                     &pref_proxy_ipaddr_s);
#if 0
    uasip_tap = register_tap("uasip");
#endif
}

void proto_reg_handoff_uasip(void)
{
    static gboolean    prefs_initialized = FALSE;

    if (!prefs_initialized)
    {
        ua_sys_to_term_handle = find_dissector("ua_sys_to_term");
        ua_term_to_sys_handle = find_dissector("ua_term_to_sys");
        prefs_initialized = TRUE;
    }

    use_proxy_ipaddr = FALSE;
    memset(proxy_ipaddr, 0, sizeof(proxy_ipaddr));

    if(uasip_enabled){
        dissector_add_string("media_type", "application/octet-stream", uasip_handle);
    }else{
        dissector_delete_string("media_type", "application/octet-stream", uasip_handle);
    }

    if (strcmp(pref_proxy_ipaddr_s, "") != 0) {
        if (str_to_ip(pref_proxy_ipaddr_s, proxy_ipaddr)) {
            use_proxy_ipaddr = TRUE;
        } else {
            g_warning("uasip: Invalid 'Proxy IP Address': \"%s\"", pref_proxy_ipaddr_s);
        }
    }
}
