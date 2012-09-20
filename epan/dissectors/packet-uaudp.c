/* packet-uaudp.c
 * Routines for UA/UDP (Universal Alcatel over UDP) packet dissection.
 * Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include "epan/packet.h"
#include "epan/prefs.h"
#include "epan/tap.h"

#include "packet-uaudp.h"

/* GLOBALS */

#if 0
static dissector_table_t uaudp_opcode_dissector_table;
#endif

#if 0
static int uaudp_tap                = -1;
#endif

static tap_struct_uaudp ua_tap_info;

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
static int hf_uaudp_expseq          = -1;
static int hf_uaudp_sntseq          = -1;

static gint ett_uaudp               = -1;

/* pref */
static guint8 sys_ip[4];
static const char* pref_sys_ip_s = "";

static gboolean use_sys_ip = FALSE;
static gboolean decode_ua  = TRUE;

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
    { 0, NULL }
};
value_string_ext uaudp_opcode_str_ext = VALUE_STRING_EXT_INIT(uaudp_opcode_str);

#if 0 /* XXX: Unused ? */
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
    { 0, NULL }
};
value_string_ext uaudp_connect_vals_ext = VALUE_STRING_EXT_INIT(uaudp_connect_vals);
#endif

static dissector_handle_t ua_sys_to_term_handle;
static dissector_handle_t ua_term_to_sys_handle;

typedef struct
{
    const char *name;
    const char *text;
    guint port;
    guint last_port;
} prefs_uaudp_t;

static prefs_uaudp_t ports[] =
{
    {"port1", "Terminal UDP port (setting 1)",  32000,  32000},
    {"port2", "Terminal UDP port (setting 2)",  32512,  32512},
    {"port3", "Terminal UDP port (setting 3)",  0,  0},
    {"port4", "Terminal UDP port (setting 4)",  0,  0},
#if 0
    {"port5", "Terminal UDP port (setting 5)",  0,  0},
    {"port6", "Terminal UDP port (setting 6)",  0,  0},
    {"port7", "Terminal UDP port (setting 7)",  0,  0},
    {"port8", "Terminal UDP port (setting 8)",  0,  0}
#endif
};
#define MAX_TERMINAL_PORTS (signed)(array_length(ports))

static gboolean find_terminal_port(guint port)
{
    int i;
    for (i=0; i<MAX_TERMINAL_PORTS; i++)
        if (ports[i].port == port)
            return TRUE;
    return FALSE;
}


static void rV(proto_tree *tree, int *V, tvbuff_t *tvb, gint offset, gint8 L)
{
    switch(L)
    {
    case 1:
        proto_tree_add_uint(tree,
                    *V,
                    tvb,
                    offset,
                    L+2,
                    tvb_get_guint8(tvb, offset+2));
        break;
    case 2:
        proto_tree_add_uint(tree,
                    *V,
                    tvb,
                    offset,
                    L+2,
                    tvb_get_ntohs(tvb, offset+2));
        break;
    case 3:
        proto_tree_add_uint(tree,
                    *V,
                    tvb,
                    offset,
                    L+2,
                    tvb_get_ntoh24(tvb, offset+2));
        break;
    case 4:
        proto_tree_add_uint(tree,
                    *V,
                    tvb,
                    offset,
                    L+2,
                    tvb_get_ntohl(tvb, offset+2));
        break;
    }
}


/* UA/UDP DISSECTOR */
static void _dissect_uaudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           e_ua_direction direction)
{
    gint        offset = 0;
    guint8      opcode;
    proto_item *uaudp_item;
    proto_tree *uaudp_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UAUDP");

    /* get the identifier; it means operation code */
    opcode = tvb_get_guint8(tvb, offset);
    offset += 1;

    ua_tap_info.opcode = opcode;
    ua_tap_info.expseq = 0;
    ua_tap_info.sntseq = 0;

    /* print in "INFO" column the type of UAUDP message */
    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo,
                 COL_INFO,
                 "%s",
                 val_to_str_ext(opcode, &uaudp_opcode_str_ext, "unknown (0x%02x)"));

    uaudp_item = proto_tree_add_protocol_format(tree, proto_uaudp, tvb, 0, 5,
                            "Universal Alcatel/UDP Encapsulation Protocol, %s",
                            val_to_str_ext(opcode, &uaudp_opcode_str_ext, "unknown (0x%02x)"));

    uaudp_tree = proto_item_add_subtree(uaudp_item, ett_uaudp);

    /* print the identifier */
    proto_tree_add_uint(uaudp_tree, hf_uaudp_opcode, tvb, 0, 1, opcode);

    switch(opcode)
    {
    case UAUDP_CONNECT:
    {
        if (!tree)
            break;
        while (tvb_offset_exists(tvb, offset))
        {
            guint8 T = tvb_get_guint8(tvb, offset+0);
            guint8 L = tvb_get_guint8(tvb, offset+1);

            switch(T)
            {
            case UAUDP_CONNECT_VERSION:
                rV(uaudp_tree, &hf_uaudp_version        , tvb, offset, L);
                break;
            case UAUDP_CONNECT_WINDOW_SIZE:
                rV(uaudp_tree, &hf_uaudp_window_size    , tvb, offset, L);
                break;
            case UAUDP_CONNECT_MTU:
                rV(uaudp_tree, &hf_uaudp_mtu            , tvb, offset, L);
                break;
            case UAUDP_CONNECT_UDP_LOST:
                rV(uaudp_tree, &hf_uaudp_udp_lost       , tvb, offset, L);
                break;
            case UAUDP_CONNECT_UDP_LOST_REINIT:
                rV(uaudp_tree, &hf_uaudp_udp_lost_reinit, tvb, offset, L);
                break;
            case UAUDP_CONNECT_KEEPALIVE:
                rV(uaudp_tree, &hf_uaudp_keepalive      , tvb, offset, L);
                break;
            case UAUDP_CONNECT_QOS_IP_TOS:
                rV(uaudp_tree, &hf_uaudp_qos_ip_tos     , tvb, offset, L);
                break;
            case UAUDP_CONNECT_QOS_8021_VLID:
                rV(uaudp_tree, &hf_uaudp_qos_8021_vlid  , tvb, offset, L);
                break;
            case UAUDP_CONNECT_QOS_8021_PRI:
                rV(uaudp_tree, &hf_uaudp_qos_8021_pri   , tvb, offset, L);
                break;
            }
            offset += (2 + L);
        }
        break;
    }

    case UAUDP_NACK:
    {
        proto_tree_add_uint(uaudp_tree,
                    hf_uaudp_expseq,
                    tvb,
                    offset,
                    2,
                    tvb_get_ntohs(tvb, offset));
        break;
    }

    case UAUDP_DATA:
    {
        int datalen;

        proto_tree_add_uint(uaudp_tree,
                    hf_uaudp_expseq,
                    tvb,
                    offset+0,
                    2,
                    tvb_get_ntohs(tvb, offset+0));

        proto_tree_add_uint(uaudp_tree,
                    hf_uaudp_sntseq,
                    tvb,
                    offset+2,
                    2,
                    tvb_get_ntohs(tvb, offset+2));

        ua_tap_info.expseq = hf_uaudp_expseq;
        ua_tap_info.sntseq = hf_uaudp_sntseq;

        offset  += 4;
        datalen  = tvb_reported_length(tvb) - offset;

        /* if there is remaining data, call the UA dissector */
        if (datalen > 0)
        {
            if (direction == SYS_TO_TERM)
                call_dissector(ua_sys_to_term_handle,
                           tvb_new_subset(tvb, offset, datalen, datalen),
                           pinfo,
                           tree);
            else if (direction == TERM_TO_SYS)
                call_dissector(ua_term_to_sys_handle,
                           tvb_new_subset(tvb, offset, datalen, datalen),
                           pinfo,
                           tree);
            else {
                /* XXX: expert ?? */
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_add_str(pinfo->cinfo,
                            COL_INFO,
                            "Data - Couldn't resolve direction. Check UAUDP Preferences.");
            }
            ua_tap_info.expseq = hf_uaudp_expseq;
        }
        else {
            /* print in "INFO" column */
            col_add_str(pinfo->cinfo,
                        COL_INFO,
                        "Data ACK");
        }
        break;
    }
    default:
        break;
    }
#if 0
    tap_queue_packet(uaudp_tap, pinfo, &ua_tap_info);
#endif
}

#if 0
/* XXX: The following are never actually used ?? */
static void dissect_uaudp_dir_unknown(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    _dissect_uaudp(tvb, pinfo, tree, DIR_UNKNOWN);
}

static void dissect_uaudp_term_to_serv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    _dissect_uaudp(tvb, pinfo, tree, TERM_TO_SYS);
}

static void dissect_uaudp_serv_to_term(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    _dissect_uaudp(tvb, pinfo, tree, SYS_TO_TERM);
}
#endif

/*
 * UA/UDP DISSECTOR
 Wireshark packet dissector entry point
*/
static void dissect_uaudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* server address, if present, has precedence on ports */
    if (use_sys_ip) {
        /* use server address to find direction*/
        if (memcmp((pinfo->src).data, sys_ip, 4*sizeof(guint8)) == 0)
        {
            _dissect_uaudp(tvb, pinfo, tree, SYS_TO_TERM);
            return;
        }
        else if (memcmp((pinfo->dst).data, sys_ip, 4*sizeof(guint8)) == 0)
        {
            _dissect_uaudp(tvb, pinfo, tree, TERM_TO_SYS);
            return;
        }
    }

    /* use ports to find direction */
    if (find_terminal_port(pinfo->srcport))
    {
        _dissect_uaudp(tvb, pinfo, tree, TERM_TO_SYS);
        return;
    }
    else if (find_terminal_port(pinfo->destport))
    {
        _dissect_uaudp(tvb, pinfo, tree, SYS_TO_TERM);
        return;
    }

    _dissect_uaudp(tvb, pinfo, tree, DIR_UNKNOWN);
}

/* XXX: Presumably there's a util fcn for this ... */
static gboolean str_to_addr_ip(const gchar *addr, guint8 *ad)
{
    int          i;
    const gchar *p = addr;
    guint32      value;

    if (addr == NULL)
        return FALSE;

    for (i=0; i<4; i++)
    {
        value = 0;
        while (*p != '.' && *p != '\0')
        {
            value = value * 10 + (*p - '0');
            p++;
        }
        if (value > 255)
        {
            return FALSE;
        }
        ad[i] = value;
        p++;
    }

    return TRUE;
}


/* Register the protocol with Wireshark */
void proto_reg_handoff_uaudp(void);

void proto_register_uaudp(void)
{
    module_t *uaudp_module;
    int       i;

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
    };

    /* Setup protocol subtree array */
    static gint *ett[] =
        {
            &ett_uaudp,
        };

    /* Register the protocol name and description */
    proto_uaudp = proto_register_protocol("UA/UDP Encapsulation Protocol",
                          "UAUDP",
                          "uaudp");

    register_dissector("uaudp",              dissect_uaudp, proto_uaudp);
#if 0 /* XXX: Not used ?? */
    register_dissector("uaudp_dir_unknown",  dissect_uaudp_dir_unknown,  proto_uaudp);
    register_dissector("uaudp_term_to_serv", dissect_uaudp_term_to_serv, proto_uaudp);
    register_dissector("uaudp_serv_to_term", dissect_uaudp_serv_to_term, proto_uaudp);
#endif

    proto_register_field_array(proto_uaudp, hf_uaudp, array_length(hf_uaudp));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    uaudp_module = prefs_register_protocol(proto_uaudp, proto_reg_handoff_uaudp);

#if 0
    prefs_register_bool_preference(uaudp_module, "enable",
                       "Enable UA/UDP decoding based on preferences",
                       "Enable UA/UDP decoding based on preferences",
                       &decode_ua);
#endif
    for (i=0; i<MAX_TERMINAL_PORTS; i++) {
        prefs_register_uint_preference(uaudp_module,
                           ports[i].name,
                           ports[i].text,
                           ports[i].text,
                           10,
                           &ports[i].port);
    }
    prefs_register_string_preference(uaudp_module, "system_ip",
                     "System IP Address (optional)",
                     "IPv4 address of the DHS3 system."
                     " (Used only in case of identical source and destination ports)",
                     &pref_sys_ip_s);

#if 0
    /* Register tap  */
    uaudp_tap = register_tap("uaudp");*/
#endif
}


void proto_reg_handoff_uaudp(void)
{
    static gboolean           prefs_initialized = FALSE;
    static dissector_handle_t uaudp_handle;
    int i;

    if (!prefs_initialized)
    {
        uaudp_handle          = find_dissector("uaudp");
        ua_sys_to_term_handle = find_dissector("ua_sys_to_term");
        ua_term_to_sys_handle = find_dissector("ua_term_to_sys");
#if 0
        uaudp_opcode_dissector_table =
            register_dissector_table("uaudp.opcode",
                                     "UAUDP opcode",
                                     FT_UINT8,
                                     BASE_DEC);
#endif
        prefs_initialized     = TRUE;
    }
    else
    {
        for (i=0; i<MAX_TERMINAL_PORTS; i++)
        {
            if (ports[i].last_port)
                dissector_delete_uint("udp.port", ports[i].last_port, uaudp_handle);
        }
        if (str_to_addr_ip(pref_sys_ip_s, sys_ip))
        {
            use_sys_ip = TRUE;
        }
        else
        {
            use_sys_ip = FALSE;
            pref_sys_ip_s = "";
        }
    }

    if (decode_ua)
    {
        int no_ports_registered = TRUE;

        for (i=0; i < MAX_TERMINAL_PORTS; i++)
        {
            if (ports[i].port)
            {
                dissector_add_uint("udp.port", ports[i].port, uaudp_handle);
                no_ports_registered = FALSE;
            }
            ports[i].last_port = ports[i].port;
        }

        if (no_ports_registered)
        {
            /* If all ports are set to 0, then just register the handle so
             * at least "Decode As..." will work. */
            dissector_add_handle("udp.port", uaudp_handle);
        }
    }
}

