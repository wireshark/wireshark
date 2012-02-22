/* packet-uaudp.c
 * Routines for UA/UDP (Universal Alcatel over UDP) packet dissection.
 * Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
 *
 * $Id: 
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "packet-uaudp.h"

#include <string.h>
#include <glib.h>

#include "epan/packet.h"
#include "epan/prefs.h"
#include "epan/tap.h"
#include "epan/value_string.h"


/* GLOBALS */

static int uaudp_tap                = -1;

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
static gboolean decode_ua = TRUE;

#define UAUDP_CONNECT_VERSION           0x00
#define UAUDP_CONNECT_WINDOW_SIZE       0x01
#define UAUDP_CONNECT_MTU               0x02
#define UAUDP_CONNECT_UDP_LOST          0x03
#define UAUDP_CONNECT_UDP_LOST_REINIT   0x04
#define UAUDP_CONNECT_KEEPALIVE         0x05
#define UAUDP_CONNECT_QOS_IP_TOS        0x06
#define UAUDP_CONNECT_QOS_8021_VLID     0x07
#define UAUDP_CONNECT_QOS_8021_PRI      0x08


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


static dissector_handle_t ua_sys_to_term_handle;
static dissector_handle_t ua_term_to_sys_handle;


typedef struct
{
    char   *name;
    char   *text;
    guint   port;
    guint   last_port;
} prefs_uaudp_t;

#define MAX_TERMINAL_PORTS 4

static prefs_uaudp_t ports[MAX_TERMINAL_PORTS] =
{
    {"port1", "Terminal UDP port (setting 1)",	32000,	32000},
    {"port2", "Terminal UDP port (setting 2)",	32512,	32512},
    {"port3", "Terminal UDP port (setting 3)",	0,	0},
    {"port4", "Terminal UDP port (setting 4)",	0,	0},
};
/*
    {"port5", "Terminal UDP port (setting 5)",	0,	0},
    {"port6", "Terminal UDP port (setting 6)",	0,	0},
    {"port7", "Terminal UDP port (setting 7)",	0,	0},
    {"port8", "Terminal UDP port (setting 8)",	0,	0}
};
*/

guint find_terminal_port(guint port)
{
    int i;
    for (i=0; i<MAX_TERMINAL_PORTS; i++)
        if (ports[i].port == port)
            return 1;
    return 0;
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
    proto_item *uaudp_item = NULL;
    proto_tree *uaudp_tree = NULL;
    gint offset = 0;
    guint8 opcode = 0;

    /* print the name of the protocol in the "PROTOCOL" column */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "UAUDP");

    /* get the identifer, it means operation code */
    opcode = tvb_get_guint8(tvb, offset);
    offset++;

    ua_tap_info.opcode = opcode;
    ua_tap_info.expseq = 0;
    ua_tap_info.sntseq = 0;

    /* print in "INFO" column the type of UAUDP message */

    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr(pinfo->cinfo,
             COL_INFO,
             "%s",
             val_to_str(opcode, uaudp_opcode_str, "unknown (0x%02x)"));

    if (tree)
    {
		uaudp_item = proto_tree_add_protocol_format(tree, proto_uaudp, tvb, 0, 5,
			"Universal Alcatel/UDP Encapsulation Protocol, %s",
			val_to_str(opcode, uaudp_opcode_str, "unknown (0x%02x)"));

        uaudp_tree = proto_item_add_subtree(uaudp_item, ett_uaudp);

        /* print the identifier */
        proto_tree_add_uint(uaudp_tree, hf_uaudp_opcode, tvb, 0, 1, opcode);

        switch(opcode)
        {
        case UAUDP_CONNECT:
        {
            while(tvb_offset_exists(tvb, offset))
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
            offset += 2;
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
            datalen  = (tvb_length(tvb) - offset);

            /* if it remains some data, call of UA dissector */
            if (datalen > 0)
            {
                if (direction==SYS_TO_TERM)
                    call_dissector(ua_sys_to_term_handle,
                                   tvb_new_subset(tvb, offset, datalen, datalen),
                                   pinfo,
                                   tree);
                else if (direction==TERM_TO_SYS)
                    call_dissector(ua_term_to_sys_handle,
                                   tvb_new_subset(tvb, offset, datalen, datalen),
                                   pinfo,
                                   tree);
                else {
                    if (check_col(pinfo->cinfo, COL_INFO))
                        col_add_str(pinfo->cinfo,
                             COL_INFO,
                             "Data - Couldn't resolve direction. Check UAUDP Preferences.");
                }
                ua_tap_info.expseq = hf_uaudp_expseq;
            }
            else {
                /* print in "INFO" column */
                if (check_col(pinfo->cinfo, COL_INFO))
                    col_add_str(pinfo->cinfo,
                                COL_INFO,
                                "Data ACK");
            }
            break;
        }
        default:
            break;
        }
    }
    tap_queue_packet(uaudp_tap, pinfo, &ua_tap_info);
}

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

/*
 * UA/UDP DISSECTOR
 * Ethereal packet dissector entry point
 */
static void dissect_uaudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* server addres has precedence on ports if present */
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


gboolean str_to_addr_ip(const gchar *addr, guint8 *ad)
{
    int i = 0;
    const gchar *p = addr;
    guint32 value;

	if (addr==NULL) return FALSE;

    for (i=0; i<4; i++)
    {
        value = 0;
        while (*p != '.' && *p != '\0')
        {
            value = value * 10 + (*p - '0');
            p++;
        }
		if(value > 255)
		{
            return FALSE;
		}
		ad[i] = value;
		p++;
    }

    return TRUE;
}


/* Register the protocol with Ethereal */
void proto_reg_handoff_uaudp(void);

void proto_register_uaudp()
{
    module_t *uaudp_module;
    int i;

    /* Setup list of header fields. See Section 1.6.1 for details */
    static hf_register_info hf_uaudp[] =
    {
        { 
            &hf_uaudp_opcode,
            {
                "Opcode",
                 "uaudp.opcode",
                 FT_UINT8,
                 BASE_DEC,
                 VALS(uaudp_opcode_str),
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
                "Sequence Number (sent)    ", 
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

    register_dissector("uaudp", dissect_uaudp, proto_uaudp);
    register_dissector("uaudp_dir_unknown", dissect_uaudp_dir_unknown, proto_uaudp);
    register_dissector("uaudp_term_to_serv", dissect_uaudp_term_to_serv, proto_uaudp);
    register_dissector("uaudp_serv_to_term", dissect_uaudp_serv_to_term, proto_uaudp);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_uaudp, hf_uaudp, array_length(hf_uaudp));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    uaudp_module = prefs_register_protocol(proto_uaudp, proto_reg_handoff_uaudp);

/*
    prefs_register_bool_preference(uaudp_module, "enable",
                                   "Enable UA/UDP decoding based on preferences",
                                   "Enable UA/UDP decoding based on preferences",
                                   &decode_ua);
*/
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
                                     "IPv4 address of the DHS3 system. (Used only in case of identical source and destination ports)",
                                     &pref_sys_ip_s);

    /* Register tap listener */
/*    uaudp_tap = register_tap("uaudp");*/
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_uaudp(void)
{
    static gboolean prefs_initialized = FALSE;
    static dissector_handle_t uaudp_handle;
    int i;

    if(!prefs_initialized)
    {
        uaudp_handle = create_dissector_handle(dissect_uaudp, proto_uaudp);
        ua_sys_to_term_handle = find_dissector("ua_sys_to_term");
        ua_term_to_sys_handle = find_dissector("ua_term_to_sys");
        prefs_initialized = TRUE;
    }
    else
    {
        for(i=0; i<MAX_TERMINAL_PORTS; i++)
        {
            dissector_delete("udp.port", ports[i].last_port, uaudp_handle);
        }
		if(str_to_addr_ip(pref_sys_ip_s, sys_ip))
        {
            use_sys_ip = TRUE;
        }
        else 
        {
            use_sys_ip = FALSE;
			pref_sys_ip_s = g_strdup("");
        }
    }

    if(decode_ua)
    {
        for(i=0; i < MAX_TERMINAL_PORTS; i++)
        {
            dissector_add("udp.port", ports[i].port, uaudp_handle);
            ports[i].last_port = ports[i].port;
        }
    }
}

