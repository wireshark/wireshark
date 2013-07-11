/* packet-openflow.c
 * Routines for OpenFlow dissection
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref https://www.opennetworking.org/sdn-resources/onf-specifications/openflow 
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

void proto_reg_handoff_openflow(void);

static int g_openflow_port = 0;

/* Initialize the protocol and registered fields */
static int proto_openflow = -1;
static int hf_openflow_version = -1;
static int hf_openflow_type = -1;
static int hf_openflow_length = -1;
static int hf_openflow_xid = -1;

static int hf_openflow_datapath_id = -1;
static int hf_openflow_datapath_mac = -1;
static int hf_openflow_datapath_impl = -1;
static int hf_openflow_n_buffers = -1;
static int hf_openflow_n_tables = -1;
static int hf_openflow_pad3 = -1;
static int hf_openflow_capabilities = -1;
static int hf_openflow_actions = -1;
static int hf_openflow_reserved32 = -1;
static int hf_openflow_cap_flow_stats = -1;
static int hf_openflow_table_stats = -1;
static int hf_openflow_port_stats = -1;
static int hf_openflow_group_stats = -1;
static int hf_openflow_ip_reasm = -1; 
static int hf_openflow_queue_stats = -1;
static int hf_openflow_port_blocked = -1;

static int hf_openflow_output = -1; /* Output to switch port. */
static int hf_openflow_set_vlan_vid = -1; /* Set the 802.1q VLAN id. */
static int hf_openflow_set_vlan_pcp = -1; /* Set the 802.1q priority. */
static int hf_openflow_strip_vlan = -1; /* Strip the 802.1q header. */
static int hf_openflow_set_dl_src = -1; /* Ethernet source address. */
static int hf_openflow_set_dl_dst = -1; /* Ethernet destination address. */
static int hf_openflow_set_nw_src = -1; /* IP source address. */
static int hf_openflow_set_nw_dst = -1; /* IP destination address. */
static int hf_openflow_set_nw_tos = -1; /* IP ToS (DSCP field, 6 bits). */
static int hf_openflow_set_tp_src = -1; /* TCP/UDP source port. */
static int hf_openflow_set_tp_dst = -1; /* TCP/UDP destination port. */
static int hf_openflow_enqueue = -1; /* Output to queue. */

static int hf_openflow_port_no = -1;
static int hf_openflow_hw_addr = -1;
static int hf_openflow_port_name = -1;


static int hf_openflow_port_config = -1;
static int hf_openflow_port_state = -1;
static int hf_openflow_port_curr = -1;
static int hf_openflow_port_advertised = -1;
static int hf_openflow_port_supported = -1;
static int hf_openflow_port_peer = -1;

static int hf_openflow_port_down = -1;    /* Port is administratively down. */
static int hf_openflow_no_stp = -1;       /* Disable 802.1D spanning tree on port. */
static int hf_openflow_no_recv = -1;      /* Drop all packets except 802.1D spanning tree packets. */
static int hf_openflow_no_recv_stp = -1;  /* Drop received 802.1D STP packets. */
static int hf_openflow_no_flood = -1;     /* Do not include this port when flooding. */
static int hf_openflow_no_fwd = -1;       /* Drop packets forwarded to port. */
static int hf_openflow_no_packet_in = -1; /* Do not send packet-in msgs for port. */

static int hf_openflow_link_down = -1;    /* No physical link present. */
static int hf_openflow_stp_listen = -1;   /* Not learning or relaying frames. */
static int hf_openflow_stp_learn = -1;    /* Learning but not relaying frames. */
static int hf_openflow_stp_forward = -1;  /* Learning and relaying frames. */
static int hf_openflow_stp_block = -1;    /* Not part of spanning tree. */
static int hf_openflow_stp_mask = -1;     /* Bit mask for OFPPS_STP_* values. */

static int hf_openflow_10mb_hd = -1;      /* 10 Mb half-duplex rate support. */
static int hf_openflow_10mb_fd = -1;      /* 10 Mb full-duplex rate support. */
static int hf_openflow_100mb_hd = -1;     /* 100 Mb half-duplex rate support. */
static int hf_openflow_100mb_fd = -1;     /* 100 Mb full-duplex rate support. */
static int hf_openflow_1gb_hd = -1;       /* 1 Gb half-duplex rate support. */
static int hf_openflow_1gb_fd = -1;       /* 1 Gb full-duplex rate support. */
static int hf_openflow_10gb_fd = -1;      /* 10 Gb full-duplex rate support. */
static int hf_openflow_copper = -1;       /* Copper medium. */
static int hf_openflow_fiber = -1;        /* Fiber medium. */
static int hf_openflow_autoneg = -1;      /* Auto-negotiation. */
static int hf_openflow_pause = -1;        /* Pause. */
static int hf_openflow_pause_asym = -1;   /* Asymmetric pause. */

/* Initialize the subtree pointers */
static gint ett_openflow = -1;
static gint ett_openflow_path_id = -1;
static gint ett_openflow_cap = -1;
static gint ett_openflow_act = -1;
static gint ett_openflow_port = -1;
static gint ett_openflow_port_cnf = -1;
static gint ett_openflow_port_state = -1;
static gint ett_port_cf = -1;


static const value_string openflow_version_values[] = {
    { 0x01, "1.0" },
    { 0x02, "1.1" },
    { 0x03, "1.2" },
    { 0x04, "1.3" },
    { 0, NULL }
};

/* Immutable messages. */
#define OFPT_HELLO                     0 /* Symmetric message */
#define OFPT_ERROR                     1 /* Symmetric message */
#define OFPT_ECHO_REQUEST              2 /* Symmetric message */
#define OFPT_ECHO_REPLY                3 /* Symmetric message */
#define OFPT_EXPERIMENTER              4 /* Symmetric message */
/* Switch configuration messages. */
#define OFPT_FEATURES_REQUEST          5 /* Controller/switch message */
#define OFPT_FEATURES_REPLY            6 /* Controller/switch message */
#define OFPT_GET_CONFIG_REQUEST        7 /* Controller/switch message */
#define OFPT_GET_CONFIG_REPLY          8 /* Controller/switch message */
#define OFPT_SET_CONFIG                9 /* Controller/switch message */
/* Asynchronous messages. */
#define OFPT_PACKET_IN                10 /* Async message */
#define OFPT_FLOW_REMOVED             11 /* Async message */
#define OFPT_PORT_STATUS              12 /* Async message */
/* Controller command messages. */
#define OFPT_PACKET_OUT               13 /* Controller/switch message */
#define OFPT_FLOW_MOD                 14 /* Controller/switch message */
#define OFPT_GROUP_MOD                15 /* Controller/switch message */
#define OFPT_PORT_MOD                 16 /* Controller/switch message */
#define OFPT_TABLE_MOD                17 /* Controller/switch message */
/* Multipart messages. */
#define OFPT_MULTIPART_REQUEST        18 /* Controller/switch message */
#define OFPT_MULTIPART_REPLY          19 /* Controller/switch message */
/* Barrier messages. */
#define OFPT_BARRIER_REQUEST          20 /* Controller/switch message */
#define OFPT_BARRIER_REPLY            21 /* Controller/switch message */
/* Queue Configuration messages. */
#define OFPT_QUEUE_GET_CONFIG_REQUEST 22 /* Controller/switch message */
#define OFPT_QUEUE_GET_CONFIG_REPLY   23 /* Controller/switch message */
/* Controller role change request messages. */
#define OFPT_ROLE_REQUEST             24 /* Controller/switch message */
#define OFPT_ROLE_REPLY               25 /* Controller/switch message */
/* Asynchronous message configuration. */
#define OFPT_GET_ASYNC_REQUEST        26 /* Controller/switch message */
#define OFPT_GET_ASYNC_REPLY          27 /* Controller/switch message */
#define OFPT_SET_ASYNC                28 /* Controller/switch message */
/* Meters and rate limiters configuration messages. */
#define OFPT_METER_MOD                29 /* Controller/switch message */

static const value_string openflow_type_values[] = {
/* Immutable messages. */
    { 0, "OFPT_HELLO" },              /* Symmetric message */
    { 1, "OFPT_ERROR" },              /* Symmetric message */
    { 2, "OFPT_ECHO_REQUEST" },       /* Symmetric message */
    { 3, "OFPT_ECHO_REPLY" },         /* Symmetric message */
    { 4, "OFPT_EXPERIMENTER" },       /* Symmetric message */
/* Switch configuration messages. */
    { 5, "OFPT_FEATURES_REQUEST" },   /* Controller/switch message */
    { 6, "OFPT_FEATURES_REPLY" },     /* Controller/switch message */
    { 7, "OFPT_GET_CONFIG_REQUEST" }, /* Controller/switch message */
    { 8, "OFPT_GET_CONFIG_REPLY" },   /* Controller/switch message */
    { 9, "OFPT_SET_CONFIG" },         /* Controller/switch message */
/* Asynchronous messages. */
    { 10, "OFPT_PACKET_IN" },                /* Async message */
    { 11, "OFPT_FLOW_REMOVED" },             /* Async message */
    { 12, "OFPT_PORT_STATUS" },              /* Async message */
/* Controller command messages. */
    { 13, "OFPT_PACKET_OUT" },               /* Controller/switch message */
    { 14, "OFPT_FLOW_MOD" },                 /* Controller/switch message */
    { 15, "OFPT_GROUP_MOD" },                /* Controller/switch message */
    { 16, "OFPT_PORT_MOD" },                 /* Controller/switch message */
    { 17, "OFPT_TABLE_MOD" },                /* Controller/switch message */
/* Multipart messages. */
    { 18, "OFPT_MULTIPART_REQUEST" },        /* Controller/switch message */
    { 19, "OFPT_MULTIPART_REPLY" },          /* Controller/switch message */
/* Barrier messages. */
    { 20, "OFPT_BARRIER_REQUEST" },          /* Controller/switch message */
    { 21, "OFPT_BARRIER_REPLY" },            /* Controller/switch message */
/* Queue Configuration messages. */
    { 22, "OFPT_QUEUE_GET_CONFIG_REQUEST" }, /* Controller/switch message */
    { 23, "OFPT_QUEUE_GET_CONFIG_REPLY" },   /* Controller/switch message */
/* Controller role change request messages. */
    { 24, "OFPT_ROLE_REQUEST" },             /* Controller/switch message */
    { 25, "OFPT_ROLE_REPLY" },               /* Controller/switch message */
/* Asynchronous message configuration. */
    { 26, "OFPT_GET_ASYNC_REQUEST" },        /* Controller/switch message */
    { 27, "OFPT_GET_ASYNC_REPLY" },          /* Controller/switch message */
    { 28, "OFPT_SET_ASYNC" },                /* Controller/switch message */
/* Meters and rate limiters configuration messages. */
    { 29, "OFPT_METER_MOD" },                /* Controller/switch message */
    { 0, NULL }
};

#define OFPC_FLOW_STATS   1<<0  /* Flow statistics. */
#define OFPC_TABLE_STATS  1<<1  /* Table statistics. */
#define OFPC_PORT_STATS   1<<2  /* Port statistics. */
#define OFPC_GROUP_STATS  1<<3  /* Group statistics. */
#define OFPC_IP_REASM     1<<5  /* Can reassemble IP fragments. */
#define OFPC_QUEUE_STATS  1<<6  /* Queue statistics. */
#define OFPC_PORT_BLOCKED 1<<8  /* Switch will block looping ports. */

#define OFPAT_OUTPUT_MASK       1<<0  /* Output to switch port. */
#define OFPAT_SET_VLAN_VID_MASK 1<<1  /* Set the 802.1q VLAN id. */
#define OFPAT_SET_VLAN_PCP_MASK 1<<2  /* Set the 802.1q priority. */
#define OFPAT_STRIP_VLAN_MASK   1<<3  /* Strip the 802.1q header. */
#define OFPAT_SET_DL_SRC_MASK   1<<4  /* Ethernet source address. */
#define OFPAT_SET_DL_DST_MASK   1<<5  /* Ethernet destination address. */
#define OFPAT_SET_NW_SRC_MASK   1<<6  /* IP source address. */
#define OFPAT_SET_NW_DST_MASK   1<<7  /* IP destination address. */
#define OFPAT_SET_NW_TOS_MASK   1<<8  /* IP ToS (DSCP field, 6 bits). */
#define OFPAT_SET_TP_SRC_MASK   1<<9  /* TCP/UDP source port. */
#define OFPAT_SET_TP_DST_MASK   1<<10 /* TCP/UDP destination port. */
#define OFPAT_ENQUEUE_MASK      1<<11 /* Output to queue. */

#define OFPPC_PORT_DOWN    1<<0 /* Port is administratively down. */
#define OFPPC_NO_STP       1<<1 /* Disable 802.1D spanning tree on port. */
#define OFPPC_NO_RECV      1<<2 /* Drop all packets except 802.1D spanning tree packets. */
#define OFPPC_NO_RECV_STP  1<<3 /* Drop received 802.1D STP packets. */
#define OFPPC_NO_FLOOD     1<<4 /* Do not include this port when flooding. */
#define OFPPC_NO_FWD       1<<5 /* Drop packets forwarded to port. */
#define OFPPC_NO_PACKET_IN 1<<6 /* Do not send packet-in msgs for port. */

#define OFP_MAX_PORT_NAME_LEN 16

#define OFPPS_LINK_DOWN    1<<0 /* No physical link present. */
#define OFPPS_STP_LISTEN   0<<8 /* Not learning or relaying frames. */
#define OFPPS_STP_LEARN    1<<8 /* Learning but not relaying frames. */
#define OFPPS_STP_FORWARD  2<<8 /* Learning and relaying frames. */
#define OFPPS_STP_BLOCK    3<<8 /* Not part of spanning tree. */
#define OFPPS_STP_MASK     3<<8 /* Bit mask for OFPPS_STP_* values. */


#define OFPPF_10MB_HD      1<<0 /* 10 Mb half-duplex rate support. */
#define OFPPF_10MB_FD      1<<1 /* 10 Mb full-duplex rate support. */
#define OFPPF_100MB_HD     1<<2 /* 100 Mb half-duplex rate support. */
#define OFPPF_100MB_FD     1<<3 /* 100 Mb full-duplex rate support. */
#define OFPPF_1GB_HD       1<<4 /* 1 Gb half-duplex rate support. */
#define OFPPF_1GB_FD       1<<5 /* 1 Gb full-duplex rate support. */
#define OFPPF_10GB_FD      1<<6 /* 10 Gb full-duplex rate support. */
#define OFPPF_COPPER       1<<7 /* Copper medium. */
#define OFPPF_FIBER        1<<8 /* Fiber medium. */
#define OFPPF_AUTONEG      1<<9 /* Auto-negotiation. */
#define OFPPF_PAUSE        1<<10 /* Pause. */
#define OFPPF_PAUSE_ASYM   1<<11 /* Asymmetric pause. */

static void
dissect_openflow_phy_port(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *ti;
    proto_tree *port_cnf_tree, *port_state_tree, *port_cf_tree;

    proto_tree_add_item(tree, hf_openflow_port_no, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(tree, hf_openflow_hw_addr, tvb, offset, 6, ENC_BIG_ENDIAN);
    offset+=6;
    proto_tree_add_item(tree, hf_openflow_port_name, tvb, offset, OFP_MAX_PORT_NAME_LEN, ENC_BIG_ENDIAN);
    offset+=OFP_MAX_PORT_NAME_LEN;

    /* Bitmap of OFPPC_* flags. */
    ti = proto_tree_add_item(tree, hf_openflow_port_config, tvb, offset, 4, ENC_BIG_ENDIAN);
    port_cnf_tree = proto_item_add_subtree(ti, ett_openflow_port_cnf);

    /* Port is administratively down. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_port_down, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Disable 802.1D spanning tree on port. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_stp, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Drop all packets except 802.1D spanning tree packets. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_recv, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Drop received 802.1D STP packets. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_recv_stp, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Do not include this port when flooding. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_flood, tvb, offset, 4, ENC_BIG_ENDIAN);
     /* Drop packets forwarded to port. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_fwd, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Do not send packet-in msgs for port. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_no_packet_in, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* Bitmap of OFPPS_* flags. */
    ti = proto_tree_add_item(tree, hf_openflow_port_state, tvb, offset, 4, ENC_BIG_ENDIAN);
    port_state_tree = proto_item_add_subtree(ti, ett_openflow_port_state);

    /* No physical link present. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_link_down, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Not learning or relaying frames. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_stp_listen, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Learning but not relaying frames. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_stp_learn, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Learning and relaying frames. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_stp_forward, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Not part of spanning tree. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_stp_block, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* Bit mask for OFPPS_STP_* values. */
    proto_tree_add_item(port_cnf_tree, hf_openflow_stp_mask, tvb, offset, 4, ENC_BIG_ENDIAN);

    offset+=4;

    /* Current features. */
    ti = proto_tree_add_item(tree, hf_openflow_port_curr, tvb, offset, 4, ENC_BIG_ENDIAN);
    port_cf_tree = proto_item_add_subtree(ti, ett_port_cf);
	/* 10 Mb half-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_10mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* 10 Mb full-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_10mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* 100 Mb half-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_100mb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* 100 Mb full-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_100mb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* 1 Gb half-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_1gb_hd, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* 1 Gb full-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_1gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* 10 Gb full-duplex rate support. */
    proto_tree_add_item(port_cf_tree, hf_openflow_10gb_fd, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* Copper medium. */
    proto_tree_add_item(port_cf_tree, hf_openflow_copper, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* Fiber medium. */
    proto_tree_add_item(port_cf_tree, hf_openflow_fiber, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* Auto-negotiation. */
    proto_tree_add_item(port_cf_tree, hf_openflow_autoneg, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* Pause. */
    proto_tree_add_item(port_cf_tree, hf_openflow_pause, tvb, offset, 4, ENC_BIG_ENDIAN);
	/* Asymmetric pause. */
    proto_tree_add_item(port_cf_tree, hf_openflow_pause_asym, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* Features being advertised by the port. */
    proto_tree_add_item(tree, hf_openflow_port_advertised, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* Features supported by the port. */
    proto_tree_add_item(tree, hf_openflow_port_supported, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    /* Features advertised by peer. */
    proto_tree_add_item(tree, hf_openflow_port_peer, tvb, offset, 4, ENC_BIG_ENDIAN);


}
/* 
 * Switch features. 
 *
   struct ofp_switch_features {
   struct ofp_header header;
   uint64_t datapath_id; * Datapath unique ID. The lower 48-bits are for
                           a MAC address, while the upper 16-bits are
                           implementer-defined. *
   uint32_t n_buffers;   * Max packets buffered at once. *
   uint8_t n_tables;     * Number of tables supported by datapath. *
   uint8_t pad[3];       * Align to 64-bits. *
* Features. *
   uint32_t capabilities;  * Bitmap of support "ofp_capabilities".   *
   uptill 1.1
       uint32_t actions;       * Bitmap of supported "ofp_action_type"s. *
   from 1.2
       uint32_t reserved;
* Port info.*
  struct ofp_phy_port ports[0]; * Port definitions. The number of ports
                                  is inferred from the length field in
                                  the header.
  };
*/
static void
dissect_openflow_features_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 version, guint16 length)
{
    proto_item *ti;
    proto_tree *path_id_tree, *cap_tree, *act_tree;

    guint16 length_remaining;
    
    ti = proto_tree_add_item(tree, hf_openflow_datapath_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    path_id_tree = proto_item_add_subtree(ti, ett_openflow_path_id);
    proto_tree_add_item(path_id_tree, hf_openflow_datapath_mac, tvb, offset, 6, ENC_BIG_ENDIAN);
    offset+=6;
    proto_tree_add_item(path_id_tree, hf_openflow_datapath_impl, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_openflow_n_buffers, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    proto_tree_add_item(tree, hf_openflow_n_tables, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if(version<3){
        proto_tree_add_item(tree, hf_openflow_pad3, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset+=3;
    }else{
    }

    ti = proto_tree_add_item(tree, hf_openflow_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
    cap_tree = proto_item_add_subtree(ti, ett_openflow_cap);

    /* Dissect flags */
    proto_tree_add_item(cap_tree, hf_openflow_cap_flow_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_table_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_port_stats,     tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_group_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_ip_reasm,       tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_queue_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_port_blocked,   tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    if(version<2){
        ti = proto_tree_add_item(tree, hf_openflow_actions, tvb, offset, 4, ENC_BIG_ENDIAN);
        act_tree = proto_item_add_subtree(ti, ett_openflow_act);
        /* Dissect flags */
        proto_tree_add_item(act_tree, hf_openflow_output, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_set_vlan_vid, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_set_vlan_pcp, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_strip_vlan, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_set_dl_src, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_set_dl_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_set_nw_src, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_set_nw_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_set_nw_tos, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_set_tp_src, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_set_tp_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(act_tree, hf_openflow_enqueue, tvb, offset, 4, ENC_BIG_ENDIAN);
    }else{
        proto_tree_add_item(tree, hf_openflow_reserved32, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset+=4;
    
    length_remaining = length-32;
    if(length_remaining > 0){
        guint16 num_ports = length_remaining/48;
        int i;
        if ((length_remaining&0x003f) != 0){
            /* protocol_error */
        }
        for(i=0; i<num_ports ;i++){
            proto_tree *port_tree;

            ti = proto_tree_add_text(tree, tvb, offset, 48, "Port data %u",i+1);
            port_tree = proto_item_add_subtree(ti, ett_openflow_port);
            dissect_openflow_phy_port(tvb, pinfo, port_tree, offset);
            offset+=48;
        }
    }

}
/* Code to actually dissect the packets */
static int
dissect_openflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *openflow_tree;
    guint offset = 0;
    guint8 type, version;
    guint16 length;


    version = tvb_get_guint8(tvb, 0);
    type    = tvb_get_guint8(tvb, 1);
    /* Set the Protocol column to the constant string of openflow */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OpenFlow");
    col_clear(pinfo->cinfo,COL_INFO);

    if((version&0x80)==0x80){
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "OpenFlow experimental version");
        proto_tree_add_text(tree, tvb, offset, -1, "Experimental versions not dissected");
    }else{
        version = version & 0x7f;
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "OpenFlow");
        col_append_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
                  val_to_str_const(type, openflow_type_values, "Unknown Messagetype"));
    }

    /* Create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_openflow, tvb, 0, -1, ENC_NA);
    openflow_tree = proto_item_add_subtree(ti, ett_openflow);

    /* A.1 OpenFlow Header. */
    /* OFP_VERSION. */
    proto_tree_add_item(openflow_tree, hf_openflow_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* One of the OFPT_ constants. */
    proto_tree_add_item(openflow_tree, hf_openflow_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Length including this ofp_header. */
    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(openflow_tree, hf_openflow_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* Transaction id associated with this packet. Replies use the same id as was in the request
     * to facilitate pairing. 
     */
    proto_tree_add_item(openflow_tree, hf_openflow_xid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    switch(type){
    case OFPT_HELLO:
        /* 5.5.1 Hello
         * The OFPT_HELLO message has no body;
         */
        break;
    case OFPT_FEATURES_REQUEST:
        /* 5.3.1 Handshake
         * Upon TLS session establishment, the controller sends an OFPT_FEATURES_REQUEST
         * message. This message does not contain a body beyond the OpenFlow header.
         */
        break;
    case OFPT_FEATURES_REPLY:
        dissect_openflow_features_reply(tvb, pinfo, openflow_tree, offset, version, length);
        break;
    default:
        if(length>8){
            proto_tree_add_text(tree, tvb, offset, -1, "Message data not dissected yet");
        }
        break;
    }

    return tvb_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_openflow(void)
{
    module_t *openflow_module;

    static hf_register_info hf[] = {
        { &hf_openflow_version,
            { "Version", "openflow.version",
               FT_UINT8, BASE_HEX, VALS(openflow_version_values), 0x7f,
               NULL, HFILL }
        },
        { &hf_openflow_type,
            { "Type", "openflow.type",
               FT_UINT8, BASE_DEC, VALS(openflow_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_xid,
            { "Transaction ID", "openflow.xid",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_length,
            { "Length", "openflow.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_datapath_id,
            { "Datapath unique ID", "openflow.datapath_id",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_datapath_mac,
            { "MAC addr", "openflow.datapath_mac",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_datapath_impl,
            { "Implementers part", "openflow.datapath_imp",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_n_buffers,
            { "n_buffers", "openflow.n_buffers",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_n_tables,
            { "n_tables", "openflow.n_tables",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_pad3,
            { "Padding", "openflow.pad3",
               FT_UINT24, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_capabilities,
            { "capabilities", "openflow.capabilities",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_actions,
            { "actions", "openflow.actions",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_reserved32,
            { "Reserved", "openflow.reserved32",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_cap_flow_stats,
            { "Flow statistics", "openflow.flow_stats",
               FT_BOOLEAN, 32, NULL, OFPC_FLOW_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_table_stats,
            { "Table statistics", "openflow.table_stats",
               FT_BOOLEAN, 32, NULL, OFPC_TABLE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_port_stats,
            { "Port statistics", "openflow.port_stats",
               FT_BOOLEAN, 32, NULL,  OFPC_PORT_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_group_stats,
            { "Group statistics", "openflow.group_stats",
               FT_BOOLEAN, 32, NULL, OFPC_GROUP_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_ip_reasm,
            { "Can reassemble IP fragments", "openflow.ip_reasm",
               FT_BOOLEAN, 32, NULL, OFPC_IP_REASM,
               NULL, HFILL }
        },
        { &hf_openflow_queue_stats,
            { "Queue statistics", "openflow.queue_stats",
               FT_BOOLEAN, 32, NULL, OFPC_QUEUE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_port_blocked,
            { "Switch will block looping ports", "openflow.port_blocked",
               FT_BOOLEAN, 32, NULL, OFPC_PORT_BLOCKED,
               NULL, HFILL }
        },
        { &hf_openflow_output,
            { "Output to switch port", "openflow.output",
               FT_BOOLEAN, 32, NULL, OFPAT_OUTPUT_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_vlan_vid,
            { "Set the 802.1q VLAN id", "openflow.set_vlan_vid",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_VLAN_VID_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_vlan_pcp,
            { "Set the 802.1q priority", "openflow.set_vlan_pcp",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_VLAN_PCP_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_strip_vlan,
            { "Strip the 802.1q header", "openflow.strip_vlan",
               FT_BOOLEAN, 32, NULL, OFPAT_STRIP_VLAN_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_dl_src,
            { "Ethernet source address", "openflow.set_dl_src",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_DL_SRC_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_dl_dst,
            { "Ethernet destination address", "openflow.set_dl_ds",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_DL_DST_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_nw_src,
            { "IP source address", "openflow.set_nw_src",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_NW_SRC_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_nw_dst,
            { "IP destination address", "openflow.set_nw_ds",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_NW_DST_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_nw_tos,
            { "IP ToS (DSCP field, 6 bits)", "openflow.set_nw_tos",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_NW_TOS_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_tp_src,
            { "TCP/UDP source port", "openflow.set_tp_src",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_TP_SRC_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_set_tp_dst,
            { "TCP/UDP destination port", "openflow.set_tp_dst",
               FT_BOOLEAN, 32, NULL, OFPAT_SET_TP_DST_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_enqueue,
            { "Output to queue", "openflow.enqueue",
               FT_BOOLEAN, 32, NULL, OFPAT_ENQUEUE_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_port_no,
            { "Port number", "openflow.port_no",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_hw_addr,
            { "HW Address", "openflow.hw_add",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_name,
            { "Name", "openflow.hw_add",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_config,
            { "Config flags", "openflow.port_config",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_state,
            { "State flags", "openflow.port_state",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_curr,
            { "Current features", "openflow.port_curr",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_advertised,
            { "Advertised features", "openflow.port_advertised",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_supported,
            { "Features supported", "openflow.port_supported",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_peer,
            { "Features advertised by peer", "openflow.port_peer",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_port_down,
            { "Port is administratively down", "openflow.port_down",
               FT_BOOLEAN, 32, NULL, OFPPC_PORT_DOWN,
               NULL, HFILL }
        },
        { &hf_openflow_no_stp,
            { "Disable 802.1D spanning tree on port", "openflow.no_stp",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_STP,
               NULL, HFILL }
        },
        { &hf_openflow_no_recv,
            { "Drop all packets except 802.1D spanning tree packets", "openflow.no_recv",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_RECV,
               NULL, HFILL }
        },
        { &hf_openflow_no_recv_stp,
            { "Drop received 802.1D STP packets", "openflow.no_recv",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_RECV_STP,
               NULL, HFILL }
        },
        { &hf_openflow_no_flood,
            { "Do not include this port when flooding", "openflow.no_flood",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_FLOOD,
               NULL, HFILL }
        },
        { &hf_openflow_no_fwd,
            { "Drop packets forwarded to port", "openflow.no_fwd",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_FWD,
               NULL, HFILL }
        },
        { &hf_openflow_no_packet_in,
            { "Do not send packet-in msgs for port", "openflow.no_packet_in",
               FT_BOOLEAN, 32, NULL, OFPPC_NO_PACKET_IN,
               NULL, HFILL }
        },
        { &hf_openflow_link_down,
            { "No physical link present", "openflow.link_down",
               FT_BOOLEAN, 32, NULL, OFPPS_LINK_DOWN,
               NULL, HFILL }
        },
        { &hf_openflow_stp_listen,
            { "Not learning or relaying frames", "openflow.stp_listen",
               FT_BOOLEAN, 32, NULL, OFPPS_STP_LISTEN,
               NULL, HFILL }
        },
        { &hf_openflow_stp_learn,
            { "Learning but not relaying frames", "openflow.stp_learn",
               FT_BOOLEAN, 32, NULL, OFPPS_STP_LEARN,
               NULL, HFILL }
        },
        { &hf_openflow_stp_forward,
            { "Learning and relaying frames", "openflow.stp_forward",
               FT_BOOLEAN, 32, NULL, OFPPS_STP_FORWARD,
               NULL, HFILL }
        },
        { &hf_openflow_stp_block,
            { "Not part of spanning tree", "openflow.stp_block",
               FT_BOOLEAN, 32, NULL, OFPPS_STP_BLOCK,
               NULL, HFILL }
        },
        { &hf_openflow_stp_mask,
            { "Bit mask for OFPPS_STP", "openflow.stp_mask",
               FT_BOOLEAN, 32, NULL, OFPPS_STP_MASK,
               NULL, HFILL }
        },
        { &hf_openflow_10mb_hd,
            { "10 Mb half-duplex rate support", "openflow.10mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_10mb_fd,
            { "10 Mb full-duplex rate support", "openflow.10mb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_100mb_hd,
            { "100 Mb half-duplex rate support", "openflow.100mb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_100mb_fd,
            { "100 Mb full-duplex rate support", "openflow.100mb_0fd",
               FT_BOOLEAN, 32, NULL, OFPPF_100MB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_1gb_hd,
            { "1 Gb half-duplex rate support", "openflow.1gb_hd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_HD,
               NULL, HFILL }
        },
        { &hf_openflow_1gb_fd,
            { "1 Gb full-duplex rate support", "openflow.1gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_1GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_10gb_fd,
            { "10 Gb full-duplex rate support", "openflow.10gb_fd",
               FT_BOOLEAN, 32, NULL, OFPPF_10GB_FD,
               NULL, HFILL }
        },
        { &hf_openflow_copper,
            { "Copper medium", "openflow.copper",
               FT_BOOLEAN, 32, NULL, OFPPF_COPPER,
               NULL, HFILL }
        },
        { &hf_openflow_fiber,
            { "Fiber medium", "openflow.fiber",
               FT_BOOLEAN, 32, NULL, OFPPF_FIBER,
               NULL, HFILL }
        },
        { &hf_openflow_autoneg,
            { "Auto-negotiation", "openflow.autoneg",
               FT_BOOLEAN, 32, NULL, OFPPF_AUTONEG,
               NULL, HFILL }
        },
        { &hf_openflow_pause,
            { "Pause", "openflow.pause",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE,
               NULL, HFILL }
        },
        { &hf_openflow_pause_asym,
            { "Asymmetric pause", "openflow.pause_asym",
               FT_BOOLEAN, 32, NULL, OFPPF_PAUSE_ASYM,
               NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_openflow,
        &ett_openflow_path_id,
        &ett_openflow_cap,
        &ett_openflow_act,
        &ett_openflow_port,
        &ett_openflow_port_cnf,
        &ett_openflow_port_state,
		&ett_port_cf
    };

    /* Register the protocol name and description */
    proto_openflow = proto_register_protocol("OpenFlow",
            "openflow", "openflow");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_openflow, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    openflow_module = prefs_register_protocol(proto_openflow, proto_reg_handoff_openflow);

    /* Register port preference */
    prefs_register_uint_preference(openflow_module, "tcp.port", "openflow TCP Port",
            " openflow TCP port if other than the default",
            10, &g_openflow_port);
}

void
proto_reg_handoff_openflow(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t openflow_handle;
    static int currentPort;

    if (!initialized) {
        openflow_handle = new_create_dissector_handle(dissect_openflow, proto_openflow);
        initialized = TRUE;

    } else {
        dissector_delete_uint("tcp.port", currentPort, openflow_handle);
    }

    currentPort = g_openflow_port;

    dissector_add_uint("tcp.port", currentPort, openflow_handle);
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
