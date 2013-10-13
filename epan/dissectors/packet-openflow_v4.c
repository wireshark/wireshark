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

void proto_reg_handoff_openflow_v4(void);
static int proto_openflow_v4 = -1;
static int hf_openflow_v4_version = -1;
static int hf_openflow_v4_type = -1;
static int hf_openflow_v4_length = -1;
static int hf_openflow_v4_xid = -1;
static int hf_openflow_v4_datapath_id = -1;
static int hf_openflow_datapath_v4_mac = -1;
static int hf_openflow_v4_datapath_impl = -1;
static int hf_openflow_v4_n_buffers = -1;
static int hf_openflow_v4_n_tables = -1;
static int hf_openflow_v4_auxiliary_id = -1;
static int hf_openflow_v4_padd16 = -1;
static int hf_openflow_v4_pad3 = -1;
static int hf_openflow_v4_padd32 = -1;
static int hf_openflow_v4_capabilities = -1;
static int hf_openflow_v4_cap_flow_stats = -1;
static int hf_openflow_v4_table_stats = -1;
static int hf_openflow_v4_port_stats = -1;
static int hf_openflow_v4_group_stats = -1;
static int hf_openflow__v4_ip_reasm = -1;
static int hf_openflow_v4_queue_stats = -1;
static int hf_openflow_v4_port_blocked = -1;
static int hf_openflow_v4_multipart_type = -1;
static int hf_openflow_v4_multipart_request_flags = -1;
static int hf_openflow_v4_multipart_reply_flags = -1;

static gint ett_openflow_v4 = -1;
static gint ett_openflow_v4_path_id = -1;
static gint ett_openflow_v4_cap = -1;

static const value_string openflow_v4_version_values[] = {
    { 0x01, "1.0" },
    { 0x02, "1.1" },
    { 0x03, "1.2" },
    { 0x04, "1.3.1" },
    { 0, NULL }
};

/* Immutable messages. */
#define OFPT_V4_HELLO                     0 /* Symmetric message */
#define OFPT_V4_ERROR                     1 /* Symmetric message */
#define OFPT_V4_ECHO_REQUEST              2 /* Symmetric message */
#define OFPT_V4_ECHO_REPLY                3 /* Symmetric message */
#define OFPT_V4_EXPERIMENTER              4 /* Symmetric message */
/* Switch configuration messages. */
#define OFPT_V4_FEATURES_REQUEST          5 /* Controller/switch message */
#define OFPT_V4_FEATURES_REPLY            6 /* Controller/switch message */
#define OFPT_V4_GET_CONFIG_REQUEST        7 /* Controller/switch message */
#define OFPT_V4_GET_CONFIG_REPLY          8 /* Controller/switch message */
#define OFPT_V4_SET_CONFIG                9 /* Controller/switch message */
/* Asynchronous messages. */
#define OFPT_V4_PACKET_IN                10 /* Async message */
#define OFPT_V4_FLOW_REMOVED             11 /* Async message */
#define OFPT_V4_PORT_STATUS              12 /* Async message */
/* Controller command messages. */
#define OFPT_V4_PACKET_OUT               13 /* Controller/switch message */
#define OFPT_V4_FLOW_MOD                 14 /* Controller/switch message */
#define OFPT_V4_GROUP_MOD                15 /* Controller/switch message */
#define OFPT_V4_PORT_MOD                 16 /* Controller/switch message */
#define OFPT_V4_TABLE_MOD                17 /* Controller/switch message */
/* Multipart messages. */
#define OFPT_V4_MULTIPART_REQUEST        18 /* Controller/switch message */
#define OFPT_V4_MULTIPART_REPLY          19 /* Controller/switch message */
/* Barrier messages. */
#define OFPT_V4_BARRIER_REQUEST          20 /* Controller/switch message */
#define OFPT_V4_BARRIER_REPLY            21 /* Controller/switch message */
/* Queue Configuration messages. */
#define OFPT_V4_QUEUE_GET_CONFIG_REQUEST 22 /* Controller/switch message */
#define OFPT_V4_QUEUE_GET_CONFIG_REPLY   23 /* Controller/switch message */
/* Controller role change request messages. */
#define OFPT_V4_ROLE_REQUEST             24 /* Controller/switch message */
#define OFPT_V4_ROLE_REPLY               25 /* Controller/switch message */
/* Asynchronous message configuration. */
#define OFPT_V4_GET_ASYNC_REQUEST        26 /* Controller/switch message */
#define OFPT_V4_GET_ASYNC_REPLY          27 /* Controller/switch message */
#define OFPT_V4_SET_ASYNC                28 /* Controller/switch message */
/* Meters and rate limiters configuration messages. */
#define OFPT_V4_METER_MOD                29 /* Controller/switch message */

static const value_string openflow_v4_type_values[] = {
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

#define OFPC_V4_FLOW_STATS   1<<0  /* Flow statistics. */
#define OFPC_V4_TABLE_STATS  1<<1  /* Table statistics. */
#define OFPC_V4_PORT_STATS   1<<2  /* Port statistics. */
#define OFPC_V4_GROUP_STATS  1<<3  /* Group statistics. */
#define OFPC_V4_IP_REASM     1<<5  /* Can reassemble IP fragments. */
#define OFPC_V4_QUEUE_STATS  1<<6  /* Queue statistics. */
#define OFPC_V4_PORT_BLOCKED 1<<8  /* Switch will block looping ports. */

/* Switch features. /
struct ofp_switch_features {
    struct ofp_header header;
    uint64_t datapath_id; / Datapath unique ID. The lower 48-bits are for
    a MAC address, while the upper 16-bits are
    implementer-defined. /
    uint32_t n_buffers; / Max packets buffered at once. /
    uint8_t n_tables; / Number of tables supported by datapath. /
    uint8_t auxiliary_id; / Identify auxiliary connections /
    uint8_t pad[2]; / Align to 64-bits. /
    / Features. /
    uint32_t capabilities; / Bitmap of support "ofp_capabilities". /
    uint32_t reserved;
};
OFP_ASSERT(sizeof(struct ofp_switch_features) == 32);
*/


static void
dissect_openflow_features_reply_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    proto_item *ti;
    proto_tree *path_id_tree, *cap_tree;

    ti = proto_tree_add_item(tree, hf_openflow_v4_datapath_id, tvb, offset, 8, ENC_BIG_ENDIAN);
    path_id_tree = proto_item_add_subtree(ti, ett_openflow_v4_path_id);
    proto_tree_add_item(path_id_tree, hf_openflow_datapath_v4_mac, tvb, offset, 6, ENC_NA);
    offset+=6;
    proto_tree_add_item(path_id_tree, hf_openflow_v4_datapath_impl, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_openflow_v4_n_buffers, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* Number of tables supported by datapath. */
    proto_tree_add_item(tree, hf_openflow_v4_n_tables, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Identify auxiliary connections */
    proto_tree_add_item(tree, hf_openflow_v4_auxiliary_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* Align to 64-bits. */
    proto_tree_add_item(tree, hf_openflow_v4_padd16, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    ti = proto_tree_add_item(tree, hf_openflow_v4_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
    cap_tree = proto_item_add_subtree(ti, ett_openflow_v4_cap);

    /* Dissect flags */
    proto_tree_add_item(cap_tree, hf_openflow_v4_cap_flow_stats, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_table_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_port_stats,     tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_group_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow__v4_ip_reasm,       tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_queue_stats,    tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(cap_tree, hf_openflow_v4_port_blocked,   tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    proto_tree_add_item(tree, hf_openflow_v4_padd32, tvb, offset, 4, ENC_BIG_ENDIAN);
    /*offset+=4;*/

}

/* enum ofp_multipart_types { */
/* Description of this OpenFlow switch.
* The request body is empty.
* The reply body is struct ofp_desc. */
#define OFPMP_DESC  0
/* Individual flow statistics.
* The request body is struct ofp_flow_stats_request.
* The reply body is an array of struct ofp_flow_stats. */
#define OFPMP_FLOW  1
/* Aggregate flow statistics.
* The request body is struct ofp_aggregate_stats_request.
* The reply body is struct ofp_aggregate_stats_reply. */
#define OFPMP_AGGREGATE  2
/* Flow table statistics.
* The request body is empty.
* The reply body is an array of struct ofp_table_stats. */
#define OFPMP_TABLE  3
/* Port statistics.
* The request body is struct ofp_port_stats_request.
* The reply body is an array of struct ofp_port_stats. */
#define OFPMP_PORT_STATS  4
/* Queue statistics for a port
* The request body is struct ofp_queue_stats_request.
* The reply body is an array of struct ofp_queue_stats */
#define OFPMP_QUEUE  5
/* Group counter statistics.
* The request body is struct ofp_group_stats_request.
* The reply is an array of struct ofp_group_stats. */
#define OFPMP_GROUP  6
/* Group description.
* The request body is empty.
* The reply body is an array of struct ofp_group_desc_stats. */
#define OFPMP_GROUP_DESC  7
/* Group features.
* The request body is empty.
* The reply body is struct ofp_group_features. */
#define OFPMP_GROUP_FEATURES  8
/* Meter statistics.
* The request body is struct ofp_meter_multipart_requests.
* The reply body is an array of struct ofp_meter_stats. */
#define OFPMP_METER  9
/* Meter configuration.
* The request body is struct ofp_meter_multipart_requests.
* The reply body is an array of struct ofp_meter_config. */
#define OFPMP_METER_CONFIG  10
/* Meter features.
* The request body is empty.
* The reply body is struct ofp_meter_features. */
#define OFPMP_METER_FEATURES  11
/* Table features.
* The request body is either empty or contains an array of
* struct ofp_table_features containing the controller's
* desired view of the switch. If the switch is unable to
* set the specified view an error is returned.
* The reply body is an array of struct ofp_table_features. */
#define OFPMP_TABLE_FEATURES  12
/* Port description.
* The request body is empty.
* The reply body is an array of struct ofp_port. */
#define OFPMP_PORT_DESC  13
/* Experimenter extension.
* The request and reply bodies begin with
* struct ofp_experimenter_multipart_header.
* The request and reply bodies are otherwise experimenter-defined. */
#define OFPMP_EXPERIMENTER  0xffff

static const value_string openflow_v4_multipart_type_values[] = {
    { OFPMP_DESC,           "OFPMP_DESC" },
    { OFPMP_FLOW,           "OFPMP_FLOW" },
    { OFPMP_TABLE,          "OFPMP_TABLE" },
    { OFPMP_PORT_STATS,     "OFPMP_PORT_STATS" },
    { OFPMP_QUEUE,          "OFPMP_QUEUE" },
    { OFPMP_GROUP,          "OFPMP_GROUP" },
    { OFPMP_GROUP_DESC,     "OFPMP_GROUP_DESC" },
    { OFPMP_GROUP_FEATURES, "OFPMP_GROUP_FEATURES" },
    { OFPMP_METER,          "OFPMP_METER" },
    { OFPMP_METER_CONFIG,   "OFPMP_METER_CONFIG" },
    { OFPMP_METER_FEATURES, "OFPMP_METER_FEATURES" },
    { OFPMP_TABLE_FEATURES, "OFPMP_TABLE_FEATURES" },
    { OFPMP_PORT_DESC,      "OFPMP_PORT_DESC" },
    { OFPMP_EXPERIMENTER,   "OFPMP_EXPERIMENTER" },
    { 0, NULL }
};

/*
struct ofp_multipart_request {
struct ofp_header header;
uint16_t type; / One of the OFPMP_* constants. /
uint16_t flags; / OFPMPF_REQ_* flags. /
uint8_t pad[4];
uint8_t body[0]; / Body of the request. /
};
*/
static void
dissect_openflow_multipart_request_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    guint16 type;

    /* type */
    type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_multipart_type , tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t flags OFPMPF_REQ_* flags. */
    proto_tree_add_item(tree, hf_openflow_v4_multipart_request_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_openflow_v4_padd32, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    switch(type){
    case OFPMP_DESC: /* 0 */
        /* The request body is empty. */
        break;
    case OFPMP_FLOW:
        /* The request body is struct ofp_flow_stats_request. */
        proto_tree_add_text(tree, tvb, offset, -1, "struct ofp_flow_stats_request - not dissected yet");
        break;
    default:
        if(length>16)
            proto_tree_add_text(tree, tvb, offset, -1, "Type - not dissected yet");
        break;
    }

}

static void
dissect_openflow_multipart_reply_v4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint16 length _U_)
{
    guint16 type;

    /* type */
    type = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_openflow_v4_multipart_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* uint16_t flags OFPMPF_REPLY_* flags. */
    proto_tree_add_item(tree, hf_openflow_v4_multipart_reply_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_openflow_v4_padd32, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    switch(type){
    case OFPMP_DESC: /* 0 */
        /* The reply body is struct ofp_desc. */
        proto_tree_add_text(tree, tvb, offset, -1, "struct ofp_desc - not dissected yet");
        break;
    case OFPMP_FLOW:
        /* The reply body is an array of struct ofp_flow_stats */
        proto_tree_add_text(tree, tvb, offset, -1, "struct ofp_flow_stats - not dissected yet");
        break;
    default:
        if(length>16)
            proto_tree_add_text(tree, tvb, offset, -1, "Type - not dissected yet");
        break;
    }

}

static int
dissect_openflow_v4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *openflow_tree;
    guint offset = 0;
    guint8 type;
    guint16 length;

    type    = tvb_get_guint8(tvb, 1);

    col_append_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
                  val_to_str_const(type, openflow_v4_type_values, "Unknown Messagetype"));

    /* Stop the Ethernet frame from overwriting the columns */
    if((type == OFPT_V4_PACKET_IN) || (type == OFPT_V4_PACKET_OUT)){
        col_set_writable(pinfo->cinfo, FALSE);
    }

    /* Create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_openflow_v4, tvb, 0, -1, ENC_NA);
    openflow_tree = proto_item_add_subtree(ti, ett_openflow_v4);

    /* A.1 OpenFlow Header. */
    /* OFP_VERSION. */
    proto_tree_add_item(openflow_tree, hf_openflow_v4_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* One of the OFPT_ constants. */
    proto_tree_add_item(openflow_tree, hf_openflow_v4_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Length including this ofp_header. */
    length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(openflow_tree, hf_openflow_v4_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    /* Transaction id associated with this packet. Replies use the same id as was in the request
     * to facilitate pairing.
     */
    proto_tree_add_item(openflow_tree, hf_openflow_v4_xid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    switch(type){
    case OFPT_V4_HELLO: /* 0 */
        /* 5.5.1 Hello
         * The OFPT_HELLO message has no body;
         */
        break;
    case OFPT_V4_FEATURES_REQUEST: /* 5 */
        /* 5.3.1 Handshake
         * Upon TLS session establishment, the controller sends an OFPT_FEATURES_REQUEST
         * message. This message does not contain a body beyond the OpenFlow header.
         */
        break;
    case OFPT_V4_FEATURES_REPLY: /* 6 */
        dissect_openflow_features_reply_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

    case OFPT_V4_MULTIPART_REQUEST: /* 18 */
        dissect_openflow_multipart_request_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

    case OFPT_V4_MULTIPART_REPLY: /* 19 */
        dissect_openflow_multipart_reply_v4(tvb, pinfo, openflow_tree, offset, length);
        break;

    default:
        if(length>8){
            proto_tree_add_text(tree, tvb, offset, -1, "Message data not dissected yet");
        }
        break;
    }

    return tvb_length(tvb);

}

/* 
 * Register the protocol with Wireshark.
 */
void
proto_register_openflow_v4(void)
{

    static hf_register_info hf[] = {
        { &hf_openflow_v4_version,
            { "Version", "openflow_v4.version",
               FT_UINT8, BASE_HEX, VALS(openflow_v4_version_values), 0x7f,
               NULL, HFILL }
        },
        { &hf_openflow_v4_type,
            { "Type", "openflow_v4.type",
               FT_UINT8, BASE_DEC, VALS(openflow_v4_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_xid,
            { "Transaction ID", "openflow_v4.xid",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_length,
            { "Length", "openflow_v4.length",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_datapath_id,
            { "Datapath unique ID", "openflow_v4.datapath_id",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_datapath_v4_mac,
            { "MAC addr", "openflow_v4.datapath_mac",
               FT_ETHER, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_datapath_impl,
            { "Implementers part", "openflow_v4.datapath_imp",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_n_buffers,
            { "n_buffers", "openflow_v4.n_buffers",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_n_tables,
            { "n_tables", "openflow_v4.n_tables",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_auxiliary_id,
            { "auxiliary_id", "openflow_v4.auxiliary_id",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_padd16,
            { "Padding", "openflow_v4.padding16",
               FT_UINT16, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_pad3,
            { "Padding", "openflow_v4.pad3",
               FT_UINT24, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_padd32,
            { "Padding", "openflow_v4.padding32",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_capabilities,
            { "capabilities", "openflow_v4.capabilities",
               FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_cap_flow_stats,
            { "Flow statistics", "openflow_v4.flow_stats",
               FT_BOOLEAN, 32, NULL, OFPC_V4_FLOW_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_table_stats,
            { "Table statistics", "openflow_v4.table_stats",
               FT_BOOLEAN, 32, NULL, OFPC_V4_TABLE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_stats,
            { "Port statistics", "openflow_v4.port_stats",
               FT_BOOLEAN, 32, NULL,  OFPC_V4_PORT_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_group_stats,
            { "Group statistics", "openflow_v4.group_stats",
               FT_BOOLEAN, 32, NULL, OFPC_V4_GROUP_STATS,
               NULL, HFILL }
        },
        { &hf_openflow__v4_ip_reasm,
            { "Can reassemble IP fragments", "openflow_v4.ip_reasm",
               FT_BOOLEAN, 32, NULL, OFPC_V4_IP_REASM,
               NULL, HFILL }
        },
        { &hf_openflow_v4_queue_stats,
            { "Queue statistics", "openflow_v4.queue_stats",
               FT_BOOLEAN, 32, NULL, OFPC_V4_QUEUE_STATS,
               NULL, HFILL }
        },
        { &hf_openflow_v4_port_blocked,
            { "Switch will block looping ports", "openflow_v4.port_blocked",
               FT_BOOLEAN, 32, NULL, OFPC_V4_PORT_BLOCKED,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_type,
            { "Type", "openflow_v4.multipart_type",
               FT_UINT16, BASE_DEC, VALS(openflow_v4_multipart_type_values), 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_request_flags,
            { "Flags", "openflow_v4.multipart_request_flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_openflow_v4_multipart_reply_flags,
            { "Flags", "openflow_v4.multipart_request_flags",
               FT_UINT16, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
    };


    static gint *ett[] = {
        &ett_openflow_v4,
        &ett_openflow_v4_path_id,
		&ett_openflow_v4_cap,
    };

    /* Register the protocol name and description */
    proto_openflow_v4 = proto_register_protocol("OpenFlow_V4",
            "openflow_v4", "openflow_v4");

	new_register_dissector("openflow_v4", dissect_openflow_v4, proto_openflow_v4);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_openflow_v4, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}