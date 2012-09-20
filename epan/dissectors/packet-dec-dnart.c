/* packet-dec-dnart.c
 *
 * Routines for DECnet NSP/RT  disassembly
 *
 * Copyright 2003-2005 Philips Medical Systems
 * Copyright 2003-2005 Fred Hoekstra, Philips Medical Systems.
 *                (fred.hoekstra@philips.com)
 *
 * $Id$
 *
 * Use was made of the following documentation:
 *
 *         DECnet DIGITAL Network Architecture
 *      Routing Layer Functional Specification
 *      Version 2.0.0 May, 1983
 *
 *         DECnet DIGITAL Network Architecture
 *      NSP Functional Specification
 *      Phase IV, Version 4.0.1, July 1984
 *
 *      DNA FS SESSION CONTROL
 *      SECON.RNO [31,1]
 *      EDITED 10/17/80
 *
 * See
 *
 *	http://h71000.www7.hp.com/wizard/decnet/
 *
 * for some DECnet specifications.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/etypes.h>
#include <epan/ppptypes.h>

typedef enum {
    RT_CTL_INITIALIZATION,
    RT_CTL_VERIFICATION,
    RT_CTL_HELLO_TEST,
    RT_CTL_LVL1_ROUTING,
    RT_CTL_LVL2_ROUTING,
    RT_CTL_ETH_ROUTER_HELLO_MSG,
    RT_CTL_ETH_ENDNODE_HELLO_MSG
} ctl_msg_types;

#define DEC_RT_SIZE        27

#define DATA_SEGMENT_MSG     0x00 /* "Data segment" */
#define LINK_SERVICE_MSG     0x10 /* "Link service message" */
#define BOM_MSG              0x20 /* "Beginning of segment (BOM)message" */
#define EOM_MSG              0x40 /* "End of segment (EOM)message" */
#define BOM_EOM_MSG          0x60 /* "BOM / EOM message" */
#define INTERRUPT_MSG        0x30 /* "Interrupt message" */
#define DATA_ACK_MSG         0x04 /* "Data acknowledgement message" */
#define OTHER_DATA_ACK_MSG   0x14 /* "Other data acknowledgement message" */
#define CONN_ACK_MSG         0x24 /* "Connect acknowledgement message" */
#define NOP_MSG              0x08 /* "NOP" */
#define CONN_INITIATE_MSG    0x18 /* "Connect initiate" */
#define CONN_CONFIRM_MSG     0x28 /* "Connect confirm" */
#define DISCONN_INITIATE_MSG 0x38 /* "Disconnect initiate" */
#define DISCONN_CONFIRM_MSG  0x48 /* "Disconnect confirm" */
#define RE_XMT_CONN_INIT_MSG 0x68 /* "Retransmitted connect initiate" */

/* Flag bits */

#define RT_FLAGS_CTRL_MSG      0x01
#define RT_FLAGS_LONG_MSG      0x04 /* Actually: 0x06->long, 0x02->short*/
#define RT_FLAGS_RQR           0x08
#define RT_FLAGS_RTS           0x10
#define RT_FLAGS_INTRA_ETHER   0x20
#define RT_FLAGS_DISCARD       0x40
#define RT_FLAGS_PAD           0x80

static int proto_dec_rt = -1;

static int hf_dec_routing_flags = -1;
static int hf_dec_rt_ctrl_msg = -1;
static int hf_dec_rt_long_msg = -1;
static int hf_dec_rt_short_msg = -1;
static int hf_dec_rt_rqr = -1;
static int hf_dec_rt_rts = -1;
static int hf_dec_rt_inter_eth = -1;
static int hf_dec_rt_discard = -1;
static int hf_dec_rt_dst_addr = -1;
static int hf_dec_rt_src_addr = -1;
static int hf_dec_rt_nl2 = -1;
static int hf_dec_rt_service_class = -1;
static int hf_dec_rt_protocol_type = -1;
static int hf_dec_rt_visit_count = -1;
static int hf_dec_rt_dst_node = -1;
static int hf_dec_rt_src_node = -1;
/* Routing control messages */
static int hf_dec_rt_visited_nodes = -1;
static int hf_dec_ctl_msgs = -1;
static int hf_dec_ctl_msg_hdr = -1;
static int hf_dec_nsp_msgs = -1;
static int hf_dec_rt_tiinfo = -1;
static int hf_dec_rt_blk_size = -1;
static int hf_dec_rt_version = -1;
static int hf_dec_rt_timer = -1;
static int hf_dec_rt_reserved = -1;
static int hf_dec_rt_fcnval = -1;
static int hf_dec_rt_test_data = -1;
static int hf_dec_rt_segment = -1;
static int hf_dec_rt_id = -1;
static int hf_dec_rt_iinfo = -1;
static int hf_dec_rt_iinfo_node_type = -1;
static int hf_dec_rt_iinfo_vrf = -1;
static int hf_dec_rt_iinfo_rej = -1;
static int hf_dec_rt_iinfo_verf = -1;
static int hf_dec_rt_iinfo_mta = -1;
static int hf_dec_rt_iinfo_blkreq = -1;
static int hf_dec_rt_iprio = -1;
static int hf_dec_rt_neighbor = -1;
static int hf_dec_rt_seed = -1;
static int hf_dec_rt_elist = -1;
static int hf_dec_rt_ename = -1;
static int hf_dec_rt_router_id = -1;
static int hf_dec_rt_router_state = -1;
static int hf_dec_rt_router_prio = -1;
static int hf_dec_rt_seg_size = -1;
static int hf_dec_rt_acknum = -1;
static int hf_dec_rt_segnum = -1;
static int hf_dec_rt_delay = -1;
static int hf_dec_flow_control = -1;
static int hf_dec_rt_fc_val = -1;
static int hf_dec_rt_services = -1;
static int hf_dec_rt_info = -1;
static int hf_dec_disc_reason = -1;
static int hf_dec_conn_contents = -1;
static int hf_dec_sess_obj_type = -1;
static int hf_dec_sess_grp_code = -1;
static int hf_dec_sess_usr_code = -1;
static int hf_dec_sess_dst_name = -1;
static int hf_dec_sess_src_name = -1;
static int hf_dec_sess_menu_ver = -1;
static int hf_dec_sess_rqstr_id = -1;

static gint ett_dec_rt = -1;
static gint ett_dec_routing_flags = -1;
static gint ett_dec_msg_flags = -1;
static gint ett_dec_rt_ctl_msg = -1;
static gint ett_dec_rt_nsp_msg = -1;
static gint ett_dec_rt_info_flags = -1;
static gint ett_dec_rt_list = -1;
static gint ett_dec_rt_rlist = -1;
static gint ett_dec_rt_state = -1;
static gint ett_dec_flow_control = -1;
static gint ett_dec_sess_contents = -1;

static gint dec_dna_total_bytes_this_segment = 0;
static gint dec_dna_previous_total = 0;

/*static const value_string protocol_id_vals[] = {
    { 0x6001, "DEC DNA dump/load" },
    { 0x6002, "DEC DNA Remote Console" },
    { 0x6003, "DEC DNA routing" },
    { 0x6004, "DEC DNA Local Area Transport" },
    { 0x6005, "DEC DNA diagnostics" },
    { 0x6006, "DEC DNA Customer specific" },
    { 0x6007, "DEC DNA System Communication Architecture" },
    { 0,    NULL }
};*/

static const value_string rt_msg_type_vals[] = {
    { 0x0   , "Initialization message" },
    { 0x1   , "Verification message" },
    { 0x2   , "Hello and test message" },
    { 0x3   , "Level 1 routing message" },
    { 0x4   , "Level 2 routing message" },
    { 0x5   , "Ethernet router hello message" },
    { 0x6   , "Ethernet endnode hello message" },
    { 0,    NULL }
};

static const value_string nsp_msg_type_vals[] = {
    { 0x00   , "Data segment continuation" },
    { 0x04   , "Data acknowledgement message" },
    { 0x08   , "NOP" },
    { 0x10   , "Link service message" },
    { 0x14   , "Other data acknowledgement message" },
    { 0x18   , "Connect initiate" },
    { 0x20   , "Beginning of segment message" },
    { 0x24   , "Connect acknowledgement message" },
    { 0x28   , "Connect confirm" },
    { 0x30   , "Interrupt message" },
    { 0x38   , "Disconnect initiate" },
    { 0x40   , "End of segment message" },
    { 0x48   , "Disconnect confirm" },
    { 0x60   , "Begin of segment / End of segment" },
    { 0x68   , "Retransmitted connect initiate" },
    { 0,    NULL }
};

static const value_string rt_tiinfo_vals[] = {
    {0x01,  "Level 2 router"},
    {0x02,  "Level 1 router"},
    {0x03,  "End node"},
    {0x04,  "Routing layer verification required"},
    {0x08,  "Blocking requested"},
    {0x0,  NULL}
};

static const value_string rt_iinfo_node_type_vals[] = {
    {0x01,  "Level 2 router"},
    {0x02,  "Level 1 router"},
    {0x03,  "End node"},
    {0x0,  NULL}
};

static const value_string rt_flow_control_vals[] = {
    {0x00,  "no change"},
    {0x01,  "do not send data"},
    {0x02,  "send data"},
    {0x03,  "reserved"},
    {0x0,  NULL}
};

static const value_string rt_services_vals[] = {
    {0x00,  "none"},
    {0x04,  "segment request count"},
    {0x08,  "Session control message request count"},
    {0x0c,  "reserved"},
    {0x0,   NULL}
};

static const value_string rt_info_version_vals[] = {
    {0x00,  "version 3.2"},
    {0x01,  "version 3.1"},
    {0x02,  "version 4.0"},
    {0x03,   "reserved"},
    {0x0,   NULL}
};

static const value_string rt_disc_reason_vals[] = {
    { 0,    "no error"},
    { 3,    "The node is shutting down"},
    { 4,    "The destination end user does not exist"},
    { 5,    "A connect message contains an invalid end user name"},
    { 6,    "Destination end user has insufficient resources"},
    { 7,    "Unspecified error"},
    { 8,    "A third party has disconnected the link"},
    { 9,    "An end user has aborted the logical link"},
    { 32,   "The node has insufficient resources"},
    { 33,   "Destination end user has insufficient resources"},
    { 34,   "Connect request rejected because incorrect RQSTRID or PASSWORD"},
    { 36,   "Connect request rejected because of unacceptable ACCOUNT info"},
    { 38,   "End user has timed out, aborted or cancelled a connect request"},
    { 43,   "Connect request RQSTRID, PASSWORD, ACCOUNT or USRDATA too long"},
    { 0,    NULL}
};

#define RT_TYPE_TOPOLOGY_CHANGE    2
#define RT_TYPE_HELLO            25

#if ! defined true
#define true 1
#endif
#if ! defined false
#define false 0
#endif

static int
handle_nsp_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    guint offset,
    guint8 nsp_msg_type);


static int
do_initialization_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *ctl_msg_tree,
    guint offset);

static int
do_verification_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *ctl_msg_tree,
    guint offset);

static int
do_hello_test_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *ctl_msg_tree,
    guint offset);

static int
do_routing_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *ctl_msg_tree,
    guint offset,
    guint msg);

static int
do_hello_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *ctl_msg_tree,
    guint offset,
    guint msg);

static int
handle_connect_contents(
    tvbuff_t *tvb,
    proto_tree *tree,
    guint offset);

static int
handle_disc_init_contents(
    guint offset);

static char *
dnet_ntoa(const guint8 *data)
{
    if (data[0] == 0xAA && data[1] == 0x00 && data[2] == 0x04 && data[3] == 0x00) {
        guint16 dnet_addr = data[4] | (data[5] << 8);
        return ep_strdup_printf("%d.%d", dnet_addr >> 10, dnet_addr & 0x03FF);
    }
    return NULL;
}

static void
set_dnet_address(address *paddr_src, address *paddr_tgt)
{
    if (paddr_tgt->type != AT_STRINGZ && paddr_src->type == AT_ETHER) {
        char *addr = dnet_ntoa(paddr_src->data);
        if (addr != NULL)
            SET_ADDRESS(paddr_tgt, AT_STRINGZ, 1, addr);
    }
}

static void
dissect_dec_rt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8  padding_length;
    guint8  forward;
    guint8  msg_flags;
    guint   rt_visit_count, rt_zero = 0;
    gint    offset;
    proto_tree *rt_tree;
    proto_tree *flags_tree;
    proto_item *ti;
    char *addr;

    offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DEC DNA");
    col_clear(pinfo->cinfo, COL_INFO);

    set_dnet_address(&pinfo->dl_src, &pinfo->net_src);
    set_dnet_address(&pinfo->dl_src, &pinfo->src);
    set_dnet_address(&pinfo->dl_dst, &pinfo->net_dst);
    set_dnet_address(&pinfo->dl_dst, &pinfo->dst);

    offset += 2;
    msg_flags = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_item(tree, proto_dec_rt, tvb, 0, -1, ENC_NA);
    rt_tree = proto_item_add_subtree(ti, ett_dec_rt);
    /* When padding, the first byte after the padding has
       the real routing flags */
    if (msg_flags & 0x80) {
        /* There is padding present, skip it */
        padding_length = msg_flags & 0x7f;
        offset += padding_length;
    }

    /* The real routing flag */
    msg_flags = tvb_get_guint8(tvb, offset);
    ti = proto_tree_add_uint(rt_tree, hf_dec_routing_flags, tvb,
                    offset, 1, msg_flags);
    flags_tree = proto_item_add_subtree(ti, ett_dec_routing_flags);

    if (msg_flags & RT_FLAGS_CTRL_MSG) {
        guint8  ctl_msg_type;
        proto_tree *ctl_msg_tree;

        ctl_msg_type = (msg_flags >> 1) & 0x7;
        proto_tree_add_boolean(flags_tree, hf_dec_rt_ctrl_msg, tvb, offset, 1,
            msg_flags);
        proto_tree_add_uint(flags_tree, hf_dec_ctl_msgs, tvb, offset, 1,
            msg_flags);

        ti = proto_tree_add_uint(rt_tree, hf_dec_ctl_msg_hdr, tvb, offset, 1,
            ctl_msg_type);
        ctl_msg_tree = proto_item_add_subtree(ti, ett_dec_rt_ctl_msg);

        /* Get past the msg_flags */
        offset++;
        switch (ctl_msg_type) {
            case RT_CTL_INITIALIZATION:
                    do_initialization_msg(
                        tvb, pinfo, ctl_msg_tree, offset);
            break;
            case RT_CTL_VERIFICATION:
                    do_verification_msg(
                        tvb, pinfo, ctl_msg_tree, offset);
            break;
            case RT_CTL_HELLO_TEST:
                    do_hello_test_msg(
                        tvb, pinfo, ctl_msg_tree, offset);
            break;
            case RT_CTL_LVL1_ROUTING:
            case RT_CTL_LVL2_ROUTING:
                    do_routing_msg(
                        tvb, pinfo, ctl_msg_tree, offset, msg_flags >> 1);
            break;
            case RT_CTL_ETH_ROUTER_HELLO_MSG:
            case RT_CTL_ETH_ENDNODE_HELLO_MSG:
                    do_hello_msg(
                        tvb, pinfo, ctl_msg_tree, offset, msg_flags >> 1);
            break;
            default:
            break;
        }
    } else if (msg_flags & RT_FLAGS_LONG_MSG){
        proto_tree_add_uint(flags_tree, hf_dec_rt_long_msg,
                tvb, offset, 1, msg_flags);
        proto_tree_add_boolean(flags_tree, hf_dec_rt_rqr, tvb,
                    offset, 1, msg_flags);
        proto_tree_add_boolean(flags_tree, hf_dec_rt_rts, tvb,
                    offset, 1, msg_flags);
        proto_tree_add_boolean(flags_tree, hf_dec_rt_inter_eth, tvb,
                    offset, 1, msg_flags);
        proto_tree_add_boolean(flags_tree, hf_dec_rt_discard, tvb,
                    offset, 1, msg_flags);

        /* Increment offset by three:
                1 to get past the flags field
                2 to skip the DEC area/subarea field
         */
        offset += 3;
        ti = proto_tree_add_item(rt_tree, hf_dec_rt_dst_addr, tvb,
                offset, 6, ENC_NA);
        addr = dnet_ntoa(ep_tvb_memdup(tvb, offset, 6));
        if (addr != NULL) {
            proto_item_append_text(ti, " (%s)", addr);
        }

        /* Skip 6 bytes for the MAC and
                2 bytes for DEC area/subarea
            */
        offset += 8;
        ti = proto_tree_add_item(rt_tree, hf_dec_rt_src_addr, tvb,
            offset, 6, ENC_NA);
        addr = dnet_ntoa(ep_tvb_memdup(tvb, offset, 6));
        if (addr != NULL) {
            proto_item_append_text(ti, " (%s)", addr);
        }

        /* Proceed to the NL2 byte */
        offset += 6;
        proto_tree_add_uint(rt_tree, hf_dec_rt_nl2, tvb,
            offset, 1, rt_zero);
        offset++;
        rt_visit_count = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(rt_tree, hf_dec_rt_visit_count, tvb,
            offset, 1, rt_visit_count);
        offset++;
        proto_tree_add_uint(rt_tree, hf_dec_rt_service_class, tvb,
            offset, 1, rt_zero);
        offset++;
        proto_tree_add_uint(rt_tree, hf_dec_rt_protocol_type, tvb,
            offset, 1, rt_zero);
        offset++;
    } else {
        proto_tree_add_uint(flags_tree, hf_dec_rt_short_msg,
                tvb, offset, 1, msg_flags);
        proto_tree_add_boolean(flags_tree, hf_dec_rt_rqr, tvb,
                    offset, 1, msg_flags);
        proto_tree_add_boolean(flags_tree, hf_dec_rt_rts, tvb,
                    offset, 1, msg_flags);

        /* Increment offset to get past the flags field
         */
        offset++;
        proto_tree_add_item(rt_tree, hf_dec_rt_dst_node, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(rt_tree, hf_dec_rt_src_node, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        forward = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(rt_tree, hf_dec_rt_visited_nodes, tvb,
            offset, 1, forward);
        offset++;
    }

    if (!(msg_flags & RT_FLAGS_CTRL_MSG)) {
        /* It is not a routing control message */
        proto_tree *nsp_msg_tree;
        proto_item *ti_local;
        guint8     nsp_msg_type;

        nsp_msg_type = tvb_get_guint8(tvb, offset);
           ti_local = proto_tree_add_uint(
            tree, hf_dec_nsp_msgs, tvb, offset, 1, nsp_msg_type);
        if (nsp_msg_type == NOP_MSG) {
            /* Only test data in this msg */
            return;
        }
        nsp_msg_tree = proto_item_add_subtree(ti_local, ett_dec_rt_nsp_msg);
        /* Get past the nsp_msg_type */
        offset++;
        proto_tree_add_item(nsp_msg_tree, hf_dec_rt_dst_node, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        if (nsp_msg_type == CONN_ACK_MSG) {
            col_set_str(pinfo->cinfo, COL_INFO, "NSP connect acknowledgement");
            /* Done with this msg type */
            return;
        }
        /* All other messages have a source node */
        proto_tree_add_item(nsp_msg_tree, hf_dec_rt_src_node, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        offset =
            handle_nsp_msg(tvb,
                           pinfo,
                           nsp_msg_tree,
                           offset,
                           nsp_msg_type);
    }
}

static int
do_initialization_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    guint offset)
{
    guint   my_offset = offset;
    guint8  version, eco_nr, user_eco;
    guint8  remainder_count;

    col_set_str(pinfo->cinfo, COL_INFO, "Routing control, initialization message");
    proto_tree_add_item(tree, hf_dec_rt_src_node, tvb,
        my_offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_dec_rt_tiinfo, tvb,
        my_offset, 2, ENC_LITTLE_ENDIAN);
    my_offset += 2;
    proto_tree_add_item(tree, hf_dec_rt_blk_size, tvb,
        my_offset, 2, ENC_LITTLE_ENDIAN);
    my_offset += 2;
    version = tvb_get_guint8(tvb, my_offset);
    eco_nr = tvb_get_guint8(tvb, my_offset + 1);
    user_eco = tvb_get_guint8(tvb, my_offset + 2);
    proto_tree_add_none_format(tree, hf_dec_rt_version, tvb,
        my_offset, 3, "Routing Layer version: %d.%d.%d.",
            version, eco_nr, user_eco);
    my_offset +=3;
    proto_tree_add_item(tree, hf_dec_rt_timer, tvb,
        my_offset, 2, ENC_LITTLE_ENDIAN);
    my_offset += 2;
    remainder_count = tvb_get_guint8(tvb, my_offset);
    if (remainder_count != 0) {
        proto_tree_add_item(tree, hf_dec_rt_reserved, tvb,
            my_offset, remainder_count, ENC_NA);
        my_offset += remainder_count;
    }
    return (my_offset);
}

static int
do_verification_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    guint offset)
{
    guint   my_offset = offset;
    guint8  remainder_count;

    col_set_str(pinfo->cinfo, COL_INFO, "Routing control, verification message");
    proto_tree_add_item(tree, hf_dec_rt_src_node, tvb,
        my_offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    remainder_count = tvb_get_guint8(tvb, my_offset);
    if (remainder_count != 0) {
        proto_tree_add_item(tree, hf_dec_rt_fcnval, tvb,
            my_offset, remainder_count, ENC_NA);
        my_offset += remainder_count;
    }
    return (my_offset);
}

static int
do_hello_test_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    guint offset)
{
    guint   my_offset = offset;
    guint   remainder_count;

    col_set_str(pinfo->cinfo, COL_INFO, "Routing control, hello/test message");
    proto_tree_add_item(tree, hf_dec_rt_src_node, tvb,
        my_offset, 2, ENC_LITTLE_ENDIAN);
    my_offset += 2;
    remainder_count = tvb_length_remaining(tvb, my_offset);
    if (remainder_count != 0) {
        proto_tree_add_item(tree, hf_dec_rt_test_data, tvb,
            my_offset, remainder_count, ENC_NA);
        my_offset += remainder_count;
    }
    return (my_offset);
}

static int
do_routing_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    guint offset,
    guint msg)
{
    guint   my_offset = offset;
    guint32 my_checksum = 1;
    guint16 checksum;
    guint16 count, startid, rtginfo;
    guint   remainder_count;

    proto_tree_add_item(tree, hf_dec_rt_src_node, tvb,
        my_offset, 2, ENC_LITTLE_ENDIAN);
    /* Skip the 1-byte reserved field */
    my_offset += 3;
    remainder_count = tvb_length_remaining(tvb, my_offset);
    do {
        /* if the remainder_count == 1, only the checksum remains */
        count = tvb_get_letohs(tvb, my_offset);
        startid = tvb_get_letohs(tvb, my_offset + 2);
        rtginfo = tvb_get_letohs(tvb, my_offset + 4);
        if (msg == 3) {
            col_set_str(pinfo->cinfo, COL_INFO, "Routing control, Level 1 routing message");
            proto_tree_add_none_format(tree, hf_dec_rt_segment, tvb,
                my_offset, 6,
                "Segment: count:%d, start Id: %d, hops:%d, cost: %d",
                count, startid, (rtginfo & 0x7c00) >> 10, rtginfo & 0x3ff);
        } else {
            col_set_str(pinfo->cinfo, COL_INFO, "Routing control, Level 2 routing message");
            proto_tree_add_none_format(tree, hf_dec_rt_segment, tvb,
                my_offset, 6,
                "Segment: count:%d, start area: %d, hops:%d, cost: %d",
                count, startid, (rtginfo & 0x7c00) >> 10, rtginfo & 0x3ff);
        };
        my_checksum += (count + startid + rtginfo);
        my_offset += 6;
        remainder_count -= 6;
    } while (remainder_count > 6);
    my_offset += remainder_count - 2;
    /* fold 32 bit sum into 16 bits */
    while (my_checksum>>16)
        my_checksum = (my_checksum & 0xffff) + (my_checksum >> 16);
    checksum = tvb_get_letohs(tvb, my_offset);
    if (checksum != my_checksum) {
        proto_tree_add_none_format(tree, hf_dec_rt_segment, tvb,
            my_offset, 2,
            "Checksum mismatch(computed 0x%x <> received 0x%x)",
            my_checksum, checksum);
    } else {
        proto_tree_add_none_format(tree, hf_dec_rt_segment, tvb,
            my_offset, 2,
            "Checksum: match (computed 0x%x = received 0x%x)",
            my_checksum, checksum);
    }
    my_offset += 2;
    return (my_offset);
}

static int
do_hello_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    guint offset,
    guint msg)
{
    guint   my_offset = offset;
    guint8  iinfo, priority;
    guint16 version, eco_nr, user_eco;
    proto_item *ti;
    proto_tree *iinfo_tree;
    char *addr;

    version = tvb_get_guint8(tvb, my_offset);
    eco_nr = tvb_get_guint8(tvb, my_offset + 1);
    user_eco = tvb_get_guint8(tvb, my_offset + 2);
    proto_tree_add_none_format(tree, hf_dec_rt_version, tvb,
        my_offset, 3, "Routing Layer Version: %d.%d.%d",
        version, eco_nr, user_eco);
    my_offset +=3;
    ti = proto_tree_add_item(tree, hf_dec_rt_id, tvb,
        my_offset, 6, ENC_NA);
    addr = dnet_ntoa(ep_tvb_memdup(tvb, my_offset, 6));
    if (addr != NULL) {
        proto_item_append_text(ti, " (%s)", addr);
    }
    my_offset += 6;
    iinfo = tvb_get_guint8(tvb, my_offset);
    ti = proto_tree_add_uint(
        tree, hf_dec_rt_iinfo, tvb, my_offset, 1, iinfo);
    iinfo_tree = proto_item_add_subtree(ti, ett_dec_rt_info_flags);
    proto_tree_add_uint(
        iinfo_tree, hf_dec_rt_iinfo_node_type, tvb, my_offset, 1, iinfo);
    proto_tree_add_boolean(iinfo_tree, hf_dec_rt_iinfo_vrf,
        tvb, my_offset, 1, iinfo);
    proto_tree_add_boolean(iinfo_tree, hf_dec_rt_iinfo_rej,
        tvb, my_offset, 1, iinfo);
    proto_tree_add_boolean(iinfo_tree, hf_dec_rt_iinfo_verf,
        tvb, my_offset, 1, iinfo);
    proto_tree_add_boolean(iinfo_tree, hf_dec_rt_iinfo_mta,
        tvb, my_offset, 1, iinfo);
    proto_tree_add_boolean(iinfo_tree, hf_dec_rt_iinfo_blkreq,
        tvb, my_offset, 1, iinfo);
    my_offset++;
    proto_tree_add_item(tree, hf_dec_rt_blk_size, tvb,
        my_offset, 2, ENC_LITTLE_ENDIAN);
    my_offset += 2;
    if (msg == 5) {
        /* Ethernet router hello message
           Has a 'priority' field in this position */
        col_set_str(pinfo->cinfo, COL_INFO, "Routing control, Ethernet Router Hello  message");
        priority = tvb_get_guint8(tvb, my_offset);
        proto_tree_add_uint(
            tree, hf_dec_rt_iprio, tvb, my_offset, 1, priority);
        my_offset++;
    }
    /* Skip the 'area' field common to both hello messages */
    my_offset += 1;
    if (msg == 6) {
        /* The endnode hello message has 'seed' and 'neighbor' fields */
        col_set_str(pinfo->cinfo, COL_INFO, "Routing control, Endnode Hello message");
        proto_tree_add_item(tree, hf_dec_rt_seed, tvb,
                            my_offset, 8, ENC_NA);
        my_offset += 8;
        ti = proto_tree_add_item(tree, hf_dec_rt_neighbor, tvb,
                my_offset, 6, ENC_NA);
        addr = dnet_ntoa(ep_tvb_memdup(tvb, my_offset, 6));
        if (addr != NULL) {
            proto_item_append_text(ti, " (%s)", addr);
        }
        my_offset += 6;
    }
    /*'Timer' and 'mpd' fields are common
      'mpd' field is reserved */
    proto_tree_add_item(tree, hf_dec_rt_timer, tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
    my_offset += 3;
    if (msg == 5) {
        /* The Ethernet router hello message contains
           a list of router states
           The Ethernet Endnode Hello Message contains
           up to 128 bytes of test data at the end.
           These data are left to be dissected as 'data'.
         */
        proto_item  *ti_locala, *ti_ether;
        proto_tree *list_tree, *list_ether;
        guint8 image_len;
        guint8 item_len;

        /* image field is preceded by count of remainder of field */
        image_len = tvb_get_guint8(tvb, my_offset);
        my_offset++;

        ti_locala = proto_tree_add_item(tree, hf_dec_rt_elist, tvb,
            my_offset, image_len, ENC_NA);
        list_tree = proto_item_add_subtree(ti_locala, ett_dec_rt_list);

        while (image_len > 0) {
            ti_ether = proto_tree_add_item(list_tree, hf_dec_rt_ename, tvb,
                my_offset, 7, ENC_NA);
            list_ether = proto_item_add_subtree(ti_ether, ett_dec_rt_rlist);
            my_offset += 7;
            image_len -= 7;

            /* image field is preceded by count of remainder of field */
            item_len = tvb_get_guint8(tvb, my_offset);
            my_offset++;
            image_len -= 1;
            while (item_len > 0)
            {
                guint8  pristate;
                proto_item  *ti_localb;
                proto_tree *pstate_tree;

                ti_localb = proto_tree_add_item(list_ether, hf_dec_rt_router_id,
                    tvb, my_offset, 6, ENC_NA);
                addr = dnet_ntoa(ep_tvb_memdup(tvb, my_offset, 6));
                if (addr != NULL) {
                    proto_item_append_text(ti_localb, " (%s)", addr);
                }
                my_offset += 6;
                pstate_tree = proto_item_add_subtree(ti_localb, ett_dec_rt_state);
                pristate = tvb_get_guint8(tvb, my_offset);
                proto_tree_add_string(pstate_tree, hf_dec_rt_router_state,
                    tvb, my_offset, 1,
                    ((pristate & 0x80) ? "known 2-way": "unknown"));
                proto_tree_add_uint(pstate_tree, hf_dec_rt_router_prio,
                    tvb, my_offset, 1, pristate);
                my_offset++;
                item_len -= 7;
                image_len -= 7;
            }
        }
    }
    return (my_offset);
}

static int
handle_nsp_msg(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    guint offset,
    guint8 nsp_msg_type)
{
    /* Offset in tvb now points at the first byte still to be handled */
    guint      my_offset = offset;
    gint       data_length;
    guint16    ack_num, ack_dat, ack_oth, seg_num;
    guint8     ls_flags, fc_val, services;
    proto_item  *ti;
    proto_tree *flow_control_tree;

    /* 'tree' is now the subtree for the NSP message */
    switch (nsp_msg_type) {
        case DATA_SEGMENT_MSG:     /* "Data segment" */
        case BOM_MSG:              /* "Beginning of segment message" */
        case EOM_MSG:              /* "End of segment message" */
        case BOM_EOM_MSG:          /* "BOM / EOM message" */
            ack_num = tvb_get_letohs(tvb, my_offset);
            if (ack_num & 0x8000) {
                proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                    tvb, my_offset, 2,
                    "Last data segment %s acknowledged: %d",
                    (ack_num & 0x1000) ? "negatively" : "positively",
                    ack_num & 0xfff);
                my_offset += 2;
                /* There may still be an ackoth field */
                ack_oth = tvb_get_letohs(tvb, my_offset);
                if (ack_oth & 0x8000) {
                    /* There is an ack_oth field */
                    proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                        tvb, my_offset, 2,
                        "Cross sub-channel %s of other data msg %d",
                        ((ack_oth & 0x3000) == 0x2000) ? "ACK" : "NAK",
                        ack_oth & 0xfff);
                    my_offset += 2;
                }
            }
            /*
             * The optional ACKNUM and ACKOTH  fields are not present
             * There is still the segnum field
             */
            seg_num = tvb_get_letohs(tvb, my_offset);
            if (nsp_msg_type == BOM_MSG) {
                dec_dna_total_bytes_this_segment = 0;
                col_append_fstr(pinfo->cinfo, COL_INFO,
                    "msg nr. %d: start of segment",
                    seg_num & 0xfff);
            } else if (nsp_msg_type == DATA_SEGMENT_MSG) {
                col_append_fstr(pinfo->cinfo, COL_INFO,
                    "msg nr. %d: continuation segment ",
                    seg_num & 0xfff);
            } else if (nsp_msg_type == EOM_MSG) {
                col_append_fstr(pinfo->cinfo, COL_INFO,
                    "msg nr. %d: end of segment",
                    seg_num & 0xfff);
            } else if (nsp_msg_type == BOM_EOM_MSG) {
                dec_dna_total_bytes_this_segment = 0;
                col_append_fstr(pinfo->cinfo, COL_INFO,
                    "msg nr. %d single segment",
                    seg_num & 0xfff);
            }
            /* This is the last field, the rest are data */
            proto_tree_add_item(tree, hf_dec_rt_segnum,
                tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_boolean(tree, hf_dec_rt_delay,
                tvb, my_offset, 2, seg_num);
            my_offset += 2;
            /* Compute the number of bytes in this data segment */
            data_length =
                tvb_reported_length_remaining(tvb, my_offset);
            dec_dna_previous_total = dec_dna_total_bytes_this_segment;
            dec_dna_total_bytes_this_segment += data_length;
            col_append_fstr(pinfo->cinfo, COL_INFO,
                ", bytes this segment: %d, total so far:%d",
                data_length, dec_dna_total_bytes_this_segment);
            /* We are done, return my_offset */
            break;
        case INTERRUPT_MSG:        /* "Interrupt message" */
            col_set_str(pinfo->cinfo, COL_INFO, "NSP interrupt message");
            ack_num = tvb_get_letohs(tvb, my_offset);
            if (ack_num & 0x8000) {
                proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                    tvb, my_offset, 2,
                    "Last interrupt/link service msg %s acknowledged: %d",
                    (ack_num & 0x1000) ? "negatively" : "positively",
                    ack_num & 0xfff);
                my_offset += 2;
                /* There may still be an ack_dat field */
            } else {
                /* There are no ack/nak fields */
                proto_tree_add_item(tree, hf_dec_rt_segnum,
                    tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_boolean(tree, hf_dec_rt_delay,
                    tvb, my_offset, 2, ack_num);
                my_offset += 2;
                /* We are done, return my_offset */
                break;
            }
            ack_dat = tvb_get_letohs(tvb, my_offset);
            if (ack_dat & 0x8000) {
                /* There is an ack_dat field */
                proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                    tvb, my_offset, 2,
                    "Cross sub-channel %s of data segment msg: %d",
                    ((ack_dat & 0x3000) == 0x2000) ? "ACK" : "NAK",
                   ack_dat & 0xfff);
                my_offset += 2;
            }
            seg_num = tvb_get_letohs(tvb, my_offset);
            /* This is the last field, the rest are data */
            proto_tree_add_item(tree, hf_dec_rt_segnum,
                tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_boolean(tree, hf_dec_rt_delay,
                tvb, my_offset, 2, seg_num);
            my_offset += 2;
            /* We are done, return my_offset */
            break;
        case LINK_SERVICE_MSG:     /* "Link service message" */
            col_set_str(pinfo->cinfo, COL_INFO, "NSP link control message");
            ack_num = tvb_get_letohs(tvb, my_offset);
            if (ack_num & 0x8000) {
                proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                    tvb, my_offset, 2,
                    "Last interrupt/link service msg %s acknowledged: %d",
                    (ack_num & 0x1000) ? "negatively" : "positively",
                    ack_num & 0xfff);
                my_offset += 2;
                /* There may still be an ack_dat field */
            } else {
                /* There are no ack/nak fields */
                proto_tree_add_item(tree, hf_dec_rt_segnum,
                    tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_boolean(tree, hf_dec_rt_delay,
                    tvb, my_offset, 2, ack_num);
                my_offset += 2;
                /* We are done, return my_offset */
                break;
            }
            ack_dat = tvb_get_letohs(tvb, my_offset);
            if (ack_dat & 0x8000) {
                /* There is an ack_dat field */
                proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                    tvb, my_offset, 2,
                    "Cross sub-channel %s of data segment msg: %d",
                    ((ack_dat & 0x3000) == 0x2000) ? "ACK" : "NAK",
                   ack_dat & 0xfff);
                my_offset += 2;
            }
            seg_num = tvb_get_letohs(tvb, my_offset);
            proto_tree_add_item(tree, hf_dec_rt_segnum,
                tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_boolean(tree, hf_dec_rt_delay,
                tvb, my_offset, 2, seg_num);
            my_offset += 2;
            /* Now follows the ls_flags field */
            ls_flags = tvb_get_guint8(tvb, my_offset);
            switch(ls_flags) {
                case 0: /* no change */
                    col_append_str(pinfo->cinfo, COL_INFO,
                       "(no change)");
                break;
                case 1: /* stop sending data */
                    col_append_str(pinfo->cinfo, COL_INFO,
                       "(stop)");
                break;
                case 2: /* send data */
                    col_append_str(pinfo->cinfo, COL_INFO,
                       "(go)");
                break;
                default:
                break;
            }
            fc_val = tvb_get_guint8(tvb, my_offset + 1);
            ti = proto_tree_add_uint(tree, hf_dec_flow_control, tvb,
                         my_offset, 1, ls_flags);
            flow_control_tree =
                proto_item_add_subtree(ti, ett_dec_flow_control);
            proto_tree_add_none_format(flow_control_tree, hf_dec_rt_fc_val,
                tvb, my_offset, 2,
                "Request for additional %d %s msgs",
                fc_val, ((ls_flags & 0x04) ? "interrupt" : "data"));
            my_offset += 2;
            break;
        case DATA_ACK_MSG:         /* "Data acknowledgement message" */
            ack_num = tvb_get_letohs(tvb, my_offset);
            proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                tvb, my_offset, 2,
                "Last data segment %s acknowledged: %d",
                (ack_num & 0x1000) ? "negatively" : "positively",
                ack_num & 0xfff);
            my_offset += 2;
            /* There may be an optional ack_oth field */
            col_append_fstr(pinfo->cinfo, COL_INFO,
                "NSP data %s message(%d)",
                    (ack_num & 0x1000) ? "NAK" : "ACK",
                    ack_num & 0xfff);

            if (tvb_length_remaining(tvb, my_offset) > 0) {
                ack_oth = tvb_get_letohs(tvb, my_offset);
                if (ack_oth & 0x8000) {
                    /* There is an ack_oth field */
                    proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                        tvb, my_offset, 2,
                        "Cross sub-channel %s of other data msg %d",
                        ((ack_oth & 0x3000) == 0x2000) ? "ACK" : "NAK",
                        ack_oth & 0xfff);
                    my_offset += 2;
                }
            }
            /* We are done, return my_offset */
            break;
        case OTHER_DATA_ACK_MSG:   /* "Other data acknowledgement message" */
            col_set_str(pinfo->cinfo, COL_INFO, "NSP other data ACK message");
            ack_num = tvb_get_letohs(tvb, my_offset);
            proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                tvb, my_offset, 2,
                "Last interrupt/link service msg %s acknowledged: %d",
                (ack_num & 0x1000) ? "negatively" : "positively",
                ack_num & 0xfff);
            my_offset += 2;
            /* There may be an optional ack_dat field */
            if (tvb_length_remaining(tvb, my_offset) > 0) {
                ack_dat = tvb_get_letohs(tvb, my_offset);
                if (ack_dat & 0x8000) {
                    /* There is an ack_dat field */
                    proto_tree_add_none_format(tree, hf_dec_rt_acknum,
                        tvb, my_offset, 2,
                        "Cross sub-channel %s of data msg %d",
                        ((ack_dat & 0x3000) == 0x2000) ? "ACK" : "NAK",
                        ack_dat & 0xfff);
                    my_offset += 2;
                }
            }
            /* We are done, return my_offset */
            break;
        case CONN_CONFIRM_MSG:     /* "Connect confirm" */
        case CONN_INITIATE_MSG:    /* "Connect initiate" */
            col_set_str(pinfo->cinfo, COL_INFO, "NSP connect confirm/initiate message");
            services = tvb_get_guint8(tvb, my_offset);
            proto_tree_add_uint(tree, hf_dec_rt_services, tvb,
                         my_offset, 1, services);
            my_offset++;
            proto_tree_add_item(tree, hf_dec_rt_info, tvb, my_offset, 1, ENC_LITTLE_ENDIAN);
            my_offset++;
            proto_tree_add_item(tree, hf_dec_rt_seg_size, tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
            my_offset += 2;
            my_offset = handle_connect_contents(tvb, tree, my_offset);
            break;
        case DISCONN_INITIATE_MSG: /* "Disconnect initiate" */
        case DISCONN_CONFIRM_MSG:  /* "Disconnect confirm" */
            col_set_str(pinfo->cinfo, COL_INFO, "NSP disconnect initiate/confirm message");
            proto_tree_add_item(tree, hf_dec_disc_reason, tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
            my_offset += 2;
            if (nsp_msg_type == DISCONN_INITIATE_MSG) {
                my_offset =
                    handle_disc_init_contents( my_offset);
            }
            break;
        default:
            break;
    }
    return (my_offset);
}

static int
handle_connect_contents(
    tvbuff_t *tvb,
    proto_tree *tree,
    guint offset)
{
    guint my_offset = offset;
    proto_item   *ti;
    proto_tree   *contents_tree;
    guint8       dst_format, src_format, obj_type, image_len, menu_ver;

    ti = proto_tree_add_item(tree, hf_dec_conn_contents,
        tvb, my_offset, -1, ENC_NA);
    contents_tree = proto_item_add_subtree(ti, ett_dec_sess_contents);
    /* The destination end user */
    dst_format = tvb_get_guint8(tvb, my_offset);
    my_offset++;
    obj_type = tvb_get_guint8(tvb, my_offset);
    proto_tree_add_uint(contents_tree, hf_dec_sess_obj_type, tvb, my_offset, 1, obj_type);
    my_offset++;
    if (dst_format == 2) {
        proto_tree_add_item(contents_tree, hf_dec_sess_grp_code, tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
        my_offset += 2;
        proto_tree_add_item(contents_tree, hf_dec_sess_usr_code, tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
        my_offset += 2;
    }
    if (dst_format != 0) {
        /* The name field for formats 1 and 2 */
        image_len = tvb_get_guint8(tvb, my_offset);
        my_offset++;
        proto_tree_add_item(contents_tree, hf_dec_sess_dst_name, tvb, my_offset, image_len, ENC_ASCII|ENC_NA);
        my_offset += image_len;
    }
    /* The source end user */
    src_format = tvb_get_guint8(tvb, my_offset);
    my_offset++;
    obj_type = tvb_get_guint8(tvb, my_offset);
    proto_tree_add_uint(contents_tree, hf_dec_sess_obj_type,
        tvb, my_offset, 1, obj_type);
    my_offset++;
    if (src_format == 2) {
        proto_tree_add_item(contents_tree, hf_dec_sess_grp_code, tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
        my_offset += 2;
        proto_tree_add_item(contents_tree, hf_dec_sess_usr_code, tvb, my_offset, 2, ENC_LITTLE_ENDIAN);
        my_offset += 2;
    }
    if (dst_format != 0) {
        /* The name field for formats 1 and 2 */
        image_len = tvb_get_guint8(tvb, my_offset);
        my_offset++;
        proto_tree_add_item(contents_tree, hf_dec_sess_src_name,
            tvb, my_offset, image_len, ENC_ASCII|ENC_NA);
        my_offset += image_len;
    }
    /* Now the MENUVER field */
    menu_ver = tvb_get_guint8(tvb, my_offset);
    switch (menu_ver) {
        case 1:
        case 3:
            proto_tree_add_string(contents_tree, hf_dec_sess_menu_ver,
                tvb, my_offset, 1,
                "Version 1.0: RQSTRID, PASSWRD and ACCOUNT fields included");
            my_offset++;
            image_len = tvb_get_guint8(tvb, my_offset);
            my_offset++;
            proto_tree_add_item(contents_tree, hf_dec_sess_rqstr_id,
                tvb, my_offset, image_len, ENC_ASCII|ENC_NA);
            my_offset += image_len;
            image_len = tvb_get_guint8(tvb, my_offset);
            my_offset++;
            proto_tree_add_item(contents_tree, hf_dec_sess_rqstr_id,
                tvb, my_offset, image_len, ENC_ASCII|ENC_NA);
            my_offset += image_len;
            image_len = tvb_get_guint8(tvb, my_offset);
            my_offset++;
            proto_tree_add_item(contents_tree, hf_dec_sess_rqstr_id,
                tvb, my_offset, image_len, ENC_ASCII|ENC_NA);
            my_offset += image_len;


            break;
        case 2:
            /* A USRDATA field is handled by dissect_data */
            proto_tree_add_string(contents_tree, hf_dec_sess_menu_ver,
                tvb, my_offset, 1,
                "Version 1.0: USRDATA field included");
            break;
        default:
            proto_tree_add_string(contents_tree, hf_dec_sess_menu_ver,
                tvb, my_offset, 1,
                "Session control version 1.0");
            break;
    }
    return (my_offset);
}

static int
handle_disc_init_contents(
    guint offset)
{
    guint my_offset = offset;

    return (my_offset);
}


void
proto_register_dec_rt(void)
{

    static hf_register_info hf[] = {
        /* Mesage header items */
        { &hf_dec_routing_flags,
          { "Routing flags",            "dec_dna.flags",
            FT_UINT8,    BASE_HEX,    NULL,    0x0,
            "DNA routing flag", HFILL }},
        { &hf_dec_rt_ctrl_msg,
          { "Control packet",            "dec_dna.flags.control",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    RT_FLAGS_CTRL_MSG,
            NULL, HFILL }},
        { &hf_dec_rt_long_msg,
          { "Long data packet format",     "dec_dna.flags.msglen",
            FT_UINT8,    BASE_HEX,    NULL, 0x06,
            "Long message indicator", HFILL }},
        { &hf_dec_rt_short_msg,
          { "Short data packet format",     "dec_dna.flags.msglen",
            FT_UINT8,    BASE_HEX,    NULL, 0x06,
            "Short message indicator", HFILL }},
        { &hf_dec_rt_rqr,
          { "Return to Sender Request",    "dec_dna.flags.RQR",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    RT_FLAGS_RQR,
            "Return to Sender", HFILL }},
        { &hf_dec_rt_rts,
          { "Packet on return trip",    "dec_dna.flags.RTS",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    RT_FLAGS_RTS,
            NULL, HFILL }},
        { &hf_dec_rt_inter_eth,
          { "Intra-ethernet packet",    "dec_dna.flags.intra_eth",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    RT_FLAGS_INTRA_ETHER,
            NULL, HFILL }},
        { &hf_dec_rt_discard,
          { "Discarded packet",            "dec_dna.flags.discard",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    RT_FLAGS_DISCARD,
            NULL, HFILL }},
        { &hf_dec_rt_dst_addr,
          { "Destination Address",        "dec_dna.dst.address",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
        { &hf_dec_rt_src_addr,
          { "Source Address",            "dec_dna.src.addr",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
        { &hf_dec_rt_nl2,
          { "Next level 2 router",        "dec_dna.nl2",
            FT_UINT8,    BASE_HEX,    NULL,   0x0,
            "reserved", HFILL }},
        { &hf_dec_rt_service_class,
          { "Service class",            "dec_dna.svc_cls",
            FT_UINT8,    BASE_HEX,    NULL,   0x0,
            "reserved", HFILL }},
        { &hf_dec_rt_protocol_type,
          { "Protocol type",            "dec_dna.proto_type",
            FT_UINT8,    BASE_HEX,    NULL,   0x0,
            "reserved", HFILL }},
        { &hf_dec_rt_visit_count,
          { "Visit count",            "dec_dna.visit_cnt",
            FT_UINT8,    BASE_HEX,    NULL,   0x0,
            NULL, HFILL }},
        { &hf_dec_flow_control,
          { "Flow control",            "dec_dna.nsp.flow_control",
            FT_UINT8,    BASE_HEX,    VALS(rt_flow_control_vals),   0x3,
            "Flow control(stop, go)", HFILL }},
        { &hf_dec_rt_services,
          { "Requested services",   "dec_dna.nsp.services",
            FT_UINT8,    BASE_HEX,    VALS(rt_services_vals),   0x0c,
            "Services requested", HFILL }},
        { &hf_dec_rt_info,
          { "Version info",            "dec_dna.nsp.info",
            FT_UINT8,    BASE_HEX,    VALS(rt_info_version_vals),   0x03,
            NULL, HFILL }},
        { &hf_dec_rt_dst_node,
          { "Destination node",            "dec_dna.dst_node",
            FT_UINT16,    BASE_HEX,    NULL,   0x0,
            NULL, HFILL }},
        { &hf_dec_rt_seg_size,
          { "Maximum data segment size", "dec_dna.nsp.segsize",
            FT_UINT16,    BASE_DEC,    NULL,   0x0,
            "Max. segment size", HFILL }},
        { &hf_dec_rt_src_node,
          { "Source node",            "dec_dna.src_node",
            FT_UINT16,    BASE_HEX,    NULL,   0x0,
            NULL, HFILL }},
        { &hf_dec_rt_segnum,
          { "Message number",        "dec_dna.nsp.segnum",
            FT_UINT16,    BASE_DEC,    NULL,   0xfff,
            "Segment number", HFILL }},
        { &hf_dec_rt_delay,
          { "Delayed ACK allowed",  "dec_dna.nsp.delay",
            FT_BOOLEAN,    16,        TFS(&tfs_yes_no),    0x1000,
            "Delayed ACK allowed?", HFILL }},
        { &hf_dec_rt_visited_nodes,
          { "Nodes visited ty this package", "dec_dna.vst_node",
            FT_UINT8,    BASE_DEC,    NULL,   0x0,
            "Nodes visited", HFILL }},
        /* Control messsage items */
        { &hf_dec_ctl_msgs,
          { "Routing control message",        "dec_dna.rt.msg_type",
            FT_UINT8,    BASE_HEX,    VALS(rt_msg_type_vals),    0xe,
            "Routing control", HFILL }},
        { &hf_dec_ctl_msg_hdr,
          { "Routing control message",    "dec_dna.rt.msg_type",
            FT_UINT8,    BASE_HEX,    VALS(rt_msg_type_vals),    0xe,
            "Routing control", HFILL }},
        { &hf_dec_nsp_msgs,
          { "DNA NSP message",        "dec_dna.nsp.msg_type",
            FT_UINT8,    BASE_HEX,    VALS(nsp_msg_type_vals),    0x0,
            "NSP message", HFILL }},
        { &hf_dec_rt_acknum,
          { "Ack/Nak",                "dec_dna.ctl.acknum",
            FT_NONE,    BASE_NONE,    NULL,    0x0,
            "ack/nak number", HFILL }},
        { &hf_dec_rt_fc_val,
          { "Flow control",            "dec_dna.nsp.fc_val",
            FT_NONE,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
        { &hf_dec_rt_tiinfo,
          { "Routing information",    "dec_dna.ctl.tiinfo",
            FT_UINT8,    BASE_HEX,    VALS(rt_tiinfo_vals), 0x0,
            NULL, HFILL }},
        { &hf_dec_rt_blk_size,
          { "Block size",            "dec_dna.ctl.blk_size",
            FT_UINT16,    BASE_DEC,    NULL,    0x0,
            NULL, HFILL }},
        { &hf_dec_disc_reason,
          { "Reason for disconnect","dec_dna.nsp.disc_reason",
            FT_UINT16,    BASE_HEX,    VALS(rt_disc_reason_vals),    0x0,
            "Disconnect reason", HFILL }},
        { &hf_dec_rt_version,
          { "Version",                "dec_dna.ctl.version",
            FT_NONE,    BASE_NONE,    NULL,    0x0,
            "Control protocol version", HFILL }},
        { &hf_dec_rt_timer,
          { "Hello timer(seconds)",  "dec_dna.ctl.timer",
            FT_UINT16,    BASE_DEC,    NULL,   0x0,
            "Hello timer in seconds", HFILL }},
        { &hf_dec_rt_reserved,
          { "Reserved", "dec_dna.ctl.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_rt_fcnval,
          { "Verification message function value", "dec_dna.ctl.fcnval",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Routing Verification function", HFILL }},
        { &hf_dec_rt_test_data,
          { "Test message data", "dec_dna.ctl.test_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Routing Test message data", HFILL }},
        { &hf_dec_rt_segment,
          { "Segment",                "dec_dna.ctl.segment",
            FT_NONE,    BASE_NONE,    NULL,    0x0,
            "Routing Segment", HFILL }},
        { &hf_dec_rt_id,
          { "Transmitting system ID",            "dec_dna.ctl.id",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
        { &hf_dec_rt_iinfo,
          { "Routing information",        "dec_dna.ctl.tiinfo",
            FT_UINT8,    BASE_HEX,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_rt_iinfo_node_type,
          { "Node type",            "dec_dna.ctl.iinfo.node_type",
            FT_UINT8,    BASE_HEX,    VALS(rt_iinfo_node_type_vals),    0x03,
            NULL, HFILL }},
        { &hf_dec_rt_iinfo_vrf,
          { "Verification required",            "dec_dna.ctl.iinfo.vrf",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    0x4,
            "Verification required?", HFILL }},
        { &hf_dec_rt_iinfo_rej,
          { "Rejected",            "dec_dna.ctl.iinfo.rej",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    0x8,
            "Rejected message", HFILL }},
        { &hf_dec_rt_iinfo_verf,
          { "Verification failed",            "dec_dna.ctl.iinfo.verf",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    0x10,
            "Verification failed?", HFILL }},
        { &hf_dec_rt_iinfo_mta,
          { "Accepts multicast traffic",            "dec_dna.ctl.iinfo.mta",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    0x20,
            "Accepts multicast traffic?", HFILL }},
        { &hf_dec_rt_iinfo_blkreq,
          { "Blocking requested",            "dec_dna.ctl.iinfo.blkreq",
            FT_BOOLEAN,    8,        TFS(&tfs_yes_no),    0x40,
            "Blocking requested?", HFILL }},
        { &hf_dec_rt_iprio,
          { "Routing priority",        "dec_dna.ctl.prio",
            FT_UINT8,    BASE_HEX,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_rt_neighbor,
          { "Neighbor",                "dec_dna.ctl_neighbor",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            "Neighbour ID", HFILL }},
        { &hf_dec_rt_seed,
          { "Verification seed",    "dec_dna.ctl.seed",
            FT_BYTES,    BASE_NONE,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_rt_elist,
          { "List of router states",    "dec_dna.ctl.elist",
            FT_NONE,    BASE_NONE,    NULL, 0x0,
            "Router states", HFILL }},
        { &hf_dec_rt_ename,
          { "Ethernet name",      "dec_dna.ctl.ename",
            FT_BYTES,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
        { &hf_dec_rt_router_id,
          { "Router ID",                "dec_dna.ctl.router_id",
            FT_ETHER,    BASE_NONE,    NULL,    0x0,
            NULL, HFILL }},
        { &hf_dec_rt_router_state,
          { "Router state",    "dec_dna.ctl.router_state",
            FT_STRING,    BASE_NONE,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_conn_contents,
          { "Session connect data",    "dec_dna.sess.conn",
            FT_NONE,    BASE_NONE,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_rt_router_prio,
          { "Router priority",    "dec_dna.ctl.router_prio",
            FT_UINT8,    BASE_HEX,    NULL, 0x7f,
            NULL, HFILL }},
        { &hf_dec_sess_grp_code,
          { "Session Group code",    "dec_dna.sess.grp_code",
            FT_UINT16,    BASE_HEX,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_sess_usr_code,
          { "Session User code",    "dec_dna.sess.usr_code",
            FT_UINT16,    BASE_HEX,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_sess_dst_name,
          { "Session Destination end user",    "dec_dna.sess.dst_name",
            FT_STRING,    BASE_NONE,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_sess_src_name,
          { "Session Source end user",    "dec_dna.sess.src_name",
            FT_STRING,    BASE_NONE,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_sess_obj_type,
          { "Session Object type",    "dec_dna.sess.obj_type",
            FT_UINT8,    BASE_HEX,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_sess_menu_ver,
          { "Session Menu version",    "dec_dna.sess.menu_ver",
            FT_STRING,    BASE_NONE,    NULL, 0x0,
            NULL, HFILL }},
        { &hf_dec_sess_rqstr_id,
          { "Session Requestor ID",    "dec_dna.sess.rqstr_id",
            FT_STRING,    BASE_NONE,    NULL, 0x0,
            NULL, HFILL }},


    };
    static gint *ett[] = {
        &ett_dec_rt,
        &ett_dec_routing_flags,
        &ett_dec_msg_flags,
        &ett_dec_rt_ctl_msg,
        &ett_dec_rt_nsp_msg,
        &ett_dec_rt_info_flags,
        &ett_dec_rt_list,
        &ett_dec_rt_rlist,
        &ett_dec_rt_state,
        &ett_dec_flow_control,
        &ett_dec_sess_contents,
    };

    proto_dec_rt = proto_register_protocol("DEC DNA Routing Protocol",
                                           "DEC_DNA", "dec_dna");
    proto_register_field_array(proto_dec_rt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dec_rt(void)
{
    dissector_handle_t dec_rt_handle;

    dec_rt_handle = create_dissector_handle(dissect_dec_rt,
                                            proto_dec_rt);
    dissector_add_uint("ethertype", ETHERTYPE_DNA_RT, dec_rt_handle);
    dissector_add_uint("chdlctype", ETHERTYPE_DNA_RT, dec_rt_handle);
    dissector_add_uint("ppp.protocol", PPP_DEC4, dec_rt_handle);
/*  dissector_add_uint("ppp.protocol", PPP_DECNETCP, dec_rt_handle);*/
}
