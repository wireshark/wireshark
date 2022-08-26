/* packet-pn-rsi.c
 * Routines for PN-RSI
 * packet dissection.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/to_str.h>
#include <epan/wmem_scopes.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/expert.h>
#include <epan/conversation_filter.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>

#include <wsutil/file_util.h>
#include <epan/prefs.h>

#include "packet-pn.h"

void proto_register_pn_rsi(void);
void proto_reg_handoff_pn_rsi(void);

static int proto_pn_rsi = -1;

static int hf_pn_rsi_dst_srv_access_point = -1;
static int hf_pn_rsi_src_srv_access_point = -1;

static int hf_pn_rsi_pdu_type = -1;
static int hf_pn_rsi_pdu_type_type = -1;
static int hf_pn_rsi_pdu_type_version = -1;

static int hf_pn_rsi_add_flags = -1;
static int hf_pn_rsi_add_flags_windowsize = -1;
static int hf_pn_rsi_add_flags_reserved1 = -1;
static int hf_pn_rsi_add_flags_tack = -1;
static int hf_pn_rsi_add_flags_morefrag = -1;
static int hf_pn_rsi_add_flags_notification = -1;
static int hf_pn_rsi_add_flags_reserved2 = -1;

static int hf_pn_rsi_send_seq_num = -1;
static int hf_pn_rsi_ack_seq_num = -1;
static int hf_pn_rsi_var_part_len = -1;

static int hf_pn_rsi_f_opnum_offset = -1;
static int hf_pn_rsi_f_opnum_offset_offset = -1;
static int hf_pn_rsi_f_opnum_offset_opnum = -1;
static int hf_pn_rsi_f_opnum_offset_callsequence = -1;

static int hf_pn_rsi_conn_block = -1;
static int hf_pn_rsi_rsp_max_length = -1;
static int hf_pn_rsi_vendor_id = -1;
static int hf_pn_rsi_device_id = -1;
static int hf_pn_rsi_instance_id = -1;
static int hf_pn_rsi_interface = -1;

static int hf_pn_rsi_svcs_block = -1;

static int hf_pn_rsi_number_of_entries = -1;
static int hf_pn_rsi_pd_rsi_instance = -1;
static int hf_pn_rsi_device_type = -1;
static int hf_pn_rsi_order_id = -1;
static int hf_pn_rsi_im_serial_number = -1;
static int hf_pn_rsi_hw_revision = -1;
static int hf_pn_rsi_sw_revision_prefix = -1;
static int hf_pn_rsi_sw_revision = -1;

static gint ett_pn_rsi = -1;
static gint ett_pn_rsi_pdu_type = -1;
static gint ett_pn_rsi_f_opnum_offset = -1;
static gint ett_pn_rsi_conn_block = -1;
static gint ett_pn_rsi_svcs_block = -1;
static gint ett_pn_rsi_add_flags = -1;
static gint ett_pn_rsi_rta = -1;
static gint ett_pn_io_pd_rsi_instance = -1;

static expert_field ei_pn_rsi_error = EI_INIT;

static const range_string pn_rsi_alarm_endpoint[] = {
    { 0x0000, 0x7FFF, "RSI Initiator Instance (ISAP) or RSI Responder Instance (RSAP)" },
    { 0x8000, 0xFFFE, "Reserved" },
    { 0xFFFF, 0xFFFF, "CON-SAP" },
    { 0, 0, NULL }
};

static const range_string pn_rsi_pdu_type_type[] = {
    { 0x00, 0x02, "Reserved" },
    { 0x03, 0x03, "RTA_TYPE_ACK" },
    { 0x04, 0x04, "RTA_TYPE_ERR" },
    { 0x05, 0x05, "RTA_TYPE_FREQ" },
    { 0x06, 0x06, "RTA_TYPE_FRSP" },
    { 0x07, 0x0F, "Reserved" },
    { 0, 0, NULL }
};

static const range_string pn_rsi_pdu_type_version[] = {
    { 0x00, 0x00, "Reserved" },
    { 0x01, 0x01, "Version 1 of the protocol" },
    { 0x02, 0x02, "Version 2 of the protocol" },
    { 0x03, 0X0F, "Reserved" },
    { 0, 0, NULL }
};

static const value_string pn_rsi_add_flags_windowsize[] = {
    { 0x00, "Reserved" },
    { 0x01, "Unknown WindowSize" },
    { 0x02, "Smallest WindowSize" },
    { 0x03, "Optional usable WindowSize" },
    { 0x04, "Optional usable WindowSize" },
    { 0x05, "Optional usable WindowSize" },
    { 0x06, "Optional usable WindowSize" },
    { 0x07, "Optional usable WindowSize" },
    { 0, NULL }
};

static const value_string pn_rsi_add_flags_tack[] = {
    { 0x00, "No immediate acknowledge" },
    { 0x01, "Immediate acknowledge" },
    { 0, NULL }
};

static const value_string pn_rsi_add_flags_morefrag[] = {
    { 0x00, "Last fragment" },
    { 0x01, "More fragments follows" },
    { 0, NULL }
};

static const value_string pn_rsi_add_flags_notification[] = {
    { 0x00, "No action necessary" },
    { 0x01, "The ApplicationReadyBlock is available for reading with the service ReadNotification" },
    { 0, NULL }
};

static const range_string pn_rsi_seq_num[] = {
    { 0x0000, 0x7FFF, "synchronization and transmission between initiator and responder" },
    { 0x8000, 0xFFFD, "Reserved" },
    { 0xFFFE, 0xFFFE, "synchronize initiator and responder for establishment of an AR" },
    { 0xFFFF, 0xFFFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string pn_rsi_var_part_len[] = {
    { 0x0000, 0x0000, "No RTA-SDU or RSI-SDU exists" },
    { 0x0001, 0x0598, "An RTA-SDU or RSI-PDU with VarPartLen octets exists" },
    { 0x0599, 0xFFFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string pn_rsi_f_opnum_offset_offset[] = {
    { 0x00000000, 0x00000000, "First fragment" },
    { 0x00000001, 0x00000003, "Reserved" },
    { 0x00000004, 0x00FFFFFF, "Not first fragment" },
    { 0, 0, NULL }
};

static const value_string pn_rsi_f_opnum_offset_opnum[] = {
    { 0x00, "Connect" },
    { 0x01, "Reserved" },
    { 0x02, "Read" },
    { 0x03, "Write" },
    { 0x04, "Control" },
    { 0x05, "ReadImplicit" },
    { 0x06, "ReadConnectionless" },
    { 0x07, "ReadNotification" },
    { 0x08, "PrmWriteMore" },
    { 0x09, "PrmWriteEnd" },
    { 0x0A, "Reserved" },
    { 0x0B, "Reserved" },
    { 0x0C, "Reserved" },
    { 0x0D, "Reserved" },
    { 0x0E, "Reserved" },
    { 0x0F, "Reserved" },
    { 0x1F, "Reserved" },
    { 0, NULL }
};

static const range_string pn_rsi_f_opnum_offset_callsequence[] = {
    { 0x00, 0x07, "Allowed values" },
    { 0, 0, NULL }
};

static const range_string pn_rsi_rsp_max_length[] = {
    { 0x00000000, 0x00000003, "Reserved" },
    { 0x00000004, 0x00FFFFFF, "Usable" },
    { 0x01FFFFFF, 0xFFFFFFFF, "Reserved" },
    { 0, 0, NULL }
};

static const range_string pn_rsi_interface[] = {
    { 0x00, 0x00, "IO device interface" },
    { 0x01, 0x01, "Read Implicit IO device interface" },
    { 0x02, 0x02, "CIM device interface" },
    { 0x03, 0x03, "Read Implicit CIM device interface" },
    { 0x04, 0xFF, "Reserved" },
    { 0, 0, NULL }
};

static int
dissect_FOpnumOffset(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep _U_, guint32 *u32FOpnumOffset)
{
    proto_item *sub_item;
    proto_tree *sub_tree;

    sub_item = proto_tree_add_item(tree, hf_pn_rsi_f_opnum_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_rsi_f_opnum_offset);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_f_opnum_offset_offset, u32FOpnumOffset);
    dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_f_opnum_offset_opnum, u32FOpnumOffset);
    offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_f_opnum_offset_callsequence, u32FOpnumOffset);

    return offset;
}

static int hf_pn_rsi_data_payload = -1;

static int hf_pn_rsi_segments = -1;
static int hf_pn_rsi_segment = -1;
//static int hf_pn_rsi_data = -1;
static int hf_pn_rsi_segment_overlap = -1;
static int hf_pn_rsi_segment_overlap_conflict = -1;
static int hf_pn_rsi_segment_multiple_tails = -1;
static int hf_pn_rsi_segment_too_long_segment = -1;
static int hf_pn_rsi_segment_error = -1;
static int hf_pn_rsi_segment_count = -1;
static int hf_pn_rsi_reassembled_in = -1;
static int hf_pn_rsi_reassembled_length = -1;

static reassembly_table pn_rsi_reassembly_table;

void
pn_rsi_reassemble_init(void)
{
    reassembly_table_register(&pn_rsi_reassembly_table, &addresses_reassembly_table_functions);
}

static gint ett_pn_rsi_segments = -1;
static gint ett_pn_rsi_segment = -1;
//static gint ett_pn_rsi_data = -1;
static gint ett_pn_rsi_data_payload = -1;

static const fragment_items pn_rsi_frag_items = {
    &ett_pn_rsi_segment,
    &ett_pn_rsi_segments,
    &hf_pn_rsi_segments,
    &hf_pn_rsi_segment,
    &hf_pn_rsi_segment_overlap,
    &hf_pn_rsi_segment_overlap_conflict,
    &hf_pn_rsi_segment_multiple_tails,
    &hf_pn_rsi_segment_too_long_segment,
    &hf_pn_rsi_segment_error,
    &hf_pn_rsi_segment_count,
    &hf_pn_rsi_reassembled_in,
    &hf_pn_rsi_reassembled_length,
    /* Reassembled data field */
    NULL,
    "segments"
};

static int
dissect_pn_rta_remaining_user_data_bytes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
    proto_tree *tree, guint8 *drep, guint32 length, guint8 u8MoreFrag, guint32 u32FOpnumOffsetOpnum, int type)
{
    fragment_head  *fd_frag;
    fragment_head  *fd_reass;
    conversation_t *conv;
    tvbuff_t       *next_tvb;
    proto_item     *pn_rsi_tree_item;
    proto_item     *payload_item = NULL;
    proto_item     *payload_tree = NULL;
    gboolean        update_col_info = TRUE;

    if (pinfo->srcport != 0 && pinfo->destport != 0) {
        /* COTP over RFC1006/TCP, try reassembling */
        conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, CONVERSATION_NONE,
            pinfo->srcport, pinfo->destport, 0);
        if (!conv) {
            conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, CONVERSATION_NONE,
                pinfo->srcport, pinfo->destport, 0);
        }

        /* XXX - don't know if this will work with multiple segmented Ack's in a single TCP stream */
        fd_frag = fragment_get(&pn_rsi_reassembly_table, pinfo, conv->conv_index, NULL);
        fd_reass = fragment_get_reassembled_id(&pn_rsi_reassembly_table, pinfo, conv->conv_index);
    }
    else {
        /* plain COTP transport (without RFC1006/TCP), try reassembling */
        conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, CONVERSATION_NONE,
            pinfo->clnp_srcref, pinfo->clnp_dstref, 0);
        if (!conv) {
            conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, CONVERSATION_NONE,
                pinfo->clnp_srcref, pinfo->clnp_dstref, 0);
        }

        /* XXX - don't know if this will work with multiple segmented Ack's in a single TCP stream */
        fd_frag = fragment_get(&pn_rsi_reassembly_table, pinfo, conv->conv_index, NULL);
        fd_reass = fragment_get_reassembled_id(&pn_rsi_reassembly_table, pinfo, conv->conv_index);
    }

    /* is this packet containing a "standalone" segment? */
    if (!u8MoreFrag && !fd_frag && !fd_reass) {
        /* "standalone" segment, simply show payload and return */
        offset = dissect_blocks(tvb, offset, pinfo, tree, drep);
        return offset;
    }

    /* multiple segments */
    if (!pinfo->fd->visited && conv != NULL) {
        /* we haven't seen it before, add to list of segments */
        fragment_add_seq_next(&pn_rsi_reassembly_table, tvb, offset, pinfo, conv->conv_index,
            NULL /*Data comes from tvb as in packet-icmp-template.c */,
            length,
            u8MoreFrag);

        fd_reass = fragment_get_reassembled_id(&pn_rsi_reassembly_table, pinfo, conv->conv_index);
    }

    /* update display */
    col_append_fstr(pinfo->cinfo, COL_INFO, " [%sPN IO RSI Segment]",
        u8MoreFrag ? "" : "Last ");

    /* reassembling completed? */
    if (fd_reass != NULL) {
        /* is this the packet to show the reassembed payload in? */
        if (pinfo->fd->num == fd_reass->reassembled_in) {
            next_tvb = process_reassembled_data(tvb, 0, pinfo,
                "Reassembled PN IO RSI packet", fd_reass, &pn_rsi_frag_items, &update_col_info, tree);

            /* XXX - create new parent tree item "Reassembled Data Segments" */
            payload_item = proto_tree_add_item(tree, hf_pn_rsi_data_payload, next_tvb, 0, tvb_captured_length(next_tvb), ENC_NA);
            payload_tree = proto_item_add_subtree(payload_item, ett_pn_rsi_data_payload);

            offset = dissect_rsi_blocks(next_tvb, 0, pinfo, payload_tree, drep, u32FOpnumOffsetOpnum, type);

            /* the toplevel fragment subtree is now behind all desegmented data,
            * move it right behind the DE2 tree item */
            // pn_rsi_tree_item = proto_tree_get_parent(tree);

        }
        else {
            /* segment of a multiple segment payload */
            proto_item *pi;

            pn_rsi_tree_item = proto_tree_get_parent(tree);
            pi = proto_tree_add_uint(pn_rsi_tree_item, hf_pn_rsi_reassembled_in,
                tvb, 0, 0, fd_reass->reassembled_in);
            PROTO_ITEM_SET_GENERATED(pi);
        }
    }

    return offset;
}

/* dissect a PN-IO RSI SVCS block (on top of PN-RT protocol) */
static int
dissect_RSI_SVCS_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16VarPartLen, guint8 u8MoreFrag, guint32 u32FOpnumOffsetOffset, guint32 u32FOpnumOffsetOpnum)
{
    proto_item* sub_item;
    proto_tree *sub_tree;

	guint32 u32RsiHeaderSize = 4;
	guint32 u32RspMaxLength;

	// PDU.FOpnumOffset.Offset + PDU.VarPartLen - 4 - RsiHeaderSize
    gint32 length = u32FOpnumOffsetOffset + u16VarPartLen - 4 - u32RsiHeaderSize;

    sub_item = proto_tree_add_item(tree, hf_pn_rsi_svcs_block, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_rsi_svcs_block);

    if (u32FOpnumOffsetOffset == 0)
    {
        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_rsp_max_length, &u32RspMaxLength);
    }
    else if (u8MoreFrag == 0)
    {
        proto_item_append_text(sub_item, ", RSI Header of SVCS is at first segment");
    }

    if (length > 0) {
        offset = dissect_pn_rta_remaining_user_data_bytes(tvb, offset, pinfo, sub_tree, drep,
            tvb_captured_length_remaining(tvb, offset), u8MoreFrag, u32FOpnumOffsetOpnum, PDU_TYPE_REQ);
    }
    return offset;
}

/* dissect a PN-IO RSI CONN block (on top of PN-RT protocol) */
static int
dissect_RSI_CONN_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16VarPartLen, guint8 u8MoreFrag, guint32 u32FOpnumOffsetOffset, guint32 u32FOpnumOffsetOpnum)
{
    proto_item *sub_item;
    proto_tree *sub_tree;

    guint32 u32RspMaxLength;
    guint16 u16VendorId;
    guint16 u16DeviceId;
    guint16 u16InstanceId;
    guint8  u8RsiInterface;
    guint32 u32RsiHeaderSize = 4;

    // PDU.FOpnumOffset.Offset + PDU.VarPartLen - 4 - RsiHeaderSize
    gint32 length = u32FOpnumOffsetOffset + u16VarPartLen - 4 - u32RsiHeaderSize;

    sub_item = proto_tree_add_item(tree, hf_pn_rsi_conn_block, tvb, offset, 0, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_rsi_conn_block);

    if (u32FOpnumOffsetOffset == 0) {

        offset = dissect_dcerpc_uint32(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_rsp_max_length, &u32RspMaxLength);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_vendor_id, &u16VendorId);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_device_id, &u16DeviceId);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_instance_id, &u16InstanceId);
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_interface, &u8RsiInterface);

        offset = dissect_pn_padding(tvb, offset, pinfo, sub_tree, 1);
    }
    else if (u8MoreFrag == 0)
    {
        proto_item_append_text(sub_item, ", RSI Header of CONN is at first segment");
    }

    if (length > 0) {
        offset = dissect_pn_rta_remaining_user_data_bytes(tvb, offset, pinfo, sub_tree, drep,
            tvb_captured_length_remaining(tvb, offset), u8MoreFrag, u32FOpnumOffsetOpnum, PDU_TYPE_REQ);
    }

    return offset;
}

/* dissect a PN-IO RSI FREQ RTA PDU (on top of PN-RT protocol) */
static int
dissect_FREQ_RTA_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16VarPartLen, guint8 u8MoreFrag)
{
    guint32    u32FOpnumOffset;
    guint32    u32FOpnumOffsetOpnum;
    guint32    u32FOpnumOffsetOffset;
    offset = dissect_FOpnumOffset(tvb, offset, pinfo, tree, drep, &u32FOpnumOffset);
    u32FOpnumOffsetOpnum = (u32FOpnumOffset & 0x1F000000) >> 24;
    u32FOpnumOffsetOffset = u32FOpnumOffset & 0x00FFFFFF;
    switch (u32FOpnumOffsetOpnum) {
    case(0x0):    /* RSI-CONN-PDU */
        col_append_str(pinfo->cinfo, COL_INFO, "Connect request");
        offset = dissect_RSI_CONN_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
        break;
    case(0x1):    /* Reserved */
        col_append_str(pinfo->cinfo, COL_INFO, "Reserved");
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_captured_length(tvb));
        break;
    case(0x2):    /* RSI-SVCS-PDU (Only valid with ARUUID<>0) */
        col_append_str(pinfo->cinfo, COL_INFO, "Read request");
        offset = dissect_RSI_SVCS_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
        break;
    case(0x3):    /* RSI-SVCS-PDU */
        col_append_str(pinfo->cinfo, COL_INFO, "Write request");
        offset = dissect_RSI_SVCS_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
        break;
    case(0x4):    /* RSI-SVCS-PDU */
        col_append_str(pinfo->cinfo, COL_INFO, "Control request");
        offset = dissect_RSI_SVCS_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
        break;
    case(0x5):    /* RSI-CONN-PDU (Only valid with ARUUID=0) */
        col_append_str(pinfo->cinfo, COL_INFO, "ReadImplicit request");
        offset = dissect_RSI_CONN_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
        break;
    case(0x6):    /* RSI-CONN-PDU (Only valid with ARUUID<>0) */
        col_append_str(pinfo->cinfo, COL_INFO, "ReadConnectionless request");
        offset = dissect_RSI_CONN_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
        break;
    case(0x7):    /* RSI-SVCS-PDU */
        col_append_str(pinfo->cinfo, COL_INFO, "ReadNotification request");
        offset = dissect_RSI_SVCS_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
        break;
    case(0x8):    /* RSI-SVCS-PDU */
        col_append_str(pinfo->cinfo, COL_INFO, "PrmWriteMore request");
        offset = dissect_RSI_SVCS_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
        break;
    case(0x9) :    /* RSI-SVCS-PDU */
        col_append_str(pinfo->cinfo, COL_INFO, "PrmWriteEnd request");
        offset = dissect_RSI_SVCS_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
        break;
    default:
        col_append_str(pinfo->cinfo, COL_INFO, "Reserved");
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_captured_length(tvb));
        break;
    }
    return offset;
}

/* dissect a PN-IO RSI RSP block (on top of PN-RT protocol) */
static int
dissect_RSI_RSP_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16VarPartLen, guint8 u8MoreFrag, guint32 u32FOpnumOffsetOffset, guint32 u32FOpnumOffsetOpnum)
{
    guint32 u32RsiHeaderSize = 4;

    // PDU.FOpnumOffset.Offset + PDU.VarPartLen - 4 - RsiHeaderSize
    gint32 length = u32FOpnumOffsetOffset + u16VarPartLen - 4 - u32RsiHeaderSize;

    if (u32FOpnumOffsetOffset == 0)
    {
        offset = dissect_PNIO_status(tvb, offset, pinfo, tree, drep);
    }

    else if (u8MoreFrag == 0)
    {
        proto_item_append_text(tree, ", RSI Header of RSP is at first fragmented frame");
    }

    if (length > 0) {
        offset = dissect_pn_rta_remaining_user_data_bytes(tvb, offset, pinfo, tree, drep,
            tvb_captured_length_remaining(tvb, offset), u8MoreFrag, u32FOpnumOffsetOpnum, PDU_TYPE_RSP);
    }

    return offset;
}

/* dissect a PN-IO RSI FRSP RTA PDU (on top of PN-RT protocol) */
static int
dissect_FRSP_RTA_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep, guint16 u16VarPartLen, guint8 u8MoreFrag)
{
    guint32    u32FOpnumOffset;
    guint32    u32FOpnumOffsetOpnum;
    guint32    u32FOpnumOffsetOffset;
    offset = dissect_FOpnumOffset(tvb, offset, pinfo, tree, drep, &u32FOpnumOffset);
    u32FOpnumOffsetOpnum = (u32FOpnumOffset & 0x1F000000) >> 24;
    u32FOpnumOffsetOffset = u32FOpnumOffset & 0x00FFFFFF;
    switch (u32FOpnumOffsetOpnum) {
    case(0x0):    /* Connect */
        col_append_str(pinfo->cinfo, COL_INFO, "Connect response");
        break;
    case(0x1):    /* Reserved */
        col_append_str(pinfo->cinfo, COL_INFO, "Reserved");
        break;
    case(0x2):    /* Read */
        col_append_str(pinfo->cinfo, COL_INFO, "Read response");
        break;
    case(0x3):    /* Write */
        col_append_str(pinfo->cinfo, COL_INFO, "Write response");
        break;
    case(0x4):    /* Control */
        col_append_str(pinfo->cinfo, COL_INFO, "Control response");
        break;
    case(0x5):    /* ReadImplicit */
        col_append_str(pinfo->cinfo, COL_INFO, "ReadImplicit response");
        break;
    case(0x6):    /* ReadConnectionless */
        col_append_str(pinfo->cinfo, COL_INFO, "ReadConnectionless response");
        break;
    case(0x7):    /* ReadNotification */
        col_append_str(pinfo->cinfo, COL_INFO, "ReadNotification response");
        break;
    case(0x8):    /* PrmWriteMore */
        col_append_str(pinfo->cinfo, COL_INFO, "PrmWriteMore response");
        break;
    case(0x9) :   /* PrmWriteEnd */
        col_append_str(pinfo->cinfo, COL_INFO, "PrmWriteEnd response");
        break;
    default:
        col_append_str(pinfo->cinfo, COL_INFO, "Reserved");
        break;
    }
    offset = dissect_RSI_RSP_block(tvb, offset, pinfo, tree, drep, u16VarPartLen, u8MoreFrag, u32FOpnumOffsetOffset, u32FOpnumOffsetOpnum);
    return offset;
}

static int
dissect_RSIAdditionalFlags(tvbuff_t *tvb, int offset,
    packet_info *pinfo _U_, proto_tree *tree, guint8 *drep _U_, guint8 *u8AddFlags)
{
    guint8      u8WindowSize;
    guint8      u8Tack;
    proto_item *sub_item;
    proto_tree *sub_tree;

    /* additional flags */
    sub_item = proto_tree_add_item(tree, hf_pn_rsi_add_flags, tvb, offset, 1, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_rsi_add_flags);
    /* Bit 0 - 2 : AddFlags.WindowSize */
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_add_flags_windowsize, u8AddFlags);
    /* Bit 3: AddFlags.Reserved */
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_add_flags_reserved1, u8AddFlags);
    /* Bit 4:  AddFlags.TACK */
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_add_flags_tack, u8AddFlags);
    /* Bit 5:  AddFlags.MoreFrag */
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_add_flags_morefrag, u8AddFlags);
    /* Bit 6: AddFlags.Notification */
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_add_flags_notification, u8AddFlags);
    /* Bit 7: AddFlags.Reserved */
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_add_flags_reserved2, u8AddFlags);
    u8WindowSize = *u8AddFlags & 0x03;
    u8Tack = (*u8AddFlags & 0x10);
    u8Tack = (u8Tack == 0x10) ? 1 : 0;

    proto_item_append_text(sub_item, ", Window Size: %u, Tack: %u  ",
        u8WindowSize, u8Tack);
    return offset;
}

/* dissect a PN-IO RTA RSI PDU (on top of PN-RT protocol) */
int
dissect_PNIO_RSI(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
    guint16     u16DestinationServiceAccessPoint;
    guint16     u16SourceServiceAccessPoint;
    guint8      u8PDUType;
    guint8      u8PDUVersion;
    guint8      u8AddFlags;
    guint8      u8MoreFrag;
    guint16     u16SendSeqNum;
    guint16     u16AckSeqNum;
    guint16     u16VarPartLen;
    int         start_offset = offset;

    proto_item *rta_item;
    proto_tree *rta_tree;

    proto_item *sub_item;
    proto_tree *sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PNIO-RSI");
    rta_item = proto_tree_add_protocol_format(tree, proto_pn_rsi, tvb, offset, tvb_captured_length(tvb),
        "PROFINET IO RSI");

    rta_tree = proto_item_add_subtree(rta_item, ett_pn_rsi_rta);

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
        hf_pn_rsi_dst_srv_access_point, &u16DestinationServiceAccessPoint);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
        hf_pn_rsi_src_srv_access_point, &u16SourceServiceAccessPoint);

    //col_append_fstr(pinfo->cinfo, COL_INFO, ", Src: 0x%x, Dst: 0x%x",
    //    u16SourceServiceAccessPoint, u16DestinationServiceAccessPoint);

    /* PDU type */
    sub_item = proto_tree_add_item(rta_tree, hf_pn_rsi_pdu_type, tvb, offset, 1, ENC_NA);
    sub_tree = proto_item_add_subtree(sub_item, ett_pn_rsi_pdu_type);

    /* PDU type type - version of RTA 2*/
    dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_pdu_type_type, &u8PDUType);
    u8PDUType &= 0x0F;

    /* PDU type version - version of RTA 2*/
    offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
        hf_pn_rsi_pdu_type_version, &u8PDUVersion);
    u8PDUVersion >>= 4;
    //proto_item_append_text(sub_item, ", Type: %s, Version: %u",
    //    val_to_str(u8PDUType, pn_rsi_pdu_type_type, "Unknown"),
    //    u8PDUVersion);
    offset = dissect_RSIAdditionalFlags(tvb, offset, pinfo, rta_tree, drep, &u8AddFlags);
    u8MoreFrag = (u8AddFlags >> 5) & 0x1;
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
        hf_pn_rsi_send_seq_num, &u16SendSeqNum);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
        hf_pn_rsi_ack_seq_num, &u16AckSeqNum);
    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, rta_tree, drep,
        hf_pn_rsi_var_part_len, &u16VarPartLen);

    switch (u8PDUType & 0x0F) {
    case(3):    /* ACK-RTA */
        col_append_str(pinfo->cinfo, COL_INFO, "ACK-RTA");

        if (u8AddFlags & 0x40) {

            col_append_str(pinfo->cinfo, COL_INFO, ", Application Ready Notification");
        }
        /* no additional data */
        break;
    case(4):    /* ERR-RTA */
        col_append_str(pinfo->cinfo, COL_INFO, "ERR-RTA");
        offset = dissect_PNIO_status(tvb, offset, pinfo, rta_tree, drep);
        break;
    case(5):    /* FREQ-RTA */
        offset = dissect_FREQ_RTA_block(tvb, offset, pinfo, rta_tree, drep, u16VarPartLen, u8MoreFrag);
        break;
    case(6):    /* FRSP-RTA */
        offset = dissect_FRSP_RTA_block(tvb, offset, pinfo, rta_tree, drep, u16VarPartLen, u8MoreFrag);
        break;
    default:
        offset = dissect_pn_undecoded(tvb, offset, pinfo, tree, tvb_captured_length(tvb));
        break;
    }

    proto_item_set_len(rta_item, offset - start_offset);

    return offset;
}

int
dissect_PDRsiInstances_block(tvbuff_t *tvb, int offset,
    packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint8 *drep, guint8 u8BlockVersionHigh, guint8 u8BlockVersionLow)
{
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint16    u16NumberOfEntries;
    guint16    u16VendorId;
    guint16    u16DeviceId;
    guint16    u16InstanceId;
    guint8     u8RsiInterface;
    const int  deviceType_size       = 25;
    const int  orderID_size          = 20;
    const int  IMserialnumber_size   = 16;
    const int  HWrevision_size       = 5;
    const int  SWrevisionprefix_size = 1;
    const int  SWrevision_size       = 9;
    char      *deviceType;
    char      *orderID;
    char      *IMserialnumber;
    char      *HWrevision;
    char      *SWrevisionprefix;
    char      *SWrevision;

    if (u8BlockVersionHigh != 1 || u8BlockVersionLow != 0) {
        expert_add_info_format(pinfo, item, &ei_pn_rsi_error,
            "Block version %u.%u not implemented yet!", u8BlockVersionHigh, u8BlockVersionLow);
        return offset;
    }

    offset = dissect_dcerpc_uint16(tvb, offset, pinfo, tree, drep, 
        hf_pn_rsi_number_of_entries, &u16NumberOfEntries);

    proto_item_append_text(item, ": NumberOfEntries:%u", u16NumberOfEntries);

    while (u16NumberOfEntries > 0) {
        u16NumberOfEntries--;

        sub_item = proto_tree_add_item(tree, hf_pn_rsi_pd_rsi_instance, tvb, offset, 0, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn_io_pd_rsi_instance);
        /* VendorID */
        /* DeviceID */
        /* InstanceID */
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_vendor_id, &u16VendorId);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_device_id, &u16DeviceId);
        offset = dissect_dcerpc_uint16(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_instance_id, &u16InstanceId);

        /* RSI Interface */
        offset = dissect_dcerpc_uint8(tvb, offset, pinfo, sub_tree, drep,
            hf_pn_rsi_interface, &u8RsiInterface);

        proto_item_append_text(sub_item, ": VendorID:%u, DeviceID:%u, InstanceID:%u, RsiInterface:%u",
            u16VendorId, u16DeviceId, u16InstanceId, u8RsiInterface);

        /* Padding */
        offset = dissect_pn_padding(tvb, offset, pinfo, sub_tree, 1);
    }

    /* SystemIdentification */
    /* DeviceType */
    deviceType = (char *)wmem_alloc(pinfo->pool, deviceType_size + 1);
    tvb_memcpy(tvb, (guint8 *)deviceType, offset, 25);
    deviceType[deviceType_size] = '\0';
    proto_tree_add_string(tree, hf_pn_rsi_device_type, tvb, offset, deviceType_size, deviceType);
    offset += deviceType_size + 1;

    /* Blank */

    /* OrderID */
    orderID = (char *)wmem_alloc(pinfo->pool, orderID_size + 1);
    tvb_memcpy(tvb, (guint8 *)orderID, offset, 20);
    orderID[orderID_size] = '\0';
    proto_tree_add_string(tree, hf_pn_rsi_order_id, tvb, offset, orderID_size, orderID);
    offset += orderID_size + 1;

    /* Blank */

    /* IM_Serial_Number */
    IMserialnumber = (char *)wmem_alloc(pinfo->pool, IMserialnumber_size + 1);
    tvb_memcpy(tvb, (guint8 *)IMserialnumber, offset, 16);
    IMserialnumber[IMserialnumber_size] = '\0';
    proto_tree_add_string(tree, hf_pn_rsi_im_serial_number, tvb, offset, IMserialnumber_size, IMserialnumber);
    offset += IMserialnumber_size + 1;

    /* Blank */

    /* HWRevision */
    HWrevision = (char *)wmem_alloc(pinfo->pool, HWrevision_size + 1);
    tvb_memcpy(tvb, (guint8 *)HWrevision, offset, 5);
    HWrevision[HWrevision_size] = '\0';
    proto_tree_add_string(tree, hf_pn_rsi_hw_revision, tvb, offset, HWrevision_size, HWrevision);
    offset += HWrevision_size + 1;

    /* Blank */

    /* SWRevisionPrefix */
    SWrevisionprefix = (char *)wmem_alloc(pinfo->pool, SWrevisionprefix_size + 1);
    tvb_memcpy(tvb, (guint8 *)SWrevisionprefix, offset, 1);
    SWrevisionprefix[SWrevisionprefix_size] = '\0';
    proto_tree_add_string(tree, hf_pn_rsi_sw_revision_prefix, tvb, offset, SWrevisionprefix_size, SWrevisionprefix);
    offset += SWrevisionprefix_size;

    /* SWRevision */
    SWrevision = (char *)wmem_alloc(pinfo->pool, SWrevision_size + 1);
    tvb_memcpy(tvb, (guint8 *)SWrevision, offset, 9);
    SWrevision[SWrevision_size] = '\0';
    proto_tree_add_string(tree, hf_pn_rsi_sw_revision, tvb, offset, SWrevision_size, SWrevision);
    offset += SWrevision_size;
    return offset;
}

void
init_pn_rsi(int proto)
{
    static hf_register_info hf[] = {
        { &hf_pn_rsi_dst_srv_access_point,
        { "DestinationServiceAccessPoint", "pn_rsi.dst_srv_access_point",
        FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_alarm_endpoint), 0x0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_src_srv_access_point,
        { "SourceServiceAccessPoint", "pn_rsi.src_srv_access_point",
        FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_alarm_endpoint), 0x0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_pdu_type,
        { "PDUType", "pn_rsi.pdu_type",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_pdu_type_type,
        { "Type", "pn_rsi.pdu_type.type",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_pdu_type_type), 0x0F,
        NULL, HFILL }
        },
        { &hf_pn_rsi_pdu_type_version,
        { "Version", "pn_rsi.pdu_type.version",
        FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_pdu_type_version), 0xF0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_add_flags,
        { "AddFlags", "pn_rsi.add_flags",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_add_flags_windowsize,
        { "WindowSize", "pn_rsi.add_flags_windowsize",
        FT_UINT8, BASE_HEX, VALS(pn_rsi_add_flags_windowsize), 0x07,
        NULL, HFILL }
        },
        { &hf_pn_rsi_add_flags_reserved1,
        { "Reserved", "pn_rsi.add_flags_reserved",
        FT_UINT8, BASE_HEX, NULL, 0x08,
        NULL, HFILL }
        },
        { &hf_pn_rsi_add_flags_tack,
        { "TACK", "pn_rsi.add_flags_tack",
        FT_UINT8, BASE_HEX, VALS(pn_rsi_add_flags_tack), 0x10,
        NULL, HFILL }
        },
        { &hf_pn_rsi_add_flags_morefrag,
        { "MoreFrag", "pn_rsi.add_flags_morefrag",
        FT_UINT8, BASE_HEX, VALS(pn_rsi_add_flags_morefrag), 0x20,
        NULL, HFILL }
        },
        { &hf_pn_rsi_add_flags_notification,
        { "Notification", "pn_rsi.add_flags_notification",
        FT_UINT8, BASE_HEX, VALS(pn_rsi_add_flags_notification), 0x40,
        NULL, HFILL }
        },
        { &hf_pn_rsi_add_flags_reserved2,
        { "Reserved", "pn_rsi.add_flags_reserved",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL }
        },
        { &hf_pn_rsi_send_seq_num,
        { "SendSeqNum", "pn_rsi.send_seq_num",
        FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_seq_num), 0x0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_ack_seq_num,
        { "AckSeqNum", "pn_rsi.ack_seq_num",
        FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_seq_num), 0x0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_var_part_len,
        { "VarPartLen", "pn_rsi.var_part_len",
        FT_UINT16, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_var_part_len), 0x0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_f_opnum_offset,
        { "FOpnumOffset", "pn_rsi.f_opnum_offset",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_f_opnum_offset_offset,
        { "FOpnumOffset.Offset", "pn_rsi.f_opnum_offset.offset",
        FT_UINT32, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_f_opnum_offset_offset), 0x00FFFFFF,
        NULL, HFILL }
        },
        { &hf_pn_rsi_f_opnum_offset_opnum,
        { "FOpnumOffset.Opnum", "pn_rsi.f_opnum_offset.opnum",
        FT_UINT32, BASE_HEX, VALS(pn_rsi_f_opnum_offset_opnum), 0x1F000000,
        NULL, HFILL }
        },
        { &hf_pn_rsi_f_opnum_offset_callsequence,
        { "FOpnumOffset.CallSequence", "pn_rsi.f_opnum_offset.callsequence",
        FT_UINT32, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_f_opnum_offset_callsequence), 0xE0000000,
        NULL, HFILL }
        },
        { &hf_pn_rsi_conn_block,
        { "RSI CONN Block", "pn_rsi.conn_block",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pn_rsi_rsp_max_length,
        { "RspMaxLength", "pn_rsi.rsp_max_length",
            FT_UINT32, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_rsp_max_length), 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_vendor_id,
        { "VendorID", "pn_rsi.vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_device_id,
        { "DeviceID", "pn_rsi.device_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_instance_id,
        { "InstanceID", "pn_rsi.instance_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_interface,
        { "RsiInterface", "pn_rsi.interface",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(pn_rsi_interface), 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_svcs_block,
        { "RSI SVCS Block", "pn_rsi.svcs_block",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_number_of_entries,
          { "NumberOfEntries", "pn_rsi.number_of_entries",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_pd_rsi_instance,
          { "PDRsiInstance", "pn_rsi.pd_rsi_instance",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_device_type,
          { "DeviceType", "pn_rsi.device_type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_order_id,
          { "OrderID", "pn_rsi.order_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_im_serial_number,
          { "IM_Serial_Number", "pn_rsi.im_serial_number",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_hw_revision,
          { "HWRevision", "pn_rsi.hw_revision",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_sw_revision_prefix,
          { "SWRevisionPrefix", "pn_rsi.sw_revision_prefix",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_sw_revision,
          { "SWRevision", "pn_rsi.sw_revision",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
            /*&hf_pn_rsi_segment_too_long_segment,
            &hf_pn_rsi_segment_error,
            &hf_pn_rsi_segment_count,
            &hf_pn_rsi_reassembled_in,
            &hf_pn_rsi_reassembled_length,*/
        { &hf_pn_rsi_segment,
          { "RSI Segment", "pn_rsi.segment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_segments,
          { "PN RSI Segments", "pn_rsi.segments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_segment_overlap,
          { "Segment overlap", "pn_rsi.segment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment overlaps with other segments", HFILL }
        },
        { &hf_pn_rsi_segment_overlap_conflict,
          { "Conflicting data in segment overlap", "pn_rsi.segment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping segments contained conflicting data", HFILL }
        },
        { &hf_pn_rsi_segment_multiple_tails,
          { "Multiple tail segments found", "pn_rsi.segment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when reassembling the packet", HFILL }
        },
        { &hf_pn_rsi_segment_too_long_segment,
          { "Segment too long", "pn_rsi.segment.toolongsegment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Segment contained data past end of packet", HFILL }
        },
        { &hf_pn_rsi_segment_error,
          { "Reassembly error", "pn_rsi.segment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Reassembly error due to illegal segments", HFILL }
        },
        { &hf_pn_rsi_segment_count,
          { "Segment count", "pn_rsi.segment.count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pn_rsi_reassembled_in,
          { "Reassembled pn_rsi in frame", "pn_rsi.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This pn_rsi packet is reassembled in this frame", HFILL }
        },
        { &hf_pn_rsi_reassembled_length,
          { "Reassembled pn_rsi length", "pn_rsi.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }
        },
        { &hf_pn_rsi_data_payload,
          { "PN IO RSI Data Payload", "pn_rsi.data_payload",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_pn_rsi,
        &ett_pn_rsi_pdu_type,
        &ett_pn_rsi_f_opnum_offset,
        &ett_pn_rsi_conn_block,
        &ett_pn_rsi_svcs_block,
        &ett_pn_rsi_add_flags,
        &ett_pn_rsi_rta,
        &ett_pn_io_pd_rsi_instance,
        &ett_pn_rsi_segments,
        &ett_pn_rsi_segment,
        &ett_pn_rsi_data_payload
    };

    static ei_register_info ei[] = {
        { &ei_pn_rsi_error, { "pn_rsi.ack_seq_num", PI_UNDECODED, PI_NOTE, "Block version not implemented yet!", EXPFILL } }

    };

    expert_module_t* expert_pn_rsi;

    proto_pn_rsi = proto;

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pn_rsi = expert_register_protocol(proto_pn_rsi);
    expert_register_field_array(expert_pn_rsi, ei, array_length(ei));

    register_init_routine(pn_rsi_reassemble_init);
}
