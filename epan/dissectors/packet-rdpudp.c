/* packet-rdpudp.c
 * Routines for UDP RDP packet dissection
 * Copyright 2021, David Fort
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
#include <epan/conversation.h>

#include "packet-rdp.h"
#include "packet-rdpudp.h"

#define PNAME  "UDP Remote Desktop Protocol"
#define PSNAME "RDPUDP"
#define PFNAME "rdpudp"

void proto_register_rdpudp(void);
void proto_reg_handoff_rdpudp(void);

static dissector_handle_t rdpudp_handle;
int proto_rdpudp = -1;

static int ett_rdpudp = -1;
static int ett_rdpudp_flags = -1;
static int ett_rdpudp_synex = -1;
static int ett_rdpudp_ack = -1;
static int ett_rdpudp_fec = -1;
static int ett_rdpudp_data = -1;
static int ett_rdpudp2_packetType = -1;
static int ett_rdpudp2_flags = -1;
static int ett_rdpudp2_ack = -1;
static int ett_rdpudp2_overhead = -1;
static int ett_rdpudp2_delayack = -1;
static int ett_rdpudp2_aoa = -1;
static int ett_rdpudp2_data = -1;
static int ett_rdpudp2_ackvec = -1;
static int ett_rdpudp2_ackvec_vecs = -1;
static int ett_rdpudp2_ackvec_vec = -1;


static int pf_rdpudp_snSourceAck = -1;
static int pf_rdpudp_ReceiveWindowSize = -1;
static int pf_rdpudp_flags = -1;
static int pf_rdpudp_flag_syn = -1;
static int pf_rdpudp_flag_fin = -1;
static int pf_rdpudp_flag_ack = -1;
static int pf_rdpudp_flag_data = -1;
static int pf_rdpudp_flag_fec = -1;
static int pf_rdpudp_flag_cn = -1;
static int pf_rdpudp_flag_cwr = -1;
static int pf_rdpudp_flag_aoa = -1;
static int pf_rdpudp_flag_synlossy = -1;
static int pf_rdpudp_flag_ackdelayed = -1;
static int pf_rdpudp_flag_correlationId = -1;
static int pf_rdpudp_flag_synex = -1;
static int pf_rdpudp_snInitialSequenceNumber = -1;
static int pf_rdpudp_upstreamMtu = -1;
static int pf_rdpudp_downstreamMtu = -1;
static int pf_rdpudp_correlationId = -1;
static int pf_rdpudp_synex_flags = -1;
static int pf_rdpudp_synex_flag_version = -1;
static int pf_rdpudp_synex_version = -1;
static int pf_rdpudp_synex_cookiehash = -1;
static int pf_rdpudp_ack_vectorsize = -1;
static int pf_rdpudp_ack_item = -1;
static int pf_rdpudp_ack_item_state = -1;
static int pf_rdpudp_ack_item_rle = -1;
static int pf_rdpudp_fec_coded = -1;
static int pf_rdpudp_fec_sourcestart = -1;
static int pf_rdpudp_fec_range = -1;
static int pf_rdpudp_fec_fecindex = -1;
static int pf_rdpudp_resetseqenum = -1;
static int pf_rdpudp_source_sncoded = -1;
static int pf_rdpudp_source_snSourceStart = -1;
static int pf_rdpudp_data = -1;

static int * const rdpudp_flags[] = {
		&pf_rdpudp_flag_syn,
		&pf_rdpudp_flag_fin,
		&pf_rdpudp_flag_ack,
		&pf_rdpudp_flag_data,
		&pf_rdpudp_flag_fec,
		&pf_rdpudp_flag_cn,
		&pf_rdpudp_flag_cwr,
		&pf_rdpudp_flag_aoa,
		&pf_rdpudp_flag_synlossy,
		&pf_rdpudp_flag_ackdelayed,
		&pf_rdpudp_flag_correlationId,
		&pf_rdpudp_flag_synex,
		NULL
};

static int pf_rdpudp2_PacketPrefixByte = -1;
static int pf_rdpudp2_packetType = -1;
static int pf_rdpudp2_shortPacketLength = -1;
static int pf_rdpudp2_flags = -1;
static int pf_rdpudp2_flag_ack = -1;
static int pf_rdpudp2_flag_data = -1;
static int pf_rdpudp2_flag_ackvec = -1;
static int pf_rdpudp2_flag_aoa = -1;
static int pf_rdpudp2_flag_overhead = -1;
static int pf_rdpudp2_flag_delayackinfo = -1;
static int pf_rdpudp2_logWindow = -1;
static int pf_rdpudp2_AckSeq = -1;
static int pf_rdpudp2_AckTs = -1;
static int pf_rdpudp2_AckSendTimeGap = -1;
static int pf_rdpudp2_ndelayedAcks = -1;
static int pf_rdpudp2_delayedTimeScale = -1;
static int pf_rdpudp2_delayedAcks = -1;
static int pf_rdpudp2_delayedAck = -1;
static int pf_rdpudp2_OverHeadSize = -1;
static int pf_rdpudp2_DelayAckMax = -1;
static int pf_rdpudp2_DelayAckTimeout = -1;
static int pf_rdpudp2_AckOfAcksSeqNum = -1;
static int pf_rdpudp2_DataSeqNumber = -1;
static int pf_rdpudp2_DataChannelSeqNumber = -1;
static int pf_rdpudp2_Data = -1;
static int pf_rdpudp2_AckvecBaseSeq = -1;
static int pf_rdpudp2_AckvecCodecAckVecSize = -1;
static int pf_rdpudp2_AckvecHaveTs = -1;
static int pf_rdpudp2_AckvecTimeStamp = -1;
static int pf_rdpudp2_SendAckTimeGapInMs = -1;
static int pf_rdpudp2_AckvecCodedAck = -1;
static int pf_rdpudp2_AckvecCodedAckMode = -1;
static int pf_rdpudp2_AckvecCodedAckRleState = -1;
static int pf_rdpudp2_AckvecCodedAckRleLen = -1;

static int * const rdpudp2_flags[] = {
	&pf_rdpudp2_flag_ack,
	&pf_rdpudp2_flag_data,
	&pf_rdpudp2_flag_ackvec,
	&pf_rdpudp2_flag_aoa,
	&pf_rdpudp2_flag_overhead,
	&pf_rdpudp2_flag_delayackinfo,
	&pf_rdpudp2_logWindow,
	NULL
};

static dissector_handle_t tls_handle;
static dissector_handle_t dtls_handle;

enum {
	RDPUDP_SYN = 0x0001,
	RDPUDP_FIN = 0x0002,
	RDPUDP_ACK = 0x0004,
	RDPUDP_DATA = 0x0008,
	RDPUDP_FEC = 0x0010,
	RDPUDP_CN = 0x0020,
	RDPUDP_CWR = 0x0040,
	RDPUDP_AOA = 0x0100,
	RDPUDP_SYNLOSSY = 0x0200,
	RDPUDP_ACKDELAYED = 0x0400,
	RDPUDP_CORRELATIONID = 0x0800,
	RDPUDP_SYNEX = 0x1000
};

#define RDPUDP_VERSION_INFO_VALID 0x0001

enum {
	RDPUDP2_ACK = 0x0001,
	RDPUDP2_DATA = 0x0004,
	RDPUDP2_ACKVEC = 0x0008,
	RDPUDP2_AOA = 0x0010,
	RDPUDP2_OVERHEAD = 0x0040,
	RDPUDP2_DELAYACK = 0x00100
};

static const value_string rdpudp_version_vals[] = {
	{ 0x0001, "UDPv1-1" },
	{ 0x0002, "UDPv1-2" },
	{ 0x0101, "UDPv2" },
	{ 0x0, NULL}
};

static const value_string rdpudp_ack_states_vals[] = {
	{ 0, "Received" },
	{ 1, "Reserved 1" },
	{ 2, "Reserved 2" },
	{ 3, "Pending" },
	{ 0x0, NULL }
};

static const value_string rdpudp2_packetType_vals[] = {
	{ 0, "Data" },
	{ 8, "Dummy"},
	{ 0x0, NULL }
};

static const value_string rdpudp2_ackvec_mode_vals[] = {
	{ 0x00, "Bitmap"},
	{ 0x01, "Run length"},
	{ 0x00, NULL }
};

static const value_string rdpudp2_ackvec_rlestates_vals[] = {
	{ 0x00, "lost" },
	{ 0x01, "received" },
	{ 0x0, NULL }
};

gboolean
rdp_isServerAddressTarget(packet_info *pinfo)
{
	conversation_t *conv;
	rdp_conv_info_t *rdp_info;
	rdpudp_conv_info_t *rdpudp_info;

	conv = find_conversation_pinfo(pinfo, 0);
	if (!conv)
		return FALSE;

	rdp_info = (rdp_conv_info_t *)conversation_get_proto_data(conv, proto_rdp);
	if (rdp_info) {
		rdp_server_address_t *server = &rdp_info->serverAddr;
		return addresses_equal(&server->addr, &pinfo->dst) && (pinfo->destport == server->port);
	}

	rdpudp_info = (rdpudp_conv_info_t *)conversation_get_proto_data(conv, proto_rdpudp);
	if (!rdpudp_info)
		return FALSE;

	return addresses_equal(&rdpudp_info->server_addr, &pinfo->dst) && (rdpudp_info->server_port == pinfo->destport);
}

gboolean
rdpudp_is_reliable_transport(packet_info *pinfo)
{
	conversation_t *conv;
	rdpudp_conv_info_t *rdpudp_info;

	conv = find_conversation_pinfo(pinfo, 0);
	if (!conv)
		return FALSE;

	rdpudp_info = (rdpudp_conv_info_t *)conversation_get_proto_data(conv, proto_rdpudp);
	if (!rdpudp_info)
		return FALSE;

	return !rdpudp_info->is_lossy;
}

static int
dissect_rdpudp_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, rdpudp_conv_info_t *conv)
{
	gint offset = 0;
	guint16 flags;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDPUDP");
	col_clear(pinfo->cinfo, COL_INFO);

	proto_tree_add_item(tree, pf_rdpudp_snSourceAck, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, pf_rdpudp_ReceiveWindowSize, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, pf_rdpudp_flags, ett_rdpudp_flags, rdpudp_flags, ENC_BIG_ENDIAN);
	flags = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
	offset += 2;

	if (flags & RDPUDP_SYN) {
		conv->is_lossy = (flags & RDPUDP_SYNLOSSY);
		if (!(flags & RDPUDP_ACK)) {
			/* set the server address only on the first SYN packet */
			copy_address_wmem(wmem_file_scope(), &conv->server_addr, &pinfo->dst);
			conv->server_port = pinfo->destport;
		}
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "SYN");
	}

	if (flags & RDPUDP_SYN) {
		proto_tree_add_item(tree, pf_rdpudp_snInitialSequenceNumber, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, pf_rdpudp_upstreamMtu, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, pf_rdpudp_downstreamMtu, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (flags & RDPUDP_CORRELATIONID) {
		proto_tree_add_item(tree, pf_rdpudp_correlationId, tvb, offset, 16, ENC_NA);
		offset += 32;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "CORRELATIONID");
	}

	if (flags & RDPUDP_SYNEX) {
		guint16 synex_flags;
		proto_tree *synex_tree;
		guint synex_sz = 2;
		guint16 version_val;

		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "SYNEX");

		synex_flags = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
		if (synex_flags & RDPUDP_VERSION_INFO_VALID) {
			synex_sz += 2; /* version */

			version_val = tvb_get_guint16(tvb, offset+2, ENC_BIG_ENDIAN);

			if (version_val == 0x101)
				synex_sz += 32; /* cookie hash */
		}

		synex_tree = proto_tree_add_subtree(tree, tvb, offset, synex_sz, ett_rdpudp_synex, NULL, "SynEx");
		proto_tree_add_item(synex_tree, pf_rdpudp_synex_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(synex_tree, pf_rdpudp_synex_flag_version, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset += 2;

		if (synex_flags & RDPUDP_VERSION_INFO_VALID) {
			proto_tree_add_item(synex_tree, pf_rdpudp_synex_version, tvb, offset, 2, ENC_BIG_ENDIAN);

			offset += 2;
			if (version_val == 0x101) {
				proto_tree_add_item(synex_tree, pf_rdpudp_synex_cookiehash, tvb, offset, 32, ENC_NA);
				offset += 32;

				if (flags & RDPUDP_ACK)
					conv->start_v2_at = pinfo->num + 1;
			}
		}
	}

	if ((flags & RDPUDP_ACK) && !(flags & RDPUDP_SYN)) {
		proto_tree *ack_tree;
		guint16 uAckVectorSize = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);

		ack_tree = proto_tree_add_subtree(tree, tvb, offset, 2 + uAckVectorSize, ett_rdpudp_ack, NULL, "Ack");
		offset += 2;
		for ( ; uAckVectorSize; uAckVectorSize--, offset++) {
			proto_tree_add_item(ack_tree, pf_rdpudp_ack_item, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(ack_tree, pf_rdpudp_ack_item_rle, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "ACK");
	}

	if (flags & RDPUDP_FEC) {
		proto_tree *fec_tree = proto_tree_add_subtree(tree, tvb, offset, 4 * 3, ett_rdpudp_fec, NULL, "FEC");

		proto_tree_add_item(fec_tree, pf_rdpudp_fec_coded, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(fec_tree, pf_rdpudp_fec_sourcestart, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(fec_tree, pf_rdpudp_fec_range, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(fec_tree, pf_rdpudp_fec_fecindex, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FEC");
	}

	if (flags & RDPUDP_AOA) {
		proto_tree_add_item(tree, pf_rdpudp_resetseqenum, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "AOA");
	}

	if (flags & RDPUDP_DATA)
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "DATA");

	if (flags & RDPUDP_DATA) {
		proto_tree *data_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rdpudp_data, NULL, "Data");
		dissector_handle_t target_dissector;

		proto_tree_add_item(data_tree, pf_rdpudp_source_sncoded, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(data_tree, pf_rdpudp_source_snSourceStart, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		target_dissector = conv->is_lossy ? dtls_handle : tls_handle;

		call_dissector(target_dissector, tvb_new_subset_remaining(tvb, offset), pinfo, data_tree);

		offset = tvb_reported_length(tvb);
	}

	return offset;
}

static tvbuff_t *
unwrap_udp_v2(tvbuff_t *tvb, packet_info *pinfo)
{
	gint len = tvb_captured_length_remaining(tvb, 0);
	guchar *buffer = (guchar*)wmem_alloc(pinfo->pool, len);

	/* copy and do the swap of byte 0 and 7*/
	tvb_memcpy(tvb, buffer, 0, len);
	buffer[0] = tvb_get_guint8(tvb, 7);
	buffer[7] = tvb_get_guint8(tvb, 0);

	return tvb_new_child_real_data(tvb, buffer, len, len);
}

static int
dissect_rdpudp_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree, *data_tree = NULL;
	guint16 flags;
	guint8 packet_type;
	tvbuff_t *subtvb;
	gint offset = 0;
	tvbuff_t *tvb2 = unwrap_udp_v2(tvb, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDPUDP2");
	col_clear(pinfo->cinfo, COL_INFO);

	add_new_data_source(pinfo, tvb2, "Unwrapped RDPUDP2 packet");

	packet_type = (tvb_get_guint8(tvb2, 0) >> 1) & 0xf;
	item = proto_tree_add_item(tree, pf_rdpudp2_PacketPrefixByte, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
	subtree = proto_item_add_subtree(item, ett_rdpudp2_packetType);
	proto_tree_add_item(subtree, pf_rdpudp2_packetType, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(subtree, pf_rdpudp2_shortPacketLength, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	proto_tree_add_bitmask(tree, tvb2, offset, pf_rdpudp2_flags, ett_rdpudp2_flags, rdpudp2_flags, ENC_LITTLE_ENDIAN);

	flags = tvb_get_guint16(tvb2, offset, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (flags & RDPUDP2_ACK) {
		guint8 nacks = tvb_get_guint8(tvb, offset + 6) & 0xf;
		subtree = proto_tree_add_subtree(tree, tvb2, offset, 7 + nacks, ett_rdpudp2_ack, NULL, "Ack");
		proto_tree_add_item(subtree, pf_rdpudp2_AckSeq, tvb2, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
		proto_tree_add_item(subtree, pf_rdpudp2_AckTs, tvb2, offset, 3, ENC_LITTLE_ENDIAN); offset += 3;
		proto_tree_add_item(subtree, pf_rdpudp2_AckSendTimeGap, tvb2, offset, 1, ENC_LITTLE_ENDIAN); offset++;

		proto_tree_add_item(subtree, pf_rdpudp2_ndelayedAcks, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(subtree, pf_rdpudp2_delayedTimeScale, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		offset += nacks;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "ACK");
	}

	if (flags & RDPUDP2_OVERHEAD) {
		subtree = proto_tree_add_subtree(tree, tvb2, offset, 1, ett_rdpudp2_overhead, NULL, "Overhead");
		proto_tree_add_item(subtree, pf_rdpudp2_OverHeadSize, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "OVERHEAD");
	}


	if (flags & RDPUDP2_DELAYACK) {
		subtree = proto_tree_add_subtree(tree, tvb2, offset, 3, ett_rdpudp2_delayack, NULL, "DelayAck");
		proto_tree_add_item(subtree, pf_rdpudp2_DelayAckMax, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;
		proto_tree_add_item(subtree, pf_rdpudp2_DelayAckTimeout, tvb2, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "DELAYACK");
	}

	if (flags & RDPUDP2_AOA) {
		subtree = proto_tree_add_subtree(tree, tvb2, offset, 1, ett_rdpudp2_aoa, NULL, "Ack of Acks");
		proto_tree_add_item(subtree, pf_rdpudp2_AckOfAcksSeqNum, tvb2, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "AOA");
	}

	if (flags & RDPUDP2_DATA) {
		gboolean isDummy = !!(packet_type == 0x8);
		data_tree = proto_tree_add_subtree(tree, tvb2, offset, 1, ett_rdpudp2_data, NULL, isDummy ? "Dummy data" : "Data");
		proto_tree_add_item(data_tree, pf_rdpudp2_DataSeqNumber, tvb2, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", isDummy ? "DUMMY" : "DATA");
	}

	if (flags & RDPUDP2_ACKVEC) {
		proto_tree *acks_tree;
		guint8 i;
		guint32 base_seq;
		gint ackvecSz = 3;
		guint8 codedAckVecSizeA = tvb_get_guint8(tvb2, offset + 2);
		guint8 codedAckVecSize = codedAckVecSizeA & 0x7f;
		gboolean haveTs = !!(codedAckVecSizeA & 0x80);

		ackvecSz += codedAckVecSize;
		if (haveTs)
			ackvecSz += 3;

		subtree = proto_tree_add_subtree(tree, tvb2, offset, ackvecSz, ett_rdpudp2_ackvec, NULL, "AckVec");
		proto_tree_add_item_ret_uint(subtree, pf_rdpudp2_AckvecBaseSeq, tvb2, offset, 2, ENC_LITTLE_ENDIAN, &base_seq);
		offset += 2;

		proto_tree_add_item(subtree, pf_rdpudp2_AckvecCodecAckVecSize, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(subtree, pf_rdpudp2_AckvecHaveTs, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		if (haveTs) {
			proto_tree_add_item(subtree, pf_rdpudp2_AckvecTimeStamp, tvb2, offset, 3, ENC_LITTLE_ENDIAN);
			offset += 3;

			proto_tree_add_item(subtree, pf_rdpudp2_SendAckTimeGapInMs, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
		}

		acks_tree = proto_tree_add_subtree(subtree, tvb2, offset, codedAckVecSize, ett_rdpudp2_ackvec_vecs, NULL, "Acks");
		for (i = 0; i < codedAckVecSize; i++) {
			proto_tree *ack_tree;

			guint8 b = tvb_get_guint8(tvb2, offset + i);

			if (b & 0x80) {
				/* run length mode */
				guint8 rle_len = (b & 0x3f);
				ack_tree = proto_tree_add_subtree_format(acks_tree, tvb2, offset + i, 1, ett_rdpudp2_ackvec_vec, NULL,
						"RLE %s %04x -> %04x", (b & 0x40) ? "received" : "lost",
						base_seq, base_seq + rle_len);

				base_seq += rle_len;
			} else {
				/* bitmap mode */
				ack_tree = proto_tree_add_subtree_format(acks_tree, tvb2, offset + i, 1, ett_rdpudp2_ackvec_vec, NULL,
						"bitmap %s%04x %s%04x %s%04x %s%04x %s%04x %s%04x %s%04x",
						(b & 0x01) ? "" : "!", base_seq,
						(b & 0x02) ? "" : "!", base_seq + 1,
						(b & 0x04) ? "" : "!", base_seq + 2,
						(b & 0x08) ? "" : "!", base_seq + 3,
						(b & 0x10) ? "" : "!", base_seq + 4,
						(b & 0x20) ? "" : "!", base_seq + 5,
						(b & 0x40) ? "" : "!", base_seq + 6
				);
				base_seq += 7;
			}

			proto_tree_add_item(ack_tree, pf_rdpudp2_AckvecCodedAckMode, tvb2, offset + i, 1, ENC_LITTLE_ENDIAN);
			if (b & 0x80) {
				proto_tree_add_item(ack_tree, pf_rdpudp2_AckvecCodedAckRleState, tvb2, offset + i, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ack_tree, pf_rdpudp2_AckvecCodedAckRleLen, tvb2, offset + i, 1, ENC_LITTLE_ENDIAN);
			}
		}

		offset += codedAckVecSize;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "ACKVEC");
	}

	if ((flags & RDPUDP2_DATA) && (packet_type != 0x8)) {
		proto_tree_add_item(data_tree, pf_rdpudp2_DataChannelSeqNumber, tvb2, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		subtvb = tvb_new_subset_length(tvb2, offset, tvb_captured_length_remaining(tvb2, offset));
		add_new_data_source(pinfo, subtvb, "SSL fragment");
		call_dissector(tls_handle, subtvb, pinfo, data_tree);

		offset = tvb_captured_length(tvb2);
	}

	return offset;
}

static int
dissect_rdpudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item;
	proto_tree *tree;
	conversation_t  *conversation;
	rdpudp_conv_info_t *rdpudp_info;

	conversation = find_or_create_conversation(pinfo);

	rdpudp_info = (rdpudp_conv_info_t *)conversation_get_proto_data(conversation, proto_rdpudp);
	if (rdpudp_info == NULL) {
		rdpudp_info = wmem_new0(wmem_file_scope(), rdpudp_conv_info_t);
		rdpudp_info->start_v2_at = G_MAXUINT32;
		rdpudp_info->is_lossy = FALSE;

		conversation_add_proto_data(conversation, proto_rdpudp, rdpudp_info);
	}

	item = proto_tree_add_item(parent_tree, proto_rdpudp, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rdpudp);

	if (rdpudp_info->start_v2_at > pinfo->num)
		return dissect_rdpudp_v1(tvb, pinfo, tree, rdpudp_info);
	else
		return dissect_rdpudp_v2(tvb, pinfo, tree);
}

/*--- proto_register_rdpudp -------------------------------------------*/
void
proto_register_rdpudp(void) {
	/* List of fields */
	static hf_register_info hf[] = {
	  { &pf_rdpudp_snSourceAck,
		{"snSourceAck", "rdpudp.snsourceack", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL},
	  },
	  { &pf_rdpudp_ReceiveWindowSize,
		{"ReceiveWindowSize", "rdpudp.receivewindowsize", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_flags,
		{"Flags", "rdpudp.flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_syn,
		{"Syn", "rdpudp.flags.syn", FT_BOOLEAN, 16, NULL, RDPUDP_SYN, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_fin,
		{"Fin", "rdpudp.flags.fin", FT_BOOLEAN, 16, NULL, RDPUDP_FIN, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_ack,
		{"Ack", "rdpudp.flags.ack", FT_BOOLEAN, 16, NULL, RDPUDP_ACK, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_data,
		{"Data", "rdpudp.flags.data", FT_BOOLEAN, 16, NULL, RDPUDP_DATA, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_fec,
		{"FECData", "rdpudp.flags.fec", FT_BOOLEAN, 16, NULL, RDPUDP_FEC, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_cn,
		{"CN", "rdpudp.flags.cn", FT_BOOLEAN, 16, NULL, RDPUDP_CN, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_cwr,
		{"CWR", "rdpudp.flags.cwr", FT_BOOLEAN, 16, NULL, RDPUDP_CWR, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_aoa,
		{"Ack of Acks", "rdpudp.flags.aoa", FT_BOOLEAN, 16, NULL, RDPUDP_AOA, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_synlossy,
		{"Syn lossy", "rdpudp.flags.synlossy", FT_BOOLEAN, 16, NULL, RDPUDP_SYNLOSSY, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_ackdelayed,
		{"Ack delayed", "rdpudp.flags.ackdelayed", FT_BOOLEAN, 16, NULL, RDPUDP_ACKDELAYED, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_correlationId,
		{"Correlation id", "rdpudp.flags.correlationid", FT_BOOLEAN, 16, NULL, RDPUDP_CORRELATIONID, NULL, HFILL}
	  },
	  { &pf_rdpudp_flag_synex,
		{"SynEx","rdpudp.flags.synex",FT_BOOLEAN,16,NULL,RDPUDP_SYNEX,NULL,HFILL}
	  },
	  { &pf_rdpudp_snInitialSequenceNumber,
		{"Initial SequenceNumber","rdpudp.initialsequencenumber", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_upstreamMtu,
		{"Upstream MTU", "rdpudp.upstreammtu", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_downstreamMtu,
		{"DownStream MTU", "rdpudp.downstreammtu", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_correlationId,
		{"Correlation Id", "rdpudp.correlationid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_synex_flags,
		{"Flags", "rdpudp.synex.flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_synex_flag_version,
		{"Version info", "rdpudp.synex.flags.versioninfo", FT_BOOLEAN, 8, NULL, 0x0001, NULL, HFILL}
	  },
	  { &pf_rdpudp_synex_version,
		{"Version", "rdpudp.synex.version", FT_UINT16, BASE_HEX, VALS(rdpudp_version_vals), 0, NULL, HFILL}
	  },
	  {&pf_rdpudp_synex_cookiehash,
		{"Cookie Hash", "rdpudp.synex.cookiehash", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_ack_vectorsize,
		{"uAckVectorSize", "rdpudp.ack.vectorsize", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_ack_item,
		{"Ack item", "rdpudp.ack.item", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_ack_item_state,
		{"VECTOR_ELEMENT_STATE", "rdpudp.ack.item.state", FT_UINT8, BASE_HEX, VALS(rdpudp_ack_states_vals), 0xc0, NULL, HFILL}
	  },
	  { &pf_rdpudp_ack_item_rle,
		{"Run length", "rdpudp.ack.item.rle", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL}
	  },
	  { &pf_rdpudp_fec_coded,
		{"snCoded", "rdpudp.fec.coded", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_fec_sourcestart,
		{"snSourceStart", "rdpudp.fec.sourcestart", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_fec_range,
		{"Range", "rdpudp.fec.range", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_fec_fecindex,
		{"Fec index", "rdpudp.fec.fecindex", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_resetseqenum,
		{"snResetSeqNum", "rdpudp.resetSeqNum", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_source_sncoded,
		{"snCoded", "rdpudp.data.sncoded", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_source_snSourceStart,
		{"snSourceStart", "rdpudp.data.sourceStart", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp_data,
		{"Data", "rdpudp.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },


	  { &pf_rdpudp2_PacketPrefixByte,
		{"PacketPrefixByte", "rdpudp2.prefixbyte", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_packetType,
		{"PacketType", "rdpudp2.packetType", FT_UINT8, BASE_HEX, VALS(rdpudp2_packetType_vals), 0x1e, NULL, HFILL}
	  },
	  { &pf_rdpudp2_shortPacketLength,
		{"Short packet length", "rdpudp2.shortpacketlen", FT_UINT8, BASE_DEC, NULL, 0x7, NULL, HFILL}
	  },
	  { &pf_rdpudp2_flags,
		 {"Flags", "rdpudp2.flags", FT_UINT16, BASE_HEX, NULL, 0xfff, NULL, HFILL}
	  },
	  { &pf_rdpudp2_flag_ack,
		{"Ack", "rdpudp2.flags.ack", FT_UINT16, BASE_HEX, NULL, RDPUDP2_ACK, NULL, HFILL}
	  },
	  { &pf_rdpudp2_flag_data,
		{"Data", "rdpudp2.flags.data", FT_UINT16, BASE_HEX, NULL, RDPUDP2_DATA, NULL, HFILL}
	  },
	  { &pf_rdpudp2_flag_ackvec,
		{"AckVec", "rdpudp2.flags.ackvec", FT_UINT16, BASE_HEX, NULL, RDPUDP2_ACKVEC, NULL, HFILL}
	  },
	  { &pf_rdpudp2_flag_aoa,
		{"AckOfAcks", "rdpudp2.flags.ackofacks", FT_UINT16, BASE_HEX, NULL, RDPUDP2_AOA, NULL, HFILL}
	  },
	  { &pf_rdpudp2_flag_overhead,
		{"OverheadSize", "rdpudp2.flags.overheadsize", FT_UINT16, BASE_HEX, NULL, RDPUDP2_OVERHEAD, NULL, HFILL}
	  },
	  { &pf_rdpudp2_flag_delayackinfo,
		{"DelayedAckInfo", "rdpudp2.flags.delayackinfo", FT_UINT16, BASE_HEX, NULL, RDPUDP2_DELAYACK, NULL, HFILL}
	  },
	  { &pf_rdpudp2_logWindow,
		{"LogWindow", "rdpudp2.logWindow", FT_UINT16, BASE_DEC, NULL, 0xf000, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckSeq,
		{"Base Seq", "rdpudp2.ack.seqnum", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckTs,
		{"receivedTS", "rdpudp2.ack.ts", FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckSendTimeGap,
		{"sendTimeGap", "rdpudp2.ack.sendTimeGap", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_ndelayedAcks,
		{"NumDelayedAcks", "rdpudp2.ack.numDelayedAcks", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}
	  },
	  { &pf_rdpudp2_delayedTimeScale,
		{"delayedTimeScale", "rdpudp2.ack.delayedTimeScale", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_delayedAcks,
		{"Delayed acks", "rdpudp2.ack.delayedAcks", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_delayedAck,
		{"Delayed ack", "rdpudp2.ack.delayedAck", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_OverHeadSize,
		{"Overhead size", "rdpudp2.overheadsize", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_DelayAckMax,
		{"MaxDelayedAcks", "rdpudp2.delayackinfo.max", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_DelayAckTimeout,
		{"DelayedAckTimeoutInMs", "rdpudp2.delayackinfo.timeout", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckOfAcksSeqNum,
		{"Sequence number", "rdpudp2.ackofacksseqnum", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_DataSeqNumber,
		{"Sequence number", "rdpudp2.data.seqnum", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_DataChannelSeqNumber,
		{"Channel sequence number", "rdpudp2.data.channelseqnumber", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_Data,
		{"Data", "rdpudp2.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckvecBaseSeq,
		{"Base sequence number", "rdpudp2.ackvec.baseseqnum", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckvecCodecAckVecSize,
		{"Coded ackvec size","rdpudp2.ackvec.codedackvecsize", FT_UINT16, BASE_DEC, NULL, 0x7f, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckvecHaveTs,
		{"Have timestamp", "rdpudp2.ackvec.havets", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckvecTimeStamp,
		{"Timestamp", "rdpudp2.ackvec.timestamp", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_SendAckTimeGapInMs,
		{"SendAckTimeGap", "rdpudp2.ackvec.sendacktimegap", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckvecCodedAck,
		{"Coded Ack", "rdpudp2.ackvec.codedAck", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckvecCodedAckMode,
		{"Mode", "rdpudp2.ackvec.codecAckMode", FT_UINT8, BASE_HEX, VALS(rdpudp2_ackvec_mode_vals), 0x80, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckvecCodedAckRleState,
		{"State", "rdpudp2.ackvec.codecAckRleState", FT_UINT8, BASE_DEC, VALS(rdpudp2_ackvec_rlestates_vals), 0x40, NULL, HFILL}
	  },
	  { &pf_rdpudp2_AckvecCodedAckRleLen,
		{"Length", "rdpudp2.ackvec.codecAckRleLen", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL}
	  }
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_rdpudp,
		&ett_rdpudp_flags,
		&ett_rdpudp_synex,
		&ett_rdpudp_ack,
		&ett_rdpudp_fec,
		&ett_rdpudp_data,
		&ett_rdpudp2_packetType,
		&ett_rdpudp2_flags,
		&ett_rdpudp2_ack,
		&ett_rdpudp2_overhead,
		&ett_rdpudp2_delayack,
		&ett_rdpudp2_aoa,
		&ett_rdpudp2_data,
		&ett_rdpudp2_ackvec,
		&ett_rdpudp2_ackvec_vecs,
		&ett_rdpudp2_ackvec_vec,
	};

	/* Register protocol */
	proto_rdpudp = proto_register_protocol(PNAME, PSNAME, PFNAME);
	/* Register fields and subtrees */
	proto_register_field_array(proto_rdpudp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	rdpudp_handle = register_dissector("rdpudp", dissect_rdpudp, proto_rdpudp);
}

void
proto_reg_handoff_rdpudp(void)
{
	tls_handle = find_dissector("tls");
	dtls_handle = find_dissector("dtls");
	dissector_add_uint("udp.port", 3389, rdpudp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
