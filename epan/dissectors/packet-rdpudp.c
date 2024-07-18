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
#include <epan/proto_data.h>

#include "packet-rdp.h"
#include "packet-rdpudp.h"

#define PNAME  "UDP Remote Desktop Protocol"
#define PSNAME "RDPUDP"
#define PFNAME "rdpudp"

void proto_register_rdpudp(void);
void proto_reg_handoff_rdpudp(void);

static dissector_handle_t rdpudp_handle;
int proto_rdpudp;

static int ett_rdpudp;
static int ett_rdpudp_flags;
static int ett_rdpudp_synex;
static int ett_rdpudp_ack;
static int ett_rdpudp_fec;
static int ett_rdpudp_data;
static int ett_rdpudp2_packetType;
static int ett_rdpudp2_flags;
static int ett_rdpudp2_ack;
static int ett_rdpudp2_overhead;
static int ett_rdpudp2_delayack;
static int ett_rdpudp2_aoa;
static int ett_rdpudp2_data;
static int ett_rdpudp2_ackvec;
static int ett_rdpudp2_ackvec_vecs;
static int ett_rdpudp2_ackvec_vec;


static int hf_rdpudp_snSourceAck;
static int hf_rdpudp_ReceiveWindowSize;
static int hf_rdpudp_flags;
static int hf_rdpudp_flag_syn;
static int hf_rdpudp_flag_fin;
static int hf_rdpudp_flag_ack;
static int hf_rdpudp_flag_data;
static int hf_rdpudp_flag_fec;
static int hf_rdpudp_flag_cn;
static int hf_rdpudp_flag_cwr;
static int hf_rdpudp_flag_aoa;
static int hf_rdpudp_flag_synlossy;
static int hf_rdpudp_flag_ackdelayed;
static int hf_rdpudp_flag_correlationId;
static int hf_rdpudp_flag_synex;
static int hf_rdpudp_snInitialSequenceNumber;
static int hf_rdpudp_upstreamMtu;
static int hf_rdpudp_downstreamMtu;
static int hf_rdpudp_correlationId;
static int hf_rdpudp_synex_flags;
static int hf_rdpudp_synex_flag_version;
static int hf_rdpudp_synex_version;
static int hf_rdpudp_synex_cookiehash;
static int hf_rdpudp_ack_vectorsize;
static int hf_rdpudp_ack_item;
static int hf_rdpudp_ack_item_state;
static int hf_rdpudp_ack_item_rle;
static int hf_rdpudp_fec_coded;
static int hf_rdpudp_fec_sourcestart;
static int hf_rdpudp_fec_range;
static int hf_rdpudp_fec_fecindex;
static int hf_rdpudp_resetseqenum;
static int hf_rdpudp_source_sncoded;
static int hf_rdpudp_source_snSourceStart;
static int hf_rdpudp_data;

static int * const rdpudp_flags[] = {
		&hf_rdpudp_flag_syn,
		&hf_rdpudp_flag_fin,
		&hf_rdpudp_flag_ack,
		&hf_rdpudp_flag_data,
		&hf_rdpudp_flag_fec,
		&hf_rdpudp_flag_cn,
		&hf_rdpudp_flag_cwr,
		&hf_rdpudp_flag_aoa,
		&hf_rdpudp_flag_synlossy,
		&hf_rdpudp_flag_ackdelayed,
		&hf_rdpudp_flag_correlationId,
		&hf_rdpudp_flag_synex,
		NULL
};

static int hf_rdpudp2_PacketPrefixByte;
static int hf_rdpudp2_packetType;
static int hf_rdpudp2_shortPacketLength;
static int hf_rdpudp2_flags;
static int hf_rdpudp2_flag_ack;
static int hf_rdpudp2_flag_data;
static int hf_rdpudp2_flag_ackvec;
static int hf_rdpudp2_flag_aoa;
static int hf_rdpudp2_flag_overhead;
static int hf_rdpudp2_flag_delayackinfo;
static int hf_rdpudp2_logWindow;
static int hf_rdpudp2_AckSeq;
static int hf_rdpudp2_AckTs;
static int hf_rdpudp2_AckSendTimeGap;
static int hf_rdpudp2_ndelayedAcks;
static int hf_rdpudp2_delayedTimeScale;
static int hf_rdpudp2_delayedAcks;
static int hf_rdpudp2_delayedAck;
static int hf_rdpudp2_OverHeadSize;
static int hf_rdpudp2_DelayAckMax;
static int hf_rdpudp2_DelayAckTimeout;
static int hf_rdpudp2_AckOfAcksSeqNum;
static int hf_rdpudp2_DataSeqNumber;
static int hf_rdpudp2_DataFullSeqNumber;
static int hf_rdpudp2_DataChannelSeqNumber;
static int hf_rdpudp2_DataChannelFullSeqNumber;
static int hf_rdpudp2_Data;
static int hf_rdpudp2_AckvecBaseSeq;
static int hf_rdpudp2_AckvecCodecAckVecSize;
static int hf_rdpudp2_AckvecHaveTs;
static int hf_rdpudp2_AckvecTimeStamp;
static int hf_rdpudp2_SendAckTimeGapInMs;
static int hf_rdpudp2_AckvecCodedAck;
static int hf_rdpudp2_AckvecCodedAckMode;
static int hf_rdpudp2_AckvecCodedAckRleState;
static int hf_rdpudp2_AckvecCodedAckRleLen;

static int * const rdpudp2_flags[] = {
	&hf_rdpudp2_flag_ack,
	&hf_rdpudp2_flag_data,
	&hf_rdpudp2_flag_ackvec,
	&hf_rdpudp2_flag_aoa,
	&hf_rdpudp2_flag_overhead,
	&hf_rdpudp2_flag_delayackinfo,
	&hf_rdpudp2_logWindow,
	NULL
};

static dissector_handle_t tls_handle;
static dissector_handle_t dtls_handle;

enum {
	RDPUDP_FULL_DATA_SEQ_KEY = 1,
	RDPUDP_FULL_CHANNEL_SEQ_KEY = 2
};

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

static bool
rdpudp_chunk_free_cb(const void *key _U_, void *value, void *userdata _U_)
{
	tvbuff_t *tvb = (tvbuff_t*)value;

	tvb_free(tvb);
	return false;
}

static bool
rdpudp_info_free_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_,
		void *user_data)
{
	rdpudp_conv_info_t *rdpudp_info = (rdpudp_conv_info_t*)user_data;

	wmem_tree_foreach(rdpudp_info->client_chunks, rdpudp_chunk_free_cb, NULL);
	wmem_tree_foreach(rdpudp_info->server_chunks, rdpudp_chunk_free_cb, NULL);

	return false;
}

bool
rdp_isServerAddressTarget(packet_info *pinfo)
{
	conversation_t *conv;
	rdp_conv_info_t *rdp_info;
	rdpudp_conv_info_t *rdpudp_info;

	conv = find_conversation_pinfo(pinfo, 0);
	if (!conv)
		return false;

	rdp_info = (rdp_conv_info_t *)conversation_get_proto_data(conv, proto_rdp);
	if (rdp_info) {
		rdp_server_address_t *server = &rdp_info->serverAddr;
		return addresses_equal(&server->addr, &pinfo->dst) && (pinfo->destport == server->port);
	}

	rdpudp_info = (rdpudp_conv_info_t *)conversation_get_proto_data(conv, proto_rdpudp);
	if (!rdpudp_info)
		return false;

	return addresses_equal(&rdpudp_info->server_addr, &pinfo->dst) && (rdpudp_info->server_port == pinfo->destport);
}

bool
rdpudp_is_reliable_transport(packet_info *pinfo)
{
	conversation_t *conv;
	rdpudp_conv_info_t *rdpudp_info;

	conv = find_conversation_pinfo(pinfo, 0);
	if (!conv)
		return false;

	rdpudp_info = (rdpudp_conv_info_t *)conversation_get_proto_data(conv, proto_rdpudp);
	if (!rdpudp_info)
		return false;

	return !rdpudp_info->is_lossy;
}

static int
dissect_rdpudp_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, rdpudp_conv_info_t *conv)
{
	int offset = 0;
	uint16_t flags;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDPUDP");
	col_clear(pinfo->cinfo, COL_INFO);

	proto_tree_add_item(tree, hf_rdpudp_snSourceAck, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_rdpudp_ReceiveWindowSize, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(tree, tvb, offset, hf_rdpudp_flags, ett_rdpudp_flags, rdpudp_flags, ENC_BIG_ENDIAN);
	flags = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
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
		proto_tree_add_item(tree, hf_rdpudp_snInitialSequenceNumber, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_rdpudp_upstreamMtu, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(tree, hf_rdpudp_downstreamMtu, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (flags & RDPUDP_CORRELATIONID) {
		proto_tree_add_item(tree, hf_rdpudp_correlationId, tvb, offset, 16, ENC_NA);
		offset += 32;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "CORRELATIONID");
	}

	if (flags & RDPUDP_SYNEX) {
		uint16_t synex_flags;
		proto_tree *synex_tree;
		unsigned synex_sz = 2;
		uint16_t version_val;

		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "SYNEX");

		synex_flags = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
		if (synex_flags & RDPUDP_VERSION_INFO_VALID) {
			synex_sz += 2; /* version */

			version_val = tvb_get_uint16(tvb, offset+2, ENC_BIG_ENDIAN);

			if (version_val == 0x101)
				synex_sz += 32; /* cookie hash */
		}

		synex_tree = proto_tree_add_subtree(tree, tvb, offset, synex_sz, ett_rdpudp_synex, NULL, "SynEx");
		proto_tree_add_item(synex_tree, hf_rdpudp_synex_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(synex_tree, hf_rdpudp_synex_flag_version, tvb, offset, 2, ENC_BIG_ENDIAN);

		offset += 2;

		if (synex_flags & RDPUDP_VERSION_INFO_VALID) {
			proto_tree_add_item(synex_tree, hf_rdpudp_synex_version, tvb, offset, 2, ENC_BIG_ENDIAN);

			offset += 2;
			if (version_val == 0x101) {
				proto_tree_add_item(synex_tree, hf_rdpudp_synex_cookiehash, tvb, offset, 32, ENC_NA);
				offset += 32;

				if (flags & RDPUDP_ACK)
					conv->start_v2_at = pinfo->num + 1;
			}
		}
	}

	if ((flags & RDPUDP_ACK) && !(flags & RDPUDP_SYN)) {
		proto_tree *ack_tree;
		uint16_t uAckVectorSize = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);

		ack_tree = proto_tree_add_subtree(tree, tvb, offset, 2 + uAckVectorSize, ett_rdpudp_ack, NULL, "Ack");
		offset += 2;
		for ( ; uAckVectorSize; uAckVectorSize--, offset++) {
			proto_tree_add_item(ack_tree, hf_rdpudp_ack_item, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(ack_tree, hf_rdpudp_ack_item_rle, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "ACK");
	}

	if (flags & RDPUDP_FEC) {
		proto_tree *fec_tree = proto_tree_add_subtree(tree, tvb, offset, 4 * 3, ett_rdpudp_fec, NULL, "FEC");

		proto_tree_add_item(fec_tree, hf_rdpudp_fec_coded, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(fec_tree, hf_rdpudp_fec_sourcestart, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(fec_tree, hf_rdpudp_fec_range, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(fec_tree, hf_rdpudp_fec_fecindex, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "FEC");
	}

	if (flags & RDPUDP_AOA) {
		proto_tree_add_item(tree, hf_rdpudp_resetseqenum, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "AOA");
	}

	if (flags & RDPUDP_DATA)
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "DATA");

	if (flags & RDPUDP_DATA) {
		proto_tree *data_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rdpudp_data, NULL, "Data");
		dissector_handle_t target_dissector;

		proto_tree_add_item(data_tree, hf_rdpudp_source_sncoded, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(data_tree, hf_rdpudp_source_snSourceStart, tvb, offset, 4, ENC_BIG_ENDIAN);
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
	int len = tvb_captured_length_remaining(tvb, 0);
	unsigned char *buffer = (unsigned char*)wmem_alloc(pinfo->pool, len);

	/* copy and do the swap of byte 0 and 7*/
	tvb_memcpy(tvb, buffer, 0, len);
	buffer[0] = tvb_get_uint8(tvb, 7);
	buffer[7] = tvb_get_uint8(tvb, 0);

	return tvb_new_child_real_data(tvb, buffer, len, len);
}

static uint64_t
computeAndUpdateSeqContext(rdpudp_seq_context_t *context, uint16_t seq)
{
	uint16_t diff = (context->last_received > seq) ? (context->last_received - seq) : (seq - context->last_received);


	if (diff < 8000) {
		/* not too much difference between last and seq, so we keep the same base
		 *         seq   seq
		 *          |     |
		 *  [0 ...................... 0xffff]
		 *             |
		 *           last
		 */
		if (seq > context->last_received)
			context->last_received = seq;
		return (context->current_base + seq);
	}

	/* when diff is bigger than 8000 that means that either we've just switched
	 * the base, or that it is a sequence number from the previous base
	 */
	if (seq < context->last_received) {
		/* in this case we have
		 *  [0 ...................... 0xffff]
		 *     |                    |
		 *    seq                 last
		 *
		 * so the new sequence number is in fact after last_received: we've just
		 * switched the base
		 */
		context->last_received = seq;
		context->current_base += 0x10000;
		return (context->current_base + seq);
	}

	/* this is a sequence number from the previous base
	 *
	 *  [0 ........................ 0xffff]
	 *      |                   |
	 *     last                seq
	 */
	return (context->current_base + seq - 0x10000);
}

static int
dissect_rdpudp_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, rdpudp_conv_info_t *rdpudp)
{
	proto_item *item;
	proto_tree *subtree, *data_tree = NULL;
	uint16_t flags;
	uint8_t packet_type;
	tvbuff_t *subtvb;
	int offset = 0;
	tvbuff_t *tvb2 = unwrap_udp_v2(tvb, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDPUDP2");
	col_clear(pinfo->cinfo, COL_INFO);

	add_new_data_source(pinfo, tvb2, "Unwrapped RDPUDP2 packet");

	packet_type = (tvb_get_uint8(tvb2, 0) >> 1) & 0xf;
	item = proto_tree_add_item(tree, hf_rdpudp2_PacketPrefixByte, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
	subtree = proto_item_add_subtree(item, ett_rdpudp2_packetType);
	proto_tree_add_item(subtree, hf_rdpudp2_packetType, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(subtree, hf_rdpudp2_shortPacketLength, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	proto_tree_add_bitmask(tree, tvb2, offset, hf_rdpudp2_flags, ett_rdpudp2_flags, rdpudp2_flags, ENC_LITTLE_ENDIAN);

	flags = tvb_get_uint16(tvb2, offset, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (flags & RDPUDP2_ACK) {
		uint8_t nacks = tvb_get_uint8(tvb, offset + 6) & 0xf;
		subtree = proto_tree_add_subtree(tree, tvb2, offset, 7 + nacks, ett_rdpudp2_ack, NULL, "Ack");
		proto_tree_add_item(subtree, hf_rdpudp2_AckSeq, tvb2, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
		proto_tree_add_item(subtree, hf_rdpudp2_AckTs, tvb2, offset, 3, ENC_LITTLE_ENDIAN); offset += 3;
		proto_tree_add_item(subtree, hf_rdpudp2_AckSendTimeGap, tvb2, offset, 1, ENC_LITTLE_ENDIAN); offset++;

		proto_tree_add_item(subtree, hf_rdpudp2_ndelayedAcks, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(subtree, hf_rdpudp2_delayedTimeScale, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		offset += nacks;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "ACK");
	}

	if (flags & RDPUDP2_OVERHEAD) {
		subtree = proto_tree_add_subtree(tree, tvb2, offset, 1, ett_rdpudp2_overhead, NULL, "Overhead");
		proto_tree_add_item(subtree, hf_rdpudp2_OverHeadSize, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "OVERHEAD");
	}


	if (flags & RDPUDP2_DELAYACK) {
		subtree = proto_tree_add_subtree(tree, tvb2, offset, 3, ett_rdpudp2_delayack, NULL, "DelayAck");
		proto_tree_add_item(subtree, hf_rdpudp2_DelayAckMax, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;
		proto_tree_add_item(subtree, hf_rdpudp2_DelayAckTimeout, tvb2, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "DELAYACK");
	}

	if (flags & RDPUDP2_AOA) {
		subtree = proto_tree_add_subtree(tree, tvb2, offset, 1, ett_rdpudp2_aoa, NULL, "Ack of Acks");
		proto_tree_add_item(subtree, hf_rdpudp2_AckOfAcksSeqNum, tvb2, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "AOA");
	}

	if (flags & RDPUDP2_DATA) {
		uint32_t rawSeq;
		uint64_t *seqPtr;
		bool is_server_target = rdp_isServerAddressTarget(pinfo);
		rdpudp_seq_context_t *target_seq_context = is_server_target ? &rdpudp->client_data_seq : &rdpudp->server_data_seq;

		bool isDummy = !!(packet_type == 0x8);
		data_tree = proto_tree_add_subtree(tree, tvb2, offset, 1, ett_rdpudp2_data, NULL, isDummy ? "Dummy data" : "Data");
		proto_tree_add_item_ret_uint(data_tree, hf_rdpudp2_DataSeqNumber, tvb2, offset, 2, ENC_LITTLE_ENDIAN, &rawSeq);

		if (!PINFO_FD_VISITED(pinfo)) {
			seqPtr = wmem_alloc(wmem_file_scope(), sizeof(*seqPtr));
			*seqPtr = computeAndUpdateSeqContext(target_seq_context, rawSeq);

			p_set_proto_data(wmem_file_scope(), pinfo, proto_rdpudp, RDPUDP_FULL_DATA_SEQ_KEY, seqPtr);
		} else {
			seqPtr = (uint64_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rdpudp, RDPUDP_FULL_DATA_SEQ_KEY);
		}
		proto_item_set_generated(
				proto_tree_add_uint(data_tree, hf_rdpudp2_DataFullSeqNumber, tvb2, offset, 2, (uint32_t)*seqPtr)
		);

		offset += 2;

		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", isDummy ? "DUMMY" : "DATA");
	}

	if (flags & RDPUDP2_ACKVEC) {
		proto_tree *acks_tree;
		uint8_t i;
		uint32_t base_seq;
		int ackvecSz = 3;
		uint8_t codedAckVecSizeA = tvb_get_uint8(tvb2, offset + 2);
		uint8_t codedAckVecSize = codedAckVecSizeA & 0x7f;
		bool haveTs = !!(codedAckVecSizeA & 0x80);

		ackvecSz += codedAckVecSize;
		if (haveTs)
			ackvecSz += 3;

		subtree = proto_tree_add_subtree(tree, tvb2, offset, ackvecSz, ett_rdpudp2_ackvec, NULL, "AckVec");
		proto_tree_add_item_ret_uint(subtree, hf_rdpudp2_AckvecBaseSeq, tvb2, offset, 2, ENC_LITTLE_ENDIAN, &base_seq);
		offset += 2;

		proto_tree_add_item(subtree, hf_rdpudp2_AckvecCodecAckVecSize, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(subtree, hf_rdpudp2_AckvecHaveTs, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;

		if (haveTs) {
			proto_tree_add_item(subtree, hf_rdpudp2_AckvecTimeStamp, tvb2, offset, 3, ENC_LITTLE_ENDIAN);
			offset += 3;

			proto_tree_add_item(subtree, hf_rdpudp2_SendAckTimeGapInMs, tvb2, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
		}

		acks_tree = proto_tree_add_subtree(subtree, tvb2, offset, codedAckVecSize, ett_rdpudp2_ackvec_vecs, NULL, "Acks");
		for (i = 0; i < codedAckVecSize; i++) {
			proto_tree *ack_tree;

			uint8_t b = tvb_get_uint8(tvb2, offset + i);

			if (b & 0x80) {
				/* run length mode */
				uint8_t rle_len = (b & 0x3f);
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

			proto_tree_add_item(ack_tree, hf_rdpudp2_AckvecCodedAckMode, tvb2, offset + i, 1, ENC_LITTLE_ENDIAN);
			if (b & 0x80) {
				proto_tree_add_item(ack_tree, hf_rdpudp2_AckvecCodedAckRleState, tvb2, offset + i, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(ack_tree, hf_rdpudp2_AckvecCodedAckRleLen, tvb2, offset + i, 1, ENC_LITTLE_ENDIAN);
			}
		}

		offset += codedAckVecSize;
		col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "ACKVEC");
	}

	if ((flags & RDPUDP2_DATA) && (packet_type != 0x8)) {
		tvbuff_t *data_tvb;
		tvbuff_t *chunk;
		uint32_t rawSeq;
		uint64_t *seqPtr;
		bool is_server_target = rdp_isServerAddressTarget(pinfo);
		wmem_tree_t *targetTree = is_server_target ? rdpudp->client_chunks : rdpudp->server_chunks;
		rdpudp_seq_context_t *target_seq_context = is_server_target ? &rdpudp->client_channel_seq : &rdpudp->server_channel_seq;

		proto_tree_add_item_ret_uint(data_tree, hf_rdpudp2_DataChannelSeqNumber, tvb2, offset, 2, ENC_LITTLE_ENDIAN, &rawSeq);
		if (!PINFO_FD_VISITED(pinfo)) {
			seqPtr = wmem_alloc(wmem_file_scope(), sizeof(*seqPtr));
			*seqPtr = computeAndUpdateSeqContext(target_seq_context, rawSeq);

			p_set_proto_data(wmem_file_scope(), pinfo, proto_rdpudp, RDPUDP_FULL_CHANNEL_SEQ_KEY, seqPtr);
		} else {
			seqPtr = (uint64_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rdpudp, RDPUDP_FULL_CHANNEL_SEQ_KEY);
		}
		proto_item_set_generated(
				proto_tree_add_uint(data_tree, hf_rdpudp2_DataChannelFullSeqNumber, tvb2, offset, 2, (uint32_t)*seqPtr)
		);
		offset += 2;

		chunk = wmem_tree_lookup32(targetTree, (uint32_t)*seqPtr);
		data_tvb = tvb_new_composite();

		if (chunk)
			tvb_composite_prepend(data_tvb, chunk);

		subtvb = tvb_new_subset_length(tvb2, offset, tvb_captured_length_remaining(tvb2, offset));
		tvb_composite_append(data_tvb, subtvb);
		tvb_composite_finalize(data_tvb);

		add_new_data_source(pinfo, data_tvb, "SSL fragment");
		pinfo->can_desegment = 2;

		call_dissector(tls_handle, data_tvb, pinfo, data_tree);

		if (!PINFO_FD_VISITED(pinfo) && pinfo->desegment_len) {
			int remaining = tvb_captured_length_remaining(subtvb, pinfo->desegment_offset);
			/* Something went wrong if seqPtr didn't advance.
			 * XXX: Should we ignore this or free the old chunk and
			 * use the new one?
			 */
			chunk = (tvbuff_t*)wmem_tree_lookup32(targetTree, (uint32_t)(*seqPtr + 1));
			if (chunk) {
				tvb_free(chunk);
			}
			chunk = tvb_clone_offset_len(data_tvb, pinfo->desegment_offset, remaining);
			wmem_tree_insert32(targetTree, (uint32_t)(*seqPtr + 1), chunk);
		}

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
		rdpudp_info->start_v2_at = UINT32_MAX;
		rdpudp_info->is_lossy = false;
		rdpudp_info->client_chunks = wmem_tree_new(wmem_file_scope());
		rdpudp_info->server_chunks = wmem_tree_new(wmem_file_scope());
		wmem_register_callback(wmem_file_scope(), rdpudp_info_free_cb, rdpudp_info);

		conversation_add_proto_data(conversation, proto_rdpudp, rdpudp_info);
	}

	item = proto_tree_add_item(parent_tree, proto_rdpudp, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rdpudp);

	if (rdpudp_info->start_v2_at > pinfo->num)
		return dissect_rdpudp_v1(tvb, pinfo, tree, rdpudp_info);
	else
		return dissect_rdpudp_v2(tvb, pinfo, tree, rdpudp_info);
}

/*--- proto_register_rdpudp -------------------------------------------*/
void
proto_register_rdpudp(void) {
	/* List of fields */
	static hf_register_info hf[] = {
	  { &hf_rdpudp_snSourceAck,
		{"snSourceAck", "rdpudp.snsourceack", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL},
	  },
	  { &hf_rdpudp_ReceiveWindowSize,
		{"ReceiveWindowSize", "rdpudp.receivewindowsize", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_flags,
		{"Flags", "rdpudp.flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_syn,
		{"Syn", "rdpudp.flags.syn", FT_BOOLEAN, 16, NULL, RDPUDP_SYN, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_fin,
		{"Fin", "rdpudp.flags.fin", FT_BOOLEAN, 16, NULL, RDPUDP_FIN, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_ack,
		{"Ack", "rdpudp.flags.ack", FT_BOOLEAN, 16, NULL, RDPUDP_ACK, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_data,
		{"Data", "rdpudp.flags.data", FT_BOOLEAN, 16, NULL, RDPUDP_DATA, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_fec,
		{"FECData", "rdpudp.flags.fec", FT_BOOLEAN, 16, NULL, RDPUDP_FEC, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_cn,
		{"CN", "rdpudp.flags.cn", FT_BOOLEAN, 16, NULL, RDPUDP_CN, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_cwr,
		{"CWR", "rdpudp.flags.cwr", FT_BOOLEAN, 16, NULL, RDPUDP_CWR, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_aoa,
		{"Ack of Acks", "rdpudp.flags.aoa", FT_BOOLEAN, 16, NULL, RDPUDP_AOA, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_synlossy,
		{"Syn lossy", "rdpudp.flags.synlossy", FT_BOOLEAN, 16, NULL, RDPUDP_SYNLOSSY, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_ackdelayed,
		{"Ack delayed", "rdpudp.flags.ackdelayed", FT_BOOLEAN, 16, NULL, RDPUDP_ACKDELAYED, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_correlationId,
		{"Correlation id", "rdpudp.flags.correlationid", FT_BOOLEAN, 16, NULL, RDPUDP_CORRELATIONID, NULL, HFILL}
	  },
	  { &hf_rdpudp_flag_synex,
		{"SynEx","rdpudp.flags.synex",FT_BOOLEAN,16,NULL,RDPUDP_SYNEX,NULL,HFILL}
	  },
	  { &hf_rdpudp_snInitialSequenceNumber,
		{"Initial SequenceNumber","rdpudp.initialsequencenumber", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_upstreamMtu,
		{"Upstream MTU", "rdpudp.upstreammtu", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_downstreamMtu,
		{"DownStream MTU", "rdpudp.downstreammtu", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_correlationId,
		{"Correlation Id", "rdpudp.correlationid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_synex_flags,
		{"Flags", "rdpudp.synex.flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_synex_flag_version,
		{"Version info", "rdpudp.synex.flags.versioninfo", FT_BOOLEAN, 8, NULL, 0x0001, NULL, HFILL}
	  },
	  { &hf_rdpudp_synex_version,
		{"Version", "rdpudp.synex.version", FT_UINT16, BASE_HEX, VALS(rdpudp_version_vals), 0, NULL, HFILL}
	  },
	  {&hf_rdpudp_synex_cookiehash,
		{"Cookie Hash", "rdpudp.synex.cookiehash", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_ack_vectorsize,
		{"uAckVectorSize", "rdpudp.ack.vectorsize", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_ack_item,
		{"Ack item", "rdpudp.ack.item", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_ack_item_state,
		{"VECTOR_ELEMENT_STATE", "rdpudp.ack.item.state", FT_UINT8, BASE_HEX, VALS(rdpudp_ack_states_vals), 0xc0, NULL, HFILL}
	  },
	  { &hf_rdpudp_ack_item_rle,
		{"Run length", "rdpudp.ack.item.rle", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL}
	  },
	  { &hf_rdpudp_fec_coded,
		{"snCoded", "rdpudp.fec.coded", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_fec_sourcestart,
		{"snSourceStart", "rdpudp.fec.sourcestart", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_fec_range,
		{"Range", "rdpudp.fec.range", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_fec_fecindex,
		{"Fec index", "rdpudp.fec.fecindex", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_resetseqenum,
		{"snResetSeqNum", "rdpudp.resetSeqNum", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_source_sncoded,
		{"snCoded", "rdpudp.data.sncoded", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_source_snSourceStart,
		{"snSourceStart", "rdpudp.data.sourceStart", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp_data,
		{"Data", "rdpudp.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },


	  { &hf_rdpudp2_PacketPrefixByte,
		{"PacketPrefixByte", "rdpudp.prefixbyte", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_packetType,
		{"PacketType", "rdpudp.packetType", FT_UINT8, BASE_HEX, VALS(rdpudp2_packetType_vals), 0x1e, NULL, HFILL}
	  },
	  { &hf_rdpudp2_shortPacketLength,
		{"Short packet length", "rdpudp.shortpacketlen", FT_UINT8, BASE_DEC, NULL, 0x7, NULL, HFILL}
	  },
	  { &hf_rdpudp2_flags,
		 {"Flags", "rdpudp.flags", FT_UINT16, BASE_HEX, NULL, 0xfff, NULL, HFILL}
	  },
	  { &hf_rdpudp2_flag_ack,
		{"Ack", "rdpudp.flags.ack", FT_BOOLEAN, 16, NULL, RDPUDP2_ACK, NULL, HFILL}
	  },
	  { &hf_rdpudp2_flag_data,
		{"Data", "rdpudp.flags.data", FT_BOOLEAN, 16, NULL, RDPUDP2_DATA, NULL, HFILL}
	  },
	  { &hf_rdpudp2_flag_ackvec,
		{"AckVec", "rdpudp.flags.ackvec", FT_UINT16, BASE_HEX, NULL, RDPUDP2_ACKVEC, NULL, HFILL}
	  },
	  { &hf_rdpudp2_flag_aoa,
		{"AckOfAcks", "rdpudp.flags.ackofacks", FT_UINT16, BASE_HEX, NULL, RDPUDP2_AOA, NULL, HFILL}
	  },
	  { &hf_rdpudp2_flag_overhead,
		{"OverheadSize", "rdpudp.flags.overheadsize", FT_UINT16, BASE_HEX, NULL, RDPUDP2_OVERHEAD, NULL, HFILL}
	  },
	  { &hf_rdpudp2_flag_delayackinfo,
		{"DelayedAckInfo", "rdpudp.flags.delayackinfo", FT_UINT16, BASE_HEX, NULL, RDPUDP2_DELAYACK, NULL, HFILL}
	  },
	  { &hf_rdpudp2_logWindow,
		{"LogWindow", "rdpudp.logWindow", FT_UINT16, BASE_DEC, NULL, 0xf000, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckSeq,
		{"Base Seq", "rdpudp.ack.seqnum", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckTs,
		{"receivedTS", "rdpudp.ack.ts", FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckSendTimeGap,
		{"sendTimeGap", "rdpudp.ack.sendTimeGap", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_ndelayedAcks,
		{"NumDelayedAcks", "rdpudp.ack.numDelayedAcks", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}
	  },
	  { &hf_rdpudp2_delayedTimeScale,
		{"delayedTimeScale", "rdpudp.ack.delayedTimeScale", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_delayedAcks,
		{"Delayed acks", "rdpudp.ack.delayedAcks", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_delayedAck,
		{"Delayed ack", "rdpudp.ack.delayedAck", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_OverHeadSize,
		{"Overhead size", "rdpudp.overheadsize", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_DelayAckMax,
		{"MaxDelayedAcks", "rdpudp.delayackinfo.max", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_DelayAckTimeout,
		{"DelayedAckTimeoutInMs", "rdpudp.delayackinfo.timeout", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckOfAcksSeqNum,
		{"Sequence number", "rdpudp.ackofacksseqnum", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_DataSeqNumber,
		{"Sequence number", "rdpudp.data.seqnum", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_DataFullSeqNumber,
		{"Full sequence number", "rdpudp.data.fullseqnum", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_DataChannelSeqNumber,
		{"Channel sequence number", "rdpudp.data.channelseqnumber", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_DataChannelFullSeqNumber,
		{"Channel full sequence number", "rdpudp.data.channelfullseqnumber", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_Data,
		{"Data", "rdpudp.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckvecBaseSeq,
		{"Base sequence number", "rdpudp.ackvec.baseseqnum", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckvecCodecAckVecSize,
		{"Coded ackvec size","rdpudp.ackvec.codedackvecsize", FT_UINT16, BASE_DEC, NULL, 0x7f, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckvecHaveTs,
		{"Have timestamp", "rdpudp.ackvec.havets", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckvecTimeStamp,
		{"Timestamp", "rdpudp.ackvec.timestamp", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_SendAckTimeGapInMs,
		{"SendAckTimeGap", "rdpudp.ackvec.sendacktimegap", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckvecCodedAck,
		{"Coded Ack", "rdpudp.ackvec.codedAck", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckvecCodedAckMode,
		{"Mode", "rdpudp.ackvec.codecAckMode", FT_UINT8, BASE_HEX, VALS(rdpudp2_ackvec_mode_vals), 0x80, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckvecCodedAckRleState,
		{"State", "rdpudp.ackvec.codecAckRleState", FT_UINT8, BASE_DEC, VALS(rdpudp2_ackvec_rlestates_vals), 0x40, NULL, HFILL}
	  },
	  { &hf_rdpudp2_AckvecCodedAckRleLen,
		{"Length", "rdpudp.ackvec.codecAckRleLen", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL}
	  }
	};

	/* List of subtrees */
	static int *ett[] = {
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
