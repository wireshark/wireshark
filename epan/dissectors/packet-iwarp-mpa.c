/* packet-iwarp-mpa.c
 * Routines for Marker Protocol data unit Aligned framing (MPA) dissection
 * According to IETF RFC 5044
 * Copyright 2008, Yves Geissbuehler <yves.geissbuehler@gmx.net>
 * Copyright 2008, Philip Frey <frey.philip@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* INCLUDES */
#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>
#include <wsutil/crc32.h>
#include "packet-tcp.h"

void proto_register_mpa(void);
void proto_reg_handoff_mpa(void);

/* DEFINES */

/* header field byte lengths */
#define MPA_REQ_REP_FRAME_HEADER_LEN 20
#define MPA_PDLENGTH_LEN 2
#define MPA_ULPDU_LENGTH_LEN 2
#define MPA_MARKER_LEN 4
#define MPA_SMALLEST_FPDU_LEN 8
#define MPA_REQ_REP_KEY_LEN 16
#define MPA_REQ_REP_FLAG_LEN 1
#define MPA_REQ_REP_REV_LEN 1
#define MPA_REQ_REP_PDLENGTH_LEN 2
#define MPA_MARKER_RSVD_LEN 2
#define MPA_MARKER_FPDUPTR_LEN 2
#define MPA_CRC_LEN 4

/* protocol constants */
#define MPA_REQ_REP_FRAME UINT64_C(0x4d50412049442052)
#define MPA_ID_REQ_FRAME UINT64_C(0x6571204672616d65)
#define MPA_ID_REP_FRAME UINT64_C(0x6570204672616d65)
#define MPA_MARKER_INTERVAL 512
#define MPA_MAX_PD_LENGTH 512
#define MPA_ALIGNMENT 4
#define TCP_MAX_SEQ ((uint32_t) 0xffffffff)

/* for code readability */
#define MPA_REQUEST_FRAME 1
#define MPA_REPLY_FRAME 2
#define MPA_FPDU 3
#define MPA_INITIATOR 0
#define MPA_RESPONDER 1

/* bitmasks */
#define	MPA_MARKER_FLAG 0x80
#define MPA_CRC_FLAG 0x40
#define MPA_REJECT_FLAG 0x20
#define MPA_RESERVED_FLAG 0x1F

/* GLOBALS */

/* initialize the protocol and registered fields */
static int proto_iwarp_mpa;

static int hf_mpa_req;
static int hf_mpa_rep;
static int hf_mpa_fpdu;
static int hf_mpa_marker;

static int hf_mpa_key_req;
static int hf_mpa_key_rep;
static int hf_mpa_flag_m;
static int hf_mpa_flag_c;
static int hf_mpa_flag_r;
static int hf_mpa_flag_res;
static int hf_mpa_rev;
static int hf_mpa_pd_length;
static int hf_mpa_private_data;

static int hf_mpa_ulpdu_length;
static int hf_mpa_pad;
static int hf_mpa_crc;
static int hf_mpa_crc_check;

static int hf_mpa_marker_res;
static int hf_mpa_marker_fpduptr;

/* initialize the subtree pointers */
static int ett_mpa;

static int ett_mpa_req;
static int ett_mpa_rep;
static int ett_mpa_fpdu;
static int ett_mpa_marker;

static expert_field ei_mpa_res_field_not_set0;
static expert_field ei_mpa_rev_field_not_set1;
static expert_field ei_mpa_reject_bit_responder;
static expert_field ei_mpa_bad_length;

/* handles of our subdissectors */
static dissector_handle_t ddp_rdmap_handle;

static const value_string mpa_messages[] = {
		{ MPA_REQUEST_FRAME, "MPA Request Frame" },
		{ MPA_REPLY_FRAME, "MPA Reply Frame" },
		{ MPA_FPDU, "MPA FPDU" },
		{ 0, NULL }
};

/*
 * CONNECTION STATE and MARKERS
 * A MPA endpoint operates in two distinct phases.
 * The Startup Phase is used to verify correct MPA setup, exchange CRC
 * and Marker configuration, and optionally pass Private Data between
 * endpoints prior to completing a DDP connection.
 * The second distinct phase is Full Operation during which FPDUs are
 * sent using all the rules that pertain (CRC, Markers, MULPDU,
 * restrictions etc.).
 * To keep track of a MPA connection configuration a mpa_state is declared
 * and maintained per TCP connection, i.e. it is associated to a conversation
 * between two endpoints.
 *
 * In some configurations MPA places MARKERs in a FPDU every 512th octet with
 * respect to the TCP sequence number of the first FPDU. The struct minfo_t
 * records the source port of a peer that has to insert Markers into its FPDUs
 * as well as the TCP sequence number of its first FPDU. This information is
 * necessary to locate the markers within a FPDU afterwards. Itis part of a
 * mpa_state.
 */

/*
 * This struct is used to record the source port 'port' and the TCP sequence
 * number 'seq' of the first FPDU. This information is used to determine the
 * position of the first Marker within the following FPDUs. The boolean 'valid'
 * specifies if Markers are inserted by the endpoint running on source port
 * 'port' or not.
 */
struct minfo {
	uint16_t port;
	uint32_t seq;
	bool valid;
};
typedef struct minfo minfo_t;

/*
 * This struct represents a MPA connection state. It specifies if Markers and
 * CRC is used for the following FPDUs. It also contains information to
 * distinguish between the MPA Startup and Full Operation Phase.the connection
 * parameters negotiated between to MPA endpoints during the MPA Startup Phase
 * as well as other information for the dissection.
 *
 * The two MPA endpoints are called Initiator, the sender of the MPA Request,
 * and Responder, the sender of the MPA Reply.
 *
 * @full_operation: true if is this state is valid and FLASE otherwise.
 * @req_frame_num: Frame number of the MPA Request to distinguish this frame
 * 		   from later FPDUs.
 * @rep_frame_num: Frame number of the MPA Reply to distinguish this frame
 * 		   from later FPDUs.
 * @ini_exp_m_res: true if the Initiator expects the Responder to insert
 * 		   Markers into his FPDUs sent to Initiator and false otherwise.
 * @res_exp_m_ini: true if the Responder expects the Initiator to insert
 * 		   Markers into his FPDUs sent to Responder and false otherwise.
 * @minfo[2]:	   Array of minfo_t whichs holds necessary information to
 * 		   determine the start position of the first Marker within a
 * 		   a FPDU.
 * 		   minfo[0] is used for the Initiator endpoint
 * 		   minfo[1] is used for the Responder endpoint
 * @crc:	   true if CRC is used by both endpoints and FLASE otherwise.
 * @revision:	   Stores the MPA protocol revision number.
 */
struct mpa_state {
	bool full_operation;
	unsigned req_frame_num;
	unsigned rep_frame_num;
	bool ini_exp_m_res;
	bool res_exp_m_ini;
	minfo_t minfo[2];
	bool crc;
	int revision;
};
typedef struct mpa_state mpa_state_t;

/*
 * Returns an initialized MPA connection state or throws an out of
 * memory exception.
 */
static mpa_state_t *
init_mpa_state(void)
{
	mpa_state_t *state;

	state = wmem_new0(wmem_file_scope(), mpa_state_t);
	state->revision = -1;
	return state;
}

/*
 * Returns the state associated with a MPA connection or NULL otherwise.
 */
static mpa_state_t *
get_mpa_state(conversation_t *conversation)
{
	if (conversation) {
		return (mpa_state_t*) conversation_get_proto_data(conversation,
				proto_iwarp_mpa);
	} else {
		return NULL;
	}
}

/*
 * Returns the offset of the first Marker in a FPDU where the beginning of a
 * FPDU has an offset of 0. It also addresses possible sequence number
 * overflows.
 * The endpoint is either the Initiator or the Responder.
 */
static uint32_t
get_first_marker_offset(mpa_state_t *state, struct tcpinfo *tcpinfo,
		uint8_t endpoint)
{
	uint32_t offset = 0;

	if (tcpinfo->seq > state->minfo[endpoint].seq) {
		offset = (tcpinfo->seq - state->minfo[endpoint].seq)
		% MPA_MARKER_INTERVAL;
	}

	if (tcpinfo->seq < state->minfo[endpoint].seq) {
		offset = state->minfo[endpoint].seq
		+ (TCP_MAX_SEQ - tcpinfo->seq) % MPA_MARKER_INTERVAL;
	}

	return (MPA_MARKER_INTERVAL - offset) % MPA_MARKER_INTERVAL;
}

/*
 * Returns the total length of this FPDU under the assumption that a TCP
 * segment carries only one FPDU.
 */
static uint32_t
fpdu_total_length(struct tcpinfo *tcpinfo)
{
	uint32_t size = 0;

	if (tcpinfo->seq < tcpinfo->nxtseq) {
		size = tcpinfo->nxtseq - tcpinfo->seq;
	}

	if (tcpinfo->seq >= tcpinfo->nxtseq) {
		size = tcpinfo->nxtseq + (TCP_MAX_SEQ - tcpinfo->seq);
	}

	return size;
}

/*
 * Returns the number of Markers of this MPA FPDU. The endpoint is either the
 * Initiator or the Responder.
 */
static uint32_t
number_of_markers(mpa_state_t *state, struct tcpinfo *tcpinfo, uint8_t endpoint)
{
	uint32_t size;
	uint32_t offset;

	size = fpdu_total_length(tcpinfo);
	offset = get_first_marker_offset(state, tcpinfo, endpoint);

	if (offset < size) {
		return ((size - offset) / MPA_MARKER_INTERVAL)+1;
	} else {
		return 0;
	}
}

/*
 * Removes any Markers from this FPDU by using memcpy or throws an out of memory
 * exception.
 */
static tvbuff_t *
remove_markers(tvbuff_t *tvb, packet_info *pinfo, uint32_t marker_offset,
		uint32_t num_markers, uint32_t orig_length)
{
	uint8_t *mfree_buff = NULL;
	uint32_t mfree_buff_length, tot_copy, cur_copy;
	uint32_t source_offset;
	tvbuff_t *mfree_tvb = NULL;

	DISSECTOR_ASSERT(num_markers > 0);
	DISSECTOR_ASSERT(orig_length > MPA_MARKER_LEN * num_markers);
	DISSECTOR_ASSERT(tvb_captured_length(tvb) == orig_length);

	/* allocate memory for the marker-free buffer */
	mfree_buff_length = orig_length - (MPA_MARKER_LEN * num_markers);
	mfree_buff = (uint8_t *)wmem_alloc(pinfo->pool, mfree_buff_length);

	tot_copy = 0;
	source_offset = 0;
	cur_copy = marker_offset;
	while (tot_copy < mfree_buff_length) {
		tvb_memcpy(tvb, mfree_buff+tot_copy, source_offset, cur_copy);
		tot_copy += cur_copy;
		source_offset += cur_copy + MPA_MARKER_LEN;
		cur_copy = MIN(MPA_MARKER_INTERVAL, (mfree_buff_length - tot_copy));
	}
	mfree_tvb = tvb_new_child_real_data(tvb, mfree_buff, mfree_buff_length,
					    mfree_buff_length);
	add_new_data_source(pinfo, mfree_tvb, "FPDU without Markers");

	return mfree_tvb;
}

/* returns true if this TCP segment carries a MPA REQUEST and FLASE otherwise */
static bool
is_mpa_req(tvbuff_t *tvb, packet_info *pinfo)
{
	conversation_t *conversation = NULL;
	mpa_state_t *state = NULL;
	uint8_t mcrres;

	if (tvb_get_ntoh64(tvb, 0) != MPA_REQ_REP_FRAME
			|| tvb_get_ntoh64(tvb, 8) != MPA_ID_REQ_FRAME)
		return false;

	conversation = find_or_create_conversation(pinfo);

	if (!get_mpa_state(conversation)) {

		/* associate a MPA connection state to this conversation if
		 * there is no MPA state already associated to this connection
		 */
		state = init_mpa_state();

		/* analyze MPA connection parameter and record them */
		mcrres = tvb_get_uint8(tvb, 16);
		state->ini_exp_m_res = mcrres & MPA_MARKER_FLAG;
		state->crc = mcrres & MPA_CRC_FLAG;
		state->revision = tvb_get_uint8(tvb, 17);
		state->req_frame_num = pinfo->num;
		state->minfo[MPA_INITIATOR].port = pinfo->srcport;
		state->minfo[MPA_RESPONDER].port = pinfo->destport;

		conversation_add_proto_data(conversation, proto_iwarp_mpa, state);

		/* update expert info */
		if (mcrres & MPA_RESERVED_FLAG)
			expert_add_info(pinfo, NULL, &ei_mpa_res_field_not_set0);

		if (state->revision != 1)
			expert_add_info(pinfo, NULL, &ei_mpa_rev_field_not_set1);
	}
	return true;
}

/* returns true if this TCP segment carries a MPA REPLY and false otherwise */
static bool
is_mpa_rep(tvbuff_t *tvb, packet_info *pinfo)
{
	conversation_t *conversation = NULL;
	mpa_state_t *state = NULL;
	uint8_t mcrres;

	if (tvb_get_ntoh64(tvb, 0) != MPA_REQ_REP_FRAME
			|| tvb_get_ntoh64(tvb, 8) != MPA_ID_REP_FRAME) {
		return false;
	}

	conversation = find_conversation_pinfo(pinfo, 0);

	if (!conversation) {
		return false;
	}

	state = get_mpa_state(conversation);
	if (!state) {
		return false;
	}

	if (!state->full_operation) {
		/* update state of this conversation */
		mcrres = tvb_get_uint8(tvb, 16);
		state->res_exp_m_ini = mcrres & MPA_MARKER_FLAG;
		state->crc = state->crc | (mcrres & MPA_CRC_FLAG);
		state->rep_frame_num = pinfo->num;

		 /* enter Full Operation Phase only if the Reject bit is not set */
		if (!(mcrres & MPA_REJECT_FLAG))
			state->full_operation = true;
		else
			expert_add_info(pinfo, NULL, &ei_mpa_reject_bit_responder);
	}
	return true;
}

/* returns true if this TCP segment carries a MPA FPDU and false otherwise */
static bool
is_mpa_fpdu(packet_info *pinfo)
{
	conversation_t *conversation = NULL;
	mpa_state_t *state = NULL;

	conversation = find_conversation_pinfo(pinfo, 0);

	if (!conversation) {
		return false;
	}

	state = get_mpa_state(conversation);
	if (!state) {
		return false;
	}

	/* make sure all MPA connection parameters have been set */
	if (!state->full_operation) {
		return false;
	}

	if (pinfo->num == state->req_frame_num
			|| pinfo->num == state->rep_frame_num) {
		return false;
	} else {
		return true;
	}
}

/* update packet list pane in the GUI */
static void
mpa_packetlist(packet_info *pinfo, int message_type)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPA");

	col_add_fstr(pinfo->cinfo, COL_INFO,
				"%d > %d %s", pinfo->srcport, pinfo->destport,
				val_to_str(message_type, mpa_messages,
						"Unknown %d"));
}

/* dissects MPA REQUEST or MPA REPLY */
static bool
dissect_mpa_req_rep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		int message_type)
{
	proto_tree *mpa_tree = NULL;
	proto_tree *mpa_header_tree = NULL;

	proto_item *mpa_item = NULL;
	proto_item *mpa_header_item = NULL;

	uint16_t pd_length;
	uint32_t offset = 0;

	mpa_packetlist(pinfo, message_type);

	if (tree) {
		mpa_item = proto_tree_add_item(tree, proto_iwarp_mpa, tvb, 0,
				-1, ENC_NA);
		mpa_tree = proto_item_add_subtree(mpa_item, ett_mpa);

		if (message_type == MPA_REQUEST_FRAME) {
			mpa_header_item = proto_tree_add_item(mpa_tree,
					hf_mpa_req, tvb, offset, -1, ENC_NA);
			mpa_header_tree = proto_item_add_subtree(
					mpa_header_item, ett_mpa);
			proto_tree_add_item(mpa_header_tree, hf_mpa_key_req,
					tvb, offset, MPA_REQ_REP_KEY_LEN, ENC_NA);
		}

		if (message_type == MPA_REPLY_FRAME) {
			mpa_header_item = proto_tree_add_item(mpa_tree,
					hf_mpa_rep, tvb, offset, -1, ENC_NA);
			mpa_header_tree = proto_item_add_subtree(
					mpa_header_item, ett_mpa);
			proto_tree_add_item(mpa_header_tree, hf_mpa_key_rep,
					tvb, offset, MPA_REQ_REP_KEY_LEN, ENC_NA);
		}
		offset += MPA_REQ_REP_KEY_LEN;

		proto_tree_add_item(mpa_header_tree, hf_mpa_flag_m, tvb,
				offset, MPA_REQ_REP_FLAG_LEN, ENC_BIG_ENDIAN);
		proto_tree_add_item(mpa_header_tree, hf_mpa_flag_c, tvb,
				offset, MPA_REQ_REP_FLAG_LEN, ENC_BIG_ENDIAN);
		proto_tree_add_item(mpa_header_tree, hf_mpa_flag_r, tvb,
				offset, MPA_REQ_REP_FLAG_LEN, ENC_BIG_ENDIAN);
		proto_tree_add_item(mpa_header_tree, hf_mpa_flag_res, tvb,
				offset, MPA_REQ_REP_FLAG_LEN, ENC_BIG_ENDIAN);
		offset += MPA_REQ_REP_FLAG_LEN;

		proto_tree_add_item(mpa_header_tree, hf_mpa_rev, tvb,
				offset, MPA_REQ_REP_REV_LEN, ENC_BIG_ENDIAN);
		offset += MPA_REQ_REP_REV_LEN;

		/* check whether the Private Data Length conforms to RFC 5044 */
		pd_length = tvb_get_ntohs(tvb, offset);
		if (pd_length > MPA_MAX_PD_LENGTH) {
			proto_tree_add_expert_format(tree, pinfo, &ei_mpa_bad_length, tvb, offset, 2,
				"[PD length field indicates more 512 bytes of Private Data]");
			return false;
		}

		proto_tree_add_uint(mpa_header_tree,
				hf_mpa_pd_length, tvb, offset,
				MPA_REQ_REP_PDLENGTH_LEN, pd_length);
		offset += MPA_REQ_REP_PDLENGTH_LEN;

		if (pd_length) {
			proto_tree_add_item(mpa_header_tree,
					hf_mpa_private_data, tvb, offset,
					pd_length, ENC_NA);
		}
	}
	return true;
}

/* returns byte length of the padding */
static uint8_t
fpdu_pad_length(uint16_t ulpdu_length)
{
	/*
	 * The padding guarantees alignment of 4. Since Markers are 4 bytes long
	 * we do need to take them into consideration for computation of pad
	 * length. The padding length depends only on ULPDU (payload) length and
	 * the length of the header field for the ULPDU length.
	 */
	uint32_t length = ulpdu_length + MPA_ULPDU_LENGTH_LEN;

	/*
	 * The extra % MPA_ALIGNMENT at the end covers for the case
	 * length % MPA_ALIGNMENT == 0.
	 */
	return (MPA_ALIGNMENT - (length % MPA_ALIGNMENT)) % MPA_ALIGNMENT;
}

/* returns offset for PAD */
static uint32_t
pad_offset(struct tcpinfo *tcpinfo, uint32_t fpdu_total_len,
		uint8_t pad_len)
{
	if ((tcpinfo->nxtseq - MPA_CRC_LEN - MPA_MARKER_LEN) % MPA_MARKER_INTERVAL
			== 0) {
		/* covers the case where a Marker resides between the padding
		 * and CRC.
		 */
		return fpdu_total_len - MPA_CRC_LEN - MPA_MARKER_LEN - pad_len;
	} else {
		return fpdu_total_len - MPA_CRC_LEN - pad_len;
	}
}

/* dissects CRC within a FPDU */
static void
dissect_fpdu_crc(tvbuff_t *tvb, proto_tree *tree, mpa_state_t *state,
		uint32_t offset, uint32_t length)
{
	uint32_t crc = 0;
	uint32_t sent_crc = 0;

	if (state->crc) {

		crc = ~crc32c_tvb_offset_calculate(tvb, 0, length, CRC32C_PRELOAD);

		sent_crc = tvb_get_ntohl(tvb, offset); /* crc start offset */

		if (crc == sent_crc) {
			proto_tree_add_uint_format_value(tree,
					hf_mpa_crc_check, tvb, offset, MPA_CRC_LEN,
					sent_crc, "0x%08x (Good CRC32)",
					sent_crc);
		} else {
			proto_tree_add_uint_format_value(tree,
					hf_mpa_crc_check, tvb, offset, MPA_CRC_LEN,
					sent_crc,
					"0x%08x (Bad CRC32, should be 0x%08x)",
					sent_crc, crc);
		}
	} else {
		proto_tree_add_item(tree, hf_mpa_crc, tvb, offset, MPA_CRC_LEN,
				ENC_BIG_ENDIAN);
	}
}

/* dissects Markers within FPDU */
static void
dissect_fpdu_markers(tvbuff_t *tvb, proto_tree *tree, mpa_state_t *state,
		struct tcpinfo *tcpinfo, uint8_t endpoint)
{
	proto_tree *mpa_marker_tree;
	proto_item *mpa_marker_item;
	uint32_t offset, i;

	mpa_marker_item = proto_tree_add_item(tree, hf_mpa_marker, tvb,
			0, -1, ENC_NA);
	mpa_marker_tree = proto_item_add_subtree(mpa_marker_item, ett_mpa);

	offset = get_first_marker_offset(state, tcpinfo, endpoint);

	for (i=0; i<number_of_markers(state, tcpinfo, endpoint); i++) {
		proto_tree_add_item(mpa_marker_tree, hf_mpa_marker_res, tvb,
				offset, MPA_MARKER_RSVD_LEN, ENC_BIG_ENDIAN);
		proto_tree_add_item(mpa_marker_tree,
				hf_mpa_marker_fpduptr, tvb,
				offset+MPA_MARKER_RSVD_LEN,	MPA_MARKER_FPDUPTR_LEN, ENC_BIG_ENDIAN);
		offset += MPA_MARKER_INTERVAL;
	}
}

/* returns the expected value of the 16 bits long MPA FPDU ULPDU LENGTH field */
static uint16_t
expected_ulpdu_length(mpa_state_t *state, struct tcpinfo *tcpinfo,
		uint8_t endpoint)
{
	uint32_t length, pad_length, markers_length;

	length = fpdu_total_length(tcpinfo);

	if (length <= MPA_CRC_LEN)
		return 0;
	length -= MPA_CRC_LEN;

	pad_length = (MPA_ALIGNMENT - (length % MPA_ALIGNMENT)) % MPA_ALIGNMENT;

	if (length <= pad_length)
		return 0;
	length -= pad_length;

	if (state->minfo[endpoint].valid) {
		markers_length =
			number_of_markers(state, tcpinfo, endpoint) * MPA_MARKER_LEN;

		if (length <= markers_length)
			return 0;
		length -= markers_length;
	}

	if (length <= MPA_ULPDU_LENGTH_LEN)
		return 0;
	length -= MPA_ULPDU_LENGTH_LEN;

	return (uint16_t) length;
}

/* dissects MPA FPDU */
static uint16_t
dissect_mpa_fpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		mpa_state_t *state, struct tcpinfo *tcpinfo, uint8_t endpoint)
{
	proto_item *mpa_item = NULL;
	proto_item *mpa_header_item = NULL;

	proto_tree *mpa_tree = NULL;
	proto_tree *mpa_header_tree = NULL;

	uint8_t pad_length;
	uint16_t ulpdu_length, exp_ulpdu_length;
	uint32_t offset, total_length;
	uint32_t num_of_m = 0;

	/*
	 * Initialize starting offset for this FPDU. Deals with the case that this
	 * FPDU may start with a Marker instead of the ULPDU_LENTH header field.
	 */
	if (state->minfo[endpoint].valid
			&& get_first_marker_offset(state, tcpinfo, endpoint) == 0) {
		offset = MPA_MARKER_LEN;
	} else {
		offset = 0;
	}

	/* get ULPDU length of this FPDU */
	ulpdu_length = (uint16_t) tvb_get_ntohs(tvb, offset);

	if (state->minfo[endpoint].valid) {
		num_of_m = number_of_markers(state, tcpinfo, endpoint);
	}


		/*
		 * Stop FPDU dissection if the read ULPDU_LENGTH field does NOT contain
		 * what is expected.
		 * Reasons for getting a wrong ULPDU_LENGTH can be lost packets (because
		 * libpcap was not able to capture every packet) or lost alignment (the
		 * MPA FPDU header does not start right after TCP header).
		 * We consider the above to be an error since we make the assumption
		 * that	exactly one MPA FPDU is contained in one TCP segment and starts
		 * always either with a Marker or the ULPDU_LENGTH header field.
		 */
		pad_length = fpdu_pad_length(ulpdu_length);
		if (num_of_m > 0) {
			exp_ulpdu_length = expected_ulpdu_length(state, tcpinfo, endpoint);
			if (!exp_ulpdu_length || exp_ulpdu_length != (ulpdu_length + pad_length)) {
				return 0;
			}
		}

		mpa_packetlist(pinfo, MPA_FPDU);

		mpa_item = proto_tree_add_item(tree, proto_iwarp_mpa, tvb, 0,
				-1, ENC_NA);
		mpa_tree = proto_item_add_subtree(mpa_item, ett_mpa);

		mpa_header_item = proto_tree_add_item(mpa_tree, hf_mpa_fpdu,
				tvb, offset, -1, ENC_NA);
		mpa_header_tree = proto_item_add_subtree(mpa_header_item,
				ett_mpa);

		/* ULPDU Length header field */
		proto_tree_add_uint(mpa_header_tree,
				hf_mpa_ulpdu_length, tvb, offset,
				MPA_ULPDU_LENGTH_LEN, ulpdu_length);

		/* Markers are present in this FPDU */
		if (num_of_m > 0) {

			total_length = fpdu_total_length(tcpinfo);

			if (pad_length > 0) {
				proto_tree_add_item(mpa_header_tree, hf_mpa_pad,
						tvb, pad_offset(tcpinfo,
								total_length,
								pad_length),
								pad_length, ENC_NA);
			}

			dissect_fpdu_crc(tvb, mpa_header_tree, state,
					total_length-MPA_CRC_LEN, num_of_m * MPA_MARKER_LEN +
					ulpdu_length + pad_length + MPA_ULPDU_LENGTH_LEN);

			dissect_fpdu_markers(tvb, mpa_tree, state, tcpinfo, endpoint);

		} else { /* Markers are not present or not enabled */

			offset += MPA_ULPDU_LENGTH_LEN + ulpdu_length;

			if (pad_length > 0) {
				proto_tree_add_item(mpa_header_tree, hf_mpa_pad, tvb, offset,
						pad_length, ENC_NA);
				offset += pad_length;
			}

			dissect_fpdu_crc(tvb, mpa_header_tree, state, offset,
					ulpdu_length+pad_length+MPA_ULPDU_LENGTH_LEN);
		}
	return ulpdu_length;
}

/* Extracted from dissect_warp_mpa, Obtain the TCP seq of the first FPDU */
static mpa_state_t*
get_state_of_first_fpdu(tvbuff_t *tvb, packet_info *pinfo, struct tcpinfo *tcpinfo, uint8_t *endpoint)
{
	conversation_t *conversation = NULL;
	mpa_state_t *state = NULL;

	if (tvb_captured_length(tvb) >= MPA_SMALLEST_FPDU_LEN && is_mpa_fpdu(pinfo)) {
		conversation = find_conversation_pinfo(pinfo, 0);
		state = get_mpa_state(conversation);

		if (pinfo->srcport == state->minfo[MPA_INITIATOR].port) {
			*endpoint = MPA_INITIATOR;
		} else if (pinfo->srcport == state->minfo[MPA_RESPONDER].port) {
			*endpoint = MPA_RESPONDER;
		} else {
			REPORT_DISSECTOR_BUG("endpoint cannot be determined");
		}

		/* Markers are used by either the Initiator or the Responder or both. */
		if ((state->ini_exp_m_res || state->res_exp_m_ini) && *endpoint <= MPA_RESPONDER) {

			/* find the TCP sequence number of the first FPDU */
			if (!state->minfo[*endpoint].valid) {
				state->minfo[*endpoint].seq = tcpinfo->seq;
				state->minfo[*endpoint].valid = true;
			}
		}
	}

	return state;
}


/*
 * Main dissection routine.
 */
static bool
dissect_iwarp_mpa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	tvbuff_t *next_tvb = NULL;
	mpa_state_t *state = NULL;
	struct tcpinfo *tcpinfo;
	uint8_t endpoint = 3;
	uint16_t ulpdu_length = 0;

	if (data == NULL)
		return false;
	tcpinfo = (struct tcpinfo *)data;

	/* FPDU */
	state = get_state_of_first_fpdu(tvb, pinfo, tcpinfo, &endpoint);
	if (state) {
		/* dissect FPDU */
		ulpdu_length = dissect_mpa_fpdu(tvb, pinfo, tree, state, tcpinfo,
				endpoint);

		/* an ulpdu_length of 0 should never happen */
		if (!ulpdu_length)
			return false;

		/* removes Markers if any and prepares new tvbuff for next dissector */
		if (endpoint <= MPA_RESPONDER && state->minfo[endpoint].valid
				&& number_of_markers(state, tcpinfo, endpoint) > 0) {
			next_tvb = tvb_new_subset_length(remove_markers(tvb, pinfo,
					get_first_marker_offset(state, tcpinfo, endpoint),
					number_of_markers(state, tcpinfo, endpoint),
					fpdu_total_length(tcpinfo)), MPA_ULPDU_LENGTH_LEN,
					ulpdu_length);
		} else {
			next_tvb = tvb_new_subset_length(tvb, MPA_ULPDU_LENGTH_LEN, ulpdu_length);
		}


		/* call subdissector */
		if (ddp_rdmap_handle) {
			call_dissector(ddp_rdmap_handle, next_tvb, pinfo, tree);
		} else {
			REPORT_DISSECTOR_BUG("ddp_handle was null");
		}

		return true;
	}

	/* MPA REQUEST or MPA REPLY */
	if (tvb_captured_length(tvb) >= MPA_REQ_REP_FRAME_HEADER_LEN) {
		if (is_mpa_req(tvb, pinfo))
			return dissect_mpa_req_rep(tvb, pinfo, tree, MPA_REQUEST_FRAME);
		else if (is_mpa_rep(tvb, pinfo))
			return dissect_mpa_req_rep(tvb, pinfo, tree, MPA_REPLY_FRAME);
	}
	return false;
}

static unsigned
iwrap_mpa_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
		     int offset, void *data _U_)
{
	uint64_t tag;
	int remaining = tvb_captured_length_remaining(tvb, offset);
	unsigned pdu_length = 0;
	uint16_t PD_Length;
	mpa_state_t *state = NULL;
	uint8_t endpoint = 3;
	uint32_t num_of_m = 0;
	struct tcpinfo *tcpinfo;
	int current_offset = offset;

	tag = tvb_get_ntoh64(tvb, offset);
	if (tag != MPA_REQ_REP_FRAME) {
		/* FPDU */
		uint16_t ULPDU_Length;
		uint8_t pad_length;

		tcpinfo = (struct tcpinfo *)data;

		state = get_state_of_first_fpdu(tvb, pinfo, tcpinfo, &endpoint);
		if (state) {
			if (state -> minfo[endpoint] . valid && get_first_marker_offset(state, tcpinfo, endpoint) == 0) {
				current_offset += MPA_MARKER_LEN;
			}

			if (state -> minfo[endpoint] . valid) {
				num_of_m = number_of_markers(state, tcpinfo, endpoint);
			}
		}

		if (num_of_m > 0) {
			pdu_length += num_of_m * MPA_MARKER_LEN;
		}
		ULPDU_Length = tvb_get_ntohs(tvb, current_offset);
		pad_length = fpdu_pad_length(ULPDU_Length);

		pdu_length += MPA_ULPDU_LENGTH_LEN;
		pdu_length += ULPDU_Length;
		pdu_length += pad_length;
		pdu_length += MPA_CRC_LEN;

		return pdu_length;
	}

	/*
	 * MPA Request and Reply Frame Format...
	 */

	if (remaining < MPA_REQ_REP_FRAME_HEADER_LEN) {
		/*
		 * We need more data.
		 */
		return 0;
	}

	offset += MPA_REQ_REP_FRAME_HEADER_LEN;
	offset -= MPA_REQ_REP_PDLENGTH_LEN;

	PD_Length = tvb_get_ntohs(tvb, offset);

	pdu_length += MPA_REQ_REP_FRAME_HEADER_LEN;
	pdu_length += PD_Length;

	return pdu_length;
}

static int
dissect_iwarp_mpa_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	bool ok;
	unsigned len;

	len = iwrap_mpa_pdu_length(pinfo, tvb, 0, data);
	ok = dissect_iwarp_mpa(tvb, pinfo, tree, data);
	if (!ok) {
		return -1;
	}

	return len;
}

static bool
dissect_iwarp_mpa_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct tcpinfo *tcpinfo = NULL;
	bool is_mpa_pdu = false;

	if (data == NULL)
		return false;
	tcpinfo = (struct tcpinfo *)data;

	/* MPA REQUEST or MPA REPLY */
	if (tvb_captured_length(tvb) >= MPA_REQ_REP_FRAME_HEADER_LEN) {
		if (is_mpa_req(tvb, pinfo)) {
			is_mpa_pdu = true;
		} else if (is_mpa_rep(tvb, pinfo)) {
			is_mpa_pdu = true;
		}
	}
	if (tvb_captured_length(tvb) >= MPA_SMALLEST_FPDU_LEN && is_mpa_fpdu(pinfo)) {
		is_mpa_pdu = true;
	}

	if (!is_mpa_pdu) {
		return false;
	}

	/* Set the port type for this packet to be iWarp MPA */
	pinfo->ptype = PT_IWARP_MPA;

	tcp_dissect_pdus(tvb, pinfo, tree,
			 true, /* proto_desegment*/
			 MPA_SMALLEST_FPDU_LEN,
			 iwrap_mpa_pdu_length,
			 dissect_iwarp_mpa_pdu,
			 tcpinfo);
	return true;
}

/* registers this protocol with Wireshark */
void proto_register_mpa(void)
{
	/* setup list of header fields */
	static hf_register_info hf[] = {
			{ &hf_mpa_req, {
					"Request frame header", "iwarp_mpa.req",
					FT_NONE, BASE_NONE, NULL, 0x0,
					NULL, HFILL	} },
			{ &hf_mpa_rep, {
					"Reply frame header", "iwarp_mpa.rep",
					FT_NONE, BASE_NONE, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_fpdu, {
					"FPDU", "iwarp_mpa.fpdu",
					FT_NONE, BASE_NONE, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_marker, {
					"Markers", "iwarp_mpa.markers",
					FT_NONE, BASE_NONE, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_key_req, {
					"ID Req frame", "iwarp_mpa.key.req",
					FT_BYTES, BASE_NONE, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_key_rep, {
					"ID Rep frame", "iwarp_mpa.key.rep",
					FT_BYTES, BASE_NONE, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_flag_m, {
					"Marker flag", "iwarp_mpa.marker_flag",
					FT_BOOLEAN, 8, NULL, MPA_MARKER_FLAG,
					NULL, HFILL } },
			{ &hf_mpa_flag_c, {
					"CRC flag", "iwarp_mpa.crc_flag",
					FT_BOOLEAN, 8, NULL, MPA_CRC_FLAG,
					NULL, HFILL } },
			{ &hf_mpa_flag_r, {
					"Connection rejected flag",
					"iwarp_mpa.rej_flag", FT_BOOLEAN, 8, NULL, MPA_REJECT_FLAG,
					NULL, HFILL } },
			{ &hf_mpa_flag_res, {
					"Reserved", "iwarp_mpa.res",
					FT_UINT8, BASE_HEX, NULL, MPA_RESERVED_FLAG,
					NULL, HFILL } },
			{ &hf_mpa_rev, {
					"Revision", "iwarp_mpa.rev",
					FT_UINT8, BASE_DEC, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_pd_length, {
					"Private data length", "iwarp_mpa.pdlength",
					FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_private_data, {
					"Private data", "iwarp_mpa.privatedata",
					FT_BYTES, BASE_NONE, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_ulpdu_length, {
					"ULPDU length", "iwarp_mpa.ulpdulength",
					FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_pad, {
					"Padding", "iwarp_mpa.pad",
					FT_BYTES, BASE_NONE, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_crc, {
					"CRC", "iwarp_mpa.crc",
					FT_UINT32, BASE_HEX, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_crc_check, {
					"CRC check", "iwarp_mpa.crc_check",
					FT_UINT32, BASE_HEX, NULL, 0x0,
					NULL, HFILL } },
			{ &hf_mpa_marker_res, {
					"Reserved", "iwarp_mpa.marker_res",
					FT_UINT16, BASE_HEX, NULL, 0x0,
					"Marker: Reserved", HFILL } },
			{ &hf_mpa_marker_fpduptr, {
					"FPDU back pointer", "iwarp_mpa.marker_fpduptr",
					FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
					"Marker: FPDU Pointer", HFILL } }
	};

	/* setup protocol subtree array */
	static int *ett[] = {
			&ett_mpa,
			&ett_mpa_req,
			&ett_mpa_rep,
			&ett_mpa_fpdu,
			&ett_mpa_marker
	};

	static ei_register_info ei[] = {
		{ &ei_mpa_res_field_not_set0, { "iwarp_mpa.res.not_set0", PI_REQUEST_CODE, PI_WARN, "Res field is NOT set to zero as required by RFC 5044", EXPFILL }},
		{ &ei_mpa_rev_field_not_set1, { "iwarp_mpa.rev.not_set1", PI_REQUEST_CODE, PI_WARN, "Rev field is NOT set to one as required by RFC 5044", EXPFILL }},
		{ &ei_mpa_reject_bit_responder, { "iwarp_mpa.reject_bit_responder", PI_RESPONSE_CODE, PI_NOTE, "Reject bit set by Responder", EXPFILL }},
		{ &ei_mpa_bad_length, { "iwarp_mpa.bad_length", PI_MALFORMED, PI_ERROR, "Bad length", EXPFILL }},
	};

	expert_module_t* expert_iwarp_mpa;

	/* register the protocol name and description */
	proto_iwarp_mpa = proto_register_protocol("iWARP Marker Protocol data unit Aligned framing", "IWARP_MPA", "iwarp_mpa");

	/* required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_iwarp_mpa, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_iwarp_mpa = expert_register_protocol(proto_iwarp_mpa);
	expert_register_field_array(expert_iwarp_mpa, ei, array_length(ei));
}

void
proto_reg_handoff_mpa(void)
{
	/*
	 * MPA does not use any specific TCP port so, when not on a specific
	 * port, try this dissector whenever there is TCP traffic.
	 */
	heur_dissector_add("tcp", dissect_iwarp_mpa_heur, "IWARP_MPA over TCP", "iwarp_mpa_tcp", proto_iwarp_mpa, HEURISTIC_ENABLE);
	ddp_rdmap_handle = find_dissector_add_dependency("iwarp_ddp_rdmap", proto_iwarp_mpa);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
