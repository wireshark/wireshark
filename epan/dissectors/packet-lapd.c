/* packet-lapd.c
 * Routines for LAPD frame disassembly
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/*
 * LAPD bitstream over RTP handling
 * Copyright 2008, Ericsson AB
 * Written by Balint Reczey <balint.reczey@ericsson.com>
 *
 * ISDN/LAPD references:
 *
 * http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/isdn.htm
 * http://www.ece.wpi.edu/courses/ee535/hwk11cd95/agrebe/agrebe.html
 * http://www.acacia-net.com/Clarinet/Protocol/q9213o84.htm
 * http://www.itu.int/rec/T-REC-Q.921/en
 * Base Station Controller - Base Transceiver Station (BSC - BTS) interface; Layer 2 specification
 * http://www.3gpp.org/ftp/Specs/html-info/48056.htm
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/xdlc.h>
#include <epan/crc16-tvb.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/lapd_sapi.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include "packet-l2tp.h"

void proto_register_lapd(void);
void proto_reg_handoff_lapd(void);

static int proto_lapd = -1;
static int hf_lapd_direction = -1;
static int hf_lapd_address = -1;
static int hf_lapd_sapi = -1;
static int hf_lapd_gsm_sapi = -1;
static int hf_lapd_cr = -1;
static int hf_lapd_ea1 = -1;
static int hf_lapd_tei = -1;
static int hf_lapd_ea2 = -1;
static int hf_lapd_control = -1;
static int hf_lapd_n_r = -1;
static int hf_lapd_n_s = -1;
static int hf_lapd_p = -1;
static int hf_lapd_p_ext = -1;
static int hf_lapd_f = -1;
static int hf_lapd_f_ext = -1;
static int hf_lapd_s_ftype = -1;
static int hf_lapd_u_modifier_cmd = -1;
static int hf_lapd_u_modifier_resp = -1;
static int hf_lapd_ftype_i = -1;
static int hf_lapd_ftype_s_u = -1;
static int hf_lapd_ftype_s_u_ext = -1;
static int hf_lapd_checksum = -1;
static int hf_lapd_checksum_status = -1;

static gint ett_lapd = -1;
static gint ett_lapd_address = -1;
static gint ett_lapd_control = -1;
static gint ett_lapd_checksum = -1;

static range_t *pref_lapd_rtp_payload_type_range = NULL;
static guint pref_lapd_sctp_ppi = 0;

static expert_field ei_lapd_abort = EI_INIT;
static expert_field ei_lapd_checksum_bad = EI_INIT;

static dissector_handle_t lapd_handle;
static dissector_handle_t lapd_phdr_handle;
static dissector_handle_t linux_lapd_handle;
static dissector_handle_t lapd_bitstream_handle;

static dissector_table_t lapd_sapi_dissector_table;
static dissector_table_t lapd_gsm_sapi_dissector_table;

/* Whether to use GSM SAPI vals or not */
static gboolean global_lapd_gsm_sapis = FALSE;

/*
 * Bits in the address field.
 */
#define	LAPD_SAPI		0xfc00	/* Service Access Point Identifier */
#define	LAPD_SAPI_SHIFT		10
#define	LAPD_CR			0x0200	/* Command/Response bit */
#define	LAPD_EA1		0x0100	/* First Address Extension bit */
#define	LAPD_TEI		0x00fe	/* Terminal Endpoint Identifier */
#define	LAPD_TEI_SHIFT		1
#define	LAPD_EA2		0x0001	/* Second Address Extension bit */

#define LAPD_DIR_USER_TO_NETWORK	0
#define LAPD_DIR_NETWORK_TO_USER	1

static const value_string lapd_direction_vals[] = {
	{ LAPD_DIR_USER_TO_NETWORK,		"User->Network"},
	{ LAPD_DIR_NETWORK_TO_USER,		"Network->User"},
	{ 0,					NULL }
};

static const value_string lapd_sapi_vals[] = {
	{ LAPD_SAPI_Q931,	"Q.931 Call control procedure" },
	{ LAPD_SAPI_PM_Q931,	"Packet mode Q.931 Call control procedure" },
	{ LAPD_SAPI_X25,	"X.25 Level 3 procedures" },
	{ LAPD_SAPI_L2,		"Layer 2 management procedures" },
	{ 0,			NULL }
};

static const value_string lapd_gsm_sapi_vals[] = {
	{ LAPD_GSM_SAPI_RA_SIG_PROC,	"Radio signalling procedures" },
	{ LAPD_GSM_SAPI_NOT_USED_1,	"(Not used in GSM PLMN)" },
	{ LAPD_GSM_SAPI_NOT_USED_16,	"(Not used in GSM PLMN)" },
	{ LAPD_GSM_SAPI_OM_PROC,	"Operation and maintenance procedure" },
	{ LAPD_SAPI_L2,			"Layer 2 management procedures" },
	{ 0,				NULL }
};

/* Used only for U frames */
static const xdlc_cf_items lapd_cf_items = {
	NULL,
	NULL,
	&hf_lapd_p,
	&hf_lapd_f,
	NULL,
	&hf_lapd_u_modifier_cmd,
	&hf_lapd_u_modifier_resp,
	NULL,
	&hf_lapd_ftype_s_u
};

/* Used only for I and S frames */
static const xdlc_cf_items lapd_cf_items_ext = {
	&hf_lapd_n_r,
	&hf_lapd_n_s,
	&hf_lapd_p_ext,
	&hf_lapd_f_ext,
	&hf_lapd_s_ftype,
	NULL,
	NULL,
	&hf_lapd_ftype_i,
	&hf_lapd_ftype_s_u_ext
};

#define MAX_LAPD_PACKET_LEN 1024

/* LAPD frame detection state */
enum lapd_bitstream_states {OUT_OF_SYNC, FLAGS, DATA};

typedef struct lapd_byte_state {
	enum lapd_bitstream_states state;	/* frame detection state */
	char		full_byte;		/* part of a full byte */
	char		bit_offset;		/* number of bits already got in the full byte */
	int		ones;			/* number of consecutive ones since the last zero */
	char            data[MAX_LAPD_PACKET_LEN];
	int             data_len;
} lapd_byte_state_t;

typedef struct lapd_ppi {
	gboolean		has_crc; 		/* CRC is captured with LAPD the frames */
	lapd_byte_state_t	start_byte_state; 	/* LAPD bitstream byte state at the beginning of processing the packet */
} lapd_ppi_t;

/* Fill values in lapd_byte_state struct */
static void
fill_lapd_byte_state(lapd_byte_state_t *ptr, enum lapd_bitstream_states state, char full_byte, char bit_offset, int ones, char *data, int data_len)
{
	ptr->state = state;
	ptr->full_byte = full_byte;
	ptr->bit_offset = bit_offset;
	ptr->ones = ones;

	ptr->data_len = MIN((int)sizeof(ptr->data), data_len);
	memcpy(ptr->data, data, ptr->data_len);
}

typedef struct lapd_convo_data {
	address		addr_a;
	address		addr_b;
	guint32		port_a;
	guint32		port_b;
	lapd_byte_state_t	*byte_state_a;
	lapd_byte_state_t	*byte_state_b;
} lapd_convo_data_t;


static void
dissect_lapd_full(tvbuff_t*, packet_info*, proto_tree*, guint32);

/* got new LAPD frame byte */
static void new_byte(char full_byte, char data[], int *data_len) {
	if (*data_len < MAX_LAPD_PACKET_LEN) {
		data[*data_len] = full_byte;
		(*data_len)++;
	} else {
		/* XXX : we are not prepared for that big messages, drop the last byte */
	}
}

static void
lapd_log_abort(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, const char *msg)
{
	proto_item *ti;

	ti = proto_tree_add_item(tree, proto_lapd, tvb, offset, 1, ENC_NA);
	expert_add_info_format(pinfo, ti, &ei_lapd_abort, "%s", msg);
}

/*
 * Flags to pass to dissect_lapd_full.
 */
#define LAPD_HAS_CRC			0x00000001
#define LAPD_HAS_DIRECTION		0x00000002
#define LAPD_HAS_LINUX_SLL		0x00000004
#define LAPD_USER_TO_NETWORK		0x00000008
#define LAPD_NETWORK_IS_REMOTE		0x00000010
#define LAPD_USER_IS_REMOTE		0x00000020

static int
dissect_lapd_bitstream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* dissector_data _U_)
{
	guint8		byte, full_byte = 0x00, bit_offset = 0;
	gboolean	bit;
	guint8		i, ones = 0, data[MAX_LAPD_PACKET_LEN];
	int		data_len = 0;
	gint		offset = 0, available;
	guint8		*buff;
	tvbuff_t	*new_tvb;

	enum lapd_bitstream_states state = OUT_OF_SYNC;
	lapd_ppi_t		*lapd_ppi;
	conversation_t		*conversation = NULL;
	lapd_convo_data_t	*convo_data = NULL;
	lapd_byte_state_t	*lapd_byte_state, *prev_byte_state = NULL;
	gboolean		forward_stream = TRUE;

	/* get remaining data from previous packets */
	conversation = find_or_create_conversation(pinfo);
	lapd_ppi = (lapd_ppi_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_lapd, 0);
	if (lapd_ppi) {
		prev_byte_state = &lapd_ppi->start_byte_state;
		if (prev_byte_state) {
			state = prev_byte_state->state;
			full_byte = prev_byte_state->full_byte;
			bit_offset = prev_byte_state->bit_offset;
			ones = prev_byte_state->ones;
			memcpy(data, prev_byte_state->data, prev_byte_state->data_len);
			data_len = prev_byte_state->data_len;
		}

	} else if (conversation) {
		convo_data = (lapd_convo_data_t*)conversation_get_proto_data(conversation, proto_lapd);
		if (NULL != convo_data) {
			if (addresses_equal(&convo_data->addr_a, &pinfo->src)
					&& addresses_equal(&convo_data->addr_b, &pinfo->dst)
					&& convo_data-> port_a == pinfo->srcport
					&& convo_data-> port_b == pinfo->destport) {
				/* "forward" direction */
				forward_stream = TRUE;
				prev_byte_state = convo_data->byte_state_a;
			} else if (addresses_equal(&convo_data-> addr_b, &pinfo->src)
					&& addresses_equal(&convo_data->addr_a, &pinfo->dst)
					&& convo_data-> port_b == pinfo->srcport
					&& convo_data-> port_a == pinfo->destport) {
				/* "backward" direction */
				forward_stream = FALSE;
				prev_byte_state = convo_data->byte_state_b;
			}
		}
		if (prev_byte_state) {
			state = prev_byte_state->state;
			full_byte = prev_byte_state->full_byte;
			bit_offset = prev_byte_state->bit_offset;
			ones = prev_byte_state->ones;

			memcpy(data, prev_byte_state->data, prev_byte_state->data_len);
			data_len = prev_byte_state->data_len;
		}
	}

	/* Consume tvb bytes */
	available = tvb_reported_length_remaining(tvb, offset);
	while (offset < available) {
		byte = tvb_get_guint8(tvb,offset);
		offset++;
		for (i=0; i < 8; i++) { /* cycle through bits */
			bit = byte & (0x80 >> i) ? TRUE : FALSE;

			/* consume a bit */
			if (bit) {
				ones++;
				full_byte |= (1 << bit_offset++);
			} else {
				if (ones == 5 && state == DATA) {
					/* we don't increase bit_offset, it is an inserted zero */
				} else if (ones == 6 && state == DATA) { /* probably starting flag sequence */
					buff = (guint8 *)wmem_memdup(pinfo->pool, data, data_len);
					/* Allocate new tvb for the LAPD frame */
					new_tvb = tvb_new_child_real_data(tvb, buff, data_len, data_len);
					add_new_data_source(pinfo, new_tvb, "Decoded LAPD bitstream");
					data_len = 0;
					state = FLAGS;
					bit_offset++;

					if (full_byte != 0x7E) {
						data_len = 0;
						state = OUT_OF_SYNC;
						lapd_log_abort(tvb, pinfo, tree, offset, "Abort! 6 ones that don't match 0x7e!");

					}
					dissect_lapd_full(new_tvb, pinfo, tree, LAPD_HAS_CRC);
				} else if (ones >= 7) { /* frame reset or 11111111 flag byte */
					data_len = 0;
					state = OUT_OF_SYNC;
					bit_offset++;

					lapd_log_abort(tvb, pinfo, tree, offset, "Abort! 7 ones!");
				} else {
					bit_offset++;
				}
				ones = 0;
			}

			if (bit_offset == 8) { /* we have a new complete byte */
				switch (state) {
					case OUT_OF_SYNC:
						if (full_byte == 0x7E) { /* we have a flag byte */
							state = FLAGS;
							full_byte = 0x00;
							bit_offset = 0;
						} else { /* no sync yet, wait for a new byte */
							full_byte = (full_byte >> 1) & 0x7F;
							bit_offset--;
						}
						break;

					case FLAGS:
						if (full_byte == 0x7E) { /* we have a flag byte */
							full_byte = 0x00;
							bit_offset = 0;
						} else { /* we got the first data byte */
							state = DATA;
							new_byte(full_byte, data, &data_len);
							full_byte = 0x00;
							bit_offset = 0;
						}
						break;

					case DATA:
						/* we got a new data byte */
						new_byte(full_byte, data, &data_len);
						full_byte = 0x00;
						bit_offset = 0;
						break;
				}
			}
		}
	}

	{
		if (NULL == p_get_proto_data(wmem_file_scope(), pinfo, proto_lapd, 0)) {
			/* Per packet information */
			lapd_ppi = wmem_new(wmem_file_scope(), lapd_ppi_t);
			lapd_ppi->has_crc = TRUE;
			if (prev_byte_state)
				fill_lapd_byte_state(&lapd_ppi->start_byte_state, prev_byte_state->state,
						prev_byte_state->full_byte, prev_byte_state->bit_offset,
						prev_byte_state->ones, prev_byte_state->data, prev_byte_state->data_len);
			else
				fill_lapd_byte_state(&lapd_ppi->start_byte_state, OUT_OF_SYNC, 0x00, 0, 0, data, 0);

			p_add_proto_data(wmem_file_scope(), pinfo, proto_lapd, 0, lapd_ppi);


			/* Conversation info*/

			if (conversation) {
				if (convo_data) { /* already have lapd convo data */
					if (forward_stream) {
						if (!convo_data->byte_state_a)
							convo_data->byte_state_a = wmem_new(wmem_file_scope(), lapd_byte_state_t);
						fill_lapd_byte_state(convo_data->byte_state_a, state, full_byte, bit_offset, ones, data, data_len);
					} else {
						if (!convo_data->byte_state_b)
							convo_data->byte_state_b = wmem_new(wmem_file_scope(), lapd_byte_state_t);
						fill_lapd_byte_state(convo_data->byte_state_b, state, full_byte, bit_offset, ones, data, data_len);
					}
				} else { /* lapd convo data has to be created */
					lapd_byte_state = wmem_new(wmem_file_scope(), lapd_byte_state_t);
					fill_lapd_byte_state(lapd_byte_state, state, full_byte, bit_offset, ones, data, data_len);
					convo_data = wmem_new(wmem_file_scope(), lapd_convo_data_t);
					copy_address_wmem(wmem_file_scope(), &convo_data->addr_a, &pinfo->src);
					copy_address_wmem(wmem_file_scope(), &convo_data->addr_b, &pinfo->dst);
					convo_data->port_a = pinfo->srcport;
					convo_data->port_b = pinfo->destport;
					convo_data->byte_state_a = lapd_byte_state;
					convo_data->byte_state_b = NULL;
					conversation_add_proto_data(conversation, proto_lapd, convo_data);
				}
			}
		}
	}
	return tvb_captured_length(tvb);
}

static int
dissect_linux_lapd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint32 flags = LAPD_HAS_LINUX_SLL | LAPD_HAS_DIRECTION;

	/* frame is captured via libpcap */
	if (pinfo->pseudo_header->lapd.pkttype == 4 /*PACKET_OUTGOING*/) {
		if (pinfo->pseudo_header->lapd.we_network) {
			/*
			 * We're the network side, so the user is remote,
			 * and we're sending it, so this is Network->User.
			 */
			flags |= LAPD_USER_IS_REMOTE;
		} else {
			/*
			 * We're the user side, so the network is remote,
			 * and we're sending it, so this is User->Network.
			 */
			flags |= LAPD_NETWORK_IS_REMOTE | LAPD_USER_TO_NETWORK;
		}
	}
	else if (pinfo->pseudo_header->lapd.pkttype == 3 /*PACKET_OTHERHOST*/) {
		/*
		 * We must be a TE, sniffing what other TE transmit, so
		 * both sides are remote.
		 *
		 * XXX - do we know whether it's User->Network or
		 * Network->User?
		 */
		flags |= LAPD_USER_IS_REMOTE | LAPD_NETWORK_IS_REMOTE | LAPD_USER_TO_NETWORK;
	}
	else {
		/* The frame is incoming */
		if (pinfo->pseudo_header->lapd.we_network) {
			/*
			 * We're the network side, so the user is remote,
			 * and we received it, so this is User->Network.
			 */
			flags |= LAPD_USER_IS_REMOTE | LAPD_USER_TO_NETWORK;
		} else {
			/*
			 * We're the user side, so the network is remote,
			 * and we received it, so this is Network->User.
			 */
			flags |= LAPD_NETWORK_IS_REMOTE;
		}
	}
	dissect_lapd_full(tvb, pinfo, tree, flags);
	return tvb_captured_length(tvb);
}

/*
 * Called from dissectors, such as the ISDN dissector, that supply a
 * struct isdn_pndr giving the packet direction.
 */
static int
dissect_lapd_phdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct isdn_phdr *isdn = (struct isdn_phdr *)data;
	guint32 flags = LAPD_HAS_DIRECTION;

	if (isdn->uton)
		flags |= LAPD_USER_TO_NETWORK;
	dissect_lapd_full(tvb, pinfo, tree, flags);
	return tvb_captured_length(tvb);
}

/*
 * Called for link-layer encapsulation.
 */
static int
dissect_lapd_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint32 flags;
	guint32 lapd_flags = 0;

	/*
	 * If we have direction flags, we have a direction;
	 * "outbound" packets are presumed to be User->Network and
	 * "inbound" packets are presumed to be Network->User.
	 * Other packets, we have no idea.
	 */
	if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_uint32_option_value(pinfo->rec->block, OPT_PKT_FLAGS, &flags)) {
		switch (PACK_FLAGS_DIRECTION(flags)) {

		case PACK_FLAGS_DIRECTION_OUTBOUND:
			lapd_flags |= LAPD_HAS_DIRECTION | LAPD_USER_TO_NETWORK;
			break;

		case PACK_FLAGS_DIRECTION_INBOUND:
			lapd_flags |= LAPD_HAS_DIRECTION;
			break;

		default:
			break;
		}
	}
	dissect_lapd_full(tvb, pinfo, tree, lapd_flags);
	return tvb_captured_length(tvb);
}

static int
dissect_lapd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* XXX - direction is unknown */
	dissect_lapd_full(tvb, pinfo, tree, 0);
	return tvb_captured_length(tvb);
}

static void
dissect_lapd_full(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 flags)
{
	proto_tree	*lapd_tree, *addr_tree;
	proto_item	*lapd_ti, *addr_ti;
	guint16		control;
	int		lapd_header_len, checksum_offset;
	guint16		addr, cr, sapi, tei;
	gboolean	is_response = 0;
	tvbuff_t	*next_tvb;
	const char	*srcname = "?";
	const char	*dstname = "?";

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LAPD");
	col_clear(pinfo->cinfo, COL_INFO);

	addr = tvb_get_ntohs(tvb, 0);
	cr = addr & LAPD_CR;
	tei = (addr & LAPD_TEI) >> LAPD_TEI_SHIFT;
	sapi = (addr & LAPD_SAPI) >> LAPD_SAPI_SHIFT;
	lapd_header_len = 2;	/* addr */

	col_add_fstr(pinfo->cinfo, COL_TEI, "%u", tei);

	/* Append TEI to info field */
	col_append_fstr(pinfo->cinfo, COL_INFO, "TEI:%02u ", tei);
	col_set_fence(pinfo->cinfo, COL_INFO);

	if (flags & LAPD_HAS_DIRECTION) {
		if (flags & LAPD_USER_TO_NETWORK) {
			is_response = cr ? TRUE : FALSE;
			if (flags & LAPD_HAS_LINUX_SLL) {
				srcname = (flags & LAPD_USER_IS_REMOTE) ?
				    "Remote User" : "Local User";
				dstname = (flags & LAPD_NETWORK_IS_REMOTE) ?
				    "Remote Network" : "Local Network";
			} else {
				srcname = "User";
				dstname = "Network";
			}
		} else {
			is_response = cr ? FALSE : TRUE;
			if (flags & LAPD_HAS_LINUX_SLL) {
				srcname = (flags & LAPD_NETWORK_IS_REMOTE) ?
				    "Remote Network" : "Local Network";
				dstname = (flags & LAPD_USER_IS_REMOTE) ?
				    "Remote User" : "Local User";
			} else {
				srcname = "Network";
				dstname = "User";
			}
		}
	}
	col_set_str(pinfo->cinfo, COL_RES_DL_SRC, srcname);
	col_set_str(pinfo->cinfo, COL_RES_DL_DST, dstname);

	if (tree) {
		proto_item *direction_ti;

		lapd_ti = proto_tree_add_item(tree, proto_lapd, tvb, 0, -1,
		    ENC_NA);
		lapd_tree = proto_item_add_subtree(lapd_ti, ett_lapd);

		/*
		 * Don't show the direction if we don't know it.
		 */
		if (flags & LAPD_HAS_DIRECTION) {
			direction_ti = proto_tree_add_uint(lapd_tree, hf_lapd_direction,
			                                   tvb, 0, 0,
			                                   (flags & LAPD_USER_TO_NETWORK) ? LAPD_DIR_USER_TO_NETWORK : LAPD_DIR_NETWORK_TO_USER);
			proto_item_set_generated(direction_ti);
		}

		addr_ti = proto_tree_add_uint(lapd_tree, hf_lapd_address, tvb,
		    0, 2, addr);
		addr_tree = proto_item_add_subtree(addr_ti, ett_lapd_address);

		if(global_lapd_gsm_sapis){
			proto_tree_add_uint(addr_tree, hf_lapd_gsm_sapi,tvb, 0, 1, addr);
		}else{
			proto_tree_add_uint(addr_tree, hf_lapd_sapi,tvb, 0, 1, addr);
		}
		proto_tree_add_uint(addr_tree, hf_lapd_cr,  tvb, 0, 1, addr);
		proto_tree_add_uint(addr_tree, hf_lapd_ea1, tvb, 0, 1, addr);
		proto_tree_add_uint(addr_tree, hf_lapd_tei, tvb, 1, 1, addr);
		proto_tree_add_uint(addr_tree, hf_lapd_ea2, tvb, 1, 1, addr);
	}
	else {
		lapd_ti = NULL;
		lapd_tree = NULL;
	}

	control = dissect_xdlc_control(tvb, 2, pinfo, lapd_tree, hf_lapd_control,
	    ett_lapd_control, &lapd_cf_items, &lapd_cf_items_ext, NULL, NULL,
	    is_response, TRUE, FALSE);
	lapd_header_len += XDLC_CONTROL_LEN(control, TRUE);

	if (tree)
		proto_item_set_len(lapd_ti, lapd_header_len);

	if (flags & LAPD_HAS_CRC) {

		/* check checksum */
		checksum_offset = tvb_reported_length(tvb) - 2;

		proto_tree_add_checksum(lapd_tree, tvb, checksum_offset, hf_lapd_checksum, hf_lapd_checksum_status, &ei_lapd_checksum_bad, pinfo,
								crc16_ccitt_tvb(tvb, tvb_reported_length(tvb) - 2), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

		next_tvb = tvb_new_subset_length(tvb, lapd_header_len, tvb_reported_length_remaining(tvb,lapd_header_len) - 2);

	} else
		next_tvb = tvb_new_subset_remaining(tvb, lapd_header_len);

	/* Dissection done, append " | " to COL_INFO */
	col_append_str(pinfo->cinfo, COL_INFO, " | ");
	col_set_fence(pinfo->cinfo, COL_INFO);

	if (XDLC_IS_INFORMATION(control)) {
		/* call next protocol */
		if(global_lapd_gsm_sapis){
			if (!dissector_try_uint(lapd_gsm_sapi_dissector_table, sapi,
				next_tvb, pinfo, tree))
				call_data_dissector(next_tvb, pinfo, tree);
		}else{
			if (!dissector_try_uint(lapd_sapi_dissector_table, sapi,
				next_tvb, pinfo, tree))
				call_data_dissector(next_tvb, pinfo, tree);
		}
	} else
		call_data_dissector(next_tvb, pinfo, tree);
}

void
proto_register_lapd(void)
{
	static hf_register_info hf[] = {

		{ &hf_lapd_direction,
		  { "Direction", "lapd.direction", FT_UINT32, BASE_DEC, VALS(lapd_direction_vals), 0x0,
		    NULL, HFILL }},

		{ &hf_lapd_address,
		  { "Address Field", "lapd.address", FT_UINT16, BASE_HEX, NULL, 0x0,
		    "Address", HFILL }},

		{ &hf_lapd_sapi,
		  { "SAPI", "lapd.sapi", FT_UINT16, BASE_DEC, VALS(lapd_sapi_vals), LAPD_SAPI,
		    "Service Access Point Identifier", HFILL }},

		{ &hf_lapd_gsm_sapi,
		  { "SAPI", "lapd.sapi", FT_UINT16, BASE_DEC, VALS(lapd_gsm_sapi_vals), LAPD_SAPI,
		    "Service Access Point Identifier", HFILL }},

		{ &hf_lapd_cr,
		  { "C/R", "lapd.cr", FT_UINT16, BASE_DEC, NULL, LAPD_CR,
		    "Command/Response bit", HFILL }},

		{ &hf_lapd_ea1,
		  { "EA1", "lapd.ea1", FT_UINT16, BASE_DEC, NULL, LAPD_EA1,
		    "First Address Extension bit", HFILL }},

		{ &hf_lapd_tei,
		  { "TEI", "lapd.tei", FT_UINT16, BASE_DEC, NULL, LAPD_TEI,
		    "Terminal Endpoint Identifier", HFILL }},

		{ &hf_lapd_ea2,
		  { "EA2", "lapd.ea2", FT_UINT16, BASE_DEC, NULL, LAPD_EA2,
		    "Second Address Extension bit", HFILL }},

		{ &hf_lapd_control,
		  { "Control Field", "lapd.control", FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_lapd_n_r,
		  { "N(R)", "lapd.control.n_r", FT_UINT16, BASE_DEC,
		    NULL, XDLC_N_R_EXT_MASK, NULL, HFILL }},

		{ &hf_lapd_n_s,
		  { "N(S)", "lapd.control.n_s", FT_UINT16, BASE_DEC,
		    NULL, XDLC_N_S_EXT_MASK, NULL, HFILL }},

		{ &hf_lapd_p,
		  { "Poll", "lapd.control.p", FT_BOOLEAN, 8,
		    TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},

		{ &hf_lapd_p_ext,
		  { "Poll", "lapd.control.p", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), XDLC_P_F_EXT, NULL, HFILL }},

		{ &hf_lapd_f,
		  { "Final", "lapd.control.f", FT_BOOLEAN, 8,
		    TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},

		{ &hf_lapd_f_ext,
		  { "Final", "lapd.control.f", FT_BOOLEAN, 16,
		    TFS(&tfs_set_notset), XDLC_P_F_EXT, NULL, HFILL }},

		{ &hf_lapd_s_ftype,
		  { "Supervisory frame type", "lapd.control.s_ftype", FT_UINT16, BASE_HEX,
		    VALS(stype_vals), XDLC_S_FTYPE_MASK, NULL, HFILL }},

		{ &hf_lapd_u_modifier_cmd,
		  { "Command", "lapd.control.u_modifier_cmd", FT_UINT8, BASE_HEX,
		    VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

		{ &hf_lapd_u_modifier_resp,
		  { "Response", "lapd.control.u_modifier_resp", FT_UINT8, BASE_HEX,
		    VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

		{ &hf_lapd_ftype_i,
		  { "Frame type", "lapd.control.ftype", FT_UINT16, BASE_HEX,
		    VALS(ftype_vals), XDLC_I_MASK, NULL, HFILL }},

		{ &hf_lapd_ftype_s_u,
		  { "Frame type", "lapd.control.ftype", FT_UINT8, BASE_HEX,
		    VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},

		{ &hf_lapd_ftype_s_u_ext,
		  { "Frame type", "lapd.control.ftype", FT_UINT16, BASE_HEX,
		    VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},

		{ &hf_lapd_checksum,
		  { "Checksum", "lapd.checksum", FT_UINT16, BASE_HEX,
		    NULL, 0x0, "Details at: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},

		{ &hf_lapd_checksum_status,
		  { "Checksum Status", "lapd.checksum.status", FT_UINT8, BASE_NONE,
		    VALS(proto_checksum_vals), 0x0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_lapd,
		&ett_lapd_address,
		&ett_lapd_control,
		&ett_lapd_checksum
	};

	static ei_register_info ei[] = {
		{ &ei_lapd_abort, { "lapd.abort.expert", PI_PROTOCOL, PI_ERROR, "Formatted message", EXPFILL }},
		{ &ei_lapd_checksum_bad, { "lapd.checksum_bad.expert", PI_CHECKSUM, PI_WARN, "Bad FCS", EXPFILL }},
	};

	module_t *lapd_module;
	expert_module_t* expert_lapd;

	proto_lapd = proto_register_protocol("Link Access Procedure, Channel D (LAPD)",
					     "LAPD", "lapd");
	proto_register_field_array (proto_lapd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_lapd = expert_register_protocol(proto_lapd);
	expert_register_field_array(expert_lapd, ei, array_length(ei));

	lapd_handle = create_dissector_handle(dissect_lapd, proto_lapd);
	lapd_phdr_handle = register_dissector("lapd-phdr", dissect_lapd_phdr, proto_lapd);
	linux_lapd_handle = register_dissector("linux-lapd", dissect_linux_lapd, proto_lapd);
	lapd_bitstream_handle = register_dissector("lapd-bitstream", dissect_lapd_bitstream, proto_lapd);

	lapd_sapi_dissector_table = register_dissector_table("lapd.sapi",
							     "LAPD SAPI", proto_lapd, FT_UINT16, BASE_DEC);

	lapd_gsm_sapi_dissector_table = register_dissector_table("lapd.gsm.sapi",
								 "LAPD GSM SAPI", proto_lapd, FT_UINT16, BASE_DEC);

	lapd_module = prefs_register_protocol(proto_lapd, proto_reg_handoff_lapd);

	prefs_register_bool_preference(lapd_module, "use_gsm_sapi_values",
				       "Use GSM SAPI values",
				       "Use SAPI values as specified in TS 48 056",
				       &global_lapd_gsm_sapis);
	prefs_register_range_preference(lapd_module, "rtp_payload_type",
				       "RTP payload types for embedded LAPD",
				       "RTP payload types for embedded LAPD"
				       "; values must be in the range 1 - 127",
				       &pref_lapd_rtp_payload_type_range, 127);
	prefs_register_uint_preference(lapd_module, "sctp_payload_protocol_identifier",
				       "SCTP Payload Protocol Identifier for LAPD",
				       "SCTP Payload Protocol Identifier for LAPD. It is a "
				       "32 bits value from 0 to 4294967295. Set it to 0 to disable.",
				       10, &pref_lapd_sctp_ppi);
}

void
proto_reg_handoff_lapd(void)
{
	static gboolean init = FALSE;
	static range_t* lapd_rtp_payload_type_range = NULL;
	static guint lapd_sctp_ppi;
	dissector_handle_t lapd_frame_handle;

	if (!init) {
		dissector_add_uint("wtap_encap", WTAP_ENCAP_LINUX_LAPD, linux_lapd_handle);

		lapd_frame_handle = create_dissector_handle(dissect_lapd_frame, proto_lapd);
		dissector_add_uint("wtap_encap", WTAP_ENCAP_LAPD, lapd_frame_handle);

		dissector_add_uint("l2tp.pw_type", L2TPv3_PROTOCOL_LAPD, lapd_handle);
		dissector_add_for_decode_as("sctp.ppi", lapd_handle);
		dissector_add_for_decode_as("sctp.port", lapd_handle);
		dissector_add_uint_range_with_preference("udp.port", "", lapd_handle);

		init = TRUE;
	} else {
		dissector_delete_uint_range("rtp.pt", lapd_rtp_payload_type_range, lapd_bitstream_handle);
		wmem_free(wmem_epan_scope(), lapd_rtp_payload_type_range);

		if (lapd_sctp_ppi > 0)
			dissector_delete_uint("sctp.ppi", lapd_sctp_ppi, lapd_handle);
	}

	lapd_rtp_payload_type_range = range_copy(wmem_epan_scope(), pref_lapd_rtp_payload_type_range);
	range_remove_value(wmem_epan_scope(), &lapd_rtp_payload_type_range, 0);
	dissector_add_uint_range("rtp.pt", lapd_rtp_payload_type_range, lapd_bitstream_handle);

	lapd_sctp_ppi = pref_lapd_sctp_ppi;
	if (lapd_sctp_ppi > 0)
		dissector_add_uint("sctp.ppi", lapd_sctp_ppi, lapd_handle);

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
