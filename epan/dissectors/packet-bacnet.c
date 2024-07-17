/* packet-bacnet.c
 * Routines for BACnet (NPDU) dissection
 * Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
 * Enhanced by Steve Karg, 2005, <skarg@users.sourceforge.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer,v 1.23
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/llcsaps.h>
#include "packet-bacnet.h"

void proto_register_bacnet(void);
void proto_reg_handoff_bacnet(void);

static dissector_handle_t bacapp_handle;
/* Defined to allow vendor identifier registration of private transfer dissectors */
static dissector_table_t bacnet_dissector_table;

static const range_string bacnet_msgtype_rvals[] = {
	{ 0x00, 0x00, "Who-Is-Router-To-Network" },
	{ 0x01, 0x01, "I-Am-Router-To-Network" },
	{ 0x02, 0x02, "I-Could-Be-Router-To-Network" },
	{ 0x03, 0x03, "Reject-Message-To-Network" },
	{ 0x04, 0x04, "Router-Busy-To-Network" },
	{ 0x05, 0x05, "Router-Available-To-Network" },
	{ 0x06, 0x06, "Initialize-Routing-Table" },
	{ 0x07, 0x07, "Initialize-Routing-Table-Ack" },
	{ 0x08, 0x08, "Establish-Connection-To-Network" },
	{ 0x09, 0x09, "Disconnect-Connection-To-Network" },
	{ 0x0A, 0x0A, "Challenge-Request" },
	{ 0x0B, 0x0B, "Security-Payload" },
	{ 0x0C, 0x0C, "Security-Response" },
	{ 0x0D, 0x0D, "Request-Key-Update" },
	{ 0x0E, 0x0E, "Update-Keyset" },
	{ 0x0F, 0x0F, "Update-distribution-Key" },
	{ 0x10, 0x10, "Request-Masterkey" },
	{ 0x11, 0x11, "Set-Masterkey" },
	{ 0x12, 0x12, "What-Is-Networknumber" },
	{ 0x13, 0x13, "Networknumber-Is" },
	{ 0x14, 0x7F, "Reserved for Use by ASHRAE" },
	{ 0x80, 0xFF, "Vendor Proprietary Message" },
	{ 0, 0, NULL }
};

static const range_string bacnet_rejectreason_name_rvals[] = {
	{ 0x00, 0x00, "Other error." },
	{ 0x01, 0x01, "The router is not directly connected to DNET and cannot find a router to DNET on any directly connected network using Who-Is-Router-To-Network messages." },
	{ 0x02, 0x02, "The router is busy and unable to accept messages for the specified DNET at the present time." },
	{ 0x03, 0x03, "It is an unknown network layer message type." },
	{ 0x04, 0x04, "The message is too long to be routed to this DNET." },
	{ 0x05, 0x05, "The router is no longer directly connected to DNET but can reconnect if requested." },
	{ 0x06, 0x06, "The router is no longer directly connected to DNET and cannot reconnect even if requested." },
	{ 0x07, 0xFF, "Invalid Rejection Reason." },
	{ 0, 0, NULL }
};

/* Network Layer Control Information */
#define BAC_CONTROL_NET		0x80
#define BAC_CONTROL_RES1	0x40
#define BAC_CONTROL_DEST	0x20
#define BAC_CONTROL_RES2	0x10
#define BAC_CONTROL_SRC		0x08
#define BAC_CONTROL_EXPECT	0x04
#define BAC_CONTROL_PRIO_HIGH	0x02
#define BAC_CONTROL_PRIO_LOW	0x01

/* Network Layer Wrapper Control Information */
#define BAC_WRAPPER_CONTROL_NET		0x80
#define BAC_WRAPPER_MSG_ENCRYPED	0x40
#define BAC_WRAPPER_RESERVED		0x20
#define BAC_WRAPPER_AUTHD_PRESENT	0x10
#define BAC_WRAPPER_DO_NOT_UNWRAP	0x08
#define BAC_WRAPPER_DO_NOT_DECRPT	0x04
#define BAC_WRAPPER_NO_TRUST_SRC	0x02
#define BAC_WRAPPER_SECURE_BY_RTR	0x01

/* Network Layer Update Keyset Control Information */
#define BAC_UPDATE_CONTROL_SET1_TIMES_PRESENT		0x80
#define BAC_UPDATE_CONTROL_SET1_PARAMS_PRESENT		0x40
#define BAC_UPDATE_CONTROL_CLEAR_SET1				0x20
#define BAC_UPDATE_CONTROL_SET2_TIMES_PRESENT		0x10
#define BAC_UPDATE_CONTROL_SET2_PARAMS_PRESENT		0x08
#define BAC_UPDATE_CONTROL_CLEAR_SET2				0x04
#define BAC_UPDATE_CONTROL_MORE_FOLLOWS				0x02
#define BAC_UPDATE_CONTROL_REMOVE_KEYS				0x01

/* Network Layer Message Types */
#define BAC_NET_WHO_R		0x00
#define BAC_NET_IAM_R		0x01
#define BAC_NET_ICB_R		0x02
#define BAC_NET_REJ			0x03
#define BAC_NET_R_BUSY		0x04
#define BAC_NET_R_AVA		0x05
#define BAC_NET_INIT_RTAB	0x06
#define BAC_NET_INIT_RTAB_ACK	0x07
#define BAC_NET_EST_CON		0x08
#define BAC_NET_DISC_CON	0x09
#define BAC_NET_CHALL_REQ	0x0A
#define BAC_NET_SECUR_PAY	0x0B
#define BAC_NET_SECUR_RESP	0x0C
#define BAC_NET_REQ_KEY_UP	0x0D
#define BAC_NET_UPD_KEYSET	0x0E
#define BAC_NET_UPD_DKEY	0x0F
#define BAC_NET_REQ_MKEY	0x10
#define BAC_NET_SET_MKEY	0x11
#define BAC_NET_WHAT_NETNR	0x12
#define BAC_NET_NETNR_IS	0x13


static const true_false_string control_net_set_high = {
	"network layer message, message type field present.",
	"BACnet APDU, message type field absent."
};

static const true_false_string control_res_high = {
	"Shall be zero, but is one.",
	"Shall be zero and is zero."
};
static const true_false_string control_dest_high = {
	"DNET, DLEN and Hop Count present. If DLEN=0: broadcast, dest. address field absent.",
	"DNET, DLEN, DADR and Hop Count absent."
};

static const true_false_string control_src_high = {
	"SNET, SLEN and SADR present, SLEN=0 invalid, SLEN specifies length of SADR",
	"SNET, SLEN and SADR absent"
};

static const true_false_string control_expect_high = {
	"BACnet-Confirmed-Request-PDU, a segment of BACnet-ComplexACK-PDU or Network Message expecting a reply present.",
	"Other than a BACnet-Confirmed-Request-PDU, segment of BACnet-ComplexACK-PDU or network layer message expecting a reply present."
};

static const true_false_string control_prio_high_high = {
	"Life Safety or Critical Equipment message.",
	"Not a Life Safety or Critical Equipment message."
};

static const true_false_string control_prio_low_high = {
	"Urgent message",
	"Normal message"
};

static const true_false_string wrapper_control_msg_net = {
	"Message is networklayer message",
	"Message is applicationlayer message"
};

static const true_false_string wrapper_control_msg_crypted = {
	"Message is encrypted message",
	"Message is not encrypted message"
};

static const true_false_string wrapper_control_reserved = {
	"Shall be zero, but is one.",
	"Shall be zero and is zero."
};

static const true_false_string wrapper_control_do_not_unwrap = {
	"Do not unwrap message",
	"Message may be unwrapped"
};

static const true_false_string wrapper_control_do_not_decrypt = {
	"Do not decrypt message",
	"Message may be decrypted"
};

static const true_false_string wrapper_control_trusted_source = {
	"Message received from trusted source",
	"Message received from untrusted source"
};

static const true_false_string security_msg_challenged = {
	"Message is challenged",
	"Message is not challenged"
};

static const true_false_string update_key_control_remove_keys = {
	"Do Remove Keys",
	"Do Not Remove Keys"
};

static const true_false_string tfs_clear_do_not_clear = {
	"Clear",
	"Do Not Clear"
};

static int proto_bacnet;
static int hf_bacnet_version;
static int hf_bacnet_control;
static int hf_bacnet_control_net;
static int hf_bacnet_control_res1;
static int hf_bacnet_control_dest;
static int hf_bacnet_control_res2;
static int hf_bacnet_control_src;
static int hf_bacnet_control_expect;
static int hf_bacnet_control_prio_high;
static int hf_bacnet_control_prio_low;
static int hf_bacnet_dnet;
static int hf_bacnet_dlen;
static int hf_bacnet_dadr_eth;
static int hf_bacnet_dadr_mstp;
static int hf_bacnet_dadr_tmp;
static int hf_bacnet_snet;
static int hf_bacnet_slen;
static int hf_bacnet_sadr_eth;
static int hf_bacnet_sadr_mstp;
static int hf_bacnet_sadr_tmp;
static int hf_bacnet_hopc;
static int hf_bacnet_mesgtyp;
static int hf_bacnet_vendor;
static int hf_bacnet_perf;
static int hf_bacnet_rejectreason;
static int hf_bacnet_rportnum;
static int hf_bacnet_portid;
static int hf_bacnet_pinfo;
static int hf_bacnet_pinfolen;
static int hf_bacnet_term_time_value;
static int hf_bacnet_netno_status;

static int hf_bacnet_wrapper_control;
static int hf_bacnet_wrapper_control_secured_by_router;
static int hf_bacnet_wrapper_control_non_trusted_source;
static int hf_bacnet_wrapper_control_do_not_decrypt;
static int hf_bacnet_wrapper_control_do_not_unwrap;
static int hf_bacnet_wrapper_control_auth_data_present;
static int hf_bacnet_wrapper_control_reserved;
static int hf_bacnet_wrapper_control_msg_is_encrypted;
static int hf_bacnet_wrapper_control_msg_is_networklayer;
static int hf_bacnet_wrapper_key_revision;
static int hf_bacnet_wrapper_key_identifier;
static int hf_bacnet_wrapper_src_dev_instance;
static int hf_bacnet_wrapper_message_id;
static int hf_bacnet_wrapper_time_stamp;
static int hf_bacnet_wrapper_dst_dev_instance;
static int hf_bacnet_wrapper_dnet;
static int hf_bacnet_wrapper_dlen;
static int hf_bacnet_wrapper_dadr;
static int hf_bacnet_wrapper_snet;
static int hf_bacnet_wrapper_slen;
static int hf_bacnet_wrapper_sadr;
static int hf_bacnet_wrapper_auth_mech;
static int hf_bacnet_wrapper_auth_usr_id;
static int hf_bacnet_wrapper_auth_usr_role;
static int hf_bacnet_wrapper_auth_len;
static int hf_bacnet_wrapper_auth_data;
static int hf_bacnet_wrapper_signature;
static int hf_bacnet_wrapper_encrypted_data;
static int hf_bacnet_msg_is_challenged;
static int hf_bacnet_security_original_message_id;
static int hf_bacnet_security_original_time_stamp;
static int hf_bacnet_security_msg_len;
static int hf_bacnet_security_response_code;
static int hf_bacnet_security_response_expected_time_stamp;
static int hf_bacnet_security_response_key_algo;
static int hf_bacnet_security_response_key_id;
static int hf_bacnet_security_response_original_authentication_mech;
static int hf_bacnet_security_response_vendor_id;
static int hf_bacnet_security_response_key_revision;
static int hf_bacnet_security_response_number_keys;
static int hf_bacnet_security_set1_key_reveision;
static int hf_bacnet_security_set1_activation_time_stamp;
static int hf_bacnet_security_set1_expiration_time_stamp;
static int hf_bacnet_security_set1_key_algo;
static int hf_bacnet_security_set1_key_id;
static int hf_bacnet_security_set1_key_data;
static int hf_bacnet_security_set2_key_reveision;
static int hf_bacnet_security_set2_activation_time_stamp;
static int hf_bacnet_security_set2_expiration_time_stamp;
static int hf_bacnet_security_set2_key_algo;
static int hf_bacnet_security_set2_key_id;
static int hf_bacnet_security_set2_key_data;
static int hf_bacnet_security_dist_key_revision;
static int hf_bacnet_security_dist_key_algo;
static int hf_bacnet_security_dist_key_id;
static int hf_bacnet_security_dist_key_data;
static int hf_bacnet_security_master_key_algo;
static int hf_bacnet_security_master_key_id;
static int hf_bacnet_security_master_key_data;
static int hf_bacnet_update_control;
static int hf_bacnet_update_control_remove;
static int hf_bacnet_update_control_more_follows;
static int hf_bacnet_update_control_clear_set2;
static int hf_bacnet_update_control_set2_params_present;
static int hf_bacnet_update_control_set2_times_present;
static int hf_bacnet_update_control_clear_set1;
static int hf_bacnet_update_control_set1_params_present;
static int hf_bacnet_update_control_set1_times_present;

static int ett_bacnet;
static int ett_bacnet_control;
static int ett_bacnet_wrapper_control;
static int ett_bacnet_update_control;

static dissector_handle_t bacnet_handle;

static int * const control_flags[] = {
	&hf_bacnet_control_net,
	&hf_bacnet_control_res1,
	&hf_bacnet_control_dest,
	&hf_bacnet_control_res2,
	&hf_bacnet_control_src,
	&hf_bacnet_control_expect,
	&hf_bacnet_control_prio_high,
	&hf_bacnet_control_prio_low,
	NULL
};

static int * const update_control_flags[] = {
	&hf_bacnet_update_control_remove,
	&hf_bacnet_update_control_more_follows,
	&hf_bacnet_update_control_clear_set2,
	&hf_bacnet_update_control_set2_params_present,
	&hf_bacnet_update_control_set2_times_present,
	&hf_bacnet_update_control_clear_set1,
	&hf_bacnet_update_control_set1_params_present,
	&hf_bacnet_update_control_set1_times_present,
	NULL
};

static int * const wrapper_control_flags[] = {
	&hf_bacnet_wrapper_control_secured_by_router,
	&hf_bacnet_wrapper_control_non_trusted_source,
	&hf_bacnet_wrapper_control_do_not_decrypt,
	&hf_bacnet_wrapper_control_do_not_unwrap,
	&hf_bacnet_wrapper_control_auth_data_present,
	&hf_bacnet_wrapper_control_reserved,
	&hf_bacnet_wrapper_control_msg_is_encrypted,
	&hf_bacnet_wrapper_control_msg_is_networklayer,
	NULL
};


int
bacnet_dissect_sec_wrapper(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
					int offset, bool *pis_net_msg_flg)
{
	uint8_t bacnet_dlen;
	uint8_t bacnet_wrapper_control;
	uint16_t bacnet_len;
	int len;

	/* get control octet from wrapper */
	bacnet_wrapper_control = tvb_get_uint8(tvb, offset);
	if (pis_net_msg_flg)
		*pis_net_msg_flg = (bacnet_wrapper_control & BAC_WRAPPER_CONTROL_NET) != 0;

	proto_tree_add_bitmask(tree, tvb, offset, hf_bacnet_wrapper_control,
		ett_bacnet_wrapper_control, wrapper_control_flags, ENC_NA);
	offset++;

	proto_tree_add_item(tree, hf_bacnet_wrapper_key_revision,
		tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_bacnet_wrapper_key_identifier,
		tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_bacnet_wrapper_src_dev_instance,
		tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;

	proto_tree_add_item(tree, hf_bacnet_wrapper_message_id,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_bacnet_wrapper_time_stamp,
		tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* we only can use unencrypted data here */
	if ((bacnet_wrapper_control & BAC_WRAPPER_MSG_ENCRYPED) == 0) {
		proto_tree_add_item(tree, hf_bacnet_wrapper_dst_dev_instance,
			tvb, offset, 3, ENC_BIG_ENDIAN);
		offset += 3;

		proto_tree_add_item(tree, hf_bacnet_wrapper_dnet,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		bacnet_dlen = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_bacnet_wrapper_dlen,
			tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree,
			hf_bacnet_wrapper_dadr, tvb, offset,
			bacnet_dlen, ENC_NA);
		offset += bacnet_dlen;

		proto_tree_add_item(tree, hf_bacnet_wrapper_snet,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		bacnet_dlen = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_bacnet_wrapper_slen,
			tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(tree,
			hf_bacnet_wrapper_sadr, tvb, offset,
			bacnet_dlen, ENC_NA);
		offset += bacnet_dlen;

		/* additional authentication data is optional */
		if ((bacnet_wrapper_control & BAC_WRAPPER_AUTHD_PRESENT) != 0) {
			bacnet_dlen = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(tree, hf_bacnet_wrapper_auth_mech,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			proto_tree_add_item(tree, hf_bacnet_wrapper_auth_usr_id,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(tree, hf_bacnet_wrapper_auth_usr_role,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			/* extra authentication data present if authentication mechanism != 0 */
			if (bacnet_dlen != 0) {
				bacnet_len = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_bacnet_wrapper_auth_len,
					tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;

				proto_tree_add_item(tree,
					hf_bacnet_wrapper_auth_data, tvb, offset,
					bacnet_len, ENC_NA);
				offset += bacnet_len;
			}
		}

		/* signature is always present and not encryped in the last 16
		   bytes of a secured BACnet frame */
		len = tvb_reported_length_remaining(tvb, 0) - 16;
		proto_tree_add_item(tree,
			hf_bacnet_wrapper_signature, tvb, len,
			16, ENC_NA);

		/* offset is pointing to the start of the secured service data which
		   is followed by the signature which we already have listed as part
		   of the wrapper so we remove the signature now */
		tvb_set_reported_length(tvb, len);
	}
	else {
		/* signature is always present and not encryped in the last 16
		bytes of a secured BACnet frame */
		len = tvb_reported_length_remaining(tvb, 0) - 16;
		proto_tree_add_item(tree,
			hf_bacnet_wrapper_signature, tvb, len,
			16, ENC_NA);
		/* print the encrypted data now because we are not able to decode it anyway */
		len = tvb_reported_length_remaining(tvb, offset) - 16;
		proto_tree_add_item(tree,
			hf_bacnet_wrapper_encrypted_data, tvb, offset,
			len, ENC_NA);
		/* no further decoding possible */
		tvb_set_reported_length(tvb, 0);
		offset = -1;
	}

	return offset;
}


static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_bacnet_npdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *bacnet_tree;

	uint8_t bacnet_version;
	uint8_t bacnet_control;
	uint8_t bacnet_update_control;
	uint8_t bacnet_dlen;
	uint8_t bacnet_slen;
	uint8_t bacnet_mesgtyp;
	uint8_t bacnet_rportnum;
	uint8_t bacnet_pinfolen;
	uint8_t i;
	tvbuff_t *next_tvb;
	uint32_t vendor_id;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BACnet-NPDU");
	col_set_str(pinfo->cinfo, COL_INFO, "Building Automation and Control Network NPDU");

	bacnet_version = tvb_get_uint8(tvb, offset);
	bacnet_control = tvb_get_uint8(tvb, offset+1);

	/* I don't know the length of the NPDU yet; Setting the length after dissection */
	ti = proto_tree_add_item(tree, proto_bacnet, tvb, 0, -1, ENC_NA);

	bacnet_tree = proto_item_add_subtree(ti, ett_bacnet);

	proto_tree_add_uint_format_value(bacnet_tree, hf_bacnet_version, tvb,
					 offset, 1,
					 bacnet_version,"0x%02x (%s)",bacnet_version,
					 (bacnet_version == 0x01)?"ASHRAE 135-1995":"unknown");
	offset ++;
	proto_tree_add_bitmask(bacnet_tree, tvb, offset, hf_bacnet_control,
					ett_bacnet_control, control_flags, ENC_NA);
	offset ++;
	if (bacnet_control & BAC_CONTROL_DEST) { /* DNET, DLEN, DADR */
		proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		bacnet_dlen = tvb_get_uint8(tvb, offset);
		/* DLEN = 0 is broadcast on dest.network */
		if( bacnet_dlen == 0) {
			/* append to hf_bacnet_dlen: broadcast */
			proto_tree_add_uint_format_value(bacnet_tree,
			    hf_bacnet_dlen, tvb, offset, 1, bacnet_dlen,
			    "%d indicates Broadcast on Destination Network",
			    bacnet_dlen);
			offset ++;
			/* going to SNET */
		} else if (bacnet_dlen==6) {
			proto_tree_add_item(bacnet_tree, hf_bacnet_dlen,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
			/* Ethernet MAC */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_dadr_eth, tvb, offset,
				bacnet_dlen, ENC_NA);
			offset += bacnet_dlen;
		} else if (bacnet_dlen==1) {
			proto_tree_add_item(bacnet_tree, hf_bacnet_dlen,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
			/* MS/TP or ARCNET MAC */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_dadr_mstp, tvb, offset,
				bacnet_dlen, ENC_BIG_ENDIAN);
			offset += bacnet_dlen;
		} else if (bacnet_dlen<7) {
			proto_tree_add_item(bacnet_tree, hf_bacnet_dlen,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
			/* Other MAC formats should be included here */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_dadr_tmp, tvb, offset,
				bacnet_dlen, ENC_NA);
			offset += bacnet_dlen;
		} else {
			proto_tree_add_uint_format_value(bacnet_tree,
			    hf_bacnet_dlen, tvb, offset, 1, bacnet_dlen,
			    "%d invalid!",
			    bacnet_dlen);
		}
	}
	if (bacnet_control & BAC_CONTROL_SRC) { /* SNET, SLEN, SADR */
		/* SNET */
		proto_tree_add_item(bacnet_tree, hf_bacnet_snet,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		bacnet_slen = tvb_get_uint8(tvb, offset);
		if( bacnet_slen == 0) { /* SLEN = 0 invalid */
			proto_tree_add_uint_format_value(bacnet_tree,
			    hf_bacnet_slen, tvb, offset, 1, bacnet_slen,
			    "%d invalid!",
			    bacnet_slen);
			offset ++;
		} else if (bacnet_slen==6) {
			/* SLEN */
			 proto_tree_add_item(bacnet_tree, hf_bacnet_slen,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
			/* Ethernet MAC */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_sadr_eth, tvb, offset,
				bacnet_slen, ENC_NA);
			offset += bacnet_slen;
		} else if (bacnet_slen==1) {
			/* SLEN */
			 proto_tree_add_item(bacnet_tree, hf_bacnet_slen,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
			/* MS/TP or ARCNET MAC */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_sadr_mstp, tvb, offset,
				bacnet_slen, ENC_BIG_ENDIAN);
			offset += bacnet_slen;
		} else if (bacnet_slen<6) { /* LON MAC */
			/* SLEN */
			 proto_tree_add_item(bacnet_tree, hf_bacnet_slen,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
			/* Other MAC formats should be included here */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_sadr_tmp, tvb, offset,
				bacnet_slen, ENC_NA);
			offset += bacnet_slen;
		} else {
			proto_tree_add_uint_format_value(bacnet_tree,
			hf_bacnet_slen, tvb, offset, 1, bacnet_slen,
			    "%d invalid!",
			    bacnet_slen);
			offset ++;
		}
	}
	if (bacnet_control & BAC_CONTROL_DEST) { /* Hopcount */
		proto_tree_add_item(bacnet_tree, hf_bacnet_hopc,
			tvb, offset, 1, ENC_BIG_ENDIAN);
		offset ++;
	}
	/* Network Layer Message Type */
	if (bacnet_control & BAC_CONTROL_NET) {
		bacnet_mesgtyp =  tvb_get_uint8(tvb, offset);
		proto_tree_add_uint(bacnet_tree, hf_bacnet_mesgtyp, tvb, offset, 1, bacnet_mesgtyp);
		/* Put the NPDU Type in the info column */
		col_add_str(pinfo->cinfo, COL_INFO, rval_to_str_const(bacnet_mesgtyp, bacnet_msgtype_rvals, "Unknown"));
		offset++;
		switch (bacnet_mesgtyp) {
		/* Performance Index (in I-Could-Be-Router-To-Network) */
		case BAC_NET_ICB_R:
			proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(bacnet_tree, hf_bacnet_perf,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
			break;
		/* Reason, DNET (in Reject-Message-To-Network) */
		case BAC_NET_REJ:
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_rejectreason,
				tvb, offset, 1, ENC_NA);
			offset ++;
			proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			break;
		/* N*DNET (in Router-Busy-To-Network,Router-Available-To-Network) */
		case BAC_NET_R_BUSY:
		case BAC_NET_WHO_R:
		case BAC_NET_R_AVA:
		case BAC_NET_IAM_R:
			while(tvb_reported_length_remaining(tvb, offset) > 1 ) {
				proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
					tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
			}
			break;
		/* Initialize-Routing-Table */
		case BAC_NET_INIT_RTAB:
		case BAC_NET_INIT_RTAB_ACK:
			bacnet_rportnum = tvb_get_uint8(tvb, offset);
			/* number of ports */
			proto_tree_add_item(bacnet_tree, hf_bacnet_rportnum,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
			for (i = 0; tvb_reported_length_remaining(tvb, offset) > 1 && i < bacnet_rportnum; i++) {
					/* Connected DNET */
					proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
					tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
					/* Port ID */
					proto_tree_add_item(bacnet_tree, hf_bacnet_portid,
					tvb, offset, 1, ENC_BIG_ENDIAN);
					offset ++;
					/* Port Info Length */
					bacnet_pinfolen = tvb_get_uint8(tvb, offset);
					proto_tree_add_item(bacnet_tree, hf_bacnet_pinfolen,
					tvb, offset, 1, ENC_BIG_ENDIAN);
					offset ++;
					proto_tree_add_item(bacnet_tree, hf_bacnet_pinfo, tvb, offset,
					bacnet_pinfolen, ENC_NA);
					offset += bacnet_pinfolen;
			}
			break;
		/* Establish-Connection-To-Network */
		case BAC_NET_EST_CON:
			proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(bacnet_tree, hf_bacnet_term_time_value,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
			break;
		/* Disconnect-Connection-To-Network */
		case BAC_NET_DISC_CON:
			proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			break;
		/* What-Is-Networknumber */
		case BAC_NET_WHAT_NETNR:
			break;
		/* Networknumber-Is */
		case BAC_NET_NETNR_IS:
			proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(bacnet_tree, hf_bacnet_netno_status,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		/* Challenge-Request */
		case BAC_NET_CHALL_REQ:
			offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
			if (offset < 0) {
				call_data_dissector(tvb, pinfo, tree);
				return tvb_captured_length(tvb);
			}

			proto_tree_add_item(tree, hf_bacnet_msg_is_challenged,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			proto_tree_add_item(tree, hf_bacnet_security_original_message_id,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(tree, hf_bacnet_security_original_time_stamp,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		/* Security-Payload */
		case BAC_NET_SECUR_PAY:
		{
			bool is_net_msg_flg;
			uint16_t bacnet_len;

			offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, &is_net_msg_flg);
			if (offset < 0) {
				call_data_dissector(tvb, pinfo, tree);
				return tvb_captured_length(tvb);
			}
			/* get payload length */
			bacnet_len = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_bacnet_security_msg_len,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			/* set length to reported length in header */
			tvb_set_reported_length(tvb, bacnet_len);
			if (is_net_msg_flg) {
				/* decode network layer message */
				increment_dissection_depth(pinfo);
				int npdu_len = dissect_bacnet_npdu(tvb, pinfo, tree, offset);
				decrement_dissection_depth(pinfo);
				return npdu_len;
			}
			/* APDU - call the APDU dissector */
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			call_dissector(bacapp_handle, next_tvb, pinfo, tree);
			return tvb_captured_length(tvb);
		}
		/* Security-Response */
		case BAC_NET_SECUR_RESP:
		{
			uint8_t bacnet_responsecode;

			offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
			if (offset < 0) {
				call_data_dissector(tvb, pinfo, tree);
				return tvb_captured_length(tvb);
			}

			bacnet_responsecode = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(tree, hf_bacnet_security_response_code,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			proto_tree_add_item(tree, hf_bacnet_security_original_message_id,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(tree, hf_bacnet_security_original_time_stamp,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			switch (bacnet_responsecode)
			{
			case 0x00: /* success */
			case 0x01: /* accessDenied */
			case 0x02: /* badDestinationAddress */
			case 0x03: /* badDestinationDeviceId */
			case 0x04: /* badSignature */
			case 0x05: /* badSourceAddress */
			case 0x08: /* cannotVerifyMessageId */
			case 0x09: /* correctKeyRevision */
			case 0x0A: /* destinationDeviceIdRequired */
			case 0x0B: /* duplicateMessage */
			case 0x0C: /* encryptionNotConfigured */
			case 0x0D: /* encryptionRequired */
			case 0x10: /* keyUpdateInProgress */
			case 0x11: /* malformedMessage */
			case 0x12: /* notKeyServer */
			case 0x13: /* securityNotConfigured */
			case 0x14: /* sourceSecurityRequired */
			case 0x19: /* unknownSourceMessage */
			default:
				/* no parameters are expected here */
				break;
			case 0x06: /* badTimestamp */
				proto_tree_add_item(tree, hf_bacnet_security_response_expected_time_stamp,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				break;
			case 0x07: /* cannotUseKey */
			case 0x0F: /* invalidKeyData */
			case 0x17: /* unknownKey */
				proto_tree_add_item(tree, hf_bacnet_security_response_key_algo,
					tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				proto_tree_add_item(tree, hf_bacnet_security_response_key_id,
					tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				break;
			case 0x0E: /* incorrectKey */
				bacnet_responsecode = tvb_get_uint8(tvb, offset);
				offset++;
				while (tvb_reported_length_remaining(tvb, offset) > 1 && bacnet_responsecode > 0) {
					proto_tree_add_item(tree, hf_bacnet_security_response_key_algo,
						tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;
					proto_tree_add_item(tree, hf_bacnet_security_response_key_id,
						tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;
					bacnet_responsecode--;
				}
				break;
			case 0x16: /* unknownAuthenticationType */
				proto_tree_add_item(tree, hf_bacnet_security_response_original_authentication_mech,
					tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				proto_tree_add_item(tree, hf_bacnet_security_response_vendor_id,
					tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				break;
			case 0x18: /* unknownKeyRevision */
				proto_tree_add_item(tree, hf_bacnet_security_response_key_revision,
					tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				break;
			case 0x15: /* tooManyKeys */
				proto_tree_add_item(tree, hf_bacnet_security_response_number_keys,
					tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				break;
			}
		}
			break;
		/* Request-Key-Update */
		case BAC_NET_REQ_KEY_UP:
			offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
			if (offset < 0) {
				call_data_dissector(tvb, pinfo, tree);
				return tvb_captured_length(tvb);
			}

			proto_tree_add_item(tree, hf_bacnet_security_set1_key_reveision,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(tree, hf_bacnet_security_set1_activation_time_stamp,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_bacnet_security_set1_expiration_time_stamp,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(tree, hf_bacnet_security_set2_key_reveision,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(tree, hf_bacnet_security_set2_activation_time_stamp,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(tree, hf_bacnet_security_set2_expiration_time_stamp,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(tree, hf_bacnet_security_dist_key_revision,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		/* Update-Keyset */
		case BAC_NET_UPD_KEYSET:
			offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
			if (offset < 0) {
				call_data_dissector(tvb, pinfo, tree);
				return tvb_captured_length(tvb);
			}

			bacnet_update_control = tvb_get_uint8(tvb, offset);
			proto_tree_add_bitmask(tree, tvb, offset, hf_bacnet_update_control,
				ett_bacnet_update_control, update_control_flags, ENC_NA);
			offset++;

			if (bacnet_update_control & BAC_UPDATE_CONTROL_SET1_TIMES_PRESENT) {
				proto_tree_add_item(tree, hf_bacnet_security_set1_key_reveision,
					tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				proto_tree_add_item(tree, hf_bacnet_security_set1_activation_time_stamp,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(tree, hf_bacnet_security_set1_expiration_time_stamp,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}

			if (bacnet_update_control & BAC_UPDATE_CONTROL_SET1_PARAMS_PRESENT) {
				uint8_t keycount;

				keycount = tvb_get_uint8(tvb, offset);
				offset++;

				for (i = 0; tvb_reported_length_remaining(tvb, offset) > 1 && i < keycount; i++)	{
					proto_tree_add_item(tree, hf_bacnet_security_set1_key_algo,
						tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;
					proto_tree_add_item(tree, hf_bacnet_security_set1_key_id,
						tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;

					bacnet_dlen = tvb_get_uint8(tvb, offset);
					offset++;

					proto_tree_add_item(tree,
						hf_bacnet_security_set1_key_data, tvb, offset,
						bacnet_dlen, ENC_NA);
					offset += bacnet_dlen;
				}
			}

			if (bacnet_update_control & BAC_UPDATE_CONTROL_SET2_TIMES_PRESENT) {
				proto_tree_add_item(tree, hf_bacnet_security_set2_key_reveision,
					tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				proto_tree_add_item(tree, hf_bacnet_security_set2_activation_time_stamp,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(tree, hf_bacnet_security_set2_expiration_time_stamp,
					tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}

			if (bacnet_update_control & BAC_UPDATE_CONTROL_SET2_PARAMS_PRESENT) {
				uint8_t keycount;

				keycount = tvb_get_uint8(tvb, offset);
				offset++;

				for (i = 0; tvb_reported_length_remaining(tvb, offset) > 1 && i < keycount; i++)	{
					proto_tree_add_item(tree, hf_bacnet_security_set2_key_algo,
						tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;
					proto_tree_add_item(tree, hf_bacnet_security_set2_key_id,
						tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;

					bacnet_dlen = tvb_get_uint8(tvb, offset);
					offset++;

					proto_tree_add_item(tree,
						hf_bacnet_security_set2_key_data, tvb, offset,
						bacnet_dlen, ENC_NA);
					offset += bacnet_dlen;
				}
			}
			break;
		/* Update-distribution-Key */
		case BAC_NET_UPD_DKEY:
			offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
			if (offset < 0) {
				call_data_dissector(tvb, pinfo, tree);
				return tvb_captured_length(tvb);
			}

			proto_tree_add_item(tree, hf_bacnet_security_dist_key_revision,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(tree, hf_bacnet_security_dist_key_algo,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(tree, hf_bacnet_security_dist_key_id,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			bacnet_dlen = tvb_get_uint8(tvb, offset);
			offset++;

			proto_tree_add_item(tree,
				hf_bacnet_security_dist_key_data, tvb, offset,
				bacnet_dlen, ENC_NA);
			offset += bacnet_dlen;
			break;
		/* Request-Masterkey */
		case BAC_NET_REQ_MKEY:
		{
			uint8_t keycount;

			offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
			if (offset < 0) {
				call_data_dissector(tvb, pinfo, tree);
				return tvb_captured_length(tvb);
			}

			keycount = tvb_get_uint8(tvb, offset);
			offset++;
			while (tvb_reported_length_remaining(tvb, offset) > 1 && keycount > 0) {
				proto_tree_add_item(tree, hf_bacnet_security_master_key_algo,
					tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				keycount--;
			}
			break;
		}
		/* Set-Masterkey */
		case BAC_NET_SET_MKEY:
			offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
			if (offset < 0) {
				call_data_dissector(tvb, pinfo, tree);
				return tvb_captured_length(tvb);
			}

			proto_tree_add_item(tree, hf_bacnet_security_master_key_algo,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item(tree, hf_bacnet_security_master_key_id,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			bacnet_dlen = tvb_get_uint8(tvb, offset);
			offset++;

			proto_tree_add_item(tree,
				hf_bacnet_security_master_key_data, tvb, offset,
				bacnet_dlen, ENC_NA);
			offset += bacnet_dlen;
			break;
		default:
			/* Vendor ID
			* The standard says: "If Bit 7 of the control octet is 1 and
			* the Message Type field contains a value in the range
			* X'80' - X'FF', then a Vendor ID field shall be present (...)."
			* We should not go any further in dissecting the packet if it's
			* not present, but we don't know about that: No length field...
			*/
			if (bacnet_mesgtyp > 0x7f) {
				/* Note: our next_tvb includes message type and vendor id! */
				next_tvb = tvb_new_subset_remaining(tvb, offset-1);
				vendor_id = tvb_get_ntohs(tvb, offset);
				proto_tree_add_item(bacnet_tree, hf_bacnet_vendor, tvb,
						offset, 2, ENC_BIG_ENDIAN);
				offset += 2;	/* vendor_id */
				if (dissector_try_uint(bacnet_dissector_table,
						vendor_id, next_tvb, pinfo, bacnet_tree)) {
						/* we parsed it so skip over length and we are done */
						/* Note: offset has now been bumped for message type and vendor
						   id so we take that out of our next_tvb size */
						offset += tvb_reported_length(next_tvb) -3;
				}
			}
			break;
		}
	}

	/* Now set NPDU length */
	proto_item_set_len(ti, offset);

	/* dissect BACnet APDU */
	next_tvb = tvb_new_subset_remaining(tvb,offset);
	if (bacnet_control & BAC_CONTROL_NET) {
		/* Unknown function - dissect the payload as data */
		call_data_dissector(next_tvb, pinfo, tree);
	} else {
		/* APDU - call the APDU dissector */
		call_dissector(bacapp_handle, next_tvb, pinfo, tree);
	}
	return tvb_captured_length(tvb);
}

static int
dissect_bacnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	return dissect_bacnet_npdu(tvb, pinfo, tree, 0);
}

void
proto_register_bacnet(void)
{
	static hf_register_info hf[] = {
		{ &hf_bacnet_version,
			{ "Version",
			"bacnet.version",
			FT_UINT8, BASE_DEC, NULL, 0,
			"BACnet Version", HFILL }
		},
		{ &hf_bacnet_control,
			{ "Control",
			"bacnet.control",
			FT_UINT8, BASE_HEX, NULL, 0,
			"BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_net,
			{ "NSDU contains",
			"bacnet.control_net",
			FT_BOOLEAN, 8, TFS(&control_net_set_high),
			BAC_CONTROL_NET, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_res1,
			{ "Reserved",
			"bacnet.control_res1",
			FT_BOOLEAN, 8, TFS(&control_res_high),
			BAC_CONTROL_RES1, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_dest,
			{ "Destination Specifier",
			"bacnet.control_dest",
			FT_BOOLEAN, 8, TFS(&control_dest_high),
			BAC_CONTROL_DEST, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_res2,
			{ "Reserved",
			"bacnet.control_res2",
			FT_BOOLEAN, 8, TFS(&control_res_high),
			BAC_CONTROL_RES2, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_src,
			{ "Source specifier",
			"bacnet.control_src",
			FT_BOOLEAN, 8, TFS(&control_src_high),
			BAC_CONTROL_SRC, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_expect,
			{ "Expecting Reply",
			"bacnet.control_expect",
			FT_BOOLEAN, 8, TFS(&control_expect_high),
			BAC_CONTROL_EXPECT, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_prio_high,
			{ "Priority",
			"bacnet.control_prio_high",
			FT_BOOLEAN, 8, TFS(&control_prio_high_high),
			BAC_CONTROL_PRIO_HIGH, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_prio_low,
			{ "Priority",
			"bacnet.control_prio_low",
			FT_BOOLEAN, 8, TFS(&control_prio_low_high),
			BAC_CONTROL_PRIO_LOW, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_dnet,
			{ "Destination Network Address",
			"bacnet.dnet",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_dlen,
			{ "Destination MAC Layer Address Length",
			"bacnet.dlen",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_dadr_eth,
			{ "Destination ISO 8802-3 MAC Address",
			"bacnet.dadr_eth",
			FT_ETHER, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_dadr_mstp,
			{ "DADR",
			"bacnet.dadr_mstp",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Destination MS/TP or ARCNET MAC Address", HFILL }
		},
		{ &hf_bacnet_dadr_tmp,
			{ "Unknown Destination MAC",
			"bacnet.dadr_tmp",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_snet,
			{ "Source Network Address",
			"bacnet.snet",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_slen,
			{ "Source MAC Layer Address Length",
			"bacnet.slen",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_sadr_eth,
			{ "SADR",
			"bacnet.sadr_eth",
			FT_ETHER, BASE_NONE, NULL, 0,
			"Source ISO 8802-3 MAC Address", HFILL }
		},
		{ &hf_bacnet_sadr_mstp,
			{ "SADR",
			"bacnet.sadr_mstp",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Source MS/TP or ARCNET MAC Address", HFILL }
		},
		{ &hf_bacnet_sadr_tmp,
			{ "Unknown Source MAC",
			"bacnet.sadr_tmp",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_hopc,
			{ "Hop Count",
			"bacnet.hopc",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_mesgtyp,
			{ "Network Layer Message Type",
			"bacnet.mesgtyp",
			FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(bacnet_msgtype_rvals), 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_vendor,
			{ "Vendor ID",
			"bacnet.vendor",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_perf,
			{ "Performance Index",
			"bacnet.perf",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_rejectreason,
			{ "Reject Reason",
			"bacnet.rejectreason",
			FT_UINT8, BASE_DEC| BASE_RANGE_STRING, RVALS(bacnet_rejectreason_name_rvals), 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_rportnum,
			{ "Number of Port Mappings",
			"bacnet.rportnum",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_pinfolen,
			{ "Port Info Length",
			"bacnet.pinfolen",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_pinfo,
			{ "Port Inf",
			"bacnet.pinfo",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_portid,
			{ "Port ID",
			"bacnet.portid",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_term_time_value,
			{ "Termination Time Value (seconds)",
			"bacnet.term_time_value",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_netno_status,
			{ "Network number status (enumerated)",
			"bacnet.netno_status",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_control,
			{ "Wrapper control",
			"bacnet.wrappercontrol",
			FT_UINT8, BASE_HEX, NULL, 0,
			"BACnet wrapper control", HFILL }
		},
		{ &hf_bacnet_wrapper_control_secured_by_router,
			{ "Secured by router",
			"bacnet.wrappercontrol_secured_by_router",
			FT_BOOLEAN, 8, TFS(&tfs_yes_no),
			BAC_WRAPPER_SECURE_BY_RTR, "BACnet wrapper control", HFILL }
		},
		{ &hf_bacnet_wrapper_control_non_trusted_source,
			{ "Non trusted source",
			"bacnet.wrappercontrol_non_trusted_source",
			FT_BOOLEAN, 8, TFS(&wrapper_control_trusted_source),
			BAC_WRAPPER_NO_TRUST_SRC, "BACnet wrapper control", HFILL }
		},
		{ &hf_bacnet_wrapper_control_do_not_decrypt,
			{ "Do not decrypt",
			"bacnet.wrappercontrol_do_not_decrypt",
			FT_BOOLEAN, 8, TFS(&wrapper_control_do_not_decrypt),
			BAC_WRAPPER_DO_NOT_DECRPT, "BACnet wrapper control", HFILL }
		},
		{ &hf_bacnet_wrapper_control_do_not_unwrap,
			{ "Do not unwrap",
			"bacnet.wrappercontrol_do_not_unwrap",
			FT_BOOLEAN, 8, TFS(&wrapper_control_do_not_unwrap),
			BAC_WRAPPER_DO_NOT_UNWRAP, "BACnet wrapper control", HFILL }
		},
		{ &hf_bacnet_wrapper_control_auth_data_present,
			{ "Authentication data present",
			"bacnet.wrappercontrol_auth_data_present",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present),
			BAC_WRAPPER_AUTHD_PRESENT, "BACnet wrapper control", HFILL }
		},
		{ &hf_bacnet_wrapper_control_reserved,
			{ "Reserved",
			"bacnet.wrappercontrol_reserved",
			FT_BOOLEAN, 8, TFS(&wrapper_control_reserved),
			BAC_WRAPPER_RESERVED, "BACnet wrapper control", HFILL }
		},
		{ &hf_bacnet_wrapper_control_msg_is_encrypted,
			{ "Message is encrypted message",
			"bacnet.wrappercontrol_msg_is_crypted",
			FT_BOOLEAN, 8, TFS(&wrapper_control_msg_crypted),
			BAC_WRAPPER_MSG_ENCRYPED, "BACnet wrapper control", HFILL }
		},
		{ &hf_bacnet_wrapper_control_msg_is_networklayer,
			{ "Message is networklayer message",
			"bacnet.wrappercontrol_msg_is_netlayer",
			FT_BOOLEAN, 8, TFS(&wrapper_control_msg_net),
			BAC_WRAPPER_CONTROL_NET, "BACnet wrapper control", HFILL }
		},
		{ &hf_bacnet_wrapper_key_revision,
			{ "Wrapper Key Revision",
			"bacnet.wrapper_key_revision",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_key_identifier,
			{ "Wrapper Key Identifier",
			"bacnet.wrapper_key_identifier",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_src_dev_instance,
			{ "Wrapper Source Device Instance",
			"bacnet.wrapper_src_device_instance",
			FT_UINT24, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_message_id,
			{ "Wrapper Message Id",
			"bacnet.wrapper_msg_id",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_time_stamp,
			{ "Wrapper Message Timestamp",
			"bacnet.wrapper_time_stamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_dst_dev_instance,
			{ "Wrapper Destination Device Instance",
			"bacnet.wrapper_dst_device_instance",
			FT_UINT24, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_dnet,
			{ "Wrapper Destination Network Address",
			"bacnet.wrapper_dnet",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_dlen,
			{ "Wrapper Destination MAC Layer Address Length",
			"bacnet.wrapper_dlen",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_dadr,
			{ "Wrapper Destination MAC",
			"bacnet.wrapper_dadr",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_snet,
			{ "Wrapper Source Network Address",
			"bacnet.wrapper_snet",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_slen,
			{ "Wrapper Source MAC Layer Address Length",
			"bacnet.wrapper_slen",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_sadr,
			{ "Wrapper Source MAC",
			"bacnet.wrapper_sadr",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_auth_mech,
			{ "Wrapper Authentication Mechanism",
			"bacnet.wrapper_auth_mech",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_auth_usr_id,
			{ "Wrapper Authentication User Id",
			"bacnet.wrapper_auth_usr_id",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_auth_usr_role,
			{ "Wrapper Authentication User Role",
			"bacnet.wrapper_auth_usr_role",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_auth_len,
			{ "Wrapper Authentication Length",
			"bacnet.wrapper_auth_len",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_auth_data,
			{ "Wrapper Authentication Data",
			"bacnet.wrapper_auth_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_signature,
			{ "Wrapper Signature",
			"bacnet.wrapper_signature",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_wrapper_encrypted_data,
			{ "Wrapper Encrypted Data",
			"bacnet.wrapper_encrypted_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_msg_is_challenged,
			{ "Message is challenged message",
			"bacnet.is_challenged_message",
			FT_BOOLEAN, 8, TFS(&security_msg_challenged),
			1, "BACnet security", HFILL }
		},
		{ &hf_bacnet_security_original_message_id,
			{ "Security Original Message Id",
			"bacnet.security_original_message_id",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_original_time_stamp,
			{ "Security Original Message Timestamp",
			"bacnet.security_original_time_stamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_msg_len,
			{ "Security Message Length",
			"bacnet.security_message_length",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_response_code,
			{ "Security Response Code",
			"bacnet.security_response_code",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_response_expected_time_stamp,
			{ "Security Expected Timestamp",
			"bacnet.security_response_expected_time_stamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_response_key_algo,
			{ "Security Response Key Algorithm",
			"bacnet.security_response_key_algorithm",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_response_key_id,
			{ "Security Response Key ID",
			"bacnet.security_response_key_id",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_response_original_authentication_mech,
			{ "Security Response Original Authentication Mechanism",
			"bacnet.security_response_original_authentication_mechanism",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_response_vendor_id,
			{ "Security Response Vendor ID",
			"bacnet.security_response_vendor_id",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_response_key_revision,
			{ "Security Response Key Revision",
			"bacnet.security_response_key_revision",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_response_number_keys,
			{ "Security Response Number Of Keys",
			"bacnet.security_response_number_of_keys",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set1_key_reveision,
			{ "Security Set 1 Key Revision",
			"bacnet.security_set1_key_revision",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set1_activation_time_stamp,
			{ "Security Set 1 Activation Timestamp",
			"bacnet.security_set1_activation_time_stamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set1_expiration_time_stamp,
			{ "Security Set 1 Expiration Timestamp",
			"bacnet.security_set1_expiration_time_stamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set1_key_algo,
			{ "Security Keyset 1 Algorithm",
			"bacnet.security_set1_key_algorithm",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set1_key_id,
			{ "Security Keyset 1 Key ID",
			"bacnet.security_set1_key_id",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set1_key_data,
			{ "Security Keyset 1 Key Data",
			"bacnet.security_set1_key_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set2_key_reveision,
			{ "Security Set 2 Key Revision",
			"bacnet.security_set2_key_revision",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set2_activation_time_stamp,
			{ "Security Set 2 Activation Timestamp",
			"bacnet.security_set2_activation_time_stamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set2_expiration_time_stamp,
			{ "Security Set 2 Expiration Timestamp",
			"bacnet.security_set2_expiration_time_stamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set2_key_algo,
			{ "Security Keyset 2 Algorithm",
			"bacnet.security_set2_key_algorithm",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set2_key_id,
			{ "Security Keyset 2 Key ID",
			"bacnet.security_set2_key_id",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_set2_key_data,
			{ "Security Keyset 2 Key Data",
			"bacnet.security_set2_key_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_dist_key_revision,
			{ "Security Distribution Key Revision",
			"bacnet.security_distribution_key_revision",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_dist_key_algo,
			{ "Security Keyset 2 Algorithm",
			"bacnet.security_distribution_key_algorithm",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_dist_key_id,
			{ "Security Keyset 2 Key ID",
			"bacnet.security_distribution_key_id",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_dist_key_data,
			{ "Security Keyset 2 Key Data",
			"bacnet.security_distribution_key_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_master_key_algo,
			{ "Security Master Key Algorithm",
			"bacnet.security_master_key_algorithm",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_master_key_id,
			{ "Security Master Key ID",
			"bacnet.security_master_key_id",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_security_master_key_data,
			{ "Security Master Key Data",
			"bacnet.security_master_key_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_update_control,
			{ "Update control",
			"bacnet.update_control",
			FT_UINT8, BASE_HEX, NULL, 0,
			"BACnet update control", HFILL }
		},
		{ &hf_bacnet_update_control_remove,
			{ "Key Update Control Remove Keys",
			"bacnet.update_control_remove_keys",
			FT_BOOLEAN, 8, TFS(&update_key_control_remove_keys),
			BAC_UPDATE_CONTROL_REMOVE_KEYS, "BACnet update keys control", HFILL }
		},
		{ &hf_bacnet_update_control_more_follows,
			{ "Key Update Control More Keys Follow",
			"bacnet.update_control_more_keys_follow",
			FT_BOOLEAN, 8, TFS(&tfs_yes_no),
			BAC_UPDATE_CONTROL_MORE_FOLLOWS, "BACnet update keys control", HFILL }
		},
		{ &hf_bacnet_update_control_clear_set2,
			{ "Key Update Control Set 2 Clear",
			"bacnet.update_control_set2_clear",
			FT_BOOLEAN, 8, TFS(&tfs_clear_do_not_clear),
			BAC_UPDATE_CONTROL_CLEAR_SET2, "BACnet update keys control", HFILL }
		},
		{ &hf_bacnet_update_control_set2_params_present,
			{ "Key Update Control Set 2 Params Present",
			"bacnet.update_control_set2_params_present",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present),
			BAC_UPDATE_CONTROL_SET2_PARAMS_PRESENT, "BACnet update keys control", HFILL }
		},
		{ &hf_bacnet_update_control_set2_times_present,
			{ "Key Update Control Set 2 Time Present",
			"bacnet.update_control_set2_time_present",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present),
			BAC_UPDATE_CONTROL_SET2_TIMES_PRESENT, "BACnet update keys control", HFILL }
		},
		{ &hf_bacnet_update_control_clear_set1,
			{ "Key Update Control Set 1 Clear",
			"bacnet.update_control_set1_clear",
			FT_BOOLEAN, 8, TFS(&tfs_clear_do_not_clear),
			BAC_UPDATE_CONTROL_CLEAR_SET1, "BACnet update keys control", HFILL }
		},
		{ &hf_bacnet_update_control_set1_params_present,
			{ "Key Update Control Set 1 Params Present",
			"bacnet.update_control_set1_params_present",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present),
			BAC_UPDATE_CONTROL_SET1_PARAMS_PRESENT, "BACnet update keys control", HFILL }
		},
		{ &hf_bacnet_update_control_set1_times_present,
			{ "Key Update Control Set 1 Time Present",
			"bacnet.update_control_set1_time_present",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present),
			BAC_UPDATE_CONTROL_SET1_TIMES_PRESENT, "BACnet update keys control", HFILL }
		},
	};

	static int *ett[] = {
		&ett_bacnet,
		&ett_bacnet_control,
		&ett_bacnet_wrapper_control,
		&ett_bacnet_update_control,
	};

	proto_bacnet = proto_register_protocol("Building Automation and Control Network NPDU", "BACnet", "bacnet");

	proto_register_field_array(proto_bacnet, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	bacnet_handle = register_dissector("bacnet", dissect_bacnet, proto_bacnet);

	bacnet_dissector_table = register_dissector_table("bacnet.vendor",
							  "BACnet Vendor Identifier", proto_bacnet,
							  FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_bacnet(void)
{
	dissector_add_uint("bvlc.function", 0x04, bacnet_handle);
	dissector_add_uint("bvlc.function", 0x09, bacnet_handle);
	dissector_add_uint("bvlc.function", 0x0a, bacnet_handle);
	dissector_add_uint("bvlc.function", 0x0b, bacnet_handle);
	dissector_add_uint("bvlc.function_ipv6", 0x01, bacnet_handle);
	dissector_add_uint("bvlc.function_ipv6", 0x02, bacnet_handle);
	dissector_add_uint("bvlc.function_ipv6", 0x0c, bacnet_handle);
	dissector_add_uint("bvlc.function_ipv6", 0x08, bacnet_handle);
	dissector_add_uint("bscvlc.function", 0x01, bacnet_handle);
	dissector_add_uint("llc.dsap", SAP_BACNET, bacnet_handle);
	bacapp_handle = find_dissector_add_dependency("bacapp", proto_bacnet);
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
