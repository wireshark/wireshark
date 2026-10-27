/* packet-mstp.c
 * Routines for BACnet MS/TP datalink dissection
 * Copyright 2008 Steve Karg <skarg@users.sourceforge.net> Alabama
 *
 * This is described in Clause 9 of ANSI/ASHRAE Standard 135-2024,
 * BACnet - A Data Communication Protocol for Building Automation
 * and Control Networks; clause 9 "describes a Multidrop Serial Bus/Token
 * Passing (MS/TP) data link protocol, which provides the same services to the
 * network layer as ISO 8802-2 Logical Link Control. It uses services
 * provided by the EIA-485 physical layer."  See section 9.3 for the
 * frame format.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>
#include <epan/address_types.h>
#include <epan/to_str.h>
#include <epan/crc16-tvb.h>
#include <epan/exceptions.h>
#include "packet-mstp.h"

void proto_register_mstp(void);
void proto_reg_handoff_mstp(void);

/* Probably should be a preference, but here for now */
#define BACNET_MSTP_SUMMARY_IN_TREE
#define BACNET_MSTP_CHECKSUM_VALIDATE

/* MS/TP Frame Type */
/* Frame Types 8 through 31 and 35 through 127 are reserved by ASHRAE. */
#define MSTP_TOKEN                                    0x00
#define MSTP_POLL_FOR_MANAGER                         0x01
#define MSTP_REPLY_TO_POLL_FOR_MANAGER                0x02
#define MSTP_TEST_REQUEST                             0x03
#define MSTP_TEST_RESPONSE                            0x04
#define MSTP_BACNET_DATA_EXPECTING_REPLY              0x05
#define MSTP_BACNET_DATA_NOT_EXPECTING_REPLY          0x06
#define MSTP_REPLY_POSTPONED                          0x07
#define MSTP_BACNET_EXTENDED_DATA_EXPECTING_REPLY     0x20
#define MSTP_BACNET_EXTENDED_DATA_NOT_EXPECTING_REPLY 0x21
#define MSTP_IPV6_ENCAPSULATION                       0x22

/* Frame Types 32 through 127 are COBS-encoded (Nmin_COBS_type through
 * Nmax_COBS_type in Clause 9). */
#define MSTP_COBS_TYPE_MIN                            32
#define MSTP_COBS_TYPE_MAX                            127

/* Valid Length of any COBS-encoded frame: Nmin_COBS_length through
 * Nmax_COBS_length (Clause 9.5.3). */
#define MSTP_COBS_LENGTH_MIN                          5
#define MSTP_COBS_LENGTH_MAX                          2043

/* BACnet NPDUs of 502 through 1497 octets go in Frame Types 32 and 33,
 * smaller ones in Frame Types 5 and 6 (Clauses 9.2 and 9.3; tested by
 * ANSI/ASHRAE 135.1 12.1.3.20). */
#define MSTP_BACNET_EXTENDED_NPDU_MIN                 502
#define MSTP_BACNET_EXTENDED_NPDU_MAX                 1497

/* Largest Length of an IPv6 over MS/TP frame: a 1500-octet IPv6 packet
 * becomes an MSDU of at most 1501 octets, plus at most 6 octets of COBS
 * overhead, plus 3 (draft-ietf-6lo-rfc8163-bis; RFC 8163 says 1509). */
#define MSTP_IPV6_LENGTH_MAX                          1510


static const value_string
bacnet_mstp_frame_type_name[] = {
	{MSTP_TOKEN,                                    "Token"},
	{MSTP_POLL_FOR_MANAGER,                         "Poll For Manager"},
	{MSTP_REPLY_TO_POLL_FOR_MANAGER,                "Reply To Poll For Manager"},
	{MSTP_TEST_REQUEST,                             "Test_Request"},
	{MSTP_TEST_RESPONSE,                            "Test_Response"},
	{MSTP_BACNET_DATA_EXPECTING_REPLY,              "BACnet Data Expecting Reply"},
	{MSTP_BACNET_DATA_NOT_EXPECTING_REPLY,          "BACnet Data Not Expecting Reply"},
	{MSTP_REPLY_POSTPONED,                          "Reply Postponed"},
	{MSTP_BACNET_EXTENDED_DATA_EXPECTING_REPLY,     "BACnet Extended Data Expecting Reply"},
	{MSTP_BACNET_EXTENDED_DATA_NOT_EXPECTING_REPLY, "BACnet Extended Data Not Expecting Reply"},
	{MSTP_IPV6_ENCAPSULATION,                       "IPv6 over MS/TP (LoBAC) Encapsulation"},
	/* Frame Types 128 through 255: Proprietary Frames */
	{0, NULL }
};

static dissector_table_t subdissector_table;

static int proto_mstp;

static int ett_bacnet_mstp;

static int hf_mstp_preamble_55;
static int hf_mstp_preamble_FF;
static int hf_mstp_frame_type;
static int hf_mstp_frame_destination;
static int hf_mstp_frame_source;
static int hf_mstp_frame_vendor_id;
static int hf_mstp_frame_pdu_len;
static int hf_mstp_frame_crc8;
static int hf_mstp_frame_crc16;
static int hf_mstp_frame_crc32k;
static int hf_mstp_frame_checksum_status;

static expert_field ei_mstp_frame_pdu_len;
static expert_field ei_mstp_frame_checksum_bad;
static expert_field ei_mstp_cobs_bad;
static expert_field ei_mstp_bacnet_npdu_len;
static expert_field ei_mstp_ipv6_len;

static int mstp_address_type = -1;

static dissector_handle_t mstp_handle;

#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
/* Accumulate "dataValue" into the CRC in crcValue. */
/* Return value is updated CRC */
/*  The ^ operator means exclusive OR. */
/* Note: This function is copied directly from the BACnet standard. */
static uint8_t
CRC_Calc_Header(
	uint8_t dataValue,
	uint8_t crcValue)
{
	uint16_t crc;

	crc = crcValue ^ dataValue; /* XOR C7..C0 with D7..D0 */

	/* Exclusive OR the terms in the table (top down) */
	crc = crc ^ (crc << 1) ^ (crc << 2) ^ (crc << 3)
		^ (crc << 4) ^ (crc << 5) ^ (crc << 6)
		^ (crc << 7);

	/* Combine bits shifted out left hand end */
	return (crc & 0xfe) ^ ((crc >> 8) & 1);
}
#endif

/* Common frame type text */
const char *
mstp_frame_type_text(wmem_allocator_t* scope, uint32_t val)
{
	return val_to_str(scope, val,
		bacnet_mstp_frame_type_name,
		"Unknown Frame Type (%u)");
}

static int mstp_str_len(const address* addr _U_)
{
	return 5;
}

static int mstp_to_str(const address* addr, char *buf, int buf_len _U_)
{
	*buf++ = '0';
	*buf++ = 'x';
	buf = bytes_to_hexstr(buf, (const uint8_t *)addr->data, 1);
	*buf = '\0'; /* NULL terminate */

	return mstp_str_len(addr);
}

static const char* mstp_col_filter_str(const address* addr _U_, bool is_src)
{
	if (is_src)
		return "mstp.src";

	return "mstp.dst";
}

static int mstp_len(void)
{
	return 1;
}

/* See ANSI/ASHRAE Standard 135-2024 [BACnet], Annex G.3.1 */
#define CRC32K_INITIAL_VALUE	0xFFFFFFFF
/* CRC-32K polynomial, 1 + x**1 + ... + x**30 (+ x**32) */
#define CRC32K_POLY		0xEB31D82E

/*
 * Accumulate 'data_value' into the CRC in 'crc_value'.
 * Return updated CRC.
 *
 * Note: crc_value must be set to CRC32K_INITIAL_VALUE
 * before initial call.
 */
static uint32_t
calc_crc32K(uint8_t data_value, uint32_t crc_value)
{
	int b;

	for (b = 0; b < 8; b++) {
		if ((data_value & 1) ^ (crc_value & 1)) {
			crc_value >>= 1;
			crc_value ^= CRC32K_POLY;
		} else {
			crc_value >>= 1;
		}
		data_value >>= 1;
	}
	return crc_value;
}

typedef enum {
	COBS_OK,
	COBS_BAD_OCTET,	/* an encoded octet equals the mask (an encoded zero) */
	COBS_OVERRUN	/* a code octet runs past the end of the data */
} cobs_result_t;

/*
 * Decodes 'length' octets of COBS-encoded data at 'from', removing the
 * 'mask' applied to every encoded octet, and writes the decoded data at
 * 'to'. Sets '*decoded_len' to the number of octets written.
 *
 * On error, sets '*error_offset' to the offset of the octet in error,
 * and 'to' holds the octets decoded before the error (for a code octet
 * that runs past the end, the data octets that follow it).
 * Note: Safe to call with 'to' <= 'from' (decodes in place).
 *
 * Based on the reference code in ANSI/ASHRAE 135-2024, extended to
 * report where decoding fails and to reject encoded zero data octets,
 * which COBS never produces.
 */
static cobs_result_t
cobs_decode(uint8_t *to, const uint8_t *from, size_t length, uint8_t mask,
	size_t *decoded_len, size_t *error_offset)
{
	size_t read_index = 0;
	size_t write_index = 0;
	cobs_result_t result = COBS_OK;
	uint8_t code;
	uint8_t last_code;
	uint8_t data;

	while (read_index < length) {
		code = from[read_index] ^ mask;
		last_code = code;
		/*
		 * A code octet equal to zero or greater than the length is
		 * illegal. For the latter, keep the data octets that are there,
		 * for display.
		 */
		if (code == 0) {
			*error_offset = read_index;
			result = COBS_BAD_OCTET;
			break;
		}
		if (read_index + code > length) {
			*error_offset = read_index;
			result = COBS_OVERRUN;
			code = (uint8_t)(length - read_index);
		}

		read_index++;
		/*
		 * Decode data octets. The code octet is included in the length,
		 * but the terminating zero octet is not. A data octet of zero
		 * cannot occur, since the whole point of COBS encoding is to
		 * remove zeroes.
		 */
		while (--code > 0) {
			data = from[read_index] ^ mask;
			if (data == 0) {
				*error_offset = read_index;
				result = COBS_BAD_OCTET;
				break;
			}
			to[write_index++] = data;
			read_index++;
		}
		if (result != COBS_OK)
			break;

		/*
		 * Restore the implicit zero at the end of each decoded block
		 * except when it contains exactly 254 non-zero octets or the
		 * end of data has been reached.
		 */
		if ((last_code != 255) && (read_index < length))
			to[write_index++] = 0;
	}

	*decoded_len = write_index;
	return result;
}

#define MSTP_ENC_CRC32K_LEN (5)	/* the Encoded CRC-32K field is always 5 octets */
#define MSTP_PREAMBLE_X55 (0x55)

static void
mstp_cobs_error(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
	unsigned offset, cobs_result_t result, const char *field)
{
	if (result == COBS_BAD_OCTET) {
		proto_tree_add_expert_format(tree, pinfo, &ei_mstp_cobs_bad, tvb,
			offset, 1,
			"Octet 0x55 (an encoded zero) in the %s field: octets may be missing, or the frame ended early",
			field);
	} else {
		proto_tree_add_expert_format(tree, pinfo, &ei_mstp_cobs_bad, tvb,
			offset, 1,
			"COBS code octet runs past the end of the %s field: octets may be missing or corrupted",
			field);
	}
}

/*
 * Dissects the Encoded Data and Encoded CRC-32K fields of a COBS-encoded
 * frame (Frame Types 32 through 127). The Length field is two octets less
 * than the encoded data plus the 5-octet Encoded CRC-32K, so that devices
 * that do not know about COBS-encoded frames can skip them as unknown.
 * The CRC-32K is calculated over the encoded data.
 */
static void
dissect_mstp_cobs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	proto_tree *subtree, unsigned offset, uint8_t frame_type,
	uint32_t frame_pdu_len, proto_item *len_item)
{
	unsigned encoded_len = frame_pdu_len + 2;
	unsigned captured_len;
	unsigned data_len;
	unsigned scan_len;
	unsigned bad_offset = 0;
	const char *bad_field = NULL;
	cobs_result_t bad_result = COBS_OK;
	uint8_t *buf;
	size_t decoded_len = 0;
	size_t error_offset = 0;
	size_t crc_len = 0;
	size_t crc_error_offset = 0;
	cobs_result_t result;
	uint32_t crc32k = CRC32K_INITIAL_VALUE;
	tvbuff_t *decoded_tvb;
	tvbuff_t *payload_tvb;
	unsigned i;

	/* Too short to hold the Encoded CRC-32K (dissect_mstp() reports it). */
	if (encoded_len < MSTP_ENC_CRC32K_LEN) {
		call_data_dissector(tvb_new_subset_length(tvb, offset, encoded_len),
			pinfo, tree);
		return;
	}

	/*
	 * Decode what was captured, even if the frame is shorter than the
	 * Length field says (the length check in dissect_mstp() flags that).
	 */
	captured_len = MIN(tvb_captured_length_remaining(tvb, offset), encoded_len);
	if (captured_len == 0)
		return;
	data_len = MIN(captured_len, encoded_len - MSTP_ENC_CRC32K_LEN);
	buf = (uint8_t *)tvb_memdup(pinfo->pool, tvb, offset, captured_len);

	/*
	 * COBS never produces an encoded zero (0x55), so the first 0x55 marks
	 * where the frame went wrong, typically because octets were lost and
	 * the next frame's preamble was read as part of this one. Only the
	 * octets before it are decoded.
	 */
	for (scan_len = 0; scan_len < captured_len; scan_len++) {
		if (buf[scan_len] == MSTP_PREAMBLE_X55)
			break;
	}

	/*
	 * The CRC-32K covers the encoded data, so calculate it before
	 * decoding in place.
	 */
	for (i = 0; i < data_len; i++)
		crc32k = calc_crc32K(buf[i], crc32k);

	result = cobs_decode(buf, buf, MIN(data_len, scan_len),
		MSTP_PREAMBLE_X55, &decoded_len, &error_offset);

	if (scan_len < captured_len) {
		bad_result = COBS_BAD_OCTET;
		bad_offset = scan_len;
		bad_field = (scan_len < data_len) ? "Encoded Data" : "Encoded CRC-32K";
	} else if (result != COBS_OK) {
		/* Running out of data is expected in a frame that was cut short. */
		if (!(result == COBS_OVERRUN && captured_len < encoded_len)) {
			bad_result = result;
			bad_offset = (unsigned)error_offset;
			bad_field = "Encoded Data";
		}
	} else if (captured_len == encoded_len) {
		result = cobs_decode(buf + decoded_len, buf + data_len,
			MSTP_ENC_CRC32K_LEN, MSTP_PREAMBLE_X55,
			&crc_len, &crc_error_offset);
		if (result == COBS_OK && crc_len == sizeof(uint32_t)) {
			decoded_tvb = tvb_new_child_real_data(tvb, buf,
				(unsigned)(decoded_len + crc_len),
				(unsigned)(decoded_len + crc_len));
			add_new_data_source(pinfo, decoded_tvb, "Decoded Data and CRC32K");

			/*
			 * Compares received CRC-32K to computed CRC-32K.
			 * The CRC-32K is sent least significant octet first. Like
			 * the Ethernet FCS, show it as the octets appear on the wire.
			 */
			proto_tree_add_checksum(subtree, decoded_tvb, (unsigned)decoded_len,
				hf_mstp_frame_crc32k, hf_mstp_frame_checksum_status,
				&ei_mstp_frame_checksum_bad, pinfo,
				GUINT32_SWAP_LE_BE(~crc32k), ENC_BIG_ENDIAN,
				PROTO_CHECKSUM_VERIFY);

			if ((frame_type == MSTP_BACNET_EXTENDED_DATA_EXPECTING_REPLY ||
			     frame_type == MSTP_BACNET_EXTENDED_DATA_NOT_EXPECTING_REPLY) &&
			    (decoded_len < MSTP_BACNET_EXTENDED_NPDU_MIN ||
			     decoded_len > MSTP_BACNET_EXTENDED_NPDU_MAX)) {
				expert_add_info_format(pinfo, len_item, &ei_mstp_bacnet_npdu_len,
					"BACnet NPDU of %u octets: Frame Types 32 and 33 carry NPDUs of %u to %u octets",
					(unsigned)decoded_len, (unsigned)MSTP_BACNET_EXTENDED_NPDU_MIN,
					(unsigned)MSTP_BACNET_EXTENDED_NPDU_MAX);
			}

			if (decoded_len > 0) {
				payload_tvb = tvb_new_subset_length(decoded_tvb, 0,
					(unsigned)decoded_len);
				/* Dissect the payload even if the CRC-32K is bad. */
				if (!dissector_try_uint(subdissector_table,
					(0/*VendorID ASHRAE*/ << 16) + frame_type,
					payload_tvb, pinfo, tree)) {
					call_data_dissector(payload_tvb, pinfo, tree);
				}
			}
			return;
		}
		bad_result = (result == COBS_OK) ? COBS_OVERRUN : result;
		bad_offset = data_len + (unsigned)crc_error_offset;
		bad_field = "Encoded CRC-32K";
	}

	/* Report where decoding failed, and show the octets decoded so far. */
	if (bad_field != NULL)
		mstp_cobs_error(subtree, pinfo, tvb, offset + bad_offset, bad_result,
			bad_field);
	if (decoded_len > 0) {
		decoded_tvb = tvb_new_child_real_data(tvb, buf,
			(unsigned)decoded_len, (unsigned)decoded_len);
		add_new_data_source(pinfo, decoded_tvb, "Decoded Data (partial)");
		call_data_dissector(decoded_tvb, pinfo, tree);
	} else {
		call_data_dissector(tvb_new_subset_length(tvb, offset, captured_len),
			pinfo, tree);
	}
}

/* dissects a BACnet MS/TP frame */
/* preamble 0x55 0xFF is not included in Cimetrics U+4 output */
void
dissect_mstp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	proto_tree *subtree, int offset)
{
	uint8_t mstp_frame_type = 0;
	uint32_t mstp_frame_pdu_len = 0; /* PDU length reported in the header */
	uint16_t mstp_tvb_pdu_len = 0; /* Reported space in parent tvb for PDU */
	uint16_t vendorid = 0;
	tvbuff_t *next_tvb = NULL;
	proto_item *item;
#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
	/* used to calculate the crc value */
	uint8_t crc8 = 0xFF;
	uint16_t crc16;
	uint8_t crcdata;
	uint16_t i; /* loop counter */
#endif

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BACnet");
	col_set_str(pinfo->cinfo, COL_INFO, "BACnet MS/TP");
	mstp_frame_type = tvb_get_uint8(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
			mstp_frame_type_text(pinfo->pool, mstp_frame_type));

	/* Add the items to the tree */
	proto_tree_add_item(subtree, hf_mstp_frame_type, tvb,
			offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(subtree, hf_mstp_frame_destination, tvb,
			offset+1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(subtree, hf_mstp_frame_source, tvb,
			offset+2, 1, ENC_LITTLE_ENDIAN);
	item = proto_tree_add_item_ret_uint(subtree, hf_mstp_frame_pdu_len, tvb,
			offset+3, 2, ENC_BIG_ENDIAN, &mstp_frame_pdu_len);
	mstp_tvb_pdu_len = tvb_reported_length_remaining(tvb, offset+6);
	/* check the length - which does not include the crc16 checksum */
	if (mstp_frame_pdu_len > 0) {
		if (mstp_frame_pdu_len + 2 > mstp_tvb_pdu_len) {
			/* We should get a ContainedBoundsError later. */
			expert_add_info(pinfo, item, &ei_mstp_frame_pdu_len);
		}
	}
#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
	/* calculate checksum to validate */
	for (i = 0; i < 5; i++) {
		crcdata = tvb_get_uint8(tvb, offset+i);
		crc8 = CRC_Calc_Header(crcdata, crc8);
	}
	crc8 = ~crc8;
	proto_tree_add_checksum(subtree, tvb, offset+5, hf_mstp_frame_crc8, hf_mstp_frame_checksum_status, &ei_mstp_frame_checksum_bad, pinfo, crc8,
							ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
#else
	proto_tree_add_checksum(subtree, tvb, offset+5, hf_mstp_frame_crc8, hf_mstp_frame_checksum_status, &ei_mstp_frame_checksum_bad, pinfo, 0,
							ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
#endif

	/* dissect BACnet PDU if there is one */
	offset += 6;

	if (mstp_frame_type >= MSTP_COBS_TYPE_MIN &&
	    mstp_frame_type <= MSTP_COBS_TYPE_MAX) {
		if (mstp_frame_pdu_len < MSTP_COBS_LENGTH_MIN ||
		    mstp_frame_pdu_len > MSTP_COBS_LENGTH_MAX) {
			expert_add_info_format(pinfo, item, &ei_mstp_frame_pdu_len,
				"Length %u is outside %u to %u, the range for COBS-encoded frames",
				mstp_frame_pdu_len, (unsigned)MSTP_COBS_LENGTH_MIN,
				(unsigned)MSTP_COBS_LENGTH_MAX);
		} else if (mstp_frame_type == MSTP_IPV6_ENCAPSULATION &&
			   mstp_frame_pdu_len > MSTP_IPV6_LENGTH_MAX) {
			expert_add_info(pinfo, item, &ei_mstp_ipv6_len);
		}
		/* COBS-encoded frames must be decoded before they are dissected */
		if (mstp_frame_pdu_len) {
			dissect_mstp_cobs(tvb, pinfo, tree, subtree, offset,
				mstp_frame_type, mstp_frame_pdu_len, item);
		}
	}
	else if (mstp_frame_pdu_len) {
		/* frame_pdu_len does not include the 16-bit crc bytes */
		if (mstp_frame_type < 128) {
			vendorid = 0;
			next_tvb = tvb_new_subset_length(tvb, offset,
				mstp_frame_pdu_len);
		} else {
			/* With Vendor ID */
			vendorid = tvb_get_ntohs(tvb, offset);

			/* Write Vendor ID as tree */
			proto_tree_add_item(subtree, hf_mstp_frame_vendor_id, tvb,
				offset, 2, ENC_BIG_ENDIAN);

			if (mstp_frame_pdu_len < 2) {
				expert_add_info_format(pinfo, item, &ei_mstp_frame_pdu_len, "Length field value is not large enough for Vendor ID");
				/* Remaining length can't be negative. */
				THROW(ReportedBoundsError);
			}
			/* NPDU - call the Vendor specific dissector */
			next_tvb = tvb_new_subset_length(tvb, offset+2,
				mstp_frame_pdu_len - 2);
		}

		if (!(dissector_try_uint(subdissector_table, (vendorid<<16) + mstp_frame_type,
			next_tvb, pinfo, tree))) {
				/* Unknown function - dissect the payload as data */
				call_data_dissector(next_tvb, pinfo, tree);
		}
#if defined(BACNET_MSTP_CHECKSUM_VALIDATE)
		/* 16-bit checksum - calculate to validate */
		crc16 = crc16_ccitt_tvb_offset(tvb, offset, mstp_frame_pdu_len);
		/* convert it to on-the-wire format */
		crc16 = g_htons(crc16);

		proto_tree_add_checksum(subtree, tvb, offset+mstp_frame_pdu_len, hf_mstp_frame_crc16, hf_mstp_frame_checksum_status, &ei_mstp_frame_checksum_bad, pinfo, crc16,
							ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
#else
		proto_tree_add_checksum(subtree, tvb, offset+mstp_frame_pdu_len, hf_mstp_frame_crc16, hf_mstp_frame_checksum_status, &ei_mstp_frame_checksum_bad, pinfo, 0,
							ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
#endif
	}
}

static int
dissect_mstp_wtap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *subtree;
	unsigned offset = 0;
#ifdef BACNET_MSTP_SUMMARY_IN_TREE
	uint8_t mstp_frame_type = 0;
	uint8_t mstp_frame_source = 0;
	uint8_t mstp_frame_destination = 0;
#endif

	/* set the MS/TP MAC address in the source/destination */
	set_address_tvb(&pinfo->dl_dst,	mstp_address_type, 1, tvb, offset+3);
	copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
	set_address_tvb(&pinfo->dl_src,	mstp_address_type, 1, tvb, offset+4);
	copy_address_shallow(&pinfo->src, &pinfo->dl_src);

#ifdef BACNET_MSTP_SUMMARY_IN_TREE
	mstp_frame_type = tvb_get_uint8(tvb, offset+2);
	mstp_frame_destination = tvb_get_uint8(tvb, offset+3);
	mstp_frame_source = tvb_get_uint8(tvb, offset+4);
	ti = proto_tree_add_protocol_format(tree, proto_mstp, tvb, offset, 8,
		"BACnet MS/TP, Src (%u), Dst (%u), %s",
		mstp_frame_source, mstp_frame_destination,
		mstp_frame_type_text(pinfo->pool, mstp_frame_type));
#else
	ti = proto_tree_add_item(tree, proto_mstp, tvb, offset, 8, ENC_NA);
#endif
	subtree = proto_item_add_subtree(ti, ett_bacnet_mstp);
	proto_tree_add_item(subtree, hf_mstp_preamble_55, tvb,
			offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(subtree, hf_mstp_preamble_FF, tvb,
			offset+1, 1, ENC_LITTLE_ENDIAN);
	dissect_mstp(tvb, pinfo, tree, subtree, offset+2);
	return tvb_captured_length(tvb);
}

void
proto_register_mstp(void)
{
	static hf_register_info hf[] = {
		{ &hf_mstp_preamble_55,
			{ "Preamble 55", "mstp.preamble_55",
			FT_UINT8, BASE_HEX, NULL, 0,
			"MS/TP Preamble 55", HFILL }
		},
		{ &hf_mstp_preamble_FF,
			{ "Preamble FF", "mstp.preamble_FF",
			FT_UINT8, BASE_HEX, NULL, 0,
			"MS/TP Preamble FF", HFILL }
		},
		{ &hf_mstp_frame_type,
			{ "Frame Type", "mstp.frame_type",
			FT_UINT8, BASE_DEC, VALS(bacnet_mstp_frame_type_name), 0,
			"MS/TP Frame Type", HFILL }
		},
		{ &hf_mstp_frame_destination,
			{ "Destination Address", "mstp.dst",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Destination MS/TP MAC Address", HFILL }
		},
		{ &hf_mstp_frame_source,
			{ "Source Address", "mstp.src",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Source MS/TP MAC Address", HFILL }
		},
		{ &hf_mstp_frame_vendor_id,
			{ "VendorID", "mstp.vendorid",
			FT_UINT16, BASE_DEC, NULL, 0,
			"MS/TP Vendor ID of proprietary frametypes", HFILL }
		},
		{ &hf_mstp_frame_pdu_len,
			{ "Length", "mstp.len",
			FT_UINT16, BASE_DEC, NULL, 0,
			"MS/TP Data Length", HFILL }
		},
		{ &hf_mstp_frame_crc8,
			{ "Header CRC",  "mstp.hdr_crc",
			FT_UINT8, BASE_HEX, NULL, 0,
			"MS/TP Header CRC", HFILL }
		},
		{ &hf_mstp_frame_crc16,
			{ "Data CRC",  "mstp.data_crc",
			FT_UINT16, BASE_HEX, NULL, 0,
			"MS/TP Data CRC", HFILL }
		},
		{ &hf_mstp_frame_crc32k,
			{ "Extended Data CRC",  "mstp.ext_data_crc",
			FT_UINT32, BASE_HEX, NULL, 0,
			"MS/TP Extended Data CRC (CRC-32K)", HFILL }
		},
		{ &hf_mstp_frame_checksum_status,
			{ "Checksum status", "mstp.checksum.status",
			FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
			NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_bacnet_mstp,
	};

	static ei_register_info ei[] = {
		{ &ei_mstp_frame_pdu_len, { "mstp.len.bad", PI_MALFORMED, PI_ERROR, "Length field value goes past the end of the payload", EXPFILL }},
		{ &ei_mstp_frame_checksum_bad, { "mstp.checksum_bad.expert", PI_CHECKSUM, PI_WARN, "Bad Checksum", EXPFILL }},
		{ &ei_mstp_cobs_bad, { "mstp.cobs.bad", PI_MALFORMED, PI_ERROR, "Invalid COBS encoding", EXPFILL }},
		{ &ei_mstp_bacnet_npdu_len, { "mstp.bacnet_npdu_len.unexpected", PI_PROTOCOL, PI_WARN, "BACnet NPDU length outside the range for Frame Types 32 and 33", EXPFILL }},
		{ &ei_mstp_ipv6_len, { "mstp.ipv6_len.too_long", PI_PROTOCOL, PI_WARN, "Length above 1510, the largest IPv6 over MS/TP frame", EXPFILL }},
	};

	expert_module_t* expert_mstp;

	proto_mstp = proto_register_protocol("BACnet MS/TP", "BACnet MS/TP", "mstp");

	proto_register_field_array(proto_mstp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mstp = expert_register_protocol(proto_mstp);
	expert_register_field_array(expert_mstp, ei, array_length(ei));

	mstp_handle = register_dissector("mstp", dissect_mstp_wtap, proto_mstp);

	subdissector_table = register_dissector_table("mstp.vendor_frame_type",
	    "MSTP Vendor specific Frametypes", proto_mstp, FT_UINT24, BASE_DEC);
	/* Table_type: (Vendor ID << 16) + Frametype */

	mstp_address_type = address_type_dissector_register("AT_MSTP", "BACnet MS/TP Address", mstp_to_str, mstp_str_len, NULL, mstp_col_filter_str, mstp_len, NULL, NULL);
}

void
proto_reg_handoff_mstp(void)
{
	dissector_handle_t bacnet_handle;

	dissector_add_uint("wtap_encap", WTAP_ENCAP_BACNET_MS_TP, mstp_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_BACNET_MS_TP_WITH_PHDR, mstp_handle);

	bacnet_handle = find_dissector("bacnet");

	dissector_add_uint("mstp.vendor_frame_type", (0/*VendorID ASHRAE*/ << 16) + MSTP_BACNET_DATA_EXPECTING_REPLY, bacnet_handle);
	dissector_add_uint("mstp.vendor_frame_type", (0/*VendorID ASHRAE*/ << 16) + MSTP_BACNET_DATA_NOT_EXPECTING_REPLY, bacnet_handle);
	dissector_add_uint("mstp.vendor_frame_type", (0/*VendorID ASHRAE*/ << 16) + MSTP_BACNET_EXTENDED_DATA_EXPECTING_REPLY, bacnet_handle);
	dissector_add_uint("mstp.vendor_frame_type", (0/*VendorID ASHRAE*/ << 16) + MSTP_BACNET_EXTENDED_DATA_NOT_EXPECTING_REPLY, bacnet_handle);
	dissector_add_uint("mstp.vendor_frame_type", (0/*VendorID ASHRAE*/ << 16) + MSTP_IPV6_ENCAPSULATION,
		find_dissector_add_dependency("6lowpan", proto_mstp));
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
