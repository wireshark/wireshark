/* packet-tzsp.c
 *
 * $Id$
 *
 * Copyright 2002, Tazmen Technologies Inc
 *
 * Tazmen Sniffer Protocol for encapsulating the packets across a network
 * from a remote packet sniffer. TZSP can encapsulate any other protocol.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>

#include <epan/packet.h>

#define UDP_PORT_TZSP	0x9090

static int proto_tzsp = -1;
static int hf_tzsp_version = -1;
static int hf_tzsp_type = -1;
static int hf_tzsp_encap = -1;

static const value_string tzsp_type[] = {
	{0,     "Received tag list"},
	{1,	"Packet for transmit"},
	{2,     "Reserved"},
	{3,     "Configuration"},
	{4,     "Keepalive"},
	{5,     "Port opener"},
	{0,     NULL}
};

static gint ett_tzsp = -1;

static dissector_handle_t data_handle;
static dissector_table_t encap_dissector_table;

/* ************************************************************************* */
/*                WLAN radio header felds                                    */
/* ************************************************************************* */

static int hf_status_field = -1;
static int hf_status_msg_type = -1;
static int hf_status_pcf = -1;
static int hf_status_mac_port = -1;
static int hf_status_undecrypted = -1;
static int hf_status_fcs_error = -1;

static int hf_time = -1;
static int hf_silence = -1;
static int hf_signal = -1;
static int hf_rate = -1;
static int hf_channel = -1;
static int hf_unknown = -1;
static int hf_original_length = -1;
static int hf_sensormac = -1;

/* ************************************************************************* */
/*                        Encapsulation type values                          */
/*               Note that these are not all the same as DLT_ values         */
/* ************************************************************************* */

#define TZSP_ENCAP_ETHERNET			1
#define TZSP_ENCAP_IEEE_802_11			18
#define TZSP_ENCAP_PRISM_HEADER			119
#define TZSP_ENCAP_WLAN_AVS			127

/* ************************************************************************* */
/*                          Generic header options                           */
/* ************************************************************************* */

#define TZSP_HDR_PAD 0 /* Pad. */
#define TZSP_HDR_END 1 /* End of the list. */
#define TZSP_HDR_ORIGINAL_LENGTH 41 /* Length of the packet before slicing. 2 bytes. */
#define TZSP_HDR_SENSOR 60 /* Sensor MAC address packet was received on, 6 byte ethernet address.*/

/* ************************************************************************* */
/*                          Options for 802.11 radios                        */
/* ************************************************************************* */

#define WLAN_RADIO_HDR_SIGNAL 10 /* Signal strength in dBm, signed byte. */
#define WLAN_RADIO_HDR_NOISE 11 /* Noise level in dBm, signed byte. */
#define WLAN_RADIO_HDR_RATE 12 /* Data rate, unsigned byte. */
#define WLAN_RADIO_HDR_TIMESTAMP 13 /* Timestamp in us, unsigned 32-bits network byte order. */
#define WLAN_RADIO_HDR_MSG_TYPE 14 /* Packet type, unsigned byte. */
#define WLAN_RADIO_HDR_CF 15 /* Whether packet arrived during CF period, unsigned byte. */
#define WLAN_RADIO_HDR_UN_DECR 16 /* Whether packet could not be decrypted by MAC, unsigned byte. */
#define WLAN_RADIO_HDR_FCS_ERR 17 /* Whether packet contains an FCS error, unsigned byte. */
#define WLAN_RADIO_HDR_CHANNEL 18 /* Channel number packet was received on, unsigned byte.*/

/* ************************************************************************* */
/*                Add option information to the display                      */
/* ************************************************************************* */

static int 
add_option_info(tvbuff_t *tvb, int pos, proto_tree *tree, proto_item *ti)
{
	guint8 tag, length, fcs_err = 0, encr = 0, seen_fcs_err = 0;
	
	/*
	 * Read all option tags in an endless loop. If the packet is malformed this
	 * loop might be a problem.
	 */
	while (TRUE) {
		tag = tvb_get_guint8(tvb, pos++);

		switch (tag) {
		case TZSP_HDR_PAD:
			length = 0;
			break;

		case TZSP_HDR_END:
			/* Fill in header with information from other tags. */
			if (seen_fcs_err) {
				if (tree)
					proto_item_append_text(ti,"%s", fcs_err?"FCS Error":(encr?"Encrypted":"Good"));
			}
			return pos;

		case TZSP_HDR_ORIGINAL_LENGTH:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_int (tree, hf_original_length, tvb, pos-2, 4,
						tvb_get_ntohs(tvb, pos));
			pos += length;
			break;

		case WLAN_RADIO_HDR_SIGNAL:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_int (tree, hf_signal, tvb, pos-2, 3,
						(char)tvb_get_guint8(tvb, pos));
			pos += length;
			break;

		case WLAN_RADIO_HDR_NOISE:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_int (tree, hf_silence, tvb, pos-2, 3,
						(char)tvb_get_guint8(tvb, pos));
			pos += length;
			break;

		case WLAN_RADIO_HDR_RATE:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_uint (tree, hf_rate, tvb, pos-2, 3,
							tvb_get_guint8(tvb, pos));
			pos += length;
			break;

		case WLAN_RADIO_HDR_TIMESTAMP:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_uint (tree, hf_time, tvb, pos-2, 6,
							tvb_get_ntohl(tvb, pos));
			pos += length;
			break;

		case WLAN_RADIO_HDR_MSG_TYPE:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_uint (tree, hf_status_msg_type, tvb, pos-2, 3,
						tvb_get_guint8(tvb, pos));
			pos += length;
			break;

		case WLAN_RADIO_HDR_CF:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_boolean (tree, hf_status_pcf, tvb, pos-2, 3,
						tvb_get_guint8(tvb, pos));
			pos += length;
			break;

		case WLAN_RADIO_HDR_UN_DECR:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_boolean (tree, hf_status_undecrypted, tvb, pos-2, 3,
						tvb_get_guint8(tvb, pos));
			encr = tvb_get_guint8(tvb, pos);
			pos += length;
			break;

		case WLAN_RADIO_HDR_FCS_ERR:
			seen_fcs_err = 1;
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_boolean (tree, hf_status_fcs_error, tvb, pos-2, 3,
						tvb_get_guint8(tvb, pos));
			fcs_err = tvb_get_guint8(tvb, pos);
			pos += length;
			break;

		case WLAN_RADIO_HDR_CHANNEL:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_uint (tree, hf_channel, tvb, pos-2, 3,
							tvb_get_guint8(tvb, pos));
			pos += length;
			break;

		case TZSP_HDR_SENSOR:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_ether(tree, hf_sensormac, tvb, pos-2, 6,
							tvb_get_ptr (tvb, pos, 6));
			pos += length;
			break;

		default:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_bytes(tree, hf_unknown, tvb, pos-2, length+2,
							tvb_get_ptr(tvb, pos, length));
			pos += length;
			break;
		}
	}
}

/* ************************************************************************* */
/*        Map TZSP encapsulation types to Wiretap encapsulation types        */
/* ************************************************************************* */
struct encap_map {
	guint16	tzsp_encap;
	int	wtap_encap;
};

static const struct encap_map map_table[] = {
	{ TZSP_ENCAP_ETHERNET,		WTAP_ENCAP_ETHERNET },
	{ TZSP_ENCAP_PRISM_HEADER,	WTAP_ENCAP_PRISM_HEADER },
	{ TZSP_ENCAP_WLAN_AVS,		WTAP_ENCAP_IEEE_802_11_WLAN_AVS },
	{ TZSP_ENCAP_IEEE_802_11,	WTAP_ENCAP_IEEE_802_11 },
	{ 0,				-1 }
};

static int
tzsp_encap_to_wtap_encap(guint16 encap)
{
	int i;

	for (i = 0; map_table[i].wtap_encap != -1; i++) {
		if (map_table[i].tzsp_encap == encap)
			return map_table[i].wtap_encap;
	}
	return -1;
}

/* ************************************************************************* */
/*                Dissect a TZSP packet                                      */
/* ************************************************************************* */

static void
dissect_tzsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *tzsp_tree = NULL;
	proto_item *ti = NULL;
	int pos = 0;
	tvbuff_t *next_tvb;
	guint16 encapsulation = 0;
	int wtap_encap;
	dissector_handle_t encap_dissector;
	const char *encap_name;
	const char *info;
	guint8 type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TZSP");
	col_clear(pinfo->cinfo, COL_INFO);

	type = tvb_get_guint8(tvb, 1);

	/* Find the dissector. */
	encapsulation = tvb_get_ntohs(tvb, 2);
	if (encapsulation != 0) {
		wtap_encap = tzsp_encap_to_wtap_encap(encapsulation);
		if (wtap_encap != -1 &&
		    (encap_dissector = dissector_get_uint_handle(encap_dissector_table, wtap_encap))) {
			encap_name = dissector_handle_get_short_name(encap_dissector);
		}
		else {
			encap_name = "Unknown";
		}
		info = encap_name;
	}
	else {
		wtap_encap = -1;
		encap_name = "Nothing";
		info = val_to_str(type, tzsp_type, "Unknown (%u)");
	}

	col_add_str(pinfo->cinfo, COL_INFO, info);

	if (tree) {
		/* Adding TZSP item and subtree */
		ti = proto_tree_add_protocol_format(tree, proto_tzsp, tvb, 0,
		    -1, "TZSP: %s: ", info);
		tzsp_tree = proto_item_add_subtree(ti, ett_tzsp);

		proto_tree_add_item (tzsp_tree, hf_tzsp_version, tvb, 0, 1,
					ENC_BIG_ENDIAN);
		proto_tree_add_uint (tzsp_tree, hf_tzsp_type, tvb, 1, 1,
					type);
		proto_tree_add_uint_format (tzsp_tree, hf_tzsp_encap, tvb, 2, 2,
					encapsulation, "Encapsulates: %s (%d)",
					encap_name, encapsulation);
	}

	if (type != 4 && type != 5) {
		pos = add_option_info(tvb, 4, tzsp_tree, ti);

		if (tree)
			proto_item_set_end(ti, tvb, pos);
		next_tvb = tvb_new_subset_remaining(tvb, pos);
		if (encapsulation != 0
		    && (wtap_encap == -1
			|| !dissector_try_uint(encap_dissector_table, wtap_encap,
				next_tvb, pinfo, tree))) {

			col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
			if (check_col(pinfo->cinfo, COL_INFO))
				col_add_fstr(pinfo->cinfo, COL_INFO, "TZSP_ENCAP = %u",
				    encapsulation);
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}
	}
}

/* ************************************************************************* */
/*                Register the TZSP dissector                                */
/* ************************************************************************* */

void
proto_register_tzsp(void)
{
	static const value_string msg_type[] = {
		{0,	"Normal"},
		{1,	"RFC1042 encoded"},
		{2,	"Bridge-tunnel encoded"},
		{4,	"802.11 management frame"},
		{0,	NULL}
	};

	static const true_false_string pcf_flag = {
		"CF: Frame received during CF period",
		"Not CF"
	};

	static const true_false_string undecr_flag = {
		"Encrypted frame could not be decrypted",
		"Unencrypted"
	};

	static const true_false_string fcs_err_flag = {
		"FCS error, frame is corrupted",
		"Frame is valid"
	};

	static const value_string channels[] = {
		/* 802.11b/g */
		{1, "1 (2.412 GHz)"},
		{2, "2 (2.417 GHz)"},
		{3, "3 (2.422 GHz)"},
		{4, "4 (2.427 GHz)"},
		{5, "5 (2.432 GHz)"},
		{6, "6 (2.437 GHz)"},
		{7, "7 (2.442 GHz)"},
		{8, "8 (2.447 GHz)"},
		{9, "9 (2.452 GHz)"},
		{10, "10 (2.457 GHz)"},
		{11, "11 (2.462 GHz)"},
		{12, "12 (2.467 GHz)"},
		{13, "13 (2.472 GHz)"},
		{14, "14 (2.484 GHz)"},
		/* 802.11a */
		{36, "36 (5.180 GHz)"},
		{40, "40 (5.200 GHz)"},
		{44, "44 (5.220 GHz)"},
		{48, "48 (5.240 GHz)"},
		{52, "52 (5.260 GHz)"},
		{56, "56 (5.280 GHz)"},
		{60, "60 (5.300 GHz)"},
		{64, "64 (5.320 GHz)"},
		{149, "149 (5.745 GHz)"},
		{153, "153 (5.765 GHz)"},
		{157, "157 (5.785 GHz)"},
		{161, "161 (5.805 GHz)"},
		{0, NULL}
	};

	static const value_string rates[] = {
		/* Old PRISM rates */
		{0x0A, "1 Mbit/s"},
		{0x14, "2 Mbit/s"},
		{0x37, "5.5 Mbit/s"},
		{0x6E, "11 Mbit/s"},
		/* MicroAP rates */
		{2, "1 Mbit/s"},
		{4, "2 Mbit/s"},
		{11, "5.5 Mbit/s"},
		{12, "6 Mbit/s"},
		{18, "9 Mbit/s"},
		{22, "11 Mbit/s"},
		{24, "12 Mbit/s"},
		{36, "18 Mbit/s"},
		{48, "24 Mbit/s"},
		{72, "36 Mbit/s"},
		{96, "48 Mbit/s"},
		{108, "54 Mbit/s"},
		{0, NULL}
	};

	static hf_register_info hf[] = {
		{ &hf_tzsp_version, {
			"Version", "tzsp.version", FT_UINT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_tzsp_type, {
			"Type", "tzsp.type", FT_UINT8, BASE_DEC,
			VALS(tzsp_type), 0, NULL, HFILL }},
		{ &hf_tzsp_encap, {
			"Encapsulation", "tzsp.encap", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_status_field, {
			"Status", "tzsp.wlan.status", FT_UINT16, BASE_HEX,
				NULL, 0, NULL, HFILL }},
		{ &hf_status_msg_type, {
			"Type", "tzsp.wlan.status.msg_type", FT_UINT8, BASE_HEX,
			VALS(msg_type), 0, "Message type", HFILL }},
		{ &hf_status_mac_port, {
			"Port", "tzsp.wlan.status.mac_port", FT_UINT8, BASE_DEC,
			NULL, 0, "MAC port", HFILL }},
		{ &hf_status_pcf, {
			"PCF", "tzsp.wlan.status.pcf", FT_BOOLEAN, BASE_NONE,
			TFS (&pcf_flag), 0x0, "Point Coordination Function", HFILL }},
		{ &hf_status_undecrypted, {
			"Undecrypted", "tzsp.wlan.status.undecrypted", FT_BOOLEAN, BASE_NONE,
			TFS (&undecr_flag), 0x0, NULL, HFILL }},
		{ &hf_status_fcs_error, {
			"FCS", "tzsp.wlan.status.fcs_err", FT_BOOLEAN, BASE_NONE,
			TFS (&fcs_err_flag), 0x0, "Frame check sequence", HFILL }},
		{ &hf_time, {
			"Time", "tzsp.wlan.time", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }},
		{ &hf_silence, {
			"Silence", "tzsp.wlan.silence", FT_INT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_original_length, {
			"Original Length", "tzsp.original_length", FT_INT16, BASE_DEC,
			NULL, 0, "OrigLength", HFILL }},
		{ &hf_signal, {
			"Signal", "tzsp.wlan.signal", FT_INT8, BASE_DEC,
			NULL, 0, NULL, HFILL }},
		{ &hf_rate, {
			"Rate", "tzsp.wlan.rate", FT_UINT8, BASE_DEC,
			VALS(rates), 0, NULL, HFILL }},
		{ &hf_channel, {
			"Channel", "tzsp.wlan.channel", FT_UINT8, BASE_DEC,
			VALS(channels), 0, NULL, HFILL }},
		{ &hf_unknown, {
			"Unknown tag", "tzsp.unknown", FT_BYTES, BASE_NONE,
			NULL, 0, "Unknown", HFILL }},
		{ &hf_sensormac, {
			"Sensor Address", "tzsp.sensormac", FT_ETHER, BASE_NONE,
			NULL, 0, "Sensor MAC", HFILL }}
	};

	static gint *ett[] = {
		&ett_tzsp
	};

	proto_tzsp = proto_register_protocol("Tazmen Sniffer Protocol", "TZSP",
	    "tzsp");
	proto_register_field_array(proto_tzsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("tzsp", dissect_tzsp, proto_tzsp);

}

void
proto_reg_handoff_tzsp(void)
{
	dissector_handle_t tzsp_handle;

	tzsp_handle = create_dissector_handle(dissect_tzsp, proto_tzsp);
	dissector_add_uint("udp.port", UDP_PORT_TZSP, tzsp_handle);

	/* Get the data dissector for handling unknown encapsulation types. */
	data_handle = find_dissector("data");

	/* Register this protocol as an ecapsulation type. */
	dissector_add_uint("wtap_encap", WTAP_ENCAP_TZSP, tzsp_handle);

	encap_dissector_table = find_dissector_table("wtap_encap");
}
