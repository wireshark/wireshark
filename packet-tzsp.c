/* packet-tzsp.c
 * Copyright 2002, Tazmen Technologies Inc
 *
 * Tazmen Sniffer Protocol for encapsulating the packets across a network
 * from a remote packet sniffer. TZSP can encapsulate any other protocol.
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
static int hf_tzsp_reserved = -1;
static int hf_tzsp_encap = -1;

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

/* ************************************************************************* */
/*                        Encapsulation type values                          */
/* ************************************************************************* */

#define TZSP_ENCAP_ETHERNET			1
#define TZSP_ENCAP_TOKEN_RING			2
#define TZSP_ENCAP_SLIP				3
#define TZSP_ENCAP_PPP				4
#define TZSP_ENCAP_FDDI				5
#define TZSP_ENCAP_FDDI_BITSWAPPED		6
#define TZSP_ENCAP_RAW_IP			7
#define TZSP_ENCAP_ARCNET			8
#define TZSP_ENCAP_ATM_RFC1483			9
#define TZSP_ENCAP_LINUX_ATM_CLIP		10
#define TZSP_ENCAP_LAPB				11
#define TZSP_ENCAP_NULL				13
#define TZSP_ENCAP_IP_OVER_FC			16
#define TZSP_ENCAP_IEEE_802_11			18
#define TZSP_ENCAP_SLL				20
#define TZSP_ENCAP_FRELAY			21
#define TZSP_ENCAP_CHDLC			22
#define TZSP_ENCAP_LOCALTALK			24
#define TZSP_ENCAP_PRISM_HEADER			25
#define TZSP_ENCAP_WLAN_HEADER			30
#define TZSP_ENCAP_WFLEET_HDLC			32
#define TZSP_ENCAP_SDLC				33

/* ************************************************************************* */
/*                          Generic header options                           */
/* ************************************************************************* */

#define TZSP_HDR_PAD 0 /* Pad. */
#define TZSP_HDR_END 1 /* End of the list. */

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
add_option_info(tvbuff_t *tvb, proto_tree *tree, proto_item *ti)
{
	guint8 tag, length, fcs_err = 0, encr = 0;
	int pos = 0;
	
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
			if (tree)
				proto_item_append_text(ti,"%s", fcs_err?"FCS Error":(encr?"Encrypted":"Good"));
			return pos;

		case WLAN_RADIO_HDR_SIGNAL:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_uint_format (tree, hf_signal, tvb, pos-2, 3,
						  tvb_get_guint8(tvb, pos),
					    "Signal: 0x%02X",
					    tvb_get_guint8(tvb, pos));
			pos += length;
			break;

		case WLAN_RADIO_HDR_NOISE:
			length = tvb_get_guint8(tvb, pos++);
			if (tree)
				proto_tree_add_uint_format (tree, hf_silence, tvb, pos-2, 3,
						  tvb_get_guint8(tvb, pos),
					    "Silence: 0x%02X",
					    tvb_get_guint8(tvb, pos));
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
	{ TZSP_ENCAP_TOKEN_RING,	WTAP_ENCAP_TOKEN_RING },
	{ TZSP_ENCAP_SLIP,		WTAP_ENCAP_SLIP },
	{ TZSP_ENCAP_PPP,		WTAP_ENCAP_PPP },
	{ TZSP_ENCAP_FDDI,		WTAP_ENCAP_FDDI },
	{ TZSP_ENCAP_FDDI_BITSWAPPED,	WTAP_ENCAP_FDDI_BITSWAPPED },
	{ TZSP_ENCAP_RAW_IP,		WTAP_ENCAP_RAW_IP },
	{ TZSP_ENCAP_ARCNET,		WTAP_ENCAP_ARCNET },
	{ TZSP_ENCAP_ATM_RFC1483,	WTAP_ENCAP_ATM_RFC1483 },
	{ TZSP_ENCAP_LINUX_ATM_CLIP,	WTAP_ENCAP_LINUX_ATM_CLIP },
	{ TZSP_ENCAP_LAPB,		WTAP_ENCAP_LAPB },
	{ TZSP_ENCAP_NULL,		WTAP_ENCAP_NULL },
	{ TZSP_ENCAP_IP_OVER_FC,	WTAP_ENCAP_IP_OVER_FC },
	{ TZSP_ENCAP_IEEE_802_11,	WTAP_ENCAP_IEEE_802_11 },
	{ TZSP_ENCAP_SLL,		WTAP_ENCAP_SLL },
	{ TZSP_ENCAP_FRELAY,		WTAP_ENCAP_FRELAY },
	{ TZSP_ENCAP_CHDLC,		WTAP_ENCAP_CHDLC },
	{ TZSP_ENCAP_LOCALTALK,		WTAP_ENCAP_LOCALTALK },
	{ TZSP_ENCAP_PRISM_HEADER,	WTAP_ENCAP_PRISM_HEADER },
	{ TZSP_ENCAP_WLAN_HEADER,	WTAP_ENCAP_WLAN_HEADER },
	{ TZSP_ENCAP_WFLEET_HDLC,	WTAP_ENCAP_WFLEET_HDLC },
	{ TZSP_ENCAP_SDLC,		WTAP_ENCAP_SDLC },
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
	char *encap_name;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TZSP");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Tazmen Sniffer Protocol");

	/* Find the dissector. */
	encapsulation = tvb_get_ntohs(tvb, 2);
	wtap_encap = tzsp_encap_to_wtap_encap(encapsulation);
	if ( wtap_encap != -1 &&
	    (encap_dissector = dissector_get_port_handle(encap_dissector_table, wtap_encap)) ) {
		encap_name = dissector_handle_get_short_name(encap_dissector);
	}
	else {
		encap_name = "UNKNOWN";
	}

	if (tree) {
		/* Adding TZSP item and subtree */
		ti = proto_tree_add_protocol_format(tree, proto_tzsp, tvb, 0,
		    tvb_length(tvb), "TZSP: %s: ", encap_name);
		tzsp_tree = proto_item_add_subtree(ti, ett_tzsp);

		proto_tree_add_uint (tzsp_tree, hf_tzsp_version, tvb, 0, 1,
					tvb_get_guint8(tvb, 0));
		proto_tree_add_uint_format (tzsp_tree, hf_tzsp_encap, tvb, 2, 2,
					encapsulation, "Encapsulates: %s (%d)", encap_name, encapsulation);
	}

	tvb = tvb_new_subset(tvb, 4, -1, -1);
	pos = add_option_info(tvb, tzsp_tree, ti);
	next_tvb = tvb_new_subset(tvb, pos, -1, -1);

	if (wtap_encap == -1
	    || !dissector_try_port(encap_dissector_table, wtap_encap,
		next_tvb, pinfo, tree)) {

		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO, "TZSP_ENCAP = %u",
			    encapsulation);
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}

/* ************************************************************************* */
/*                Register the TZSP dissector                                */
/* ************************************************************************* */

void
proto_register_tzsp(void)
{

  static const value_string msg_type[] = {
    {0,     "Normal"},
    {1,	    "RFC1042 encoded"},
    {2,     "Bridge-tunnel encoded"},
    {4,     "802.11 management frame"},
    {0,     NULL}
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

  static const value_string rates[] = {
    {0x0A, "1 Mbit/s"},
    {0x14, "2 Mbit/s"},
    {0x37, "5.5 Mbit/s"},
    {0x6E, "11 Mbit/s"},
    {0, NULL}
  };

	static hf_register_info hf[] = {
		{ &hf_tzsp_version, {
			"Version", "tzsp.version", FT_UINT8, BASE_DEC,
			NULL, 0, "Version", HFILL }},
		{ &hf_tzsp_reserved, {
			"Reserved", "tzsp.reserved", FT_UINT8, BASE_DEC,
			NULL, 0, "Reserved", HFILL }},
		{ &hf_tzsp_encap, {
			"Encapsulation", "tzsp.encap", FT_UINT16, BASE_DEC,
			NULL, 0, "Encapsulation", HFILL }},
		{ &hf_status_field, {
			"Status", "tzsp.wlan.status", FT_UINT16, BASE_HEX,
				NULL, 0, "Status", HFILL }},
		{ &hf_status_msg_type, {
			"Type", "tzsp.wlan.status.msg_type", FT_UINT8, BASE_HEX,
			VALS(msg_type), 0, "Message type", HFILL }},
		{ &hf_status_mac_port, {
			"Port", "tzsp.wlan.status.mac_port", FT_UINT8, BASE_DEC,
			NULL, 0, "MAC port", HFILL }},
		{ &hf_status_pcf, {
			"PCF", "tzsp.wlan.status.pcf", FT_BOOLEAN, BASE_HEX,
			VALS (&pcf_flag), 0, "Point Coordination Function", HFILL }},
		{ &hf_status_undecrypted, {
			"Undecrypted", "tzsp.wlan.status.undecrypted", FT_BOOLEAN, BASE_HEX,
			VALS (&undecr_flag), 0, "Undecrypted", HFILL }},
		{ &hf_status_fcs_error, {
			"FCS", "tzsp.wlan.status.fcs_err", FT_BOOLEAN, BASE_HEX,
			VALS (&fcs_err_flag), 0, "Frame check sequence", HFILL }},
		{ &hf_time, {
			"Time", "tzsp.wlan.time", FT_UINT32, BASE_HEX,
			NULL, 0, "Time", HFILL }},
		{ &hf_silence, {
			"Silence", "tzsp.wlan.silence", FT_UINT8, BASE_HEX,
			NULL, 0, "Silence", HFILL }},
		{ &hf_signal, {
			"Signal", "tzsp.wlan.signal", FT_UINT8, BASE_HEX,
			NULL, 0, "Signal", HFILL }},
		{ &hf_rate, {
			"Rate", "tzsp.wlan.rate", FT_UINT8, BASE_HEX,
			VALS(rates), 0, "Rate", HFILL }},
		{ &hf_channel, {
			"Channel", "tzsp.wlan.channel", FT_UINT8, BASE_DEC,
			NULL, 0, "Channel", HFILL }}
	};

	static gint *ett[] = {
		&ett_tzsp
	};

	proto_tzsp = proto_register_protocol("Tazmen Sniffer Protocol", "TZSP",
	    "tzsp");
	proto_register_field_array(proto_tzsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_tzsp(void)
{
	dissector_handle_t tzsp_handle;

	tzsp_handle = create_dissector_handle(dissect_tzsp, proto_tzsp);
	dissector_add("udp.port", UDP_PORT_TZSP, tzsp_handle);

	/* Get the data dissector for handling unknown encapsulation types. */
	data_handle = find_dissector("data");

	/* Register this protocol as an ecapsulation type. */
	dissector_add("wtap_encap", WTAP_ENCAP_TZSP, tzsp_handle);

	encap_dissector_table = find_dissector_table("wtap_encap");
}
