/* packet-ebhscr.c
 * Routines for EBHSCR dissection
 * Copyright 2019, Ana Pantar <ana.pantar@gmail.com> for Elektrobit
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * For more information on this protocol see:
 * https://www.elektrobit.com/ebhscr
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>

void proto_reg_handoff_ebhscr(void);
void proto_register_ebhscr(void);

static int proto_ebhscr = -1;

static int hf_ebhscr_packet_header = -1;
static int hf_ebhscr_major_number = -1;
static int hf_ebhscr_slot = -1;
static int hf_ebhscr_channel = -1;
static int hf_ebhscr_status = -1;

static int hf_eth_link_up_down = -1;
static int hf_eth_master_slave = -1;
static int hf_eth_speed = -1;
static int hf_eth_phy = -1;

static int hf_eth_crc_error = -1;
static int hf_eth_mii_foe = -1;
static int hf_eth_payload_foe = -1;
static int hf_eth_hdr_foe = -1;
static int hf_eth_rcv_dec_err = -1;
static int hf_eth_sym_error = -1;
static int hf_eth_jabber_event = -1;
static int hf_eth_pol_ch_event = -1;

static int hf_ebhscr_version = -1;
static int hf_ebhscr_length = -1;
static int hf_ebhscr_start_timestamp = -1;
static int hf_ebhscr_stop_timestamp = -1;
static int hf_ebhscr_mjr_hdr = -1;

static gint ett_ebhscr = -1;
static gint ett_ebhscr_packet_header = -1;
static gint ett_ebhscr_status = -1;
static gint ett_ebhscr_mjr_hdr = -1;

static int * const eth_error_bits[] = {
	&hf_eth_crc_error,
	&hf_eth_mii_foe,
	&hf_eth_payload_foe,
	&hf_eth_hdr_foe,
	&hf_eth_rcv_dec_err,
	&hf_eth_sym_error,
	&hf_eth_jabber_event,
	&hf_eth_pol_ch_event,
	NULL
};

static int * const eth_mjr_hdr_bits[] = {
	&hf_eth_link_up_down,
	&hf_eth_master_slave,
	&hf_eth_speed,
	&hf_eth_phy,
	NULL
};
static const value_string eth_link_strings[] = {
	{ 0,	"Link Down" },
	{ 1,	"Link Up" },
	{ 0, NULL },
};

static const value_string eth_master_strings[] = {
	{ 0,	"Slave" },
	{ 1,	"Master" },
	{ 0, NULL },
};

static const value_string eth_speed_strings[] = {
	{ 0,	"Speed 10M" },
	{ 1,	"Speed 100M" },
	{ 2,	"Speed 1000M" },
	{ 3,	"Speed 2.5G" },
	{ 4,	"Speed 5G" },
	{ 5,	"Speed 10G" },
	{ 6,	"Speed 25G" },
	{ 7,	"Speed 40G" },
	{ 8,	"Speed 100G" },
	{ 9,	"Reserved" },
	{ 10,	"Reserved" },
	{ 11,	"Reserved" },
	{ 12,	"Reserved" },
	{ 13,	"Reserved" },
	{ 14,	"Reserved" },
	{ 15,	"Reserved" },
	{ 0, NULL },
};

static const value_string eth_phy_strings[] = {
	{ 0,	"Base T1" },
	{ 1,	"Reserved" },
	{ 2,	"Reserved" },
	{ 3,	"Reserved" },
	{ 4,	"Reserved" },
	{ 5,	"Reserved" },
	{ 6,	"Reserved" },
	{ 7,	"Reserved" },
	{ 8,	"Reserved" },
	{ 9,	"Reserved" },
	{ 10,	"Reserved" },
	{ 11,	"Reserved" },
	{ 12,	"Reserved" },
	{ 13,	"Reserved" },
	{ 14,	"Reserved" },
	{ 15,	"Reserved" },
	{ 0, NULL },
};

static expert_field ei_ebhscr_frame_header = EI_INIT;
static expert_field ei_ebhscr_status_flag = EI_INIT;

static dissector_handle_t eth_withfcs_handle;
static dissector_handle_t ebhscr_user_handle;

static dissector_table_t subdissector_table;

#define EBHSCR_USER_FIRST 0X43
#define EBHSCR_USER_LAST 0X4F

#define ETHERNET_FRAME 0x50
#define NMEA_FRAME 0x51
#define EBHSCR_HEADER_LENGTH 32

static int
dissect_ebhscr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *ebhscr_packet_header_tree = NULL;
	proto_tree *ebhscr_tree = NULL;
	tvbuff_t* next_tvb;
	guint32 ebhscr_frame_length, ebhscr_length;
	gint ebhscr_current_payload_length;
	guint8 ebhscr_major_num, ebhscr_channel;
	guint16 ebhscr_status = 0;

	guint8 *nmea_str;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EBHSCR");
	col_clear(pinfo->cinfo, COL_INFO);

	ebhscr_frame_length = tvb_captured_length(tvb);

	ti = proto_tree_add_item(tree, proto_ebhscr, tvb, 0, -1, ENC_NA);
	ebhscr_tree = proto_item_add_subtree(ti, ett_ebhscr);

	if (ebhscr_frame_length < EBHSCR_HEADER_LENGTH) {
		expert_add_info(pinfo, ebhscr_tree, &ei_ebhscr_frame_header);
		return tvb_captured_length(tvb);
	}

	ebhscr_major_num = tvb_get_guint8(tvb, 0);
	ebhscr_channel = tvb_get_guint8(tvb, 1) & 0x3F;

	col_add_fstr(pinfo->cinfo, COL_DEF_DST, "%u ", ebhscr_channel);

	ebhscr_status = tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN) & 0xFFF0;
	if (ebhscr_status) {
		expert_add_info(pinfo, ebhscr_tree, &ei_ebhscr_status_flag);
	}

	ti = proto_tree_add_item(ebhscr_tree, hf_ebhscr_packet_header, tvb, 0, 4, ENC_BIG_ENDIAN);
	ebhscr_packet_header_tree = proto_item_add_subtree(ti, ett_ebhscr_packet_header);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_major_number, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_slot, tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_channel, tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_version, tvb, 2, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_length, tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_start_timestamp, tvb, 8, 8, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_stop_timestamp, tvb, 16, 8, ENC_BIG_ENDIAN);
	proto_tree_add_item(ebhscr_packet_header_tree, hf_ebhscr_mjr_hdr, tvb, 24, 8, ENC_BIG_ENDIAN);

	/* received hdr only and no data */
	if (ebhscr_frame_length == EBHSCR_HEADER_LENGTH) {
		return tvb_captured_length(tvb);
	}

	ebhscr_current_payload_length = ebhscr_frame_length - EBHSCR_HEADER_LENGTH;

	if ((ebhscr_major_num >= EBHSCR_USER_FIRST) && (ebhscr_major_num <= EBHSCR_USER_LAST)) {
		if (ebhscr_user_handle != NULL) {
			next_tvb = tvb_new_subset_length(tvb, 0, ebhscr_frame_length);
			call_dissector(ebhscr_user_handle, next_tvb, pinfo, ebhscr_tree);
		}
		else {
			next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
			call_data_dissector(next_tvb, pinfo, tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "  %s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, 32, ebhscr_current_payload_length, ' '));
		}
	}

	if (ebhscr_major_num == ETHERNET_FRAME) {
		proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 2, hf_ebhscr_status, ett_ebhscr_status, eth_error_bits, ENC_BIG_ENDIAN);
		proto_tree_add_bitmask(ebhscr_packet_header_tree, tvb, 24, hf_ebhscr_mjr_hdr, ett_ebhscr_mjr_hdr, eth_mjr_hdr_bits, ENC_BIG_ENDIAN);
		/* payload is 802.3 Ethernet frame */
		next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
		call_dissector(eth_withfcs_handle, next_tvb, pinfo, tree);
	}

	if (ebhscr_major_num == NMEA_FRAME)
	{
		ebhscr_length = tvb_get_guint32(tvb, 4, ENC_BIG_ENDIAN);
		next_tvb = tvb_new_subset_length(tvb, 32, ebhscr_current_payload_length);
		call_data_dissector(next_tvb, pinfo, tree);
		nmea_str = tvb_get_string_enc(wmem_packet_scope(), tvb, 32, ebhscr_length, ENC_UTF_8);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", "NMEA:", nmea_str);
	}
	return tvb_captured_length(tvb);
}

void
proto_register_ebhscr(void)
{
	expert_module_t *expert_ebhscr;

	static hf_register_info hf[] = {
		{ &hf_ebhscr_packet_header,
			{ "Packet header", "ebhscr.hdr",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
			},
		{ &hf_ebhscr_major_number,
			{ "Major number", "ebhscr.mjr",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_slot,
			{ "Slot", "ebhscr.slot",
			FT_UINT8, BASE_HEX,
			NULL, 0xc0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_channel,
			{ "Channel", "ebhscr.channel",
			FT_UINT8, BASE_HEX,
			NULL, 0x3f,
			NULL, HFILL }
		},
		{ &hf_ebhscr_status,
			{ "Status", "ebhscr.sts",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_version,
			{ "Version", "ebhscr.ver",
			FT_UINT16, BASE_HEX,
			NULL, 0xF000,
			NULL, HFILL }
		},
		{ &hf_ebhscr_length,
			{ "Length", "ebhscr.len",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_start_timestamp,
			{ "Start timestamp", "ebhscr.strt",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_stop_timestamp,
			{ "Stop timestamp", "ebhscr.stpt",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ebhscr_mjr_hdr,
			{ "Major number specific header", "ebhscr.mjrhdr",
			FT_UINT64, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_eth_link_up_down,
			{ "Link Up or Down", "ebhscr.elud",
			FT_UINT32, BASE_DEC,
			VALS(eth_link_strings), 0x00000001,
			NULL, HFILL }
		},
		{ &hf_eth_master_slave,
			{ "Master or Slave (if supported)", "ebhscr.ems",
			FT_UINT32, BASE_DEC,
			VALS(eth_master_strings), 0x00000002,
			NULL, HFILL }
		},
		{ &hf_eth_speed,
			{ "Ethernet speed", "ebhscr.espd",
			FT_UINT32, BASE_DEC, VALS(eth_speed_strings), 0x000000F0,
			NULL, HFILL }
		},
		{ &hf_eth_phy,
			{ "Ethernet phy", "ebhscr.ephy",
			FT_UINT32, BASE_DEC, VALS(eth_phy_strings), 0x00000F00,
			NULL, HFILL }
		},
		{ &hf_eth_crc_error,
			{ "Ethernet CRC Error", "ebhscr.ece",
			FT_BOOLEAN, 16,
			NULL, 0x0001,
			NULL, HFILL }
		},
		{ &hf_eth_mii_foe,
			{ "Media-independent interface FIFO Overflow Error", "ebhscr.emiifoe",
			FT_BOOLEAN, 16,
			NULL, 0x0002,
			NULL, HFILL }
		},
		{ &hf_eth_payload_foe,
			{ "Payload FIFO Overflow Error", "ebhscr.epfoe",
			FT_BOOLEAN, 16,
			NULL, 0x0004,
			NULL, HFILL }
		},
		{ &hf_eth_hdr_foe,
			{ "Header FIFO Overflow Error", "ebhscr.ehfoe",
			FT_BOOLEAN, 16,
			NULL, 0x0008,
			NULL, HFILL }
		},
		{ &hf_eth_rcv_dec_err,
			{ "Receiver Decoder Error", "ebhscr.erde",
			FT_BOOLEAN, 16,
			NULL, 0x0010,
			NULL, HFILL }
		},
		{ &hf_eth_sym_error,
			{ "Symbol Error", "ebhscr.ese",
			FT_BOOLEAN, 16,
			NULL, 0x0020,
			NULL, HFILL }
		},
		{ &hf_eth_jabber_event,
			{ "Jabber", "ebhscr.ejbr",
			FT_BOOLEAN, 16,
			NULL, 0x0040,
			NULL, HFILL }
		},
		{ &hf_eth_pol_ch_event,
			{ "Polarity Change", "ebhscr.epch",
			FT_BOOLEAN, 16,
			NULL, 0x0080,
			NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_ebhscr,
		&ett_ebhscr_packet_header,
		&ett_ebhscr_status,
		&ett_ebhscr_mjr_hdr,
	};

	static ei_register_info ei[] = {
		{ &ei_ebhscr_frame_header,
			{ "ebhscr.frame_header", PI_MALFORMED, PI_ERROR,
			"Frame Header is malformed", EXPFILL }
		},
		{ &ei_ebhscr_status_flag,
			{ "ebhscr.sts", PI_PROTOCOL, PI_WARN,
			"Status Error Flag is set", EXPFILL }
		},
	};

	proto_ebhscr = proto_register_protocol(
		"EBHSCR Protocol",
		"EBHSCR",
		"ebhscr"
		);

	proto_register_field_array(proto_ebhscr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_ebhscr = expert_register_protocol(proto_ebhscr);
	expert_register_field_array(expert_ebhscr, ei, array_length(ei));

	register_dissector("ebhscr", dissect_ebhscr, proto_ebhscr);
	subdissector_table = register_decode_as_next_proto(proto_ebhscr, "ebhscr.subdissector", "ebhscr next level dissector", NULL);
}

void
proto_reg_handoff_ebhscr(void)
{
	static dissector_handle_t ebhscr_handle;

	eth_withfcs_handle = find_dissector_add_dependency("eth_withfcs", proto_ebhscr);
	ebhscr_user_handle = find_dissector_add_dependency("ebhscr_user", proto_ebhscr);

	ebhscr_handle = create_dissector_handle( dissect_ebhscr, proto_ebhscr);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_EBHSCR, ebhscr_handle);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
