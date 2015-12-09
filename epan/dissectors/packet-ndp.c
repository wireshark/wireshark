/* packet-ndp.c
 * Routines for the disassembly of the Nortel Discovery Protocol, formerly
 * the SynOptics Network Management Protocol (SONMP).
 * (c) Copyright Giles Scott <giles.scott1 [AT] arubanetworks.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This protocol has gone by many names over the years:
 *
 * Bay Discovery Protocol (BDP), Bay Topology Protocol, Bay Network Management
 * Protocol (BNMP), Nortel Management MIB (NMM), Nortel Topology Discovery
 * Protocol (NTDP), SynOptics Network Management Protocol (SONMP).
 *   (source: Wikipedia article on "Nortel Discovery Protocol")
 *
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_ndp(void);
void proto_reg_handoff_ndp(void);

/* Although this protocol is proprietary it is documented in the SynOptics MIB's
 * So I'm not giving anything away :-)
 * The only thing I have not done is decode the segment identifier;
 * This changes so much depending on whether the chassis supports
 * multi-segment autotopology. As the 5000 is now EOL don't see much point.
 *
 * MIB's s5emt104.mib, s5tcs112.mib, synro199.mib these should be available via
 * http://www.nortelnetworks.com
 */


/* chassis types */
/* Last updated from version 229 ("200609010000Z") of SnpxChassisType in SYNOPTICS-ROOT-MIB.mib */
static const value_string ndp_chassis_val[] =
{
	{  1, "other"},
	{  2, "3000"},
	{  3, "3030"},
	{  4, "2310"},
	{  5, "2810"},
	{  6, "2912"},
	{  7, "2914"},
	{  8, "271x"},
	{  9, "2813"},
	{ 10, "2814"},
	{ 11, "2915"},
	{ 12, "5000"},
	{ 13, "2813SA"},
	{ 14, "2814SA"},
	{ 15, "810M"},
	{ 16, "Ethercell"},
	{ 17, "5005"},
	{ 18, "Alcatel Ethernet workgroup conc."},

	{ 20, "2715SA"},
	{ 21, "2486"},
	{ 22, "28000 series"},
	{ 23, "23000 series"},
	{ 24, "5DN00x series"},
	{ 25, "BayStack Ethernet"},
	{ 26, "23100 series"},
	{ 27, "100Base-T Hub"},
	{ 28, "3000 Fast Ethernet"},
	{ 29, "Orion switch"},
	/* 30 is "not used" */
	{ 31, "DDS"},
	{ 32, "Centillion (6 slot)"},
	{ 33, "Centillion (12 slot)"},
	{ 34, "Centillion (1 slot)"},
	{ 35, "BayStack 301"},
	{ 36, "BayStack TokenRing Hub"},
	{ 37, "FVC Multimedia Switch"},
	{ 38, "Switch Node"},
	{ 39, "BayStack 302 Switch"},
	{ 40, "BayStack 350 Switch"},
	{ 41, "BayStack 150 Ethernet Hub"},
	{ 42, "Centillion 50N switch"},
	{ 43, "Centillion 50T switch"},
	{ 44, "BayStack 303 and 304 Switches"},
	{ 45, "BayStack 200 Ethernet Hub"},
	{ 46, "BayStack 250 10/100 Ethernet Hub"},
	/*{ 47, "StackProbe"}, XXX - No longer listed */
	{ 48, "BayStack 450 10/100/1000 Switches"},
	{ 49, "BayStack 410 10/100 Switches"},
	{ 50, "Passport 1200 L3 Switch"},
	{ 51, "Passport 1250 L3 Switch"},
	{ 52, "Passport 1100 L3 Switch"},
	{ 53, "Passport 1150 L3 Switch"},
	{ 54, "Passport 1050 L3 Switch"},
	{ 55, "Passport 1051 L3 Switch"},
	{ 56, "Passport 8610 L3 Switch"},
	{ 57, "Passport 8606 L3 Switch"},
	{ 58, "Passport 8010"},
	{ 59, "Passport 8006"},
	{ 60, "BayStack 670 wireless access point"},
	{ 61, "Passport 740"},
	{ 62, "Passport 750"},
	{ 63, "Passport 790"},
	{ 64, "Business Policy Switch 2000 10/100 Switches"},
	{ 65, "Passport 8110 L2 Switch"},
	{ 66, "Passport 8106 L2 Switch"},
	{ 67, "BayStack 3580 Gig Switch"},
	{ 68, "BayStack 10 Power Supply Unit"},
	{ 69, "BayStack 420 10/100 Switch"},
	{ 70, "OPTera Metro 1200 Ethernet Service Module"},
	{ 71, "OPTera 8010co"},
	{ 72, "OPTera 8610co L3 switch"},
	{ 73, "OPTera 8110co L2 switch"},
	{ 74, "OPTera 8003"},
	{ 75, "OPTera 8603 L3 switch"},
	{ 76, "OPTera 8103 L2 switch"},
	{ 77, "BayStack 380 10/100/1000 Switch"},
	{ 78, "Ethernet Switch 470-48T"},
	{ 79, "OPTera Metro 1450 Ethernet Service Module"},
	{ 80, "OPTera Metro 1400 Ethernet Service Module"},
	{ 81, "Alteon Switch Family"},
	{ 82, "Ethernet Switch 460-24T-PWR"},
	{ 83, "OPTera Metro 8010 OPM L2 Switch"},
	{ 84, "OPTera Metro 8010co OPM L2 Switch"},
	{ 85, "OPTera Metro 8006 OPM L2 Switch"},
	{ 86, "OPTera Metro 8003 OPM L2 Switch"},
	{ 87, "Alteon 180e"},
	{ 88, "Alteon AD3"},
	{ 89, "Alteon 184"},
	{ 90, "Alteon AD4"},
	{ 91, "Passport 1424 L3 switch"},
	{ 92, "Passport 1648 L3 switch"},
	{ 93, "Passport 1612 L3 switch"},
	{ 94, "Passport 1624 L3 switch"},
	{ 95, "BayStack 380-24F Fiber 1000 Switch"},
	{ 96, "Ethernet Routing Switch 5510-24T"},
	{ 97, "Ethernet Routing Switch 5510-48T"},
	{ 98, "Ethernet Switch 470-24T"},
	{ 99, "Nortel Networks Wireless LAN Access Point 2220"},
	{100, "Passport RBS 2402 L3 switch"},
	{101, "Alteon Application Switch 2424"},
	{102, "Alteon Application Switch 2224"},
	{103, "Alteon Application Switch 2208"},
	{104, "Alteon Application Switch 2216"},
	{105, "Alteon Application Switch 3408"},
	{106, "Alteon Application Switch 3416"},
	{107, "Nortel Networks Wireless LAN SecuritySwitch 2250"},
	{108, "Ethernet Switch 425-48T"},
	{109, "Ethernet Switch 425-24T"},
	{110, "Nortel Networks Wireless LAN Access Point 2221"},
	{111, "Nortel Metro Ethernet Service Unit 24-T SPF switch"},
	{112, " Nortel Metro Ethernet Service Unit 24-T LX DC switch"},
	{113, "Passport 8300 10-slot chassis"},
	{114, "Passport 8300 6-slot chassis"},
	{115, "Ethernet Routing Switch 5520-24T-PWR"},
	{116, "Ethernet Routing Switch 5520-48T-PWR"},
	{117, "Nortel Networks VPN Gateway 3050"},
	{118, "Alteon SSL 310 10/100"},
	{119, "Alteon SSL 310 10/100 Fiber"},
	{120, "Alteon SSL 310 10/100 FIPS"},
	{121, "Alteon SSL 410 10/100/1000"},
	{122, "Alteon SSL 410 10/100/1000 Fiber"},
	{123, "Alteon Application Switch 2424-SSL"},
	{124, "Ethernet Switch 325-24T"},
	{125, "Ethernet Switch 325-24G"},
	{126, "Nortel Networks Wireless LAN Access Point 2225"},
	{127, "Nortel Networks Wireless LAN SecuritySwitch 2270"},
	{128, "24-port Ethernet Switch 470-24T-PWR"},
	{129, "48-port Ethernet Switch 470-48T-PWR"},
	{130, "Ethernet Routing Switch 5530-24TFD"},
	{131, "Ethernet Switch 3510-24T"},
	{132, "Nortel Metro Ethernet Service Unit 12G AC L3 switch"},
	{133, "Nortel Metro Ethernet Service Unit 12G DC L3 switch"},
	{134, "Nortel Secure Access Switch"},
	{135, "Nortel Networks VPN Gateway 3070"},
	{136, "OPTera Metro 3500"},
	{137, "SMB BES 1010 24T"},
	{138, "SMB BES 1010 48T"},
	{139, "SMB BES 1020 24T PWR"},
	{140, "SMB BES 1020 48T PWR"},
	{141, "SMB BES 2010 24T"},
	{142, "SMB BES 2010 48T"},
	{143, "SMB BES 2020 24T PWR"},
	{144, "SMB BES 2020 48T PWR"},
	{145, "SMB BES 110 24T"},
	{146, "SMB BES 110 48T"},
	{147, "SMB BES 120 24T PWR"},
	{148, "SMB BES 120 48T PWR"},
	{149, "SMB BES 210 24T"},
	{150, "SMB BES 210 48T"},
	{151, "SMB BES 220 24T PWR"},
	{152, "SMB BES 220 48T PWR"},
	{153, "OME 6500"},
	{154, "Ethernet Routing Switch 4548GT"},
	{155, "Ethernet Routing Switch 4548GT-PWR"},
	{156, "Ethernet Routing Switch 4550T"},
	{157, "Ethernet Routing Switch 4550T-PWR"},
	{158, "Ethernet Routing Switch 4526FX"},
	{159, "Ethernet Routing Switch 2500-26T"},
	{160, "Ethernet Routing Switch 2500-26T-PWR"},
	{161, "Ethernet Routing Switch 2500-50T"},
	{162, "Ethernet Routing Switch 2500-50T-PWR"},
	{0, NULL}
};
static value_string_ext ndp_chassis_val_ext = VALUE_STRING_EXT_INIT(ndp_chassis_val);

/* from synro179.mib - SnpxBackplaneType */
static const value_string ndp_backplane_val[] =
{
	{ 1, "Other"},
	{ 2, "Ethernet"},
	{ 3, "Ethernet and Tokenring"},
	{ 4, "Ethernet and FDDI"},
	{ 5, "Ethernet, Tokenring and FDDI"},
	{ 6, "Ethernet and Tokenring with redundant power"},
	{ 7, "Ethernet, Tokenring, FDDI with redundant power"},
	{ 8, "Token Ring"},
	{ 9, "Ethernet, Tokenring and Fast Ethernet"},
	{10, "Ethernet and Fast Ethernet"},
	{11, "Ethernet, Tokenring, Fast Ethernet with redundant power"},
	{12, "Ethernet, Fast Ethernet and Gigabit Ethernet"},
	{0, NULL}
};
static value_string_ext ndp_backplane_val_ext = VALUE_STRING_EXT_INIT(ndp_backplane_val);

static const value_string ndp_state_val[] =
{
	{1, "Topology Change"},
	{2, "Heartbeat"},
	{3, "New"},
	{0, NULL}
};


/* Offsets in NDP Hello structure. */
#define NDP_IP_ADDRESS	        0
#define NDP_SEGMENT_IDENTIFIER  4
#define NDP_CHASSIS_TYPE        7
#define NDP_BACKPLANE_TYPE      8
#define NDP_STATE	        9
#define NDP_NUMBER_OF_LINKS    10

static int proto_ndp = -1;
static int hf_ndp_ip_address = -1;
static int hf_ndp_segment_identifier = -1;
static int hf_ndp_chassis_type = -1;
static int hf_ndp_backplane_type = -1;
static int hf_ndp_state = -1;
static int hf_ndp_number_of_links = -1;

static gint ett_ndp = -1;


static int
dissect_ndp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	const char *hello_type;
	proto_tree *ndp_tree = NULL;
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDP");

	hello_type = "";
	if (pinfo->dl_dst.type == AT_ETHER) {
		const guint8 *dstmac = (const guint8 *)pinfo->dl_dst.data;

		switch (dstmac[5]) {

		case 0:
			hello_type = "Segment ";
			break;

		case 1:
			hello_type = "FlatNet ";
			break;
		}
	}
	col_add_fstr(pinfo->cinfo, COL_INFO, "%sHello", hello_type);

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_ndp, tvb, 0, 11,
			"Nortel Discovery Protocol");

		ndp_tree = proto_item_add_subtree(ti, ett_ndp);

		proto_tree_add_item(ndp_tree, hf_ndp_ip_address, tvb,
			NDP_IP_ADDRESS, 4, ENC_BIG_ENDIAN);


		proto_tree_add_item(ndp_tree, hf_ndp_segment_identifier, tvb,
			NDP_SEGMENT_IDENTIFIER, 3, ENC_BIG_ENDIAN);


		proto_tree_add_item(ndp_tree, hf_ndp_chassis_type, tvb,
			NDP_CHASSIS_TYPE, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(ndp_tree, hf_ndp_backplane_type, tvb,
			NDP_BACKPLANE_TYPE, 1, ENC_BIG_ENDIAN);


		proto_tree_add_item(ndp_tree, hf_ndp_state, tvb,
			NDP_STATE, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(ndp_tree, hf_ndp_number_of_links, tvb,
			NDP_NUMBER_OF_LINKS, 1, ENC_BIG_ENDIAN);
	}

	return tvb_captured_length(tvb);
}



void
proto_register_ndp(void)
{
	static hf_register_info hf[] = {
		{ &hf_ndp_ip_address,
		  { "IP address",		"ndp.ipaddress",  FT_IPv4, BASE_NONE, NULL, 0x0,
		    "IP address of the Network Management Module (NMM))", HFILL }},

		{ &hf_ndp_segment_identifier,
		  { "Segment Identifier",		"ndp.segmentident", FT_UINT24, BASE_HEX, NULL, 0x0,
		    "Segment id of the segment from which the agent is sending the topology message", HFILL }},

		{ &hf_ndp_chassis_type,
		  { "Chassis type",		"ndp.chassis", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
		    &ndp_chassis_val_ext, 0x0,
		    "Chassis type of the agent sending the topology message", HFILL }},

		{ &hf_ndp_backplane_type,
		  { "Backplane type",		"ndp.backplane", FT_UINT8, BASE_DEC|BASE_EXT_STRING,
		    &ndp_backplane_val_ext, 0x0,
		    "Backplane type of the agent sending the topology message", HFILL }},

		{ &hf_ndp_state,
		  { "State",		"ndp.state", FT_UINT8, BASE_DEC,
		    VALS(ndp_state_val), 0x0,
		    "Current state of this Network Management Module (NMM)", HFILL }},

		{ &hf_ndp_number_of_links,
		  { "Number of links",		"ndp.numberoflinks", FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of interconnect ports", HFILL }},
	};

	static gint *ett[] = {
		&ett_ndp,
	};
	proto_ndp = proto_register_protocol("Nortel Discovery Protocol", "NDP", "ndp");
	proto_register_field_array(proto_ndp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("ndp", dissect_ndp, proto_ndp);
}

void
proto_reg_handoff_ndp(void)
{
	dissector_handle_t ndp_handle;

	ndp_handle = find_dissector("ndp");

	dissector_add_uint("llc.nortel_pid", 0x01a1, ndp_handle); /* flatnet hello */
	dissector_add_uint("llc.nortel_pid", 0x01a2, ndp_handle); /* Segment hello */
	/* not got round to adding this but it's really old, so I'm not sure people will see it */
	/* it uses a different packet format */
	/*      dissector_add_uint("llc.nortel_pid", 0x01a3, ndp_handle); */ /* Bridge hello */
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
