/* packet-sonmp.c
* Routines for the disassembly of the "Nortel Networks / SynOptics Network Management Protocol"
* (c) Copyright Giles Scott <giles.scott1 [AT] arubanetworks.com>
*
* $Id$
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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
/* #include "strutil.h" */
#include <epan/nlpid.h>

/* Although this protocol is propietary it is documented in the SynOptics MIB's
* So I'm not giving anything away :-)
* The only thing I have not done is decode the segment identifier;
* This changes so much depending on whether the chassis supports
* multi-segment autotopology. As the 5000 is now EOL don't see much point.
*
* MIB's s5emt104.mib, s5tcs112.mib, synro199.mib these should be available via
* http://www.nortelnetworks.com
*/

  
/* chassis types */
/* From  synro199.mib - SnpxChassisType */
static value_string sonmp_chassis_val[] =
{
	{2, "m3000"},
	{3, "m3030"},
	{4, "m2310"},
	{5, "m2810"},
	{6, "m2912"},
	{7, "m2914"},
	{8, "m271x"},
	{9, "m2813"},
	{10, "m2814"},
	{11, "m2915"},
	{12, "m5000"},
	{13, "m2813SA"},
	{14, "m2814SA"},
	{15, "m810M"},
	{16, "m1032x Ethercell"},
	{17, "5005"},
	{18, "Alcatel Ethernet workgroup conc"},
	{20, "m2715SA"},
	{21, "m2486"},
	{22, "m28xxx"},
	{23, "m23xxx"},
	{24, "5DN000"},
	{25, "NBayStack"},
	{26, "m2310x"},
	{27, "BayStack100 hub"},
	{28, "M3000 Fast ethernet"},
	{29, "Xedia"},
	{31, "28200"},
	{32, "Centillion-sixSlot"},
	{33, "Centillion-twelveSlot"},
	{34, "Centillion-singleSlot"},
	{35, "BayStack301"},
	{36, "BayStackTr"},
	{37, "FVC Multimedia Switch"},
	{38, "SwitchNode"},
	{39, "BayStack 302"},
	{40, "BayStack 350"},
	{41, "BayStack 150"},
	{42, "Centillion 50"},
	{43, "Centillion 50tr"},
	{44, "BayStack 303-304"},
	{45, "BayStack 200"},
	{46, "BayStack 250"},
	{47, "StackProbe"},
	{48, "BayStack 450"},
	{49, "BayStack 303-24T"},
	{50, "Accelar 1200 L3 switch"},
	{51, "Accelar 1250 L3 switch"},
	{52, "Accelar 1100 L3 switch"},
	{53, "Accelar 1150 L3 switch"},
	{54, "Accelar 1050 L3 switch"},
	{55, "Accelar 1051 L3 switch"},
	{56, "Accelar 8610 L3 switch"},
	{57, "Accelar 8006"},
	{58, "Accelar 8010"},
	{59, "Accelar 8006"},
	{60, "BayStack 670"},
	{61, "Accelar 740"},
	{62, "Accelar 750"},
	{63, "Accelar 790"},
	{64, "Business Policy switch 2000"},
	{65, "Accelar 8110 L2 switch"},
	{66, "Accelar 8106 L2 switch"},
	{67, "BayStack 3580"},
	{68, "Baystack 10 PSU"},
	{69, "BayStack 420"},
	{70, "OPTera Metro 1200ESM"},
	{71, "OPTera 8010co"},
	{72, "OPTera 8610co L3 switch"},
	{73, "OPTera 8110co L2 switch"},
	{74, "OPTera 8003"},
	{75, "OPTera 8603 L3 switch"},
	{76, "OPTera 8103 L2 switch"},
	{77, "Baystack 380 10/100/1000 switch"},
	{78, "Baystack 470 10/100 switch"},
	{79, "OPTera Metro 1450ESM"},
	{80, "OPTera Metro 1400ESM"},
	{81, "Alteon switch family"},
	{82, "BayStack 460-24T-PWR"},
	{83, "OPTera Metro 8010 OPM L2 Switch"},
	{84, "OPTera Metro 8010co OPM L2 Switch"},
	{85, "OPTera Metro 8006 OPM L2 Switch"},
	{86, "OPTera Metro 8003 OPM L2 Switch"},
	{87, "Alteon 180e"},
	{88, "Alteon AD3"},
	{89, "Alteon 184"},
	{90, "Alteon AD4"},
	{91, "Passport 1424 L3 switch"},
	{92, "Passport 1648 L3 switch"},
	{93, "Passport 1612 L3 switch"},
	{94, "Passport 1624 L3 switch"},
	{95, "BayStack 380-24F Fiber 1000 switch"},
	{96, "BayStack 4700 24T switch"},
	{97, "BayStack 4700 48T switch"},
	{98, "BayStack 5510 24-port"},
	{99, "BayStack 2200 Wireless LAN AP"},
	{100, "Passport RBS 2402 L3 switch"},
	{101, "Alteon AAS 2424"},
	{102, "Alteon AAS 2224"},
	{103, "Alteon AAS 2208"},
	{104, "Alteon AAS 2216"},
	{105, "Alteon AAS 3408"},
	{106, "Alteon AAS 3416"}, 
        {107, "WLAN SecuritySwitch 2250"},
        {108, "BayStack 425 48-port"},
        {109, "Baystack 425 24-port"},
        {110, "WLAN AP 2221"},
	{0, NULL}
};

/* from synro179.mib - SnpxBackplaneType */
static value_string sonmp_backplane_val[] =
{
	{1, "Other"},
	{2, "ethernet"},
	{3, "ethernet and tokenring"},
	{4, "ethernet and FDDI"},
	{5, "ethernet, tokenring and FDDI"},
	{6, "ethernet and tokenring with redundant power"},
	{7, "ethernet, tokenring, FDDI with redunadant power"},
	{8, "token ring"},
	{9, "ethernet, tokenring and fast ethernet"},
	{10, "ethernet and fast ethernet"},
	{11, "ethernet, tokenring, fast ethernet with redunant power"},
	{12, "ethernet, fast ethernet and gigabit ethernet"},
	{0, NULL}
};

static value_string sonmp_nmm_state_val[] =
{
	{1, "Topology Change"},
	{2, "Heartbeat"},
	{3, "New"},
	{0, NULL}
};


/* Offsets in SONMP NMM Hello structure. */
#define SONMP_IP_ADDRESS 0
#define SONMP_SEGMENT_IDENTIFIER 4
#define SONMP_CHASSIS_TYPE 7
#define SONMP_BACKPLANE_TYPE 8
#define SONMP_NMM_STATE 9
#define SONMP_NUMBER_OF_LINKS 10

static int proto_sonmp = -1;
static int hf_sonmp_ip_address = -1;
static int hf_sonmp_segment_identifier = -1; 
static int hf_sonmp_chassis_type = -1;
static int hf_sonmp_backplane_type = -1;
static int hf_sonmp_nmm_state = -1;
static int hf_sonmp_number_of_links = -1;

static gint ett_sonmp = -1;


static void 
dissect_sonmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	const char *hello_type;
	proto_tree *sonmp_tree = NULL;
	proto_item *ti;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SONMP");
	
	if (check_col(pinfo->cinfo, COL_INFO)) {
		hello_type = "";
		if (pinfo->dl_dst.type == AT_ETHER) {

			switch (pinfo->dl_dst.data[5]) {

			case 0:
				hello_type = "Segment ";
				break;

			case 1:
				hello_type = "FlatNet ";
				break;
			}
		}
		col_add_fstr(pinfo->cinfo, COL_INFO, "SONMP - %sHello",
		    hello_type);
	}
	
	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_sonmp, tvb, 0, 11,
			"Nortel Networks / SynOptics Network Management Protocol");
		sonmp_tree = proto_item_add_subtree(ti, ett_sonmp);
		
		proto_tree_add_item(sonmp_tree, hf_sonmp_ip_address, tvb,
			SONMP_IP_ADDRESS, 4, FALSE);
		
		
		proto_tree_add_item(sonmp_tree, hf_sonmp_segment_identifier, tvb, 
			SONMP_SEGMENT_IDENTIFIER, 3, FALSE);
		
		
		proto_tree_add_item(sonmp_tree, hf_sonmp_chassis_type, tvb,
			SONMP_CHASSIS_TYPE, 1, FALSE);
		
		proto_tree_add_item(sonmp_tree, hf_sonmp_backplane_type, tvb,
			SONMP_BACKPLANE_TYPE, 1, FALSE);
		
		
		proto_tree_add_item(sonmp_tree, hf_sonmp_nmm_state, tvb,
			SONMP_NMM_STATE, 1, FALSE);
		
		proto_tree_add_item(sonmp_tree, hf_sonmp_number_of_links, tvb,
			SONMP_NUMBER_OF_LINKS, 1, FALSE);
	}
	
	
}



void
proto_register_sonmp(void)
{
    static hf_register_info hf[] = {
		{ &hf_sonmp_ip_address,
		{ "NMM IP address",		"sonmp.ipaddress",  FT_IPv4, BASE_NONE, NULL, 0x0,
		"IP address of the agent (NMM)", HFILL }},
		
		{ &hf_sonmp_segment_identifier,
		{ "Segment Identifier",		"sonmp.segmentident", FT_UINT24, BASE_HEX, NULL, 0x0,
		"Segment id of the segment from which the agent is sending the topology message", HFILL }},
		
		{ &hf_sonmp_chassis_type,
		{ "Chassis type",		"sonmp.chassis", FT_UINT8, BASE_DEC, 
		VALS(sonmp_chassis_val), 0x0,
		"Chassis type of the agent sending the topology message", HFILL }},
		
		{ &hf_sonmp_backplane_type,
		{ "Backplane type",		"sonmp.backplane", FT_UINT8, BASE_DEC,
		 VALS(sonmp_backplane_val), 0x0,
		"Backplane type of the agent sending the topology message", HFILL }},
		
		{ &hf_sonmp_nmm_state,
		{ "NMM state",		"sonmp.nmmstate", FT_UINT8, BASE_DEC,
		 VALS(sonmp_nmm_state_val), 0x0,
		"Current state of this agent", HFILL }},
		
		{ &hf_sonmp_number_of_links,
		{ "Number of links",		"sonmp.numberoflinks", FT_UINT8, BASE_DEC, NULL, 0x0,
		"Number of interconnect ports", HFILL }},
    };
	
    static gint *ett[] = {
		&ett_sonmp,
    };
    proto_sonmp = proto_register_protocol("Nortel SONMP", "SONMP", "sonmp");
    proto_register_field_array(proto_sonmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
	
    register_dissector("sonmp", dissect_sonmp, proto_sonmp);
}

void
proto_reg_handoff_sonmp(void)
{
	dissector_handle_t sonmp_handle;
	
	sonmp_handle = create_dissector_handle(dissect_sonmp, proto_sonmp);
	
	dissector_add("llc.nortel_pid", 0x01a1, sonmp_handle); /* flatnet hello */
	dissector_add("llc.nortel_pid", 0x01a2, sonmp_handle); /* Segment hello */ 
	/* not got round to adding this but its really old, so I'm not sure people will see it */
	/* it uses a different packet format */
	/*      dissector_add("llc.nortel_pid", 0x01a3, sonmp_handle); */ /* Bridge hello */
}
