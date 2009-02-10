/* packet-gtpv2.c
 *
 * Routines for GTPv2 dissection
 * Copyright 2009, Anders Broman <anders.broman [at] ericcsson.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * Ref: ETSI TS 129 274 V8.0.0 (2009-01)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

static int proto_gtpv2 = -1;
static int hf_gtpv2_flags = -1;
static int hf_gtpv2_version = -1;
static int hf_gtpv2_t = -1;
static int hf_gtpv2_message_type = -1;
static int hf_gtpv2_msg_length = -1;
static int hf_gtpv2_teid = -1;
static int hf_gtpv2_seq = -1;
static int hf_gtpv2_spare = -1;
static int hf_gtpv2_ie = -1;
static int hf_gtpv2_ie_len = -1;
static int hf_gtpv2_cr = -1;
static int hf_gtpv2_instance = -1;

static gint ett_gtpv2 = -1;
static gint ett_gtpv2_flags = -1;
static gint ett_gtpv2_ie = -1;


static const value_string gtpv2_message_type_vals[] = {
	{0, "Reserved"},
	{1, "Echo Request"},
	{2, "Echo Response"},
	{4, "Version Not Supported Indication"},
	/* 4-24 Reserved for S101 interface TS 29.276 */
	/* 25-31 Reserved for Sv interface TS 29.280 */
	{32, "Create Session Request"},
	{33, "Create Session Response"},
	{34, "Update User Plane Request"},
	{35, "Update User Plane Response"},
	{36, "Modify Bearer Request"},
	{37, "Modify Bearer Response"},
	{38, "Delete Session Request"},
	{39, "Delete Session Response"},
	{40, "Change Notification Request"},
	{41, "Change Notification Response"},
	/* 42-63 For future use */
	/* Messages without explicit response */
	{64, "Modify Bearer Command"},							/* (MME/SGSN to PGW –S11/S4, S5/S8) */
	{65, "Modify Bearer Failure Indication"},				/*(PGW to MME/SGSN –S5/S8, S11/S4) */
	{66, "Delete Bearer Command"},							/* (MME to PGW –S11, S5/S8) */
	{67, "Delete Bearer Failure Indication"},				/* (PGW to MME –S5/S8, S11) */
	{68, "Bearer Resource Command"},						/* (MME/SGSN to PGW –S11/S4, S5/S8) */
	{69, "Bearer Resource Failure Indication"},				/* (PGW to MME/SGSN –S5/S8, S11/S4) */
	{70, "Downlink Data Notification Failure Indication"},	/*(SGSN/MME to SGW –S4/S11) */
	/* 71-94 For future use PDN-GW to SGSN/MME (S5/S8, S4/S11) */
	{95, "Create Bearer Request "},
	{96, "Create Bearer Response "},
	{97, "Update Bearer Request "},
	{98, "Update Bearer Response "},
	{99, "Delete Bearer Request "},
	{100, "Delete Bearer Response "},
	/* 101-127 For future use MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN (S3/10/S16) */
	{128, "Identification Request "},
	{129, "Identification Response "},
	{130, "Context Request "},
	{131, "Context Response "},
	{132, "Context Acknowledge "},
	{133, "Forward Relocation Request "},
	{134, "Forward Relocation Response "},
	{135, "Forward Relocation Complete Notification "},
	{136, "Forward Relocation Complete Acknowledge "},
	{137, "Forward SRNS Context Notification "},
	{138, "Forward SRNS Context Acknowledge "},
	{139, "Relocation Cancel Request "},
	{140, "Relocation Cancel Response "},
	/* 141-148 For future use SGSN to MME, MME to SGSN (S3) */
	{149, "Detach Notification "},
	{150, "Detach Acknowledge "},
	{151, "CS Paging Indication "},
	/* 152-159 For future use */
	{160, "Create Forwarding Tunnel Request "},
	{161, "Create Forwarding Tunnel Response "},
	{162, "Suspend Notification "},
	{163, "Suspend Acknowledge "},
	{164, "Resume Notification "},
	{165, "Resume Acknowledge "},
	{166, "Create Indirect Data Forwarding Tunnel Request "},
	{167, "Create Indirect Data Forwarding Tunnel Response "},
	/* 168-175 For future use SGW to SGSN/MME (S4/S11) */
	{176, "Downlink Data Notification "},
	{177, "Downlink Data Notification Acknowledgement "},
	{178, "Update Bearer Complete "},
	/* 179-191 For future use */
	/* Other */
	/* 192-244 For future use */
	/* 245-255 Reserved for GTP-U TS 29.281 [13] */
    {0, NULL}
};

/* Table 8.1-1: Information Element types for GTPv2 */
static const value_string gtpv2_element_type_vals[] = {
	{0, "Reserved"},
	{1, "International Mobile Subscriber Identity (IMSI)"},		/* Extendable / 8.3 */
	{2, "Cause (without embedded offending IE)"},				/* Extendable / 8.4 */
	{3, "Recovery (Restart Counter)"},							/* Extendable / 8.5 */
	/* 4-50 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
	/* 51-70 Reserved for Sv interface Extendable / See 3GPP TS 29.280 [15] */
	{71, "Access Point Name (APN)"},							/* Extendable / 8.6 */
	{72, "Aggregate Maximum Bit Rate (AMBR)"},					/* Extendable / 8.7 */
	{73, "EPS Bearer ID (EBI)"},								/* Extendable / 8.8 */
	{74, "IP Address"},											/* Extendable / 8.9 */
	{75, "Mobile Equipment Identity (MEI)"},					/* Extendable / 8.10 */
	{76, "MSISDN"},												/* Extendable / 8.11 */
	{77, "Indication"},											/* Extendable / 8.12 */
	{78, "Protocol Configuration Options (PCO)"},				/* Extendable / 8.13 */
	{79, "PDN Address Allocation (PAA)"},						/* Extendable / 8.14 */
	{80, "Bearer Level Quality of Service (Bearer QoS)"},		/* Extendable / 8.15 */
	{81, "Flow Quality of Service (Flow QoS)"},					/* Extendable / 8.16 */
	{82, "RAT Type"},											/* Extendable / 8.17 */
	{83, "Serving Network"},									/* Extendable / 8.18 */
	{84, "TEID-C"},												/* Extendable / 8.19 */
																/* TEID-U Extendable / 8.19a */
																/* TEID-U with EPS Bearer ID Extendable / 8.19b */
	{85, "EPS Bearer Level Traffic Flow Template (Bearer TFT)"},/* Extendable / 8.20 */
	{86, "Traffic Aggregation Description (TAD)"},				/* Extendable / 8.21 */
	{87, "User Location Info (ULI)"},							/* Extendable / 8.22 */
	{88, "Fully Qualified Tunnel Endpoint Identifier (F-TEID)"},/* Extendable / 8.23 */
	{89, "TMSI"},												/* Extendable / 8.24 */
	{90, "Global CN-Id"},										/* Extendable / 8.25 */
	{91, "Legacy Quality of Service (Legacy QoS)"},				/* Extendable / 8.26 */
	{92, "S103 PDN Data Forwarding Info (S103PDF)"},			/* Extendable / 8.27 */
	{93, "S1-U Data Forwarding Info (S1UDF)"},					/* Extendable / 8.28 */
	{94, "Delay Value"},										/* Extendable / 8.29 */
	{95, "Bearer ID List"},										/* Extendable / 8.30 */
	{96, "Bearer Context"},										/* Extendable / 8.31 */
	{97, "S101-IP-Address"},									/* Extendable / 8.32 */
	{98, "S102-IP-Address"},									/* Extendable / 8.33 */
	{99, "Charging ID"},										/* Extendable / 8.34 */
	{100, "Charging Characteristics"},							/* Extendable / 8.35 */
	{101, "Trace Information"},									/* Extendable / 8.36 */
	{102, "Bearer Flags"},										/* Extendable / 8.37 */
	{103, "Paging Cause"},										/* Extendable / 8.38 */
	{104, "PDN Type"},											/* Extendable / 8.39 */
	{105, "Procedure Transaction ID"},							/* Extendable / 8.40 */
	{106, "DRX Parameter"},										/* Extendable / 8.41 */
	{107, "UE Network Capability"},												/* Extendable / 8.42 */
	{108, "PDU Numbers"},														/* Extendable / 8.46 */
	{109, "MM Context (GSM Key and Triplets)"},									/* Extendable / 8.43 */
	{110, "MM Context (UMTS Key, Used Cipher and Quintuplets)"},				/* Extendable / 8.43 */
	{111, "MM Context (GSM Key, Used Cipher and Quintuplets)"},					/* Extendable / 8.43 */
	{112, "MM Context (UMTS Key and Quintuplets)"},								/* Extendable / 8.43 */
	{113, "MM Context (EPS Security Context, Quadruplets and Quintuplets)"},	/* Extendable / 8.43 */
	{114, "MM Context (UMTS Key, Quadruplets and Quintuplets)"},				/* Extendable / 8.43 */
	{115, "PDN Connection"},													/* Extendable / 8.44 */
	{116, "GRE Key"},															/* Extendable / 8.45 */
	{117, "Bearer Control Mode"},												/* Extendable / 8.68 */
	{118, "EPS Bearer Contexts Prioritization (Contexts Prioritization)"},		/* Extendable / 8.47 */
	{119, "LMA IP Address"},													/* Extendable / 8.48 */
	{120, "P-TMSI"},															/* Extendable / 8.49 */
	{121, "P-TMSI Signature"},													/* Extendable / 8.50 */
	{122, "Hop Counter"},														/* Extendable / 8.51 */
	{123, "Authentication Quintuplet"},											/* Extendable / 8.52 */
	{124, "Authentication Quadruplet"},											/* Extendable / 8.53 */
	{125, "Complete Request Message"},											/* Extendable / 8.54 */
	{126, "GUTI"},																/* Extendable / 8.55 */
	{127, "F-Container"},														/* Extendable / 8.56 */
	{128, "F-Cause"},															/* Extendable / 8.57 */
	{129, "Selected PLMN ID"},													/* Extendable / 8.58 */
	{130, "Target Identification"},												/* Extendable / 8.59 */
	{131, "Cell Identification"},												/* Extendable / 8.67 */
	{132, "NSAPI"},																/* Extendable / 8.60 */
	{133, "Packet Flow ID"},													/* Extendable / 8.61 */
	{134, "RAB Context"},														/* Extendable / 8.62 */
	{135, "Source RNC PDCP Context Info"},										/* Extendable / 8.63 */
	{136, "UDP Source Port Number"},											/* Extendable / 8.64 */
	{137, "APN Restriction"},													/* Extendable / 8.65 */
	{138, "Selection Mode"},													/* Extendable / 8.66 */
	{139, "Change Reporting Action"},											/* Extendable / 8.69 */
	{140, "Cause including an embedded offending IE"},							/* Extendable / 8.4 */
	{141, "PDN Connection Set Identifier (CSID)"},								/* Extendable / 8.70 */
	/* 142-254 Spare."},														/* For future use. FFS */
	{255, "Private"},															/* Extension Extendable / 8.71 */
    {0, NULL}
};
static void
dissect_gtpv2_ie_common(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint offset)
{
	proto_tree *ie_tree;
	proto_item *ti;
	guint8 type;
	guint16 length;
	/*
	 * Octets	8	7	6	5		4	3	2	1
	 *	1		Type
	 *	2-3		Length = n
	 *	4		CR			Spare	Instance
	 * 5-(n+4)	IE specific data
	 */
	while(offset <= (gint)tvb_reported_length(tvb)){
		/* Get the type and length */
		type = tvb_get_guint8(tvb,offset);
		length = tvb_get_ntohs(tvb, offset+1);
		ti = proto_tree_add_text(tree, tvb, offset, 4 + length, "%s : ", val_to_str(type, gtpv2_element_type_vals, "Unknown")); 
		ie_tree = proto_item_add_subtree(ti, ett_gtpv2_ie);
		/* Octet 1 */
		proto_tree_add_item(ie_tree, hf_gtpv2_ie, tvb, offset, 1, FALSE);
		offset++;
		
		/*Octet 2 - 3 */
		proto_tree_add_item(ie_tree, hf_gtpv2_ie_len, tvb, offset, 2, FALSE);
		offset+=2;
		/* CR Spare Instance Octet 4*/
		proto_tree_add_item(ie_tree, hf_gtpv2_cr, tvb, offset, 1, FALSE);
		proto_tree_add_item(ie_tree, hf_gtpv2_instance, tvb, offset, 1, FALSE);
		offset++;
		/* TODO: call IE dissector here */
		offset = offset + length;
	}

}
static void
dissect_gtpv2(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    proto_tree *gtpv2_tree, *flags_tree;
    proto_item *ti, *tf;
	guint8 message_type, t_flag;
	int offset = 0;


	/* Currently we get called from the GTP dissector no need to check the version */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTPv2");
    if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	/* message type is in octet 2 */
	message_type = tvb_get_guint8(tvb,1);
    if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, gtpv2_message_type_vals, "Unknown"));

    if (tree) {
		ti = proto_tree_add_item(tree, proto_gtpv2, tvb, offset, -1, FALSE);
		gtpv2_tree = proto_item_add_subtree(ti, ett_gtpv2);

		
		/* Control Plane GTP uses a variable length header. Control Plane GTP header 
		 * length shall be a multiple of 4 octets.
		 * Figure 5.1-1 illustrates the format of the GTPv2-C Header.
		 * Bits		  8  7  6	5		4	3		2		1
		 * Octets	1 Version	Spare	T	Spare	Spare	Spare
		 *			2 Message Type
		 *			3 Message Length (1st Octet)
		 *			4 Message Length (2nd Octet)
		 *	m–k(m+3)	If T flag is set to 1, then TEID shall be placed into octets 5-8.
		 *				Otherwise, TEID field is not present at all.
		 *	n-(n+1)	  Sequence Number
		 * (n+2)-(n+3) Spare
		 * Figure 5.1-1: General format of GTPv2 Header for Control Plane
		 */
		tf = proto_tree_add_item(gtpv2_tree, hf_gtpv2_flags, tvb, offset, 1, FALSE);
		flags_tree = proto_item_add_subtree(tf, ett_gtpv2_flags);

		/* Octet 1 */
		t_flag = (tvb_get_guint8(tvb,offset) & 0x08)>>3;
		proto_tree_add_item(flags_tree, hf_gtpv2_version, tvb, offset, 1, FALSE);
		proto_tree_add_item(flags_tree, hf_gtpv2_t, tvb, offset, 1, FALSE);
		offset++;

		/* Octet 2 */
		proto_tree_add_item(gtpv2_tree, hf_gtpv2_message_type, tvb, offset, 1, FALSE);
		offset++;
		/* Octet 3 - 4 */
		proto_tree_add_item(gtpv2_tree, hf_gtpv2_msg_length, tvb, offset, 2, FALSE);
		offset+=2;

		if(t_flag){
			/* Tunnel Endpoint Identifier 4 octets */
			proto_tree_add_item(gtpv2_tree, hf_gtpv2_teid, tvb, offset, 4, FALSE);
			offset+=4;
		}
		/* Sequence Number 2 octets */
		proto_tree_add_item(gtpv2_tree, hf_gtpv2_seq, tvb, offset, 2, FALSE);
		offset+=2;

		/* Spare 2 octets */
		proto_tree_add_item(gtpv2_tree, hf_gtpv2_spare, tvb, offset, 2, FALSE);
		offset+=2;

		dissect_gtpv2_ie_common(tvb, pinfo, tree, offset);
	}


}
void proto_register_gtpv2(void)
{
    static hf_register_info hf_gtpv2[] = {
		{&hf_gtpv2_flags,
		{"Flags", "gtpv2.flags",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Flags", HFILL}
		},
		{&hf_gtpv2_version,
		{"Version", "gtpv2.version",
		FT_UINT8, BASE_DEC, NULL, 0xe0,
		"Version", HFILL}
		},
		{ &hf_gtpv2_t,
		{"T", "gtpv2.t",
		FT_UINT8, BASE_DEC, NULL, 0x08,
		"If TEID field is present or not", HFILL}
		},
		{ &hf_gtpv2_message_type,
		{"Message Type", "gtpv2.message_type",
		FT_UINT8, BASE_DEC, VALS(gtpv2_message_type_vals), 0x0,
		"Message Type", HFILL}
		},
		{ &hf_gtpv2_msg_length,
		{"Message Length", "gtpv2.msg_lengt",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Message Length", HFILL}
		},
		{ &hf_gtpv2_teid,
		{"Tunnel Endpoint Identifier", "gtpv2.msg_lengt",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"TEID", HFILL}
		},
		{ &hf_gtpv2_seq,
		{"Sequence Number", "gtpv2.seq",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SEQ", HFILL}
		},
		{ &hf_gtpv2_spare,
		{"Spare", "gtpv2.seq",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Spare", HFILL}
		},
		{ &hf_gtpv2_ie,
		{"IE Type", "gtpv2.ie_type",
		FT_UINT8, BASE_DEC, VALS(gtpv2_element_type_vals), 0x0,
		"IE Type", HFILL}
		},
		{ &hf_gtpv2_ie_len,
		{"IE Length", "gtpv2.ie_len",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"length of the information element excluding the first four octets", HFILL}
		},
		{ &hf_gtpv2_cr,
		{"CR flag", "gtpv2.cr",
		FT_UINT8, BASE_DEC, NULL, 0xe0,
		"CR flag", HFILL}
		},
		{ &hf_gtpv2_instance,
		{"Instance", "gtpv2.instance",
		FT_UINT8, BASE_DEC, NULL, 0x0f,
		"Instance", HFILL}
		},
	 };

    static gint *ett_gtpv2_array[] = {
		&ett_gtpv2,
		&ett_gtpv2_flags,
		&ett_gtpv2_ie,
    };

	proto_gtpv2 = proto_register_protocol("GPRS Tunneling Protocol V2", "GTPv2", "gtpv2");
    proto_register_field_array(proto_gtpv2, hf_gtpv2, array_length(hf_gtpv2));
    proto_register_subtree_array(ett_gtpv2_array, array_length(ett_gtpv2_array));

	register_dissector("gtpv2", dissect_gtpv2, proto_gtpv2);
}

/* The registration hand-off routine */
void
proto_reg_handoff_gtpv2(void)
{

  
}

