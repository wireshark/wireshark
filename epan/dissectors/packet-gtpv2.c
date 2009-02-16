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
 * Ref: 3GPP TS 29.274 version 8.0.0 Release 8, ETSI TS 129 274 V8.0.0 (2009-01)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-gsm_a_common.h"
#include "packet-gsm_map.h"
#include "packet-e212.h"

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
static int hf_gtpv2_cause = -1;
static int hf_gtpv2_rec = -1;
static int hf_gtpv2_apn = -1;
static int hf_gtpv2_ebi = -1;
static int hf_gtpv2_daf = -1;
static int hf_gtpv2_dtf = -1;
static int hf_gtpv2_hi = -1;
static int hf_gtpv2_dfi = -1;
static int hf_gtpv2_oi = -1;
static int hf_gtpv2_isrsi = -1;
static int hf_gtpv2_israi = -1;
static int hf_gtpv2_sgwci = -1;
static int hf_gtpv2_pt = -1;
static int hf_gtpv2_tdi = -1;
static int hf_gtpv2_si = -1;
static int hf_gtpv2_msv = -1;

static int hf_gtpv2_rat_type = -1;
static int hf_gtpv2_cng_rep_act = -1;

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

#define GTPV2_IE_RESERVED		0
#define GTPV2_IE_IMSI			1
#define GTPV2_IE_CAUSE			2
#define GTPV2_REC_REST_CNT		3
#define GTPV2_APN				71
#define GTPV2_EBI				73
#define GTPV2_IE_MSISDN			76
#define GTPV2_INDICATION		77
#define GTPV2_PCO				78
#define GTPV2_IE_RAT_TYPE		82
#define GTPV2_IE_SERV_NET		83
#define GTPV2_IE_CNG_REP_ACT	139

/* Table 8.1-1: Information Element types for GTPv2 */
static const value_string gtpv2_element_type_vals[] = {
	{0, "Reserved"},
	{1, "International Mobile Subscriber Identity (IMSI)"},						/* Extendable / 8.3 */
	{2, "Cause (without embedded offending IE)"},								/* Extendable / 8.4 */
	{3, "Recovery (Restart Counter)"},											/* Extendable / 8.5 */
	/* 4-50 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
	/* 51-70 Reserved for Sv interface Extendable / See 3GPP TS 29.280 [15] */
	{71, "Access Point Name (APN)"},											/* Extendable / 8.6 */
	{72, "Aggregate Maximum Bit Rate (AMBR)"},									/* Extendable / 8.7 */
	{73, "EPS Bearer ID (EBI)"},												/* Extendable / 8.8 */
	{74, "IP Address"},															/* Extendable / 8.9 */
	{75, "Mobile Equipment Identity (MEI)"},									/* Extendable / 8.10 */
	{76, "MSISDN"},																/* Extendable / 8.11 */
	{77, "Indication"},															/* Extendable / 8.12 */
	{78, "Protocol Configuration Options (PCO)"},								/* Extendable / 8.13 */
	{79, "PDN Address Allocation (PAA)"},										/* Extendable / 8.14 */
	{80, "Bearer Level Quality of Service (Bearer QoS)"},						/* Extendable / 8.15 */
	{81, "Flow Quality of Service (Flow QoS)"},									/* Extendable / 8.16 */
	{82, "RAT Type"},															/* Extendable / 8.17 */
	{83, "Serving Network"},													/* Extendable / 8.18 */
	{84, "TEID-C"},																/* Extendable / 8.19 */
																				/* TEID-U Extendable / 8.19a */
																				/* TEID-U with EPS Bearer ID Extendable / 8.19b */
	{85, "EPS Bearer Level Traffic Flow Template (Bearer TFT)"},				/* Extendable / 8.20 */
	{86, "Traffic Aggregation Description (TAD)"},								/* Extendable / 8.21 */
	{87, "User Location Info (ULI)"},											/* Extendable / 8.22 */
	{88, "Fully Qualified Tunnel Endpoint Identifier (F-TEID)"},				/* Extendable / 8.23 */
	{89, "TMSI"},																/* Extendable / 8.24 */
	{90, "Global CN-Id"},														/* Extendable / 8.25 */
	{91, "Legacy Quality of Service (Legacy QoS)"},								/* Extendable / 8.26 */
	{92, "S103 PDN Data Forwarding Info (S103PDF)"},							/* Extendable / 8.27 */
	{93, "S1-U Data Forwarding Info (S1UDF)"},									/* Extendable / 8.28 */
	{94, "Delay Value"},														/* Extendable / 8.29 */
	{95, "Bearer ID List"},														/* Extendable / 8.30 */
	{96, "Bearer Context"},														/* Extendable / 8.31 */
	{97, "S101-IP-Address"},													/* Extendable / 8.32 */
	{98, "S102-IP-Address"},													/* Extendable / 8.33 */
	{99, "Charging ID"},														/* Extendable / 8.34 */
	{100, "Charging Characteristics"},											/* Extendable / 8.35 */
	{101, "Trace Information"},													/* Extendable / 8.36 */
	{102, "Bearer Flags"},														/* Extendable / 8.37 */
	{103, "Paging Cause"},														/* Extendable / 8.38 */
	{104, "PDN Type"},															/* Extendable / 8.39 */
	{105, "Procedure Transaction ID"},											/* Extendable / 8.40 */
	{106, "DRX Parameter"},														/* Extendable / 8.41 */
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
	/* 142-254 "Spare."},	*/													/* For future use. FFS */
	{255, "Private"},															/* Extension Extendable / 8.71 */
    {0, NULL}
};

/* Code to dissect IE's */

static void
dissect_gtpv2_unknown(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{

	proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet"); 
}

/* 
 * 8.3 International Mobile Subscriber Identity (IMSI)
 *
 * IMSI is defined in 3GPP TS 23.003
 * Editor’s note: IMSI coding will be defined in 3GPP TS 24.301
 * Editor’s note: In the first release of GTPv2 spec (TS 29.274v8.0.0) n = 8. 
 * That is, the overall length of the IE is 11 octets.
 */
static void
dissect_gtpv2_imsi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{
	proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet"); 

}
/* Table 8.4-1: Cause values */
static const value_string gtpv2_cause_vals[] = {
	{0, "Reserved"},
	{1, "Paging Cause"},
	{2, "Local Detach"},
	{3, "Complete Detach"},
	/* 4-15 Spare. This value range is reserved for Cause values in a request message */
	{16, "Request accepted"},
	{17, "Request accepted partially"},
	{18, "New PDN type due to subscription limitation"},
	{19, "New PDN type due to network preference"},
	{20, "New PDN type due to single address bearer only"},
	/* 21-63 Spare. This value range is reserved for Cause values in acceptance response message */
	{64, "Context Non Existent/Found"},
	{65, "Invalid Message Format"},
	{66, "Version not supported by next peer"},
	{67, "Invalid length"},
	{68, "Service not supported"},
	{69, "Mandatory IE incorrect"},
	{70, "Mandatory IE missing"},
	{71, "Optional IE incorrect"},
	{72, "System failure"},
	{73, "No resources available"},
	{74, "Semantic error in the TFT operation"},
	{75, "Syntactic error in the TFT operation"},
	{76, "Semantic errors in packet filter(s)"},
	{77, "Syntactic errors in packet filter(s)"},
	{78, "Missing or unknown APN"},
	{79, "Unexpected repeated IE"},
	{80, "GRE key not found"},
	{81, "Reallocation failure"},
	{82, "Denied in RAT"},
	{83, "Preferred PDN type not supported"},
	{84, "All dynamic addresses are occupied"},
	{85, "UE context without TFT already activated"},
	{86, "Protocol type not supported"},
	{87, "UE not responding"},
	{88, "UE refuses"},
	{89, "Service denied"},
	{90, "Unable to page UE"},
	{91, "No memory available"},
	{92, "User authentication failed"},
	{93, "APN access denied – no subscription"},
	/* 94-255 Spare. This value range is reserved for Cause values in rejection response message */
    {0, NULL}
};

/*
 * 8.4 Cause
 */

static void
dissect_gtpv2_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{
	int offset = 0;
	/* Cause value octet 5 */
	proto_tree_add_item(tree, hf_gtpv2_cause, tvb, offset, 1, FALSE);
	if (length >1)
			proto_tree_add_text(tree, tvb, offset, length, "IE data not dissected yet");

}
/*
 * 8.5 Recovery (Restart Counter)
 */
static void
dissect_gtpv2_recovery(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{
	int offset = 0;
	/*  */
	proto_tree_add_item(tree, hf_gtpv2_rec, tvb, offset, 1, FALSE);

}
/*
 * 8.6 Access Point Name (APN)
 */
static void
dissect_gtpv2_apn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{
	int offset = 0;
    guint8 *apn = NULL;
    int name_len, tmp;

    if (length > 0) {
		name_len = tvb_get_guint8(tvb, offset);

		if (name_len < 0x20) {
			apn = tvb_get_ephemeral_string(tvb, offset + 1, length - 1);
			for (;;) {
				if (name_len >= length - 1)
				break;
				tmp = name_len;
				name_len = name_len + apn[tmp] + 1;
				apn[tmp] = '.';
			}
		} else{
			apn = tvb_get_ephemeral_string(tvb, offset, length);
		}
		proto_tree_add_string(tree, hf_gtpv2_apn, tvb, offset, length, apn);
    }

}
/*
 * 8.7 Aggregate Maximum Bit Rate (AMBR)
 */
/* 
 * 8.8 EPS Bearer ID (EBI)
 */
static void
dissect_gtpv2_ebi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{

	int offset = 0;
	/* Spare (all bits set to 0) B8 - B5*/
	/* EPS Bearer ID (EBI) B4 - B1 */
	proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, FALSE);

}
/*
 * 8.9 IP Address
 * 8.10 Mobile Equipment Identity (MEI)
 */

/*
 * 8.11 MSISDN
 *
 * MSISDN is defined in 3GPP TS 23.003
 * Editor’s note: MSISDN coding will be defined in TS 24.301.
 */
static void
dissect_gtpv2_msisdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{
	dissect_gsm_map_msisdn(tvb, pinfo, tree); 

}

/*
 * 8.12 Indication
 */
static void
dissect_gtpv2_ind(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_gtpv2_daf,			tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_dtf,			tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_hi,			tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_hi,			tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_dfi,			tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_oi,			tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_isrsi,		tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_israi,		tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_sgwci,		tvb, offset, 1, FALSE);

	offset++;
	proto_tree_add_item(tree, hf_gtpv2_pt,			tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_tdi,			tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_si	,		tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gtpv2_msv,			tvb, offset, 1, FALSE);
	
}
/*
 * 8.13 Protocol Configuration Options (PCO)
 * Editor’s note: PCO will be defined in 3GPP TS 23.003 and its coding in TS 24.301
 * Dissected in packey-gsm_a_gm.c
 */
static void
dissect_gtpv2_pco(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{
	de_sm_pco(tvb, tree, 0, length, NULL, 0);
}
/*
 * 8.14 PDN Address Allocation (PAA) 
 * 8.15 Bearer Quality of Service (Bearer QoS)
 * 8.16 Flow Quality of Service (Flow QoS)
 */
/*
 * 8.17 RAT Type
 */
static const value_string gtpv2_rat_type_vals[] = {
	{0, "Reserved"},
	{1, "UTRAN"},
	{2, "GERAN"},
	{3, "WLAN"},
	{4, "GAN"},
	{5, "HSPA Evolution"},
	{6, "EUTRAN"},
	{0, NULL}
};

static void
dissect_gtpv2_rat_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{
	proto_tree_add_item(tree, hf_gtpv2_rat_type, tvb, 0, 1, FALSE);
}
/*
 * 8.18 Serving Network
 */
static void
dissect_gtpv2_serv_net(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{

	dissect_e212_mcc_mnc(tvb, tree, 0); 
}
/*
 * 8.19 Tunnel Endpoint Identifier for Control Plane (TEID-C) 
 * 8.19a Tunnel Endpoint Identifier for User Plane (TEID-U) 
 * 8.19b Tunnel Endpoint Identifier for User Plane with EBI (TEID-U EBI)
 * 8.20 EPS Bearer Level Traffic Flow Template (Bearer TFT)
 * 8.21 Traffic Aggregate Description (TAD)
 * 8.22 User Location Info (ULI) 
 * 8.22.1 CGI field 
 * 8.22.2 SAI field 
 * 8.22.3 RAI field 
 * 8.22.4 TAI field 
 * 8.22.5 ECGI field
 * 8.23 Fully Qualified TEID (F-TEID)
 * 8.24 TMSI 
 * 8.25 Global CN-Id
 * 8.26 Legacy Quality of Service (QoS)
 * 8.27 S103 PDN Data Forwarding Info (S103PDF)
 * 8.28 S1-U Data Forwarding (S1UDF)
 * 8.29 Delay Value
 * 8.30 Bearer ID List
 * 8.31 Bearer Context
 * 8.32 S101 IP Address 
 * 8.33 S102 IP Address 
 * 8.34 Charging ID
 * 8.35 Charging Characteristics 
 * 8.36 Trace Information
 * 8.37 Bearer Flags
 * 8.38 Paging Cause 
 * 8.39 PDN Type
 * 8.40 Procedure Transaction ID (PTI)
 * 8.41 DRX Parameter 
 * 8.42 UE Network Capability
 * 8.43 MM Context 
 * 8.44 PDN Connection
 * 8.45 GRE Key
 * 8.46 PDU Numbers 
 * 8.47 EPS Bearer Contexts Prioritization (Contexts Prioritization)
 * 8.48 LMA IP Address 
 * 8.49 Packet TMSI (P-TMSI)
 * 8.50 P-TMSI Signature
 * 8.51 Hop Counter
 * 8.52 Authentication Quintuplet
 * 8.53 Authentication Quadruplet
 * 8.54 Complete Request Message
 * 8.55 GUTI
 * 8.56 Fully Qualified Container (F-Container)
 * 8.57 Fully Qualified Cause (F-Cause)
 * 8.58 Selected PLMN ID
 * 8.59 Target Identification
 * 8.60 NSAPI
 * 8.61 Packet Flow ID
 * 8.62 RAB Context
 * 8.63 Source RNC PDCP context info
 * 8.64 UDP Source Port Number
 * 8.65 APN Restriction 
 * 8.66 Selection Mode
 * 8.67 Cell Identification
 * 8.68 Bearer Control Mode
 */
/*
 * 8.69 Change Reporting Action
 */
static const value_string gtpv2_cng_rep_act_vals[] = {
	{0, "Stop Reporting"},
	{1, "Start Reporting CGI/SAI"},
	{2, "Start Reporting RAI"},
	{0, NULL}
};

static void
dissect_cng_rep_act(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_)
{

	proto_tree_add_item(tree, hf_gtpv2_cng_rep_act, tvb, 0, 1, FALSE); 
}
/*
 * 8.70 PDN Connection Set Identifier (CSID)
 * 8.71 Private Extension
 */
typedef struct _gtpv2_ie {
    int ie_type;
    void (*decode) (tvbuff_t *, packet_info *, proto_tree *, proto_item *, guint16, guint8);
} gtpv2_ie_t;

static const gtpv2_ie_t gtpv2_ies[] = {
    {GTPV2_IE_IMSI, dissect_gtpv2_imsi},
	{GTPV2_IE_CAUSE, dissect_gtpv2_cause},				/* 2, Cause (without embedded offending IE) 8.4 */
	{GTPV2_REC_REST_CNT, dissect_gtpv2_recovery},		/* 3, Recovery (Restart Counter) 8.5 */
														/* 4-50 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
														/* 51-70 Reserved for Sv interface Extendable / See 3GPP TS 29.280 [15] */
	{GTPV2_APN, dissect_gtpv2_apn},						/* 71, Access Point Name (APN) 8.6 */
	{GTPV2_EBI, dissect_gtpv2_ebi},						/* 73, EPS Bearer ID (EBI)  8.8 */
	{GTPV2_IE_MSISDN, dissect_gtpv2_msisdn},			/* 76, MSISDN 8.11 */
	{GTPV2_INDICATION, dissect_gtpv2_ind},				/* 77 Indication 8.12 */
	{GTPV2_PCO, dissect_gtpv2_pco},						/* 78 Protocol Configuration Options (PCO) 8.13 */
	{GTPV2_IE_RAT_TYPE, dissect_gtpv2_rat_type},		/* 82, RAT Type  8.17 */
	{GTPV2_IE_SERV_NET, dissect_gtpv2_serv_net},		/* 83, Serving Network 8.18 */
	{GTPV2_IE_CNG_REP_ACT, dissect_cng_rep_act},		/* 139, Change Reporting Action 8.69 */
														/* 142-254 Spare. For future use. FFS */

    {0, dissect_gtpv2_unknown}
};



static void
dissect_gtpv2_ie_common(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint offset)
{
	proto_tree *ie_tree;
	proto_item *ti;
	tvbuff_t *ie_tvb;
	guint8 type, instance;
	guint16 length;
	int i;
	/*
	 * Octets	8	7	6	5		4	3	2	1
	 *	1		Type
	 *	2-3		Length = n
	 *	4		CR			Spare	Instance
	 * 5-(n+4)	IE specific data
	 */
	while(offset < (gint)tvb_reported_length(tvb)){
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

		instance = tvb_get_guint8(tvb,offset)& 0x0f;
		proto_tree_add_item(ie_tree, hf_gtpv2_instance, tvb, offset, 1, FALSE);
		offset++;
		
		/* TODO: call IE dissector here */
		if(type==GTPV2_IE_RESERVED){
			/* Treat IE type zero specal as type zero is used to end the loop in the else branch */
			proto_tree_add_text(ie_tree, tvb, offset, length, "IE type Zero is Reserved and should not be used");
		}else{
			i = -1;
			/* Loop over the IE dissector list to se if we find an entry, the last entry will have ie_type=0 braking the loop */
			while (gtpv2_ies[++i].ie_type){
				if (gtpv2_ies[i].ie_type == type)
					break;
			}
			/* Just give the IE dissector the IE */
			ie_tvb = tvb_new_subset(tvb, offset, length, length);
			(*gtpv2_ies[i].decode) (ie_tvb, pinfo , ie_tree, ti, length, instance);
		}

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


	proto_tree_add_item(tree, proto_gtpv2, tvb, offset, -1, FALSE);

    if (tree) {
		ti = proto_tree_add_text(tree, tvb, offset, -1, "%s", val_to_str(message_type, gtpv2_message_type_vals, "Unknown"));
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

		dissect_gtpv2_ie_common(tvb, pinfo, gtpv2_tree, offset);
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
		{"Tunnel Endpoint Identifier", "gtpv2.teid",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"TEID", HFILL}
		},
		{ &hf_gtpv2_seq,
		{"Sequence Number", "gtpv2.seq",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SEQ", HFILL}
		},
		{ &hf_gtpv2_spare,
		{"Spare", "gtpv2.spare",
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
		{ &hf_gtpv2_cause,
		{"Cause", "gtpv2.cause",
		FT_UINT8, BASE_DEC, VALS(gtpv2_cause_vals), 0x0,
		"cause", HFILL}
		},
		{ &hf_gtpv2_rec,
		{"Restart Counter", "gtpv2.rec",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Restart Counter", HFILL}
		},
		{&hf_gtpv2_apn,
		{"APN", "gtp.apn", 
		FT_STRING, BASE_DEC, NULL, 0x0,
		"Access Point Name", HFILL}
		},
		{&hf_gtpv2_ebi,
		{"EPS Bearer ID (EBI)", "gtpv2.ebi",
		FT_UINT8, BASE_DEC, NULL, 0x0f,
		"EPS Bearer ID (EBI)", HFILL}
		},
		{&hf_gtpv2_daf,	
		{"DAF (Dual Address Bearer Flag)", "gtpv2.daf",	
		FT_BOOLEAN, 8, NULL, 0x40, "DAF", HFILL}
		},
		{&hf_gtpv2_dtf,
		{"DTF (Direct Tunnel Flag)","gtpv2.dtf",
		FT_BOOLEAN, 8, NULL, 0x40, "DTF", HFILL}
		},
		{&hf_gtpv2_hi,
		{"HI (Handover Indication)", "gtpv2.hi",
		FT_BOOLEAN, 8, NULL, 0x20, "HI", HFILL}
		},
		{&hf_gtpv2_dfi,
		{"DFI (Direct Forwarding Indication)", "gtpv2.dfi",
		FT_BOOLEAN, 8, NULL, 0x10, "DFI", HFILL}
		},
		{&hf_gtpv2_oi,
		{"OI (Operation Indication)","gtp.oi",
		FT_BOOLEAN, 8, NULL, 0x08, "OI", HFILL}
		},
		{&hf_gtpv2_isrsi,
		{"ISRSI (Idle mode Signalling Reduction Supported Indication)", "gtpv2.isrsi",
		FT_BOOLEAN, 8, NULL, 0x04, "ISRSI", HFILL}
		},
		{&hf_gtpv2_israi,
		{"ISRAI (Idle mode Signalling Reduction Activation Indication)",	"gtpv2.israi",
		FT_BOOLEAN, 8, NULL, 0x02, "ISRAI", HFILL}
		},
		{&hf_gtpv2_sgwci,
		{"SGWCI (SGW Change Indication)", "gtpv2.sgwci", 
		FT_BOOLEAN, 8, NULL, 0x01, "SGWCI", HFILL}
		},
		{&hf_gtpv2_pt,
		{"PT (Protocol Type)", "gtpv2.pt", 
		FT_BOOLEAN, 8, NULL, 0x08, "PT", HFILL}
		},
		{&hf_gtpv2_tdi,
		{"TDI (Teardown Indication)", "gtpv2.tdi", 
		FT_BOOLEAN, 8, NULL, 0x04, "TDI", HFILL}
		},
		{&hf_gtpv2_si,
		{"SI (Scope Indication)", "gtpv2.si", 
		FT_BOOLEAN, 8, NULL, 0x02, "SI", HFILL}
		},
		{&hf_gtpv2_msv,
		{"MSV (MS Validated)", "gtpv2.msv", 
		FT_BOOLEAN, 8, NULL, 0x01, "MSV", HFILL}
		},
		{ &hf_gtpv2_rat_type,
		{"RAT Type", "gtpv2.rat_type",
		FT_UINT8, BASE_DEC, VALS(gtpv2_rat_type_vals), 0x0,
		"RAT Type", HFILL}
		},
		{ &hf_gtpv2_cng_rep_act,
		{"Change Reporting Action", "gtpv2.cng_rep_act",
		FT_UINT8, BASE_DEC, VALS(gtpv2_cng_rep_act_vals), 0x0,
		"Change Reporting Action", HFILL}
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

