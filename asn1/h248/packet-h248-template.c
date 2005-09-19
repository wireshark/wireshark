/* packet-h248.c
 * Routines for H.248/MEGACO packet dissection
 * Ronnie Sahlberg 2004
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/strutil.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-h248.h"
#include "packet-isup.h"
#include "packet-q931.h"

#include <epan/sctpppids.h>
#define PNAME  "H.248 MEGACO"
#define PSNAME "H248"
#define PFNAME "h248"

/*XXX this define should be moved to packet-m3ua.h ? */
#define GATEWAY_CONTROL_PROTOCOL_USER_ID 14

/* Initialize the protocol and registered fields */
static int proto_h248				= -1;
static int hf_h248_mtpaddress_ni	= -1;
static int hf_h248_mtpaddress_pc	= -1;
static int hf_h248_package_name		= -1;
static int hf_h248_event_name		= -1;
static int hf_h248_signal_name		= -1;
static int hf_h248_package_bcp_BNCChar_PDU = -1;
static int hf_h248_package_annex_C_ACodec = -1;
static int hf_h248_package_annex_C_tdmc_ec = -1;
static int hf_h248_package_annex_C_tdmc_gain = -1;
static int hf_h248_package_annex_C_TMR = -1;
static int hf_h248_package_annex_C_Mediatx = -1;
static int hf_h248_package_annex_C_USI = -1;
static int hf_h248_package_annex_C_NSAP = -1;
static int hf_h248_package_annex_C_BIR = -1;
static int hf_h248_package_3GUP_Mode = -1;
static int hf_h248_package_3GUP_UPversions = -1;
static int hf_h248_package_3GUP_delerrsdu = -1;
static int hf_h248_package_3GUP_interface = -1;
static int hf_h248_package_3GUP_initdir = -1;
static int hf_h248_contextId_64			= -1;
static int hf_h248_transactionId_64		= -1;

#include "packet-h248-hf.c"

/* Initialize the subtree pointers */
static gint ett_h248 = -1;
static gint ett_mtpaddress = -1;
static gint ett_packagename = -1;
static gint ett_codec = -1;

#include "packet-h248-ett.c"

static const gchar* command_string;
static gboolean it_is_wildcard;

static dissector_handle_t h248_term_handle;

static dissector_table_t h248_package_bin_dissector_table=NULL;

static const value_string package_name_vals[] = {
  {   0x0000, "Media stream properties H.248.1 Annex C" },
  {   0x0001, "g H.248.1 Annex E" },
  {   0x0002, "root H.248.1 Annex E" },
  {   0x0003, "tonegen H.248.1 Annex E" },
  {   0x0004, "tonedet H.248.1 Annex E" },
  {   0x0005, "dg H.248.1 Annex E" },
  {   0x0006, "dd H.248.1 Annex E" },
  {   0x0007, "cg H.248.1 Annex E" }, 
  {   0x0008, "cd H.248.1 Annex E" },
  {   0x0009, "al H.248.1 Annex E" },
  {   0x000a, "ct H.248.1 Annex E" }, 
  {   0x000b, "nt H.248.1 Annex E" },
  {   0x000c, "rtp H.248.1 Annex E" },
  {   0x000d, "tdmc H.248.1 Annex E" },
  {   0x000e, "ftmd H.248.1 Annex E" },
  {   0x000f, "txc H.248.2" },											/* H.248.2 */
  {   0x0010, "txp H.248.2" },
  {   0x0011, "ctyp H.248.2" },
  {   0x0012, "fax H.248.2" },
  {   0x0013, "ipfax H.248.2" },
  {   0x0014, "dis H.248.3" },											/* H.248.3 */
  {   0x0015, "key H.248.3" },
  {   0x0016, "kp H.248.3" },
  {   0x0017, "labelkey H.248.3" },   
  {   0x0018, "kf H.248.3" },
  {   0x0019, "ind H.248.3" },
  {   0x001a, "ks H.248.3" },
  {   0x001b, "anci H.248.3" },
  {   0x001c, "dtd H.248.6" },											/* H.248.6 */
  {   0x001d, "an H.248.7" },											/* H.248.7 */
  {   0x001e, "Bearer Characteristics Q.1950 Annex A" }, 				/* Q.1950 Annex A */ 
  {   0x001f, "Bearer Network Connection Cut Q.1950 Annex A" },
  {   0x0020, "Reuse Idle Q.1950 Annex A" },
  {   0x0021, "Generic Bearer Connection Q.1950 Annex A" }, 
  {   0x0022, "Bearer Control Tunnelling Q.1950 Annex A" },
  {   0x0023, "Basic Call Progress Tones Q.1950 Annex A" },
  {   0x0024, "Expanded Call Progress Tones Q.1950 Annex A" },
  {   0x0025, "Basic Services Tones Q.1950 Annex A" },
  {   0x0026, "Expanded Services Tones Q.1950 Annex A" },
  {   0x0027, "Intrusion Tones Q.1950 Annex A" },
  {   0x0028, "Business Tones Q.1950 Annex A" },
  {   0x0029, "Media Gateway Resource Congestion Handling H.248.10" },	/* H.248.10 */
  {   0x002a, "H245 package H248.12" },									/* H.248.12 */
  {   0x002b, "H323 bearer control package H.248.12" },					/* H.248.12 */
  {   0x002c, "H324 package H.248.12" },								/* H.248.12 */
  {   0x002d, "H245 command package H.248.12" },						/* H.248.12 */
  {   0x002e, "H245 indication package H.248.12" },						/* H.248.12 */
  {   0x002f, "3G User Plane" },										/* 3GPP TS 29.232 v4.1.0 */
  {   0x0030, "3G Circuit Switched Data" },
  {   0x0031, "3G TFO Control" },
  {   0x0032, "3G Expanded Call Progress Tones" },
  {   0x0033, "Advanced Audio Server (AAS Base)" },						/* H.248.9 */
  {   0x0034, "AAS Digit Collection" }, 								/* H.248.9 */
  {   0x0035, "AAS Recording" }, 										/* H.248.9 */
  {   0x0036, "AAS Segment Management" },								/* H.248.9 */ 
  {   0x0037, "Quality Alert Ceasing" },								/* H.248.13 */
  {   0x0038, "Conferencing Tones Generation" },						/* H.248.27 */
  {   0x0039, "Diagnostic Tones Generation" },							/* H.248.27 */
  {   0x003a, "Carrier Tones Generation Package H.248.23" },			/* H.248.27 */
  {   0x003b, "Enhanced Alerting Package H.248.23" },					/* H.248.23 */
  {   0x003c, "Analog Display Signalling Package H.248.23" },			/* H.248.23 */
  {   0x003d, "Multi-Frequency Tone Generation Package H.248.24" },		/* H.248.24 */												   
  {   0x003e, "H.248.23Multi-Frequency Tone Detection Package H.248.24" }, /* H.248.24 */
  {   0x003f, "Basic CAS Package H.248.25" },							/* H.248.25 */												   
  {   0x0040, "Robbed Bit Signalling Package H.248.25" },		        /* H.248.25 */
  {   0x0041, "Operator Services and Emgergency Services Package H.248.25" },												   
  {   0x0042, "Operator Services Extension Package H.248.25" },
  {   0x0043, "Extended Analog Line Supervision Package H.248.26" },
  {   0x0044, "Automatic Metering Package H.248.26" },  
  {   0x0045, "Inactivity Timer Package H.248.14" },      
  {   0x0046, "3G Modification of Link Characteristics Bearer Capability" }, /* 3GPP TS 29.232 v4.4.0 */ 
  {   0x0047, "Base Announcement Syntax H.248.9" },
  {   0x0048, "Voice Variable Syntax H.248.9" },
  {   0x0049, "Announcement Set Syntax H.248.9" },
  {   0x004a, "Phrase Variable Syntax H.248.9" },
  {   0x004b, "Basic NAS package" },
  {   0x004c, "NAS incoming package" },
  {   0x004d, "NAS outgoing package" },
  {   0x004e, "NAS control package" },
  {   0x004f, "NAS root package" },
  {   0x0050, "Profile Handling Package H.248.18" }, 
  {   0x0051, "Media Gateway Overload Control Package H.248.11" }, 
  {   0x0052, "Extended DTMF Detection Package H.248.16" },
  {   0x0053, "Quiet Termination Line Test" },
  {   0x0054, "Loopback Line Test Response" }, 							/* H.248.17 */
  {   0x0055, "ITU 404Hz Line Test" },									/* H.248.17 */
  {   0x0056, "ITU 816Hz Line Test" },									/* H.248.17 */
  {   0x0057, "ITU 1020Hz Line Test" },									/* H.248.17 */
  {   0x0058, "ITU 2100Hz Disable Tone Line Test" },					/* H.248.17 */
  {   0x0059, "ITU 2100Hz Disable Echo Canceller Tone Line Test" },		/* H.248.17 */
  {   0x005a, "ITU 2804Hz Tone Line Test" },							/* H.248.17 */
  {   0x005b, "ITU Noise Test Tone Line Test" },						/* H.248.17 */
  {   0x005c, "ITU Digital Pseudo Random Test Line Test" },				/* H.248.17 */
  {   0x005d, "ITU ATME No.2 Test Line Response" },						/* H.248.17 */
  {   0x005e, "ANSI 1004Hz Test Tone Line Test" },						/* H.248.17 */
  {   0x005f, "ANSI Test Responder Line Test" },						/* H.248.17 */
  {   0x0060, "ANSI 2225Hz Test Progress Tone Line Test" },				/* H.248.17 */
  {   0x0061, "ANSI Digital Test Signal Line Test" },					/* H.248.17 */
  {   0x0062, "ANSI Inverting Loopback Line Test Repsonse" },			/* H.248.17 */
  {   0x0063, "Extended H.324 Packages H.248.12 Annex A" },
  {   0x0064, "Extended H.245 Command Package H.248.12 Annex A" },
  {   0x0065, "Extended H.245 Indication Package H.248.12 Annex A" },
  {   0x0066, "Enhanced DTMF Detection Package H.248.16" }, 
  {   0x0067, "Connection Group Identity Package Q.1950 Annex E" }, 
  {   0x0068, "CTM Text Transport 3GPP TS 29.232 v5.2.0" }, 
  {   0x0069, "SPNE Control Package Q.115.0" },
  {   0x006a, "Semi-permanent Connection Package H.248.21" },
  {   0x006b, "Shared Risk Group Package H.248.22" },
  {   0x006c, "isuptn Annex B of ITU-T Rec. J.171" },
  {   0x006d, "Basic CAS Addressing Package H.248.25" },
  {   0x006e, "Floor Control Package H.248.19" },
  {   0x006f, "Indication of Being Viewed Package H.248.19" },
  {   0x0070, "Volume Control Package H.248.19" },
  {   0x0071, "UNASSIGNED" },
  {   0x0072, "Volume Detection Package H.248.19" },
  {   0x0073, "Volume Level Mixing Package H.248.19" },
  {   0x0074, "Mixing Volume Level Control Package H.248.19" },
  {   0x0075, "Voice Activated Video Switch Package H.248.19" },
  {   0x0076, "Lecture Video Mode Package H.248.19" },
  {   0x0077, "Contributing Video Source Package H.248.19" },
  {   0x0078, "Video Window Package H.248.19" },
  {   0x0079, "Tiled Window Package H.248.19" },
  {   0x007a, "Adaptive Jitter Buffer Package H.248.31" },
  {   0x007b, "International CAS Package H.248.28" },
  {   0x007c, "CAS Blocking Package H.248.28" },
  {   0x007d, "International CAS Compelled Package H.248.29" },
  {   0x007e, "International CAS Compelled with Overlap Package H.248.29" },
  {   0x007f, "International CAS Compelled with End-to-end Package H.248.29" },
  {   0x0080, "RTCP XR Package H.248.30" },
  {   0x0081, "RTCP XR Burst Metrics Package H.248.30" },
  {   0x0082, "threegcsden 3G Circuit Switched Data" },				/* 3GPP TS 29.232 v5.6.0 */
  {   0x0083, "threegiptra 3G Circuit Switched Data" },				/* 3GPP TS 29.232 v5.6.0 */
  {   0x0084, "threegflex 3G Circuit Switched Data" },				/* 3GPP TS 29.232 v5.6.0 */												   
  {   0x0085, "H.248 PCMSB" },
  {   0x008a, "TIPHON Extended H.248/MEGACO Package" },				/* ETSI specification TS 101 3 */
  {   0x008b, "Differentiated Services Package" },					/* Annex A of ETSI TS 102 333 */
  {   0x008c, "Gate Management Package" },							/* Annex B of ETSI TS 102 333 */
  {   0x008d, "Traffic Management Package" },						/* Annex C of ETSI TS 102 333 */
  {   0x008e, "Gate Recovery Information Package" },				/* Annex D of ETSI TS 102 333 */
  {   0x008f, "NAT Traversal Package" },							/* Annex E of ETSI TS 102 333 */
  {   0x0090, "MPLS Package" },										/* Annex F of ETSI TS 102 333 */
  {   0x0091, "VLAN Package" },										/* Annex G of ETSI TS 102 333 */
  {   0x8000, "Ericsson IU" }, 
  {   0x8001, "Ericsson UMTS and GSM Circuit" },
  {   0x8002, "Ericsson Tone Generator Package" },
  {   0x8003, "Ericsson Line Test Package" },
  {   0x8004, "Nokia Advanced TFO Package" },
  {   0x8005, "Nokia IWF Package" },
  {   0x8006, "Nokia Root Package" },
  {   0x8007, "Nokia Trace Package" },
  {   0x8008, "Ericsson  V5.2 Layer" },
  {   0x8009, "Ericsson Detailed Termination Information Package" },
  {   0x800a, "Nokia Bearer Characteristics Package" },
	{0,     NULL}
};
/* 
 * This table consist of PackageName + EventName and its's corresponding string 
 * 
 */
static const value_string event_name_vals[] = {
  {   0x00000000, "Media stream properties H.248.1 Annex C" },
  {   0x00010000, "g H.248.1 Annex E" },
  {   0x00010001, "g, Cause" },
  {   0x00010002, "g, Signal Completion" },
  {   0x00210000, "Generic Bearer Connection Q.1950 Annex A" }, 
  {   0x00210001, "GB BNC change" }, 
  {   0x800a0000, "Nokia Bearer Characteristics Package" },
	{0,     NULL}
};

/* 
 * This table consist of PackageName + SignalName and its's corresponding string 
 */
static const value_string signal_name_vals[] = {
  {   0x00000000, "Media stream properties H.248.1 Annex C" },
  {   0x00010000, "g H.248.1 Annex E" },
  {   0x00210000, "GB Generic Bearer Connection Q.1950 Annex A" }, 
  {   0x00210001, "GB Establish BNC" }, 
  {   0x00210002, "GB Modify BNC" }, 
  {   0x00210003, "GB Release BNC" }, 
  {   0x800a0000, "Nokia Bearer Characteristics Package" },
	{0,     NULL}
};

static const value_string h248_package_annex_C_Mediatx_vals[] = {
  {   0x0000, "TDM Circuit" },
  {   0x0001, "ATM" },
  {   0x0002, "FR" },
  {   0x0003, "Ipv4" },
  {   0x0004, "Ipv6" },
	{0,     NULL}
};


static const true_false_string h248_tdmc_ec_vals = {
	"On",
	"Off"
};


#if 0
static const value_string context_id_type[] = {
	{0x00000000,"0 (Null Context)"},
	{0xFFFFFFFE,"$ (Choose Context)"},
	{0xFFFFFFFF,"* (All Contexts)"},
	{0,NULL}
};
#endif

static int dissect_h248_trx_id(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
	guint64 trx_id = 0;
  	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	guint32 i;
	
	if(!implicit_tag){
		offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	} else {
		len=tvb_length_remaining(tvb, offset);
	}
	
	
	if (len > 8 || len < 1) {
		THROW(BoundsError);
	} else {
		for(i=1;i<=len;i++){
			trx_id=(trx_id<<8)|tvb_get_guint8(tvb, offset);
			offset++;
		}
		if (trx_id > 0xffffffff) {
			proto_tree_add_uint64_format(tree, hf_h248_transactionId_64, tvb, offset-len, len,
									 trx_id,"transactionId %" PRIu64, trx_id);
		} else {
			proto_tree_add_uint(tree, hf_h248_transactionId, tvb, offset-len, len, (guint32)trx_id);			
		}
	}	
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_fstr(pinfo->cinfo, COL_INFO, "Trx %" PRIu64 " { ", trx_id);
	}
	
	return offset;	
}

static int dissect_h248_ctx_id(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	guint64 context_id = 0;
	guint32 i;
	static gchar context_string[64];
	static gchar context_string_long[64];
	
	if(!implicit_tag){
		offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	} else {
		len=tvb_length_remaining(tvb, offset);
	}
	
	
	if (len > 8 || len < 1) {
		THROW(BoundsError);
	} else {
		for(i=1;i<=len;i++){
			context_id=(context_id<<8)|tvb_get_guint8(tvb, offset);
			offset++;
		}
		
		if (context_id == 0x0000000 ) {
			strncpy(context_string,"Ctx 0",sizeof(context_string));
			strncpy(context_string_long,"0 (Null Context)",sizeof(context_string));
		} else if (context_id == 0xFFFFFFFF ) {
			strncpy(context_string,"Ctx *",sizeof(context_string));
			strncpy(context_string_long,"* (All Contexts)",sizeof(context_string));
		} else if (context_id == 0xFFFFFFFE ) {
			strncpy(context_string,"Ctx $",sizeof(context_string));
			strncpy(context_string_long,"$ (Choose One)",sizeof(context_string));
		} else {
			g_snprintf(context_string,sizeof(context_string),"Ctx 0x%" PRIx64, context_id);
			g_snprintf(context_string_long,sizeof(context_string),"0x%" PRIx64, context_id);
		}
		
		if (context_id > 0xffffffff) {
			proto_tree_add_uint64_format(tree, hf_h248_contextId_64,
										  tvb, offset-len, len,
										  context_id, "contextId: %s", context_string_long);
		} else {
			proto_tree_add_uint_format(tree, hf_h248_contextId, tvb, offset-len, len,
									   (guint32)context_id, "contextId: %s", context_string_long);
		}
	}	
	
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s { ", context_string);
	}
	
	return offset;
}

static void 
dissect_h248_annex_C_PDU(gboolean implicit_tag, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 name_minor) {
	int offset = 0;
	tvbuff_t *new_tvb;
	int len;
	
	switch ( name_minor ){

	case 0x1001: /* Media */
		proto_tree_add_text(tree, tvb, offset, -1,"Media");
		break;
	case 0x1006: /* ACodec Ref.: ITU-T Rec. Q.765.5 */
		dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_h248_package_annex_C_ACodec, &new_tvb);
		tree = proto_item_add_subtree(get_ber_last_created_item(),ett_codec);
		len = tvb_get_guint8(tvb,0);
		dissect_codec_mode(tree,tvb,1,len);
		break;
	case 0x3001: /* Mediatx */
		offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_package_annex_C_Mediatx, NULL);
		break;
	case 0x3002: /* BIR */
		offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_h248_package_annex_C_BIR, &new_tvb);
		break;
	case 0x3003: /* NSAP */
		offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_h248_package_annex_C_NSAP, &new_tvb);
		dissect_nsap(new_tvb, 0,tvb_length_remaining(new_tvb, 0), tree);
		break;
	case 0x9001: /* TMR */
		offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_package_annex_C_TMR, NULL);
		break;
	case 0x9023: /* User Service Information */
		offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_h248_package_annex_C_USI, &new_tvb);
		dissect_q931_bearer_capability_ie(new_tvb, 0, 3, tree);
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, -1,"PropertyID not decoded(yet) 0x%x",name_minor);
		break;
	}
}

static const value_string h248_3GUP_Mode_vals[] = {
  {   0x00000001, "Transparent mode" },
  {   0x00000002, "Support mode for predefined SDU sizes" },
	{0,     NULL}
};

static const value_string h248_3GUP_upversions_vals[] = {
  {   0x01, "Version 1" },
  {   0x02, "Version 2" },
  {   0x03, "Version 3" },
  {   0x04, "Version 4" },
  {   0x05, "Version 5" },
  {   0x06, "Version 6" },
  {   0x07, "Version 7" },
  {   0x08, "Version 8" },
  {   0x09, "Version 9" },
  {   0x0A, "Version 10" },
  {   0x0B, "Version 11" },
  {   0x0C, "Version 12" },
  {   0x0D, "Version 13" },
  {   0x0E, "Version 14" },
  {   0x0F, "Version 15" },
  {   0x10, "Version 16" },
	{0,     NULL}
};

static const value_string h248_3GUP_delerrsdu_vals[] = {
  {   0x0001, "Yes" },
  {   0x0002, "No" },
  {   0x0003, "Not Applicable" },
	{0,     NULL}
};

static const value_string h248_3GUP_interface_vals[] = {
  {   0x0001, "RAN (Iu interface)" },
  {   0x0002, "CN (Nb interfac)" },
	{0,     NULL}
};

static const value_string h248_3GUP_initdir_vals[] = {
  {   0x0001, "Incoming" },
  {   0x0002, "Outgoing" },
	{0,     NULL}
};

static void
dissect_3G_User_Plane_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 name_minor){
	int offset = 0;

	switch ( name_minor ){
	case 0x0001:
			offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_package_3GUP_Mode, NULL);
			break;
	case 0x0002:
			offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_package_3GUP_UPversions, NULL);
			break;
	case 0x0003:
			offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_package_3GUP_delerrsdu, NULL);
			break;
	case 0x0004:
			offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_package_3GUP_interface, NULL);
			break;
	case 0x0005:
			offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_package_3GUP_initdir, NULL);
			break;
		default:
			proto_tree_add_text(tree, tvb, offset, -1,"PropertyID not decoded(yet) 0x%x",name_minor);
			break;
	}

 
}
static const value_string BNCChar_vals[] = {
  {   1, "aal1" },
  {   2, "aal2" },
  {   3, "aal1struct" },
  {   4, "ipRtp" },
  {   5, "tdm" },
  { 0, NULL }
};
static void
dissect_h248_package_data(gboolean implicit_tag, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,guint16 name_major, guint16 name_minor){

guint offset=0;

	switch ( name_major ){
		case 0x0000: /* Media stream properties H.248.1 Annex C */
			dissect_h248_annex_C_PDU(implicit_tag, tvb, pinfo, tree, name_minor);
			break;
		case 0x0001: /* g H.248.1 Annex E */
			proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), "H.248: Dissector for Package/ID:0x%04x not implemented (yet).", name_major);
			break;
		case 0x000d: /* tdmc H.248.1 Annex E */
			switch (name_minor){
				case 0x0008: /*ec*/
					offset = dissect_ber_boolean(TRUE, pinfo, tree, tvb, offset, hf_h248_package_annex_C_tdmc_ec);
					break;
				case 0x000a: /* gain */
					offset = dissect_ber_integer(TRUE, pinfo, tree, tvb, offset, hf_h248_package_annex_C_tdmc_gain, NULL);
					break;
				default:
					proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), "H.248: Dissector for Package/ID:0x%04x not implemented (yet).", name_major);
					break;
			}
			break;
		case 0x001e: /* Bearer Characteristics Q.1950 Annex A */
			offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_package_bcp_BNCChar_PDU, NULL);
			break;
		case 0x0021: /* Generic Bearer Connection Q.1950 Annex A */
			proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), "H.248: Dissector for Package/ID:0x%04x not implemented (yet).", name_major);
			break;
		case 0x002f: /* 3G User Plane TS 29.232 */
			dissect_3G_User_Plane_PDU(implicit_tag, tvb, pinfo, tree, name_minor);
			break;
		default:
			proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), "H.248: Dissector for Package/ID:0x%04x not implemented (yet).", name_major);
			break;
	}

}
static guint32 packageandid;

static int 
dissect_h248_PkgdName(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  tvbuff_t *new_tvb;
  proto_tree *package_tree=NULL;
  guint16 name_major, name_minor;
  int old_offset;

  old_offset=offset;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index, &new_tvb);


  /* this field is always 4 bytes  so just read it into two integers */
  name_major=tvb_get_ntohs(new_tvb, 0);
  name_minor=tvb_get_ntohs(new_tvb, 2);
  packageandid=(name_major<<16)|name_minor;

  /* do the prettification */
  proto_item_append_text(ber_last_created_item, "  %s (%04x)", val_to_str(name_major, package_name_vals, "Unknown Package"), name_major);
  if(tree){
    package_tree = proto_item_add_subtree(ber_last_created_item, ett_packagename);
  }
  proto_tree_add_uint(package_tree, hf_h248_package_name, tvb, offset-4, 2, name_major);
  return offset;
}


static int 
dissect_h248_EventName(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  tvbuff_t *new_tvb;
  proto_tree *package_tree=NULL;
  guint16 name_major, name_minor;
  int old_offset;

  old_offset=offset;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index, &new_tvb);


  /* this field is always 4 bytes  so just read it into two integers */
  name_major=tvb_get_ntohs(new_tvb, 0);
  name_minor=tvb_get_ntohs(new_tvb, 2);
  packageandid=(name_major<<16)|name_minor;

  /* do the prettification */
  proto_item_append_text(ber_last_created_item, "  %s (%04x)", val_to_str(name_major, package_name_vals, "Unknown Package"), name_major);
  if(tree){
    package_tree = proto_item_add_subtree(ber_last_created_item, ett_packagename);
  }
  proto_tree_add_uint(package_tree, hf_h248_event_name, tvb, offset-4, 4, packageandid);
  return offset;
}



static int
dissect_h248_SignalName(gboolean implicit_tag , tvbuff_t *tvb, int offset, packet_info *pinfo , proto_tree *tree, int hf_index) {
  tvbuff_t *new_tvb;
  proto_tree *package_tree=NULL;
  guint16 name_major, name_minor;
  int old_offset;

  old_offset=offset;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index, &new_tvb);


  /* this field is always 4 bytes  so just read it into two integers */
  name_major=tvb_get_ntohs(new_tvb, 0);
  name_minor=tvb_get_ntohs(new_tvb, 2);
  packageandid=(name_major<<16)|name_minor;

  /* do the prettification */
  proto_item_append_text(ber_last_created_item, "  %s (%04x)", val_to_str(name_major, package_name_vals, "Unknown Package"), name_major);
  if(tree){
    package_tree = proto_item_add_subtree(ber_last_created_item, ett_packagename);
  }
  proto_tree_add_uint(package_tree, hf_h248_signal_name, tvb, offset-4, 4, packageandid);
  return offset;
}
static int
dissect_h248_PropertyID(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_) {

	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	guint16 name_major;
	guint16 name_minor;
	int old_offset, end_offset;
	tvbuff_t *next_tvb;

	old_offset=offset;
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
	end_offset=offset+len;

	if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_OCTETSTRING) ){
		proto_tree_add_text(tree, tvb, offset-2, 2, "H.248 BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}


	next_tvb = tvb_new_subset(tvb, offset , len , len );
	name_major = packageandid >> 16;
	name_minor = packageandid & 0xffff;
/*
	if(!dissector_try_port(h248_package_bin_dissector_table, name_major, next_tvb, pinfo, tree)){
		proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "H.248: Dissector for Package/ID:0x%08x not implemented (yet).", packageandid);

		offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, old_offset, hf_index, NULL);
	}
*/
	dissect_h248_package_data(implicit_tag, next_tvb, pinfo, tree, name_major, name_minor);
	
	return end_offset;
}



static int 
dissect_h248_MtpAddress(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  tvbuff_t *new_tvb;
  proto_tree *mtp_tree=NULL;
  guint32 val;
  int i, len, old_offset;

  old_offset=offset;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index, &new_tvb);


  /* this field is either 2 or 4 bytes  so just read it into an integer */
  val=0;
  len=tvb_length(new_tvb);
  for(i=0;i<len;i++){
    val= (val<<8)|tvb_get_guint8(new_tvb, i);
  }

  /* do the prettification */
  proto_item_append_text(ber_last_created_item, "  NI = %d, PC = %d ( %d-%d )", val&0x03,val>>2,val&0x03,val>>2);
  if(tree){
    mtp_tree = proto_item_add_subtree(ber_last_created_item, ett_mtpaddress);
  }
  proto_tree_add_uint(mtp_tree, hf_h248_mtpaddress_ni, tvb, old_offset, offset-old_offset, val&0x03);
  proto_tree_add_uint(mtp_tree, hf_h248_mtpaddress_pc, tvb, old_offset, offset-old_offset, val>>2);


  return offset;
}

#include "packet-h248-fn.c"


static void
dissect_h248(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *h248_item;
  proto_tree *h248_tree = NULL;

  /* Check if it is actually a text based h248 encoding, which we call
     megaco in ehtereal.
  */
  if(tvb_length(tvb)>=6){
    if(!tvb_strneql(tvb, 0, "MEGACO", 6)){
      static dissector_handle_t megaco_handle=NULL;
      if(!megaco_handle){
        megaco_handle = find_dissector("megaco");
      }
      if(megaco_handle){
        call_dissector(megaco_handle, tvb, pinfo, tree);
        return;
      }
    }
  }

  /* Make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.248");

  if (tree) {
    h248_item = proto_tree_add_item(tree, proto_h248, tvb, 0, -1, FALSE);
    h248_tree = proto_item_add_subtree(h248_item, ett_h248);
  }

  dissect_h248_MegacoMessage(FALSE, tvb, 0, pinfo, h248_tree, -1);

}



/*--- proto_register_h248 ----------------------------------------------*/
void proto_register_h248(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_h248_mtpaddress_ni, {
      "NI", "h248.mtpaddress.ni", FT_UINT32, BASE_DEC,
      NULL, 0, "NI", HFILL }},
    { &hf_h248_mtpaddress_pc, {
      "PC", "h248.mtpaddress.pc", FT_UINT32, BASE_DEC,
      NULL, 0, "PC", HFILL }},
    { &hf_h248_transactionId_64, {
	  "transactionId", "h248.transactionId",
	  FT_UINT64, BASE_HEX, NULL, 0,"", HFILL }}, 
    { &hf_h248_contextId_64, {
	  "contextId", "h248.contextId",
	  FT_UINT64, BASE_HEX, NULL, 0,"", HFILL }}, 
    { &hf_h248_package_name, {
      "Package", "h248.package_name", FT_UINT16, BASE_HEX,
      VALS(package_name_vals), 0, "Package", HFILL }},
    { &hf_h248_event_name, {
      "Package and Event name", "h248.event_name", FT_UINT32, BASE_HEX,
      VALS(event_name_vals), 0, "Package", HFILL }},
    { &hf_h248_signal_name, {
      "Package and Signal name", "h248.signal_name", FT_UINT32, BASE_HEX,
      VALS(signal_name_vals), 0, "Package", HFILL }},
	{ &hf_h248_package_bcp_BNCChar_PDU,
      { "BNCChar", "h248.package_bcp.BNCChar",
        FT_UINT32, BASE_DEC, VALS(BNCChar_vals), 0,
        "BNCChar", HFILL }},
	{ &hf_h248_package_annex_C_tdmc_ec,
      { "Echo Cancellation", "h248.package_annex_C.tdmc.ec",
        FT_BOOLEAN, 8, TFS(&h248_tdmc_ec_vals), 0,
        "Echo Cancellation", HFILL }},
	{ &hf_h248_package_annex_C_tdmc_gain,
      { "Gain", "h248.package_annex_C.tdmc.gain",
        FT_UINT32, BASE_HEX, NULL, 0,
        "Gain", HFILL }},
	{ &hf_h248_package_annex_C_ACodec,
      { "ACodec", "h248.package_annex_C.ACodec",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ACodec", HFILL }},
	{ &hf_h248_package_annex_C_TMR,
      { "TMR", "h248.package_annex_C.TMR",
        FT_UINT32, BASE_DEC, VALS(isup_transmission_medium_requirement_value), 0,
        "BNCChar", HFILL }},
	{ &hf_h248_package_annex_C_Mediatx,
      { "Mediatx", "h248.package_annex_C.Mediatx",
        FT_UINT32, BASE_DEC, VALS(h248_package_annex_C_Mediatx_vals), 0,
        "Mediatx", HFILL }},
	{ &hf_h248_package_annex_C_USI,
      { "USI", "h248.package_annex_C.USI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "User Service Information", HFILL }},
	{ &hf_h248_package_annex_C_BIR,
      { "BIR", "h248.package_annex_C.BIR",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BIR", HFILL }},
	{ &hf_h248_package_annex_C_NSAP,
      { "NSAP", "h248.package_annex_C.NSAP",
        FT_BYTES, BASE_HEX, NULL, 0,
        "NSAP", HFILL }},
	{ &hf_h248_package_3GUP_Mode,
      { "Mode", "h248.package_3GUP.Mode",
        FT_UINT32, BASE_DEC, VALS(h248_3GUP_Mode_vals), 0,
        "Mode", HFILL }},
	{ &hf_h248_package_3GUP_UPversions,
      { "UPversions", "h248.package_3GUP.upversions",
        FT_UINT32, BASE_DEC, VALS(h248_3GUP_upversions_vals), 0,
        "UPversions", HFILL }},
	{ &hf_h248_package_3GUP_delerrsdu,
      { "Delivery of erroneous SDUs", "h248.package_3GUP.delerrsdu",
        FT_UINT32, BASE_DEC, VALS(h248_3GUP_delerrsdu_vals), 0,
        "Delivery of erroneous SDUs", HFILL }},
	{ &hf_h248_package_3GUP_interface,
      { "Interface", "h248.package_3GUP.interface",
        FT_UINT32, BASE_DEC, VALS(h248_3GUP_interface_vals), 0,
        "Interface", HFILL }},
	{ &hf_h248_package_3GUP_initdir,
      { "Initialisation Direction", "h248.package_3GUP.initdir",
        FT_UINT32, BASE_DEC, VALS(h248_3GUP_initdir_vals), 0,
        "Initialisation Direction", HFILL }},

#include "packet-h248-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h248,
    &ett_mtpaddress,
    &ett_packagename,
	&ett_codec,
#include "packet-h248-ettarr.c"
  };

  /* Register protocol */
  proto_h248 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("h248", dissect_h248, proto_h248);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h248, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* register a dissector table packages can attach to */
  h248_package_bin_dissector_table = register_dissector_table("h248.package.bin", "Binary H.248 Package Dissectors", FT_UINT16,BASE_HEX);
  
}


/*--- proto_reg_handoff_h248 -------------------------------------------*/
void proto_reg_handoff_h248(void) {
  dissector_handle_t h248_handle;

  h248_handle = find_dissector("h248");
  h248_term_handle = find_dissector("h248term");

  dissector_add("m3ua.protocol_data_si", GATEWAY_CONTROL_PROTOCOL_USER_ID, h248_handle);
  dissector_add("mtp3.service_indicator", GATEWAY_CONTROL_PROTOCOL_USER_ID, h248_handle);
  dissector_add("sctp.ppi", H248_PAYLOAD_PROTOCOL_ID, h248_handle);
}

