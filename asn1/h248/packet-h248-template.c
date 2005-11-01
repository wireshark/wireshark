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
#include <epan/emem.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <stdio.h>
#include <string.h>

#include <epan/dissectors/packet-ber.h>
#include "packet-h248.h"
#include <epan/dissectors/packet-isup.h>
#include <epan/dissectors/packet-q931.h>

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
static int hf_h248_context_id = -1;
static int hf_h248_error_code = -1;

static int hf_h248_cmd_trx = -1;
static int hf_h248_cmd_request = -1;
static int hf_h248_cmd_reply = -1;
static int hf_h248_cmd_pending = -1;
static int hf_h248_cmd_dup_request = -1;
static int hf_h248_cmd_dup_reply = -1;
static int hf_h248_cmd_start = -1;
static int hf_h248_cmd_error = -1;
static int hf_h248_cmd_ctx = -1;
static int hf_h248_ctx_start = -1;
static int hf_h248_ctx_last = -1;
static int hf_h248_ctx_cmd = -1;
static int hf_h248_ctx_cmd_type = -1;
static int hf_h248_ctx_cmd_request = -1;
static int hf_h248_ctx_cmd_reply = -1;
static int hf_h248_ctx_cmd_error = -1;


#include "packet-h248-hf.c"

/* Initialize the subtree pointers */
static gint ett_h248 = -1;
static gint ett_mtpaddress = -1;
static gint ett_packagename = -1;
static gint ett_codec = -1;


static gint ett_cmd = -1;
static gint ett_ctx = -1;
static gint ett_ctx_cmd = -1;
static gint ett_ctx_cmds = -1;
static gint ett_debug = -1;

#include "packet-h248-ett.c"

static dissector_handle_t h248_term_handle;

#if 0
static GHashTable* h248_package_signals = NULL;
static GHashTable* h248_package_events = NULL;
static GHashTable* h248_package_properties = NULL;

static dissector_table_t h248_package_bin_dissector_table=NULL;
#endif

static GHashTable* transactions = NULL;
static GHashTable* transactions_by_framenum = NULL;
static GHashTable* contexts_creating = NULL;
static GHashTable* contexts = NULL;

static gboolean keep_persistent_data = FALSE;

static h248_cmdmsg_info_t* h248_cmdmsg;
static guint32 transaction_id;
static guint32 context_id;

static proto_tree *h248_tree;

static dissector_handle_t h248_term_handle;


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




#define NULL_CONTEXT 0
#define CHOOSE_CONTEXT 0xFFFFFFFE
#define ALL_CONTEXTS 0xFFFFFFFF

#if 0
static const value_string context_id_type[] = {
	{NULL_CONTEXT,"0 (Null Context)"},
	{CHOOSE_CONTEXT,"$ (Choose Context)"},
	{ALL_CONTEXTS,"* (All Contexts)"},
	{0,NULL}
};
#endif

static const value_string h248_reasons[] = {
    { 400, "Syntax error in message"},
    { 401, "Protocol Error"},
    { 402, "Unauthorized"},
    { 403, "Syntax error in transaction request"},
    { 406, "Version Not Supported"},
    { 410, "Incorrect identifier"},
    { 411, "The transaction refers to an unknown ContextId"},
    { 412, "No ContextIDs available"},
    { 421, "Unknown action or illegal combination of actions"},
    { 422, "Syntax Error in Action"},
    { 430, "Unknown TerminationID"},
    { 431, "No TerminationID matched a wildcard"},
    { 432, "Out of TerminationIDs or No TerminationID available"},
    { 433, "TerminationID is already in a Context"},
    { 434, "Max number of Terminations in a Context exceeded"},
    { 435, "Termination ID is not in specified Context"},
    { 440, "Unsupported or unknown Package"},
    { 441, "Missing Remote or Local Descriptor"},
    { 442, "Syntax Error in Command"},
    { 443, "Unsupported or Unknown Command"},
    { 444, "Unsupported or Unknown Descriptor"},
    { 445, "Unsupported or Unknown Property"},
    { 446, "Unsupported or Unknown Parameter"},
    { 447, "Descriptor not legal in this command"},
    { 448, "Descriptor appears twice in a command"},
    { 449, "Unsupported or Unknown Parameter or Property Value"},
    { 450, "No such property in this package"},
    { 451, "No such event in this package"},
    { 452, "No such signal in this package"},
    { 453, "No such statistic in this package"},
    { 454, "No such parameter value in this package"},
    { 455, "Property illegal in this Descriptor"},
    { 456, "Property appears twice in this Descriptor"},
    { 457, "Missing parameter in signal or event"},
    { 458, "Unexpected Event/Request ID"},
    { 459, "Unsupported or Unknown Profile"},
    { 460, "Unable to set statistic on stream"},
    { 471, "Implied Add for Multiplex failure"},
    { 500, "Internal software Failure in MG"},
    { 501, "Not Implemented"},
    { 502, "Not ready"},
    { 503, "Service Unavailable"},
    { 504, "Command Received from unauthorized entity"},
    { 505, "Transaction Request Received before a Service Change Reply has been received"},
    { 506, "Number of Transaction Pendings Exceeded"},
    { 510, "Insufficient resources"},
    { 512, "Media Gateway unequipped to detect requested Event"},
    { 513, "Media Gateway unequipped to generate requested Signals"},
    { 514, "Media Gateway cannot send the specified announcement"},
    { 515, "Unsupported Media Type"},
    { 517, "Unsupported or invalid mode"},
    { 518, "Event buffer full"},
    { 519, "Out of space to store digit map"},
    { 520, "Digit Map undefined in the MG"},
    { 521, "Termination is ServiceChangeing"},
    { 522, "Functionality Requested in Topology Triple Not Supported"},
    { 526, "Insufficient bandwidth"},
    { 529, "Internal hardware failure in MG"},
    { 530, "Temporary Network failure"},
    { 531, "Permanent Network failure"},
    { 532, "Audited Property, Statistic, Event or Signal does not exist"},
    { 533, "Response exceeds maximum transport PDU size"},
    { 534, "Illegal write or read only property"},
    { 540, "Unexpected initial hook state"},
    { 542, "Command is not allowed on this termination"},
    { 581, "Does Not Exist"},
    { 600, "Illegal syntax within an announcement specification"},
    { 601, "Variable type not supported"},
    { 602, "Variable value out of range"},
    { 603, "Category not supported"},
    { 604, "Selector type not supported"},
    { 605, "Selector value not supported"},
    { 606, "Unknown segment ID"},
    { 607, "Mismatch between play specification and provisioned data"},
    { 608, "Provisioning error"},
    { 609, "Invalid offset"},
    { 610, "No free segment IDs"},
    { 611, "Temporary segment not found"},
    { 612, "Segment in use"},
    { 613, "ISP port limit overrun"},
    { 614, "No modems available"},
    { 615, "Calling number unacceptable"},
    { 616, "Called number unacceptable"},
    { 900, "Service Restored"},
    { 901, "Cold Boot"},
    { 902, "Warm Boot"},
    { 903, "MGC Directed Change"},
    { 904, "Termination malfunctioning"},
    { 905, "Termination taken out of service"},
    { 906, "Loss of lower layer connectivity (e.g. downstream sync)"},
    { 907, "Transmission Failure"},
    { 908, "MG Impending Failure"},
    { 909, "MGC Impending Failure"},
    { 910, "Media Capability Failure"},
    { 911, "Modem Capability Failure"},
    { 912, "Mux Capability Failure"},
    { 913, "Signal Capability Failure"},
    { 914, "Event Capability Failure"},
    { 915, "State Loss"},
    { 916, "Packages Change"},
    { 917, "Capabilities Change"},
    { 918, "Cancel Graceful"},
    { 919, "Warm Failover"},
    { 920, "Cold Failover"},
	{0,NULL}
};

static const value_string request_types[] = {
    { 0, "unknown" },
    { 1, "add" },
    { 2, "move" },
    { 3, "mod" },
    { 4, "subtract" },
    { 5, "auditCap" },
    { 6, "auditValue" },
    { 7, "notify" },
    { 8, "serviceChange" }
};

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
			proto_item* pi = proto_tree_add_text(tree, tvb, offset-len, len,"transactionId %" PRIu64, trx_id);
            proto_item_set_expert_flags(pi, PI_MALFORMED, PI_WARN);

            transaction_id = 0;

		} else {
			proto_tree_add_uint(tree, hf_h248_transactionId, tvb, offset-len, len, (guint32)trx_id);
            transaction_id = (guint32)trx_id;
		}
	}	

    return offset;
}

static int dissect_h248_ctx_id(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	guint64 ctx_id = 0;
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
			ctx_id=(ctx_id<<8)|tvb_get_guint8(tvb, offset);
			offset++;
		}
		if (ctx_id > 0xffffffff) {
			proto_item* pi = proto_tree_add_text(tree, tvb, offset-len, len,
                                                 "contextId: %" PRIu64, ctx_id);
            proto_item_set_expert_flags(pi, PI_MALFORMED, PI_WARN);

            context_id = 0xfffffffd;
            
		} else {
			proto_tree_add_uint(tree, hf_h248_context_id, tvb, offset-len, len, (guint32)ctx_id);
            
            context_id = (guint32) ctx_id;
		}
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
		if (new_tvb)
			dissect_nsap(new_tvb, 0,tvb_length_remaining(new_tvb, 0), tree);
		break;
	case 0x9001: /* TMR */
		offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_package_annex_C_TMR, NULL);
		break;
	case 0x9023: /* User Service Information */
		offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_h248_package_annex_C_USI, &new_tvb);
		if (new_tvb)
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
  
  if (new_tvb) {
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
  }
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

  if (new_tvb) {
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
  }
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

  if (new_tvb) {
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
  }
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

  if (new_tvb) {
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
  }
  
  return offset;
}

static gchar* cmd_str(h248_cmdmsg_info_t* cmdmsg) {
    static gchar* command_strings[][2] = {
    { "unkReq", "unkReply" },
    { "addReq", "addReply" },
    { "moveReq", "moveReply" },
    { "modReq", "modReply" },
    { "subtractReq", "subtractReply" },
    { "auditCapRequest", "auditCapReply" },
    { "auditValueRequest", "auditValueReply" },
    { "notifyReq", "notifyReply" },
    { "serviceChangeReq", "serviceChangeReply" }
    };
    
    gchar* ctx_str;
    gchar* cmd_str;
    gchar* param_str;
    
    switch (cmdmsg->msg_type) {
        case H248_TRX_REQUEST:
            cmd_str = command_strings[cmdmsg->cmd_type][0];
            
            if (cmdmsg->term_is_wildcard) {
                param_str = "Term *";
            } else {
                param_str = ep_strdup_printf("Term %s",cmdmsg->term_id);
            }
                
                break;
        case H248_TRX_REPLY:
            cmd_str = command_strings[cmdmsg->cmd_type][1];
            
            if ( cmdmsg->error_code ) {
                param_str = ep_strdup_printf("Error %u",cmdmsg->error_code);
            } else {
                if (cmdmsg->term_is_wildcard) {
                    param_str = "Term *";
                } else {
                    param_str = ep_strdup_printf("Term %s",cmdmsg->term_id);
                }
            }
                break;
        case H248_TRX_PENDING:
            return ep_strdup_printf("T %x { Pending }", cmdmsg->transaction_id);
        case H248_TRX_ACK:
            return ep_strdup_printf("T %x { Ack }", cmdmsg->transaction_id);
        default:
            return "[ Bad Command ]";
    };
    
    switch (cmdmsg->context_id) {
        case NULL_CONTEXT: ctx_str = "0"; break;
        case CHOOSE_CONTEXT: ctx_str = "$"; break;
        case ALL_CONTEXTS: ctx_str = "*"; break;
        default: ctx_str = ep_strdup_printf("%u",cmdmsg->context_id); break;
    }
    
    return ep_strdup_printf("T %x { C %s { %s { %s }}} ",
                            cmdmsg->transaction_id, ctx_str, cmd_str, param_str );
    
}

static proto_tree* cmdmsg_tree(h248_cmdmsg_info_t* cmdmsg) {
    proto_item* pi = proto_tree_add_text(h248_tree,NULL,0,0,"cmd msg");
    proto_tree* debug_tree = proto_item_add_subtree(pi,ett_debug);
    
    proto_tree_add_text(debug_tree,NULL,0,0,"transaction_id = %x",cmdmsg->transaction_id);
    proto_tree_add_text(debug_tree,NULL,0,0,"context_id = %x",cmdmsg->context_id);
    proto_tree_add_text(debug_tree,NULL,0,0,"cmd_type = %u",cmdmsg->cmd_type);
    proto_tree_add_text(debug_tree,NULL,0,0,"msg_type = %u",cmdmsg->msg_type);
    proto_tree_add_text(debug_tree,NULL,0,0,"error_code = %u",cmdmsg->error_code);
    proto_tree_add_text(debug_tree,NULL,0,0,"term_is_wildcard = %x", cmdmsg->term_is_wildcard);
    proto_tree_add_text(debug_tree,NULL,0,0,"term_id = %s", cmdmsg->term_id);
    
    return debug_tree;
}

static void analyze_h248_cmd(packet_info* pinfo, h248_cmdmsg_info_t* cmdmsg) {
    h248_cmd_info_t* cmd_info;
    static h248_cmd_info_t no_cmd_info = {NULL,0,H248_CMD_NONE,0,0,0,FALSE,0,NULL,NULL,NULL};
    gchar* low_addr;
    gchar* high_addr;
    guint framenum = pinfo->fd->num;
    gchar* cmd_key;


    cmd_info = g_hash_table_lookup(transactions_by_framenum,GUINT_TO_POINTER(framenum));
    
    if (cmd_info == &no_cmd_info) {
        cmdmsg->cmd_info = NULL;
        return;
    } else if ( cmd_info == NULL ) {
        gboolean dup = FALSE;

        if (CMP_ADDRESS(&(pinfo->net_src), &(pinfo->net_dst)) < 0) {
            low_addr = address_to_str(&(pinfo->net_src));
            high_addr = address_to_str(&(pinfo->net_dst));
        } else {
            low_addr = address_to_str(&(pinfo->net_dst));
            high_addr = address_to_str(&(pinfo->net_src));
        }
        
        cmd_key = ep_strdup_printf("%s <-> %s : %x",low_addr,high_addr,cmdmsg->transaction_id);
        
        cmd_info = g_hash_table_lookup(transactions,cmd_key);
        
        if ( cmd_info ) {
            switch (cmdmsg->msg_type) {
                case H248_TRX_REQUEST:
                    dup = TRUE;
                    break;
                case H248_TRX_REPLY:
                    if (cmd_info->response_frame) {
                        dup = TRUE;
                    } else {
                        cmd_info->response_frame = framenum;
                        cmd_info->error_code = cmdmsg->error_code;
                    }
                    break;
                case H248_TRX_PENDING:
                    cmd_info->pendings++;
                default:
                    break;
            }
        } else {
            
            switch (cmdmsg->msg_type) {
                case H248_TRX_REQUEST:
                    cmd_info = se_alloc(sizeof(h248_cmd_info_t));
                    cmd_info->key = se_strdup(cmd_key);
                    cmd_info->trx_id = cmdmsg->transaction_id;
                    cmd_info->type = cmdmsg->cmd_type;
                    cmd_info->request_frame = framenum;
                    cmd_info->response_frame = 0;
                    cmd_info->pendings = 0;
                    cmd_info->choose_ctx = (cmdmsg->context_id == CHOOSE_CONTEXT);
                    cmd_info->error_code = 0;
                    cmd_info->context = NULL;
                    cmd_info->next = NULL;
                    cmd_info->last = NULL;
                    
                    g_hash_table_insert(transactions,cmd_info->key,cmd_info);
                    break;
                default:
                    cmd_info = &no_cmd_info;
                    break;
            }
            
        }

        g_hash_table_insert(transactions_by_framenum,GUINT_TO_POINTER(framenum),cmd_info);
        
        cmdmsg->cmd_info = cmd_info;
        
        if ( cmd_info && (! cmd_info->context || cmd_info->context->ctx_id == 0 ) ) {
            h248_context_info_t** ctx_ptr;
            gchar* ctx_key;
            
            if (cmd_info->choose_ctx) {
                /* the fisrt transaction of a new context */
                
                ctx_key = ep_strdup_printf("%s-%s-%i",low_addr,high_addr,cmdmsg->transaction_id);

                switch (cmdmsg->msg_type) {
                    case H248_TRX_REQUEST: {
                        cmd_info->context = se_alloc(sizeof(h248_context_info_t));
                        cmd_info->context->key = NULL;
                        cmd_info->context->ctx_id = 0;
                        cmd_info->context->creation_frame = framenum;
                        cmd_info->context->cmds = cmd_info;
                        cmd_info->context->prior = NULL;
                        
                        cmd_info->next = NULL;
                        cmd_info->last = cmd_info;
                        
                        /*
                         * XXX: leak: the "transaction key" of a context should be freed
                         * as we get the context_id one, there's no need for it afterwards.
                         *
                         * We're no using an ep_allocated one because g_hashtables do not
                         * behave propperly if the key changes.
                         *
                         * g_strdup/g_free should be used instead of se_strdup.
                         */
                        
                        g_hash_table_insert(contexts_creating,se_strdup(ctx_key),cmd_info->context);
                        
                    }
                        break;
                    case H248_TRX_REPLY: {

                        /* XXX: former leak: this one should be an extended lookup to g_free the key */
                        if (( cmd_info->context = g_hash_table_lookup(contexts_creating,ctx_key) )) {
                            
                            ctx_key = ep_strdup_printf("%s<->%s : %.8x",low_addr,high_addr,cmdmsg->context_id);
                            
                            cmd_info->context->ctx_id = cmdmsg->context_id;
                            
                            if ((ctx_ptr = g_hash_table_lookup(contexts,ctx_key))) {
                                cmd_info->context->prior = *ctx_ptr;
                                cmd_info->context->key = cmd_info->context->prior->key;
                                *ctx_ptr = cmd_info->context;
                            } else {
                                ctx_ptr = se_alloc(sizeof(void*));
                                *ctx_ptr = cmd_info->context;
                                cmd_info->context->key = se_strdup(ctx_key);
                                
                                g_hash_table_insert(contexts,cmd_info->context->key,ctx_ptr);
                            }
                        }
                    }
                        break;
                    default:
                        break;
                }
            } else {
                ctx_key = ep_strdup_printf("%s<->%s : %.8x",low_addr,high_addr,cmdmsg->context_id);
                
                if (( ctx_ptr = g_hash_table_lookup(contexts,ctx_key) )) {
                    cmd_info->context = *ctx_ptr;
                    cmd_info->context->cmds->last->next = cmd_info;
                    cmd_info->context->cmds->last = cmd_info;
                }
            }
            
            if (cmd_info && cmd_info->context) {
                cmd_info->context->last_frame = framenum;
            }
        }
    } else {
        cmdmsg->cmd_info = cmd_info;
        return;
    }
    
}

static void analysis_tree(packet_info* pinfo, tvbuff_t *tvb, proto_tree* tree, h248_cmdmsg_info_t* cmdmsg) {
    h248_cmd_info_t* cmd_info = cmdmsg->cmd_info;
    guint framenum = pinfo->fd->num;

    if (cmd_info) {
        proto_item* pi = proto_tree_add_string(tree,hf_h248_cmd_trx,tvb,0,0,cmd_info->key);
        proto_tree* cmd_tree = proto_item_add_subtree(pi, ett_cmd);
        PROTO_ITEM_SET_GENERATED(pi);
        
        switch (cmdmsg->msg_type) {
            case H248_TRX_REQUEST:
                if (cmd_info->response_frame) {
                    pi = proto_tree_add_uint(cmd_tree,hf_h248_cmd_reply,tvb,0,0,cmd_info->response_frame);
                } else {
                    pi = proto_tree_add_text(cmd_tree,tvb,0,0,"No response");
                    proto_item_set_expert_flags(pi, PI_SEQUENCE, PI_NOTE);
                }
                PROTO_ITEM_SET_GENERATED(pi);

                if (cmd_info->request_frame != framenum) {
                    pi = proto_tree_add_uint(cmd_tree,hf_h248_cmd_dup_request,tvb,0,0,cmd_info->request_frame);
                    proto_item_set_expert_flags(pi, PI_SEQUENCE, PI_NOTE);
                    PROTO_ITEM_SET_GENERATED(pi);
                }
                break;
            case H248_TRX_REPLY:
                
                if (cmd_info->request_frame) {
                    proto_tree_add_uint(cmd_tree,hf_h248_cmd_request,tvb,0,0,cmd_info->request_frame);
                } else {
                    pi = proto_tree_add_text(cmd_tree,tvb,0,0,"No request");
                    proto_item_set_expert_flags(pi, PI_SEQUENCE, PI_NOTE);                    
                }
                
                if (cmd_info->response_frame != framenum) {
                    pi = proto_tree_add_uint(cmd_tree,hf_h248_cmd_dup_reply,tvb,0,0,cmd_info->response_frame);
                    proto_item_set_expert_flags(pi, PI_SEQUENCE, PI_NOTE);
                }
                break;
            default:
                if (cmd_info->request_frame) {
                    proto_tree_add_uint(cmd_tree,hf_h248_cmd_request,tvb,0,0,cmd_info->request_frame);
                } else {
                    pi = proto_tree_add_text(cmd_tree,tvb,0,0,"No request");
                    proto_item_set_expert_flags(pi, PI_SEQUENCE, PI_NOTE);                    
                }
                
                if (cmd_info->response_frame) {
                    pi = proto_tree_add_uint(cmd_tree,hf_h248_cmd_reply,tvb,0,0,cmd_info->response_frame);
                } else {
                    pi = proto_tree_add_text(cmd_tree,tvb,0,0,"No response");
                    proto_item_set_expert_flags(pi, PI_SEQUENCE, PI_NOTE);
                }
                
                break;
        }
        
        if (cmd_info->pendings) {
            pi = proto_tree_add_uint(cmd_tree,hf_h248_cmd_pending,tvb,0,0,cmd_info->pendings);
            PROTO_ITEM_SET_GENERATED(pi);
            proto_item_set_expert_flags(pi, PI_SEQUENCE, PI_NOTE);            
        }
        
        if (cmd_info->choose_ctx) {
            pi = proto_tree_add_boolean(cmd_tree,hf_h248_cmd_start,tvb,0,0,TRUE);
            PROTO_ITEM_SET_GENERATED(pi);
            proto_item_set_expert_flags(pi, PI_SEQUENCE, PI_NOTE);
        }
        
        if (cmd_info->error_code) {
            pi = proto_tree_add_uint(cmd_tree,hf_h248_cmd_error,tvb,0,0,cmd_info->error_code);
            PROTO_ITEM_SET_GENERATED(pi);
            expert_add_info_format(pinfo, pi, PI_RESPONSE_CODE, PI_WARN, "Errored Command");
        }
        
        
        if (cmd_info->context) {
            proto_tree* ctx_tree;
            proto_tree* cmds_tree;
            h248_cmd_info_t* cmd;
            
            if (cmd_info->context->key) {
                pi = proto_tree_add_string(tree,hf_h248_cmd_ctx,tvb,0,0,cmd_info->context->key);
            } else {
                pi = proto_tree_add_text(tree,tvb,0,0,"Embryonic Context");
            }
            ctx_tree = proto_item_add_subtree(pi, ett_ctx);
            PROTO_ITEM_SET_GENERATED(pi);
            
            pi = proto_tree_add_uint(ctx_tree,hf_h248_ctx_start,tvb,0,0,cmd_info->context->creation_frame);
            PROTO_ITEM_SET_GENERATED(pi);
            
            pi = proto_tree_add_uint(ctx_tree,hf_h248_ctx_last,tvb,0,0,cmd_info->context->last_frame);
            PROTO_ITEM_SET_GENERATED(pi);
            
            pi = proto_tree_add_text(ctx_tree,tvb,0,0,"[ Commands ]");
            cmds_tree = proto_item_add_subtree(pi, ett_ctx_cmds);
            
            for(cmd = cmd_info->context->cmds; cmd; cmd = cmd->next) {
                proto_tree* ctx_cmd_tree;
                
                pi = proto_tree_add_uint(cmds_tree,hf_h248_ctx_cmd_type,tvb,0,0,cmd->type);
                PROTO_ITEM_SET_GENERATED(pi);
                ctx_cmd_tree = proto_item_add_subtree(pi,ett_ctx_cmd);
                
                if (cmd == cmd_info ) {
                    pi = proto_tree_add_uint_format(ctx_cmd_tree,hf_h248_ctx_cmd,tvb,0,0,cmd->trx_id,"This Transaction: %u",cmd->trx_id);
                } else {
                    pi = proto_tree_add_uint_format(ctx_cmd_tree,hf_h248_ctx_cmd,tvb,0,0,cmd->trx_id,"Transaction: %u",cmd->trx_id);
                }
                PROTO_ITEM_SET_GENERATED(pi);
                
                pi = proto_tree_add_uint(ctx_cmd_tree,hf_h248_ctx_cmd_request,tvb,0,0,cmd->request_frame);
                PROTO_ITEM_SET_GENERATED(pi);
                
                pi = proto_tree_add_uint(ctx_cmd_tree,hf_h248_ctx_cmd_reply,tvb,0,0,cmd->response_frame);
                PROTO_ITEM_SET_GENERATED(pi);
                
                if (cmd->error_code) {
                    pi = proto_tree_add_uint(ctx_cmd_tree,hf_h248_ctx_cmd_error,tvb,0,0,cmd->error_code);
                    PROTO_ITEM_SET_GENERATED(pi);
                    expert_add_info_format(pinfo, pi, PI_RESPONSE_CODE, PI_NOTE, "Errored Context");
                }
                
            }
            
        }
    }
}

#include "packet-h248-fn.c"

static void
dissect_h248(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *h248_item;
    
    h248_tree = NULL;
    
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


static void h248_init(void)  {
    
    if (transactions) g_hash_table_destroy(transactions);
    if (transactions_by_framenum) g_hash_table_destroy(transactions_by_framenum);
    if (contexts_creating) g_hash_table_destroy(contexts_creating);
    if (contexts) g_hash_table_destroy(contexts);
    
    transactions = g_hash_table_new(g_str_hash,g_str_equal);
    transactions_by_framenum = g_hash_table_new(g_direct_hash,g_direct_equal);
    contexts_creating = g_hash_table_new(g_str_hash,g_str_equal);
    contexts = g_hash_table_new(g_str_hash,g_str_equal);
    
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
  { &hf_h248_error_code,
  { "errorCode", "h248.errorCode",
      FT_UINT32, BASE_DEC, VALS(h248_reasons), 0,
      "ErrorDescriptor/errorCode", HFILL }},
  { &hf_h248_context_id,
  { "contextId", "h248.contextId",
      FT_UINT32, BASE_DEC, NULL, 0,
      "Context ID", HFILL }},
      
  { &hf_h248_cmd_trx, { "Transaction", "h248.trx", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_cmd_request, { "Request for this Reply", "h248.cmd.request", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_cmd_reply, { "Reply to this Request", "h248.cmd.reply", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_cmd_dup_request, { "This Request is a Duplicate of", "h248.cmd.dup_request", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_cmd_dup_reply, { "This Reply is a Duplicate of", "h248.cmd.dup_reply", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_cmd_pending, { "Pendings", "h248.cmd.pending", FT_UINT32, BASE_DEC, NULL, 0, "Number Of Pending Messages", HFILL }},
  { &hf_h248_cmd_start, { "This Transaction Starts a New Context", "h248.cmd.start", FT_BOOLEAN, BASE_NONE, NULL, 0, "", HFILL }},
  { &hf_h248_cmd_error, { "Error", "h248.cmd.error", FT_UINT32, BASE_DEC, VALS(h248_reasons), 0, "", HFILL }},
  { &hf_h248_cmd_ctx, { "Context", "h248.ctx", FT_STRING, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_start, { "Start", "h248.ctx.start", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_last, { "Last", "h248.ctx.last", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_cmd, { "Command", "h248.ctx.cmd", FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_cmd_type, { "Command Type", "h248.ctx.cmd.type", FT_UINT32, BASE_DEC, VALS(request_types), 0, "", HFILL }},
  { &hf_h248_ctx_cmd_request, { "Request", "h248.ctx.cmd.request", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_cmd_reply, { "Reply", "h248.ctx.cmd.reply", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_cmd_error, { "Error", "h248.ctx.cmd.error", FT_UINT32, BASE_DEC, VALS(h248_reasons), 0, "", HFILL }},

#include "packet-h248-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h248,
    &ett_mtpaddress,
    &ett_packagename,
    &ett_codec,
    &ett_cmd,
    &ett_ctx,
    &ett_ctx_cmd,
    &ett_ctx_cmds,
    &ett_debug,
      
#include "packet-h248-ettarr.c"
  };
  
  module_t *h248_module;


  /* Register protocol */
  proto_h248 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("h248", dissect_h248, proto_h248);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h248, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

#if 0
  /* register a dissector table packages can attach to */
  h248_package_signals = g_hash_table_new(g_hash_direct,g_direct_equal);
  h248_package_events = g_hash_table_new(g_hash_direct,g_direct_equal);
  h248_package_properties = g_hash_table_new(g_hash_direct,g_direct_equal);
#endif
  
  h248_module = prefs_register_protocol(proto_h248, h248_init);
  
  prefs_register_bool_preference(h248_module, "ctx_info",
                                 "Keep Context Information",
                                 "Whether persistent context information is to be kept",
                                 &keep_persistent_data);
  
  register_init_routine( &h248_init );

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

