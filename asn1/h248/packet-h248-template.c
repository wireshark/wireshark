/* packet-h248.c
 * Routines for H.248/MEGACO packet dissection
 *
 * Ronnie Sahlberg 2004
 *
 * Luis Ontanon 2005 - Context and Transaction Tracing
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

#include "packet-h248.h"

#define PNAME  "H.248 MEGACO"
#define PSNAME "H248"
#define PFNAME "h248"

#define GATEWAY_CONTROL_PROTOCOL_USER_ID 14

/* Initialize the protocol and registered fields */
static int proto_h248				= -1;
static int hf_h248_mtpaddress_ni	= -1;
static int hf_h248_mtpaddress_pc	= -1;
static int hf_h248_pkg_name		= -1;
static int hf_248_no_pkg_param = -1;
static int hf_h248_event_name		= -1;
static int hf_h248_signal_name		= -1;
static int hf_h248_pkg_bcp_BNCChar_PDU = -1;



static int hf_h248_context_id = -1;
static int hf_h248_error_code = -1;
static int hf_h248_term_wild_type = -1;
static int hf_h248_term_wild_level = -1;
static int hf_h248_term_wild_position = -1;

static int hf_h248_ctx = -1;
static int hf_h248_ctx_term = -1;
static int hf_h248_ctx_term_type = -1;
static int hf_h248_ctx_term_bir = -1;
static int hf_h248_ctx_term_nsap = -1;
static int hf_h248_ctx_cmd = -1;


static int hf_h248_no_pkg = -1;
static int hf_h248_no_sig = -1;
static int hf_h248_no_evt = -1;
static int hf_h248_no_param = -1;

static int hf_h248_serviceChangeReasonStr = -1;

#include "packet-h248-hf.c"

/* Initialize the subtree pointers */
static gint ett_h248 = -1;
static gint ett_mtpaddress = -1;
static gint ett_packagename = -1;
static gint ett_codec = -1;
static gint ett_wildcard = -1;

static gint ett_cmd = -1;
static gint ett_ctx = -1;
static gint ett_ctx_cmds = -1;
static gint ett_ctx_terms = -1;
static gint ett_ctx_term = -1;

static gint ett_h248_no_pkg = -1;
static gint ett_h248_no_sig = -1;
static gint ett_h248_no_evt = -1;

#include "packet-h248-ett.c"

static dissector_handle_t h248_term_handle;

#if 0
static GHashTable* h248_pkg_signals = NULL;
static GHashTable* h248_pkg_events = NULL;
static GHashTable* h248_pkg_properties = NULL;
static GHashTable* h248_wild_terms = NULL;

static dissector_table_t h248_pkg_bin_dissector_table=NULL;
#endif

static emem_tree_t* msgs = NULL;
static emem_tree_t* trxs = NULL;
static emem_tree_t* ctxs_by_trx = NULL;
static emem_tree_t* ctxs = NULL;

static gboolean h248_prefs_initialized = FALSE;
static gboolean keep_persistent_data = FALSE;
static guint32 udp_port = 0;
static guint32 temp_udp_port = 0;


static proto_tree *h248_tree;
static tvbuff_t* h248_tvb;

static dissector_handle_t h248_handle;
static dissector_handle_t h248_term_handle;

/* Forward declarations */
static int dissect_h248_ServiceChangeReasonStr(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);


static const value_string package_name_vals[] = {
  {   0x0000, "Media stream properties H.248.1 Annex C" },
  {   0x0001, "Generic H.248.1 Annex E" },
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
  {   0x00010001, "g/Cause" },
  {   0x00010002, "g/Signal Completion" },
  {   0x00040001, "tonedet/std(Start tone detected)" },
  {   0x00040002, "tonedet/etd(End tone detected)" },
  {   0x00040003, "tonedet/ltd(Long tone detected)" },
  {   0x00060004, "dd, DigitMap Completion Event" },
  {   0x00060010, "dd, DTMF character 0" },
  {   0x00060011, "dd, DTMF character 1" },
  {   0x00060012, "dd, DTMF character 2" },
  {   0x00060013, "dd, DTMF character 3" },
  {   0x00060014, "dd, DTMF character 4" },
  {   0x00060015, "dd, DTMF character 5" },
  {   0x00060016, "dd, DTMF character 6" },
  {   0x00060017, "dd, DTMF character 7" },
  {   0x00060018, "dd, DTMF character 8" },
  {   0x00060019, "dd, DTMF character 9" },
  {   0x0006001a, "dd, DTMF character A" },
  {   0x0006001b, "dd, DTMF character B" },
  {   0x0006001c, "dd, DTMF character C" },
  {   0x0006001d, "dd, DTMF character D" },
  {   0x00060020, "dd, DTMF character *" },
  {   0x00060021, "dd, DTMF character #" },
  {   0x00080030, "cd, Dial Tone" },
  {   0x00080031, "cd, Ringing Tone" },
  {   0x00080032, "cd, Busy Tone" },
  {   0x00080033, "cd, Congestion Tone" },
  {   0x00080034, "cd, Special Information Tone" },
  {   0x00080035, "cd, (Recording) Warning Tone" },
  {   0x00080036, "cd, Payphone Recognition Tone" },
  {   0x00080037, "cd, Call Waiting Tone" },
  {   0x00080038, "cd, Caller Waiting Tone" },
  {   0x00090004, "al, onhook" },
  {   0x00090005, "al, offhook" },
  {   0x00090006, "al, flashhook" },
  {   0x0009ffff, "al, *" },
  {   0x000a0005, "ct, Completion" },
  {   0x000b0005, "nt, network failure" },
  {   0x000b0006, "nt, quality alert" },
  {   0x000c0001, "rtp, Payload Transition" },
  {   0x00210000, "Generic Bearer Connection Q.1950 Annex A" },
  {   0x00210001, "GB/BNCChange" },
  {   0x002a0001, "H.245/h245msg (Incoming H.245 Message)" },
  {   0x002a0004, "H.245/h245ChC (H.245 Channel Closed)" },
  {   0x800a0000, "Nokia Bearer Characteristics Package" },
	{0,     NULL}
};

/*
 * This table consist of PackageName + SignalName and its's corresponding string
 */
static const value_string signal_name_vals[] = {
  {   0x00000000, "Media stream properties H.248.1 Annex C" },
  {   0x00010000, "g H.248.1 Annex E" },
  {   0x00030001, "tonegen/pt(Play tone)" },
  {   0x00050010, "dg, DTMF character 0" },
  {   0x00050011, "dg, DTMF character 1" },
  {   0x00050012, "dg, DTMF character 2" },
  {   0x00050013, "dg, DTMF character 3" },
  {   0x00050014, "dg, DTMF character 4" },
  {   0x00050015, "dg, DTMF character 5" },
  {   0x00050016, "dg, DTMF character 6" },
  {   0x00050017, "dg, DTMF character 7" },
  {   0x00050018, "dg, DTMF character 8" },
  {   0x00050019, "dg, DTMF character 9" },
  {   0x0005001a, "dg, DTMF character A" },
  {   0x0005001b, "dg, DTMF character B" },
  {   0x0005001c, "dg, DTMF character C" },
  {   0x0005001d, "dg, DTMF character D" },
  {   0x00050020, "dg, DTMF character *" },
  {   0x00050021, "dg, DTMF character #" },
  {   0x00070030, "cg, Dial Tone" },
  {   0x00070031, "cg/rt (Ringing Tone)" },
  {   0x00070032, "cg, Busy Tone" },
  {   0x00070033, "cg, Congestion Tone" },
  {   0x00070034, "cg, Special Information Tone" },
  {   0x00070035, "cg, (Recording) Warning Tone" },
  {   0x00070036, "cg, Payphone Recognition Tone" },
  {   0x00070037, "cg, Call Waiting Tone" },
  {   0x00070038, "cg, Caller Waiting Tone" },
  {   0x00090002, "al, ring" },
  {   0x0009ffff, "al, *" },
  {   0x000a0003, "ct, Continuity test" },
  {   0x000a0004, "ct, Continuity respond" },
  {   0x00210000, "GB Generic Bearer Connection Q.1950 Annex A" },
  {   0x00210001, "GB/EstBNC(Establish BNC)" },
  {   0x00210002, "GB/ModBNC (Modify BNC)" },
  {   0x00210003, "GB/RelBNC(Release BNC)" },

  {   0x002a0001, "H.245/cs (channel state)" },
  {   0x002a0002, "H.245/termtype (Terminal Type)" },

  {   0x002c0001, "H.324/cmod (Communication mode)" },
  {   0x002c0002, "H.324/muxlv (Highest Multiplexing level)" },
  {   0x002c0003, "H.324/demux (Demultiplex)" },
  {   0x002c0004, "H.324/h223capr (Remote H.223 capability)" },
  {   0x002c0005, "H.324/muxtbl_in (Incoming Multiplex Table)" },
  {   0x002c0006, "H.324/muxtbl_out (Outgoing Multiplex Table)" },

  {   0x800a0000, "Nokia Bearer Characteristics Package" },
  {0,     NULL}
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

static const value_string wildcard_modes[] = {
    { 0, "All" },
    { 1, "Choose" },
    { 0, NULL }
};

static const value_string wildcard_levels[] = {
    { 0, "This One Level" },
    { 1, "This Level and those below" },
    { 0, NULL }
};


static const value_string cmd_type[] = {
    { H248_CMD_NONE, "NoCommand"},
    { H248_CMD_ADD_REQ, "addReq"},
    { H248_CMD_MOVE_REQ, "moveReq"},
    { H248_CMD_MOD_REQ, "modReq"},
    { H248_CMD_SUB_REQ, "subReq"},
    { H248_CMD_AUDITCAP_REQ, "auditCapReq"},
    { H248_CMD_AUDITVAL_REQ, "auditValReq"},
    { H248_CMD_NOTIFY_REQ, "notifyReq"},
    { H248_CMD_SVCCHG_REQ, "svcChgReq"},
    { H248_CMD_TOPOLOGY_REQ, "topologyReq"},
    { H248_CMD_CTX_ATTR_AUDIT_REQ, "ctxAttrAuditReq"},
    { H248_CMD_ADD_REPLY, "addReply"},
    { H248_CMD_MOVE_REPLY, "moveReply"},
    { H248_CMD_MOD_REPLY, "modReply"},
    { H248_CMD_SUB_REPLY, "subReply"},
    { H248_CMD_AUDITCAP_REPLY, "auditCapReply"},
    { H248_CMD_AUDITVAL_REPLY, "auditValReply"},
    { H248_CMD_NOTIFY_REPLY, "notifyReply"},
    { H248_CMD_SVCCHG_REPLY, "svcChgReply"},
    { H248_CMD_TOPOLOGY_REPLY, "topologyReply"},
    { 0, NULL }
};

h248_curr_info_t curr_info = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
static guint32 error_code;
static h248_wildcard_t wild_term;


extern void h248_param_ber_integer(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* u _U_, void* implicit) {
	dissect_ber_integer(implicit ? *((gboolean*)implicit) : FALSE, pinfo, tree, tvb, 0, hfid, NULL);
}

extern void h248_param_ber_octetstring(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* u _U_, void* implicit) {
	dissect_ber_octet_string(implicit ? *((gboolean*)implicit) : FALSE, pinfo, tree, tvb, 0, hfid, NULL);
}

extern void h248_param_ber_boolean(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* u _U_, void* implicit) {
	dissect_ber_boolean(implicit ? *((gboolean*)implicit) : FALSE, pinfo, tree, tvb, 0, hfid);
}

extern void h248_param_item(proto_tree* tree,
							 tvbuff_t* tvb,
							 packet_info* pinfo _U_,
							 int hfid,
							 h248_curr_info_t* h248_info _U_,
							 void* lenp ) {
	int len = lenp ? *((int*)lenp) : -1;
	proto_tree_add_item(tree,hfid,tvb,0,len,FALSE);
}

extern void h248_param_external_dissector(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo , int hfid _U_, h248_curr_info_t* u _U_, void* dissector_hdl) {
	call_dissector((dissector_handle_t) dissector_hdl,tvb,pinfo,tree);
}


static h248_package_t no_package = { 0xffff, &hf_h248_no_pkg, &hf_248_no_pkg_param, &ett_h248_no_pkg, NULL, NULL, NULL, NULL };
static h248_pkg_sig_t no_signal = { 0, &hf_h248_no_sig, &ett_h248_no_sig, NULL };
static h248_pkg_param_t no_param = { 0, &hf_h248_no_param, h248_param_item,  NULL };
static h248_pkg_evt_t no_event = { 0, &hf_h248_no_evt, &ett_h248_no_evt, NULL };

static int dissect_h248_trx_id(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint32* trx_id_p) {
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

            *trx_id_p = 0;

		} else {
			proto_tree_add_uint(tree, hf_h248_transactionId, tvb, offset-len, len, (guint32)trx_id);
            *trx_id_p = (guint32)trx_id;
		}
	}

    return offset;
}

static int dissect_h248_ctx_id(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint32* ctx_id_p) {
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

            *ctx_id_p = 0xfffffffd;

		} else {
			proto_item* pi = proto_tree_add_uint(tree, hf_h248_context_id, tvb, offset-len, len, (guint32)ctx_id);

            if ( ctx_id ==  NULL_CONTEXT ) {
                proto_item_set_text(pi,"contextId: Null Context(0)");
            } else if ( ctx_id ==  CHOOSE_CONTEXT ) {
                proto_item_set_text(pi,"contextId: $ (Choose Context = 0xfffffffe)");
            } else if ( ctx_id ==  ALL_CONTEXTS ) {
                proto_item_set_text(pi,"contextId: * (All Contexts = 0xffffffff)");
            }

            *ctx_id_p = (guint32) ctx_id;
		}
	}

	return offset;
}



static const value_string BNCChar_vals[] = {
  {   H248_TERM_TYPE_AAL1, "aal1" },
  {   H248_TERM_TYPE_AAL2, "aal2" },
  {   H248_TERM_TYPE_AAL1_STRUCT, "aal1struct" },
  {   H248_TERM_TYPE_IP_RTP, "ipRtp" },
  {   H248_TERM_TYPE_TDM, "tdm" },
  { 0, NULL }
};



static GPtrArray* packages = NULL;

void h248_register_package(h248_package_t* pkg) {
	if (! packages) packages = g_ptr_array_new();

	g_assert(pkg != NULL);

	g_ptr_array_add(packages,pkg);
}

#if 0
static void
dissect_h248_pkg_data(gboolean implicit_tag, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,guint16 name_major, guint16 name_minor){

guint offset=0;

	switch ( name_major ){
		case 0x001e: /* Bearer Characteristics Q.1950 Annex A */
        {
            guint bearer_type = 0;
			offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_h248_pkg_bcp_BNCChar_PDU, &bearer_type);
            if ( bearer_type && curr_info.term )
                curr_info.term->type = bearer_type;
			break;
        }
	}

}

#endif

static guint32 packageandid;

static int dissect_h248_PkgdName(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  tvbuff_t *new_tvb = NULL;
  proto_tree *package_tree=NULL;
  guint16 name_major, name_minor;
  int old_offset;
  int hf_param;
  h248_package_t* pkg = NULL;
  guint i;

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
		proto_tree_add_uint(package_tree, hf_h248_pkg_name, tvb, offset-4, 2, name_major);
    }

	for(i=0; i < packages->len; i++) {
		pkg = g_ptr_array_index(packages,i);

		if (name_major == pkg->id) {
			break;
		} else {
			pkg = NULL;
		}
	}

	if (! pkg ) pkg = &no_package;

	hf_param = *(pkg->hfid_params);

	if (hf_param > 0)
		/* TODO: Will this ever happen now??*/
		proto_tree_add_uint(package_tree, hf_param, tvb, offset-2, 2, name_minor);

  } else {
	  pkg = &no_package;
  }

  curr_info.pkg = pkg;

  return offset;
}


static int
dissect_h248_EventName(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  tvbuff_t *new_tvb;
  proto_tree *package_tree=NULL;
  guint16 name_major, name_minor;
  int old_offset;
  h248_package_t* pkg = NULL;
  h248_pkg_evt_t* evt = NULL;
  guint i;

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


	for(i=0; i < packages->len; i++) {
		pkg = g_ptr_array_index(packages,i);

		if (name_major == pkg->id) {
			break;
		}
	}

	if (!pkg->hfid) pkg = &no_package;

	curr_info.pkg = pkg;

	if (pkg->events) {
		for (evt = pkg->events; evt->hfid; evt++) {
			if (name_minor == evt->id) {
				break;
			}
		}

		if (! evt->hfid) evt = &no_event;
	} else {
		evt = &no_event;
	}

	curr_info.evt = evt;

  } else {
	  curr_info.pkg = &no_package;
	  curr_info.evt = &no_event;
  }

  return offset;
}



static int
dissect_h248_SignalName(gboolean implicit_tag , tvbuff_t *tvb, int offset, packet_info *pinfo , proto_tree *tree, int hf_index) {
  tvbuff_t *new_tvb;
  proto_tree *package_tree=NULL;
  guint16 name_major, name_minor;
  int old_offset;
  h248_package_t* pkg = NULL;
  h248_pkg_sig_t* sig;
  guint i;

  old_offset=offset;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index, &new_tvb);

  if (new_tvb) {
    /* this field is always 4 bytes so just read it into two integers */
    name_major=tvb_get_ntohs(new_tvb, 0);
    name_minor=tvb_get_ntohs(new_tvb, 2);
    packageandid=(name_major<<16)|name_minor;

    /* do the prettification */
    proto_item_append_text(ber_last_created_item, "  %s (%04x)", val_to_str(name_major, package_name_vals, "Unknown Package"), name_major);
    if(tree){
      package_tree = proto_item_add_subtree(ber_last_created_item, ett_packagename);
    }
    proto_tree_add_uint(package_tree, hf_h248_signal_name, tvb, offset-4, 4, packageandid);

    for(i=0; i < packages->len; i++) {
		pkg = g_ptr_array_index(packages,i);

		if (name_major == pkg->id) {
			break;
		} else {
			pkg = NULL;
		}
	}

	if (! pkg ) pkg = &no_package;

	if (pkg->signals) {
		for (sig = pkg->signals; sig->hfid; sig++) {
			if (name_minor == sig->id) {
				break;
			}
		}

		if (! sig->hfid) sig = &no_signal;

		curr_info.pkg = pkg;
		curr_info.sig = sig;
	} else {
		curr_info.pkg = &no_package;
		curr_info.sig = &no_signal;
	}

  } else {
	  curr_info.pkg = &no_package;
	  curr_info.sig = &no_signal;
  }

  return offset;
}

static int
dissect_h248_PropertyID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_) {

	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	guint16 name_major;
	guint16 name_minor;
	int old_offset, end_offset;
	tvbuff_t *next_tvb;
	h248_package_t* pkg;
	h248_pkg_param_t* prop;

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

	pkg = (curr_info.pkg) ? curr_info.pkg : &no_package;

	if (pkg->properties) {
		for (prop = pkg->properties; prop && prop->hfid; prop++) {
			if (name_minor == prop->id) {
				break;
			}
		}
	} else {
		prop = &no_param;
	}

	if (prop && prop->hfid && prop->data) {
		if (!prop->dissector) prop = &no_param;
		prop->dissector(tree, next_tvb, pinfo, *(prop->hfid), &curr_info, prop->data);
	}

	return end_offset;
}


static int
dissect_h248_SigParameterName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
	tvbuff_t *next_tvb;
	guint32 param_id = 0xffffffff;
	h248_pkg_param_t* sigpar;

	offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset,  hf_index, &next_tvb);
	switch(tvb_length(next_tvb)) {
		case 4: param_id = tvb_get_ntohl(next_tvb,0); break;
		case 3: param_id = tvb_get_ntoh24(next_tvb,0); break;
		case 2: param_id = tvb_get_ntohs(next_tvb,0); break;
		case 1: param_id = tvb_get_guint8(next_tvb,0); break;
		default: break;
	}

	curr_info.par = &no_param;

	if (curr_info.sig && curr_info.sig->parameters) {
		for(sigpar = curr_info.sig->parameters; sigpar->hfid; sigpar++) {
			if (sigpar->id == param_id) {
				curr_info.par = sigpar;
				break;
			}
		}
	}

	return offset;
}

static int
dissect_h248_SigParamValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
	tvbuff_t *next_tvb;
	int old_offset, end_offset;
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;

	old_offset=offset;
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
	end_offset=offset+len;

	if( (class!=BER_CLASS_UNI)
		||(tag!=BER_UNI_TAG_OCTETSTRING) ){
		proto_tree_add_text(tree, tvb, offset-2, 2, "H.248 BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}


	next_tvb = tvb_new_subset(tvb,offset,len,len);

	if ( curr_info.par && curr_info.par->dissector) {
		curr_info.par->dissector(tree, next_tvb, pinfo, *(curr_info.par->hfid), &curr_info, curr_info.par->data);
	}

	return end_offset;
}

static int
dissect_h248_EventParameterName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
	tvbuff_t *next_tvb;
	guint32 param_id = 0xffffffff;
	h248_pkg_param_t* evtpar;

	offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index, &next_tvb);

	if (next_tvb) {
		switch(tvb_length(next_tvb)) {
			case 4: param_id = tvb_get_ntohl(next_tvb,0); break;
			case 3: param_id = tvb_get_ntoh24(next_tvb,0); break;
			case 2: param_id = tvb_get_ntohs(next_tvb,0); break;
			case 1: param_id = tvb_get_guint8(next_tvb,0); break;
			default: break;
		}
	}

	curr_info.par = &no_param;

	if (curr_info.evt->parameters) {
		for(evtpar = curr_info.evt->parameters; evtpar->hfid; evtpar++) {
			if (evtpar->id == param_id) {
				curr_info.par = evtpar;
				break;
			}
		}
	} else {
		curr_info.par = &no_param;
	}

	return offset;
}

static int
dissect_h248_EventParamValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
	tvbuff_t *next_tvb;
	int old_offset, end_offset;
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;

	old_offset=offset;
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
	end_offset=offset+len;

	if( (class!=BER_CLASS_UNI)
		||(tag!=BER_UNI_TAG_OCTETSTRING) ){
		proto_tree_add_text(tree, tvb, offset-2, 2, "H.248 BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", class, pc, tag);
		return end_offset;
	}


	next_tvb = tvb_new_subset(tvb,offset,len,len);

	if ( curr_info.par && curr_info.par->dissector) {
		curr_info.par->dissector(tree, next_tvb, pinfo, *(curr_info.par->hfid), &curr_info, curr_info.par->data);
	}

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

/*
 *   Context and Transaction Tracing
 */



static h248_msg_t* h248_msg(packet_info* pinfo, int o) {
    h248_msg_t* m;
    guint32 framenum = (guint32)pinfo->fd->num;
	guint32 offset = (guint32)o;
	address* src = &(pinfo->src);
	address* dst = &(pinfo->dst);
	address* lo_addr;
	address* hi_addr;


    if (keep_persistent_data) {
		emem_tree_key_t key[] = {
			{1,&(framenum)},
			{1,&offset},
			{0,NULL},
		};

        if (( m = se_tree_lookup32_array(msgs,key) )) {
            m->commited = TRUE;
			return m;
        } else {
            m = se_alloc(sizeof(h248_msg_t));
            m->framenum = framenum;
            m->trxs = NULL;
            m->commited = FALSE;

            se_tree_insert32_array(msgs,key,m);
        }
    } else {
        m = ep_new0(h248_msg_t);
        m->framenum = framenum;
        m->trxs = NULL;
        m->commited = FALSE;
    }

	if (CMP_ADDRESS(src, dst) < 0)  {
		lo_addr = src;
		hi_addr = dst;
	} else {
		lo_addr = dst;
		hi_addr = src;
	}

	switch(lo_addr->type) {
		case AT_NONE:
			m->lo_addr = 0;
			m->hi_addr = 0;
			break;
		case AT_IPv4:
			memcpy((guint8*)&(m->hi_addr),hi_addr->data,4);
			memcpy((guint8*)&(m->lo_addr),lo_addr->data,4);
			break;
		case AT_SS7PC:
			m->hi_addr = mtp3_pc_hash(hi_addr->data);
			m->lo_addr = mtp3_pc_hash(lo_addr->data);
			break;
		default:
			/* XXX: heuristic and error prone */
			m->hi_addr = g_str_hash(address_to_str(hi_addr));
			m->lo_addr = g_str_hash(address_to_str(lo_addr));
			break;
	}

    return m;
}

static h248_trx_t* h248_trx(h248_msg_t* m ,guint32 t_id , h248_trx_type_t type) {
    h248_trx_t* t = NULL;
    h248_trx_msg_t* trxmsg;

    if ( !m ) return NULL;

    if (keep_persistent_data) {
        if (m->commited) {

            for ( trxmsg = m->trxs; trxmsg; trxmsg = trxmsg->next) {
                if (trxmsg->trx && trxmsg->trx->id == t_id) {
                    return trxmsg->trx;
                }
            }

            DISSECTOR_ASSERT(! "a trx that should exist does not!" );

        } else {
			emem_tree_key_t key[] = {
				{1,&(m->hi_addr)},
				{1,&(m->lo_addr)},
				{1,&(t_id)},
				{0,NULL}
			};

            trxmsg = se_alloc(sizeof(h248_trx_msg_t));
            t = se_tree_lookup32_array(trxs,key);

            if (!t) {
                t = se_alloc(sizeof(h248_trx_t));
                t->initial = m;
                t->id = t_id;
                t->type = type;
                t->pendings = 0;
                t->error = 0;
                t->cmds = NULL;

                se_tree_insert32_array(trxs,key,t);
            }

            /* XXX: request, reply and ack + point to frames where they are */
            switch ( type ) {
                case H248_TRX_PENDING:
                    t->pendings++;
                    break;
                default:
                    break;
            }

        }
    } else {
        t = ep_new(h248_trx_t);
        trxmsg = ep_new(h248_trx_msg_t);
        t->initial = NULL;
        t->id = t_id;
        t->type = type;
        t->pendings = 0;
        t->error = 0;
        t->cmds = NULL;
    }

    trxmsg->trx = t;
    trxmsg->next = NULL;
    trxmsg->last = trxmsg;

    if (m->trxs) {
        m->trxs->last = m->trxs->last->next = trxmsg;
    } else {
        m->trxs = trxmsg;
    }

    return t;
}


static h248_ctx_t* h248_ctx(h248_msg_t* m, h248_trx_t* t, guint32 c_id) {
    h248_ctx_t* context = NULL;
    h248_ctx_t** context_p = NULL;

    if ( !m || !t ) return NULL;

    if (keep_persistent_data) {
		emem_tree_key_t ctx_key[] = {
		{1,&(m->hi_addr)},
		{1,&(m->lo_addr)},
		{1,&(c_id)},
		{0,NULL}
		};

		emem_tree_key_t trx_key[] = {
		{1,&(m->hi_addr)},
		{1,&(m->lo_addr)},
		{1,&(t->id)},
		{0,NULL}
		};

        if (m->commited) {
            if (( context = se_tree_lookup32_array(ctxs_by_trx,trx_key) )) {
                return context;
            } if ((context_p = se_tree_lookup32_array(ctxs,ctx_key))) {
                context = *context_p;

                do {
                    if (context->initial->framenum <= m->framenum) {
                        return context;
                    }
                } while(( context = context->prev ));

                DISSECTOR_ASSERT(! "a context should exist");
            }
        } else {
            if (c_id == CHOOSE_CONTEXT) {
                if (! ( context = se_tree_lookup32_array(ctxs_by_trx,trx_key))) {
                    context = se_alloc(sizeof(h248_ctx_t));
                    context->initial = m;
                    context->cmds = NULL;
                    context->id = c_id;
                    context->terms.last = &(context->terms);
                    context->terms.next = NULL;
                    context->terms.term = NULL;

                    se_tree_insert32_array(ctxs_by_trx,trx_key,context);
                }
            } else {
                if (( context = se_tree_lookup32_array(ctxs_by_trx,trx_key) )) {
                    if (( context_p = se_tree_lookup32_array(ctxs,ctx_key) )) {
                        if (context != *context_p) {
                            context = se_alloc(sizeof(h248_ctx_t));
                            context->initial = m;
                            context->id = c_id;
                            context->cmds = NULL;
                            context->terms.last = &(context->terms);
                            context->terms.next = NULL;
                            context->terms.term = NULL;

                            context->prev = *context_p;
                            *context_p = context;
                        }
                    } else {
                        context_p = se_alloc(sizeof(void*));
                        *context_p = context;
                        context->initial = m;
                        context->id = c_id;
                        se_tree_insert32_array(ctxs,ctx_key,context_p);
                    }
                } else if (! ( context_p = se_tree_lookup32_array(ctxs,ctx_key) )) {
                    context = se_alloc(sizeof(h248_ctx_t));
                    context->initial = m;
                    context->id = c_id;
                    context->cmds = NULL;
                    context->terms.last = &(context->terms);
                    context->terms.next = NULL;
                    context->terms.term = NULL;

                    context_p = se_alloc(sizeof(void*));
                    *context_p = context;
                    se_tree_insert32_array(ctxs,ctx_key,context_p);
                } else {
                    context = *context_p;
                }
            }
        }
    } else {
        context = ep_new(h248_ctx_t);
        context->initial = m;
        context->cmds = NULL;
        context->id = c_id;
        context->terms.last = &(context->terms);
        context->terms.next = NULL;
        context->terms.term = NULL;
    }

    return context;
}

static h248_cmd_t* h248_cmd(h248_msg_t* m, h248_trx_t* t, h248_ctx_t* c, h248_cmd_type_t type, guint offset) {
    h248_cmd_t* cmd;
    h248_cmd_msg_t* cmdtrx;
    h248_cmd_msg_t* cmdctx;

    if ( !m || !t || !c) return NULL;

    if (keep_persistent_data) {
        if (m->commited) {
            DISSECTOR_ASSERT(t->cmds != NULL);

            for (cmdctx = t->cmds; cmdctx; cmdctx = cmdctx->next) {
                cmd = cmdctx->cmd;
                if (cmd->msg == m && cmd->offset == offset) {
                    return cmd;
                }
            }

            DISSECTOR_ASSERT(!"called for a command that does not exist!");

            return NULL;
        } else {
            cmd = se_alloc(sizeof(h248_cmd_t));
            cmdtrx = se_alloc(sizeof(h248_cmd_msg_t));
            cmdctx = se_alloc(sizeof(h248_cmd_msg_t));
        }
    } else {
        cmd = ep_new(h248_cmd_t);
        cmdtrx = ep_new(h248_cmd_msg_t);
        cmdctx = ep_new(h248_cmd_msg_t);
    }

    cmd->type = type;
    cmd->offset = offset;
    cmd->terms.term = NULL;
    cmd->terms.next = NULL;
    cmd->terms.last = &(cmd->terms);
    cmd->msg = m;
    cmd->trx = t;
    cmd->ctx = c;
    cmd->error = 0;

    cmdctx->cmd = cmdtrx->cmd = cmd;
    cmdctx->next =  cmdtrx->next = NULL;
    cmdctx->last = cmdtrx->last = NULL;

    if (t->cmds) {
        t->cmds->last->next = cmdtrx;
        t->cmds->last = cmdtrx;
    } else {
        t->cmds = cmdtrx;
        t->cmds->last = cmdtrx;
    }

    if (c->cmds) {
        c->cmds->last->next = cmdctx;
        c->cmds->last = cmdctx;
    } else {
        c->cmds = cmdctx;
        c->cmds->last = cmdctx;
    }

    return cmd;
}


static h248_term_t* h248_cmd_add_term(h248_msg_t* m, h248_trx_t* tr, h248_cmd_t* c, h248_term_t* t, h248_wildcard_t wildcard) {
    h248_terms_t* ct;
    h248_terms_t* ct2;

    static h248_term_t all_terms = {"$",(guint8*)"",1,H248_TERM_TYPE_UNKNOWN,NULL,NULL,NULL};

    if ( !c ) return NULL;

    if ( wildcard == H248_WILDCARD_CHOOSE) {
        return &all_terms;
    }

    if (keep_persistent_data) {
        if ( c->msg->commited ) {
            if (wildcard == H248_WILDCARD_ALL) {
                for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                    /* XXX not handling more wilcards in one msg */
                    if ( ct->term->start == m ) {
                        return ct->term;
                    }
                }
                return NULL;
            } else {
                for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                    if ( g_str_equal(ct->term->str,t->str) ) {
                        return ct->term;
                    }
                }
                return NULL;
            }
        } else {

            for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                if ( g_str_equal(ct->term->str,t->str) || ct->term->start == m) {
                    break;
                }
            }

            if ( ! ct ) {

                if (wildcard == H248_WILDCARD_ALL) {
                    ct = se_alloc(sizeof(h248_terms_t));
                    ct->next = NULL;
                    ct->term = se_alloc0(sizeof(h248_term_t));

                    ct->term->start = m;
                    ct->term->str = "*";
                    ct->term->buffer = NULL;
                    ct->term->len = 0;

                    c->terms.last = c->terms.last->next = ct;

                    ct2 = se_alloc0(sizeof(h248_terms_t));
                    ct2->term = ct->term;

                    c->ctx->terms.last->next = ct2;
                    c->ctx->terms.last = ct2;

                    return ct->term;
                } else {
                    for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                        /* XXX not handling more wilcards in one msg */
                        if ( ct->term->buffer == NULL && tr->cmds->cmd->msg == ct->term->start ) {
                            ct->term->str = se_strdup(t->str);
                            ct->term->buffer = se_memdup(t->buffer,t->len);
                            ct->term->len = t->len;

                            ct2 = se_alloc0(sizeof(h248_terms_t));
                            ct2->term = ct->term;

                            c->terms.last = c->terms.last->next = ct2;

                            return ct->term;
                        }

                        if  ( g_str_equal(ct->term->str,t->str) ) {
                            ct2 = se_alloc0(sizeof(h248_terms_t));
                            ct2->term = ct->term;

                            c->terms.last = c->terms.last->next = ct2;

                            return ct->term;
                        }
                    }

                    ct = se_alloc(sizeof(h248_terms_t));
                    ct->next = NULL;
                    ct->term = se_alloc0(sizeof(h248_term_t));

                    ct->term->start = m;
                    ct->term->str = se_strdup(t->str);
                    ct->term->buffer = se_memdup(t->buffer,t->len);
                    ct->term->len = t->len;

                    ct2 = se_alloc0(sizeof(h248_terms_t));
                    ct2->term = ct->term;

                    c->terms.last = c->terms.last->next = ct2;

                    ct2 = se_alloc0(sizeof(h248_terms_t));
                    ct2->term = ct->term;

                    c->ctx->terms.last = c->ctx->terms.last->next = ct2;

                    return ct->term;
                }
            } else {
                ct2 = se_alloc0(sizeof(h248_terms_t));
                ct2->term = ct->term;

                c->terms.last = c->terms.last->next = ct2;
                return ct->term;
            }

            DISSECTOR_ASSERT_NOT_REACHED();
            return NULL;
        }
    } else {
        ct = ep_new(h248_terms_t);
        ct->term = t;
        ct->next = NULL;
        c->terms.last = c->terms.last->next = ct;

        return t;
    }

}

static gchar* h248_cmd_to_str(h248_cmd_t* c) {
    gchar* s = "-";
    h248_terms_t* term;

    if ( !c ) return "-";

    switch (c->type) {
        case H248_CMD_NONE:
            return "-";
            break;
        case H248_CMD_ADD_REQ:
            s = "AddReq {";
            break;
        case H248_CMD_MOVE_REQ:
            s = "MoveReq {";
            break;
        case H248_CMD_MOD_REQ:
            s = "ModReq {";
            break;
        case H248_CMD_SUB_REQ:
            s = "SubReq {";
            break;
        case H248_CMD_AUDITCAP_REQ:
            s = "AuditCapReq {";
            break;
        case H248_CMD_AUDITVAL_REQ:
            s = "AuditValReq {";
            break;
        case H248_CMD_NOTIFY_REQ:
            s = "NotifyReq {";
            break;
        case H248_CMD_SVCCHG_REQ:
            s = "SvcChgReq {";
            break;
        case H248_CMD_TOPOLOGY_REQ:
            s = "TopologyReq {";
            break;
        case H248_CMD_CTX_ATTR_AUDIT_REQ:
            s = "CtxAttribAuditReq {";
            break;
        case H248_CMD_ADD_REPLY:
            s = "AddReply {";
            break;
        case H248_CMD_MOVE_REPLY:
            s = "MoveReply {";
            break;
        case H248_CMD_MOD_REPLY:
            s = "ModReply {";
            break;
        case H248_CMD_SUB_REPLY:
            s = "SubReply {";
            break;
        case H248_CMD_AUDITCAP_REPLY:
            s = "AuditCapReply {";
            break;
        case H248_CMD_AUDITVAL_REPLY:
            s = "AuditValReply {";
            break;
        case H248_CMD_NOTIFY_REPLY:
            s = "NotifyReply {";
            break;
        case H248_CMD_SVCCHG_REPLY:
            s = "SvcChgReply {";
            break;
        case H248_CMD_TOPOLOGY_REPLY:
            s = "TopologyReply {";
            break;
        case H248_CMD_REPLY:
            s = "ActionReply {";
            break;
    }

    for (term = c->terms.next; term; term = term->next) {
        s = ep_strdup_printf("%s %s",s,term->term->str);
    };

    if (c->error) {
        s = ep_strdup_printf("%s Error=%i",s,c->error);
    }


    return ep_strdup_printf("%s }", s);
}

static gchar* h248_trx_to_str(h248_msg_t* m, h248_trx_t* t) {
    gchar* s;
    h248_cmd_msg_t* c;

    if ( !m || !t ) return "-";

	s = ep_strdup_printf("T %x { ",t->id);

    if (t->cmds) {
        if (t->cmds->cmd->ctx) {
            s = ep_strdup_printf("%s C %x {",s,t->cmds->cmd->ctx->id);

            for (c = t->cmds; c; c = c->next) {
                if (c->cmd->msg == m)
                    s = ep_strdup_printf("%s %s",s,h248_cmd_to_str(c->cmd));
            }

            s = ep_strdup_printf("%s %s",s,"}");
        }
    }

    if (t->error) {
        s = ep_strdup_printf("%s Error=%i",s,t->error);
    }

    return ep_strdup_printf("%s %s",s,"}");
}

static gchar* h248_msg_to_str(h248_msg_t* m) {
    h248_trx_msg_t* t;
    gchar* s = "";

    if ( !m ) return "-";

    for (t = m->trxs; t; t = t->next) {
        s = ep_strdup_printf("%s %s",s,h248_trx_to_str(m,t->trx));
    };

    return s;
}

typedef struct _h248_ctxs_t {
    struct _h248_ctx_t* ctx;
    struct _h248_ctxs_t* next;
} h248_ctxs_t;

/*static const gchar* trx_types[] = {"None","Req","Reply","Pending","Ack"};*/

static void analyze_h248_msg(h248_msg_t* m) {
    h248_trx_msg_t* t;
    h248_ctxs_t contexts = {NULL,NULL};
    h248_ctxs_t* ctx_node;
    h248_cmd_msg_t* c;


    for (t = m->trxs; t; t = t->next) {
        for (c = t->trx->cmds; c; c = c->next) {
            h248_ctx_t* ctx = c->cmd->ctx;

            for (ctx_node = contexts.next; ctx_node; ctx_node = ctx_node->next) {
                if (ctx_node->ctx->id == ctx->id) {
                    break;
                }
            }

            if (! ctx_node) {
                ctx_node = ep_new(h248_ctxs_t);
                ctx_node->ctx = ctx;
                ctx_node->next = contexts.next;
                contexts.next = ctx_node;
            }

        }
    }

    for (ctx_node = contexts.next; ctx_node; ctx_node = ctx_node->next) {
        h248_ctx_t* ctx = ctx_node->ctx;
        proto_item* ctx_item = proto_tree_add_uint(h248_tree,hf_h248_ctx,h248_tvb,0,0,ctx->id);
        proto_tree* ctx_tree = proto_item_add_subtree(ctx_item,ett_ctx);
        h248_terms_t *ctx_term;

        PROTO_ITEM_SET_GENERATED(ctx_item);

        if (( c = ctx->cmds )) {
            proto_item* history_item = proto_tree_add_text(ctx_tree,h248_tvb,0,0,"[ Command History ]");
            proto_tree* history_tree = proto_item_add_subtree(history_item,ett_ctx_cmds);

            for (c = ctx->cmds; c; c = c->next) {
                proto_item* cmd_item = proto_tree_add_uint(history_tree,hf_h248_ctx_cmd,h248_tvb,0,0,c->cmd->msg->framenum);
                proto_item_set_text(cmd_item,"%s",h248_cmd_to_str(c->cmd) );
                PROTO_ITEM_SET_GENERATED(cmd_item);
                if (c->cmd->error) {
                    proto_item_set_expert_flags(cmd_item, PI_RESPONSE_CODE, PI_WARN);
                }
            }
        }

        if (( ctx_term = ctx->terms.next )) {
            proto_item* terms_item = proto_tree_add_text(ctx_tree,h248_tvb,0,0,"[ Terminations Used ]");
            proto_tree* terms_tree = proto_item_add_subtree(terms_item,ett_ctx_terms);

            for (; ctx_term; ctx_term = ctx_term->next ) {
                if ( ctx_term->term && ctx_term->term->str) {
                    proto_item* pi = proto_tree_add_string(terms_tree,hf_h248_ctx_term,h248_tvb,0,0,ctx_term->term->str);
                    proto_tree* term_tree = proto_item_add_subtree(pi,ett_ctx_term);

                    PROTO_ITEM_SET_GENERATED(pi);

                    if (ctx_term->term->type) {
                        pi = proto_tree_add_uint(term_tree,hf_h248_ctx_term_type,h248_tvb,0,0,ctx_term->term->type);
                        PROTO_ITEM_SET_GENERATED(pi);
                    }

                    if (ctx_term->term->bir) {
                        pi = proto_tree_add_string(term_tree,hf_h248_ctx_term_bir,h248_tvb,0,0,ctx_term->term->bir);
                        PROTO_ITEM_SET_GENERATED(pi);
                    }

                    if (ctx_term->term->nsap) {
                        pi = proto_tree_add_string(term_tree,hf_h248_ctx_term_nsap,h248_tvb,0,0,ctx_term->term->nsap);
                        PROTO_ITEM_SET_GENERATED(pi);
                    }

                    if (ctx_term->term->bir && ctx_term->term->nsap) {
                        gchar* key = ep_strdup_printf("%s:%s",ctx_term->term->nsap,ctx_term->term->bir);
                        g_strdown(key);
                        alcap_tree_from_bearer_key(term_tree, h248_tvb, key);
                    }
                }
            }
        }
    }
}

#define h248_cmd_set_error(c,e) (c->error = e)
#define h248_trx_set_error(t,e) (t->error = e)

#include "packet-h248-fn.c"

static void
dissect_h248(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *h248_item;

    h248_tree = NULL;
    h248_tvb = NULL;

    curr_info.msg = NULL;
    curr_info.trx = NULL;
    curr_info.ctx = NULL;
    curr_info.cmd = NULL;
    curr_info.term = NULL;
    curr_info.pkg = NULL;
    curr_info.evt = NULL;
    curr_info.sig = NULL;
    curr_info.stat = NULL;
    curr_info.par = NULL;

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

    if (!h248_prefs_initialized) {
		h248_prefs_initialized = TRUE;
    } else {
        if ( udp_port )
            dissector_delete("udp.port", udp_port, h248_handle);
	}

    udp_port = temp_udp_port;

    if ( udp_port ) {
		dissector_add("udp.port", udp_port, h248_handle);
	}

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
    { &hf_h248_pkg_name, {
      "Package", "h248.package_name", FT_UINT16, BASE_HEX,
      VALS(package_name_vals), 0, "Package", HFILL }},
    { &hf_248_no_pkg_param, {
      "Parameter ID", "h248.package_paramid", FT_UINT16, BASE_HEX,
      NULL, 0, "Unknown Package Parameter ID", HFILL }},
    { &hf_h248_event_name, {
      "Package and Event name", "h248.event_name", FT_UINT32, BASE_HEX,
      VALS(event_name_vals), 0, "Package", HFILL }},
  { &hf_h248_signal_name, {
      "Package and Signal name", "h248.signal_name", FT_UINT32, BASE_HEX,
      VALS(signal_name_vals), 0, "Package", HFILL }},
	{ &hf_h248_pkg_bcp_BNCChar_PDU,
      { "BNCChar", "h248.package_bcp.BNCChar",
        FT_UINT32, BASE_DEC, VALS(BNCChar_vals), 0,
        "BNCChar", HFILL }},

  { &hf_h248_error_code,
  { "errorCode", "h248.errorCode",
      FT_UINT32, BASE_DEC, VALS(h248_reasons), 0,
      "ErrorDescriptor/errorCode", HFILL }},
  { &hf_h248_context_id,
  { "contextId", "h248.contextId",
      FT_UINT32, BASE_HEX, NULL, 0,
      "Context ID", HFILL }},
  { &hf_h248_term_wild_type,
  { "Wildcard Mode", "h248.term.wildcard.mode",
      FT_UINT8, BASE_DEC, VALS(wildcard_modes), 0x80,
      "", HFILL }},
  { &hf_h248_term_wild_level,
  { "Wildcarding Level", "h248.term.wildcard.level",
      FT_UINT8, BASE_DEC, VALS(wildcard_levels), 0x40,
      "", HFILL }},
  { &hf_h248_term_wild_position,
  { "Wildcarding Position", "h248.term.wildcard.pos",
      FT_UINT8, BASE_DEC, NULL, 0x3F,
      "", HFILL }},

  { &hf_h248_no_pkg,
  { "Unknown Package", "h248.pkg.unknown",
	  FT_BYTES, BASE_HEX, NULL, 0,
	  "", HFILL }},
  { &hf_h248_no_sig,
  { "Unknown Signal", "h248.pkg.unknown.sig",
	  FT_BYTES, BASE_HEX, NULL, 0,
	  "", HFILL }},
  { &hf_h248_no_evt,
  { "Unknown Event", "h248.pkg.unknown.evt",
	  FT_BYTES, BASE_HEX, NULL, 0,
	  "", HFILL }},
  { &hf_h248_no_param,
  { "Unknown Parameter", "h248.pkg.unknown.param",
	  FT_BYTES, BASE_HEX, NULL, 0,
	  "", HFILL }},
  { &hf_h248_serviceChangeReasonStr,
      { "ServiceChangeReasonStr", "h248.serviceChangeReasonstr",
        FT_STRING, BASE_NONE, NULL, 0,
        "h248.IA5String", HFILL }},

#include "packet-h248-hfarr.c"

  { &hf_h248_ctx, { "Context", "h248.ctx", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_term, { "Termination", "h248.ctx.term", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_term_type, { "Type", "h248.ctx.term.type", FT_UINT32, BASE_HEX, VALS(BNCChar_vals), 0, "", HFILL }},
  { &hf_h248_ctx_term_bir, { "BIR", "h248.ctx.term.bir", FT_STRING, BASE_HEX, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_term_nsap, { "NSAP", "h248.ctx.term.nsap", FT_STRING, BASE_NONE, NULL, 0, "", HFILL }},
  { &hf_h248_ctx_cmd, { "Command", "h248.ctx.cmd", FT_FRAMENUM, BASE_DEC, NULL, 0, "", HFILL }},
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h248,
    &ett_mtpaddress,
    &ett_packagename,
    &ett_codec,
    &ett_wildcard,
    &ett_cmd,
    &ett_ctx,
    &ett_ctx_cmds,
    &ett_ctx_terms,
    &ett_ctx_term,
	  &ett_h248_no_pkg,
	  &ett_h248_no_sig,
	  &ett_h248_no_evt,
#include "packet-h248-ettarr.c"
  };

  module_t *h248_module;


  /* Register protocol */
  proto_h248 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("h248", dissect_h248, proto_h248);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h248, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  h248_module = prefs_register_protocol(proto_h248, h248_init);
  prefs_register_bool_preference(h248_module, "ctx_info",
                                 "Keep Persistent Context Information",
                                 "Whether persistent context information is to be kept",
                                 &keep_persistent_data);
  prefs_register_uint_preference(h248_module, "udp_port",
                                 "UDP port",
                                 "Port to be decoded as h248",
                                 10,
                                 &temp_udp_port);

  register_init_routine( &h248_init );

  msgs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "h248_msgs");
  trxs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "h248_trxs");
  ctxs_by_trx = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "h248_ctxs_by_trx");
  ctxs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "h248_ctxs");

}

/*--- proto_reg_handoff_h248 -------------------------------------------*/
void proto_reg_handoff_h248(void) {

  h248_handle = find_dissector("h248");
  h248_term_handle = find_dissector("h248term");

  dissector_add("mtp3.service_indicator", GATEWAY_CONTROL_PROTOCOL_USER_ID, h248_handle);
  dissector_add("sctp.ppi", H248_PAYLOAD_PROTOCOL_ID, h248_handle);
  dissector_add("udp.port", udp_port, h248_handle);
}

