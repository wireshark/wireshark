/* packet-h248.c
 * Routines for H.248/MEGACO packet dissection
 *
 * Ronnie Sahlberg 2004
 *
 * Luis Ontanon 2005 - Context and Transaction Tracing
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include "packet-h248.h"
#include <epan/tap.h>
#include "packet-tpkt.h"
#include <ctype.h>
#include "packet-mtp3.h"

#define PNAME  "H.248 MEGACO"
#define PSNAME "H248"
#define PFNAME "h248"

/* Initialize the protocol and registered fields */
static int proto_h248                   = -1;
static int hf_248_magic_num             = -1;
static int hf_h248_mtpaddress_ni        = -1;
static int hf_h248_mtpaddress_pc        = -1;
static int hf_h248_pkg_name             = -1;
static int hf_248_pkg_param             = -1;
static int hf_h248_event_name           = -1;
static int hf_h248_signal_name          = -1;
static int hf_h248_signal_code          = -1;
static int hf_h248_event_code           = -1;
static int hf_h248_pkg_bcp_BNCChar_PDU  = -1;



static int hf_h248_context_id = -1;
static int hf_h248_error_code = -1;
static int hf_h248_term_wild_type = -1;
static int hf_h248_term_wild_level = -1;
static int hf_h248_term_wild_position = -1;

static int hf_h248_no_pkg = -1;
static int hf_h248_no_sig = -1;
static int hf_h248_no_evt = -1;
static int hf_h248_param = -1;

static int hf_h248_serviceChangeReasonStr = -1;

/* h248v1 support */
static int hf_h248_auditValueReplyV1 = -1;

#include "packet-h248-hf.c"

/* Initialize the subtree pointers */
static gint ett_h248 = -1;
static gint ett_mtpaddress = -1;
static gint ett_packagename = -1;
static gint ett_codec = -1;
static gint ett_wildcard = -1;

static gint ett_h248_no_pkg = -1;
static gint ett_h248_no_sig = -1;
static gint ett_h248_no_evt = -1;

static int h248_tap = -1;

static gcp_hf_ett_t h248_arrel = {{-1,-1,-1,-1,-1,-1},{-1,-1,-1,-1}};

#include "packet-h248-ett.c"

static dissector_handle_t h248_term_handle;
static dissector_table_t subdissector_table;

static emem_tree_t* msgs = NULL;
static emem_tree_t* trxs = NULL;
static emem_tree_t* ctxs_by_trx = NULL;
static emem_tree_t* ctxs = NULL;

static gboolean keep_persistent_data = FALSE;
static guint    global_udp_port = 2945;
static guint    global_tcp_port = 2945;
static gboolean h248_desegment = TRUE;



static proto_tree *h248_tree;
static tvbuff_t* h248_tvb;

static dissector_handle_t h248_handle;
static dissector_handle_t h248_term_handle;
static dissector_handle_t h248_tpkt_handle;

/* Forward declarations */
static int dissect_h248_ServiceChangeReasonStr(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

/* h248v1 support */
static int dissect_h248_AuditReplyV1(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

static int dissect_h248_EventParameterV1(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
static int dissect_h248_SigParameterV1(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
static int dissect_h248_SigParamValueV1(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
static int dissect_h248_ValueV1(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
#if 0
static const value_string context_id_type[] = {
    {NULL_CONTEXT,"0 (Null Context)"},
    {CHOOSE_CONTEXT,"$ (Choose Context)"},
    {ALL_CONTEXTS,"* (All Contexts)"},
    {0,NULL}
};
#endif

/* the following value_strings are used to build defalut packages.
   To add additional detail to a package, build a register a h248_package_t structure
 */

static const value_string base_package_name_vals[] = {
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
    {   0x000f, "txc H.248.2" },                                          /* H.248.2 */
    {   0x0010, "txp H.248.2" },
    {   0x0011, "ctyp H.248.2" },
    {   0x0012, "fax H.248.2" },
    {   0x0013, "ipfax H.248.2" },
    {   0x0014, "dis H.248.3" },                                          /* H.248.3 */
    {   0x0015, "key H.248.3" },
    {   0x0016, "kp H.248.3" },
    {   0x0017, "labelkey H.248.3" },
    {   0x0018, "kf H.248.3" },
    {   0x0019, "ind H.248.3" },
    {   0x001a, "ks H.248.3" },
    {   0x001b, "anci H.248.3" },
    {   0x001c, "dtd H.248.6" },                                              /* H.248.6 */
    {   0x001d, "an H.248.7" },                                               /* H.248.7 */
    {   0x001e, "Bearer Characteristics Q.1950 Annex A" },                    /* Q.1950 Annex A */
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
    {   0x0029, "Media Gateway Resource Congestion Handling H.248.10" },      /* H.248.10 */
    {   0x002a, "H245 package H248.12" },                                     /* H.248.12 */
    {   0x002b, "H323 bearer control package H.248.12" },                     /* H.248.12 */
    {   0x002c, "H324 package H.248.12" },                                    /* H.248.12 */
    {   0x002d, "H245 command package H.248.12" },                            /* H.248.12 */
    {   0x002e, "H245 indication package H.248.12" },                         /* H.248.12 */
    {   0x002f, "3G User Plane" },                                            /* 3GPP TS 29.232 v4.1.0 */
    {   0x0030, "3G Circuit Switched Data" },
    {   0x0031, "3G TFO Control" },
    {   0x0032, "3G Expanded Call Progress Tones" },
    {   0x0033, "Advanced Audio Server (AAS Base)" },                         /* H.248.9 */
    {   0x0034, "AAS Digit Collection" },                                     /* H.248.9 */
    {   0x0035, "AAS Recording" },                                            /* H.248.9 */
    {   0x0036, "AAS Segment Management" },                                   /* H.248.9 */
    {   0x0037, "Quality Alert Ceasing" },                                    /* H.248.13 */
    {   0x0038, "Conferencing Tones Generation" },                            /* H.248.27 */
    {   0x0039, "Diagnostic Tones Generation" },                              /* H.248.27 */
    {   0x003a, "Carrier Tones Generation Package H.248.23" },                /* H.248.27 */
    {   0x003b, "Enhanced Alerting Package H.248.23" },                       /* H.248.23 */
    {   0x003c, "Analog Display Signalling Package H.248.23" },               /* H.248.23 */
    {   0x003d, "Multi-Frequency Tone Generation Package H.248.24" },         /* H.248.24 */
    {   0x003e, "H.248.23Multi-Frequency Tone Detection Package H.248.24" },  /* H.248.24 */
    {   0x003f, "Basic CAS Package H.248.25" },                               /* H.248.25 */
    {   0x0040, "Robbed Bit Signalling Package H.248.25" },                   /* H.248.25 */
    {   0x0041, "Operator Services and Emergency Services Package H.248.25" },
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
    {   0x0054, "Loopback Line Test Response" },                              /* H.248.17 */
    {   0x0055, "ITU 404Hz Line Test" },                                      /* H.248.17 */
    {   0x0056, "ITU 816Hz Line Test" },                                      /* H.248.17 */
    {   0x0057, "ITU 1020Hz Line Test" },                                     /* H.248.17 */
    {   0x0058, "ITU 2100Hz Disable Tone Line Test" },                        /* H.248.17 */
    {   0x0059, "ITU 2100Hz Disable Echo Canceller Tone Line Test" },         /* H.248.17 */
    {   0x005a, "ITU 2804Hz Tone Line Test" },                                /* H.248.17 */
    {   0x005b, "ITU Noise Test Tone Line Test" },                            /* H.248.17 */
    {   0x005c, "ITU Digital Pseudo Random Test Line Test" },                 /* H.248.17 */
    {   0x005d, "ITU ATME No.2 Test Line Response" },                         /* H.248.17 */
    {   0x005e, "ANSI 1004Hz Test Tone Line Test" },                          /* H.248.17 */
    {   0x005f, "ANSI Test Responder Line Test" },                            /* H.248.17 */
    {   0x0060, "ANSI 2225Hz Test Progress Tone Line Test" },                 /* H.248.17 */
    {   0x0061, "ANSI Digital Test Signal Line Test" },                       /* H.248.17 */
    {   0x0062, "ANSI Inverting Loopback Line Test Response" },               /* H.248.17 */
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
    {   0x0082, "threegcsden 3G Circuit Switched Data" },                     /* 3GPP TS 29.232 v5.6.0 */
    {   0x0083, "threegiptra 3G Circuit Switched Data" },                     /* 3GPP TS 29.232 v5.6.0 */
    {   0x0084, "threegflex 3G Circuit Switched Data" },                      /* 3GPP TS 29.232 v5.6.0 */
    {   0x0085, "H.248 PCMSB" },
    {   0x008a, "TIPHON Extended H.248/MEGACO Package" },                     /* ETSI specification TS 101 3 */
    {   0x008b, "Differentiated Services Package" },                          /* Annex A of ETSI TS 102 333 */
    {   0x008c, "Gate Management Package" },                                  /* Annex B of ETSI TS 102 333 */
    {   0x008d, "Traffic Management Package" },                               /* Annex C of ETSI TS 102 333 */
    {   0x008e, "Gate Recovery Information Package" },                        /* Annex D of ETSI TS 102 333 */
    {   0x008f, "NAT Traversal Package" },                                    /* Annex E of ETSI TS 102 333 */
    {   0x0090, "MPLS Package" },                                             /* Annex F of ETSI TS 102 333 */
    {   0x0091, "VLAN Package" },                                             /* Annex G of ETSI TS 102 333 */
    {   0x0092, "Detailed Congestion Reporting Package" },                    /* H.248.32 */
    {   0x0093, "Stimulus Analogue Lines Package" },                          /* H.248.34 */
    {   0x0094, "icascgen" },                                                 /* H.248.29 Annex B */
    {   0x0095, "Coin Operated Phone Control Package" },                      /* H.248.35 */
    {   0x0096, "Metering Pulse Detection Package" },                         /* H.248.26 Amendment 1 */
    {   0x0097, "Trace Package" },                                            /* 3GPP TS 29.232 v6.3.0 */
    {   0x0098, "Hanging Termination Package" },                              /* H.248.36 */
    {   0x0099, "IP NAPT Traversal Package" },                                /* H.248.37 */
    {   0x009a, "Notification Behaviour Package" },                           /* H.248.1v3 */
    {   0x009b, "Base Context Package" },                                     /* H.248.38 */
    {   0x009c, "Application Data Inactivity Detection Package" },            /* H.248.40 */
    {   0x009d, "Domain Connection Package " },                               /* H.248.41 */
    {   0x009e, "Digital Circuit Multiplication Equipment Package" },         /* H.248.42 */
    {   0x009f, "Multi-level Precedence and Pre-emption Package" },           /* H.248.44 */
    {   0x00a0, "MGC Information Package" },                                  /* H.248.45 */
    {   0x00a1, "Text Overlay Package" },                                     /* H.248.19 Amendment 1 */
    {   0x00a2, "Border and Background Package" },                            /* H.248.19 Amendment 1 */
    {   0x00a3, "Segmentation Package" },                                     /* H.248.1v3 */
    {   0x00a4, "ETSI notification behaviour package" },                      /* ETSI ES 283 039-3 */
    {   0x00a5, "ETSI notification rate package" },                           /* ETSI ES 283 039-4 */
    {   0x00a6, "Automatic Speech Recognition Package" },                     /* H.248.9 Amendment 1 */
    {   0x00a7, "Set extension to basic syntax for TTS enhancement Package" },/* H.248.9 Amendment 1 */
    {   0x00a8, "Advanced audio server base package for TTS enhancement" },   /* H.248.9 Amendment 1 */
    {   0x00a9, "Multimedia Play Package" },                                  /* H.248.9 Amendment 1 */
    {   0x00aa, "Floor Status Detection Package" },                           /* H.248.19 Amendment 2 */
    {   0x00ab, "Floor Control Policy Package" },                             /* H.248.19 Amendment 2 */
    {   0x00ac, "Address Reporting Package" },                                /* H.248.37 Amendment 1 */
    {   0x00ad, "Connection Capability Control Package" },                    /* H.248.46 */
    {   0x00ae, "Statistic Conditional Reporting Package" },                  /* H.248.47 Amendment 1 */
    {   0x00af, "RTCP HR QoS Statistics Package" },                           /* H.248.48 */
    {   0x00b0, "Received RTCP XR Package" },                                 /* H.248.30 (01/2007) */
    {   0x00b1, "Received RTCP XR Burst Metrics Package" },                   /* H.248.30 (01/2007) */
    {   0x00b2, "ASCI Group call package" },                                  /* 3GPP TS 29.232 v7.4.0 */
    {   0x00b3, "Multimedia Recording Package" },                             /* H.248.9 Amendment 1 */
    {   0x00b4, "H.245 Transport Package" },                                  /* H.248.12 Amendment 2 */
    {   0x00b5, "RTCP Handling package" },                                    /* H.248.57 */
    {   0x00b6, "Gate Management - Outgoing Destination Address/Port Filtering Package" },/* H.248.43 */
    {   0x00b7, "Gate Management - Incoming Protocol Filtering Package" },    /* H.248.43 */
    {   0x00b8, "Gate Management - Outgoing Protocol Filtering Package" },    /* H.248.43 */
    {   0x00b9, "Gate Management - Incoming Filtering Behaviour Package" },   /* H.248.43 */
    {   0x00ba, "Gate Management - Outgoing Filtering Behaviour Package" },   /* H.248.43 */
    {   0x00bb, "Session Description Protocol RFC Package" },                 /* H.248.49 */
    {   0x00bc, "Session Description Protocol Capabilities Package" },        /* H.248.49 */
    {   0x00bd, "NAT Traversal Toolkit - STUN Base Package" },                /* H.248.50 */
    {   0x00be, "NAT Traversal Toolkit - MG STUN Client Package" },           /* H.248.50 */
    {   0x00bf, "NAT Traversal Toolkit - MG TURN Client Package" },           /* H.248.50 */
    {   0x00c0, "NAT Traversal Toolkit - MGC STUN Client Package" },          /* H.248.50 */
    {   0x00c1, "NAT Traversal Toolkit - STUN Information Package" },         /* H.248.50 */
    {   0x00c2, "NAT Traversal Toolkit - MG Act-as STUN Server Package" },    /* H.248.50 */
    {   0x00c3, "NAT Traversal Toolkit - Originate STUN Continuity Check Package" },  /* H.248.50 */
    {   0x00c4, "NAT Traversal Toolkit - MGC Originated STUN Request Package" },      /* H.248.50 */
    {   0x00c5, "NAT Traversal Toolkit - RTP NOOP Request Package" },         /* H.248.50 */
    {   0x00c6, "Termination Connection Model Package" },                     /* H.248.51 */
    {   0x00c7, "QoS Class Package" },                                        /* H.248.52 */
    {   0x00c8, "Traffic Policing Statistics Package" },                      /* H.248.53 */
    {   0x00c9, "Packet Size Package" },                                      /* H.248.53 */
    {   0x00ca, "Pull Mode Package" },                                        /* H.248.55 */
    {   0x00cb, "RTP Application Data Package" },                             /* H.248.58 */
    {   0x00cc, "Event Timestamp Notification Package" },                     /* H.248.59 */
    {   0x00cd, "Resource Management Rules Package" },                        /* H.248.63 */
    {   0x00ce, "Resource Management Configuration Package" },                /* H.248.63 */
    {   0x00cf, "Abstract Resource Management Packages" },                    /* H.248.63 */
    {   0x00d0, "IP layer octets count statistics Package" },                 /* H.248.61 */
    {   0x00d1, "Content of Communication Identity Package" },                /* H.248.60 */
    {   0x00d2, "RSVP extension package" },                                   /* H.248.65 */
    {   0x00d3, "GCP Transport Mode Indication Package" },                    /* H.248.67 */
    {   0x00d4, "IP Router Package" },                                        /* H.248.64 */
    {   0x00d5, "Media Resource Identification Package" },                    /* H.248.66 */
    {   0x00d6, "Range Format Support Package" },                             /* H.248.66 */
    {   0x00d7, "Media Resource Description Expiry Package" },                /* H.248.66 */
    {   0x00d8, "Media Block Size Package" },                                 /* H.248.66 */
    {   0x00d9, "RTSP Media Resource Syntax Package" },                       /* H.248.66 */
    {   0x00da, "RTSP Play Package" },                                        /* H.248.66 */
    {   0x00db, "Signal Pause Package" },                                     /* H.248.66 */
    {   0x00dc, "Data Delivery Speed Adjustme Package" },                     /* H.248.66 */
    {   0x00dd, "Playback Relative Scale Adjustment Package" },               /* H.248.66 */
    {   0x00de, "RTP Information Package" },                                  /* H.248.66 */
    {   0x00df, "RTP Interleaving Package" },                                 /* H.248.66 */
    {   0x00e0, "IP Realm Availability Package" },                            /* H.248.41 Amendment 1 */
    {   0x00e1, "General IP Header QoS Octet Package" },                      /* H.248.52  */
    {   0x00e2, "Re-answer Package" },                                        /* H.248.62  */
    {   0x00e3, "3G Interface Type package" },                                /* 3GPP TS 29.232 v8.4.0 */
    {   0x00e4, "Latch Statistics Package" },                                 /* H.248.37 */
    {   0x00e5, "Floor Control Signalling Package" },                         /* H.248.19 Amendment 2 */
    {   0x00e6, "Include Participant in Mix Package" },                       /* H.248.19 Amendment 2 */
    {   0x00e7, "Speaker Reporting Package" },                                /* H.248.19 Amendment 2 */
    {   0x00e8, "IP Layer Packet Count Statistics Package" },                 /* H.248.61 */
    {   0x00e9, "Removal of Digits and Tones Package" },                      /* H.248.68 */
    {   0x00ea, "MSRP Statistics Package" },                                  /* H.248.69 */
    {   0x00eb, "MSRP Connection Status Package" },                           /* H.248.69 */
    {   0x00ec, "Play Message Package" },                                     /* H.248.69 */
    {   0x00ed, "Delete Stored Message Package" },                            /* H.248.69 */
    {   0x00ee, "Message Session Information Package" },                      /* H.248.69 */
    {   0x00ef, "Message Filtering Package" },                                /* H.248.69 */
    {   0x00f0, "Stored Message Information Package" },                       /* H.248.69 */
    {   0x00f1, "Record Message Package" },                                   /* H.248.69 */
    {   0x00f2, "Digit Dialling Method Information Package" },                /* H.248.70 */
    {   0x00f3, "Digit Dialling Method Information for Extended Digitmap Detection Package" }, /* H.248.70 */
    {   0x00f4, "Digit Dialling Method Information for Enhanced Digitmap Detection Package" }, /* H.248.70 */
    {   0x00f5, "Received RTCP Package " },                                   /* H.248.71 */
    {   0x00f6, "RTP Cumulative Loss Package" },                              /* H.248.71 */
    {   0x00f7, "H.245 Transport Package for SPC use" },                      /* H.248.72 */
    {   0x00f8, "MONA Preference Package" },                                  /* H.248.72 */
    {   0x00f9, "TDM Gain Control Package" },                                 /* H.248.73 */
    {   0x00fa, "Media Start Package" },                                      /* H.248.74 */
    {   0x00fb, "Trim Package" },                                             /* H.248.74 */
    {   0x00fc, "Enhanced Recording Package" },                               /* H.248.74 */
    {   0x00fd, "Enhanced ASR Package" },                                     /* H.248.74      */
    {   0x00fe, "Enhanced TTS Package" },                                     /* H.248.74 */
    {   0x00ff, "Play Offset Control Package" },                              /* H.248.74 */
    {   0x0100, "Enhanced DTMF Detection Package" },                          /* H.248.9 Revised 2009 */
    {   0x0101, "IP Router NAT Package" },                                    /* H.248.64 */
    {   0x0102, "Voice Enrolled Grammar Package" },                           /* H.248.74 */
    {   0x0103, "Filter Group Package" },                                     /* H.248.76 */
    {   0x0104, "RTCP Source Description Package" },                          /* H.248.71 */
    {   0x0105, "Speaker Verification and Identification Package" },          /* H.248.74 */
    {   0x0106, "Package Identifier Publishing and Application Package" },    /* H.248 */
    {   0x0107, "Secure RTP Package " },                                      /* H.248.77 */
    {   0x0108, "MGC Controlled Bearer Level ALG Package" },                  /* H.248.78 */
    {   0x0109, "Enhanced Revised Offer/Answer SDP Support Package" },        /* H.248.80 */
    {   0x010a, "Enhanced SDP Media Capabilities Negotiation Support Package" }, /* H.248.80 */
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
    {   0x800b, "Nokia Test Call Package" },
    {   0x800c, "Nokia Extended Continuity Package" },
    {   0x800d, "Nokia IPnwR Package" },
    {   0x800e, "Ericsson Tracing Enhancements Package" },
    {   0x800f, "Ericsson Partially Wildcarded TerminationID Package" },
    {   0x8010, "SCTP Stream Handling Package" },
    {0,     NULL}
};

/*
 * This table consist of PackageName + EventName and its's corresponding string
 *
 */
static const value_string base_event_name_vals[] = {
    {   0x00000000, "Media stream properties H.248.1 Annex C" },
    {   0x00010000, "g H.248.1 Annex E" },
    {   0x00010001, "g/Cause" },
    {   0x00010002, "g/Signal Completion" },
    {   0x00040000, "tonedet H.248.1 Annex E" },
    {   0x00040001, "tonedet/std(Start tone detected)" },
    {   0x00040002, "tonedet/etd(End tone detected)" },
    {   0x00040003, "tonedet/ltd(Long tone detected)" },
    {   0x00060000, "dd H.248.1 Annex E" },
    {   0x00060001, "dd/std" },
    {   0x00060002, "dd/etd" },
    {   0x00060003, "dd/ltd" },
    {   0x00060004, "dd, DigitMap Completion Event" },
    {   0x00060010, "dd/d0, DTMF character 0" },
    {   0x00060011, "dd/d1, DTMF character 1" },
    {   0x00060012, "dd/d2, DTMF character 2" },
    {   0x00060013, "dd/d3, DTMF character 3" },
    {   0x00060014, "dd/d4, DTMF character 4" },
    {   0x00060015, "dd/d5, DTMF character 5" },
    {   0x00060016, "dd/d6, DTMF character 6" },
    {   0x00060017, "dd/d7, DTMF character 7" },
    {   0x00060018, "dd/d8, DTMF character 8" },
    {   0x00060019, "dd/d9, DTMF character 9" },
    {   0x0006001a, "dd/a, DTMF character A" },
    {   0x0006001b, "dd/b, DTMF character B" },
    {   0x0006001c, "dd/c, DTMF character C" },
    {   0x0006001d, "dd/d, DTMF character D" },
    {   0x00060020, "dd/*, DTMF character *" },
    {   0x00060021, "dd/#, DTMF character #" },
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
    {   0x000a0005, "ct, Completion of Continuity test" },
    {   0x000b0005, "nt, network failure" },
    {   0x000b0006, "nt, quality alert" },
    {   0x000c0001, "rtp, Payload Transition" },
    {   0x00210000, "Generic Bearer Connection Q.1950 Annex A" },
    {   0x00210001, "GB/BNCChange" },
    {   0x00220001, "BT/TIND (Tunnel Indication)" },
    {   0x002a0001, "H.245/h245msg (Incoming H.245 Message)" },
    {   0x002a0004, "H.245/h245ChC (H.245 Channel Closed)" },
    {   0x00450000, "Inactivity Timer H.248.14" },
    {   0x00450001, "it/ito" },
    {   0x00450002, "it/ito" },
    {   0x00460001, "threegmlc/mod_link_supp (Bearer Modification Support Event)" },
    {   0x00980000, "Hanging Termination Package" },
    {   0x00980001, "Termination Heartbeat" },
    {   0x800a0000, "Nokia Bearer Characteristics Package" },
    {0,     NULL}
};

/*
 * This table consist of PackageName + SignalName and its's corresponding string
 */
static const value_string base_signal_name_vals[] = {
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


static const value_string h248_reasons[] = {
    { 400, "Syntax error in message"},
    { 401, "Protocol Error"},
    { 402, "Unauthorized"},
    { 403, "Syntax error in transaction request"},
    { 406, "Version Not Supported"},
    { 410, "Incorrect identifier"},
    { 411, "The transaction refers to an unknown ContextId"},
    { 412, "No ContextIDs available"},
    { 413, "Number of transactions in message exceeds maximum"},    /* [H.248.8 (08/07)] */
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
    { 461, "Unsupported or Unknown Profile"},                               /*[H.248.18] */

    { 471, "Implied Add for Multiplex failure"},
    { 472, "Required Information Missing"},                                 /*[H.248.8 (08/07)] */
    { 473, "Conflicting Property Values"},                                  /*[H.248.8 (08/07)] */
    { 474, "Invalid SDP Syntax"},                                           /*[H.248.49] */
    { 475, "Unable to pause the playout of the signal"},                    /*[H.248.66] */
    { 476, "Unable to adjust the data delivery speed of the Signal"},       /*[H.248.66] */

    { 477, "Unable to adjust the playback relative scale of the signal"},   /*[H.248.66] */

    { 478, "Behaviour Contradicts Resource Rule"},                          /*[H.248.63] */

    { 500, "Internal software Failure in MG"},
    { 501, "Not Implemented"},
    { 502, "Not ready"},
    { 503, "Service Unavailable"},
    { 504, "Command Received from unauthorized entity"},
    { 505, "Transaction Request Received before a Service Change Reply has been received"},
    { 506, "Number of Transaction Pendings Exceeded"},
    { 510, "Insufficient resources"},
    { 511, "Temporarily Busy"},                                     /* [H.248.8 (08/07)] */
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
    { 541, "Unexpected Spare Bit State"},                               /* [H.248.33] */
    { 542, "Command is not allowed on this termination"},
    { 543, "MGC requested event detection timestamp not supported"},    /* [H.248.8 (08/07)] */
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
    { 617, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 618, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 622, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 623, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 624, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 625, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 626, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 627, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 628, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 629, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 700, "Sieve Script Syntax Error"},            /* [H.248.69] */
    { 701, "Unsupported Sieve Require Error"},      /* [H.248.69] */
    { 702, "Sieve Actions Exceeded Error"},         /* [H.248.69] */

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
static value_string_ext h248_reasons_ext = VALUE_STRING_EXT_INIT(h248_reasons);

static const value_string wildcard_modes[] = {
    { 0, "Choose" },
    { 1, "All" },
    { 0, NULL }
};

static const value_string wildcard_levels[] = {
    { 0, "This One Level" },
    { 1, "This Level and those below" },
    { 0, NULL }
};

static h248_curr_info_t curr_info = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
static guint32 error_code;
static guint32 h248_version = 0; /* h248v1 support */
static gcp_wildcard_t wild_term;
static guint8 wild_card = 0xFF; /* place to store wildcardField */

extern void h248_param_ber_integer(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* u _U_, void* implicit) {
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
    dissect_ber_integer(implicit ? *((gboolean*)implicit) : FALSE, &asn1_ctx, tree, tvb, 0, hfid, NULL);
}

extern void h248_param_ber_octetstring(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* u _U_, void* implicit) {
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	dissect_ber_octet_string(implicit ? *((gboolean*)implicit) : FALSE, &asn1_ctx, tree, tvb, 0, hfid, NULL);
}

extern void h248_param_ber_boolean(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* u _U_, void* implicit) {
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	dissect_ber_boolean(implicit ? *((gboolean*)implicit) : FALSE, &asn1_ctx, tree, tvb, 0, hfid, NULL);
}

extern void h248_param_bytes_item(proto_tree* tree,
                             tvbuff_t* tvb,
                             packet_info* pinfo _U_,
                             int hfid,
                             h248_curr_info_t* h248_info _U_,
                             void* lenp ) {
    int len = lenp ? *((int*)lenp) : -1;
    proto_tree_add_item(tree,hfid,tvb,0,len,ENC_NA);
}

extern void h248_param_uint_item(proto_tree* tree,
                                 tvbuff_t* tvb,
                                 packet_info* pinfo _U_,
                                 int hfid,
                                 h248_curr_info_t* h248_info _U_,
                                 void* lenp ) {
    int len = lenp ? *((int*)lenp) : -1;
    proto_tree_add_item(tree,hfid,tvb,0,len,ENC_BIG_ENDIAN);
}

extern void h248_param_external_dissector(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo , int hfid _U_, h248_curr_info_t* u _U_, void* dissector_hdl) {
    call_dissector((dissector_handle_t) dissector_hdl,tvb,pinfo,tree);
}


static const h248_package_t no_package = { 0xffff, &hf_h248_no_pkg, &ett_h248_no_pkg, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
static const h248_pkg_sig_t no_signal = { 0, &hf_h248_no_sig, &ett_h248_no_sig, NULL, NULL };
static const h248_pkg_param_t no_param = { 0, &hf_h248_param, h248_param_uint_item,  NULL };
static const h248_pkg_evt_t no_event = { 0, &hf_h248_no_evt, &ett_h248_no_evt, NULL, NULL };

const h248_package_t *find_package_id(guint16 pkgid);
static GTree* packages = NULL;

extern void h248_param_PkgdName(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo , int hfid _U_, h248_curr_info_t* u1 _U_, void* u2 _U_) {
    tvbuff_t *new_tvb = NULL;
    proto_tree *package_tree=NULL;
    guint16 name_major, name_minor;
    const h248_package_t* pkg = NULL;
    int offset = 0;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, offset, hfid , &new_tvb);

    if (new_tvb) {
        /* this field is always 4 bytes  so just read it into two integers */
        name_major=tvb_get_ntohs(new_tvb, 0);
        name_minor=tvb_get_ntohs(new_tvb, 2);
		pkg = find_package_id(name_major);
        /* do the prettification */
        proto_item_append_text(asn1_ctx.created_item, "  %s (%04x)",
                               val_to_str(0, pkg->param_names, "Unknown Package"),
                               name_major);

        if(tree){
            proto_item* pi;
            const gchar* strval;

            package_tree = proto_item_add_subtree(asn1_ctx.created_item, ett_packagename);
			proto_tree_add_uint_format(package_tree, hf_h248_pkg_name, tvb, offset-4, 2, name_major,
				"%s (0x%04x)", val_to_str(0, pkg->param_names, "Unknown Package"), name_major);

            pi = proto_tree_add_uint(package_tree, hf_248_pkg_param, tvb, offset-2, 2, name_minor);

            if (pkg->signal_names && ( strval = match_strval(name_minor, pkg->signal_names) )) {
                strval = ep_strdup_printf("%s (%d)",strval,name_minor);
            } else {
                strval = ep_strdup_printf("Unknown (%d)",name_minor);
            }

            proto_item_set_text(pi,"Signal ID: %s", strval);
        }

    }
}


static int dissect_h248_trx_id(gboolean implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint32* trx_id_p) {
    guint64 trx_id = 0;
    gint8 ber_class;
    gboolean pc;
    gint32 tag;
    guint32 len;
    guint32 i;

    if(!implicit_tag){
        offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
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
            proto_item* pi = proto_tree_add_text(tree, tvb, offset-len, len,"transactionId %" G_GINT64_MODIFIER "u", trx_id);
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
    gint8 ber_class;
    gboolean pc;
    gint32 tag;
    guint32 len;
    guint64 ctx_id = 0;
    guint32 i;

    if(!implicit_tag){
        offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
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
                                                 "contextId: %" G_GINT64_MODIFIER "u", ctx_id);
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

s_h248_package_t *s_find_package_id(guint16 pkgid) {
	s_h248_package_t *s_pkg = NULL;
	s_pkg = g_tree_lookup(packages, GUINT_TO_POINTER((guint32)(pkgid)));
	return s_pkg;
}

const h248_package_t *find_package_id(guint16 pkgid) {
	s_h248_package_t *s_pkg = NULL;
	s_pkg = s_find_package_id(pkgid); /*(packages, GUINT_TO_POINTER((guint32)(pkgid))); */
	if (! s_pkg ) return &no_package;
	return s_pkg->pkg;
}

static gint32 comparePkgID(gconstpointer a, gconstpointer b) {
	return GPOINTER_TO_UINT(b) - GPOINTER_TO_UINT(a);
}

gboolean is_pkg_default(guint16 pkgid) {
	s_h248_package_t *s_pkg = NULL;
	s_pkg = g_tree_lookup(packages, GUINT_TO_POINTER((guint32)(pkgid)));
	if(! s_pkg ) return TRUE;
	return s_pkg->is_default;
}

void h248_register_package(const h248_package_t* pkg, pkg_reg_action reg_action) {
	h248_package_t *pkg_found = NULL, *pkg_high = NULL, *pkg_low = NULL;
	s_h248_package_t *s_pkg = NULL;
	value_string *vst; 
	gboolean pkg_default = FALSE;
	gint j = 0, idx = 0, i = 0, k = 0;
    if (! packages) {
		/* no packaegs are yet registerd so create tree and add default packages to tree
		 */
		packages = g_tree_new(comparePkgID); /* init tree if no entries */
		while (base_package_name_vals[i].strptr != NULL) {
			pkg_found = g_new0(h248_package_t, 1); /* create a h248 package structure */
			pkg_found->id = base_package_name_vals[i].value;
			vst = g_new0(value_string,2);
			vst[0].strptr = base_package_name_vals[i].strptr;
			pkg_found->param_names = vst;
			pkg_found->hfid = &hf_h248_pkg_name;
			pkg_found->ett = &ett_packagename;
			match_strval_idx((pkg_found->id)<<16,base_event_name_vals, &j);
			/* now look for events and signals that may be defined for package.  If found, create value_strings */
			if (j != -1) {
				j++; idx=j;
				while((base_event_name_vals[j].strptr!=NULL) && (((base_event_name_vals[j].value)>>16) == (pkg_found->id))) {
					j++; 
				};
				if (idx < j) {
					vst = g_new0(value_string,j-idx+1);
					for (k=0;idx<j;k++) {
						vst[k].strptr = base_event_name_vals[idx].strptr;
						vst[k].value = (base_event_name_vals[idx].value & 0xffff);
						idx++;
					};
					pkg_found->event_names = vst;
				}
			}
			/* now look at signals */
			if (!match_strval_idx((pkg_found->id)<<16, base_signal_name_vals, &j)) {
				j++; idx=j;
				while((base_signal_name_vals[j].strptr != NULL) && ((base_signal_name_vals[j].value>>16) == (pkg_found->id))) {
				};
				if (idx < j) {
					vst = g_new0(value_string,j-idx+1);
					for (k=0;idx<i;k++) {
						vst[k].strptr = base_signal_name_vals[idx].strptr;
						vst[k].value = (base_signal_name_vals[idx].value &0xffff);
						idx++;
					};
					pkg_found->signal_names = vst;
				}
			};
			s_pkg = g_new0(s_h248_package_t,1);
			s_pkg->is_default = TRUE;
			s_pkg->pkg = pkg_found;
			g_tree_insert(packages, GINT_TO_POINTER(pkg_found->id), (gpointer)s_pkg);
			i++;
		};
		pkg_found = NULL; /* reset pointer */
	};
	pkg_default = is_pkg_default(pkg->id);
	if (((reg_action==REPLACE_PKG) || (reg_action==ADD_PKG)) && pkg_default) {
		/* add/replace in tree */
		s_pkg = g_new0(s_h248_package_t,1);
		s_pkg->is_default = FALSE;
		s_pkg->pkg = (h248_package_t *)pkg;
		g_tree_replace(packages, GINT_TO_POINTER(pkg->id), (gpointer)s_pkg);
		return;
	};
	if(pkg_default) reg_action = MERGE_PKG_HIGH; /* always make new package overide default */
	s_pkg = s_find_package_id(pkg->id);
	if (s_pkg == NULL) { /* no need to merge - package not in tree */
		s_pkg = g_new0(s_h248_package_t,1);
		s_pkg->is_default = FALSE;
		s_pkg->pkg = (h248_package_t *)pkg;
		g_tree_insert(packages, GINT_TO_POINTER(pkg->id), (gpointer)s_pkg);
		return;
	}
	pkg_found = s_pkg->pkg;
	if (reg_action==MERGE_PKG_HIGH) {
			pkg_high = (h248_package_t *)pkg;
			pkg_low = pkg_found;
	};
	if (reg_action==MERGE_PKG_LOW) {
			pkg_high = pkg_found;
			pkg_low = (h248_package_t *)pkg;
	};
	/* if h248_package_t High Priority value !NULL, replace it in the found tree entry else use current entry */
	(pkg_high->hfid ? (pkg_found->hfid=pkg_high->hfid) : (pkg_found->hfid=pkg_low->hfid));
	(pkg_high->ett ? (pkg_found->ett=pkg_high->ett ):( pkg_found->ett=pkg_low->ett));
	(pkg_high->param_names ? (pkg_found->param_names=pkg_high->param_names ):( pkg_found->param_names=pkg_low->param_names));
	(pkg_high->signal_names ? (pkg_found->signal_names=pkg_high->signal_names ):( pkg_found->signal_names=pkg_low->signal_names));
	(pkg_high->event_names ? (pkg_found->event_names=pkg_high->event_names ):( pkg_found->event_names=pkg_low->event_names));
	(pkg_high->stats_names ? (pkg_found->stats_names=pkg_high->stats_names ):( pkg_found->stats_names=pkg_low->stats_names));
	(pkg_high->properties ? (pkg_found->properties=pkg_high->properties ):( pkg_found->properties=pkg_low->properties));
	(pkg_high->signals ? (pkg_found->signals=pkg_high->signals ):( pkg_found->signals=pkg_low->signals));
	(pkg_high->events ? (pkg_found->events=pkg_high->events ):( pkg_found->events=pkg_low->events));
	(pkg_high->statistics ? (pkg_found->statistics=pkg_high->statistics ):( pkg_found->statistics=pkg_low->statistics));
	s_pkg->pkg = pkg_found;
	s_pkg->is_default = FALSE;
}


static guint32 packageandid;

static int dissect_h248_PkgdName(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
    tvbuff_t *new_tvb = NULL;
    proto_tree *package_tree=NULL;
    guint16 name_major, name_minor;
    const h248_package_t* pkg = NULL;
    
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);

    if (new_tvb) {
        /* this field is always 4 bytes  so just read it into two integers */
        name_major=tvb_get_ntohs(new_tvb, 0);
        name_minor=tvb_get_ntohs(new_tvb, 2);
        packageandid=(name_major<<16)|name_minor;

		pkg = find_package_id(name_major);
        /* do the prettification */
        proto_item_append_text(actx->created_item, "  %s (%04x)",
                               val_to_str(0, pkg->param_names, "Unknown Package"),
                               name_major);

        if(tree){
            package_tree = proto_item_add_subtree(actx->created_item, ett_packagename);
			proto_tree_add_uint_format(package_tree, hf_h248_pkg_name, tvb, offset-4, 2, name_major,
				"PkgName: %s (0x%04x)", val_to_str(0, pkg->param_names, "Unknown Package"), name_major);
        }

        {
            proto_item* pi = proto_tree_add_uint(package_tree, hf_248_pkg_param, tvb, offset-2, 2, name_minor);
            const gchar* strval;

            if (pkg->param_names && ( strval = match_strval(name_minor, pkg->param_names) )) {
                strval = ep_strdup_printf("%s (%d)",strval,name_minor);
            } else {
                strval = ep_strdup_printf("Unknown (%d)",name_minor);
            }

            proto_item_set_text(pi,"Parameter: %s", strval);
        }
    } else {
        pkg = &no_package;
    }

    curr_info.pkg = pkg;

    return offset;
}

static int dissect_h248_EventName(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
    tvbuff_t *new_tvb;
    proto_tree *package_tree=NULL;
    guint16 name_major, name_minor;
    const h248_package_t* pkg = NULL;
    const h248_pkg_evt_t* evt = NULL;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);

    if (new_tvb) {
        /* this field is always 4 bytes  so just read it into two integers */
        name_major=tvb_get_ntohs(new_tvb, 0);
        name_minor=tvb_get_ntohs(new_tvb, 2);
        packageandid=(name_major<<16)|name_minor;

		pkg = find_package_id(name_major);
        /* do the prettification */
        proto_item_append_text(actx->created_item, "  %s (%04x)",
                               val_to_str(0, pkg->param_names, "Unknown Package"),
                               name_major);
        if(tree){
            package_tree = proto_item_add_subtree(actx->created_item, ett_packagename);
        }
		proto_tree_add_uint_format(package_tree, hf_h248_pkg_name, tvb, offset-4, 2, name_major,
			"%s (0x%04x)", val_to_str(0, pkg->param_names, "Unknown Package"), name_major);

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

        {
            proto_item* pi = proto_tree_add_uint(package_tree, hf_h248_event_code, tvb, offset-2, 2, name_minor);
            const gchar* strval;

            if (pkg->event_names && ( strval = match_strval(name_minor, pkg->event_names) )) {
                strval = ep_strdup_printf("%s (%d)",strval,name_minor);
            } else {
                strval = ep_strdup_printf("Unknown (%d)",name_minor);
            }

            proto_item_set_text(pi,"Event ID: %s", strval);
        }

    } else {
        curr_info.pkg = &no_package;
        curr_info.evt = &no_event;
    }

    return offset;
}



static int dissect_h248_SignalName(gboolean implicit_tag , tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
    tvbuff_t *new_tvb;
    proto_tree *package_tree=NULL;
    guint16 name_major, name_minor;
    const h248_package_t* pkg = NULL;
    const h248_pkg_sig_t* sig;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);

    if (new_tvb) {
        /* this field is always 4 bytes so just read it into two integers */
        name_major=tvb_get_ntohs(new_tvb, 0);
        name_minor=tvb_get_ntohs(new_tvb, 2);
        packageandid=(name_major<<16)|name_minor;

		pkg = find_package_id(name_major);
        /* do the prettification */
        proto_item_append_text(actx->created_item, "  %s (%04x)",
                               val_to_str(0, pkg->param_names, "Unknown Package"),
                               name_major);
        if(tree){
            package_tree = proto_item_add_subtree(actx->created_item, ett_packagename);
        }
		proto_tree_add_uint_format(package_tree, hf_h248_pkg_name, tvb, offset-4, 2, name_major,
			"%s (0x%04x)", val_to_str(0, pkg->param_names, "Unknown Package"), name_major);

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

        {
            proto_item* pi = proto_tree_add_uint(package_tree, hf_h248_signal_code, tvb, offset-2, 2, name_minor);
            const gchar* strval;

            if (pkg->signal_names && ( strval = match_strval(name_minor, pkg->signal_names) )) {
                strval = ep_strdup_printf("%s (%d)",strval,name_minor);
            } else {
                strval = ep_strdup_printf("Unknown (%d)",name_minor);
            }

            proto_item_set_text(pi,"Signal ID: %s", strval);
        }

    } else {
        curr_info.pkg = &no_package;
        curr_info.sig = &no_signal;
    }

    return offset;
}

static int dissect_h248_PropertyID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {

    gint8 ber_class;
    gboolean pc, ind;
    gint32 tag;
    guint32 len;
    guint16 name_minor;
    int end_offset;
    const h248_package_t* pkg;
    const h248_pkg_param_t* prop;
    tvbuff_t *next_tvb = NULL;

    offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
    offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
    end_offset=offset+len;

    if( (ber_class!=BER_CLASS_UNI)
      ||(tag!=BER_UNI_TAG_OCTETSTRING) ){
        proto_tree_add_text(tree, tvb, offset-2, 2, "H.248 BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", ber_class, pc, tag);
        return end_offset;
    }

    next_tvb = tvb_new_subset(tvb,offset,len,len);

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
    if (prop && prop->hfid ) {
        if (!prop->dissector) prop = &no_param;
        prop->dissector(tree, next_tvb, actx->pinfo, *(prop->hfid), &curr_info, prop->data);
    }

    return end_offset;
}



static int dissect_h248_SigParameterName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    tvbuff_t *next_tvb;
    guint32 param_id = 0xffffffff;
    const h248_pkg_param_t* sigpar;
    const gchar* strval;
    proto_item* pi;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset,  hf_index, &next_tvb);
    pi = actx->created_item;

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

    if (curr_info.sig && curr_info.sig->param_names && ( strval = match_strval(param_id, curr_info.sig->param_names) )) {
        strval = ep_strdup_printf("%s (%d)",strval,param_id);
    } else {
        strval = ep_strdup_printf("Unknown (%d)",param_id);
    }

    proto_item_set_text(pi,"Parameter: %s", strval);

    return offset;
}

static int dissect_h248_SigParamValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    int end_offset;
    gint8 ber_class;
    gboolean pc, ind;
    gint32 tag;
    guint32 len;
    tvbuff_t *next_tvb = NULL;

    offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
    offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
    end_offset=offset+len;

    if( (ber_class!=BER_CLASS_UNI)
        ||(tag!=BER_UNI_TAG_OCTETSTRING) ){
        proto_tree_add_text(tree, tvb, offset-2, 2, "H.248 BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", ber_class, pc, tag);
        return end_offset;
    }

    next_tvb = tvb_new_subset(tvb,offset,len,len);

    if ( curr_info.par && curr_info.par->dissector) {
        curr_info.par->dissector(tree, next_tvb, actx->pinfo, *(curr_info.par->hfid), &curr_info, curr_info.par->data);
    }

    return end_offset;
}

static int dissect_h248_SigParamValueV1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset _U_,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
	return dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);
}


static int dissect_h248_EventParameterName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    tvbuff_t *next_tvb;
    guint32 param_id = 0xffffffff;
    const h248_pkg_param_t* evtpar;
    const gchar* strval;
    proto_item* pi;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &next_tvb);
    pi = actx->created_item;

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

    if (curr_info.evt && curr_info.evt->parameters) {
        for(evtpar = curr_info.evt->parameters; evtpar->hfid; evtpar++) {
            if (evtpar->id == param_id) {
                curr_info.par = evtpar;
                break;
            }
        }
    } else {
        curr_info.par = &no_param;
    }

    if (curr_info.evt && curr_info.evt->param_names && ( strval = match_strval(param_id, curr_info.evt->param_names) )) {
        strval = ep_strdup_printf("%s (%d)",strval,param_id);
    } else {
        strval = ep_strdup_printf("Unknown (%d)",param_id);
    }

    proto_item_set_text(pi,"Parameter: %s", strval);


    return offset;
}

static int dissect_h248_EventParamValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    tvbuff_t *next_tvb;
    int end_offset;
    gint8 ber_class;
    gboolean pc, ind;
    gint32 tag;
    guint32 len;

	offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
	offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
	end_offset=offset+len;

	if( (ber_class!=BER_CLASS_UNI)
        ||(tag!=BER_UNI_TAG_OCTETSTRING) ){
        proto_tree_add_text(tree, tvb, offset-2, 2, "H.248 BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", ber_class, pc, tag);
        return end_offset;
    }

    next_tvb = tvb_new_subset(tvb,offset,len,len);

	if ( curr_info.par && curr_info.par->dissector) {
        curr_info.par->dissector(tree, next_tvb, actx->pinfo, *(curr_info.par->hfid), &curr_info, curr_info.par->data);
    }

    return end_offset;
}

static int dissect_h248_EventParamValueV1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset _U_,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
	return dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &tvb);
}


static int dissect_h248_MtpAddress(gboolean implicit_tag, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
    tvbuff_t *new_tvb;
    proto_tree *mtp_tree=NULL;
    guint32 val;
    int i, len, old_offset;

    old_offset=offset;
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);

    if (new_tvb) {
        /* this field is either 2 or 4 bytes  so just read it into an integer */
        val=0;
        len=tvb_length(new_tvb);
        for(i=0;i<len;i++){
            val= (val<<8)|tvb_get_guint8(new_tvb, i);
        }

        /* do the prettification */
        proto_item_append_text(actx->created_item, "  NI = %d, PC = %d ( %d-%d )", val&0x03,val>>2,val&0x03,val>>2);
        if(tree){
            mtp_tree = proto_item_add_subtree(actx->created_item, ett_mtpaddress);
        }
        proto_tree_add_uint(mtp_tree, hf_h248_mtpaddress_ni, tvb, old_offset, offset-old_offset, val&0x03);
        proto_tree_add_uint(mtp_tree, hf_h248_mtpaddress_pc, tvb, old_offset, offset-old_offset, val>>2);
    }

    return offset;
}

#define H248_TAP() do { if (keep_persistent_data && curr_info.cmd) tap_queue_packet(h248_tap, actx->pinfo, curr_info.cmd); } while(0)

#include "packet-h248-fn.c"

static void dissect_h248_tpkt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    dissect_tpkt_encap(tvb, pinfo, tree, h248_desegment, h248_handle);
}

static void
dissect_h248(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *h248_item;
    asn1_ctx_t asn1_ctx;
    h248_tree = NULL;
    h248_tvb = NULL;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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

    /* Check if it is actually a text-based H.248 encoding, which we
       dissect with the "megaco" dissector in Wireshark.  (Both
       encodings are MEGACO (RFC 3015) and both are H.248.)
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
        {
			proto_item *hidden_item = NULL;
			guint32 magic_num = 0, offset = 0;
			magic_num = tvb_get_ntohl(tvb, offset);
			hidden_item = proto_tree_add_uint(tree, hf_248_magic_num, tvb, offset, 4, magic_num);
			PROTO_ITEM_SET_HIDDEN(hidden_item);
			if( dissector_try_uint(subdissector_table, magic_num, tvb, pinfo, tree) ) {
				return;
			}
		}
    }

    /* Make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.248");

    if (tree) {
        h248_item = proto_tree_add_item(tree, proto_h248, tvb, 0, -1, ENC_NA);
        h248_tree = proto_item_add_subtree(h248_item, ett_h248);
    }

    dissect_h248_MegacoMessage(FALSE, tvb, 0, &asn1_ctx, h248_tree, -1);

}

/*--- proto_register_h248 ----------------------------------------------*/
void proto_reg_handoff_h248(void);

void proto_register_h248(void) {

    /* List of fields */
    static hf_register_info hf[] = {
		{ &hf_248_magic_num, {
			"Magic Number for Avaya H248", "h248.magic_num", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},
        { &hf_h248_mtpaddress_ni, {
                "NI", "h248.mtpaddress.ni", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},
        { &hf_h248_mtpaddress_pc, {
                "PC", "h248.mtpaddress.pc", FT_UINT32, BASE_DEC,
                NULL, 0, NULL, HFILL }},
		{ &hf_h248_pkg_name, {
                "Package", "h248.package_name", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL }},
        { &hf_248_pkg_param, {
                "Parameter ID", "h248.package_paramid", FT_UINT16, BASE_HEX,
                NULL, 0, NULL, HFILL }},
        { &hf_h248_signal_code, {
                "Signal ID", "h248.package_signalid", FT_UINT16, BASE_HEX,
                NULL, 0, "Parameter ID", HFILL }},
        { &hf_h248_event_code, {
                "Event ID", "h248.package_eventid", FT_UINT16, BASE_HEX,
                NULL, 0, "Parameter ID", HFILL }},
        { &hf_h248_event_name, {
                "Package and Event name", "h248.event_name", FT_UINT32, BASE_HEX,
                NULL, 0, "Package", HFILL }},
        { &hf_h248_signal_name, {
                "Package and Signal name", "h248.signal_name", FT_UINT32, BASE_HEX,
                NULL, 0, "Package", HFILL }},
        { &hf_h248_pkg_bcp_BNCChar_PDU,
          { "BNCChar", "h248.package_bcp.BNCChar",
            FT_UINT32, BASE_DEC, VALS(gcp_term_types), 0,
            NULL, HFILL }},

        { &hf_h248_error_code,
          { "errorCode", "h248.errorCode",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING, &h248_reasons_ext, 0,
            "ErrorDescriptor/errorCode", HFILL }},
        { &hf_h248_context_id,
          { "contextId", "h248.contextId",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Context ID", HFILL }},
        { &hf_h248_term_wild_type,
          { "Wildcard Mode", "h248.term.wildcard.mode",
            FT_UINT8, BASE_DEC, VALS(wildcard_modes), 0x80,
            NULL, HFILL }},
        { &hf_h248_term_wild_level,
          { "Wildcarding Level", "h248.term.wildcard.level",
            FT_UINT8, BASE_DEC, VALS(wildcard_levels), 0x40,
            NULL, HFILL }},
        { &hf_h248_term_wild_position,
          { "Wildcarding Position", "h248.term.wildcard.pos",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }},

        { &hf_h248_no_pkg,
          { "Unknown Package", "h248.pkg.unknown",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_no_sig,
          { "Unknown Signal", "h248.pkg.unknown.sig",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_no_evt,
          { "Unknown Event", "h248.pkg.unknown.evt",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_param,
          { "Parameter", "h248.pkg.unknown.param",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_serviceChangeReasonStr,
          { "ServiceChangeReasonStr", "h248.serviceChangeReasonstr",
            FT_STRING, BASE_NONE, NULL, 0,
            "h248.IA5String", HFILL }},

/* h248v1 support */
        { &hf_h248_auditValueReplyV1,
          { "auditValueReplyV1", "h248.auditValueReplyV1",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},

#include "packet-h248-hfarr.c"

        GCP_HF_ARR_ELEMS("h248",h248_arrel)

    };

    /* List of subtrees */
    static gint *ett[] = {
        &ett_h248,
        &ett_mtpaddress,
        &ett_packagename,
        &ett_codec,
        &ett_wildcard,
        &ett_h248_no_pkg,
        &ett_h248_no_sig,
        &ett_h248_no_evt,
        GCP_ETT_ARR_ELEMS(h248_arrel),

#include "packet-h248-ettarr.c"
    };

    module_t *h248_module;


    /* Register protocol */
    proto_h248 = proto_register_protocol(PNAME, PSNAME, PFNAME);
    register_dissector("h248", dissect_h248, proto_h248);
    register_dissector("h248.tpkt", dissect_h248_tpkt, proto_h248);

    /* Register fields and subtrees */
    proto_register_field_array(proto_h248, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
	
	subdissector_table = register_dissector_table("h248.magic_num", "H248 Magic Num", FT_UINT32, BASE_HEX);

    h248_module = prefs_register_protocol(proto_h248, proto_reg_handoff_h248);
    prefs_register_bool_preference(h248_module, "ctx_info",
                                   "Track Context",
                                   "Mantain relationships between transactions and contexts and display an extra tree showing context data",
                                   &keep_persistent_data);
    prefs_register_uint_preference(h248_module, "udp_port",
                                   "UDP port",
                                   "Port to be decoded as h248",
                                   10,
                                   &global_udp_port);
    prefs_register_uint_preference(h248_module, "tcp_port",
                                   "TCP port",
                                   "Port to be decoded as h248",
                                   10,
                                   &global_tcp_port);
    prefs_register_bool_preference(h248_module, "desegment",
                                   "Desegment H.248 over TCP",
                                   "Desegment H.248 messages that span more TCP segments",
                                   &h248_desegment);

    msgs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "h248_msgs");
    trxs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "h248_trxs");
    ctxs_by_trx = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "h248_ctxs_by_trx");
    ctxs = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "h248_ctxs");

    h248_tap = register_tap("h248");

    gcp_init();
}

/*--- proto_reg_handoff_h248 -------------------------------------------*/
void proto_reg_handoff_h248(void) {

    static gboolean initialized = FALSE;
    static guint32 udp_port;
    static guint32 tcp_port;

    if (!initialized) {
        h248_handle = find_dissector("h248");
        h248_tpkt_handle = find_dissector("h248.tpkt");
        dissector_add_uint("mtp3.service_indicator", MTP_SI_GCP, h248_handle);
        h248_term_handle = find_dissector("h248term");
        initialized = TRUE;
    } else {
        if (udp_port != 0)
            dissector_delete_uint("udp.port", udp_port, h248_handle);

        if (tcp_port != 0)
            dissector_delete_uint("tcp.port", tcp_port, h248_tpkt_handle);
    }

    udp_port = global_udp_port;
    tcp_port = global_tcp_port;

    if (udp_port != 0) {
        dissector_add_uint("udp.port", udp_port, h248_handle);
    }

    if (tcp_port != 0) {
        dissector_add_uint("tcp.port", tcp_port, h248_tpkt_handle);
    }
}

