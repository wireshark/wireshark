/* packet-ppp.c
 * Routines for ppp packet disassembly
 *
 * $Id: packet-ppp.c,v 1.84 2002/01/03 20:30:32 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 *
 * This file created and by Mike Hall <mlh@io.com>
 * Copyright 1998
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
#include "prefs.h"
#include "packet.h"
#include "packet-ppp.h"
#include "ppptypes.h"
#include "etypes.h"
#include "atalk-utils.h"
#include "packet-chdlc.h"
#include "packet-ip.h"
#include "packet-ipx.h"
#include "packet-vines.h"
#include "nlpid.h"

#define ppp_min(a, b)  ((a<b) ? a : b)

static int proto_ppp = -1;
static int hf_ppp_address = -1;
static int hf_ppp_control = -1;
static int hf_ppp_protocol = -1;

static gint ett_ppp = -1;

static int proto_lcp = -1;

static gint ett_lcp = -1;
static gint ett_lcp_options = -1;
static gint ett_lcp_mru_opt = -1;
static gint ett_lcp_async_map_opt = -1;
static gint ett_lcp_authprot_opt = -1;
static gint ett_lcp_qualprot_opt = -1;
static gint ett_lcp_magicnum_opt = -1;
static gint ett_lcp_fcs_alternatives_opt = -1;
static gint ett_lcp_numbered_mode_opt = -1;
static gint ett_lcp_callback_opt = -1;
static gint ett_lcp_multilink_ep_disc_opt = -1;
static gint ett_lcp_internationalization_opt = -1;

static int proto_ipcp = -1;

static gint ett_ipcp = -1;
static gint ett_ipcp_options = -1;
static gint ett_ipcp_ipaddrs_opt = -1;
static gint ett_ipcp_compressprot_opt = -1;

static int proto_ccp = -1;

static gint ett_ccp = -1;
static gint ett_ccp_options = -1;
static gint ett_ccp_stac_opt = -1;
static gint ett_ccp_mppc_opt = -1;
static gint ett_ccp_lzsdcp_opt = -1;

static int proto_cbcp = -1;

static gint ett_cbcp = -1;
static gint ett_cbcp_options = -1;
static gint ett_cbcp_no_callback_opt = -1;
static gint ett_cbcp_callback_opt = -1;

static int proto_bacp = -1;

static gint ett_bacp = -1;
static gint ett_bacp_options = -1;
static gint ett_bacp_favored_peer_opt = -1;

static int proto_bap = -1;

static gint ett_bap = -1;
static gint ett_bap_options = -1;
static gint ett_bap_link_type_opt = -1;
static gint ett_bap_phone_delta_opt = -1;
static gint ett_bap_reason_opt = -1;
static gint ett_bap_link_disc_opt = -1;
static gint ett_bap_call_status_opt = -1;

static int proto_comp_data = -1;

static gint ett_comp_data = -1;

static int proto_pppmuxcp = -1;

static gint ett_pppmuxcp = -1;
static gint ett_pppmuxcp_options = -1;
static gint ett_pppmuxcp_def_pid_opt = -1;

static int proto_pppmux = -1;

static gint ett_pppmux = -1;
static gint ett_pppmux_subframe = -1;
static gint ett_pppmux_subframe_hdr = -1;
static gint ett_pppmux_subframe_flags = -1;
static gint ett_pppmux_subframe_info = -1;

static int proto_mp = -1;
static int hf_mp_frag_first = -1;
static int hf_mp_frag_last = -1;
static int hf_mp_sequence_num = -1;

static int ett_mp = -1;
static int ett_mp_flags = -1;

static int proto_pap			= -1;		/* PAP vars */
static gint ett_pap			= -1;
static gint ett_pap_data		= -1;
static gint ett_pap_peer_id		= -1;
static gint ett_pap_password		= -1;
static gint ett_pap_message		= -1;

static int proto_chap			= -1;		/* CHAP vars */
static gint ett_chap			= -1;
static gint ett_chap_data		= -1;
static gint ett_chap_value		= -1;
static gint ett_chap_name		= -1;
static gint ett_chap_message		= -1;

static dissector_table_t subdissector_table;
static dissector_handle_t chdlc_handle;
static dissector_handle_t data_handle;

/* options */
static gint ppp_fcs_decode = 0; /* 0 = No FCS, 1 = 16 bit FCS, 2 = 32 bit FCS */
#define NO_FCS 0
#define FCS_16 1
#define FCS_32 2
gboolean ppp_vj_decomp = TRUE; /* Default to VJ header decompression */
				
/*
 * For Default Protocol ID negotiated with PPPMuxCP. We need to
 * this ID so that if the first subframe doesn't have protocol
 * ID, we can use it
 */

static guint pppmux_def_prot_id = 0;

/* PPP definitions */

static const value_string ppp_vals[] = {
	{PPP_IP,        "IP"             },
	{PPP_OSI,       "OSI"            },
	{PPP_AT,        "Appletalk"      },
	{PPP_IPX,       "Netware IPX/SPX"},
	{PPP_VJC_COMP,	"VJ compressed TCP"},
	{PPP_VJC_UNCOMP,"VJ uncompressed TCP"},
	{PPP_BPDU,      "Bridging PDU"},
	{PPP_VINES,     "Vines"          },
        {PPP_MP,	"Multilink"},
	{PPP_IPV6,      "IPv6"           },
        {PPP_MUX,       "PPP Multiplexing"},
	{PPP_COMP,	"compressed packet" },
	{PPP_DEC_LB,	"DEC LANBridge100 Spanning Tree"},
	{PPP_MPLS_UNI,  "MPLS Unicast"},
	{PPP_MPLS_MULTI, "MPLS Multicast"},
	{PPP_IPCP,	"IP Control Protocol" },
	{PPP_OSICP,     "OSI Control Protocol" },
	{PPP_ATCP,	"AppleTalk Control Protocol" },
	{PPP_IPXCP,	"IPX Control Protocol" },
	{PPP_MUXCP,     "PPPMux Control Protocol"},
	{PPP_CCP,	"Compression Control Protocol" },
	{PPP_LCP,	"Link Control Protocol" },
	{PPP_PAP,	"Password Authentication Protocol"  },
	{PPP_LQR,	"Link Quality Report protocol" },
	{PPP_SPAP,	"Shiva Password Authentication Protocol" },
	{PPP_CHAP,	"Cryptographic Handshake Auth. Protocol" },
	{PPP_EAP,	"Extensible Authentication Protocol" },
	{PPP_CBCP,	"Callback Control Protocol" },
	{PPP_BACP,	"Bandwidth Allocation Control Protocol" },
	{PPP_BAP,	"Bandwitdh Allocation Protocol" },
	{0,             NULL            }
};

/* CP (LCP, IPCP, etc.) codes.
 * from pppd fsm.h 
 */
#define CONFREQ    1  /* Configuration Request */
#define CONFACK    2  /* Configuration Ack */
#define CONFNAK    3  /* Configuration Nak */
#define CONFREJ    4  /* Configuration Reject */
#define TERMREQ    5  /* Termination Request */
#define TERMACK    6  /* Termination Ack */
#define CODEREJ    7  /* Code Reject */

static const value_string cp_vals[] = {
	{CONFREQ,    "Configuration Request" },
	{CONFACK,    "Configuration Ack" },
	{CONFNAK,    "Configuration Nak" },
	{CONFREJ,    "Configuration Reject" },
	{TERMREQ,    "Termination Request" },
	{TERMACK,    "Termination Ack" },
	{CODEREJ,    "Code Reject" },
	{0,          NULL            } };

/*
 * LCP-specific packet types.
 */
#define PROTREJ    8  /* Protocol Reject */
#define ECHOREQ    9  /* Echo Request */
#define ECHOREP    10 /* Echo Reply */
#define DISCREQ    11 /* Discard Request */
#define IDENT      12 /* Identification */
#define TIMEREMAIN 13 /* Time remaining */

/* 
 * CCP-specific packet types.
 */
#define RESETREQ   14  /* Reset Request */
#define RESETACK   15  /* Reset Ack */

/*
 * CBCP-specific packet types.
 */
#define CBREQ      1  /* Callback Request */
#define CBRES      2  /* Callback Response */
#define CBACK      3  /* Callback Ack */

#define CBCP_OPT  6 /* Use callback control protocol */

/*
 * BAP-specific packet types.
 */
#define BAP_CREQ   1  /* Call Request */
#define BAP_CRES   2  /* Call Response */
#define BAP_CBREQ  3  /* Callback Request */
#define BAP_CBRES  4  /* Callback Response */
#define BAP_LDQREQ 5  /* Link Drop Query Request */
#define BAP_LDQRES 6  /* Link Drop Query Response */
#define BAP_CSI    7  /* Call Status Indication */
#define BAP_CSRES  8  /* Call Status Response */

static const value_string lcp_vals[] = {
	{CONFREQ,    "Configuration Request" },
	{CONFACK,    "Configuration Ack" },
	{CONFNAK,    "Configuration Nak" },
	{CONFREJ,    "Configuration Reject" },
	{TERMREQ,    "Termination Request" },
	{TERMACK,    "Termination Ack" },
	{CODEREJ,    "Code Reject" },
	{PROTREJ,    "Protocol Reject" },
	{ECHOREQ,    "Echo Request" },
	{ECHOREP,    "Echo Reply" },
	{DISCREQ,    "Discard Request" },
	{IDENT,      "Identification" },
	{TIMEREMAIN, "Time Remaining" },
	{0,          NULL }
};

static const value_string ccp_vals[] = {
	{CONFREQ,    "Configuration Request" },
	{CONFACK,    "Configuration Ack" },
	{CONFNAK,    "Configuration Nak" },
	{CONFREJ,    "Configuration Reject" },
	{TERMREQ,    "Termination Request" },
	{TERMACK,    "Termination Ack" },
	{CODEREJ,    "Code Reject" },
	{RESETREQ,   "Reset Request" },
	{RESETACK,   "Reset Ack" },
	{0,          NULL } 
};

static const value_string cbcp_vals[] = {
	{CBREQ,      "Callback Request" },
	{CBRES,      "Callback Response" },
	{CBACK,      "Callback Ack" },
	{0,          NULL } 
};

static const value_string bap_vals[] = {
	{BAP_CREQ,	"Call Request" },
	{BAP_CRES,	"Call Response" },
	{BAP_CBREQ,	"Callback Request" },
	{BAP_CBRES,	"Callback Response" },
	{BAP_LDQREQ,	"Link Drop Query Request" },
	{BAP_LDQRES,	"Link Drop Query Response" },
	{BAP_CSI,	"Call Status Indication" },
	{BAP_CSRES,	"Call Status Response" },
	{0,		NULL }
};

#define BAP_RESP_CODE_REQACK	0x00
#define BAP_RESP_CODE_REQNAK	0x01
#define BAP_RESP_CODE_REQREJ	0x02
#define BAP_RESP_CODE_REQFULLNAK	0x03
static const value_string bap_resp_code_vals[] = {
	{BAP_RESP_CODE_REQACK,	"Request Ack" },
	{BAP_RESP_CODE_REQNAK,	"Request Nak" },
	{BAP_RESP_CODE_REQREJ,	"Request Rej" },
	{BAP_RESP_CODE_REQFULLNAK,	"Request Full Nak" },
	{0,			NULL }
};

#define BAP_LINK_TYPE_ISDN	0	/* ISDN */
#define BAP_LINK_TYPE_X25	1	/* X.25 */
#define BAP_LINK_TYPE_ANALOG	2	/* Analog */
#define BAP_LINK_TYPE_SD	3	/* Switched Digital (non-ISDN) */
#define BAP_LINK_TYPE_ISDNOV	4	/* ISDN data over voice */
#define BAP_LINK_TYPE_RESV5	5	/* Reserved */
#define BAP_LINK_TYPE_RESV6	6	/* Reserved */
#define BAP_LINK_TYPE_RESV7	7	/* Reserved */
static const value_string bap_link_type_vals[] = {
	{BAP_LINK_TYPE_ISDN,	"ISDN" },
	{BAP_LINK_TYPE_X25,	"X.25" },
	{BAP_LINK_TYPE_ANALOG,	"Analog" },
	{BAP_LINK_TYPE_SD,	"Switched Digital (non-ISDN)" },
	{BAP_LINK_TYPE_ISDNOV,	"ISDN data over voice" },
	{BAP_LINK_TYPE_RESV5,	"Reserved" },
	{BAP_LINK_TYPE_RESV6,	"Reserved" },
	{BAP_LINK_TYPE_RESV7,	"Reserved" },
	{0,			NULL }
};

#define BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT	1	/* Unique Digit */
#define BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM	2	/* Subscriber Number */
#define BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR	3 /* Phone Number Sub Address */
static const value_string bap_phone_delta_subopt_vals[] = {
	{BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT,	"Unique Digit" },
	{BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM,	"Subscriber Number" },
	{BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR, "Phone Number Sub Address" },
	{0,					NULL }
};

/*
 * Cause codes for Cause.
 *
 * The following code table is taken from packet-q931.c but is slightly 
 * adapted to BAP protocol.
 */
static const value_string q931_cause_code_vals[] = {
	{ 0x00,	"Call successful" },
	{ 0x01,	"Unallocated (unassigned) number" },
	{ 0x02,	"No route to specified transit network" },
	{ 0x03,	"No route to destination" },
	{ 0x04,	"Send special information tone" },
	{ 0x05,	"Misdialled trunk prefix" },
	{ 0x06,	"Channel unacceptable" },
	{ 0x07,	"Call awarded and being delivered in an established channel" },
	{ 0x08,	"Prefix 0 dialed but not allowed" },
	{ 0x09,	"Prefix 1 dialed but not allowed" },
	{ 0x0A,	"Prefix 1 dialed but not required" },
	{ 0x0B,	"More digits received than allowed, call is proceeding" },
	{ 0x10,	"Normal call clearing" },
	{ 0x11,	"User busy" },
	{ 0x12,	"No user responding" },
	{ 0x13,	"No answer from user (user alerted)" },
	{ 0x14,	"Subscriber absent" },
	{ 0x15,	"Call rejected" },
	{ 0x16,	"Number changed" },
	{ 0x17,	"Reverse charging rejected" },
	{ 0x18,	"Call suspended" },
	{ 0x19,	"Call resumed" },
	{ 0x1A,	"Non-selected user clearing" },
	{ 0x1B,	"Destination out of order" },
	{ 0x1C,	"Invalid number format (incomplete number)" },
	{ 0x1D,	"Facility rejected" },
	{ 0x1E,	"Response to STATUS ENQUIRY" },
	{ 0x1F,	"Normal unspecified" },
	{ 0x21,	"Circuit out of order" },
	{ 0x22,	"No circuit/channel available" },
	{ 0x23,	"Destination unattainable" },
	{ 0x25,	"Degraded service" },
	{ 0x26,	"Network out of order" },
	{ 0x27,	"Transit delay range cannot be achieved" },
	{ 0x28,	"Throughput range cannot be achieved" },
	{ 0x29,	"Temporary failure" },
	{ 0x2A,	"Switching equipment congestion" },
	{ 0x2B,	"Access information discarded" },
	{ 0x2C,	"Requested circuit/channel not available" },
	{ 0x2D,	"Pre-empted" },
	{ 0x2E,	"Precedence call blocked" },
	{ 0x2F,	"Resources unavailable, unspecified" },
	{ 0x31,	"Quality of service unavailable" },
	{ 0x32,	"Requested facility not subscribed" },
	{ 0x33,	"Reverse charging not allowed" },
	{ 0x34,	"Outgoing calls barred" },
	{ 0x35,	"Outgoing calls barred within CUG" },
	{ 0x36,	"Incoming calls barred" },
	{ 0x37,	"Incoming calls barred within CUG" },
	{ 0x38,	"Call waiting not subscribed" },
	{ 0x39,	"Bearer capability not authorized" },
	{ 0x3A,	"Bearer capability not presently available" },
	{ 0x3E,	"Inconsistency in designated outgoing access information and subscriber class" },
	{ 0x3F,	"Service or option not available, unspecified" },
	{ 0x41,	"Bearer capability not implemented" },
	{ 0x42,	"Channel type not implemented" },
	{ 0x43,	"Transit network selection not implemented" },
	{ 0x44,	"Message not implemented" },
	{ 0x45,	"Requested facility not implemented" },
	{ 0x46,	"Only restricted digital information bearer capability is available" },
	{ 0x4F,	"Service or option not implemented, unspecified" },
	{ 0x51,	"Invalid call reference value" },
	{ 0x52,	"Identified channel does not exist" },
	{ 0x53,	"Call identity does not exist for suspended call" },
	{ 0x54,	"Call identity in use" },
	{ 0x55,	"No call suspended" },
	{ 0x56,	"Call having the requested call identity has been cleared" },
	{ 0x57,	"Called user not member of CUG" },
	{ 0x58,	"Incompatible destination" },
	{ 0x59,	"Non-existent abbreviated address entry" },
	{ 0x5A,	"Destination address missing, and direct call not subscribed" },
	{ 0x5B,	"Invalid transit network selection (national use)" },
	{ 0x5C,	"Invalid facility parameter" },
	{ 0x5D,	"Mandatory information element is missing" },
	{ 0x5F,	"Invalid message, unspecified" },
	{ 0x60,	"Mandatory information element is missing" },
	{ 0x61,	"Message type non-existent or not implemented" },
	{ 0x62,	"Message not compatible with call state or message type non-existent or not implemented" },
	{ 0x63,	"Information element nonexistant or not implemented" },
	{ 0x64,	"Invalid information element contents" },
	{ 0x65,	"Message not compatible with call state" },
	{ 0x66,	"Recovery on timer expiry" },
	{ 0x67,	"Parameter non-existent or not implemented - passed on" },
	{ 0x6E,	"Message with unrecognized parameter discarded" },
	{ 0x6F,	"Protocol error, unspecified" },
	{ 0x7F,	"Internetworking, unspecified" },
	{ 0xFF, "Non-specific failure" },
	{ 0,	NULL }
};

static const value_string bap_call_status_opt_action_vals[] = {
	{0,	"No retry" },
	{1,	"Retry" },
	{0,	NULL }
};

#define STAC_CM_NONE		0
#define STAC_CM_LCB		1
#define	STAC_CM_CRC		2
#define	STAC_CM_SN		3
#define STAC_CM_EXTMODE		4
static const value_string stac_checkmode_vals[] = {
	{STAC_CM_NONE,		"None" },
	{STAC_CM_LCB,		"LCB" },
	{STAC_CM_CRC,		"CRC" },
	{STAC_CM_SN,		"Sequence Number" },
	{STAC_CM_EXTMODE,	"Extended Mode" },
	{0,			NULL }
};

#define LZSDCP_CM_NONE		0
#define LZSDCP_CM_LCB		1
#define	LZSDCP_CM_SN		2
#define	LZSDCP_CM_SN_LCB	3
static const value_string lzsdcp_checkmode_vals[] = {
	{LZSDCP_CM_NONE,	"None" },
	{LZSDCP_CM_LCB,		"LCB" },
	{LZSDCP_CM_SN,		"Sequence Number" },
	{LZSDCP_CM_SN_LCB,	"Sequence Number + LCB" },
	{0,			NULL }
};

#define LZSDCP_PM_NONE		0
#define LZSDCP_PM_PROC_UNCOMP	1
static const value_string lzsdcp_processmode_vals[] = {
	{LZSDCP_PM_NONE,	"None" },
	{LZSDCP_PM_PROC_UNCOMP,	"Process-Uncompressed" },
	{0,			NULL }
};

/*
 * Options.  (LCP)
 */
#define CI_MRU			1	/* Maximum Receive Unit */
#define CI_ASYNCMAP		2	/* Async Control Character Map */
#define CI_AUTHTYPE		3	/* Authentication Type */
#define CI_QUALITY		4	/* Quality Protocol */
#define CI_MAGICNUMBER		5	/* Magic Number */
#define CI_PCOMPRESSION		7	/* Protocol Field Compression */
#define CI_ACCOMPRESSION	8	/* Address/Control Field Compression */
#define CI_FCS_ALTERNATIVES	9	/* FCS Alternatives (RFC 1570) */
#define CI_SELF_DESCRIBING_PAD	10	/* Self-Describing Pad (RFC 1570) */
#define CI_NUMBERED_MODE	11	/* Numbered Mode (RFC 1663) */
#define CI_CALLBACK		13	/* Callback (RFC 1570) */
#define CI_COMPOUND_FRAMES	15	/* Compound frames (RFC 1570) */
#define CI_MULTILINK_MRRU	17	/* Multilink MRRU (RFC 1717) */
#define CI_MULTILINK_SSNH	18	/* Multilink Short Sequence Number
					   Header (RFC 1717) */
#define CI_MULTILINK_EP_DISC	19	/* Multilink Endpoint Discriminator
					   (RFC 1717) */
#define CI_DCE_IDENTIFIER	21	/* DCE Identifier */
#define CI_MULTILINK_PLUS_PROC	22	/* Multilink Plus Procedure */
#define CI_LINK_DISC_FOR_BACP	23	/* Link Discriminator for BACP
					   (RFC 2125) */
#define CI_LCP_AUTHENTICATION	24	/* LCP Authentication Option */
#define CI_COBS			25	/* Consistent Overhead Byte
					   Stuffing */
#define CI_PREFIX_ELISION	26	/* Prefix elision */
#define CI_MULTILINK_HDR_FMT	27	/* Multilink header format */
#define CI_INTERNATIONALIZATION	28	/* Internationalization (RFC 2484) */
#define	CI_SDL_ON_SONET_SDH	29	/* Simple Data Link on SONET/SDH */

static void dissect_lcp_mru_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree);
static void dissect_lcp_async_map_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree);
static void dissect_lcp_protocol_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree);
static void dissect_lcp_authprot_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree);
static void dissect_lcp_magicnumber_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			packet_info *pinfo, proto_tree *tree);
static void dissect_lcp_fcs_alternatives_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			packet_info *pinfo, proto_tree *tree);
static void dissect_lcp_numbered_mode_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			packet_info *pinfo, proto_tree *tree);
static void dissect_lcp_self_describing_pad_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			packet_info *pinfo, proto_tree *tree);
static void dissect_lcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree);
static void dissect_lcp_multilink_mrru_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			packet_info *pinfo, proto_tree *tree);
static void dissect_lcp_multilink_ep_disc_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			packet_info *pinfo, proto_tree *tree);
static void dissect_lcp_bap_link_discriminator_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			packet_info *pinfo, proto_tree *tree);
static void dissect_lcp_internationalization_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			packet_info *pinfo, proto_tree *tree);
static void dissect_mp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static const ip_tcp_opt lcp_opts[] = {
	{
		CI_MRU,
		"Maximum Receive Unit",
		&ett_lcp_mru_opt,
		FIXED_LENGTH,
		4,
		dissect_lcp_mru_opt
	},
	{
		CI_ASYNCMAP,
		"Async Control Character Map",
		&ett_lcp_async_map_opt,
		FIXED_LENGTH,
		6,
		dissect_lcp_async_map_opt
	},
	{
		CI_AUTHTYPE,
		"Authentication protocol",
		&ett_lcp_authprot_opt,
		VARIABLE_LENGTH,
		4,
		dissect_lcp_authprot_opt
	},
	{
		CI_QUALITY,
		"Quality protocol",
		&ett_lcp_qualprot_opt,
		VARIABLE_LENGTH,
		4,
		dissect_lcp_protocol_opt
	},
	{
		CI_MAGICNUMBER,
		NULL,
		&ett_lcp_magicnum_opt,
		FIXED_LENGTH,
		6,
		dissect_lcp_magicnumber_opt
	},
	{
		CI_PCOMPRESSION,
		"Protocol field compression",
		NULL,
		FIXED_LENGTH,
		2,
		NULL
	},
	{
		CI_ACCOMPRESSION,
		"Address/control field compression",
		NULL,
		FIXED_LENGTH,
		2,
		NULL
	},
	{
		CI_FCS_ALTERNATIVES,
		NULL,
		&ett_lcp_fcs_alternatives_opt,
		FIXED_LENGTH,
		3,
		dissect_lcp_fcs_alternatives_opt
	},
	{
		CI_SELF_DESCRIBING_PAD,
		NULL,
		NULL,
		FIXED_LENGTH,
		3,
		dissect_lcp_self_describing_pad_opt
	},
	{
		CI_NUMBERED_MODE,
		"Numbered mode",
		&ett_lcp_numbered_mode_opt,
		VARIABLE_LENGTH,
		4,
		dissect_lcp_numbered_mode_opt
	},
	{
		CI_CALLBACK,
		"Callback",
		&ett_lcp_callback_opt,
		VARIABLE_LENGTH,
		3,
		dissect_lcp_callback_opt,
	},
	{
		CI_COMPOUND_FRAMES,
		"Compound frames",
		NULL,
		FIXED_LENGTH,
		2,
		NULL
	},
	{
		CI_MULTILINK_MRRU,
		NULL,
		NULL,
		FIXED_LENGTH,
		4,
		dissect_lcp_multilink_mrru_opt
	},
	{
		CI_MULTILINK_SSNH,
		"Use short sequence number headers",
		NULL,
		FIXED_LENGTH,
		2,
		NULL
	},
	{
		CI_MULTILINK_EP_DISC,
		"Multilink endpoint discriminator",
		&ett_lcp_multilink_ep_disc_opt,
		VARIABLE_LENGTH,
		3,
		dissect_lcp_multilink_ep_disc_opt,
	},
	{
		CI_DCE_IDENTIFIER,
		"DCE identifier",
		NULL,
		VARIABLE_LENGTH,
		2,
		NULL
	},
	{
		CI_MULTILINK_PLUS_PROC,
		"Multilink Plus Procedure",
		NULL,
		VARIABLE_LENGTH,
		2,
		NULL
	},
	{
		CI_LINK_DISC_FOR_BACP,
		NULL,
		NULL,
		FIXED_LENGTH,
		4,
		dissect_lcp_bap_link_discriminator_opt
	},
	{
		CI_LCP_AUTHENTICATION,
		"LCP authentication",
		NULL,
		VARIABLE_LENGTH,
		2,
		NULL
	},
	{
		CI_COBS,
		"Consistent Overhead Byte Stuffing",
		NULL,
		VARIABLE_LENGTH,
		2,
		NULL
	},
	{
		CI_PREFIX_ELISION,
		"Prefix elision",
		NULL,
		VARIABLE_LENGTH,
		2,
		NULL
	},
	{
		CI_MULTILINK_HDR_FMT,
		"Multilink header format",
		NULL,
		VARIABLE_LENGTH,
		2,
		NULL
	},
	{
		CI_INTERNATIONALIZATION,
		"Internationalization",
		&ett_lcp_internationalization_opt,
		VARIABLE_LENGTH,
		7,
		dissect_lcp_internationalization_opt
	},
	{
		CI_SDL_ON_SONET_SDH,
		"Simple data link on SONET/SDH",
		NULL,
		VARIABLE_LENGTH,
		2,
		NULL
	}
};

#define N_LCP_OPTS	(sizeof lcp_opts / sizeof lcp_opts[0])

/* 
 * CHAP Algorithms
 */
#define CHAP_ALG_MD5	0x05	/* CHAP with MD5 */
#define CHAP_ALG_MSV1	0x80	/* MS-CHAPv1 */
#define CHAP_ALG_MSV2	0x81	/* MS-CHAPv2 */

static const value_string chap_alg_vals[] = {
	{CHAP_ALG_MD5,	"CHAP with MD5" },
	{CHAP_ALG_MSV1,	"MS-CHAP" },
	{CHAP_ALG_MSV2,	"MS-CHAP-2" },
	{0,          	NULL }
};


/*
 * Options.  (IPCP)
 */
#define CI_ADDRS	1	/* IP Addresses (deprecated) (RFC 1172) */
#define CI_COMPRESSTYPE	2	/* Compression Type (RFC 1332) */
#define CI_ADDR		3	/* IP Address (RFC 1332) */
#define CI_MOBILE_IPv4	4	/* Mobile IPv4 (RFC 2290) */
#define CI_MS_DNS1	129	/* Primary DNS value (RFC 1877) */
#define CI_MS_WINS1	130	/* Primary WINS value (RFC 1877) */
#define CI_MS_DNS2	131	/* Secondary DNS value (RFC 1877) */
#define CI_MS_WINS2	132	/* Secondary WINS value (RFC 1877) */

static void dissect_ipcp_addrs_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree);
static void dissect_ipcp_addr_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static const ip_tcp_opt ipcp_opts[] = {
	{
		CI_ADDRS,
		"IP addresses (deprecated)",
		&ett_ipcp_ipaddrs_opt,
		FIXED_LENGTH,
		10,
		dissect_ipcp_addrs_opt
	},
	{
		CI_COMPRESSTYPE,
		"IP compression protocol",
		&ett_ipcp_compressprot_opt,
		VARIABLE_LENGTH,
		4,
		dissect_lcp_protocol_opt
	},
	{
		CI_ADDR,
		"IP address",
		NULL,
		FIXED_LENGTH,
		6,
		dissect_ipcp_addr_opt
	},
	{
		CI_MOBILE_IPv4,
		"Mobile node's home IP address",
		NULL,
		FIXED_LENGTH,
		6,
		dissect_ipcp_addr_opt
	},
	{
		CI_MS_DNS1,
		"Primary DNS server IP address",
		NULL,
		FIXED_LENGTH,
		6,
		dissect_ipcp_addr_opt
	},
	{
		CI_MS_WINS1,
		"Primary WINS server IP address",
		NULL,
		FIXED_LENGTH,
		6,
		dissect_ipcp_addr_opt
	},
	{
		CI_MS_DNS2,
		"Secondary DNS server IP address",
		NULL,
		FIXED_LENGTH,
		6,
		dissect_ipcp_addr_opt
	},
	{
		CI_MS_WINS2,
		"Secondary WINS server IP address",
		NULL,
		FIXED_LENGTH,
		6,
		dissect_ipcp_addr_opt
	}
};

#define N_IPCP_OPTS	(sizeof ipcp_opts / sizeof ipcp_opts[0])

/*
 * Options.  (CCP)
 */
#define CI_CCP_OUI	0	/* OUI (RFC1962) */
#define CI_CCP_PREDICT1	1	/* Predictor type 1 (RFC1962) */
#define CI_CCP_PREDICT2	2	/* Predictor type 2 (RFC1962) */
#define CI_CCP_PUDDLE	3	/* Puddle Jumper (RFC1962) */
#define CI_CCP_HPPPC	16	/* Hewlett-Packard PPC (RFC1962) */
#define CI_CCP_STAC	17	/* stac Electronics LZS (RFC1974) */
#define CI_CCP_MPPC	18	/* Microsoft PPC (RFC2218/3078) */
#define CI_CCP_GFZA	19	/* Gandalf FZA */
#define CI_CCP_V42BIS	20	/* V.42bis compression */
#define CI_CCP_BSDLZW	21	/* BSD LZW Compress */
#define CI_CCP_LZSDCP	23	/* LZS-DCP (RFC1967) */
#define CI_CCP_MVRCA	24	/* MVRCA (Magnalink) (RFC1975) */
#define CI_CCP_DEFLATE	26	/* Deflate (RFC1979) */
#define CI_CCP_RESERVED	255	/* Reserved (RFC1962) */

/*
 * Microsoft Point-To-Point Compression (MPPC) and Encryption (MPPE) 
 * supported bits.
 */
#define MPPC_SUPPORTED_BITS_C	0x00000001	/* MPPC negotiation */
#define MPPE_SUPPORTED_BITS_D	0x00000010	/* Obsolete */
#define MPPE_SUPPORTED_BITS_L	0x00000020	/* 40-bit encryption */
#define MPPE_SUPPORTED_BITS_S	0x00000040	/* 128-bit encryption */
#define MPPE_SUPPORTED_BITS_M	0x00000080	/* 56-bit encryption */
#define MPPE_SUPPORTED_BITS_H	0x01000000	/* stateless mode */

static void dissect_ccp_stac_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_ccp_mppc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_ccp_lzsdcp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static const ip_tcp_opt ccp_opts[] = {
	{
		CI_CCP_STAC,
		"Stac Electronics LZS",
		&ett_ccp_stac_opt,
		VARIABLE_LENGTH,
		5,
		/* In RFC 1974, this is a fixed-length field of size 5,
		   but in Ascend Proprietary STAC compression this field
		   is 6 octets. Sigh... */
		dissect_ccp_stac_opt
	},
	{
		CI_CCP_MPPC,
		"Microsoft PPC",
		&ett_ccp_mppc_opt,
		FIXED_LENGTH,
		6,
		dissect_ccp_mppc_opt
	},
	{
		CI_CCP_LZSDCP,
		"LZS-DCP",
		&ett_ccp_lzsdcp_opt,
		FIXED_LENGTH,
		6,
		dissect_ccp_lzsdcp_opt
	}

};

#define N_CCP_OPTS	(sizeof ccp_opts / sizeof ccp_opts[0])

/*
 * Options.  (CBCP)
 */
#define CI_CBCP_NO_CALLBACK	1  /* No callback */
#define CI_CBCP_CB_USER		2  /* Callback to a user-specified number */
#define CI_CBCP_CB_PRE		3  /* Callback to a pre-specified or 
                                            administrator specified number */
#define CI_CBCP_CB_ANY		4  /* Callback to any of a list of numbers */

static void dissect_cbcp_no_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_cbcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static const ip_tcp_opt cbcp_opts[] = {
	{
		CI_CBCP_NO_CALLBACK,
		"No callback",
		&ett_cbcp_no_callback_opt,
		FIXED_LENGTH,
		2,
		dissect_cbcp_no_callback_opt
	},
	{
		CI_CBCP_CB_USER,
		"Callback to a user-specified number",
		&ett_cbcp_callback_opt,
		VARIABLE_LENGTH,
		4,
		dissect_cbcp_callback_opt
	},
	{
		CI_CBCP_CB_PRE,
		"Callback to a pre-specified or admin-specified number",
		&ett_cbcp_callback_opt,
		FIXED_LENGTH,
		3,
		dissect_cbcp_callback_opt
	},
	{
		CI_CBCP_CB_ANY,
		"Callback to any of a list of numbers",
		&ett_cbcp_callback_opt,
		VARIABLE_LENGTH,
		4,
		dissect_cbcp_callback_opt
	}

};

#define N_CBCP_OPTS	(sizeof cbcp_opts / sizeof cbcp_opts[0])

/*
 * Options.  (BACP)
 */
#define CI_BACP_FAVORED_PEER	1  /* Favored-Peer */

static void dissect_bacp_favored_peer_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static const ip_tcp_opt bacp_opts[] = {
	{
		CI_BACP_FAVORED_PEER,
		"Favored-Peer",
		&ett_bacp_favored_peer_opt,
		FIXED_LENGTH,
		6,
		dissect_bacp_favored_peer_opt
	}
};

#define N_BACP_OPTS	(sizeof bacp_opts / sizeof bacp_opts[0])

/*
 * Options.  (BAP)
 */
#define CI_BAP_LINK_TYPE	1  /* Link Type */
#define CI_BAP_PHONE_DELTA	2  /* Phone-Delta */
#define CI_BAP_NO_PHONE_NUM_NEEDED	3  /* No Phone Number Needed */
#define CI_BAP_REASON		4  /* Reason */
#define CI_BAP_LINK_DISC	5  /* Link Discriminator */
#define CI_BAP_CALL_STATUS	6  /* Call Status */

static void dissect_bap_link_type_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_bap_phone_delta_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_bap_link_disc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_bap_reason_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_bap_call_status_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static const ip_tcp_opt bap_opts[] = {
	{
		CI_BAP_LINK_TYPE,
		"Link Type",
		&ett_bap_link_type_opt,
		FIXED_LENGTH,
		5,
		dissect_bap_link_type_opt
	},
	{
		CI_BAP_PHONE_DELTA,
		"Phone Delta",
		&ett_bap_phone_delta_opt,
		VARIABLE_LENGTH,
		4,
		dissect_bap_phone_delta_opt
	},
	{
		CI_BAP_NO_PHONE_NUM_NEEDED,
		"No Phone Number Needed",
		NULL,
		FIXED_LENGTH,
		2,
		NULL
	},
	{
		CI_BAP_REASON,
		"Reason",
		&ett_bap_reason_opt,
		VARIABLE_LENGTH,
		2,
		dissect_bap_reason_opt
	},
	{
		CI_BAP_LINK_DISC,
		"Link Discriminator",
		&ett_bap_link_disc_opt,
		FIXED_LENGTH,
		4,
		dissect_bap_link_disc_opt
	},
	{
		CI_BAP_CALL_STATUS,
		"Call Status",
		&ett_bap_call_status_opt,
		FIXED_LENGTH,
		4,
		dissect_bap_call_status_opt
	}
};

#define N_BAP_OPTS	(sizeof bap_opts / sizeof bap_opts[0])

static void dissect_ppp(tvbuff_t *tvb, packet_info *pinfo, 
    proto_tree *tree);

static const value_string pap_vals[] = {
	{CONFREQ,    "Authenticate-Request" },
	{CONFACK,    "Authenticate-Ack" },
	{CONFNAK,    "Authenticate-Nak" },
	{0,          NULL            } };

static void dissect_pap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#define CHAP_CHAL  1  /* CHAP Challenge */
#define CHAP_RESP  2  /* CHAP Response */
#define CHAP_SUCC  3  /* CHAP Success */
#define CHAP_FAIL  4  /* CHAP Failure */

static const value_string chap_vals[] = {
	{CHAP_CHAL,  "Challenge" },
	{CHAP_RESP,  "Response" },
	{CHAP_SUCC,  "Success" },
        {CHAP_FAIL,  "Failure" },
	{0,          NULL            } };

static void dissect_chap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static const value_string pppmuxcp_vals[] = {
	{CONFREQ,    "Configuration Request" },
	{CONFACK,    "Configuration Ack" },
	{0,          NULL}
};

/*
 * PPPMuxCP options
 */

#define CI_DEFAULT_PID   1

static void dissect_pppmuxcp_def_pid_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo, proto_tree *tree);


static const ip_tcp_opt pppmuxcp_opts[] = {
	{
		CI_DEFAULT_PID,
		"Default Protocol ID",
		&ett_pppmuxcp_def_pid_opt,
		FIXED_LENGTH,
		4,
		dissect_pppmuxcp_def_pid_opt
	}
};

#define N_PPPMUXCP_OPTS (sizeof pppmuxcp_opts / sizeof pppmuxcp_opts[0])

const unsigned int fcstab_32[256] =
      {
      0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
      0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
      0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
      0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
      0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
      0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
      0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
      0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
      0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
      0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
      0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
      0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
      0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
      0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
      0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
      0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
      0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
      0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
      0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
      0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
      0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
      0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
      0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
      0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
      0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
      0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
      0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
      0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
      0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
      0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
      0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
      0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
      0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
      0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
      0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
      0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
      0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
      0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
      0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
      0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
      0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
      0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
      0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
      0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
      0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
      0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
      0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
      0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
      0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
      0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
      0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
      0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
      0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
      0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
      0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
      0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
      0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
      0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
      0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
      0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
      0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
      0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
      0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
      0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
      };

const unsigned short fcstab_16[256] = {
        0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
        0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
        0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
        0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
        0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
        0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
        0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
        0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
        0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
        0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
        0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
        0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
        0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
        0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
        0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
        0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
        0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
        0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
        0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
        0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
        0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
        0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
        0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
        0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
        0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
        0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
        0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
        0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
        0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
        0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
        0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
        0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
    };
  
/*
*******************************************************************************
* DETAILS : Calculate a new FCS-16 given the current FCS-16 and the new data.
*******************************************************************************
*/
guint16
fcs16(register guint16 fcs,
         tvbuff_t * tvbuff,
         guint32 offset,
         guint32 len)
{
    guint8 val;

    /* Check for Invalid Length */
    if (len == 0)
        return (0x0000);
    while (len--) {
	val = tvb_get_guint8(tvbuff, offset++);
	fcs = (guint16)((fcs >> 8) & 0x00ff) ^
            fcstab_16[((guint16)(fcs ^ (guint16)((val) & 0x00ff)) & 0x00ff)];
    }

    return (fcs ^ 0xffff);
}
  
/*
*******************************************************************************
* DETAILS : Calculate a new FCS-32 given the current FCS-32 and the new data.
*******************************************************************************
*/
guint32
fcs32(guint32 fcs,
         tvbuff_t * tvbuff,
         guint32 offset,
         guint32 len)
{
    guint8 val;

    /* Check for invalid Length */
    if (len == 0)
        return (0x00000000);

    while (len--) {
	val = tvb_get_guint8(tvbuff, offset++);
	fcs = (((fcs) >> 8) ^ fcstab_32[((fcs) ^ (val)) & 0xff]);
    }
    return (fcs ^ 0xffffffff);
}

void
capture_ppp_hdlc( const u_char *pd, int offset, int len, packet_counts *ld ) {
  if (!BYTES_ARE_IN_FRAME(offset, len, 2)) {
    ld->other++;
    return;
  }
  if (pd[0] == CHDLC_ADDR_UNICAST || pd[0] == CHDLC_ADDR_MULTICAST) {
    capture_chdlc(pd, offset, len, ld);
    return;
  }
  if (!BYTES_ARE_IN_FRAME(offset, len, 4)) {
    ld->other++;
    return;
  }
  switch (pntohs(&pd[offset + 2])) {
    case PPP_IP:
      capture_ip(pd, offset + 4, len, ld);
      break;
    case PPP_IPX:
      capture_ipx(pd, offset + 4, len, ld);
      break;
    case PPP_VINES:
      capture_vines(pd, offset + 4, len, ld);
      break;
    default:
      ld->other++;
      break;
  }
}

static void
dissect_lcp_mru_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, packet_info *pinfo, proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "MRU: %u",
			tvb_get_ntohs(tvb, offset + 2));
}

static void
dissect_lcp_async_map_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, packet_info *pinfo, proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "Async characters to map: 0x%08x",
			tvb_get_ntohl(tvb, offset + 2));
}

static void
dissect_lcp_protocol_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, packet_info *pinfo, proto_tree *tree)
{
  guint16 protocol;
  proto_item *tf;
  proto_tree *field_tree = NULL;
  
  tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u byte%s",
	  optp->name, length, plurality(length, "", "s"));
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;
  length -= 2;
  protocol = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(field_tree, tvb, offset, 2, "%s: %s (0x%02x)", optp->name,
		val_to_str(protocol, ppp_vals, "Unknown"), protocol);
  offset += 2;
  length -= 2;
  if (length > 0)
    proto_tree_add_text(field_tree, tvb, offset, length, "Data (%d byte%s)", length,
    			plurality(length, "", "s"));
}

static void
dissect_lcp_authprot_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			 guint length, packet_info *pinfo, proto_tree *tree)
{
  guint16 protocol;
  guint8 algorithm;
  proto_item *tf;
  proto_tree *field_tree = NULL;
  
  tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u byte%s",
	  optp->name, length, plurality(length, "", "s"));
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;
  length -= 2;
  protocol = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(field_tree, tvb, offset, 2, "%s: %s (0x%02x)", optp->name,
		val_to_str(protocol, ppp_vals, "Unknown"), protocol);
  offset += 2;
  length -= 2;
  if (length > 0) {
    if (protocol == PPP_CHAP) {
      algorithm = tvb_get_guint8(tvb, offset);
      proto_tree_add_text(field_tree, tvb, offset, length, 
			  "Algorithm: %s (0x%02x)", 
			  val_to_str(algorithm, chap_alg_vals, "Unknown"), 
			  algorithm);
      offset++;
    } else {
      proto_tree_add_text(field_tree, tvb, offset, length, "Data (%d byte%s)", length,
    			plurality(length, "", "s"));
    }
  }
}

static void
dissect_lcp_magicnumber_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "Magic number: 0x%08x",
			tvb_get_ntohl(tvb, offset + 2));
}

static void
dissect_lcp_fcs_alternatives_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree = NULL;
  guint8 alternatives;
  
  alternatives = tvb_get_guint8(tvb, offset + 2);
  tf = proto_tree_add_text(tree, tvb, offset, length, "%s: 0x%02x",
	  optp->name, alternatives);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;
  if (alternatives & 0x1)
    proto_tree_add_text(field_tree, tvb, offset + 2, 1, "%s",
       decode_boolean_bitfield(alternatives, 0x1, 8, "Null FCS", NULL));
  if (alternatives & 0x2)
    proto_tree_add_text(field_tree, tvb, offset + 2, 1, "%s",
       decode_boolean_bitfield(alternatives, 0x2, 8, "CCITT 16-bit FCS", NULL));
  if (alternatives & 0x4)
    proto_tree_add_text(field_tree, tvb, offset + 2, 1, "%s",
       decode_boolean_bitfield(alternatives, 0x4, 8, "CCITT 32-bit FCS", NULL));
}

static void
dissect_lcp_self_describing_pad_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length,
			"Maximum octets of self-describing padding: %u",
			tvb_get_guint8(tvb, offset + 2));
}

static void
dissect_lcp_numbered_mode_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree = NULL;
  
  tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u byte%s",
	  optp->name, length, plurality(length, "", "s"));
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;
  length -= 2;
  proto_tree_add_text(field_tree, tvb, offset, 1, "Window: %u",
			tvb_get_guint8(tvb, offset));
  offset += 1;
  length -= 1;
  if (length > 0)
    proto_tree_add_text(field_tree, tvb, offset, length, "Address (%d byte%s)",
			length, plurality(length, "", "s"));
}

static const value_string callback_op_vals[] = {
	{0, "Location is determined by user authentication" },
	{1, "Message is dialing string" },
	{2, "Message is location identifier" },
	{3, "Message is E.164" },
	{4, "Message is distinguished name" },
	{5, "unassigned"},
	{6, "Location is determined during CBCP negotiation" },
	{0, NULL }
};

static void
dissect_lcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, packet_info *pinfo, proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree = NULL;
  guint8 operation;
  
  tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u byte%s",
	  optp->name, length, plurality(length, "", "s"));
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;
  length -= 2;
  operation = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(field_tree, tvb, offset, 1, "Operation: %s (0x%02x)",
		val_to_str(operation, callback_op_vals, "Unknown"),
		operation);
  offset += 1;
  length -= 1;
  if (length > 0)
    proto_tree_add_text(field_tree, tvb, offset, length, "Message (%d byte%s)",
			length, plurality(length, "", "s"));
}

static void
dissect_lcp_multilink_mrru_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "Multilink MRRU: %u",
			tvb_get_ntohs(tvb, offset + 2));
}

#define CLASS_NULL			0
#define CLASS_LOCAL			1
#define CLASS_IP			2
#define CLASS_IEEE_802_1		3
#define CLASS_PPP_MAGIC_NUMBER		4
#define CLASS_PSDN_DIRECTORY_NUMBER	5

static const value_string multilink_ep_disc_class_vals[] = {
	{CLASS_NULL,                  "Null" },
	{CLASS_LOCAL,                 "Locally assigned address" },
	{CLASS_IP,                    "IP address" },
	{CLASS_IEEE_802_1,            "IEEE 802.1 globally assigned MAC address" },
	{CLASS_PPP_MAGIC_NUMBER,      "PPP magic-number block" },
	{CLASS_PSDN_DIRECTORY_NUMBER, "Public switched network directory number" },
	{0,                           NULL }
};

static void
dissect_lcp_multilink_ep_disc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree = NULL;
  guint8 ep_disc_class;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u byte%s",
	  optp->name, length, plurality(length, "", "s"));
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;
  length -= 2;
  ep_disc_class = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(field_tree, tvb, offset, 1, "Class: %s (%u)",
		val_to_str(ep_disc_class, multilink_ep_disc_class_vals, "Unknown"),
		ep_disc_class);
  offset += 1;
  length -= 1;
  if (length > 0) {
    switch (ep_disc_class) {

    case CLASS_NULL:
      proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s), should have been empty",
			length, plurality(length, "", "s"));
      break;

    case CLASS_LOCAL:
      if (length > 20) {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s), should have been <20",
			length, plurality(length, "", "s"));
      } else {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s)",
			length, plurality(length, "", "s"));
      }
      break;

    case CLASS_IP:
      if (length != 4) {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s), should have been 4",
			length, plurality(length, "", "s"));
      } else {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address: %s", ip_to_str(tvb_get_ptr(tvb, offset, 4)));
      }
      break;

    case CLASS_IEEE_802_1:
      if (length != 6) {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s), should have been 6",
			length, plurality(length, "", "s"));
      } else {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address: %s", ether_to_str(tvb_get_ptr(tvb, offset, 6)));
      }
      break;

    case CLASS_PPP_MAGIC_NUMBER:
      /* XXX - dissect as 32-bit magic numbers */
      if (length > 20) {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s), should have been <20",
			length, plurality(length, "", "s"));
      } else {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s)",
			length, plurality(length, "", "s"));
      }
      break;

    case CLASS_PSDN_DIRECTORY_NUMBER:
      if (length > 15) {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s), should have been <20",
			length, plurality(length, "", "s"));
      } else {
        proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s)",
			length, plurality(length, "", "s"));
      }
      break;

    default:
      proto_tree_add_text(field_tree, tvb, offset, length,
			"Address (%d byte%s)",
			length, plurality(length, "", "s"));
      break;
    }
  }
}

static void
dissect_lcp_bap_link_discriminator_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length,
			"Link discriminator for BAP: 0x%04x",
			tvb_get_ntohs(tvb, offset + 2));
}

/* Character set numbers from the IANA charset registry. */
static const value_string charset_num_vals[] = {
	{105, "UTF-8" },
	{0,   NULL }
};

static void
dissect_lcp_internationalization_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree = NULL;
  guint32 charset;
  
  tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u byte%s",
	  optp->name, length, plurality(length, "", "s"));
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;
  length -= 2;
  charset = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(field_tree, tvb, offset, 4, "Character set: %s (0x%04x)",
		val_to_str(charset, charset_num_vals, "Unknown"),
		charset);
  offset += 4;
  length -= 4;
  if (length > 0) {
    /* XXX - should be displayed as an ASCII string */
    proto_tree_add_text(field_tree, tvb, offset, length, "Language tag (%d byte%s)",
			length, plurality(length, "", "s"));
  }
}

static void
dissect_ipcp_addrs_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree = NULL;
  
  tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u byte%s",
	  optp->name, length, plurality(length, "", "s"));
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  offset += 2;
  length -= 2;
  proto_tree_add_text(field_tree, tvb, offset, 4,
			"Source IP address: %s",
			ip_to_str(tvb_get_ptr(tvb, offset, 4)));
  offset += 4;
  length -= 4;
  proto_tree_add_text(field_tree, tvb, offset, 4,
			"Destination IP address: %s",
			ip_to_str(tvb_get_ptr(tvb, offset, 4)));
}

static void dissect_ipcp_addr_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
			ip_to_str(tvb_get_ptr(tvb, offset + 2, 4)));
}

static void dissect_pppmuxcp_def_pid_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo, proto_tree *tree)
{ 
  pppmux_def_prot_id = tvb_get_ntohs(tvb, offset + 2);
  proto_tree_add_text(tree, tvb, offset + 2, length - 2, "%s: %s (0x%02x)",optp->name,
		      val_to_str(pppmux_def_prot_id, ppp_vals, "Unknown"), pppmux_def_prot_id);
}


static void
dissect_ccp_stac_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  guint8 check_mode;

  if (length == 6) {
	  proto_tree_add_text(tree, tvb, offset, length, 
			      "%s (Ascend Proprietary version)", optp->name);
	  /* We don't know how to decode the following 4 octets, since
	     there's no public document that describe their usage. */
	  return;
  } else {
	  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  }

  proto_tree_add_text(tf, tvb, offset + 2, 2,
		      "History Count: %u", tvb_get_ntohs(tvb, offset + 2));
  check_mode = tvb_get_guint8(tvb, offset + 4);
  proto_tree_add_text(tf, tvb, offset + 4, 1, "Check Mode: %s (0x%02X)", 
      val_to_str(check_mode, stac_checkmode_vals, "Unknown"), check_mode); 
}

static void
dissect_ccp_mppc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *flags_tree;
  guint32 supported_bits;

  supported_bits = tvb_get_ntohl(tvb, offset + 2);
  tf = proto_tree_add_text(tree, tvb, offset, length, 
	      "%s: Supported Bits: 0x%08X", optp->name, supported_bits);
  flags_tree = proto_item_add_subtree(tf, ett_ccp_mppc_opt);
  proto_tree_add_text(flags_tree, tvb, offset + 2, 4, "%s",
      decode_boolean_bitfield(supported_bits, MPPC_SUPPORTED_BITS_C, 8*4, 
      "Desire to negotiate MPPC", "NOT Desire to negotiate MPPC"));
  proto_tree_add_text(flags_tree, tvb, offset + 2, 4, "%s",
      decode_boolean_bitfield(supported_bits, MPPE_SUPPORTED_BITS_D, 8*4, 
      "Obsolete (should NOT be 1)", "Obsolete (should ALWAYS be 0)"));
  proto_tree_add_text(flags_tree, tvb, offset + 2, 4, "%s",
      decode_boolean_bitfield(supported_bits, MPPE_SUPPORTED_BITS_L, 8*4, 
      "40-bit encryption ON", "40-bit encryption OFF"));
  proto_tree_add_text(flags_tree, tvb, offset + 2, 4, "%s",
      decode_boolean_bitfield(supported_bits, MPPE_SUPPORTED_BITS_S, 8*4, 
      "128-bit encryption ON", "128-bit encryption OFF"));
  proto_tree_add_text(flags_tree, tvb, offset + 2, 4, "%s",
      decode_boolean_bitfield(supported_bits, MPPE_SUPPORTED_BITS_M, 8*4, 
      "56-bit encryption ON", "56-bit encryption OFF"));
  proto_tree_add_text(flags_tree, tvb, offset + 2, 4, "%s",
      decode_boolean_bitfield(supported_bits, MPPE_SUPPORTED_BITS_H, 8*4, 
      "Stateless mode ON", "Stateless mode OFF"));
}

static void
dissect_ccp_lzsdcp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  guint8 check_mode;
  guint8 process_mode;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);

  proto_tree_add_text(tf, tvb, offset + 2, 2,
		      "History Count: %u", tvb_get_ntohs(tvb, offset + 2));
  check_mode = tvb_get_guint8(tvb, offset + 4);
  proto_tree_add_text(tf, tvb, offset + 4, 1, "Check Mode: %s (0x%02X)", 
      val_to_str(check_mode, lzsdcp_checkmode_vals, "Unknown"), check_mode); 
  process_mode = tvb_get_guint8(tvb, offset + 5);
  proto_tree_add_text(tf, tvb, offset + 5, 1, "Process Mode: %s (0x%02X)", 
      val_to_str(process_mode, lzsdcp_processmode_vals, "Unkown"), process_mode); 
}

static void
dissect_cbcp_no_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
}

static void
dissect_cbcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  proto_item *ta;
  guint8 addr_type;
  gint addr_len;
  guint8 buf[256];	/* Since length field in Callback Conf Option is
			   8 bits, 256-octet buf is large enough. */
  
  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  proto_tree_add_text(tf, tvb, offset + 2, 1,
		      "Callback delay: %u", tvb_get_guint8(tvb, offset + 2));
  offset += 3;
  length -= 3;
  
  while (length > 0) {
	  ta = proto_tree_add_text(tf, tvb, offset, length, 
				   "Callback Address");
	  addr_type = tvb_get_guint8(tvb, offset); 
	  proto_tree_add_text(ta, tvb, offset, 1, 
		    "Address Type: %s (%u)", 
		    ((addr_type == 1) ? "PSTN/ISDN" : "Other"), addr_type);
	  offset++;
	  length--;
	  addr_len = tvb_get_nstringz0(tvb, offset, sizeof(buf), buf);
	  proto_tree_add_text(ta, tvb, offset, addr_len + 1, 
		    "Address: %s", buf);
	  offset += (addr_len + 1);
	  length -= (addr_len + 1);
  }
}

static void
dissect_bacp_favored_peer_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);

  proto_tree_add_text(tf, tvb, offset + 2, 4,
		      "Magic number: 0x%08x", tvb_get_ntohl(tvb, offset + 2));
}

static void
dissect_bap_link_type_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  guint8 link_type;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);

  proto_tree_add_text(tf, tvb, offset + 2, 2,
	      "Link Speed : %u kbps", tvb_get_ntohs(tvb, offset + 2));
  link_type = tvb_get_guint8(tvb, offset + 4);
  proto_tree_add_text(tf, tvb, offset + 4, 1,
	      "Link Type : %s (%u)", val_to_str(link_type, bap_link_type_vals,
						"Unknown"), link_type);
}

static void
dissect_bap_phone_delta_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *ti;
  proto_item *tf;
  guint8 link_type;
  guint8 subopt_type;
  guint8 subopt_len;
  guint8 buf[256];	/* Since Sub-Option length field in BAP Phone-Delta
			   Option is 8 bits, 256-octets buf is large enough */

  ti = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);

  offset += 2;
  length -= 2;

  while (length > 0) {
    subopt_type = tvb_get_guint8(tvb, offset);
    subopt_len = tvb_get_guint8(tvb, offset + 1);
    tf = proto_tree_add_text(ti, tvb, offset, subopt_len, 
		"Sub-Option (%d byte%s)",
		subopt_len, plurality(subopt_len, "", "s"));

    proto_tree_add_text(tf, tvb, offset, 1,
	"Sub-Option Type : %s (%u)", 
	val_to_str(subopt_type, bap_phone_delta_subopt_vals, "Unknown"),
	subopt_type);

    proto_tree_add_text(tf, tvb, offset + 1, 1,
	"Sub-Option Length : %u", subopt_len);

    switch (subopt_type) {
    case BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT:
      proto_tree_add_text(tf, tvb, offset + 2, 1, "Uniq Digit: %u", 
			  tvb_get_guint8(tvb, offset + 2));
      break;
    case BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM:
      tvb_get_nstringz0(tvb, offset + 2, subopt_len - 2, buf);
      proto_tree_add_text(tf, tvb, offset + 2, subopt_len - 2, 
			  "Subscriber Number: %s", buf);
      break;
    case BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR:
      tvb_get_nstringz0(tvb, offset + 2, subopt_len - 2, buf);
      proto_tree_add_text(tf, tvb, offset + 2, subopt_len - 2, 
			  "Phone Number Sub Address: %s", buf);
      break;
    default:
      proto_tree_add_text(tf, tvb, offset + 2, subopt_len - 2, "Unknown");
      break;
    }
    offset += subopt_len;
    length -= subopt_len;
  }
}

static void
dissect_bap_reason_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  guint8 link_type;
  guint8 buf[256];	/* Since length field in BAP Reason Option is
			   8 bits, 256-octets buf is large enough */

  tvb_get_nstringz0(tvb, offset + 2, length - 2, buf);
  proto_tree_add_text(tree, tvb, offset, length, "%s : %s", 
			   optp->name, buf);
}

static void
dissect_bap_link_disc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  guint8 link_type;

  proto_tree_add_text(tree, tvb, offset, length, "%s : 0x%04x", 
		      optp->name, tvb_get_ntohs(tvb, offset + 2));
}

static void
dissect_bap_call_status_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree)
{
  proto_item *tf;
  guint8 link_type;
  guint8 status, action;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);

  status = tvb_get_guint8(tvb, offset + 2);
  proto_tree_add_text(tf, tvb, offset + 2, 1,
      "Status : %s (0x%02x)", 
      val_to_str(status, q931_cause_code_vals, "Unknown"), status);

  action = tvb_get_guint8(tvb, offset + 3);
  proto_tree_add_text(tf, tvb, offset + 3, 1,
      "Action : %s (0x%02x)", 
      val_to_str(action, bap_call_status_opt_action_vals, "Unknown"), action);
}

static void
dissect_cp( tvbuff_t *tvb, int proto_id, int proto_subtree_index,
	const value_string *proto_vals, int options_subtree_index,
	const ip_tcp_opt *opts, int nopts, packet_info *pinfo, proto_tree *tree ) {
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  proto_item *tf;
  proto_tree *field_tree;

  guint8 code;
  guint8 id;
  int length, offset;
  guint16 protocol;

  code = tvb_get_guint8(tvb, 0);
  id = tvb_get_guint8(tvb, 1);
  length = tvb_get_ntohs(tvb, 2);

  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL,
		proto_get_protocol_short_name(proto_id));

  if(check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
		proto_get_protocol_short_name(proto_id),
		val_to_str(code, proto_vals, "Unknown"));

  if(tree) {
    ti = proto_tree_add_item(tree, proto_id, tvb, 0, length, FALSE);
    fh_tree = proto_item_add_subtree(ti, proto_subtree_index);
    proto_tree_add_text(fh_tree, tvb, 0, 1, "Code: %s (0x%02x)",
      val_to_str(code, proto_vals, "Unknown"), code);
    proto_tree_add_text(fh_tree, tvb, 1, 1, "Identifier: 0x%02x",
			id);
    proto_tree_add_text(fh_tree, tvb, 2, 2, "Length: %u",
			length);
  }
  offset = 4;
  length -= 4;

  switch (code) {
    case CONFREQ:
    case CONFACK:
    case CONFNAK:
    case CONFREJ:
      if(tree) {
        if (length > 0) {
          tf = proto_tree_add_text(fh_tree, tvb, offset, length,
            "Options: (%d byte%s)", length, plurality(length, "", "s"));
          field_tree = proto_item_add_subtree(tf, options_subtree_index);
          dissect_ip_tcp_options(tvb, offset, length, opts, nopts, -1,
				 pinfo, field_tree);
        }
      }
      break;

    case ECHOREQ:
    case ECHOREP:
    case DISCREQ:
    case IDENT:
      if(tree) {
	proto_tree_add_text(fh_tree, tvb, offset, 4, "Magic number: 0x%08x",
			tvb_get_ntohl(tvb, offset));
	offset += 4;
	length -= 4;
	if (length > 0)
          proto_tree_add_text(fh_tree, tvb, offset, length, "Message (%d byte%s)",
				length, plurality(length, "", "s"));
      }
      break;

    case TIMEREMAIN:
      if(tree) {
	proto_tree_add_text(fh_tree, tvb, offset, 4, "Magic number: 0x%08x",
			tvb_get_ntohl(tvb, offset));
	offset += 4;
	length -= 4;
	proto_tree_add_text(fh_tree, tvb, offset, 4, "Seconds remaining: %u",
			tvb_get_ntohl(tvb, offset));
	offset += 4;
	length -= 4;
	if (length > 0)
          proto_tree_add_text(fh_tree, tvb, offset, length, "Message (%d byte%s)",
				length, plurality(length, "", "s"));
      }
      break;

    case PROTREJ:
      if(tree) {
      	protocol = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(fh_tree, tvb, offset, 2, "Rejected protocol: %s (0x%04x)",
		val_to_str(protocol, ppp_vals, "Unknown"), protocol);
	offset += 2;
	length -= 2;
	if (length > 0)
          proto_tree_add_text(fh_tree, tvb, offset, length, "Rejected packet (%d byte%s)",
				length, plurality(length, "", "s"));
		/* XXX - should be dissected as a PPP packet */
      }
      break;

    case CODEREJ:
		/* decode the rejected LCP packet here. */
      if (length > 0)
        proto_tree_add_text(fh_tree, tvb, offset, length, "Rejected packet (%d byte%s)",
				length, plurality(length, "", "s"));
      break;

    case TERMREQ:
    case TERMACK:
      if (length > 0)
        proto_tree_add_text(fh_tree, tvb, offset, length, "Data (%d byte%s)",
				length, plurality(length, "", "s"));
      break;

    default:
      if (length > 0)
        proto_tree_add_text(fh_tree, tvb, offset, length, "Stuff (%d byte%s)",
				length, plurality(length, "", "s"));
      break;
  }
}

/* Protocol field compression */
#define PFC_BIT 0x01

static void
dissect_ppp_common( tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, proto_tree *fh_tree,
		proto_item *ti ) {
  guint16 ppp_prot;
  int     proto_len;
  tvbuff_t	*next_tvb;

  ppp_prot = tvb_get_guint8(tvb, offset);
  if (ppp_prot & PFC_BIT) {
    /* Compressed protocol field - just the byte we fetched. */
    proto_len = 1;
  } else {
    /* Uncompressed protocol field - fetch all of it. */
    ppp_prot = tvb_get_ntohs(tvb, offset);
    proto_len = 2;
  }

  /* If "ti" is not null, it refers to the top-level "proto_ppp" item
     for PPP, and was given a length equal to the length of any
     stuff in the header preceding the protocol type, e.g. an HDLC
     header, which is just "offset"; add the length of the protocol
     type field to it. */
  if (ti != NULL)
    proto_item_set_len(ti, offset + proto_len);

  if (tree) {
    proto_tree_add_uint(fh_tree, hf_ppp_protocol, tvb, offset, proto_len,
      ppp_prot);
  }

  next_tvb = tvb_new_subset(tvb, offset + proto_len, -1, -1);

  /* do lookup with the subdissector table */
  if (!dissector_try_port(subdissector_table, ppp_prot, next_tvb, pinfo, tree)) {
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", ppp_prot);
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "PPP %s (0x%04x)",
		   val_to_str(ppp_prot, ppp_vals, "Unknown"), ppp_prot);
    call_dissector(data_handle,next_tvb, pinfo, tree);
  }
}

static void
dissect_lcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_lcp, ett_lcp, lcp_vals, ett_lcp_options,
	     lcp_opts, N_LCP_OPTS, pinfo, tree);
}

static void
dissect_ipcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_ipcp, ett_ipcp, cp_vals, ett_ipcp_options,
	     ipcp_opts, N_IPCP_OPTS, pinfo, tree);
}

static void
dissect_ccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_ccp, ett_ccp, ccp_vals, ett_ccp_options,
	     ccp_opts, N_CCP_OPTS, pinfo, tree);
}

static void
dissect_cbcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_cbcp, ett_cbcp, cbcp_vals, ett_cbcp_options,
	     cbcp_opts, N_CBCP_OPTS, pinfo, tree);
}

static void
dissect_bacp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_bacp, ett_bacp, cp_vals, ett_bacp_options,
	     bacp_opts, N_BACP_OPTS, pinfo, tree);
}

static void
dissect_bap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  proto_item *tf;
  proto_tree *field_tree;

  guint8 type;
  guint8 id;
  int length, offset;
  guint8 resp_code;

  type = tvb_get_guint8(tvb, 0);
  id = tvb_get_guint8(tvb, 1);
  length = tvb_get_ntohs(tvb, 2);

  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL,
		proto_get_protocol_short_name(proto_bap));

  if(check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
		proto_get_protocol_short_name(proto_bap),
		val_to_str(type, bap_vals, "Unknown"));

  if(tree) {
    ti = proto_tree_add_item(tree, proto_bap, tvb, 0, length, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_bap_options);
    proto_tree_add_text(fh_tree, tvb, 0, 1, "Type: %s (0x%02x)",
      val_to_str(type, bap_vals, "Unknown"), type);
    proto_tree_add_text(fh_tree, tvb, 1, 1, "Identifier: 0x%02x",
			id);
    proto_tree_add_text(fh_tree, tvb, 2, 2, "Length: %u",
			length);
  }
  offset = 4;
  length -= 4;

  if (type == BAP_CRES || type == BAP_CBRES || 
      type == BAP_LDQRES || type == BAP_CSRES) {
    resp_code = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(fh_tree, tvb, offset, 1, "Response Code: %s (0x%02x)",
	val_to_str(resp_code, bap_resp_code_vals, "Unknown"), resp_code);
    offset++;
    length--;
  }

  if(tree) {
    if (length > 0) {
      tf = proto_tree_add_text(fh_tree, tvb, offset, length,
	       "Data (%d byte%s)", length, plurality(length, "", "s"));
      field_tree = proto_item_add_subtree(tf, ett_bap_options);
      dissect_ip_tcp_options(tvb, offset, length, bap_opts, N_BAP_OPTS, -1,
			     pinfo, field_tree);
    }
  }
}

static void
dissect_comp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *comp_data_tree;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, 
		proto_get_protocol_short_name(proto_comp_data));

  if(check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
		 proto_get_protocol_short_name(proto_comp_data),
		 val_to_str(PPP_COMP, ppp_vals, "Unknown"));

  if (tree) {
    ti = proto_tree_add_item(tree, proto_comp_data, tvb, 0, tvb_length(tvb), FALSE);
    comp_data_tree = proto_item_add_subtree(ti, ett_comp_data);
  }
}

static void
dissect_pppmuxcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb,proto_pppmuxcp,ett_pppmuxcp,pppmuxcp_vals,
	     ett_pppmuxcp_options,pppmuxcp_opts,N_PPPMUXCP_OPTS,pinfo,tree);
}

#define PPPMUX_FLAGS_MASK          0xc0
#define PPPMUX_PFF_BIT_SET         0x80
#define PPPMUX_LXT_BIT_SET         0x40

static void 
dissect_pppmux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *mux_tree, *hdr_tree, *sub_tree, *flag_tree;
  proto_tree *info_tree;
  proto_item *ti = NULL,*sub_ti = NULL;
  guint8 flags, byte;
  guint16 length;
  static guint16 pid;
  tvbuff_t *next_tvb;    
  int offset = 0, length_remaining;
  int length_field = 0, pid_field = 0,hdr_length = 0;
  dissector_handle_t prot_handle; 
  
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo,COL_PROTOCOL, "PPP PPPMux");
	
  if (check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "PPP Multiplexing");
	
  length_remaining = tvb_length(tvb);
  
  if (tree) {
    ti = proto_tree_add_item(tree, proto_pppmux, tvb, 0, length_remaining,
			     FALSE);
    mux_tree = proto_item_add_subtree(ti,ett_pppmux);
    
    while (length_remaining > 0) {
	
      flags = tvb_get_guint8(tvb,offset) & PPPMUX_FLAGS_MASK;
      
      if (flags && PPPMUX_LXT_BIT_SET ) {
	length = tvb_get_ntohs(tvb,offset) & 0x3fff;
	length_field = 2;
      } else {
	length = tvb_get_guint8(tvb,offset) & 0x3f;
	length_field = 1;
      }
      
      if (flags && PPPMUX_PFF_BIT_SET) {
	byte = tvb_get_guint8(tvb,offset + length_field);
	if (byte && PFC_BIT) {		  /* Compressed PID field*/
	  pid = byte;
	  pid_field = 1;
	} else {		  /*PID field is 2 bytes*/
	  pid = tvb_get_ntohs(tvb,offset + length_field);
	  pid_field = 2;
	}
      } else {
	if (!pid){	 /*No Last PID, hence use the default */
	  if (pppmux_def_prot_id) 
	    pid = pppmux_def_prot_id;
	}
      }
      
      hdr_length = length_field + pid_field;
      
      ti = proto_tree_add_text(mux_tree, tvb, offset, length + length_field,
			       "PPPMux Sub-frame");
      sub_tree = proto_item_add_subtree(ti,ett_pppmux_subframe);
      sub_ti = proto_tree_add_text(sub_tree, tvb, offset,
				   hdr_length,"Header field");
      
      hdr_tree = proto_item_add_subtree(sub_ti,ett_pppmux_subframe_hdr);
      ti = proto_tree_add_text(hdr_tree, tvb, offset, length_field, "PFF/LXT: 0x%02X",
			       flags);
      
      flag_tree = proto_item_add_subtree(ti,ett_pppmux_subframe_flags);
      proto_tree_add_text(flag_tree,tvb,offset,length_field,"%s",
			  decode_boolean_bitfield(flags,0x80,8,"PID Present","PID not present"));
      proto_tree_add_text(flag_tree,tvb,offset,length_field,"%s",
			  decode_boolean_bitfield(flags,0x40,8,"2 bytes ength field ","1 byte length field"));
      
      ti = proto_tree_add_text(hdr_tree,tvb,offset,length_field,"Sub-frame Length = %u",length);
      
      if (flags && PPPMUX_PFF_BIT_SET)
	proto_tree_add_text(hdr_tree,tvb,offset + length_field,pid_field,"%s: %s(0x%02x)",
			    "Protocol ID",val_to_str(pid,ppp_vals,"Unknown"), pid);
      
      offset += hdr_length;
      length_remaining -= hdr_length;
      length -= pid_field;
      
      sub_ti = proto_tree_add_text(sub_tree,tvb,offset,length,"Information Field");
      info_tree = proto_item_add_subtree(sub_ti,ett_pppmux_subframe_info);
      
      next_tvb = tvb_new_subset(tvb,offset,length,-1); 
      
      if (!dissector_try_port(subdissector_table, pid, next_tvb, pinfo, info_tree)) {
	call_dissector(data_handle, next_tvb, pinfo, info_tree);
      }
      offset += length;
      length_remaining -= length;
    }  /* While length_remaining */
    pid = 0; 
  } /* if tree */  
}


#define MP_FRAG_MASK     0xC0
#define MP_FRAG(bits)    ((bits) & MP_FRAG_MASK)
#define MP_FRAG_FIRST    0x80
#define MP_FRAG_LAST     0x40
#define MP_FRAG_RESERVED 0x3f

static const true_false_string frag_truth = {
  "Yes",
  "No"
};

/* According to RFC 1717, the length the MP header isn't indicated anywhere
   in the header itself.  It starts out at four bytes and can be
   negotiated down to two using LCP.  We currently assume that all
   headers are four bytes.  - gcc
 */
static void
dissect_mp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *mp_tree, *hdr_tree;
  proto_item *ti = NULL;
  guint8      flags;
  gchar      *flag_str;
  tvbuff_t   *next_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP MP");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "PPP Multilink");

  flags = tvb_get_guint8(tvb, 0);

  if (tree) {
    switch (flags) {
      case MP_FRAG_FIRST:
        flag_str = "First";
        break;
      case MP_FRAG_LAST:
        flag_str = "Last";
        break;
      case MP_FRAG_FIRST|MP_FRAG_LAST:
        flag_str = "First, Last";
        break;
      default:
        flag_str = "Unknown";
        break;
    }
    ti = proto_tree_add_item(tree, proto_mp, tvb, 0, 4, FALSE);
    mp_tree = proto_item_add_subtree(ti, ett_mp);
    ti = proto_tree_add_text(mp_tree, tvb, 0, 1, "Fragment: 0x%2X (%s)",
      flags, flag_str);
    hdr_tree = proto_item_add_subtree(ti, ett_mp_flags);
    proto_tree_add_boolean(hdr_tree, hf_mp_frag_first, tvb, 0, 1, flags);
    proto_tree_add_boolean(hdr_tree, hf_mp_frag_last, tvb, 0, 1, flags),
    proto_tree_add_text(hdr_tree, tvb, 0, 1, "%s",
      decode_boolean_bitfield(flags, MP_FRAG_RESERVED, sizeof(flags) * 8,
        "reserved", "reserved"));
    proto_tree_add_item(mp_tree, hf_mp_sequence_num, tvb,  1, 3, FALSE);
  }

  if (tvb_reported_length_remaining(tvb, 4) > 0) {
    next_tvb = tvb_new_subset(tvb, 4, -1, -1);
    dissect_ppp(next_tvb, pinfo, tree);
  }
}

/*
 * Handles PPP without HDLC framing, just a protocol field (RFC 1661).
 */
static void
dissect_ppp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree ) {
  proto_item *ti = NULL;
  proto_tree *fh_tree = NULL;

  if(tree) {
    ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, 0, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_ppp);
  }

  dissect_ppp_common(tvb, 0, pinfo, tree, fh_tree, ti);
}

/*
 * Handles link-layer encapsulations where the frame might be
 * a PPP in HDLC-like Framing frame (RFC 1662) or a Cisco HDLC frame.
 */
static void
dissect_ppp_hdlc( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree ) {
  proto_item *ti = NULL;
  proto_tree *fh_tree = NULL;
  guint8     byte0;
  int        proto_offset;
  int        rx_fcs_offset;
  guint32    rx_fcs_exp;
  guint32    rx_fcs_got;

  byte0 = tvb_get_guint8(tvb, 0);
  if (byte0 == CHDLC_ADDR_UNICAST || byte0 == CHDLC_ADDR_MULTICAST) {
    /* Cisco HDLC encapsulation */
    call_dissector(chdlc_handle, tvb, pinfo, tree);
  }

  /*
   * XXX - should we have a routine that always dissects PPP, for use
   * when we know the packets are PPP, not CHDLC?
   */

  /* PPP HDLC encapsulation */
  if (byte0 == 0xff)
    proto_offset = 2;
  else {
    /* address and control are compressed (NULL) */
    proto_offset = 0;
  }

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */

  if(check_col(pinfo->cinfo, COL_RES_DL_SRC))
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A" );
  if(check_col(pinfo->cinfo, COL_RES_DL_DST))
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A" );
  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP" );

  if(tree) {
    ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, proto_offset, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_ppp);
    if (byte0 == 0xff) {
      proto_tree_add_item(fh_tree, hf_ppp_address, tvb, 0, 1, FALSE);
      proto_tree_add_item(fh_tree, hf_ppp_control, tvb, 1, 1, FALSE);
    }
  }

  dissect_ppp_common(tvb, proto_offset, pinfo, tree, fh_tree, ti);

  /* Calculate the FCS check */
  /* XXX - deal with packets cut off by the snapshot length */
  if (ppp_fcs_decode == FCS_16) {
    rx_fcs_offset = tvb_length(tvb) - 2;
    rx_fcs_exp = fcs16(0xFFFF, tvb, 0, rx_fcs_offset);
    rx_fcs_got = tvb_get_letohs(tvb, rx_fcs_offset);
    if (rx_fcs_got != rx_fcs_exp) {
      proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 2, "FCS 16: 0x%04x (incorrect, should be %04x)", rx_fcs_got, rx_fcs_exp);
    } else {
      proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 2, "FCS 16: 0x%04x (correct)", rx_fcs_got);
    }
  } else if (ppp_fcs_decode == FCS_32) {
    rx_fcs_offset = tvb_length(tvb) - 4;
    rx_fcs_exp = fcs32(0xFFFFFFFF, tvb, 0, rx_fcs_offset);
    rx_fcs_got = tvb_get_letohl(tvb, rx_fcs_offset);
    if (rx_fcs_got != rx_fcs_exp) {
      proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 4, "FCS 32: 0x%08x (incorrect, should be %08x) ", rx_fcs_got, rx_fcs_exp);
    } else {
      proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 4, "FCS 32: 0x%08x (correct)", rx_fcs_got);
    }
  }
}

/*
 * Handles PAP just as a protocol field
 */
static void
dissect_pap( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree ) {
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  proto_item *tf;
  proto_tree *field_tree;
  proto_item *tm;
  proto_tree *message_tree;
  proto_item *tp;
  proto_tree *peer_id_tree;
  proto_item *tpw;
  proto_tree *passwd_tree;

  guint8 code;
  guint8 id, peer_id_length, password_length, msg_length;
  int length, offset;

  code = tvb_get_guint8(tvb, 0);
  id = tvb_get_guint8(tvb, 1);
  length = tvb_get_ntohs(tvb, 2);

  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL,
		proto_get_protocol_short_name(proto_pap));

  if(check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
		proto_get_protocol_short_name(proto_pap),
		val_to_str(code, pap_vals, "Unknown"));

  if(tree) {
    ti = proto_tree_add_item(tree, proto_pap, tvb, 0, length, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_pap);
    proto_tree_add_text(fh_tree, tvb, 0, 1, "Code: %s (0x%02x)",
      val_to_str(code, pap_vals, "Unknown"), code);
    proto_tree_add_text(fh_tree, tvb, 1, 1, "Identifier: 0x%02x",
			id);
    proto_tree_add_text(fh_tree, tvb, 2, 2, "Length: %u",
			length);
  }
  offset = 4;
  length -= 4;

  switch (code) {
    case CONFREQ:
      if(tree) {
        if (length > 0) {
          tf = proto_tree_add_text(fh_tree, tvb, offset, length,
            "Data (%d byte%s)", length, plurality(length, "", "s"));
          field_tree = proto_item_add_subtree(tf, ett_pap_data);
		  peer_id_length = tvb_get_guint8(tvb, offset);
		  tp = proto_tree_add_text(field_tree, tvb, offset,      1,
              "Peer ID length: %d byte%s", peer_id_length, plurality(peer_id_length, "", "s"));
		  if (--length > 0) {
			  peer_id_tree = proto_item_add_subtree(tp, ett_pap_peer_id);
			  proto_tree_add_text(peer_id_tree, tvb, ++offset, ppp_min(peer_id_length, length),
              "Peer-ID (%d byte%s)", peer_id_length, plurality(peer_id_length, "", "s"));
			  offset+=peer_id_length;
			  length-=peer_id_length;
			  if (length > 0) {
				password_length = tvb_get_guint8(tvb, offset);
				if (--length > 0) {
					tpw = proto_tree_add_text(field_tree, tvb, offset,      1,
						"Password length: %d byte%s", password_length, plurality(password_length, "", "s"));
					passwd_tree = proto_item_add_subtree(tpw, ett_pap_password);
					proto_tree_add_text(passwd_tree, tvb, ++offset, ppp_min(password_length, length),
						"Password (%d byte%s)", password_length, plurality(password_length, "", "s"));
				}
			  }
		  }
        }
      }
      break;

    case CONFACK:
    case CONFNAK:
      if(tree) {
        if (length > 0) {
          tf = proto_tree_add_text(fh_tree, tvb, offset, length,
            "Data (%d byte%s)", length, plurality(length, "", "s"));
          field_tree = proto_item_add_subtree(tf, ett_pap_data);
		  msg_length = tvb_get_guint8(tvb, offset);
		  tm = proto_tree_add_text(field_tree, tvb, offset,      1,
              "Message length: %d byte%s", msg_length, plurality(msg_length, "", "s"));
		  if (--length > 0) {
			message_tree = proto_item_add_subtree(tm, ett_pap_message);
		    proto_tree_add_text(message_tree, tvb, ++offset, ppp_min(msg_length, length),
              "Message (%d byte%s)", msg_length, plurality(msg_length, "", "s"));
		  }
        }
      }
      break;
    default:
      if (length > 0)
        proto_tree_add_text(fh_tree, tvb, offset, length, "Stuff (%d byte%s)",
				length, plurality(length, "", "s"));
      break;
  }
}

/*
 * Handles CHAP just as a protocol field
 */
static void
dissect_chap( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree ) {
  proto_item *ti;
  proto_tree *fh_tree = NULL;
  proto_item *tf;
  proto_tree *field_tree;
  proto_item *tv;
  proto_tree *value_tree;

  guint8 code, id, value_size;
  guint16 length;
  int offset;
  int name_length;

  code = tvb_get_guint8(tvb, 0);
  id = tvb_get_guint8(tvb, 1);
  length = tvb_get_ntohs(tvb, 2);

  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL,
		proto_get_protocol_short_name(proto_chap));

  if(check_col(pinfo->cinfo, COL_INFO))
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
		proto_get_protocol_short_name(proto_chap),
		val_to_str(code, chap_vals, "Unknown"));

  if(tree) {
    ti = proto_tree_add_item(tree, proto_chap, tvb, 0, length, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_chap);
    proto_tree_add_text(fh_tree, tvb, 0, 1, "Code: %s (0x%02x)",
      val_to_str(code, chap_vals, "Unknown"), code);
    proto_tree_add_text(fh_tree, tvb, 1, 1, "Identifier: 0x%02x",
			id);
    proto_tree_add_text(fh_tree, tvb, 2, 2, "Length: %u",
			length);
  }
  offset = 4;
  length -= 4;

  switch (code) {
    case CHAP_CHAL:
    case CHAP_RESP:
      if(tree) {
        if (length > 0) {
          tf = proto_tree_add_text(fh_tree, tvb, offset, length,
				   "Data (%d byte%s)", length, 
				   plurality(length, "", "s"));
          field_tree = proto_item_add_subtree(tf, ett_chap_data);
	  value_size = tvb_get_guint8(tvb, offset);
	  name_length = length - value_size - 1; 
	  tv = proto_tree_add_text(field_tree, tvb, offset, 1,
				   "Value Size: %d byte%s", 
				   value_size, plurality(value_size, "", "s"));
	  if (--length > 0) {
	    value_tree = proto_item_add_subtree(tv, ett_chap_value);
	    proto_tree_add_text(value_tree, tvb, ++offset, 
				ppp_min(value_size, length),
				"Value (%d byte%s)", 
				value_size, plurality(value_size, "", "s"));
	    offset+=value_size;
	    length-=value_size;
	    if (length > 0) {
	      proto_tree_add_text(field_tree, tvb, offset, 
				  ppp_min(name_length, length),
				  "Name (%d byte%s)", name_length, 
				  plurality(name_length, "", "s"));
	    }
	  }
        }
      }
      break;

    case CHAP_SUCC:
    case CHAP_FAIL:
      if(tree) {
        if (length > 0) {
          tf = proto_tree_add_text(fh_tree, tvb, offset, length,
				   "Data (%d byte%s)", length, 
				   plurality(length, "", "s"));
          field_tree = proto_item_add_subtree(tf, ett_chap_data);
	  tv = proto_tree_add_text(field_tree, tvb, offset, length,
				   "Message: %d byte%s", 
				   length, plurality(length, "", "s"));
	}
      }
      break;
    default:
      if (length > 0)
        proto_tree_add_text(fh_tree, tvb, offset, length, "Stuff (%d byte%s)",
				length, plurality(length, "", "s"));
      break;
  }
}


void
proto_register_ppp(void)
{
  static hf_register_info hf[] = {
    { &hf_ppp_address,
    { "Address", "ppp.address", FT_UINT8, BASE_HEX,
        NULL, 0x0, "", HFILL }},

    { &hf_ppp_control,
    { "Control", "ppp.control", FT_UINT8, BASE_HEX,
        NULL, 0x0, "", HFILL }},

    { &hf_ppp_protocol,
    { "Protocol", "ppp.protocol", FT_UINT16, BASE_HEX,
        VALS(ppp_vals), 0x0, "", HFILL }},
  };
  static gint *ett[] = {
    &ett_ppp,
  };

  static enum_val_t ppp_options[] = {
    {"None", 0},
    {"16-Bit", 1},
    {"32-Bit", 2},
    {NULL, -1}
  };

  module_t *ppp_module;

  proto_ppp = proto_register_protocol("Point-to-Point Protocol", "PPP", "ppp");
  proto_register_field_array(proto_ppp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
  subdissector_table = register_dissector_table("ppp.protocol",
	"PPP protocol", FT_UINT16, BASE_HEX);

  register_dissector("ppp_hdlc", dissect_ppp_hdlc, proto_ppp);
  register_dissector("ppp", dissect_ppp, proto_ppp);

  /* Register the preferences for the ppp protocol */
  ppp_module = prefs_register_protocol(proto_ppp, NULL);

  prefs_register_enum_preference(ppp_module,
    "ppp_fcs",
    "PPP Frame Checksum Type",
    "The type of PPP frame checksum (none, 16-bit, 32-bit)",
    &ppp_fcs_decode,
    ppp_options, FALSE);
  prefs_register_bool_preference(ppp_module,
    "ppp_vj",
    "PPP Van Jacobson Compression",
    "Whether Van Jacobson-compressed PPP frames should be decompressed",
    &ppp_vj_decomp);

  prefs_register_uint_preference(ppp_module, "default_proto_id",
				 "PPPMuxCP Default PID",
				 "Default Protocol ID to be used",
				 16, &pppmux_def_prot_id);
}

void
proto_reg_handoff_ppp(void)
{
  dissector_handle_t ppp_hdlc_handle, ppp_handle;

  /*
   * Get a handle for the CHDLC dissector.
   */
  chdlc_handle = find_dissector("chdlc");
  data_handle = find_dissector("data");

  ppp_hdlc_handle = find_dissector("ppp_hdlc");
  ppp_handle = find_dissector("ppp");
  dissector_add("wtap_encap", WTAP_ENCAP_PPP, ppp_hdlc_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_PPP_WITH_PHDR, ppp_hdlc_handle);
  dissector_add("fr.ietf", NLPID_PPP, ppp_handle);
  dissector_add("gre.proto", ETHERTYPE_PPP, ppp_hdlc_handle);
}

void
proto_register_mp(void)
{
  static hf_register_info hf[] = {
    { &hf_mp_frag_first,
    { "First fragment",		"mp.first",	FT_BOOLEAN, 8,
        TFS(&frag_truth), MP_FRAG_FIRST, "", HFILL }},

    { &hf_mp_frag_last,
    { "Last fragment",		"mp.last",	FT_BOOLEAN, 8,
        TFS(&frag_truth), MP_FRAG_LAST, "", HFILL }},

    { &hf_mp_sequence_num,
    { "Sequence number",	"mp.seq",	FT_UINT24, BASE_DEC, NULL, 0x0,
    	"", HFILL }}
  };
  static gint *ett[] = {
    &ett_mp,
    &ett_mp_flags,
  };

  proto_mp = proto_register_protocol("PPP Multilink Protocol", "PPP MP", "mp");
  proto_register_field_array(proto_mp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mp(void)
{
  dissector_handle_t mp_handle;

  mp_handle = create_dissector_handle(dissect_mp, proto_mp);
  dissector_add("ppp.protocol", PPP_MP, mp_handle);
}

void
proto_register_lcp(void)
{
  static gint *ett[] = {
    &ett_lcp,
    &ett_lcp_options,
    &ett_lcp_mru_opt,
    &ett_lcp_async_map_opt,
    &ett_lcp_authprot_opt,
    &ett_lcp_qualprot_opt,
    &ett_lcp_magicnum_opt,
    &ett_lcp_fcs_alternatives_opt,
    &ett_lcp_numbered_mode_opt,
    &ett_lcp_callback_opt,
    &ett_lcp_multilink_ep_disc_opt,
    &ett_lcp_internationalization_opt,
  };

  proto_lcp = proto_register_protocol("PPP Link Control Protocol", "PPP LCP",
				      "lcp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lcp(void)
{
  dissector_handle_t lcp_handle;

  lcp_handle = create_dissector_handle(dissect_lcp, proto_lcp);
  dissector_add("ppp.protocol", PPP_LCP, lcp_handle);

  /*
   * NDISWAN on Windows translates Ethernet frames from higher-level
   * protocols into PPP frames to hand to the PPP driver, and translates
   * PPP frames from the PPP driver to hand to the higher-level protocols.
   *
   * Apparently the PPP driver, on at least some versions of Windows,
   * passes frames for internal-to-PPP protocols up through NDISWAN;
   * the protocol type field appears to be passed through unchanged
   * (unlike what's done with, for example, the protocol type field
   * for IP, which is mapped from its PPP value to its Ethernet value).
   *
   * This means that we may see, on Ethernet captures, frames for
   * protocols internal to PPP, so we register PPP_LCP with the
   * "ethertype" dissector table as well as the PPP protocol dissector
   * table.
   */
  dissector_add("ethertype", PPP_LCP, lcp_handle);
}

void
proto_register_ipcp(void)
{
  static gint *ett[] = {
    &ett_ipcp,
    &ett_ipcp_options,
    &ett_ipcp_ipaddrs_opt,
    &ett_ipcp_compressprot_opt,
  };

  proto_ipcp = proto_register_protocol("PPP IP Control Protocol", "PPP IPCP",
				      "ipcp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipcp(void)
{
  dissector_handle_t ipcp_handle;

  ipcp_handle = create_dissector_handle(dissect_ipcp, proto_ipcp);
  dissector_add("ppp.protocol", PPP_IPCP, ipcp_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_IPCP, ipcp_handle);
}

void
proto_register_ccp(void)
{
  static gint *ett[] = {
    &ett_ccp,
    &ett_ccp_options,
    &ett_ccp_stac_opt,
    &ett_ccp_mppc_opt,
    &ett_ccp_lzsdcp_opt
  };

  proto_ccp = proto_register_protocol("PPP Compression Control Protocol", 
				      "PPP CCP", "ccp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ccp(void)
{
  dissector_handle_t ccp_handle;

  ccp_handle = create_dissector_handle(dissect_ccp, proto_ccp);
  dissector_add("ppp.protocol", PPP_CCP, ccp_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_CCP, ccp_handle);
}

void
proto_register_cbcp(void)
{
  static gint *ett[] = {
    &ett_cbcp,
    &ett_cbcp_options,
    &ett_cbcp_no_callback_opt,
    &ett_cbcp_callback_opt
  };

  proto_cbcp = proto_register_protocol("PPP Callback Control Protocoll", 
				      "PPP CBCP", "cbcp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cbcp(void)
{
  dissector_handle_t cbcp_handle;

  cbcp_handle = create_dissector_handle(dissect_cbcp, proto_cbcp);
  dissector_add("ppp.protocol", PPP_CBCP, cbcp_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_CBCP, cbcp_handle);
}

void
proto_register_bacp(void)
{
  static gint *ett[] = {
    &ett_bacp,
    &ett_bacp_options,
    &ett_bacp_favored_peer_opt
  };

  proto_bacp = proto_register_protocol("PPP Bandwidth Allocation Control Protocol", 
				      "PPP BACP", "bacp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bacp(void)
{
  dissector_handle_t bacp_handle;

  bacp_handle = create_dissector_handle(dissect_bacp, proto_bacp);
  dissector_add("ppp.protocol", PPP_BACP, bacp_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_BACP, bacp_handle);
}

void
proto_register_bap(void)
{
  static gint *ett[] = {
    &ett_bap,
    &ett_bap_options,
    &ett_bap_link_type_opt,
    &ett_bap_phone_delta_opt,
    &ett_bap_reason_opt,
    &ett_bap_link_disc_opt,
    &ett_bap_call_status_opt
  };

  proto_bap = proto_register_protocol("PPP Bandwidth Allocation Protocol", 
				      "PPP BAP", "bap");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bap(void)
{
  dissector_handle_t bap_handle;

  bap_handle = create_dissector_handle(dissect_bap, proto_bap);
  dissector_add("ppp.protocol", PPP_BAP, bap_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_BAP, bap_handle);
}

void
proto_register_comp_data(void)
{
  static gint *ett[] = {
    &ett_comp_data
  };

  proto_comp_data = proto_register_protocol("PPP Compressed Datagram",
				      "PPP Comp", "comp_data");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_comp_data(void)
{
  dissector_handle_t comp_data_handle;

  comp_data_handle = create_dissector_handle(dissect_comp_data,
					proto_comp_data);
  dissector_add("ppp.protocol", PPP_COMP, comp_data_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_COMP, comp_data_handle);
}

void
proto_register_pap(void)
{
  static gint *ett[] = {
    &ett_pap,
	&ett_pap_data,
	&ett_pap_peer_id,
	&ett_pap_password,
	&ett_pap_message,
  };

  proto_pap = proto_register_protocol("PPP Password Authentication Protocol", "PPP PAP",
				      "pap");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pap(void)
{
  dissector_handle_t pap_handle;

  pap_handle = create_dissector_handle(dissect_pap, proto_pap);
  dissector_add("ppp.protocol", PPP_PAP, pap_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_PAP, pap_handle);
}

void
proto_register_chap(void)
{
  static gint *ett[] = {
    &ett_chap,
    &ett_chap_data,
    &ett_chap_value,
    &ett_chap_name,
    &ett_chap_message,
  };

  proto_chap = proto_register_protocol("PPP Challenge Handshake Authentication Protocol", "PPP CHAP",
				      "chap");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_chap(void)
{
  dissector_handle_t chap_handle;

  chap_handle = create_dissector_handle(dissect_chap, proto_chap);
  dissector_add("ppp.protocol", PPP_CHAP, chap_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_CHAP, chap_handle);
}

void
proto_register_pppmuxcp(void)
{
  static gint *ett[] = {
    &ett_pppmuxcp,
    &ett_pppmuxcp_options,
    &ett_pppmuxcp_def_pid_opt,
  };

  proto_pppmuxcp = proto_register_protocol("PPPMux Control Protocol", 
				       "PPP PPPMuxCP",
				      "pppmuxcp");
  proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_pppmuxcp(void)
{ 
  dissector_handle_t muxcp_handle; 
 
  muxcp_handle = create_dissector_handle(dissect_pppmuxcp, proto_pppmuxcp);
  dissector_add("ppp.protocol", PPP_MUXCP, muxcp_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_MUXCP, muxcp_handle);
}


void 
proto_register_pppmux(void) 
{ 
  static gint *ett[] = { 
    &ett_pppmux, 
    &ett_pppmux_subframe, 
    &ett_pppmux_subframe_hdr, 
    &ett_pppmux_subframe_flags, 
    &ett_pppmux_subframe_info, 
  }; 
 
  proto_pppmux = proto_register_protocol("PPP Multiplexing",  
				       "PPP PPPMux", 
				      "pppmux"); 
  proto_register_subtree_array(ett, array_length(ett)); 
} 
 
void 
proto_reg_handoff_pppmux(void) 
{ 
  dissector_handle_t pppmux_handle; 
 
  pppmux_handle = create_dissector_handle(dissect_pppmux, proto_pppmux); 
  dissector_add("ppp.protocol", PPP_MUX, pppmux_handle); 
 
  /* 
   * See above comment about NDISWAN for an explanation of why we're 
   * registering with the "ethertype" dissector table. 
   */ 
  dissector_add("ethertype", PPP_MUX, pppmux_handle); 
} 

