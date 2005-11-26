/* packet-ppp.c
 * Routines for ppp packet disassembly
 * RFC 1661, RFC 1662
 *
 * $Id$
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

#include <string.h>
#include <glib.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include "packet-ppp.h"
#include <epan/ppptypes.h>
#include <epan/etypes.h>
#include <epan/ip_opts.h>
#include <epan/atalk-utils.h>
#include "packet-chdlc.h"
#include "packet-ip.h"
#include "packet-ipx.h"
#include "packet-vines.h"
#include <epan/nlpid.h>
#include <epan/crc16.h>
#include <epan/crc32.h>

#define ppp_min(a, b)  ((a<b) ? a : b)

static int proto_ppp = -1;
static int hf_ppp_address = -1;
static int hf_ppp_control = -1;
static int hf_ppp_protocol = -1;

static gint ett_ppp = -1;

static int proto_ppp_hdlc = -1;

static gint ett_ppp_hdlc_data = -1;

static int proto_lcp = -1;

static gint ett_lcp = -1;
static gint ett_lcp_options = -1;
static gint ett_lcp_authprot_opt = -1;
static gint ett_lcp_qualprot_opt = -1;
static gint ett_lcp_fcs_alternatives_opt = -1;
static gint ett_lcp_numbered_mode_opt = -1;
static gint ett_lcp_callback_opt = -1;
static gint ett_lcp_multilink_ep_disc_opt = -1;
static gint ett_lcp_internationalization_opt = -1;

static int proto_ipcp = -1;

static gint ett_ipcp = -1;
static gint ett_ipcp_options = -1;
static gint ett_ipcp_ipaddrs_opt = -1;
static gint ett_ipcp_compress_opt = -1;
static gint ett_ipcp_iphc_disableprot_opt = -1;

static int proto_osicp = -1;

static gint ett_osicp = -1;
static gint ett_osicp_options = -1;
static gint ett_osicp_align_npdu_opt = -1;

static int proto_ccp = -1;

static gint ett_ccp = -1;
static gint ett_ccp_options = -1;
static gint ett_ccp_stac_opt = -1;
static gint ett_ccp_mppc_opt = -1;
static gint ett_ccp_bsdcomp_opt = -1;
static gint ett_ccp_lzsdcp_opt = -1;
static gint ett_ccp_mvrca_opt = -1;
static gint ett_ccp_deflate_opt = -1;

static int proto_cbcp = -1;

static gint ett_cbcp = -1;
static gint ett_cbcp_options = -1;
static gint ett_cbcp_callback_opt = -1;
static gint ett_cbcp_callback_opt_addr = -1;

static int proto_bacp = -1;

static gint ett_bacp = -1;
static gint ett_bacp_options = -1;
static gint ett_bacp_favored_peer_opt = -1;

static int proto_bap = -1;

static gint ett_bap = -1;
static gint ett_bap_options = -1;
static gint ett_bap_link_type_opt = -1;
static gint ett_bap_phone_delta_opt = -1;
static gint ett_bap_phone_delta_subopt = -1;
static gint ett_bap_call_status_opt = -1;

static int proto_comp_data = -1;

static gint ett_comp_data = -1;

static int proto_pppmuxcp = -1;

static gint ett_pppmuxcp = -1;
static gint ett_pppmuxcp_options = -1;

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

static int proto_mplscp = -1;
static gint ett_mplscp = -1;
static gint ett_mplscp_options = -1;

static int proto_cdpcp = -1;
static gint ett_cdpcp = -1;
static gint ett_cdpcp_options = -1;

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


static gint hf_chap_code		= -1;
static gint hf_chap_identifier		= -1;
static gint hf_chap_length		= -1;
static gint hf_chap_value_size	= -1;
static gint hf_chap_value	= -1;
static gint hf_chap_name	= -1;
static gint hf_chap_message	= -1;


static int proto_ipv6cp = -1;  /* IPv6CP vars */

static gint ett_ipv6cp = -1;
static gint ett_ipv6cp_options = -1;
static gint ett_ipv6cp_if_id_opt = -1;
static gint ett_ipv6cp_compress_opt = -1;  

static dissector_table_t ppp_subdissector_table;
static dissector_handle_t chdlc_handle;
static dissector_handle_t data_handle;

/* options */
static gint ppp_fcs_decode = 0; /* 0 = No FCS, 1 = 16 bit FCS, 2 = 32 bit FCS */
#define NO_FCS 0
#define FCS_16 1
#define FCS_32 2

const enum_val_t fcs_options[] = {
  {"none", "None", NO_FCS},
  {"16-bit", "16-Bit", FCS_16},
  {"32-bit", "32-Bit", FCS_32},
  {NULL, NULL, -1}
};

gboolean ppp_vj_decomp = TRUE; /* Default to VJ header decompression */

/*
 * For Default Protocol ID negotiated with PPPMuxCP. We need to
 * this ID so that if the first subframe doesn't have protocol
 * ID, we can use it
 */

static guint pppmux_def_prot_id = 0;

/* PPP definitions */

/*
 * Used by the GTP dissector as well.
 */
const value_string ppp_vals[] = {
	{PPP_PADDING,	"Padding Protocol" },
	{PPP_ROHC_SCID,	"ROHC small-CID" },
	{PPP_ROHC_LCID,	"ROHC large-CID" },
	{PPP_IP,        "IP"             },
	{PPP_OSI,       "OSI"            },
	{PPP_DEC4,	"DECnet Phase IV" },
	{PPP_AT,        "Appletalk"      },
	{PPP_IPX,       "Netware IPX/SPX"},
	{PPP_VJC_COMP,	"VJ compressed TCP"},
	{PPP_VJC_UNCOMP,"VJ uncompressed TCP"},
	{PPP_BPDU,      "Bridging PDU"},
	{PPP_ST,	"Stream Protocol (ST-II)" },
	{PPP_VINES,     "Vines"          },
	{PPP_AT_EDDP,	"AppleTalk EDDP" },
	{PPP_AT_SB,	"AppleTalk SmartBuffered" },
	{PPP_MP,	"Multilink"},
	{PPP_NB,	"NETBIOS Framing" },
	{PPP_CISCO,	"Cisco Systems" },
	{PPP_ASCOM,	"Ascom Timeplex" },
	{PPP_LBLB,	"Fujitsu Link Backup and Load Balancing" },
	{PPP_RL,	"DCA Remote Lan" },
	{PPP_SDTP,	"Serial Data Transport Protocol" },
	{PPP_LLC,	"SNA over LLC" },
	{PPP_SNA,	"SNA" },
	{PPP_IPV6HC,	"IPv6 Header Compression " },
	{PPP_KNX,	"KNX Bridging Data" },
	{PPP_ENCRYPT,	"Encryption" },
	{PPP_ILE,	"Individual Link Encryption" },
	{PPP_IPV6,      "IPv6"           },
        {PPP_MUX,       "PPP Multiplexing"},
	{PPP_RTP_FH,	"RTP IPHC Full Header" },
	{PPP_RTP_CTCP,	"RTP IPHC Compressed TCP" },
	{PPP_RTP_CNTCP,	"RTP IPHC Compressed Non TCP" },
	{PPP_RTP_CUDP8,	"RTP IPHC Compressed UDP 8" },
	{PPP_RTP_CRTP8,	"RTP IPHC Compressed RTP 8" },
	{PPP_STAMPEDE,	"Stampede Bridging" },
	{PPP_MPPLUS,	"MP+ Protocol" },
	{PPP_NTCITS_IPI,"NTCITS IPI" },
	{PPP_ML_SLCOMP,	"single link compression in multilink" },
	{PPP_COMP,	"compressed packet" },
	{PPP_STP_HELLO,	"802.1D Hello Packet" },
	{PPP_IBM_SR,	"IBM Source Routing BPDU" },
	{PPP_DEC_LB,	"DEC LANBridge100 Spanning Tree"},
	{PPP_CDP,       "Cisco Discovery Protocol" },
	{PPP_NETCS,	"Netcs Twin Routing" },
	{PPP_STP,       "Scheduled Transfer Protocol" },
	{PPP_EDP,       "Extreme Discovery Protocol" },
	{PPP_OSCP,	"Optical Supervisory Channel Protocol" },
	{PPP_OSCP2,	"Optical Supervisory Channel Protocol" },
	{PPP_LUXCOM,	"Luxcom" },
	{PPP_SIGMA,	"Sigma Network Systems" },
	{PPP_ACSP,	"Apple Client Server Protocol" },
	{PPP_MPLS_UNI,  "MPLS Unicast"},
	{PPP_MPLS_MULTI, "MPLS Multicast"},
	{PPP_P12844,	"IEEE p1284.4 standard - data packets" },
	{PPP_ETSI,	"ETSI TETRA Networks Procotol Type 1" },
	{PPP_MFTP,	"Multichannel Flow Treatment Protocol" },
	{PPP_RTP_CTCPND,"RTP IPHC Compressed TCP No Delta" },
	{PPP_RTP_CS,	"RTP IPHC Context State" },
	{PPP_RTP_CUDP16,"RTP IPHC Compressed UDP 16" },
	{PPP_RTP_CRDP16,"RTP IPHC Compressed RTP 16" },
	{PPP_CCCP,	"Cray Communications Control Protocol" },
	{PPP_CDPD_MNRP,	"CDPD Mobile Network Registration Protocol" },
	{PPP_EXPANDAP,	"Expand accelarator protocol" },
	{PPP_ODSICP,	"ODSICP NCP" },
	{PPP_DOCSIS,	"DOCSIS DLL" },
	{PPP_LZS,	"Stacker LZS" },
	{PPP_REFTEK,	"RefTek Protocol" },
	{PPP_FC,	"Fibre Channel" },
	{PPP_EMIT,	"EMIT Protocols" },
	{PPP_IPCP,	"IP Control Protocol" },
	{PPP_OSICP,     "OSI Control Protocol" },
	{PPP_XNSIDPCP,	"Xerox NS IDP Control Protocol" },
	{PPP_DECNETCP,	"DECnet Phase IV Control Protocol" },
	{PPP_ATCP,	"AppleTalk Control Protocol" },
	{PPP_IPXCP,	"IPX Control Protocol" },
	{PPP_BRIDGENCP,	"Bridging NCP" },
	{PPP_SPCP,	"Stream Protocol Control Protocol" },
	{PPP_BVCP,	"Banyan Vines Control Protocol" },
	{PPP_MLCP,	"Multi-Link Control Protocol" },
	{PPP_NBCP,	"NETBIOS Framing Control Protocol" },
	{PPP_CISCOCP,	"Cisco Systems Control Protocol" },
	{PPP_ASCOMCP,	"Ascom Timeplex" },
	{PPP_LBLBCP,	"Fujitsu LBLB Control Protocol" },
	{PPP_RLNCP,	"DCA Remote Lan Network Control Protocol" },
	{PPP_SDCP,	"Serial Data Control Protocol" },
	{PPP_LLCCP,	"SNA over LLC Control Protocol" },
	{PPP_SNACP,	"SNA Control Protocol" },
	{PPP_KNXCP,	"KNX Bridging Control Protocol" },
	{PPP_ECP,	"Encryption Control Protocol" },
	{PPP_ILECP,	"Individual Encryption Control Protocol" },
	{PPP_IPV6CP,	"IPv6 Control Protocol" },
	{PPP_MUXCP,     "PPPMux Control Protocol"},
	{PPP_STAMPEDECP,"Stampede Bridging Control Protocol" },
	{PPP_MPPCP,	"MP+ Contorol Protocol" },
	{PPP_IPICP,	"NTCITS IPI Control Protocol" },
	{PPP_SLCC,	"single link compression in multilink control" },
	{PPP_CCP,	"Compression Control Protocol" },
	{PPP_CDPCP,	"CDP Control Protocol" },
	{PPP_NETCSCP,	"Netcs Twin Routing" },
	{PPP_STPCP,	"STP - Control Protocol" },
	{PPP_EDPCP,	"EDP Control Protocol" },
	{PPP_ACSPC,	"Apple Client Server Protocol Control" },
	{PPP_MPLSCP,	"MPLS Control Protocol" },
	{PPP_P12844CP,	"IEEE p1284.4 standard - Protocol Control" },
	{PPP_ETSICP,	"ETSI TETRA TNP1 Control Protocol" },
	{PPP_MFTPCP,	"Multichannel Flow Treatment Protocol" },
	{PPP_LCP,	"Link Control Protocol" },
	{PPP_PAP,	"Password Authentication Protocol"  },
	{PPP_LQR,	"Link Quality Report protocol" },
	{PPP_SPAP,	"Shiva Password Authentication Protocol" },
	{PPP_CBCP,	"Callback Control Protocol" },
	{PPP_BACP,	"Bandwidth Allocation Control Protocol" },
	{PPP_BAP,	"Bandwidth Allocation Protocol" },
	{PPP_CONTCP,	"Container Control Protocol" },
	{PPP_CHAP,	"Challenge Handshake Authentication Protocol" },
	{PPP_RSAAP,	"RSA Authentication Protocol" },
	{PPP_EAP,	"Extensible Authentication Protocol" },
	{PPP_SIEP,	"Mitsubishi Security Information Exchange Protocol"},
	{PPP_SBAP,	"Stampede Bridging Authorization Protocol" },
	{PPP_PRPAP,	"Proprietary Authentication Protocol" },
	{PPP_PRPAP2,	"Proprietary Authentication Protocol" },
	{PPP_PRPNIAP,	"Proprietary Node ID Authentication Protocol" },
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
		NULL,
		FIXED_LENGTH,
		4,
		dissect_lcp_mru_opt
	},
	{
		CI_ASYNCMAP,
		"Async Control Character Map",
		NULL,
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
		"Magic number",
		NULL,
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
		"FCS alternatives",
		&ett_lcp_fcs_alternatives_opt,
		FIXED_LENGTH,
		3,
		dissect_lcp_fcs_alternatives_opt
	},
	{
		CI_SELF_DESCRIBING_PAD,
		"Maximum octets of self-describing padding",
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
		"Multilink MRRU",
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
		"Link discriminator for BAP",
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
static void dissect_ipcp_compress_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree);
static void dissect_ipcp_iphc_disableprot_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
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
		"IP compression",
		&ett_ipcp_compress_opt,
		VARIABLE_LENGTH,
		4,
		dissect_ipcp_compress_opt
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
 * IP Compression options
 */
#define IPCP_COMPRESS_VJ_1172	0x37	/* value defined in RFC1172 (typo) */
#define IPCP_COMPRESS_VJ	0x2d	/* value defined in RFC1332 (correct) */
#define IPCP_COMPRESS_IPHC	0x61

const value_string ipcp_compress_proto_vals[] = {
    { IPCP_COMPRESS_VJ_1172,	"VJ compression (RFC1172-typo)" },
    { IPCP_COMPRESS_VJ,		"VJ compression" },
    { IPCP_COMPRESS_IPHC,	"IPHC compression" },
    { 0,			NULL }
};

/* IPHC suboptions (RFC2508, 3544) */
#define IPCP_IPHC_CRTP		1
#define IPCP_IPHC_ECRTP		2
#define IPCP_IPHC_DISABLE_PROTO	3	/* Disable compression for protocol */

const value_string ipcp_iphc_disable_proto_vals[] = {
    { 1,	"TCP" },
    { 2,	"Non-TCP" },
    { 0,	NULL }
};

static const ip_tcp_opt ipcp_iphc_subopts[] = {
	{
		IPCP_IPHC_CRTP,
		"RTP compression (RFC2508)",
		NULL,
		FIXED_LENGTH,
		2,
		NULL
	},
	{
		IPCP_IPHC_ECRTP,
		"Enhanced RTP compression (RFC3545)",
		NULL,
		FIXED_LENGTH,
		2,
		NULL
	},
	{
		IPCP_IPHC_DISABLE_PROTO,
		"Enhanced RTP compression (RFC3545)",
		&ett_ipcp_iphc_disableprot_opt,
		FIXED_LENGTH,
		3,
		dissect_ipcp_iphc_disableprot_opt
	},
};

#define N_IPCP_IPHC_SUBOPTS (sizeof ipcp_iphc_subopts / sizeof ipcp_iphc_subopts[0])


/*
 * Options.  (OSICP)
 */
#define CI_OSICP_ALIGN_NPDU      1       /* Alignment of the OSI NPDU (RFC 1377) */

static void dissect_osicp_align_npdu_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
                        proto_tree *tree);

static const ip_tcp_opt osicp_opts[] = {
        {
                CI_OSICP_ALIGN_NPDU,
                "Align-NPDU",
                &ett_osicp_align_npdu_opt,
                FIXED_LENGTH,
                3,
                dissect_osicp_align_npdu_opt
        }
};

#define N_OSICP_OPTS     (sizeof osicp_opts / sizeof osicp_opts[0])

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
#define CI_CCP_GFZA	19	/* Gandalf FZA (RFC1962) */
#define CI_CCP_V42BIS	20	/* V.42bis compression */
#define CI_CCP_BSDLZW	21	/* BSD LZW Compress (RFC1977) */
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

static void dissect_ccp_bsdcomp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_ccp_lzsdcp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_ccp_mvrca_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static void dissect_ccp_deflate_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
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
		CI_CCP_BSDLZW,
		"BSD Compress",
		&ett_ccp_bsdcomp_opt,
		FIXED_LENGTH,
		3,
		dissect_ccp_bsdcomp_opt
	},
	{
		CI_CCP_LZSDCP,
		"LZS-DCP",
		&ett_ccp_lzsdcp_opt,
		FIXED_LENGTH,
		6,
		dissect_ccp_lzsdcp_opt
	},
	{
		CI_CCP_MVRCA,
		"MVRCA (Magnalink)",
		&ett_ccp_mvrca_opt,
		FIXED_LENGTH,
		4,
		dissect_ccp_mvrca_opt
	},
	{
		CI_CCP_DEFLATE,
		"Deflate",
		&ett_ccp_deflate_opt,
		FIXED_LENGTH,
		4,   /* RFC1979 says the length is 3 but it's actually 4. */
		dissect_ccp_deflate_opt
	},
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
		NULL,
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
		NULL,
		VARIABLE_LENGTH,
		2,
		dissect_bap_reason_opt
	},
	{
		CI_BAP_LINK_DISC,
		"Link Discriminator",
		NULL,
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
		NULL,
		FIXED_LENGTH,
		4,
		dissect_pppmuxcp_def_pid_opt
	}
};

#define N_PPPMUXCP_OPTS (sizeof pppmuxcp_opts / sizeof pppmuxcp_opts[0])

/*
 * Options.  (IPv6CP)
 */
#define CI_IPV6CP_IF_ID		1	/* Interface Identifier (RFC 2472) */
#define CI_IPV6CP_COMPRESSTYPE	2	/* Compression Type (RFC 2472) */

static void dissect_ipv6cp_if_id_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo,
			proto_tree *tree);

static const ip_tcp_opt ipv6cp_opts[] = {
	{
		CI_IPV6CP_IF_ID,
		"Interface Identifier",
		&ett_ipv6cp_if_id_opt,
		FIXED_LENGTH,
		10,
		dissect_ipv6cp_if_id_opt
	},
	{
		CI_COMPRESSTYPE,
		"IPv6 compression",
		&ett_ipv6cp_compress_opt,
		VARIABLE_LENGTH,
		4,
		dissect_ipcp_compress_opt
	},
};

#define N_IPV6CP_OPTS	(sizeof ipv6cp_opts / sizeof ipv6cp_opts[0])

/*
*******************************************************************************
* DETAILS : Calculate a new FCS-16 given the current FCS-16 and the new data.
*******************************************************************************
*/
static guint16
fcs16(tvbuff_t * tvbuff)
{
    guint len = tvb_length(tvbuff)-2;

    /* Check for Invalid Length */
    if (len == 0)
        return (0x0000);
    return crc16_ccitt_tvb(tvbuff, len);
}

/*
*******************************************************************************
* DETAILS : Calculate a new FCS-32 given the current FCS-32 and the new data.
*******************************************************************************
*/
static guint32
fcs32(tvbuff_t * tvbuff)
{
    guint len = tvb_length(tvbuff)-4;

    /* Check for invalid Length */
    if (len == 0)
        return (0x00000000);
    return crc32_ccitt_tvb(tvbuff, len);
}

tvbuff_t *
decode_fcs(tvbuff_t *tvb, proto_tree *fh_tree, int fcs_decode, int proto_offset)
{
  tvbuff_t   *next_tvb;
  gint       len, reported_len;
  int        rx_fcs_offset;
  guint32    rx_fcs_exp;
  guint32    rx_fcs_got;

  /*
   * Remove the FCS, if any, from the packet data.
   */
  switch (fcs_decode) {

  case NO_FCS:
    next_tvb = tvb_new_subset(tvb, proto_offset, -1, -1);
    break;

  case FCS_16:
    /*
     * Do we have the entire packet, and does it include a 2-byte FCS?
     */
    len = tvb_length_remaining(tvb, proto_offset);
    reported_len = tvb_reported_length_remaining(tvb, proto_offset);
    if (reported_len < 2 || len < 0) {
      /*
       * The packet is claimed not to even have enough data for a 2-byte FCS,
       * or we're already past the end of the captured data.
       * Don't slice anything off.
       */
      next_tvb = tvb_new_subset(tvb, proto_offset, -1, -1);
    } else if (len < reported_len) {
      /*
       * The packet is claimed to have enough data for a 2-byte FCS, but
       * we didn't capture all of the packet.
       * Slice off the 2-byte FCS from the reported length, and trim the
       * captured length so it's no more than the reported length; that
       * will slice off what of the FCS, if any, is in the captured
       * length.
       */
      reported_len -= 2;
      if (len > reported_len)
        len = reported_len;
      next_tvb = tvb_new_subset(tvb, proto_offset, len, reported_len);
    } else {
      /*
       * We have the entire packet, and it includes a 2-byte FCS.
       * Slice it off.
       */
      len -= 2;
      reported_len -= 2;
      next_tvb = tvb_new_subset(tvb, proto_offset, len, reported_len);

      /*
       * Compute the FCS and put it into the tree.
       */
      rx_fcs_offset = proto_offset + len;
      rx_fcs_exp = fcs16(tvb);
      rx_fcs_got = tvb_get_letohs(tvb, rx_fcs_offset);
      if (rx_fcs_got != rx_fcs_exp) {
        proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 2,
                            "FCS 16: 0x%04x [incorrect, should be 0x%04x]",
                            rx_fcs_got, rx_fcs_exp);
      } else {
        proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 2,
                            "FCS 16: 0x%04x [correct]",
                            rx_fcs_got);
      }
    }
    break;

  case FCS_32:
    /*
     * Do we have the entire packet, and does it include a 4-byte FCS?
     */
    len = tvb_length_remaining(tvb, proto_offset);
    reported_len = tvb_reported_length_remaining(tvb, proto_offset);
    if (reported_len < 4) {
      /*
       * The packet is claimed not to even have enough data for a 4-byte FCS.
       * Just pass on the tvbuff as is.
       */
      next_tvb = tvb_new_subset(tvb, proto_offset, -1, -1);
    } else if (len < reported_len) {
      /*
       * The packet is claimed to have enough data for a 4-byte FCS, but
       * we didn't capture all of the packet.
       * Slice off the 4-byte FCS from the reported length, and trim the
       * captured length so it's no more than the reported length; that
       * will slice off what of the FCS, if any, is in the captured
       * length.
       */
      reported_len -= 4;
      if (len > reported_len)
        len = reported_len;
      next_tvb = tvb_new_subset(tvb, proto_offset, len, reported_len);
    } else {
      /*
       * We have the entire packet, and it includes a 4-byte FCS.
       * Slice it off.
       */
      len -= 4;
      reported_len -= 4;
      next_tvb = tvb_new_subset(tvb, proto_offset, len, reported_len);

      /*
       * Compute the FCS and put it into the tree.
       */
      rx_fcs_offset = proto_offset + len;
      rx_fcs_exp = fcs32(tvb);
      rx_fcs_got = tvb_get_letohl(tvb, rx_fcs_offset);
      if (rx_fcs_got != rx_fcs_exp) {
        proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 4,
                            "FCS 32: 0x%08x [incorrect, should be 0x%08x]",
                            rx_fcs_got, rx_fcs_exp);
      } else {
        proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 4,
                            "FCS 32: 0x%08x [correct]",
                            rx_fcs_got);
      }
    }
    break;

  default:
   DISSECTOR_ASSERT_NOT_REACHED();
   next_tvb = NULL;
  }

  return next_tvb;
}

void
capture_ppp_hdlc( const guchar *pd, int offset, int len, packet_counts *ld ) {
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
      capture_ipx(ld);
      break;
    case PPP_VINES:
      capture_vines(ld);
      break;
    default:
      ld->other++;
      break;
  }
}

static void
dissect_lcp_mru_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s: %u", optp->name,
			tvb_get_ntohs(tvb, offset + 2));
}

static void
dissect_lcp_async_map_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  guint32 map;
  char *mapstr;
  static const char *ctrlchars[32] = {
    "NUL", "SOH",       "STX", "ETX",        "EOT",      "ENQ", "ACK", "BEL",
    "BS",  "HT",        "NL",  "VT",         "NP (FF)",  "CR",  "SO",  "SI",
    "DLE", "DC1 (XON)", "DC2", "DC3 (XOFF)", "DC4",      "NAK", "SYN", "ETB",
    "CAN", "EM",        "SUB", "ESC",        "FS",       "GS",  "RS",  "US"
  };
  char *mapp;
  int i;

  /*
   * XXX - walk through the map and show the characters to map?
   * Put them in a subtree of this item, and have the top-level item
   * either say "None", "All", or give a list of the characters?)
   */
  map = tvb_get_ntohl(tvb, offset + 2);
  if (map == 0x00000000)
    mapstr = "None";	/* don't map any control characters */
  else if (map == 0xffffffff)
    mapstr = "All";	/* map all control characters */
  else {
#define MAX_MAPSTR_LEN (32*(10+2)+1)
    mapstr=ep_alloc(MAX_MAPSTR_LEN);
    /*
     * Show the names of the control characters being mapped.
     */
    mapp = mapstr;
    for (i = 0; i < 32; i++) {
      if (map & (1 << i)) {
        mapp+=g_snprintf(mapp, MAX_MAPSTR_LEN-(mapp-mapstr), "%s%s", (mapp==mapstr)?"":", ", ctrlchars[i]);
      }
    }
  }
  proto_tree_add_text(tree, tvb, offset, length, "%s: 0x%08x (%s)", optp->name,
		      map, mapstr);
}

static void
dissect_lcp_protocol_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, packet_info *pinfo _U_,
			proto_tree *tree)
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
			 guint length, packet_info *pinfo _U_,
			 proto_tree *tree)
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
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s: 0x%08x", optp->name,
			tvb_get_ntohl(tvb, offset + 2));
}

static void
dissect_lcp_fcs_alternatives_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
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
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s: %u", optp->name,
			tvb_get_guint8(tvb, offset + 2));
}

static void
dissect_lcp_numbered_mode_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
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
			guint length, packet_info *pinfo _U_,
			proto_tree *tree)
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
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s: %u", optp->name,
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
			int offset, guint length, packet_info *pinfo _U_,
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
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length,
			"%s: 0x%04x", optp->name,
			tvb_get_ntohs(tvb, offset + 2));
}

/* Character set numbers from the IANA charset registry. */
static const value_string charset_num_vals[] = {
	{105, "UTF-8" },
	{0,   NULL }
};

static void
dissect_lcp_internationalization_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
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
			int offset, guint length, packet_info *pinfo _U_,
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
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
			ip_to_str(tvb_get_ptr(tvb, offset + 2, 4)));
}

static void dissect_ipcp_compress_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
    guint8  ub;
    guint16 us;
    proto_item *tf;
    proto_tree *field_tree = NULL;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u byte%s",
			     optp->name, length, plurality(length, "", "s"));

    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    offset += 2;	/* Skip option type + length */
    length -= 2;

    us = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text( field_tree, tvb, offset, 2, "IP compression protocol: %s (0x%04x)",
			 val_to_str( us, ipcp_compress_proto_vals, "Unknown protocol" ),
			 us );
    offset += 2;	/* skip protocol */
    length -= 2;

    if (length > 0) {
	switch ( us ) {
	case IPCP_COMPRESS_VJ_1172:
	case IPCP_COMPRESS_VJ:
	    /* First byte is max slot id */
	    ub = tvb_get_guint8( tvb, offset );
	    proto_tree_add_text( field_tree, tvb, offset, 1,
				 "Max slot id: %u (0x%02x)",
				 ub, ub );
	    offset++;
	    length--;

	    if ( length > 0 ) {
		/* second byte is "compress slot id" */
		ub = tvb_get_guint8( tvb, offset );
		proto_tree_add_text( field_tree, tvb, offset, 1,
				     "Compress slot id: %s (0x%02x)",
				     ub ? "yes" : "no",  ub );
		offset++;
		length--;
	    }
	    break;

	    
	case IPCP_COMPRESS_IPHC:
	    if ( length < 2 ) {
		break;
	    }
	    us = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text( field_tree, tvb, offset, 2,
				 "TCP space: %u (0x%04x)",
				 us, us );
	    offset += 2;
	    length -= 2;


	    if ( length < 2 ) {
		break;
	    }
	    us = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text( field_tree, tvb, offset, 2,
				 "Non-TCP space: %u (0x%04x)",
				 us, us );
	    offset += 2;
	    length -= 2;


	    if ( length < 2 ) {
		break;
	    }
	    us = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text( field_tree, tvb, offset, 2,
				 "Max period: %u (0x%04x) compressed packets",
				 us, us );
	    offset += 2;
	    length -= 2;


	    if ( length < 2 ) {
		break;
	    }
	    us = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text( field_tree, tvb, offset, 2,
				 "Max time: %u (0x%04x) seconds",
				 us, us );
	    offset += 2;
	    length -= 2;


	    if ( length < 2 ) {
		break;
	    }
	    us = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text( field_tree, tvb, offset, 2,
				 "Max header: %u (0x%04x) bytes",
				 us, us );
	    offset += 2;
	    length -= 2;

	    if ( length > 0 ) {
		/* suboptions */
		tf = proto_tree_add_text(field_tree, tvb, offset, length,
					 "Suboptions: (%u byte%s)",
					 length, plurality(length, "", "s"));
		field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
		dissect_ip_tcp_options(tvb, offset, length,
				       ipcp_iphc_subopts, N_IPCP_IPHC_SUBOPTS, -1,
				       pinfo, field_tree);
	    }
	    return;
	}

	if (length > 0) {
	    proto_tree_add_text(field_tree, tvb, offset, length,
				"Data (%d byte%s)", length,
				plurality(length, "", "s"));
	}
    }
}

static void dissect_ipcp_iphc_disableprot_opt(const ip_tcp_opt *optp,
					      tvbuff_t *tvb,
					      int offset, guint length,
					      packet_info *pinfo _U_,
					      proto_tree *tree)
{
    proto_item *tf;
    proto_tree *field_tree;
    guint8 param;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    param = tvb_get_guint8(tvb, offset + 2);
    proto_tree_add_text(field_tree, tvb, offset + 2, 1,
			"Protocol: %s (0x%02x)",
			val_to_str( param, ipcp_iphc_disable_proto_vals, "Unknown" ),
			param );
}


static void dissect_osicp_align_npdu_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
                        int offset, guint length, packet_info *pinfo _U_,
                        proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;
  guint8 alignment;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  alignment = tvb_get_guint8(tvb, offset + 2);
  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
      "Alignment: %u", alignment);
}

static void dissect_pppmuxcp_def_pid_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  pppmux_def_prot_id = tvb_get_ntohs(tvb, offset + 2);
  proto_tree_add_text(tree, tvb, offset + 2, length - 2, "%s: %s (0x%02x)",optp->name,
		      val_to_str(pppmux_def_prot_id, ppp_vals, "Unknown"), pppmux_def_prot_id);
}


static void
dissect_ccp_stac_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;
  guint8 check_mode;

  if (length == 6) {
    proto_tree_add_text(tree, tvb, offset, length,
			"%s (Ascend Proprietary version)", optp->name);
    /* We don't know how to decode the following 4 octets, since
       there's no public document that describe their usage. */
  } else {
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_text(field_tree, tvb, offset + 2, 2,
			"History Count: %u", tvb_get_ntohs(tvb, offset + 2));
    check_mode = tvb_get_guint8(tvb, offset + 4);
    proto_tree_add_text(field_tree, tvb, offset + 4, 1,
			"Check Mode: %s (0x%02X)",
			val_to_str(check_mode, stac_checkmode_vals, "Unknown"),
			check_mode);
  }
}

static void
dissect_ccp_mppc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *flags_tree;
  guint32 supported_bits;

  supported_bits = tvb_get_ntohl(tvb, offset + 2);
  tf = proto_tree_add_text(tree, tvb, offset, length,
	      "%s: Supported Bits: 0x%08X", optp->name, supported_bits);
  flags_tree = proto_item_add_subtree(tf, *optp->subtree_index);
  proto_tree_add_text(flags_tree, tvb, offset + 2, 4, "%s",
      decode_boolean_bitfield(supported_bits, MPPC_SUPPORTED_BITS_C, 8*4,
      "Desire to negotiate MPPC", "NO Desire to negotiate MPPC"));
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
dissect_ccp_bsdcomp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
		      "Version: %u", tvb_get_guint8(tvb, offset + 2) >> 5);
  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
		      "Dict: %u bits",
		      tvb_get_guint8(tvb, offset + 2) & 0x1f);
}

static void
dissect_ccp_lzsdcp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;
  guint8 check_mode;
  guint8 process_mode;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  proto_tree_add_text(field_tree, tvb, offset + 2, 2,
		      "History Count: %u", tvb_get_ntohs(tvb, offset + 2));
  check_mode = tvb_get_guint8(tvb, offset + 4);
  proto_tree_add_text(field_tree, tvb, offset + 4, 1,
		      "Check Mode: %s (0x%02X)",
		      val_to_str(check_mode, lzsdcp_checkmode_vals, "Unknown"),
		      check_mode);
  process_mode = tvb_get_guint8(tvb, offset + 5);
  proto_tree_add_text(field_tree, tvb, offset + 5, 1,
		      "Process Mode: %s (0x%02X)",
		      val_to_str(process_mode, lzsdcp_processmode_vals, "Unkown"),
		      process_mode);
}

static void
dissect_ccp_mvrca_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
		      "Features: %u", tvb_get_guint8(tvb, offset + 2) >> 5);
  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
		      "Packet by Packet flag: %s",
		      tvb_get_guint8(tvb, offset + 2) & 0x20 ? "true" : "false");
  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
		      "History: %u", tvb_get_guint8(tvb, offset + 2) & 0x20);
  proto_tree_add_text(field_tree, tvb, offset + 3, 1,
		      "Number of contexts: %u", tvb_get_guint8(tvb, offset + 3));
}

static void
dissect_ccp_deflate_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;
  guint8 method;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
		      "Window: %u", hi_nibble(tvb_get_guint8(tvb, offset + 2)));
  method = lo_nibble(tvb_get_guint8(tvb, offset + 2));
  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
		      "Method: %s (0x%02x)",
		      method == 0x08 ?  "zlib compression" : "other", method);
  proto_tree_add_text(field_tree, tvb, offset + 3, 1,
		      "Sequence number check method: %u",
		      tvb_get_guint8(tvb, offset + 2) & 0x03);
}

static void
dissect_cbcp_no_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
}

static void
dissect_cbcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;
  proto_item *ta;
  proto_tree *addr_tree;
  guint8 addr_type;
  guint addr_len;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
		      "Callback delay: %u", tvb_get_guint8(tvb, offset + 2));
  offset += 3;
  length -= 3;

  while (length > 0) {
    ta = proto_tree_add_text(field_tree, tvb, offset, length,
			     "Callback Address");
    addr_type = tvb_get_guint8(tvb, offset);
    addr_tree = proto_item_add_subtree(tf, ett_cbcp_callback_opt_addr);
    proto_tree_add_text(addr_tree, tvb, offset, 1,
			"Address Type: %s (%u)",
			((addr_type == 1) ? "PSTN/ISDN" : "Other"), addr_type);
    offset++;
    length--;
    addr_len = tvb_strsize(tvb, offset);
    if (addr_len > length) {
      proto_tree_add_text(addr_tree, tvb, offset, length,
			  "Address: (runs past end of option)");
      break;
    }
    proto_tree_add_text(addr_tree, tvb, offset, addr_len,
			"Address: %s",
			tvb_format_text(tvb, offset, addr_len - 1));
    offset += addr_len;
    length -= addr_len;
  }
}

static void
dissect_bacp_favored_peer_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  proto_tree_add_text(field_tree, tvb, offset + 2, 4,
		      "Magic number: 0x%08x", tvb_get_ntohl(tvb, offset + 2));
}

static void
dissect_bap_link_type_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;
  guint8 link_type;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  proto_tree_add_text(field_tree, tvb, offset + 2, 2,
	      "Link Speed: %u kbps", tvb_get_ntohs(tvb, offset + 2));
  link_type = tvb_get_guint8(tvb, offset + 4);
  proto_tree_add_text(field_tree, tvb, offset + 4, 1,
	      "Link Type: %s (%u)", val_to_str(link_type, bap_link_type_vals,
						"Unknown"), link_type);
}

static void
dissect_bap_phone_delta_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;
  proto_item *ti;
  proto_tree *suboption_tree;
  guint8 subopt_type;
  guint8 subopt_len;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  offset += 2;
  length -= 2;

  while (length > 0) {
    subopt_type = tvb_get_guint8(tvb, offset);
    subopt_len = tvb_get_guint8(tvb, offset + 1);
    ti = proto_tree_add_text(field_tree, tvb, offset, subopt_len,
		"Sub-Option (%u byte%s)",
		subopt_len, plurality(subopt_len, "", "s"));
    suboption_tree = proto_item_add_subtree(ti, ett_bap_phone_delta_subopt);

    proto_tree_add_text(suboption_tree, tvb, offset, 1,
	"Sub-Option Type: %s (%u)",
	val_to_str(subopt_type, bap_phone_delta_subopt_vals, "Unknown"),
	subopt_type);

    if (subopt_len < 2) {
      proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
	  "Sub-Option Length: %u (invalid, must be >= 2)", subopt_len);
      return;
    }
    if (subopt_len > length) {
      proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
	  "Sub-Option Length: %u (invalid, must be <= length remaining in option %u)", subopt_len, length);
      return;
    }

    proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
	"Sub-Option Length: %u", subopt_len);

    switch (subopt_type) {
    case BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT:
      if (subopt_len == 3) {
        proto_tree_add_text(suboption_tree, tvb, offset + 2, 1, "Unique Digit: %u",
			    tvb_get_guint8(tvb, offset + 2));
      } else {
        proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
			  "Invalid suboption length: %u (must be == 3)",
			  subopt_len);
      }
      break;
    case BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM:
      if (subopt_len > 2) {
        proto_tree_add_text(suboption_tree, tvb, offset + 2, subopt_len - 2,
			  "Subscriber Number: %s",
			  tvb_format_text(tvb, offset + 2, subopt_len - 2));
      } else {
        proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
			  "Invalid suboption length: %u (must be > 2)",
			  subopt_len);
      }
      break;
    case BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR:
      if (subopt_len > 2) {
        proto_tree_add_text(suboption_tree, tvb, offset + 2, subopt_len - 2,
			  "Phone Number Sub Address: %s",
			  tvb_format_text(tvb, offset + 2, subopt_len - 2));
      } else {
        proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
			  "Invalid suboption length: %u (must be > 2)",
			  subopt_len);
      }
      break;
    default:
      if (subopt_len > 2) {
        proto_tree_add_text(suboption_tree, tvb, offset + 2, subopt_len - 2,
			  "Unknown");
      } else {
        proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
			  "Invalid suboption length: %u (must be > 2)",
			  subopt_len);
      }
      break;
    }
    offset += subopt_len;
    length -= subopt_len;
  }
}

static void
dissect_bap_reason_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  if (length > 2) {
    proto_tree_add_text(tree, tvb, offset, length, "%s: %s",
			   optp->name,
			   tvb_format_text(tvb, offset + 2, length - 2));
  }
}

static void
dissect_bap_link_disc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s: 0x%04x",
		      optp->name, tvb_get_ntohs(tvb, offset + 2));
}

static void
dissect_bap_call_status_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_item *tf;
  proto_tree *field_tree;
  guint8 status, action;

  tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
  field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

  status = tvb_get_guint8(tvb, offset + 2);
  proto_tree_add_text(field_tree, tvb, offset + 2, 1,
      "Status: %s (0x%02x)",
      val_to_str(status, q931_cause_code_vals, "Unknown"), status);

  action = tvb_get_guint8(tvb, offset + 3);
  proto_tree_add_text(field_tree, tvb, offset + 3, 1,
      "Action: %s (0x%02x)",
      val_to_str(action, bap_call_status_opt_action_vals, "Unknown"), action);
}

static void
dissect_cp( tvbuff_t *tvb, int proto_id, int proto_subtree_index,
	const value_string *proto_vals, int options_subtree_index,
	const ip_tcp_opt *opts, int nopts, packet_info *pinfo,
	proto_tree *tree )
{
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
		proto_get_protocol_short_name(find_protocol_by_id(proto_id)));

  if(check_col(pinfo->cinfo, COL_INFO))
	col_add_str(pinfo->cinfo, COL_INFO,
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

    case IDENT:
      if(tree) {
	proto_tree_add_text(fh_tree, tvb, offset, 4, "Magic number: 0x%08x",
			tvb_get_ntohl(tvb, offset));
	offset += 4;
	length -= 4;
	if (length > 0)
          proto_tree_add_text(fh_tree, tvb, offset, length, "Message: %s",
				tvb_format_text(tvb, offset, length));
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
	gboolean save_in_error_pkt;
	tvbuff_t *next_tvb;

	protocol = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(fh_tree, tvb, offset, 2,
			    "Rejected protocol: %s (0x%04x)",
			    val_to_str(protocol, ppp_vals, "Unknown"),
			    protocol);
	offset += 2;
	length -= 2;
	if (length > 0) {
          proto_tree_add_text(fh_tree, tvb, offset, length,
			      "Rejected packet (%d byte%s)",
			      length, plurality(length, "", "s"));

	  /* Save the current value of the "we're inside an error packet"
	     flag, and set that flag; subdissectors may treat packets
	     that are the payload of error packets differently from
	     "real" packets. */
	  save_in_error_pkt = pinfo->in_error_pkt;
	  pinfo->in_error_pkt = TRUE;

	  /* Decode the rejected packet. */
	  next_tvb = tvb_new_subset(tvb, offset, length, length);
	  if (!dissector_try_port(ppp_subdissector_table, protocol,
				  next_tvb, pinfo, fh_tree)) {
	    call_dissector(data_handle, next_tvb, pinfo, fh_tree);
	  }

	  /* Restore the "we're inside an error packet" flag. */
	  pinfo->in_error_pkt = save_in_error_pkt;
        }
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
dissect_ppp_common( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		proto_tree *fh_tree, proto_item *ti, int proto_offset )
{
  guint16 ppp_prot;
  int     proto_len;
  tvbuff_t	*next_tvb;

  ppp_prot = tvb_get_guint8(tvb, 0);
  if (ppp_prot & PFC_BIT) {
    /* Compressed protocol field - just the byte we fetched. */
    proto_len = 1;
  } else {
    /* Uncompressed protocol field - fetch all of it. */
    ppp_prot = tvb_get_ntohs(tvb, 0);
    proto_len = 2;
  }

  /* If "ti" is not null, it refers to the top-level "proto_ppp" item
     for PPP, and proto_offset is the length of any stuff in the header
     preceding the protocol type, e.g. an HDLC header; add the length
     of the protocol type field to it, and set the length of that item
     to the result. */
  if (ti != NULL)
    proto_item_set_len(ti, proto_offset + proto_len);

  if (tree)
    proto_tree_add_uint(fh_tree, hf_ppp_protocol, tvb, 0, proto_len, ppp_prot);

  next_tvb = tvb_new_subset(tvb, proto_len, -1, -1);

  /* do lookup with the subdissector table */
  if (!dissector_try_port(ppp_subdissector_table, ppp_prot, next_tvb, pinfo, tree)) {
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", ppp_prot);
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_fstr(pinfo->cinfo, COL_INFO, "PPP %s (0x%04x)",
		   val_to_str(ppp_prot, ppp_vals, "Unknown"), ppp_prot);
    call_dissector(data_handle,next_tvb, pinfo, tree);
  }
}

static void
dissect_lcp_options(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_ip_tcp_options(tvb, 0, tvb_reported_length(tvb), lcp_opts, N_LCP_OPTS, 
            -1, pinfo, tree);
}

/*
 * RFC 1661.
 */
static void
dissect_lcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_lcp, ett_lcp, lcp_vals, ett_lcp_options,
	     lcp_opts, N_LCP_OPTS, pinfo, tree);
}

/*
 * RFC 1332.
 */
static void
dissect_ipcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_ipcp, ett_ipcp, cp_vals, ett_ipcp_options,
	     ipcp_opts, N_IPCP_OPTS, pinfo, tree);
}

/*
 * RFC 1377.
 */
static void
dissect_osicp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_osicp, ett_osicp, cp_vals, ett_osicp_options,
             osicp_opts, N_OSICP_OPTS, pinfo, tree);
}

/*
 * RFC 1962.
 */
static void
dissect_ccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_ccp, ett_ccp, ccp_vals, ett_ccp_options,
	     ccp_opts, N_CCP_OPTS, pinfo, tree);
}

/*
 * Callback Control Protocol - see
 *
 *	http://www.linet.gr.jp/~manabe/PPxP/doc/Standards/draft-gidwani-ppp-callback-cp-00.txt
 */
static void
dissect_cbcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_cbcp, ett_cbcp, cbcp_vals, ett_cbcp_options,
	     cbcp_opts, N_CBCP_OPTS, pinfo, tree);
}

/*
 * RFC 2125 (BACP and BAP).
 */
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
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP BAP");

  if(check_col(pinfo->cinfo, COL_INFO))
	col_add_str(pinfo->cinfo, COL_INFO,
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
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP Comp");

  if(check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed data");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_comp_data, tvb, 0, -1, FALSE);
    comp_data_tree = proto_item_add_subtree(ti, ett_comp_data);
  }
}

/*
 * RFC 3153 (both PPPMuxCP and PPPMux).
 */
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

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo,COL_PROTOCOL, "PPP PPPMux");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_set_str(pinfo->cinfo, COL_INFO, "PPP Multiplexing");

  length_remaining = tvb_reported_length(tvb);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_pppmux, tvb, 0, -1, FALSE);
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

      tvb_ensure_bytes_exist (tvb,offset,length);
      sub_ti = proto_tree_add_text(sub_tree,tvb,offset,length,"Information Field");
      info_tree = proto_item_add_subtree(sub_ti,ett_pppmux_subframe_info);

      next_tvb = tvb_new_subset(tvb,offset,length,-1);

      if (!dissector_try_port(ppp_subdissector_table, pid, next_tvb, pinfo, info_tree)) {
	call_dissector(data_handle, next_tvb, pinfo, info_tree);
      }
      offset += length;
      length_remaining -= length;
    }  /* While length_remaining */
    pid = 0;
  } /* if tree */
}

/*
 * RFC 3032.
 */
static void
dissect_mplscp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_mplscp, ett_mplscp, cp_vals, ett_mplscp_options,
	     NULL, 0, pinfo, tree);
}

/*
 * Cisco Discovery Protocol Control Protocol.
 * XXX - where is this documented?
 */
static void
dissect_cdpcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_cdpcp, ett_cdpcp, cp_vals, ett_cdpcp_options,
	     NULL, 0, pinfo, tree);
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
  proto_tree  *mp_tree, *hdr_tree;
  proto_item  *ti = NULL;
  guint8       flags;
  const gchar *flag_str;
  tvbuff_t    *next_tvb;

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
    ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, -1, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_ppp);
  }

  dissect_ppp_common(tvb, pinfo, tree, fh_tree, ti, 0);
}

static void
dissect_ppp_hdlc_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti = NULL;
  proto_tree *fh_tree = NULL;
  guint8     byte0;
  int        proto_offset;
  tvbuff_t  *next_tvb;

  byte0 = tvb_get_guint8(tvb, 0);

  /* PPP HDLC encapsulation */
  if (byte0 == 0xff)
    proto_offset = 2;
  else {
    /* address and control are compressed (NULL) */
    proto_offset = 0;
  }

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  if(tree) {
    ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, -1, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_ppp);
    if (byte0 == 0xff) {
      proto_tree_add_item(fh_tree, hf_ppp_address, tvb, 0, 1, FALSE);
      proto_tree_add_item(fh_tree, hf_ppp_control, tvb, 1, 1, FALSE);
    }
  }

  next_tvb = decode_fcs(tvb, fh_tree, ppp_fcs_decode, proto_offset);

  dissect_ppp_common(next_tvb, pinfo, tree, fh_tree, ti, proto_offset);
}

/*
 * Handles link-layer encapsulations where the frame might be
 * a PPP in HDLC-like Framing frame (RFC 1662) or a Cisco HDLC frame.
 */
static void
dissect_ppp_hdlc( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
  guint8     byte0;

  byte0 = tvb_get_guint8(tvb, 0);
  if (byte0 == CHDLC_ADDR_UNICAST || byte0 == CHDLC_ADDR_MULTICAST) {
    /* Cisco HDLC encapsulation */
    call_dissector(chdlc_handle, tvb, pinfo, tree);
    return;
  }

  /*
   * XXX - should we have an exported dissector that always dissects PPP,
   * for use when we know the packets are PPP, not CHDLC?
   */
  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP");
  switch (pinfo->p2p_dir) {

  case P2P_DIR_SENT:
    if(check_col(pinfo->cinfo, COL_RES_DL_SRC))
      col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
    if(check_col(pinfo->cinfo, COL_RES_DL_DST))
      col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
    break;

  case P2P_DIR_RECV:
    if(check_col(pinfo->cinfo, COL_RES_DL_SRC))
      col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
    if(check_col(pinfo->cinfo, COL_RES_DL_DST))
      col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
    break;

  default:
    if(check_col(pinfo->cinfo, COL_RES_DL_SRC))
      col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
    if(check_col(pinfo->cinfo, COL_RES_DL_DST))
      col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
    break;
  }

  dissect_ppp_hdlc_common(tvb, pinfo, tree);
}

static tvbuff_t*
remove_escape_chars(tvbuff_t *tvb, int offset, int length)
{
  guint8	*buff;
  int		i;
  int		scanned_len = 0;
  guint8	octet;
  tvbuff_t  *next_tvb;
	
  buff = g_malloc(length);
  i = 0;
  while ( scanned_len < length ){
	  octet = tvb_get_guint8(tvb,offset);
	  if (octet == 0x7d){
		  offset++;
		  scanned_len++;
		  if (scanned_len >= length)
			  break;
		  octet = tvb_get_guint8(tvb,offset);
		  buff[i] = octet ^ 0x20;
	  }else{
		  buff[i]= octet;
	  }
	  offset++;
	  scanned_len++;
	  i++;
  }
  if (i == 0) {
	  g_free(buff);
	  return NULL;
  }
  next_tvb = tvb_new_real_data(buff,i,i);

  /* Arrange that the allocated packet data copy be freed when the
   * tvbuff is freed. 
   */
  tvb_set_free_cb( next_tvb, g_free );

  tvb_set_child_real_data_tvbuff(tvb,next_tvb);
  return next_tvb;

}

/*
 * Handles link-layer encapsulations where we have a raw RFC 1662
 * HDLC-like asynchronous framing byte stream, and have to
 * break the byte stream into frames and remove escapes.
 */
static void
dissect_ppp_raw_hdlc( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
  proto_item *ti;
  proto_tree *bs_tree = NULL;
  gint	      offset, end_offset, data_offset;
  int	      length, data_length;
  tvbuff_t   *ppp_tvb;
  gboolean    first = TRUE;

  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP" );

  if (tree) {
    ti = proto_tree_add_item(tree, proto_ppp_hdlc, tvb, 0, -1, FALSE);
    bs_tree = proto_item_add_subtree(ti, ett_ppp_hdlc_data);
  }

  /*
   * XXX - this needs to handle a PPP frame split over multiple higher-level
   * packets.
   */

  /*
   * Look for a frame delimiter.
   */
  offset = tvb_find_guint8(tvb, 0, -1, 0x7e);
  if (offset == -1) {
	  /*
	   * None found - this is presumably continued from an earlier
	   * packet and continued in a later packet.
	   */
	  if (check_col(pinfo->cinfo, COL_INFO)){
		  col_add_str(pinfo->cinfo, COL_INFO,"PPP Fragment");
	  }
	  if (tree)
		  proto_tree_add_text(bs_tree, tvb, offset, -1, "PPP Fragment");
	  offset++;
	  length = tvb_length_remaining(tvb,offset);
	  ppp_tvb = remove_escape_chars(tvb, offset,length);
	  if (ppp_tvb != NULL) {
		  add_new_data_source(pinfo, ppp_tvb, "PPP Fragment");
		  call_dissector(data_handle, ppp_tvb, pinfo, tree);
	  }
	  return;
  }
  if (offset != 0) {
  	  /*
  	   * We have some data preceding the first PPP packet;
  	   * mark it as a PPP fragment.
  	   */
	  if(check_col(pinfo->cinfo, COL_INFO)){
		  col_add_str(pinfo->cinfo, COL_INFO,"PPP Fragment");
	  }
	  length = offset;
	  if (tree)
		  proto_tree_add_text(bs_tree, tvb, 0, length, "PPP Fragment");
	  if (length != 0) {
		  ppp_tvb = remove_escape_chars(tvb, 0, length - 1);
		  if (ppp_tvb != NULL) {
			  add_new_data_source(pinfo, ppp_tvb, "PPP Fragment");
			  call_dissector(data_handle, ppp_tvb, pinfo, tree);
		  }
	  }
  }
  while ( tvb_reported_length_remaining(tvb, offset) > 0 ){
	  /*
	   * Look for the next frame delimiter.
	   */
	  end_offset = tvb_find_guint8(tvb, offset+1, -1, 0x7e);
	  if ( end_offset == -1 ){
	  	  /*
	  	   * We didn't find one.  This is probably continued in
	  	   * a later packet.
	  	   */
		  if (first) {
			  if(check_col(pinfo->cinfo, COL_INFO)){
				  col_add_str(pinfo->cinfo, COL_INFO,"PPP Fragment");
			  }
		  }
		  if (tree)
			  proto_tree_add_text(bs_tree, tvb, offset, -1, "PPP Fragment");
		  offset++;
		  length = tvb_length_remaining(tvb, offset);
		  ppp_tvb = remove_escape_chars(tvb, offset,length);
		  if (ppp_tvb != NULL) {
			  add_new_data_source(pinfo, ppp_tvb, "PPP Fragment");
			  call_dissector(data_handle, ppp_tvb, pinfo, tree);
		  }
		  return;
	  }

	  data_offset = offset+1;	/* skip starting frame delimiter */
	  data_length = end_offset - data_offset;

	  /*
	   * Is that frame delimiter immediately followed by another one?
	   * Some PPP implementations put a frame delimiter at the
	   * beginning and the end of each frame, although RFC 1662
	   * appears only to require that there be one frame delimiter
	   * between adjacent frames:
	   *
	   *  Each frame begins and ends with a Flag Sequence, which is the
	   *  binary sequence 01111110 (hexadecimal 0x7e).  All implementations
	   *  continuously check for this flag, which is used for frame
	   *  synchronization.
	   *
	   *  Only one Flag Sequence is required between two frames.  Two
	   *  consecutive Flag Sequences constitute an empty frame, which is
	   *  silently discarded, and not counted as a FCS error.
	   *
	   * If the delimiter at the end of this frame is followed by
	   * another delimiter, we consider the first delimiter part
	   * of this frame.
	   */
	  if (tvb_offset_exists(tvb, end_offset+1) &&
	      tvb_get_guint8(tvb, end_offset+1) == 0x7e)
		  end_offset++;
	  length = end_offset - offset;
	  if (tree)
		  proto_tree_add_text(bs_tree, tvb, offset, length, "PPP Data");
	  if (length > 1) {
		  ppp_tvb = remove_escape_chars(tvb, data_offset, data_length);
		  if (ppp_tvb != NULL) {
			  add_new_data_source(pinfo, ppp_tvb, "PPP Message");
			  dissect_ppp_hdlc_common(ppp_tvb, pinfo, tree);
			  first = FALSE;
		  }
	  }
	  offset = end_offset;
  } /* end while */
}

void
proto_register_ppp_raw_hdlc(void)
{
  static gint *ett[] = {
    &ett_ppp_hdlc_data
  };

  proto_ppp_hdlc = proto_register_protocol("PPP In HDLC-Like Framing", "PPP-HDLC", "ppp_hdlc");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ppp_raw_hdlc(void)
{
  dissector_handle_t ppp_raw_hdlc_handle;

  ppp_raw_hdlc_handle = create_dissector_handle(dissect_ppp_raw_hdlc, proto_ppp);
  dissector_add("gre.proto", ETHERTYPE_CDMA2000_A10_UBS, ppp_raw_hdlc_handle);
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
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP PAP");

  if(check_col(pinfo->cinfo, COL_INFO))
	col_add_str(pinfo->cinfo, COL_INFO,
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

  guint8 code, id, value_size;
  gint32 length;
  int offset;

  code = tvb_get_guint8(tvb, 0);
  id = tvb_get_guint8(tvb, 1);
  length = tvb_get_ntohs(tvb, 2);

  if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP CHAP");

  if(check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(code, chap_vals, "Unknown"));

  if(tree) {
    /* Create CHAP protocol tree */
    ti = proto_tree_add_item(tree, proto_chap, tvb, 0, length, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_chap);

    /* Code */
    proto_tree_add_item(fh_tree, hf_chap_code, tvb, 0, 1, FALSE);

    /* Identifier */
    proto_tree_add_item(fh_tree, hf_chap_identifier, tvb, 1, 1, FALSE);
    
    /* Show length if valid */
    if(length < 4)
    {
      proto_tree_add_text(fh_tree, tvb, 2, 2, "Length: %u (invalid, must be >= 4)",
                          length);
      return;
    }
    proto_tree_add_item(fh_tree, hf_chap_length, tvb, 2, 2, FALSE);    
  }

  /* Offset moved to after length field */
  offset = 4;
  /* Length includes previous 4 bytes, subtract */ 
  length -= 4;

  switch (code) {
    /* Challenge or Response data */
    case CHAP_CHAL:
    case CHAP_RESP:
      if(tree) {
        if (length > 0) {
          guint value_offset=0;
          guint name_offset=0, name_size = 0;

          /* Create data subtree */
          tf = proto_tree_add_text(fh_tree, tvb, offset, length,
                                   "Data (%d byte%s)", length,
                                   plurality(length, "", "s"));
          field_tree = proto_item_add_subtree(tf, ett_chap_data);
          length--;

          /* Value size */
          value_size = tvb_get_guint8(tvb, offset);
          if (value_size > length) {
            proto_tree_add_text(field_tree, tvb, offset, 1,
                                "Value Size: %d byte%s (invalid, must be <= %u)",
                                value_size, plurality(value_size, "", "s"),
                                length);
            return;
          }
          proto_tree_add_item(field_tree, hf_chap_value_size, tvb, offset, 1, FALSE);
          offset++;

          /* Value */
          if (length > 0) {
            value_offset = offset;
            proto_tree_add_item(field_tree, hf_chap_value, tvb, offset, value_size, FALSE);

            /* Move along value_size bytes */
            offset+=value_size;
            length-=value_size;

            /* Find name in remaining bytes */
            if (length > 0) {
              tvb_ensure_bytes_exist(tvb, offset, length);
              proto_tree_add_item(field_tree, hf_chap_name, tvb, offset, length, FALSE);
              name_offset = offset;
              name_size = length;
            }

            /* Show name and value in info column */
            if(check_col(pinfo->cinfo, COL_INFO)){
              col_append_fstr(pinfo->cinfo, COL_INFO, " (NAME='0x%s%s', VALUE=0x%s)",
                              tvb_get_ephemeral_string(tvb, name_offset,
                                                       (name_size > 20) ? 20 : name_size),
                              (name_size > 20) ? "..." : "",
                              tvb_bytes_to_str(tvb, value_offset, value_size));
            }
          }
        }
      }
      break;

    /* Success or Failure data */
    case CHAP_SUCC:
    case CHAP_FAIL:
      if(tree) {
        if (length > 0) {
          proto_tree_add_item(fh_tree, hf_chap_message, tvb, offset, length, FALSE);
        }
      }
      
      /* Show message in info column */
      if(check_col(pinfo->cinfo, COL_INFO)){
        col_append_fstr(pinfo->cinfo, COL_INFO, " (MESSAGE='%s')",
                        tvb_get_ephemeral_string(tvb, offset, length));
      }
      break;

    /* Code from unknown code type... */
    default:
      if (length > 0)
        proto_tree_add_text(fh_tree, tvb, offset, length, "Stuff (%u byte%s)",
                            length, plurality(length, "", "s"));
      break;
  }
}

/*
 * RFC 2472.
 */
static void
dissect_ipv6cp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_cp(tvb, proto_ipv6cp, ett_ipv6cp, cp_vals, ett_ipv6cp_options,
	     ipv6cp_opts, N_IPV6CP_OPTS, pinfo, tree);
}

static void dissect_ipv6cp_if_id_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, packet_info *pinfo _U_,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s: %02x%02x:%02x%02x:%02x%x:%02x%02x",
		      optp->name,
		      tvb_get_guint8(tvb, offset + 2),
		      tvb_get_guint8(tvb, offset + 3),
		      tvb_get_guint8(tvb, offset + 4),
		      tvb_get_guint8(tvb, offset + 5),
		      tvb_get_guint8(tvb, offset + 6),
		      tvb_get_guint8(tvb, offset + 7),
		      tvb_get_guint8(tvb, offset + 8),
		      tvb_get_guint8(tvb, offset + 9)
		      );
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
    &ett_ppp
  };

  module_t *ppp_module;

  proto_ppp = proto_register_protocol("Point-to-Point Protocol", "PPP", "ppp");
  proto_register_field_array(proto_ppp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
  ppp_subdissector_table = register_dissector_table("ppp.protocol",
	"PPP protocol", FT_UINT16, BASE_HEX);

  register_dissector("ppp_hdlc", dissect_ppp_hdlc, proto_ppp);
  register_dissector("ppp_lcp_options", dissect_lcp_options, proto_ppp);
  register_dissector("ppp", dissect_ppp, proto_ppp);

  /* Register the preferences for the ppp protocol */
  ppp_module = prefs_register_protocol(proto_ppp, NULL);

  prefs_register_enum_preference(ppp_module,
	"fcs_type",
	"PPP Frame Checksum Type",
	"The type of PPP frame checksum (none, 16-bit, 32-bit)",
	&ppp_fcs_decode,
	fcs_options, FALSE);
  prefs_register_bool_preference(ppp_module,
	"decompress_vj",
	"Decompress Van Jacobson-compressed frames",
	"Whether Van Jacobson-compressed PPP frames should be decompressed",
	&ppp_vj_decomp);
  prefs_register_uint_preference(ppp_module,
	"default_proto_id",
	"PPPMuxCP Default PID",
	"Default Protocol ID to be used for PPPMuxCP",
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

  ppp_handle = find_dissector("ppp");
  dissector_add("fr.ietf", NLPID_PPP, ppp_handle);

  ppp_hdlc_handle = find_dissector("ppp_hdlc");
  dissector_add("wtap_encap", WTAP_ENCAP_PPP, ppp_hdlc_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_PPP_WITH_PHDR, ppp_hdlc_handle);
  dissector_add("osinl.excl", NLPID_PPP, ppp_handle);
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
    &ett_lcp_authprot_opt,
    &ett_lcp_qualprot_opt,
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

  /*
   * for GSM-A / MobileL3 / GPRS SM / PCO
   */
  dissector_add("sm_pco.protocol", PPP_LCP, lcp_handle);

}

void
proto_register_ipcp(void)
{
  static gint *ett[] = {
    &ett_ipcp,
    &ett_ipcp_options,
    &ett_ipcp_ipaddrs_opt,
    &ett_ipcp_compress_opt,
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

  /*
   * for GSM-A / MobileL3 / GPRS SM / PCO
   */
  dissector_add("sm_pco.protocol", PPP_IPCP, ipcp_handle);

}

void
proto_register_osicp(void)
{
  static gint *ett[] = {
    &ett_osicp,
    &ett_osicp_options,
    &ett_osicp_align_npdu_opt,
  };

  proto_osicp = proto_register_protocol("PPP OSI Control Protocol", "PPP OSICP",
                                      "osicp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_osicp(void)
{
  dissector_handle_t osicp_handle;

  osicp_handle = create_dissector_handle(dissect_osicp, proto_osicp);
  dissector_add("ppp.protocol", PPP_OSICP, osicp_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_OSICP, osicp_handle);
}

void
proto_register_ccp(void)
{
  static gint *ett[] = {
    &ett_ccp,
    &ett_ccp_options,
    &ett_ccp_stac_opt,
    &ett_ccp_mppc_opt,
    &ett_ccp_bsdcomp_opt,
    &ett_ccp_lzsdcp_opt,
    &ett_ccp_mvrca_opt,
    &ett_ccp_deflate_opt,
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
    &ett_cbcp_callback_opt,
    &ett_cbcp_callback_opt_addr
  };

  proto_cbcp = proto_register_protocol("PPP Callback Control Protocol",
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
    &ett_bap_phone_delta_subopt,
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

  /*
   * for GSM-A / MobileL3 / GPRS SM / PCO
   */
  dissector_add("sm_pco.protocol", PPP_PAP, pap_handle);
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

  static hf_register_info hf[] =
  {
    {
      &hf_chap_code,
      {
        "Code", "chap.code",
        FT_UINT8, BASE_DEC,
        VALS(chap_vals), 0x0,
        "CHAP code", HFILL
      }
    },
    {
      &hf_chap_identifier,
      {
        "Identifier", "chap.identifier",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        "CHAP identifier", HFILL
      }
    },
    {
      &hf_chap_length,
      {
        "Length", "chap.length",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        "CHAP length", HFILL
      }
    },
    {
      &hf_chap_value_size,
      {
        "Value Size", "chap.value_size",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        "CHAP value size", HFILL
      }
    },
    {
      &hf_chap_value,
      {
        "Value", "chap.value",
        FT_BYTES, BASE_HEX,
        NULL, 0x0,
        "CHAP value data", HFILL
      }
    },
    {
      &hf_chap_name,
      {
        "Name", "chap.value",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        "CHAP name", HFILL
      }
    },
    {
      &hf_chap_message,
      {
        "Message", "chap.message",
        FT_STRING, BASE_NONE,
        NULL, 0x0,
        "CHAP message", HFILL
      }
    }
  };


  proto_chap = proto_register_protocol("PPP Challenge Handshake Authentication Protocol", "PPP CHAP",
                                       "chap");
  proto_register_field_array(proto_chap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_chap(void)
{
  dissector_handle_t chap_handle = create_dissector_handle(dissect_chap, proto_chap);
  dissector_add("ppp.protocol", PPP_CHAP, chap_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_CHAP, chap_handle);
  
  /*
   * for GSM-A / MobileL3 / GPRS SM / PCO
   */
  dissector_add("sm_pco.protocol", PPP_CHAP, chap_handle);
}

void
proto_register_pppmuxcp(void)
{
  static gint *ett[] = {
    &ett_pppmuxcp,
    &ett_pppmuxcp_options,
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

void
proto_register_mplscp(void)
{
  static gint *ett[] = {
    &ett_mplscp,
    &ett_mplscp_options,
  };

  proto_mplscp = proto_register_protocol("PPP MPLS Control Protocol",
					 "PPP MPLSCP", "mplscp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mplscp(void)
{
  dissector_handle_t mplscp_handle;

  mplscp_handle = create_dissector_handle(dissect_mplscp, proto_mplscp);
  dissector_add("ppp.protocol", PPP_MPLSCP, mplscp_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_MPLSCP, mplscp_handle);
}

void
proto_register_cdpcp(void)
{
  static gint *ett[] = {
    &ett_cdpcp,
    &ett_cdpcp_options,
  };

  proto_cdpcp = proto_register_protocol("PPP CDP Control Protocol",
					 "PPP CDPCP", "cdpcp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cdpcp(void)
{
  dissector_handle_t cdpcp_handle;

  cdpcp_handle = create_dissector_handle(dissect_cdpcp, proto_cdpcp);
  dissector_add("ppp.protocol", PPP_CDPCP, cdpcp_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_CDPCP, cdpcp_handle);
}

void
proto_register_ipv6cp(void)
{
  static gint *ett[] = {
    &ett_ipv6cp,
    &ett_ipv6cp_options,
    &ett_ipv6cp_if_id_opt,
    &ett_ipv6cp_compress_opt,
  };

  proto_ipv6cp = proto_register_protocol("PPP IPv6 Control Protocol",
					 "PPP IPV6CP", "ipv6cp");
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipv6cp(void)
{
  dissector_handle_t ipv6cp_handle;

  ipv6cp_handle = create_dissector_handle(dissect_ipv6cp, proto_ipv6cp);
  dissector_add("ppp.protocol", PPP_IPV6CP, ipv6cp_handle);

  /*
   * See above comment about NDISWAN for an explanation of why we're
   * registering with the "ethertype" dissector table.
   */
  dissector_add("ethertype", PPP_IPV6CP, ipv6cp_handle);
}
