/* packet-ppp.c
 * Routines for ppp packet disassembly
 * RFC 1661, RFC 1662
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
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
#include <epan/crc16-tvb.h>
#include <epan/crc32-tvb.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include "packet-usb.h"
#include "packet-sll.h"


static int proto_ppp = -1;
static int hf_ppp_direction = -1;
static int hf_ppp_address = -1;
static int hf_ppp_control = -1;
static int hf_ppp_protocol = -1;
static int hf_ppp_code = -1;
static int hf_ppp_identifier = -1;
static int hf_ppp_length = -1;
static int hf_ppp_magic_number = -1;
static int hf_ppp_oui = -1;
static int hf_ppp_kind = -1;
static int hf_ppp_data = -1;

static gint ett_ppp = -1;

static int proto_ppp_hdlc = -1;

static gint ett_ppp_hdlc_data = -1;

static int proto_lcp = -1;

static gint ett_lcp = -1;
static gint ett_lcp_options = -1;
static gint ett_lcp_vendor_opt = -1;
static gint ett_lcp_mru_opt = -1;
static gint ett_lcp_asyncmap_opt = -1;
static gint ett_lcp_authprot_opt = -1;
static gint ett_lcp_qualprot_opt = -1;
static gint ett_lcp_magicnumber_opt = -1;
static gint ett_lcp_linkqualmon_opt = -1;
static gint ett_lcp_pcomp_opt = -1;
static gint ett_lcp_acccomp_opt = -1;
static gint ett_lcp_fcs_alternatives_opt = -1;
static gint ett_lcp_self_desc_pad_opt = -1;
static gint ett_lcp_numbered_mode_opt = -1;
static gint ett_lcp_callback_opt = -1;
static gint ett_lcp_compound_frames_opt = -1;
static gint ett_lcp_nomdataencap_opt = -1;
static gint ett_lcp_multilink_mrru_opt = -1;
static gint ett_lcp_multilink_ssnh_opt = -1;
static gint ett_lcp_multilink_ep_disc_opt = -1;
static gint ett_lcp_magic_block = -1;
static gint ett_lcp_dce_identifier_opt = -1;
static gint ett_lcp_multilink_pp_opt = -1;
static gint ett_lcp_bacp_link_discrim_opt = -1;
static gint ett_lcp_auth_opt = -1;
static gint ett_lcp_cobs_opt = -1;
static gint ett_lcp_prefix_elision_opt = -1;
static gint ett_multilink_hdr_fmt_opt = -1;
static gint ett_lcp_internationalization_opt = -1;
static gint ett_lcp_simple_opt = -1;

static int proto_ipcp = -1;

static gint ett_ipcp = -1;
static gint ett_ipcp_options = -1;
static gint ett_ipcp_ipaddrs_opt = -1;
static gint ett_ipcp_compress_opt = -1;
static gint ett_ipcp_ipaddr_opt = -1;
static gint ett_ipcp_mobileipv4_opt = -1;
static gint ett_ipcp_pridns_opt = -1;
static gint ett_ipcp_secdns_opt = -1;
static gint ett_ipcp_prinbns_opt = -1;
static gint ett_ipcp_secnbns_opt = -1;

static gint ett_ipcp_iphc_rtp_compress_opt = -1;
static gint ett_ipcp_iphc_enhanced_rtp_compress_opt = -1;
static gint ett_ipcp_iphc_neghdrcomp_opt = -1;
static gint ett_ipcp_rohc_profiles_opt = -1;

static int proto_vsncp = -1;

static gint ett_vsncp = -1;
static gint ett_vsncp_options = -1;

static int proto_vsnp = -1;
static gint hf_vsnp_pdnid = -1;

static gint ett_vsnp =-1;

static int proto_osinlcp = -1;

static gint ett_osinlcp = -1;
static gint ett_osinlcp_options = -1;
static gint ett_osinlcp_align_npdu_opt = -1;

static int proto_bcp = -1;
static int hf_bcp_flags = -1;
static int hf_bcp_fcs_present = -1;
static int hf_bcp_zeropad = -1;
static int hf_bcp_bcontrol = -1;
static int hf_bcp_pads = -1;
static int hf_bcp_mac_type = -1;

static gint ett_bcp = -1;
static gint ett_bcp_flags = -1;

static int proto_ccp = -1;

static gint ett_ccp = -1;
static gint ett_ccp_options = -1;
static gint ett_ccp_oui_opt = -1;
static gint ett_ccp_predict1_opt = -1;
static gint ett_ccp_predict2_opt = -1;
static gint ett_ccp_puddle_opt = -1;
static gint ett_ccp_hpppc_opt = -1;
static gint ett_ccp_stac_opt = -1;
static gint ett_ccp_stac_opt_check_mode = -1;
static gint ett_ccp_mppe_opt = -1;
static gint ett_ccp_mppe_opt_supp_bits = -1;
static gint ett_ccp_gfza_opt = -1;
static gint ett_ccp_v42bis_opt = -1;
static gint ett_ccp_bsdcomp_opt = -1;
static gint ett_ccp_lzsdcp_opt = -1;
static gint ett_ccp_mvrca_opt = -1;
static gint ett_ccp_dce_opt = -1;
static gint ett_ccp_deflate_opt = -1;
static gint ett_ccp_v44lzjh_opt = -1;

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

#if 0  /* see dissect_comp_data() */
static gint ett_comp_data = -1;
#endif
static int proto_pppmuxcp = -1;

static int hf_pppmux_flags_pid = -1;
static int hf_pppmux_flags_field_length = -1;

static gint ett_pppmuxcp = -1;
static gint ett_pppmuxcp_options = -1;

static int proto_pppmux = -1;
static int hf_pppmux_protocol = -1;

static gint ett_pppmux = -1;
static gint ett_pppmux_subframe = -1;
static gint ett_pppmux_subframe_hdr = -1;
static gint ett_pppmux_subframe_flags = -1;
static gint ett_pppmux_subframe_info = -1;

static int proto_mp = -1;
static int hf_mp_frag_first = -1;
static int hf_mp_frag_last = -1;
static int hf_mp_short_sequence_num_reserved = -1;
static int hf_mp_sequence_num = -1;
static int hf_mp_sequence_num_reserved = -1;
static int hf_mp_short_sequence_num = -1;

static int ett_mp = -1;
static int ett_mp_flags = -1;

static int proto_mplscp = -1;
static gint ett_mplscp = -1;
static gint ett_mplscp_options  = -1;

static int proto_cdpcp = -1;
static gint ett_cdpcp = -1;
static gint ett_cdpcp_options   = -1;

static int proto_pap = -1;           /* PAP vars */
static gint ett_pap = -1;
static gint ett_pap_data = -1;

static gint hf_pap_code = -1;
static gint hf_pap_identifier = -1;
static gint hf_pap_length = -1;
static gint hf_pap_data = -1;
static gint hf_pap_peer_id = -1;
static gint hf_pap_peer_id_length = -1;
static gint hf_pap_password = -1;
static gint hf_pap_password_length = -1;
static gint hf_pap_message = -1;
static gint hf_pap_message_length = -1;
static gint hf_pap_stuff = -1;

static int proto_chap = -1;           /* CHAP vars */
static gint ett_chap = -1;
static gint ett_chap_data = -1;


static gint hf_chap_code = -1;
static gint hf_chap_identifier = -1;
static gint hf_chap_length = -1;
static gint hf_chap_data = -1;
static gint hf_chap_value_size = -1;
static gint hf_chap_value = -1;
static gint hf_chap_name = -1;
static gint hf_chap_message = -1;


static int proto_ipv6cp = -1;  /* IPv6CP vars */

static gint ett_ipv6cp = -1;
static gint ett_ipv6cp_options = -1;
static gint ett_ipv6cp_if_id_opt = -1;
static gint ett_ipv6cp_compress_opt = -1;

static int proto_iphc_crtp = -1;            /* CRTP vars */
static int hf_iphc_crtp_cid8 = -1;
static int hf_iphc_crtp_cid16 = -1;
static int hf_iphc_crtp_gen = -1;
static int hf_iphc_crtp_seq = -1;
static int hf_iphc_crtp_fh_flags = -1;
static int hf_iphc_crtp_cs_flags = -1;
static int hf_iphc_crtp_cs_cnt = -1;
static int hf_iphc_crtp_cs_invalid = -1;

static gint ett_iphc_crtp = -1;
static gint ett_iphc_crtp_hdr = -1;
static gint ett_iphc_crtp_info = -1;

static dissector_table_t ppp_subdissector_table;
static dissector_handle_t chdlc_handle;
static dissector_handle_t data_handle;
static dissector_handle_t eth_withfcs_handle;
static dissector_handle_t eth_withoutfcs_handle;

static const value_string ppp_direction_vals[] = {
    {P2P_DIR_RECV, "DCE->DTE"},
    {P2P_DIR_SENT, "DTE->DCE"},
    {0,            NULL}
};

/* options */
static gint ppp_fcs_decode = 0; /* 0 = No FCS, 1 = 16 bit FCS, 2 = 32 bit FCS */
#define NO_FCS 0
#define FCS_16 1
#define FCS_32 2

const enum_val_t fcs_options[] = {
    {"none",   "None",   NO_FCS},
    {"16-bit", "16-Bit", FCS_16},
    {"32-bit", "32-Bit", FCS_32},
    {NULL,     NULL,     -1}
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
 * www.iana.org/assignments/ppp-numbers
 */
static const value_string ppp_vals[] = {
    {PPP_PADDING,     "Padding Protocol"},
    {PPP_ROHC_SCID,   "ROHC small-CID"},
    {PPP_ROHC_LCID,   "ROHC large-CID"},
    {PPP_IP,          "Internet Protocol version 4"},
    {PPP_OSI,         "OSI Network Layer"},
    {PPP_XNSIDP,      "Xerox NS IDP"},
    {PPP_DEC4,        "DECnet Phase IV"},
    {PPP_AT,          "Appletalk"},
    {PPP_IPX,         "Novell IPX"},
    {PPP_VJC_COMP,    "Van Jacobson Compressed TCP/IP"},
    {PPP_VJC_UNCOMP,  "Van Jacobson Uncompressed TCP/IP"},
    {PPP_BCP,         "Bridging PDU"},
    {PPP_ST,          "Stream Protocol (ST-II)"},
    {PPP_VINES,       "Banyan Vines"},
    {PPP_AT_EDDP,     "AppleTalk EDDP"},
    {PPP_AT_SB,       "AppleTalk SmartBuffered"},
    {PPP_MP,          "Multi-Link"},
    {PPP_NB,          "NETBIOS Framing"},
    {PPP_CISCO,       "Cisco Systems"},
    {PPP_ASCOM,       "Ascom Timeplex"},
    {PPP_LBLB,        "Fujitsu Link Backup and Load Balancing (LBLB)"},
    {PPP_RL,          "DCA Remote Lan"},
    {PPP_SDTP,        "Serial Data Transport Protocol (PPP-SDTP)"},
    {PPP_LLC,         "SNA over 802.2"},
    {PPP_SNA,         "SNA"},
    {PPP_IPV6HC,      "IPv6 Header Compression "},
    {PPP_KNX,         "KNX Bridging Data"},
    {PPP_ENCRYPT,     "Encryption"},
    {PPP_ILE,         "Individual Link Encryption"},
    {PPP_IPV6,        "Internet Protocol version 6"},
    {PPP_MUX,         "PPP Muxing"},
    {PPP_VSNP,        "Vendor-Specific Network Protocol (VSNP)"},
    {PPP_TNP,         "TRILL Network Protocol (TNP)"},
    {PPP_RTP_FH,      "RTP IPHC Full Header"},
    {PPP_RTP_CTCP,    "RTP IPHC Compressed TCP"},
    {PPP_RTP_CNTCP,   "RTP IPHC Compressed Non TCP"},
    {PPP_RTP_CUDP8,   "RTP IPHC Compressed UDP 8"},
    {PPP_RTP_CRTP8,   "RTP IPHC Compressed RTP 8"},
    {PPP_STAMPEDE,    "Stampede Bridging"},
    {PPP_MPPLUS,      "MP+ Protocol"},
    {PPP_NTCITS_IPI,  "NTCITS IPI"},
    {PPP_ML_SLCOMP,   "Single link compression in multilink"},
    {PPP_COMP,        "Compressed datagram"},
    {PPP_STP_HELLO,   "802.1d Hello Packets"},
    {PPP_IBM_SR,      "IBM Source Routing BPDU"},
    {PPP_DEC_LB,      "DEC LANBridge100 Spanning Tree"},
    {PPP_CDP,         "Cisco Discovery Protocol"},
    {PPP_NETCS,       "Netcs Twin Routing"},
    {PPP_STP,         "STP - Scheduled Transfer Protocol"},
    {PPP_EDP,         "EDP - Extreme Discovery Protocol"},
    {PPP_OSCP,        "Optical Supervisory Channel Protocol (OSCP)"},
    {PPP_OSCP2,       "Optical Supervisory Channel Protocol (OSCP)"},
    {PPP_LUXCOM,      "Luxcom"},
    {PPP_SIGMA,       "Sigma Network Systems"},
    {PPP_ACSP,        "Apple Client Server Protocol"},
    {PPP_MPLS_UNI,    "MPLS Unicast"},
    {PPP_MPLS_MULTI,  "MPLS Multicast"},
    {PPP_P12844,      "IEEE p1284.4 standard - data packets"},
    {PPP_TETRA,       "ETSI TETRA Network Protocol Type 1"},
    {PPP_MFTP,        "Multichannel Flow Treatment Protocol"},
    {PPP_RTP_CTCPND,  "RTP IPHC Compressed TCP No Delta"},
    {PPP_RTP_CS,      "RTP IPHC Context State"},
    {PPP_RTP_CUDP16,  "RTP IPHC Compressed UDP 16"},
    {PPP_RTP_CRDP16,  "RTP IPHC Compressed RTP 16"},
    {PPP_CCCP,        "Cray Communications Control Protocol"},
    {PPP_CDPD_MNRP,   "CDPD Mobile Network Registration Protocol"},
    {PPP_EXPANDAP,    "Expand accelerator protocol"},
    {PPP_ODSICP,      "ODSICP NCP"},
    {PPP_DOCSIS,      "DOCSIS DLL"},
    {PPP_CETACEANNDP, "Cetacean Network Detection Protocol"},
    {PPP_LZS,         "Stacker LZS"},
    {PPP_REFTEK,      "RefTek Protocol"},
    {PPP_FC,          "Fibre Channel"},
    {PPP_EMIT,        "EMIT Protocols"},
    {PPP_VSP,         "Vendor-Specific Protocol (VSP)"},
    {PPP_TLSP,        "TRILL Link State Protocol (TLSP)"},
    {PPP_IPCP,        "Internet Protocol Control Protocol"},
    {PPP_OSINLCP,     "OSI Network Layer Control Protocol"},
    {PPP_XNSIDPCP,    "Xerox NS IDP Control Protocol"},
    {PPP_DECNETCP,    "DECnet Phase IV Control Protocol"},
    {PPP_ATCP,        "AppleTalk Control Protocol"},
    {PPP_IPXCP,       "Novell IPX Control Protocol"},
    {PPP_BRIDGENCP,   "Bridging NCP"},
    {PPP_SPCP,        "Stream Protocol Control Protocol"},
    {PPP_BVCP,        "Banyan Vines Control Protocol"},
    {PPP_MLCP,        "Multi-Link Control Protocol"},
    {PPP_NBCP,        "NETBIOS Framing Control Protocol"},
    {PPP_CISCOCP,     "Cisco Systems Control Protocol"},
    {PPP_ASCOMCP,     "Ascom Timeplex"},
    {PPP_LBLBCP,      "Fujitsu LBLB Control Protocol"},
    {PPP_RLNCP,       "DCA Remote Lan Network Control Protocol (RLNCP)"},
    {PPP_SDCP,        "Serial Data Control Protocol (PPP-SDCP)"},
    {PPP_LLCCP,       "SNA over 802.2 Control Protocol"},
    {PPP_SNACP,       "SNA Control Protocol"},
    {PPP_IP6HCCP,     "IP6 Header Compression Control Protocol"},
    {PPP_KNXCP,       "KNX Bridging Control Protocol"},
    {PPP_ECP,         "Encryption Control Protocol"},
    {PPP_ILECP,       "Individual Link Encryption Control Protocol"},
    {PPP_IPV6CP,      "IPv6 Control Protocol"},
    {PPP_MUXCP,       "PPP Muxing Control Protocol"},
    {PPP_VSNCP,       "Vendor-Specific Network Control Protocol (VSNCP)"},
    {PPP_TNCP,        "TRILL Network Control Protocol"},
    {PPP_STAMPEDECP,  "Stampede Bridging Control Protocol"},
    {PPP_MPPCP,       "MP+ Control Protocol"},
    {PPP_IPICP,       "NTCITS IPI Control Protocol"},
    {PPP_SLCC,        "Single link compression in multilink control"},
    {PPP_CCP,         "Compression Control Protocol"},
    {PPP_CDPCP,       "Cisco Discovery Protocol Control Protocol"},
    {PPP_NETCSCP,     "Netcs Twin Routing"},
    {PPP_STPCP,       "STP - Control Protocol"},
    {PPP_EDPCP,       "EDPCP - Extreme Discovery Protocol Control Protocol"},
    {PPP_ACSPC,       "Apple Client Server Protocol Control"},
    {PPP_MPLSCP,      "MPLS Control Protocol"},
    {PPP_P12844CP,    "IEEE p1284.4 standard - Protocol Control"},
    {PPP_TETRACP,     "ETSI TETRA TNP1 Control Protocol"},
    {PPP_MFTPCP,      "Multichannel Flow Treatment Protocol"},
    {PPP_LCP,         "Link Control Protocol"},
    {PPP_PAP,         "Password Authentication Protocol"},
    {PPP_LQR,         "Link Quality Report"},
    {PPP_SPAP,        "Shiva Password Authentication Protocol"},
    {PPP_CBCP,        "Callback Control Protocol (CBCP)"},
    {PPP_BACP,        "BACP Bandwidth Allocation Control Protocol"},
    {PPP_BAP,         "BAP Bandwidth Allocation Protocol"},
    {PPP_VSAP,        "Vendor-Specific Authentication Protocol (VSAP)"},
    {PPP_CONTCP,      "Container Control Protocol"},
    {PPP_CHAP,        "Challenge Handshake Authentication Protocol"},
    {PPP_RSAAP,       "RSA Authentication Protocol"},
    {PPP_EAP,         "Extensible Authentication Protocol"},
    {PPP_SIEP,        "Mitsubishi Security Information Exchange Protocol (SIEP)"},
    {PPP_SBAP,        "Stampede Bridging Authorization Protocol"},
    {PPP_PRPAP,       "Proprietary Authentication Protocol"},
    {PPP_PRPAP2,      "Proprietary Authentication Protocol"},
    {PPP_PRPNIAP,     "Proprietary Node ID Authentication Protocol"},
    {0,               NULL}
};
value_string_ext ppp_vals_ext = VALUE_STRING_EXT_INIT(ppp_vals);

/* CP (LCP, CCP, IPCP, etc.) codes.
 * from pppd fsm.h
 */
#define VNDRSPCFC  0  /* Vendor Specific: RFC 2153 */
#define CONFREQ    1  /* Configuration Request */
#define CONFACK    2  /* Configuration Ack */
#define CONFNAK    3  /* Configuration Nak */
#define CONFREJ    4  /* Configuration Reject */
#define TERMREQ    5  /* Termination Request */
#define TERMACK    6  /* Termination Ack */
#define CODEREJ    7  /* Code Reject */

static const value_string cp_vals[] = {
    {VNDRSPCFC, "Vendor Specific"},
    {CONFREQ,   "Configuration Request"},
    {CONFACK,   "Configuration Ack"},
    {CONFNAK,   "Configuration Nak"},
    {CONFREJ,   "Configuration Reject"},
    {TERMREQ,   "Termination Request"},
    {TERMACK,   "Termination Ack"},
    {CODEREJ,   "Code Reject"},
    {0,         NULL}
};

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
    {VNDRSPCFC,  "Vendor Specific"},
    {CONFREQ,    "Configuration Request"},
    {CONFACK,    "Configuration Ack"},
    {CONFNAK,    "Configuration Nak"},
    {CONFREJ,    "Configuration Reject"},
    {TERMREQ,    "Termination Request"},
    {TERMACK,    "Termination Ack"},
    {CODEREJ,    "Code Reject"},
    {PROTREJ,    "Protocol Reject"},
    {ECHOREQ,    "Echo Request"},
    {ECHOREP,    "Echo Reply"},
    {DISCREQ,    "Discard Request"},
    {IDENT,      "Identification"},
    {TIMEREMAIN, "Time Remaining"},
    {0,          NULL}
};

static const value_string ccp_vals[] = {
    {VNDRSPCFC, "Vendor Specific"},
    {CONFREQ,   "Configuration Request"},
    {CONFACK,   "Configuration Ack"},
    {CONFNAK,   "Configuration Nak"},
    {CONFREJ,   "Configuration Reject"},
    {TERMREQ,   "Termination Request"},
    {TERMACK,   "Termination Ack"},
    {CODEREJ,   "Code Reject"},
    {RESETREQ,  "Reset Request"},
    {RESETACK,  "Reset Ack"},
    {0,         NULL}
};

static const value_string cbcp_vals[] = {
    {CBREQ, "Callback Request"},
    {CBRES, "Callback Response"},
    {CBACK, "Callback Ack"},
    {0,     NULL}
};

static const value_string bap_vals[] = {
    {BAP_CREQ,   "Call Request"},
    {BAP_CRES,   "Call Response"},
    {BAP_CBREQ,  "Callback Request"},
    {BAP_CBRES,  "Callback Response"},
    {BAP_LDQREQ, "Link Drop Query Request"},
    {BAP_LDQRES, "Link Drop Query Response"},
    {BAP_CSI,    "Call Status Indication"},
    {BAP_CSRES,  "Call Status Response"},
    {0,          NULL}
};

#define BAP_RESP_CODE_REQACK     0x00
#define BAP_RESP_CODE_REQNAK     0x01
#define BAP_RESP_CODE_REQREJ     0x02
#define BAP_RESP_CODE_REQFULLNAK 0x03
static const value_string bap_resp_code_vals[] = {
    {BAP_RESP_CODE_REQACK,     "Request Ack"},
    {BAP_RESP_CODE_REQNAK,     "Request Nak"},
    {BAP_RESP_CODE_REQREJ,     "Request Rej"},
    {BAP_RESP_CODE_REQFULLNAK, "Request Full Nak"},
    {0,                        NULL}
};

#define BAP_LINK_TYPE_ISDN      0       /* ISDN */
#define BAP_LINK_TYPE_X25       1       /* X.25 */
#define BAP_LINK_TYPE_ANALOG    2       /* Analog */
#define BAP_LINK_TYPE_SD        3       /* Switched Digital (non-ISDN) */
#define BAP_LINK_TYPE_ISDNOV    4       /* ISDN data over voice */
#define BAP_LINK_TYPE_RESV5     5       /* Reserved */
#define BAP_LINK_TYPE_RESV6     6       /* Reserved */
#define BAP_LINK_TYPE_RESV7     7       /* Reserved */
static const value_string bap_link_type_vals[] = {
    {BAP_LINK_TYPE_ISDN,   "ISDN"},
    {BAP_LINK_TYPE_X25,    "X.25"},
    {BAP_LINK_TYPE_ANALOG, "Analog"},
    {BAP_LINK_TYPE_SD,     "Switched Digital (non-ISDN)"},
    {BAP_LINK_TYPE_ISDNOV, "ISDN data over voice"},
    {BAP_LINK_TYPE_RESV5,  "Reserved"},
    {BAP_LINK_TYPE_RESV6,  "Reserved"},
    {BAP_LINK_TYPE_RESV7,  "Reserved"},
    {0,                    NULL}
};

#define BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT       1 /* Unique Digit */
#define BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM        2 /* Subscriber Number */
#define BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR 3 /* Phone Number Sub Address */
static const value_string bap_phone_delta_subopt_vals[] = {
    {BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT,       "Unique Digit"},
    {BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM,        "Subscriber Number"},
    {BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR, "Phone Number Sub Address"},
    {0,                                       NULL}
};

/*
 * Cause codes for Cause.
 *
 * The following code table is taken from packet-q931.c but is slightly
 * adapted to BAP protocol.
 */
static const value_string q931_cause_code_vals[] = {
    {0x00, "Call successful"},
    {0x01, "Unallocated (unassigned) number"},
    {0x02, "No route to specified transit network"},
    {0x03, "No route to destination"},
    {0x04, "Send special information tone"},
    {0x05, "Misdialled trunk prefix"},
    {0x06, "Channel unacceptable"},
    {0x07, "Call awarded and being delivered in an established channel"},
    {0x08, "Prefix 0 dialed but not allowed"},
    {0x09, "Prefix 1 dialed but not allowed"},
    {0x0A, "Prefix 1 dialed but not required"},
    {0x0B, "More digits received than allowed, call is proceeding"},
    {0x10, "Normal call clearing"},
    {0x11, "User busy"},
    {0x12, "No user responding"},
    {0x13, "No answer from user (user alerted)"},
    {0x14, "Subscriber absent"},
    {0x15, "Call rejected"},
    {0x16, "Number changed"},
    {0x17, "Reverse charging rejected"},
    {0x18, "Call suspended"},
    {0x19, "Call resumed"},
    {0x1A, "Non-selected user clearing"},
    {0x1B, "Destination out of order"},
    {0x1C, "Invalid number format (incomplete number)"},
    {0x1D, "Facility rejected"},
    {0x1E, "Response to STATUS ENQUIRY"},
    {0x1F, "Normal unspecified"},
    {0x21, "Circuit out of order"},
    {0x22, "No circuit/channel available"},
    {0x23, "Destination unattainable"},
    {0x25, "Degraded service"},
    {0x26, "Network out of order"},
    {0x27, "Transit delay range cannot be achieved"},
    {0x28, "Throughput range cannot be achieved"},
    {0x29, "Temporary failure"},
    {0x2A, "Switching equipment congestion"},
    {0x2B, "Access information discarded"},
    {0x2C, "Requested circuit/channel not available"},
    {0x2D, "Pre-empted"},
    {0x2E, "Precedence call blocked"},
    {0x2F, "Resources unavailable, unspecified"},
    {0x31, "Quality of service unavailable"},
    {0x32, "Requested facility not subscribed"},
    {0x33, "Reverse charging not allowed"},
    {0x34, "Outgoing calls barred"},
    {0x35, "Outgoing calls barred within CUG"},
    {0x36, "Incoming calls barred"},
    {0x37, "Incoming calls barred within CUG"},
    {0x38, "Call waiting not subscribed"},
    {0x39, "Bearer capability not authorized"},
    {0x3A, "Bearer capability not presently available"},
    {0x3E, "Inconsistency in designated outgoing access information and subscriber class"},
    {0x3F, "Service or option not available, unspecified"},
    {0x41, "Bearer capability not implemented"},
    {0x42, "Channel type not implemented"},
    {0x43, "Transit network selection not implemented"},
    {0x44, "Message not implemented"},
    {0x45, "Requested facility not implemented"},
    {0x46, "Only restricted digital information bearer capability is available"},
    {0x4F, "Service or option not implemented, unspecified"},
    {0x51, "Invalid call reference value"},
    {0x52, "Identified channel does not exist"},
    {0x53, "Call identity does not exist for suspended call"},
    {0x54, "Call identity in use"},
    {0x55, "No call suspended"},
    {0x56, "Call having the requested call identity has been cleared"},
    {0x57, "Called user not member of CUG"},
    {0x58, "Incompatible destination"},
    {0x59, "Non-existent abbreviated address entry"},
    {0x5A, "Destination address missing, and direct call not subscribed"},
    {0x5B, "Invalid transit network selection (national use)"},
    {0x5C, "Invalid facility parameter"},
    {0x5D, "Mandatory information element is missing"},
    {0x5F, "Invalid message, unspecified"},
    {0x60, "Mandatory information element is missing"},
    {0x61, "Message type non-existent or not implemented"},
    {0x62, "Message not compatible with call state or message type non-existent or not implemented"},
    {0x63, "Information element non-existent or not implemented"},
    {0x64, "Invalid information element contents"},
    {0x65, "Message not compatible with call state"},
    {0x66, "Recovery on timer expiry"},
    {0x67, "Parameter non-existent or not implemented - passed on"},
    {0x6E, "Message with unrecognized parameter discarded"},
    {0x6F, "Protocol error, unspecified"},
    {0x7F, "Internetworking, unspecified"},
    {0xFF, "Non-specific failure"},
    {0,    NULL}
};
static value_string_ext q931_cause_code_vals_ext = VALUE_STRING_EXT_INIT(q931_cause_code_vals);

static const value_string bap_call_status_opt_action_vals[] = {
    {0, "No retry"},
    {1, "Retry"},
    {0, NULL}
};

#define STAC_CM_NONE            0
#define STAC_CM_LCB             1
#define STAC_CM_CRC             2
#define STAC_CM_SN              3
#define STAC_CM_EXTMODE         4
static const value_string stac_checkmode_vals[] = {
    {STAC_CM_NONE,    "None"},
    {STAC_CM_LCB,     "LCB"},
    {STAC_CM_CRC,     "CRC"},
    {STAC_CM_SN,      "Sequence Number"},
    {STAC_CM_EXTMODE, "Extended Mode"},
    {0,               NULL}
};

#define LZSDCP_CM_NONE          0
#define LZSDCP_CM_LCB           1
#define LZSDCP_CM_SN            2
#define LZSDCP_CM_SN_LCB        3
static const value_string lzsdcp_checkmode_vals[] = {
    {LZSDCP_CM_NONE,   "None"},
    {LZSDCP_CM_LCB,    "LCB"},
    {LZSDCP_CM_SN,     "Sequence Number"},
    {LZSDCP_CM_SN_LCB, "Sequence Number + LCB (default)"},
    {0,                NULL}
};

#define LZSDCP_PM_NONE          0
#define LZSDCP_PM_PROC_UNCOMP   1
static const value_string lzsdcp_processmode_vals[] = {
    {LZSDCP_PM_NONE,        "None (default)"},
    {LZSDCP_PM_PROC_UNCOMP, "Process-Uncompressed"},
    {0,                     NULL}
};

#define DCE_MODE_1  1
#define DCE_MODE_2  2
static const value_string dce_mode_vals[] = {
    {DCE_MODE_1, "No Additional Negotiation"},
    {DCE_MODE_2, "Full PPP Negotiation and State Machine"},
    {0,          NULL}
};

/*
 * Options.  (LCP)
 */
#define CI_VENDORSPECIFIC       0   /* Vendor Specific [RFC2153] */
#define CI_MRU                  1   /* Maximum Receive Unit [RFC1661] */
#define CI_ASYNCMAP             2   /* Async Control Character Map */
#define CI_AUTHPROT             3   /* Authentication Protocol [RFC1661] */
#define CI_QUALITY              4   /* Quality Protocol [RFC1661] */
#define CI_MAGICNUMBER          5   /* Magic Number [RFC1661] */
#define CI_LINKQUALMON          6   /* DEPRECATED (Quality Protocol) [RFC1172] */
#define CI_PCOMPRESSION         7   /* Protocol Field Compression [RFC1661] */
#define CI_ACCOMPRESSION        8   /* Address/Control Field Compression
                                       [RFC1661] */
#define CI_FCS_ALTERNATIVES     9   /* FCS Alternatives [RFC1570] */
#define CI_SELF_DESCRIBING_PAD  10  /* Self-Describing Pad [RFC1570] */
#define CI_NUMBERED_MODE        11  /* Numbered Mode [RFC1663] */
#define CI_MULTILINK_PROC       12  /* DEPRECATED (Multi-Link Procedure) */
#define CI_CALLBACK             13  /* Callback [RFC1570] */
#define CI_CONNECTTIME          14  /* DEPRECATED (Connect Time) */
#define CI_COMPOUND_FRAMES      15  /* DEPRECATED (Compound Frames) [RFC1570] */
#define CI_NOMDATAENCAP         16  /* DEPRECATED (Nominal Data Encapsulation) */
/* NOTE: IANA lists CI_NOMDATAENCAP as 16, but it is listed as 14 in
 *       http://tools.ietf.org/html/draft-ietf-pppext-dataencap-03.
 *       Which is correct is anyone's guess. */
#define CI_MULTILINK_MRRU       17  /* Multilink MRRU [RFC1990] */
#define CI_MULTILINK_SSNH       18  /* Multilink Short Sequence Number Header
                                       [RFC1990] */
#define CI_MULTILINK_EP_DISC    19  /* Multilink Endpoint Discriminator
                                       [RFC1990] */
#define CI_PROP_KEN             20  /* Proprietary [Ken Culbert] ken@funk.com */
#define CI_DCE_IDENTIFIER       21  /* DCE Identifier [RFC1976]: Warning:
                                       Option type 25 in the RFC is incorrect */
#define CI_MULTILINK_PLUS_PROC  22  /* Multilink Plus Procedure [RFC1934] */
#define CI_LINK_DISC_FOR_BACP   23  /* Link Discriminator for BACP [RFC2125] */
#define CI_LCP_AUTHENTICATION   24  /* LCP Authentication Option [Culbert] */
#define CI_COBS                 25  /* Consistent Overhead Byte Stuffing (COBS)
                                       [Carlson] */
#define CI_PREFIX_ELISION       26  /* Prefix elision [RFC2686][RFC2687] */
#define CI_MULTILINK_HDR_FMT    27  /* Multilink header format
                                       [RFC2686][RFC2687] */
#define CI_INTERNATIONALIZATION 28  /* Internationalization [RFC2484] */
#define CI_SDL_ON_SONET_SDH     29  /* Simple Data Link on SONET/SDH
                                      [RFC2823] */
#define CI_UNASSIGNED           30  /* Unassigned ... but so are 31-255, so
                                       why do they bother specifically
                                       mentioning this one, I wonder? */

static int hf_lcp_magic_number = -1;
static int hf_lcp_data = -1;
static int hf_lcp_message = -1;
static int hf_lcp_secs_remaining = -1;
static int hf_lcp_rej_proto = -1;
static int hf_lcp_opt_type = -1;
static int hf_lcp_opt_length = -1;
static int hf_lcp_opt_oui = -1;
static int hf_lcp_opt_kind = -1;
static int hf_lcp_opt_data = -1;
static int hf_lcp_opt_mru = -1;
static int hf_lcp_opt_asyncmap = -1;
static int hf_lcp_opt_asyncmap_nul = -1;
static int hf_lcp_opt_asyncmap_soh = -1;
static int hf_lcp_opt_asyncmap_stx = -1;
static int hf_lcp_opt_asyncmap_etx = -1;
static int hf_lcp_opt_asyncmap_eot = -1;
static int hf_lcp_opt_asyncmap_enq = -1;
static int hf_lcp_opt_asyncmap_ack = -1;
static int hf_lcp_opt_asyncmap_bel = -1;
static int hf_lcp_opt_asyncmap_bs = -1;
static int hf_lcp_opt_asyncmap_ht = -1;
static int hf_lcp_opt_asyncmap_lf = -1;
static int hf_lcp_opt_asyncmap_vt = -1;
static int hf_lcp_opt_asyncmap_ff = -1;
static int hf_lcp_opt_asyncmap_cr = -1;
static int hf_lcp_opt_asyncmap_so = -1;
static int hf_lcp_opt_asyncmap_si = -1;
static int hf_lcp_opt_asyncmap_dle = -1;
static int hf_lcp_opt_asyncmap_dc1 = -1;
static int hf_lcp_opt_asyncmap_dc2 = -1;
static int hf_lcp_opt_asyncmap_dc3 = -1;
static int hf_lcp_opt_asyncmap_dc4 = -1;
static int hf_lcp_opt_asyncmap_nak = -1;
static int hf_lcp_opt_asyncmap_syn = -1;
static int hf_lcp_opt_asyncmap_etb = -1;
static int hf_lcp_opt_asyncmap_can = -1;
static int hf_lcp_opt_asyncmap_em = -1;
static int hf_lcp_opt_asyncmap_sub = -1;
static int hf_lcp_opt_asyncmap_esc = -1;
static int hf_lcp_opt_asyncmap_fs = -1;
static int hf_lcp_opt_asyncmap_gs = -1;
static int hf_lcp_opt_asyncmap_rs = -1;
static int hf_lcp_opt_asyncmap_us = -1;
static int hf_lcp_opt_auth_protocol = -1;
static int hf_lcp_opt_algorithm = -1;
static int hf_lcp_opt_quality_protocol = -1;
static int hf_lcp_opt_magic_number = -1;
static int hf_lcp_opt_reportingperiod = -1;
static int hf_lcp_opt_fcs_alternatives = -1;
static int hf_lcp_opt_fcs_alternatives_null = -1;
static int hf_lcp_opt_fcs_alternatives_ccitt16 = -1;
static int hf_lcp_opt_fcs_alternatives_ccitt32 = -1;
static int hf_lcp_opt_maximum = -1;
static int hf_lcp_opt_window = -1;
static int hf_lcp_opt_hdlc_address = -1;
static int hf_lcp_opt_operation = -1;
static int hf_lcp_opt_message = -1;
static int hf_lcp_opt_mrru = -1;
static int hf_lcp_opt_ep_disc_class = -1;
static int hf_lcp_opt_ip_address = -1;
static int hf_lcp_opt_802_1_address = -1;
static int hf_lcp_opt_magic_block = -1;
static int hf_lcp_opt_psndn = -1;
static int hf_lcp_opt_mode = -1;
static int hf_lcp_opt_unused = -1;
static int hf_lcp_opt_link_discrim = -1;
static int hf_lcp_opt_id = -1;
static int hf_lcp_opt_cobs_flags = -1;
static int hf_lcp_opt_cobs_flags_res = -1;
static int hf_lcp_opt_cobs_flags_pre = -1;
static int hf_lcp_opt_cobs_flags_zxe = -1;
static int hf_lcp_opt_class = -1;
static int hf_lcp_opt_prefix = -1;
static int hf_lcp_opt_code = -1;
static int hf_lcp_opt_max_susp_classes = -1;
static int hf_lcp_opt_MIBenum = -1;
static int hf_lcp_opt_language_tag = -1;

static void dissect_lcp_vendor_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_mru_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_async_map_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_authprot_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_qualprot_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_magicnumber_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_linkqualmon_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_simple_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_fcs_alternatives_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_lcp_self_describing_pad_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_lcp_numbered_mode_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_lcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_multilink_mrru_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_lcp_multilink_ep_disc_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
        proto_tree *tree, void *data _U_);
static void dissect_lcp_dce_identifier_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_lcp_multilink_pp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_bacp_link_discriminator_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_lcp_auth_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_cobs_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_lcp_prefix_elision_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_lcp_multilink_hdr_fmt_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_lcp_internationalization_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_mp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static const ip_tcp_opt lcp_opts[] = {
    {CI_VENDORSPECIFIC, "Vendor Specific", &ett_lcp_vendor_opt,
        OPT_LEN_VARIABLE_LENGTH, 6, dissect_lcp_vendor_opt},
    {CI_MRU, "Maximum Receive Unit", &ett_lcp_mru_opt,
        OPT_LEN_FIXED_LENGTH, 4, dissect_lcp_mru_opt},
    {CI_ASYNCMAP, "Async Control Character Map", &ett_lcp_asyncmap_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_lcp_async_map_opt},
    {CI_AUTHPROT, "Authentication Protocol", &ett_lcp_authprot_opt,
        OPT_LEN_VARIABLE_LENGTH, 4, dissect_lcp_authprot_opt},
    {CI_QUALITY, "Quality Protocol", &ett_lcp_qualprot_opt,
        OPT_LEN_VARIABLE_LENGTH, 4, dissect_lcp_qualprot_opt},
    {CI_MAGICNUMBER, "Magic Number", &ett_lcp_magicnumber_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_lcp_magicnumber_opt},
    {CI_LINKQUALMON, "Link Quality Monitoring", &ett_lcp_linkqualmon_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_lcp_linkqualmon_opt},
    {CI_PCOMPRESSION, "Protocol Field Compression", &ett_lcp_pcomp_opt,
        OPT_LEN_FIXED_LENGTH, 2, dissect_lcp_simple_opt},
    {CI_ACCOMPRESSION, "Address and Control Field Compression", &ett_lcp_acccomp_opt,
        OPT_LEN_FIXED_LENGTH, 2, dissect_lcp_simple_opt},
    {CI_FCS_ALTERNATIVES, "FCS Alternatives", &ett_lcp_fcs_alternatives_opt,
        OPT_LEN_FIXED_LENGTH, 3, dissect_lcp_fcs_alternatives_opt},
    {CI_SELF_DESCRIBING_PAD, "Self Describing Pad", &ett_lcp_self_desc_pad_opt,
        OPT_LEN_FIXED_LENGTH, 3, dissect_lcp_self_describing_pad_opt},
    {CI_NUMBERED_MODE, "Numbered Mode", &ett_lcp_numbered_mode_opt,
        OPT_LEN_VARIABLE_LENGTH, 4, dissect_lcp_numbered_mode_opt},
    /* TODO? CI_MULTILINK_PROC */
    {CI_CALLBACK, "Callback", &ett_lcp_callback_opt,
        OPT_LEN_VARIABLE_LENGTH, 3, dissect_lcp_callback_opt},
    /* TODO? CI_CONNECTTIME */
    {CI_COMPOUND_FRAMES, "Compound Frames (Deprecated)", &ett_lcp_compound_frames_opt,
        OPT_LEN_FIXED_LENGTH, 2, dissect_lcp_simple_opt},
    {CI_NOMDATAENCAP, "Nominal Data Encapsulation (Deprecated)", &ett_lcp_nomdataencap_opt,
        OPT_LEN_FIXED_LENGTH, 2, dissect_lcp_simple_opt},
    {CI_MULTILINK_MRRU, "Multilink MRRU", &ett_lcp_multilink_mrru_opt,
        OPT_LEN_FIXED_LENGTH, 4, dissect_lcp_multilink_mrru_opt},
    {CI_MULTILINK_SSNH, "Multilink Short Sequence Number Header", &ett_lcp_multilink_ssnh_opt,
        OPT_LEN_FIXED_LENGTH, 2, dissect_lcp_simple_opt},
    {CI_MULTILINK_EP_DISC, "Multilink Endpoint Discriminator", &ett_lcp_multilink_ep_disc_opt,
        OPT_LEN_VARIABLE_LENGTH, 3, dissect_lcp_multilink_ep_disc_opt},
    /* TODO? CI_PROP_KEN: ken@funk.com: www.funk.com => www.juniper.net */
    {CI_DCE_IDENTIFIER, "DCE Identifier", &ett_lcp_dce_identifier_opt,
        OPT_LEN_FIXED_LENGTH, 3, dissect_lcp_dce_identifier_opt},
    {CI_MULTILINK_PLUS_PROC, "Multi Link Plus Procedure", &ett_lcp_multilink_pp_opt,
        OPT_LEN_FIXED_LENGTH, 4, dissect_lcp_multilink_pp_opt},
    {CI_LINK_DISC_FOR_BACP, "Link Discriminator for BACP", &ett_lcp_bacp_link_discrim_opt,
        OPT_LEN_FIXED_LENGTH, 4, dissect_lcp_bacp_link_discriminator_opt},
    {CI_LCP_AUTHENTICATION, "LCP Authentication Option", &ett_lcp_auth_opt,
        OPT_LEN_VARIABLE_LENGTH, 3, dissect_lcp_auth_opt},
    {CI_COBS, "Consistent Overhead Byte Stuffing (COBS)", &ett_lcp_cobs_opt,
        OPT_LEN_FIXED_LENGTH, 3, dissect_lcp_cobs_opt},
    {CI_PREFIX_ELISION, "Prefix Elision", &ett_lcp_prefix_elision_opt,
        OPT_LEN_VARIABLE_LENGTH, 2, dissect_lcp_prefix_elision_opt},
    {CI_MULTILINK_HDR_FMT, "Multilink header format", &ett_multilink_hdr_fmt_opt,
        OPT_LEN_FIXED_LENGTH, 4, dissect_lcp_multilink_hdr_fmt_opt},
    {CI_INTERNATIONALIZATION, "Internationalization", &ett_lcp_internationalization_opt,
        OPT_LEN_VARIABLE_LENGTH, 7, dissect_lcp_internationalization_opt},
    {CI_SDL_ON_SONET_SDH, "Simple Data Link on SONET/SDH", &ett_lcp_simple_opt,
        OPT_LEN_FIXED_LENGTH, 2, dissect_lcp_simple_opt}
    /* TODO? CI_UNASSIGNED */
};

#define N_LCP_OPTS      (sizeof lcp_opts / sizeof lcp_opts[0])

/*
 * Options.  (VSNCP)
 */

#define CI_PDN_IDENTIFIER       1
#define CI_ACCESS_POINT_NM      2
#define CI_PDN_TYPE             3
#define CI_PDN_ADDRESS          4
#define CI_PROTOCOL_CONFIG      5
#define CI_ERROR_CODE           6
#define CI_ATTACH_TYPE          7
#define CI_IPv4DEFAULT_ROUTER   8
#define CI_ADDRESS_ALLOC        9
#define CI_APN_AMBR             10

static void dissect_vsncp_pdnid_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_vsncp_apname_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_vsncp_pdntype_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_vsncp_pdnaddress_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_vsncp_pco_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_vsncp_errorcode_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_vsncp_attachtype_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_vsncp_ipv4address_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_vsncp_addressalloc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);

static const ip_tcp_opt vsncp_opts[] = {
    {CI_PDN_IDENTIFIER, "PDN Identifier", NULL,
        OPT_LEN_FIXED_LENGTH, 3, dissect_vsncp_pdnid_opt},
    {CI_ACCESS_POINT_NM, "Access Point Name", NULL,
        OPT_LEN_VARIABLE_LENGTH, 2, dissect_vsncp_apname_opt},
    {CI_PDN_TYPE, "PDN Type", NULL,
        OPT_LEN_FIXED_LENGTH, 3, dissect_vsncp_pdntype_opt},
    {CI_PDN_ADDRESS, "PDN Address", NULL,
        OPT_LEN_VARIABLE_LENGTH, 3, dissect_vsncp_pdnaddress_opt},
    {CI_PROTOCOL_CONFIG, "Protocol Configuration Options", NULL,
        OPT_LEN_VARIABLE_LENGTH, 3, dissect_vsncp_pco_opt},
    {CI_ERROR_CODE, "Error Code", NULL,
        OPT_LEN_FIXED_LENGTH, 3, dissect_vsncp_errorcode_opt},
    {CI_ATTACH_TYPE, "Attach Type", NULL,
        OPT_LEN_FIXED_LENGTH, 3, dissect_vsncp_attachtype_opt},
    {CI_IPv4DEFAULT_ROUTER, "IPv4 Default Router Address", NULL,
        OPT_LEN_FIXED_LENGTH, 6, dissect_vsncp_ipv4address_opt},
    {CI_ADDRESS_ALLOC, "Address Allocation Cause", NULL,
        OPT_LEN_FIXED_LENGTH, 3, dissect_vsncp_addressalloc_opt},
    {CI_APN_AMBR, "APN-AMBR", NULL,
        OPT_LEN_VARIABLE_LENGTH, 4, NULL}
};

#define N_VSNCP_OPTS    (sizeof vsncp_opts / sizeof vsncp_opts[0])

/*
 * CHAP Algorithms
 */
/* 0-4: Reserved */
#define CHAP_ALG_MD5    5       /* CHAP with MD5 */
#define CHAP_AGL_SHA1   6       /* CHAP with SHA-1 [Black] */
/* 7-127: Unassigned */
#define CHAP_ALG_MSV1   128     /* MS-CHAP */
#define CHAP_ALG_MSV2   129     /* MS-CHAP-2 */

static const range_string chap_alg_rvals[] = {
    {0,             4,             "Reserved"},
    {CHAP_ALG_MD5,  CHAP_ALG_MD5,  "CHAP with MD5"},
    {CHAP_AGL_SHA1, CHAP_AGL_SHA1, "CHAP with SHA-1"},
    {CHAP_ALG_MSV1, CHAP_ALG_MSV1, "MS-CHAP"},
    {CHAP_ALG_MSV2, CHAP_ALG_MSV2, "MS-CHAP-2"},
    {0,             0,             NULL}
};


/*
 * Options.  (IPCP)
 * http://tools.ietf.org/html/rfc1172
 * http://tools.ietf.org/html/rfc1332
 * http://tools.ietf.org/html/rfc1877
 * http://tools.ietf.org/html/rfc2290
 * http://tools.ietf.org/html/rfc3241
 * http://tools.ietf.org/html/rfc3545
 */
#define CI_ADDRS            1       /* IP Addresses (deprecated) (RFC 1172) */
#define CI_COMPRESS_PROTO   2       /* Compression Protocol (RFC 1332) */
#define CI_ADDR             3       /* IP Address (RFC 1332) */
#define CI_MOBILE_IPv4      4       /* Mobile IPv4 (RFC 2290) */
#define CI_PRI_DNS          129     /* Primary DNS value (RFC 1877) */
#define CI_PRI_NBNS         130     /* Primary NBNS value (RFC 1877) */
#define CI_SEC_DNS          131     /* Secondary DNS value (RFC 1877) */
#define CI_SEC_NBNS         132     /* Secondary NBNS value (RFC 1877) */

static int hf_ipcp_opt_type = -1;
static int hf_ipcp_opt_length = -1;
static int hf_ipcp_opt_src_address = -1;
static int hf_ipcp_opt_dst_address = -1;
static int hf_ipcp_opt_compress_proto = -1;
static int hf_ipcp_opt_max_cid = -1;
static int hf_ipcp_opt_mrru = -1;
static int hf_ipcp_opt_max_slot_id = -1;
static int hf_ipcp_opt_comp_slot_id = -1;
static int hf_ipcp_opt_tcp_space = -1;
static int hf_ipcp_opt_non_tcp_space = -1;
static int hf_ipcp_opt_f_max_period = -1;
static int hf_ipcp_opt_f_max_time = -1;
static int hf_ipcp_opt_max_header = -1;
static int hf_ipcp_data = -1;
static int hf_ipcp_opt_ip_address = -1;
static int hf_ipcp_opt_mobilenodehomeaddr = -1;
static int hf_ipcp_opt_pri_dns_address = -1;
static int hf_ipcp_opt_pri_nbns_address = -1;
static int hf_ipcp_opt_sec_dns_address = -1;
static int hf_ipcp_opt_sec_nbns_address = -1;

static int hf_ipcp_opt_rohc_type = -1;
static int hf_ipcp_opt_rohc_length = -1;
static int hf_ipcp_opt_rohc_profile = -1;
static int hf_ipcp_opt_iphc_type = -1;
static int hf_ipcp_opt_iphc_length = -1;
static int hf_ipcp_opt_iphc_param = -1;

static void dissect_ipcp_addrs_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ipcp_compress_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ipcp_rohc_profiles_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_ipcp_iphc_simple_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ipcp_iphc_neghdrcomp_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo _U_,
    proto_tree *tree, void *data _U_);
static void dissect_ipcp_addr_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ipcp_mobileipv4_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ipcp_pri_dns_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ipcp_pri_nbns_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ipcp_sec_dns_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ipcp_sec_nbns_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);

static const ip_tcp_opt ipcp_opts[] = {
    {CI_ADDRS, "IP Addresses (deprecated)", &ett_ipcp_ipaddrs_opt,
        OPT_LEN_FIXED_LENGTH, 10, dissect_ipcp_addrs_opt},
    {CI_COMPRESS_PROTO, "IP Compression Protocol", &ett_ipcp_compress_opt,
        OPT_LEN_VARIABLE_LENGTH, 4, dissect_ipcp_compress_opt},
    {CI_ADDR, "IP address", &ett_ipcp_ipaddr_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_ipcp_addr_opt},
    {CI_MOBILE_IPv4, "Mobile Node's Home IP Address", &ett_ipcp_mobileipv4_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_ipcp_mobileipv4_opt},
    {CI_PRI_DNS, "Primary DNS Server IP Address", &ett_ipcp_pridns_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_ipcp_pri_dns_opt},
    {CI_PRI_NBNS, "Primary NBNS Server IP Address", &ett_ipcp_prinbns_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_ipcp_pri_nbns_opt},
    {CI_SEC_DNS, "Secondary DNS Server IP Address", &ett_ipcp_secdns_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_ipcp_sec_dns_opt},
    {CI_SEC_NBNS, "Secondary NBNS Server IP Address", &ett_ipcp_secnbns_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_ipcp_sec_nbns_opt}
};

#define N_IPCP_OPTS     (sizeof ipcp_opts / sizeof ipcp_opts[0])


/*
 * IP Compression options
 */
#define IPCP_ROHC               0x0003  /* RFC3241 */
#define IPCP_COMPRESS_VJ_1172   0x0037  /* value defined in RFC1172 (typo) */
#define IPCP_COMPRESS_VJ        0x002d  /* value defined in RFC1332 (correct) */
#define IPCP_COMPRESS_IPHC      0x0061  /* RFC3544 (and RFC2509) */

static const value_string ipcp_compress_proto_vals[] = {
    {IPCP_ROHC,             "Robust Header Compression (ROHC)"},
    {IPCP_COMPRESS_VJ,      "VJ compression"},
    {IPCP_COMPRESS_VJ_1172, "VJ compression (RFC1172-typo)"},
    {IPCP_COMPRESS_IPHC,    "IPHC compression"},
    {0,                     NULL}
};

/* IPHC suboptions (RFC2508, 3544) */
#define IPCP_IPHC_CRTP          1
#define IPCP_IPHC_ECRTP         2
#define IPCP_IPHC_NEGHC         3

static const value_string ipcp_iphc_parameter_vals[] = {
    {1, "The number of contexts for TCP Space is 0"},
    {2, "The number of contexts for Non TCP Space is 0"},
    {0, NULL}
};

static const ip_tcp_opt ipcp_iphc_subopts[] = {
    {IPCP_IPHC_CRTP, "RTP compression (RFC2508)",
        &ett_ipcp_iphc_rtp_compress_opt, OPT_LEN_FIXED_LENGTH, 2,
        dissect_ipcp_iphc_simple_opt},
    {IPCP_IPHC_ECRTP, "Enhanced RTP compression (RFC3545)",
        &ett_ipcp_iphc_enhanced_rtp_compress_opt, OPT_LEN_FIXED_LENGTH, 2,
        dissect_ipcp_iphc_simple_opt},
    {IPCP_IPHC_NEGHC, "Negotiating header compression (RFC3545)",
        &ett_ipcp_iphc_neghdrcomp_opt, OPT_LEN_FIXED_LENGTH, 3,
        dissect_ipcp_iphc_neghdrcomp_opt}
};

#define N_IPCP_IPHC_SUBOPTS (sizeof ipcp_iphc_subopts / sizeof ipcp_iphc_subopts[0])


/* ROHC suboptions */
#define IPCP_ROHC_PROFILES      1

/* From http://tools.ietf.org/html/rfc3095 */
static const value_string ipcp_rohc_profile_vals[] = {
    {0x0000, "ROHC uncompressed -- no compression"},
    {0x0002, "ROHC UDP -- non-RTP UDP/IP compression"},
    {0x0003, "ROHC ESP -- ESP/IP compression"},
    {0,      NULL}
};

static const ip_tcp_opt ipcp_rohc_subopts[] = {
    {IPCP_ROHC_PROFILES, "Profiles (RFC3241)", &ett_ipcp_rohc_profiles_opt,
        OPT_LEN_VARIABLE_LENGTH, 2, dissect_ipcp_rohc_profiles_opt}
};

#define N_IPCP_ROHC_SUBOPTS (sizeof ipcp_rohc_subopts / sizeof ipcp_rohc_subopts[0])

/*
 * Options.  (OSINLCP)
 */
#define CI_OSINLCP_ALIGN_NPDU    1  /* Alignment of the OSI NPDU (RFC 1377) */

static int hf_osinlcp_opt_type = -1;
static int hf_osinlcp_opt_length = -1;
static int hf_osinlcp_opt_alignment = -1;

static void dissect_osinlcp_align_npdu_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo,
    proto_tree *tree, void *data _U_);

static const ip_tcp_opt osinlcp_opts[] = {
    {CI_OSINLCP_ALIGN_NPDU, "Align-NPDU", &ett_osinlcp_align_npdu_opt,
        OPT_LEN_FIXED_LENGTH, 3, dissect_osinlcp_align_npdu_opt}
};

#define N_OSINLCP_OPTS   (sizeof osinlcp_opts / sizeof osinlcp_opts[0])

/*
 * Options.  (CCP)
 */
#define CI_CCP_OUI      0       /* OUI (RFC1962) */
#define CI_CCP_PREDICT1 1       /* Predictor type 1 (RFC1962) */
#define CI_CCP_PREDICT2 2       /* Predictor type 2 (RFC1962) */
#define CI_CCP_PUDDLE   3       /* Puddle Jumper (RFC1962) */
#define CI_CCP_HPPPC    16      /* Hewlett-Packard PPC (RFC1962) */
#define CI_CCP_STAC     17      /* stac Electronics LZS (RFC1974) */
#define CI_CCP_MPPE     18      /* Microsoft PPE/C (RFC2218/3078) */
#define CI_CCP_GFZA     19      /* Gandalf FZA (RFC1962) */
#define CI_CCP_V42BIS   20      /* V.42bis compression */
#define CI_CCP_BSDLZW   21      /* BSD LZW Compress (RFC1977) */
#define CI_CCP_LZSDCP   23      /* LZS-DCP (RFC1967) */
#define CI_CCP_MVRCA    24      /* MVRCA (Magnalink) (RFC1975) */
#define CI_CCP_DCE      25      /* DCE (RFC1976) */
#define CI_CCP_DEFLATE  26      /* Deflate (RFC1979) */
#define CI_CCP_V44LZJH  27      /* V.44/LZJH (http://www.watersprings.org/pub/id/draft-heath-ppp-v44-01.txt) */
#define CI_CCP_RESERVED 255     /* Reserved (RFC1962) */

static int hf_ccp_opt_type = -1;
static int hf_ccp_opt_length = -1;
static int hf_ccp_opt_oui = -1;
static int hf_ccp_opt_subtype = -1;
static int hf_ccp_opt_data = -1;
static int hf_ccp_opt_history_count = -1;
static int hf_ccp_opt_cm = -1;
static int hf_ccp_opt_cm_reserved = -1;
static int hf_ccp_opt_cm_check_mode = -1;
static int hf_ccp_opt_supported_bits = -1;
static int hf_ccp_opt_supported_bits_h = -1;
static int hf_ccp_opt_supported_bits_m = -1;
static int hf_ccp_opt_supported_bits_s = -1;
static int hf_ccp_opt_supported_bits_l = -1;
static int hf_ccp_opt_supported_bits_d = -1;
static int hf_ccp_opt_supported_bits_c = -1;
static int hf_ccp_opt_history = -1;
static int hf_ccp_opt_version = -1;
static int hf_ccp_opt_vd = -1;
static int hf_ccp_opt_vd_vers = -1;
static int hf_ccp_opt_vd_dict = -1;
static int hf_ccp_opt_check_mode = -1;
static int hf_ccp_opt_process_mode = -1;
static int hf_ccp_opt_fe = -1;
static int hf_ccp_opt_p = -1;
static int hf_ccp_opt_History = -1; /* Different than hf_ccp_opt_history */
static int hf_ccp_opt_contexts = -1;
static int hf_ccp_opt_mode = -1;
static int hf_ccp_opt_window = -1;
static int hf_ccp_opt_method = -1;
static int hf_ccp_opt_mbz = -1;
static int hf_ccp_opt_chk = -1;
static int hf_ccp_opt_mode_dictcount = -1;
static int hf_ccp_opt_dict_size = -1;
static int hf_ccp_opt_history_length = -1;

static void dissect_ccp_oui_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ccp_other_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
#define dissect_ccp_predict1_opt    dissect_ccp_other_opt
#define dissect_ccp_predict2_opt    dissect_ccp_other_opt
#define dissect_ccp_puddle_opt      dissect_ccp_other_opt
#define dissect_ccp_hpppc_opt       dissect_ccp_other_opt
static void dissect_ccp_stac_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ccp_mppe_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ccp_gfza_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
#define dissect_ccp_v42bis_opt      dissect_ccp_other_opt
static void dissect_ccp_bsdcomp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ccp_lzsdcp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ccp_mvrca_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ccp_dce_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ccp_deflate_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);
static void dissect_ccp_v44lzjh_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);

static const ip_tcp_opt ccp_opts[] = {

    {CI_CCP_OUI, "OUI", &ett_ccp_oui_opt,
        OPT_LEN_VARIABLE_LENGTH, 6, dissect_ccp_oui_opt},
    {CI_CCP_PREDICT1, "Predictor type 1", &ett_ccp_predict1_opt,
        OPT_LEN_VARIABLE_LENGTH, 2, dissect_ccp_predict1_opt},
    {CI_CCP_PREDICT2, "Predictor type 2", &ett_ccp_predict2_opt,
        OPT_LEN_VARIABLE_LENGTH, 2, dissect_ccp_predict2_opt},
    {CI_CCP_PUDDLE, "Puddle Jumper", &ett_ccp_puddle_opt,
        OPT_LEN_VARIABLE_LENGTH, 2, dissect_ccp_puddle_opt},
    {CI_CCP_HPPPC, "Hewlett-Packard PPC", &ett_ccp_hpppc_opt,
        OPT_LEN_VARIABLE_LENGTH, 2, dissect_ccp_hpppc_opt},
    {CI_CCP_STAC, "Stac Electronics LZS", &ett_ccp_stac_opt,
        /* In RFC 1974, this is a fixed-length field of size 5, but in
         * Ascend Proprietary STAC compression this field is 6 octets. */
        OPT_LEN_VARIABLE_LENGTH, 5, dissect_ccp_stac_opt},
    {CI_CCP_MPPE, "Microsoft PPE/PPC", &ett_ccp_mppe_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_ccp_mppe_opt},
    {CI_CCP_GFZA, "Gandalf FZA", &ett_ccp_gfza_opt,
        OPT_LEN_VARIABLE_LENGTH, 3, dissect_ccp_gfza_opt},
    {CI_CCP_V42BIS, "V.42bis compression", &ett_ccp_v42bis_opt,
        OPT_LEN_VARIABLE_LENGTH, 2, dissect_ccp_v42bis_opt},
    {CI_CCP_BSDLZW, "BSD LZW Compress", &ett_ccp_bsdcomp_opt,
        OPT_LEN_FIXED_LENGTH, 3, dissect_ccp_bsdcomp_opt},
    {CI_CCP_LZSDCP, "LZS-DCP", &ett_ccp_lzsdcp_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_ccp_lzsdcp_opt},
    {CI_CCP_MVRCA, "MVRCA (Magnalink)", &ett_ccp_mvrca_opt,
        OPT_LEN_FIXED_LENGTH, 4, dissect_ccp_mvrca_opt},
    {CI_CCP_DCE,
        "PPP for Data Compression in Data Circuit-Terminating Equipment (DCE)",
        &ett_ccp_dce_opt,
        OPT_LEN_FIXED_LENGTH, 3, dissect_ccp_dce_opt},
    {CI_CCP_DEFLATE, "Deflate", &ett_ccp_deflate_opt,
        /* RFC1979 says the length is 3 but it's actually 4. */
        OPT_LEN_FIXED_LENGTH, 4, dissect_ccp_deflate_opt},
    {CI_CCP_V44LZJH, "V.44/LZJH compression", &ett_ccp_v44lzjh_opt,
        OPT_LEN_VARIABLE_LENGTH, 4, dissect_ccp_v44lzjh_opt}
};

#define N_CCP_OPTS      (sizeof ccp_opts / sizeof ccp_opts[0])

/*
 * Options.  (CBCP)
 */
#define CI_CBCP_NO_CALLBACK     1  /* No callback */
#define CI_CBCP_CB_USER         2  /* Callback to a user-specified number */
#define CI_CBCP_CB_PRE          3  /* Callback to a pre-specified or
                                      administrator specified number */
#define CI_CBCP_CB_ANY          4  /* Callback to any of a list of numbers */

static void dissect_cbcp_no_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);

static void dissect_cbcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);

static const ip_tcp_opt cbcp_opts[] = {
    {CI_CBCP_NO_CALLBACK, "No callback", NULL,
        OPT_LEN_FIXED_LENGTH, 2, dissect_cbcp_no_callback_opt},
    {CI_CBCP_CB_USER, "Callback to a user-specified number", &ett_cbcp_callback_opt,
        OPT_LEN_VARIABLE_LENGTH, 4, dissect_cbcp_callback_opt},
    {CI_CBCP_CB_PRE, "Callback to a pre-specified or admin-specified number", &ett_cbcp_callback_opt,
        OPT_LEN_FIXED_LENGTH, 3, dissect_cbcp_callback_opt},
    {CI_CBCP_CB_ANY, "Callback to any of a list of numbers", &ett_cbcp_callback_opt,
        OPT_LEN_VARIABLE_LENGTH, 4, dissect_cbcp_callback_opt}
};

#define N_CBCP_OPTS     (sizeof cbcp_opts / sizeof cbcp_opts[0])

/*
 * Options.  (BACP)
 */
#define CI_BACP_FAVORED_PEER    1  /* Favored-Peer */

static void dissect_bacp_favored_peer_opt(const ip_tcp_opt *optp,
    tvbuff_t *tvb, int offset, guint length, packet_info *pinfo,
    proto_tree *tree, void *data _U_);

static const ip_tcp_opt bacp_opts[] = {
    {CI_BACP_FAVORED_PEER, "Favored-Peer", &ett_bacp_favored_peer_opt,
        OPT_LEN_FIXED_LENGTH, 6, dissect_bacp_favored_peer_opt}
};

#define N_BACP_OPTS     (sizeof bacp_opts / sizeof bacp_opts[0])

/*
 * Options.  (BAP)
 */
#define CI_BAP_LINK_TYPE           1  /* Link Type */
#define CI_BAP_PHONE_DELTA         2  /* Phone-Delta */
#define CI_BAP_NO_PHONE_NUM_NEEDED 3  /* No Phone Number Needed */
#define CI_BAP_REASON              4  /* Reason */
#define CI_BAP_LINK_DISC           5  /* Link Discriminator */
#define CI_BAP_CALL_STATUS         6  /* Call Status */

static void dissect_bap_link_type_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_bap_phone_delta_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_bap_link_disc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_bap_reason_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);
static void dissect_bap_call_status_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);

static const ip_tcp_opt bap_opts[] = {
    {CI_BAP_LINK_TYPE, "Link Type", &ett_bap_link_type_opt,
        OPT_LEN_FIXED_LENGTH, 5, dissect_bap_link_type_opt},
    {CI_BAP_PHONE_DELTA, "Phone Delta", &ett_bap_phone_delta_opt,
        OPT_LEN_VARIABLE_LENGTH, 4, dissect_bap_phone_delta_opt},
    {CI_BAP_NO_PHONE_NUM_NEEDED, "No Phone Number Needed", NULL,
        OPT_LEN_FIXED_LENGTH, 2, NULL},
    {CI_BAP_REASON, "Reason", NULL,
        OPT_LEN_VARIABLE_LENGTH, 2, dissect_bap_reason_opt},
    {CI_BAP_LINK_DISC, "Link Discriminator", NULL,
        OPT_LEN_FIXED_LENGTH, 4, dissect_bap_link_disc_opt},
    {CI_BAP_CALL_STATUS, "Call Status", &ett_bap_call_status_opt,
        OPT_LEN_FIXED_LENGTH, 4, dissect_bap_call_status_opt}
};

#define N_BAP_OPTS     (sizeof bap_opts / sizeof bap_opts[0])

static void dissect_ppp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static const value_string pap_vals[] = {
    {CONFREQ, "Authenticate-Request"},
    {CONFACK, "Authenticate-Ack"},
    {CONFNAK, "Authenticate-Nak"},
    {0,       NULL}
};

static void dissect_pap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#define CHAP_CHAL  1  /* CHAP Challenge */
#define CHAP_RESP  2  /* CHAP Response */
#define CHAP_SUCC  3  /* CHAP Success */
#define CHAP_FAIL  4  /* CHAP Failure */

static const value_string chap_vals[] = {
    {CHAP_CHAL, "Challenge"},
    {CHAP_RESP, "Response"},
    {CHAP_SUCC, "Success"},
    {CHAP_FAIL, "Failure"},
    {0,         NULL}
};

static void dissect_chap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static const value_string pppmuxcp_vals[] = {
    {CONFREQ, "Configuration Request"},
    {CONFACK, "Configuration Ack"},
    {0,       NULL}
};

/*
 * PPPMuxCP options
 */

#define CI_DEFAULT_PID   1

static void dissect_pppmuxcp_def_pid_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);


static const ip_tcp_opt pppmuxcp_opts[] = {
    {CI_DEFAULT_PID, "Default Protocol ID", NULL,
        OPT_LEN_FIXED_LENGTH, 4, dissect_pppmuxcp_def_pid_opt}
};

static const true_false_string tfs_pppmux_length_field = { "2 bytes", "1 byte" };

#define N_PPPMUXCP_OPTS (sizeof pppmuxcp_opts / sizeof pppmuxcp_opts[0])

/*
 * Options.  (IPv6CP)
 */
#define CI_IPV6CP_IF_ID         1       /* Interface Identifier (RFC 2472) */
#define CI_IPV6CP_COMPRESSTYPE  2       /* Compression Type (RFC 2472) */

static void dissect_ipv6cp_if_id_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo, proto_tree *tree, void *data _U_);

static const ip_tcp_opt ipv6cp_opts[] = {
    {CI_IPV6CP_IF_ID, "Interface Identifier", &ett_ipv6cp_if_id_opt,
        OPT_LEN_FIXED_LENGTH, 10, dissect_ipv6cp_if_id_opt},
    {CI_COMPRESS_PROTO, "IPv6 compression", &ett_ipv6cp_compress_opt,
        OPT_LEN_VARIABLE_LENGTH, 4, dissect_ipcp_compress_opt}
};

#define N_IPV6CP_OPTS   (sizeof ipv6cp_opts / sizeof ipv6cp_opts[0])

/*
*******************************************************************************
* DETAILS : Calculate a new FCS-16 given the current FCS-16 and the new data.
*******************************************************************************
*/
static guint16
fcs16(tvbuff_t *tvbuff)
{
    guint len = tvb_length(tvbuff) - 2;

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
fcs32(tvbuff_t *tvbuff)
{
    guint len = tvb_length(tvbuff) - 4;

    /* Check for invalid Length */
    if (len == 0)
        return (0x00000000);
    return crc32_ccitt_tvb(tvbuff, len);
}

tvbuff_t *
decode_fcs(tvbuff_t *tvb, proto_tree *fh_tree, int fcs_decode, int proto_offset)
{
    tvbuff_t *next_tvb;
    gint      len, reported_len;
    int       rx_fcs_offset;
    guint32   rx_fcs_exp;
    guint32   rx_fcs_got;

    /*
     * Remove the FCS, if any, from the packet data.
     */
    switch (fcs_decode) {

    case NO_FCS:
        next_tvb = tvb_new_subset_remaining(tvb, proto_offset);
        break;

    case FCS_16:
        /*
         * Do we have the entire packet, and does it include a 2-byte FCS?
         */
        len = tvb_length_remaining(tvb, proto_offset);
        reported_len = tvb_reported_length_remaining(tvb, proto_offset);
        if (reported_len < 2 || len < 0) {
            /*
             * The packet is claimed not to even have enough data for a 2-byte
             * FCS, or we're already past the end of the captured data.
             * Don't slice anything off.
             */
            next_tvb = tvb_new_subset_remaining(tvb, proto_offset);
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
                    "FCS 16: 0x%04x [correct]", rx_fcs_got);
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
             * The packet is claimed not to even have enough data for a 4-byte
             * FCS.  Just pass on the tvbuff as is.
             */
            next_tvb = tvb_new_subset_remaining(tvb, proto_offset);
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
                    "FCS 32: 0x%08x [correct]", rx_fcs_got);
            }
        }
        break;

    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        next_tvb = NULL;
        break;
    }

    return next_tvb;
}

void
capture_ppp_hdlc(const guchar *pd, int offset, int len, packet_counts *ld)
{
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
dissect_lcp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_lcp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_lcp_opt_length, tvb, offset + 1, 1, ENC_NA);
}

static void
dissect_lcp_vendor_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf, *ti;
    guint32 oui;
    const gchar *manuf;

    oui = tvb_get_ntoh24(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    ti = proto_tree_add_uint_format_value(field_tree, hf_lcp_opt_oui, tvb,
        offset + 2, 3, oui, "%02x:%02x:%02x",
        (oui >> 16) & 0xff, (oui >> 8) & 0xff, oui & 0xff);
    manuf = uint_get_manuf_name_if_known(oui);
    if (manuf)
        proto_item_append_text(ti, "(%s)", manuf);

    proto_tree_add_item(field_tree, hf_lcp_opt_kind, tvb, offset + 5, 1,
        ENC_NA);
    if (length > 6) {
        proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset + 6,
            length - 6, ENC_NA);
    }
}

static void
dissect_lcp_mru_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u", optp->name,
        tvb_get_ntohs(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_mru, tvb, offset + 2, 2,
        ENC_BIG_ENDIAN);
}

static void
dissect_lcp_async_map_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf, *ti;
    static const int *asyncmap_fields[] = {
        &hf_lcp_opt_asyncmap_us,  &hf_lcp_opt_asyncmap_rs,
        &hf_lcp_opt_asyncmap_gs,  &hf_lcp_opt_asyncmap_fs,
        &hf_lcp_opt_asyncmap_esc, &hf_lcp_opt_asyncmap_sub,
        &hf_lcp_opt_asyncmap_em,  &hf_lcp_opt_asyncmap_can,
        &hf_lcp_opt_asyncmap_etb, &hf_lcp_opt_asyncmap_syn,
        &hf_lcp_opt_asyncmap_nak, &hf_lcp_opt_asyncmap_dc4,
        &hf_lcp_opt_asyncmap_dc3, &hf_lcp_opt_asyncmap_dc2,
        &hf_lcp_opt_asyncmap_dc1, &hf_lcp_opt_asyncmap_dle,
        &hf_lcp_opt_asyncmap_si,  &hf_lcp_opt_asyncmap_so,
        &hf_lcp_opt_asyncmap_cr,  &hf_lcp_opt_asyncmap_ff,
        &hf_lcp_opt_asyncmap_vt,  &hf_lcp_opt_asyncmap_lf,
        &hf_lcp_opt_asyncmap_ht,  &hf_lcp_opt_asyncmap_bs,
        &hf_lcp_opt_asyncmap_bel, &hf_lcp_opt_asyncmap_ack,
        &hf_lcp_opt_asyncmap_enq, &hf_lcp_opt_asyncmap_eot,
        &hf_lcp_opt_asyncmap_etx, &hf_lcp_opt_asyncmap_stx,
        &hf_lcp_opt_asyncmap_soh, &hf_lcp_opt_asyncmap_nul,
        NULL
    };

    static const char *ctrlchars[32] = {
        "NUL", "SOH",       "STX", "ETX",        "EOT", "ENQ", "ACK", "BEL",
        "BS",  "HT",        "LF",  "VT",         "FF",  "CR",  "SO",  "SI",
        "DLE", "DC1 (XON)", "DC2", "DC3 (XOFF)", "DC4", "NAK", "SYN", "ETB",
        "CAN", "EM",        "SUB", "ESC",        "FS",  "GS",  "RS",  "US"
    };

    gboolean anyctrlchars;
    guint32 map;
    int i;

    map = tvb_get_ntohl(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: 0x%08x (",
        optp->name, map);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    ti = proto_tree_add_bitmask(field_tree, tvb, offset + 2,
        hf_lcp_opt_asyncmap, *optp->subtree_index, asyncmap_fields,
        ENC_BIG_ENDIAN);
    if (map == 0x00000000) {
        proto_item_append_text(tf, "None)");
        proto_item_append_text(ti, " (None)");
    } else if (map == 0xffffffff) {
        proto_item_append_text(tf, "All)");
        proto_item_append_text(ti, " (All)");
    } else {
        for (anyctrlchars = FALSE, i = 31; i >= 0; i--) {
            if (map & (1 << i)) {
                if (anyctrlchars)
                    proto_item_append_text(tf, ", %s", ctrlchars[i]);
                else {
                    anyctrlchars = TRUE;
                    proto_item_append_text(tf, "%s", ctrlchars[i]);
                }
            }
        }
        proto_item_append_text(tf, ")");
    }
}

static void
dissect_lcp_authprot_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    guint16 protocol;

    protocol = tvb_get_ntohs(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s (0x%02x)",
        optp->name, val_to_str_ext_const(protocol, &ppp_vals_ext, "Unknown"),
        protocol);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_auth_protocol, tvb, offset + 2,
        2, ENC_BIG_ENDIAN);

    if (length > 4) {
        offset += 4;
        length -= 4;
        if (protocol == PPP_CHAP) {
            proto_tree_add_item(field_tree, hf_lcp_opt_algorithm, tvb, offset,
                1, ENC_NA);
            if (length > 1) {
                proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb,
                    offset + 1, length - 1, ENC_NA);
            }
        } else {
            proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
                length, ENC_NA);
        }
    }
}

static void
dissect_lcp_qualprot_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    guint16 protocol;

    protocol = tvb_get_ntohs(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s (0x%02x)",
        optp->name, val_to_str_ext_const(protocol, &ppp_vals_ext, "Unknown"),
        protocol);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_quality_protocol, tvb,
        offset + 2, 2, ENC_BIG_ENDIAN);

    if (length > 4) {
        proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset + 4,
            length + 4, ENC_NA);
    }
}

static void
dissect_lcp_magicnumber_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: 0x%08x",
        optp->name, tvb_get_ntohl(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_magic_number, tvb, offset + 2,
        4, ENC_BIG_ENDIAN);
}

static void
dissect_lcp_linkqualmon_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    guint32 reportingperiod;

    reportingperiod = tvb_get_ntohl(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length,
        "%s: %u microsecond%s%s", optp->name, reportingperiod,
        plurality(reportingperiod, "", "s"),
        reportingperiod ? "" : " [illegal]");
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_uint_format_value(field_tree, hf_lcp_opt_reportingperiod,
        tvb, offset + 2, 4, reportingperiod, "%u microsecond%s%s",
        reportingperiod, plurality(reportingperiod, "", "s"),
        reportingperiod ? "" : "[illegal]");
}

/* Used for:
 *  Protocol Field Compression
 *  Address and Control Field Compression
 *  Compound Frames (Deprecated)
 *  Nominal Data Encapsulation (Deprecated)
 *  Multilink Short Sequence Number Header
 *  Simple Data Link on SONET/SDH
 */
static void
dissect_lcp_simple_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
}

static void
dissect_lcp_fcs_alternatives_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree,
    void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    static const int *fcs_alternatives_fields[] = {
        &hf_lcp_opt_fcs_alternatives_ccitt32,
        &hf_lcp_opt_fcs_alternatives_ccitt16,
        &hf_lcp_opt_fcs_alternatives_null,
        NULL
    };

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: 0x%02x",
        optp->name, tvb_get_guint8(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_bitmask(field_tree, tvb, offset + 2,
        hf_lcp_opt_fcs_alternatives, *optp->subtree_index,
        fcs_alternatives_fields, ENC_NA);
}

static void
dissect_lcp_self_describing_pad_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree,
    void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    guint8 maximum;

    maximum = tvb_get_guint8(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u octet%s%s",
        optp->name, maximum, plurality(maximum, "", "s"),
        maximum ? "" : " [invalid]");
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_uint_format_value(field_tree, hf_lcp_opt_maximum, tvb,
        offset + 2, 1, maximum, "%u octet%s%s", maximum,
        plurality(maximum, "", "s"), maximum ? "" : " [invalid]");
}

static void
dissect_lcp_numbered_mode_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree,
    void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    guint8 window;

    window = tvb_get_guint8(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u frame%s%s",
        optp->name, window, plurality(window, "", "s"),
        (window == 0 || window > 127) ? " [invalid]" : "");
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_uint_format_value(field_tree, hf_lcp_opt_window, tvb,
        offset + 2, 1, window, "%u frame%s%s", window,
        plurality(window, "", "s"),
        (window == 0 || window > 127) ? " [invalid]" : "");
    if (length > 3) {
        proto_tree_add_item(field_tree, hf_lcp_opt_hdlc_address, tvb,
            offset + 3, length - 3, ENC_NA);
    }
}

/* http://tools.ietf.org/html/rfc1570#section-2.3 only lists 0-4, but
 * http://tools.ietf.org/html/draft-ietf-pppext-callback-ds-02 lists 5 as
 * "E.165 number", rather than "unassigned", and
 * http://msdn.microsoft.com/en-us/library/ff632847%28v=prot.10%29.aspx does
 * indicate 6 as below.  Since 5 is only mentioned in the draft, leave it as
 * "unassigned"?
 */
static const value_string callback_op_vals[] = {
    {0, "Location is determined by user authentication"},
    {1, "Message is dialing string"},
    {2, "Message is location identifier"},
    {3, "Message is E.164"},
    {4, "Message is distinguished name"},
    {5, "unassigned"}, /* "Message is E.165"? */
    {6, "Location is determined during CBCP negotiation"},
    {0, NULL}
};

static void
dissect_lcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    guint8 operation;

    operation = tvb_get_guint8(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        val_to_str_const(operation, callback_op_vals, "Unknown"));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_operation, tvb, offset + 2, 1,
        ENC_NA);

    if (length > 3) {
        proto_tree_add_item(field_tree, hf_lcp_opt_message, tvb, offset + 3,
            length - 3, ENC_NA);
    }
}

/* http://tools.ietf.org/html/rfc1990#section-5.1.1 */
static void
dissect_lcp_multilink_mrru_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree,
    void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u", optp->name,
        tvb_get_ntohs(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_mrru, tvb, offset + 2, 2,
        ENC_BIG_ENDIAN);
}

#define CLASS_NULL                      0
#define CLASS_LOCAL                     1
#define CLASS_IP                        2
#define CLASS_IEEE_802_1                3
#define CLASS_PPP_MAGIC_NUMBER          4
#define CLASS_PSDN_DIRECTORY_NUMBER     5

static const value_string multilink_ep_disc_class_vals[] = {
    {CLASS_NULL,                  "Null"},
    {CLASS_LOCAL,                 "Locally assigned address"},
    {CLASS_IP,                    "Internet Protocol (IP) address"},
    {CLASS_IEEE_802_1,            "IEEE 802.1 globally assigned MAC address"},
    {CLASS_PPP_MAGIC_NUMBER,      "PPP magic-number block"},
    {CLASS_PSDN_DIRECTORY_NUMBER, "Public switched network directory number"},
    {0,                           NULL}
};

static void
dissect_lcp_multilink_ep_disc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree,
    void *data _U_)
{
    proto_tree *field_tree;
    proto_tree *magic_tree;
    proto_item *tf, *tm;
    guint8 ep_disc_class;

    ep_disc_class = tvb_get_guint8(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: Class: %s",
        optp->name, val_to_str_const(ep_disc_class,
            multilink_ep_disc_class_vals, "Unknown"));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_ep_disc_class, tvb, offset + 2,
        1, ENC_NA);

    if (length <= 3)
        return;

    length -= 3;
    offset += 3;
    switch (ep_disc_class) {
    case CLASS_NULL:
        break;

    case CLASS_LOCAL:
        proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
            length <= 20 ? length : 20, ENC_NA);
        break;

    case CLASS_IP:
        if (length >= 4) {
            proto_tree_add_item(field_tree, hf_lcp_opt_ip_address, tvb, offset,
                4, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
                length, ENC_NA);
        }
        break;

    case CLASS_IEEE_802_1:
        if (length >= 6) {
            proto_tree_add_item(field_tree, hf_lcp_opt_802_1_address, tvb,
                offset, 6, ENC_NA);
        } else {
            proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
                length, ENC_NA);
        }
        break;

    case CLASS_PPP_MAGIC_NUMBER:
        if (length % 4) {
            proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
                length, ENC_NA);
        } else {
            tm = proto_tree_add_item(field_tree, hf_lcp_opt_magic_block, tvb,
                offset, length <= 20 ? length : 20, ENC_NA);
            magic_tree = proto_item_add_subtree(tm, ett_lcp_magic_block);
            for ( ; length >= 4; length -= 4, offset += 4) {
                proto_tree_add_item(magic_tree, hf_lcp_opt_magic_number, tvb,
                    offset, 4, ENC_BIG_ENDIAN);
            }
        }
        break;

    case CLASS_PSDN_DIRECTORY_NUMBER:
        proto_tree_add_item(field_tree, hf_lcp_opt_psndn, tvb, offset,
            length > 15 ? 15 : length, ENC_NA);
        break;

    default:
        proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset, length,
            ENC_NA);
        break;
    }
}

static const value_string dce_id_mode_vals[] = {
    {1, "Mode-1 (No Additional Negotiation)"},
    {2, "Mode-2 (Full PPP Negotiation and State Machine)"},
    {0, NULL}
};

static void
dissect_lcp_dce_identifier_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    guint8 mode;

    mode = tvb_get_guint8(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        val_to_str_const(mode, dce_id_mode_vals, "Unknown"));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_mode, tvb, offset + 2, 1,
        ENC_NA);
}

static void
dissect_lcp_multilink_pp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_unused, tvb, offset + 2, 2,
        ENC_NA);
}

static void
dissect_lcp_bacp_link_discriminator_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %u (0x%04x)",
        optp->name, tvb_get_ntohs(tvb, offset + 2),
        tvb_get_ntohs(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_link_discrim, tvb, offset + 2,
        2, ENC_BIG_ENDIAN);
}

/* Assuming it's this one:
 * http://tools.ietf.org/html/draft-ietf-pppext-link-negot-00
 */
static void
dissect_lcp_auth_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    guint8 id_len;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_id, tvb, offset + 2, 1, ENC_NA);

    if (length > 3) {
        id_len = tvb_get_guint8(tvb, offset + 2);
        length -= 3;
        offset += 3;
        if (id_len < length) {
            length -= id_len;
            offset += id_len;
            proto_tree_add_item(field_tree, hf_lcp_opt_data, tvb, offset,
                length, ENC_NA);
        }
    }
}

/* Asuming it's this one:
 * http://tools.ietf.org/html/draft-ietf-pppext-cobs-00
 */
static void
dissect_lcp_cobs_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    static const int *cobs_flags_fields[] = {
        &hf_lcp_opt_cobs_flags_res,
        &hf_lcp_opt_cobs_flags_pre,
        &hf_lcp_opt_cobs_flags_zxe,
        NULL
    };

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_bitmask(field_tree, tvb, offset + 2, hf_lcp_opt_cobs_flags,
        *optp->subtree_index, cobs_flags_fields, ENC_NA);
}

static void
dissect_lcp_prefix_elision_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;
    guint8 pre_len;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);

    if (length > 2) {
        length -= 2;
        offset += 2;
        while (length >= 2) {
            proto_tree_add_item(field_tree, hf_lcp_opt_class, tvb, offset, 1,
                ENC_NA);
            pre_len = tvb_get_guint8(tvb, offset + 1);
            if ((guint)(pre_len + 2) <= length) {
                proto_tree_add_item(field_tree, hf_lcp_opt_prefix, tvb,
                    offset + 2, 1, ENC_NA);
                length -= (2 + pre_len);
            } else {
                /* Prefix length doesn't make sense, so bail out */
                length = 0;
            }
        }
    }
}

static const value_string ml_hdr_fmt_code_vals[] = {
    {2, "Long sequence number fragment format with classes"},
    {6, "Short sequence number fragment format with classes"},
    {0, NULL}
};

static void
dissect_lcp_multilink_hdr_fmt_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_code, tvb, offset + 2, 1,
        ENC_NA);
    proto_tree_add_item(field_tree, hf_lcp_opt_max_susp_classes, tvb,
        offset + 3, 1, ENC_NA);
}


/* Character sets from http://www.iana.org/assignments/character-sets. */
static const value_string charset_vals[] = {
    {3,    "ANSI_X3.4-1968"},
    {4,    "ISO_8859-1:1987"},
    {5,    "ISO_8859-2:1987"},
    {6,    "ISO_8859-3:1988"},
    {7,    "ISO_8859-4:1988"},
    {8,    "ISO_8859-5:1988"},
    {9,    "ISO_8859-6:1987"},
    {10,   "ISO_8859-7:1987"},
    {11,   "ISO_8859-8:1988"},
    {12,   "ISO_8859-9:1989"},
    {13,   "ISO-8859-10"},
    {14,   "ISO_6937-2-add"},
    {15,   "JIS_X0201"},
    {16,   "JIS_Encoding"},
    {17,   "Shift_JIS"},
    {18,   "Extended_UNIX_Code_Packed_Format_for_Japanese"},
    {19,   "Extended_UNIX_Code_Fixed_Width_for_Japanese"},
    {20,   "BS_4730"},
    {21,   "SEN_850200_C"},
    {22,   "IT"},
    {23,   "ES"},
    {24,   "DIN_66003"},
    {25,   "NS_4551-1"},
    {26,   "NF_Z_62-010"},
    {27,   "ISO-10646-UTF-1"},
    {28,   "ISO_646.basic:1983"},
    {29,   "INVARIANT"},
    {30,   "ISO_646.irv:1983"},
    {31,   "NATS-SEFI"},
    {32,   "NATS-SEFI-ADD"},
    {33,   "NATS-DANO"},
    {34,   "NATS-DANO-ADD"},
    {35,   "SEN_850200_B"},
    {36,   "KS_C_5601-1987"},
    {37,   "ISO-2022-KR"},
    {38,   "EUC-KR"},
    {39,   "ISO-2022-JP"},
    {40,   "ISO-2022-JP-2"},
    {41,   "JIS_C6220-1969-jp"},
    {42,   "JIS_C6220-1969-ro"},
    {43,   "PT"},
    {44,   "greek7-old"},
    {45,   "latin-greek"},
    {46,   "NF_Z_62-010_(1973)"},
    {47,   "Latin-greek-1"},
    {48,   "ISO_5427"},
    {49,   "JIS_C6226-1978"},
    {50,   "BS_viewdata"},
    {51,   "INIS"},
    {52,   "INIS-8"},
    {53,   "INIS-cyrillic"},
    {54,   "ISO_5427:1981"},
    {55,   "ISO_5428:1980"},
    {56,   "GB_1988-80"},
    {57,   "GB_2312-80"},
    {58,   "NS_4551-2"},
    {59,   "videotex-suppl"},
    {60,   "PT2"},
    {61,   "ES2"},
    {62,   "MSZ_7795.3"},
    {63,   "JIS_C6226-1983"},
    {64,   "greek7"},
    {65,   "ASMO_449"},
    {66,   "iso-ir-90"},
    {67,   "JIS_C6229-1984-a"},
    {68,   "JIS_C6229-1984-b"},
    {69,   "JIS_C6229-1984-b-add"},
    {70,   "JIS_C6229-1984-hand"},
    {71,   "JIS_C6229-1984-hand-add"},
    {72,   "JIS_C6229-1984-kana"},
    {73,   "ISO_2033-1983"},
    {74,   "ANSI_X3.110-1983"},
    {75,   "T.61-7bit"},
    {76,   "T.61-8bit"},
    {77,   "ECMA-cyrillic"},
    {78,   "CSA_Z243.4-1985-1"},
    {79,   "CSA_Z243.4-1985-2"},
    {80,   "CSA_Z243.4-1985-gr"},
    {81,   "ISO_8859-6-E"},
    {82,   "ISO_8859-6-I"},
    {83,   "T.101-G2"},
    {84,   "ISO_8859-8-E"},
    {85,   "ISO_8859-8-I"},
    {86,   "CSN_369103"},
    {87,   "JUS_I.B1.002"},
    {88,   "IEC_P27-1"},
    {89,   "JUS_I.B1.003-serb"},
    {90,   "JUS_I.B1.003-mac"},
    {91,   "greek-ccitt"},
    {92,   "NC_NC00-10:81"},
    {93,   "ISO_6937-2-25"},
    {94,   "GOST_19768-74"},
    {95,   "ISO_8859-supp"},
    {96,   "ISO_10367-box"},
    {97,   "latin-lap"},
    {98,   "JIS_X0212-1990"},
    {99,   "DS_2089"},
    {100,  "us-dk"},
    {101,  "dk-us"},
    {102,  "KSC5636"},
    {103,  "UNICODE-1-1-UTF-7"},
    {104,  "ISO-2022-CN"},
    {105,  "ISO-2022-CN-EXT"},
    {106,  "UTF-8"},
    {109,  "ISO-8859-13"},
    {110,  "ISO-8859-14"},
    {111,  "ISO-8859-15"},
    {112,  "ISO-8859-16"},
    {113,  "GBK"},
    {114,  "GB18030"},
    {115,  "OSD_EBCDIC_DF04_15"},
    {116,  "OSD_EBCDIC_DF03_IRV"},
    {117,  "OSD_EBCDIC_DF04_1"},
    {118,  "ISO-11548-1"},
    {119,  "KZ-1048"},
    {1000, "ISO-10646-UCS-2"},
    {1001, "ISO-10646-UCS-4"},
    {1002, "ISO-10646-UCS-Basic"},
    {1003, "ISO-10646-Unicode-Latin1"},
    {1004, "ISO-10646-J-1"},
    {1005, "ISO-Unicode-IBM-1261"},
    {1006, "ISO-Unicode-IBM-1268"},
    {1007, "ISO-Unicode-IBM-1276"},
    {1008, "ISO-Unicode-IBM-1264"},
    {1009, "ISO-Unicode-IBM-1265"},
    {1010, "UNICODE-1-1"},
    {1011, "SCSU"},
    {1012, "UTF-7"},
    {1013, "UTF-16BE"},
    {1014, "UTF-16LE"},
    {1015, "UTF-16"},
    {1016, "CESU-8"},
    {1017, "UTF-32"},
    {1018, "UTF-32BE"},
    {1019, "UTF-32LE"},
    {1020, "BOCU-1"},
    {2000, "ISO-8859-1-Windows-3.0-Latin-1"},
    {2001, "ISO-8859-1-Windows-3.1-Latin-1"},
    {2002, "ISO-8859-2-Windows-Latin-2"},
    {2003, "ISO-8859-9-Windows-Latin-5"},
    {2004, "hp-roman8"},
    {2005, "Adobe-Standard-Encoding"},
    {2006, "Ventura-US"},
    {2007, "Ventura-International"},
    {2008, "DEC-MCS"},
    {2009, "IBM850"},
    {2010, "IBM852"},
    {2011, "IBM437"},
    {2012, "PC8-Danish-Norwegian"},
    {2013, "IBM862"},
    {2014, "PC8-Turkish"},
    {2015, "IBM-Symbols"},
    {2016, "IBM-Thai"},
    {2017, "HP-Legal"},
    {2018, "HP-Pi-font"},
    {2019, "HP-Math8"},
    {2020, "Adobe-Symbol-Encoding"},
    {2021, "HP-DeskTop"},
    {2022, "Ventura-Math"},
    {2023, "Microsoft-Publishing"},
    {2024, "Windows-31J"},
    {2025, "GB2312"},
    {2026, "Big5"},
    {2027, "macintosh"},
    {2028, "IBM037"},
    {2029, "IBM038"},
    {2030, "IBM273"},
    {2031, "IBM274"},
    {2032, "IBM275"},
    {2033, "IBM277"},
    {2034, "IBM278"},
    {2035, "IBM280"},
    {2036, "IBM281"},
    {2037, "IBM284"},
    {2038, "IBM285"},
    {2039, "IBM290"},
    {2040, "IBM297"},
    {2041, "IBM420"},
    {2042, "IBM423"},
    {2043, "IBM424"},
    {2044, "IBM500"},
    {2045, "IBM851"},
    {2046, "IBM855"},
    {2047, "IBM857"},
    {2048, "IBM860"},
    {2049, "IBM861"},
    {2050, "IBM863"},
    {2051, "IBM864"},
    {2052, "IBM865"},
    {2053, "IBM868"},
    {2054, "IBM869"},
    {2055, "IBM870"},
    {2056, "IBM871"},
    {2057, "IBM880"},
    {2058, "IBM891"},
    {2059, "IBM903"},
    {2060, "IBM904"},
    {2061, "IBM905"},
    {2062, "IBM918"},
    {2063, "IBM1026"},
    {2064, "EBCDIC-AT-DE"},
    {2065, "EBCDIC-AT-DE-A"},
    {2066, "EBCDIC-CA-FR"},
    {2067, "EBCDIC-DK-NO"},
    {2068, "EBCDIC-DK-NO-A"},
    {2069, "EBCDIC-FI-SE"},
    {2070, "EBCDIC-FI-SE-A"},
    {2071, "EBCDIC-FR"},
    {2072, "EBCDIC-IT"},
    {2073, "EBCDIC-PT"},
    {2074, "EBCDIC-ES"},
    {2075, "EBCDIC-ES-A"},
    {2076, "EBCDIC-ES-S"},
    {2077, "EBCDIC-UK"},
    {2078, "EBCDIC-US"},
    {2079, "UNKNOWN-8BIT"},
    {2080, "MNEMONIC"},
    {2081, "MNEM"},
    {2082, "VISCII"},
    {2083, "VIQR"},
    {2084, "KOI8-R"},
    {2085, "HZ-GB-2312"},
    {2086, "IBM866"},
    {2087, "IBM775"},
    {2088, "KOI8-U"},
    {2089, "IBM00858"},
    {2090, "IBM00924"},
    {2091, "IBM01140"},
    {2092, "IBM01141"},
    {2093, "IBM01142"},
    {2094, "IBM01143"},
    {2095, "IBM01144"},
    {2096, "IBM01145"},
    {2097, "IBM01146"},
    {2098, "IBM01147"},
    {2099, "IBM01148"},
    {2100, "IBM01149"},
    {2101, "Big5-HKSCS"},
    {2102, "IBM1047"},
    {2103, "PTCP154"},
    {2104, "Amiga-1251"},
    {2105, "KOI7-switched"},
    {2106, "BRF"},
    {2107, "TSCII"},
    {2108, "CP51932"},
    {2109, "windows-874"},
    {2250, "windows-1250"},
    {2251, "windows-1251"},
    {2252, "windows-1252"},
    {2253, "windows-1253"},
    {2254, "windows-1254"},
    {2255, "windows-1255"},
    {2256, "windows-1256"},
    {2257, "windows-1257"},
    {2258, "windows-1258"},
    {2259, "TIS-620"},
    {2260, "CP50220"},
    {0,    NULL}
};
value_string_ext charset_vals_ext = VALUE_STRING_EXT_INIT(charset_vals);

static void
dissect_lcp_internationalization_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_lcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_lcp_opt_MIBenum, tvb, offset + 2, 4,
        ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_lcp_opt_language_tag, tvb, offset + 6,
        length - 6, ENC_NA);
}

static void
dissect_ipcp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_ipcp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_ipcp_opt_length, tvb, offset + 1, 1, ENC_NA);
}

/* http://tools.ietf.org/html/rfc1172#section-5.1 */
static void
dissect_ipcp_addrs_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: Src: %s, Dst: %s",
        optp->name, tvb_ip_to_str(tvb, offset + 2),
        tvb_ip_to_str(tvb, offset + 6));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_ipcp_opt_src_address, tvb, offset + 2,
        4, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ipcp_opt_dst_address, tvb, offset + 6,
        4, ENC_BIG_ENDIAN);
}

static const true_false_string tfs_comp_slot_id = {
    "The slot identifier may be compressed",
    "The slot identifier must not be compressed"
};

/* http://tools.ietf.org/html/rfc1332#section-3.2 */
static void
dissect_ipcp_compress_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    guint16     us;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        val_to_str_const(tvb_get_ntohs(tvb, offset + 2),
            ipcp_compress_proto_vals, "Unknown"));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_ipcp_opt_compress_proto, tvb,
        offset + 2, 2, ENC_BIG_ENDIAN);

    us = tvb_get_ntohs(tvb, offset + 2);
    switch (us) {
    case IPCP_ROHC:
        proto_tree_add_item(field_tree, hf_ipcp_opt_max_cid, tvb, offset + 4,
            2, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_ipcp_opt_mrru, tvb, offset + 6, 2,
            ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_ipcp_opt_max_header, tvb,
            offset + 8, 2, ENC_BIG_ENDIAN);

        if (length > 10) {
            proto_item *tso;
            proto_tree *subopt_tree;

            /* suboptions */
            offset += 10;
            length -= 10;
            tso = proto_tree_add_text(field_tree, tvb, offset, length,
                "Suboptions: (%u byte%s)", length, plurality(length, "", "s"));
            subopt_tree = proto_item_add_subtree(tso, *optp->subtree_index);
            dissect_ip_tcp_options(tvb, offset, length, ipcp_rohc_subopts,
                N_IPCP_ROHC_SUBOPTS, -1, pinfo, subopt_tree, NULL, NULL);
        }
        break;

    case IPCP_COMPRESS_VJ_1172:
    case IPCP_COMPRESS_VJ:
        proto_tree_add_item(field_tree, hf_ipcp_opt_max_slot_id, tvb,
            offset + 4, 1, ENC_NA);
        proto_tree_add_item(field_tree, hf_ipcp_opt_comp_slot_id, tvb,
            offset + 5, 1, ENC_NA);
      break;

    case IPCP_COMPRESS_IPHC:
        proto_tree_add_item(field_tree, hf_ipcp_opt_tcp_space, tvb, offset + 4,
            2, ENC_BIG_ENDIAN);
        proto_tree_add_item(field_tree, hf_ipcp_opt_non_tcp_space, tvb,
            offset + 6, 2, ENC_BIG_ENDIAN);
        us = tvb_get_ntohs(tvb, offset + 8);
        proto_tree_add_uint_format_value(field_tree, hf_ipcp_opt_f_max_period,
            tvb, offset + 8, 2, us, "%u%s", us,
            (us == 0) ? " (infinity)" : "");
        us = tvb_get_ntohs(tvb, offset + 10);
        proto_tree_add_uint_format_value(field_tree, hf_ipcp_opt_f_max_time,
            tvb, offset + 10, 2, us, "%u%s", us,
            (us == 0) ? " (infinity)" : "");
        proto_tree_add_item(field_tree, hf_ipcp_opt_max_header, tvb,
            offset + 12, 2, ENC_BIG_ENDIAN);

        if ( length > 14 ) {
            proto_item *tso;
            proto_tree *subopt_tree;

            /* suboptions */
            offset += 14;
            length -= 14;
            tso = proto_tree_add_text(field_tree, tvb, offset, length,
                "Suboptions: (%u byte%s)", length, plurality(length, "", "s"));
            subopt_tree = proto_item_add_subtree(tso, *optp->subtree_index);
            dissect_ip_tcp_options(tvb, offset, length, ipcp_iphc_subopts,
                N_IPCP_IPHC_SUBOPTS, -1, pinfo, subopt_tree, NULL, NULL);
        }
        break;

    default:
        if (length > 4) {
            proto_tree_add_item(field_tree, hf_ipcp_data, tvb, offset + 4,
                length - 4, ENC_NA);
        }
        break;
    }
}

static void
dissect_ipcp_opt_rohc_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_ipcp_opt_rohc_type, tvb, offset,
        1, type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_ipcp_opt_rohc_length, tvb, offset + 1, 1,
        ENC_NA);
}

static void
dissect_ipcp_rohc_profiles_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_rohc_type_len(tvb, offset, field_tree, optp->name);
    if (length <= 2)
        return;

    for (offset += 2, length -= 2; length >= 2; length -= 2, offset += 2) {
        proto_tree_add_item(field_tree, hf_ipcp_opt_rohc_profile, tvb,
            offset, 2, ENC_BIG_ENDIAN);
    }
}

static void
dissect_ipcp_opt_iphc_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_ipcp_opt_iphc_type, tvb, offset,
        1, type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_ipcp_opt_iphc_length, tvb, offset + 1, 1,
        ENC_NA);
}

static void
dissect_ipcp_iphc_simple_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_iphc_type_len(tvb, offset, field_tree, optp->name);
}

static void
dissect_ipcp_iphc_neghdrcomp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_iphc_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_ipcp_opt_iphc_param, tvb, offset + 2, 1,
        ENC_NA);
}

static void
dissect_ipcp_addr_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        tvb_ip_to_str(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_ipcp_opt_ip_address, tvb, offset + 2, 4,
        ENC_BIG_ENDIAN);
}

static void
dissect_ipcp_mobileipv4_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        tvb_ip_to_str(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_ipcp_opt_mobilenodehomeaddr, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
}

static void
dissect_ipcp_pri_dns_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        tvb_ip_to_str(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_ipcp_opt_pri_dns_address, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
}

static void
dissect_ipcp_pri_nbns_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        tvb_ip_to_str(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_ipcp_opt_pri_nbns_address, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
}

static void
dissect_ipcp_sec_dns_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        tvb_ip_to_str(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_ipcp_opt_sec_dns_address, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
}

static void
dissect_ipcp_sec_nbns_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        tvb_ip_to_str(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ipcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_ipcp_opt_sec_nbns_address, tvb,
        offset + 2, 4, ENC_BIG_ENDIAN);
}


static void
dissect_osinlcp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_osinlcp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_osinlcp_opt_length, tvb, offset + 1, 1,
        ENC_NA);
}

static void
dissect_osinlcp_align_npdu_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: Alignment: %u",
        optp->name, tvb_get_guint8(tvb, offset + 2));
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_osinlcp_opt_type_len(tvb, offset, field_tree, optp->name);
    proto_tree_add_item(field_tree, hf_osinlcp_opt_alignment, tvb, offset + 2,
        1, ENC_NA);
}

static void
dissect_pppmuxcp_def_pid_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    pppmux_def_prot_id = tvb_get_ntohs(tvb, offset + 2);
    proto_tree_add_text(tree, tvb, offset + 2, length - 2, "%s: %s (0x%02x)",
        optp->name,
        val_to_str_ext_const(pppmux_def_prot_id, &ppp_vals_ext, "Unknown"),
        pppmux_def_prot_id);
}


static void
dissect_ccp_opt_type_len(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *name)
{
    guint8 type;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_ccp_opt_type, tvb, offset, 1,
        type, "%s (%u)", name, type);
    proto_tree_add_item(tree, hf_ccp_opt_length, tvb, offset + 1, 1, ENC_NA);
}

/* http://tools.ietf.org/html/rfc1962 */
static void dissect_ccp_oui_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf, *ti;
    guint32 oui;
    const gchar *manuf;

    oui = tvb_get_ntoh24(tvb, offset + 2);
    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);
    ti = proto_tree_add_uint_format_value(field_tree, hf_ccp_opt_oui, tvb,
        offset + 2, 3, oui, "%02x:%02x:%02x",
        (oui >> 16) & 0xff, (oui >> 8) & 0xff, oui & 0xff);
    manuf = uint_get_manuf_name_if_known(oui);
    if (manuf)
        proto_item_append_text(ti, "(%s)", manuf);

    proto_tree_add_item(field_tree, hf_ccp_opt_subtype, tvb, offset + 5, 1,
        ENC_NA);
    if (length > 6) {
        proto_tree_add_item(field_tree, hf_ccp_opt_data, tvb, offset + 6,
            length - 6, ENC_NA);
    }
}

/* The following configuration option types are mentioned at
 * http://www.iana.org/assignments/ppp-numbers as referencing RFC1962; however,
 * RFC1962 only mentions Proprietary Compression OUI in section 4.1.  These
 * others are therefore being treated as section 4.2 "Other Compression Types",
 * in terms of how they are dissected:
 *      1)  Predictor type 1
 *      2)  Predictor type 2
 *      3)  Puddle Jumper
 *      16) Hewlett-Packard PPC
 *      20) V.42bis compression
 */
static void dissect_ccp_other_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

    if (length > 2) {
        proto_tree_add_item(field_tree, hf_ccp_opt_data, tvb, offset + 2,
            length - 2, ENC_NA);
    }
}

/* http://tools.ietf.org/html/rfc1974 */
static void
dissect_ccp_stac_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    const char *stac_ascend = "Stac Electronics LZS (Ascend Proprietary version)";
    static const int *check_mode_fields[] = {
        &hf_ccp_opt_cm_reserved,
        &hf_ccp_opt_cm_check_mode,
        NULL
    };

    if (length == 6) {
        tf = proto_tree_add_text(tree, tvb, offset, length, "%s", stac_ascend);
        field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
        dissect_ccp_opt_type_len(tvb, offset, field_tree, stac_ascend);

        /* We don't know how to decode the following 4 octets, since
           there are no public documents that describe their usage. */
        proto_tree_add_item(field_tree, hf_ccp_opt_data, tvb, offset + 2,
            length - 2, ENC_NA);
    } else {
        tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
        field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
        dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

        proto_tree_add_item(field_tree, hf_ccp_opt_history_count, tvb,
            offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(field_tree, tvb, offset + 4, hf_ccp_opt_cm,
            ett_ccp_stac_opt_check_mode, check_mode_fields, ENC_NA);
    }
}

/*
 * Microsoft Point-To-Point Compression (MPPC) and Encryption (MPPE)
 * supported bits.
 */
#define MPPC_SUPPORTED_BITS_C   0x00000001      /* MPPC negotiation */
#define MPPE_SUPPORTED_BITS_D   0x00000010      /* Obsolete */
#define MPPE_SUPPORTED_BITS_L   0x00000020      /* 40-bit encryption */
#define MPPE_SUPPORTED_BITS_S   0x00000040      /* 128-bit encryption */
#define MPPE_SUPPORTED_BITS_M   0x00000080      /* 56-bit encryption */
#define MPPE_SUPPORTED_BITS_H   0x01000000      /* stateless mode */

static const true_false_string ccp_mppe_h_tfs = {
    "Stateless mode ON",
    "Stateless mode OFF"
};
static const true_false_string ccp_mppe_m_tfs = {
    "56-bit encryption ON",
    "56-bit encryption OFF"
};
static const true_false_string ccp_mppe_s_tfs = {
    "128-bit encryption ON",
    "128-bit encryption OFF"
};
static const true_false_string ccp_mppe_l_tfs = {
    "40-bit encryption ON",
    "40-bit encryption OFF"
};
static const true_false_string ccp_mppe_d_tfs = {
    "Obsolete (should NOT be 1)",
    "Obsolete (should ALWAYS be 0)"
};
static const true_false_string ccp_mppe_c_tfs = {
    "Desire to negotiate MPPC",
    "No desire to negotiate MPPC"
};

/* http://tools.ietf.org/html/rfc2118,
 * http://tools.ietf.org/html/rfc3078 */
static void
dissect_ccp_mppe_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    static const int *supported_bits_fields[] = {
        &hf_ccp_opt_supported_bits_h,
        &hf_ccp_opt_supported_bits_m,
        &hf_ccp_opt_supported_bits_s,
        &hf_ccp_opt_supported_bits_l,
        &hf_ccp_opt_supported_bits_d,
        &hf_ccp_opt_supported_bits_c,
        NULL
    };

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

    proto_tree_add_bitmask(field_tree, tvb, offset + 2,
        hf_ccp_opt_supported_bits, ett_ccp_mppe_opt_supp_bits,
        supported_bits_fields, ENC_BIG_ENDIAN);
}

/* http://tools.ietf.org/html/rfc1993 */
static void dissect_ccp_gfza_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *field_tree;
    proto_item *tf;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

    proto_tree_add_item(field_tree, hf_ccp_opt_history, tvb, offset + 2, 1,
        ENC_NA);

    if (length > 3) {
        proto_tree_add_item(field_tree, hf_ccp_opt_version, tvb, offset + 3,
            length - 3, ENC_NA);
    }
}

/* http://tools.ietf.org/html/rfc1977 */
static void
dissect_ccp_bsdcomp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    static const int *vd_fields[] = {
        &hf_ccp_opt_vd_vers,
        &hf_ccp_opt_vd_dict
    };

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

    proto_tree_add_bitmask(field_tree, tvb, offset + 2, hf_ccp_opt_vd,
        *optp->subtree_index, vd_fields, ENC_BIG_ENDIAN);
}

/* http://tools.ietf.org/html/rfc1967 */
static void
dissect_ccp_lzsdcp_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

    proto_tree_add_item(field_tree, hf_ccp_opt_history_count, tvb,
        offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ccp_opt_check_mode, tvb, offset + 4, 1,
        ENC_NA);
    proto_tree_add_item(field_tree, hf_ccp_opt_process_mode, tvb, offset + 5,
        1, ENC_NA);
}

/* http://tools.ietf.org/html/rfc1975 */
static void
dissect_ccp_mvrca_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

    proto_tree_add_item(field_tree, hf_ccp_opt_fe, tvb, offset + 2, 1, ENC_NA);
    proto_tree_add_item(field_tree, hf_ccp_opt_p, tvb, offset + 2, 1, ENC_NA);
    proto_tree_add_item(field_tree, hf_ccp_opt_History, tvb, offset + 2, 1,
        ENC_NA);
    proto_tree_add_item(field_tree, hf_ccp_opt_contexts, tvb, offset + 3, 1,
        ENC_NA);
}

/* http://tools.ietf.org/html/rfc1976 */
static void
dissect_ccp_dce_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

    proto_tree_add_item(field_tree, hf_ccp_opt_mode, tvb, offset + 2, 1,
        ENC_NA);
}

static const value_string deflate_method_vals[] = {
    {8, "zlib compression"},
    {0, NULL}
};

static const value_string deflate_chk_vals[] = {
    {0, "sequence number check method"},
    {0, NULL}
};

/* http://tools.ietf.org/html/rfc1979 */
static void
dissect_ccp_deflate_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    guint8 window;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

    window = tvb_get_guint8(tvb, offset + 2);
    proto_tree_add_uint_format_value(field_tree, hf_ccp_opt_window, tvb,
        offset + 2, 1, window, "%u", 1 << (hi_nibble(window) + 8));
    proto_tree_add_item(field_tree, hf_ccp_opt_method, tvb, offset + 2, 1,
        ENC_NA);
    proto_tree_add_item(field_tree, hf_ccp_opt_mbz, tvb, offset + 3, 1,
        ENC_NA);
    proto_tree_add_item(field_tree, hf_ccp_opt_chk, tvb, offset + 3, 1,
        ENC_NA);
}

static const range_string v44lzjh_mode_dict_rvals[] = {
    {0, 0, "Datagram Mode (one dictionary and no history)"},
    {1, 1, "Multi-Datagram Mode (one dictionary with history)"},
    {2, G_MAXUINT16, "Individual Link Mode" /* "(and proposed number of
                                                 dictionaries each with a
                                                 corresponding history" */},
    {0, 0, NULL}
};

/* http://www.watersprings.org/pub/id/draft-heath-ppp-v44-01.txt */
static void dissect_ccp_v44lzjh_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);
    dissect_ccp_opt_type_len(tvb, offset, field_tree, optp->name);

    proto_tree_add_item(field_tree, hf_ccp_opt_mode_dictcount, tvb, offset + 2,
        2, ENC_BIG_ENDIAN);

    if (length > 4) {
        proto_tree_add_item(field_tree, hf_ccp_opt_dict_size, tvb, offset + 4,
            2, ENC_BIG_ENDIAN);
        if (length > 6) {
            proto_tree_add_item(field_tree, hf_ccp_opt_history_length, tvb,
                offset + 6, 2, ENC_BIG_ENDIAN);
        }
    }
}


static void
dissect_cbcp_no_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
}

static void
dissect_cbcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    proto_tree *addr_tree;
    guint8      addr_type;
    guint       addr_len;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_text(field_tree, tvb, offset + 2, 1, "Callback delay: %u",
        tvb_get_guint8(tvb, offset + 2));
    offset += 3;
    length -= 3;

    while (length > 0) {
        proto_tree_add_text(field_tree, tvb, offset, length,
            "Callback Address");
        addr_type = tvb_get_guint8(tvb, offset);
        addr_tree = proto_item_add_subtree(tf, ett_cbcp_callback_opt_addr);
        proto_tree_add_text(addr_tree, tvb, offset, 1, "Address Type: %s (%u)",
            ((addr_type == 1) ? "PSTN/ISDN" : "Other"), addr_type);
        offset++;
        length--;
        addr_len = tvb_strsize(tvb, offset);
        if (addr_len > length) {
            proto_tree_add_text(addr_tree, tvb, offset, length,
                "Address: (runs past end of option)");
            break;
        }
        proto_tree_add_text(addr_tree, tvb, offset, addr_len, "Address: %s",
            tvb_format_text(tvb, offset, addr_len - 1));
        offset += addr_len;
        length -= addr_len;
    }
}

static void
dissect_bacp_favored_peer_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_text(field_tree, tvb, offset + 2, 4, "Magic number: 0x%08x",
        tvb_get_ntohl(tvb, offset + 2));
}

static void
dissect_bap_link_type_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    guint8      link_type;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    proto_tree_add_text(field_tree, tvb, offset + 2, 2, "Link Speed: %u kbps",
        tvb_get_ntohs(tvb, offset + 2));
    link_type = tvb_get_guint8(tvb, offset + 4);
    proto_tree_add_text(field_tree, tvb, offset + 4, 1, "Link Type: %s (%u)",
        val_to_str_const(link_type, bap_link_type_vals, "Unknown"), link_type);
}

static void
dissect_bap_phone_delta_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    proto_item *ti;
    proto_tree *suboption_tree;
    guint8      subopt_type;
    guint8      subopt_len;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    offset += 2;
    length -= 2;

    while (length > 0) {
        subopt_type = tvb_get_guint8(tvb, offset);
        subopt_len = tvb_get_guint8(tvb, offset + 1);
        ti = proto_tree_add_text(field_tree, tvb, offset, subopt_len,
            "Sub-Option (%u byte%s)", subopt_len,
            plurality(subopt_len, "", "s"));
        suboption_tree = proto_item_add_subtree(ti,
            ett_bap_phone_delta_subopt);

        proto_tree_add_text(suboption_tree, tvb, offset, 1,
            "Sub-Option Type: %s (%u)",  val_to_str_const(subopt_type,
                bap_phone_delta_subopt_vals, "Unknown"), subopt_type);

        if (subopt_len < 2) {
            proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
                "Sub-Option Length: %u (invalid, must be >= 2)", subopt_len);
            return;
        }
        if (subopt_len > length) {
            proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
                "Sub-Option Length: %u (invalid, must be <= length remaining "
                "in option %u)", subopt_len, length);
            return;
        }

        proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
            "Sub-Option Length: %u", subopt_len);

        switch (subopt_type) {
        case BAP_PHONE_DELTA_SUBOPT_UNIQ_DIGIT:
            if (subopt_len == 3) {
                proto_tree_add_text(suboption_tree, tvb, offset + 2, 1,
                    "Unique Digit: %u", tvb_get_guint8(tvb, offset + 2));
            } else {
                proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
                    "Invalid suboption length: %u (must be == 3)", subopt_len);
            }
            break;
        case BAP_PHONE_DELTA_SUBOPT_SUBSC_NUM:
            if (subopt_len > 2) {
                proto_tree_add_text(suboption_tree, tvb, offset + 2,
                    subopt_len - 2, "Subscriber Number: %s",
                    tvb_format_text(tvb, offset + 2, subopt_len - 2));
            } else {
                proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
                    "Invalid suboption length: %u (must be > 2)", subopt_len);
            }
            break;
        case BAP_PHONE_DELTA_SUBOPT_PHONENUM_SUBADDR:
            if (subopt_len > 2) {
                proto_tree_add_text(suboption_tree, tvb, offset + 2,
                    subopt_len - 2, "Phone Number Sub Address: %s",
                    tvb_format_text(tvb, offset + 2, subopt_len - 2));
            } else {
                proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
                    "Invalid suboption length: %u (must be > 2)", subopt_len);
            }
            break;
        default:
            if (subopt_len > 2) {
                proto_tree_add_text(suboption_tree, tvb, offset + 2,
                    subopt_len - 2, "Unknown");
            } else {
                proto_tree_add_text(suboption_tree, tvb, offset + 1, 1,
                    "Invalid suboption length: %u (must be > 2)", subopt_len);
            }
            break;
        }
        offset += subopt_len;
        length -= subopt_len;
    }
}

static void
dissect_bap_reason_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    if (length > 2) {
        proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
            tvb_format_text(tvb, offset + 2, length - 2));
    }
}

static void
dissect_bap_link_disc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_text(tree, tvb, offset, length, "%s: 0x%04x", optp->name,
        tvb_get_ntohs(tvb, offset + 2));
}

static void
dissect_bap_call_status_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;
    guint8      status, action;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s", optp->name);
    field_tree = proto_item_add_subtree(tf, *optp->subtree_index);

    status = tvb_get_guint8(tvb, offset + 2);
    proto_tree_add_text(field_tree, tvb, offset + 2, 1, "Status: %s (0x%02x)",
        val_to_str_ext_const(status, &q931_cause_code_vals_ext, "Unknown"),
        status);

    action = tvb_get_guint8(tvb, offset + 3);
    proto_tree_add_text(field_tree, tvb, offset + 3, 1, "Action: %s (0x%02x)",
        val_to_str_const(action, bap_call_status_opt_action_vals, "Unknown"),
        action);
}

static void
dissect_vsncp_pdnid_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    guint8 PDNID;

    PDNID = tvb_get_guint8(tvb, offset + 2);
    proto_tree_add_text(tree, tvb, offset, length, "%s: 0x%02x", optp->name,
        PDNID);
}

static void
dissect_vsncp_attachtype_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    static const value_string attach_vals[] = {
        {1, "Initial Attach"},
        {3, "Handover Attach"},
        {0, NULL}
    };
    guint8 attach;

    if (tree) {
        attach = tvb_get_guint8(tvb, offset + 2);
        proto_tree_add_text(tree, tvb, offset, length, "%s: %s (0x%02x)",
            optp->name, val_to_str_const(attach , attach_vals, "Unknown"),
            attach);
    }
}

static void
dissect_vsncp_pdntype_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    static const value_string pdntype_vals[] = {
        {1, "IPv4"},
        {2, "IPv6"},
        {3, "IPv6/IPv4"},
        {0, NULL}
    };
    guint8 pdntype;

    if (tree) {
        pdntype = tvb_get_guint8(tvb, offset + 2);
        proto_tree_add_text(tree, tvb, offset, length, "%s: %s (0x%02x)",
            optp->name, val_to_str_const(pdntype, pdntype_vals, "Unknown"),
            pdntype);
    }
}

static void
dissect_vsncp_errorcode_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    static const value_string errorcode_vals[] = {
        {0,  "General Eror"},
        {1,  "Unauthorized APN"},
        {2,  "PDN Limit Exceeded"},
        {3,  "NO PG-W Available"},
        {4,  "P-GW Unreachable"},
        {5,  "P-GW Reject"},
        {6,  "Insufficient Parameters"},
        {7,  "Resource Unavailable"},
        {8,  "Admin Prohibited"},
        {9,  "PDN-ID Already in Use"},
        {10, "Subscription Limitation"},
        {11, "PDN connection already exists for APN"},
        {0,  NULL}
    };
    guint8 pdntype;

    if (tree) {
        pdntype = tvb_get_guint8(tvb, offset + 2);
        proto_tree_add_text(tree, tvb, offset, length, "%s: %s (0x%02x)",
            optp->name, val_to_str_const(pdntype, errorcode_vals, "Unknown"),
            pdntype);
    }
}

static void
dissect_vsncp_pdnaddress_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    guint8 pdnaddtype;
    static const value_string pdntype_vals[] = {
        {0, "Initial Request by UE"},
        {1, "IPv4 Address"},
        {2, "IPv6 Address"},
        {3, "IPv6/IPv4 Address"},
        {0, NULL}
    };
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: (%d byte%s)",
        optp->name, length, plurality(length, "", "s"));
    field_tree = proto_item_add_subtree(tf, ett_lcp_options);

    pdnaddtype = tvb_get_guint8(tvb, offset + 2);
    proto_tree_add_text(field_tree, tvb, offset + 2, 1,
        "PDN Type (%s): 0x%02x",
        val_to_str_const(pdnaddtype, pdntype_vals, "Unknown"), pdnaddtype);

    switch (pdnaddtype) {
    case 1:
        proto_tree_add_text(field_tree, tvb, offset + 3, length - 3, "%s: %s",
            val_to_str_const(pdnaddtype, pdntype_vals, "Unknown"),
            tvb_ip_to_str(tvb, offset + 3));
        break;

    case 2:
    {
        struct e_in6_addr *ad = ep_alloc0(sizeof (struct e_in6_addr));

        tvb_memcpy(tvb, &ad->bytes[8], offset + 3, 8);
        proto_tree_add_text(field_tree, tvb, offset + 3, length - 3, "%s: %s",
            val_to_str_const(pdnaddtype, pdntype_vals, "Unknown"),
            ip6_to_str(ad));
        break;
    }

    case 3:
    {
        struct e_in6_addr *ad = ep_alloc0(sizeof (struct e_in6_addr));

        tvb_memcpy(tvb, &ad->bytes[8], offset + 3, 8);
        proto_tree_add_text(field_tree, tvb, offset + 3, length - 3, "%s: %s",
            val_to_str_const(pdnaddtype, pdntype_vals, "Unknown"),
            ip6_to_str(ad));
        proto_tree_add_text(field_tree, tvb, offset + 11, length - 11,
            "%s: %s", val_to_str_const(pdnaddtype, pdntype_vals, "Unknown"),
            tvb_ip_to_str(tvb, offset + 11));
        break;
    }

    default:
        break;
    }
}

static void
dissect_vsncp_ipv4address_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
        tvb_ip_to_str(tvb, offset + 2));
}

static void
dissect_vsncp_apname_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: (%d byte%s)",
        optp->name, length, plurality(length, "", "s"));
    field_tree = proto_item_add_subtree(tf, ett_lcp_options);

    if (length > 2) {
        guint8 i = 0;
        guint8 j = 1;
        guint8 lengthofapn;
        int off = offset + 2;

        while (i < (length - 2)) {
            lengthofapn = tvb_get_guint8(tvb, off++);
            proto_tree_add_text(field_tree, tvb, off, lengthofapn,
                "Label%d (%d byte%s): %s", j++, lengthofapn,
                plurality(lengthofapn, "", "s"),
                tvb_format_text(tvb, off, lengthofapn));
            off += lengthofapn;
            i += lengthofapn + 1;
        }
    }
}

static void
dissect_vsncp_addressalloc_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
    int offset, guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    static const value_string alloc_vals[] = {
        {0,   "Null Value (Attach or Handover)"},
        {18,  "New PDN type due to network preference"},
        {255, "Success"},
        {0,   NULL}
    };

    guint8 alloc;

    if (tree) {
        alloc = tvb_get_guint8(tvb, offset + 2);
        proto_tree_add_text(tree, tvb, offset, length, "%s: %s (0x%02x)",
            optp->name, val_to_str_const(alloc, alloc_vals, "Unknown"), alloc);
    }
}

static void
dissect_vsncp_pco_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    static const value_string pco_vals[] = {
        {0x8021, "IPCP (DNS Address Request)"},
        {0x0001, "P-CSCF Address Request (IPv6)"},
        {0x0003, "DNS Server Address (IPv6)"},
        {0x000A, "IP address allocation via NAS signalling"},
        {0,      NULL}
    };
    int off = offset + 3;
    guint8  i = 0;
    guint16 pcotype;
    guint8 len;
    proto_item *tf;
    proto_tree *field_tree;

    tf = proto_tree_add_text(tree, tvb, offset, length, "%s: (%d byte%s)",
        optp->name, length, plurality(length, "", "s"));
    field_tree = proto_item_add_subtree(tf, ett_lcp_options);

    while (i < (length - 3)) {
        pcotype = tvb_get_ntohs(tvb, off);
        len = tvb_get_guint8(tvb, (off + 2));
        proto_tree_add_text(field_tree, tvb, off, 2, "Protocol: %s (0x%02x)",
            val_to_str_const(pcotype, pco_vals, "Unknown"), pcotype);
        proto_tree_add_text(field_tree, tvb, off + 2, 1, "Length:(0x%02x)",
            len);
        if (len > 0) {
            proto_tree_add_text(field_tree, tvb, off + 3, len,
                "Data (%d byte%s)", len, plurality(len, "", "s"));
        }

        off += 3 + len;
        i += 3 + len;
    }
}

static void
dissect_cp(tvbuff_t *tvb, int proto_id, int proto_subtree_index,
    const value_string *proto_vals, int options_subtree_index,
    const ip_tcp_opt *opts, int nopts, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *fh_tree = NULL;
    guint8 code;
    int length, offset;

    code   = tvb_get_guint8(tvb, 0);
    length = tvb_get_ntohs(tvb, 2);

    col_set_str(pinfo->cinfo, COL_PROTOCOL,
        proto_get_protocol_short_name(find_protocol_by_id(proto_id)));
    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str_const(code, proto_vals, "Unknown"));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_id, tvb, 0, length, ENC_NA);
        fh_tree = proto_item_add_subtree(ti, proto_subtree_index);
        proto_tree_add_uint_format_value(fh_tree, hf_ppp_code, tvb, 0, 1, code,
            "%s (%u)", val_to_str_const(code, proto_vals, "Unknown"), code);
        proto_tree_add_item(fh_tree, hf_ppp_identifier, tvb, 1, 1, ENC_NA);
        proto_tree_add_item(fh_tree, hf_ppp_length, tvb, 2, 2, ENC_BIG_ENDIAN);
    }
    offset = 4;
    length -= 4;

    switch (code) {
    case VNDRSPCFC:
        if (tree) {
            guint32 oui;
            const gchar *manuf;

            proto_tree_add_item(fh_tree, hf_ppp_magic_number, tvb, offset, 4,
                ENC_BIG_ENDIAN);
            oui = tvb_get_ntoh24(tvb, offset + 4);
            ti = proto_tree_add_uint_format_value(fh_tree, hf_ppp_oui, tvb,
                offset + 4, 3, oui, "%02x:%02x:%02x", (oui >> 16) & 0xff,
                (oui >> 8) & 0xff, oui & 0xff);
            manuf = uint_get_manuf_name_if_known(oui);
            if (manuf)
                proto_item_append_text(ti, "(%s)", manuf);
            proto_tree_add_item(fh_tree, hf_ppp_kind, tvb, offset + 7, 1,
                ENC_NA);
            if (length > 8) {
                proto_tree_add_item(fh_tree, hf_ppp_data, tvb, offset + 8,
                    length - 8, ENC_NA);
            }
        }
        break;

    case CONFREQ:
    case CONFACK:
    case CONFNAK:
    case CONFREJ:
        if (length > 0) {
            proto_item *tf;
            proto_tree *field_tree;

            tf = proto_tree_add_text(fh_tree, tvb, offset, length,
                "Options: (%d byte%s)", length, plurality(length, "", "s"));
            field_tree = proto_item_add_subtree(tf, options_subtree_index);
            dissect_ip_tcp_options(tvb, offset, length, opts, nopts, -1, pinfo,
                field_tree, NULL, NULL);
        }
        break;

    case CODEREJ:
        if (tree && (length > 0)) {
            /* TODO: Decode the rejected packet here ... but wait until we have
             * a valid capture file with a CODEREJ, since the only capture file
             * with CODEREJ packets in it that I know of is pppoe.dump.gz from
             * the menagerie, and that file appears to have malformed CODEREJ
             * packets as they don't include the Code, Identifier or Length
             * fields so it's impossible to do the decode. */
            proto_tree_add_bytes_format(fh_tree, hf_ppp_data, tvb, offset,
                length, NULL, "Rejected Packet (%d byte%s): %s", length,
                plurality(length, "", "s"),
                tvb_bytes_to_str(tvb, offset, length));
        }
        break;

    case PROTREJ:       /* LCP only: RFC 1661 */
        if (tree) {
            proto_tree_add_item(fh_tree, hf_lcp_rej_proto, tvb, offset, 2,
                ENC_BIG_ENDIAN);
        }
        if (length > 2) {
            gboolean save_in_error_pkt;
            tvbuff_t *next_tvb;
            guint16 protocol;

            protocol = tvb_get_ntohs(tvb, offset);
            offset += 2;
            length -= 2;

            /*
             * Save the current value of the "we're inside an error packet"
             * flag, and set that flag; subdissectors may treat packets that
             * are the payload of error packets differently from "real"
             * packets.
             */
            save_in_error_pkt = pinfo->flags.in_error_pkt;
            pinfo->flags.in_error_pkt = TRUE;

            /* Decode the rejected packet. */
            next_tvb = tvb_new_subset(tvb, offset, length, length);
            if (!dissector_try_uint(ppp_subdissector_table, protocol, next_tvb,
                pinfo, fh_tree)) {
                call_dissector(data_handle, next_tvb, pinfo, fh_tree);
            }

            /* Restore the "we're inside an error packet" flag. */
            pinfo->flags.in_error_pkt = save_in_error_pkt;
        }
        break;

    case ECHOREQ: /* All 3 are LCP only: RFC 1661 */
    case ECHOREP:
    case DISCREQ:
        if (tree) {
            proto_tree_add_item(fh_tree, hf_lcp_magic_number, tvb, offset, 4,
                ENC_BIG_ENDIAN);
            if (length > 4) {
                proto_tree_add_item(fh_tree, hf_lcp_data, tvb, offset + 4,
                    length - 4, ENC_NA);
            }
        }
        break;

    case IDENT:         /* LCP only: RFC 1570 */
        if (tree) {
            proto_tree_add_item(fh_tree, hf_lcp_magic_number, tvb, offset, 4,
                ENC_BIG_ENDIAN);
            if (length > 4) {
                proto_tree_add_item(fh_tree, hf_lcp_message, tvb, offset + 4,
                    length - 4, ENC_NA);
            }
        }
        break;

    case TIMEREMAIN:    /* LCP only: RFC 1570 */
        if (tree) {
            guint32 secs_remaining;

            proto_tree_add_item(fh_tree, hf_lcp_magic_number, tvb, offset, 4,
                ENC_BIG_ENDIAN);
            secs_remaining = tvb_get_ntohl(tvb, offset + 4);
            proto_tree_add_uint_format_value(fh_tree, hf_lcp_secs_remaining,
                tvb, offset + 4, 4, secs_remaining, "%u %s", secs_remaining,
                (secs_remaining == 0xffffffff) ? "(forever)" : "seconds");
            if (length > 8) {
                proto_tree_add_item(fh_tree, hf_lcp_message, tvb, offset + 8,
                    length - 8, ENC_NA);
            }
        }
        break;

    case TERMREQ:
    case TERMACK:
    case RESETREQ:  /* RESETREQ and RESETACK are CCP only: RFC 1962 */
    case RESETACK:
    default:
        if (tree && (length > 0)) {
            proto_tree_add_item(fh_tree, hf_ppp_data, tvb, offset, length,
                ENC_NA);
        }
        break;
    }
}

/* Protocol field compression */
#define PFC_BIT 0x01

static void
dissect_ppp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_tree *fh_tree, proto_item *ti, int proto_offset)
{
    guint16   ppp_prot;
    int       proto_len;
    tvbuff_t *next_tvb;

    /* Make direction information filterable */
    if (tree &&
        (pinfo->p2p_dir == P2P_DIR_RECV || pinfo->p2p_dir == P2P_DIR_SENT)) {
        proto_item *direction_ti = proto_tree_add_uint(tree, hf_ppp_direction,
            tvb, 0, 0, pinfo->p2p_dir);
        PROTO_ITEM_SET_GENERATED(direction_ti);
    }

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

    if (tree) {
        proto_tree_add_uint(fh_tree, hf_ppp_protocol, tvb, 0, proto_len,
            ppp_prot);
    }

    next_tvb = tvb_new_subset_remaining(tvb, proto_len);

    /* do lookup with the subdissector table */
    if (!dissector_try_uint(ppp_subdissector_table, ppp_prot, next_tvb, pinfo,
        tree)) {
        col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", ppp_prot);
        col_add_fstr(pinfo->cinfo, COL_INFO, "PPP %s (0x%04x)",
            val_to_str_ext_const(ppp_prot, &ppp_vals_ext, "Unknown"),
            ppp_prot);
        call_dissector(data_handle,next_tvb, pinfo, tree);
    }
}

static void
dissect_lcp_options(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_ip_tcp_options(tvb, 0, tvb_reported_length(tvb), lcp_opts,
        N_LCP_OPTS, -1, pinfo, tree, NULL, NULL);
}

/*
 * RFC's 1661, 2153 and 1570.
 */
static void
dissect_lcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_cp(tvb, proto_lcp, ett_lcp, lcp_vals, ett_lcp_options, lcp_opts,
        N_LCP_OPTS, pinfo, tree);
}

static void
dissect_vsncp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *fh_tree = NULL;
    proto_item *tf;
    proto_tree *field_tree;
    guint8 code;
    guint8 id;
    int length, offset;
    int OUI;

    static const value_string OUI_vals[] = {
        {0xcf0002, "3GPP2 Unique Organization Number"},
        {0,        NULL}
    };

    code = tvb_get_guint8(tvb, 0);
    id = tvb_get_guint8(tvb, 1);
    length = tvb_get_ntohs(tvb, 2);
    OUI = tvb_get_ntoh24(tvb, 4);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VSNCP");
    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str_const(code, cp_vals, "Unknown"));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_vsncp, tvb, 0, length, ENC_NA);
        fh_tree = proto_item_add_subtree(ti, ett_vsncp);
        proto_tree_add_text(fh_tree, tvb, 0, 1, "Code: %s (0x%02x)",
            val_to_str_const(code, cp_vals, "Unknown"), code);
        proto_tree_add_text(fh_tree, tvb, 1, 1, "Identifier: 0x%02x", id);
        proto_tree_add_text(fh_tree, tvb, 2, 2, "Length: %u", length);
        proto_tree_add_text(fh_tree, tvb, 4, 3, "OUI: %s (0x%02x)",
            val_to_str_const(OUI, OUI_vals, "Unknown"), OUI);
    }
    offset = 7;
    length -= 7;

    switch (code) {
    case CONFREQ:
    case CONFACK:
    case CONFNAK:
    case CONFREJ:
    case TERMREQ:
    case TERMACK:
        if (length > 0) {
            tf = proto_tree_add_text(fh_tree, tvb, offset, length,
                                     "Options: (%d byte%s)", length,
                                     plurality(length, "", "s"));
            field_tree = proto_item_add_subtree(tf, ett_vsncp_options);
            dissect_ip_tcp_options(tvb, offset, length, vsncp_opts,
                                   N_VSNCP_OPTS, -1, pinfo, field_tree, NULL, NULL);
        }
        break;

    default:
        /* TODO? */
        break;
    }
}

static void
dissect_vsnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *vsnp_item = NULL;
    proto_tree *vsnp_tree = NULL;
    guint32     offset    = 0;
    tvbuff_t *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VSNP");

    if (tree) {
        vsnp_item = proto_tree_add_item(tree, proto_vsnp, tvb, 0, -1, ENC_NA);
        vsnp_tree = proto_item_add_subtree(vsnp_item, ett_vsnp);
        proto_tree_add_item(vsnp_tree, hf_vsnp_pdnid, tvb, offset, 1,
            ENC_BIG_ENDIAN);
    }

    next_tvb = tvb_new_subset_remaining(tvb, 1);
    if (!dissector_try_uint(ppp_subdissector_table, PPP_IP, next_tvb, pinfo,
        tree)) {
        col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", PPP_IP);
        col_add_fstr(pinfo->cinfo, COL_INFO, "PPP %s (0x%04x)",
            val_to_str_ext_const(PPP_IP, &ppp_vals_ext, "Unknown"), PPP_IP);
        call_dissector(data_handle, next_tvb, pinfo, tree);
    }
}

/*
 * RFC 1332.
 */
static void
dissect_ipcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_cp(tvb, proto_ipcp, ett_ipcp, cp_vals, ett_ipcp_options, ipcp_opts,
        N_IPCP_OPTS, pinfo, tree);
}

/*
 * RFC 3518
 */
#define BCP_FCS_PRESENT         0x80
#define BCP_ZEROPAD             0x20
#define BCP_IS_BCONTROL         0x10
#define BCP_PADS_MASK           0x0f

#define BCP_MACT_ETHERNET       1
#define BCP_MACT_802_4          2
#define BCP_MACT_802_5_NONCANON 3
#define BCP_MACT_FDDI_NONCANON  4
#define BCP_MACT_802_5_CANON    11
#define BCP_MACT_FDDI_CANON     12

static const value_string bcp_mac_type_vals[] = {
    {BCP_MACT_ETHERNET,       "IEEE 802.3/Ethernet"},
    {BCP_MACT_802_4,          "IEEE 802.4"},
    {BCP_MACT_802_5_NONCANON, "IEEE 802.5, non-canonical addresses"},
    {BCP_MACT_FDDI_NONCANON,  "FDDI, non-canonical addresses"},
    {BCP_MACT_802_5_CANON,    "IEEE 802.5, canonical addresses"},
    {BCP_MACT_FDDI_CANON,     "FDDI, canonical addresses"},
    {0,                       NULL}
};

static void
dissect_bcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL, *flags_item;
    proto_tree *bcp_tree = NULL, *flags_tree;
    int offset = 0;
    guint8 flags;
    guint8 mac_type;
    gint captured_length, reported_length, pad_length;
    tvbuff_t *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP BCP");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        ti = proto_tree_add_item(tree, proto_bcp, tvb, 0, -1, ENC_NA);
        bcp_tree = proto_item_add_subtree(ti, ett_bcp);
    }

    flags = tvb_get_guint8(tvb, offset);
    if (flags & BCP_IS_BCONTROL) {
        col_set_str(pinfo->cinfo, COL_INFO, "Bridge control");
    }
    if (tree) {
        flags_item = proto_tree_add_uint(bcp_tree, hf_bcp_flags, tvb, offset,
            1, flags);
        flags_tree = proto_item_add_subtree(flags_item, ett_bcp_flags);
        proto_tree_add_boolean(flags_tree, hf_bcp_fcs_present, tvb, offset,
            1, flags);
        proto_tree_add_boolean(flags_tree, hf_bcp_zeropad, tvb, offset, 1,
            flags);
        proto_tree_add_boolean(flags_tree, hf_bcp_bcontrol, tvb, offset, 1,
            flags);
        proto_tree_add_uint(flags_tree, hf_bcp_pads, tvb, offset, 1, flags);
    }
    offset++;

    mac_type = tvb_get_guint8(tvb, offset);
    if (!(flags & BCP_IS_BCONTROL)) {
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(mac_type, bcp_mac_type_vals,
                "Unknown MAC type %u"));
        }
    }
    if (tree) {
        proto_tree_add_uint(bcp_tree, hf_bcp_mac_type, tvb, offset, 1,
            mac_type);
    }
    offset++;

    switch (mac_type) {

    case BCP_MACT_802_4:
    case BCP_MACT_802_5_NONCANON:
    case BCP_MACT_FDDI_NONCANON:
    case BCP_MACT_802_5_CANON:
    case BCP_MACT_FDDI_CANON:
        if (tree)
            proto_tree_add_text(bcp_tree, tvb, offset, 1, "Pad");
        offset++;
        break;

    default:
        /* TODO? */
        break;
    }

    if (!(flags & BCP_IS_BCONTROL)) {
        captured_length = tvb_length_remaining(tvb, offset);
        reported_length = tvb_reported_length_remaining(tvb, offset);
        pad_length = flags & BCP_PADS_MASK;
        if (reported_length >= pad_length) {
            reported_length -= pad_length;
            if (captured_length > reported_length)
                captured_length = reported_length;
            next_tvb = tvb_new_subset(tvb, offset, captured_length,
                reported_length);
            switch (mac_type) {

            case BCP_MACT_ETHERNET:
                if (flags & BCP_FCS_PRESENT) {
                    call_dissector(eth_withfcs_handle, next_tvb, pinfo, tree);
                } else {
                    call_dissector(eth_withoutfcs_handle, next_tvb, pinfo,
                        tree);
                }
                break;

            case BCP_MACT_802_4:
            case BCP_MACT_802_5_NONCANON:
            case BCP_MACT_FDDI_NONCANON:
            case BCP_MACT_802_5_CANON:
            case BCP_MACT_FDDI_CANON:
                break;

            default:
                call_dissector(data_handle, next_tvb, pinfo, tree);
                break;
            }
        }
    }
}

/*
 * RFC 1377.
 */
static void
dissect_osinlcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_cp(tvb, proto_osinlcp, ett_osinlcp, cp_vals, ett_osinlcp_options,
        osinlcp_opts, N_OSINLCP_OPTS, pinfo, tree);
}

/*
 * RFC 1962.
 */
static void
dissect_ccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_cp(tvb, proto_ccp, ett_ccp, ccp_vals, ett_ccp_options, ccp_opts,
        N_CCP_OPTS, pinfo, tree);
}

/*
 * Callback Control Protocol - see
 *
 * http://www.linet.gr.jp/~manabe/PPxP/doc/Standards/draft-gidwani-ppp-callback-cp-00.txt
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
    dissect_cp(tvb, proto_bacp, ett_bacp, cp_vals, ett_bacp_options, bacp_opts,
        N_BACP_OPTS, pinfo, tree);
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

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP BAP");
    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str_const(type, bap_vals, "Unknown"));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_bap, tvb, 0, length, ENC_NA);
        fh_tree = proto_item_add_subtree(ti, ett_bap_options);
        proto_tree_add_text(fh_tree, tvb, 0, 1, "Type: %s (0x%02x)",
            val_to_str_const(type, bap_vals, "Unknown"), type);
        proto_tree_add_text(fh_tree, tvb, 1, 1, "Identifier: 0x%02x", id);
        proto_tree_add_text(fh_tree, tvb, 2, 2, "Length: %u", length);
    }
    offset = 4;
    length -= 4;

    if (type == BAP_CRES || type == BAP_CBRES ||
        type == BAP_LDQRES || type == BAP_CSRES) {
        resp_code = tvb_get_guint8(tvb, offset);
        proto_tree_add_text(fh_tree, tvb, offset, 1,
            "Response Code: %s (0x%02x)",
            val_to_str_const(resp_code, bap_resp_code_vals, "Unknown"),
            resp_code);
        offset++;
        length--;
    }

    if (length > 0) {
        tf = proto_tree_add_text(fh_tree, tvb, offset, length,
                                 "Data (%d byte%s)", length, plurality(length, "", "s"));
        field_tree = proto_item_add_subtree(tf, ett_bap_options);
        dissect_ip_tcp_options(tvb, offset, length, bap_opts, N_BAP_OPTS,
                               -1, pinfo, field_tree, NULL, NULL);
    }
}

#if 0 /* TODO? */
static void
dissect_comp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *comp_data_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP Comp");
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed data");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_comp_data, tvb, 0, -1, ENC_NA);
        comp_data_tree = proto_item_add_subtree(ti, ett_comp_data);
    }
}
#else
static void
dissect_comp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP Comp");
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed data");

    if (tree)
        proto_tree_add_item(tree, proto_comp_data, tvb, 0, -1, ENC_NA);
}
#endif

/*
 * RFC 3153 (both PPPMuxCP and PPPMux).
 */
static void
dissect_pppmuxcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_cp(tvb, proto_pppmuxcp, ett_pppmuxcp, pppmuxcp_vals,
        ett_pppmuxcp_options, pppmuxcp_opts, N_PPPMUXCP_OPTS,pinfo, tree);
}

#define PPPMUX_FLAGS_MASK          0xc0
#define PPPMUX_PFF_BIT_SET         0x80
#define PPPMUX_LXT_BIT_SET         0x40

static void
dissect_pppmux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree     *mux_tree, *hdr_tree, *sub_tree, *flag_tree;
    proto_tree     *info_tree;
    proto_item     *ti           = NULL, *sub_ti = NULL;
    guint8          flags, byte;
    guint16         length;
    static guint16  pid;
    tvbuff_t       *next_tvb;
    int             offset       = 0, length_remaining;
    int             length_field = 0, pid_field = 0, hdr_length = 0;

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "PPP PPPMux");
    col_set_str(pinfo->cinfo, COL_INFO, "PPP Multiplexing");

    length_remaining = tvb_reported_length(tvb);

    ti = proto_tree_add_item(tree, proto_pppmux, tvb, 0, -1, ENC_NA);
    mux_tree = proto_item_add_subtree(ti, ett_pppmux);

    while (length_remaining > 0) {
        flags = tvb_get_guint8(tvb,offset) & PPPMUX_FLAGS_MASK;

        if (flags & PPPMUX_LXT_BIT_SET) {
            length = tvb_get_ntohs(tvb,offset) & 0x3fff;
            length_field = 2;
        } else {
            length = tvb_get_guint8(tvb,offset) & 0x3f;
            length_field = 1;
        }

        if (flags & PPPMUX_PFF_BIT_SET) {
            byte = tvb_get_guint8(tvb,offset + length_field);
            if (byte & PFC_BIT) {             /* Compressed PID field */
                pid = byte;
                pid_field = 1;
            } else {                  /* PID field is 2 bytes */
                pid = tvb_get_ntohs(tvb,offset + length_field);
                pid_field = 2;
            }
        } else {
            pid_field = 0;   /* PID field is 0 bytes */
            if (!pid) {       /* No Last PID, hence use the default */
                if (pppmux_def_prot_id)
                    pid = pppmux_def_prot_id;
            }
        }

        hdr_length = length_field + pid_field;

        ti = proto_tree_add_text(mux_tree, tvb, offset, length + length_field,
            "PPPMux Sub-frame");
        sub_tree = proto_item_add_subtree(ti, ett_pppmux_subframe);
        sub_ti = proto_tree_add_text(sub_tree, tvb, offset, hdr_length,
            "Header field");

        hdr_tree = proto_item_add_subtree(sub_ti, ett_pppmux_subframe_hdr);
        ti = proto_tree_add_text(hdr_tree, tvb, offset, length_field,
            "PFF/LXT: 0x%02X", flags);
        flag_tree = proto_item_add_subtree(ti, ett_pppmux_subframe_flags);
        proto_tree_add_item(flag_tree, hf_pppmux_flags_pid, tvb,  offset, length_field,
                ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_pppmux_flags_field_length, tvb,  offset, length_field,
                ENC_BIG_ENDIAN);
        proto_tree_add_text(hdr_tree, tvb,offset, length_field,
            "Sub-frame Length = %u", length);

        ti = proto_tree_add_uint(hdr_tree, hf_pppmux_protocol, tvb,
            offset + length_field, pid_field, pid);

        /* if protocol is not present in the sub-frame */
        if (!(flags & PPPMUX_PFF_BIT_SET)) {
            /* mark this item as generated */
            PROTO_ITEM_SET_GENERATED(ti);
        }

        offset += hdr_length;
        length_remaining -= hdr_length;
        length -= pid_field;

        tvb_ensure_bytes_exist (tvb, offset, length);
        sub_ti = proto_tree_add_text(sub_tree, tvb,offset, length,
            "Information Field");
        info_tree = proto_item_add_subtree(sub_ti, ett_pppmux_subframe_info);
        next_tvb = tvb_new_subset(tvb, offset, length, length);

        if (!dissector_try_uint(ppp_subdissector_table, pid, next_tvb, pinfo,
            info_tree)) {
            call_dissector(data_handle, next_tvb, pinfo, info_tree);
        }
        offset += length;
        length_remaining -= length;
    }
}

/*
 * RFC 2508 Internet Protocol Header Compression
 */
#define IPHC_CRTP_FH_FLAG_MASK  0xc0
#define IPHC_CRTP_FH_FLAG_POS   6
#define IPHC_CRTP_FH_CID8       1
#define IPHC_CRTP_FH_CID16      3

#define IPHC_CRTP_CS_CID8       1
#define IPHC_CRTP_CS_CID16      2

static const value_string iphc_crtp_fh_flags[] = {
    {IPHC_CRTP_FH_CID8,  "8-bit Context Id"},
    {IPHC_CRTP_FH_CID16, "16-bit Context Id"},
    {0,                  NULL}
};

static const value_string iphc_crtp_cs_flags[] = {
    {IPHC_CRTP_CS_CID8,  "8-bit Context Id"},
    {IPHC_CRTP_CS_CID16, "16-bit Context Id"},
    {0,                  NULL}
};

/*
 * 0x61 Packets: Full IP/UDP Header
 */
static void
dissect_iphc_crtp_fh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *fh_tree = NULL, *info_tree;
    proto_item *ti = NULL;
    guint     ip_hdr_len, flags;
    guint     length;
    guint     hdr_len;
    tvbuff_t *next_tvb;
    int       offset_seq;
    int       offset_cid;
    guint8    ip_version;
    guint8    next_protocol;
    guchar   *ip_packet;

    length = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Full Header");

    /* only dissect IPv4 and UDP */
    ip_version = tvb_get_guint8(tvb, 0) >> 4;
    flags = (tvb_get_guint8(tvb, 2) & IPHC_CRTP_FH_FLAG_MASK) >>
        IPHC_CRTP_FH_FLAG_POS;
    next_protocol = tvb_get_guint8(tvb, 9);

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s", val_to_str_ext_const(PPP_RTP_FH, &ppp_vals_ext, "Unknown"));
        fh_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

        proto_tree_add_item(fh_tree, hf_iphc_crtp_fh_flags, tvb, 2, 1,
            ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_tree, hf_iphc_crtp_gen, tvb, 2, 1,
            ENC_BIG_ENDIAN);

    }

    /* calculate length of IP header, assume IPv4 */
    ip_hdr_len = (tvb_get_guint8(tvb, 0) & 0x0f) * 4;

    /* calculate total hdr length, assume UDP */
    hdr_len = ip_hdr_len + 8;

    if (ip_version != 4) {
        proto_tree_add_text(fh_tree, tvb, 3, -1,
                            "IP version is %u: the only supported version is 4",
                            ip_version);
        return;
    }

    if (next_protocol != IP_PROTO_UDP) {
        proto_tree_add_text(fh_tree, tvb, 3, -1,
                            "Next protocol is %s (%u): the only supported protocol is UDP",
                            ipprotostr(next_protocol), next_protocol);
        return;
    }

    /* context id and sequence fields */
    switch (flags) {
    case IPHC_CRTP_FH_CID8:
        offset_cid = 3;
        offset_seq = ip_hdr_len + 5;
        proto_tree_add_item(fh_tree, hf_iphc_crtp_cid8, tvb, offset_cid, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_tree, hf_iphc_crtp_seq, tvb, offset_seq, 1,
                            ENC_BIG_ENDIAN);
        break;

    case IPHC_CRTP_FH_CID16:
        offset_seq = 3;
        offset_cid = ip_hdr_len + 4;
        proto_tree_add_item(fh_tree, hf_iphc_crtp_seq, tvb, offset_seq, 1,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_tree, hf_iphc_crtp_cid16, tvb, offset_cid,
                            2, ENC_BIG_ENDIAN);
        break;

    default:
        /* TODO? */
        break;
    }

    /* information field */
    ti = proto_tree_add_text(fh_tree, tvb, 0, length, "Information Field");
    info_tree = proto_item_add_subtree(ti,ett_iphc_crtp_info);

    /* XXX: 1: May trap above; 2: really only need to check for ip_hdr_len+6 ?? */
    tvb_ensure_bytes_exist (tvb, 0, hdr_len);  /* ip_hdr_len + 8 */

    /* allocate a copy of the IP packet */
    ip_packet = tvb_memdup(tvb, 0, length);

    /* restore the proper values to the IP and UDP length fields */
    ip_packet[2] = length >> 8;
    ip_packet[3] = length;

    ip_packet[ip_hdr_len + 4] = (length - ip_hdr_len) >> 8;
    ip_packet[ip_hdr_len + 5] = (length - ip_hdr_len);

    next_tvb = tvb_new_child_real_data(tvb, ip_packet, length, length);
    add_new_data_source(pinfo, next_tvb, "Decompressed Data");
    tvb_set_free_cb(next_tvb, g_free);

    if (!dissector_try_uint(ppp_subdissector_table, PPP_IP, next_tvb, pinfo,
        info_tree)) {
        call_dissector_only(data_handle, next_tvb, pinfo, info_tree, NULL);
    }
}

/*
 * 0x2067 Packets:  Compressed UDP with 16-bit Context Identifier
 */
static void
dissect_iphc_crtp_cudp16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *cudp_tree;
    proto_item *ti     = NULL;
    guint       length;
    guint       hdr_length;
    int         offset = 0;

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed UDP 16");

    length = tvb_reported_length(tvb);

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s",
            val_to_str_ext_const(PPP_RTP_CUDP16, &ppp_vals_ext, "Unknown"));
        cudp_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

        hdr_length = 3;

        proto_tree_add_item(cudp_tree, hf_iphc_crtp_cid16, tvb, 0, 2,
            ENC_BIG_ENDIAN);
        proto_tree_add_item(cudp_tree, hf_iphc_crtp_seq, tvb, 2, 1,
            ENC_BIG_ENDIAN);

        offset += hdr_length;
        length -= hdr_length;

        proto_tree_add_text(cudp_tree, tvb, offset, length, "Data (%d bytes)",
            length);
    }
}

/*
 * 0x67 Packets:  Compressed UDP with 8-bit Context Identifier
 */
static void
dissect_iphc_crtp_cudp8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *cudp_tree;
    proto_item *ti     = NULL;
    guint       length;
    guint       hdr_length;
    int         offset = 0;

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Compressed UDP 8");

    length = tvb_reported_length(tvb);

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s",
            val_to_str_ext_const(PPP_RTP_CUDP8, &ppp_vals_ext, "Unknown"));
        cudp_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

        hdr_length = 2;

        proto_tree_add_item(cudp_tree, hf_iphc_crtp_cid8, tvb, 0, 1,
            ENC_BIG_ENDIAN);
        proto_tree_add_item(cudp_tree, hf_iphc_crtp_seq, tvb, 1, 1,
            ENC_BIG_ENDIAN);

        offset += hdr_length;
        length -= hdr_length;

        proto_tree_add_text(cudp_tree, tvb, offset, length, "Data (%d bytes)",
            length);
    }
}


/*
 * 0x2065 Packets:  Context State
 */
static void
dissect_iphc_crtp_cs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *cs_tree;
    proto_item *ti     = NULL;
    guint8      flags, cnt;
    guint       length, cid_size;
    guint       offset = 2, hf;

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Context State");

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s", val_to_str_ext_const(PPP_RTP_CS, &ppp_vals_ext, "Unknown"));

        cs_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

        proto_tree_add_item(cs_tree, hf_iphc_crtp_cs_flags, tvb, 0, 1,
            ENC_BIG_ENDIAN);
        proto_tree_add_item(cs_tree, hf_iphc_crtp_cs_cnt, tvb, 1, 1,
            ENC_BIG_ENDIAN);

        /* calculate required length */
        flags = tvb_get_guint8(tvb, 0);
        cnt = tvb_get_guint8(tvb, 1);

        if (flags == IPHC_CRTP_CS_CID8) {
            hf = hf_iphc_crtp_cid8;
            cid_size = 1;
            length = 3 * cnt;
        } else {
            hf = hf_iphc_crtp_cid16;
            cid_size = 2;
            length = 4 * cnt;
        }

        tvb_ensure_bytes_exist(tvb, offset, length);

        while (offset < length) {
            proto_tree_add_item(cs_tree, hf, tvb, offset, cid_size,
                ENC_BIG_ENDIAN);
            offset += cid_size;
            proto_tree_add_item(cs_tree, hf_iphc_crtp_cs_invalid, tvb, offset,
                1, ENC_BIG_ENDIAN);
            proto_tree_add_item(cs_tree, hf_iphc_crtp_seq, tvb, offset, 1,
                ENC_BIG_ENDIAN);
            ++offset;
            proto_tree_add_item(cs_tree, hf_iphc_crtp_gen, tvb, offset, 1,
                ENC_BIG_ENDIAN);
            ++offset;
        }
    }
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
    dissect_cp(tvb, proto_cdpcp, ett_cdpcp, cp_vals, ett_cdpcp_options, NULL,
        0, pinfo, tree);
}

static gboolean mp_short_seqno = FALSE; /* Default to long sequence numbers */

#define MP_FRAG_MASK           0xC0
#define MP_FRAG(bits)          ((bits) & MP_FRAG_MASK)
#define MP_FRAG_FIRST          0x80
#define MP_FRAG_LAST           0x40
#define MP_FRAG_RESERVED       0x3f
#define MP_FRAG_RESERVED_SHORT 0x30

/* According to RFC 1990, the length the MP header isn't indicated anywhere
   in the header itself.  It starts out at four bytes and can be
   negotiated down to two using LCP.  We currently have a preference
   to select short headers.  - gcc & gh
*/
static void
dissect_mp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *mp_tree = NULL, *hdr_tree;
    proto_item  *ti = NULL;
    guint8       flags;
    const gchar *flag_str;
    gint        hdrlen;
    tvbuff_t    *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP MP");
    col_set_str(pinfo->cinfo, COL_INFO, "PPP Multilink");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_mp, tvb, 0,
            mp_short_seqno ? 2 : 4, ENC_NA);
        mp_tree = proto_item_add_subtree(ti, ett_mp);
    }

    flags = tvb_get_guint8(tvb, 0);

    if (tree) {
        switch (MP_FRAG(flags)) {
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
        ti = proto_tree_add_text(mp_tree, tvb, 0, 1, "Fragment: 0x%2X (%s)",
            MP_FRAG(flags), flag_str);
        hdr_tree = proto_item_add_subtree(ti, ett_mp_flags);

        proto_tree_add_boolean(hdr_tree, hf_mp_frag_first, tvb, 0, 1, flags);
        proto_tree_add_boolean(hdr_tree, hf_mp_frag_last, tvb, 0, 1, flags);
        if (mp_short_seqno) {
            proto_tree_add_item(hdr_tree, hf_mp_short_sequence_num_reserved, tvb,  0, 1,
                ENC_BIG_ENDIAN);
            proto_tree_add_item(mp_tree, hf_mp_short_sequence_num, tvb,  0, 2,
                ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item(hdr_tree, hf_mp_sequence_num_reserved, tvb,  0, 1,
                ENC_BIG_ENDIAN);
            proto_tree_add_item(mp_tree, hf_mp_sequence_num, tvb,  1, 3,
                ENC_BIG_ENDIAN);
        }
    }

    hdrlen = mp_short_seqno ? 2 : 4;
    if (tvb_reported_length_remaining(tvb, hdrlen) > 0) {
        next_tvb = tvb_new_subset_remaining(tvb, hdrlen);
        dissect_ppp(next_tvb, pinfo, tree);
    }
}

/*
 * Handles PPP without HDLC framing, just a protocol field (RFC 1661).
 */
static void
dissect_ppp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti      = NULL;
    proto_tree *fh_tree = NULL;

    if (tree) {
        ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, -1, ENC_NA);
        fh_tree = proto_item_add_subtree(ti, ett_ppp);
    }

    dissect_ppp_common(tvb, pinfo, tree, fh_tree, ti, 0);
}

static void
dissect_ppp_hdlc_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti      = NULL;
    proto_tree *fh_tree = NULL;
    guint8      byte0;
    int         proto_offset;
    tvbuff_t   *next_tvb;

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
    if (tree) {
        ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, -1, ENC_NA);
        fh_tree = proto_item_add_subtree(ti, ett_ppp);
        if (byte0 == 0xff) {
            proto_tree_add_item(fh_tree, hf_ppp_address, tvb, 0, 1,
                ENC_BIG_ENDIAN);
            proto_tree_add_item(fh_tree, hf_ppp_control, tvb, 1, 1,
                ENC_BIG_ENDIAN);
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
dissect_ppp_hdlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
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
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP");
    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
        col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
        break;

    case P2P_DIR_RECV:
        col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
        col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
        break;

    default:
        col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
        col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
        break;
    }

    dissect_ppp_hdlc_common(tvb, pinfo, tree);
}

static tvbuff_t*
remove_escape_chars(tvbuff_t *tvb, int offset, int length)
{
    guint8    *buff;
    int        i;
    int        scanned_len = 0;
    guint8     octet;
    tvbuff_t  *next_tvb;

    buff = g_malloc(length);
    i = 0;
    while (scanned_len < length) {
        octet = tvb_get_guint8(tvb, offset);
        if (octet == 0x7d) {
            offset++;
            scanned_len++;
            if (scanned_len >= length)
                break;
            octet = tvb_get_guint8(tvb, offset);
            buff[i] = octet ^ 0x20;
        } else {
            buff[i] = octet;
        }
        offset++;
        scanned_len++;
        i++;
    }
    if (i == 0) {
        g_free(buff);
        return NULL;
    }
    next_tvb = tvb_new_child_real_data(tvb, buff, i, i);

    /* Arrange that the allocated packet data copy be freed when the tvbuff is
     * freed. */
    tvb_set_free_cb(next_tvb, g_free);
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
    gint        offset, end_offset, data_offset;
    int         length, data_length;
    tvbuff_t   *ppp_tvb;
    gboolean    first   = TRUE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_ppp_hdlc, tvb, 0, -1, ENC_NA);
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
        col_set_str(pinfo->cinfo, COL_INFO, "PPP Fragment");
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
        col_set_str(pinfo->cinfo, COL_INFO, "PPP Fragment");
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
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        /*
         * Look for the next frame delimiter.
         */
        end_offset = tvb_find_guint8(tvb, offset + 1, -1, 0x7e);
        if (end_offset == -1) {
            /*
             * We didn't find one.  This is probably continued in a later
             * packet.
             */
            if (first)
                col_set_str(pinfo->cinfo, COL_INFO, "PPP Fragment");
            if (tree)
                proto_tree_add_text(bs_tree, tvb, offset, -1, "PPP Fragment");
            offset++;
            length = tvb_length_remaining(tvb, offset);
            ppp_tvb = remove_escape_chars(tvb, offset, length);
            if (ppp_tvb != NULL) {
                add_new_data_source(pinfo, ppp_tvb, "PPP Fragment");
                call_dissector(data_handle, ppp_tvb, pinfo, tree);
            }
            return;
        }

        data_offset = offset + 1;     /* skip starting frame delimiter */
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
        if (tvb_offset_exists(tvb, end_offset + 1) &&
            tvb_get_guint8(tvb, end_offset+1) == 0x7e) {
            end_offset++;
        }
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
    }
}

/*
 * At least for the PPP/USB captures I've seen, the data either starts with
 * 0x7eff03 or 0x7eff7d23 or 0xff03, so this function performs that heuristic
 * matching first before calling dissect_ppp_raw_hdlc().  Otherwise, if we call
 * it directly for USB captures, some captures like the following will not be
 * dissected correctly:
 * http://wiki.wireshark.org/SampleCaptures#head-886e340c31ca977f321c921f81cbec4c21bb7738
 *
 * NOTE: I don't know if these heuristics are sufficient.  Time will tell ...
 */
static gboolean
dissect_ppp_usb( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    /*
     * In some cases, the 0x03 normally in byte 3 is escaped so we must look
     * for the 2 byte sequence of 0x7d23 instead of 0x03.  The 0x23 is
     * generated by 0x20^0x03 per section 4.2 of:
     * http://tools.ietf.org/html/rfc1662.html.
     */
    const guchar buf1[3] = {0x7e, 0xff, 0x03};
    const guchar buf2[4] = {0x7e, 0xff, 0x7d, 0x23};
    tvbuff_t *next_tvb;

    if ((tvb_memeql(tvb, 0, buf2, sizeof(buf2)) == 0) ||
        (tvb_memeql(tvb, 0, buf1, sizeof(buf1)) == 0)) {
        dissect_ppp_raw_hdlc(tvb, pinfo, tree);
    } else if ((tvb_memeql(tvb, 0, &buf1[1], sizeof(buf1) - 1) == 0) ||
        (tvb_memeql(tvb, 0, &buf2[1], sizeof(buf2) - 1) == 0)) {
        /* It's missing the 0x7e framing character.  What TODO?
         * Should we try faking it by sticking 0x7e in front?  Or try telling
         * dissect_ppp_raw_hdlc() NOT to look for the 0x7e frame deliminator?
         * Or is this a bug in libpcap (used 1.1.0)?
         * Or a bug in the Linux kernel (tested with 2.6.24.4)  Or a bug in
         * usbmon?  Or is the data we're looking at really just part of the
         * payload and not control data?  Well, at least in my case it's
         * definitely not, but not sure if this is always the case. Is this
         * issue applicable only to PPP/USB or PPP/XYZ, in which case a more
         * general solution should be found?
         */
        /* For now, just try skipping the framing I guess??? */
        if (tvb_get_guint8(tvb, 1) == 0x03)
            next_tvb = tvb_new_subset_remaining(tvb, 2);
        else
            next_tvb = tvb_new_subset_remaining(tvb, 3);
        dissect_ppp(next_tvb, pinfo, tree);
    } else if (tvb_get_guint8(tvb, 0) == 0x7e) {
        /* Well, let's guess that since the 1st byte is 0x7e that it really is
         * a PPP frame, and the address and control bytes are compressed (NULL)
         * per http://tools.ietf.org/html/rfc1662, section 3.2. */
        next_tvb = tvb_new_subset_remaining(tvb, 1);
        dissect_ppp_hdlc_common(next_tvb, pinfo, tree);
    } else
        return (FALSE);
    return (TRUE);
}

void
proto_register_ppp_raw_hdlc(void)
{
    static gint *ett[] = {
        &ett_ppp_hdlc_data
    };

    proto_ppp_hdlc = proto_register_protocol("PPP In HDLC-Like Framing",
        "PPP-HDLC", "ppp_hdlc");
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ppp_raw_hdlc(void)
{
    dissector_handle_t ppp_raw_hdlc_handle;

    ppp_raw_hdlc_handle = create_dissector_handle(dissect_ppp_raw_hdlc,
        proto_ppp);
    dissector_add_uint("gre.proto", ETHERTYPE_CDMA2000_A10_UBS,
        ppp_raw_hdlc_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_3GPP2, ppp_raw_hdlc_handle);

    heur_dissector_add("usb.bulk", dissect_ppp_usb, proto_ppp);
}

/*
 * Handles PAP just as a protocol field
 */
static void
dissect_pap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti, *data_ti;
    proto_tree *fh_tree, *data_tree = NULL;
    guint8      code;
    gchar      *peer_id, *password, *message;
    guint8      peer_id_length, password_length, message_length;
    int         offset              = 0;

    code = tvb_get_guint8(tvb, 0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP PAP");
    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str_const(code, pap_vals, "Unknown"));

    ti = proto_tree_add_item(tree, proto_pap, tvb, 0, -1, ENC_NA);
    fh_tree = proto_item_add_subtree(ti, ett_pap);

    proto_tree_add_item(fh_tree, hf_pap_code, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(fh_tree, hf_pap_identifier, tvb, offset, 1,
                        ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(fh_tree, hf_pap_length, tvb, offset, 2,
                        ENC_BIG_ENDIAN);
    offset += 2;

    data_ti = proto_tree_add_item(fh_tree, hf_pap_data, tvb, offset, -1,
                                  ENC_NA);
    data_tree = proto_item_add_subtree(data_ti, ett_pap_data);

    switch (code) {
    case CONFREQ:
        proto_tree_add_item(data_tree, hf_pap_peer_id_length, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        peer_id_length = tvb_get_guint8(tvb, offset);
        offset++;

        proto_tree_add_item(data_tree, hf_pap_peer_id, tvb, offset,
                            peer_id_length, ENC_ASCII|ENC_NA);
        peer_id = tvb_format_text(tvb, offset, peer_id_length);
        offset += peer_id_length;

        proto_tree_add_item(data_tree, hf_pap_password_length, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        password_length = tvb_get_guint8(tvb, offset);
        offset++;

        proto_tree_add_item(data_tree, hf_pap_password, tvb, offset,
                            password_length, ENC_ASCII|ENC_NA);
        password = tvb_format_text(tvb, offset, password_length);

        col_append_fstr(pinfo->cinfo, COL_INFO,
                        " (Peer-ID='%s', Password='%s')", peer_id, password);
        break;

    case CONFACK:
    case CONFNAK:
        proto_tree_add_item(data_tree, hf_pap_message_length, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        message_length = tvb_get_guint8(tvb, offset);
        offset +=1;

        proto_tree_add_item(data_tree, hf_pap_message, tvb, offset,
                            message_length, ENC_ASCII|ENC_NA);
        message = tvb_format_text(tvb, offset, message_length);

        col_append_fstr(pinfo->cinfo, COL_INFO, " (Message='%s')",
                        message);
        break;

    default:
        proto_tree_add_item(data_tree, hf_pap_stuff, tvb, offset, -1,
                            ENC_NA);
        break;
    }
}

/*
 * RFC 1994
 * Handles CHAP just as a protocol field
 */
static void
dissect_chap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti      = NULL;
    proto_tree *fh_tree = NULL;
    proto_item *tf;
    proto_tree *field_tree;
    guint8      code, value_size;
    guint32     length;
    int         offset;

    code = tvb_get_guint8(tvb, 0);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPP CHAP");
    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str_const(code, chap_vals, "Unknown"));

    if (tree) {
        /* Create CHAP protocol tree */
        ti = proto_tree_add_item(tree, proto_chap, tvb, 0, -1, ENC_NA);
        fh_tree = proto_item_add_subtree(ti, ett_chap);

        proto_tree_add_item(fh_tree, hf_chap_code, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_tree, hf_chap_identifier, tvb, 1, 1,
            ENC_BIG_ENDIAN);
    }

    /* Length - make sure it's valid */
    length = tvb_get_ntohs(tvb, 2);
    if (length < 4) {
        if (tree) {
            proto_tree_add_uint_format(fh_tree, hf_chap_length, tvb, 2, 2,
                length, "Length: %u (invalid, must be >= 4)", length);
        }
        return;
    }
    proto_item_set_len(ti, length);
    if (tree) {
        proto_tree_add_item(fh_tree, hf_chap_length, tvb, 2, 2,
            ENC_BIG_ENDIAN);
    }

    offset = 4;     /* Offset moved to after length field */
    length -= 4;    /* Length includes previous 4 bytes, subtract */

    switch (code) {
    /* Challenge or Response data */
    case CHAP_CHAL:
    case CHAP_RESP:
        if (length > 0) {
            guint value_offset = 0;
            guint name_offset  = 0, name_size = 0;

            /* Create data subtree */
            tf = proto_tree_add_item(fh_tree, hf_chap_data, tvb, offset,
                                     length, ENC_NA);
            field_tree = proto_item_add_subtree(tf, ett_chap_data);
            length--;

            /* Value size */
            value_size = tvb_get_guint8(tvb, offset);
            if (value_size > length) {
                proto_tree_add_text(field_tree, tvb, offset, 1,
                                    "Value Size: %d byte%s (invalid, must be <= %u)",
                                    value_size, plurality(value_size, "", "s"), length);
                return;
            }
            proto_tree_add_item(field_tree, hf_chap_value_size, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
            offset++;

            /* Value */
            if (length > 0) {
                value_offset = offset;
                proto_tree_add_item(field_tree, hf_chap_value, tvb, offset,
                                    value_size, ENC_NA);

                /* Move along value_size bytes */
                offset += value_size;
                length -= value_size;

                /* Find name in remaining bytes */
                if (length > 0) {
                    tvb_ensure_bytes_exist(tvb, offset, length);
                    proto_tree_add_item(field_tree, hf_chap_name, tvb,
                                        offset, length, ENC_ASCII|ENC_NA);
                    name_offset = offset;
                    name_size = length;
                }

                /* Show name and value in info column */
                col_append_fstr(pinfo->cinfo, COL_INFO,
                                " (NAME='%s%s', VALUE=0x%s)",
                                tvb_format_text(tvb, name_offset,
                                                (name_size > 20) ? 20 : name_size),
                                (name_size > 20) ? "..." : "",
                                tvb_bytes_to_str(tvb, value_offset, value_size));
            }
        }
        break;

    /* Success or Failure data */
    case CHAP_SUCC:
    case CHAP_FAIL:
        if (tree) {
            if (length > 0) {
                proto_tree_add_item(fh_tree, hf_chap_message, tvb, offset,
                    length, ENC_ASCII|ENC_NA);
            }
        }

        /* Show message in info column */
        col_append_fstr(pinfo->cinfo, COL_INFO, " (MESSAGE='%s')",
            tvb_format_text(tvb, offset, length));
        break;

    /* Code from unknown code type... */
    default:
        if (length > 0)
            proto_tree_add_text(fh_tree, tvb, offset, length,
                "Stuff (%u byte%s)", length, plurality(length, "", "s"));
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

static void
dissect_ipv6cp_if_id_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
    guint length, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_text(tree, tvb, offset, length,
        "%s: %02x%02x:%02x%02x:%02x%x:%02x%02x", optp->name,
        tvb_get_guint8(tvb, offset + 2), tvb_get_guint8(tvb, offset + 3),
        tvb_get_guint8(tvb, offset + 4), tvb_get_guint8(tvb, offset + 5),
        tvb_get_guint8(tvb, offset + 6), tvb_get_guint8(tvb, offset + 7),
        tvb_get_guint8(tvb, offset + 8), tvb_get_guint8(tvb, offset + 9));
}

void
proto_register_ppp(void)
{
    static hf_register_info hf[] = {
        { &hf_ppp_direction,
            { "Direction", "ppp.direction", FT_UINT8, BASE_DEC,
                VALS(ppp_direction_vals), 0x0, "PPP direction", HFILL }},
        { &hf_ppp_address,
            { "Address", "ppp.address", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_control,
            { "Control", "ppp.control", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_protocol,
            { "Protocol", "ppp.protocol", FT_UINT16, BASE_HEX|BASE_EXT_STRING,
                &ppp_vals_ext, 0x0, NULL, HFILL }},
        { &hf_ppp_code,
            { "Code", "ppp.code", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_identifier,
            { "Identifier", "ppp.identifier", FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_length,
            { "Length", "ppp.length", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_magic_number,
            { "Magic Number", "ppp.magic_number", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_oui,
            { "OUI", "ppp.oui", FT_UINT24, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_kind,
            { "Kind", "ppp.kind", FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ppp_data,
            { "Data", "ppp.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }}
    };
    static gint *ett[] = {
        &ett_ppp
    };

    module_t *ppp_module;

    proto_ppp = proto_register_protocol("Point-to-Point Protocol", "PPP",
        "ppp");
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

    prefs_register_enum_preference(ppp_module, "fcs_type",
        "PPP Frame Checksum Type",
        "The type of PPP frame checksum (none, 16-bit, 32-bit)",
        &ppp_fcs_decode, fcs_options, FALSE);
    prefs_register_bool_preference(ppp_module, "decompress_vj",
        "Decompress Van Jacobson-compressed frames",
        "Whether Van Jacobson-compressed PPP frames should be decompressed",
        &ppp_vj_decomp);
    prefs_register_uint_preference(ppp_module, "default_proto_id",
        "PPPMuxCP Default PID (in hex)",
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
    dissector_add_uint("fr.ietf", NLPID_PPP, ppp_handle);

    ppp_hdlc_handle = find_dissector("ppp_hdlc");
    dissector_add_uint("wtap_encap", WTAP_ENCAP_PPP, ppp_hdlc_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_PPP_WITH_PHDR,
        ppp_hdlc_handle);
    dissector_add_uint("sll.ltype", LINUX_SLL_P_PPPHDLC, ppp_hdlc_handle);
    dissector_add_uint("osinl.excl", NLPID_PPP, ppp_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_PPP, ppp_hdlc_handle);
}

void
proto_register_mp(void)
{
    static hf_register_info hf[] = {
        { &hf_mp_frag_first,
            { "First fragment", "mp.first", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), MP_FRAG_FIRST, NULL, HFILL }},
        { &hf_mp_frag_last,
            { "Last fragment", "mp.last", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), MP_FRAG_LAST, NULL, HFILL }},
        { &hf_mp_sequence_num,
            { "Sequence number", "mp.seq", FT_UINT24, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_mp_sequence_num_reserved,
            { "Reserved", "mp.sequence_num_reserved", FT_BOOLEAN, 8,
                NULL, MP_FRAG_RESERVED, NULL, HFILL }},
        { &hf_mp_short_sequence_num,
            { "Short Sequence number", "mp.sseq", FT_UINT16, BASE_DEC,
                NULL, 0x0FFF, NULL, HFILL }},
        { &hf_mp_short_sequence_num_reserved,
            { "Reserved", "mp.short_sequence_num_reserved", FT_BOOLEAN, 8,
                NULL, MP_FRAG_RESERVED_SHORT, NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_mp,
        &ett_mp_flags
    };

    module_t *mp_module;

    proto_mp = proto_register_protocol("PPP Multilink Protocol", "PPP MP",
        "mp");
    proto_register_field_array(proto_mp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the preferences for the PPP multilink protocol */
    mp_module = prefs_register_protocol(proto_mp, NULL);

    prefs_register_bool_preference(mp_module, "short_seqno",
        "Short sequence numbers",
        "Whether PPP Multilink frames use 12-bit sequence numbers",
        &mp_short_seqno);
}

void
proto_reg_handoff_mp(void)
{
    dissector_handle_t mp_handle;

    mp_handle = create_dissector_handle(dissect_mp, proto_mp);
    dissector_add_uint("ppp.protocol", PPP_MP, mp_handle);
}

void
proto_register_lcp(void)
{
    static hf_register_info hf[] = {
        { &hf_lcp_magic_number,
            { "Magic Number", "lcp.magic_number", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_data,
            { "Data", "lcp.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_message,
            { "Message", "lcp.message", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_secs_remaining,
            { "Seconds Remaining", "lcp.secs_remaining", FT_UINT32, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_rej_proto,
            { "Rejected Protocol", "lcp.rej_proto", FT_UINT16,
                BASE_HEX | BASE_EXT_STRING, &ppp_vals_ext, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_type,
            { "Type", "lcp.opt.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_length,
            { "Length", "lcp.opt.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_oui,
            { "OUI", "lcp.opt.oui", FT_UINT24, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_kind,
            { "Kind", "lcp.opt.kind", FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_data,
            { "Data", "lcp.opt.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_mru,
            { "Maximum Receive Unit", "lcp.opt.mru", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap,
            { "Async Control Character Map", "lcp.opt.asyncmap", FT_UINT32,
                BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_nul,
            { "NUL", "lcp.opt.asyncmap.nul", FT_BOOLEAN, 32,
                NULL, 0x00000001, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_soh,
            { "SOH", "lcp.opt.asyncmap.soh", FT_BOOLEAN, 32,
                NULL, 0x00000002, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_stx,
            { "STX", "lcp.opt.asyncmap.stx", FT_BOOLEAN, 32,
                NULL, 0x00000004, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_etx,
            { "ETX", "lcp.opt.asyncmap.etx", FT_BOOLEAN, 32,
                NULL, 0x00000008, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_eot,
            { "EOT", "lcp.opt.asyncmap.eot", FT_BOOLEAN, 32,
                NULL, 0x00000010, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_enq,
            { "ENQ", "lcp.opt.asyncmap.enq", FT_BOOLEAN, 32,
                NULL, 0x00000020, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_ack,
            { "ACK", "lcp.opt.asyncmap.ack", FT_BOOLEAN, 32,
                NULL, 0x00000040, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_bel,
            { "BEL", "lcp.opt.asyncmap.bel", FT_BOOLEAN, 32,
                NULL, 0x00000080, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_bs,
            { "BS", "lcp.opt.asyncmap.bs", FT_BOOLEAN, 32,
                NULL, 0x00000100, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_ht,
            { "HT", "lcp.opt.asyncmap.ht", FT_BOOLEAN, 32,
                NULL, 0x00000200, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_lf,
            { "LF", "lcp.opt.asyncmap.lf", FT_BOOLEAN, 32,
                NULL, 0x00000400, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_vt,
            { "VT", "lcp.opt.asyncmap.vt", FT_BOOLEAN, 32,
                NULL, 0x00000800, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_ff,
            { "FF", "lcp.opt.asyncmap.ff", FT_BOOLEAN, 32,
                NULL, 0x00001000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_cr,
            { "CR", "lcp.opt.asyncmap.cr", FT_BOOLEAN, 32,
                NULL, 0x00002000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_so,
            { "SO", "lcp.opt.asyncmap.so", FT_BOOLEAN, 32,
                NULL, 0x00004000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_si,
            { "SI", "lcp.opt.asyncmap.si", FT_BOOLEAN, 32,
                NULL, 0x00008000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dle,
            { "DLE", "lcp.opt.asyncmap.dle", FT_BOOLEAN, 32,
                NULL, 0x00010000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dc1,
            { "DC1 (XON)", "lcp.opt.asyncmap.dc1", FT_BOOLEAN, 32,
                NULL, 0x00020000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dc2,
            { "DC2", "lcp.opt.asyncmap.dc2", FT_BOOLEAN, 32,
                NULL, 0x00040000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dc3,
            { "DC3 (XOFF)", "lcp.opt.asyncmap.dc3", FT_BOOLEAN, 32,
                NULL, 0x00080000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_dc4,
            { "DC4", "lcp.opt.asyncmap.dc4", FT_BOOLEAN, 32,
                NULL, 0x00100000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_nak,
            { "NAK", "lcp.opt.asyncmap.nak", FT_BOOLEAN, 32,
                NULL, 0x00200000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_syn,
            { "SYN", "lcp.opt.asyncmap.syn", FT_BOOLEAN, 32,
                NULL, 0x00400000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_etb,
            { "ETB", "lcp.opt.asyncmap.etb", FT_BOOLEAN, 32,
                NULL, 0x00800000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_can,
            { "CAN", "lcp.opt.asyncmap.can", FT_BOOLEAN, 32,
                NULL, 0x01000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_em,
            { "EM", "lcp.opt.asyncmap.em", FT_BOOLEAN, 32,
                NULL, 0x02000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_sub,
            { "SUB", "lcp.opt.asyncmap.sub", FT_BOOLEAN, 32,
                NULL, 0x04000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_esc,
            { "ESC", "lcp.opt.asyncmap.esc", FT_BOOLEAN, 32,
                NULL, 0x08000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_fs,
            { "FS", "lcp.opt.asyncmap.fs", FT_BOOLEAN, 32,
                NULL, 0x10000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_gs,
            { "GS", "lcp.opt.asyncmap.gs", FT_BOOLEAN, 32,
                NULL, 0x20000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_rs,
            { "RS", "lcp.opt.asyncmap.rs", FT_BOOLEAN, 32,
                NULL, 0x40000000, NULL, HFILL }},
        { &hf_lcp_opt_asyncmap_us,
            { "US", "lcp.opt.asyncmap.us", FT_BOOLEAN, 32,
                NULL, 0x80000000, NULL, HFILL }},
        { &hf_lcp_opt_auth_protocol,
            { "Authentication Protocol", "lcp.opt.auth_protocol", FT_UINT16,
                BASE_HEX | BASE_EXT_STRING, &ppp_vals_ext, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_algorithm,
            { "Algorithm", "lcp.opt.algorithm", FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING, &chap_alg_rvals,
                0x0, NULL, HFILL }},
        { &hf_lcp_opt_quality_protocol,
            { "Quality Protocol", "lcp.opt.quality_protocol", FT_UINT16,
                BASE_HEX | BASE_EXT_STRING, &ppp_vals_ext, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_magic_number,
            { "Magic Number", "lcp.opt.magic_number", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_reportingperiod,
            { "Reporting Period", "lcp.opt.reporting_period", FT_UINT32,
                BASE_DEC, NULL, 0x0,
                "Maximum time in micro-seconds that the remote end should "
                "wait between transmission of LCP Link-Quality-Report packets",
                HFILL }},
        { &hf_lcp_opt_fcs_alternatives,
            { "FCS Alternatives", "lcp.opt.fcs_alternatives", FT_UINT8,
                BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_fcs_alternatives_null,
            { "NULL FCS", "lcp.opt.fcs_alternatives.null", FT_BOOLEAN, 8,
                NULL, 0x01, NULL, HFILL }},
        { &hf_lcp_opt_fcs_alternatives_ccitt16,
            { "CCITT 16-bit", "lcp.opt.fcs_alternatives.ccitt16", FT_BOOLEAN,
                8, NULL, 0x02, NULL, HFILL }},
        { &hf_lcp_opt_fcs_alternatives_ccitt32,
            { "CCITT 32-bit", "lcp.opt.fcs_alternatives.ccitt32", FT_BOOLEAN,
                8, NULL, 0x04, NULL, HFILL }},
        { &hf_lcp_opt_maximum,
            { "Maximum", "lcp.opt.maximum", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The largest number of padding octets which may be added "
                "to the frame.", HFILL }},
        { &hf_lcp_opt_window,
            { "Window", "lcp.opt.window", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The number of frames the receiver will buffer.", HFILL }},
        { &hf_lcp_opt_hdlc_address,
            { "Address", "lcp.opt.hdlc_address", FT_BYTES, BASE_NONE, NULL,
                0x0, "An HDLC Address as specified in ISO 3309.", HFILL }},
        { &hf_lcp_opt_operation,
            { "Operation", "lcp.opt.operation", FT_UINT8, BASE_DEC,
                VALS(callback_op_vals), 0x0, NULL, HFILL }},
        { &hf_lcp_opt_message,
            { "Message", "lcp.opt.message", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_mrru,
            { "MRRU", "lcp.opt.mrru", FT_UINT16, BASE_DEC, NULL, 0x0,
                "Maximum Receive Reconstructed Unit", HFILL }},
        { &hf_lcp_opt_ep_disc_class,
            { "Class", "lcp.opt.ep_disc_class", FT_UINT8, BASE_DEC,
                VALS(multilink_ep_disc_class_vals), 0x0, NULL, HFILL }},
        { &hf_lcp_opt_ip_address,
            { "IP Address", "lcp.opt.ip_address", FT_IPv4, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_802_1_address,
            { "IEEE 802.1 Address", "lcp.opt.802_1_address", FT_ETHER,
                BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_magic_block,
            { "PPP Magic-Number Block", "lcp.opt.magic_block", FT_BYTES,
                BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_psndn,
            { "Public Switched Network Directory Number", "lcp.opt.psndn",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_mode,
            { "Mode", "lcp.opt.mode", FT_UINT8, BASE_DEC,
                VALS(dce_id_mode_vals), 0x0, NULL, HFILL }},
        { &hf_lcp_opt_unused,
            { "Unused", "lcp.opt.unused", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_link_discrim,
            { "Link Discriminator", "lcp.opt.link_discrim", FT_UINT16,
                BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_id,
            { "Identification", "lcp.opt.id", FT_UINT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_cobs_flags,
            { "Flags", "lcp.opt.flags", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_cobs_flags_res,
            { "Reserved", "lcp.opt.flags.reserved", FT_UINT8, BASE_HEX,
                NULL, 0xFC, NULL, HFILL }},
        { &hf_lcp_opt_cobs_flags_pre,
            { "PRE", "lcp.opt.flags.pre", FT_BOOLEAN, 8,
                NULL, 0x02, "Preemption", HFILL }},
        { &hf_lcp_opt_cobs_flags_zxe,
            { "ZXE", "lcp.opt.flags.zxe", FT_BOOLEAN, 8,
                NULL, 0x01, "Zero pair/run elimination", HFILL }},
        { &hf_lcp_opt_class,
            { "Class", "lcp.opt.class", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_prefix,
            { "Prefix", "lcp.opt.prefix", FT_UINT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_code,
            { "Code", "lcp.opt.code", FT_UINT8, BASE_DEC,
                VALS(ml_hdr_fmt_code_vals), 0x0, NULL, HFILL }},
        { &hf_lcp_opt_max_susp_classes,
            { "Max suspendable classes", "lcp.opt.max_susp_classes",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lcp_opt_MIBenum,
            { "MIBenum", "lcp.opt.MIBenum", FT_UINT32,
                BASE_DEC | BASE_EXT_STRING, &charset_vals_ext, 0x0,
                "A unique integer value identifying a charset", HFILL }},
        { &hf_lcp_opt_language_tag,
            { "Language-Tag", "lcp.opt.language_tag", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_lcp,
        &ett_lcp_options,
        &ett_lcp_vendor_opt,
        &ett_lcp_mru_opt,
        &ett_lcp_asyncmap_opt,
        &ett_lcp_authprot_opt,
        &ett_lcp_qualprot_opt,
        &ett_lcp_magicnumber_opt,
        &ett_lcp_linkqualmon_opt,
        &ett_lcp_pcomp_opt,
        &ett_lcp_acccomp_opt,
        &ett_lcp_fcs_alternatives_opt,
        &ett_lcp_self_desc_pad_opt,
        &ett_lcp_numbered_mode_opt,
        &ett_lcp_callback_opt,
        &ett_lcp_compound_frames_opt,
        &ett_lcp_nomdataencap_opt,
        &ett_lcp_multilink_mrru_opt,
        &ett_lcp_multilink_ssnh_opt,
        &ett_lcp_multilink_ep_disc_opt,
        &ett_lcp_magic_block,
        &ett_lcp_dce_identifier_opt,
        &ett_lcp_multilink_pp_opt,
        &ett_lcp_bacp_link_discrim_opt,
        &ett_lcp_auth_opt,
        &ett_lcp_cobs_opt,
        &ett_lcp_prefix_elision_opt,
        &ett_multilink_hdr_fmt_opt,
        &ett_lcp_internationalization_opt,
        &ett_lcp_simple_opt
    };

    proto_lcp = proto_register_protocol("PPP Link Control Protocol", "PPP LCP",
        "lcp");
    proto_register_field_array(proto_lcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lcp(void)
{
    dissector_handle_t lcp_handle;

    lcp_handle = create_dissector_handle(dissect_lcp, proto_lcp);
    dissector_add_uint("ppp.protocol", PPP_LCP, lcp_handle);

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
    dissector_add_uint("ethertype", PPP_LCP, lcp_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_LCP, lcp_handle);
}

void
proto_register_vsncp(void)
{
    static gint *ett[] = {
        &ett_vsncp,
        &ett_vsncp_options
    };

    proto_vsncp = proto_register_protocol("Vendor Specific Control Protocol",
        "VSNCP", "vsncp");
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vsncp(void)
{
    dissector_handle_t vsncp_handle;

    vsncp_handle = create_dissector_handle(dissect_vsncp, proto_vsncp);
    dissector_add_uint("ppp.protocol", PPP_VSNCP, vsncp_handle);
}

void
proto_register_vsnp(void)
{
    static gint *ett[] = {
        &ett_vsnp
    };

    static hf_register_info hf[] = {
        { &hf_vsnp_pdnid,
            { "PDN ID", "vsnp.pdnid", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }}
    };

    proto_vsnp = proto_register_protocol("Vendor Specific Network Protocol",
        "PPP VSNP", "vsnp");
    proto_register_subtree_array(ett, array_length(ett));
    proto_register_field_array(proto_vsnp, hf, array_length(hf));
}

void
proto_reg_handoff_vsnp(void)
{
    dissector_handle_t vsnp_handle;

    vsnp_handle = create_dissector_handle(dissect_vsnp, proto_vsnp);
    dissector_add_uint("ppp.protocol", PPP_VSNP, vsnp_handle);
}

void
proto_register_ipcp(void)
{
    static hf_register_info hf[] = {
        { &hf_ipcp_opt_type,
            { "Type", "ipcp.opt.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_length,
            { "Length", "ipcp.opt.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_src_address,
            { "Source IP Address", "ipcp.opt.src_address", FT_IPv4, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_dst_address,
            { "Destination IP Address", "ipcp.opt.dst_address", FT_IPv4,
                BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_compress_proto,
            { "IP Compression Protocol", "ipcp.opt.compress_proto", FT_UINT16,
                BASE_HEX, VALS(ipcp_compress_proto_vals), 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_max_cid,
            { "Max CID", "ipcp.opt.max_cid", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Maximum value of a context identifier", HFILL }},
        { &hf_ipcp_opt_mrru,
            { "MRRU", "ipcp.opt.mrru", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Maximum Reconstructed Reception Unit", HFILL }},
        { &hf_ipcp_opt_max_slot_id,
            { "Max Slot ID", "ipcp.opt.max_slot_id", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_comp_slot_id,
            { "Comp Slot ID", "ipcp.opt.comp_slot_id", FT_BOOLEAN, 8,
                TFS(&tfs_comp_slot_id), 0x01, NULL, HFILL }},
        { &hf_ipcp_opt_tcp_space,
            { "TCP Space", "ipcp.opt.tcp_space", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_non_tcp_space,
            { "Non TCP Space", "ipcp.opt.non_tcp_space", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_f_max_period,
            { "F Max Period", "ipcp.opt.f_max_period", FT_UINT16, BASE_DEC,
                NULL, 0x0, "Maximum interval between full headers", HFILL }},
        { &hf_ipcp_opt_f_max_time,
            { "F Max Time", "ipcp.opt.f_max_time", FT_UINT16, BASE_DEC, NULL,
                0x0, "Maximum time interval between full headers", HFILL }},
        { &hf_ipcp_opt_max_header,
            { "Max Header", "ipcp.opt.max_header", FT_UINT16, BASE_DEC, NULL,
                0x0,
                "The largest header size in octets that may be compressed",
                HFILL }},
        { &hf_ipcp_data,
            { "Data", "ipcp.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_ip_address,
            { "IP Address", "ipcp.opt.ip_address", FT_IPv4, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_mobilenodehomeaddr,
            { "Mobile Node's Home Address", "ipcp.opt.mobilenodehomeaddress",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_pri_dns_address,
            { "Primary DNS Address", "ipcp.opt.pri_dns_address",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_pri_nbns_address,
            { "Primary NBNS Address", "ipcp.opt.pri_nbns_address",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_sec_dns_address,
            { "Secondary DNS Address", "ipcp.opt.sec_dns_address",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_sec_nbns_address,
            { "Secondary NBNS Address", "ipcp.opt.sec_nbns_address",
                FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_rohc_type,
            { "Type", "ipcp.opt.rohc.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_rohc_length,
            { "Length", "ipcp.opt.rohc.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_rohc_profile,
            { "Profile", "ipcp.opt.rohc.profile", FT_UINT16, BASE_HEX,
                VALS(ipcp_rohc_profile_vals), 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_iphc_type,
            { "Type", "ipcp.opt.iphc.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_iphc_length,
            { "Length", "ipcp.opt.iphc.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ipcp_opt_iphc_param,
            { "Parameter", "ipcp.opt.iphc.param", FT_UINT8, BASE_DEC,
                VALS(ipcp_iphc_parameter_vals), 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_ipcp,
        &ett_ipcp_options,
        &ett_ipcp_ipaddrs_opt,
        &ett_ipcp_compress_opt,
        &ett_ipcp_ipaddr_opt,
        &ett_ipcp_mobileipv4_opt,
        &ett_ipcp_pridns_opt,
        &ett_ipcp_secdns_opt,
        &ett_ipcp_prinbns_opt,
        &ett_ipcp_secnbns_opt,
        &ett_ipcp_iphc_rtp_compress_opt,
        &ett_ipcp_iphc_enhanced_rtp_compress_opt,
        &ett_ipcp_iphc_neghdrcomp_opt,
        &ett_ipcp_rohc_profiles_opt
    };

    proto_ipcp = proto_register_protocol("PPP IP Control Protocol", "PPP IPCP",
        "ipcp");
    proto_register_field_array(proto_ipcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipcp(void)
{
    dissector_handle_t ipcp_handle;

    ipcp_handle = create_dissector_handle(dissect_ipcp, proto_ipcp);
    dissector_add_uint("ppp.protocol", PPP_IPCP, ipcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_IPCP, ipcp_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_IPCP, ipcp_handle);
}

void
proto_register_bcp(void)
{
    static hf_register_info hf[] = {
        { &hf_bcp_flags,
            { "Flags", "bcp.flags", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_bcp_fcs_present,
            { "LAN FCS present", "bcp.flags.fcs_present", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), BCP_FCS_PRESENT, NULL, HFILL }},
        { &hf_bcp_zeropad,
            { "802.3 pad zero-filled", "bcp.flags.zeropad", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), BCP_ZEROPAD, NULL, HFILL }},
        { &hf_bcp_bcontrol,
            { "Bridge control", "bcp.flags.bcontrol", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), BCP_IS_BCONTROL, NULL, HFILL }},
        { &hf_bcp_pads,
            { "Pads", "bcp.pads", FT_UINT8, BASE_DEC,
                NULL, BCP_PADS_MASK, NULL, HFILL }},
        { &hf_bcp_mac_type,
            { "MAC Type", "bcp.mac_type", FT_UINT8, BASE_DEC,
                VALS(bcp_mac_type_vals), 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_bcp,
        &ett_bcp_flags
    };

    proto_bcp = proto_register_protocol("PPP Bridging Control Protocol",
        "PPP BCP", "bcp");
    proto_register_field_array(proto_bcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_register_osinlcp(void)
{
    static hf_register_info hf[] = {
        { &hf_osinlcp_opt_type,
            { "Type", "osinlcp.opt.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_osinlcp_opt_length,
            { "Length", "osinlcp.opt.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_osinlcp_opt_alignment,
            { "Alignment", "osinlcp.opt.alignment", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_osinlcp,
        &ett_osinlcp_options,
        &ett_osinlcp_align_npdu_opt
    };

    proto_osinlcp = proto_register_protocol(
        "PPP OSI Network Layer Control Protocol", "PPP OSINLCP", "osinlcp");
    proto_register_field_array(proto_osinlcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bcp(void)
{
    dissector_handle_t bcp_handle;

    eth_withfcs_handle    = find_dissector("eth_withfcs");
    eth_withoutfcs_handle = find_dissector("eth_withoutfcs");

    bcp_handle = create_dissector_handle(dissect_bcp, proto_bcp);
    dissector_add_uint("ppp.protocol", PPP_BCP, bcp_handle);
}

void
proto_reg_handoff_osinlcp(void)
{
    dissector_handle_t osinlcp_handle;

    osinlcp_handle = create_dissector_handle(dissect_osinlcp, proto_osinlcp);
    dissector_add_uint("ppp.protocol", PPP_OSINLCP, osinlcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_OSINLCP, osinlcp_handle);
}

void
proto_register_ccp(void)
{
    static hf_register_info hf[] = {
        { &hf_ccp_opt_type,
            { "Type", "ccp.opt.type", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_length,
            { "Length", "ccp.opt.length", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_oui,
            { "OUI", "ccp.opt.oui", FT_UINT24, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_subtype,
            { "Subtype", "ccp.opt.subtype", FT_UINT8, BASE_DEC_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_history_count,
            { "History Count", "ccp.opt.history_count", FT_UINT16, BASE_DEC,
                NULL, 0x0, "The maximum number of compression histories",
                HFILL }},
        { &hf_ccp_opt_cm,
            { "Check Mode Field", "ccp.opt.cm", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_cm_reserved,
            { "Reserved", "ccp.opt.cm.reserved", FT_UINT8, BASE_DEC,
                NULL, 0xF8, NULL, HFILL }},
        { &hf_ccp_opt_cm_check_mode,
            { "Check Mode", "ccp.opt.cm.check_mode", FT_UINT8, BASE_DEC,
                VALS(stac_checkmode_vals), 0x07, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits,
            { "Supported Bits", "ccp.opt.supported_bits", FT_UINT32, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_h,
            { "H", "ccp.opt.supported_bits.h", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_h_tfs), MPPE_SUPPORTED_BITS_H, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_m,
            { "M", "ccp.opt.supported_bits.m", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_m_tfs), MPPE_SUPPORTED_BITS_M, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_s,
            { "S", "ccp.opt.supported_bits.s", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_s_tfs), MPPE_SUPPORTED_BITS_S, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_l,
            { "L", "ccp.opt.supported_bits.l", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_l_tfs), MPPE_SUPPORTED_BITS_L, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_d,
            { "D", "ccp.opt.supported_bits.d", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_d_tfs), MPPE_SUPPORTED_BITS_D, NULL, HFILL }},
        { &hf_ccp_opt_supported_bits_c,
            { "C", "ccp.opt.supported_bits.c", FT_BOOLEAN, 32,
                TFS(&ccp_mppe_c_tfs), MPPC_SUPPORTED_BITS_C, NULL, HFILL }},
        { &hf_ccp_opt_history,
            { "History", "ccp.opt.history", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Maximum size of the compression history in powers of 2",
                HFILL }},
        { &hf_ccp_opt_version,
            { "Version", "ccp.opt.version", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_vd,
            { "Vers/Dict", "ccp.opt.vd", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_vd_vers,
            { "Vers", "ccp.opt.vd.vers", FT_UINT8, BASE_DEC,
                NULL, 0xE0, NULL, HFILL }},
        { &hf_ccp_opt_vd_dict,
            { "Dict", "ccp.opt.vd.dict", FT_UINT8, BASE_DEC, NULL,
                0x1F, "The size in bits of the largest code used", HFILL }},
        { &hf_ccp_opt_check_mode,
            { "Check Mode", "ccp.opt.check_mode", FT_UINT8, BASE_DEC,
                VALS(&lzsdcp_checkmode_vals), 0x0, NULL, HFILL }},
        { &hf_ccp_opt_process_mode,
            { "Process Mode", "ccp.opt.process_mode", FT_UINT8, BASE_DEC,
                VALS(&lzsdcp_processmode_vals), 0x0, NULL, HFILL }},
        { &hf_ccp_opt_fe,
            { "Features", "ccp.opt.fe", FT_UINT8, BASE_DEC,
                NULL, 0xC0, NULL, HFILL }},
        { &hf_ccp_opt_p,
            { "Packet by Packet flag", "ccp.opt.p", FT_BOOLEAN, 8,
                TFS(&tfs_enabled_disabled), 0x20, NULL, HFILL }},
        { &hf_ccp_opt_History,
            { "History", "ccp.opt.History", FT_UINT8, BASE_DEC,
                NULL, 0x1F, NULL, HFILL }},
        { &hf_ccp_opt_contexts,
            { "# Contexts", "ccp.opt.contexts", FT_UINT8, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_mode,
            { "Mode", "ccp.opt.mode", FT_UINT8, BASE_DEC,
                VALS(&dce_mode_vals), 0x0, NULL, HFILL }},
        { &hf_ccp_opt_window,
            { "Window", "ccp.opt.window", FT_UINT8, BASE_DEC,
                NULL, 0xF0, NULL, HFILL }},
        { &hf_ccp_opt_method,
            { "Method", "ccp.opt.method", FT_UINT8, BASE_DEC,
                VALS(&deflate_method_vals), 0x0F, NULL, HFILL }},
        { &hf_ccp_opt_mbz,
            { "MBZ", "ccp.opt.mbz", FT_UINT8, BASE_DEC,
                NULL, 0xFC, NULL, HFILL }},
        { &hf_ccp_opt_chk,
            { "Chk", "ccp.opt.chk", FT_UINT8, BASE_DEC,
                VALS(&deflate_chk_vals), 0x03, NULL, HFILL }},
        { &hf_ccp_opt_mode_dictcount,
            { "Mode/Dictionary Count", "ccp.opt.mode_dictcount", FT_UINT16,
                BASE_DEC | BASE_RANGE_STRING, RVALS(v44lzjh_mode_dict_rvals),
                0x0, NULL, HFILL }},
        { &hf_ccp_opt_dict_size,
            { "Dictionary Size", "ccp.opt.dict_size", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_history_length,
            { "History Length", "ccp.opt.history_length", FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL }},
        { &hf_ccp_opt_data,
            { "Data", "ccp.opt.data", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
    };
    static gint *ett[] = {
        &ett_ccp,
        &ett_ccp_options,
        &ett_ccp_oui_opt,
        &ett_ccp_predict1_opt,
        &ett_ccp_predict2_opt,
        &ett_ccp_puddle_opt,
        &ett_ccp_hpppc_opt,
        &ett_ccp_stac_opt,
        &ett_ccp_stac_opt_check_mode,
        &ett_ccp_mppe_opt,
        &ett_ccp_mppe_opt_supp_bits,
        &ett_ccp_gfza_opt,
        &ett_ccp_v42bis_opt,
        &ett_ccp_bsdcomp_opt,
        &ett_ccp_lzsdcp_opt,
        &ett_ccp_mvrca_opt,
        &ett_ccp_dce_opt,
        &ett_ccp_deflate_opt,
        &ett_ccp_v44lzjh_opt
    };

    proto_ccp = proto_register_protocol("PPP Compression Control Protocol",
        "PPP CCP", "ccp");
    proto_register_field_array(proto_ccp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ccp(void)
{
    dissector_handle_t ccp_handle;

    ccp_handle = create_dissector_handle(dissect_ccp, proto_ccp);
    dissector_add_uint("ppp.protocol", PPP_CCP, ccp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_CCP, ccp_handle);
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
    dissector_add_uint("ppp.protocol", PPP_CBCP, cbcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_CBCP, cbcp_handle);
}

void
proto_register_bacp(void)
{
    static gint *ett[] = {
        &ett_bacp,
        &ett_bacp_options,
        &ett_bacp_favored_peer_opt
    };

    proto_bacp = proto_register_protocol(
        "PPP Bandwidth Allocation Control Protocol", "PPP BACP", "bacp");
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bacp(void)
{
    dissector_handle_t bacp_handle;

    bacp_handle = create_dissector_handle(dissect_bacp, proto_bacp);
    dissector_add_uint("ppp.protocol", PPP_BACP, bacp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_BACP, bacp_handle);
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
    dissector_add_uint("ppp.protocol", PPP_BAP, bap_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_BAP, bap_handle);
}

void
proto_register_comp_data(void)
{
#if 0 /* See dissect_comp_data() */
    static gint *ett[] = {
        &ett_comp_data
    };
#endif

    proto_comp_data = proto_register_protocol("PPP Compressed Datagram",
        "PPP Comp", "comp_data");
#if 0
    proto_register_subtree_array(ett, array_length(ett));
#endif
}

void
proto_reg_handoff_comp_data(void)
{
    dissector_handle_t comp_data_handle;

    comp_data_handle = create_dissector_handle(dissect_comp_data,
        proto_comp_data);
    dissector_add_uint("ppp.protocol", PPP_COMP, comp_data_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_COMP, comp_data_handle);
}

void
proto_register_pap(void)
{
    static gint *ett[] = {
        &ett_pap,
        &ett_pap_data
    };

    static hf_register_info hf[] = {
        { &hf_pap_code,
            { "Code", "pap.code", FT_UINT8, BASE_DEC, VALS(pap_vals), 0x0,
                "The Code field is one octet and identifies the type of PAP "
                "packet", HFILL }},
        { &hf_pap_identifier,
            { "Identifier", "pap.identifier", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The Identifier field is one octet and aids in matching "
                "requests and replies.", HFILL }},
        { &hf_pap_length,
            { "Length", "pap.length", FT_UINT16, BASE_DEC, NULL, 0x0,
                "The Length field is two octets and indicates the length of "
                "the PAP packet", HFILL }},
        { &hf_pap_data,
            { "Data", "pap.data", FT_NONE, BASE_NONE, NULL, 0x0,
                "The format of the Data field is determined by the Code field",
                HFILL }},
        { &hf_pap_peer_id_length,
            { "Peer-ID-Length", "pap.peer_id.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "The Peer-ID-Length field is one octet and indicates the "
                "length of the Peer-ID field", HFILL }},
        { &hf_pap_peer_id,
            { "Peer-ID", "pap.peer_id", FT_STRING, BASE_NONE, NULL, 0x0,
                "The Peer-ID field is zero or more octets and indicates the "
                "name of the peer to be authenticated", HFILL }},
        { &hf_pap_password_length,
            { "Password-Length", "pap.password.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "The Password-Length field is one octet and indicates the "
                "length of the Password field", HFILL }},
        { &hf_pap_password,
            { "Password", "pap.password", FT_STRING, BASE_NONE, NULL, 0x0,
                "The Password field is zero or more octets and indicates the "
                "password to be used for authentication", HFILL }},
        { &hf_pap_message_length,
            { "Message-Length", "pap.message.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "The Message-Length field is one octet and indicates the "
                "length of the Message field", HFILL }},
        { &hf_pap_message,
            { "Message", "pap.message", FT_STRING, BASE_NONE, NULL, 0x0,
                "The Message field is zero or more octets, and its contents "
                "are implementation dependent.", HFILL }},
        { &hf_pap_stuff,
            { "stuff", "pap.stuff", FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL }}
    };

    proto_pap = proto_register_protocol("PPP Password Authentication Protocol",
        "PPP PAP", "pap");
    proto_register_field_array(proto_pap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pap(void)
{
    dissector_handle_t pap_handle;

    pap_handle = create_dissector_handle(dissect_pap, proto_pap);
    dissector_add_uint("ppp.protocol", PPP_PAP, pap_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_PAP, pap_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_PAP, pap_handle);
}

void
proto_register_chap(void)
{
    static gint *ett[] = {
        &ett_chap,
        &ett_chap_data
    };

    static hf_register_info hf[] = {
        { &hf_chap_code,
            { "Code", "chap.code", FT_UINT8, BASE_DEC, VALS(chap_vals), 0x0,
                "CHAP code", HFILL }},
        { &hf_chap_identifier,
            { "Identifier", "chap.identifier", FT_UINT8, BASE_DEC, NULL, 0x0,
                "CHAP identifier", HFILL }},
        { &hf_chap_length,
            { "Length", "chap.length", FT_UINT16, BASE_DEC, NULL, 0x0,
                "CHAP length", HFILL  }},
        { &hf_chap_data,
            { "Data", "chap.data", FT_NONE, BASE_NONE, NULL, 0x0,
                "CHAP Data", HFILL }},
         { &hf_chap_value_size,
            { "Value Size", "chap.value_size", FT_UINT8, BASE_DEC, NULL, 0x0,
                "CHAP value size", HFILL }},
        { &hf_chap_value,
            { "Value", "chap.value", FT_BYTES, BASE_NONE, NULL, 0x0,
                "CHAP value data", HFILL }},
        { &hf_chap_name,
            { "Name", "chap.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "CHAP name", HFILL }},
        { &hf_chap_message,
            { "Message", "chap.message", FT_STRING, BASE_NONE, NULL, 0x0,
                "CHAP message", HFILL }}
        };

    proto_chap = proto_register_protocol(
        "PPP Challenge Handshake Authentication Protocol", "PPP CHAP", "chap");
    proto_register_field_array(proto_chap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_chap(void)
{
    dissector_handle_t chap_handle = create_dissector_handle(dissect_chap,
        proto_chap);
    dissector_add_uint("ppp.protocol", PPP_CHAP, chap_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_CHAP, chap_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_CHAP, chap_handle);
}

void
proto_register_pppmuxcp(void)
{
    static hf_register_info hf[] = {
        { &hf_pppmux_flags_pid,
            { "PID", "pppmuxcp.flags.pid", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80,
                NULL, HFILL }},
        { &hf_pppmux_flags_field_length,
            { "Length field", "pppmuxcp.flags.field_length", FT_BOOLEAN, 8, TFS(&tfs_pppmux_length_field), 0x40,
                NULL, HFILL }},
        };

    static gint *ett[] = {
        &ett_pppmuxcp,
        &ett_pppmuxcp_options
    };

    proto_pppmuxcp = proto_register_protocol("PPPMux Control Protocol",
        "PPP PPPMuxCP", "pppmuxcp");
    proto_register_field_array(proto_pppmuxcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_pppmuxcp(void)
{
    dissector_handle_t muxcp_handle;

    muxcp_handle = create_dissector_handle(dissect_pppmuxcp, proto_pppmuxcp);
    dissector_add_uint("ppp.protocol", PPP_MUXCP, muxcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_MUXCP, muxcp_handle);
}


void
proto_register_pppmux(void)
{
    static hf_register_info hf[] = {
        { &hf_pppmux_protocol,
            { "Protocol", "pppmux.protocol", FT_UINT16,
                BASE_HEX|BASE_EXT_STRING, &ppp_vals_ext, 0x0,
                "The protocol of the sub-frame.", HFILL }}
    };

    static gint *ett[] = {
        &ett_pppmux,
        &ett_pppmux_subframe,
        &ett_pppmux_subframe_hdr,
        &ett_pppmux_subframe_flags,
        &ett_pppmux_subframe_info
    };

    proto_pppmux = proto_register_protocol("PPP Multiplexing", "PPP PPPMux",
        "pppmux");
    proto_register_field_array(proto_pppmux, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pppmux(void)
{
    dissector_handle_t pppmux_handle;

    pppmux_handle = create_dissector_handle(dissect_pppmux, proto_pppmux);
    dissector_add_uint("ppp.protocol", PPP_MUX, pppmux_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_MUX, pppmux_handle);
}

void
proto_register_mplscp(void)
{
    static gint *ett[] = {
        &ett_mplscp,
        &ett_mplscp_options
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
    dissector_add_uint("ppp.protocol", PPP_MPLSCP, mplscp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_MPLSCP, mplscp_handle);
}

void
proto_register_cdpcp(void)
{
    static gint *ett[] = {
        &ett_cdpcp,
        &ett_cdpcp_options
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
    dissector_add_uint("ppp.protocol", PPP_CDPCP, cdpcp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_CDPCP, cdpcp_handle);
}

void
proto_register_ipv6cp(void)
{
    static gint *ett[] = {
        &ett_ipv6cp,
        &ett_ipv6cp_options,
        &ett_ipv6cp_if_id_opt,
        &ett_ipv6cp_compress_opt
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
    dissector_add_uint("ppp.protocol", PPP_IPV6CP, ipv6cp_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_IPV6CP, ipv6cp_handle);

    /*
     * for GSM-A / MobileL3 / GPRS SM / PCO
     */
    dissector_add_uint("sm_pco.protocol", PPP_IPV6CP, ipv6cp_handle);
}

void
proto_register_iphc_crtp(void)
{
    static hf_register_info hf[] = {
        { &hf_iphc_crtp_cid16,
            { "Context Id", "crtp.cid", FT_UINT16, BASE_DEC, NULL, 0x0,
                "The context identifier of the compressed packet.", HFILL }},
        { &hf_iphc_crtp_cid8,
            { "Context Id", "crtp.cid", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The context identifier of the compressed packet.", HFILL }},
        { &hf_iphc_crtp_gen,
            { "Generation", "crtp.gen", FT_UINT8, BASE_DEC, NULL, 0x3f,
                "The generation of the compressed packet.", HFILL }},
        { &hf_iphc_crtp_seq,
            { "Sequence", "crtp.seq", FT_UINT8, BASE_DEC, NULL, 0x0f,
                "The sequence of the compressed packet.", HFILL }},
        { &hf_iphc_crtp_fh_flags,
            { "Flags", "crtp.fh_flags", FT_UINT8, BASE_HEX, iphc_crtp_fh_flags,
                0xc0, "The flags of the full header packet.", HFILL }},
        { &hf_iphc_crtp_cs_flags,
            { "Flags", "crtp.cs_flags", FT_UINT8, BASE_DEC, iphc_crtp_cs_flags,
                0x0, "The flags of the context state packet.", HFILL }},
        { &hf_iphc_crtp_cs_cnt,
            { "Count", "crtp.cnt", FT_UINT8, BASE_DEC, NULL, 0x0,
                "The count of the context state packet.", HFILL }},
        { &hf_iphc_crtp_cs_invalid,
            { "Invalid", "crtp.invalid", FT_BOOLEAN, 8, NULL, 0x80,
                "The invalid bit of the context state packet.", HFILL }}
        };

    static gint *ett[] = {
        &ett_iphc_crtp,
        &ett_iphc_crtp_hdr,
        &ett_iphc_crtp_info
    };

    proto_iphc_crtp = proto_register_protocol("CRTP", "CRTP", "crtp");
    proto_register_field_array(proto_iphc_crtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_iphc_crtp(void)
{
    dissector_handle_t fh_handle;
    dissector_handle_t cudp16_handle;
    dissector_handle_t cudp8_handle;
    dissector_handle_t cs_handle;

    fh_handle = create_dissector_handle(dissect_iphc_crtp_fh, proto_iphc_crtp);
    dissector_add_uint("ppp.protocol", PPP_RTP_FH, fh_handle);

    cudp16_handle = create_dissector_handle(dissect_iphc_crtp_cudp16,
        proto_iphc_crtp);
    dissector_add_uint("ppp.protocol", PPP_RTP_CUDP16, cudp16_handle);

    cudp8_handle = create_dissector_handle(dissect_iphc_crtp_cudp8,
        proto_iphc_crtp);
    dissector_add_uint("ppp.protocol", PPP_RTP_CUDP8, cudp8_handle);

    cs_handle = create_dissector_handle(dissect_iphc_crtp_cs, proto_iphc_crtp);
    dissector_add_uint("ppp.protocol", PPP_RTP_CS, cs_handle);

    /*
     * See above comment about NDISWAN for an explanation of why we're
     * registering with the "ethertype" dissector table.
     */
    dissector_add_uint("ethertype", PPP_RTP_FH, fh_handle);
    dissector_add_uint("ethertype", PPP_RTP_CUDP16, cudp16_handle);
    dissector_add_uint("ethertype", PPP_RTP_CUDP8, cudp16_handle);
    dissector_add_uint("ethertype", PPP_RTP_CS, cs_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
