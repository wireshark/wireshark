/* packet-ppp.c
 * Routines for ppp packet disassembly
 *
 * $Id: packet-ppp.c,v 1.58 2001/03/29 09:18:34 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
#include "packet-ipv6.h"
#include "packet-ipx.h"
#include "packet-vines.h"
#include "nlpid.h"

static int proto_ppp = -1;

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

static int proto_mp = -1;
static int hf_mp_frag_first = -1;
static int hf_mp_frag_last = -1;
static int hf_mp_sequence_num = -1;

static int ett_mp = -1;
static int ett_mp_flags = -1;

static dissector_table_t subdissector_table;
static dissector_handle_t chdlc_handle;

/* options */
static gint ppp_fcs_decode = 0; /* 0 = No FCS, 1 = 16 bit FCS, 2 = 32 bit FCS */
#define NO_FCS 0
#define FCS_16 1
#define FCS_32 2

/* PPP definitions */

static const value_string ppp_vals[] = {
	{PPP_IP,        "IP"             },
	{PPP_AT,        "Appletalk"      },
	{PPP_IPX,       "Netware IPX/SPX"},
	{PPP_VJC_COMP,	"VJ compressed TCP"},
	{PPP_VJC_UNCOMP,"VJ uncompressed TCP"},
	{PPP_BPDU,      "Bridging PDU"},
	{PPP_VINES,     "Vines"          },
        {PPP_MP,	"Multilink"},
	{PPP_IPV6,      "IPv6"           },
	{PPP_COMP,	"compressed packet" },
	{PPP_DEC_LB,	"DEC LANBridge100 Spanning Tree"},
	{PPP_MPLS_UNI,  "MPLS Unicast"},
	{PPP_MPLS_MULTI, "MPLS Multicast"},
	{PPP_IPCP,	"IP Control Protocol" },
	{PPP_ATCP,	"AppleTalk Control Protocol" },
	{PPP_IPXCP,	"IPX Control Protocol" },
	{PPP_CCP,	"Compression Control Protocol" },
	{PPP_LCP,	"Link Control Protocol" },
	{PPP_PAP,	"Password Authentication Protocol"  },
	{PPP_LQR,	"Link Quality Report protocol" },
	{PPP_CHAP,	"Cryptographic Handshake Auth. Protocol" },
	{PPP_CBCP,	"Callback Control Protocol" },
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

#define CBCP_OPT  6 /* Use callback control protocol */

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
			int offset, guint length, frame_data *fd,
			proto_tree *tree);
static void dissect_lcp_async_map_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, frame_data *fd,
			proto_tree *tree);
static void dissect_lcp_protocol_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, frame_data *fd,
			proto_tree *tree);
static void dissect_lcp_magicnumber_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			frame_data *fd, proto_tree *tree);
static void dissect_lcp_fcs_alternatives_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			frame_data *fd, proto_tree *tree);
static void dissect_lcp_numbered_mode_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			frame_data *fd, proto_tree *tree);
static void dissect_lcp_self_describing_pad_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			frame_data *fd, proto_tree *tree);
static void dissect_lcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, frame_data *fd,
			proto_tree *tree);
static void dissect_lcp_multilink_mrru_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			frame_data *fd, proto_tree *tree);
static void dissect_lcp_multilink_ep_disc_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			frame_data *fd, proto_tree *tree);
static void dissect_lcp_bap_link_discriminator_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			frame_data *fd, proto_tree *tree);
static void dissect_lcp_internationalization_opt(const ip_tcp_opt *optp,
			tvbuff_t *tvb, int offset, guint length,
			frame_data *fd, proto_tree *tree);
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
		dissect_lcp_protocol_opt
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
			int offset, guint length, frame_data *fd,
			proto_tree *tree);
static void dissect_ipcp_addr_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, frame_data *fd,
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

static void dissect_payload_ppp(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree);

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
capture_ppp( const u_char *pd, int offset, packet_counts *ld ) {
  if (pd[0] == CHDLC_ADDR_UNICAST || pd[0] == CHDLC_ADDR_MULTICAST) {
    capture_chdlc(pd, offset, ld);
    return;
  }
  switch (pntohs(&pd[offset + 2])) {
    case PPP_IP:
      capture_ip(pd, offset + 4, ld);
      break;
    case PPP_IPX:
      capture_ipx(pd, offset + 4, ld);
      break;
    case PPP_VINES:
      capture_vines(pd, offset + 4, ld);
      break;
    default:
      ld->other++;
      break;
  }
}

static void
dissect_lcp_mru_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, frame_data *fd, proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "MRU: %u",
			tvb_get_ntohs(tvb, offset + 2));
}

static void
dissect_lcp_async_map_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, frame_data *fd, proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "Async characters to map: 0x%08x",
			tvb_get_ntohl(tvb, offset + 2));
}

static void
dissect_lcp_protocol_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, frame_data *fd, proto_tree *tree)
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
dissect_lcp_magicnumber_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, frame_data *fd,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "Magic number: 0x%08x",
			tvb_get_ntohl(tvb, offset + 2));
}

static void
dissect_lcp_fcs_alternatives_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, frame_data *fd,
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
			int offset, guint length, frame_data *fd,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length,
			"Maximum octets of self-describing padding: %u",
			tvb_get_guint8(tvb, offset + 2));
}

static void
dissect_lcp_numbered_mode_opt(const ip_tcp_opt *optp, tvbuff_t *tvb,
			int offset, guint length, frame_data *fd,
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
	{0, NULL }
};

static void
dissect_lcp_callback_opt(const ip_tcp_opt *optp, tvbuff_t *tvb, int offset,
			guint length, frame_data *fd, proto_tree *tree)
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
			int offset, guint length, frame_data *fd,
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
			int offset, guint length, frame_data *fd,
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
			int offset, guint length, frame_data *fd,
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
			int offset, guint length, frame_data *fd,
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
			int offset, guint length, frame_data *fd,
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
			int offset, guint length, frame_data *fd,
			proto_tree *tree)
{
  proto_tree_add_text(tree, tvb, offset, length, "%s: %s", optp->name,
			ip_to_str(tvb_get_ptr(tvb, offset + 2, 4)));
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

  if(check_col(pinfo->fd, COL_INFO))
	col_add_fstr(pinfo->fd, COL_INFO, "%s %s",
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
				 pinfo->fd, field_tree);
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
dissect_ppp_stuff( tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree, proto_tree *fh_tree,
		proto_item *ti ) {
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
     for PPP, and was given a length equal to the length of any
     stuff in the header preceding the protocol type, e.g. an HDLC
     header; add the length of the protocol type field to it. */
  if (ti != NULL)
    proto_item_set_len(ti, proto_item_get_len(ti) + proto_len);

  if (tree) {
    proto_tree_add_text(fh_tree, tvb, 0, proto_len, "Protocol: %s (0x%04x)",
      val_to_str(ppp_prot, ppp_vals, "Unknown"), ppp_prot);
  }

  next_tvb = tvb_new_subset(tvb, proto_len, -1, -1);

  /* do lookup with the subdissector table */
  if (!dissector_try_port(subdissector_table, ppp_prot, next_tvb, pinfo, tree)) {
    if (check_col(pinfo->fd, COL_PROTOCOL))
      col_add_fstr(pinfo->fd, COL_PROTOCOL, "0x%04x", ppp_prot);
    if (check_col(pinfo->fd, COL_INFO))
      col_add_fstr(pinfo->fd, COL_INFO, "PPP %s (0x%04x)",
		   val_to_str(ppp_prot, ppp_vals, "Unknown"), ppp_prot);
    dissect_data(next_tvb, 0, pinfo, tree);
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

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "PPP MP");

  if (check_col(pinfo->fd, COL_INFO))
    col_set_str(pinfo->fd, COL_INFO, "PPP Multilink");

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
    dissect_payload_ppp(next_tvb, pinfo, tree);
  }
}

/*
 * Handles PPP without HDLC headers, just a protocol field.
 */
static void
dissect_payload_ppp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree ) {
  proto_item *ti = NULL;
  proto_tree *fh_tree = NULL;

  if(tree) {
    ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, 0, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_ppp);
  }

  dissect_ppp_stuff(tvb, pinfo, tree, fh_tree, ti);
}

/*
 * Handles link-layer encapsulations where the frame might be:
 *
 *	a PPP frame with no HDLC header;
 *
 *	a PPP frame with an HDLC header (FF 03);
 *
 *	a Cisco HDLC frame.
 */
static void
dissect_ppp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree ) {
  proto_item *ti = NULL;
  proto_tree *fh_tree = NULL;
  guint8     byte0;
  int        proto_offset;
  tvbuff_t   *next_tvb;
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

  if(check_col(pinfo->fd, COL_RES_DL_SRC))
    col_set_str(pinfo->fd, COL_RES_DL_SRC, "N/A" );
  if(check_col(pinfo->fd, COL_RES_DL_DST))
    col_set_str(pinfo->fd, COL_RES_DL_DST, "N/A" );
  if(check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "PPP" );

  if(tree) {
    ti = proto_tree_add_item(tree, proto_ppp, tvb, 0, proto_offset, FALSE);
    fh_tree = proto_item_add_subtree(ti, ett_ppp);
    if (byte0 == 0xff) {
      proto_tree_add_text(fh_tree, tvb, 0, 1, "Address: %02x",
			  tvb_get_guint8(tvb, 0));
      proto_tree_add_text(fh_tree, tvb, 1, 1, "Control: %02x",
			  tvb_get_guint8(tvb, 1));
    }
  }

  next_tvb = tvb_new_subset(tvb, proto_offset, -1, -1);
  dissect_ppp_stuff(next_tvb, pinfo, tree, fh_tree, ti);

  /* Calculate the FCS check */
  /* XXX - deal with packets cut off by the snapshot length */
  if (ppp_fcs_decode == FCS_16) {
    rx_fcs_offset = tvb_length(tvb) - 2;
    rx_fcs_exp = fcs16(0xFFFF, tvb, 0, rx_fcs_offset);
    rx_fcs_got = tvb_get_letohs(tvb, rx_fcs_offset);
    if (rx_fcs_got != rx_fcs_exp) {
      proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 2, "FCS 16: %04x (incorrect, should be %04x)", rx_fcs_got, rx_fcs_exp);
    } else {
      proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 2, "FCS 16: %04x (correct)", rx_fcs_got);
    }
  } else if (ppp_fcs_decode == FCS_32) {
    rx_fcs_offset = tvb_length(tvb) - 4;
    rx_fcs_exp = fcs32(0xFFFFFFFF, tvb, 0, rx_fcs_offset);
    rx_fcs_got = tvb_get_letohl(tvb, rx_fcs_offset);
    if (rx_fcs_got != rx_fcs_exp) {
      proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 4, "FCS 32: %08x (incorrect, should be %08x) ", rx_fcs_got, rx_fcs_exp);
    } else {
      proto_tree_add_text(fh_tree, tvb, rx_fcs_offset, 4, "FCS 32: %08x (correct)", rx_fcs_got);
    }
  }
}

void
proto_register_ppp(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "ppp.abbreviation", TYPE, VALS_POINTER }},
        };*/
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

        proto_ppp = proto_register_protocol("Point-to-Point Protocol",
	    "PPP", "ppp");
 /*       proto_register_field_array(proto_ppp, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));

/* subdissector code */
	subdissector_table = register_dissector_table("ppp.protocol");

	register_dissector("ppp", dissect_ppp, proto_ppp);
	register_dissector("payload_ppp", dissect_payload_ppp, proto_ppp);

	/* Register the preferences for the ppp protocol */
	ppp_module = prefs_register_protocol(proto_ppp, NULL);

	prefs_register_enum_preference(ppp_module, 
	    "ppp_fcs",
	    "PPP Frame Checksum",
	    "PPP Frame Checksum", 
	    &ppp_fcs_decode,
	    ppp_options, FALSE);
}

void
proto_reg_handoff_ppp(void)
{
  /*
   * Get a handle for the CHDLC dissector.
   */
  chdlc_handle = find_dissector("chdlc");

  dissector_add("wtap_encap", WTAP_ENCAP_PPP, dissect_ppp, proto_ppp);
  dissector_add("wtap_encap", WTAP_ENCAP_PPP_WITH_PHDR, dissect_ppp, proto_ppp);
  dissector_add("fr.ietf", NLPID_PPP, dissect_ppp, proto_ppp);
  dissector_add("gre.proto", ETHERTYPE_PPP, dissect_ppp, proto_ppp);
}

void
proto_register_mp(void)
{
  static hf_register_info hf[] = {
    { &hf_mp_frag_first,
    { "First fragment",		"mp.first",	FT_BOOLEAN, 8,
        TFS(&frag_truth), MP_FRAG_FIRST, "" }},

    { &hf_mp_frag_last,
    { "Last fragment",		"mp.last",	FT_BOOLEAN, 8,
        TFS(&frag_truth), MP_FRAG_LAST, "" }},

    { &hf_mp_sequence_num,
    { "Sequence number",	"mp.seq",	FT_UINT24, BASE_DEC, NULL, 0x0,
    	"" }}
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
  dissector_add("ppp.protocol", PPP_MP, dissect_mp, proto_mp);
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
  dissector_add("ppp.protocol", PPP_LCP, dissect_lcp, proto_lcp);
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
  dissector_add("ppp.protocol", PPP_IPCP, dissect_ipcp, proto_ipcp);
}
