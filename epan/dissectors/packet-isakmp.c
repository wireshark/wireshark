/* packet-isakmp.c
 * Routines for the Internet Security Association and Key Management Protocol
 * (ISAKMP) (RFC 2408) and the Internet IP Security Domain of Interpretation
 * for ISAKMP (RFC 2407)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * Added routines for the Internet Key Exchange (IKEv2) Protocol
 * (draft-ietf-ipsec-ikev2-17.txt)
 * Shoichi Sakane <sakane@tanu.org>
 *
 * Added routines for RFC3947 Negotiation of NAT-Traversal in the IKE
 *   ronnie sahlberg
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

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/dissectors/packet-x509if.h>
#include <epan/dissectors/packet-isakmp.h>

#define isakmp_min(a, b)  ((a<b) ? a : b)

#define ARLEN(a) (sizeof(a)/sizeof(a[0]))

static int proto_isakmp = -1;
static int hf_ike_certificate_authority = -1;
static int hf_ike_v2_certificate_authority = -1;
static int hf_ike_nat_keepalive = -1;

static gint ett_isakmp = -1;
static gint ett_isakmp_flags = -1;
static gint ett_isakmp_payload = -1;

/* IKE port number assigned by IANA */
#define UDP_PORT_ISAKMP	500
#define TCP_PORT_ISAKMP 500

/*
 * Identifier Type 
 *   RFC2407 for IKEv1
 *   draft-ietf-ipsec-ikev2-17.txt for IKEv2
 */
#define IKE_ID_IPV4_ADDR		1
#define IKE_ID_FQDN			2
#define IKE_ID_USER_FQDN		3
#define IKE_ID_IPV4_ADDR_SUBNET		4
#define IKE_ID_IPV6_ADDR		5
#define IKE_ID_IPV6_ADDR_SUBNET		6
#define IKE_ID_IPV4_ADDR_RANGE		7
#define IKE_ID_IPV6_ADDR_RANGE		8
#define IKE_ID_DER_ASN1_DN		9
#define IKE_ID_DER_ASN1_GN		10
#define IKE_ID_KEY_ID			11

/*
 * Traffic Selector Type
 *   Not in use for IKEv1
 */
#define IKEV2_TS_IPV4_ADDR_RANGE	7
#define IKEV2_TS_IPV6_ADDR_RANGE	8

static const value_string vs_proto[] = {
  { 0,	"RESERVED" },
  { 1,	"ISAKMP" },
  { 2,	"IPSEC_AH" },
  { 3,	"IPSEC_ESP" },
  { 4,	"IPCOMP" },
  { 0,	NULL },
};

struct isakmp_hdr {
  guint8	icookie[8];
  guint8	rcookie[8];
  guint8	next_payload;
  guint8	version;
  guint8	exch_type;
  guint8	flags;
#define E_FLAG		0x01
#define C_FLAG		0x02
#define A_FLAG		0x04
#define I_FLAG		0x08
#define V_FLAG		0x10
#define R_FLAG		0x20
  guint32	message_id;
  guint32	length;
};

static proto_tree *dissect_payload_header(tvbuff_t *, int, int, int, guint8,
    guint8 *, guint16 *, proto_tree *);

static void dissect_sa(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_proposal(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_transform(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_transform2(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_key_exch(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_id(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_cert(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_certreq_v1(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_certreq_v2(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_hash(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_auth(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_sig(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_nonce(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_notif(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_delete(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_vid(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_config(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_nat_discovery(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_nat_original_address(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_ts(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_enc(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);
static void dissect_eap(tvbuff_t *, int, int, proto_tree *,
    packet_info *, int, int);

static void
dissect_payloads(tvbuff_t *tvb, proto_tree *tree, int isakmp_version,
		 guint8 initial_payload, int offset, int length,
		 packet_info *pinfo);


static const char *payloadtype2str(int, guint8);
static const char *exchtype2str(int, guint8);
static const char *doitype2str(guint32);
static const char *msgtype2str(int, guint16);
static const char *situation2str(guint32);
static const char *v1_attrval2str(int, guint16, guint32);
static const char *v2_attrval2str(guint16, guint32);
static const char *cfgtype2str(int, guint8);
static const char *cfgattr2str(int, guint16);
static const char *id2str(int, guint8);
static const char *v2_tstype2str(guint8);
static const char *v2_auth2str(guint8);
static const char *certtype2str(int, guint8);

static gboolean get_num(tvbuff_t *, int, guint16, guint32 *);

#define LOAD_TYPE_NONE		0	/* payload type for None */
#define LOAD_TYPE_PROPOSAL	2	/* payload type for Proposal */
#define	LOAD_TYPE_TRANSFORM	3	/* payload type for Transform */

struct payload_func {
  guint8 type;
  const char *	str;
  void (*func)(tvbuff_t *, int, int, proto_tree *, packet_info *, int, int);
};

static struct payload_func v1_plfunc[] = {
  {  0, "NONE",			NULL              },
  {  1, "Security Association",	dissect_sa        },
  {  2, "Proposal",		dissect_proposal  },
  {  3, "Transform",		dissect_transform },
  {  4, "Key Exchange",		dissect_key_exch  },
  {  5, "Identification",	dissect_id        },
  {  6, "Certificate",		dissect_cert      },
  {  7, "Certificate Request",	dissect_certreq_v1},
  {  8, "Hash",			dissect_hash      },
  {  9, "Signature",		dissect_sig       },
  { 10, "Nonce",		dissect_nonce     },
  { 11, "Notification",		dissect_notif     },
  { 12, "Delete",		dissect_delete    },
  { 13, "Vendor ID",		dissect_vid       },
  { 14, "Attrib",		dissect_config	  },
  { 15, "NAT-Discovery",	dissect_nat_discovery }, /* draft-ietf-ipsec-nat-t-ike-04 */
  { 16, "NAT-Original Address",	dissect_nat_original_address }, /* draft-ietf-ipsec-nat-t-ike */
  { 20, "NAT-D (RFC 3947)",	dissect_nat_discovery },
  { 21, "NAT-OA (RFC 3947)",	dissect_nat_original_address },
  { 130, "NAT-D (draft-ietf-ipsec-nat-t-ike-01 to 03)",		dissect_nat_discovery },
  { 131, "NAT-OA (draft-ietf-ipsec-nat-t-ike-01 to 04)",	dissect_nat_original_address },
};

static struct payload_func v2_plfunc[] = {
  {  2, "Proposal",		dissect_proposal  },
  {  3, "Transform",		dissect_transform2 },
  { 33, "Security Association",	dissect_sa        },
  { 34, "Key Exchange",		dissect_key_exch  },
  { 35, "Identification - I",	dissect_id        },
  { 36, "Identification - R",	dissect_id        },
  { 37, "Certificate",		dissect_cert      },
  { 38, "Certificate Request",	dissect_certreq_v2},
  { 39, "Authentication",	dissect_auth      },
  { 40, "Nonce",		dissect_nonce     },
  { 41, "Notification",		dissect_notif     },
  { 42, "Delete",		dissect_delete    },
  { 43, "Vendor ID",		dissect_vid       },
  { 44, "Traffic Selector - I",	dissect_ts       },
  { 45, "Traffic Selector - R",	dissect_ts       },
  { 46, "Encrypted",		dissect_enc       },
  { 47, "Configuration",	dissect_config	  },
  { 48, "Extensible Authentication",	dissect_eap	  },
};

static struct payload_func * getpayload_func(guint8, int);

#define VID_LEN 16
#define VID_MS_LEN 20
static const guint8 VID_MS_W2K_WXP[VID_MS_LEN] = {0x1E, 0x2B, 0x51, 0x69, 0x5, 0x99, 0x1C, 0x7D, 0x7C, 0x96, 0xFC, 0xBF, 0xB5, 0x87, 0xE4, 0x61, 0x0, 0x0, 0x0, 0x2}; /* according to http://www.microsoft.com/technet/treeview/default.asp?url=/technet/columns/cableguy/cg0602.asp */

#define VID_CP_LEN 20
static const guint8 VID_CP[VID_CP_LEN] = {0xF4, 0xED, 0x19, 0xE0, 0xC1, 0x14, 0xEB, 0x51, 0x6F, 0xAA, 0xAC, 0x0E, 0xE3, 0x7D, 0xAF, 0x28, 0x7, 0xB4, 0x38, 0x1F};

static const guint8 VID_CYBERGUARD[VID_LEN] = {0x9A, 0xA1, 0xF3, 0xB4, 0x34, 0x72, 0xA4, 0x5D, 0x5F, 0x50, 0x6A, 0xEB, 0x26, 0xC, 0xF2, 0x14};

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_03[VID_LEN] = {0x7D, 0x94, 0x19, 0xA6, 0x53, 0x10, 0xCA, 0x6F, 0x2C, 0x17, 0x9D, 0x92, 0x15, 0x52, 0x9d, 0x56}; /* according to http://www.ietf.org/internet-drafts/draft-ietf-ipsec-nat-t-ike-03.txt */

static const guint8 VID_rfc3947[VID_LEN] = {0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f}; /* RFC 3947 Negotiation of NAT-Traversal in the IKE*/

static const guint8 VID_SSH_IPSEC_EXPRESS_1_1_0[VID_LEN] = {0xfB, 0xF4, 0x76, 0x14, 0x98, 0x40, 0x31, 0xFA, 0x8E, 0x3B, 0xB6, 0x19, 0x80, 0x89, 0xB2, 0x23}; /* Ssh Communications Security IPSEC Express version 1.1.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_1_1_1[VID_LEN] = {0x19, 0x52, 0xDC, 0x91, 0xAC, 0x20, 0xF6, 0x46, 0xFB, 0x01, 0xCF, 0x42, 0xA3, 0x3A, 0xEE, 0x30}; /* Ssh Communications Security IPSEC Express version 1.1.1 */
   
static const guint8 VID_SSH_IPSEC_EXPRESS_1_1_2[VID_LEN] = {0xE8, 0xBF, 0xFA, 0x64, 0x3E, 0x5C, 0x8F, 0x2C, 0xD1, 0x0F, 0xDA, 0x73, 0x70, 0xB6, 0xEB, 0xE5}; /* Ssh Communications Security IPSEC Express version 1.1.2 */

static const guint8 VID_SSH_IPSEC_EXPRESS_1_2_1[VID_LEN] = {0xC1, 0x11, 0x1B, 0x2D, 0xEE, 0x8C, 0xBC, 0x3D, 0x62, 0x05, 0x73, 0xEC, 0x57, 0xAA, 0xB9, 0xCB}; /* Ssh Communications Security IPSEC Express version 1.2.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_1_2_2[VID_LEN] = {0x09, 0xEC, 0x27, 0xBF, 0xBC, 0x09, 0xC7, 0x58, 0x23, 0xCF, 0xEC, 0xBF, 0xFE, 0x56, 0x5A, 0x2E}; /* Ssh Communications Security IPSEC Express version 1.2.2 */
   
static const guint8 VID_SSH_IPSEC_EXPRESS_2_0_0[VID_LEN] = {0x7F, 0x21, 0xA5, 0x96, 0xE4, 0xE3, 0x18, 0xF0, 0xB2, 0xF4, 0x94, 0x4C, 0x23, 0x84, 0xCB, 0x84};  /* SSH Communications Security IPSEC Express version 2.0.0 */
   
static const guint8 VID_SSH_IPSEC_EXPRESS_2_1_0[VID_LEN] = {0x28, 0x36, 0xD1, 0xFD, 0x28, 0x07, 0xBC, 0x9E, 0x5A, 0xE3, 0x07, 0x86, 0x32, 0x04, 0x51, 0xEC}; /* SSH Communications Security IPSEC Express version 2.1.0 */
   
static const guint8 VID_SSH_IPSEC_EXPRESS_2_1_1[VID_LEN] = {0xA6, 0x8D, 0xE7, 0x56, 0xA9, 0xC5, 0x22, 0x9B, 0xAE, 0x66, 0x49, 0x80, 0x40, 0x95, 0x1A, 0xD5}; /* SSH Communications Security IPSEC Express version 2.1.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_2_1_2[VID_LEN] = {0x3F, 0x23, 0x72, 0x86, 0x7E, 0x23, 0x7C, 0x1C, 0xD8, 0x25, 0x0A, 0x75, 0x55, 0x9C, 0xAE, 0x20}; /* SSH Communications Security IPSEC Express version 2.1.2 */

static const guint8 VID_SSH_IPSEC_EXPRESS_3_0_0[VID_LEN] = {0x0E, 0x58, 0xD5, 0x77, 0x4D, 0xF6, 0x02, 0x00, 0x7D, 0x0B, 0x02, 0x44, 0x36, 0x60, 0xF7, 0xEB}; /* SSH Communications Security IPSEC Express version 3.0.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_3_0_1[VID_LEN] = {0xF5, 0xCE, 0x31, 0xEB, 0xC2, 0x10, 0xF4, 0x43, 0x50, 0xCF, 0x71, 0x26, 0x5B, 0x57, 0x38, 0x0F}; /* SSH Communications Security IPSEC Express version 3.0.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_4_0_0[VID_LEN] = {0xF6, 0x42, 0x60, 0xAF, 0x2E, 0x27, 0x42, 0xDA, 0xDD, 0xD5, 0x69, 0x87, 0x06, 0x8A, 0x99, 0xA0}; /* SSH Communications Security IPSEC Express version 4.0.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_4_0_1[VID_LEN] = {0x7A, 0x54, 0xD3, 0xBD, 0xB3, 0xB1, 0xE6, 0xD9, 0x23, 0x89, 0x20, 0x64, 0xBE, 0x2D, 0x98, 0x1C}; /* SSH Communications Security IPSEC Express version 4.0.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_4_1_0[VID_LEN] = {0x9A, 0xA1, 0xF3, 0xB4, 0x34, 0x72, 0xA4, 0x5D, 0x5F, 0x50, 0x6A, 0xEB, 0x26, 0x0C, 0xF2, 0x14}; /* SSH Communications Security IPSEC Express version 4.1.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_4_1_1[VID_LEN] = {0x89, 0xF7, 0xB7, 0x60, 0xD8, 0x6B, 0x01, 0x2A, 0xCF, 0x26, 0x33, 0x82, 0x39, 0x4D, 0x96, 0x2F}; /* SSH Communications Security IPSEC Express version 4.1.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_5_0[VID_LEN] = {0xB0, 0x37, 0xA2, 0x1A, 0xCE, 0xCC, 0xB5, 0x57, 0x0F, 0x60, 0x25, 0x46, 0xF9, 0x7B, 0xDE, 0x8C}; /* SSH Communications Security IPSEC Express version 5.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_5_0_0[VID_LEN] = {0x2B, 0x2D, 0xAD, 0x97, 0xC4, 0xD1, 0x40, 0x93, 0x00, 0x53, 0x28, 0x7F, 0x99, 0x68, 0x50, 0xB0}; /* SSH Communications Security IPSEC Express version 5.0.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_5_1_0[VID_LEN] = {0x45, 0xE1, 0x7F, 0x3A, 0xBE, 0x93, 0x94, 0x4C, 0xB2, 0x02, 0x91, 0x0C, 0x59, 0xEF, 0x80, 0x6B}; /* SSH Communications Security IPSEC Express version 5.1.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_5_1_1[VID_LEN] = {0x59, 0x25, 0x85, 0x9F, 0x73, 0x77, 0xED, 0x78, 0x16, 0xD2, 0xFB, 0x81, 0xC0, 0x1F, 0xA5, 0x51}; /* SSH Communications Security IPSEC Express version 5.1.1 */

static const guint8 VID_SSH_SENTINEL[VID_LEN] = {0x05, 0x41, 0x82, 0xA0, 0x7C, 0x7A, 0xE2, 0x06, 0xF9, 0xD2, 0xCF, 0x9D, 0x24, 0x32, 0xC4, 0x82}; /* SSH Sentinel */

static const guint8 VID_SSH_SENTINEL_1_1[VID_LEN] = {0xB9, 0x16, 0x23, 0xE6, 0x93, 0xCA, 0x18, 0xA5, 0x4C, 0x6A, 0x27, 0x78, 0x55, 0x23, 0x05, 0xE8}; /* SSH Sentinel 1.1 */

static const guint8 VID_SSH_SENTINEL_1_2[VID_LEN] = {0x54, 0x30, 0x88, 0x8D, 0xE0, 0x1A, 0x31, 0xA6, 0xFA, 0x8F, 0x60, 0x22, 0x4E, 0x44, 0x99, 0x58}; /* SSH Sentinel 1.2 */

static const guint8 VID_SSH_SENTINEL_1_3[VID_LEN] = {0x7E, 0xE5, 0xCB, 0x85, 0xF7, 0x1C, 0xE2, 0x59, 0xC9, 0x4A, 0x5C, 0x73, 0x1E, 0xE4, 0xE7, 0x52}; /* SSH Sentinel 1.3 */

static const guint8 VID_SSH_QUICKSEC_0_9_0[VID_LEN] = {0x37, 0xEB, 0xA0, 0xC4, 0x13, 0x61, 0x84, 0xE7, 0xDA, 0xF8, 0x56, 0x2A, 0x77, 0x06, 0x0B, 0x4A}; /* SSH Communications Security QuickSec 0.9.0 */

static const guint8 VID_SSH_QUICKSEC_1_1_0[VID_LEN] = {0x5D, 0x72, 0x92, 0x5E, 0x55, 0x94, 0x8A, 0x96, 0x61, 0xA7, 0xFC, 0x48, 0xFD, 0xEC, 0x7F, 0xF9}; /* SSH Communications Security QuickSec 1.1.0 */

static const guint8 VID_SSH_QUICKSEC_1_1_1[VID_LEN] = {0x77, 0x7F, 0xBF, 0x4C, 0x5A, 0xF6, 0xD1, 0xCD, 0xD4, 0xB8, 0x95, 0xA0, 0x5B, 0xF8, 0x25, 0x94}; /* SSH Communications Security QuickSec 1.1.1 */

static const guint8 VID_SSH_QUICKSEC_1_1_2[VID_LEN] = {0x2C, 0xDF, 0x08, 0xE7, 0x12, 0xED, 0xE8, 0xA5, 0x97, 0x87, 0x61, 0x26, 0x7C, 0xD1, 0x9B, 0x91}; /* SSH Communications Security QuickSec 1.1.2 */

static const guint8 VID_SSH_QUICKSEC_1_1_3[VID_LEN] = {0x59, 0xE4, 0x54, 0xA8, 0xC2, 0xCF, 0x02, 0xA3, 0x49, 0x59, 0x12, 0x1F, 0x18, 0x90, 0xBC, 0x87}; /* SSH Communications Security QuickSec 1.1.3 */

static const guint8 VID_draft_huttunen_ipsec_esp_in_udp_01[VID_LEN] = {0x50, 0x76, 0x0F, 0x62, 0x4C, 0x63, 0xE5, 0xC5, 0x3E, 0xEA, 0x38, 0x6C, 0x68, 0x5C, 0xA0, 0x83}; /* draft-huttunen-ipsec-esp-in-udp-01.txt */

static const guint8 VID_draft_stenberg_ipsec_nat_traversal_01[VID_LEN] = {0x27, 0xBA, 0xB5, 0xDC, 0x01, 0xEA, 0x07, 0x60, 0xEA, 0x4E, 0x31, 0x90, 0xAC, 0x27, 0xC0, 0xD0}; /* draft-stenberg-ipsec-nat-traversal-01 */

static const guint8 VID_draft_stenberg_ipsec_nat_traversal_02[VID_LEN]= {0x61, 0x05, 0xC4, 0x22, 0xE7, 0x68, 0x47, 0xE4, 0x3F, 0x96, 0x84, 0x80, 0x12, 0x92, 0xAE, 0xCD}; /* draft-stenberg-ipsec-nat-traversal-02 */

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_00[VID_LEN]= {0x44, 0x85, 0x15, 0x2D, 0x18, 0xB6, 0xBB, 0xCD, 0x0B, 0xE8, 0xA8, 0x46, 0x95, 0x79, 0xDD, 0xCC}; /* draft-ietf-ipsec-nat-t-ike-00 */

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_02a[VID_LEN]= {0xCD, 0x60, 0x46, 0x43, 0x35, 0xDF, 0x21, 0xF8, 0x7C, 0xFD, 0xB2, 0xFC, 0x68, 0xB6, 0xA4, 0x48}; /* draft-ietf-ipsec-nat-t-ike-02 */

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_02b[VID_LEN]= {0x90, 0xCB, 0x80, 0x91, 0x3E, 0xBB, 0x69, 0x6E, 0x08, 0x63, 0x81, 0xB5, 0xEC, 0x42, 0x7B, 0x1F}; /* draft-ietf-ipsec-nat-t-ike-02 */

static const guint8 VID_draft_beaulieu_ike_xauth_02[VID_LEN]= {0x09, 0x00, 0x26, 0x89, 0xDF, 0xD6, 0xB7, 0x12, 0x80, 0xA2, 0x24, 0xDE, 0xC3, 0x3B, 0x81, 0xE5}; /* draft-beaulieu-ike-xauth-02.txt */


static const guint8 VID_rfc3706_dpd[VID_LEN]= {0xAF, 0xCA,0xD7, 0x13, 0x68, 0xA1, 0xF1, 0xC9, 0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57, 0x01, 0x00}; /* RFC 3706 */

static const guint8 VID_IKE_CHALLENGE_RESPONSE_1[VID_LEN]= {0xBA, 0x29, 0x04, 0x99, 0xC2, 0x4E, 0x84, 0xE5, 0x3A, 0x1D, 0x83, 0xA0, 0x5E, 0x5F, 0x00, 0xC9}; /* IKE Challenge/Response for Authenticated Cryptographic Keys */

static const guint8 VID_IKE_CHALLENGE_RESPONSE_2[VID_LEN]= {0x0D, 0x33, 0x61, 0x1A, 0x5D, 0x52, 0x1B, 0x5E, 0x3C, 0x9C, 0x03, 0xD2, 0xFC, 0x10, 0x7E, 0x12}; /* IKE Challenge/Response for Authenticated Cryptographic Keys */

static const guint8 VID_IKE_CHALLENGE_RESPONSE_REV_1[VID_LEN]= {0xAD, 0x32, 0x51, 0x04, 0x2C, 0xDC, 0x46, 0x52, 0xC9, 0xE0, 0x73, 0x4C, 0xE5, 0xDE, 0x4C, 0x7D}; /* IKE Challenge/Response for Authenticated Cryptographic Keys (Revised) */

static const guint8 VID_IKE_CHALLENGE_RESPONSE_REV_2[VID_LEN]= {0x01, 0x3F, 0x11, 0x82, 0x3F, 0x96, 0x6F, 0xA9, 0x19, 0x00, 0xF0, 0x24, 0xBA, 0x66, 0xA8, 0x6B}; /* IKE Challenge/Response for Authenticated Cryptographic Keys (Revised) */

static const guint8 VID_MS_L2TP_IPSEC_VPN_CLIENT[VID_LEN]= {0x40, 0x48, 0xB7, 0xD5, 0x6E, 0xBC, 0xE8, 0x85, 0x25, 0xE7, 0xDE, 0x7F, 0x00, 0xD6, 0xC2, 0xD3}; /* Microsoft L2TP/IPSec VPN Client */

static const guint8 VID_GSS_API_1[VID_LEN]= {0xB4, 0x6D, 0x89, 0x14, 0xF3, 0xAA, 0xA3, 0xF2, 0xFE, 0xDE, 0xB7, 0xC7, 0xDB, 0x29, 0x43, 0xCA}; /* A GSS-API Authentication Method for IKE */

static const guint8 VID_GSS_API_2[VID_LEN]= {0xAD, 0x2C, 0x0D, 0xD0, 0xB9, 0xC3, 0x20, 0x83, 0xCC, 0xBA, 0x25, 0xB8, 0x86, 0x1E, 0xC4, 0x55}; /* A GSS-API Authentication Method for IKE */

static const guint8 VID_GSSAPI[VID_LEN]= {0x62, 0x1B, 0x04, 0xBB, 0x09, 0x88, 0x2A, 0xC1, 0xE1, 0x59, 0x35, 0xFE, 0xFA, 0x24, 0xAE, 0xEE}; /* GSSAPI */

static const guint8 VID_MS_NT5_ISAKMPOAKLEY[VID_LEN]= {0x1E, 0x2B, 0x51, 0x69, 0x05, 0x99, 0x1C, 0x7D, 0x7C, 0x96, 0xFC, 0xBF, 0xB5, 0x87, 0xE4, 0x61}; /* MS NT5 ISAKMPOAKLEY */

static const guint8 VID_CISCO_UNITY[VID_LEN]= {0x12, 0xF5, 0xF2, 0x8C, 0x45, 0x71, 0x68, 0xA9, 0x70, 0x2D, 0x9F, 0xE2, 0x74, 0xCC, 0x02, 0xD4}; /* CISCO-UNITY */

#define VID_LEN_8 8
static const guint8 VID_draft_ietf_ipsec_antireplay_00[VID_LEN_8]= {0x32, 0x5D, 0xF2, 0x9A, 0x23, 0x19, 0xF2, 0xDD}; /* draft-ietf-ipsec-antireplay-00.txt */

static const guint8 VID_draft_ietf_ipsec_heartbeats_00[VID_LEN_8]= {0x8D, 0xB7, 0xA4, 0x18, 0x11, 0x22, 0x16, 0x60}; /* draft-ietf-ipsec-heartbeats-00.txt */

/* 
*  Seen in Netscreen. Suppose to be ASCII HeartBeat_Notify - but I don't know the rest yet. I suspect it then proceeds with
*  8k10, which means every 8K (?), and version 1.0 of the protocol (?). I won't add it to the code, until I know what it really
*  means. ykaul-at-bezeqint.net
*/
static const guint8 VID_HeartBeat_Notify[VID_LEN] = {0x48, 0x65, 0x61, 0x72, 0x74, 0x42, 0x65, 0x61, 0x74, 0x5f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79}; 

void
isakmp_dissect_payloads(tvbuff_t *tvb, proto_tree *tree, int isakmp_version,
			guint8 initial_payload, int offset, int length,
			packet_info *pinfo)
{
  dissect_payloads(tvb, tree, isakmp_version, initial_payload, offset, length,
		   pinfo);
}

static void
dissect_payloads(tvbuff_t *tvb, proto_tree *tree, int isakmp_version,
		 guint8 initial_payload, int offset, int length, packet_info *pinfo)
{
  guint8 payload, next_payload;
  guint16		payload_length;
  proto_tree *		ntree;
  struct payload_func *	f;

  for (payload = initial_payload; length > 0; payload = next_payload) {
    if (payload == LOAD_TYPE_NONE) {
      /*
       * What?  There's more stuff in this chunk of data, but the
       * previous payload had a "next payload" type of None?
       */
      proto_tree_add_text(tree, tvb, offset, length,
			  "Extra data: %s",
			  tvb_bytes_to_str(tvb, offset, length));
      break;
    }
    ntree = dissect_payload_header(tvb, offset, length, isakmp_version,
      payload, &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (payload_length >= 4) {	/* XXX = > 4? */
      tvb_ensure_bytes_exist(tvb, offset + 4, payload_length - 4);
      if ((f = getpayload_func(payload, isakmp_version)) != NULL && f->func != NULL)
        (*f->func)(tvb, offset + 4, payload_length - 4, ntree, pinfo,
                   isakmp_version, -1);
      else {
        proto_tree_add_text(ntree, tvb, offset + 4, payload_length - 4,
                            "Payload");
      }
    }
    else if (payload_length > length) {
        proto_tree_add_text(ntree, tvb, 0, 0,
            "Payload (bogus, length is %u, greater than remaining length %d",
            payload_length, length);
        return;
    }
    else {
        proto_tree_add_text(ntree, tvb, 0, 0,
            "Payload (bogus, length is %u, must be at least 4)",
            payload_length);
        payload_length = 4;
    }
    offset += payload_length;
    length -= payload_length;
  }
}

static struct payload_func *
getpayload_func(guint8 payload, int isakmp_version)
{
  struct payload_func *f = 0;
  int i, len;

  if (isakmp_version == 1) {
    f = v1_plfunc;
    len = ARLEN(v1_plfunc);
  } else if (isakmp_version == 2) {
    f = v2_plfunc;
    len = ARLEN(v2_plfunc);
  } else
    return NULL;
  for (i = 0; i < len; i++) {
    if (f[i].type == payload)
      return &f[i];
  }
  return NULL;
}

static void
dissect_isakmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int			offset = 0, len;
  struct isakmp_hdr 	hdr;
  proto_item *		ti;
  proto_tree *		isakmp_tree = NULL;
  int			isakmp_version;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISAKMP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_isakmp, tvb, offset, -1, FALSE);
    isakmp_tree = proto_item_add_subtree(ti, ett_isakmp);
  }

  /* RFC3948 2.3 NAT Keepalive packet:
   * 1 byte payload with the value 0xff.
   */
  if( (tvb_length(tvb)==1) && (tvb_get_guint8(tvb, offset)==0xff) ){
    if (check_col(pinfo->cinfo, COL_INFO)){
      col_add_str(pinfo->cinfo, COL_INFO, "NAT Keepalive");
    }
    proto_tree_add_item(isakmp_tree, hf_ike_nat_keepalive, tvb, offset, 1, FALSE);
    return;
  }

  hdr.length = tvb_get_ntohl(tvb, offset + sizeof(hdr) - sizeof(hdr.length));
  hdr.exch_type = tvb_get_guint8(tvb, sizeof(hdr.icookie) + sizeof(hdr.rcookie) + sizeof(hdr.next_payload) + sizeof(hdr.version));
  hdr.version = tvb_get_guint8(tvb, sizeof(hdr.icookie) + sizeof(hdr.rcookie) + sizeof(hdr.next_payload));
  isakmp_version = hi_nibble(hdr.version);	/* save the version */
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
                exchtype2str(isakmp_version, hdr.exch_type));

  if (tree) {
    tvb_memcpy(tvb, (guint8 *)&hdr.icookie, offset, sizeof(hdr.icookie));
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.icookie),
			"Initiator cookie: 0x%s", tvb_bytes_to_str(tvb, offset, sizeof(hdr.icookie)));
    offset += sizeof(hdr.icookie);

    tvb_memcpy(tvb, (guint8 *)&hdr.rcookie, offset, sizeof(hdr.rcookie));
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.rcookie),
			"Responder cookie: 0x%s", tvb_bytes_to_str(tvb, offset, sizeof(hdr.rcookie)));
    offset += sizeof(hdr.rcookie);

    hdr.next_payload = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.next_payload),
			"Next payload: %s (%u)",
			payloadtype2str(isakmp_version, hdr.next_payload),
			hdr.next_payload);
    offset += sizeof(hdr.next_payload);

    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.version),
			"Version: %u.%u",
			hi_nibble(hdr.version), lo_nibble(hdr.version));
    offset += sizeof(hdr.version);

    hdr.exch_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.exch_type),
			"Exchange type: %s (%u)",
			exchtype2str(isakmp_version, hdr.exch_type),
			hdr.exch_type);
    offset += sizeof(hdr.exch_type);

    {
      proto_item *	fti;
      proto_tree *	ftree;

      hdr.flags = tvb_get_guint8(tvb, offset);
      fti   = proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.flags), "Flags");
      ftree = proto_item_add_subtree(fti, ett_isakmp_flags);

      if (isakmp_version == 1) {
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, E_FLAG, sizeof(hdr.flags)*8,
						  "Encrypted", "Not encrypted"));
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, C_FLAG, sizeof(hdr.flags)*8,
						  "Commit", "No commit"));
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, A_FLAG, sizeof(hdr.flags)*8,
						  "Authentication", "No authentication"));
      } else if (isakmp_version == 2) {
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, I_FLAG, sizeof(hdr.flags)*8,
						  "Initiator", "Responder"));
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, V_FLAG, sizeof(hdr.flags)*8,
						  "A higher version enabled", ""));
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, R_FLAG, sizeof(hdr.flags)*8,
						  "Response", "Request"));
      }
      offset += sizeof(hdr.flags);
    }

    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.message_id),
        "Message ID: 0x%s", tvb_bytes_to_str(tvb, offset, sizeof(hdr.message_id)));
    offset += sizeof(hdr.message_id);

    if (hdr.length < sizeof(hdr)) {
        proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.length),
			    "Length: (bogus, length is %u, should be at least %lu)",
			    hdr.length, (unsigned long)sizeof(hdr));
        return;
    }

    len = hdr.length - sizeof(hdr);

    if (len < 0) {
        proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.length),
			    "Length: (bogus, length is %u, which is too large)",
			    hdr.length);
        return;
    }

    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.length),
			"Length: %u", hdr.length);
    offset += sizeof(hdr.length);

    if (hdr.flags & E_FLAG) {
      if (len && isakmp_tree) {
        proto_tree_add_text(isakmp_tree, tvb, offset, len,
			"Encrypted payload (%d byte%s)",
			len, plurality(len, "", "s"));
      }
    } else
      dissect_payloads(tvb, isakmp_tree, isakmp_version, hdr.next_payload,
		       offset, len, pinfo);
  }
}

static proto_tree *
dissect_payload_header(tvbuff_t *tvb, int offset, int length,
    int isakmp_version, guint8 payload, guint8 *next_payload_p,
    guint16 *payload_length_p, proto_tree *tree)
{
  guint8		next_payload;
  guint16		payload_length;
  proto_item *		ti;
  proto_tree *		ntree;

  if (length < 4) {
    proto_tree_add_text(tree, tvb, offset, length,
          "Not enough room in payload for all transforms");
    return NULL;
  }
  next_payload = tvb_get_guint8(tvb, offset);
  payload_length = tvb_get_ntohs(tvb, offset + 2);

  ti = proto_tree_add_text(tree, tvb, offset, payload_length,
            "%s payload", payloadtype2str(isakmp_version, payload));
  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);

  proto_tree_add_text(ntree, tvb, offset, 1,
		      "Next payload: %s (%u)",
		      payloadtype2str(isakmp_version, next_payload),
		      next_payload);
  if (isakmp_version == 2) {
    proto_tree_add_text(ntree, tvb, offset + 1, 1, "%s",
        	decode_boolean_bitfield(tvb_get_guint8(tvb, offset + 1), 0x80,
        	8, "Critical", "Not critical"));
  }
  proto_tree_add_text(ntree, tvb, offset + 2, 2, "Length: %u", payload_length);

  *next_payload_p = next_payload;
  *payload_length_p = payload_length;
  return ntree;
}

static void
dissect_sa(tvbuff_t *tvb, int offset, int length, proto_tree *tree, 
    packet_info *pinfo, int isakmp_version, int unused _U_)
{
  guint32		doi;
  guint32		situation;

  if (length < 4) {
    proto_tree_add_text(tree, tvb, offset, length,
			"DOI %s (length is %u, should be >= 4)",
			tvb_bytes_to_str(tvb, offset, length), length);
    return;
  }
  if (isakmp_version == 1) {
    doi = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4,
		      "Domain of interpretation: %s (%u)",
		      doitype2str(doi), doi);
    offset += 4;
    length -= 4;

    if (doi == 1) {
      /* IPSEC */
      if (length < 4) {
        proto_tree_add_text(tree, tvb, offset, length,
			  "Situation: %s (length is %u, should be >= 4)",
			  tvb_bytes_to_str(tvb, offset, length), length);
        return;
      }
      situation = tvb_get_ntohl(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, 4,
			"Situation: %s (%u)",
			situation2str(situation), situation);
      offset += 4;
      length -= 4;

      dissect_payloads(tvb, tree, isakmp_version, LOAD_TYPE_PROPOSAL, offset,
		       length, pinfo);
    } else {
      /* Unknown */
      proto_tree_add_text(tree, tvb, offset, length,
			"Situation: %s",
			tvb_bytes_to_str(tvb, offset, length));
    }
  } else if (isakmp_version == 2) {
    dissect_payloads(tvb, tree, isakmp_version, LOAD_TYPE_PROPOSAL, offset,
		     length, pinfo);
  }
}

static void
dissect_proposal(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version, int unused _U_)
{
  guint8		protocol_id;
  guint8		spi_size;
  guint8		num_transforms;
  guint8		next_payload;
  guint16		payload_length;
  proto_tree *		ntree;
  guint8		proposal_num;

  proposal_num = tvb_get_guint8(tvb, offset);

  proto_item_append_text(tree, " # %d",proposal_num);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Proposal number: %u", proposal_num);
  offset += 1;
  length -= 1;

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Protocol ID: %s (%u)",
		      val_to_str(protocol_id, vs_proto, "UNKNOWN-PROTO-TYPE"), protocol_id);
  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "SPI size: %u", spi_size);
  offset += 1;
  length -= 1;

  num_transforms = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Number of transforms: %u", num_transforms);
  offset += 1;
  length -= 1;

  if (spi_size) {
    proto_tree_add_text(tree, tvb, offset, spi_size, "SPI: 0x%s",
			tvb_bytes_to_str(tvb, offset, spi_size));
    offset += spi_size;
    length -= spi_size;
  }

  while (num_transforms > 0) {
    ntree = dissect_payload_header(tvb, offset, length, isakmp_version,
      LOAD_TYPE_TRANSFORM, &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (length < payload_length) {
      proto_tree_add_text(tree, tvb, offset + 4, length,
          "Not enough room in payload for all transforms");
      break;
    }
    if (payload_length >= 4) {
      if (isakmp_version == 1)
        dissect_transform(tvb, offset + 4, payload_length - 4, ntree,
			pinfo, isakmp_version, protocol_id);
      else if (isakmp_version == 2)
        dissect_transform2(tvb, offset + 4, payload_length - 4, ntree,
			pinfo, isakmp_version, protocol_id);
    }
    else
      proto_tree_add_text(ntree, tvb, offset + 4, payload_length - 4, "Payload");
    offset += payload_length;
    length -= payload_length;
    num_transforms--;
  }
}

static void
dissect_transform(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int protocol_id)
{
  static const value_string vs_v1_attr[] = {
    { 1,	"Encryption-Algorithm" },
    { 2,	"Hash-Algorithm" },
    { 3,	"Authentication-Method" },
    { 4,	"Group-Description" },
    { 5,	"Group-Type" },
    { 6,	"Group-Prime" },
    { 7,	"Group-Generator-One" },
    { 8,	"Group-Generator-Two" },
    { 9,	"Group-Curve-A" },
    { 10,	"Group-Curve-B" },
    { 11,	"Life-Type" },
    { 12,	"Life-Duration" },
    { 13,	"PRF" },
    { 14,	"Key-Length" },
    { 15,	"Field-Size" },
    { 16,	"Group-Order" },
    { 0,	NULL },
  };

  static const value_string vs_v2_sttr[] = {
    { 1,	"SA-Life-Type" },
    { 2,	"SA-Life-Duration" },
    { 3,	"Group-Description" },
    { 4,	"Encapsulation-Mode" },
    { 5,	"Authentication-Algorithm" },
    { 6,	"Key-Length" },
    { 7,	"Key-Rounds" },
    { 8,	"Compress-Dictinary-Size" },
    { 9,	"Compress-Private-Algorithm" },
    { 10,	"ECN Tunnel" },
    { 0,	NULL },
  };

  static const value_string vs_v1_trans_isakmp[] = {
    { 0,	"RESERVED" },
    { 1,	"KEY_IKE" },
    { 0,	NULL },
  };

  static const value_string vs_v1_trans_ah[] = {
    { 0,	"RESERVED" },
    { 1,	"RESERVED" },
    { 2,	"MD5" },
    { 3,	"SHA" },
    { 4,	"DES" },
    { 5,	"SHA2-256" },
    { 6,	"SHA2-384" },
    { 7,	"SHA2-512" },
    { 0,	NULL },
  };

  static const value_string vs_v1_trans_esp[] = {
    { 0,	"RESERVED" },
    { 1,	"DES-IV64" },
    { 2,	"DES" },
    { 3,	"3DES" },
    { 4,	"RC5" },
    { 5,	"IDEA" },
    { 6,	"CAST" },
    { 7,	"BLOWFISH" },
    { 8,	"3IDEA" },
    { 9,	"DES-IV32" },
    { 10,	"RC4" },
    { 11,	"NULL" },
    { 12,	"AES" },
    { 0,	NULL },
  };

  static const value_string vs_v1_trans_ipcomp[] = {
    { 0,	"RESERVED" },
    { 1,	"OUI" },
    { 2,	"DEFLATE" },
    { 3,	"LZS" },
    { 4,	"LZJH" },
    { 0,	NULL },
  };

  guint8		transform_id;
  guint8		transform_num;

  transform_num = tvb_get_guint8(tvb, offset);
  proto_item_append_text(tree," # %d",transform_num);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Transform number: %u", transform_num);
  offset += 1;
  length -= 1;

  transform_id = tvb_get_guint8(tvb, offset);
  switch (protocol_id) {
  default:
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %u", transform_id);
    break;
  case 1:	/* ISAKMP */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			val_to_str(transform_id, vs_v1_trans_isakmp, "UNKNOWN-TRANS-TYPE"), transform_id);
    break;
  case 2:	/* AH */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			val_to_str(transform_id, vs_v1_trans_ah, "UNKNOWN-AH-TRANS-TYPE"), transform_id);
    break;
  case 3:	/* ESP */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			val_to_str(transform_id, vs_v1_trans_esp, "UNKNOWN-ESP-TRANS-TYPE"), transform_id);
    break;
  case 4:	/* IPCOMP */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			val_to_str(transform_id, vs_v1_trans_ipcomp, "UNKNOWN-IPCOMP-TRANS-TYPE"), transform_id);
    break;
  }
  offset += 3;
  length -= 3;

  while (length>0) {
    const char *str;
    int ike_phase1 = 0;
    guint16 aft     = tvb_get_ntohs(tvb, offset);
    guint16 type    = aft & 0x7fff;
    guint16 len;
    guint32 val;
    guint pack_len;

    if (protocol_id == 1 && transform_id == 1) {
      ike_phase1 = 1;
      str = val_to_str(type, vs_v1_attr, "UNKNOWN-ATTRIBUTE-TYPE");
    }
    else {
      str = val_to_str(type, vs_v2_sttr, "UNKNOWN-ATTRIBUTE-TYPE");
    }

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u): %s (%u)",
			  str, type,
			  v1_attrval2str(ike_phase1, type, val), val);
      offset += 4;
      length -= 4;
    }
    else {
      len = tvb_get_ntohs(tvb, offset + 2);
      pack_len = 4 + len;
      if (!get_num(tvb, offset + 4, len, &val)) {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): <too big (%u bytes)>",
			    str, type, len);
      } else {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): %s (%u)",
			    str, type,
			    v1_attrval2str(ike_phase1, type, val), val);
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

/* For Transform Type 1 (Encryption Algorithm), defined Transform IDs */
static const char *
v2_tid2encstr(guint16 tid)
{
  static const value_string vs_v2_trans_enc[] = {
    { 0,	"RESERVED" },
    { 1,	"ENCR_DES_IV64" },
    { 2,	"ENCR_DES" },
    { 3,	"ENCR_3DE" },
    { 4,	"ENCR_RC5" },
    { 5,	"ENCR_IDEA" },
    { 6,	"ENCR_CAST" },
    { 7,	"ENCR_BLOWFISH" },
    { 8,	"ENCR_3IDEA" },
    { 9,	"ENCR_DES_IV32" },
    { 10,	"RESERVED" },
    { 11,	"ENCR_NULL" },
    { 12,	"ENCR_AES_CBC" },
    { 13,	"ENCR_AES_CTR" },
    { 0,	NULL },
  };

  return val_to_str(tid, vs_v2_trans_enc, "UNKNOWN-ENC-ALG");
}

/* For Transform Type 2 (Pseudo-random Function), defined Transform IDs */
static const char *
v2_tid2prfstr(guint16 tid)
{
  static const value_string vs_v2_trans_prf[] = {
    { 0,	"RESERVED" },
    { 1,	"PRF_HMAC_MD5" },
    { 2,	"PRF_HMAC_SHA1" },
    { 3,	"PRF_HMAC_TIGER" },
    { 4,	"PRF_AES128_CBC" },
    { 0,	NULL },
  };
  return val_to_str(tid, vs_v2_trans_prf, "UNKNOWN-PRF");
}

/* For Transform Type 3 (Integrity Algorithm), defined Transform IDs */
static const char *
v2_tid2iastr(guint16 tid)
{
  static const value_string vs_v2_trans_integrity[] = {
    { 0,	"NONE" },
    { 1,	"AUTH_HMAC_MD5_96" },
    { 2,	"AUTH_HMAC_SHA1_96" },
    { 3,	"AUTH_DES_MAC" },
    { 4,	"AUTH_KPDK_MD5" },
    { 5,	"AUTH_AES_XCBC_96" },
    { 0,	NULL },
  };
  return val_to_str(tid, vs_v2_trans_integrity, "UNKNOWN-INTEGRITY-ALG");
}

/* For Transform Type 4 (Diffie-Hellman Group), defined Transform IDs */
static const char *
v2_tid2dhstr(guint16 tid)
{
  static const value_string vs_v2_trans_dhgroup[] = {
    {  0,	"NONE" },
    {  1,	"Group 1 - 768 Bit MODP" },
    {  2,	"Group 2 - 1024 Bit MODP" },
    {  3,	"RESERVED" },
    {  4,	"RESERVED" },
    {  5,	"group 5 - 1536 Bit MODP" },
    { 14,	"2048-bit MODP Group" },
    { 15,	"3072-bit MODP Group" },
    { 16,	"4096-bit MODP Group" },
    { 17,	"6144-bit MODP Group" },
    { 18,	"8192-bit MODP Group" },
    { 0,	NULL },
  };

  if ((tid >= 6 && tid <= 13) || (tid >= 19 && tid <= 1023))
    return "RESERVED TO IANA";
  if (tid >= 1024)
    return "PRIVATE USE";
  return val_to_str(tid, vs_v2_trans_dhgroup, "UNKNOWN-DH-GROUP");
}

/* For Transform Type 5 (Extended Sequence Numbers), defined Transform */
static const char *
v2_tid2esnstr(guint16 tid)
{
  static const value_string vs_v2_trans_esn[] = {
    { 0,	"No Extended Sequence Numbers" },
    { 1,	"Extended Sequence Numbers" },
    { 0,	NULL },
  };

  return val_to_str(tid, vs_v2_trans_esn, "UNKNOWN-ESN-TYPE");
}

static struct {
  const gint8 type;
  const char *str;
  const char *(*func)(guint16);
} v2_tid_func[] = {
  { 0,	"RESERVED", NULL, },
  { 1,	"Encryption Algorithm (ENCR)", v2_tid2encstr },
  { 2,	"Pseudo-random Function (PRF)", v2_tid2prfstr }, 
  { 3,	"Integrity Algorithm (INTEG)", v2_tid2iastr },
  { 4,	"Diffie-Hellman Group (D-H)", v2_tid2dhstr },
  { 5,	"Extended Sequence Numbers (ESN)", v2_tid2esnstr },
};

static const char *
v2_trans2str(guint8 type)
{
  if (type < ARLEN(v2_tid_func)) return v2_tid_func[type].str;
  if (type < 240) return "RESERVED TO IANA";
  return "PRIVATE USE";
}

static const char *
v2_tid2str(guint8 type, guint16 tid)
{
  if (type < ARLEN(v2_tid_func) && v2_tid_func[type].func != NULL) {
    return (v2_tid_func[type].func)(tid);
  }
  return "RESERVED";
}

static const char *
v2_aft2str(guint16 aft)
{
    if (aft < 14 || (aft > 14 && aft < 18)) return "RESERVED";
    if (aft == 14) return "Key Length (in bits)";
    if (aft >= 18 && aft < 16384) return "RESERVED TO IANA";
    return "PRIVATE USE";
}

static void
dissect_transform2(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  guint8 transform_type;
  guint16 transform_id;

  transform_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
    "Transform type: %s (%u)", v2_trans2str(transform_type), transform_type);
  offset += 2;
  length -= 2;

  transform_id = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 2,
    "Transform ID: %s (%u)", v2_tid2str(transform_type, transform_id),
    transform_id);
  offset += 2;
  length -= 2;

  while (length>0) {
    const char *str;
    guint16 aft     = tvb_get_ntohs(tvb, offset);
    guint16 type    = aft & 0x7fff;
    guint16 len;
    guint32 val;
    guint pack_len;

    str = v2_aft2str(aft);

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u): %s (%u)",
			  str, type,
			  v2_attrval2str(type, val), val);
      offset += 4;
      length -= 4;
    }
    else {
      len = tvb_get_ntohs(tvb, offset + 2);
      pack_len = 4 + len;
      if (!get_num(tvb, offset + 4, len, &val)) {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): <too big (%u bytes)>",
			    str, type, len);
      } else {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): %s (%u)",
			    str, type,
			    v2_attrval2str(type, val), val);
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

static void
dissect_key_exch(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version, int unused _U_)
{
  guint16 dhgroup;

  if (isakmp_version == 2) {
    dhgroup = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2,
  		      "DH Group #: %u", dhgroup);
    offset += 4;
    length -= 4;
  }

  proto_tree_add_text(tree, tvb, offset, length, "Key Exchange Data");
}

static void
dissect_id(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo, int isakmp_version, int unused _U_)
{
  guint8		id_type;
  guint8		protocol_id;
  guint16		port;

  id_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "ID type: %s (%u)",
		      id2str(isakmp_version, id_type), id_type);
  offset += 1;
  length -= 1;

  protocol_id = tvb_get_guint8(tvb, offset);
  if (protocol_id == 0) {
    proto_tree_add_text(tree, tvb, offset, 1,
			"Protocol ID: Unused");
  } else {
    proto_tree_add_text(tree, tvb, offset, 1,
			"Protocol ID: %s (%u)",
			ipprotostr(protocol_id), protocol_id);
  }
  offset += 1;
  length -= 1;

  port = tvb_get_ntohs(tvb, offset);
  if (port == 0)
    proto_tree_add_text(tree, tvb, offset, 2, "Port: Unused");
  else
    proto_tree_add_text(tree, tvb, offset, 2, "Port: %u", port);
  offset += 2;
  length -= 2;

  /*
   * It shows strings of all types though some of types are not
   * supported in IKEv2 specification actually.
   */
  switch (id_type) {
    case IKE_ID_IPV4_ADDR:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s",
			  ip_to_str(tvb_get_ptr(tvb, offset, 4)));
      break;
    case IKE_ID_FQDN:
    case IKE_ID_USER_FQDN:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %.*s", length,
			  tvb_get_ptr(tvb, offset, length));
      break;
    case IKE_ID_IPV4_ADDR_SUBNET:
    case IKE_ID_IPV4_ADDR_RANGE:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s/%s",
			  ip_to_str(tvb_get_ptr(tvb, offset, 4)),
			  ip_to_str(tvb_get_ptr(tvb, offset+4, 4)));
      break;
    case IKE_ID_IPV6_ADDR:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s",
			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, 16)));
      break;
    case IKE_ID_IPV6_ADDR_SUBNET:
    case IKE_ID_IPV6_ADDR_RANGE:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s/%s",
			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, 16)),
			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset+16, 16)));
      break;
    case IKE_ID_DER_ASN1_DN:
      dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree,
			  hf_ike_certificate_authority);
      break;
    default:
      proto_tree_add_text(tree, tvb, offset, length, "Identification Data");
      break;
  }
}

static void
dissect_cert(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version, int unused _U_)
{
  guint8		cert_enc;

  cert_enc = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Certificate encoding: %u - %s",
		      cert_enc, certtype2str(isakmp_version, cert_enc));
  offset += 1;
  length -= 1;

  proto_tree_add_text(tree, tvb, offset, length, "Certificate Data");
}

static void
dissect_certreq_v1(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo, int isakmp_version, int unused _U_)
{
  guint8		cert_type;

  cert_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Certificate type: %u - %s",
		      cert_type, certtype2str(isakmp_version, cert_type));
  offset += 1;
  length -= 1;

  if (length) {
    if (cert_type == 4){
      dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_ike_certificate_authority);
    } else {
      proto_tree_add_text(tree, tvb, offset, length, "Certificate Authority");
    }
  }
  else
    proto_tree_add_text(tree, tvb, offset, length, "Certificate Authority (empty)");
}

static void
dissect_certreq_v2(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version, int unused _U_)
{
  guint8		cert_type;

  cert_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Certificate type: %u - %s",
		      cert_type, certtype2str(isakmp_version, cert_type));
  offset += 1;
  length -= 1;

  /* this is a list of 20 byte SHA-1 hashes */
  while (length > 0) {
    proto_tree_add_item(tree, hf_ike_v2_certificate_authority, tvb, offset, 20, FALSE);
    length-=20;
  }
}

static void
dissect_hash(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Hash Data");
}

static void
dissect_auth(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  guint8 auth;

  auth = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
  		      "Auth Method: %s (%u)", v2_auth2str(auth), auth);
  offset += 4;
  length -= 4;

  proto_tree_add_text(tree, tvb, offset, length, "Authentication Data");
}

static void
dissect_sig(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Signature Data");
}

static void
dissect_nonce(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Nonce Data");
}

static const char *
v2_ipcomptype2str(guint8 type)
{
  static const value_string vs_v2_ipcomptype[] = {
    { 0,	"RESERVED" },
    { 1,	"IPCOMP_OUI" },
    { 2,	"IPCOMP_DEFLATE" },
    { 3,	"IPCOMP_LZS" },
    { 4,	"IPCOMP_LZJH" },
    { 0,	NULL },
  };

  if (type >= 5 && type <= 240)
    return "RESERVED TO IANA";
  if (type >= 241)
    return "PRIVATE USE";
  return val_to_str(type, vs_v2_ipcomptype, "UNKNOWN-IPCOMP-TYPE");
}

static void
dissect_notif(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version, int unused _U_)
{
  guint32		doi;
  guint8		protocol_id;
  guint8		spi_size;
  guint16		msgtype;
  guint8		ipcomptype;

  if (isakmp_version == 1) {
    doi = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4,
  		      "Domain of Interpretation: %s (%u)",
  		      doitype2str(doi), doi);
    offset += 4;
    length -= 4;
  }

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Protocol ID: %s (%u)",
		      val_to_str(protocol_id, vs_proto, "UNKNOWN-PROTO-TYPE"), protocol_id);
  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "SPI size: %u", spi_size);
  offset += 1;
  length -= 1;

  msgtype = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Message type: %s (%u)",
		      msgtype2str(isakmp_version, msgtype), msgtype);
  offset += 2;
  length -= 2;

  if (spi_size) {
    proto_tree_add_text(tree, tvb, offset, spi_size, "SPI: 0x%s",
			tvb_bytes_to_str(tvb, offset, spi_size));
    offset += spi_size;
    length -= spi_size;
  }

  if (length > 0) {
    proto_tree_add_text(tree, tvb, offset, length, "Notification Data");

    /* notification data */
    if (isakmp_version == 2 && msgtype == 16387) {
      /* IPCOMP_SUPPORTED */
      proto_tree_add_text(tree, tvb, offset, 2,
      			"IPComp CPI (%u)", tvb_get_ntohs(tvb, offset));
      ipcomptype = tvb_get_guint8(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset + 2, 1,
      			"Transform ID: %s (%u)",
      			v2_ipcomptype2str(ipcomptype), ipcomptype);
      offset += 3;
      length -= 3;
    }
  }
}

static void
dissect_delete(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  guint32		doi;
  guint8		protocol_id;
  guint8		spi_size;
  guint16		num_spis;
  guint16		i;

  if (isakmp_version == 1) {
    doi = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4,
		        "Domain of Interpretation: %s (%u)",
		        doitype2str(doi), doi);
    offset += 4;
    length -= 4;
  }

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Protocol ID: %s (%u)",
		      val_to_str(protocol_id, vs_proto, "UNKNOWN-PROTO-TYPE"), protocol_id);
  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "SPI size: %u", spi_size);
  offset += 1;
  length -= 1;

  num_spis = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Number of SPIs: %u", num_spis);
  offset += 2;
  length -= 2;

  for (i = 0; i < num_spis; ++i) {
    if (length < spi_size) {
      proto_tree_add_text(tree, tvb, offset, length,
          "Not enough room in payload for all SPI's");
      break;
    }
    proto_tree_add_text(tree, tvb, offset, spi_size, "SPI: 0x%s",
			tvb_bytes_to_str(tvb, offset, spi_size));
    offset += spi_size;
    length -= spi_size;
  }
}

static void
dissect_vid(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  guint32 CPproduct, CPversion;
  const guint8 * pVID;
  proto_item * pt;
  proto_tree * ntree;
  pVID = tvb_get_ptr(tvb, offset, length);
  pt = proto_tree_add_text(tree, tvb, offset, length, "Vendor ID: ");
  if (memcmp(pVID, VID_MS_W2K_WXP, isakmp_min(VID_MS_LEN, length)) == 0)
	proto_item_append_text(pt, "Microsoft Win2K/WinXP");
  else
  if (memcmp(pVID, VID_CP, isakmp_min(VID_CP_LEN, length)) == 0)
  {
	proto_item_append_text(pt, "Check Point");
	offset += VID_CP_LEN;
	CPproduct = tvb_get_ntohl(tvb, offset);
	ntree = proto_item_add_subtree(pt, ett_isakmp_payload);
	pt = proto_tree_add_text(ntree, tvb, offset, sizeof(CPproduct), "Check Point Product: ");
	switch (CPproduct) {
		case 1: proto_item_append_text(pt, "VPN-1");
			break;
		case 2: proto_item_append_text(pt, "SecuRemote/SecureClient");
			break;
		default: proto_item_append_text(pt, "Unknown CP product!");
			break;
	}
	offset += sizeof(CPproduct);
	CPversion = tvb_get_ntohl(tvb, offset);
	pt = proto_tree_add_text(ntree, tvb, offset, sizeof(CPversion), "Version: ");
	switch (CPversion) {
		case 2: proto_item_append_text(pt, "4.1");
			break;
		case 3: proto_item_append_text(pt, "4.1 SP-1");
			break;
		case 4002: proto_item_append_text(pt, "4.1 (SP-2 or above)");
			break;
		case 5000: proto_item_append_text(pt, "NG");
			break;
		case 5001: proto_item_append_text(pt, "NG Feature Pack 1");
			break;
		case 5002: proto_item_append_text(pt, "NG Feature Pack 2");
			break;
		case 5003: proto_item_append_text(pt, "NG Feature Pack 3");
			break;
		case 5004: proto_item_append_text(pt, "NG with Application Intelligence");
			break;
		case 5005: proto_item_append_text(pt, "NG with Application Intelligence R55");
			break;
		default: proto_item_append_text(pt, " Unknown CP version!");
			break;
	}
	offset += sizeof(CPversion);
	proto_tree_add_text(ntree, tvb, offset, length - VID_CP_LEN - sizeof(CPproduct) - sizeof(CPversion),"Check Point Vendor ID parameters"); 
  }
  else
  if (memcmp(pVID, VID_CYBERGUARD, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Cyber Guard");
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_03, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-ietf-ipsec-nat-t-ike-03");
  else
  if (memcmp(pVID,  VID_rfc3947, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "RFC 3947 Negotiation of NAT-Traversal in the IKE");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_1_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 1.1.0");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_1_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 1.1.1");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_1_2, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 1.1.2");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_2_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 1.2.1");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_2_2, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 1.2.2");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_2_0_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 2.0.0");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_2_1_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 2.1.0");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_2_1_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 2.1.1");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_2_1_2, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 2.1.2");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_3_0_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 3.0.0");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_3_0_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 3.0.1");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_4_0_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 4.0.0");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_4_0_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 4.0.1");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_4_1_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 4.1.0");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_4_1_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 4.1.1");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_5_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 5.0");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_5_0_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 5.0.0");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_5_1_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 5.1.0");
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_5_1_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Ssh Communications Security IPSEC Express version 5.1.1");
  else
  if (memcmp(pVID,  VID_SSH_SENTINEL, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "SSH Sentinel");
  else
  if (memcmp(pVID,  VID_SSH_SENTINEL_1_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "SSH Sentinel 1.1");
  else
  if (memcmp(pVID,  VID_SSH_SENTINEL_1_2, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "SSH Sentinel 1.2");
  else
  if (memcmp(pVID,  VID_SSH_SENTINEL_1_3, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "SSH Sentinel 1.3");
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_0_9_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "SSH Communications Security QuickSec 0.9.0");
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_1_1_0, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "SSH Communications Security QuickSec 1.1.0");
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_1_1_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "SSH Communications Security QuickSec 1.1.1");
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_1_1_2, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "SSH Communications Security QuickSec 1.1.2");
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_1_1_3, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "SSH Communications Security QuickSec 1.1.3");
  else
  if (memcmp(pVID,  VID_draft_huttunen_ipsec_esp_in_udp_01, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-huttunen-ipsec-esp-in-udp-01.txt");
  else
  if (memcmp(pVID,  VID_draft_stenberg_ipsec_nat_traversal_01, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-stenberg-ipsec-nat-traversal-01");
  else
  if (memcmp(pVID,  VID_draft_stenberg_ipsec_nat_traversal_02, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-stenberg-ipsec-nat-traversal-02");
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_00, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-ietf-ipsec-nat-t-ike-00");
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_02a, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-ietf-ipsec-nat-t-ike-02");
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_02b, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-ietf-ipsec-nat-t-ike-02");
  else
  if (memcmp(pVID,  VID_draft_beaulieu_ike_xauth_02, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-beaulieu-ike-xauth-02.txt");
  else
  if (memcmp(pVID,  VID_rfc3706_dpd, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "RFC 3706 Detecting Dead IKE Peers (DPD)");
  else
  if (memcmp(pVID,  VID_IKE_CHALLENGE_RESPONSE_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "IKE Challenge/Response for Authenticated Cryptographic Keys");
  else
  if (memcmp(pVID,  VID_IKE_CHALLENGE_RESPONSE_2, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "IKE Challenge/Response for Authenticated Cryptographic Keys");
  else
  if (memcmp(pVID,  VID_IKE_CHALLENGE_RESPONSE_REV_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)");
  else
  if (memcmp(pVID,  VID_IKE_CHALLENGE_RESPONSE_REV_2, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)");
  else
  if (memcmp(pVID,  VID_MS_L2TP_IPSEC_VPN_CLIENT, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Microsoft L2TP/IPSec VPN Client");
  else
  if (memcmp(pVID,  VID_GSS_API_1, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "A GSS-API Authentication Method for IKE");
  else
  if (memcmp(pVID,  VID_GSS_API_2, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "A GSS-API Authentication Method for IKE");
  else
  if (memcmp(pVID,  VID_GSSAPI, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "GSSAPI");
  else
  if (memcmp(pVID,  VID_MS_NT5_ISAKMPOAKLEY, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "MS NT5 ISAKMPOAKLEY");
  else
  if (memcmp(pVID,  VID_CISCO_UNITY, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "CISCO-UNITY");
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_antireplay_00, isakmp_min(VID_LEN_8, length)) == 0)
        proto_item_append_text(pt, "draft-ietf-ipsec-antireplay-00.txt");
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_heartbeats_00, isakmp_min(VID_LEN_8, length)) == 0)
        proto_item_append_text(pt, "draft-ietf-ipsec-heartbeats-00.txt");
  else
        proto_item_append_text(pt, "unknown vendor ID: 0x%s",tvb_bytes_to_str(tvb, offset, length));
}

static void
dissect_config(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version, int unused _U_)
{
  guint8		type;

  if (isakmp_version == 1) {
    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
    			"Type %s (%u)",
    			cfgtype2str(isakmp_version, type), type);
    offset += 2;
    length -= 2;

    proto_tree_add_text(tree, tvb, offset, 2,
    			"Identifier: %u", tvb_get_ntohs(tvb, offset));
    offset += 2;
    length -= 2;
  } else if (isakmp_version == 2) {
    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
    			"CFG Type %s (%u)",
    			cfgtype2str(isakmp_version, type), type);
    offset += 4;
    length -= 4;
  }

  while(length>0) {
    guint16 aft     = tvb_get_ntohs(tvb, offset);
    guint16 type    = aft & 0x7fff;
    guint16 len;
    guint32 val;
    guint pack_len;

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u)",
			  cfgattr2str(isakmp_version, type), val);
      offset += 4;
      length -= 4;
    }
    else {
      len = tvb_get_ntohs(tvb, offset + 2);
      pack_len = 4 + len;
      if (!get_num(tvb, offset + 4, len, &val)) {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s: <too big (%u bytes)>",
			    cfgattr2str(isakmp_version, type), len);
      } else {
        proto_tree_add_text(tree, tvb, offset, 4,
			    "%s (%ue)",
			    cfgattr2str(isakmp_version, type), val);
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

static void
dissect_nat_discovery(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length,
		      "Hash of address and port: %s",
		      tvb_bytes_to_str(tvb, offset, length));
}

static void
dissect_nat_original_address(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version, int unused _U_)
{
  guint8 id_type;
  guint32 addr_ipv4;
  struct e_in6_addr addr_ipv6;

  id_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "ID type: %s (%u)",
		      id2str(isakmp_version, id_type), id_type);
  offset += 1;
  length -= 1;

  offset += 3;		/* reserved */
  length -= 3;

  switch (id_type) {

  case IKE_ID_IPV4_ADDR:
    if (length == 4) {
      addr_ipv4 = tvb_get_ipv4(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: %s",
			  ip_to_str((guint8 *)&addr_ipv4));
    } else {
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: bad length, should be 4, is %u",
			  length);
    }
    break;

  case IKE_ID_IPV6_ADDR:
    if (length == 16) {
      tvb_get_ipv6(tvb, offset, &addr_ipv6);
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: %s",
			  ip6_to_str(&addr_ipv6));
    } else {
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: bad length, should be 16, is %u",
			  length);
    }
    break;

  default:
    proto_tree_add_text(tree, tvb, offset, length,
			"Original address: bad address type");
    break;
  }
}

static void
dissect_ts(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  guint8	num, tstype, protocol_id, addrlen;
  guint16	len, port;

  proto_tree_add_text(tree, tvb, offset, length, "Traffic Selector");

  num = tvb_get_guint8(tvb, offset);
  proto_item_append_text(tree," # %d", num);
  proto_tree_add_text(tree, tvb, offset, 1,
  		      "Number of TSs: %u", num);
  offset += 4;
  length -= 4;

  while (length > 0) {
    tstype = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
  		      "TS Type: %s (%u)",
  		      v2_tstype2str(tstype), tstype);
    switch (tstype) {
    case IKEV2_TS_IPV4_ADDR_RANGE:
      addrlen = 4;
      break;
    case IKEV2_TS_IPV6_ADDR_RANGE:
      addrlen = 16;
      break;
    default:
      proto_item_append_text(tree, "unknown TS data (aborted decoding): 0x%s",
			tvb_bytes_to_str(tvb, offset, length));
      return;
    }

    /*
     * XXX should the remaining of the length check be done here ?
     * it seems other routines don't check the length.
     */
    if (length < (8 + addrlen * 2)) {
      proto_tree_add_text(tree, tvb, offset, length,
			  "Length mismatch (%u)", length);
      return;
    }
    offset += 1;
    length -= 1;

    protocol_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
  		      "Protocol ID: (%u)", protocol_id);
    offset += 1;
    length -= 1;

    len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2,
  		      "Selector Length: %u", len);
    offset += 2;
    length -= 2;

    port = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2,
  		      "Start Port: (%u)", port);
    offset += 2;
    length -= 2;

    port = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2,
  		      "End Port: (%u)", port);
    offset += 2;
    length -= 2;

    switch (tstype) {
    case IKEV2_TS_IPV4_ADDR_RANGE:
	proto_tree_add_text(tree, tvb, offset, length,
			  "Starting Address: %s",
			  ip_to_str(tvb_get_ptr(tvb, offset, addrlen)));
	offset += addrlen;
	length -= addrlen;
	proto_tree_add_text(tree, tvb, offset, length,
  			  "Ending Address: %s",
  			  ip_to_str(tvb_get_ptr(tvb, offset, addrlen)));
	offset += addrlen;
	length -= addrlen;
	break;
    case IKEV2_TS_IPV6_ADDR_RANGE:
	proto_tree_add_text(tree, tvb, offset, length,
			  "Starting Address: %s",
			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, addrlen)));
	offset += addrlen;
	length -= addrlen;
	proto_tree_add_text(tree, tvb, offset, length,
  			  "Ending Address: %s",
  			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, addrlen)));
	offset += addrlen;
	length -= addrlen;
	break;
    }
  }
}

static void
dissect_enc(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, 4, "Initialization Vector: 0x%s",
                      tvb_bytes_to_str(tvb, offset, 4));
  proto_tree_add_text(tree, tvb, offset + 4, length, "Encrypted Data");
}

static void
dissect_eap(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "EAP Message");
}

static const char *
payloadtype2str(int isakmp_version, guint8 type)
{
  struct payload_func *f;

  if ((f = getpayload_func(type, isakmp_version)) != NULL)
      return f->str;

  if (isakmp_version == 1) {
    if (type < 128)
      return "RESERVED";
    return "Private USE";
  } else if (isakmp_version == 2) {
    if (type > 127)
      return "PRIVATE USE";
    if (type > 48)
      return "RESERVED TO IANA";
    return "RESERVED";
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
exchtype2str(int isakmp_version, guint8 type)
{
  static const value_string vs_v1_exchange[] = {
    { 0,	"NONE" },
    { 1,	"Base" },
    { 2,	"Identity Protection (Main Mode)" },
    { 3,	"Authentication Only" },
    { 4,	"Aggressive" },
    { 5,	"Informational" },
    { 6,	"Transaction (Config Mode)" },
    { 32,	"Quick Mode" },
    { 33,	"New Group Mode" },
    { 0,	NULL },
  };

  static const value_string vs_v2_exchange[] = {
    { 34,	"IKE_SA_INIT" },
    { 35,	"IKE_AUTH " },
    { 36,	"CREATE_CHILD_SA" },
    { 37,	"INFORMATIONAL" },
    { 0,	NULL },
  };

  if (isakmp_version == 1) {
    if (type > 6 && type < 32)
      return "ISAKMP Future Use";
    if (type > 33 && type < 240)
      return "DOI Specific Use";
    return val_to_str(type, vs_v1_exchange, "Private Use");
  } else if (isakmp_version == 2) {
    if (type < 34)
      return "RESERVED";
    if (type > 37 && type < 240)
      return "Reserved for IKEv2+";
    return val_to_str(type, vs_v2_exchange, "Reserved for private use");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
doitype2str(guint32 type)
{
  if (type == 1) return "IPSEC";
  return "Unknown DOI Type";
}

static const char *
msgtype2str(int isakmp_version, guint16 type)
{
  static const value_string vs_v1_notifmsg[] = {
    { 0,	"<UNKNOWN>" },
    { 1,	"INVALID-PAYLOAD-TYPE" },
    { 2,	"DOI-NOT-SUPPORTED" },
    { 3,	"SITUATION-NOT-SUPPORTED" },
    { 4,	"INVALID-COOKIE" },
    { 5,	"INVALID-MAJOR-VERSION" },
    { 6,	"INVALID-MINOR-VERSION" },
    { 7,	"INVALID-EXCHANGE-TYPE" },
    { 8,	"INVALID-FLAGS" },
    { 9,	"INVALID-MESSAGE-ID" },
    { 10,	"INVALID-PROTOCOL-ID" },
    { 11,	"INVALID-SPI" },
    { 12,	"INVALID-TRANSFORM-ID" },
    { 13,	"ATTRIBUTES-NOT-SUPPORTED" },
    { 14,	"NO-PROPOSAL-CHOSEN" },
    { 15,	"BAD-PROPOSAL-SYNTAX" },
    { 16,	"PAYLOAD-MALFORMED" },
    { 17,	"INVALID-KEY-INFORMATION" },
    { 18,	"INVALID-ID-INFORMATION" },
    { 19,	"INVALID-CERT-ENCODING" },
    { 20,	"INVALID-CERTIFICATE" },
    { 21,	"CERT-TYPE-UNSUPPORTED" },
    { 22,	"INVALID-CERT-AUTHORITY" },
    { 23,	"INVALID-HASH-INFORMATION" },
    { 24,	"AUTHENTICATION-FAILED" },
    { 25,	"INVALID-SIGNATURE" },
    { 26,	"ADDRESS-NOTIFICATION" },
    { 27,	"NOTIFY-SA-LIFETIME" },
    { 28,	"CERTIFICATE-UNAVAILABLE" },
    { 29,	"UNSUPPORTED-EXCHANGE-TYPE" },
    { 30,	"UNEQUAL-PAYLOAD-LENGTHS" },
    { 8192,	"RESERVED" },
    { 16384,	"CONNECTED" },
    { 24576,	"RESPONDER-LIFETIME" },
    { 24577,	"REPLAY-STATUS" },
    { 24578,	"INITIAL-CONTACT" },
    { 0,	NULL },
  };

  static const value_string vs_v2_notifmsg[] = {
    {     0,	"RESERVED" },
    {     4,	"INVALID_IKE_SPI" },
    {     5,	"INVALID_MAJOR_VERSION" },
    {     7,	"INVALID_SYNTAX" },
    {     9,	"INVALID_MESSAGE_ID" },
    {    11,	"INVALID_SPI" },
    {    14,	"NO_PROPOSAL_CHOSEN" },
    {    17,	"INVALID_KE_PAYLOAD" },
    {    24,	"AUTHENTICATION_FAILED" },
    {    34,	"SINGLE_PAIR_REQUIRED" },
    {    35,	"NO_ADDITIONAL_SAS" },
    {    36,	"INTERNAL_ADDRESS_FAILURE" },
    {    37,	"FAILED_CP_REQUIRED" },
    {    38,	"TS_UNACCEPTABLE" },
    {    39,	"INVALID_SELECTORS" },
    { 16384,	"INITIAL_CONTACT" },
    { 16385,	"SET_WINDOW_SIZE" },
    { 16386,	"ADDITIONAL_TS_POSSIBLE" },
    { 16387,	"IPCOMP_SUPPORTED" },
    { 16388,	"NAT_DETECTION_SOURCE_IP" },
    { 16389,	"NAT_DETECTION_DESTINATION_IP" },
    { 16390,	"COOKIE" },
    { 16391,	"USE_TRANSPORT_MODE" },
    { 16392,	"HTTP_CERT_LOOKUP_SUPPORTED" },
    { 16393,	"REKEY_SA" },
    { 16394,	"ESP_TFC_PADDING_NOT_SUPPORTED" },
    { 16395,	"NON_FIRST_FRAGMENTS_ALSO" },
    { 0,	NULL },
  };

  if (isakmp_version == 1) {
    if (type > 30 && type < 8192)
      return "RESERVED (Future Use)";
    if (type > 8192 && type < 16384)
      return "Private Use";
    if (type > 16384 && type < 24576)
      return "RESERVED (Future Use) - status";
    if (type > 24578 && type < 32768)
      return "DOI-specific codes";
    if (type > 32767 && type < 40960)
      return "Private Use - status";
    if (type > 40959 && type < 65535)
      return "RESERVED (Future Use) - status (2)";
    return val_to_str(type, vs_v1_notifmsg, "UNKNOWN-NOTIFY-MESSAGE-TYPE");
  } else if (isakmp_version == 2) {
    if (type >= 40 && type <= 8191)
      return "RESERVED TO IANA - Error types";
    if (type >= 16396 && type <= 40959)
      return "RESERVED TO IANA - STATUS TYPES";
    if (type >= 8192 && type <= 16383)
      return "Private Use - Errors";
    if (type >= 40960)
      return "Private Use - STATUS TYPES";
    return val_to_str(type, vs_v2_notifmsg, "UNKNOWN-NOTIFY-MESSAGE-TYPE");
  } 
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
situation2str(guint32 type)
{

#define SIT_MSG_NUM	1024
#define SIT_IDENTITY	0x01
#define SIT_SECRECY	0x02
#define SIT_INTEGRITY	0x04

  static char	msg[SIT_MSG_NUM];
  int		n = 0;
  const char *	sep = "";
  int		ret;

  if (type & SIT_IDENTITY) {
    ret = g_snprintf(msg, SIT_MSG_NUM-n, "%sIDENTITY", sep);
    if (ret == -1 || ret >= SIT_MSG_NUM-n) {
      /* Truncated. */
      msg[SIT_MSG_NUM-1] = '\0';
      return msg;
    }
    n += ret;
    sep = " & ";
  }
  if (type & SIT_SECRECY) {
    if (n >= SIT_MSG_NUM) {
      /* No more room. */
      return msg;
    }
    ret = g_snprintf(msg, SIT_MSG_NUM-n, "%sSECRECY", sep);
    if (ret == -1 || ret >= SIT_MSG_NUM-n) {
      /* Truncated. */
      msg[SIT_MSG_NUM-1] = '\0';
      return msg;
    }
    n += ret;
    sep = " & ";
  }
  if (type & SIT_INTEGRITY) {
    if (n >= SIT_MSG_NUM) {
      /* No more room. */
      return msg;
    }
    ret = g_snprintf(msg, SIT_MSG_NUM-n, "%sINTEGRITY", sep);
    if (ret == -1 || ret >= SIT_MSG_NUM-n) {
      /* Truncated. */
      msg[SIT_MSG_NUM-1] = '\0';
      return msg;
    }
    n += ret;
    sep = " & ";
  }

  return msg;
}

static const char *
v2_attrval2str(guint16 att_type, guint32 value)
{
  value = 0;	/* dummy to be less warning in compiling it */
  switch (att_type) {
  case 14:
    return "Key-Length";
  default:
    return "UNKNOWN-ATTRIBUTE-TYPE";
  }
}

static const char *
v1_attrval2str(int ike_p1, guint16 att_type, guint32 value)
{
  static const value_string vs_v1_attrval_lttype[] = {
    { 0,	"RESERVED" },
    { 1,	"Seconds" },
    { 2,	"Kilobytes" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_encap[] = {
    { 0,	"RESERVED" },
    { 1,	"Tunnel" },
    { 2,	"Transport" },
    { 3,	"UDP-Encapsulated-Tunnel" }, /* http://www.ietf.org/internet-drafts/draft-ietf-ipsec-nat-t-ike-05.txt */
    { 4,	"UDP-Encapsulated-Transport" }, /* http://www.ietf.org/internet-drafts/draft-ietf-ipsec-nat-t-ike-05.txt */
    { 61440,	"Check Point IPSec UDP Encapsulation" },
    { 61443,	"UDP-Encapsulated-Tunnel (draft)" },
    { 61444,	"UDP-Encapsulated-Transport (draft)" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_auth[] = {
    { 0,	"RESERVED" },
    { 1,	"HMAC-MD5" },
    { 2,	"HMAC-SHA" },
    { 3,	"DES-MAC" },
    { 4,	"KPDK" },
    { 5,	"HMAC-SHA2-256" },
    { 6,	"HMAC-SHA2-384" },
    { 7,	"HMAC-SHA2-512" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_enc[] = {
    { 0,	"RESERVED" },
    { 1,	"DES-CBC" },
    { 2,	"IDEA-CBC" },
    { 3,	"BLOWFISH-CBC" },
    { 4,	"RC5-R16-B64-CBC" },
    { 5,	"3DES-CBC" },
    { 6,	"CAST-CBC" },
    { 7,	"AES-CBC" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_hash[] = {
    { 0,	"RESERVED" },
    { 1,	"MD5" },
    { 2,	"SHA" },
    { 3,	"TIGER" },
    { 4,	"SHA2-256" },
    { 5,	"SHA2-384" },
    { 6,	"SHA2-512" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_authmeth[] = {
    { 0,	"RESERVED" },
    { 1,	"PSK" },
    { 2,	"DSS-SIG" },
    { 3,	"RSA-SIG" },
    { 4,	"RSA-ENC" },
    { 5,	"RSA-Revised-ENC" },
    { 6,	"Encryption with El-Gamal" },
    { 7,	"Revised encryption with El-Gamal" },
    { 8,	"ECDSA signatures" },
    { 9,	"AES-XCBC-MAC" },
    { 64221,	"HybridInitRSA" },
    { 64222,	"HybridRespRSA" },
    { 64223,	"HybridInitDSS" },
    { 64224,	"HybridRespDSS" },
    { 65001,	"XAUTHInitPreShared" },
    { 65002,	"XAUTHRespPreShared" },
    { 65003,	"XAUTHInitDSS" },
    { 65004,	"XAUTHRespDSS" },
    { 65005,	"XAUTHInitRSA" },
    { 65006,	"XAUTHRespRSA" },
    { 65007,	"XAUTHInitRSAEncryption" },
    { 65008,	"XAUTHRespRSAEncryption" },
    { 65009,	"XAUTHInitRSARevisedEncryption" },
    { 65010,	"XAUTHRespRSARevisedEncryption" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_grpdesc[] = {
    { 0,	"UNDEFINED - 0" },
    { 1,	"Default 768-bit MODP group" },
    { 2,	"Alternate 1024-bit MODP group" },
    { 3,	"EC2N group on GP[2^155] group" },
    { 4,	"EC2N group on GP[2^185] group" },
    { 5,	"1536 bit MODP group" },
    { 6,	"EC2N group over GF[2^163]" },
    { 7,	"EC2N group over GF[2^163]" },
    { 8,	"EC2N group over GF[2^283]" },
    { 9,	"EC2N group over GF[2^283]" },
    { 10,	"EC2N group over GF[2^409]" },
    { 11,	"EC2N group over GF[2^409]" },
    { 12,	"EC2N group over GF[2^571]" },
    { 13,	"EC2N group over GF[2^571]" },
    { 14,	"2048 bit MODP group" },
    { 15,	"3072 bit MODP group" },
    { 16,	"4096 bit MODP group" },
    { 17,	"6144 bit MODP group" },
    { 18,	"8192 bit MODP group" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_grptype[] = {
    { 0,	"UNDEFINED - 0" },
    { 1,	"MODP" },
    { 2,	"ECP" },
    { 3,	"EC2N" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_lifetype[] = {
    { 0,	"UNDEFINED - 0" },
    { 1,	"Seconds" },
    { 2,	"Kilobytes" },
    { 0,	NULL },
  };

  if (value == 0) return "RESERVED";

  if (!ike_p1) {
    switch (att_type) {
      case 1:
        return val_to_str(value, vs_v1_attrval_lttype, "UNKNOWN-LIFETIME-TYPE");
      case 2:
        return "Duration-Value";
      case 3:
        return "Group-Value";
      case 4:
        return val_to_str(value, vs_v1_attrval_encap, "UNKNOWN-ENCAPSULATION-VALUE");
      case 5:
        return val_to_str(value, vs_v1_attrval_auth, "UNKNOWN-AUTHENTICATION-VALUE");
      case 6:
        return "Key-Length";
      case 7:
        return "Key-Rounds";
      case 8:
        return "Compress-Dictionary-size";
      case 9:
        return "Compress Private Algorithm";
      default:
        return "UNKNOWN-ATTRIBUTE-TYPE";
    }
  }
  else {
    switch (att_type) {
      case 1:
        return val_to_str(value, vs_v1_attrval_enc, "UNKNOWN-ENCRYPTION-ALG");
      case 2:
        return val_to_str(value, vs_v1_attrval_hash, "UNKNOWN-HASH-ALG");
      case 3:
        return val_to_str(value, vs_v1_attrval_authmeth, "UNKNOWN-AUTH-METHOD");
      case 4:
        return val_to_str(value, vs_v1_attrval_grpdesc, "UNKNOWN-GROUP-DESCRIPTION");
      case 6:
      case 7:
      case 8:
      case 9:
      case 10:
      case 16:
        return "Group-Value";
      case 5:
        return val_to_str(value, vs_v1_attrval_grptype, "UNKNOWN-GROUP-TYPE");
      case 11:
        return val_to_str(value, vs_v1_attrval_lifetype, "UNKNOWN-LIFE-TYPE");
      case 12:
        return "Duration-Value";
      case 13:
        return "PRF-Value";
      case 14:
        return "Key-Length";
      case 15:
        return "Field-Size";
      default:
        return "UNKNOWN-ATTRIBUTE-TYPE";
    }
  }
}

static const char *
cfgtype2str(int isakmp_version, guint8 type)
{
  static const value_string vs_v1_cfgtype[] = {
    { 0,	"Reserved" },
    { 1,	"ISAKMP_CFG_REQUEST" },
    { 2,	"ISAKMP_CFG_REPLY" },
    { 3,	"ISAKMP_CFG_SET" },
    { 4,	"ISAKMP_CFG_ACK" },
    { 0,	NULL },
  };

#if 0
  static const value_string vs_v2_cfgtype[] = {
    { 0,	"RESERVED" },
    { 1,	"CFG_REQUEST" },
    { 2,	"CFG_REPLY" },
    { 3,	"CFG_SET" },
    { 4,	"CFG_ACK" },
    { 0,	NULL },
  };
#endif

  if (isakmp_version == 1) {
    if (type >= 5 && type <= 127)
      return "Future use";
    if (type >= 128)
      return "Private Use";
    return val_to_str(type, vs_v1_cfgtype, "UNKNOWN-CFG-TYPE");
  } else if (isakmp_version == 2) {
    if (type >= 5 && type <= 127)
      return "RESERVED TO IANA";
    if (type >= 128)
      return "PRIVATE USE";
    return val_to_str(type, vs_v1_cfgtype, "UNKNOWN-CFG-TYPE");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
id2str(int isakmp_version, guint8 type)
{
  static const value_string vs_ident[] = {
    { IKE_ID_IPV4_ADDR,		"IPV4_ADDR" },
    { IKE_ID_FQDN,		"FQDN" },
    { IKE_ID_USER_FQDN,		"USER_FQDN" },
    { IKE_ID_IPV4_ADDR_SUBNET,	"IPV4_ADDR_SUBNET" },
    { IKE_ID_IPV6_ADDR,		"IPV6_ADDR" },
    { IKE_ID_IPV6_ADDR_SUBNET,	"IPV6_ADDR_SUBNET" },
    { IKE_ID_IPV4_ADDR_RANGE,	"IPV4_ADDR_RANGE" },
    { IKE_ID_IPV6_ADDR_RANGE,	"IPV6_ADDR_RANGE" },
    { IKE_ID_DER_ASN1_DN,	"DER_ASN1_DN" },
    { IKE_ID_DER_ASN1_GN,	"DER_ASN1_GN" },
    { IKE_ID_KEY_ID,		"KEY_ID" },
    { 0,			NULL },
  };

  if (isakmp_version == 1) {
    if (type == 0)
      return "RESERVED";
    return val_to_str(type, vs_ident, "UNKNOWN-ID-TYPE");
  } else if (isakmp_version == 2) {
    if (type == 4 || (type >= 6 && type <=8) || (type >= 12 && type <= 200))
      return "Reserved to IANA";
    if (type >= 201)
      return "Reserved for private use";
    if (type == IKE_ID_USER_FQDN)
      return "RFC822_ADDR";
    return val_to_str(type, vs_ident, "UNKNOWN-ID-TYPE");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
v2_tstype2str(guint8 type)
{
  static const value_string vs_v2_tstype[] = {
    { IKEV2_TS_IPV4_ADDR_RANGE,	"TS_IPV4_ADDR_RANGE" },
    { IKEV2_TS_IPV6_ADDR_RANGE,	"TS_IPV6_ADDR_RANGE" },
    { 0,	NULL },
  };

  if (type <= 6)
    return "RESERVED";
  if (type >= 9 && type <= 240)
    return "RESERVED TO IANA";
  if (type >= 241)
    return "PRIVATE USE";
  return val_to_str(type, vs_v2_tstype, "UNKNOWN-TS-TYPE");
}

static const char *
v2_auth2str(guint8 type)
{
  static const value_string vs_v2_authmeth[] = {
    { 0,	"RESERVED TO IANA" },
    { 1,	"RSA Digital Signature" },
    { 2,	"Shared Key Message Integrity Code" },
    { 3,	"DSS Digital Signature" },
    { 0,	NULL },
  };

  if (type >= 4 && type <= 200)
    return "RESERVED TO IANA";
  if (type >= 201)
    return "PRIVATE USE";
  return val_to_str(type, vs_v2_authmeth, "UNKNOWN-AUTHMETHOD-TYPE");
}

static const char *
cfgattr2str(int isakmp_version, guint16 ident)
{
  static const value_string vs_v1_cfgattr[] = {
    { 0,	"RESERVED" },
    { 1,	"INTERNAL_IP4_ADDRESS" },
    { 2,	"INTERNAL_IP4_NETMASK" },
    { 3,	"INTERNAL_IP4_DNS" },
    { 4,	"INTERNAL_IP4_NBNS" },
    { 5,	"INTERNAL_ADDRESS_EXPIREY" },
    { 6,	"INTERNAL_IP4_DHCP" },
    { 7,	"APPLICATION_VERSION" },
    { 8,	"INTERNAL_IP6_ADDRESS" },
    { 9,	"INTERNAL_IP6_NETMASK" },
    { 10,	"INTERNAL_IP6_DNS" },
    { 11,	"INTERNAL_IP6_NBNS" },
    { 12,	"INTERNAL_IP6_DHCP" },
    { 13,	"INTERNAL_IP4_SUBNET" },
    { 14,	"SUPPORTED_ATTRIBUTES" },
    { 16520,	"XAUTH_TYPE" },
    { 16521,	"XAUTH_USER_NAME" },
    { 16522,	"XAUTH_USER_PASSWORD" },
    { 16523,	"XAUTH_PASSCODE" },
    { 16524,	"XAUTH_MESSAGE" },
    { 16525,	"XAUTH_CHALLANGE" },
    { 16526,	"XAUTH_DOMAIN" },
    { 16527,	"XAUTH_STATUS" },
    { 16528,	"XAUTH_NEXT_PIN" },
    { 16529,	"XAUTH_ANSWER" },
    { 0,	NULL },
  };

  static const value_string vs_v2_cfgattr[] = {
    { 0,	"RESERVED" },
    { 1,	"INTERNAL_IP4_ADDRESS" },
    { 2,	"INTERNAL_IP4_NETMASK" },
    { 3,	"INTERNAL_IP4_DNS" },
    { 4,	"INTERNAL_IP4_NBNS" },
    { 5,	"INTERNAL_ADDRESS_EXPIREY" },
    { 6,	"INTERNAL_IP4_DHCP" },
    { 7,	"APPLICATION_VERSION" },
    { 8,	"INTERNAL_IP6_ADDRESS" },
    { 9,	"RESERVED" },
    { 10,	"INTERNAL_IP6_DNS" },
    { 11,	"INTERNAL_IP6_NBNS" },
    { 12,	"INTERNAL_IP6_DHCP" },
    { 13,	"INTERNAL_IP4_SUBNET" },
    { 14,	"SUPPORTED_ATTRIBUTES" },
    { 15,	"INTERNAL_IP6_SUBNET" },
    { 0,	NULL },
  };

  if (isakmp_version == 1) {
    if (ident >= 15 && ident <= 16383)
      return "Future use";
    if (ident >= 16384 && ident <= 16519)
      return "PRIVATE USE";
    if (ident >= 16530 && ident <= 32767)
      return "PRIVATE USE";
    return val_to_str(ident, vs_v1_cfgattr, "UNKNOWN-CFG-ATTRIBUTE");
  } else if (isakmp_version == 2) {
    if (ident >= 16 && ident <= 16383)
      return "RESERVED TO IANA";
    if (ident >= 16384 && ident <= 32767)
      return "PRIVATE USE";
    return val_to_str(ident, vs_v2_cfgattr, "UNKNOWN-CFG-ATTRIBUTE");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
certtype2str(int isakmp_version, guint8 type)
{
  static const value_string vs_v1_certtype[] = {
    { 0,	"NONE" },
    { 1,	"PKCS #7 wrapped X.509 certificate" },
    { 2,	"PGP Certificate" },
    { 3,	"DNS Signed Key" },
    { 4,	"X.509 Certificate - Signature" },
    { 5,	"X.509 Certificate - Key Exchange" },
    { 6,	"Kerberos Tokens" },
    { 7,	"Certificate Revocation List (CRL)" },
    { 8,	"Authority Revocation List (ARL)" },
    { 9,	"SPKI Certificate" },
    { 10,	"X.509 Certificate - Attribute" },
    { 0,	NULL },
  };

  static const value_string vs_v2_certtype[] = {
    { 0,	"RESERVED" },
    { 1,	"PKCS #7 wrapped X.509 certificate" },
    { 2,	"PGP Certificate" },
    { 3,	"DNS Signed Key" },
    { 4,	"X.509 Certificate - Signature" },
    { 5,	"*undefined by any document*" },
    { 6,	"Kerberos Tokens" },
    { 7,	"Certificate Revocation List (CRL)" },
    { 8,	"Authority Revocation List (ARL)" },
    { 9,	"SPKI Certificate" },
    { 10,	"X.509 Certificate - Attribute" },
    { 11,	"Raw RSA Key" },
    { 12,	"Hash and URL of X.509 certificate" },
    { 13,	"Hash and URL of X.509 bundle" },
    { 0,	NULL },
  };

  if (isakmp_version == 1)
    return val_to_str(type, vs_v1_certtype, "RESERVED");
  else if (isakmp_version == 2) {
    if (type >= 14 && type <= 200)
      return "RESERVED to IANA";
    if (type >= 201)
      return "PRIVATE USE";
    return val_to_str(type, vs_v2_certtype, "RESERVED");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static gboolean
get_num(tvbuff_t *tvb, int offset, guint16 len, guint32 *num_p)
{
  switch (len) {
  case 1:
    *num_p = tvb_get_guint8(tvb, offset);
    break;
  case 2:
    *num_p = tvb_get_ntohs(tvb, offset);
    break;
  case 3:
    *num_p = tvb_get_ntoh24(tvb, offset);
    break;
  case 4:
    *num_p = tvb_get_ntohl(tvb, offset);
    break;
  default:
    return FALSE;
  }

  return TRUE;
}

void
proto_register_isakmp(void)
{
  static hf_register_info hf[] = {
    { &hf_ike_certificate_authority,
      { "Certificate Authority Distinguished Name", "ike.cert_authority_dn", FT_UINT32, BASE_DEC, NULL, 0x0, "Certificate Authority Distinguished Name", HFILL }
    },
    { &hf_ike_v2_certificate_authority,
      { "Certificate Authority", "ike.cert_authority", FT_BYTES, BASE_HEX, NULL, 0x0, "SHA-1 hash of the Certificate Authority", HFILL }
    },
    { &hf_ike_nat_keepalive,
      { "NAT Keepalive", "ike.nat_keepalive", FT_NONE, BASE_HEX, NULL, 0x0, "NAT Keepalive packet", HFILL }
    },
  };
  static gint *ett[] = {
    &ett_isakmp,
    &ett_isakmp_flags,
    &ett_isakmp_payload,
  };

  proto_isakmp = proto_register_protocol("Internet Security Association and Key Management Protocol",
					       "ISAKMP", "isakmp");
  proto_register_field_array(proto_isakmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("isakmp", dissect_isakmp, proto_isakmp);
}

void
proto_reg_handoff_isakmp(void)
{
  dissector_handle_t isakmp_handle;

  isakmp_handle = find_dissector("isakmp");
  dissector_add("udp.port", UDP_PORT_ISAKMP, isakmp_handle);
  dissector_add("tcp.port", TCP_PORT_ISAKMP, isakmp_handle);
}
