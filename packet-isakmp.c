/* packet-isakmp.c
 * Routines for the Internet Security Association and Key Management Protocol
 * (ISAKMP) (RFC 2408) and the Internet IP Security Domain of Interpretation
 * for ISAKMP (RFC 2407)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * $Id: packet-isakmp.c,v 1.71 2003/10/09 22:40:28 guy Exp $
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include <epan/ipv6-utils.h>
#include "ipproto.h"

#define isakmp_min(a, b)  ((a<b) ? a : b)

static int proto_isakmp = -1;

static gint ett_isakmp = -1;
static gint ett_isakmp_flags = -1;
static gint ett_isakmp_payload = -1;

#define UDP_PORT_ISAKMP	500
#define TCP_PORT_ISAKMP 500

#define NUM_PROTO_TYPES	5
#define proto2str(t)	\
  ((t < NUM_PROTO_TYPES) ? prototypestr[t] : "UNKNOWN-PROTO-TYPE")

static const char *prototypestr[NUM_PROTO_TYPES] = {
  "RESERVED",
  "ISAKMP",
  "IPSEC_AH",
  "IPSEC_ESP",
  "IPCOMP"
};

#define NUM_P1_ATT_TYPES	17
#define p1_atttype2str(t)	\
  ((t < NUM_P1_ATT_TYPES) ? p1_atttypestr[t] : "UNKNOWN-ATTRIBUTE-TYPE")

static const char *p1_atttypestr[NUM_P1_ATT_TYPES] = {
  "UNKNOWN-ATTRIBUTE-TYPE",
  "Encryption-Algorithm",
  "Hash-Algorithm",
  "Authentication-Method",
  "Group-Description",
  "Group-Type",
  "Group-Prime",
  "Group-Generator-One",
  "Group-Generator-Two",
  "Group-Curve-A",
  "Group-Curve-B",
  "Life-Type",
  "Life-Duration",
  "PRF",
  "Key-Length",
  "Field-Size",
  "Group-Order"
};

#define NUM_ATT_TYPES	11
#define atttype2str(t)	\
  ((t < NUM_ATT_TYPES) ? atttypestr[t] : "UNKNOWN-ATTRIBUTE-TYPE")

static const char *atttypestr[NUM_ATT_TYPES] = {
  "UNKNOWN-ATTRIBUTE-TYPE",
  "SA-Life-Type",
  "SA-Life-Duration",
  "Group-Description",
  "Encapsulation-Mode",
  "Authentication-Algorithm",
  "Key-Length",
  "Key-Rounds",
  "Compress-Dictinary-Size",
  "Compress-Private-Algorithm",
  "ECN Tunnel"
};

#define NUM_TRANS_TYPES	2
#define trans2str(t)	\
  ((t < NUM_TRANS_TYPES) ? transtypestr[t] : "UNKNOWN-TRANS-TYPE")

static const char *transtypestr[NUM_TRANS_TYPES] = {
  "RESERVED",
  "KEY_IKE"
};

#define NUM_AH_TRANS_TYPES	8
#define ah_trans2str(t)		\
  ((t < NUM_AH_TRANS_TYPES) ? ah_transtypestr[t] : "UNKNOWN-AH-TRANS-TYPE")

static const char *ah_transtypestr[NUM_AH_TRANS_TYPES] = {
  "RESERVED",
  "RESERVED",
  "MD5",
  "SHA",
  "DES",
  "SHA2-256",
  "SHA2-384",
  "SHA2-512"
};

#define NUM_ESP_TRANS_TYPES	13
#define esp_trans2str(t)	\
  ((t < NUM_ESP_TRANS_TYPES) ? esp_transtypestr[t] : "UNKNOWN-ESP-TRANS-TYPE")

static const char *esp_transtypestr[NUM_ESP_TRANS_TYPES] = {
  "RESERVED",
  "DES-IV64",
  "DES",
  "3DES",
  "RC5",
  "IDEA",
  "CAST",
  "BLOWFISH",
  "3IDEA",
  "DES-IV32",
  "RC4",
  "NULL",
  "AES"
};

#define NUM_IPCOMP_TRANS_TYPES    5
#define ipcomp_trans2str(t)  \
  ((t < NUM_IPCOMP_TRANS_TYPES) ? ipcomp_transtypestr[t] : "UNKNOWN-IPCOMP-TRANS-TYPE")

static const char *ipcomp_transtypestr[NUM_IPCOMP_TRANS_TYPES] = {
  "RESERVED",
  "OUI",
  "DEFLATE",
  "LZS",
  "LZJH"
};

#define NUM_ID_TYPES	12
#define id2str(t)	\
  ((t < NUM_ID_TYPES) ? idtypestr[t] : "UNKNOWN-ID-TYPE")

static const char *idtypestr[NUM_ID_TYPES] = {
  "RESERVED",
  "IPV4_ADDR",
  "FQDN",
  "USER_FQDN",
  "IPV4_ADDR_SUBNET",
  "IPV6_ADDR",
  "IPV6_ADDR_SUBNET",
  "IPV4_ADDR_RANGE",
  "IPV6_ADDR_RANGE",
  "DER_ASN1_DN",
  "DER_ASN1_GN",
  "KEY_ID"
};

#define NUM_GRPDESC_TYPES 19
#define grpdesc2str(t) ((t < NUM_GRPDESC_TYPES) ? grpdescstr[t] : "UNKNOWN-GROUP-DESCRIPTION")

static const char *grpdescstr[NUM_GRPDESC_TYPES] = {
  "UNDEFINED - 0",
  "Default 768-bit MODP group",
  "Alternate 1024-bit MODP group",
  "EC2N group on GP[2^155] group",
  "EC2N group on GP[2^185] group",
  "1536 bit MODP group",
  "EC2N group over GF[2^163]",
  "EC2N group over GF[2^163]",
  "EC2N group over GF[2^283]",
  "EC2N group over GF[2^283]",
  "EC2N group over GF[2^409]",
  "EC2N group over GF[2^409]",
  "EC2N group over GF[2^571]",
  "EC2N group over GF[2^571]",
  "2048 bit MODP group",
  "3072 bit MODP group",
  "4096 bit MODP group",
  "6144 bit MODP group",
  "8192 bit MODP group",
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
  guint32	message_id;
  guint32	length;
};

struct udp_encap_hdr {
  guint8	non_esp_marker[4];
  guint32	esp_SPI;
};

static proto_tree *dissect_payload_header(tvbuff_t *, int, int, guint8,
    guint8 *, guint16 *, proto_tree *);

static void dissect_sa(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_proposal(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_transform(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_key_exch(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_id(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_cert(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_certreq(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_hash(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_sig(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_nonce(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_notif(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_delete(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_vid(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_config(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_nat_discovery(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_nat_original_address(tvbuff_t *, int, int, proto_tree *, int);

static const char *payloadtype2str(guint8);
static const char *exchtype2str(guint8);
static const char *doitype2str(guint32);
static const char *msgtype2str(guint16);
static const char *situation2str(guint32);
static const char *value2str(int, guint16, guint16);
static const char *attrtype2str(guint8);
static const char *cfgattrident2str(guint16);
static const char *certtype2str(guint8);

static gboolean get_num(tvbuff_t *, int, guint16, guint32 *);

#define LOAD_TYPE_NONE		0	/* payload type for None */
#define LOAD_TYPE_PROPOSAL	2	/* payload type for Proposal */
#define	LOAD_TYPE_TRANSFORM	3	/* payload type for Transform */
#define NUM_LOAD_TYPES		17
#define loadtype2str(t)	\
  ((t < NUM_LOAD_TYPES) ? strfuncs[t].str : "Unknown payload type")

static struct strfunc {
  const char *	str;
  void          (*func)(tvbuff_t *, int, int, proto_tree *, int);
} strfuncs[NUM_LOAD_TYPES] = {
  {"NONE",			NULL              },
  {"Security Association",	dissect_sa        },
  {"Proposal",			dissect_proposal  },
  {"Transform",			dissect_transform },
  {"Key Exchange",		dissect_key_exch  },
  {"Identification",		dissect_id        },
  {"Certificate",		dissect_cert      },
  {"Certificate Request",	dissect_certreq   },
  {"Hash",			dissect_hash      },
  {"Signature",			dissect_sig       },
  {"Nonce",			dissect_nonce     },
  {"Notification",		dissect_notif     },
  {"Delete",			dissect_delete    },
  {"Vendor ID",			dissect_vid       },
  {"Attrib",			dissect_config	  },
  {"NAT-Discovery",		dissect_nat_discovery }, /* draft-ietf-ipsec-nat-t-ike */
  {"NAT-Original Address",	dissect_nat_original_address } /* draft-ietf-ipsec-nat-t-ike */
};

#define VID_LEN 16
#define VID_MS_LEN 20
static const guint8 VID_MS_W2K_WXP[VID_MS_LEN] = {0x1E, 0x2B, 0x51, 0x69, 0x5, 0x99, 0x1C, 0x7D, 0x7C, 0x96, 0xFC, 0xBF, 0xB5, 0x87, 0xE4, 0x61, 0x0, 0x0, 0x0, 0x2}; /* according to http://www.microsoft.com/technet/treeview/default.asp?url=/technet/columns/cableguy/cg0602.asp */

#define VID_CP_LEN 20
static const guint8 VID_CP[VID_CP_LEN] = {0xF4, 0xED, 0x19, 0xE0, 0xC1, 0x14, 0xEB, 0x51, 0x6F, 0xAA, 0xAC, 0x0E, 0xE3, 0x7D, 0xAF, 0x28, 0x7, 0xB4, 0x38, 0x1F};

static const guint8 VID_CYBERGUARD[VID_LEN] = {0x9A, 0xA1, 0xF3, 0xB4, 0x34, 0x72, 0xA4, 0x5D, 0x5F, 0x50, 0x6A, 0xEB, 0x26, 0xC, 0xF2, 0x14};

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_03[VID_LEN] = {0x7D, 0x94, 0x19, 0xA6, 0x53, 0x10, 0xCA, 0x6F, 0x2C, 0x17, 0x9D, 0x92, 0x15, 0x52, 0x9d, 0x56}; /* according to http://www.ietf.org/internet-drafts/draft-ietf-ipsec-nat-t-ike-03.txt */

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


static const guint8 VID_draft_ietf_ipsec_dpd_00[VID_LEN]= {0xAF, 0xCA,0xD7, 0x13, 0x68, 0xA1, 0xF1, 0xC9, 0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57, 0x01, 0x00}; /* draft-ietf-ipsec-dpd-00.txt */

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
*  means. ykaul-at-netvision.net.il
*/
static const guint8 VID_HeartBeat_Notify[VID_LEN] = {0x48, 0x65, 0x61, 0x72, 0x74, 0x42, 0x65, 0x61, 0x74, 0x5f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79}; 

static dissector_handle_t esp_handle;
static dissector_handle_t ah_handle;

static void
dissect_payloads(tvbuff_t *tvb, proto_tree *tree, guint8 initial_payload,
		 int offset, int length)
{
  guint8 payload, next_payload;
  guint16		payload_length;
  proto_tree *		ntree;

  for (payload = initial_payload; length != 0; payload = next_payload) {
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
    ntree = dissect_payload_header(tvb, offset, length, payload,
      &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (payload_length >= 4) {	/* XXX = > 4? */
      if (payload < NUM_LOAD_TYPES && strfuncs[payload].func != NULL) {
        (*strfuncs[payload].func)(tvb, offset + 4, payload_length - 4, ntree,
				  -1);
      }
      else {
        proto_tree_add_text(ntree, tvb, offset + 4, payload_length - 4,
            "Payload");
      }
    }
    else {
        proto_tree_add_text(ntree, tvb, offset + 4, 0,
            "Payload (bogus, length is %u, must be at least 4)",
            payload_length);
        payload_length = 4;
    }
    offset += payload_length;
    length -= payload_length;
  }
}

static void
dissect_isakmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int			offset = 0;
  struct isakmp_hdr 	hdr;
  proto_item *		ti;
  proto_tree *		isakmp_tree = NULL;
  struct udp_encap_hdr  encap_hdr;
  guint32		len;
  static const guint8	non_esp_marker[4] = { 0, 0, 0, 0 };
  tvbuff_t *		next_tvb;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISAKMP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  hdr.length = tvb_get_ntohl(tvb, offset + sizeof(hdr) - sizeof(hdr.length));

  if (tree) {
    ti = proto_tree_add_item(tree, proto_isakmp, tvb, offset, hdr.length, FALSE);
    isakmp_tree = proto_item_add_subtree(ti, ett_isakmp);
  }

  tvb_memcpy(tvb, (guint8 *)&encap_hdr, 0, sizeof(encap_hdr));

  if (encap_hdr.non_esp_marker[0] == 0xFF) {
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_str(pinfo->cinfo, COL_INFO, "UDP encapsulated IPSec - NAT Keepalive");
    return;
  }
  if (memcmp(encap_hdr.non_esp_marker,non_esp_marker,4) == 0) {
    if (check_col(pinfo->cinfo, COL_INFO))
          col_add_str(pinfo->cinfo, COL_INFO, "UDP encapsulated IPSec - ESP");
    if (tree)
      proto_tree_add_text(isakmp_tree, tvb, offset,
			  sizeof(encap_hdr.non_esp_marker),
			  "Non-ESP-Marker");
    offset += sizeof(encap_hdr.non_esp_marker);
    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
    call_dissector(esp_handle, next_tvb, pinfo, tree);
    return;
  }
  hdr.exch_type = tvb_get_guint8(tvb, sizeof(hdr.icookie) + sizeof(hdr.rcookie) + sizeof(hdr.next_payload) + sizeof(hdr.version));
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO, exchtype2str(hdr.exch_type));

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
			payloadtype2str(hdr.next_payload), hdr.next_payload);
    offset += sizeof(hdr.next_payload);

    hdr.version = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.version),
			"Version: %u.%u",
			hi_nibble(hdr.version), lo_nibble(hdr.version));
    offset += sizeof(hdr.version);

    hdr.exch_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.exch_type),
			"Exchange type: %s (%u)",
			exchtype2str(hdr.exch_type), hdr.exch_type);
    offset += sizeof(hdr.exch_type);

    {
      proto_item *	fti;
      proto_tree *	ftree;

      hdr.flags = tvb_get_guint8(tvb, offset);
      fti   = proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.flags), "Flags");
      ftree = proto_item_add_subtree(fti, ett_isakmp_flags);

      proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, E_FLAG, sizeof(hdr.flags)*8,
						  "Encryption", "No encryption"));
      proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, C_FLAG, sizeof(hdr.flags)*8,
						  "Commit", "No commit"));
      proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, A_FLAG, sizeof(hdr.flags)*8,
						  "Authentication", "No authentication"));
      offset += sizeof(hdr.flags);
    }

    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.message_id),
        "Message ID: 0x%s", tvb_bytes_to_str(tvb, offset, sizeof(hdr.message_id)));
    offset += sizeof(hdr.message_id);

    proto_tree_add_text(isakmp_tree, tvb, offset, sizeof(hdr.length),
			"Length: %u", hdr.length);
    offset += sizeof(hdr.length);

    len = hdr.length - sizeof(hdr);

    if (hdr.flags & E_FLAG) {
      if (len && isakmp_tree) {
        proto_tree_add_text(isakmp_tree, tvb, offset, len,
			"Encrypted payload (%d byte%s)",
			len, plurality(len, "", "s"));
      }
    } else
      dissect_payloads(tvb, isakmp_tree, hdr.next_payload, offset, len);
  }
}

static proto_tree *
dissect_payload_header(tvbuff_t *tvb, int offset, int length, guint8 payload,
    guint8 *next_payload_p, guint16 *payload_length_p, proto_tree *tree)
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
            "%s payload", loadtype2str(payload));
  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);

  proto_tree_add_text(ntree, tvb, offset, 1,
		      "Next payload: %s (%u)",
		      payloadtype2str(next_payload), next_payload);
  proto_tree_add_text(ntree, tvb, offset+2, 2, "Length: %u", payload_length);

  *next_payload_p = next_payload;
  *payload_length_p = payload_length;
  return ntree;
}

static void
dissect_sa(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  guint32		doi;
  guint32		situation;

  if (length < 4) {
    proto_tree_add_text(tree, tvb, offset, length,
			"DOI %s (length is %u, should be >= 4)",
			tvb_bytes_to_str(tvb, offset, length), length);
    return;
  }
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

    dissect_payloads(tvb, tree, LOAD_TYPE_PROPOSAL, offset, length);
  } else {
    /* Unknown */
    proto_tree_add_text(tree, tvb, offset, length,
			"Situation: %s",
			tvb_bytes_to_str(tvb, offset, length));
  }
}

static void
dissect_proposal(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
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
		      proto2str(protocol_id), protocol_id);
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
    proto_tree_add_text(tree, tvb, offset, spi_size, "SPI: %s",
			tvb_bytes_to_str(tvb, offset, spi_size));
    offset += spi_size;
    length -= spi_size;
  }

  while (num_transforms > 0) {
    ntree = dissect_payload_header(tvb, offset, length, LOAD_TYPE_TRANSFORM,
      &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (length < payload_length) {
      proto_tree_add_text(tree, tvb, offset + 4, length,
          "Not enough room in payload for all transforms");
      break;
    }
    if (payload_length >= 4)
      dissect_transform(tvb, offset + 4, payload_length - 4, ntree, protocol_id);
    else
      proto_tree_add_text(ntree, tvb, offset + 4, payload_length - 4, "Payload");
    offset += payload_length;
    length -= payload_length;
    num_transforms--;
  }
}

static void
dissect_transform(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int protocol_id)
{
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
			trans2str(transform_id), transform_id);
    break;
  case 2:	/* AH */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			ah_trans2str(transform_id), transform_id);
    break;
  case 3:	/* ESP */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			esp_trans2str(transform_id), transform_id);
    break;
  case 4:	/* IPCOMP */
    proto_tree_add_text(tree, tvb, offset, 1,
			"Transform ID: %s (%u)",
			ipcomp_trans2str(transform_id), transform_id);
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
      str = p1_atttype2str(type);
    }
    else {
      str = atttype2str(type);
    }

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u): %s (%u)",
			  str, type,
			  value2str(ike_phase1, type, val), val);
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
			    value2str(ike_phase1, type, val), val);
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

static void
dissect_key_exch(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Key Exchange Data");
}

static void
dissect_id(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  guint8		id_type;
  guint8		protocol_id;
  guint16		port;

  id_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "ID type: %s (%u)", id2str(id_type), id_type);
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

  switch (id_type) {
    case 1:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s",
			  ip_to_str(tvb_get_ptr(tvb, offset, 4)));
      break;
    case 2:
    case 3:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %.*s", length,
			  tvb_get_ptr(tvb, offset, length));
      break;
    case 4:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s/%s",
			  ip_to_str(tvb_get_ptr(tvb, offset, 4)),
			  ip_to_str(tvb_get_ptr(tvb, offset+4, 4)));
      break;
    default:
      proto_tree_add_text(tree, tvb, offset, length, "Identification Data");
      break;
  }
}

static void
dissect_cert(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  guint8		cert_enc;

  cert_enc = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Certificate encoding: %u - %s",
		      cert_enc, certtype2str(cert_enc));
  offset += 1;
  length -= 1;

  proto_tree_add_text(tree, tvb, offset, length, "Certificate Data");
}

static void
dissect_certreq(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  guint8		cert_type;

  cert_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Certificate type: %u - %s",
		      cert_type, certtype2str(cert_type));
  offset += 1;
  length -= 1;

  proto_tree_add_text(tree, tvb, offset, length, "Certificate Authority");
}

static void
dissect_hash(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Hash Data");
}

static void
dissect_sig(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Signature Data");
}

static void
dissect_nonce(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Nonce Data");
}

static void
dissect_notif(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  guint32		doi;
  guint8		protocol_id;
  guint8		spi_size;
  guint16		msgtype;

  doi = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Domain of Interpretation: %s (%u)",
		      doitype2str(doi), doi);
  offset += 4;
  length -= 4;

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Protocol ID: %s (%u)",
		      proto2str(protocol_id), protocol_id);
  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "SPI size: %u", spi_size);
  offset += 1;
  length -= 1;

  msgtype = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 2,
		      "Message type: %s (%u)", msgtype2str(msgtype), msgtype);
  offset += 2;
  length -= 2;

  if (spi_size) {
    proto_tree_add_text(tree, tvb, offset, spi_size, "Security Parameter Index");
    offset += spi_size;
    length -= spi_size;
  }

  if (length > 0)
    proto_tree_add_text(tree, tvb, offset, length, "Notification Data");
}

static void
dissect_delete(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  guint32		doi;
  guint8		protocol_id;
  guint8		spi_size;
  guint16		num_spis;
  guint16		i;

  doi = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 4,
		      "Domain of Interpretation: %s (%u)",
		      doitype2str(doi), doi);
  offset += 4;
  length -= 4;

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Protocol ID: %s (%u)",
		      proto2str(protocol_id), protocol_id);
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
    proto_tree_add_text(tree, tvb, offset, spi_size,
			"SPI (%d)", i);
    offset += spi_size;
    length -= spi_size;
  }
}

static void
dissect_vid(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
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
	pt = proto_tree_add_text(ntree, tvb, offset, length, "Version: ");
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
		default: proto_item_append_text(pt, " Uknown CP version!");
			break;
	}
  }
  else
  if (memcmp(pVID, VID_CYBERGUARD, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "Cyber Guard");
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_03, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-ietf-ipsec-nat-t-ike-03");
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
  if (memcmp(pVID,  VID_draft_ietf_ipsec_dpd_00, isakmp_min(VID_LEN, length)) == 0)
        proto_item_append_text(pt, "draft-ietf-ipsec-dpd-00.txt");
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
    int unused _U_)
{
  guint8		type;

  type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Type %s (%u)",attrtype2str(type),type);

  offset += 2;
  length -= 2;

  proto_tree_add_text(tree, tvb, offset, 2,
                      "Identifier: %u", tvb_get_ntohs(tvb, offset));
  offset += 2;
  length -= 2;

  while(length>0) {
    guint16 aft     = tvb_get_ntohs(tvb, offset);
    guint16 type    = aft & 0x7fff;
    guint16 len;
    guint32 val;
    guint pack_len;

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u)", cfgattrident2str(type), val);
      offset += 4;
      length -= 4;
    }
    else {
      len = tvb_get_ntohs(tvb, offset + 2);
      pack_len = 4 + len;
      if (!get_num(tvb, offset + 4, len, &val)) {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s: <too big (%u bytes)>",
			    cfgattrident2str(type), len);
      } else {
        proto_tree_add_text(tree, tvb, offset, 4,
			    "%s (%ue)", cfgattrident2str(type),
			    val);
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

static void
dissect_nat_discovery(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  proto_tree_add_text(tree, tvb, offset, length,
		      "Hash of address and port: %s",
		      tvb_bytes_to_str(tvb, offset, length));
}

static void
dissect_nat_original_address(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    int unused _U_)
{
  guint8 id_type;
  guint32 addr_ipv4;
  struct e_in6_addr addr_ipv6;

  id_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "ID type: %s (%u)", id2str(id_type), id_type);
  offset += 1;
  length -= 1;

  offset += 3;		/* reserved */
  length -= 3;

  switch (id_type) {

  case 1:	/* ID_IPV4_ADDR */
    if (length == 4) {
      tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset, length);
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: %s",
			  ip_to_str((guint8 *)&addr_ipv4));
    } else {
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: bad length, should be 4, is %u",
			  length);
    }
    break;

  case 5:	/* ID_IPV6_ADDR */
    if (length == 16) {
      tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset, length);
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

static const char *
payloadtype2str(guint8 type) {

  if (type < NUM_LOAD_TYPES)
    return strfuncs[type].str;
  if (type < 128)
    return "RESERVED";
  return "Private USE";
}

static const char *
exchtype2str(guint8 type) {

#define NUM_EXCHSTRS	7
  static const char * exchstrs[NUM_EXCHSTRS] = {
    "NONE",
    "Base",
    "Identity Protection (Main Mode)",
    "Authentication Only",
    "Aggressive",
    "Informational",
    "Transaction (Config Mode)"
  };

  if (type < NUM_EXCHSTRS) return exchstrs[type];
  if (type < 32)           return "ISAKMP Future Use";
  switch (type) {
  case 32:
    return "Quick Mode";
  case 33:
    return "New Group Mode";
  }
  if (type < 240)
    return "DOI Specific Use";
  return "Private Use";
}

static const char *
doitype2str(guint32 type) {
  if (type == 1) return "IPSEC";
  return "Unknown DOI Type";
}

static const char *
msgtype2str(guint16 type) {

#define NUM_PREDEFINED	31
  static const char *msgs[NUM_PREDEFINED] = {
    "<UNKNOWN>",
    "INVALID-PAYLOAD-TYPE",
    "DOI-NOT-SUPPORTED",
    "SITUATION-NOT-SUPPORTED",
    "INVALID-COOKIE",
    "INVALID-MAJOR-VERSION",
    "INVALID-MINOR-VERSION",
    "INVALID-EXCHANGE-TYPE",
    "INVALID-FLAGS",
    "INVALID-MESSAGE-ID",
    "INVALID-PROTOCOL-ID",
    "INVALID-SPI",
    "INVALID-TRANSFORM-ID",
    "ATTRIBUTES-NOT-SUPPORTED",
    "NO-PROPOSAL-CHOSEN",
    "BAD-PROPOSAL-SYNTAX",
    "PAYLOAD-MALFORMED",
    "INVALID-KEY-INFORMATION",
    "INVALID-ID-INFORMATION",
    "INVALID-CERT-ENCODING",
    "INVALID-CERTIFICATE",
    "CERT-TYPE-UNSUPPORTED",
    "INVALID-CERT-AUTHORITY",
    "INVALID-HASH-INFORMATION",
    "AUTHENTICATION-FAILED",
    "INVALID-SIGNATURE",
    "ADDRESS-NOTIFICATION",
    "NOTIFY-SA-LIFETIME",
    "CERTIFICATE-UNAVAILABLE",
    "UNSUPPORTED-EXCHANGE-TYPE",
    "UNEQUAL-PAYLOAD-LENGTHS"
  };

  if (type < NUM_PREDEFINED) return msgs[type];
  if (type < 8192)           return "RESERVED (Future Use)";
  if (type < 16384)          return "Private Use";
  if (type < 16385)          return "CONNECTED";
  if (type < 24576)          return "RESERVED (Future Use) - status";
  if (type < 24577)          return "RESPONDER-LIFETIME";
  if (type < 24578)          return "REPLAY-STATUS";
  if (type < 24579)          return "INITIAL-CONTACT";
  if (type < 32768)          return "DOI-specific codes";
  if (type < 40960)          return "Private Use - status";
  if (type < 65535)          return "RESERVED (Future Use) - status (2)";

  return "Huh? You should never see this! Shame on you!";
}

static const char *
situation2str(guint32 type) {

#define SIT_MSG_NUM	1024
#define SIT_IDENTITY	0x01
#define SIT_SECRECY	0x02
#define SIT_INTEGRITY	0x04

  static char	msg[SIT_MSG_NUM];
  int		n = 0;
  char *	sep = "";
  int		ret;

  if (type & SIT_IDENTITY) {
    ret = snprintf(msg, SIT_MSG_NUM-n, "%sIDENTITY", sep);
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
    ret = snprintf(msg, SIT_MSG_NUM-n, "%sSECRECY", sep);
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
    ret = snprintf(msg, SIT_MSG_NUM-n, "%sINTEGRITY", sep);
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
value2str(int ike_p1, guint16 att_type, guint16 value) {

  if (value == 0) return "RESERVED";

  if (!ike_p1) {
  switch (att_type) {
    case 1:
      switch (value) {
	case 0: return "RESERVED";
        case 1:  return "Seconds";
        case 2:  return "Kilobytes";
        default: return "UNKNOWN-SA-VALUE";
      }
    case 2:
      return "Duration-Value";
    case 3:
      return "Group-Value";
    case 4:
      switch (value) {
	case 0:  return "RESERVED";
        case 1:  return "Tunnel";
        case 2:  return "Transport";
	case 3:  return "UDP-Encapsulated-Tunnel"; /* http://www.ietf.org/internet-drafts/draft-ietf-ipsec-nat-t-ike-05.txt */
	case 4:  return "UDP-Encapsulated-Transport"; /* http://www.ietf.org/internet-drafts/draft-ietf-ipsec-nat-t-ike-05.txt */
	case 61440: return "Check Point IPSec UDP Encapsulation";
	case 61443: return "UDP-Encapsulated-Tunnel (draft)";
	case 61444: return "UDP-Encapsulated-Transport (draft)";
        default: return "UNKNOWN-ENCAPSULATION-VALUE";
      }
    case 5:
      switch (value) {
	case 0:  return "RESERVED";
        case 1:  return "HMAC-MD5";
        case 2:  return "HMAC-SHA";
        case 3:  return "DES-MAC";
        case 4:  return "KPDK";
	case 5:  return "HMAC-SHA2-256";
	case 6:  return "HMAC-SHA2-384";
	case 7:  return "HMAC-SHA2-512";
        default: return "UNKNOWN-AUTHENTICATION-VALUE";
      }
    case 6:
      return "Key-Length";
    case 7:
      return "Key-Rounds";
    case 8:
      return "Compress-Dictionary-size";
    case 9:
      return "Compress Private Algorithm";
    default: return "UNKNOWN-ATTRIBUTE-TYPE";
  }
  }
  else {
    switch (att_type) {
      case 1:
        switch (value) {
          case 1:  return "DES-CBC";
          case 2:  return "IDEA-CBC";
          case 3:  return "BLOWFISH-CBC";
          case 4:  return "RC5-R16-B64-CBC";
          case 5:  return "3DES-CBC";
          case 6:  return "CAST-CBC";
	  case 7:  return "AES-CBC";
          default: return "UNKNOWN-ENCRYPTION-ALG";
        }
      case 2:
        switch (value) {
          case 1:  return "MD5";
          case 2:  return "SHA";
          case 3:  return "TIGER";
	  case 4:  return "SHA2-256";
	  case 5:  return "SHA2-384";
	  case 6:  return "SHA2-512";
          default: return "UNKNOWN-HASH-ALG";
        }
      case 3:
        switch (value) {
          case 1:  return "PSK";
          case 2:  return "DSS-SIG";
          case 3:  return "RSA-SIG";
          case 4:  return "RSA-ENC";
          case 5:  return "RSA-Revised-ENC";
	  case 6:  return "Encryption with El-Gamal";
 	  case 7:  return "Revised encryption with El-Gamal";
	  case 8:  return "ECDSA signatures";
	  case 9:  return "AES-XCBC-MAC";
	  case 64221: return "HybridInitRSA";
	  case 64222: return "HybridRespRSA";
	  case 64223: return "HybridInitDSS";
	  case 64224: return "HybridRespDSS";
          case 65001: return "XAUTHInitPreShared";
          case 65002: return "XAUTHRespPreShared";
          case 65003: return "XAUTHInitDSS";
          case 65004: return "XAUTHRespDSS";
          case 65005: return "XAUTHInitRSA";
          case 65006: return "XAUTHRespRSA";
          case 65007: return "XAUTHInitRSAEncryption";
          case 65008: return "XAUTHRespRSAEncryption";
          case 65009: return "XAUTHInitRSARevisedEncryption";
          case 65010: return "XAUTHRespRSARevisedEncryption";
	  default: return "UNKNOWN-AUTH-METHOD";
        }
      case 4: return grpdesc2str(value);
      case 6:
      case 7:
      case 8:
      case 9:
      case 10:
      case 16:
        return "Group-Value";
      case 5:
        switch (value) {
          case 1:  return "MODP";
          case 2:  return "ECP";
          case 3:  return "EC2N";
          default: return "UNKNOWN-GROUPT-TYPE";
        }
      case 11:
        switch (value) {
          case 1:  return "Seconds";
          case 2:  return "Kilobytes";
          default: return "UNKNOWN-SA-VALUE";
        }
      case 12:
        return "Duration-Value";
      case 13:
        return "PRF-Value";
      case 14:
        return "Key-Length";
      case 15:
        return "Field-Size";
      default: return "UNKNOWN-ATTRIBUTE-TYPE";
    }
  }
}

static const char *
attrtype2str(guint8 type) {
  switch (type) {
  case 0: return "Reserved";
  case 1: return "ISAKMP_CFG_REQUEST";
  case 2: return "ISAKMP_CFG_REPLY";
  case 3: return "ISAKMP_CFG_SET";
  case 4: return "ISAKMP_CFG_ACK";
  }
  if(type < 127)
    return "Future use";
  return "Private use";
}

static const char *
cfgattrident2str(guint16 ident) {
#define NUM_ATTR_DEFINED	12
  static const char *msgs[NUM_PREDEFINED] = {
    "RESERVED",
    "INTERNAL_IP4_ADDRESS",
    "INTERNAL_IP4_NETMASK",
    "INTERNAL_IP4_DNS",
    "INTERNAL_IP4_NBNS",
    "INTERNAL_ADDRESS_EXPIREY",
    "INTERNAL_IP4_DHCP",
    "APPLICATION_VERSION"
    "INTERNAL_IP6_ADDRESS",
    "INTERNAL_IP6_NETMASK",
    "INTERNAL_IP6_DNS",
    "INTERNAL_IP6_NBNS",
    "INTERNAL_IP6_DHCP",
  };
  if(ident < NUM_ATTR_DEFINED)
    return msgs[ident];
  if(ident < 16383)
    return "Future use";
  switch(ident) {
  case 16520: return "XAUTH_TYPE";
  case 16521: return "XAUTH_USER_NAME";
  case 16522: return "XAUTH_USER_PASSWORD";
  case 16523: return "XAUTH_PASSCODE";
  case 16524: return "XAUTH_MESSAGE";
  case 16525: return "XAUTH_CHALLANGE";
  case 16526: return "XAUTH_DOMAIN";
  case 16527: return "XAUTH_STATUS";
  case 16528: return "XAUTH_NEXT_PIN";
  case 16529: return "XAUTH_ANSWER";
  default: return "Private use";
  }
}

static const char *
certtype2str(guint8 type) {
#define NUM_CERTTYPE 11
  static const char *msgs[NUM_CERTTYPE] = {
    "NONE",
    "PKCS #7 wrapped X.509 certificate",
    "PGP Certificate",
    "DNS Signed Key",
    "X.509 Certificate - Signature",
    "X.509 Certificate - Key Exchange",
    "Kerberos Tokens",
    "Certificate Revocation List (CRL)",
    "Authority Revocation List (ARL)",
    "SPKI Certificate",
    "X.509 Certificate - Attribute",
  };
  if(type > NUM_CERTTYPE)
    return "RESERVED";
  return msgs[type];
}

static gboolean
get_num(tvbuff_t *tvb, int offset, guint16 len, guint32 *num_p) {

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
/*  static hf_register_info hf[] = {
    { &variable,
    { "Name",           "isakmp.abbreviation", TYPE, VALS_POINTER }},
  };*/
  static gint *ett[] = {
    &ett_isakmp,
    &ett_isakmp_flags,
    &ett_isakmp_payload,
  };

  proto_isakmp = proto_register_protocol("Internet Security Association and Key Management Protocol",
					       "ISAKMP", "isakmp");
/*  proto_register_field_array(proto_isakmp, hf, array_length(hf));*/
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("isakmp", dissect_isakmp, proto_isakmp);
}

void
proto_reg_handoff_isakmp(void)
{
  dissector_handle_t isakmp_handle;

  /*
   * Get handle for the AH & ESP dissectors.
   */
  esp_handle = find_dissector("esp");
  ah_handle = find_dissector("ah");

  isakmp_handle = find_dissector("isakmp");
  dissector_add("udp.port", UDP_PORT_ISAKMP, isakmp_handle);
  dissector_add("tcp.port", TCP_PORT_ISAKMP, isakmp_handle);
}
