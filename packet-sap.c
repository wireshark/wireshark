/* packet-tftp.c
 * Routines for sap packet dissection
 * <draft-ietf-mmusic-sap-v2-03.txt>
 *
 * Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * $Id: packet-sap.c,v 1.4 2000/01/07 22:05:36 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-ipv6.h"


#define MCAST_SAP_VERSION_MASK 0xE0 /* 3 bits for  SAP version*/
#define MCAST_SAP_VERSION_SHIFT 5   /* Right shift 5 bits to get the version */
#define MCAST_SAP_VER0 0            /* Version 0 */
#define MCAST_SAP_VER1PLUS 1        /* Version 1 or later */
static const value_string mcast_sap_ver[] = {
                  { MCAST_SAP_VER0,     "SAPv0"},
                  { MCAST_SAP_VER1PLUS, "SAPv1 or later"},
                  { 0,                  NULL} };

static const true_false_string mcast_sap_address_type = {
        "IPv6",
        "IPv4"
};

static const true_false_string flags_set_truth = {
        "Set",
        "Not set"
};

static const true_false_string mcast_sap_message_type = {
        "Deletion",
        "Announcement"
};

static const true_false_string mcast_sap_crypt_type = {
        "Payload encrypted",
        "Payload not encrypted "
};

static const true_false_string mcast_sap_comp_type = {
        "Payload compressed",
        "Payload not compressed"
};

static const value_string mcast_sap_auth_ver[] = {
                  { 1, "SAP authentication header v1"},
                  { 0,                  NULL} };

static const true_false_string mcast_sap_auth_pad = {
        "Authentication subheader padded to 32 bits",
        "No padding required for the authentication subheader"
};

#define MCAST_SAP_AUTH_TYPE_MASK 0x0F /* 4 bits for the type of the authentication header */
#define MCAST_SAP_AUTH_TYPE_PGP 0
#define MCAST_SAP_AUTH_TYPE_CMS 1
static const value_string mcast_sap_auth_type[] = {
                  { MCAST_SAP_AUTH_TYPE_PGP,  "PGP"},
                  { MCAST_SAP_AUTH_TYPE_CMS,  "CMS"},
                  { 0,                   NULL} };

#define MCAST_SAP_BIT_A 0x10 /* Address type: 0 IPv4, 1 IPv6 */
#define MCAST_SAP_BIT_R 0x08 /* Reserved: Must be 0 */
#define MCAST_SAP_BIT_T 0x04 /* Message Type: 0 announcement, 1 deletion */
#define MCAST_SAP_BIT_E 0x02 /* Encryption Bit: 1 payload encrypted */
#define MCAST_SAP_BIT_C 0x01 /* Compressed Bit: 1 payload zlib compressed */

#define MCAST_SAP_AUTH_BIT_P 0x10 /* Padding required for the authentication header */


static int proto_sap = -1;
static int hf_sap_flags = -1;
static int hf_sap_flags_v = -1;
static int hf_sap_flags_a = -1;
static int hf_sap_flags_r = -1;
static int hf_sap_flags_t = -1;
static int hf_sap_flags_e = -1;
static int hf_sap_flags_c = -1;
static int hf_auth_data = -1;
static int hf_auth_flags = -1;
static int hf_auth_flags_v = -1;
static int hf_auth_flags_p = -1;
static int hf_auth_flags_t = -1;

static gint ett_sap = -1;
static gint ett_sap_flags = -1;
static gint ett_sap_auth = -1;
static gint ett_sap_authf = -1;

void dissect_sap(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        int sap_version, is_ipv6, is_del, is_enc, is_comp, addr_len;
        guint8 auth_len;
        guint16 tmp1;
        guint32 tmp2;

        proto_item *si, *sif;
        proto_tree *sap_tree, *sap_flags_tree;

        is_ipv6 = pd[offset]&MCAST_SAP_BIT_A;
        is_del = pd[offset]&MCAST_SAP_BIT_T;
        is_enc = pd[offset]&MCAST_SAP_BIT_E;
        is_comp = pd[offset]&MCAST_SAP_BIT_C;

        sap_version = (pd[offset]&MCAST_SAP_VERSION_MASK)>>MCAST_SAP_VERSION_SHIFT;
        addr_len = (is_ipv6) ? sizeof(struct e_in6_addr) : 4;

        if (check_col(fd, COL_PROTOCOL))
                col_add_str(fd, COL_PROTOCOL, "SAP");
        
        if (check_col(fd, COL_INFO)) {
                col_add_fstr(fd, COL_INFO, "%s (v%u)",
                             (is_del) ? "Deletion" : "Announcement", sap_version);
        }

	if (tree) {
	  si = proto_tree_add_item(tree, proto_sap, offset, END_OF_FRAME, NULL);
	  sap_tree = proto_item_add_subtree(si, ett_sap);

	  sif = proto_tree_add_item(sap_tree, hf_sap_flags, offset, 1, pd[offset]);
          sap_flags_tree = proto_item_add_subtree(sif, ett_sap_flags);
          proto_tree_add_item(sap_flags_tree, hf_sap_flags_v, offset, 1, pd[offset]);
          proto_tree_add_item(sap_flags_tree, hf_sap_flags_a, offset, 1, pd[offset]);
          proto_tree_add_item(sap_flags_tree, hf_sap_flags_r, offset, 1, pd[offset]);
          proto_tree_add_item(sap_flags_tree, hf_sap_flags_t, offset, 1, pd[offset]);
          proto_tree_add_item(sap_flags_tree, hf_sap_flags_e, offset, 1, pd[offset]);
          proto_tree_add_item(sap_flags_tree, hf_sap_flags_c, offset, 1, pd[offset]);
          offset++;

          proto_tree_add_text(sap_tree, offset, 1, "Authentication Length: %u", pd[offset]);
          auth_len = pd[offset];
          offset++;

          tmp1 = pntohs(pd+offset);
          proto_tree_add_text(sap_tree, offset, 2, "Message Identifier Hash: 0x%x", tmp1);
          offset +=2;

          proto_tree_add_text(sap_tree, offset, addr_len, "Originating Source: %s",
                              (is_ipv6) ? ip6_to_str((struct e_in6_addr*)(pd+offset)) : ip_to_str(pd+offset));
          offset += addr_len;

          /* Authentication data lives in its own subtree */
          if (auth_len > 0) {
                  guint32 auth_data_len;
                  proto_item *sdi, *sai;
                  proto_tree *sa_tree, *saf_tree;
                  int has_pad;
                  guint8 pad_len = 0;

                  auth_data_len = auth_len * sizeof(guint32);

                  sdi = proto_tree_add_item(sap_tree, hf_auth_data, offset, auth_data_len, pd[offset]);
                  sa_tree = proto_item_add_subtree(sdi, ett_sap_auth);

                  sai = proto_tree_add_item(sa_tree, hf_auth_flags, offset, 1, pd[offset]);
                  saf_tree = proto_item_add_subtree(sai, ett_sap_authf);
                  proto_tree_add_item(saf_tree, hf_auth_flags_v, offset, 1, pd[offset]);
                  proto_tree_add_item(saf_tree, hf_auth_flags_p, offset, 1, pd[offset]);
                  proto_tree_add_item(saf_tree, hf_auth_flags_t, offset, 1, pd[offset]);

                  has_pad = pd[offset]&MCAST_SAP_AUTH_BIT_P;
                  if (has_pad) pad_len = *(pd+offset+auth_data_len-1);

                  proto_tree_add_text(sa_tree, offset+1, auth_data_len-pad_len-1,
                                      "Authentication subheader: (%u byte%s)",
                                      auth_data_len-1, plurality(auth_data_len-1, "", "s"));
                  if (has_pad) {
                          proto_tree_add_text(sa_tree, offset+auth_data_len-pad_len, pad_len,
                                              "Authentication data padding: (%u byte%s)",
                                              pad_len, plurality(pad_len, "", "s"));
                          proto_tree_add_text(sa_tree, offset+auth_data_len-1, 1,
                                              "Authentication data pad count: %u byte%s",
                                              pad_len, plurality(pad_len, "", "s"));
                  }

                  offset += auth_data_len;
          }

          if (is_enc) { /* Encrypted payload implies valid timeout in the SAP header */
                  tmp2 = pntohl(pd+offset);
                  proto_tree_add_text(sap_tree, offset, 4, "Timeout: %u", tmp2);
                  offset += sizeof(guint32);
          }

          if (is_enc || is_comp) {
                  proto_tree_add_text(sap_tree, offset, END_OF_FRAME,
                                      "Rest of the packet is encrypted or compressed");
                  return;
          }

          /* Do we have the optional payload type aka. MIME content specifier */
          if (strncasecmp(pd+offset, "v=", strlen("v="))) {
                  guint32 pt_len = strlen(pd+offset); /* BUG: should use strnlen */
                  proto_tree_add_text(sap_tree, offset, pt_len, "Payload type: %s", pd+offset);
                  offset += pt_len;
                  if (pd[offset] == '\0')
                          offset++; /* Skip possible '\0' */
          }
          
          /* Done with SAP */
          dissect_sdp(pd, offset, fd, tree);
	}

        return;
}

void proto_register_sap(void)
{

  static hf_register_info hf[] = {
    { &hf_sap_flags,
      { "Flags",         "sap.flags",
	FT_UINT8, BASE_HEX, NULL, 0x0,
      	"Bits in the beginning of the SAP header" }},

    { &hf_sap_flags_v,
      { "Version Number",         "sap.flags.v",
	FT_UINT8, BASE_DEC, VALS(mcast_sap_ver), MCAST_SAP_VERSION_MASK,
      	"3 bit version field in the SAP header" }},

    { &hf_sap_flags_a,
      { "Address Type",           "sap.flags.a",
	FT_BOOLEAN, 8, TFS(&mcast_sap_address_type), MCAST_SAP_BIT_A,
      	"Originating source address type" }},

    { &hf_sap_flags_r,
      { "Reserved",               "sap.flags.r",
	FT_BOOLEAN, 8, TFS(&flags_set_truth), MCAST_SAP_BIT_R,
      	"Reserved" }},

    { &hf_sap_flags_t,
      { "Message Type",           "sap.flags.t",
	FT_BOOLEAN, 8, TFS(&mcast_sap_message_type), MCAST_SAP_BIT_T,
      	"Announcement type" }},

    { &hf_sap_flags_e,
      { "Encryption Bit",         "sap.flags.e",
	FT_BOOLEAN, 8, TFS(&mcast_sap_crypt_type), MCAST_SAP_BIT_E,
      	"Encryption" }},

    { &hf_sap_flags_c,
      { "Compression Bit",         "sap.flags.c",
	FT_BOOLEAN, 8, TFS(&mcast_sap_comp_type), MCAST_SAP_BIT_C,
      	"Compression" }},

    { &hf_auth_data,
      { "Authentication data",     "sap.auth",
	FT_NONE, BASE_NONE, NULL, 0x0,
      	"Auth data" }},

    { &hf_auth_flags,
      { "Authentication data flags", "sap.auth.flags",
	FT_UINT8, BASE_HEX, NULL, 0x0,
      	"Auth flags" }},

    { &hf_auth_flags_v,
      { "Version Number",         "sap.auth.flags.v",
	FT_UINT8, BASE_DEC, VALS(&mcast_sap_auth_ver), MCAST_SAP_VERSION_MASK,
      	"Version" }},

    { &hf_auth_flags_p,
      { "Padding Bit",            "sap.auth.flags.p",
	FT_BOOLEAN, 8, TFS(&mcast_sap_auth_pad), MCAST_SAP_AUTH_BIT_P,
      	"Compression" }},

    { &hf_auth_flags_t,
      { "Authentication Type",         "sap.auth.flags.t",
	FT_UINT8, BASE_DEC, VALS(&mcast_sap_auth_type), MCAST_SAP_AUTH_TYPE_MASK,
      	"Auth type" }}
  };
  static gint *ett[] = {
    &ett_sap,
    &ett_sap_flags,
    &ett_sap_auth,
    &ett_sap_authf,
  };

  proto_sap = proto_register_protocol("Session Announcement Protocol", "sap");
  proto_register_field_array(proto_sap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}
