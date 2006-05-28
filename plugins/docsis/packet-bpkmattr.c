/* packet-bpkmattr.c
 * Routines for Baseline Privacy Key Management Attributes dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmodule.h>

#include <epan/packet.h>

/* BPKM Attributes defined in:
 * http://www.cablemodem.com/downloads/specs/SP-BPI+_I10-030730.pdf
 */
#define BPKM_RESERVED 0
#define BPKM_SERIAL_NUM 1
#define BPKM_MANUFACTURER_ID 2
#define BPKM_MAC_ADDR 3
#define BPKM_RSA_PUB_KEY 4
#define BPKM_CM_ID 5
#define BPKM_DISPLAY_STR 6
#define BPKM_AUTH_KEY 7
#define BPKM_TEK 8
#define BPKM_KEY_LIFETIME 9
#define BPKM_KEY_SEQ_NUM 10
#define BPKM_HMAC_DIGEST 11
#define BPKM_SAID 12
#define BPKM_TEK_PARAM 13
#define BPKM_OBSOLETED 14
#define BPKM_CBC_IV 15
#define BPKM_ERROR_CODE 16
#define BPKM_CA_CERT 17
#define BPKM_CM_CERT 18
#define BPKM_SEC_CAPABILITIES 19
#define BPKM_CRYPTO_SUITE 20
#define BPKM_CRYPTO_SUITE_LIST 21
#define BPKM_BPI_VERSION 22
#define BPKM_SA_DESCRIPTOR 23
#define BPKM_SA_TYPE 24
#define BPKM_SA_QUERY 25
#define BPKM_SA_QUERY_TYPE 26
#define BPKM_IP_ADDRESS 27
#define BPKM_DNLD_PARAMS 28
#define BPKM_VENDOR_DEFINED 127

/* Initialize the protocol and registered fields */
static int proto_docsis_bpkmattr = -1;
static int hf_docsis_bpkmattr = -1;
static int hf_docsis_bpkmattr_serial_num = -1;
static int hf_docsis_bpkmattr_manf_id = -1;
static int hf_docsis_bpkmattr_mac_addr = -1;
static int hf_docsis_bpkmattr_rsa_pub_key = -1;
static int hf_docsis_bpkmattr_cm_id = -1;
static int hf_docsis_bpkmattr_display_str = -1;
static int hf_docsis_bpkmattr_auth_key = -1;
static int hf_docsis_bpkmattr_tek = -1;
static int hf_docsis_bpkmattr_key_life = -1;
static int hf_docsis_bpkmattr_key_seq = -1;
static int hf_docsis_bpkmattr_hmac_digest = -1;
static int hf_docsis_bpkmattr_said = -1;
static int hf_docsis_bpkmattr_tek_params = -1;
static int hf_docsis_bpkmattr_cbc_iv = -1;
static int hf_docsis_bpkmattr_error_code = -1;
static int hf_docsis_bpkmattr_vendor_def = -1;
static int hf_docsis_bpkmattr_ca_cert = -1;
static int hf_docsis_bpkmattr_cm_cert = -1;
static int hf_docsis_bpkmattr_security_cap = -1;
static int hf_docsis_bpkmattr_crypto_suite = -1;
static int hf_docsis_bpkmattr_crypto_suite_list = -1;
static int hf_docsis_bpkmattr_bpi_version = -1;
static int hf_docsis_bpkmattr_sa_descr = -1;
static int hf_docsis_bpkmattr_sa_type = -1;
static int hf_docsis_bpkmattr_sa_query = -1;
static int hf_docsis_bpkmattr_sa_query_type = -1;
static int hf_docsis_bpkmattr_ip_address = -1;
static int hf_docsis_bpkmattr_download_param = -1;



/* Initialize the subtree pointers */
static gint ett_docsis_bpkmattr = -1;
static gint ett_docsis_bpkmattr_cmid = -1;
static gint ett_docsis_bpkmattr_scap = -1;
static gint ett_docsis_bpkmattr_tekp = -1;
static gint ett_docsis_bpkmattr_sadsc = -1;
static gint ett_docsis_bpkmattr_saqry = -1;
static gint ett_docsis_bpkmattr_dnld = -1;


static const value_string error_code_vals[] = {
  {0, "no information"},
  {1, "Unauthorized CM"},
  {2, "Unauthorized SAID"},
  {3, "Unsolicited"},
  {4, "Invalid Key Sequence Number"},
  {5, "Key Request authentication failure"},
  {6, "Permanent Authorization Failure"},
  {7, "Not authorized for requested downstream traffic flow"},
  {8, "Downstream traffic flow not mapped to BPI+ SAID"},
  {9, "Time of day not acquired"},
  {0, NULL},
};

static const value_string crypto_suite_attr_vals[] = {
  {0x0100, "CBC Mode, 56 Bit DES & no Data Authentication"},
  {0x0200, "CBC Mode, 40 Bit DES & no Data Authentication"},
  {0, NULL},
};

static const value_string bpi_ver_vals[] = {
  {0, "Reserved"},
  {1, "BPI+"},
  {0, NULL},
};

/* Code to actually dissect the packets */

/* The dissect_attrs() function does the actual work to dissect the
 * attributes.  It's called recursively, to dissect embedded attributes
 */
static void
dissect_attrs (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  guint8 type;
  guint16 length;
  int pos = 0;
  gint total_len;
  proto_item *cmid_it, *tekp_it, *scap_it;
  proto_item *saqry_it, *dnld_it, *sadsc_it;
  proto_tree *cmid_tree, *tekp_tree, *scap_tree;
  proto_tree *saqry_tree, *dnld_tree, *sadsc_tree;
  tvbuff_t *cmid_tvb, *tekp_tvb, *scap_tvb;
  tvbuff_t *saqry_tvb, *dnld_tvb, *sadsc_tvb;

  total_len = tvb_reported_length_remaining (tvb, 0);
  while (pos < total_len)
    {
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_ntohs (tvb, pos);
      pos += 2;
      switch (type)
	{
	case BPKM_RESERVED:
	  break;
	case BPKM_SERIAL_NUM:
	  proto_tree_add_item (tree, hf_docsis_bpkmattr_serial_num, tvb, pos,
			       length, FALSE);
	  break;
	case BPKM_MANUFACTURER_ID:
	  if (length == 3)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_manf_id, tvb, pos,
				 length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_MAC_ADDR:
	  if (length == 6)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_mac_addr, tvb, pos,
				 length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_RSA_PUB_KEY:
	  proto_tree_add_item (tree, hf_docsis_bpkmattr_rsa_pub_key, tvb, pos,
			       length, FALSE);
	  break;
	case BPKM_CM_ID:
	  cmid_it =
	    proto_tree_add_text (tree, tvb, pos, length,
				 "5 CM Identification");
	  cmid_tree =
	    proto_item_add_subtree (cmid_it, ett_docsis_bpkmattr_cmid);
	  cmid_tvb = tvb_new_subset (tvb, pos, length, length);
	  dissect_attrs (cmid_tvb, pinfo, cmid_tree);
	  break;
	case BPKM_DISPLAY_STR:
	  proto_tree_add_item (tree, hf_docsis_bpkmattr_display_str, tvb, pos,
			       length, FALSE);
	  break;
	case BPKM_AUTH_KEY:
	  if ((length == 96) || (length == 128))
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_auth_key, tvb, pos,
				 length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_TEK:
	  if (length == 8)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_tek, tvb, pos,
				 length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_KEY_LIFETIME:
	  if (length == 4)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_key_life, tvb, pos,
				 length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_KEY_SEQ_NUM:
	  if (length == 1)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_key_seq, tvb, pos,
				 length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_HMAC_DIGEST:
	  if (length == 20)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_hmac_digest, tvb,
				 pos, length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_SAID:
	  if (length == 2)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_said, tvb, pos,
				 length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_TEK_PARAM:
	  tekp_it =
	    proto_tree_add_text (tree, tvb, pos, length, "13 TEK Parameters");
	  tekp_tree =
	    proto_item_add_subtree (tekp_it, ett_docsis_bpkmattr_tekp);
	  tekp_tvb = tvb_new_subset (tvb, pos, length, length);
	  dissect_attrs (tekp_tvb, pinfo, tekp_tree);
	  break;
	case BPKM_OBSOLETED:
	  break;
	case BPKM_CBC_IV:
	  if (length == 8)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_cbc_iv, tvb, pos,
				 length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_ERROR_CODE:
	  if (length == 1)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_error_code, tvb,
				 pos, length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_CA_CERT:
	  proto_tree_add_item (tree, hf_docsis_bpkmattr_ca_cert, tvb, pos,
			       length, FALSE);
	  break;
	case BPKM_CM_CERT:
	  proto_tree_add_item (tree, hf_docsis_bpkmattr_cm_cert, tvb, pos,
			       length, FALSE);
	  break;
	case BPKM_SEC_CAPABILITIES:
	  scap_it =
	    proto_tree_add_text (tree, tvb, pos, length,
				 "19 Security Capabilities");
	  scap_tree =
	    proto_item_add_subtree (scap_it, ett_docsis_bpkmattr_scap);
	  scap_tvb = tvb_new_subset (tvb, pos, length, length);
	  dissect_attrs (scap_tvb, pinfo, scap_tree);
	  break;
	case BPKM_CRYPTO_SUITE:
	  if (length == 2)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_crypto_suite, tvb,
				 pos, length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_CRYPTO_SUITE_LIST:
	  proto_tree_add_item (tree, hf_docsis_bpkmattr_crypto_suite_list,
			       tvb, pos, length, FALSE);
	  break;
	case BPKM_BPI_VERSION:
	  if (length == 1)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_bpi_version, tvb,
				 pos, length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_SA_DESCRIPTOR:
	  sadsc_it =
	    proto_tree_add_text (tree, tvb, pos, length, "23 SA Descriptor");
	  sadsc_tree =
	    proto_item_add_subtree (sadsc_it, ett_docsis_bpkmattr_sadsc);
	  sadsc_tvb = tvb_new_subset (tvb, pos, length, length);
	  dissect_attrs (sadsc_tvb, pinfo, sadsc_tree);
	  break;
	case BPKM_SA_TYPE:
	  if (length == 1)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_sa_type, tvb, pos,
				 length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_SA_QUERY:
	  saqry_it =
	    proto_tree_add_text (tree, tvb, pos, length, "25 SA Query");
	  saqry_tree =
	    proto_item_add_subtree (saqry_it, ett_docsis_bpkmattr_saqry);
	  saqry_tvb = tvb_new_subset (tvb, pos, length, length);
	  dissect_attrs (saqry_tvb, pinfo, saqry_tree);
	  break;
	case BPKM_SA_QUERY_TYPE:
	  if (length == 1)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_sa_query_type, tvb,
				 pos, length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_IP_ADDRESS:
	  if (length == 4)
	    proto_tree_add_item (tree, hf_docsis_bpkmattr_ip_address, tvb,
				 pos, length, FALSE);
	  else
	    THROW (ReportedBoundsError);
	  break;
	case BPKM_VENDOR_DEFINED:
	  proto_tree_add_item (tree, hf_docsis_bpkmattr_vendor_def, tvb, pos,
			       length, FALSE);
	case BPKM_DNLD_PARAMS:
	  dnld_it =
	    proto_tree_add_text (tree, tvb, pos, length,
				 "28 Download Parameters");
	  dnld_tree =
	    proto_item_add_subtree (dnld_it, ett_docsis_bpkmattr_dnld);
	  dnld_tvb = tvb_new_subset (tvb, pos, length, length);
	  dissect_attrs (dnld_tvb, pinfo, dnld_tree);
	  break;
	default:
	  proto_tree_add_item (tree, hf_docsis_bpkmattr_vendor_def, tvb, pos,
			       length, FALSE);
	  break;
	}
      pos += length;		/* switch */
    }				/* while */
}

static void
dissect_bpkmattr (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{

  proto_item *it;
  proto_tree *bpkmattr_tree;

  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_bpkmattr, tvb, 0, -1,
					"BPKM Attributes");
      bpkmattr_tree = proto_item_add_subtree (it, ett_docsis_bpkmattr);
      dissect_attrs (tvb, pinfo, bpkmattr_tree);
    }

}



/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_bpkmattr (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_bpkmattr,
     {"BPKM Attributes", "docsis.bpkmattr",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "BPKM Attributes", HFILL}
     },
    {&hf_docsis_bpkmattr_serial_num,
     {"1 Serial Number", "docsis.bpkmattr.serialnum",
      FT_STRING, BASE_DEC, NULL, 0x0,
      "Serial Number", HFILL}
     },
    {&hf_docsis_bpkmattr_manf_id,
     {"2 Manufacturer Id", "docsis.bpkmattr.manfid",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Manufacturer Id", HFILL}
     },
    {&hf_docsis_bpkmattr_mac_addr,
     {"3 Mac Address", "docsis.bpkmattr.macaddr",
      FT_ETHER, BASE_HEX, NULL, 0x0,
      "Mac Address", HFILL}
     },
    {&hf_docsis_bpkmattr_rsa_pub_key,
     {"4 RSA Public Key", "docsis.bpkmattr.rsa_pub_key",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "RSA Public Key", HFILL}
     },
    {&hf_docsis_bpkmattr_cm_id,
     {"5 CM Identification", "docsis.bpkmattr.cmid",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "CM Identification", HFILL}
     },
    {&hf_docsis_bpkmattr_display_str,
     {"6 Display String", "docsis.bpkmattr.dispstr",
      FT_STRING, BASE_DEC, NULL, 0x0,
      "Display String", HFILL}
     },
    {&hf_docsis_bpkmattr_auth_key,
     {"7 Auth Key", "docsis.bpkmattr.auth_key",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Auth Key", HFILL}
     },
    {&hf_docsis_bpkmattr_tek,
     {"8 Traffic Encryption Key", "docsis.bpkmattr.tek",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Traffic Encryption Key", HFILL}
     },
    {&hf_docsis_bpkmattr_key_life,
     {"9 Key Lifetime (s)", "docsis.bpkmattr.keylife",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Key Lifetime (s)", HFILL}
     },
    {&hf_docsis_bpkmattr_key_seq,
     {"10 Key Sequence Number", "docsis.bpkmattr.keyseq",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Key Sequence Number", HFILL}
     },
    {&hf_docsis_bpkmattr_hmac_digest,
     {"11 HMAC Digest", "docsis.bpkmattr.hmacdigest",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "HMAC Digest", HFILL}
     },
    {&hf_docsis_bpkmattr_said,
     {"12 SAID", "docsis.bpkmattr.said",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Security Association ID", HFILL}
     },
    {&hf_docsis_bpkmattr_tek_params,
     {"13 TEK Parameters", "docsis.bpkmattr.tekparams",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "TEK Parameters", HFILL}
     },
    {&hf_docsis_bpkmattr_cbc_iv,
     {"14 CBC IV", "docsis.bpkmattr.cbciv",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Cypher Block Chaining", HFILL}
     },
    {&hf_docsis_bpkmattr_error_code,
     {"16 Error Code", "docsis.bpkmattr.errcode",
      FT_UINT8, BASE_DEC, VALS (error_code_vals), 0x0,
      "Error Code", HFILL}
     },
    {&hf_docsis_bpkmattr_vendor_def,
     {"127 Vendor Defined", "docsis.bpkmattr.vendordef",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Vendor Defined", HFILL}
     },
    {&hf_docsis_bpkmattr_ca_cert,
     {"17 CA Certificate", "docsis.bpkmattr.cacert",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "CA Certificate", HFILL}
     },
    {&hf_docsis_bpkmattr_cm_cert,
     {"18 CM Certificate", "docsis.bpkmattr.cmcert",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "CM Certificate", HFILL}
     },
    {&hf_docsis_bpkmattr_security_cap,
     {"19 Security Capabilities", "docsis.bpkmattr.seccap",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Security Capabilities", HFILL}
     },
    {&hf_docsis_bpkmattr_crypto_suite,
     {"20 Cryptographic Suite", "docsis.bpkmattr.cryptosuite",
      FT_UINT16, BASE_HEX, VALS(crypto_suite_attr_vals), 0x0,
      "Cryptographic Suite", HFILL}
     },
    {&hf_docsis_bpkmattr_crypto_suite_list,
     {"21 Cryptographic Suite List", "docsis.bpkmattr.crypto_suite_lst",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Cryptographic Suite", HFILL}
     },
    {&hf_docsis_bpkmattr_bpi_version,
     {"22 BPI Version", "docsis.bpkmattr.bpiver",
      FT_UINT8, BASE_DEC, VALS (bpi_ver_vals), 0x0,
      "BPKM Attributes", HFILL}
     },
    {&hf_docsis_bpkmattr_sa_descr,
     {"23 SA Descriptor", "docsis.bpkmattr.sadescr",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "SA Descriptor", HFILL}
     },
    {&hf_docsis_bpkmattr_sa_type,
     {"24 SA Type", "docsis.bpkmattr.satype",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "SA Type", HFILL}
     },
    {&hf_docsis_bpkmattr_sa_query,
     {"25 SA Query", "docsis.bpkmattr.saquery",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "SA Query", HFILL}
     },
    {&hf_docsis_bpkmattr_sa_query_type,
     {"26 SA Query Type", "docsis.bpkmattr.saquery_type",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "SA Query Type", HFILL}
     },
    {&hf_docsis_bpkmattr_ip_address,
     {"27 IP Address", "docsis.bpkmattr.ipaddr",
      FT_IPv4, BASE_DEC, NULL, 0x0,
      "IP Address", HFILL}
     },
    {&hf_docsis_bpkmattr_download_param,
     {"28 Download Parameters", "docsis.bpkmattr.dnld_params",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Download Parameters", HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_bpkmattr,
    &ett_docsis_bpkmattr_cmid,
    &ett_docsis_bpkmattr_scap,
    &ett_docsis_bpkmattr_tekp,
    &ett_docsis_bpkmattr_sadsc,
    &ett_docsis_bpkmattr_saqry,
    &ett_docsis_bpkmattr_dnld
  };

/* Register the protocol name and description */
  proto_docsis_bpkmattr =
    proto_register_protocol
    ("DOCSIS Baseline Privacy Key Management Attributes", "DOCSIS BPKM-ATTR",
     "docsis_bpkmattr");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_bpkmattr, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_bpkmattr", dissect_bpkmattr,
		      proto_docsis_bpkmattr);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_bpkmattr (void)
{
  dissector_handle_t docsis_bpkmattr_handle;

  docsis_bpkmattr_handle = find_dissector ("docsis_bpkmattr");
  dissector_add ("docsis", 0xFE, docsis_bpkmattr_handle);

}
