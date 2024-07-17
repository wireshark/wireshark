/* packet-vendor.c
 * Routines for Vendor Specific Encodings dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* Notes to Adding dissectors for Vendor specific TLVs:
 * 1. Create a dissect_<vendorname> function with the following prototype:
 *   dissect_foovendor(tvbuff_t *tvb, proto_tree *tree, int vsif_len)
 * 2. vsif_len will be the *entire* length of the vsif TLV (including the
 *   Vendor ID TLV, which is 5 bytes long).
 * 3. Create a new 'case' statement in dissect_vsif, for your specific Vendor
 *   ID.
 * 4. In that 'case' statement you will make the following calls:
 *   (assume for this example that your vendor ID is 0x000054)
 *   #define VENDOR_FOOVENDOR 0x00054
 *   case VENDOR_FOOVENDOR:
 *      proto_item_append_text (it, " (foo vendor)");
 *      dissect_foovendor (tvb, vsif_tree, vsif_len);
 *      break;
 * 5.  Please see dissect_cisco for an example of how to do this.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

/* Define Vendor ID's here */
#define VENDOR_CISCO 0x00000C
#define VENDOR_GENERAL 0xFFFFFF

void proto_register_docsis_vsif(void);
void proto_reg_handoff_docsis_vsif(void);

/* Initialize the protocol and registered fields */
static int proto_docsis_vsif;
static int hf_docsis_vsif_vendorid;
static int hf_docsis_vsif_vendor_unknown;
static int hf_docsis_vsif_cisco_numphones;
/* static int hf_docsis_vsif_cisco_ipprec; */
static int hf_docsis_vsif_cisco_ipprec_val;
static int hf_docsis_vsif_cisco_ipprec_bw;
static int hf_docsis_vsif_cisco_config_file;

static int hf_docsis_vsif_gex_loadbal_policy_id;
static int hf_docsis_vsif_gex_loadbal_priority;
static int hf_docsis_vsif_gex_loadbal_group_id;
static int hf_docsis_vsif_gex_ranging_class_id_extension;
static int hf_docsis_vsif_gex_l2vpn_encoding;
static int hf_docsis_vsif_gex_ecm;
static int hf_docsis_vsif_gex_sav;
static int hf_docsis_vsif_gex_cmam;
static int hf_docsis_vsif_gex_imja;
static int hf_docsis_vsif_gex_service_type_identifier;

static int hf_docsis_vsif_gex_ecm_extended_cmts_mic_hmac_type;
static int hf_docsis_vsif_gex_ecm_extended_cmts_mic_bitmap;
static int hf_docsis_vsif_gex_ecm_explicit_extended_cmts_mic_digest_subtype;

static int hf_docsis_vsif_gex_sav_group_name;
static int hf_docsis_vsif_gex_sav_static_prefix_rule;

static int hf_docsis_vsif_gex_sav_static_prefix_addressv4;
static int hf_docsis_vsif_gex_sav_static_prefix_addressv6;
static int hf_docsis_vsif_gex_sav_static_prefix_length;

static int hf_docsis_vsif_gex_cmam_cm_required_downstream_attribute_mask;
static int hf_docsis_vsif_gex_cmam_cm_forbidden_downstream_attribute_mask;
static int hf_docsis_vsif_gex_cmam_cm_required_upstream_attribute_mask;
static int hf_docsis_vsif_gex_cmam_cm_forbidden_upstream_attribute_mask;

static int hf_docsis_vsif_gex_imja_ip_multicast_profile_name;
static int hf_docsis_vsif_gex_imja_ssr;
static int hf_docsis_vsif_gex_imja_maximum_multicast_sessions;

static int hf_docsis_vsif_gex_imja_ssr_rule_priority;
static int hf_docsis_vsif_gex_imja_ssr_authorization_action;
static int hf_docsis_vsif_gex_imja_ssr_source_prefix_addressv4;
static int hf_docsis_vsif_gex_imja_ssr_source_prefix_addressv6;
static int hf_docsis_vsif_gex_imja_ssr_source_prefix_length;
static int hf_docsis_vsif_gex_imja_ssr_group_prefix_addressv4;
static int hf_docsis_vsif_gex_imja_ssr_group_prefix_addressv6;
static int hf_docsis_vsif_gex_imja_ssr_group_prefix_length;

static int hf_docsis_vsif_tlv_unknown;


/* Initialize the subtree pointers */
static int ett_docsis_vsif;
static int ett_docsis_vsif_ipprec;
static int ett_docsis_vsif_gex_ecm;
static int ett_docsis_vsif_gex_sav;
static int ett_docsis_vsif_gex_sav_spr;
static int ett_docsis_vsif_gex_cmam;
static int ett_docsis_vsif_gex_imja;
static int ett_docsis_vsif_gex_imja_ssr;


static expert_field ei_docsis_vsif_tlvlen_bad;
static expert_field ei_docsis_vsif_tlvtype_unknown;

static const value_string vendorid_vals[] = {
  {VENDOR_CISCO, "Cisco Systems, Inc."},
  {VENDOR_GENERAL, "General Extension Information"},
  {0, NULL},
};

static const value_string hmac_vals[] = {
       {1, "MD5 HMAC [RFC 2104]"},
       {2, "MMH16-sigma-n HMAC [DOCSIS SECv3.0]"},
       {43, "Vendor Specific"},
       {0, NULL},
};

static const value_string authorization_action_vals[] = {
       {0, "permit"},
       {1, "deny"},
       {0, NULL},
};


/* Dissector for Cisco Vendor Specific TLVs */

#define NUM_PHONES      0x0a
#define IOS_CONFIG_FILE 0x80
#define IP_PREC         0x0b
#define IP_PREC_VAL     0x01
#define IP_PREC_BW      0x02

static void dissect_general_extension_information (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
                          int vsif_len);


static void
dissect_cisco (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int vsif_len)
{
  /* Start at pos = 5, since tvb includes the Vendor ID field */
  int pos = 5;
  uint8_t type, length;
  proto_tree *ipprec_tree;
  proto_item *ipprec_item;
  int templen;

  while (pos < vsif_len)
    {
      /* Extract the type and length Fields from the TLV */
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case NUM_PHONES:
            proto_tree_add_item (tree, hf_docsis_vsif_cisco_numphones, tvb,
                                 pos, length, ENC_BIG_ENDIAN);
            break;
          case IP_PREC:
            ipprec_tree =
              proto_tree_add_subtree(tree, tvb, pos, length, ett_docsis_vsif_ipprec, &ipprec_item, "IP Precedence");
            /* Handle Sub-TLVs in IP Precedence */
            templen = pos + length;
            while (pos < templen)
              {
                type = tvb_get_uint8 (tvb, pos++);
                length = tvb_get_uint8 (tvb, pos++);
                switch (type)
                  {
                    case IP_PREC_VAL:
                      if (length == 1)
                      {
                        proto_tree_add_item (ipprec_tree,
                                           hf_docsis_vsif_cisco_ipprec_val, tvb,
                                           pos, length, ENC_BIG_ENDIAN);
                      }
                      else
                      {
                        expert_add_info_format(pinfo, ipprec_item, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
                      }
                      break;
                    case IP_PREC_BW:
                      if (length != 4)
                      {
                        proto_tree_add_item (ipprec_tree,
                                           hf_docsis_vsif_cisco_ipprec_bw, tvb,
                                           pos, length, ENC_BIG_ENDIAN);
                      }
                      else
                      {
                        expert_add_info_format(pinfo, ipprec_item, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
                      }
                      break;
                    default:
                        expert_add_info_format(pinfo, ipprec_item, &ei_docsis_vsif_tlvtype_unknown, "Unknown TLV: %u", type);
                  }
                pos += length;
              }
            break;
          case IOS_CONFIG_FILE:
            proto_tree_add_item (tree, hf_docsis_vsif_cisco_config_file, tvb,
                                 pos, length, ENC_ASCII);
        }
      pos += length;
    }
}

/* Dissection */
static int
dissect_vsif (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *vsif_tree;
  uint8_t type;
  uint8_t length;
  uint32_t value;
  int vsif_len;

  /* get the reported length of the VSIF TLV */
  vsif_len = tvb_reported_length_remaining (tvb, 0);

  it = proto_tree_add_protocol_format (tree, proto_docsis_vsif, tvb, 0, -1,
                                        "VSIF Encodings");
  vsif_tree = proto_item_add_subtree (it, ett_docsis_vsif);
  proto_tree_add_item_ret_uint(vsif_tree, hf_docsis_vsif_vendorid, tvb, 2, 3, ENC_BIG_ENDIAN, &value);

  /* The first TLV in the VSIF encodings must be type 0x08 (Vendor ID) and
   * length 3.
   */
  type = tvb_get_uint8 (tvb, 0);
  if (type != 0x08)
     expert_add_info_format(pinfo, it, &ei_docsis_vsif_tlvtype_unknown, "Unknown TLV: %u", type);

  length = tvb_get_uint8 (tvb, 1);
  if (length != 3)
     expert_add_info_format(pinfo, it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);

  /* switch on the Vendor ID */
  switch (value)
  {
    case VENDOR_CISCO:
      proto_item_append_text (it, " (Cisco)");
      dissect_cisco (tvb, pinfo, vsif_tree, vsif_len);
      break;
    case VENDOR_GENERAL:
      proto_item_append_text (it, " (General Extension Information)");
      dissect_general_extension_information (tvb, pinfo, vsif_tree, vsif_len);
      break;
    default:
      proto_item_append_text (it, " (Unknown)");
      proto_tree_add_item (vsif_tree, hf_docsis_vsif_vendor_unknown, tvb,
                            0, -1, ENC_NA);
    break;
  }

  return tvb_captured_length(tvb);
}


#define GEX_ECM_EXTENDED_CMTS_MIC_HMAC_TYPE 1
#define GEX_ECM_EXTENDED_CMTS_MIC_BITMAP 2
#define GEX_ECM_EXPLICIT_EXTENDED_CMTS_MIC_DIGEST_SUBTYPE 3

static void
dissect_extended_cmts_mic(tvbuff_t * tvb, proto_tree *tree, int start, uint16_t len)
{
  proto_item *ecm_it;
  proto_tree *ecm_tree;
  uint8_t type, length;
  int pos = start;

  ecm_it = proto_tree_add_item (tree, hf_docsis_vsif_gex_ecm, tvb, start, len, ENC_NA);
  ecm_tree = proto_item_add_subtree(ecm_it, ett_docsis_vsif_gex_ecm);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case GEX_ECM_EXTENDED_CMTS_MIC_HMAC_TYPE:
            proto_tree_add_item (ecm_tree, hf_docsis_vsif_gex_ecm_extended_cmts_mic_hmac_type, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          case GEX_ECM_EXTENDED_CMTS_MIC_BITMAP:
            proto_tree_add_item (ecm_tree, hf_docsis_vsif_gex_ecm_extended_cmts_mic_bitmap, tvb, pos, length, ENC_NA);
            break;
          case GEX_ECM_EXPLICIT_EXTENDED_CMTS_MIC_DIGEST_SUBTYPE:
            proto_tree_add_item (ecm_tree, hf_docsis_vsif_gex_ecm_explicit_extended_cmts_mic_digest_subtype, tvb, pos, length, ENC_NA);
            break;
          default:
            proto_tree_add_item (ecm_tree, hf_docsis_vsif_tlv_unknown, tvb, pos, length, ENC_NA);
            break;
        }  /* switch */
      pos += length;
    }   /* while */
}

#define GEX_SAV_STATIC_PREFIX_ADDRESS 1
#define GEX_SAV_STATIC_PREFIX_LENGTH 2

static void
dissect_sav_static_prefix_rule(tvbuff_t * tvb, packet_info * pinfo,  proto_tree *tree, int start, uint16_t len)
{
  proto_item *sav_spr_it;
  proto_tree *sav_spr_tree;
  uint8_t type, length;
  int pos = start;

  sav_spr_it = proto_tree_add_item (tree, hf_docsis_vsif_gex_sav_static_prefix_rule, tvb, start, len, ENC_NA);
  sav_spr_tree = proto_item_add_subtree(sav_spr_it, ett_docsis_vsif_gex_sav_spr);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case GEX_SAV_STATIC_PREFIX_ADDRESS:
            if (length == 4) {
              proto_tree_add_item (sav_spr_tree, hf_docsis_vsif_gex_sav_static_prefix_addressv4, tvb, pos, length, ENC_BIG_ENDIAN);
            } else if (length == 6) {
              proto_tree_add_item (sav_spr_tree, hf_docsis_vsif_gex_sav_static_prefix_addressv6, tvb, pos, length, ENC_NA);
            } else {
              expert_add_info_format(pinfo, sav_spr_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            break;
          case GEX_SAV_STATIC_PREFIX_LENGTH:
            if (length == 1) {
              proto_tree_add_item (sav_spr_tree, hf_docsis_vsif_gex_sav_static_prefix_length, tvb, pos, length, ENC_BIG_ENDIAN);
            } else {
              expert_add_info_format(pinfo, sav_spr_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            break;
          default:
            proto_tree_add_item (sav_spr_tree, hf_docsis_vsif_tlv_unknown, tvb, pos, length, ENC_NA);
            break;
        }  /* switch */
        pos += length;
    }   /* while */
}



#define GEX_SAV_GROUP_NAME 1
#define GEX_SAV_STATIC_PREFIX_RULE 2


static void
dissect_sav(tvbuff_t * tvb, packet_info * pinfo,  proto_tree *tree, int start, uint16_t len)
{
  proto_item *sav_it;
  proto_tree *sav_tree;
  uint8_t type, length;
  int pos = start;

  sav_it = proto_tree_add_item (tree, hf_docsis_vsif_gex_sav, tvb, start, len, ENC_NA);
  sav_tree = proto_item_add_subtree(sav_it, ett_docsis_vsif_gex_sav);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
        case GEX_SAV_GROUP_NAME:
          proto_tree_add_item (sav_tree, hf_docsis_vsif_gex_sav_group_name, tvb, pos, length, ENC_ASCII);
          break;
        case GEX_SAV_STATIC_PREFIX_RULE:
          dissect_sav_static_prefix_rule(tvb, pinfo, sav_tree, pos, length);
          break;
        default:
          proto_tree_add_item (sav_tree, hf_docsis_vsif_tlv_unknown, tvb, pos, length, ENC_NA);
          break;
        }  /* switch */
        pos += length;
    }   /* while */
}


#define GEX_CM_REQUIRED_DOWNSTREAM_ATTRIBUTE_MASK 1
#define GEX_CM_FORBIDDEN_DOWNSTREAM_ATTRIBUTE_MASK 2
#define GEX_CM_REQUIRED_UPSTREAM_ATTRIBUTE_MASK 3
#define GEX_CM_FORBIDDEN_UPSTREAM_ATTRIBUTE_MASK 4

static void
dissect_cable_modem_attribute_masks(tvbuff_t * tvb, packet_info * pinfo, proto_tree *tree, int start, uint16_t len)
{
  proto_item *cmam_it;
  proto_tree *cmam_tree;
  uint8_t type, length;
  int pos = start;

  cmam_it = proto_tree_add_item (tree, hf_docsis_vsif_gex_cmam, tvb, start, len, ENC_NA);
  cmam_tree = proto_item_add_subtree(cmam_it, ett_docsis_vsif_gex_cmam);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case GEX_CM_REQUIRED_DOWNSTREAM_ATTRIBUTE_MASK:
            if (length != 4) {
              expert_add_info_format(pinfo, cmam_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (cmam_tree, hf_docsis_vsif_gex_cmam_cm_required_downstream_attribute_mask, tvb, pos, length, ENC_NA);
            break;
          case GEX_CM_FORBIDDEN_DOWNSTREAM_ATTRIBUTE_MASK:
            if (length != 4) {
              expert_add_info_format(pinfo, cmam_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (cmam_tree, hf_docsis_vsif_gex_cmam_cm_forbidden_downstream_attribute_mask, tvb, pos, length, ENC_NA);
            break;
          case GEX_CM_REQUIRED_UPSTREAM_ATTRIBUTE_MASK:
            if (length != 4) {
              expert_add_info_format(pinfo, cmam_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (cmam_tree, hf_docsis_vsif_gex_cmam_cm_required_upstream_attribute_mask, tvb, pos, length, ENC_NA);
            break;
          case GEX_CM_FORBIDDEN_UPSTREAM_ATTRIBUTE_MASK:
            if (length != 4) {
              expert_add_info_format(pinfo, cmam_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (cmam_tree, hf_docsis_vsif_gex_cmam_cm_forbidden_upstream_attribute_mask, tvb, pos, length, ENC_NA);
            break;
          default: proto_tree_add_item (cmam_tree, hf_docsis_vsif_tlv_unknown, tvb, pos, length, ENC_NA);
        }  /* switch */
        pos += length;
    }   /* while */
}


#define GEX_IMJA_SSR_RULE_PRIORITY 1
#define GEX_IMJA_SSR_AUTHORIZATION_ACTION 2
#define GEX_IMJA_SSR_AUTHORIZATION_SOURCE_PREFIX_ADDRESS 3
#define GEX_IMJA_SSR_AUTHORIZATION_SOURCE_PREFIX_LENGTH 4
#define GEX_IMJA_SSR_AUTHORIZATION_GROUP_PREFIX_ADDRESS 5
#define GEX_IMJA_SSR_AUTHORIZATION_GROUP_PREFIX_LENGTH 6


static void
dissect_ip_multicast_join_authorization_static_session_rule(tvbuff_t * tvb, packet_info * pinfo, proto_tree *tree, int start, uint16_t len)
{
  proto_item *imja_ssr_it;
  proto_tree *imja_ssr_tree;
  uint8_t type, length;
  int pos = start;

  imja_ssr_it = proto_tree_add_item (tree, hf_docsis_vsif_gex_imja_ssr, tvb, start, len, ENC_NA);
  imja_ssr_tree = proto_item_add_subtree(imja_ssr_it, ett_docsis_vsif_gex_imja_ssr);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case GEX_IMJA_SSR_RULE_PRIORITY:
            if (length != 1) {
              expert_add_info_format(pinfo, imja_ssr_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (imja_ssr_tree, hf_docsis_vsif_gex_imja_ssr_rule_priority, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          case GEX_IMJA_SSR_AUTHORIZATION_ACTION:
            if (length != 1) {
              expert_add_info_format(pinfo, imja_ssr_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (imja_ssr_tree, hf_docsis_vsif_gex_imja_ssr_authorization_action, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          case GEX_IMJA_SSR_AUTHORIZATION_SOURCE_PREFIX_ADDRESS:
            if (length == 4) {
              proto_tree_add_item (imja_ssr_tree, hf_docsis_vsif_gex_imja_ssr_source_prefix_addressv4, tvb, pos, length, ENC_BIG_ENDIAN);
            } else if (length == 6) {
              proto_tree_add_item (imja_ssr_tree, hf_docsis_vsif_gex_imja_ssr_source_prefix_addressv6, tvb, pos, length, ENC_NA);
            } else {
              expert_add_info_format(pinfo, imja_ssr_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            break;
          case GEX_IMJA_SSR_AUTHORIZATION_SOURCE_PREFIX_LENGTH:
            if (length != 1) {
              expert_add_info_format(pinfo, imja_ssr_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (imja_ssr_tree, hf_docsis_vsif_gex_imja_ssr_source_prefix_length, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          case GEX_IMJA_SSR_AUTHORIZATION_GROUP_PREFIX_ADDRESS:
            if (length == 4) {
              proto_tree_add_item (imja_ssr_tree, hf_docsis_vsif_gex_imja_ssr_group_prefix_addressv4, tvb, pos, length, ENC_BIG_ENDIAN);
            } else if (length == 6) {
              proto_tree_add_item (imja_ssr_tree, hf_docsis_vsif_gex_imja_ssr_group_prefix_addressv6, tvb, pos, length, ENC_NA);
            } else {
              expert_add_info_format(pinfo, imja_ssr_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            break;
          case GEX_IMJA_SSR_AUTHORIZATION_GROUP_PREFIX_LENGTH:
            if (length != 1) {
              expert_add_info_format(pinfo, imja_ssr_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (imja_ssr_tree, hf_docsis_vsif_gex_imja_ssr_group_prefix_length, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          default: proto_tree_add_item (imja_ssr_tree, hf_docsis_vsif_tlv_unknown, tvb, pos, length, ENC_NA);
        }  /* switch */
        pos += length;
    }   /* while */
}

#define GEX_IMJA_IP_MULTICAST_PROFILE_NAME 1
#define GEX_IMJA_IP_MULTICAST_PROFILE_JOIN_AUTHORIZATION_STATIC_SESSION_RULE 2
#define GEX_IMJA_MAXIMUM_MULTICAST_SESSIONS 3


static void
dissect_ip_multicast_join_authorization(tvbuff_t * tvb, packet_info * pinfo,  proto_tree *tree, int start, uint16_t len)
{
  proto_item *imja_it;
  proto_tree *imja_tree;
  uint8_t type, length;
  int pos = start;

  imja_it = proto_tree_add_item (tree, hf_docsis_vsif_gex_imja, tvb, start, len, ENC_NA);
  imja_tree = proto_item_add_subtree(imja_it, ett_docsis_vsif_gex_imja);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case GEX_IMJA_IP_MULTICAST_PROFILE_NAME:
            if ((length < 1) || (length > 15)) {
              expert_add_info_format(pinfo, imja_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (imja_tree, hf_docsis_vsif_gex_imja_ip_multicast_profile_name, tvb, pos, length, ENC_ASCII);
            break;
          case GEX_IMJA_IP_MULTICAST_PROFILE_JOIN_AUTHORIZATION_STATIC_SESSION_RULE:
            dissect_ip_multicast_join_authorization_static_session_rule(tvb, pinfo, imja_tree, pos, length);
            break;
          case GEX_IMJA_MAXIMUM_MULTICAST_SESSIONS:
            if (length != 2) {
              expert_add_info_format(pinfo, imja_it, &ei_docsis_vsif_tlvlen_bad, "Wrong TLV length: %u", length);
            }
            proto_tree_add_item (imja_tree, hf_docsis_vsif_gex_imja_maximum_multicast_sessions, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          default: proto_tree_add_item (imja_tree, hf_docsis_vsif_tlv_unknown, tvb, pos, length, ENC_NA);
        }  /* switch */
        pos += length;
    }   /* while */
}



/* Dissector for General Extension TLVs */

#define GEX_CM_LOAD_BALANCING_POLICY_ID 1
#define GEX_CM_LOAD_BALANCING_PRIORITY 2
#define GEX_CM_LOAD_BALANCING_GROUP_ID 3
#define GEX_CM_RANGING_CLASS_ID_EXTENSION 4
#define GEX_L2VPN_ENCODING 5
#define GEX_EXTENDED_CMTS_MIC_CONFIGURATION_SETTING 6
#define GEX_EXTENDED_SAV 7
#define GEX_CABLE_MODEM_ATTRIBUTE_MASKS 9
#define GEX_IP_MULTICAST_JOIN_AUTHORIZATION 10
#define GEX_SERVICE_TYPE_IDENTIFIER 11



static void
dissect_general_extension_information (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int vsif_len)
{
  /* Start at pos = 5, since tvb includes the Vendor ID field */
  int pos = 5;
  uint8_t type, length;

  while (pos < vsif_len)
    {
      /* Extract the type and length Fields from the TLV */
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case GEX_CM_LOAD_BALANCING_POLICY_ID:
            proto_tree_add_item (tree, hf_docsis_vsif_gex_loadbal_policy_id, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          case GEX_CM_LOAD_BALANCING_PRIORITY:
            proto_tree_add_item (tree, hf_docsis_vsif_gex_loadbal_priority, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          case GEX_CM_LOAD_BALANCING_GROUP_ID:
            proto_tree_add_item (tree, hf_docsis_vsif_gex_loadbal_group_id, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          case GEX_CM_RANGING_CLASS_ID_EXTENSION:
            proto_tree_add_item (tree, hf_docsis_vsif_gex_ranging_class_id_extension, tvb, pos, length, ENC_BIG_ENDIAN);
            break;
          case GEX_L2VPN_ENCODING:
            proto_tree_add_item (tree, hf_docsis_vsif_gex_l2vpn_encoding, tvb, pos, length, ENC_NA);
            break;
          case GEX_EXTENDED_CMTS_MIC_CONFIGURATION_SETTING:
            dissect_extended_cmts_mic(tvb, tree, pos, length);
            break;
          case GEX_EXTENDED_SAV:
            dissect_sav(tvb, pinfo, tree, pos, length);
            break;
          case GEX_CABLE_MODEM_ATTRIBUTE_MASKS:
            dissect_cable_modem_attribute_masks(tvb, pinfo, tree, pos, length);
            break;
          case GEX_IP_MULTICAST_JOIN_AUTHORIZATION:
            dissect_ip_multicast_join_authorization(tvb, pinfo, tree, pos, length);
            break;
          case GEX_SERVICE_TYPE_IDENTIFIER:
            proto_tree_add_item (tree, hf_docsis_vsif_gex_service_type_identifier, tvb, pos, length, ENC_ASCII);
            break;
          default:
            proto_tree_add_item (tree, hf_docsis_vsif_tlv_unknown, tvb, pos, length, ENC_NA);
      }
      pos += length;
    }
}


/* Register the protocol with Wireshark */
void
proto_register_docsis_vsif (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_vsif_vendorid,
     {"Vendor ID", "docsis_vsif.vendorid",
      FT_UINT24, BASE_HEX, VALS(vendorid_vals), 0x0,
      "Vendor Identifier", HFILL}
    },
    {&hf_docsis_vsif_vendor_unknown,
     {"VSIF Encodings", "docsis_vsif.unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Unknown Vendor", HFILL}
    },
    {&hf_docsis_vsif_cisco_numphones,
     {"Number of phone lines", "docsis_vsif.cisco.numphones",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_vsif_cisco_ipprec,
     {"IP Precedence Encodings", "docsis_vsif.cisco.ipprec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_vsif_cisco_ipprec_val,
     {"IP Precedence Value", "docsis_vsif.cisco.ipprec.value",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_vsif_cisco_ipprec_bw,
     {"IP Precedence Bandwidth", "docsis_vsif.cisco.ipprec.bw",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_vsif_cisco_config_file,
     {"IOS Config File", "docsis_vsif.cisco.iosfile",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_vsif_gex_loadbal_policy_id,
     {".1 CM Load Balancing Policy ID", "docsis_vsif.gex.loadbal_policyid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "General Extension Information - CM Load Balancing Policy ID", HFILL}
    },
    {&hf_docsis_vsif_gex_loadbal_priority,
     {".2 CM Load Balancing Priority", "docsis_vsif.gex.loadbal_priority",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "General Extension Information - CM Load Balancing Priority", HFILL}
    },
    {&hf_docsis_vsif_gex_loadbal_group_id,
     {".3 CM Load Balancing Group ID", "docsis_vsif.gex.loadbal_group_id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "General Extension Information - CM Load Balancing Group ID", HFILL}
    },
    {&hf_docsis_vsif_gex_ranging_class_id_extension,
     {".4 CM Ranging Class ID Extension", "docsis_vsif.gex.ranging_class_id_extension",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "General Extension Information - CM Ranging Class ID Extension", HFILL}
    },
    {&hf_docsis_vsif_gex_l2vpn_encoding,
     {".5 L2VPN Encoding", "docsis_vsif.gex.l2vpn_encoding",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - L2VPN Encoding", HFILL}
    },
    {&hf_docsis_vsif_gex_ecm,
     {".6 Extended CMTS MIC Configuration Setting", "docsis_vsif.gex.extended_cmts_mic_configuration_setting",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - Extended CMTS MIC Configuration Setting", HFILL}
    },
    {&hf_docsis_vsif_gex_ecm_extended_cmts_mic_hmac_type,
     {"..1 Extended CMTS MIC Hmac type", "docsis_vsif.gex.extended_cmts_mic_hmac_type",
      FT_UINT8, BASE_DEC, VALS(hmac_vals), 0x0,
      "General Extension Information - Extended CMTS MIC Hmac type", HFILL}
    },
    {&hf_docsis_vsif_gex_ecm_extended_cmts_mic_bitmap,
     {"..2 Extended CMTS MIC Bitmap", "docsis_vsif.gex.extended_cmts_mic_bitmap",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - Extended CMTS MIC Bitmap", HFILL}
    },
    {&hf_docsis_vsif_gex_ecm_explicit_extended_cmts_mic_digest_subtype,
     {"..3 Explicit Extended CMTS MIC Digest Subtype", "docsis_vsif.gex.extended_cmts_mic_digest_subtype",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - Explicit Extended CMTS MIC Digest Subtype", HFILL}
    },
    {&hf_docsis_vsif_gex_sav,
     {".7 Source Address Verification (SAV) Authorization Encoding", "docsis_vsif.gex.sav",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - Source Address Verification (SAV) Authorization Encoding", HFILL}
    },
    {&hf_docsis_vsif_gex_sav_group_name,
     {"..1 SAV Group Name", "docsis_vsif.gex.sav.sav_group_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "General Extension Information - SAV - SAV Group Name", HFILL}
    },
    {&hf_docsis_vsif_gex_sav_static_prefix_rule,
     {"..2 SAV Static Prefix Rule", "docsis_vsif.gex.sav.static_prefix_rule",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - SAV -Static Prefix Rule", HFILL}
    },
    {&hf_docsis_vsif_gex_sav_static_prefix_addressv4,
     {"...1 SAV Static Prefix Address", "docsis_vsif.gex.sav.spr.static_prefix_address4",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "General Extension Information - SAV -Static Prefix Rule - Static Prefix Address", HFILL}
    },
    {&hf_docsis_vsif_gex_sav_static_prefix_addressv6,
     {"...1 SAV Static Prefix Address", "docsis_vsif.gex.sav.spr.static_prefix_address6",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      "General Extension Information - SAV -Static Prefix Rule - Static Prefix Address", HFILL}
    },
    {&hf_docsis_vsif_gex_sav_static_prefix_length,
     {"...2 SAV Static Prefix Length", "docsis_vsif.gex.sav.spr.static_prefix_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "General Extension Information - SAV -Static Prefix Rule - Static Prefix Length", HFILL}
    },
    {&hf_docsis_vsif_gex_cmam,
     {".9 CM Attribute Mask", "docsis_vsif.gex.cmam",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - CM Attribute Mask", HFILL}
    },
    {&hf_docsis_vsif_gex_cmam_cm_required_downstream_attribute_mask,
     {"..1 CM Required Downstream Attribute", "docsis_vsif.gex.cmam.cm_required_downstream_attribute",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - CM Attribute Mask - CM Required Downstream Attribute", HFILL}
    },
    {&hf_docsis_vsif_gex_cmam_cm_forbidden_downstream_attribute_mask,
     {"..2 CM Forbidden Downstream Attribute", "docsis_vsif.gex.cmam.cm_forbidden_downstream_attribute",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - CM Attribute Mask - CM Forbidden Downstream Attribute", HFILL}
    },
    {&hf_docsis_vsif_gex_cmam_cm_required_upstream_attribute_mask,
     {"..3 CM Required Upstream Attribute", "docsis_vsif.gex.cmam.cm_required_upstream_attribute",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - CM Attribute Mask - CM Required Upstream Attribute", HFILL}
    },
    {&hf_docsis_vsif_gex_cmam_cm_forbidden_upstream_attribute_mask,
     {"..4 CM Forbidden Upstream Attribute", "docsis_vsif.gex.cmam.cm_forbidden_upstream_attribute",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - CM Attribute Mask - CM Forbidden Upstream Attribute", HFILL}
    },
    {&hf_docsis_vsif_gex_imja,
     {".10 IP Multicast Join Authorization", "docsis_vsif.gex.imja",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ip_multicast_profile_name,
     {"..1 IP Multicast Profile Name", "docsis_vsif.gex.imja.ip_multicast_profile_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Name", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ssr,
     {"..2 IP Multicast Profile Join Authorization Static Session Rule", "docsis_vsif.gex.imja.ip_multicast_join_authorization_static_session_rule",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Join Authorization Static Session Rule", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ssr_rule_priority,
     {"...1 Rule Priority", "docsis_vsif.gex.imja.imja_ssr_rule_priority",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Join Authorization Static Session Rule - Rule Priority", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ssr_authorization_action,
     {"...2 Authorization Action", "docsis_vsif.gex.imja.imja_ssr_authorization_action",
      FT_UINT8, BASE_DEC, VALS(authorization_action_vals), 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Join Authorization Static Session Rule - Rule Priority", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ssr_source_prefix_addressv4,
     {"...3 Source Prefix Address", "docsis_vsif.gex.imja.imja_ssr_source_prefix_address4",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Join Authorization Static Session Rule - Source Prefix Address", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ssr_source_prefix_addressv6,
     {"...3 Source Prefix Address", "docsis_vsif.gex.imja.imja_ssr_source_prefix_address6",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Join Authorization Static Session Rule - Source Prefix Address", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ssr_source_prefix_length,
     {"...4 Source Prefix Length", "docsis_vsif.gex.imja.imja_ssr_source_prefix_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Join Authorization Static Session Rule - Source Prefix Length", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ssr_group_prefix_addressv4,
     {"...5 Group Prefix Address", "docsis_vsif.gex.imja.imja_ssr_group_prefix_address4",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Join Authorization Static Session Rule - Group Prefix Address", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ssr_group_prefix_addressv6,
     {"...5 Group Prefix Address", "docsis_vsif.gex.imja.imja_ssr_group_prefix_address6",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Join Authorization Static Session Rule - Group Prefix Address", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_ssr_group_prefix_length,
     {"...6 Group Prefix Length", "docsis_vsif.gex.imja.imja_ssr_group_prefix_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - IP Multicast Profile Join Authorization Static Session Rule - Group Prefix Length", HFILL}
    },
    {&hf_docsis_vsif_gex_imja_maximum_multicast_sessions,
     {"..3 Maximum Multicast Sessions", "docsis_vsif.gex.imja.imja_maximum_multicast_sessions",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "General Extension Information - IP Multicast Join Authorization - Maximum Multicast Sessions", HFILL}
    },
    {&hf_docsis_vsif_gex_service_type_identifier,
     {".11 Service Type Identifier", "docsis_vsif.gex.service_type_identifier",
      FT_STRING, BASE_NONE, NULL, 0x0,
      "General Extension Information - Service Type Identifier", HFILL}
    },
    {&hf_docsis_vsif_tlv_unknown,
     {"Unknown VSIF TLV", "docsis_vsif.unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
  };

  static int *ett[] = {
    &ett_docsis_vsif,
    &ett_docsis_vsif_ipprec,
    &ett_docsis_vsif_gex_ecm,
    &ett_docsis_vsif_gex_sav,
    &ett_docsis_vsif_gex_sav_spr,
    &ett_docsis_vsif_gex_cmam,
    &ett_docsis_vsif_gex_imja,
    &ett_docsis_vsif_gex_imja_ssr
  };

  expert_module_t* expert_docsis_vsif;

  static ei_register_info ei[] = {
    {&ei_docsis_vsif_tlvlen_bad, { "docsis_vsif.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
    {&ei_docsis_vsif_tlvtype_unknown, { "docsis_vsif.tlvtypeunknown", PI_PROTOCOL, PI_WARN, "Unknown TLV type", EXPFILL}},
  };

  proto_docsis_vsif =
    proto_register_protocol ("DOCSIS Vendor Specific Encodings",
                             "DOCSIS VSIF", "docsis_vsif");

  proto_register_field_array (proto_docsis_vsif, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_vsif = expert_register_protocol(proto_docsis_vsif);
  expert_register_field_array(expert_docsis_vsif, ei, array_length(ei));

  register_dissector ("docsis_vsif", dissect_vsif, proto_docsis_vsif);
}

void
proto_reg_handoff_docsis_vsif (void)
{
#if 0
  dissector_handle_t docsis_vsif_handle;

  docsis_vsif_handle = find_dissector ("docsis_vsif");
  dissector_add_uint ("docsis", 0xFD, docsis_vsif_handle);
#endif
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
