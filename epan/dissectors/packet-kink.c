/* packet-kink.c
 * Routines for KINK packet disassembly
 * It is referrenced draft-ietf-kink-kink-jp-04.txt,v 1.14 2003/02/10
 *
 * Copyright 2004, Takeshi Nakashima <T.Nakashima@jp.yokogawa.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include "packet-kerberos.h"
#include "packet-isakmp.h"

#define KINK_PORT       57203

#define KINK_ISAKMP_PAYLOAD_BASE 14

static int proto_kink = -1;

/* Argument for proto_tree_add_uint() */
static int hf_kink_type = -1;
static int hf_kink_length = -1;
static int hf_kink_transactionId = -1;
static int hf_kink_checkSumLength = -1;
static int hf_kink_A = -1;
static int hf_kink_reserved = -1;
static int hf_kink_checkSum = -1;
static int hf_kink_next_payload = -1;

/* Argument for making the subtree */
static gint ett_kink = -1;
/*static gint ett_kink_version = -1;*/
static gint ett_kink_payload = -1;
static gint ett_payload_kink_ap_req = -1;
static gint ett_payload_kink_ap_rep = -1;
static gint ett_payload_kink_krb_error = -1;
static gint ett_payload_kink_tgt_req = -1;
static gint ett_payload_kink_tgt_rep = -1;
static gint ett_payload_kink_isakmp = -1;
static gint ett_payload_kink_encrypt = -1;
static gint ett_payload_kink_error = -1;
static gint ett_payload_not_defined = -1;
static gint ett_decrypt_kink_encrypt = -1;

/* Define the kink type value */
#define KINK_TYPE_RESERVED 0
#define KINK_TYPE_CREATE   1
#define KINK_TYPE_DELETE   2
#define KINK_TYPE_REPLY    3
#define KINK_TYPE_GETTGT   4
#define KINK_TYPE_ACK      5
#define KINK_TYPE_STATUS   6

static const value_string kink_type_vals[]={
  {KINK_TYPE_RESERVED,"RESERVED"},
  {KINK_TYPE_CREATE,"CREATE"},
  {KINK_TYPE_DELETE,"DELETE"},
  {KINK_TYPE_REPLY,"REPLY"},
  {KINK_TYPE_GETTGT,"GETTGT"},
  {KINK_TYPE_ACK,"ACK"},
  {KINK_TYPE_STATUS,"STATUS"},
  {0, NULL},
};

/* Define the kink A value */
#define KINK_A_NOT_REQUEST_ACK  0
#define KINK_A_REQUEST_ACK      1

static const value_string kink_A_vals[]={
  {KINK_A_NOT_REQUEST_ACK,"Not Request ACK"},
  {KINK_A_REQUEST_ACK,"Request ACK"},
  {0, NULL},
};

/* Define the kink payload */
#define KINK_DONE                                0
#define KINK_AP_REQ     KINK_ISAKMP_PAYLOAD_BASE+0
#define KINK_AP_REP     KINK_ISAKMP_PAYLOAD_BASE+1
#define KINK_KRB_ERROR  KINK_ISAKMP_PAYLOAD_BASE+2
#define KINK_TGT_REQ    KINK_ISAKMP_PAYLOAD_BASE+3
#define KINK_TGT_REP    KINK_ISAKMP_PAYLOAD_BASE+4
#define KINK_ISAKMP     KINK_ISAKMP_PAYLOAD_BASE+5
#define KINK_ENCRYPT    KINK_ISAKMP_PAYLOAD_BASE+6
#define KINK_ERROR      KINK_ISAKMP_PAYLOAD_BASE+7

static const value_string kink_next_payload[]={
  {KINK_DONE, "KINK_DONE"},
  {KINK_AP_REQ, "KINK_AP_REQ"},
  {KINK_AP_REP, "KINK_AP_REP"},
  {KINK_KRB_ERROR, "KINK_KRB_ERROR"},
  {KINK_TGT_REQ, "KINK_TGT_REQ"},
  {KINK_TGT_REP, "KINK_TGT_REP"},
  {KINK_ISAKMP, "KINK_ISAKMP"},
  {KINK_ENCRYPT, "KINK_ENCRYPT"},
  {KINK_ERROR, "KINK_ERROR"},
  {0, NULL},
};

/* Define the magic number
 * Using at the kink error
 */
#define KINK_OK                   0
#define KINK_PROTOERR             1
#define KINK_INVDOI               2
#define KINK_INVMAJ               3
#define KINK_INVMIN               4
#define KINK_INTERR               5
#define KINK_BADQMVERS            6
#define BOTTOM_RESERVED           7
#define TOP_RESERVED           8191
#define BOTTOM_PRIVATE_USE     8192
#define TOP_PRIVATE_USE       16383

/* Using at the kink header */
#define IPSEC                     1
#define VERSION_BIT_SHIFT         4
#define A_BIT_SHIFT               7
#define FROM_TYPE_TO_RESERVED    16

/* Using at the payload */
#define TO_PAYLOAD_LENGTH         2
#define PADDING                   4
#define KINK_KRB_ERROR_HEADER     4
#define FROM_NP_TO_PL             4
#define TO_REALM_NAME_LENGTH      4
#define KINK_TGT_REQ_HEADER       6
#define FRONT_TGT_REP_HEADER      6
#define PAYLOAD_HEADER            8
#define KINK_ERROR_LENGTH         8


/* define hexadecimal */
#define FRONT_FOUR_BIT         0xf0
#define SECOND_FOUR_BIT        0x0f
#define FRONT_ONE_BIT          0x80
#define SECOND_FIFTEEN_BIT   0x7fff

/* decrypt element */
static guint32 keytype;

static void control_payload(packet_info *pinfo, tvbuff_t *tvb, int offset, guint8 next_payload, proto_tree *kink_payload_tree);
static void dissect_payload_kink_ap_req(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_payload_kink_ap_rep(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_payload_kink_krb_error(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_payload_kink_tgt_req(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_payload_kink_tgt_rep(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_payload_kink_isakmp(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_payload_kink_encrypt(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_payload_kink_error(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_payload_kink_not_defined(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree);
#ifdef HAVE_KERBEROS
static void dissect_decrypt_kink_encrypt(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, int payload_length);
#endif

/* This function is dissecting the kink header. */
static void
dissect_kink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
  proto_item *ti = NULL;
  proto_tree *kink_tree = NULL;
  guint8 type;
  guint8 major_version, minor_version, version;
  guint32 doi;
  guint chsumlen;
  guint8 next_payload;
  guint8 value_a_and_front_reserved;
  guint16 value_a_and_reserved;
  guint8 value_a;
  guint16 value_reserved;
  int offset=0;

  type = tvb_get_guint8(tvb,offset);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "KINK");

  /* It shows kink type by the type value. */
  if(check_col(pinfo->cinfo, COL_INFO)){
    col_add_str(pinfo->cinfo, COL_INFO,  val_to_str(type, kink_type_vals, "unknown"));
  }
  /* Make the kink tree */
  if(tree){
    ti = proto_tree_add_item(tree, proto_kink, tvb, offset, -1, ENC_NA);
    kink_tree = proto_item_add_subtree(ti, ett_kink);
  }

  proto_tree_add_uint(kink_tree, hf_kink_type, tvb, offset, 1, type);
  offset++;

  /* This part is the version. Consider less than 1 octet value.
   * Major version and minor version is 4bit. Front half of 1octet
   * is major version, and second half of 1octet is minor version.
   * The calculation of major version is shown below.
   * The logical product of the value of 1octet and 0xf0 is performed.
   * And It is performed 4bit right shift.
   * Secondarily, the calculation of minor version is shown below.
   * The logical product of the value of 1octet and 0x0f is performed.
   */
  version = tvb_get_guint8(tvb,offset);
  major_version = (version & FRONT_FOUR_BIT) >> VERSION_BIT_SHIFT;
  minor_version = version & SECOND_FOUR_BIT;
  proto_tree_add_text(kink_tree, tvb, offset, 1, "version: %u.%u", major_version, minor_version);
  offset++;

  proto_tree_add_item(kink_tree, hf_kink_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  doi = tvb_get_ntohl(tvb, offset);

  if(doi == IPSEC){
    proto_tree_add_text(kink_tree, tvb, offset, 4, "Domain Of Interpretation: %s (%u)", "IPsec", doi);
  }
  else{
    proto_tree_add_text(kink_tree, tvb, offset, 4, "Domain Of Interpretation: %s (%u)", "Not IPsec", doi);
  }
  offset += 4;

  proto_tree_add_item(kink_tree, hf_kink_transactionId, tvb, offset, 4,  ENC_BIG_ENDIAN);
  offset += 4;

  chsumlen = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(kink_tree, hf_kink_checkSumLength, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset ++;

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(kink_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  /* A is 1bit field. The caluculation of A is shown below.
   * The logical product of 1octet value and 0x80 is performed.
   * And It is performed 7bit right shift.
   */
  value_a_and_front_reserved = tvb_get_guint8(tvb, offset);
  value_a = (value_a_and_front_reserved & FRONT_ONE_BIT) >> A_BIT_SHIFT;
  proto_tree_add_uint(kink_tree, hf_kink_A, tvb, offset, 1, value_a);

  /* The reserved field is 15bit.
   * The logical product of 2octet value and 0x7fff is performed.
   */
  value_a_and_reserved = tvb_get_ntohs(tvb, offset);
  value_reserved = value_a_and_reserved & SECOND_FIFTEEN_BIT;
  proto_tree_add_uint(kink_tree, hf_kink_reserved, tvb, offset, 2, value_reserved);
  offset += 2;

  proto_tree_add_item(kink_tree, hf_kink_checkSum, tvb, offset, chsumlen, ENC_NA);

  /* This part consider the padding. Chsumlen don't contain the padding. */
  if((chsumlen % PADDING) != 0){
    chsumlen += (PADDING - (chsumlen % PADDING));
    offset += chsumlen;
  }
  else{
    offset += chsumlen;
  }

  control_payload(pinfo, tvb, offset, next_payload, kink_tree);

}

/* This part call the dissect payload function by next_payload value.
 * This function called by the respective function again.
 */
static void
control_payload(packet_info *pinfo, tvbuff_t *tvb, int offset, guint8 next_payload, proto_tree *kink_tree){
  switch(next_payload){
  case KINK_DONE:
    break;
  case KINK_AP_REQ:
    dissect_payload_kink_ap_req(pinfo, tvb, offset, kink_tree);
    break;
  case KINK_AP_REP:
    dissect_payload_kink_ap_rep(pinfo, tvb, offset, kink_tree);
    break;
  case KINK_KRB_ERROR:
    dissect_payload_kink_krb_error(pinfo, tvb, offset, kink_tree);
    break;
  case KINK_TGT_REQ:
    dissect_payload_kink_tgt_req(pinfo, tvb, offset, kink_tree);
    break;
  case KINK_TGT_REP:
    dissect_payload_kink_tgt_rep(pinfo, tvb, offset, kink_tree);
    break;
  case KINK_ISAKMP:
    dissect_payload_kink_isakmp(pinfo, tvb, offset, kink_tree);
    break;
  case KINK_ENCRYPT:
    dissect_payload_kink_encrypt(pinfo, tvb, offset, kink_tree);
    break;
  case KINK_ERROR:
    dissect_payload_kink_error(pinfo, tvb, offset, kink_tree);
    break;
  default:
    dissect_payload_kink_not_defined(pinfo, tvb, offset, kink_tree);
    break;
  }
}

static void
dissect_payload_kink_ap_req(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree){
  proto_tree *payload_kink_ap_req_tree;
  proto_item *ti;
  guint8 next_payload;
  guint8 reserved;
  guint payload_length;
  guint16 krb_ap_req_length;
  time_t timer;                  /* For showing utc */
  int start_payload_offset = 0;  /* Keep begining of payload offset */

  start_payload_offset = offset;
  payload_length = tvb_get_ntohs(tvb, offset + TO_PAYLOAD_LENGTH);

  /* Make the subtree. */
  ti = proto_tree_add_text(tree, tvb, offset, payload_length, "KINK_AP_REQ");
  payload_kink_ap_req_tree = proto_item_add_subtree(ti, ett_payload_kink_ap_req);

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(payload_kink_ap_req_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(payload_kink_ap_req_tree, tvb, offset, 1, "RESERVED: %u", reserved);
  offset ++;

  if(payload_length <= PAYLOAD_HEADER){
    proto_tree_add_text(payload_kink_ap_req_tree, tvb, offset, 2, "This Payload Length is too small.: %u", payload_length);
  }
  else{
    proto_tree_add_text(payload_kink_ap_req_tree, tvb, offset, 2, "Payload Length: %u", payload_length);
  }
  offset += 2;

  /* Show time as UTC, not local time. */
  timer = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(payload_kink_ap_req_tree, tvb, offset, 4, "EPOCH: %s",
                      abs_time_secs_to_str(timer, ABSOLUTE_TIME_UTC, TRUE));
  offset += 4;

  if(payload_length > PAYLOAD_HEADER){
    tvbuff_t *krb_tvb;

    krb_ap_req_length = payload_length - PAYLOAD_HEADER;
    krb_tvb=tvb_new_subset(tvb, offset, (krb_ap_req_length>tvb_length_remaining(tvb, offset))?tvb_length_remaining(tvb, offset):krb_ap_req_length, krb_ap_req_length);
    keytype=kerberos_output_keytype();
    dissect_kerberos_main(krb_tvb, pinfo, payload_kink_ap_req_tree, FALSE, NULL);
    offset += krb_ap_req_length;
  }

  /* This part consider padding the padding. Payload_length don't contain the padding. */
  if(payload_length % PADDING != 0){
    payload_length += (PADDING - (payload_length % PADDING));
  }
  offset = start_payload_offset + payload_length;

  if(payload_length > 0) {
    control_payload(pinfo, tvb, offset, next_payload, tree); /* Recur control_payload() */
  }
}


static void
dissect_payload_kink_ap_rep(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree){
  proto_tree *payload_kink_ap_rep_tree;
  proto_item *ti;
  guint8 next_payload;
  guint8 reserved;
  guint payload_length;
  guint16 krb_ap_rep_length;
  time_t timer;
  int start_payload_offset = 0; /* Keep begining of payload offset */

  payload_length = tvb_get_ntohs(tvb, offset + TO_PAYLOAD_LENGTH);
  start_payload_offset = offset;

  /* Make the subtree */
  ti = proto_tree_add_text(tree, tvb, offset, payload_length,"KINK_AP_REP");
  payload_kink_ap_rep_tree = proto_item_add_subtree(ti, ett_payload_kink_ap_rep);

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(payload_kink_ap_rep_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(payload_kink_ap_rep_tree, tvb, offset, 1, "RESERVED: %u", reserved);
  offset ++;

  if(payload_length <= PAYLOAD_HEADER){
    proto_tree_add_text(payload_kink_ap_rep_tree, tvb, offset, 2, "This Payload Length is too small.: %u", payload_length);
  }
  else{
    proto_tree_add_text(payload_kink_ap_rep_tree, tvb, offset, 2, "Payload Length: %u", payload_length);
  }
  offset += 2;

  /* Show time as UTC, not local time. */
  timer = tvb_get_ntohl(tvb, offset);
  proto_tree_add_text(payload_kink_ap_rep_tree, tvb, offset, 4, "EPOCH: %s",
                      abs_time_secs_to_str(timer, ABSOLUTE_TIME_UTC, TRUE));
  offset += 4;

  if(payload_length > PAYLOAD_HEADER){
    tvbuff_t *krb_tvb;

    krb_ap_rep_length = payload_length - PAYLOAD_HEADER;
    krb_tvb=tvb_new_subset(tvb, offset, (krb_ap_rep_length>tvb_length_remaining(tvb, offset))?tvb_length_remaining(tvb, offset):krb_ap_rep_length, krb_ap_rep_length);
    keytype=kerberos_output_keytype();
    dissect_kerberos_main(krb_tvb, pinfo, payload_kink_ap_rep_tree, FALSE, NULL);

    offset += krb_ap_rep_length;
  }

  /* This part consider the padding. Payload_length don't contain the padding. */
  if(payload_length % PADDING != 0){
    payload_length += (PADDING - (payload_length % PADDING));
  }
  offset = start_payload_offset + payload_length;

  if(payload_length > 0) {
    control_payload(pinfo, tvb, offset, next_payload, tree); /* Recur control_payload() */
  }
}

static void
dissect_payload_kink_krb_error(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree){
  proto_tree *payload_kink_krb_error_tree;
  proto_item *ti;
  guint8 next_payload;
  guint8 reserved;
  guint payload_length;
  guint16 krb_error_length;
  int start_payload_offset = 0; /* Keep the begining of the payload offset  */

  payload_length = tvb_get_ntohs(tvb, offset + TO_PAYLOAD_LENGTH);
  start_payload_offset = offset;

  /* Make the subtree */
  ti = proto_tree_add_text(tree, tvb, offset, payload_length,"KINK_KRB_ERROR");
  payload_kink_krb_error_tree = proto_item_add_subtree(ti, ett_payload_kink_krb_error);

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(payload_kink_krb_error_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(payload_kink_krb_error_tree, tvb, offset, 1, "RESERVED: %u", reserved);
  offset ++;

  if(payload_length <= KINK_KRB_ERROR_HEADER){
    proto_tree_add_text(payload_kink_krb_error_tree, tvb, offset, 2, "This Payload Length is too small.: %u", payload_length);
  }
  else{
    proto_tree_add_text(payload_kink_krb_error_tree, tvb, offset, 2, "Payload Length: %u", payload_length);
    offset += 2;
  }

  if(payload_length > KINK_KRB_ERROR_HEADER){
    tvbuff_t *krb_tvb;

    krb_error_length = payload_length - KINK_KRB_ERROR_HEADER;
    krb_tvb=tvb_new_subset(tvb, offset, (krb_error_length>tvb_length_remaining(tvb, offset))?tvb_length_remaining(tvb, offset):krb_error_length, krb_error_length);

    dissect_kerberos_main(krb_tvb, pinfo, payload_kink_krb_error_tree, FALSE, NULL);
    offset += krb_error_length;
  }

  /* This part consider the padding. Payload_length don't contain the padding. */
  if(payload_length % PADDING != 0){
    payload_length += (PADDING - (payload_length % PADDING));
  }
  offset = start_payload_offset + payload_length;

  if(payload_length > 0) {
    control_payload(pinfo, tvb, offset, next_payload, tree); /* Recur control_payload() */
  }
}

static void
dissect_payload_kink_tgt_req(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree){
  proto_tree *payload_kink_tgt_req_tree;
  proto_item *ti;
  guint8 next_payload;
  guint8 reserved;
  guint payload_length;
  guint16 realm_name_length;
  int start_payload_offset = 0; /* Keep the begining of the payload offset  */

  payload_length = tvb_get_ntohs(tvb, offset + TO_PAYLOAD_LENGTH);
  realm_name_length = tvb_get_ntohs(tvb, offset + TO_REALM_NAME_LENGTH);
  start_payload_offset = offset;

  /* Make the subtree */
  ti = proto_tree_add_text(tree, tvb, offset, payload_length,"KINK_TGT_REQ");
  payload_kink_tgt_req_tree = proto_item_add_subtree(ti, ett_payload_kink_tgt_req);

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(payload_kink_tgt_req_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(payload_kink_tgt_req_tree, tvb, offset, 1, "RESERVED: %u", reserved);
  offset ++;

  proto_tree_add_text(payload_kink_tgt_req_tree, tvb, offset, 2, "Payload Length: %u", payload_length);
  offset += 2;

  proto_tree_add_text(payload_kink_tgt_req_tree, tvb, offset, 2, "RealmNameLength: %u", realm_name_length);
  offset += 2;

  proto_tree_add_text(payload_kink_tgt_req_tree, tvb, offset, realm_name_length, "RealmName: %s",
                      tvb_format_text(tvb, offset, realm_name_length));
  offset += realm_name_length;

  /* This part consider the padding. Payload_length don't contain the padding. */
  if(payload_length % PADDING != 0){
    payload_length += (PADDING - (payload_length % PADDING));
  }
  offset = start_payload_offset + payload_length;

  if(payload_length > 0) {
    control_payload(pinfo, tvb, offset, next_payload, tree); /* Recur control_payload() */
  }
}

static void
dissect_payload_kink_tgt_rep(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree){
  proto_tree *payload_kink_tgt_rep_tree;
  proto_item *ti;
  guint8 next_payload;
  guint8 reserved;
  guint payload_length;
  guint princ_name_length;
  guint16 tgt_length;
  int start_payload_offset = 0; /* Keep the begining of the payload offset  */

  payload_length = tvb_get_ntohs(tvb, offset + TO_PAYLOAD_LENGTH);
  start_payload_offset = offset;

  /* Make the subtree */
  ti = proto_tree_add_text(tree, tvb, offset, payload_length,"KINK_TGT_REP");
  payload_kink_tgt_rep_tree = proto_item_add_subtree(ti, ett_payload_kink_tgt_rep);

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(payload_kink_tgt_rep_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(payload_kink_tgt_rep_tree, tvb, offset, 1, "RESERVED: %u", reserved);
  offset ++;

  proto_tree_add_text(payload_kink_tgt_rep_tree, tvb, offset, 2, "Payload Length: %u", payload_length);
  offset += 2;

  princ_name_length = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(payload_kink_tgt_rep_tree, tvb, offset, 2, "PrincNameLength: %u", princ_name_length);
  offset += 2;

  proto_tree_add_text(payload_kink_tgt_rep_tree, tvb, offset, princ_name_length, "PrincName: %s", tvb_format_text(tvb, offset, princ_name_length));

  /* This part consider the padding. Princ_name_length don't contain the padding. */
  if((princ_name_length + FRONT_TGT_REP_HEADER) % PADDING != 0){
    offset += (princ_name_length + PADDING - ((princ_name_length + FRONT_TGT_REP_HEADER) %  PADDING));
  }
  else{
    offset += princ_name_length;
  }

  tgt_length = tvb_get_ntohs(tvb,offset);

  proto_tree_add_text(payload_kink_tgt_rep_tree, tvb, offset, 2, "TGTlength: %u", tgt_length);
  offset += 2;

  proto_tree_add_text(payload_kink_tgt_rep_tree, tvb, offset, tgt_length, "TGT: %s", tvb_format_text(tvb, offset, tgt_length));
  offset += tgt_length;

  /* This part consider the padding. Payload_length don't contain the padding. */
  if(payload_length % PADDING!=0){
    payload_length += (PADDING - (payload_length % PADDING));
  }
  offset = start_payload_offset + payload_length;

  if(payload_length > 0) {
    control_payload(pinfo, tvb, offset, next_payload, tree); /* Recur control_payload() */
  }
}

static void
dissect_payload_kink_isakmp(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree){
  proto_tree *payload_kink_isakmp_tree;
  proto_item *ti;
  guint8 next_payload;
  guint8 reserved;
  guint payload_length,isakmp_length;
  int length, reported_length;
  guint8 inner_next_pload;
  guint8 qm, qmmaj, qmmin;
  guint16 reserved2;
  int start_payload_offset = 0;      /* Keep the begining of the payload offset */
  tvbuff_t *isakmp_tvb;

  payload_length = tvb_get_ntohs(tvb, offset + TO_PAYLOAD_LENGTH);
  start_payload_offset = offset;

  /* Make the subtree. */
  ti = proto_tree_add_text(tree, tvb, offset, payload_length,"KINK_ISAKMP");
  payload_kink_isakmp_tree = proto_item_add_subtree(ti, ett_payload_kink_isakmp);

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(payload_kink_isakmp_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(payload_kink_isakmp_tree, tvb, offset, 1, "RESERVED: %u", reserved);
  offset ++;

  if(payload_length <= PAYLOAD_HEADER){
    proto_tree_add_text(payload_kink_isakmp_tree, tvb, offset, 2, "This Payload Length is too small.: %u", payload_length);
  }
  else{
    proto_tree_add_text(payload_kink_isakmp_tree, tvb, offset, 2, "Payload Length: %u", payload_length);
  }
  offset += 2;

  inner_next_pload = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(payload_kink_isakmp_tree, tvb, offset, 1, "InnerNextPload: %u", inner_next_pload);
  offset += 1;

  /* The qmmaj is first half 4bit field of the octet. Therefore, the logical product
   * of the 1octet value and 0xf0 is performed, and performed 4bit right shift.
   * The qmmin is second half 4bit field of the octet. Therefore, the logical product
   * of the 1octet value and 0x0f is performed.
   */
  qm = tvb_get_guint8(tvb,offset);
  qmmaj = (qm & FRONT_FOUR_BIT) >> VERSION_BIT_SHIFT;
  qmmin = qm & SECOND_FOUR_BIT;

  proto_tree_add_text(payload_kink_isakmp_tree, tvb, offset, 1, "QMVersion: %u.%u", qmmaj, qmmin);
  offset += 1;

  reserved2 = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(payload_kink_isakmp_tree, tvb, offset, 2, "RESERVED: %u", reserved2);
  offset += 2;

  if(payload_length > PAYLOAD_HEADER){
    isakmp_length = payload_length - PAYLOAD_HEADER;
    length = tvb_length_remaining(tvb, offset);
    if (length > (int)isakmp_length)
      length = isakmp_length;
    reported_length = tvb_reported_length_remaining(tvb, offset);
    if (reported_length > (int)isakmp_length)
      reported_length = isakmp_length;
    isakmp_tvb = tvb_new_subset(tvb, offset, length, reported_length);
    isakmp_dissect_payloads(isakmp_tvb, payload_kink_isakmp_tree, 1, inner_next_pload, 0, isakmp_length, pinfo);
  }

  /* This part consider the padding. Payload_length don't contain the padding. */
  if(payload_length % PADDING != 0){
    payload_length += (PADDING - (payload_length % PADDING));
  }
  offset = start_payload_offset + payload_length;

  if(payload_length > 0) {
    control_payload(pinfo, tvb, offset, next_payload, tree);  /* Recur control_payload() */
  }
}

static void
dissect_payload_kink_encrypt(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree){
  proto_tree *payload_kink_encrypt_tree;
  proto_item *ti;
  guint8 next_payload;
  guint8 reserved;
  guint payload_length;
  gint encrypt_length;
  guint8 inner_next_pload;
  guint32 reserved2;
  guint16 inner_payload_length;
  int start_payload_offset = 0;    /* Keep the begining of the payload offset */

  payload_length = tvb_get_ntohs(tvb,offset + TO_PAYLOAD_LENGTH);
  start_payload_offset = offset;

  encrypt_length = payload_length - FROM_NP_TO_PL;

  /* Make the subtree */
  ti = proto_tree_add_text(tree, tvb, offset, payload_length,"KINK_ENCRYPT");
  payload_kink_encrypt_tree = proto_item_add_subtree(ti, ett_payload_kink_encrypt);

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(payload_kink_encrypt_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(payload_kink_encrypt_tree, tvb, offset, 1, "RESERVED: %u", reserved);
  offset ++;

  if(payload_length <= PAYLOAD_HEADER){
    proto_tree_add_text(payload_kink_encrypt_tree, tvb, offset, 2, "This Payload Length is too small.: %u", payload_length);
  }
  else{
    proto_tree_add_text(payload_kink_encrypt_tree, tvb, offset, 2, "Payload Length: %u", payload_length);
  }
  offset += 2;

  /* decrypt kink encrypt */

  if(keytype != 0){
#ifdef HAVE_KERBEROS
    tvbuff_t *next_tvb;
    guint8 *plaintext=NULL;

    next_tvb=tvb_new_subset(tvb, offset, MIN(tvb_length_remaining(tvb, offset), encrypt_length), encrypt_length);
    plaintext=decrypt_krb5_data(tree, pinfo, 0, next_tvb, keytype, NULL);
    if(plaintext){
      next_tvb=tvb_new_child_real_data(tvb, plaintext, encrypt_length, encrypt_length);
      tvb_set_free_cb(next_tvb, g_free);
      add_new_data_source(pinfo, next_tvb, "decrypted kink encrypt");
      dissect_decrypt_kink_encrypt(pinfo, next_tvb, tree, encrypt_length);
    }
#endif
  }
  else{
    inner_next_pload = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(payload_kink_encrypt_tree, tvb, offset, 1, "InnerNextPload: %u", inner_next_pload);
    offset += 1;

    reserved2 = 65536*tvb_get_guint8(tvb, offset) + 256*tvb_get_guint8(tvb, offset+1) + tvb_get_guint8(tvb, offset+2);
    proto_tree_add_text(payload_kink_encrypt_tree, tvb, offset, 3, "RESERVED: %u", reserved2);
    offset += 3;

    if(payload_length > PAYLOAD_HEADER){
      inner_payload_length = payload_length - PAYLOAD_HEADER;
      proto_tree_add_text(payload_kink_encrypt_tree, tvb, offset, inner_payload_length, "Payload");
      offset += inner_payload_length;
    }
  }
  /* This part consider the padding. Payload_length don't contain the padding. */
  if(payload_length % PADDING !=0){
    payload_length += (PADDING - (payload_length % PADDING));
  }
  offset = start_payload_offset + payload_length;

  if(payload_length > 0) {
    control_payload(pinfo, tvb, offset, next_payload, tree);  /* Recur control_payload() */
  }
}

#ifdef HAVE_KERBEROS
static void
dissect_decrypt_kink_encrypt(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, int payload_length){

  proto_tree *decrypt_kink_encrypt_tree;
  proto_item *ti;
  int offset=0;
  guint8 next_payload;
  guint32 reserved;

  ti = proto_tree_add_text(tree, tvb, offset, payload_length, "decrypted data");
  decrypt_kink_encrypt_tree = proto_item_add_subtree(ti, ett_decrypt_kink_encrypt);

  next_payload = tvb_get_guint8(tvb, offset);

  proto_tree_add_uint(decrypt_kink_encrypt_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = 65536*tvb_get_guint8(tvb, offset) + 256*tvb_get_guint8(tvb, offset+1) + tvb_get_guint8(tvb, offset+2);
  proto_tree_add_text(decrypt_kink_encrypt_tree, tvb, offset, 3, "RESERVED: %u", reserved);
  offset += 3;

  control_payload(pinfo, tvb, offset, next_payload, decrypt_kink_encrypt_tree);
}
#endif

static void
dissect_payload_kink_error(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree){
  proto_tree *payload_kink_error_tree;
  proto_item *ti;
  guint8 next_payload;
  guint8 reserved;
  guint16 payload_length;
  guint32 error_code;
  int start_payload_offset = 0; /* Keep the begining of the payload offset */
  const char *char_error_code[] = {
    "KINK_OK",
    "KINK_PROTOERR",
    "KINK_INVDOI",
    "KINK_INVMAJ",
    "KINK_INVMIN",
    "KINK_INTERR",
    "KINK_BADQMVERS"
  };

  payload_length = tvb_get_ntohs(tvb,offset + TO_PAYLOAD_LENGTH);
  start_payload_offset = offset;

  /* Make the subtree */
  ti = proto_tree_add_text(tree, tvb, offset, payload_length,"KINK_ERROR");
  payload_kink_error_tree = proto_item_add_subtree(ti, ett_payload_kink_error);

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(payload_kink_error_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = tvb_get_guint8(tvb,offset);
  proto_tree_add_text(payload_kink_error_tree, tvb, offset, 1, "RESERVED: %u", reserved);
  offset ++;

  if(payload_length != KINK_ERROR_LENGTH){
    proto_tree_add_text(payload_kink_error_tree, tvb, offset, 2, "This Payload Length is mismatch.: %u", payload_length);
  }
  else{
    proto_tree_add_text(payload_kink_error_tree, tvb, offset, 2, "Payload Length: %u", payload_length);
  }
  offset += 2;

  error_code = tvb_get_ntohl(tvb, offset);

  /* Choosed the error code by erro_code */
  switch(error_code){
  case KINK_OK:
  case KINK_PROTOERR:
  case KINK_INVDOI:
  case KINK_INVMAJ:
  case KINK_INVMIN:
  case KINK_INTERR:
  case KINK_BADQMVERS:
    proto_tree_add_text(payload_kink_error_tree, tvb, offset, 4, "ErrorCode: %s (%u)", char_error_code[error_code], error_code);
    break;
  default:
    if(BOTTOM_RESERVED <= error_code && TOP_RESERVED >= error_code){
      proto_tree_add_text(payload_kink_error_tree, tvb, offset, 4, "ErrorCode: %s (%u)", "RESERVED", error_code);
    }
    else if(BOTTOM_PRIVATE_USE <= error_code && TOP_PRIVATE_USE >= error_code){
      proto_tree_add_text(payload_kink_error_tree, tvb, offset, 4, "ErrorCode: %s (%u)", "PRIVATE USE", error_code);
    }
    else{
      proto_tree_add_text(payload_kink_error_tree, tvb, offset, 4, "ErrorCode: %s (%u)", "This Error Code is not Defined.", error_code);
    }
    break;
  }
  offset += 4;

  offset = start_payload_offset + KINK_ERROR_LENGTH;
  control_payload(pinfo, tvb, offset, next_payload, tree);  /* Recur control_payload() */
}

static void
dissect_payload_kink_not_defined(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree){
  proto_tree *payload_kink_not_defined_tree;
  proto_item *ti;
  guint8 next_payload;
  guint payload_length;
  guint8 reserved;
  int start_payload_offset = 0;   /* Keep the begining of the payload offset */

  start_payload_offset = offset;
  payload_length = tvb_get_ntohs(tvb, offset + TO_PAYLOAD_LENGTH);

  /* Make the subtree */
  ti = proto_tree_add_text(tree, tvb, offset, payload_length, "UNKNOWN PAYLOAD");
  payload_kink_not_defined_tree = proto_item_add_subtree(ti, ett_payload_not_defined);

  next_payload = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint(payload_kink_not_defined_tree, hf_kink_next_payload, tvb, offset, 1, next_payload);
  offset ++;

  reserved = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(payload_kink_not_defined_tree, tvb, offset, 1, "RESERVED: %u", reserved);
  offset ++;

  proto_tree_add_text(payload_kink_not_defined_tree, tvb, offset, 2, "Payload Length: %u", payload_length);
  offset += 2;

  /* This part consider the padding. Payload_length don't contain the padding. */
  if(payload_length % PADDING != 0){
    payload_length += (PADDING - (payload_length % PADDING));
  }
  offset = start_payload_offset + payload_length;

  /* XXX - prevent an endless loop if payload_length is 0, don't know the correct way to handle this! */
  if(payload_length > 0) {
    control_payload(pinfo, tvb, offset, next_payload, tree);
  }
}

/* Output part */
void
proto_register_kink(void) {

  static hf_register_info hf[] = {
    { &hf_kink_type,
      { "Type", "kink.type",
        FT_UINT8,       BASE_DEC,       VALS(kink_type_vals),   0x0,
        "the type of the kink", HFILL }},
    { &hf_kink_length,
      { "Length",       "kink.length",
        FT_UINT16,      BASE_DEC,       NULL,   0x0,
        "the length of the kink length", HFILL }},
    { &hf_kink_transactionId,
      { "Transaction ID",       "kink.transactionId",
        FT_UINT32,      BASE_DEC,       NULL,   0x0,
        "the transactionID of kink", HFILL }},
    { &hf_kink_checkSumLength,
      { "Checksum Length",       "kink.checkSumLength",
        FT_UINT8,       BASE_DEC,       NULL,   0x0,
        "the check sum length of kink", HFILL }},
    { &hf_kink_A,
      { "A",       "kink.A",
        FT_UINT8,       BASE_DEC,       VALS(kink_A_vals),      0x0,
        "the A of kink", HFILL }},
    { &hf_kink_reserved,
      { "Reserved",       "kink.reserved",
        FT_UINT16,      BASE_DEC,       NULL,   0x0,
        "the reserved of kink", HFILL }},
    { &hf_kink_checkSum,
      { "Checksum",       "kink.checkSum",
        FT_BYTES,       BASE_NONE,      NULL,   0x0,
        "the checkSum of kink", HFILL }},
    { &hf_kink_next_payload,
      { "Next Payload",       "kink.nextPayload",
        FT_UINT8,       BASE_DEC,       VALS(kink_next_payload),        0x0,
        "the next payload of kink", HFILL }}

  };

  /* Argument for making the subtree. */
  static gint *ett[] = {
    &ett_kink,
    /*    &ett_kink_version, */
    &ett_kink_payload,
    &ett_payload_kink_ap_req,
    &ett_payload_kink_ap_rep,
    &ett_payload_kink_krb_error,
    &ett_payload_kink_tgt_req,
    &ett_payload_kink_tgt_rep,
    &ett_payload_kink_isakmp,
    &ett_payload_kink_encrypt,
    &ett_payload_kink_error,
    &ett_payload_not_defined,
    &ett_decrypt_kink_encrypt,

  };

  proto_kink = proto_register_protocol("Kerberized Internet Negotiation of Key", "KINK", "kink");
  proto_register_field_array(proto_kink, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

void proto_reg_handoff_kink(void) {

  dissector_handle_t kink_handle = NULL;

  kink_handle = create_dissector_handle(dissect_kink, proto_kink);

  dissector_add_uint("udp.port", KINK_PORT, kink_handle);

}

