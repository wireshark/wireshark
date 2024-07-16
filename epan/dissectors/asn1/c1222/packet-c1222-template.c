/* packet-c1222.c
 * Routines for ANSI C12.22 packet dissection
 * Copyright 2010, Edward J. Beroset, edward.beroset@elster.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/uat.h>
#include <epan/oids.h>
#include <wsutil/eax.h>
#include "packet-ber.h"
#include "packet-tcp.h"
#include "packet-c1222.h"

#define PNAME  "ANSI C12.22"
#define PSNAME "C12.22"
#define PFNAME "c1222"
#define C1222_PORT 1153    /* TCP port */

/* C12.22 flag definitions */
#define C1222_EPSEM_FLAG_RESERVED 0x80
#define C1222_EPSEM_FLAG_RECOVERY_SESSION 0x40
#define C1222_EPSEM_FLAG_PROXY_SERVICE_USED 0x20
#define C1222_EPSEM_FLAG_ED_CLASS_INCLUDED 0x10
#define C1222_EPSEM_FLAG_SECURITY_MODE 0x0c
#define C1222_EPSEM_FLAG_RESPONSE_CONTROL 0x03

#define C1222_PROCEDURE_RESPONSE 0xf000
#define C1222_PROCEDURE_MFG      0x0800
#define C1222_PROCEDURE_NUMBER   0x07ff

/* if the packet is encrypted, it can be
 * good, bad, or simply not checked
 */
#define C1222_EPSEM_CRYPTO_GOOD 0x01
#define C1222_EPSEM_CRYPTO_BAD 0x02

/* these defines are for each of the C12.22 services */
#define C1222_CMD_IDENTIFY 0x20
#define C1222_CMD_TERMINATE 0x21
#define C1222_CMD_DISCONNECT 0x22
#define C1222_CMD_FULL_READ 0x30
#define C1222_CMD_DEFAULT_READ 0x3E
#define C1222_CMD_PARTIAL_READ_OFFSET 0x3F
#define C1222_CMD_FULL_WRITE 0x40
#define C1222_CMD_DEFAULT_WRITE 0x4E
#define C1222_CMD_PARTIAL_WRITE_OFFSET 0x4F
#define C1222_CMD_LOGON 0x50
#define C1222_CMD_SECURITY 0x51
#define C1222_CMD_LOGOFF 0x52
#define C1222_CMD_AUTHENTICATE 0x53
#define C1222_CMD_NEGOTIATE 0x60
#define C1222_CMD_WAIT 0x70
#define C1222_CMD_TIMING_SETUP 0x71

void proto_register_c1222(void);

static dissector_handle_t c1222_handle;
static dissector_handle_t c1222_udp_handle;

/* Initialize the protocol and registered fields */
static int proto_c1222;

#include "packet-c1222-hf.c"
/* These are the EPSEM pieces */
/* first, the flag components */
static int hf_c1222_epsem_flags;
static int hf_c1222_epsem_flags_reserved;
static int hf_c1222_epsem_flags_recovery;
static int hf_c1222_epsem_flags_proxy;
static int hf_c1222_epsem_flags_ed_class;
static int hf_c1222_epsem_flags_security_modes;
static int hf_c1222_epsem_flags_response_control;
/* and the structure of the flag components */
static int * const c1222_flags[] = {
  &hf_c1222_epsem_flags_reserved,
  &hf_c1222_epsem_flags_recovery,
  &hf_c1222_epsem_flags_proxy,
  &hf_c1222_epsem_flags_ed_class,
  &hf_c1222_epsem_flags_security_modes,
  &hf_c1222_epsem_flags_response_control,
  NULL
};
/* next the optional ed_class */
static int hf_c1222_epsem_ed_class;
/* now the aggregate epsem */
static int hf_c1222_epsem_total;
/* generic command */
static int hf_c1222_cmd;
static int hf_c1222_err;
static int hf_c1222_data;
/* individual epsem fields */
static int hf_c1222_logon_id;
static int hf_c1222_logon_user;
static int hf_c1222_security_password;
static int hf_c1222_auth_len;
static int hf_c1222_auth_data;
static int hf_c1222_read_table;
static int hf_c1222_read_offset;
static int hf_c1222_read_count;
static int hf_c1222_write_table;
static int hf_c1222_write_offset;
static int hf_c1222_write_size;
static int hf_c1222_write_data;
static int hf_c1222_procedure_response;
static int hf_c1222_procedure_mfg;
static int hf_c1222_procedure_num;
static int hf_c1222_procedure_sequence;
static int hf_c1222_write_chksum;
static int hf_c1222_write_chksum_status;
static int hf_c1222_wait_secs;
static int hf_c1222_neg_pkt_size;
static int hf_c1222_neg_nbr_pkts;
static int hf_c1222_timing_setup_traffic;
static int hf_c1222_timing_setup_inter_char;
static int hf_c1222_timing_setup_resp_to;
static int hf_c1222_timing_setup_nbr_retries;

/* the MAC */
static int hf_c1222_epsem_mac;

/* crypto result flags */
static int hf_c1222_epsem_crypto_good;
static int hf_c1222_epsem_crypto_bad;

/* Initialize the subtree pointers */
static int ett_c1222;
static int ett_c1222_epsem;
static int ett_c1222_flags;
static int ett_c1222_crypto;
static int ett_c1222_cmd;

/* these pointers are for the header elements that may be needed to verify the crypto */
static uint8_t *aSO_context;
static uint8_t *called_AP_title;
static uint8_t *called_AP_invocation_id;
static uint8_t *calling_AE_qualifier;
static uint8_t *calling_AP_invocation_id;
static uint8_t *mechanism_name;
static uint8_t *calling_authentication_value;
static uint8_t *user_information;
static uint8_t *calling_AP_title;
static uint8_t *key_id_element;
static uint8_t *iv_element;

/* these are the related lengths */
static uint32_t aSO_context_len;
static uint32_t called_AP_title_len;
static uint32_t called_AP_invocation_id_len;
static uint32_t calling_AE_qualifier_len;
static uint32_t calling_AP_invocation_id_len;
static uint32_t mechanism_name_len;
static uint32_t calling_authentication_value_len;
static uint32_t user_information_len;
static uint32_t calling_AP_title_len;
static uint32_t key_id_element_len;
static uint32_t iv_element_len;

/* these are the related allocation sizes (which might be different from the lengths) */
static uint32_t aSO_context_allocated;
static uint32_t called_AP_title_allocated;
static uint32_t called_AP_invocation_id_allocated;
static uint32_t calling_AE_qualifier_allocated;
static uint32_t calling_AP_invocation_id_allocated;
static uint32_t mechanism_name_allocated;
static uint32_t calling_authentication_value_allocated;
static uint32_t user_information_allocated;
static uint32_t calling_AP_title_allocated;
static uint32_t key_id_element_allocated;
static uint32_t iv_element_allocated;

#include "packet-c1222-ett.c"

static expert_field ei_c1222_command_truncated;
static expert_field ei_c1222_bad_checksum;
static expert_field ei_c1222_epsem_missing;
static expert_field ei_c1222_epsem_failed_authentication;
static expert_field ei_c1222_epsem_not_decrypted;
static expert_field ei_c1222_ed_class_missing;
static expert_field ei_c1222_epsem_ber_length_error;
static expert_field ei_c1222_epsem_field_length_error;
static expert_field ei_c1222_mac_missing;

/* Preferences */
static bool c1222_desegment = true;
static bool c1222_decrypt = true;
static bool c1222_big_endian;
static const char *c1222_baseoid_str;
static uint8_t *c1222_baseoid;
static unsigned c1222_baseoid_len;

/*------------------------------
 * Data Structures
 *------------------------------
 */
static const value_string c1222_security_modes[] = {
  { 0x00, "Cleartext"},
  { 0x01, "Cleartext with authentication"},
  { 0x02, "Ciphertext with authentication"},
  { 0, NULL }
};

static const value_string c1222_response_control[] = {
  { 0x00, "Always respond"},
  { 0x01, "Respond on exception"},
  { 0x02, "Never respond"},
  { 0, NULL }
};

static const value_string tableflags[] = {
  { 0x00, "ST" },
  { 0x08, "MT" },
  { 0x10, "Pending ST" },
  { 0x18, "Pending MT" },
  { 0x20, "UDT" },
  { 0x30, "Pending UDT" },
  { 0, NULL }
};

static const value_string procflags[] = {
  { 0x00, "SF" },
  { 0x08, "MF" },
  { 0, NULL }
};

static const value_string c1222_proc_response_control[] = {
  { 0x00, "Post response in ST-8 on completion" },
  { 0x01, "Post response in ST-8 on exception" },
  { 0x02, "Do not post response in ST-8" },
  { 0x03, "Post response in ST-8 now, and on completion" },
  { 0, NULL }
};

static const value_string commandnames[] = {
/* error codes are in the range 0x00 - 0x1f inclusive */
  { 0x00, "OK" },
  { 0x01, "Error" },
  { 0x02, "Service Not Supported" },
  { 0x03, "Insufficient Security Clearance" },
  { 0x04, "Operation Not Possible" },
  { 0x05, "Inappropriate Action Requested" },
  { 0x06, "Device Busy" },
  { 0x07, "Data Not Ready" },
  { 0x08, "Data Locked" },
  { 0x09, "Renegotiate Request" },
  { 0x0A, "Invalid Service Sequence State" },
  { 0x0B, "Security Mechanism Error" },
  { 0x0C, "Unknown Application Title" },
  { 0x0D, "Network Time-out" },
  { 0x0E, "Network Not Reachable" },
  { 0x0F, "Request Too Large" },
  { 0x10, "Response Too Large" },
  { 0x11, "Segmentation Not Possible" },
  { 0x12, "Segmentation Error" },
/* commands are in the range 0x20 - 0x7f inclusive */
  {C1222_CMD_IDENTIFY, "Identify" },
  {C1222_CMD_TERMINATE, "Terminate" },
  {C1222_CMD_DISCONNECT, "Disconnect" },
  {C1222_CMD_FULL_READ, "Full Read" },
  {C1222_CMD_DEFAULT_READ, "Default Read" },
  {C1222_CMD_PARTIAL_READ_OFFSET, "Partial Read Offset" },
  {C1222_CMD_FULL_WRITE, "Full Write" },
  {C1222_CMD_DEFAULT_WRITE, "Default Write" },
  {C1222_CMD_PARTIAL_WRITE_OFFSET, "Partial Write Offset" },
  {C1222_CMD_LOGON, "Logon" },
  {C1222_CMD_SECURITY, "Security" },
  {C1222_CMD_LOGOFF, "Logoff" },
  {C1222_CMD_AUTHENTICATE, "Authenticate" },
  {C1222_CMD_NEGOTIATE, "Negotiate" },
  {C1222_CMD_NEGOTIATE | 0x1, "Negotiate w/ 1 Baud Rate" },
  {C1222_CMD_NEGOTIATE | 0x2, "Negotiate w/ 2 Baud Rates" },
  {C1222_CMD_NEGOTIATE | 0x3, "Negotiate w/ 3 Baud Rates" },
  {C1222_CMD_NEGOTIATE | 0x4, "Negotiate w/ 4 Baud Rates" },
  {C1222_CMD_NEGOTIATE | 0x5, "Negotiate w/ 5 Baud Rates" },
  {C1222_CMD_NEGOTIATE | 0x6, "Negotiate w/ 6 Baud Rates" },
  {C1222_CMD_NEGOTIATE | 0x7, "Negotiate w/ 7 Baud Rates" },
  {C1222_CMD_NEGOTIATE | 0x8, "Negotiate w/ 8 Baud Rates" },
  {C1222_CMD_NEGOTIATE | 0x9, "Negotiate w/ 9 Baud Rates" },
  {C1222_CMD_NEGOTIATE | 0xA, "Negotiate w/ 10 Baud Rates" },
  {C1222_CMD_NEGOTIATE | 0xB, "Negotiate w/ 11 Baud Rates" },
  {C1222_CMD_WAIT, "Wait" },
  {C1222_CMD_TIMING_SETUP, "Timing Setup" },
  { 0, NULL }
};

/* these are for the key tables */
typedef struct _c1222_uat_data {
  unsigned keynum;
  unsigned char *key;
  unsigned  keylen;
} c1222_uat_data_t;

UAT_HEX_CB_DEF(c1222_users, keynum, c1222_uat_data_t)
UAT_BUFFER_CB_DEF(c1222_users, key, c1222_uat_data_t, key, keylen)

static c1222_uat_data_t *c1222_uat_data;
static unsigned num_c1222_uat_data;
static uat_t *c1222_uat;

/* these macros ares used to populate fields needed to verify crypto */
#define FILL_START int length, start_offset = offset;
#define FILL_TABLE(fieldname)  \
  length = offset - start_offset; \
  fieldname = (uint8_t *)tvb_memdup(actx->pinfo->pool, tvb, start_offset, length); \
  fieldname##_len = length; \
  fieldname##_allocated = length;
#define FILL_TABLE_TRUNCATE(fieldname, len)  \
  length = 1 + 2*(offset - start_offset); \
  fieldname = (uint8_t *)tvb_memdup(actx->pinfo->pool, tvb, start_offset, length); \
  fieldname##_len = len; \
  fieldname##_allocated = length;
#define FILL_TABLE_APTITLE(fieldname) \
  length = offset - start_offset; \
  switch (tvb_get_uint8(tvb, start_offset)) { \
    case 0x80: /* relative OID */ \
      tvb_ensure_bytes_exist(tvb, start_offset, length); \
      fieldname##_len = length + c1222_baseoid_len; \
      fieldname = (uint8_t *)wmem_alloc(actx->pinfo->pool, fieldname##_len); \
      fieldname##_allocated = fieldname##_len; \
      fieldname[0] = 0x06;  /* create absolute OID tag */ \
      fieldname[1] = (fieldname##_len - 2) & 0xff;  \
      memcpy(&(fieldname[2]), c1222_baseoid, c1222_baseoid_len); \
      tvb_memcpy(tvb, &(fieldname[c1222_baseoid_len+2]), start_offset+2, length-2); \
      break; \
    case 0x06:  /* absolute OID */ \
    default: \
      fieldname = (uint8_t *)tvb_memdup(actx->pinfo->pool, tvb, start_offset, length); \
      fieldname##_len = length; \
      fieldname##_allocated = length; \
      break; \
  }

/*------------------------------
 * Function Prototypes
 *------------------------------
 */
void proto_reg_handoff_c1222(void);


/*------------------------------
 * Code
 *------------------------------
 */

/**
 * Calculates simple one's complement checksum.
 *
 * \param tvb pointer to tvbuff containing data to be checksummed
 * \param offset offset within tvbuff to beginning of data
 * \param len length of data to be checksummed
 * \returns calculated checksum
 */
static uint8_t
c1222_cksum(tvbuff_t *tvb, int offset, int len)
{
  uint8_t sum;
  for (sum = 0; len; offset++, len--)
    sum += tvb_get_uint8(tvb, offset);
  return ~sum + 1;
}
/**
 * Dissects C12.22 packet in detail (with a tree).
 *
 * \param tvb input buffer containing packet to be dissected
 * \param pinfo the packet info of the current data
 * \param tree the tree to append this item to
 * \param length length of data
 * \param offset the offset in the tvb
 */
static void
parse_c1222_detailed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int cmd, uint32_t *length, int *offset)
{
  uint16_t user_id = 0;
  const uint8_t *user_name = NULL;
  const uint8_t *password = NULL;
  uint8_t auth_len = 0;
  char *auth_req = NULL;
  uint16_t table = 0;
  uint16_t tblsize = 0;
  uint16_t calcsum = 0;
  uint8_t wait_seconds = 0;
  uint8_t proc_seq = 0;
  int numrates = 0;
  uint16_t packet_size;
  uint16_t procedure_num = 0;
  uint8_t nbr_packet;
  /* timing setup parameters */
  uint8_t traffic;
  uint8_t inter_char;
  uint8_t resp_to;
  uint8_t nbr_retries;

  /* special case to simplify handling of Negotiate service */
  if ((cmd & 0xF0) == C1222_CMD_NEGOTIATE) {
    numrates = cmd & 0x0F;
    cmd = C1222_CMD_NEGOTIATE;
  }
  proto_tree_add_uint(tree, cmd >= 0x20 ? hf_c1222_cmd : hf_c1222_err, tvb, *offset, 1, cmd);
  (*offset)++;
  (*length)--;
  switch (cmd) {
    case C1222_CMD_LOGON:
      if (*length >= 12) {
        user_id = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_logon_id, tvb, *offset, 2, user_id);
        *offset += 2;
        proto_tree_add_item_ret_string(tree, hf_c1222_logon_user, tvb, *offset, 10, ENC_ASCII|ENC_NA, pinfo->pool, &user_name);
        *offset += 10;
        *length -= 12;
        proto_item_set_text(tree, "C12.22 EPSEM: %s (id %d, user \"%s\")",
                val_to_str(cmd,commandnames,"Unknown (0x%02x)"), user_id, user_name);
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 LOGON command truncated");
      }
      break;
    case C1222_CMD_SECURITY:
      if (*length >= 20) {
        proto_tree_add_item_ret_string(tree, hf_c1222_security_password, tvb, *offset, 20, ENC_ASCII|ENC_NA, pinfo->pool, &password);
        *offset += 20;
        *length -= 20;
        if (*length >= 2) {
          user_id = tvb_get_ntohs(tvb, *offset);
          proto_tree_add_uint(tree, hf_c1222_logon_id, tvb, *offset, 2, user_id);
          *offset += 2;
          *length -= 2;
          proto_item_set_text(tree, "C12.22 EPSEM: %s (password \"%s\", id %d)",
                  val_to_str(cmd,commandnames,"Unknown (0x%02x)"), password, user_id);
        } else {
          proto_item_set_text(tree, "C12.22 EPSEM: %s (password \"%s\")",
                  val_to_str(cmd,commandnames,"Unknown (0x%02x)"), password);
        }
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 SECURITY command truncated");
      }
      break;
    case C1222_CMD_AUTHENTICATE:
      if (*length >= 1) {
        auth_len = tvb_get_uint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_auth_len, tvb, *offset, 1, auth_len);
        *offset += 1;
        if (*length >= auth_len) {
          auth_req = tvb_bytes_to_str(pinfo->pool, tvb, *offset, auth_len);
          proto_tree_add_item(tree, hf_c1222_auth_data, tvb, *offset, auth_len, ENC_NA);
          *offset += auth_len;
          *length -= auth_len + 1;
          proto_item_set_text(tree, "C12.22 EPSEM: %s (%d bytes: %s)",
              val_to_str(cmd,commandnames,"Unknown (0x%02x)"), auth_len, auth_req);
        } else {
          expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 AUTHENTICATE command truncated");
        }
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 AUTHENTICATE command truncated");
      }
      break;
    case C1222_CMD_FULL_READ:
      if (*length >= 2) {
        table = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_read_table, tvb, *offset, 2, table);
        proto_item_set_text(tree, "C12.22 EPSEM: %s (%s-%d)",
                val_to_str(cmd,commandnames,"Unknown (0x%02x)"),
                val_to_str((table >> 8) & 0xF8, tableflags,"Unknown (0x%04x)"), table & 0x7FF);
        *offset += 2;
        *length -= 2;
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 READ command truncated");
      }
      break;
    case C1222_CMD_PARTIAL_READ_OFFSET:
      if (*length >= 7) {
        table = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_read_table, tvb, *offset, 2, table);
        *offset += 2;
        *length -= 2;
        proto_tree_add_item(tree, hf_c1222_read_offset, tvb, *offset, 3, ENC_BIG_ENDIAN);
        *offset += 3;
        *length -= 3;
        proto_tree_add_item(tree, hf_c1222_read_count, tvb, *offset, 2, ENC_BIG_ENDIAN);
        *offset += 2;
        *length -= 2;
        proto_item_set_text(tree, "C12.22 EPSEM: %s (%s-%d)",
                val_to_str(cmd,commandnames,"Unknown (0x%02x)"),
                val_to_str((table >> 8) & 0xF8, tableflags,"Unknown (0x%04x)"), table & 0x7FF);
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 READ command truncated");
      }
      break;
    case C1222_CMD_FULL_WRITE:
      if (*length >= 5) {
        table = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_write_table, tvb, *offset, 2, table);
        *offset += 2;
        *length -= 2;
        tblsize = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_write_size, tvb, *offset, 2, tblsize);
        *offset += 2;
        *length -= 2;
        if (*length >= tblsize+1U) {
          if (table == 7) {/* is it a procedure call? */
            procedure_num = tvb_get_uint16(tvb, *offset, c1222_big_endian ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN);
            proto_tree_add_uint(tree, hf_c1222_procedure_response, tvb, *offset, 2, procedure_num);
            proto_tree_add_uint(tree, hf_c1222_procedure_mfg, tvb, *offset, 2, procedure_num);
            proto_tree_add_uint(tree, hf_c1222_procedure_num, tvb, *offset, 2, procedure_num);
            *offset += 2;
            *length -= 2;
            proc_seq = tvb_get_uint8(tvb, *offset);
            proto_tree_add_uint(tree, hf_c1222_procedure_sequence, tvb, *offset, 1, proc_seq);
            *offset += 1;
            *length -= 1;
            tblsize -= 3;
          }
          proto_tree_add_item(tree, hf_c1222_write_data, tvb, *offset, tblsize, ENC_NA);
          *offset += tblsize;
          *length -= tblsize;
          if (table == 7) {/* is it a procedure call? */
            calcsum = c1222_cksum(tvb, (*offset)-tblsize-3, tblsize+3);
          } else {
            calcsum = c1222_cksum(tvb, (*offset)-tblsize, tblsize);
          }
          proto_tree_add_checksum(tree, tvb, *offset, hf_c1222_write_chksum, hf_c1222_write_chksum_status,
                                  &ei_c1222_bad_checksum, pinfo, calcsum, ENC_NA, PROTO_CHECKSUM_VERIFY);

          if (table == 7) {/* is it a procedure call? */
            proto_item_set_text(tree, "C12.22 EPSEM: %s (%s-%d, %s-%d)",
                    val_to_str(cmd,commandnames,"Unknown (0x%02x)"),
                    val_to_str((table >> 8) & 0xF8, tableflags,"Unknown (0x%04x)"), table & 0x7FF,
                    val_to_str((procedure_num >> 8) & 0x08, procflags,"Unknown (0x%04x)"), procedure_num & 0x7FF);
          } else {
            proto_item_set_text(tree, "C12.22 EPSEM: %s (%s-%d)",
                    val_to_str(cmd,commandnames,"Unknown (0x%02x)"),
                    val_to_str((table >> 8) & 0xF8, tableflags,"Unknown (0x%04x)"), table & 0x7FF);
          }
          *offset += 1;
          *length -= 1;
        } else {
          expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 WRITE command truncated");
        }
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 WRITE command truncated");
      }
      break;
    case C1222_CMD_PARTIAL_WRITE_OFFSET:
      if (*length >= 8) {
        table = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_write_table, tvb, *offset, 2, table);
        *offset += 2;
        *length -= 2;
        proto_tree_add_item(tree, hf_c1222_write_offset, tvb, *offset, 3, ENC_BIG_ENDIAN);
        *offset += 3;
        *length -= 3;
        tblsize = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_write_size, tvb, *offset, 2, tblsize);
        *offset += 2;
        *length -= 2;
        if (*length >= tblsize+1U) {
          proto_tree_add_item(tree, hf_c1222_write_data, tvb, *offset, tblsize, ENC_NA);
          *offset += tblsize;
          *length -= tblsize;
          calcsum = c1222_cksum(tvb, (*offset)-tblsize, tblsize);
          proto_tree_add_checksum(tree, tvb, *offset, hf_c1222_write_chksum, hf_c1222_write_chksum_status,
                                  &ei_c1222_bad_checksum, pinfo, calcsum, ENC_NA, PROTO_CHECKSUM_VERIFY);
          proto_item_set_text(tree, "C12.22 EPSEM: %s (%s-%d)",
                  val_to_str(cmd,commandnames,"Unknown (0x%02x)"),
                  val_to_str((table >> 8) & 0xF8, tableflags,"Unknown (0x%04x)"), table & 0x7FF);
          *offset += 1;
          *length -= 1;
        } else {
          expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 WRITE command truncated");
        }
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 WRITE command truncated");
      }
      break;
    case C1222_CMD_WAIT:
      if (*length >= 1) {
        wait_seconds = tvb_get_uint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_wait_secs, tvb, *offset, 1, wait_seconds);
        *offset += 1;
        *length -= 1;
        proto_item_set_text(tree, "C12.22 EPSEM: %s (%d seconds)",
            val_to_str(cmd,commandnames,"Unknown (0x%02x)"), wait_seconds);
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 WAIT command truncated");
      }
      break;
    case C1222_CMD_NEGOTIATE:
      if (*length >= 3) {
        packet_size = tvb_get_ntohs(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_neg_pkt_size, tvb, *offset, 2, packet_size);
        *offset += 2;
        *length -= 2;
        nbr_packet = tvb_get_uint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_neg_nbr_pkts, tvb, *offset, 1, nbr_packet);
        *offset += 1;
        *length -= 1;
        proto_item_set_text(tree, "C12.22 EPSEM: %s (pkt size %d, num pkts %d, with %d baud rates)",
                val_to_str(cmd,commandnames,"Unknown (0x%02x)"), packet_size, nbr_packet, numrates);
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 NEGOTIATE command truncated");
      }
      break;
    case C1222_CMD_TIMING_SETUP:
      if (*length >= 4) {
        traffic = tvb_get_uint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_timing_setup_traffic, tvb, *offset, 1, traffic);
        *offset += 1;
        *length -= 1;
        inter_char = tvb_get_uint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_timing_setup_inter_char, tvb, *offset, 1, inter_char);
        *offset += 1;
        *length -= 1;
        resp_to = tvb_get_uint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_timing_setup_resp_to, tvb, *offset, 1, resp_to);
        *offset += 1;
        *length -= 1;
        nbr_retries = tvb_get_uint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_timing_setup_nbr_retries, tvb, *offset, 1, nbr_retries);
        *offset += 1;
        *length -= 1;
        proto_item_set_text(tree, "C12.22 EPSEM: %s (traffic to %d s, inter-char to %d s, response to %d s, %d retries)",
                val_to_str(cmd,commandnames,"Unknown (0x%02x)"), traffic, inter_char, resp_to, nbr_retries);
      } else {
        expert_add_info_format(pinfo, tree, &ei_c1222_command_truncated, "C12.22 NEGOTIATE command truncated");
      }
      break;

    default:
      /* don't do anything */
      proto_item_set_text(tree, "C12.22 EPSEM: %s", val_to_str(cmd, commandnames, "Unknown (0x%02x)"));
      if (*length) {
        proto_tree_add_item(tree, hf_c1222_data, tvb, *offset, *length, ENC_NA);
      }
      break;
  }
}

typedef struct tagTOP_ELEMENT_CONTROL
{
  /* true if this tag is required */
  bool required;
  /* true if we must truncate this tag */
  bool truncate;
  /* actual hex value of the tag we're seeking */
  uint8_t tag;
  /* if true, add tag and length before copying */
  bool addtag;
  /* pointer to pointer to memory copy of element */
  uint8_t **element;
  /* pointer to element length */
  uint32_t *length;
  /* pointer to element allocated size */
  uint32_t *allocated;
} TOP_ELEMENT_CONTROL;

static const TOP_ELEMENT_CONTROL canonifyTable[] = {
  { false, false, 0xA1, true, &aSO_context, &aSO_context_len, &aSO_context_allocated },
  { true , false, 0xA2, true, &called_AP_title, &called_AP_title_len, &called_AP_title_allocated },
  { false, false, 0xA4, true, &called_AP_invocation_id, &called_AP_invocation_id_len, &called_AP_invocation_id_allocated },
  { false, false, 0xA7, true, &calling_AE_qualifier, &calling_AE_qualifier_len, &calling_AE_qualifier_allocated },
  { true,  false, 0xA8, true, &calling_AP_invocation_id, &calling_AP_invocation_id_len, &calling_AP_invocation_id_allocated },
  { false, false, 0x8B, true, &mechanism_name, &mechanism_name_len, &mechanism_name_allocated },
  { false, false, 0xAC, true, &calling_authentication_value, &calling_authentication_value_len, &calling_authentication_value_allocated },
  { true , true , 0xBE, true, &user_information, &user_information_len, &user_information_allocated },
  { false, false, 0xA6, true, &calling_AP_title, &calling_AP_title_len, &calling_AP_title_allocated },
  { false, false, 0xAC, false, &key_id_element, &key_id_element_len, &key_id_element_allocated },
  { false, false, 0xAC, false, &iv_element, &iv_element_len, &iv_element_allocated },
  { false, false, 0x0,  true, NULL, NULL, NULL }
};

static void
clear_canon(void)
{
  const TOP_ELEMENT_CONTROL *t = canonifyTable;

  for (t = canonifyTable; t->element != NULL; t++) {
    *(t->length) = 0;
    *(t->element) = NULL;
  }
}

/**
 * Calculates the size of the passed number n as encoded as a BER length field.
 *
 * \param n is the length value to be BER encoded
 * \returns the sized of the encoding
 */
static uint32_t
get_ber_len_size(uint32_t n)
{
  uint32_t len = 1;
  if (n > 0x7f) len++;
  if (n > 0xff) len++;
  if (n > 0xffff) len++;
  if (n > 0xffffff) len++;
  return len;
}
/**
 * Encodes the passed value n as a BER-encoded length at puts it in memory.
 *
 * \param ptr points to the buffer to be written
 * \param n is the length to be BER encoded
 * \param maxsize is the maximum number of bytes we're allowed to write
 * \returns length of encoded value in bytes
 */
static int
encode_ber_len(uint8_t *ptr, uint32_t n, int maxsize)
{
  int len = get_ber_len_size(n);
  if (len > maxsize) return 0;
  if (len == 1) {
    *ptr = 0x7f & n;
  } else {
    *ptr = (len -1) | 0x80;
    for (ptr += len-1; n; n >>= 8)
      *ptr-- = n & 0xff;
  }
  return len;

}

static void*
c1222_uat_data_copy_cb(void *dest, const void *source, size_t len _U_)
{
    const c1222_uat_data_t* o = (const c1222_uat_data_t*)source;
    c1222_uat_data_t* d = (c1222_uat_data_t*)dest;

    d->keynum = o->keynum;
    d->keylen = o->keylen;
    d->key = (unsigned char *)g_memdup2(o->key, o->keylen);

    return dest;
}

/**
 * Checks a new encryption table item for validity.
 *
 * \param n points to the new record
 * \param err is updated to point to an error string if needed
 * \return false if error; true otherwise
 */
static bool
c1222_uat_data_update_cb(void* n, char** err)
{
  c1222_uat_data_t* new_rec = (c1222_uat_data_t *)n;

  if (new_rec->keynum > 0xff) {
    *err = g_strdup("Invalid key number; must be less than 256");
    return false;
  }
  if (new_rec->keylen != EAX_SIZEOF_KEY) {
    *err = g_strdup("Invalid key size; must be 16 bytes");
    return false;
  }
  return true;
}

static void
c1222_uat_data_free_cb(void *r)
{
    c1222_uat_data_t *rec = (c1222_uat_data_t *)r;
    g_free(rec->key);
}

/**
 * Canonifies header fields in preparation for authenticating and/or decrypting the packet.
 *
 * \param buff points to the allocated canonization buffer
 * \param offset points to start of unallocated space in buffer and
      is updated as we put bytes into buffer
 * \param buffsize total size of allocated buffer
 * \return false if element is required and not present; otherwise true
 */
static bool
canonify_unencrypted_header(unsigned char *buff, uint32_t *offset, uint32_t buffsize)
{
  const TOP_ELEMENT_CONTROL *t = canonifyTable;
  uint32_t len, allocated;

  for (t = canonifyTable; t->element != NULL; t++)
  {
    len = *(t->length);
    allocated = *(t->allocated);
    if (t->required && *(t->element) == NULL)
      return false;
    if (*(t->element) != NULL) {
      if (t->addtag) {
        /* recreate original tag and length */
        buff[(*offset)++] = t->tag;
        (*offset) += encode_ber_len(&buff[*offset], len, 4);
      }
      if (t->truncate) {
        len = 3+2*get_ber_len_size(len);
      }
      /* bail out if the cannonization buffer is too small */
      /* this should never happen! */
      if (buffsize < *offset + len) {
        return false;
      }
      /* bail out if our we're trying to read past the end of our element */
      /* the network is always hostile */
      if (allocated < len) {
        return false;
      }
      memcpy(&buff[*offset], *(t->element), len);
      (*offset) += len;
      if (t->addtag) {
          *(t->element) = NULL;
      }
    }
  }
  return true;
}

/**
 * Looks up the required key in the key table.
 *
 * \param keybuff is updated with a copy of the key data if successful lookup.
 * \param keyid is the ID number of the desired key
 * \returns true if key was found; otherwise false
 */
static bool
keylookup(uint8_t *keybuff, uint8_t keyid)
{
  unsigned i;

  if (c1222_uat_data == NULL)
    return false;
  for (i = 0; i < num_c1222_uat_data; i++) {
    if (c1222_uat_data[i].keynum == keyid) {
      memcpy(keybuff, c1222_uat_data[i].key, EAX_SIZEOF_KEY);
      return true;
    }
  }
  return false;
}

/**
 * Authenticates and decrypts the passed packet.
 *
 * \param buffer points to a memory copy of the packet to be authenticated/decrypted
 *        and contains the decrypted value on successful return.
 * \param length lenth of input packet
 * \param decrypt true if packet is to be authenticated and decrypted; false if authentication only is requested
 * \returns true if the requested operation was successful; otherwise false
 */
static bool
decrypt_packet(unsigned char *buffer, uint32_t length, bool decrypt)
{
#define CANONBUFFSIZE 300U
  unsigned char canonbuff[CANONBUFFSIZE];
  uint8_t c1222_key[EAX_SIZEOF_KEY];
  unsigned char key_id = 0;
  uint32_t offset = 0;
  bool status = false;

  /* must be at least 4 bytes long to include the MAC */
  if (length < 4)
    return status;
  if (key_id_element != NULL)
    key_id = key_id_element[0];
  /* extract unencrypted header information */
  if (!canonify_unencrypted_header(canonbuff, &offset, CANONBUFFSIZE))
    return status;
  /* decrypt and authenticate in place */
/* PARAMETERS:     pN     : Pointer to ClearText (Input, Canonified form).    */
/*                 pK     : Pointer to secret key (Input).                    */
/*                 pC     : Pointer to CipherText (Input/Output).             */
/*                 SizeN  : Byte length of ClearText buffer.                  */
/*                 SizeK  : Byte length of secret key.                        */
/*                 SizeC  : Byte length of CipherText buffer.                 */
/*                 pMac   : Four byte Message Authentication Code.            */
/*                 Mode   : Operating mode (See EAX_MODE_xxx).                */
/* RETURNS:        true if message has been authenticated.                    */
/*                 false if not authenticated, invalid Mode, or error.        */
  if (offset) {
    if (!keylookup((uint8_t *)&c1222_key, key_id))
      return false;
    status = Eax_Decrypt(canonbuff, c1222_key, buffer,
                  offset, EAX_SIZEOF_KEY, length-4,
                  (MAC_T *)&buffer[length-4],
                  decrypt ? EAX_MODE_CIPHERTEXT_AUTH : EAX_MODE_CLEARTEXT_AUTH);
  }
  return status;
}

/**
 * Checks to make sure that a complete, valid BER-encoded length is in the buffer.
 *
 * \param tvb contains the buffer to be examined
 * \param offset is the offset within the buffer at which the BER-encoded length begins
 * \returns true if a complete, valid BER-encoded length is in the buffer; otherwise false
 */
static bool
ber_len_ok(tvbuff_t *tvb, int offset)
{
  uint8_t ch;

  if (tvb_offset_exists(tvb, offset)) {
    ch = tvb_get_uint8(tvb, offset);
    offset++;
    if (!(ch & 0x80)) {
      return true;
    } else if (tvb_offset_exists(tvb, offset)) {
      ch = tvb_get_uint8(tvb, offset);
      offset++;
      if (!(ch & 0x80)) {
        return true;
      } else if (tvb_offset_exists(tvb, offset)) {
        ch = tvb_get_uint8(tvb, offset);
        offset++;
        if (!(ch & 0x80)) {
          return true;
        } else if (tvb_offset_exists(tvb, offset)) {
          ch = tvb_get_uint8(tvb, offset);
          /*offset++;*/
          if (!(ch & 0x80)) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

/**
 * Dissects the EPSEM portion of the User-information part of a C12.22 message.
 *
 * \param tvb the tv buffer of the current data
 * \param offset the offset in the tvb
 * \param len length of data
 * \param pinfo the packet info of the current data
 * \param tree the tree to append this item to
 */
static int
dissect_epsem(tvbuff_t *tvb, int offset, uint32_t len, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cmd_tree = NULL;
  proto_tree *ct = NULL;
  proto_tree *crypto_tree = NULL;
  proto_tree *yt = NULL;
  proto_item *item = NULL;
  uint8_t flags;
  int local_offset;
  int len2;
  int cmd_err;
  bool ind;
  unsigned char *buffer;
  tvbuff_t *epsem_buffer = NULL;
  bool crypto_good = false;
  bool crypto_bad = false;
  bool hasmac = false;
  bool encrypted = false;

  if ((tvb == NULL) && (len == 0)) {
    expert_add_info(pinfo, tree, &ei_c1222_epsem_missing);
    return offset;
  }
  /* parse the flags byte which is always unencrypted */
  flags = tvb_get_uint8(tvb, offset);
  proto_tree_add_bitmask(tree, tvb, offset, hf_c1222_epsem_flags, ett_c1222_flags, c1222_flags, ENC_BIG_ENDIAN);
  offset++;
  switch ((flags & C1222_EPSEM_FLAG_SECURITY_MODE) >> 2) {
    case EAX_MODE_CIPHERTEXT_AUTH:
      /* mode is ciphertext with authentication */
      hasmac = true;
      len2 = tvb_reported_length_remaining(tvb, offset);
      if (len2 <= 0)
        return offset;
      encrypted = true;
      if (c1222_decrypt) {
        buffer = (unsigned char *)tvb_memdup(pinfo->pool, tvb, offset, len2);
        if (!decrypt_packet(buffer, len2, true)) {
          crypto_bad = true;
        } else {
          epsem_buffer = tvb_new_real_data(buffer, len2, len2);
          tvb_set_child_real_data_tvbuff(tvb, epsem_buffer);
          add_new_data_source(pinfo, epsem_buffer, "Decrypted EPSEM Data");
          crypto_good = true;
          encrypted = false;
        }
      }
      break;
    case EAX_MODE_CLEARTEXT_AUTH:
      /* mode is cleartext with authentication */
      hasmac = true;
      len2 = tvb_reported_length_remaining(tvb, offset);
      if (len2 <= 0)
        return offset;
      epsem_buffer = tvb_new_subset_remaining(tvb, offset);
      buffer = (unsigned char *)tvb_memdup(pinfo->pool, tvb, offset, len2);
      if (c1222_decrypt) {
        if (!decrypt_packet(buffer, len2, false)) {
          crypto_bad = true;
          expert_add_info(pinfo, tree, &ei_c1222_epsem_failed_authentication);
        } else {
          crypto_good = true;
        }
      }
      break;
    default:
      /* it's not encrypted */
      epsem_buffer = tvb_new_subset_remaining(tvb, offset);
  }
  /* it's only encrypted if we have an undecrypted payload */
  if (encrypted) {
    proto_tree_add_item(tree, hf_c1222_epsem_total, tvb, offset, -1, ENC_NA);
    expert_add_info(pinfo, tree, &ei_c1222_epsem_not_decrypted);
    local_offset = offset+len2-4;
    epsem_buffer = tvb;
  } else {  /* it's not (now) encrypted */
    local_offset = 0;
    /* retrieve the ed_class if it's there */
    if (flags & C1222_EPSEM_FLAG_ED_CLASS_INCLUDED) {
      if (tvb_offset_exists(epsem_buffer, local_offset+4-1)) {
        proto_tree_add_item(tree, hf_c1222_epsem_ed_class, epsem_buffer, local_offset, 4, ENC_NA);
        local_offset += 4;
      } else {
        expert_add_info(pinfo, tree, &ei_c1222_ed_class_missing);
      }
    }
    /* what follows are one or more <epsem-data> elements possibly followed by
     * a <mac>.  Each <epsem-data> element is defined as <service-length><res-req>,
     * so we fetch such pairs until there isn't anything left (except possibly
     * the <mac>).
     */
    while (tvb_offset_exists(epsem_buffer, local_offset+(hasmac?5:1))) {
      if (ber_len_ok(epsem_buffer, local_offset)) {
        local_offset = dissect_ber_length(pinfo, tree, epsem_buffer, local_offset, (uint32_t *)&len2, &ind);
      } else {
        expert_add_info(pinfo, tree, &ei_c1222_epsem_ber_length_error);
        return offset+len;
      }
      if (tvb_offset_exists(epsem_buffer, local_offset+len2-1)) {
        cmd_err = tvb_get_uint8(epsem_buffer, local_offset);
        ct = proto_tree_add_item(tree, hf_c1222_epsem_total, epsem_buffer, local_offset, len2, ENC_NA);
        cmd_tree = proto_item_add_subtree(ct, ett_c1222_cmd);
        parse_c1222_detailed(epsem_buffer, pinfo, cmd_tree, cmd_err, (uint32_t *)&len2, &local_offset);
        local_offset += len2;
      } else {
        expert_add_info(pinfo, tree, &ei_c1222_epsem_field_length_error);
        return offset+len;
      }
    }
  }
  if (hasmac) {
    if (tvb_offset_exists(epsem_buffer, local_offset+4-1)) {
      yt = proto_tree_add_item(tree, hf_c1222_epsem_mac, epsem_buffer, local_offset, 4, ENC_NA);
      /* now we have enough information to fill in the crypto subtree */
      crypto_tree = proto_item_add_subtree(yt, ett_c1222_crypto);
      item = proto_tree_add_boolean(crypto_tree, hf_c1222_epsem_crypto_good, tvb, local_offset, 4, crypto_good);
      proto_item_set_generated(item);
      item = proto_tree_add_boolean(crypto_tree, hf_c1222_epsem_crypto_bad, tvb, local_offset, 4, crypto_bad);
      proto_item_set_generated(item);
    } else {
      expert_add_info(pinfo, tree, &ei_c1222_mac_missing);
      return offset+len;
    }
  }
  return offset;
}

#include "packet-c1222-fn.c"

/**
 * Dissects a a full (reassembled) C12.22 message.
 *
 * \param tvb the tv buffer of the current data
 * \param pinfo the packet info of the current data
 * \param tree the tree to append this item to
 */
static int
dissect_c1222_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item      *c1222_item = NULL;
    proto_tree      *c1222_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* create the c1222 protocol tree */
    c1222_item = proto_tree_add_item(tree, proto_c1222, tvb, 0, -1, ENC_NA);
    c1222_tree = proto_item_add_subtree(c1222_item, ett_c1222);
    return dissect_MESSAGE_PDU(tvb, pinfo, c1222_tree, NULL);
}

/**
 * Fetches the length of an entire C12.22 message to assist in reassembly.
 *
 * \param pinfo the packet info of the current data
 * \param tvb the tv buffer of the current data
 * \param offset the offset in the tvb
 * \returns length of entire C12.22 message
 */
static unsigned
get_c1222_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
  int orig_offset;
  unsigned length;
  bool ind;

  orig_offset = offset;
  /* note that this assumes a Tag length of 1 which is always valid for C12.22 */
  offset = dissect_ber_length(pinfo, NULL, tvb, offset+1, &length, &ind);
  return length+(offset - orig_offset);
}

/**
 * Reassembles and dissects C12.22 messages.
 *
 * \param tvb the tv buffer of the current data
 * \param pinfo the packet info of the current data
 * \param tree the tree to append this item to
 */
static int
dissect_c1222(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, c1222_desegment, 5,
          get_c1222_message_len, dissect_c1222_common, data);
  return tvb_captured_length(tvb);
}

/*--- proto_register_c1222 -------------------------------------------*/
void proto_register_c1222(void) {

  /* List of fields */
  static hf_register_info hf[] = {
   { &hf_c1222_epsem_flags,
    { "C12.22 EPSEM Flags", "c1222.epsem.flags",
    FT_UINT8, BASE_HEX,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_flags_reserved,
    { "C12.22 Reserved Flag", "c1222.epsem.flags.reserved",
    FT_BOOLEAN, 8,
    NULL, C1222_EPSEM_FLAG_RESERVED,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_flags_recovery,
    { "C12.22 Recovery Flag", "c1222.epsem.flags.recovery",
    FT_BOOLEAN, 8,
    NULL, C1222_EPSEM_FLAG_RECOVERY_SESSION,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_flags_proxy,
    { "C12.22 Proxy Service Used Flag", "c1222.epsem.flags.proxy",
    FT_BOOLEAN, 8,
    NULL, C1222_EPSEM_FLAG_PROXY_SERVICE_USED,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_flags_ed_class,
    { "C12.22 ED Class Flag", "c1222.epsem.flags.ed_class",
    FT_BOOLEAN, 8,
    NULL, C1222_EPSEM_FLAG_ED_CLASS_INCLUDED,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_flags_security_modes,
    { "C12.22 Security Mode Flags", "c1222.epsem.flags.security",
    FT_UINT8, BASE_HEX,
    VALS(c1222_security_modes), C1222_EPSEM_FLAG_SECURITY_MODE,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_flags_response_control,
    { "C12.22 Response Control Flags", "c1222.epsem.flags.response_control",
    FT_UINT8, BASE_HEX,
    VALS(c1222_response_control), C1222_EPSEM_FLAG_RESPONSE_CONTROL,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_ed_class,
    { "C12.22 EPSEM ED Class", "c1222.epsem.edclass",
    FT_BYTES, BASE_NONE,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_total,
    { "C12.22 EPSEM", "c1222.epsem.data",
    FT_BYTES, BASE_NONE,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_mac,
    { "C12.22 EPSEM MAC", "c1222.epsem.mac",
    FT_BYTES, BASE_NONE,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_cmd,
    { "C12.22 Command", "c1222.cmd",
    FT_UINT8, BASE_HEX,
    VALS(commandnames), 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_err,
    { "C12.22 Response", "c1222.err",
    FT_UINT8, BASE_HEX,
    VALS(commandnames), 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_logon_id,
    { "C12.22 Logon User-Id", "c1222.logon.id",
    FT_UINT16, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_logon_user,
    { "C12.22 Logon User", "c1222.logon.user",
    FT_STRING, BASE_NONE,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_security_password,
    { "C12.22 Security Password", "c1222.security.password",
    FT_STRING, BASE_NONE,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_auth_len,
    { "C12.22 Authenticate Request Length", "c1222.authenticate.len",
    FT_UINT8, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_auth_data,
    { "C12.22 Authenticate Data", "c1222.authenticate.data",
    FT_BYTES, BASE_NONE,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_read_table,
    { "C12.22 Table", "c1222.read.table",
    FT_UINT16, BASE_HEX,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_read_offset,
    { "C12.22 Offset", "c1222.read.offset",
    FT_UINT24, BASE_HEX,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_read_count,
    { "C12.22 Count", "c1222.read.count",
    FT_UINT16, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_write_table,
    { "C12.22 Table", "c1222.write.table",
    FT_UINT16, BASE_HEX,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_write_offset,
    { "C12.22 Offset", "c1222.write.offset",
    FT_UINT24, BASE_HEX,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_write_size,
    { "C12.22 Table Size", "c1222.write.size",
    FT_UINT16, BASE_HEX,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_write_data,
    { "C12.22 Table Data", "c1222.write.data",
    FT_BYTES, BASE_NONE,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_write_chksum,
    { "C12.22 Table Data Checksum", "c1222.write.chksum",
    FT_UINT8, BASE_HEX,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_write_chksum_status,
    { "C12.22 Table Data Checksum Status", "c1222.write.chksum.status",
    FT_UINT8, BASE_NONE,
    VALS(proto_checksum_vals), 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_procedure_response,
    { "C12.22 Procedure Response", "c1222.procedure.response",
    FT_UINT16, BASE_DEC,
    VALS(c1222_proc_response_control), C1222_PROCEDURE_RESPONSE,
    NULL, HFILL }
   },
   { &hf_c1222_procedure_mfg,
    { "C12.22 Procedure Mfg", "c1222.procedure.mfg",
    FT_UINT16, BASE_DEC,
    NULL, C1222_PROCEDURE_MFG,
    NULL, HFILL }
   },
   { &hf_c1222_procedure_num,
    { "C12.22 Procedure Number", "c1222.procedure.num",
    FT_UINT16, BASE_DEC,
    NULL, C1222_PROCEDURE_NUMBER,
    NULL, HFILL }
   },
   { &hf_c1222_procedure_sequence,
    { "C12.22 Procedure Sequence Number", "c1222.procedure.sequence",
    FT_UINT8, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_neg_pkt_size,
    { "C12.22 Negotiate Packet Size", "c1222.negotiate.pktsize",
    FT_UINT16, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_neg_nbr_pkts,
    { "C12.22 Negotiate Number of Packets", "c1222.negotiate.numpkts",
    FT_UINT8, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_wait_secs,
    { "C12.22 Wait Seconds", "c1222.wait.seconds",
    FT_UINT8, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_timing_setup_traffic,
    { "C12.22 Timing Setup Channel Traffic Timeout", "c1222.timingsetup.traffic",
    FT_UINT8, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_timing_setup_inter_char,
    { "C12.22 Timing Setup Intercharacter Timeout", "c1222.timingsetup.interchar",
    FT_UINT8, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_timing_setup_resp_to,
    { "C12.22 Timing Setup Response Timeout", "c1222.timingsetup.respto",
    FT_UINT8, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_timing_setup_nbr_retries,
    { "C12.22 Timing Setup Number of Retries", "c1222.timingsetup.nbrretries",
    FT_UINT8, BASE_DEC,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_data,
    { "C12.22 data", "c1222.data",
    FT_BYTES, BASE_NONE,
    NULL, 0x0,
    NULL, HFILL }
   },
   { &hf_c1222_epsem_crypto_good,
    { "Crypto good", "c1222.crypto_good",
    FT_BOOLEAN, BASE_NONE,
    NULL, 0x0,
    "True: crypto ok; False: doesn't match or not checked", HFILL }
   },
   { &hf_c1222_epsem_crypto_bad,
    { "Crypto bad", "c1222.crypto_bad",
    FT_BOOLEAN, BASE_NONE,
    NULL, 0x0,
    "True: crypto bad; False: crypto ok or not checked", HFILL }
   },
#include "packet-c1222-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
                  &ett_c1222,
                  &ett_c1222_epsem,
                  &ett_c1222_flags,
                  &ett_c1222_crypto,
                  &ett_c1222_cmd,
#include "packet-c1222-ettarr.c"
  };

  static ei_register_info ei[] = {
    { &ei_c1222_command_truncated, { "c1222.command_truncated", PI_MALFORMED, PI_ERROR, "C12.22 command truncated", EXPFILL }},
    { &ei_c1222_bad_checksum, { "c1222.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    { &ei_c1222_epsem_missing, { "c1222.epsem.missing", PI_MALFORMED, PI_ERROR, "C12.22 EPSEM missing", EXPFILL }},
    { &ei_c1222_epsem_failed_authentication, { "c1222.epsem.failed_authentication", PI_SECURITY, PI_ERROR, "C12.22 EPSEM failed authentication", EXPFILL }},
    { &ei_c1222_epsem_not_decrypted, { "c1222.epsem.not_decrypted", PI_UNDECODED, PI_WARN, "C12.22 EPSEM could not be decrypted", EXPFILL }},
    { &ei_c1222_ed_class_missing, { "c1222.ed_class_missing", PI_SECURITY, PI_ERROR, "C12.22 ED Class missing", EXPFILL }},
    { &ei_c1222_epsem_ber_length_error, { "c1222.epsem.ber_length_error", PI_MALFORMED, PI_ERROR, "C12.22 EPSEM BER length error", EXPFILL }},
    { &ei_c1222_epsem_field_length_error, { "c1222.epsem.field_length_error", PI_MALFORMED, PI_ERROR, "C12.22 EPSEM field length error", EXPFILL }},
    { &ei_c1222_mac_missing, { "c1222.mac_missing", PI_MALFORMED, PI_ERROR, "C12.22 MAC missing", EXPFILL }},
  };

  expert_module_t* expert_c1222;
  module_t *c1222_module;

  static uat_field_t c1222_uat_flds[] = {
    UAT_FLD_HEX(c1222_users,keynum,"Key ID","Key identifier in hexadecimal"),
    UAT_FLD_BUFFER(c1222_users, key, "Key", "Encryption key as 16-byte hex string"),
    UAT_END_FIELDS
  };

  /* Register protocol */
  proto_c1222 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_c1222, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_c1222 = expert_register_protocol(proto_c1222);
  expert_register_field_array(expert_c1222, ei, array_length(ei));
  /* Register dissectors */
  c1222_handle = register_dissector("c1222.tcp", dissect_c1222, proto_c1222);
  c1222_udp_handle = register_dissector("c1222.udp", dissect_c1222_common, proto_c1222);
  /* Register dissection preferences */
  c1222_module = prefs_register_protocol(proto_c1222, proto_reg_handoff_c1222);
  prefs_register_bool_preference(c1222_module, "desegment",
        "Reassemble all C12.22 messages spanning multiple TCP segments",
        "Whether the C12.22 dissector should reassemble all messages spanning multiple TCP segments",
        &c1222_desegment);
  prefs_register_string_preference(c1222_module, "baseoid", "Base OID to use for relative OIDs",
        "Base object identifier for use in resolving relative object identifiers",
        &c1222_baseoid_str);
  prefs_register_bool_preference(c1222_module, "decrypt",
        "Verify crypto for all applicable C12.22 messages",
        "Whether the C12.22 dissector should verify the crypto for all relevant messages",
        &c1222_decrypt);
  prefs_register_bool_preference(c1222_module, "big_endian",
        "Interpret multibyte numbers as big endian",
        "Whether the C12.22 dissector should interpret procedure numbers as big-endian",
        &c1222_big_endian);

  c1222_uat = uat_new("Decryption Table",
      sizeof(c1222_uat_data_t),         /* record size */
      "c1222_decryption_table",         /* filename */
      true,                             /* from_profile */
      &c1222_uat_data,                  /* data_ptr */
      &num_c1222_uat_data,              /* numitems_ptr */
      UAT_AFFECTS_DISSECTION,           /* affects dissection of packets, but not set of named fields */
      NULL,                             /* help */
      c1222_uat_data_copy_cb,           /* copy callback */
      c1222_uat_data_update_cb,         /* update callback */
      c1222_uat_data_free_cb,           /* free callback */
      NULL,                             /* post update callback */
      NULL,                             /* reset callback */
      c1222_uat_flds);                  /* UAT field definitions */

  prefs_register_uat_preference(c1222_module,
      "decryption_table",
      "Decryption Table",
      "Table of security parameters for decryption of C12.22 packets",
      c1222_uat);
}

/*--- proto_reg_handoff_c1222 ---------------------------------------*/
void
proto_reg_handoff_c1222(void)
{
  static bool initialized = false;
  uint8_t *temp = NULL;

  if( !initialized ) {
    dissector_add_uint_with_preference("tcp.port", C1222_PORT, c1222_handle);
    dissector_add_uint_with_preference("udp.port", C1222_PORT, c1222_udp_handle);
    initialized = true;
  }
  if (c1222_baseoid_str && (c1222_baseoid_str[0] != '\0') &&
      ((c1222_baseoid_len = oid_string2encoded(NULL, c1222_baseoid_str, &temp)) != 0)) {
    c1222_baseoid = (uint8_t *)wmem_realloc(wmem_epan_scope(), c1222_baseoid, c1222_baseoid_len);
    memcpy(c1222_baseoid, temp, c1222_baseoid_len);
    wmem_free(NULL, temp);
  } else if (c1222_baseoid) {
      wmem_free(wmem_epan_scope(), c1222_baseoid);
      c1222_baseoid = NULL;
      c1222_baseoid_len = 0;
  }
}
/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
