/* packet-c1222.c
 * Routines for ANSI C12.22 packet dissection
 * Copyright 2010, Edward J. Beroset, edward.beroset@elster.com
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <wsutil/eax.h>

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/uat.h>
#include <epan/oids.h>

#include <stdio.h>
#include <string.h>

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

static dissector_handle_t c1222_handle=NULL;
static dissector_handle_t c1222_udp_handle=NULL;

/* Initialize the protocol and registered fields */
static int proto_c1222 = -1;
static int global_c1222_port = C1222_PORT;
static gboolean c1222_desegment = TRUE;
static gboolean c1222_decrypt = TRUE;
static const gchar *c1222_baseoid_str = NULL;
static guint8 *c1222_baseoid = NULL;
static guint c1222_baseoid_len = 0;

#include "packet-c1222-hf.c"
/* These are the EPSEM pieces */
/* first, the flag components */
static int hf_c1222_epsem_flags = -1;
static int hf_c1222_epsem_flags_reserved = -1;
static int hf_c1222_epsem_flags_recovery = -1;
static int hf_c1222_epsem_flags_proxy = -1;
static int hf_c1222_epsem_flags_ed_class = -1;
static int hf_c1222_epsem_flags_security_modes = -1;
static int hf_c1222_epsem_flags_response_control = -1;
/* and the structure of the flag components */
static const int *c1222_flags[] = {
  &hf_c1222_epsem_flags_reserved,
  &hf_c1222_epsem_flags_recovery,
  &hf_c1222_epsem_flags_proxy,
  &hf_c1222_epsem_flags_ed_class,
  &hf_c1222_epsem_flags_security_modes,
  &hf_c1222_epsem_flags_response_control,
  NULL
};
/* next the optional ed_class */
static int hf_c1222_epsem_ed_class = -1;
/* now the aggregate epsem */
static int hf_c1222_epsem_total = -1;
/* generic command */
static int hf_c1222_cmd = -1;
static int hf_c1222_err = -1;
static int hf_c1222_data = -1;
/* individual epsem fields */
static int hf_c1222_logon_id = -1;
static int hf_c1222_logon_user = -1;
static int hf_c1222_security_password = -1;
static int hf_c1222_auth_len = -1;
static int hf_c1222_auth_data = -1;
static int hf_c1222_read_table = -1;
static int hf_c1222_read_offset = -1;
static int hf_c1222_read_count = -1;
static int hf_c1222_write_table = -1;
static int hf_c1222_write_offset = -1;
static int hf_c1222_write_size = -1;
static int hf_c1222_write_data = -1;
static int hf_c1222_procedure_num = -1;
static int hf_c1222_write_chksum = -1;
static int hf_c1222_wait_secs = -1;
static int hf_c1222_neg_pkt_size = -1;
static int hf_c1222_neg_nbr_pkts = -1;
static int hf_c1222_timing_setup_traffic = -1;
static int hf_c1222_timing_setup_inter_char = -1;
static int hf_c1222_timing_setup_resp_to = -1;
static int hf_c1222_timing_setup_nbr_retries = -1;

/* the MAC */
static int hf_c1222_epsem_mac = -1;

/* crypto result flags */
static int hf_c1222_epsem_crypto_good = -1;
static int hf_c1222_epsem_crypto_bad = -1;

/* Initialize the subtree pointers */
static int ett_c1222 = -1;
static int ett_c1222_epsem = -1;
static int ett_c1222_flags = -1;
static int ett_c1222_crypto = -1;
static int ett_c1222_cmd = -1;

#ifdef HAVE_LIBGCRYPT
/* these pointers are for the header elements that may be needed to verify the crypto */
static guint8 *aSO_context = NULL;
static guint8 *called_AP_title = NULL;
static guint8 *called_AP_invocation_id = NULL;
static guint8 *calling_AE_qualifier = NULL;
static guint8 *calling_AP_invocation_id = NULL;
static guint8 *mechanism_name = NULL;
static guint8 *calling_authentication_value = NULL;
static guint8 *user_information = NULL;
static guint8 *calling_AP_title = NULL;
static guint8 *key_id_element = NULL;
static guint8 *iv_element = NULL;

/* these are the related lengths */
static guint32 aSO_context_len = 0;
static guint32 called_AP_title_len = 0;
static guint32 called_AP_invocation_id_len = 0;
static guint32 calling_AE_qualifier_len = 0;
static guint32 calling_AP_invocation_id_len = 0;
static guint32 mechanism_name_len = 0;
static guint32 calling_authentication_value_len = 0;
static guint32 user_information_len = 0;
static guint32 calling_AP_title_len = 0;
static guint32 key_id_element_len = 0;
static guint32 iv_element_len = 0;
#endif /* HAVE_LIBGCRYPT */

#include "packet-c1222-ett.c"

static expert_field ei_c1222_command_truncated = EI_INIT;
static expert_field ei_c1222_bad_checksum = EI_INIT;
static expert_field ei_c1222_epsem_missing = EI_INIT;
#ifdef HAVE_LIBGCRYPT
static expert_field ei_c1222_epsem_failed_authentication = EI_INIT;
#else
static expert_field ei_c1222_epsem_not_authenticated = EI_INIT;
#endif
static expert_field ei_c1222_epsem_not_decryped = EI_INIT;
static expert_field ei_c1222_ed_class_missing = EI_INIT;
static expert_field ei_c1222_epsem_ber_length_error = EI_INIT;
static expert_field ei_c1222_epsem_field_length_error = EI_INIT;
static expert_field ei_c1222_mac_missing = EI_INIT;

/*------------------------------
 * Data Structures
 *------------------------------
 */
typedef struct _c1222_uat_data {
  guint keynum;
  guchar *key;
  guint  keylen;
} c1222_uat_data_t;

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
  { 0, NULL }
};

static const value_string procflags[] = {
  { 0x00, "SF" },
  { 0x08, "MF" },
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

#ifdef HAVE_LIBGCRYPT
/* these are for the key tables */
UAT_HEX_CB_DEF(c1222_users, keynum, c1222_uat_data_t)
UAT_BUFFER_CB_DEF(c1222_users, key, c1222_uat_data_t, key, keylen)

static c1222_uat_data_t *c1222_uat_data = NULL;
static guint num_c1222_uat_data = 0;
static uat_t *c1222_uat;

/* these macros ares used to populate fields needed to verify crypto */
#define FILL_START int length, start_offset = offset;
#define FILL_TABLE(fieldname)  \
  length = offset - start_offset; \
  fieldname = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, start_offset, length); \
  fieldname##_len = length;
#define FILL_TABLE_TRUNCATE(fieldname, len)  \
  length = 1 + 2*(offset - start_offset); \
  fieldname = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, start_offset, length); \
  fieldname##_len = len;
#define FILL_TABLE_APTITLE(fieldname) \
  length = offset - start_offset; \
  switch (tvb_get_guint8(tvb, start_offset)) { \
    case 0x80: /* relative OID */ \
      tvb_ensure_bytes_exist(tvb, start_offset, length); \
      fieldname##_len = length + c1222_baseoid_len; \
      fieldname = (guint8 *)wmem_alloc(wmem_packet_scope(), fieldname##_len); \
      fieldname[0] = 0x06;  /* create absolute OID tag */ \
      fieldname[1] = (fieldname##_len - 2) & 0xff;  \
      memcpy(&(fieldname[2]), c1222_baseoid, c1222_baseoid_len); \
      tvb_memcpy(tvb, &(fieldname[c1222_baseoid_len+2]), start_offset+2, length-2); \
      break; \
    case 0x06:  /* absolute OID */ \
    default: \
      fieldname = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, start_offset, length); \
      fieldname##_len = length; \
      break; \
  }
#else /* HAVE_LIBGCRYPT */
#define FILL_TABLE(fieldname)
#define FILL_TABLE_TRUNCATE(fieldname, len)
#define FILL_TABLE_APTITLE(fieldname)
#define FILL_START
#endif /* HAVE_LIBGCRYPT */

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
static guint8
c1222_cksum(tvbuff_t *tvb, gint offset, int len)
{
  guint8 sum;
  for (sum = 0; len; offset++, len--)
    sum += tvb_get_guint8(tvb, offset);
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
parse_c1222_detailed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int cmd, guint32 *length, int *offset)
{
  guint16 user_id = 0;
  guint8 *user_name = NULL;
  guint8 *password = NULL;
  guint8 auth_len = 0;
  gchar *auth_req = NULL;
  guint16 table = 0;
  guint16 tblsize = 0;
  guint8 chksum = 0;
  guint16 calcsum = 0;
  guint8 wait_seconds = 0;
  int numrates = 0;
  guint16 packet_size;
  guint16 procedure_num = 0;
  guint8 nbr_packet;
  /* timing setup parameters */
  guint8 traffic;
  guint8 inter_char;
  guint8 resp_to;
  guint8 nbr_retries;
  proto_item *item = NULL;

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
        user_name = tvb_get_string_enc(wmem_packet_scope(),tvb, *offset, 10, ENC_ASCII);
        proto_tree_add_string(tree, hf_c1222_logon_user, tvb, *offset, 10, user_name);
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
        password = tvb_get_string_enc(wmem_packet_scope(),tvb, *offset, 20, ENC_ASCII);
        proto_tree_add_string(tree, hf_c1222_security_password, tvb, *offset, 20, password);
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
        auth_len = tvb_get_guint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_auth_len, tvb, *offset, 1, auth_len);
        *offset += 1;
        if (*length >= auth_len) {
          auth_req = tvb_bytes_to_ep_str(tvb, *offset, auth_len);
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
            procedure_num = tvb_get_letohs(tvb, *offset);
            proto_tree_add_uint(tree, hf_c1222_procedure_num, tvb, *offset, 2, procedure_num);
            *offset += 2;
            *length -= 2;
            tblsize -= 2;
          }
          proto_tree_add_item(tree, hf_c1222_write_data, tvb, *offset, tblsize, ENC_NA);
          *offset += tblsize;
          *length -= tblsize;
          chksum = tvb_get_guint8(tvb, *offset);
          item = proto_tree_add_uint(tree, hf_c1222_write_chksum, tvb, *offset, 1, chksum);
          if (table == 7) {/* is it a procedure call? */
            calcsum = c1222_cksum(tvb, (*offset)-tblsize-2, tblsize+2);
          } else {
            calcsum = c1222_cksum(tvb, (*offset)-tblsize, tblsize);
          }
          if (chksum != calcsum) {
            expert_add_info_format(pinfo, item, &ei_c1222_bad_checksum, "Bad checksum [should be 0x%02x]", calcsum);
          }
          if (table == 7) {/* is it a procedure call? */
            proto_item_set_text(tree, "C12.22 EPSEM: %s (%s-%d, %s-%d)",
                    val_to_str(cmd,commandnames,"Unknown (0x%02x)"),
                    val_to_str((table >> 8) & 0xF8, tableflags,"Unknown (0x%04x)"), table & 0x7FF,
                    val_to_str((procedure_num >> 8) & 0xF8, procflags,"Unknown (0x%04x)"), procedure_num & 0x7FF);
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
          chksum = tvb_get_guint8(tvb, *offset);
          item = proto_tree_add_uint(tree, hf_c1222_write_chksum, tvb, *offset, 1, chksum);
          calcsum = c1222_cksum(tvb, (*offset)-tblsize, tblsize);
          if (chksum != calcsum) {
            expert_add_info_format(pinfo, item, &ei_c1222_bad_checksum, "Bad checksum [should be 0x%02x]", calcsum);
          }
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
        wait_seconds = tvb_get_guint8(tvb, *offset);
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
        nbr_packet = tvb_get_guint8(tvb, *offset);
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
        traffic = tvb_get_guint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_timing_setup_traffic, tvb, *offset, 1, traffic);
        *offset += 1;
        *length -= 1;
        inter_char = tvb_get_guint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_timing_setup_inter_char, tvb, *offset, 1, inter_char);
        *offset += 1;
        *length -= 1;
        resp_to = tvb_get_guint8(tvb, *offset);
        proto_tree_add_uint(tree, hf_c1222_timing_setup_resp_to, tvb, *offset, 1, resp_to);
        *offset += 1;
        *length -= 1;
        nbr_retries = tvb_get_guint8(tvb, *offset);
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

#ifdef HAVE_LIBGCRYPT
typedef struct tagTOP_ELEMENT_CONTROL
{
  /* TRUE if this tag is required */
  gboolean required;
  /* TRUE if we must truncate this tag */
  gboolean truncate;
  /* actual hex value of the tag we're seeking */
  guint8 tag;
  /* if TRUE, add tag and length before copying */
  gboolean addtag;
  /* pointer to pointer to memory copy of element */
  guint8 **element;
  /* pointer to element length */
  guint32 *length;
} TOP_ELEMENT_CONTROL;

static const TOP_ELEMENT_CONTROL canonifyTable[] = {
  { FALSE, FALSE, 0xA1, TRUE, &aSO_context, &aSO_context_len },
  { TRUE , FALSE, 0xA2, TRUE, &called_AP_title, &called_AP_title_len },
  { FALSE, FALSE, 0xA4, TRUE, &called_AP_invocation_id, &called_AP_invocation_id_len },
  { FALSE, FALSE, 0xA7, TRUE, &calling_AE_qualifier, &calling_AE_qualifier_len },
  { TRUE,  FALSE, 0xA8, TRUE, &calling_AP_invocation_id, &calling_AP_invocation_id_len },
  { FALSE, FALSE, 0x8B, TRUE, &mechanism_name, &mechanism_name_len },
  { FALSE, FALSE, 0xAC, TRUE, &calling_authentication_value, &calling_authentication_value_len },
  { TRUE , TRUE , 0xBE, TRUE, &user_information, &user_information_len },
  { FALSE, FALSE, 0xA6, TRUE, &calling_AP_title, &calling_AP_title_len },
  { FALSE, FALSE, 0xAC, FALSE, &key_id_element, &key_id_element_len },
  { FALSE, FALSE, 0xAC, FALSE, &iv_element, &iv_element_len },
  { FALSE, FALSE, 0x0,  TRUE, NULL, NULL }
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
static guint32
get_ber_len_size(guint32 n)
{
  guint32 len = 1;
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
 * \maxsize is the maximum number of bytes we're allowed to write
 * \returns length of encoded value in bytes
 */
static int
encode_ber_len(guint8 *ptr, guint32 n, int maxsize)
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

/**
 * Checks a new encryption table item for validity.
 *
 * \param n points to the new record
 * \param err is updated to point to an error string if needed
 */
static void
c1222_uat_data_update_cb(void* n, const char** err)
{
  c1222_uat_data_t* new_rec = (c1222_uat_data_t *)n;

  if (new_rec->keynum > 0xff) {
    *err = g_strdup("Invalid key number; must be less than 256");
  }
  if (new_rec->keylen != EAX_SIZEOF_KEY) {
    *err = g_strdup("Invalid key size; must be 16 bytes");
  }
}

/**
 * Canonifies header fields in preparation for authenticating and/or decrypting the packet.
 *
 * \param buff points to the allocated canonization buffer
 * \param offset points to start of unallocated space in buffer and
      is updated as we put bytes into buffer
 * \param buffsize total size of allocated buffer
 * \return FALSE if element is required and not present; otherwise TRUE
 */
static gboolean
canonify_unencrypted_header(guchar *buff, guint32 *offset, guint32 buffsize)
{
  const TOP_ELEMENT_CONTROL *t = canonifyTable;
  guint32 len;

  for (t = canonifyTable; t->element != NULL; t++)
  {
    len = *(t->length);
    if (t->required && *(t->element) == NULL)
      return FALSE;
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
        return FALSE;
      }
      memcpy(&buff[*offset], *(t->element), len);
      (*offset) += len;
      if (t->addtag) {
          *(t->element) = NULL;
      }
    }
  }
  return TRUE;
}

/**
 * Looks up the required key in the key table.
 *
 * \param keybuff is updated with a copy of the key data if successful lookup.
 * \param keyid is the ID number of the desired key
 * \returns TRUE if key was found; otherwise FALSE
 */
static gboolean
keylookup(guint8 *keybuff, guint8 keyid)
{
  guint i;

  if (c1222_uat_data == NULL)
    return FALSE;
  for (i = 0; i < num_c1222_uat_data; i++) {
    if (c1222_uat_data[i].keynum == keyid) {
      memcpy(keybuff, c1222_uat_data[i].key, EAX_SIZEOF_KEY);
      return TRUE;
    }
  }
  return FALSE;
}

/**
 * Authenticates and decrypts the passed packet.
 *
 * \param buffer points to a memory copy of the packet to be authenticated/decrypted
 *        and contains the decrypted value on successful return.
 * \param length lenth of input packet
 * \param decrypt TRUE if packet is to be authenticated and decrypted; FALSE if authentication only is requested
 * \returns TRUE if the requested operation was successful; otherwise FALSE
 */
static gboolean
decrypt_packet(guchar *buffer, guint32 length, gboolean decrypt)
{
#define CANONBUFFSIZE 300U
  guchar canonbuff[CANONBUFFSIZE];
  guint8 c1222_key[EAX_SIZEOF_KEY];
  guchar key_id = 0;
  guint32 offset = 0;
  gboolean status = FALSE;

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
/* RETURNS:        TRUE if message has been authenticated.                    */
/*                 FALSE if not authenticated, invalid Mode, or error.        */
  if (offset) {
    if (!keylookup((guint8 *)&c1222_key, key_id))
      return FALSE;
    status = Eax_Decrypt(canonbuff, c1222_key, buffer,
                  offset, EAX_SIZEOF_KEY, length-4,
                  (MAC_T *)&buffer[length-4],
                  decrypt ? EAX_MODE_CIPHERTEXT_AUTH : EAX_MODE_CLEARTEXT_AUTH);
  }
  return status;
}
#else /* HAVE_LIBCRYPT */
static gboolean
decrypt_packet(guchar *buffer _U_, guint32 length _U_, gboolean decrypt _U_)
{
  return FALSE;
}
#endif /* HAVE_LIBGCRYPT */

/**
 * Checks to make sure that a complete, valid BER-encoded length is in the buffer.
 *
 * \param tvb contains the buffer to be examined
 * \param offset is the offset within the buffer at which the BER-encded length begins
 * \returns TRUE if a complete, valid BER-encoded length is in the buffer; otherwise FALSE
 */
static gboolean
ber_len_ok(tvbuff_t *tvb, int offset)
{
  guint8 ch;

  if (tvb_offset_exists(tvb, offset)) {
    ch = tvb_get_guint8(tvb, offset);
    offset++;
    if (!(ch & 0x80)) {
      return TRUE;
    } else if (tvb_offset_exists(tvb, offset)) {
      ch = tvb_get_guint8(tvb, offset);
      offset++;
      if (!(ch & 0x80)) {
        return TRUE;
      } else if (tvb_offset_exists(tvb, offset)) {
        ch = tvb_get_guint8(tvb, offset);
        offset++;
        if (!(ch & 0x80)) {
          return TRUE;
        } else if (tvb_offset_exists(tvb, offset)) {
          ch = tvb_get_guint8(tvb, offset);
          /*offset++;*/
          if (!(ch & 0x80)) {
            return TRUE;
          }
        }
      }
    }
  }
  return FALSE;
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
dissect_epsem(tvbuff_t *tvb, int offset, guint32 len, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *cmd_tree = NULL;
  proto_tree *ct = NULL;
  proto_tree *crypto_tree = NULL;
  proto_tree *yt = NULL;
  proto_item *item = NULL;
  guint8 flags;
  int local_offset;
  gint len2;
  int cmd_err;
  gboolean ind;
  guchar *buffer;
  tvbuff_t *epsem_buffer = NULL;
  gboolean crypto_good = FALSE;
  gboolean crypto_bad = FALSE;
  gboolean hasmac = FALSE;
  gboolean encrypted = FALSE;

  if ((tvb == NULL) && (len == 0)) {
    expert_add_info(pinfo, tree, &ei_c1222_epsem_missing);
    return offset;
  }
  /* parse the flags byte which is always unencrypted */
  flags = tvb_get_guint8(tvb, offset);
  proto_tree_add_bitmask(tree, tvb, offset, hf_c1222_epsem_flags, ett_c1222_flags, c1222_flags, ENC_BIG_ENDIAN);
  offset++;
  switch ((flags & C1222_EPSEM_FLAG_SECURITY_MODE) >> 2) {
    case EAX_MODE_CIPHERTEXT_AUTH:
      /* mode is ciphertext with authentication */
      hasmac = TRUE;
      len2 = tvb_length_remaining(tvb, offset);
      if (len2 <= 0)
        return offset;
      encrypted = TRUE;
      if (c1222_decrypt) {
        buffer = (guchar *)tvb_memdup(wmem_packet_scope(), tvb, offset, len2);
        if (!decrypt_packet(buffer, len2, TRUE)) {
          crypto_bad = TRUE;
        } else {
          epsem_buffer = tvb_new_real_data(buffer, len2, len2);
          tvb_set_child_real_data_tvbuff(tvb, epsem_buffer);
          add_new_data_source(pinfo, epsem_buffer, "Decrypted EPSEM Data");
          crypto_good = TRUE;
          encrypted = FALSE;
        }
      }
      break;
    case EAX_MODE_CLEARTEXT_AUTH:
      /* mode is cleartext with authentication */
      hasmac = TRUE;
      len2 = tvb_length_remaining(tvb, offset);
      if (len2 <= 0)
        return offset;
      buffer = (guchar *)tvb_memdup(wmem_packet_scope(), tvb, offset, len2);
      epsem_buffer = tvb_new_subset_remaining(tvb, offset);
      if (c1222_decrypt) {
        if (!decrypt_packet(buffer, len2, FALSE)) {
#ifdef HAVE_LIBGCRYPT
          crypto_bad = TRUE;
          expert_add_info(pinfo, tree, &ei_c1222_epsem_failed_authentication);
#else /* HAVE_LIBGCRYPT */
          expert_add_info(pinfo, tree, &ei_c1222_epsem_not_authenticated);
#endif /* HAVE_LIBGCRYPT */
        } else {
          crypto_good = TRUE;
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
    expert_add_info(pinfo, tree, &ei_c1222_epsem_not_decryped);
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
        local_offset = dissect_ber_length(pinfo, tree, epsem_buffer, local_offset, (guint32 *)&len2, &ind);
      } else {
        expert_add_info(pinfo, tree, &ei_c1222_epsem_ber_length_error);
        return offset+len;
      }
      if (tvb_offset_exists(epsem_buffer, local_offset+len2-1)) {
        cmd_err = tvb_get_guint8(epsem_buffer, local_offset);
        ct = proto_tree_add_item(tree, hf_c1222_epsem_total, epsem_buffer, local_offset, len2, ENC_NA);
        cmd_tree = proto_item_add_subtree(ct, ett_c1222_cmd);
        parse_c1222_detailed(epsem_buffer, pinfo, cmd_tree, cmd_err, (guint32 *)&len2, &local_offset);
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
      PROTO_ITEM_SET_GENERATED(item);
      item = proto_tree_add_boolean(crypto_tree, hf_c1222_epsem_crypto_bad, tvb, local_offset, 4, crypto_bad);
      PROTO_ITEM_SET_GENERATED(item);
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
    if (tree) {
      c1222_item = proto_tree_add_item(tree, proto_c1222, tvb, 0, -1, ENC_NA);
      c1222_tree = proto_item_add_subtree(c1222_item, ett_c1222);
      dissect_MESSAGE_PDU(tvb, pinfo, c1222_tree);
    }

    return tvb_captured_length(tvb);
}

/**
 * Fetches the length of an entire C12.22 message to assist in reassembly.
 *
 * \param pinfo the packet info of the current data
 * \param tvb the tv buffer of the current data
 * \param offset the offset in the tvb
 * \returns length of entire C12.22 message
 */
static guint
get_c1222_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
  int orig_offset;
  guint length;
  gboolean ind;

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
   { &hf_c1222_procedure_num,
    { "C12.22 Procedure Number", "c1222.procedure.num",
    FT_UINT16, BASE_DEC,
    NULL, 0x7ff,
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
  static gint *ett[] = {
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
#ifdef HAVE_LIBGCRYPT
    { &ei_c1222_epsem_failed_authentication, { "c1222.epsem.failed_authentication", PI_SECURITY, PI_ERROR, "C12.22 EPSEM failed authentication", EXPFILL }},
#else
    { &ei_c1222_epsem_not_authenticated, { "c1222.epsem.not_authenticated", PI_SECURITY, PI_WARN, "C12.22 EPSEM could not be authenticated", EXPFILL }},
#endif
    { &ei_c1222_epsem_not_decryped, { "c1222.epsem.not_decryped", PI_UNDECODED, PI_WARN, "C12.22 EPSEM could not be decrypted", EXPFILL }},
    { &ei_c1222_ed_class_missing, { "c1222.ed_class_missing", PI_SECURITY, PI_ERROR, "C12.22 ED Class missing", EXPFILL }},
    { &ei_c1222_epsem_ber_length_error, { "c1222.epsem.ber_length_error", PI_MALFORMED, PI_ERROR, "C12.22 EPSEM BER length error", EXPFILL }},
    { &ei_c1222_epsem_field_length_error, { "c1222.epsem.field_length_error", PI_MALFORMED, PI_ERROR, "C12.22 EPSEM field length error", EXPFILL }},
    { &ei_c1222_mac_missing, { "c1222.mac_missing", PI_MALFORMED, PI_ERROR, "C12.22 MAC missing", EXPFILL }},
  };

  expert_module_t* expert_c1222;
  module_t *c1222_module;

#ifdef HAVE_LIBGCRYPT
  static uat_field_t c1222_uat_flds[] = {
    UAT_FLD_HEX(c1222_users,keynum,"Key ID","Key identifier in hexadecimal"),
    UAT_FLD_BUFFER(c1222_users, key, "Key", "Encryption key as 16-byte hex string"),
    UAT_END_FIELDS
  };
#endif /* HAVE_LIBGCRYPT */

  /* Register protocol */
  proto_c1222 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_c1222, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_c1222 = expert_register_protocol(proto_c1222);
  expert_register_field_array(expert_c1222, ei, array_length(ei));
  c1222_module = prefs_register_protocol(proto_c1222, proto_reg_handoff_c1222);
  prefs_register_bool_preference(c1222_module, "desegment",
        "Reassemble all C12.22 messages spanning multiple TCP segments",
        "Whether the C12.22 dissector should reassemble all messages spanning multiple TCP segments",
        &c1222_desegment);
  prefs_register_string_preference(c1222_module, "baseoid", "Base OID to use for relative OIDs",
        "Base object identifier for use in resolving relative object identifiers",
        &c1222_baseoid_str);
#ifdef HAVE_LIBGCRYPT
  prefs_register_bool_preference(c1222_module, "decrypt",
        "Verify crypto for all applicable C12.22 messages",
        "Whether the C12.22 dissector should verify the crypto for all relevant messages",
        &c1222_decrypt);

  c1222_uat = uat_new("Decryption Table",
      sizeof(c1222_uat_data_t),         /* record size */
      "c1222_decryption_table",         /* filename */
      TRUE,                             /* from_profile */
      &c1222_uat_data,                  /* data_ptr */
      &num_c1222_uat_data,              /* numitems_ptr */
      UAT_AFFECTS_DISSECTION,           /* affects dissection of packets, but not set of named fields */
      NULL,                             /* help */
      NULL,                             /* copy callback */
      c1222_uat_data_update_cb,         /* update callback */
      NULL,                             /* free callback */
      NULL,                             /* post update callback */
      c1222_uat_flds);                  /* UAT field definitions */

  prefs_register_uat_preference(c1222_module,
      "decryption_table",
      "Decryption Table",
      "Table of security parameters for decryption of C12.22 packets",
      c1222_uat);
#endif /* HAVE_LIBGCRYPT */
}

/*--- proto_reg_handoff_c1222 ---------------------------------------*/
void
proto_reg_handoff_c1222(void)
{
  static gboolean initialized = FALSE;
  guint8 *temp = NULL;

  if( !initialized ) {
    c1222_handle = new_create_dissector_handle(dissect_c1222, proto_c1222);
    c1222_udp_handle = new_create_dissector_handle(dissect_c1222_common, proto_c1222);
    dissector_add_uint("tcp.port", global_c1222_port, c1222_handle);
    dissector_add_uint("udp.port", global_c1222_port, c1222_udp_handle);
    initialized = TRUE;
  }
  c1222_baseoid_len = oid_string2encoded(c1222_baseoid_str, &temp);
  c1222_baseoid = (guint8 *)wmem_realloc(wmem_epan_scope(), c1222_baseoid, c1222_baseoid_len);
  memcpy(c1222_baseoid, temp, c1222_baseoid_len);
}
/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
