/* packet-imf.c
 * Routines for Internet Message Format (IMF) packet disassembly
 *
 * Copyright (c) 2007 by Graeme Lunt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/expert.h>
#include <wsutil/str_util.h>

#include <epan/tap.h>
#include <epan/export_object.h>

#include "packet-ber.h"
#include "packet-http.h"
#include "packet-imf.h"
#include "packet-ess.h"
#include "packet-p1.h"

void proto_register_imf(void);
void proto_reg_handoff_imf(void);

static int imf_eo_tap = -1;

#define PNAME  "Internet Message Format"
#define PSNAME "IMF"
#define PFNAME "imf"

static int proto_imf = -1;

static int hf_imf_date = -1;
static int hf_imf_from = -1;
static int hf_imf_sender = -1;
static int hf_imf_reply_to = -1;
static int hf_imf_to = -1;
static int hf_imf_cc = -1;
static int hf_imf_bcc = -1;
static int hf_imf_message_id = -1;
static int hf_imf_in_reply_to = -1;
static int hf_imf_references = -1;
static int hf_imf_subject = -1;
static int hf_imf_comments = -1;
static int hf_imf_user_agent = -1;
static int hf_imf_keywords = -1;
static int hf_imf_resent_date = -1;
static int hf_imf_resent_from = -1;
static int hf_imf_resent_sender = -1;
static int hf_imf_resent_to = -1;
static int hf_imf_resent_cc = -1;
static int hf_imf_resent_bcc = -1;
static int hf_imf_resent_message_id = -1;
static int hf_imf_return_path = -1;
static int hf_imf_received = -1;
static int hf_imf_content_type = -1;
static int hf_imf_content_type_type = -1;
static int hf_imf_content_type_parameters = -1;
static int hf_imf_content_id = -1;
static int hf_imf_content_transfer_encoding = -1;
static int hf_imf_content_description = -1;
static int hf_imf_mime_version = -1;
static int hf_imf_thread_index = -1;
static int hf_imf_lines = -1;
static int hf_imf_precedence = -1;
static int hf_imf_ext_mailer = -1;
static int hf_imf_ext_mimeole = -1;
static int hf_imf_ext_tnef_correlator = -1;
static int hf_imf_ext_expiry_date = -1;
static int hf_imf_ext_uidl = -1;
static int hf_imf_ext_authentication_warning = -1;
static int hf_imf_ext_virus_scanned = -1;
static int hf_imf_ext_original_to = -1;
static int hf_imf_extension = -1;
static int hf_imf_extension_type = -1;
static int hf_imf_extension_value = -1;

/* RFC 2156 */
static int hf_imf_autoforwarded = -1;
static int hf_imf_autosubmitted = -1;
static int hf_imf_x400_content_identifier = -1;
static int hf_imf_content_language = -1;
static int hf_imf_conversion = -1;
static int hf_imf_conversion_with_loss = -1;
static int hf_imf_delivery_date = -1;
static int hf_imf_discarded_x400_ipms_extensions = -1;
static int hf_imf_discarded_x400_mts_extensions = -1;
static int hf_imf_dl_expansion_history = -1;
static int hf_imf_deferred_delivery = -1;
static int hf_imf_expires = -1;
static int hf_imf_importance = -1;
static int hf_imf_incomplete_copy = -1;
static int hf_imf_latest_delivery_time = -1;
static int hf_imf_message_type = -1;
static int hf_imf_original_encoded_information_types = -1;
static int hf_imf_originator_return_address = -1;
static int hf_imf_priority = -1;
static int hf_imf_reply_by = -1;
static int hf_imf_sensitivity = -1;
static int hf_imf_supersedes = -1;
static int hf_imf_x400_content_type = -1;
static int hf_imf_x400_mts_identifier = -1;
static int hf_imf_x400_originator = -1;
static int hf_imf_x400_received = -1;
static int hf_imf_x400_recipients = -1;

static int hf_imf_delivered_to = -1;

static int hf_imf_message_text = -1;

static int hf_imf_display_name = -1;
static int hf_imf_address = -1;
/* static int hf_imf_mailbox_list = -1; */
static int hf_imf_mailbox_list_item = -1;
/* static int hf_imf_address_list = -1; */
static int hf_imf_address_list_item = -1;

/* draft-zeilenga-email-seclabel-04 */
static int hf_imf_siolabel = -1;
static int hf_imf_siolabel_marking = -1;
static int hf_imf_siolabel_fgcolor = -1;
static int hf_imf_siolabel_bgcolor = -1;
static int hf_imf_siolabel_type = -1;
static int hf_imf_siolabel_label = -1;
static int hf_imf_siolabel_unknown = -1;

static int ett_imf = -1;
static int ett_imf_content_type = -1;
static int ett_imf_mailbox = -1;
static int ett_imf_group = -1;
static int ett_imf_mailbox_list = -1;
static int ett_imf_address_list = -1;
static int ett_imf_siolabel = -1;
static int ett_imf_extension = -1;
static int ett_imf_message_text = -1;

static dissector_handle_t imf_handle;

static expert_field ei_imf_unknown_param = EI_INIT;

/* Used for IMF Export Object feature */
typedef struct _imf_eo_t {
  gchar    *filename;
  gchar    *sender_data;
  gchar    *subject_data;
  guint32  payload_len;
  gchar    *payload_data;
} imf_eo_t;

static tap_packet_status
imf_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
  export_object_list_t *object_list = (export_object_list_t *)tapdata;
  const imf_eo_t *eo_info = (const imf_eo_t *)data;
  export_object_entry_t *entry;

  if(eo_info) { /* We have data waiting for us */
    /* These values will be freed when the Export Object window
     * is closed. */
    entry = g_new(export_object_entry_t, 1);

    gchar *start = g_strrstr_len(eo_info->sender_data, -1, "<");
    gchar *stop = g_strrstr_len(eo_info->sender_data, -1,  ">");
    /* Only include the string inside of the "<>" brackets. If there is nothing between
    the two brackets use the sender_data string */
    if(start && stop && stop > start && (stop - start) > 2){
        entry->hostname = ws_strdup_printf("%.*s", (int) (stop - start - 1), start + 1);
    } else {
        entry->hostname = g_strdup(eo_info->sender_data);
    }

    entry->pkt_num = pinfo->num;
    entry->content_type = g_strdup("EML file");
    entry->filename = ws_strdup_printf("%s.eml", eo_info->subject_data);
    entry->payload_len = eo_info->payload_len;
    entry->payload_data = (guint8 *)g_memdup2(eo_info->payload_data, eo_info->payload_len);

    object_list->add_entry(object_list->gui_data, entry);

    return TAP_PACKET_REDRAW; /* State changed - window should be redrawn */
  } else {
    return TAP_PACKET_DONT_REDRAW; /* State unchanged - no window updates needed */
  }
}


struct imf_field {
  char         *name;           /* field name - in lower case for matching purposes */
  int          *hf_id;          /* wireshark field */
  void         (*subdissector)(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo);
  gboolean     add_to_col_info; /* add field to column info */
};

#define NO_SUBDISSECTION NULL

static void dissect_imf_mailbox(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo);
static void dissect_imf_address(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo);
static void dissect_imf_address_list(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo);
static void dissect_imf_mailbox_list(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo);
static void dissect_imf_siolabel(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo);

static struct imf_field imf_fields[] = {
  {"unknown-extension",                   &hf_imf_extension_type, NO_SUBDISSECTION, FALSE}, /* unknown extension */
  {"date",                                &hf_imf_date, NO_SUBDISSECTION, FALSE}, /* date-time */
  {"from",                                &hf_imf_from, dissect_imf_mailbox_list , TRUE}, /* mailbox_list */
  {"sender",                              &hf_imf_sender, dissect_imf_mailbox, FALSE}, /* mailbox */
  {"reply-to",                            &hf_imf_reply_to, dissect_imf_address_list , FALSE}, /* address_list */
  {"to",                                  &hf_imf_to, dissect_imf_address_list , FALSE}, /* address_list */
  {"cc",                                  &hf_imf_cc, dissect_imf_address_list , FALSE}, /* address_list */
  {"bcc",                                 &hf_imf_bcc, dissect_imf_address_list , FALSE}, /* address_list */
  {"message-id",                          &hf_imf_message_id, NO_SUBDISSECTION, FALSE}, /* msg-id */
  {"in-reply-to",                         &hf_imf_in_reply_to, NO_SUBDISSECTION, FALSE}, /* msg-id */
  {"references",                          &hf_imf_references, NO_SUBDISSECTION, FALSE}, /* msg-id */
  {"subject",                             &hf_imf_subject, NO_SUBDISSECTION, TRUE}, /* unstructured */
  {"comments",                            &hf_imf_comments, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"user-agent",                          &hf_imf_user_agent, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"keywords",                            &hf_imf_keywords, NULL, FALSE}, /* phrase_list */
  {"resent-date",                         &hf_imf_resent_date, NO_SUBDISSECTION, FALSE},
  {"resent-from",                         &hf_imf_resent_from, dissect_imf_mailbox_list, FALSE},
  {"resent-sender",                       &hf_imf_resent_sender, dissect_imf_mailbox, FALSE},
  {"resent-to",                           &hf_imf_resent_to, dissect_imf_address_list, FALSE},
  {"resent-cc",                           &hf_imf_resent_cc, dissect_imf_address_list, FALSE},
  {"resent-bcc",                          &hf_imf_resent_bcc, dissect_imf_address_list, FALSE},
  {"resent-message-id",                   &hf_imf_resent_message_id, NO_SUBDISSECTION, FALSE},
  {"return-path",                         &hf_imf_return_path, NULL, FALSE},
  {"received",                            &hf_imf_received, NO_SUBDISSECTION, FALSE},
  /* these are really multi-part - but we parse them anyway */
  {"content-type",                        &hf_imf_content_type, NULL, FALSE}, /* handled separately as a special case */
  {"content-id",                          &hf_imf_content_id, NULL, FALSE},
  {"content-description",                 &hf_imf_content_description, NULL, FALSE},
  {"content-transfer-encoding",           &hf_imf_content_transfer_encoding, NULL, FALSE},
  {"mime-version",                        &hf_imf_mime_version, NO_SUBDISSECTION, FALSE},
  /* MIXER - RFC 2156 */
  {"autoforwarded",                       &hf_imf_autoforwarded, NULL, FALSE},
  {"autosubmitted",                       &hf_imf_autosubmitted, NULL, FALSE},
  {"x400-content-identifier",             &hf_imf_x400_content_identifier, NULL, FALSE},
  {"content-language",                    &hf_imf_content_language, NULL, FALSE},
  {"conversion",                          &hf_imf_conversion, NULL, FALSE},
  {"conversion-with-loss",                &hf_imf_conversion_with_loss, NULL, FALSE},
  {"delivery-date",                       &hf_imf_delivery_date, NULL, FALSE},
  {"discarded-x400-ipms-extensions",      &hf_imf_discarded_x400_ipms_extensions, NULL, FALSE},
  {"discarded-x400-mts-extensions",       &hf_imf_discarded_x400_mts_extensions, NULL, FALSE},
  {"dl-expansion-history",                &hf_imf_dl_expansion_history, NULL, FALSE},
  {"deferred-delivery",                   &hf_imf_deferred_delivery, NULL, FALSE},
  {"expires",                             &hf_imf_expires, NULL, FALSE},
  {"importance",                          &hf_imf_importance, NULL, FALSE},
  {"incomplete-copy",                     &hf_imf_incomplete_copy, NULL, FALSE},
  {"latest-delivery-time",                &hf_imf_latest_delivery_time, NULL, FALSE},
  {"message-type",                        &hf_imf_message_type, NULL, FALSE},
  {"original-encoded-information-types",  &hf_imf_original_encoded_information_types, NULL, FALSE},
  {"originator-return-address",           &hf_imf_originator_return_address, NULL, FALSE},
  {"priority",                            &hf_imf_priority, NULL, FALSE},
  {"reply-by",                            &hf_imf_reply_by, NULL, FALSE},
  {"sensitivity",                         &hf_imf_sensitivity, NULL, FALSE},
  {"supersedes",                          &hf_imf_supersedes, NULL, FALSE},
  {"x400-content-type",                   &hf_imf_x400_content_type, NULL, FALSE},
  {"x400-mts-identifier",                 &hf_imf_x400_mts_identifier, NULL, FALSE},
  {"x400-originator",                     &hf_imf_x400_originator, NULL, FALSE},
  {"x400-received",                       &hf_imf_x400_received, NULL, FALSE},
  {"x400-recipients",                     &hf_imf_x400_recipients, NULL, FALSE},
  /* delivery */
  {"delivered-to",                        &hf_imf_delivered_to, dissect_imf_mailbox, FALSE}, /* mailbox */
  /* some others */
  {"x-mailer",                            &hf_imf_ext_mailer, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"thread-index",                        &hf_imf_thread_index, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"lines",                               &hf_imf_lines, NULL, FALSE},
  {"precedence",                          &hf_imf_precedence, NULL, FALSE},
  {"x-mimeole",                           &hf_imf_ext_mimeole, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"expiry-date",                         &hf_imf_ext_expiry_date, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"x-ms-tnef-correlator",                &hf_imf_ext_tnef_correlator, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"x-uidl",                              &hf_imf_ext_uidl, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"x-authentication-warning",            &hf_imf_ext_authentication_warning, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"x-virus-scanned",                     &hf_imf_ext_virus_scanned, NO_SUBDISSECTION, FALSE}, /* unstructured */
  {"x-original-to",                       &hf_imf_ext_original_to, dissect_imf_address_list, FALSE},
  {"sio-label",                           &hf_imf_siolabel, dissect_imf_siolabel, FALSE}, /* sio-label */
  {NULL, NULL, NULL, FALSE},
};

static wmem_map_t *imf_field_table=NULL;

#define FORMAT_UNSTRUCTURED  0
#define FORMAT_MAILBOX       1
#define FORMAT_ADDRESS       2
#define FORMAT_MAILBOX_LIST  3
#define FORMAT_ADDRESS_LIST  4
#define FORMAT_SIO_LABEL     5

static const value_string header_format[] = {
  { FORMAT_UNSTRUCTURED, "Unstructured" },
  { FORMAT_MAILBOX,      "Mailbox"      },
  { FORMAT_ADDRESS,      "Address"      },
  { FORMAT_MAILBOX_LIST, "Mailbox List" },
  { FORMAT_ADDRESS_LIST, "Address List" },
  { FORMAT_SIO_LABEL,    "SIO-Label"    },
  { 0, NULL }
};

static const value_string add_to_col_info[] = {
  { 0, "No"  },
  { 1, "Yes" },
  { 0, NULL }
};

typedef struct _header_field_t {
  gchar *header_name;
  gchar *description;
  guint  header_format;
  guint  add_to_col_info;
} header_field_t;

static header_field_t *header_fields;
static guint num_header_fields;

static GHashTable *custom_field_table;
static hf_register_info *dynamic_hf;
static guint dynamic_hf_size;

static gboolean
header_fields_update_cb(void *r, char **err)
{
  header_field_t *rec = (header_field_t *)r;
  char c;

  if (rec->header_name == NULL) {
    *err = g_strdup("Header name can't be empty");
    return FALSE;
  }

  g_strstrip(rec->header_name);
  if (rec->header_name[0] == 0) {
    *err = g_strdup("Header name can't be empty");
    return FALSE;
  }

  /* Check for invalid characters (to avoid asserting out when
   * registering the field).
   */
  c = proto_check_field_name(rec->header_name);
  if (c) {
    *err = ws_strdup_printf("Header name can't contain '%c'", c);
    return FALSE;
  }

  *err = NULL;
  return TRUE;
}

static void *
header_fields_copy_cb(void *n, const void *o, size_t siz _U_)
{
  header_field_t *new_rec = (header_field_t *)n;
  const header_field_t *old_rec = (const header_field_t *)o;

  new_rec->header_name = g_strdup(old_rec->header_name);
  new_rec->description = g_strdup(old_rec->description);
  new_rec->header_format = old_rec->header_format;
  new_rec->add_to_col_info = old_rec->add_to_col_info;

  return new_rec;
}

static void
header_fields_free_cb(void *r)
{
  header_field_t *rec = (header_field_t *)r;

  g_free(rec->header_name);
  g_free(rec->description);
}

UAT_CSTRING_CB_DEF(header_fields, header_name, header_field_t)
UAT_CSTRING_CB_DEF(header_fields, description, header_field_t)
UAT_VS_DEF(header_fields, header_format, header_field_t, guint, 0, "Unstructured")
UAT_VS_DEF(header_fields, add_to_col_info, header_field_t, guint, 0, "No")


/* Define media_type/Content type table */
static dissector_table_t media_type_dissector_table;

static void
dissect_imf_address(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo)
{
  proto_tree *group_tree;
  proto_item *group_item;
  int addr_pos;

  /* if there is a colon present it is a group */
  if((addr_pos = tvb_find_guint8(tvb, offset, length, ':')) == -1) {

    /* there isn't - so it must be a mailbox */
    dissect_imf_mailbox(tvb, offset, length, item, pinfo);

  } else {

    /* it is a group */
    group_tree = proto_item_add_subtree(item, ett_imf_group);

    /* the display-name is mandatory */
    group_item = proto_tree_add_item(group_tree, hf_imf_display_name, tvb, offset, addr_pos - offset - 1, ENC_ASCII);

    /* consume any whitespace */
    for(addr_pos++ ;addr_pos < (offset + length); addr_pos++) {
      if(!g_ascii_isspace(tvb_get_guint8(tvb, addr_pos))) {
        break;
      }
    }

    if(tvb_get_guint8(tvb, addr_pos) != ';') {

      dissect_imf_mailbox_list(tvb, addr_pos, length - (addr_pos - offset), group_item, pinfo);

      /* XXX: need to check for final ';' */

    }

  }
}

static void
dissect_imf_mailbox(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo _U_)
{
  proto_tree *mbox_tree;
  int        addr_pos, end_pos;

  mbox_tree = proto_item_add_subtree(item, ett_imf_mailbox);

  /* Here is the plan:
     If we can't find and angle brackets, then the whole field is an address.
     If we find angle brackets, then the address is between them and the display name is
     anything before the opening angle bracket
  */

  if((addr_pos = tvb_find_guint8(tvb, offset, length, '<')) == -1) {
    /* we can't find an angle bracket - the whole field is therefore the address */

    (void) proto_tree_add_item(mbox_tree, hf_imf_address, tvb, offset, length, ENC_ASCII);

  } else {
    /* we can find an angle bracket - let's see if we can find a display name */
    /* XXX: the '<' could be in the display name */

    for(; offset < addr_pos; offset++) {
      if(!g_ascii_isspace(tvb_get_guint8(tvb, offset))) {
        break;
      }
    }

    if(offset != addr_pos) { /* there is a display name */
      (void) proto_tree_add_item(mbox_tree, hf_imf_display_name, tvb, offset, addr_pos - offset - 1, ENC_ASCII);
    }
    end_pos = tvb_find_guint8(tvb, addr_pos + 1, length - (addr_pos + 1 - offset), '>');

    if(end_pos != -1) {
      (void) proto_tree_add_item(mbox_tree, hf_imf_address, tvb, addr_pos + 1, end_pos - addr_pos - 1, ENC_ASCII);
    }
  }
}

static void
dissect_imf_address_list(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo)
{
  proto_item *addr_item = NULL;
  proto_tree *tree = NULL;
  int         count = 0;
  int         item_offset;
  int         end_offset;
  int         item_length;

  /* a comma separated list of addresses */
  tree = proto_item_add_subtree(item, ett_imf_address_list);

  item_offset = offset;

  do {

    end_offset = tvb_find_guint8(tvb, item_offset, length - (item_offset - offset), ',');

    count++; /* increase the number of items */

    if(end_offset == -1) {
      /* length is to the end of the buffer */
      item_length = length - (item_offset - offset);
    } else {
      item_length = end_offset - item_offset;
    }
    addr_item = proto_tree_add_item(tree, hf_imf_address_list_item, tvb, item_offset, item_length, ENC_ASCII);
    dissect_imf_address(tvb, item_offset, item_length, addr_item, pinfo);

    if(end_offset != -1) {
      item_offset = end_offset + 1;
    }
  } while(end_offset != -1);

  /* now indicate the number of items found */
  proto_item_append_text(item, ", %d item%s", count, plurality(count, "", "s"));
}

static void
dissect_imf_mailbox_list(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo)
{
  proto_item *mbox_item = NULL;
  proto_tree *tree = NULL;
  int         count = 0;
  int         item_offset;
  int         end_offset;
  int         item_length;

  /* a comma separated list of mailboxes */
  tree = proto_item_add_subtree(item, ett_imf_mailbox_list);

  item_offset = offset;

  do {

    end_offset = tvb_find_guint8(tvb, item_offset, length - (item_offset - offset), ',');

    count++; /* increase the number of items */

    if(end_offset == -1) {
      /* length is to the end of the buffer */
      item_length = length - (item_offset - offset);
    } else {
      item_length = end_offset - item_offset;
    }
    mbox_item = proto_tree_add_item(tree, hf_imf_mailbox_list_item, tvb, item_offset, item_length, ENC_ASCII);
    dissect_imf_mailbox(tvb, item_offset, item_length, mbox_item, pinfo);

    if(end_offset != -1) {
      item_offset = end_offset + 1;
    }
  } while(end_offset != -1);

  /* now indicate the number of items found */
  proto_item_append_text(item, ", %d item%s", count, plurality(count, "", "s"));
}

static void
dissect_imf_siolabel(tvbuff_t *tvb, int offset, int length, proto_item *item, packet_info *pinfo)
{
  proto_tree *tree = NULL;
  proto_item *sub_item = NULL;
  int         item_offset, item_length;
  int         value_offset, value_length;
  int         end_offset;
  tvbuff_t   *label_tvb;
  gchar      *type = NULL;
  wmem_strbuf_t  *label_string = wmem_strbuf_new(pinfo->pool, "");

  /* a semicolon separated list of attributes */
  tree = proto_item_add_subtree(item, ett_imf_siolabel);
  item_offset = offset;

  do {
    end_offset = tvb_find_guint8(tvb, item_offset, length - (item_offset - offset), ';');

    /* skip leading space */
    while (g_ascii_isspace(tvb_get_guint8(tvb, item_offset))) {
      item_offset++;
    }

    if (end_offset == -1) {
      /* length is to the end of the buffer */
      item_length = tvb_find_line_end(tvb, item_offset, length - (item_offset - offset), NULL, FALSE);
    } else {
      item_length = end_offset - item_offset;
    }

    value_offset = tvb_find_guint8(tvb, item_offset, length - (item_offset - offset), '=') + 1;
    while (g_ascii_isspace(tvb_get_guint8(tvb, value_offset))) {
      value_offset++;
    }

    value_length = item_length - (value_offset - item_offset);
    while (g_ascii_isspace(tvb_get_guint8(tvb, value_offset + value_length - 1))) {
      value_length--;
    }

    if (tvb_strneql(tvb, item_offset, "marking", 7) == 0) {
      const guint8* marking;
      proto_tree_add_item_ret_string(tree, hf_imf_siolabel_marking, tvb, value_offset, value_length, ENC_ASCII|ENC_NA, pinfo->pool, &marking);
      proto_item_append_text(item, ": %s", marking);

    } else if (tvb_strneql(tvb, item_offset, "fgcolor", 7) == 0) {
      proto_tree_add_item(tree, hf_imf_siolabel_fgcolor, tvb, value_offset, value_length, ENC_ASCII);

    } else if (tvb_strneql(tvb, item_offset, "bgcolor", 7) == 0) {
      proto_tree_add_item(tree, hf_imf_siolabel_bgcolor, tvb, value_offset, value_length, ENC_ASCII);

    } else if (tvb_strneql(tvb, item_offset, "type", 4) == 0) {
      type = tvb_get_string_enc(pinfo->pool, tvb, value_offset + 1, value_length - 2, ENC_ASCII); /* quoted */
      proto_tree_add_item(tree, hf_imf_siolabel_type, tvb, value_offset, value_length, ENC_ASCII);

    } else if (tvb_strneql(tvb, item_offset, "label", 5) == 0) {
      gchar *label = tvb_get_string_enc(pinfo->pool, tvb, value_offset + 1, value_length - 2, ENC_ASCII); /* quoted */
      wmem_strbuf_append(label_string, label);

      if (tvb_get_guint8(tvb, item_offset + 5) == '*') { /* continuations */
        int num = (int)strtol(tvb_get_string_enc(pinfo->pool, tvb, item_offset + 6, value_offset - item_offset + 6, ENC_ASCII), NULL, 10);
        proto_tree_add_string_format(tree, hf_imf_siolabel_label, tvb, value_offset, value_length,
                                     label, "Label[%d]: \"%s\"", num, label);
      } else {
        proto_tree_add_item(tree, hf_imf_siolabel_label, tvb, value_offset, value_length, ENC_ASCII);
      }

    } else {
      sub_item = proto_tree_add_item(tree, hf_imf_siolabel_unknown, tvb, item_offset, item_length, ENC_ASCII);
      expert_add_info(pinfo, sub_item, &ei_imf_unknown_param);
    }

    if (end_offset != -1) {
      item_offset = end_offset + 1;
    }
  } while (end_offset != -1);

  if (type && wmem_strbuf_get_len(label_string) > 0) {
    if (strcmp (type, ":ess") == 0) {
      label_tvb = base64_to_tvb(tvb, wmem_strbuf_get_str(label_string));
      add_new_data_source(pinfo, label_tvb, "ESS Security Label");
      dissect_ess_ESSSecurityLabel_PDU(label_tvb, pinfo, tree, NULL);
    } else if (strcmp (type, ":x411") == 0) {
      label_tvb = base64_to_tvb(tvb, wmem_strbuf_get_str(label_string));
      add_new_data_source(pinfo, label_tvb, "X.411 Security Label");
      dissect_p1_MessageSecurityLabel_PDU(label_tvb, pinfo, tree, NULL);
    }
  }
}

static void
dissect_imf_content_type(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_item *item,
                         const guint8 **type, const guint8 **parameters)
{
  int first_colon;
  int end_offset;
  int len;
  int i;
  proto_tree *ct_tree;

  /* first strip any whitespace */
  for(i = 0; i < length; i++) {
    if(!g_ascii_isspace(tvb_get_guint8(tvb, offset + i))) {
      offset += i;
      break;
    }
  }

  /* find the first colon - there has to be a colon as there will have to be a boundary */
  first_colon = tvb_find_guint8(tvb, offset, length, ';');

  if(first_colon != -1) {
    ct_tree = proto_item_add_subtree(item, ett_imf_content_type);

    len = first_colon - offset;
    proto_tree_add_item_ret_string(ct_tree, hf_imf_content_type_type, tvb, offset, len, ENC_ASCII|ENC_NA, pinfo->pool, type);
    end_offset = imf_find_field_end (tvb, first_colon + 1, offset + length, NULL);
    if (end_offset == -1) {
       /* No end found */
       return;
    }
    len = end_offset - (first_colon + 1) - 2;  /* Do not include the last CRLF */
    proto_tree_add_item_ret_string(ct_tree, hf_imf_content_type_parameters, tvb, first_colon + 1, len, ENC_ASCII|ENC_NA, pinfo->pool, parameters);
  }
}


int
imf_find_field_end(tvbuff_t *tvb, int offset, gint max_length, gboolean *last_field)
{

  while(offset < max_length) {

    /* look for CR */
    offset = tvb_find_guint8(tvb, offset, max_length - offset, '\r');

    if(offset != -1) {
      /* protect against buffer overrun and only then look for next char */
        if (++offset < max_length && tvb_get_guint8(tvb, offset) == '\n') {
        /* OK - so we have found CRLF */
          if (++offset >= max_length) {
            /* end of buffer and also end of fields */
            if (last_field) {
              *last_field = TRUE;
            }
            /* caller expects that there is CRLF after returned offset, if last_field is set */
            return offset - 2;
          }
        /* peek the next character */
        switch(tvb_get_guint8(tvb, offset)) {
        case '\r':
          /* probably end of the fields */
          if ((offset + 1) < max_length && tvb_get_guint8(tvb, offset + 1) == '\n') {
            if(last_field) {
              *last_field = TRUE;
            }
          }
          return offset;
        case  ' ':
        case '\t':
          /* continuation line */
          break;
        default:
          /* this is a new field */
          return offset;
        }
      }
    } else {
      /* couldn't find a CR - strange */
      break;
    }

  }

  return -1;  /* Fail: No CR found (other than possible continuation) */

}

static int
dissect_imf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item  *item;
  proto_tree  *unknown_tree, *text_tree;
  const guint8 *content_type_str = NULL;
  char  *content_encoding_str = NULL;
  const guint8 *parameters = NULL;
  int   hf_id;
  gint  start_offset = 0;
  gint  value_offset = 0;
  gint  unknown_offset = 0;
  gint  end_offset = 0;
  gint   max_length;
  guint8 *key;
  gboolean last_field = FALSE;
  tvbuff_t *next_tvb;
  struct imf_field *f_info;
  imf_eo_t *eo_info = NULL;

  if (have_tap_listener(imf_eo_tap)) {
    eo_info = wmem_new(pinfo->pool, imf_eo_t);
    /* initialize the eo_info fields in case they are missing later */
    eo_info->sender_data = "";
    eo_info->subject_data = "";
  }

  /* Want to preserve existing protocol name and show that it is carrying IMF */
  col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
  col_set_fence(pinfo->cinfo, COL_PROTOCOL);
  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  col_clear(pinfo->cinfo, COL_INFO);

  item = proto_tree_add_item(tree, proto_imf, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_imf);

  max_length = tvb_captured_length(tvb);
  /* first go through the tvb until we find a blank line and extract the content type if
     we find one */

  /* XXX: What if the tvb contains encrypted data ? is there a way to bypass dissection if so ?  */
  /*      As it is, the following code blithely tries to parse what may be binary data.          */

  while(!last_field) {

    /* look for a colon first */
    end_offset = tvb_find_guint8(tvb, start_offset, max_length - start_offset, ':');

    if(end_offset == -1) {
      /* we couldn't find another colon - strange - we should have broken out of here by now */
      /* XXX: flag an error */
      break;
    } else {
      key = tvb_get_string_enc(pinfo->pool, tvb, start_offset, end_offset - start_offset, ENC_ASCII);

      /* convert to lower case */
      ascii_strdown_inplace (key);

      /* look up the key in built-in fields */
      f_info = (struct imf_field *)wmem_map_lookup(imf_field_table, key);

      if(f_info == NULL && custom_field_table) {
        /* look up the key in custom fields */
        f_info = (struct imf_field *)g_hash_table_lookup(custom_field_table, key);
      }

      if(f_info == NULL) {
        /* set as an unknown extension */
        f_info = imf_fields;
        unknown_offset = start_offset;
      }

      hf_id = *(f_info->hf_id);

      /* value starts immediately after the colon */
      start_offset = end_offset+1;

      end_offset = imf_find_field_end(tvb, start_offset, max_length, &last_field);
      if(end_offset == -1) {
        break;   /* Something's fishy */
      }

      /* remove any leading whitespace */

      for(value_offset = start_offset; value_offset < end_offset; value_offset++)
        if(!g_ascii_isspace(tvb_get_guint8(tvb, value_offset))) {
          break;
        }

      if(value_offset == end_offset) {
        /* empty field - show whole value */
        value_offset = start_offset;
      }

      if(hf_id == hf_imf_extension_type) {

        /* remove 2 bytes to take off the final CRLF to make things a little prettier */
        item = proto_tree_add_item(tree, hf_imf_extension, tvb, unknown_offset, end_offset - unknown_offset - 2, ENC_ASCII);

        proto_item_append_text(item, " (Contact Wireshark developers if you want this supported.)");

        unknown_tree = proto_item_add_subtree(item, ett_imf_extension);

        proto_tree_add_item(unknown_tree, hf_imf_extension_type, tvb, unknown_offset, start_offset - 1 - unknown_offset, ENC_ASCII);

        /* remove 2 bytes to take off the final CRLF to make things a little prettier */
        item = proto_tree_add_item(unknown_tree, hf_imf_extension_value, tvb, value_offset, end_offset - value_offset - 2, ENC_ASCII);

      } else {
        /* remove 2 bytes to take off the final CRLF to make things a little prettier */
        item = proto_tree_add_item(tree, hf_id, tvb, value_offset, end_offset - value_offset - 2, ENC_ASCII|ENC_NA);
      }
      if(f_info->add_to_col_info) {

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s: %s, ", f_info->name,
                        tvb_format_text(pinfo->pool, tvb, value_offset, end_offset - value_offset - 2));

        /* if sender or subject, store for sending to the tap */
        if (eo_info && have_tap_listener(imf_eo_tap)) {
          if (*f_info->hf_id == hf_imf_from) {
            eo_info->sender_data = tvb_get_string_enc(pinfo->pool, tvb, value_offset, end_offset - value_offset - 2, ENC_ASCII|ENC_NA);
          } else if(*f_info->hf_id == hf_imf_subject) {
            eo_info->subject_data = tvb_get_string_enc(pinfo->pool, tvb, value_offset, end_offset - value_offset - 2, ENC_ASCII|ENC_NA);
          }
        }
      }

      if(hf_id == hf_imf_content_type) {
        /* we need some additional processing to extract the content type and parameters */

        dissect_imf_content_type(tvb, pinfo, start_offset, end_offset - start_offset, item,
                                 &content_type_str, &parameters);

      } else if (hf_id == hf_imf_content_transfer_encoding) {
        content_encoding_str = tvb_get_string_enc (pinfo->pool, tvb, value_offset, end_offset - value_offset - 2, ENC_ASCII);
      } else if(f_info->subdissector) {

        /* we have a subdissector */
        f_info->subdissector(tvb, value_offset, end_offset - value_offset, item, pinfo);

      }
    }
    start_offset = end_offset;
  }

  if (last_field) {
    /* Remove the extra CRLF after all the fields */
    end_offset += 2;
  }

  if (end_offset == -1) {
    end_offset = 0;
  }

  /* specify a content type until we can work it out for ourselves */
  /* content_type_str = "multipart/mixed"; */

  /* now dissect the MIME based upon the content type */

  if(content_type_str && media_type_dissector_table) {
    http_message_info_t message_info;

    col_set_fence(pinfo->cinfo, COL_INFO);

    if(content_encoding_str && !g_ascii_strncasecmp(content_encoding_str, "base64", 6)) {
      char *string_data = tvb_get_string_enc(pinfo->pool, tvb, end_offset, tvb_reported_length(tvb) - end_offset, ENC_ASCII);
      next_tvb = base64_to_tvb(tvb, string_data);
      add_new_data_source(pinfo, next_tvb, content_encoding_str);
    } else {
      next_tvb = tvb_new_subset_remaining(tvb, end_offset);
    }

    message_info.type = HTTP_OTHERS;
    message_info.media_str = parameters;
    message_info.data = NULL;
    dissector_try_string(media_type_dissector_table, content_type_str, next_tvb, pinfo, tree, (void*)&message_info);
  } else {

    /* just show the lines or highlight the rest of the buffer as message text */

    item = proto_tree_add_item(tree, hf_imf_message_text, tvb, end_offset, tvb_reported_length_remaining(tvb, end_offset) , ENC_NA);
    text_tree = proto_item_add_subtree(item, ett_imf_message_text);

    start_offset = end_offset;
    while (tvb_offset_exists(tvb, start_offset)) {

      /*
       * Find the end of the line.
       */
      tvb_find_line_end(tvb, start_offset, -1, &end_offset, FALSE);

      /*
       * Put this line.
       */
      proto_tree_add_format_wsp_text(text_tree, tvb, start_offset, end_offset - start_offset);
      col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
                         tvb_format_text_wsp(pinfo->pool, tvb, start_offset, end_offset - start_offset));

      /*
       * Step to the next line.
       */
      start_offset = end_offset;
    }
  }

  if (eo_info && have_tap_listener(imf_eo_tap)) {
    /* Set payload info */
    eo_info->payload_len = max_length;
    eo_info->payload_data = (gchar *) tvb_memdup(pinfo->pool, tvb, 0, max_length);

    /* Send to tap */
    tap_queue_packet(imf_eo_tap, pinfo, eo_info);
  }
  return tvb_captured_length(tvb);
}

static void
free_imf_field (gpointer data)
{
  struct imf_field *imffield = (struct imf_field *) data;

  g_free (imffield->name);
  g_free (imffield);
}

static void
deregister_header_fields(void)
{
  if (dynamic_hf) {
    /* Deregister all fields */
    for (guint i = 0; i < dynamic_hf_size; i++) {
      proto_deregister_field (proto_imf, *(dynamic_hf[i].p_id));
      g_free (dynamic_hf[i].p_id);
    }

    proto_add_deregistered_data (dynamic_hf);
    dynamic_hf = NULL;
    dynamic_hf_size = 0;
  }

  if (custom_field_table) {
    g_hash_table_destroy (custom_field_table);
    custom_field_table = NULL;
  }
}

static void
header_fields_post_update_cb (void)
{
  gint *hf_id;
  struct imf_field *imffield;
  gchar *header_name;

  deregister_header_fields();

  if (num_header_fields) {
    custom_field_table = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, free_imf_field);
    dynamic_hf = g_new0(hf_register_info, num_header_fields);
    dynamic_hf_size = num_header_fields;

    for (guint i = 0; i < dynamic_hf_size; i++) {
      hf_id = g_new(gint, 1);
      *hf_id = -1;
      header_name = g_strdup (header_fields[i].header_name);

      dynamic_hf[i].p_id = hf_id;
      dynamic_hf[i].hfinfo.name = header_name;
      dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf ("imf.header.%s", header_name);
      dynamic_hf[i].hfinfo.type = FT_STRING;
      dynamic_hf[i].hfinfo.display = BASE_NONE;
      dynamic_hf[i].hfinfo.strings = NULL;
      dynamic_hf[i].hfinfo.bitmask = 0;
      dynamic_hf[i].hfinfo.blurb = g_strdup (header_fields[i].description);
      HFILL_INIT(dynamic_hf[i]);

      imffield = g_new(struct imf_field, 1);
      imffield->hf_id = hf_id;
      imffield->name = g_ascii_strdown(header_name, -1);
      switch (header_fields[i].header_format) {
      case FORMAT_UNSTRUCTURED:
        imffield->subdissector = NO_SUBDISSECTION;
        break;
      case FORMAT_MAILBOX:
        imffield->subdissector = dissect_imf_mailbox;
        break;
      case FORMAT_ADDRESS:
        imffield->subdissector = dissect_imf_address;
        break;
      case FORMAT_MAILBOX_LIST:
        imffield->subdissector = dissect_imf_mailbox_list;
        break;
      case FORMAT_ADDRESS_LIST:
        imffield->subdissector = dissect_imf_address_list;
        break;
      case FORMAT_SIO_LABEL:
        dynamic_hf[i].hfinfo.type = FT_NONE; /* constructed */
        imffield->subdissector = dissect_imf_siolabel;
        break;
      default:
        /* unknown */
        imffield->subdissector = NO_SUBDISSECTION;
        break;
      }
      imffield->add_to_col_info = header_fields[i].add_to_col_info;
      g_hash_table_insert (custom_field_table, (gpointer)imffield->name, (gpointer)imffield);
    }

    proto_register_field_array (proto_imf, dynamic_hf, dynamic_hf_size);
  }
}

static void
header_fields_reset_cb(void)
{
  deregister_header_fields();
}

/* Register all the bits needed by the filtering engine */

void
proto_register_imf(void)
{
  static hf_register_info hf[] = {
    { &hf_imf_date,
      { "Date", "imf.date", FT_STRING,  BASE_NONE, NULL, 0x0,
        "DateTime", HFILL }},
    { &hf_imf_from,
      { "From", "imf.from", FT_STRING,  BASE_NONE, NULL, 0x0,
        "MailboxList", HFILL }},
    { &hf_imf_sender,
      { "Sender", "imf.sender", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_reply_to,
      { "Reply-To", "imf.reply_to", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_to,
      { "To", "imf.to", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_cc,
      { "Cc", "imf.cc", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_bcc,
      { "Bcc", "imf.bcc", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_message_id,
      { "Message-ID", "imf.message_id", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_in_reply_to,
      { "In-Reply-To", "imf.in_reply_to", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_references,
      { "References", "imf.references", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_subject,
      { "Subject", "imf.subject", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_comments,
      { "Comments", "imf.comments", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_user_agent,
      { "User-Agent", "imf.user_agent", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_keywords,
      { "Keywords", "imf.keywords", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_resent_date,
      { "Resent-Date", "imf.resent.date", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_resent_from,
      { "Resent-From", "imf.resent.from", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_resent_sender,
      { "Resent-Sender", "imf.resent.sender", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_resent_to,
      { "Resent-To", "imf.resent.to", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_resent_cc,
      { "Resent-Cc", "imf.resent.cc", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_resent_bcc,
      { "Resent-Bcc", "imf.resent.bcc", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_resent_message_id,
      { "Resent-Message-ID", "imf.resent.message_id", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_return_path,
      { "Return-Path", "imf.return_path", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_received,
      { "Received", "imf.received", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_content_type,
      { "Content-Type", "imf.content.type", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_content_type_type,
      { "Type", "imf.content.type.type", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_content_type_parameters,
      { "Parameters", "imf.content.type.parameters", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_content_description,
      { "Content-Description", "imf.content.description", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_content_id,
      { "Content-ID", "imf.content.id", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_content_transfer_encoding,
      { "Content-Transfer-Encoding", "imf.content.transfer_encoding", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_mime_version,
      { "MIME-Version", "imf.mime_version", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_autoforwarded,
      { "Autoforwarded", "imf.autoforwarded", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_autosubmitted,
      { "Autosubmitted", "imf.autosubmitted", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_x400_content_identifier,
      { "X400-Content-Identifier", "imf.x400_content_identifier", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_content_language,
      { "Content-Language", "imf.content_language", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_conversion,
        { "Conversion", "imf.conversion", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_conversion_with_loss,
        { "Conversion-With-Loss", "imf.conversion_with_loss", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_delivery_date,
        { "Delivery-Date", "imf.delivery_date", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_discarded_x400_ipms_extensions,
        { "Discarded-X400-IPMS-Extensions", "imf.discarded_x400_ipms_extensions", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_discarded_x400_mts_extensions,
      { "Discarded-X400-MTS-Extensions", "imf.discarded_x400_mts_extensions", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_dl_expansion_history,
        { "DL-Expansion-History", "imf.dl_expansion_history", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_deferred_delivery,
        { "Deferred-Delivery", "imf.deferred_delivery", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_expires,
        { "Expires", "imf.expires", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_importance,
      { "Importance", "imf.importance", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_incomplete_copy,
        { "Incomplete-Copy", "imf.incomplete_copy", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_latest_delivery_time,
      { "Latest-Delivery-Time", "imf.latest_delivery_time", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_message_type,
        { "Message-Type", "imf.message_type", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_original_encoded_information_types,
        { "Original-Encoded-Information-Types", "imf.original_encoded_information_types", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_originator_return_address,
        { "Originator-Return-Address", "imf.originator_return_address", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_priority,
        { "Priority", "imf.priority", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_reply_by,
        { "Reply-By", "imf.reply_by", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_sensitivity,
        { "Sensitivity", "imf.sensitivity", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_supersedes,
        { "Supersedes", "imf.supersedes", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_x400_content_type,
        { "X400-Content-Type", "imf.x400_content_type", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_x400_mts_identifier,
        { "X400-MTS-Identifier", "imf.x400_mts_identifier", FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},
    { &hf_imf_x400_originator,
        { "X400-Originator", "imf.x400_originator", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_x400_received,
        { "X400-Received", "imf.x400_received", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_x400_recipients,
        { "X400-Recipients", "imf.x400_recipients", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_delivered_to,
      { "Delivered-To", "imf.delivered_to", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_ext_mailer,
      { "X-Mailer", "imf.ext.mailer", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_ext_mimeole,
      { "X-MimeOLE", "imf.ext.mimeole", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_ext_expiry_date,
      { "Expiry-Date", "imf.ext.expiry-date", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_ext_tnef_correlator,
      { "X-MS-TNEF-Correlator", "imf.ext.tnef-correlator", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_ext_uidl,
      { "X-UIDL", "imf.ext.uidl", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_ext_authentication_warning,
      { "X-Authentication-Warning", "imf.ext.authentication_warning", FT_STRING,  BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_imf_ext_virus_scanned,
      { "X-Virus-Scanned", "imf.ext.virus_scanned", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_ext_original_to,
      { "X-Original-To", "imf.ext.original-to", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_thread_index,
      { "Thread-Index", "imf.thread-index", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_lines,
      { "Lines", "imf.lines", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_precedence,
      { "Precedence", "imf.precedence", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_extension,
      { "Unknown-Extension", "imf.extension", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_extension_type,
      { "Type", "imf.extension.type", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_extension_value,
      { "Value", "imf.extension.value", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_display_name,
      { "Display-Name", "imf.display_name", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_address,
      { "Address", "imf.address", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
#if 0
    { &hf_imf_address_list,
      { "Address List", "imf.address_list", FT_UINT32,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
#endif
    { &hf_imf_address_list_item,
      { "Item", "imf.address_list.item", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
#if 0
    { &hf_imf_mailbox_list,
      { "Mailbox List", "imf.mailbox_list", FT_UINT32,  BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
#endif
    { &hf_imf_mailbox_list_item,
      { "Item", "imf.mailbox_list.item", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_siolabel,
      { "SIO-Label", "imf.siolabel", FT_NONE,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_siolabel_marking,
      { "Marking", "imf.siolabel.marking", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_siolabel_fgcolor,
      { "Foreground Color", "imf.siolabel.fgcolor", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_siolabel_bgcolor,
      { "Background Color", "imf.siolabel.bgcolor", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_siolabel_type,
      { "Type", "imf.siolabel.type", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_siolabel_label,
      { "Label", "imf.siolabel.label", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_siolabel_unknown,
      { "Unknown parameter", "imf.siolabel.unknown", FT_STRING,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_imf_message_text,
      { "Message-Text", "imf.message_text", FT_NONE,  BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_imf,
    &ett_imf_content_type,
    &ett_imf_group,
    &ett_imf_mailbox,
    &ett_imf_mailbox_list,
    &ett_imf_address_list,
    &ett_imf_siolabel,
    &ett_imf_extension,
    &ett_imf_message_text,
  };

  static ei_register_info ei[] = {
     { &ei_imf_unknown_param, { "imf.unknown_param", PI_PROTOCOL, PI_WARN, "Unknown parameter", EXPFILL }},
  };

  static uat_field_t attributes_flds[] = {
    UAT_FLD_CSTRING(header_fields, header_name, "Header name", "IMF header name"),
    UAT_FLD_CSTRING(header_fields, description, "Description", "Description of the value contained in the header"),
    UAT_FLD_VS(header_fields, header_format, "Format", header_format, 0),
    UAT_FLD_VS(header_fields, add_to_col_info, "Add to Info column", add_to_col_info, 0),
    UAT_END_FIELDS
  };

  uat_t *headers_uat = uat_new("Custom IMF headers",
                               sizeof(header_field_t),
                               "imf_header_fields",
                               TRUE,
                               &header_fields,
                               &num_header_fields,
                               /* specifies named fields, so affects dissection
                                  and the set of named fields */
                               UAT_AFFECTS_DISSECTION|UAT_AFFECTS_FIELDS,
                               NULL,
                               header_fields_copy_cb,
                               header_fields_update_cb,
                               header_fields_free_cb,
                               header_fields_post_update_cb,
                               header_fields_reset_cb,
                               attributes_flds);

  module_t *imf_module;
  expert_module_t* expert_imf;
  struct imf_field *f;

  proto_imf = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_imf, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_imf = expert_register_protocol(proto_imf);
  expert_register_field_array(expert_imf, ei, array_length(ei));

  /* Allow dissector to find be found by name. */
  imf_handle = register_dissector(PFNAME, dissect_imf, proto_imf);

  imf_module = prefs_register_protocol(proto_imf, NULL);
  prefs_register_uat_preference(imf_module, "custom_header_fields", "Custom IMF headers",
                                "A table to define custom IMF headers for which fields can be "
                                "setup and used for filtering/data extraction etc.",
                                headers_uat);

  imf_field_table=wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal); /* oid to syntax */

  /* register the fields for lookup */
  for(f = imf_fields; f->name; f++)
    wmem_map_insert(imf_field_table, (gpointer)f->name, (gpointer)f);

  /* Register for tapping */
  imf_eo_tap = register_export_object(proto_imf, imf_eo_packet, NULL);

}

/* The registration hand-off routine */
void
proto_reg_handoff_imf(void)
{
  dissector_add_string("media_type",
                       "message/rfc822", imf_handle);

  register_ber_oid_dissector_handle("1.2.840.113549.1.7.1", imf_handle, proto_imf, "id-data");

  /*
   * Get the content type and Internet media type table
   */
  media_type_dissector_table = find_dissector_table("media_type");

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
