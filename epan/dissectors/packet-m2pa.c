/* packet-m2pa.c
 * Routines for MTP2 Peer Adaptation Layer dissection
 * It is hopefully (needs testing) compliant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m2pa-02.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m2pa-08.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m2pa-12.txt
 *
 * Copyright 2001, 2002, Jeff Morriss <jeff.morriss[AT]ulticom.com>,
 * updated by Michael Tuexen <tuexen [AT] fh-muenster.de>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-m3ua.c
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>

#define NETWORK_BYTE_ORDER          FALSE
#define SCTP_PORT_M2PA              3565

static guint global_sctp_port       = SCTP_PORT_M2PA;
static guint sctp_port              = 0;

void proto_reg_handoff_m2pa(void);

static int proto_m2pa      = -1;
static module_t *m2pa_module;

static int hf_version      = -1;
static int hf_spare        = -1;
static int hf_v2_type      = -1;
static int hf_v8_type      = -1;
static int hf_v12_type     = -1;
static int hf_class        = -1;
static int hf_length       = -1;
static int hf_unused       = -1;
static int hf_bsn          = -1;
static int hf_fsn          = -1;
static int hf_v2_status    = -1;
static int hf_v8_status    = -1;
static int hf_v12_status   = -1;
static int hf_v2_li_spare  = -1;
static int hf_v8_li_spare  = -1;
static int hf_v2_li_prio   = -1;
static int hf_v8_li_prio   = -1;
static int hf_filler       = -1;
static int hf_unknown_data = -1;
static int hf_pri_prio     = -1;
static int hf_pri_spare    = -1;

static gint ett_m2pa       = -1;
static gint ett_m2pa_li    = -1;

static int mtp3_proto_id;
static dissector_handle_t mtp3_handle;

typedef enum {
  M2PA_V02 = 1,
  M2PA_V08 = 2,
  M2PA_V12 = 3
} Version_Type;

static gint m2pa_version = M2PA_V12;

#define VERSION_LENGTH         1
#define SPARE_LENGTH           1
#define CLASS_LENGTH           1
#define V2_TYPE_LENGTH         2
#define V8_TYPE_LENGTH         1
#define V12_TYPE_LENGTH        V8_TYPE_LENGTH
#define LENGTH_LENGTH          4
#define UNUSED_LENGTH          1
#define BSN_LENGTH             3
#define FSN_LENGTH             3

#define V2_HEADER_LENGTH        (VERSION_LENGTH + SPARE_LENGTH + \
                                V2_TYPE_LENGTH + LENGTH_LENGTH)
                                
#define V8_HEADER_LENGTH        (VERSION_LENGTH + SPARE_LENGTH + \
                                CLASS_LENGTH + V8_TYPE_LENGTH + LENGTH_LENGTH + \
                                UNUSED_LENGTH + BSN_LENGTH + UNUSED_LENGTH + \
                                FSN_LENGTH)
#define V12_HEADER_LENGTH       V8_HEADER_LENGTH

#define HEADER_OFFSET          0
#define VERSION_OFFSET         HEADER_OFFSET
#define SPARE_OFFSET           (VERSION_OFFSET + VERSION_LENGTH)
#define CLASS_OFFSET           (SPARE_OFFSET + SPARE_LENGTH)
#define V2_TYPE_OFFSET         (SPARE_OFFSET + SPARE_LENGTH)
#define V8_TYPE_OFFSET         (CLASS_OFFSET + CLASS_LENGTH)
#define V12_TYPE_OFFSET        V8_TYPE_OFFSET
#define V8_LENGTH_OFFSET       (V8_TYPE_OFFSET + V8_TYPE_LENGTH)
#define V12_LENGTH_OFFSET      V8_LENGTH_OFFSET
#define V2_LENGTH_OFFSET       (V2_TYPE_OFFSET + V2_TYPE_LENGTH)
#define FIRST_UNUSED_OFFSET    (V8_LENGTH_OFFSET + LENGTH_LENGTH)
#define BSN_OFFSET             (FIRST_UNUSED_OFFSET + UNUSED_LENGTH)
#define SECOND_UNUSED_OFFSET   (BSN_OFFSET + BSN_LENGTH)
#define FSN_OFFSET             (SECOND_UNUSED_OFFSET + UNUSED_LENGTH)

static const value_string protocol_version_values[] = {
  { 1,      "Release 1" },
  { 0,      NULL } };

static const value_string message_class_values[] = {
  { 0xb,    "M2PA" },
  { 0,      NULL } };
  
#define V2_USER_DATA_TYPE   0x0601
#define V2_LINK_STATUS_TYPE 0x0602

static const value_string v2_message_type_values[] = {
  { V2_USER_DATA_TYPE,   "User Data" },
  { V2_LINK_STATUS_TYPE, "Link Status" },
  { 0,                   NULL } };

#define V8_USER_DATA_TYPE   0x0001
#define V8_LINK_STATUS_TYPE 0x0002

static const value_string v8_message_type_values[] = {
  { V8_USER_DATA_TYPE,   "User Data" },
  { V8_LINK_STATUS_TYPE, "Link Status" },
  { 0,                   NULL } };

#define V12_USER_DATA_TYPE   V8_USER_DATA_TYPE
#define V12_LINK_STATUS_TYPE V8_LINK_STATUS_TYPE

static const value_string v12_message_type_values[] = {
  { V12_USER_DATA_TYPE,   "User Data" },
  { V12_LINK_STATUS_TYPE, "Link Status" },
  { 0,                   NULL } };

static void
dissect_v2_header(tvbuff_t *header_tvb, packet_info *pinfo, proto_tree *m2pa_tree)
{
  guint16 message_type;
  
  message_type  = tvb_get_ntohs(header_tvb, V2_TYPE_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_type, v2_message_type_values, "reserved"));

  if (m2pa_tree) {
    proto_tree_add_item(m2pa_tree, hf_version, header_tvb, VERSION_OFFSET,       VERSION_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_spare,   header_tvb, SPARE_OFFSET,         SPARE_LENGTH,   NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_v2_type, header_tvb, V2_TYPE_OFFSET,       V2_TYPE_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_length,  header_tvb, V2_LENGTH_OFFSET,     LENGTH_LENGTH,  NETWORK_BYTE_ORDER);
  }
}

static void
dissect_v8_header(tvbuff_t *header_tvb, packet_info *pinfo, proto_tree *m2pa_tree)
{
  guint8 message_type;
  
  message_type  = tvb_get_guint8(header_tvb, V8_TYPE_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_type, v8_message_type_values, "Unknown"));

  if (m2pa_tree) {
    proto_tree_add_item(m2pa_tree, hf_version, header_tvb, VERSION_OFFSET,       VERSION_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_spare,   header_tvb, SPARE_OFFSET,         SPARE_LENGTH,   NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_class,   header_tvb, CLASS_OFFSET,         CLASS_LENGTH,   NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_v8_type, header_tvb, V8_TYPE_OFFSET,       V8_TYPE_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_length,  header_tvb, V8_LENGTH_OFFSET,     LENGTH_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_unused,  header_tvb, FIRST_UNUSED_OFFSET,  UNUSED_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_bsn,     header_tvb, BSN_OFFSET,           BSN_LENGTH,     NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_unused,  header_tvb, SECOND_UNUSED_OFFSET, UNUSED_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_fsn,     header_tvb, FSN_OFFSET,           FSN_LENGTH,     NETWORK_BYTE_ORDER);
  }
}

static void
dissect_v12_header(tvbuff_t *header_tvb, packet_info *pinfo, proto_tree *m2pa_tree)
{
  guint8 message_type;
  
  message_type  = tvb_get_guint8(header_tvb, V8_TYPE_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(message_type, v8_message_type_values, "Unknown"));

  if (m2pa_tree) {
    proto_tree_add_item(m2pa_tree, hf_version,  header_tvb, VERSION_OFFSET,       VERSION_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_spare,    header_tvb, SPARE_OFFSET,         SPARE_LENGTH,    NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_class,    header_tvb, CLASS_OFFSET,         CLASS_LENGTH,    NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_v12_type, header_tvb, V12_TYPE_OFFSET,      V12_TYPE_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_length,   header_tvb, V12_LENGTH_OFFSET,    LENGTH_LENGTH,   NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_unused,   header_tvb, FIRST_UNUSED_OFFSET,  UNUSED_LENGTH,   NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_bsn,      header_tvb, BSN_OFFSET,           BSN_LENGTH,      NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_unused,   header_tvb, SECOND_UNUSED_OFFSET, UNUSED_LENGTH,   NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_fsn,      header_tvb, FSN_OFFSET,           FSN_LENGTH,      NETWORK_BYTE_ORDER);
  }
}

#define LI_OFFSET           0
#define LI_LENGTH           1
#define MTP3_OFFSET         (LI_OFFSET + LI_LENGTH)

#define V2_LI_SPARE_MASK    0xfc
#define V2_LI_PRIORITY_MASK 0x3

static void
dissect_v2_user_data_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  proto_item *m2pa_li_item;
  proto_tree *m2pa_li_tree;
  tvbuff_t *payload_tvb;

  if (tvb_length(message_data_tvb) > 0) {
    if (m2pa_tree) {
      m2pa_li_item = proto_tree_add_text(m2pa_tree, message_data_tvb, LI_OFFSET, LI_LENGTH, "Length Indicator");
      m2pa_li_tree = proto_item_add_subtree(m2pa_li_item, ett_m2pa_li);

      proto_tree_add_item(m2pa_li_tree, hf_v2_li_spare, message_data_tvb, LI_OFFSET, LI_LENGTH, NETWORK_BYTE_ORDER);
      proto_tree_add_item(m2pa_li_tree, hf_v2_li_prio,  message_data_tvb, LI_OFFSET, LI_LENGTH, NETWORK_BYTE_ORDER);

      /* Re-adjust length of M2PA item since it will be dissected as MTP3 */
      proto_item_set_len(m2pa_item, V2_HEADER_LENGTH + LI_LENGTH);
     }
  }

  payload_tvb = tvb_new_subset(message_data_tvb, MTP3_OFFSET, -1, -1);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
}

#define V8_LI_SPARE_MASK        0x3f
#define V8_LI_PRIORITY_MASK     0xc0

static void
dissect_v8_user_data_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  proto_item *m2pa_li_item;
  proto_tree *m2pa_li_tree;
  tvbuff_t *payload_tvb;

  if (tvb_length(message_data_tvb) > 0) {
    if (m2pa_tree) {
      m2pa_li_item = proto_tree_add_text(m2pa_tree, message_data_tvb, LI_OFFSET, LI_LENGTH, "Length Indicator");
      m2pa_li_tree = proto_item_add_subtree(m2pa_li_item, ett_m2pa_li);
      proto_tree_add_item(m2pa_li_tree, hf_v8_li_prio,  message_data_tvb, LI_OFFSET, LI_LENGTH, NETWORK_BYTE_ORDER);
      proto_tree_add_item(m2pa_li_tree, hf_v8_li_spare, message_data_tvb, LI_OFFSET, LI_LENGTH, NETWORK_BYTE_ORDER);

        /* Re-adjust length of M2PA item since it will be dissected as MTP3 */
      proto_item_set_len(m2pa_item, V8_HEADER_LENGTH + LI_LENGTH);
    }

    payload_tvb = tvb_new_subset(message_data_tvb, MTP3_OFFSET, -1, -1);
    call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
  }
}

#define PRIORITY_MASK     0xc0
#define SPARE_MASK        0x3f

#define PRI_OFFSET           0
#define PRI_LENGTH           1

static void
dissect_v12_user_data_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  proto_item *m2pa_li_item;
  proto_tree *m2pa_li_tree;
  tvbuff_t *payload_tvb;

  if (tvb_length(message_data_tvb) > 0) {
    if (m2pa_tree) {
      m2pa_li_item = proto_tree_add_text(m2pa_tree, message_data_tvb, PRI_OFFSET, PRI_LENGTH, "Priority");
      m2pa_li_tree = proto_item_add_subtree(m2pa_li_item, ett_m2pa_li);
      proto_tree_add_item(m2pa_li_tree, hf_pri_prio,  message_data_tvb, PRI_OFFSET, PRI_LENGTH, NETWORK_BYTE_ORDER);
      proto_tree_add_item(m2pa_li_tree, hf_pri_spare, message_data_tvb, PRI_OFFSET, PRI_LENGTH, NETWORK_BYTE_ORDER);

        /* Re-adjust length of M2PA item since it will be dissected as MTP3 */
      proto_item_set_len(m2pa_item, V12_HEADER_LENGTH + PRI_LENGTH);
    }

    payload_tvb = tvb_new_subset(message_data_tvb, MTP3_OFFSET, -1, -1);
    call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
  }
}

static const value_string v2_link_status_values[] = {
  { 1, "In Service" },
  { 2, "Processor Outage" },
  { 3, "Processor Outage Ended" },
  { 4, "Busy" },
  { 5, "Busy Ended" },
  { 0, NULL } };

#define STATUS_LENGTH    4
#define STATUS_OFFSET    0
#define FILLER_OFFSET    (STATUS_OFFSET + STATUS_LENGTH)

static void
dissect_v2_link_status_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_tree *m2pa_tree)
{
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ", val_to_str(tvb_get_ntohl(message_data_tvb, STATUS_OFFSET), v2_link_status_values, "Unknown"));
  if (m2pa_tree)
    proto_tree_add_item(m2pa_tree, hf_v2_status, message_data_tvb, STATUS_OFFSET, STATUS_LENGTH, NETWORK_BYTE_ORDER);
}

static const value_string v8_link_status_values[] = {
  { 1, "Alignment" },
  { 2, "Proving Normal" },
  { 3, "Proving Emergency" },
  { 4, "Ready" },
  { 5, "Processor Outage" },
  { 6, "Processor Outage Ended" },
  { 7, "Busy" },
  { 8, "Busy Ended" },
  { 9, "Out of Service" },
  { 0, NULL } };

static void
dissect_v8_link_status_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_tree *m2pa_tree)
{
  guint16 filler_length;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ", val_to_str(tvb_get_ntohl(message_data_tvb, STATUS_OFFSET), v8_link_status_values, "Unknown"));

  filler_length = tvb_length(message_data_tvb) - STATUS_LENGTH;
  
  proto_tree_add_item(m2pa_tree, hf_v8_status, message_data_tvb, STATUS_OFFSET, STATUS_LENGTH, NETWORK_BYTE_ORDER);
  if (filler_length > 0)
      proto_tree_add_item(m2pa_tree, hf_filler, message_data_tvb, FILLER_OFFSET, filler_length, NETWORK_BYTE_ORDER);
}

static const value_string v12_link_status_values[] = {
  { 1, "Alignment" },
  { 2, "Proving Normal" },
  { 3, "Proving Emergency" },
  { 4, "Ready" },
  { 5, "Processor Outage" },
  { 6, "Processor Outage Ended" },
  { 7, "Busy" },
  { 8, "Busy Ended" },
  { 9, "Out of Service" },
  { 0, NULL } };

static void
dissect_v12_link_status_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_tree *m2pa_tree)
{
  guint16 filler_length;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ", val_to_str(tvb_get_ntohl(message_data_tvb, STATUS_OFFSET), v12_link_status_values, "Unknown"));

  filler_length = tvb_length(message_data_tvb) - STATUS_LENGTH;
  
  proto_tree_add_item(m2pa_tree, hf_v12_status, message_data_tvb, STATUS_OFFSET, STATUS_LENGTH, NETWORK_BYTE_ORDER);
  if (filler_length > 0)
      proto_tree_add_item(m2pa_tree, hf_filler, message_data_tvb, FILLER_OFFSET, filler_length, NETWORK_BYTE_ORDER);
}

static void
dissect_unknown_message(tvbuff_t *message_data_tvb, proto_tree *m2pa_tree)
{
  guint length;
   
  length = tvb_length(message_data_tvb);
  if ((m2pa_tree) && (length > 0))
    proto_tree_add_item(m2pa_tree, hf_unknown_data, message_data_tvb, 0, length, NETWORK_BYTE_ORDER);
}

#define V2_MESSAGE_DATA_OFFSET (HEADER_OFFSET + V2_HEADER_LENGTH)

static void
dissect_v2_message_data(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  guint32 message_data_length;
  guint16 type;
  tvbuff_t *message_data_tvb;

  message_data_length = tvb_get_ntohl(message_tvb, V2_LENGTH_OFFSET);
  message_data_tvb    = tvb_new_subset(message_tvb, V2_MESSAGE_DATA_OFFSET, message_data_length, message_data_length);
  type                = tvb_get_ntohs(message_tvb, V2_TYPE_OFFSET);

  switch(type) {
  case V2_USER_DATA_TYPE:
    dissect_v2_user_data_message(message_data_tvb, pinfo, m2pa_item, m2pa_tree, tree);
    break;
  case V2_LINK_STATUS_TYPE:
    dissect_v2_link_status_message(message_data_tvb, pinfo, m2pa_tree);
    break;
  default:
    dissect_unknown_message(message_data_tvb, m2pa_tree);
  }
}

#define V8_MESSAGE_DATA_OFFSET (HEADER_OFFSET + V8_HEADER_LENGTH)

static void
dissect_v8_message_data(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  guint32 message_data_length;
  guint8 type;
  tvbuff_t *message_data_tvb;

  message_data_length = tvb_get_ntohl(message_tvb, V8_LENGTH_OFFSET) - V8_HEADER_LENGTH;
  message_data_tvb    = tvb_new_subset(message_tvb, V8_MESSAGE_DATA_OFFSET, message_data_length, message_data_length);
  type                = tvb_get_guint8(message_tvb, V8_TYPE_OFFSET);


  switch(type) {
  case V8_USER_DATA_TYPE:
    dissect_v8_user_data_message(message_data_tvb, pinfo, m2pa_item, m2pa_tree, tree);
    break;
  case V8_LINK_STATUS_TYPE:
    dissect_v8_link_status_message(message_data_tvb, pinfo, m2pa_tree);
    break;
  default:
    dissect_unknown_message(message_data_tvb, m2pa_tree);
  }
}

#define V12_MESSAGE_DATA_OFFSET (HEADER_OFFSET + V12_HEADER_LENGTH)

static void
dissect_v12_message_data(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  guint32 message_data_length;
  guint8 type;
  tvbuff_t *message_data_tvb;

  message_data_length = tvb_get_ntohl(message_tvb, V12_LENGTH_OFFSET) - V8_HEADER_LENGTH;
  message_data_tvb    = tvb_new_subset(message_tvb, V12_MESSAGE_DATA_OFFSET, message_data_length, message_data_length);
  type                = tvb_get_guint8(message_tvb, V12_TYPE_OFFSET);


  switch(type) {
  case V12_USER_DATA_TYPE:
    dissect_v12_user_data_message(message_data_tvb, pinfo, m2pa_item, m2pa_tree, tree);
    break;
  case V12_LINK_STATUS_TYPE:
    dissect_v12_link_status_message(message_data_tvb, pinfo, m2pa_tree);
    break;
  default:
    dissect_unknown_message(message_data_tvb, m2pa_tree);
  }
}

static void
dissect_v2_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  dissect_v2_header(message_tvb, pinfo, m2pa_tree);
  dissect_v2_message_data(message_tvb, pinfo, m2pa_item, m2pa_tree, tree);
}

static void
dissect_v8_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  dissect_v8_header(message_tvb, pinfo, m2pa_tree);
  dissect_v8_message_data(message_tvb, pinfo, m2pa_item, m2pa_tree, tree);
}

static void
dissect_v12_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  dissect_v12_header(message_tvb, pinfo, m2pa_tree);
  dissect_v12_message_data(message_tvb, pinfo, m2pa_item, m2pa_tree, tree);
}

static void
dissect_m2pa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *m2pa_item;
  proto_tree *m2pa_tree;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    switch(m2pa_version) {
    case M2PA_V02:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "M2PA (ID 02)");
      break;
    case M2PA_V08:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "M2PA (ID 08)");
      break;
    case M2PA_V12:
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "M2PA (ID 12)");
      break;
    };      

  if (tree) {
    m2pa_item = proto_tree_add_item(tree, proto_m2pa, tvb, 0, -1, FALSE);
    m2pa_tree = proto_item_add_subtree(m2pa_item, ett_m2pa);
  } else {
    m2pa_item = NULL;
    m2pa_tree = NULL;
  }

  switch(m2pa_version) {
    case M2PA_V02:
      dissect_v2_message(tvb, pinfo, m2pa_item, m2pa_tree, tree);
      break;
    case M2PA_V08:
      dissect_v8_message(tvb, pinfo, m2pa_item, m2pa_tree, tree);
      break;
    case M2PA_V12:
      dissect_v12_message(tvb, pinfo, m2pa_item, m2pa_tree, tree);
      break;
  };      
}

void
proto_register_m2pa(void)
{
  static hf_register_info hf[] = 
  { { &hf_version,      { "Version",        "m2pa.version",        FT_UINT8,  BASE_DEC,  VALS(protocol_version_values), 0x0,                 "", HFILL} },
    { &hf_spare,        { "Spare",          "m2pa.spare",          FT_UINT8,  BASE_HEX,  NULL,                          0x0,                 "", HFILL} },
    { &hf_v2_type,      { "Message Type",   "m2pa.type",           FT_UINT16, BASE_HEX,  VALS(v2_message_type_values),  0x0,                 "", HFILL} },
    { &hf_v8_type,      { "Message Type",   "m2pa.type",           FT_UINT8,  BASE_DEC,  VALS(v8_message_type_values),  0x0,                 "", HFILL} },
    { &hf_v12_type,     { "Message Type",   "m2pa.type",           FT_UINT8,  BASE_DEC,  VALS(v12_message_type_values), 0x0,                 "", HFILL} },
    { &hf_class,        { "Message Class",  "m2pa.class",          FT_UINT8,  BASE_DEC,  VALS(message_class_values),    0x0,                 "", HFILL} },
    { &hf_length,       { "Message length", "m2pa.length",         FT_UINT32, BASE_DEC,  NULL,                          0x0,                 "", HFILL} },
    { &hf_unused,       { "Unused",         "m2pa.unused",         FT_UINT8,  BASE_DEC,  NULL,                          0x0,                 "", HFILL} },
    { &hf_bsn,          { "BSN",            "m2pa.bsn",            FT_UINT24, BASE_DEC,  NULL,                          0x0,                 "", HFILL} },
    { &hf_fsn,          { "FSN",            "m2pa.fsn",            FT_UINT24, BASE_DEC,  NULL,                          0x0,                 "", HFILL} },
    { &hf_v2_li_spare,  { "Spare",          "m2pa.li_spare",       FT_UINT8,  BASE_DEC,  NULL,                          V2_LI_SPARE_MASK,    "", HFILL} },
    { &hf_v8_li_spare,  { "Spare",          "m2pa.li_spare",       FT_UINT8,  BASE_HEX,  NULL,                          V8_LI_SPARE_MASK,    "", HFILL} },
    { &hf_pri_spare,    { "Spare",          "m2pa.priority_spare", FT_UINT8,  BASE_HEX,  NULL,                          SPARE_MASK,          "", HFILL} },
    { &hf_v2_li_prio,   { "Priority",       "m2pa.li_priority",    FT_UINT8,  BASE_DEC,  NULL,                          V2_LI_PRIORITY_MASK, "", HFILL} },
    { &hf_v8_li_prio,   { "Priority",       "m2pa.li_priority",    FT_UINT8,  BASE_HEX,  NULL,                          V8_LI_PRIORITY_MASK, "", HFILL} },
    { &hf_pri_prio,     { "Priority",       "m2pa.priority",       FT_UINT8,  BASE_HEX,  NULL,                          PRIORITY_MASK,       "", HFILL} },
    { &hf_v2_status,    { "Link Status",    "m2pa.status",         FT_UINT32, BASE_DEC,  VALS(v2_link_status_values),   0x0,                 "", HFILL} },
    { &hf_v8_status,    { "Link Status",    "m2pa.status",         FT_UINT32, BASE_DEC,  VALS(v8_link_status_values),   0x0,                 "", HFILL} },
    { &hf_v12_status,   { "Link Status",    "m2pa.status",         FT_UINT32, BASE_DEC,  VALS(v12_link_status_values),  0x0,                 "", HFILL} },
    { &hf_filler,       { "Filler",         "m2pa.filler",         FT_BYTES,  BASE_NONE, NULL,                          0x0,                 "", HFILL} },
    { &hf_unknown_data, { "Unknown Data",   "m2pa.unknown_data",   FT_BYTES,  BASE_NONE, NULL,                          0x0,                 "", HFILL} }
  };

  static gint *ett[] = {
    &ett_m2pa,
    &ett_m2pa_li
  };

  static enum_val_t m2pa_version_options[] = {
    { "draft-2",  "Internet Draft version 2",  M2PA_V02 },
    { "draft-8",  "Internet Draft version 8",  M2PA_V08 },
    { "draft-12", "Internet Draft version 12", M2PA_V12 },
    { NULL, NULL, 0 }
  };

  proto_m2pa = proto_register_protocol("MTP2 Peer Adaptation Layer", "M2PA", "m2pa");

  proto_register_field_array(proto_m2pa, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  m2pa_module = prefs_register_protocol(proto_m2pa, proto_reg_handoff_m2pa);

  prefs_register_enum_preference(m2pa_module, "version", "M2PA version", "Version used by Ethereal", &m2pa_version, m2pa_version_options, FALSE);
  prefs_register_uint_preference(m2pa_module, "port", "M2PA SCTP Port", "Set the port for M2PA messages (Default of 3565)", 10, &global_sctp_port);
}

void
proto_reg_handoff_m2pa(void)
{
  static int prefs_initialized = FALSE;
  static dissector_handle_t m2pa_handle;

  /* Port preferences code shamelessly copied from packet-beep.c */
  if (!prefs_initialized) {
    mtp3_handle   = find_dissector("mtp3");
    mtp3_proto_id = proto_get_id_by_filter_name("mtp3");
    m2pa_handle   = create_dissector_handle(dissect_m2pa, proto_m2pa);

    dissector_add("sctp.ppi", M2PA_PAYLOAD_PROTOCOL_ID, m2pa_handle);

    prefs_initialized = TRUE;

  } else {

    dissector_delete("sctp.port", sctp_port, m2pa_handle);

  }

  /* Set our port number for future use */
  sctp_port = global_sctp_port;

  dissector_add("sctp.port", sctp_port, m2pa_handle);
}
