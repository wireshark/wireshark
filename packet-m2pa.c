/* packet-m2pa.c
 * Routines for MTP2 Peer Adaptation Layer dissection
 * It is hopefully (needs testing) compliant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m2pa-05.txt
 *
 * Copyright 2001, 2002, Jeff Morriss <jeff.morriss[AT]ulticom.com>, 
 * updated by Michael Tuexen <michael.tuexen[AT]siemens.com>
 *
 * $Id: packet-m2pa.c,v 1.11 2002/08/27 19:28:23 tuexen Exp $
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

#define NETWORK_BYTE_ORDER          FALSE
#define SCTP_PORT_M2PA              3565
#define M2PA_PAYLOAD_PROTOCOL_ID    5

static int proto_m2pa      = -1;
static int hf_version      = -1;
static int hf_spare        = -1;
static int hf_type         = -1;
static int hf_class        = -1;
static int hf_length       = -1;
static int hf_unused       = -1;
static int hf_bsn          = -1;
static int hf_fsn          = -1;
static int hf_status       = -1;
static int hf_li_spare     = -1;
static int hf_li_prio      = -1;
static int hf_filler       = -1;
static int hf_unknown_data = -1;

static gint ett_m2pa       = -1;
static gint ett_m2pa_li    = -1;

static int mtp3_proto_id;
static dissector_handle_t mtp3_handle;

#define VERSION_LENGTH         1
#define SPARE_LENGTH           1
#define CLASS_LENGTH           1
#define TYPE_LENGTH            1
#define LENGTH_LENGTH          4
#define UNUSED_LENGTH          1
#define BSN_LENGTH             3
#define FSN_LENGTH             3

#define HEADER_LENGTH          (VERSION_LENGTH + SPARE_LENGTH + \
                                CLASS_LENGTH + TYPE_LENGTH + LENGTH_LENGTH + \
                                UNUSED_LENGTH + BSN_LENGTH + UNUSED_LENGTH + FSN_LENGTH)

#define HEADER_OFFSET          0
#define VERSION_OFFSET         HEADER_OFFSET
#define SPARE_OFFSET           (VERSION_OFFSET + VERSION_LENGTH)
#define CLASS_OFFSET           (SPARE_OFFSET + SPARE_LENGTH)
#define TYPE_OFFSET            (CLASS_OFFSET + CLASS_LENGTH)
#define LENGTH_OFFSET          (TYPE_OFFSET + TYPE_LENGTH)
#define FIRST_UNUSED_OFFSET    (LENGTH_OFFSET + LENGTH_LENGTH)
#define BSN_OFFSET             (FIRST_UNUSED_OFFSET + UNUSED_LENGTH)
#define SECOND_UNUSED_OFFSET   (BSN_OFFSET + BSN_LENGTH)
#define FSN_OFFSET             (SECOND_UNUSED_OFFSET + UNUSED_LENGTH)

#define PROTOCOL_VERSION_RELEASE_1        1

static const value_string protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };

#define MESSAGE_CLASS_M2PA                0xb

static const value_string message_class_values[] = {
  { MESSAGE_CLASS_M2PA,          "M2PA" },
  { 0,                           NULL } };

#define MESSAGE_TYPE_USER_DATA            0x1
#define MESSAGE_TYPE_LINK_STATUS          0x2

static const value_string message_type_values[] = {
  { MESSAGE_TYPE_USER_DATA,     "User Data" },
  { MESSAGE_TYPE_LINK_STATUS,   "Link Status" },
  { 0,                           NULL } };

static void
dissect_m2pa_header(tvbuff_t *header_tvb, proto_tree *m2pa_tree)
{
  if (m2pa_tree) {
    proto_tree_add_item(m2pa_tree, hf_version, header_tvb, VERSION_OFFSET,       VERSION_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_spare,   header_tvb, SPARE_OFFSET,         SPARE_LENGTH,   NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_class,   header_tvb, CLASS_OFFSET,         CLASS_LENGTH,   NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_type,    header_tvb, TYPE_OFFSET,          TYPE_LENGTH,    NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_length,  header_tvb, LENGTH_OFFSET,        LENGTH_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_unused,  header_tvb, FIRST_UNUSED_OFFSET,  UNUSED_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_bsn,     header_tvb, BSN_OFFSET,           BSN_LENGTH,     NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_unused,  header_tvb, SECOND_UNUSED_OFFSET, UNUSED_LENGTH,  NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_tree, hf_fsn,     header_tvb, FSN_OFFSET,           FSN_LENGTH,     NETWORK_BYTE_ORDER);
  }
}

#define LI_OFFSET             0
#define LI_LENGTH             1
#define MTP3_OFFSET           (LI_OFFSET + LI_LENGTH)
#define LI_SPARE_MASK         0x3f
#define LI_PRIORITY_MASK      0xc0

static void
dissect_m2pa_user_data_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  proto_item *m2pa_li_item;
  proto_tree *m2pa_li_tree;
  tvbuff_t *payload_tvb;

  if (m2pa_tree) {
    m2pa_li_item = proto_tree_add_text(m2pa_tree, message_data_tvb, LI_OFFSET, LI_LENGTH, "Length Indicator");
    m2pa_li_tree = proto_item_add_subtree(m2pa_li_item, ett_m2pa_li);
    proto_tree_add_item(m2pa_li_tree, hf_li_prio,  message_data_tvb, LI_OFFSET, LI_LENGTH, NETWORK_BYTE_ORDER);
    proto_tree_add_item(m2pa_li_tree, hf_li_spare, message_data_tvb, LI_OFFSET, LI_LENGTH, NETWORK_BYTE_ORDER);
    /* Re-adjust length of M2PA item since it will be dissected as MTP3 */
    proto_item_set_len(m2pa_item, HEADER_LENGTH + LI_LENGTH);
  }

  payload_tvb = tvb_new_subset(message_data_tvb, MTP3_OFFSET, -1, -1);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
  if (!(proto_is_protocol_enabled (mtp3_proto_id)))
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_str(pinfo->cinfo, COL_INFO, "User Data ");
}

#define STATUS_LENGTH    4
#define STATUS_OFFSET    0
#define FILLER_OFFSET    (STATUS_OFFSET + STATUS_LENGTH)

#define STATUS_ALIGNMENT              1
#define STATUS_PROVING_NORMAL         2
#define STATUS_PROVING_EMERGENCY      3
#define STATUS_READY                  4
#define STATUS_PROCESSOR_OUTAGE       5
#define STATUS_PROCESSOR_OUTAGE_ENDED 6
#define STATUS_BUSY                   7
#define STATUS_BUSY_ENDED             8
#define STATUS_OUT_OF_SERVICE         9
#define STATUS_IN_SERVICE            10

static const value_string link_status_values[] = {
  { STATUS_ALIGNMENT,                "Alignment" },
  { STATUS_PROVING_NORMAL,           "Proving Normal" },
  { STATUS_PROVING_EMERGENCY,        "Proving Emergency" },
  { STATUS_READY,                    "Ready" },    
  { STATUS_PROCESSOR_OUTAGE,         "Processor Outage" },
  { STATUS_PROCESSOR_OUTAGE_ENDED,   "Processor Outage Ended" },
  { STATUS_BUSY,                     "Busy" },
  { STATUS_BUSY_ENDED,               "Busy Ended" },
  { STATUS_OUT_OF_SERVICE,           "Out of Service" },
  { STATUS_IN_SERVICE,               "In Service" },
  { 0,                               NULL } };

static void
dissect_m2pa_link_status_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_tree *m2pa_tree)
{
  guint16 filler_length;
  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "Link status ");
  if (m2pa_tree) {
    filler_length = tvb_length(message_data_tvb) - STATUS_LENGTH;
    proto_tree_add_item(m2pa_tree, hf_status, message_data_tvb, STATUS_OFFSET, STATUS_LENGTH, NETWORK_BYTE_ORDER);
    if (filler_length > 0)
      proto_tree_add_item(m2pa_tree, hf_filler, message_data_tvb, FILLER_OFFSET, filler_length, NETWORK_BYTE_ORDER);
  }
}

static void
dissect_m2pa_unknown_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_tree *m2pa_tree)
{  
  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_str(pinfo->cinfo, COL_INFO, "Unknown ");
  if (m2pa_tree)
    proto_tree_add_item(m2pa_tree, hf_unknown_data, message_data_tvb, 0, tvb_length(message_data_tvb), NETWORK_BYTE_ORDER);
}

#define MESSAGE_DATA_OFFSET (HEADER_OFFSET + HEADER_LENGTH)

static void
dissect_m2pa_message_data(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  guint32 message_data_length;
  guint8 type;
  tvbuff_t *message_data_tvb;

  message_data_length = tvb_get_ntohl(message_tvb,  LENGTH_OFFSET) - HEADER_LENGTH;
  message_data_tvb    = tvb_new_subset(message_tvb, MESSAGE_DATA_OFFSET, message_data_length, message_data_length);
  type                = tvb_get_guint8(message_tvb, TYPE_OFFSET);

  switch(type) {
  case MESSAGE_TYPE_USER_DATA:
    dissect_m2pa_user_data_message(message_data_tvb, pinfo, m2pa_item, m2pa_tree, tree);
    break;

  case MESSAGE_TYPE_LINK_STATUS:
    dissect_m2pa_link_status_message(message_data_tvb, pinfo, m2pa_tree);
    break;

  default:
    dissect_m2pa_unknown_message(message_data_tvb, pinfo, m2pa_tree);
  }

}
static void
dissect_m2pa_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  tvbuff_t *header_tvb;

  header_tvb = tvb_new_subset(message_tvb, HEADER_OFFSET, HEADER_LENGTH, HEADER_LENGTH);
  dissect_m2pa_header(header_tvb, m2pa_tree);
  dissect_m2pa_message_data(message_tvb, pinfo, m2pa_item, m2pa_tree, tree);
}

static void
dissect_m2pa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *m2pa_item;
  proto_tree *m2pa_tree;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "M2PA");

  if (tree) {
    m2pa_item = proto_tree_add_item(tree, proto_m2pa, tvb, 0, -1, FALSE);
    m2pa_tree = proto_item_add_subtree(m2pa_item, ett_m2pa);
  } else {
    m2pa_item = NULL;
    m2pa_tree = NULL;
  };

  dissect_m2pa_message(tvb, pinfo, m2pa_item, m2pa_tree, tree);
}

void
proto_register_m2pa(void)
{
  static hf_register_info hf[] = {
    { &hf_version,      { "Version",        "m2pa.version",      FT_UINT8,  BASE_DEC,  VALS(protocol_version_values), 0x0,              "", HFILL} },
    { &hf_spare,        { "Spare",          "m2pa.spare",        FT_UINT8,  BASE_HEX,  NULL,                          0x0,              "", HFILL} },
    { &hf_type,         { "Message Type",   "m2pa.type",         FT_UINT8,  BASE_DEC,  VALS(message_type_values),     0x0,              "", HFILL} },
    { &hf_class,        { "Message Class",  "m2pa.class",        FT_UINT8,  BASE_DEC,  VALS(message_class_values),    0x0,              "", HFILL} },
    { &hf_length,       { "Message length", "m2pa.length",       FT_UINT32, BASE_DEC,  NULL,                          0x0,              "", HFILL} },
    { &hf_unused,       { "Unused",         "m2pa.unused",       FT_UINT8,  BASE_DEC,  NULL,                          0x0,              "", HFILL} },
    { &hf_bsn,          { "BSN",            "m2pa.bsn",          FT_UINT24, BASE_DEC,  NULL,                          0x0,              "", HFILL} },
    { &hf_fsn,          { "FSN",            "m2pa.fsn",          FT_UINT24, BASE_DEC,  NULL,                          0x0,              "", HFILL} },
    { &hf_li_spare,     { "Spare",          "m2pa.li_spare",     FT_UINT8,  BASE_HEX,  NULL,                          LI_SPARE_MASK,    "", HFILL} },
    { &hf_li_prio,      { "Priority",       "m2pa.li_priority",  FT_UINT8,  BASE_HEX,  NULL,                          LI_PRIORITY_MASK, "", HFILL} },
    { &hf_status,       { "Link Status",    "m2pa.status",       FT_UINT32, BASE_DEC,  VALS(link_status_values),      0x0,              "", HFILL} },
    { &hf_filler,       { "Filler",         "m2pa.filler",       FT_BYTES,  BASE_NONE, NULL,                          0x0,              "", HFILL } },
    { &hf_unknown_data, { "Unknown Data",   "m2pa.unknown_data", FT_BYTES,  BASE_NONE, NULL,                          0x0,              "", HFILL } }
  };

  static gint *ett[] = {
    &ett_m2pa,
    &ett_m2pa_li
  };

  proto_m2pa = proto_register_protocol("MTP2 Peer Adaptation Layer (draft-ietf-sigtran-m2pa-05.txt)", "M2PA", "m2pa");

  proto_register_field_array(proto_m2pa, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_m2pa(void)
{
  dissector_handle_t m2pa_handle;

  mtp3_handle   = find_dissector("mtp3");
  mtp3_proto_id = proto_get_id_by_filter_name("mtp3");
  m2pa_handle   = create_dissector_handle(dissect_m2pa, proto_m2pa);
  dissector_add("sctp.ppi",  M2PA_PAYLOAD_PROTOCOL_ID, m2pa_handle);
  dissector_add("sctp.port", SCTP_PORT_M2PA,           m2pa_handle);
}