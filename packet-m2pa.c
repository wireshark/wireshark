/* packet-m2pa.c
 * Routines for MTP2 Peer Adaptation Layer dissection
 * It is hopefully (needs testing) compliant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m2pa-04.txt
 *
 * Copyright 2001, Jeff Morriss <jeff.morriss[AT]ulticom.com>, 
 * updated by Michael Tuexen <michael.tuexen[AT]icn.siemens.de>
 *
 * $Id: packet-m2pa.c,v 1.7 2002/03/28 21:41:30 guy Exp $
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

#include <stdio.h>
#include <stdlib.h>


#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "prefs.h"

/* Warning:  Neither of these are standardized yet! */
#define SCTP_PORT_M2PA             2904
#define M2PA_PAYLOAD_PROTOCOL_ID   5

#define VERSION_LENGTH         1
#define SPARE_LENGTH           1
#define CLASS_LENGTH           1
#define TYPE_LENGTH            1
#define LENGTH_LENGTH          4
#define BSN_LENGTH             2
#define FSN_LENGTH             2

#define HEADER_LENGTH          (VERSION_LENGTH + SPARE_LENGTH + \
                                CLASS_LENGTH + TYPE_LENGTH + LENGTH_LENGTH + \
                                BSN_LENGTH + FSN_LENGTH)

#define VERSION_OFFSET         0
#define SPARE_OFFSET           (VERSION_OFFSET + VERSION_LENGTH)
#define CLASS_OFFSET           (SPARE_OFFSET + SPARE_LENGTH)
#define TYPE_OFFSET            (CLASS_OFFSET + CLASS_LENGTH)
#define LENGTH_OFFSET          (TYPE_OFFSET + TYPE_LENGTH)
#define BSN_OFFSET             (LENGTH_OFFSET + LENGTH_LENGTH)
#define FSN_OFFSET             (BSN_OFFSET + BSN_LENGTH)
#define HEADER_OFFSET          VERSION_OFFSET
#define MESSAGE_DATA_OFFSET    (HEADER_OFFSET + HEADER_LENGTH)

#define PROTOCOL_VERSION_RELEASE_1        1
static const value_string m2pa_protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };


#define MESSAGE_CLASS_M2PA                0xb

static const value_string m2pa_message_class_values[] = {
  { MESSAGE_CLASS_M2PA,          "M2PA" },
  { 0,                           NULL } };


#define MESSAGE_TYPE_USER_DATA            0x1
#define MESSAGE_TYPE_LINK_STATUS          0x2

static const value_string m2pa_message_type_values[] = {
  { MESSAGE_TYPE_USER_DATA,     "User Data" },
  { MESSAGE_TYPE_LINK_STATUS,   "Link Status" },
  { 0,                           NULL } };


/* parts of User Data message */
#define LI_OFFSET             0
#define LI_LENGTH             1
#define MTP3_OFFSET           (LI_OFFSET + LI_LENGTH)

/* LI is only used for (ITU national) priority in M2PA */
#define LI_SPARE_MASK              0xfc
#define LI_PRIORITY_MASK           0x3


/* parts of Link Status message */
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

static const value_string m2pa_link_status_values[] = {
  { STATUS_ALIGNMENT,                   "Alignment" },
  { STATUS_PROVING_NORMAL,              "Proving Normal" },
  { STATUS_PROVING_EMERGENCY,           "Proving Emergency" },
  { STATUS_READY,                       "Ready" },    
  { STATUS_PROCESSOR_OUTAGE,            "Processor Outage" },
  { STATUS_PROCESSOR_OUTAGE_ENDED,      "Processor Outage Ended" },
  { STATUS_BUSY,                        "Busy" },
  { STATUS_BUSY_ENDED,                  "Busy Ended" },
  { STATUS_OUT_OF_SERVICE,              "Out of Service" },
  { STATUS_IN_SERVICE,                  "In Service" },
  { 0,                                  NULL } };


/* Initialize the protocol and registered fields */
static int proto_m2pa = -1;
static int hf_m2pa_version = -1;
static int hf_m2pa_spare = -1;
static int hf_m2pa_type = -1;
static int hf_m2pa_class = -1;
static int hf_m2pa_length = -1;
static int hf_m2pa_bsn = -1;
static int hf_m2pa_fsn = -1;
static int hf_m2pa_status = -1;
static int hf_m2pa_li_spare = -1;
static int hf_m2pa_li_prio = -1;
static int hf_m2pa_filler = -1;
static int hf_m2pa_unknown_data = -1;
/* Initialize the subtree pointers */
static gint ett_m2pa = -1;
static gint ett_m2pa_li = -1;

static dissector_handle_t mtp3_handle;

static void
dissect_m2pa_user_data_message(tvbuff_t *message_data_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  proto_item *m2pa_li_item;
  proto_tree *m2pa_li_tree;
  tvbuff_t *payload_tvb;
  guint8 li;
  guint32 payload_length;

  payload_length = tvb_length(message_data_tvb) - LI_LENGTH;

  if (m2pa_tree) {
    li = tvb_get_guint8(message_data_tvb, LI_OFFSET);
    m2pa_li_item = proto_tree_add_text(m2pa_tree, message_data_tvb, LI_OFFSET, LI_LENGTH, "Length Indicator");
    m2pa_li_tree = proto_item_add_subtree(m2pa_li_item, ett_m2pa_li);
    proto_tree_add_uint(m2pa_li_tree, hf_m2pa_li_spare, message_data_tvb, LI_OFFSET, LI_LENGTH, li);
    proto_tree_add_uint(m2pa_li_tree, hf_m2pa_li_prio,  message_data_tvb, LI_OFFSET, LI_LENGTH, li);

    /* Re-adjust length of M2PA item since it will be dissected as MTP3 */
    proto_item_set_len(m2pa_item, HEADER_LENGTH + LI_LENGTH);
  };

  payload_tvb = tvb_new_subset(message_data_tvb, MTP3_OFFSET, payload_length, payload_length);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);
}

static void
dissect_m2pa_link_status_message(tvbuff_t *message_data_tvb, proto_tree *m2pa_tree)
{
  guint32 status;
  guint16 filler_length;
  
  if (m2pa_tree) {
    status = tvb_get_ntohl (message_data_tvb, STATUS_OFFSET);
    filler_length = tvb_length(message_data_tvb) - STATUS_LENGTH;
    proto_tree_add_uint(m2pa_tree, hf_m2pa_status, message_data_tvb, STATUS_OFFSET, STATUS_LENGTH, status);
    proto_tree_add_bytes(m2pa_tree, hf_m2pa_filler, message_data_tvb, FILLER_OFFSET, filler_length,
                         tvb_get_ptr(message_data_tvb, FILLER_OFFSET, filler_length));
  };

}

static void
dissect_m2pa_unknown_message(tvbuff_t *message_data_tvb, proto_tree *m2pa_tree)
{
  guint32 message_data_length;
  
  if (m2pa_tree) {
    message_data_length = tvb_length(message_data_tvb);
    proto_tree_add_bytes(m2pa_tree, hf_m2pa_unknown_data, message_data_tvb, 0, message_data_length,
                         tvb_get_ptr(message_data_tvb, 0, message_data_length));
  }
}

static void
dissect_m2pa_header(tvbuff_t *header_tvb, packet_info *pinfo, proto_tree *m2pa_tree)
{
  guint8  version, spare, class, type;
  guint16 bsn, fsn;
  guint32 length;

  version        = tvb_get_guint8(header_tvb, VERSION_OFFSET);
  spare          = tvb_get_guint8(header_tvb, SPARE_OFFSET);
  class          = tvb_get_guint8(header_tvb, CLASS_OFFSET);
  type           = tvb_get_guint8(header_tvb, TYPE_OFFSET);
  length         = tvb_get_ntohl(header_tvb,  LENGTH_OFFSET);
  bsn            = tvb_get_ntohs(header_tvb,  BSN_OFFSET);
  fsn            = tvb_get_ntohs(header_tvb,  FSN_OFFSET);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(type, m2pa_message_type_values, "Invalid"));
    col_append_str(pinfo->cinfo, COL_INFO, " ");
  };

  if (m2pa_tree) {
    proto_tree_add_uint(m2pa_tree, hf_m2pa_version, header_tvb, VERSION_OFFSET, VERSION_LENGTH, version);
    proto_tree_add_uint(m2pa_tree, hf_m2pa_spare, header_tvb, SPARE_OFFSET, SPARE_LENGTH, spare);
    proto_tree_add_uint(m2pa_tree, hf_m2pa_type, header_tvb, TYPE_OFFSET, TYPE_LENGTH, type);
    proto_tree_add_uint(m2pa_tree, hf_m2pa_class, header_tvb, CLASS_OFFSET, CLASS_LENGTH, class);
    proto_tree_add_uint(m2pa_tree, hf_m2pa_length, header_tvb, LENGTH_OFFSET, LENGTH_LENGTH, length);
    proto_tree_add_uint(m2pa_tree, hf_m2pa_bsn, header_tvb, BSN_OFFSET, BSN_LENGTH, bsn);
    proto_tree_add_uint(m2pa_tree, hf_m2pa_fsn, header_tvb, FSN_OFFSET, FSN_LENGTH, fsn);
  };
}

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
    dissect_m2pa_link_status_message(message_data_tvb, m2pa_tree);
    break;

  default:
    dissect_m2pa_unknown_message(message_data_tvb, m2pa_tree);
  }

}
static void
dissect_m2pa_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_item *m2pa_item, proto_tree *m2pa_tree, proto_tree *tree)
{
  tvbuff_t *header_tvb;

  header_tvb = tvb_new_subset(message_tvb, HEADER_OFFSET, HEADER_LENGTH, HEADER_LENGTH);
  dissect_m2pa_header(header_tvb, pinfo, m2pa_tree);
  dissect_m2pa_message_data(message_tvb, pinfo, m2pa_item, m2pa_tree, tree);

}

static void
dissect_m2pa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *m2pa_item;
  proto_tree *m2pa_tree;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "M2PA");

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the m2pa protocol tree */
    m2pa_item = proto_tree_add_item(tree, proto_m2pa, tvb, 0, -1, FALSE);
    m2pa_tree = proto_item_add_subtree(m2pa_item, ett_m2pa);
  } else {
    m2pa_item = NULL;
    m2pa_tree = NULL;
  };

  /* dissect the message */
  dissect_m2pa_message(tvb, pinfo, m2pa_item, m2pa_tree, tree);
}

/* Register the protocol with Ethereal */
void
proto_register_m2pa(void)
{

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_m2pa_version,
      { "Version", "m2pa.version",
	      FT_UINT8, BASE_DEC, VALS(m2pa_protocol_version_values), 0x0,
	      "", HFILL}
    },
    { &hf_m2pa_spare,
      { "Spare", "m2pa.spare",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      "", HFILL}
    },
    { &hf_m2pa_type,
      { "Message Type", "m2pa.type",
	      FT_UINT8, BASE_DEC, VALS(m2pa_message_type_values), 0x0,
	      "", HFILL}
    },
    { &hf_m2pa_class,
      { "Message Class", "m2pa.class",
	      FT_UINT8, BASE_DEC, VALS(m2pa_message_class_values), 0x0,
	      "", HFILL}
    },
    { &hf_m2pa_length,
      { "Message length", "m2pa.length",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      "", HFILL}
    },
    { &hf_m2pa_bsn,
      { "BSN", "m2pa.bsn",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      "", HFILL}
    },
    { &hf_m2pa_fsn,
      { "FSN", "m2pa.fsn",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      "", HFILL}
    },
    { &hf_m2pa_li_spare,
      { "Spare", "m2pa.li_spare",
	      FT_UINT8, BASE_HEX, NULL, LI_SPARE_MASK,
        "", HFILL}
    },
    { &hf_m2pa_li_prio,
      { "Priority", "m2pa.li_priority",
	      FT_UINT8, BASE_HEX, NULL, LI_PRIORITY_MASK,
	      "", HFILL}
    },
    { &hf_m2pa_status,
      { "Link Status Status", "m2pa.status",
	      FT_UINT32, BASE_DEC, VALS(m2pa_link_status_values), 0x0,
	      "", HFILL}
    },
    { &hf_m2pa_filler,
      { "Filler", "m2pa.filler",
	       FT_BYTES, BASE_NONE, NULL, 0x0,          
	       "", HFILL }
    },
    { &hf_m2pa_unknown_data,
      { "Unknown Data", "m2pa.unknown_data",
	       FT_BYTES, BASE_NONE, NULL, 0x0,          
	       "", HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_m2pa,
    &ett_m2pa_li
  };

  /* Register the protocol name and description */
  proto_m2pa = proto_register_protocol("MTP2 Peer Adaptation Layer", "M2PA", "m2pa");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_m2pa, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

};

void
proto_reg_handoff_m2pa(void)
{
  dissector_handle_t m2pa_handle;

  /*
   *  Get a handle for the MTP3 dissector.
   */
  mtp3_handle = find_dissector("mtp3");

  m2pa_handle = create_dissector_handle(dissect_m2pa, proto_m2pa);
  dissector_add("sctp.ppi",  M2PA_PAYLOAD_PROTOCOL_ID, m2pa_handle);
  dissector_add("sctp.port", SCTP_PORT_M2PA, m2pa_handle);
}
