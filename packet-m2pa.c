/* packet-m2pa.c
 * Routines for MTP2 Peer Adaptation Layer dissection
 * It is hopefully (needs testing) compliant to
 * http://www.ietf.org/internet-drafts/draft-ietf-sigtran-m2pa-02.txt
 *
 * Copyright 2001, Jeff Morriss <jeff.morriss[AT]ulticom.com>
 *
 * $Id: packet-m2pa.c,v 1.2 2001/12/03 03:59:37 guy Exp $
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

#include "packet.h"
#include "prefs.h"

/* Warning:  Neither of these are standardized yet! */
#define SCTP_PORT_M2PA 2904
#define M2PA_PAYLOAD_PROTOCOL_ID   5

#define VERSION_LENGTH         1
#define SPARE_LENGTH           1
#define MESSAGE_TYPE_LENGTH    2
#define MESSAGE_LENGTH_LENGTH  4
#define COMMON_HEADER_LENGTH   (VERSION_LENGTH + SPARE_LENGTH + \
                                MESSAGE_TYPE_LENGTH + MESSAGE_LENGTH_LENGTH)

#define VERSION_OFFSET         0
#define SPARE_OFFSET           (VERSION_OFFSET + VERSION_LENGTH)
#define MESSAGE_TYPE_OFFSET    (SPARE_OFFSET + SPARE_LENGTH)
#define MESSAGE_LENGTH_OFFSET  (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)


#define PROTOCOL_VERSION_RELEASE_1        1
static const value_string m2pa_protocol_version_values[] = {
  { PROTOCOL_VERSION_RELEASE_1,  "Release 1" },
  { 0,                           NULL } };


#define MESSAGE_TYPE_USER_DATA            0x0601
#define MESSAGE_TYPE_LINK_STATUS          0x0602
static const value_string m2pa_message_type_values[] = {
  { MESSAGE_TYPE_USER_DATA,     "User Data" },
  { MESSAGE_TYPE_LINK_STATUS,   "Link Status" },
  { 0,                           NULL } };


/* parts of User Data message */
#define LI_OFFSET             0
#define LI_LENGTH             1
#define USER_OFFSET           (LI_OFFSET + LI_LENGTH)

/* LI is only used for (ITU national) priority in M2PA */
#define LI_SPARE_MASK              0xfc
#define LI_PRIORITY_MASK           0x3


/* parts of Link Status message */
#define STATUS_LENGTH    4
#define STATUS_OFFSET    0

#define STATUS_IS        1
#define STATUS_PO        2
#define STATUS_POE       3
#define STATUS_BUSY      4
#define STATUS_BUSY_E    5
static const value_string m2pa_link_status_values[] = {
  { STATUS_IS,      "In Service" },
  { STATUS_PO,      "Processor Outage" },
  { STATUS_POE,     "Processor Outage Ended" },
  { STATUS_BUSY,    "Busy" },
  { STATUS_BUSY_E,  "Busy Ended" },
  { 0,              NULL } };


/* Initialize the protocol and registered fields */
static int proto_m2pa = -1;
static int hf_m2pa_version = -1;
static int hf_m2pa_spare = -1;
static int hf_m2pa_message_type = -1;
static int hf_m2pa_message_length = -1;
static int hf_m2pa_ls_status = -1;
static int hf_m2pa_data_li = -1;
static int hf_m2pa_data_li_spare = -1;
static int hf_m2pa_data_li_prio = -1;

/* Initialize the subtree pointers */
static gint ett_m2pa = -1;
static gint ett_m2pa_message_ud = -1;
static gint ett_m2pa_message_ud_li = -1;
static gint ett_m2pa_message_ls = -1;

static dissector_handle_t mtp3_handle;

static void
dissect_m2pa_unknown_message(tvbuff_t *message_tvb, packet_info *pinfo,
			     proto_tree *m2pa_tree, guint32 message_length,
			     guint16 message_type)
{

  if (check_col(pinfo->fd, COL_INFO)) {
    col_set_str(pinfo->fd, COL_INFO,
		val_to_str(message_type, m2pa_message_type_values, "Unknown"));
  };

  if (m2pa_tree) {
    proto_tree_add_text(m2pa_tree, message_tvb, 0, message_length,
			"Unknown message (%u byte%s)",
			message_length, plurality(message_length, "", "s"));
  };

}


static void
dissect_m2pa_link_status_message(tvbuff_t *message_tvb, packet_info *pinfo,
				 proto_tree *m2pa_tree, guint16 message_type)
{
  guint32 status;
  proto_item *m2pa_ls_item;
  proto_tree *m2pa_ls_tree;

  status = tvb_get_ntohl (message_tvb, STATUS_OFFSET);

  if (check_col(pinfo->fd, COL_INFO)) {
    col_set_str(pinfo->fd, COL_INFO,
		val_to_str(message_type, m2pa_message_type_values, "unknown"));

    col_append_str(pinfo->fd, COL_INFO, " (");
    col_append_str(pinfo->fd, COL_INFO,
		   val_to_str(status, m2pa_link_status_values, "unknown"));
    col_append_str(pinfo->fd, COL_INFO, ")");
  };

  if (m2pa_tree) {
    /* create the link status message tree */
    m2pa_ls_item = proto_tree_add_text(m2pa_tree, message_tvb, 0,
				       STATUS_LENGTH,
				       val_to_str(message_type,
						  m2pa_message_type_values,
						  "Unknown"));
    m2pa_ls_tree = proto_item_add_subtree(m2pa_ls_item, ett_m2pa_message_ls);

    /* add the components of the link status message to the protocol tree */
    proto_tree_add_uint(m2pa_ls_tree, hf_m2pa_ls_status,
					  message_tvb, STATUS_OFFSET,
					  STATUS_LENGTH, status);
  };

}


static void
dissect_m2pa_user_data_message(tvbuff_t *message_tvb, packet_info *pinfo,
			       proto_item *m2pa_item, proto_tree *m2pa_tree,
			       guint32 message_length, proto_tree *tree,
			       guint16 message_type)
{
  proto_item *m2pa_ud_item;
  proto_tree *m2pa_ud_tree;
  proto_item *m2pa_ud_li_item;
  proto_tree *m2pa_ud_li_tree;
  tvbuff_t *payload_tvb;
  guint8 li;
  guint32 payload_length;

  li = tvb_get_guint8(message_tvb, LI_OFFSET);
  payload_length = message_length - LI_LENGTH;

  if (m2pa_tree) {
    /* create the user data message tree */
    m2pa_ud_item = proto_tree_add_item(m2pa_tree, proto_m2pa, message_tvb, 0,
				       tvb_length(message_tvb), FALSE);
    m2pa_ud_tree = proto_item_add_subtree(m2pa_ud_item, ett_m2pa_message_ud);

    /* add the components of the user data message to the protocol tree */
    /* LI */
    m2pa_ud_li_item = proto_tree_add_uint(m2pa_ud_tree, hf_m2pa_data_li,
					  message_tvb, LI_OFFSET, LI_LENGTH,
					  li);
    m2pa_ud_li_tree = proto_item_add_subtree(m2pa_ud_li_item,
					     ett_m2pa_message_ud_li);
    proto_tree_add_uint(m2pa_ud_li_tree, hf_m2pa_data_li_spare, message_tvb,
			LI_OFFSET, LI_LENGTH, li);
    proto_tree_add_uint(m2pa_ud_li_tree, hf_m2pa_data_li_prio, message_tvb,
			LI_OFFSET, LI_LENGTH, li);

    proto_item_set_text(m2pa_ud_item, "Protocol data (SS7 message of %u byte%s)",
		        payload_length, plurality(payload_length, "", "s"));

    /* Re-adjust length of M2PA item since it will be dissected as MTP3 */
    proto_item_set_len(m2pa_item, COMMON_HEADER_LENGTH + LI_LENGTH);

  };

  payload_tvb = tvb_new_subset(message_tvb, USER_OFFSET, payload_length,
			       payload_length);
  call_dissector(mtp3_handle, payload_tvb, pinfo, tree);

}

static void
dissect_m2pa_message(tvbuff_t *tvb, packet_info *pinfo, proto_item *m2pa_item,
		     proto_tree *m2pa_tree, proto_tree *tree)
{
  guint8  version, spare;
  guint16 message_type;
  guint32 message_length;
  tvbuff_t *message_tvb;

  /* Extract the common header */
  version        = tvb_get_guint8(tvb, VERSION_OFFSET);
  spare          = tvb_get_guint8(tvb, SPARE_OFFSET);
  message_type   = tvb_get_ntohs(tvb, MESSAGE_TYPE_OFFSET);
  message_length = tvb_get_ntohl(tvb, MESSAGE_LENGTH_OFFSET);

  if (m2pa_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint(m2pa_tree, hf_m2pa_version, tvb, VERSION_OFFSET,
			VERSION_LENGTH, version);
    proto_tree_add_uint(m2pa_tree, hf_m2pa_spare,
			tvb, SPARE_OFFSET, SPARE_LENGTH,
			spare);
    proto_tree_add_uint(m2pa_tree, hf_m2pa_message_type, tvb,
			MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH,
			message_type);
    proto_tree_add_uint(m2pa_tree, hf_m2pa_message_length,
			tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH,
			message_length);
  };

  /* create a tvb for the message */
  message_tvb = tvb_new_subset(tvb, COMMON_HEADER_LENGTH, message_length,
			       message_length);

  switch(message_type) {
  case MESSAGE_TYPE_USER_DATA:
    dissect_m2pa_user_data_message(message_tvb, pinfo, m2pa_item, m2pa_tree,
				   message_length, tree, message_type);
      break;

  case MESSAGE_TYPE_LINK_STATUS:
    dissect_m2pa_link_status_message(message_tvb, pinfo, m2pa_tree,
				     message_type);
    break;

  default:
    dissect_m2pa_unknown_message(message_tvb, pinfo, m2pa_tree,
				 message_length, message_type);
  }

}

static void
dissect_m2pa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *m2pa_item;
  proto_tree *m2pa_tree;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_set_str(pinfo->fd, COL_PROTOCOL, "M2PA");

  /* Clear entries in Info column on summary display */
  if (check_col(pinfo->fd, COL_INFO))
    col_clear(pinfo->fd, COL_INFO);

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the m2pa protocol tree */
    m2pa_item = proto_tree_add_item(tree, proto_m2pa, tvb, 0,
				    COMMON_HEADER_LENGTH, FALSE);
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
    { &hf_m2pa_message_type,
      { "Message Type", "m2pa.message_type",
	FT_UINT16, BASE_HEX, VALS(m2pa_message_type_values), 0x0,
	"", HFILL}
    },
    { &hf_m2pa_message_length,
      { "Message length", "m2pa.message_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"", HFILL}
    },
    { &hf_m2pa_ls_status,
      { "Link Status Status", "m2pa.status",
	FT_UINT32, BASE_DEC, VALS(m2pa_link_status_values), 0x0,
	"", HFILL}
    },
    { &hf_m2pa_data_li,
      { "Length Indicator", "m2pa.li",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	"", HFILL}
    },
    { &hf_m2pa_data_li_spare,
      { "Spare", "m2pa.li.spare",
	FT_UINT8, BASE_HEX, NULL, LI_SPARE_MASK,
	"", HFILL}
    },
    { &hf_m2pa_data_li_prio,
      { "Priority", "m2pa.li.prio",
	FT_UINT8, BASE_HEX, NULL, LI_PRIORITY_MASK,
	"", HFILL}
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_m2pa,
    &ett_m2pa_message_ud,
    &ett_m2pa_message_ud_li,
    &ett_m2pa_message_ls
  };

  /* Register the protocol name and description */
  proto_m2pa = proto_register_protocol("MTP2 Peer Adaptation Layer",
                                      "M2PA", "m2pa");

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
