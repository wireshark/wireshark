/* packet-sual.c
 * Routines for SUA light, a Siemens propriatary protocol
 *
 * Copyright 2001, Martin Held <Martin.Held@icn.siemens.de>
 *                 Michael TŸxen <Michael.Tuexen@icn.siemens.de>
 *
 * $Id: packet-sual.c,v 1.1 2001/01/22 09:04:09 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
#include "packet-ip.h"

#define SUAL_PAYLOAD_PROTO_ID 4

#define VERSION_LENGTH          1
#define SPARE_1_LENGTH          1
#define MESSAGE_TYPE_LENGTH     2
#define SUBSYSTEM_NUMBER_LENGTH 2
#define SPARE_2_LENGTH          2
#define MESSAGE_LENGTH_LENGTH   4
#define COMMON_HEADER_LENGTH   (VERSION_LENGTH + SPARE_1_LENGTH + MESSAGE_TYPE_LENGTH + \
                                SUBSYSTEM_NUMBER_LENGTH + SPARE_2_LENGTH + MESSAGE_LENGTH_LENGTH)

#define VERSION_OFFSET          0
#define SPARE_1_OFFSET          (VERSION_OFFSET + VERSION_LENGTH)
#define MESSAGE_TYPE_OFFSET     (SPARE_1_OFFSET + SPARE_1_LENGTH)
#define SUBSYSTEM_NUMBER_OFFSET (MESSAGE_TYPE_OFFSET + MESSAGE_TYPE_LENGTH)
#define SPARE_2_OFFSET          (SUBSYSTEM_NUMBER_OFFSET + SUBSYSTEM_NUMBER_LENGTH)
#define MESSAGE_LENGTH_OFFSET   (SPARE_2_OFFSET + SPARE_2_LENGTH)

/* SUAL message type coding */
#define SUAL_MSG_CLDT                     0x0501
#define SUAL_MSG_CORE                     0x0701
#define SUAL_MSG_COAK_CC            	  0x0702
#define SUAL_MSG_COAK_CREF                0x0712
#define SUAL_MSG_RELRE                    0x0703
#define SUAL_MSG_RELCO                    0x0704
#define SUAL_MSG_CODT                     0x0707
#define SUAL_MSG_ERR                      0x0000

static const value_string   sual_message_type_values[] = {
  {  SUAL_MSG_CLDT,              "Connectionless Data Transfer (CLDT)"},
  {  SUAL_MSG_CORE,              "Connection Request (CORE)"},
  {  SUAL_MSG_COAK_CC,           "Connection Acknowledge (COAK_CC)"},
  {  SUAL_MSG_COAK_CREF,         "Connection Acknowledge (COAK_CREF)"},
  {  SUAL_MSG_RELRE,             "Release Request (RELRE)"},
  {  SUAL_MSG_RELCO,             "Release Complete (RELCO)"},
  {  SUAL_MSG_CODT,              "Connection Oriented Data Transfer (CODT)"},
  {  SUAL_MSG_ERR,               "Error (ERR)"},
  {  0,                          NULL}};

static const value_string sual_message_type_acro_values[] = {
  {  SUAL_MSG_CLDT,              "CLDT"},
  {  SUAL_MSG_CORE,              "CORE"},
  {  SUAL_MSG_COAK_CC,           "COAK_CC"},
  {  SUAL_MSG_COAK_CREF,         "COAK_CREF"},
  {  SUAL_MSG_RELRE,             "RELRE"},
  {  SUAL_MSG_RELCO,             "RELCO"},
  {  SUAL_MSG_CODT,              "CODT"},
  {  SUAL_MSG_ERR,               "ERR"},
  {  0,                          NULL}};

/* Initialize the protocol and registered fields */
static int proto_sual = -1;
static int hf_sual_version = -1;
static int hf_sual_spare_1 = -1;
static int hf_sual_message_type = -1;
static int hf_sual_subsystem_number = -1;
static int hf_sual_spare_2 = -1;
static int hf_sual_message_length = -1;

/* Initialize the subtree pointers */
static gint ett_sual = -1;

static void
dissect_sual_common_header(tvbuff_t *common_header_tvb, packet_info *pinfo, proto_tree *sual_tree)
{
  guint8  version, spare_1;
  guint16 message_type, subsystem_number, spare_2; 
  guint32 message_length;

  /* Extract the common header */
  version          = tvb_get_guint8(common_header_tvb, VERSION_OFFSET);
  spare_1          = tvb_get_guint8(common_header_tvb, SPARE_1_OFFSET);
  message_type     = tvb_get_ntohs(common_header_tvb, MESSAGE_TYPE_OFFSET);
  subsystem_number = tvb_get_ntohs(common_header_tvb, SUBSYSTEM_NUMBER_OFFSET);
  spare_2          = tvb_get_ntohs(common_header_tvb, SPARE_2_OFFSET);
  message_length   = tvb_get_ntohl (common_header_tvb, MESSAGE_LENGTH_OFFSET);

  if (check_col(pinfo->fd, COL_INFO)) {
    col_append_str(pinfo->fd, COL_INFO, val_to_str(message_type, sual_message_type_acro_values, "Unknown"));
    col_append_str(pinfo->fd, COL_INFO, " ");
  };

  if (sual_tree) {
    /* add the components of the common header to the protocol tree */
    proto_tree_add_uint(sual_tree, hf_sual_version, 
			common_header_tvb, VERSION_OFFSET, VERSION_LENGTH,
			version);
    proto_tree_add_uint(sual_tree, hf_sual_spare_1,
			common_header_tvb, SPARE_1_OFFSET, SPARE_1_LENGTH,
			spare_1);
    proto_tree_add_uint_format(sual_tree, hf_sual_message_type, 
			       common_header_tvb, MESSAGE_TYPE_OFFSET, MESSAGE_TYPE_LENGTH,
			       message_type, "Message type: %u (%s)",
			       message_type, val_to_str(message_type, sual_message_type_values, "Unknown"));
    proto_tree_add_uint(sual_tree, hf_sual_subsystem_number,
			common_header_tvb, SUBSYSTEM_NUMBER_OFFSET, SUBSYSTEM_NUMBER_LENGTH,
			subsystem_number);
    proto_tree_add_uint(sual_tree, hf_sual_spare_2,
			common_header_tvb, SPARE_2_OFFSET, SPARE_2_LENGTH,
			spare_2);
    proto_tree_add_uint(sual_tree, hf_sual_message_length,
			common_header_tvb, MESSAGE_LENGTH_OFFSET, MESSAGE_LENGTH_LENGTH,
			message_length);
  };
}

static void
dissect_sual_message(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *sual_tree)
{
  gint offset, payload_length;
  tvbuff_t *common_header_tvb;

  offset = 0;
  /* extract and process the common header */
  common_header_tvb = tvb_new_subset(message_tvb, offset, COMMON_HEADER_LENGTH, COMMON_HEADER_LENGTH);
  dissect_sual_common_header(common_header_tvb, pinfo, sual_tree);
  offset += COMMON_HEADER_LENGTH;
  
  if (sual_tree) {
    payload_length = tvb_length(message_tvb) - COMMON_HEADER_LENGTH;
    proto_tree_add_text(sual_tree, message_tvb, offset, payload_length,
			"Payload: %u byte%s",
			payload_length, plurality(payload_length, "", "s"));
  }
}

static void
dissect_sual(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *sual_item;
  proto_tree *sual_tree;

  /* make entry in the Protocol column on summary display */
  if (check_col(pinfo->fd, COL_PROTOCOL)) 
    col_set_str(pinfo->fd, COL_PROTOCOL, "SUAL");
  
  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the sual protocol tree */
    sual_item = proto_tree_add_item(tree, proto_sual, message_tvb, 0, tvb_length(message_tvb), FALSE);
    sual_tree = proto_item_add_subtree(sual_item, ett_sual);
  } else {
    sual_tree = NULL;
  };
  /* dissect the message */
  dissect_sual_message(message_tvb, pinfo, sual_tree);
}

/* Register the protocol with Ethereal */
void
proto_register_sual(void)
{                 

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_sual_version,
      { "Version", "sual.version",
	FT_UINT8, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_sual_spare_1,
      { "Spare", "sual.spare_1",
	FT_UINT8, BASE_HEX, NULL, 0x0,          
	""}
    }, 
    { &hf_sual_message_type,
      { "Message Type", "sual.message_type",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_sual_subsystem_number,
      { "Subsystem number", "sual.subsystem_number",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_sual_spare_2,
      { "Spare", "sual.spare_2",
	FT_UINT16, BASE_DEC, NULL, 0x0,          
	""}
    },
    { &hf_sual_message_length,
      { "Message length", "sual.message_length",
	FT_UINT32, BASE_DEC, NULL, 0x0,          
	""}
    }, 
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sual,
  };
  
  /* Register the protocol name and description */
  proto_sual = proto_register_protocol("SCCP user adaptation layer light",
				       "SUAL",  "sual");
  
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sual, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_sual(void)
{
  dissector_add("sctp.ppi",  SUAL_PAYLOAD_PROTO_ID, dissect_sual, proto_sual);
}
