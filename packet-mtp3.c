/* packet-mtp3.c
 * Routines for Message Transfer Part Level 3 dissection
 * Copyright 2001, Michael Tuexen <Michael.Tuexen@icn.siemens.de>
 *
 * $Id: packet-mtp3.c,v 1.2 2001/05/25 16:19:31 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include "packet.h"
#include "prefs.h"

/* Initialize the protocol and registered fields */
static int proto_mtp3  = -1;
static module_t *mtp3_module;

static int hf_mtp3_service_indicator = -1;
static int hf_mtp3_network_indicator = -1;
static int hf_mtp3_spare = -1;
static int hf_mtp3_opc = -1;
static int hf_mtp3_dpc = -1;
static int hf_mtp3_sls = -1;

/* Initialize the subtree pointers */
static gint ett_mtp3 = -1;
static gint ett_mtp3_sio = -1;
static gint ett_mtp3_label = -1;

static dissector_table_t mtp3_sio_dissector_table;

#define ITU_STANDARD   1
#define ANSI_STANDARD  2

static gint mtp3_standard = ITU_STANDARD;
 
#define ITU_SIO_OFFSET 0
#define ITU_SIO_LENGTH 1
#define ITU_ROUTING_LABEL_OFFSET 1
#define ITU_ROUTING_LABEL_LENGTH 4
#define ITU_MTP_PAYLOAD_OFFSET 5

#define SERVICE_INDICATOR_MASK 0x0F
#define SPARE_MASK 0x30
#define NETWORK_INDICATOR_MASK 0xC0
#define DPC_MASK 0x00003FFF
#define OPC_MASK 0x0FFFC000
#define SLS_MASK 0xF0000000

static const value_string service_indicator_code_vals[] = {
	{ 0x0,	"Signalling network management message" },
	{ 0x1,	"Signalling network testing and maintenance message" },
	{ 0x2,	"Spare" },
	{ 0x3,	"SCCP" },
	{ 0x4,	"TUP" },
	{ 0x5,	"ISUP" },
	{ 0x6,	"DUP (call and circuit related messages)" },
	{ 0x7,	"DUP (facility registration and cancellation message)" },
	{ 0x8,	"MTP testing user part" },
	{ 0x9,	"Spare" },
	{ 0xa,	"Spare" },
	{ 0xb,	"Spare" },
	{ 0xc,	"Spare" },
	{ 0xd,	"Spare" },
	{ 0xe,	"Spare" },
	{ 0xf,	"Spare" },
	{ 0,	NULL }
};

static const value_string network_indicator_vals[] = {
	{ 0x0,	"International network" },
	{ 0x1,	"Spare (for international use only)" },
	{ 0x2,	"National network" },
	{ 0x3,	"Reserved for national use" },
	{ 0,	NULL }
};

static void
dissect_mtp3_sio(tvbuff_t *tvb, proto_tree *mtp3_tree)
{
  guint8 sio;
  proto_item *sio_item;
  proto_tree *sio_tree;
  
  sio_item = proto_tree_add_text(mtp3_tree, tvb, ITU_SIO_OFFSET, ITU_SIO_LENGTH, "Service information octet");    
  sio_tree = proto_item_add_subtree(sio_item, ett_mtp3_sio);

  sio = tvb_get_guint8(tvb, ITU_SIO_OFFSET);
  proto_tree_add_uint(sio_tree, hf_mtp3_network_indicator,
		      tvb, ITU_SIO_OFFSET, ITU_SIO_LENGTH,
		      sio);
  proto_tree_add_uint(sio_tree, hf_mtp3_spare,
		      tvb, ITU_SIO_OFFSET, ITU_SIO_LENGTH,
		      sio);
  proto_tree_add_uint(sio_tree, hf_mtp3_service_indicator,
		      tvb, ITU_SIO_OFFSET, ITU_SIO_LENGTH,
		      sio);
}

static void
dissect_mtp3_routing_label(tvbuff_t *tvb, proto_tree *mtp3_tree)
{
  guint32 label;
  proto_item *label_item;
  proto_tree *label_tree;
  
  label_item = proto_tree_add_text(mtp3_tree, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, "Routing label");    
  label_tree = proto_item_add_subtree(label_item, ett_mtp3_label);

  label = tvb_get_letohl(tvb, ITU_ROUTING_LABEL_OFFSET);
  proto_tree_add_uint(label_tree, hf_mtp3_dpc,
		      tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH,
		      label);
  proto_tree_add_uint(label_tree, hf_mtp3_opc,
		      tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH,
		      label);
  proto_tree_add_uint(label_tree, hf_mtp3_sls,
		      tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH,
		      label);
}

static void
dissect_mtp3_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 sio;
  guint8 service_indicator;
  tvbuff_t *payload_tvb;

  sio = tvb_get_guint8(tvb, ITU_SIO_OFFSET);
  service_indicator = sio & SERVICE_INDICATOR_MASK;
  payload_tvb = tvb_new_subset(tvb, ITU_MTP_PAYLOAD_OFFSET, -1, -1);
  if (!dissector_try_port(mtp3_sio_dissector_table, service_indicator, payload_tvb, pinfo, tree)) {
    proto_tree_add_text(tree, payload_tvb, 0, tvb_length(payload_tvb),
			"Payload (%u byte%s)",
			tvb_length(payload_tvb), plurality(tvb_length(payload_tvb), "", "s")); 
  }
}

/* Code to actually dissect the packets */
static void
dissect_mtp3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *mtp3_item;
  proto_tree *mtp3_tree;

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->fd, COL_PROTOCOL)) 
    col_set_str(pinfo->fd, COL_PROTOCOL, "MTP3");    
  if (check_col(pinfo->fd, COL_INFO)) 
    col_clear(pinfo->fd, COL_INFO);

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */

  if (tree) {

    /* create display subtree for the protocol */
    mtp3_item = proto_tree_add_item(tree, proto_mtp3, tvb, 0, tvb_length(tvb), FALSE);    
    mtp3_tree = proto_item_add_subtree(mtp3_item, ett_mtp3);
    
    /* dissect the packet */
    dissect_mtp3_sio(tvb, mtp3_tree);
    dissect_mtp3_routing_label(tvb, mtp3_tree);
    dissect_mtp3_payload(tvb, pinfo, tree);    
  }
}

void
proto_register_mtp3(void)
{                 
  
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_mtp3_service_indicator,
      { "Service indicator",
	"mtp3.service_indicator",
	FT_UINT8, BASE_HEX, VALS(service_indicator_code_vals), SERVICE_INDICATOR_MASK,          
	"" }}, 
    { &hf_mtp3_network_indicator,
      { "Network indicator",
	"mtp3.network_indicator",
	FT_UINT8, BASE_HEX, VALS(network_indicator_vals), NETWORK_INDICATOR_MASK,          
	"" }}, 
    { &hf_mtp3_spare,
      { "Spare",
	"mtp3.spare",
	FT_UINT8, BASE_HEX, NULL, SPARE_MASK,          
	"" }}, 
    { &hf_mtp3_opc,
      { "OPC",
	"mtp3.opc",
	FT_UINT32, BASE_DEC, NULL, OPC_MASK,          
	"" }}, 
    { &hf_mtp3_dpc,
      { "DPC",
	"mtp3.dpc",
	FT_UINT32, BASE_DEC, NULL, DPC_MASK,          
	"" }}, 
    { &hf_mtp3_sls,
      { "SLS",
	"mtp3.sls",
	FT_UINT32, BASE_DEC, NULL, SLS_MASK,          
	"" }}, 
  };
  
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_mtp3,
    &ett_mtp3_sio,
    &ett_mtp3_label
  };

  static enum_val_t mtp3_options[] = {
    {"ITU",  ITU_STANDARD},
    /*    {"ANSI", ANSI_STANDARD}, */
    {NULL, 0}
  };
  
  /* Register the protocol name and description */
  proto_mtp3 = proto_register_protocol("Message Transfer Part Level 3",
				       "MTP Level 3", "MTP3");
  
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_mtp3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the dissector */
  register_dissector("mtp3", dissect_mtp3, proto_mtp3);

  mtp3_sio_dissector_table = register_dissector_table("mtp3.service_indicator");
  
  mtp3_module = prefs_register_protocol(proto_mtp3, NULL);

  prefs_register_enum_preference(mtp3_module, 
				 "mtp3_standard",
				 "MTP3 standard",
				 "MTP3 standard", 
				 &mtp3_standard,
				 mtp3_options, FALSE);
}
