/* packet-mtp3.c
 * Routines for Message Transfer Part Level 3 dissection
 * Copyright 2001, Michael Tuexen <Michael.Tuexen@icn.siemens.de>
 * Updated for ANSI support by Jeff Morriss <jeff.morriss[AT]ulticom.com>
 *
 * $Id: packet-mtp3.c,v 1.11 2002/03/04 22:39:22 guy Exp $
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

#include <glib.h>

#include <epan/packet.h>
#include "prefs.h"

/* Initialize the protocol and registered fields */
static int proto_mtp3  = -1;
static module_t *mtp3_module;

static int hf_mtp3_service_indicator = -1;
static int hf_mtp3_network_indicator = -1;
static int hf_mtp3_itu_spare = -1;
static int hf_mtp3_ansi_priority = -1;
static int hf_mtp3_itu_opc = -1;
static int hf_mtp3_opc_network = -1;
static int hf_mtp3_opc_cluster = -1;
static int hf_mtp3_opc_member = -1;
static int hf_mtp3_itu_dpc = -1;
static int hf_mtp3_dpc_network = -1;
static int hf_mtp3_dpc_cluster = -1;
static int hf_mtp3_dpc_member = -1;
static int hf_mtp3_itu_sls = -1;
static int hf_mtp3_ansi_sls = -1;

/* Initialize the subtree pointers */
static gint ett_mtp3 = -1;
static gint ett_mtp3_sio = -1;
static gint ett_mtp3_label = -1;
static gint ett_mtp3_label_dpc = -1;
static gint ett_mtp3_label_opc = -1;

static dissector_table_t mtp3_sio_dissector_table;

#include <packet-mtp3.h>
Standard_Type mtp3_standard = ITU_STANDARD;

#define SIO_LENGTH                1

#define ITU_ROUTING_LABEL_LENGTH  4
#define ITU_HEADER_LENGTH         (SIO_LENGTH + ITU_ROUTING_LABEL_LENGTH)
#define ITU_SLS_LENGTH            1

#define SIO_OFFSET                0
#define ITU_SLS_OFFSET            (SIO_OFFSET + ITU_HEADER_LENGTH - ITU_SLS_LENGTH)
#define ITU_ROUTING_LABEL_OFFSET  (SIO_OFFSET + SIO_LENGTH)
#define ITU_MTP_PAYLOAD_OFFSET    (SIO_OFFSET + ITU_HEADER_LENGTH)

#define ANSI_SLS_LENGTH           1
#define ANSI_ROUTING_LABEL_LENGTH (ANSI_PC_LENGTH + ANSI_PC_LENGTH + ANSI_SLS_LENGTH)
#define ANSI_HEADER_LENGTH        (SIO_LENGTH + ANSI_ROUTING_LABEL_LENGTH)

#define ANSI_ROUTING_LABEL_OFFSET (SIO_OFFSET + SIO_LENGTH)
#define ANSI_DPC_OFFSET           ANSI_ROUTING_LABEL_OFFSET
#define ANSI_OPC_OFFSET           (ANSI_DPC_OFFSET + ANSI_PC_LENGTH)
#define ANSI_SLS_OFFSET           (ANSI_OPC_OFFSET + ANSI_PC_LENGTH)
#define ANSI_MTP_PAYLOAD_OFFSET   (SIO_OFFSET + ANSI_HEADER_LENGTH)

#define SERVICE_INDICATOR_MASK         0x0F
#define SPARE_MASK                     0x30
#define ANSI_PRIORITY_MASK             SPARE_MASK
#define NETWORK_INDICATOR_MASK         0xC0
#define ITU_DPC_MASK                   0x00003FFF
#define ITU_OPC_MASK                   0x0FFFC000
#define ITU_SLS_MASK                   0xF0000000

#define ANSI_NETWORK_MASK              0x0000FF
#define ANSI_CLUSTER_MASK              0x00FF00
#define ANSI_MEMBER_MASK               0xFF0000
#define ANSI_5BIT_SLS_MASK             0x1F
/* TODO: eventually add support for ANSI 8-bit SLS */
#define ANSI_8BIT_SLS_MASK             0xFF

static const value_string service_indicator_code_vals[] = {
	{ 0x0,	"Signalling Network Management Message (SNM)" },
	{ 0x1,	"Maintenance Regular Message (MTN)" },
	{ 0x2,	"Maintenance Special Message (MTNS)" },
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

static dissector_handle_t data_handle;

static void
dissect_mtp3_sio(tvbuff_t *tvb, proto_tree *mtp3_tree)
{
  guint8 sio;
  proto_item *sio_item;
  proto_tree *sio_tree;

  sio_item = proto_tree_add_text(mtp3_tree, tvb, SIO_OFFSET, SIO_LENGTH, "Service information octet");
  sio_tree = proto_item_add_subtree(sio_item, ett_mtp3_sio);

  sio = tvb_get_guint8(tvb, SIO_OFFSET);
  proto_tree_add_uint(sio_tree, hf_mtp3_network_indicator, tvb, SIO_OFFSET, SIO_LENGTH, sio);
  
  switch(mtp3_standard){
  case ANSI_STANDARD:
    proto_tree_add_uint(sio_tree, hf_mtp3_ansi_priority, tvb, SIO_OFFSET, SIO_LENGTH, sio);
    break;
  case ITU_STANDARD:
    proto_tree_add_uint(sio_tree, hf_mtp3_itu_spare, tvb, SIO_OFFSET, SIO_LENGTH, sio);
    break;
  }
  
  proto_tree_add_uint(sio_tree, hf_mtp3_service_indicator, tvb, SIO_OFFSET, SIO_LENGTH, sio);
}

static void
dissect_mtp3_routing_label(tvbuff_t *tvb, proto_tree *mtp3_tree)
{
  guint32 label, dpc, opc;
  guint8 sls;
  proto_item *label_item, *label_dpc_item, *label_opc_item;
  proto_tree *label_tree, *label_dpc_tree, *label_opc_tree;

  switch (mtp3_standard) {
  case ITU_STANDARD:
    label_item = proto_tree_add_text(mtp3_tree, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, "Routing label");
    label_tree = proto_item_add_subtree(label_item, ett_mtp3_label);

    label = tvb_get_letohl(tvb, ITU_ROUTING_LABEL_OFFSET);
    sls   = tvb_get_guint8(tvb, ITU_ROUTING_LABEL_OFFSET);

    proto_tree_add_uint(label_tree, hf_mtp3_itu_dpc, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, label);
    proto_tree_add_uint(label_tree, hf_mtp3_itu_opc, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, label);
    proto_tree_add_uint(label_tree, hf_mtp3_itu_sls, tvb, ITU_SLS_OFFSET, ITU_SLS_LENGTH, sls);
    break;

  case ANSI_STANDARD:
    /* this could be 5 or 8 bits */
    sls = tvb_get_guint8(tvb, ANSI_SLS_OFFSET);

    /* Create the Routing Label Tree */
    label_item = proto_tree_add_text(mtp3_tree, tvb, ANSI_ROUTING_LABEL_OFFSET, ANSI_ROUTING_LABEL_LENGTH, "Routing label");
    label_tree = proto_item_add_subtree(label_item, ett_mtp3_label);

    /* create the DPC tree */
    dpc = tvb_get_ntoh24(tvb, ANSI_DPC_OFFSET);
    label_dpc_item = proto_tree_add_text(label_tree, tvb, ANSI_DPC_OFFSET, ANSI_PC_LENGTH,
					 "DPC (%d-%d-%d)", (dpc & ANSI_NETWORK_MASK), ((dpc & ANSI_CLUSTER_MASK) >> 8), ((dpc & ANSI_MEMBER_MASK) >> 16));

    label_dpc_tree = proto_item_add_subtree(label_dpc_item, ett_mtp3_label_dpc);

    proto_tree_add_uint(label_dpc_tree, hf_mtp3_dpc_member, tvb, ANSI_DPC_OFFSET, ANSI_PC_LENGTH, dpc);
    proto_tree_add_uint(label_dpc_tree, hf_mtp3_dpc_cluster,tvb, ANSI_DPC_OFFSET, ANSI_PC_LENGTH, dpc);
    proto_tree_add_uint(label_dpc_tree, hf_mtp3_dpc_network,tvb, ANSI_DPC_OFFSET, ANSI_PC_LENGTH, dpc);

    /* create the OPC tree */
    opc = tvb_get_ntoh24(tvb, ANSI_OPC_OFFSET);

    label_opc_item = proto_tree_add_text(label_tree, tvb, ANSI_OPC_OFFSET, ANSI_PC_LENGTH,
					 "OPC (%d-%d-%d)", (opc & ANSI_NETWORK_MASK), ((opc & ANSI_CLUSTER_MASK) >> 8), ((opc & ANSI_MEMBER_MASK) >> 16));
    label_opc_tree = proto_item_add_subtree(label_opc_item, ett_mtp3_label_opc);

    proto_tree_add_uint(label_opc_tree, hf_mtp3_opc_member, tvb, ANSI_OPC_OFFSET, ANSI_PC_LENGTH, opc);
    proto_tree_add_uint(label_opc_tree, hf_mtp3_opc_cluster, tvb, ANSI_OPC_OFFSET, ANSI_PC_LENGTH, opc);
    proto_tree_add_uint(label_opc_tree, hf_mtp3_opc_network,tvb, ANSI_OPC_OFFSET, ANSI_PC_LENGTH, opc);
    /* SLS */
    /* TODO: separate 5-bit and 8-bit SLS */
    proto_tree_add_item(label_tree, hf_mtp3_ansi_sls, tvb, ANSI_SLS_OFFSET, ANSI_SLS_LENGTH, sls);
    /*    proto_tree_add_uint(label_tree, hf_mtp3_ansi_sls, tvb,ANSI_SLS_OFFSET, ANSI_SLS_LENGTH, sls);*/
    break;
  }
}

static void
dissect_mtp3_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 sio;
  guint8 service_indicator;
  tvbuff_t *payload_tvb = NULL;

  sio               = tvb_get_guint8(tvb, SIO_OFFSET);
  service_indicator = sio & SERVICE_INDICATOR_MASK;

  switch (mtp3_standard) {
  case ITU_STANDARD:
    payload_tvb = tvb_new_subset(tvb, ITU_MTP_PAYLOAD_OFFSET, -1, -1);
    break;
  case ANSI_STANDARD:
    payload_tvb = tvb_new_subset(tvb, ANSI_MTP_PAYLOAD_OFFSET, -1, -1);
    break;
  }

  if (!dissector_try_port(mtp3_sio_dissector_table, service_indicator, payload_tvb, pinfo, tree)) {
    call_dissector(data_handle, payload_tvb, pinfo, tree);
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_str(pinfo->cinfo, COL_INFO, "DATA ");
  }
}

/* Code to actually dissect the packets */
static void
dissect_mtp3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *mtp3_item = NULL;
  proto_tree *mtp3_tree = NULL;

  /* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP3");

  if (tree) {
    /* create display subtree for the protocol */
    switch (mtp3_standard) {
    case ITU_STANDARD:
      mtp3_item = proto_tree_add_item(tree, proto_mtp3, tvb, 0, ITU_HEADER_LENGTH, FALSE);
      break;
    case ANSI_STANDARD:
      mtp3_item = proto_tree_add_item(tree, proto_mtp3, tvb, 0, ANSI_HEADER_LENGTH, FALSE);
      break;
    }
    mtp3_tree = proto_item_add_subtree(mtp3_item, ett_mtp3);

    /* dissect the packet */
    dissect_mtp3_sio(tvb, mtp3_tree);
    dissect_mtp3_routing_label(tvb, mtp3_tree);
  }

  /* Need to dissect payload even if !tree so can call sub-dissectors */
  dissect_mtp3_payload(tvb, pinfo, tree);
}

void
proto_register_mtp3(void)
{

  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_mtp3_service_indicator,
      { "Service indicator", "mtp3.service_indicator",
        FT_UINT8, BASE_HEX, VALS(service_indicator_code_vals), SERVICE_INDICATOR_MASK,
	      "", HFILL }},
    { &hf_mtp3_network_indicator,
      { "Network indicator", "mtp3.network_indicator",
	      FT_UINT8, BASE_HEX, VALS(network_indicator_vals), NETWORK_INDICATOR_MASK,
	      "", HFILL }},
    { &hf_mtp3_itu_spare,
      { "Spare", "mtp3.spare",
	      FT_UINT8, BASE_HEX, NULL, SPARE_MASK,
	      "", HFILL }},
    { &hf_mtp3_ansi_priority,
      { "Priority", "mtp3.priority",
	      FT_UINT8, BASE_HEX, NULL, ANSI_PRIORITY_MASK,
	      "", HFILL }},
    { &hf_mtp3_itu_opc,
      { "OPC", "mtp3.opc",
	      FT_UINT32, BASE_DEC, NULL, ITU_OPC_MASK,
	      "", HFILL }},
    { &hf_mtp3_opc_network,
     { "OPC Network", "mtp3.opc.network",
	     FT_UINT24, BASE_DEC, NULL, ANSI_NETWORK_MASK,
	     "", HFILL }},
    { &hf_mtp3_opc_cluster,
      { "OPC Cluster", "mtp3.opc.cluster",
	      FT_UINT24, BASE_DEC, NULL, ANSI_CLUSTER_MASK,
	      "", HFILL }},
    { &hf_mtp3_opc_member,
      { "OPC Member", "mtp3.opc.member",
	      FT_UINT24, BASE_DEC, NULL, ANSI_MEMBER_MASK,
	      "", HFILL }},
    { &hf_mtp3_itu_dpc,
      { "DPC", "mtp3.dpc",
	      FT_UINT32, BASE_DEC, NULL, ITU_DPC_MASK,
	      "", HFILL }},
    { &hf_mtp3_dpc_network,
      { "DPC Network", "mtp3.dpc.network",
	      FT_UINT24, BASE_DEC, NULL, ANSI_NETWORK_MASK,
	      "", HFILL }},
    { &hf_mtp3_dpc_cluster,
      { "DPC Cluster", "mtp3.dpc.cluster",
	      FT_UINT24, BASE_DEC, NULL, ANSI_CLUSTER_MASK,
	      "", HFILL }},
    { &hf_mtp3_dpc_member,
      { "DPC Member", "mtp3.dpc.member",
	      FT_UINT24, BASE_DEC, NULL, ANSI_MEMBER_MASK,
	      "", HFILL }},
    { &hf_mtp3_itu_sls,
      { "Signalling Link Selector", "mtp3.sls",
	      FT_UINT32, BASE_DEC, NULL, ITU_SLS_MASK,
	      "", HFILL }},
    { &hf_mtp3_ansi_sls,
      { "Signalling Link Selector", "mtp3.sls",
	      FT_UINT8, BASE_DEC, NULL, ANSI_5BIT_SLS_MASK,
	      "", HFILL }}
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_mtp3,
    &ett_mtp3_sio,
    &ett_mtp3_label,
    &ett_mtp3_label_dpc,
    &ett_mtp3_label_opc
  };

  static enum_val_t mtp3_options[] = {
    { "ITU",  ITU_STANDARD },
    { "ANSI", ANSI_STANDARD },
    { NULL, 0 }
  };

  /* Register the protocol name and description */
  proto_mtp3 = proto_register_protocol("Message Transfer Part Level 3", "MTP3", "mtp3");
  register_dissector("mtp3", dissect_mtp3, proto_mtp3);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_mtp3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  mtp3_sio_dissector_table = register_dissector_table("mtp3.service_indicator", "MTP3 Service indicator", FT_UINT8, BASE_HEX);
  mtp3_module = prefs_register_protocol(proto_mtp3, NULL);
  prefs_register_enum_preference(mtp3_module, "mtp3_standard", "MTP3 standard", "MTP3 standard",  (gint *)&mtp3_standard, mtp3_options, FALSE);
}

void
proto_reg_handoff_mtp3(void)
{
  data_handle = find_dissector("data");
}
