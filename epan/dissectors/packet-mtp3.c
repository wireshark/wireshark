/* packet-mtp3.c
 * Routines for Message Transfer Part Level 3 dissection
 *
 * It is (hopefully) compliant to:
 *   ANSI T1.111.4-1996
 *   ITU-T Q.704 7/1996
 *   GF 001-9001 (Chinese ITU variant)
 *
 * Copyright 2001, Michael Tuexen <tuexen [AT] fh-muenster.de>
 * Updated for ANSI and Chinese ITU support by Jeff Morriss <jeff.morriss[AT]ulticom.com>
 *
 * $Id$
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

#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/prefs.h>
#include <epan/emem.h>

/* Initialize the protocol and registered fields */
static int proto_mtp3  = -1;

static int mtp3_tap = -1;

static module_t *mtp3_module;

static int hf_mtp3_service_indicator = -1;
static int hf_mtp3_network_indicator = -1;
static int hf_mtp3_itu_spare = -1;
static int hf_mtp3_ansi_priority = -1;
static int hf_mtp3_itu_pc = -1;
static int hf_mtp3_24bit_pc = -1;
static int hf_mtp3_itu_opc = -1;
static int hf_mtp3_24bit_opc = -1;
static int hf_mtp3_ansi_opc = -1;
static int hf_mtp3_chinese_opc = -1;
static int hf_mtp3_opc_network = -1;
static int hf_mtp3_opc_cluster = -1;
static int hf_mtp3_opc_member = -1;
static int hf_mtp3_itu_dpc = -1;
static int hf_mtp3_24bit_dpc = -1;
static int hf_mtp3_ansi_dpc = -1;
static int hf_mtp3_chinese_dpc = -1;
static int hf_mtp3_dpc_network = -1;
static int hf_mtp3_dpc_cluster = -1;
static int hf_mtp3_dpc_member = -1;
static int hf_mtp3_itu_sls = -1;
static int hf_mtp3_ansi_5_bit_sls = -1;
static int hf_mtp3_ansi_8_bit_sls = -1;
static int hf_mtp3_chinese_itu_sls = -1;

/* Initialize the subtree pointers */
static gint ett_mtp3 = -1;
static gint ett_mtp3_sio = -1;
static gint ett_mtp3_label = -1;
static gint ett_mtp3_label_dpc = -1;
static gint ett_mtp3_label_opc = -1;

static dissector_table_t mtp3_sio_dissector_table;

typedef enum {
  ITU_PC_STRUCTURE_NONE    = 1,
  ITU_PC_STRUCTURE_3_8_3   = 2,
  ITU_PC_STRUCTURE_4_3_4_3 = 3
} ITU_PC_Structure_Type;

gint itu_pc_structure = ITU_PC_STRUCTURE_NONE;

#include <packet-mtp3.h>
gint mtp3_standard = ITU_STANDARD;

static gboolean mtp3_use_ansi_5_bit_sls = FALSE;
static gint mtp3_net_addr_fmt = MTP3_NET_ADDR_FMT_DASHED;
static mtp3_addr_pc_t mtp3_addr_dpc, mtp3_addr_opc;

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
#define ANSI_8BIT_SLS_MASK             0xFF
#define CHINESE_ITU_SLS_MASK           0xF

/* the higher values are taken from the M3UA RFC */
static const value_string mtp3_service_indicator_code_vals[] = {
        { 0x0,  "Signalling Network Management Message (SNM)" },
        { 0x1,  "Maintenance Regular Message (MTN)" },
        { 0x2,  "Maintenance Special Message (MTNS)" },
        { 0x3,  "SCCP" },
        { 0x4,  "TUP" },
        { 0x5,  "ISUP" },
        { 0x6,  "DUP (call and circuit related messages)" },
        { 0x7,  "DUP (facility registration and cancellation message)" },
        { 0x8,  "MTP testing user part" },
        { 0x9,  "Broadband ISUP" },
        { 0xa,  "Satellite ISUP" },
        { 0xb,  "Spare" },
        { 0xc,  "AAL type2 Signaling" },
        { 0xd,  "Bearer Independent Call Control (BICC)" },
        { 0xe,  "Gateway Control Protocol" },
        { 0xf,  "Spare" },
        { 0,    NULL }
};

const value_string mtp3_service_indicator_code_short_vals[] = {
        { 0x0,  "SNM" },
        { 0x1,  "MTN" },
        { 0x2,  "MTNS" },
        { 0x3,  "SCCP" },
        { 0x4,  "TUP" },
        { 0x5,  "ISUP" },
        { 0x6,  "DUP (CC)" },
        { 0x7,  "DUP (FAC/CANC)" },
        { 0x8,  "MTP Test" },
        { 0x9,  "ISUP-b" },
        { 0xa,  "ISUP-s" },
        { 0xc,  "AAL type 2" },
        { 0xd,  "BICC" },
        { 0xe,  "GCP" },
        { 0,    NULL }
};

static const value_string network_indicator_vals[] = {
        { 0x0,  "International network" },
        { 0x1,  "Spare (for international use only)" },
        { 0x2,  "National network" },
        { 0x3,  "Reserved for national use" },
        { 0,    NULL }
};

static dissector_handle_t data_handle;


/*
 * helper routine to format a point code in structured form
 */

void 
mtp3_pc_to_str_buf(const guint32 pc, gchar *buf, int buf_len)
{
  switch (mtp3_standard)
  {
    case ITU_STANDARD:
      switch (itu_pc_structure) {
        case ITU_PC_STRUCTURE_NONE:
          g_snprintf(buf, buf_len, "%u", pc);
          break;
        case ITU_PC_STRUCTURE_3_8_3:
          /* this format is used in international ITU networks */
          g_snprintf(buf, buf_len, "%u-%u-%u", (pc & 0x3800)>>11, (pc & 0x7f8) >> 3, (pc & 0x07) >> 0);
          break;
        case ITU_PC_STRUCTURE_4_3_4_3:
          /* this format is used in some national ITU networks, the German one for example. */
          g_snprintf(buf, buf_len, "%u-%u-%u-%u", (pc & 0x3c00) >>10, (pc & 0x0380) >> 7, (pc & 0x0078) >> 3, (pc & 0x0007) >> 0);
          break;
        default:
          DISSECTOR_ASSERT_NOT_REACHED();
      }
      break;
    case ANSI_STANDARD:
    case CHINESE_ITU_STANDARD:
      g_snprintf(buf, buf_len, "%u-%u-%u", (pc & ANSI_NETWORK_MASK), (pc & ANSI_CLUSTER_MASK) >> 8, (pc & ANSI_MEMBER_MASK) >> 16);
      break;
    default:
      DISSECTOR_ASSERT_NOT_REACHED();
  }
}

#define MAX_STRUCTURED_PC_LENGTH 20

gchar *
mtp3_pc_to_str(const guint32 pc)
{
  gchar *str;
  
  str=ep_alloc(MAX_STRUCTURED_PC_LENGTH);
  mtp3_pc_to_str_buf(pc, str, MAX_STRUCTURED_PC_LENGTH);
  return str;
}

gboolean
mtp3_pc_structured(void)
{
  if ((mtp3_standard == ITU_STANDARD) && (itu_pc_structure == ITU_PC_STRUCTURE_NONE))
    return FALSE;
  else
    return TRUE;
}

/*
 * helper routine to format address to string
 */
 
void
mtp3_addr_to_str_buf(
  const guint8          *data,
  gchar                 *buf,
  int                   buf_len)
{
  const mtp3_addr_pc_t  *addr_pc_p = (const mtp3_addr_pc_t *)data;

  switch (mtp3_net_addr_fmt)
  {
  case MTP3_NET_ADDR_FMT_DEC:
    switch (addr_pc_p->type)
    {
    case ITU_STANDARD:
      g_snprintf(buf, buf_len, "%u", addr_pc_p->pc & ITU_PC_MASK);
      break;
    default:
      /* assuming 24-bit */
      g_snprintf(buf, buf_len, "%u", addr_pc_p->pc & ANSI_PC_MASK);
      break;
    }
    break;

  case MTP3_NET_ADDR_FMT_HEX:
    switch (addr_pc_p->type)
    {
    case ITU_STANDARD:
      g_snprintf(buf, buf_len, "%x", addr_pc_p->pc & ITU_PC_MASK);
      break;
    default:
      /* assuming 24-bit */
      g_snprintf(buf, buf_len, "%x", addr_pc_p->pc & ANSI_PC_MASK);
      break;
    }
    break;

  case MTP3_NET_ADDR_FMT_NI_DEC:
    switch (addr_pc_p->type)
    {
    case ITU_STANDARD:
      g_snprintf(buf, buf_len, "%u:%u", addr_pc_p->ni, addr_pc_p->pc & ITU_PC_MASK);
      break;
    default:
      /* assuming 24-bit */
      g_snprintf(buf, buf_len, "%u:%u", addr_pc_p->ni, addr_pc_p->pc & ANSI_PC_MASK);
      break;
    }
    break;

  case MTP3_NET_ADDR_FMT_NI_HEX:
    switch (addr_pc_p->type)
    {
    case ITU_STANDARD:
      g_snprintf(buf, buf_len, "%u:%x", addr_pc_p->ni, addr_pc_p->pc & ITU_PC_MASK);
      break;
    default:
      /* assuming 24-bit */
      g_snprintf(buf, buf_len, "%u:%x", addr_pc_p->ni, addr_pc_p->pc & ANSI_PC_MASK);
      break;
    }
    break;

  default:
    /* FALLTHRU */

  case MTP3_NET_ADDR_FMT_DASHED:
    mtp3_pc_to_str_buf(addr_pc_p->pc, buf, buf_len);
    break;
  }
}

static void
dissect_mtp3_sio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mtp3_tree)
{
  guint8 sio;
  proto_item *sio_item;
  proto_tree *sio_tree;

  sio_item = proto_tree_add_text(mtp3_tree, tvb, SIO_OFFSET, SIO_LENGTH, "Service information octet");
  sio_tree = proto_item_add_subtree(sio_item, ett_mtp3_sio);

  sio = tvb_get_guint8(tvb, SIO_OFFSET);
  proto_tree_add_uint(sio_tree, hf_mtp3_network_indicator, tvb, SIO_OFFSET, SIO_LENGTH, sio);

  mtp3_addr_opc.ni = (sio & NETWORK_INDICATOR_MASK) >> 6;
  mtp3_addr_dpc.ni = (sio & NETWORK_INDICATOR_MASK) >> 6;

  switch(mtp3_standard){
  case ANSI_STANDARD:
    proto_tree_add_uint(sio_tree, hf_mtp3_ansi_priority, tvb, SIO_OFFSET, SIO_LENGTH, sio);
    break;
  case ITU_STANDARD:
  case CHINESE_ITU_STANDARD:
    proto_tree_add_uint(sio_tree, hf_mtp3_itu_spare, tvb, SIO_OFFSET, SIO_LENGTH, sio);
    break;
  }

  proto_tree_add_uint(sio_tree, hf_mtp3_service_indicator, tvb, SIO_OFFSET, SIO_LENGTH, sio);

  /* Store the SI so that subidissectors know what SI this msg is */
  pinfo->private_data = GUINT_TO_POINTER(sio & SERVICE_INDICATOR_MASK);
}

static void
dissect_mtp3_routing_label(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mtp3_tree)
{
  guint32 label, dpc = 0, opc = 0;
  proto_item *label_item, *label_dpc_item, *label_opc_item;
  proto_tree *label_tree, *label_dpc_tree, *label_opc_tree;
  int *hf_dpc_string;
  int *hf_opc_string;


  switch (mtp3_standard) {
  case ITU_STANDARD:
    label_item = proto_tree_add_text(mtp3_tree, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, "Routing label");
    label_tree = proto_item_add_subtree(label_item, ett_mtp3_label);

    label = tvb_get_letohl(tvb, ITU_ROUTING_LABEL_OFFSET);

    opc = (label & ITU_OPC_MASK) >> 14;
    dpc =  label & ITU_DPC_MASK;

    proto_tree_add_uint_hidden(label_tree, hf_mtp3_itu_pc, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, opc);
    proto_tree_add_uint_hidden(label_tree, hf_mtp3_itu_pc, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, dpc);

    label_dpc_item = proto_tree_add_uint(label_tree, hf_mtp3_itu_dpc, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, label);
    if (mtp3_pc_structured())
      proto_item_append_text(label_dpc_item, " (%s)", mtp3_pc_to_str(dpc));

    label_opc_item = proto_tree_add_uint(label_tree, hf_mtp3_itu_opc, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, label);
    if (mtp3_pc_structured())
      proto_item_append_text(label_opc_item, " (%s)", mtp3_pc_to_str(opc));

    proto_tree_add_uint(label_tree, hf_mtp3_itu_sls, tvb, ITU_ROUTING_LABEL_OFFSET, ITU_ROUTING_LABEL_LENGTH, label);
    break;

  case ANSI_STANDARD:
  case CHINESE_ITU_STANDARD:
    if (mtp3_standard == ANSI_STANDARD)
    {
      hf_dpc_string = &hf_mtp3_ansi_dpc;
      hf_opc_string = &hf_mtp3_ansi_opc;
    } else /* CHINESE_ITU_STANDARD */ {
      hf_dpc_string = &hf_mtp3_chinese_dpc;
      hf_opc_string = &hf_mtp3_chinese_opc;
    }

    /* Create the Routing Label Tree */
    label_item = proto_tree_add_text(mtp3_tree, tvb, ANSI_ROUTING_LABEL_OFFSET, ANSI_ROUTING_LABEL_LENGTH, "Routing label");
    label_tree = proto_item_add_subtree(label_item, ett_mtp3_label);

    /* create the DPC tree */
    dpc = tvb_get_ntoh24(tvb, ANSI_DPC_OFFSET);
    label_dpc_item = proto_tree_add_string_format(label_tree, *hf_dpc_string, tvb, ANSI_DPC_OFFSET, ANSI_PC_LENGTH, mtp3_pc_to_str(dpc), "DPC (%s) (%u)", mtp3_pc_to_str(dpc), dpc);
    label_dpc_tree = proto_item_add_subtree(label_dpc_item, ett_mtp3_label_dpc);

    proto_tree_add_uint(label_dpc_tree, hf_mtp3_dpc_member,  tvb, ANSI_DPC_OFFSET + ANSI_MEMBER_OFFSET,  ANSI_NCM_LENGTH, dpc);
    proto_tree_add_uint(label_dpc_tree, hf_mtp3_dpc_cluster, tvb, ANSI_DPC_OFFSET + ANSI_CLUSTER_OFFSET, ANSI_NCM_LENGTH, dpc);
    proto_tree_add_uint(label_dpc_tree, hf_mtp3_dpc_network, tvb, ANSI_DPC_OFFSET + ANSI_NETWORK_OFFSET, ANSI_NCM_LENGTH, dpc);

    /* add full integer values of DPC as hidden for filtering purposes */
    proto_tree_add_uint_hidden(label_dpc_tree, hf_mtp3_24bit_dpc, tvb, ANSI_DPC_OFFSET, ANSI_PC_LENGTH, dpc);
    proto_tree_add_uint_hidden(label_dpc_tree, hf_mtp3_24bit_pc,  tvb, ANSI_DPC_OFFSET, ANSI_PC_LENGTH, dpc);

    /* create the OPC tree */
    opc = tvb_get_ntoh24(tvb, ANSI_OPC_OFFSET);
    label_opc_item = proto_tree_add_string_format(label_tree, *hf_opc_string, tvb, ANSI_OPC_OFFSET, ANSI_PC_LENGTH, mtp3_pc_to_str(opc), "OPC (%s) (%u)", mtp3_pc_to_str(opc), opc);
    label_opc_tree = proto_item_add_subtree(label_opc_item, ett_mtp3_label_opc);

    proto_tree_add_uint(label_opc_tree, hf_mtp3_opc_member,  tvb, ANSI_OPC_OFFSET + ANSI_MEMBER_OFFSET,  ANSI_NCM_LENGTH, opc);
    proto_tree_add_uint(label_opc_tree, hf_mtp3_opc_cluster, tvb, ANSI_OPC_OFFSET + ANSI_CLUSTER_OFFSET, ANSI_NCM_LENGTH, opc);
    proto_tree_add_uint(label_opc_tree, hf_mtp3_opc_network, tvb, ANSI_OPC_OFFSET + ANSI_NETWORK_OFFSET, ANSI_NCM_LENGTH, opc);

    /* add full integer values of OPC as hidden for filtering purposes */
    proto_tree_add_uint_hidden(label_opc_tree, hf_mtp3_24bit_opc, tvb, ANSI_OPC_OFFSET, ANSI_PC_LENGTH, opc);
    proto_tree_add_uint_hidden(label_opc_tree, hf_mtp3_24bit_pc,  tvb, ANSI_OPC_OFFSET, ANSI_PC_LENGTH, opc);

    /* SLS */
    if (mtp3_standard == ANSI_STANDARD) {
      if (mtp3_use_ansi_5_bit_sls)
        proto_tree_add_item(label_tree, hf_mtp3_ansi_5_bit_sls, tvb, ANSI_SLS_OFFSET, ANSI_SLS_LENGTH, TRUE);
      else
        proto_tree_add_item(label_tree, hf_mtp3_ansi_8_bit_sls, tvb, ANSI_SLS_OFFSET, ANSI_SLS_LENGTH, TRUE);
    } else /* CHINESE_ITU_STANDARD */ {
      proto_tree_add_item(label_tree, hf_mtp3_chinese_itu_sls, tvb, ANSI_SLS_OFFSET, ITU_SLS_LENGTH, FALSE);
    }
    break;
  }

  mtp3_addr_opc.type = mtp3_standard;
  mtp3_addr_opc.pc = opc;
  SET_ADDRESS(&pinfo->src, AT_SS7PC, sizeof(mtp3_addr_opc), (guint8 *) &mtp3_addr_opc);

  mtp3_addr_dpc.type = mtp3_standard;
  mtp3_addr_dpc.pc = dpc;
  SET_ADDRESS(&pinfo->dst, AT_SS7PC, sizeof(mtp3_addr_dpc), (guint8 *) &mtp3_addr_dpc);
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
  case CHINESE_ITU_STANDARD:
    payload_tvb = tvb_new_subset(tvb, ANSI_MTP_PAYLOAD_OFFSET, -1, -1);
    break;
  }

  if (check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "DATA ");

  if (!dissector_try_port(mtp3_sio_dissector_table, service_indicator, payload_tvb, pinfo, tree))
    call_dissector(data_handle, payload_tvb, pinfo, tree);
}

/* Code to actually dissect the packets */
static void
dissect_mtp3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  static mtp3_tap_rec_t tap_rec;

  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *mtp3_item = NULL;
  proto_tree *mtp3_tree = NULL;

  /* Make entries in Protocol column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    switch(mtp3_standard) {
      case ITU_STANDARD:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP3 (Int. ITU)");
        break;
      case ANSI_STANDARD:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP3 (ANSI)");
        break;
      case CHINESE_ITU_STANDARD:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MTP3 (Chin. ITU)");
        break;
    };      

  if (tree) {
    /* create display subtree for the protocol */
    switch (mtp3_standard) {
    case ITU_STANDARD:
      mtp3_item = proto_tree_add_item(tree, proto_mtp3, tvb, 0, ITU_HEADER_LENGTH, TRUE);
      break;
    case ANSI_STANDARD:
    case CHINESE_ITU_STANDARD:
      mtp3_item = proto_tree_add_item(tree, proto_mtp3, tvb, 0, ANSI_HEADER_LENGTH, TRUE);
      break;
    }
    mtp3_tree = proto_item_add_subtree(mtp3_item, ett_mtp3);

  }

  memset(&mtp3_addr_opc, 0, sizeof(mtp3_addr_opc));
  memset(&mtp3_addr_dpc, 0, sizeof(mtp3_addr_dpc));

  /* Dissect the packet (even if !tree so can call sub-dissectors and update
   * the source and destination address columns) */
  dissect_mtp3_sio(tvb, pinfo, mtp3_tree);
  dissect_mtp3_routing_label(tvb, pinfo, mtp3_tree);

  tap_rec.addr_opc = mtp3_addr_opc;
  tap_rec.addr_dpc = mtp3_addr_dpc;
  tap_rec.si_code = (tvb_get_guint8(tvb, SIO_OFFSET) & SERVICE_INDICATOR_MASK);
  tap_rec.size = tvb_length(tvb);

  tap_queue_packet(mtp3_tap, pinfo, &tap_rec);

  dissect_mtp3_payload(tvb, pinfo, tree);
}

void
proto_register_mtp3(void)
{

  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_mtp3_service_indicator, { "Service indicator",        "mtp3.service_indicator", FT_UINT8,  BASE_HEX,  VALS(mtp3_service_indicator_code_vals), SERVICE_INDICATOR_MASK, "", HFILL }},
    { &hf_mtp3_network_indicator, { "Network indicator",        "mtp3.network_indicator", FT_UINT8,  BASE_HEX,  VALS(network_indicator_vals),           NETWORK_INDICATOR_MASK, "", HFILL }},
    { &hf_mtp3_itu_spare,         { "Spare",                    "mtp3.spare",             FT_UINT8,  BASE_HEX,  NULL,                                   SPARE_MASK,             "", HFILL }},
    { &hf_mtp3_ansi_priority,     { "Priority",                 "mtp3.priority",          FT_UINT8,  BASE_HEX,  NULL,                                   ANSI_PRIORITY_MASK,     "", HFILL }},
    { &hf_mtp3_itu_opc,           { "OPC",                      "mtp3.opc",               FT_UINT32, BASE_DEC,  NULL,                                   ITU_OPC_MASK,           "", HFILL }},
    { &hf_mtp3_itu_pc,            { "PC",                       "mtp3.pc",                FT_UINT32, BASE_DEC,  NULL,                                   0x0,                    "", HFILL }},
    { &hf_mtp3_24bit_pc,          { "PC",                       "mtp3.pc",                FT_UINT32, BASE_DEC,  NULL,                                   ANSI_PC_MASK,           "", HFILL }},
    { &hf_mtp3_24bit_opc,         { "OPC",                      "mtp3.opc",               FT_UINT32, BASE_DEC,  NULL,                                   ANSI_PC_MASK,           "", HFILL }},
    { &hf_mtp3_ansi_opc,          { "DPC",                      "mtp3.ansi_opc",          FT_STRING, BASE_NONE, NULL,                                   0x0,                    "", HFILL }},
    { &hf_mtp3_chinese_opc,       { "DPC",                      "mtp3.chinese_opc",       FT_STRING, BASE_NONE, NULL,                                   0x0,                    "", HFILL }},
    { &hf_mtp3_opc_network,       { "OPC Network",              "mtp3.opc.network",       FT_UINT24, BASE_DEC,  NULL,                                   ANSI_NETWORK_MASK,      "", HFILL }},
    { &hf_mtp3_opc_cluster,       { "OPC Cluster",              "mtp3.opc.cluster",       FT_UINT24, BASE_DEC,  NULL,                                   ANSI_CLUSTER_MASK,      "", HFILL }},
    { &hf_mtp3_opc_member,        { "OPC Member",               "mtp3.opc.member",        FT_UINT24, BASE_DEC,  NULL,                                   ANSI_MEMBER_MASK,       "", HFILL }},
    { &hf_mtp3_itu_dpc,           { "DPC",                      "mtp3.dpc",               FT_UINT32, BASE_DEC,  NULL,                                   ITU_DPC_MASK,           "", HFILL }},
    { &hf_mtp3_24bit_dpc,         { "DPC",                      "mtp3.dpc",               FT_UINT32, BASE_DEC,  NULL,                                   ANSI_PC_MASK,           "", HFILL }},
    { &hf_mtp3_ansi_dpc,          { "DPC",                      "mtp3.ansi_dpc",          FT_STRING, BASE_NONE, NULL,                                   0x0,                    "", HFILL }},
    { &hf_mtp3_chinese_dpc,       { "DPC",                      "mtp3.chinese_dpc",       FT_STRING, BASE_NONE, NULL,                                   0x0,                    "", HFILL }},
    { &hf_mtp3_dpc_network,       { "DPC Network",              "mtp3.dpc.network",       FT_UINT24, BASE_DEC,  NULL,                                   ANSI_NETWORK_MASK,      "", HFILL }},
    { &hf_mtp3_dpc_cluster,       { "DPC Cluster",              "mtp3.dpc.cluster",       FT_UINT24, BASE_DEC,  NULL,                                   ANSI_CLUSTER_MASK,      "", HFILL }},
    { &hf_mtp3_dpc_member,        { "DPC Member",               "mtp3.dpc.member",        FT_UINT24, BASE_DEC,  NULL,                                   ANSI_MEMBER_MASK,       "", HFILL }},
    { &hf_mtp3_itu_sls,           { "Signalling Link Selector", "mtp3.sls",               FT_UINT32, BASE_DEC,  NULL,                                   ITU_SLS_MASK,           "", HFILL }},
    { &hf_mtp3_ansi_5_bit_sls,    { "Signalling Link Selector", "mtp3.sls",               FT_UINT8,  BASE_DEC,  NULL,                                   ANSI_5BIT_SLS_MASK,     "", HFILL }},
    { &hf_mtp3_ansi_8_bit_sls,    { "Signalling Link Selector", "mtp3.sls",               FT_UINT8,  BASE_DEC,  NULL,                                   ANSI_8BIT_SLS_MASK,     "", HFILL }},
    { &hf_mtp3_chinese_itu_sls,   { "Signalling Link Selector", "mtp3.sls",               FT_UINT8,  BASE_DEC,  NULL,                                   CHINESE_ITU_SLS_MASK,   "", HFILL }}
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
    { "itu",         "ITU",         ITU_STANDARD },
    { "ansi",        "ANSI",        ANSI_STANDARD },
    { "chinese-itu", "Chinese ITU", CHINESE_ITU_STANDARD },
    { NULL, NULL, 0 }
  };

  static enum_val_t mtp3_net_addr_fmt_str_e[] = {
    { "decimal",        "Decimal",              MTP3_NET_ADDR_FMT_DEC },
    { "hexadecimal",    "Hexadecimal",          MTP3_NET_ADDR_FMT_HEX },
    { "ni-decimal",     "NI-Decimal",           MTP3_NET_ADDR_FMT_NI_DEC },
    { "ni-hexadecimal", "NI-Hexadecimal",       MTP3_NET_ADDR_FMT_NI_HEX },
    { "dashed",         "Dashed",               MTP3_NET_ADDR_FMT_DASHED },
    { NULL,             NULL,                   0 }
  };

  static enum_val_t itu_pc_structures[] = {
    { "unstructured", "Unstructured", ITU_PC_STRUCTURE_NONE},
    { "3-8-3",        "3-8-3",        ITU_PC_STRUCTURE_3_8_3 },
    { "4-3-4-3",      "4-3-4-3",      ITU_PC_STRUCTURE_4_3_4_3 },
    { NULL,           NULL,           0 }
  };
  
 /* Register the protocol name and description */
  proto_mtp3 = proto_register_protocol("Message Transfer Part Level 3",
                                       "MTP3", "mtp3");
  register_dissector("mtp3", dissect_mtp3, proto_mtp3);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_mtp3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  mtp3_sio_dissector_table = register_dissector_table("mtp3.service_indicator",
                                                      "MTP3 Service indicator",
                                                      FT_UINT8, BASE_HEX);

  mtp3_tap = register_tap("mtp3");

  mtp3_module = prefs_register_protocol(proto_mtp3, NULL);

  prefs_register_enum_preference(mtp3_module, "standard", "MTP3 standard",
                                 "The SS7 standard used in MTP3 packets",
                                 &mtp3_standard, mtp3_options, FALSE);

  prefs_register_enum_preference(mtp3_module, "itu_pc_structure", "ITU Pointcode structure",
                                 "The structure of the pointcodes in ITU networks",
                                 &itu_pc_structure, itu_pc_structures, FALSE);

  prefs_register_bool_preference(mtp3_module, "ansi_5_bit_sls",
                                 "Use 5-bit SLS (ANSI only)",
                                 "Use 5-bit (instead of 8-bit) SLS in ANSI MTP3 packets",
                                 &mtp3_use_ansi_5_bit_sls);

  prefs_register_enum_preference(mtp3_module, "net_addr_format", "Network Address Format",
                                 "Format for point code in the network address columns",
                                 &mtp3_net_addr_fmt, mtp3_net_addr_fmt_str_e, FALSE);
}

void
proto_reg_handoff_mtp3(void)
{
  dissector_handle_t mtp3_handle;        
         
  mtp3_handle = create_dissector_handle(dissect_mtp3, proto_mtp3);       
                 
  dissector_add("wtap_encap", WTAP_ENCAP_MTP3, mtp3_handle);     
  dissector_add_string("tali.opcode", "mtp3", mtp3_handle);
                 
  data_handle = find_dissector("data");
}
