/* packet-cpfi.c
 * Routines for CPFI Cross Point Frame Injector dissection
 * CPFI - Cross Point Frame Injector is a CNT proprietary
 * protocol used to carry Fibre Channel data over UDP
 *
 * Copyright 2003, Dave Sclarsky <dave_sclarsky[AT]cnt.com>
 *
 * $Id: packet-cpfi.c,v 1.1 2003/11/19 04:00:52 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-m2tp.c
 * Thanks to Heinz Prantner for his motivation and assistance
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

void proto_reg_handoff_cpfi(void);

#define CPFI_DEFAULT_UDP_PORT      5000

/* SOF defines */
#define CPFI_FRAME_TYPE_MASK  0xF0000000
#define CPFI_FRAME_TYPE_SHIFT 28
#define CPFI_SOURCE_MASK      0x0FFC0000
#define CPFI_SOURCE_SHIFT     18
#define CPFI_DEST_MASK        0x0003FF00
#define CPFI_DEST_SHIFT       8
#define CPFI_SOF_TYPE_MASK    0x000000F0
#define CPFI_SPEED_MASK       0x0000000C
#define CPFI_OPM_ERROR_MASK   0x00000002
#define CPFI_FROM_LCM_MASK    0x00000001

/* EOF defines */
#define CPFI_EOF_TYPE_MASK    0x78000000
#define CPFI_EOF_ERROR_MASK   0x7FE00000


/* Initialize the protocol and registered fields */
static int proto_cpfi = -1;
static int cpfi_configured_udp_port = CPFI_DEFAULT_UDP_PORT;
static int cpfi_current_udp_port;
static int hf_cpfi_word_one = -1;
static int hf_cpfi_word_two = -1;
/* SOF word 1: */
static int hf_cpfi_frame_type = -1;
static int hf_cpfi_source = -1;
static int hf_cpfi_dest = -1;
static int hf_cpfi_SOF_type = -1;
static int hf_cpfi_speed = -1;
static int hf_cpfi_OPM_error = -1;
static int hf_cpfi_from_LCM = -1;
/* SOF word 2: */
static int hf_cpfi_time_stamp = -1;
static int hf_cpfi_TBD = -1;
/* EOF */
static int hf_cpfi_CRC_32 = -1;
static int hf_cpfi_EOF_type = -1;
static int hf_cpfi_EOF_error = -1;

static guint32 word1;
static guint32 word2;
static guint8 frame_type;
static guint8 board;
static guint8 port;
const char *direction_and_port_string = "%u:%u";

/* Initialize the subtree pointers */
static gint ett_cpfi = -1;
static gint ett_cpfi_header = -1;
static gint ett_cpfi_footer = -1;

static dissector_handle_t fc_handle;
static dissector_handle_t data_handle;


static const value_string sof_type_vals[] = {
    {0,     "SOFf"},
    {1,     "SOFi2"},
    {2,     "SOFn2"},
    {3,     "SOFi3"},
    {4,     "SOFn3"},
    {5,     "SOFc1"},
    {6,     "SOFi1"},
    {7,     "SOFn1"},
    {8,     "SOFc4"},
    {9,     "SOFi4"},
    {10,    "SOFn4"},
    {0, NULL},
};

static const value_string speed_vals[] = {
    {0,     "1 GBIT"},
    {1,     "2 GBIT"},
    {2,     "4 GBIT"},
    {3,     "10 GBIT"},
    {0, NULL},
};

static const value_string eof_type_vals[] = {
    {0,     "EOFn"},
    {1,     "EOFt"},
    {2,     "EOFni"},
    {3,     "EOFa"},
    {4,     "EOFdt"},
    {5,     "EOFdti"},
    {6,     "EOFrt"},
    {7,     "EOFrti"},
    {0, NULL},
};

/* Header */
static void
dissect_cpfi_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint32 tda;
  proto_item *extra_item = NULL;
  proto_tree *extra_tree = NULL;

  /* add a tree for the header */
  if ( tree != NULL)
  {
    extra_item = proto_tree_add_protocol_format(tree, proto_cpfi, tvb, 0, -1, "Header");
    extra_tree = proto_item_add_subtree(extra_item, ett_cpfi_header);
  }

  /* Extract the common header, and get the bits we need */
  word1 = tvb_get_ntohl (tvb, 0);
  word2 = tvb_get_ntohl (tvb, sizeof(word1));

  frame_type = (word1 & CPFI_FRAME_TYPE_MASK) >> CPFI_FRAME_TYPE_SHIFT;
  /* Choose either source or dest as the one to display */
  if (pinfo->srcport == cpfi_current_udp_port)
  {
    direction_and_port_string = "[CPFI <-- % 2u/%-2u] ";
    tda = (word1 & CPFI_DEST_MASK) >> CPFI_DEST_SHIFT;
  }
  else
  {
    direction_and_port_string = "[CPFI --> % 2u/%-2u] ";
    tda = (word1 & CPFI_SOURCE_MASK) >> CPFI_SOURCE_SHIFT;
  }
  board = tda >> 4;
  port = tda & 0x0f;

  if (extra_tree) {
    /* add word 1 components to the protocol tree */
    proto_tree_add_item(extra_tree, hf_cpfi_word_one  , tvb, 0, 4, FALSE);

    proto_tree_add_item(extra_tree, hf_cpfi_frame_type, tvb, 0, 4, FALSE);
    proto_tree_add_item(extra_tree, hf_cpfi_source    , tvb, 0, 4, FALSE);
    proto_tree_add_item(extra_tree, hf_cpfi_dest      , tvb, 0, 4, FALSE);
    proto_tree_add_item(extra_tree, hf_cpfi_SOF_type  , tvb, 0, 4, FALSE);
    proto_tree_add_item(extra_tree, hf_cpfi_speed     , tvb, 0, 4, FALSE);
    proto_tree_add_item(extra_tree, hf_cpfi_OPM_error , tvb, 0, 4, FALSE);
    proto_tree_add_item(extra_tree, hf_cpfi_from_LCM  , tvb, 0, 4, FALSE);

    /* add word 2 components to the protocol tree */
    proto_tree_add_item(extra_tree, hf_cpfi_word_two  , tvb, 4, 4, FALSE);
  };
}

/* Footer */
static void
dissect_cpfi_footer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *extra_item = NULL;
  proto_tree *extra_tree = NULL;

  /* add a tree for the footer */
  if ( tree != NULL)
  {
    extra_item = proto_tree_add_protocol_format(tree, proto_cpfi, tvb, 0, -1, "Footer");
    extra_tree = proto_item_add_subtree(extra_item, ett_cpfi_footer);
  }

  if (extra_tree) {
    proto_tree_add_item(extra_tree, hf_cpfi_CRC_32  , tvb, 0, 4, FALSE);
    proto_tree_add_item(extra_tree, hf_cpfi_EOF_type, tvb, 4, 4, FALSE);
  }
}

/* CPFI */
static void
dissect_cpfi(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *header_tvb, *body_tvb, *footer_tvb;
  proto_item *cpfi_item = NULL;
  proto_tree *cpfi_tree = NULL;
  proto_item *extra_item = NULL;
  proto_tree *extra_tree = NULL;

  /* In the interest of speed, if "tree" is NULL, don't do any work not
     necessary to generate protocol tree items. */
  if (tree) {
    /* create the protocol tree */
    cpfi_item = proto_tree_add_item(tree, proto_cpfi, message_tvb, 0, -1, FALSE);
    cpfi_tree = proto_item_add_subtree(cpfi_item, ett_cpfi);
  }

  /* Set up the frame controls - can we do better than this? */
  pinfo->sof_eof = 0;
  pinfo->sof_eof = PINFO_SOF_FIRST_FRAME;
  pinfo->sof_eof |= PINFO_EOF_LAST_FRAME;
  pinfo->sof_eof |= PINFO_EOF_INVALID;

  /* dissect the message */

  /* extract and process the header */
  header_tvb = tvb_new_subset(message_tvb, 0, 8, 8);
  dissect_cpfi_header(header_tvb, pinfo, cpfi_tree);


  /* Got good CPFI frame? */
  if ( (frame_type == 9) && fc_handle )
  {
    /* create a tvb for the rest of the fc frame (exclude the checksum and CPFI trailer) */
    body_tvb = tvb_new_subset(message_tvb, 8, tvb_length(message_tvb)-16, -1);
    call_dissector(fc_handle, body_tvb, pinfo, tree);

    /* add more info, now that FC added it's */
    proto_item_append_text(cpfi_item, direction_and_port_string, board, port);
    if (check_col(pinfo->cinfo, COL_INFO))
    {
      col_prepend_fstr(pinfo->cinfo, COL_INFO, direction_and_port_string, board, port);
    }

    /* Do the footer */
    footer_tvb = tvb_new_subset(message_tvb, tvb_length(message_tvb)-8, 8, -1);
    dissect_cpfi_footer(footer_tvb, pinfo, cpfi_tree);

  }
  else if ( data_handle )
  {
    /* create a tvb for the rest of the frame */
    body_tvb = tvb_new_subset(message_tvb, 8, -1, -1);
    call_dissector(data_handle, body_tvb, pinfo, tree);
  }

}

/* Register the protocol with Ethereal */
void
proto_register_cpfi(void)
{
  module_t *cpfi_module;

  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_cpfi_word_one,
      { "Word one", "cpfi.word_one",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "", HFILL}},
    { &hf_cpfi_word_two,
      { "Word two", "cfpi.word_two",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "", HFILL}},

    { &hf_cpfi_frame_type,
      { "FrmType", "cpfi.frmtype",
        FT_UINT32, BASE_HEX, NULL, CPFI_FRAME_TYPE_MASK,
        "Frame Type", HFILL}},
    { &hf_cpfi_source,
      { "srcTDA", "cpfi.srcTDA",
        FT_UINT32, BASE_HEX, NULL, CPFI_SOURCE_MASK,
        "Source TDA (10 bits)", HFILL}},
    { &hf_cpfi_dest,
      { "dstTDA", "cpfi.dstTDA",
        FT_UINT32, BASE_HEX, NULL, CPFI_DEST_MASK,
        "Source TDA (10 bits)", HFILL}},
    { &hf_cpfi_SOF_type,
      { "SOFtype", "cpfi.SOFtype",
        FT_UINT32, BASE_HEX, VALS(sof_type_vals), CPFI_SOF_TYPE_MASK,
        "SOF Type", HFILL}},
    { &hf_cpfi_speed,
      { "speed", "cpfi.speed",
        FT_UINT32, BASE_HEX, VALS(speed_vals), CPFI_SPEED_MASK,
        "SOF Type", HFILL}},
    { &hf_cpfi_OPM_error,
      { "OPMerror", "cpfi.OPMerror",
        FT_BOOLEAN, 32, NULL, CPFI_OPM_ERROR_MASK,
        "OPM Error?", HFILL}},
    { &hf_cpfi_from_LCM,
      { "fromLCM", "cpfi.fromLCM",
        FT_BOOLEAN, 32, NULL, CPFI_FROM_LCM_MASK,
        "from LCM?", HFILL}},

    { &hf_cpfi_CRC_32,
      { "CRC-32", "cpfi.crc-32",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "", HFILL}},

    { &hf_cpfi_EOF_type,
      { "EOFtype", "cpfi.EOFtype",
        FT_UINT32, BASE_HEX, VALS(eof_type_vals), CPFI_EOF_TYPE_MASK,
        "EOF Type", HFILL}},
  };


  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_cpfi,
    &ett_cpfi_header,
    &ett_cpfi_footer
  };

  /* Register the protocol name and description */
  proto_cpfi = proto_register_protocol("Cross Point Frame Injector ", "CPFI",  "cpfi");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_cpfi, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for CPFI */
  cpfi_module = prefs_register_protocol(proto_cpfi, proto_reg_handoff_cpfi);
  prefs_register_uint_preference(cpfi_module, "upd.port", "CPFI UDP Port",
                 "Set the port for CPFI messages (if other"
                 " than the default of 5000)",
                 10, &cpfi_configured_udp_port);
};

void
proto_reg_handoff_cpfi(void)
{
  static int cpfi_init_complete = FALSE;
  static dissector_handle_t cpfi_handle;
  if ( !cpfi_init_complete )
  {
    cpfi_init_complete = TRUE;
    fc_handle     = find_dissector("fc");
    data_handle   = find_dissector("data");
    cpfi_handle   = create_dissector_handle(dissect_cpfi, proto_cpfi);
  }
  else
  {
    dissector_delete("udp.port", cpfi_current_udp_port, cpfi_handle);
  }

  /* remember udp port for later use */
  cpfi_current_udp_port = cpfi_configured_udp_port;

  dissector_add("udp.port", cpfi_current_udp_port, cpfi_handle);
}
