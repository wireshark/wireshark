/* packet-ascend.c
 * Routines for decoding Lucent/Ascend packet traces
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

static int proto_ascend  = -1;
static int hf_link_type  = -1;
static int hf_session_id = -1;
static int hf_called_number = -1;
static int hf_chunk      = -1;
static int hf_task       = -1;
static int hf_user_name  = -1;

static gint ett_raw = -1;

static const value_string encaps_vals[] = {
  {ASCEND_PFX_WDS_X, "PPP Transmit"},
  {ASCEND_PFX_WDS_R, "PPP Receive" },
  {ASCEND_PFX_WDD,   "Ethernet"    },
  {0,                NULL          } };

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t ppp_hdlc_handle;

static void
dissect_ascend(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree                    *fh_tree;
  proto_item                    *ti, *hidden_item;
  union wtap_pseudo_header      *pseudo_header = pinfo->pseudo_header;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
  col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "N/A");
  col_set_str(pinfo->cinfo, COL_INFO, "Lucent/Ascend packet trace");

  /* If this is a transmitted or received PPP frame, set the PPP direction. */
  switch (pseudo_header->ascend.type) {

  case ASCEND_PFX_WDS_X:
    pinfo->p2p_dir = P2P_DIR_SENT;
    break;

  case ASCEND_PFX_WDS_R:
    pinfo->p2p_dir = P2P_DIR_RECV;
    break;
  }

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  if(tree) {
    ti = proto_tree_add_protocol_format(tree, proto_ascend, tvb, 0, 0,
                                        "Lucent/Ascend packet trace");
    fh_tree = proto_item_add_subtree(ti, ett_raw);
    proto_tree_add_uint(fh_tree, hf_link_type, tvb, 0, 0,
                        pseudo_header->ascend.type);
    if (pseudo_header->ascend.type == ASCEND_PFX_WDD) {
      proto_tree_add_string(fh_tree, hf_called_number, tvb, 0, 0,
                            pseudo_header->ascend.call_num);
      proto_tree_add_uint(fh_tree, hf_chunk, tvb, 0, 0,
                          pseudo_header->ascend.chunk);
      hidden_item = proto_tree_add_uint(fh_tree, hf_session_id, tvb, 0, 0, 0);
      PROTO_ITEM_SET_HIDDEN(hidden_item);
    } else {  /* It's wandsession data */
      proto_tree_add_string(fh_tree, hf_user_name, tvb, 0, 0,
                            pseudo_header->ascend.user);
      proto_tree_add_uint(fh_tree, hf_session_id, tvb, 0, 0,
                          pseudo_header->ascend.sess);
      hidden_item = proto_tree_add_uint(fh_tree, hf_chunk, tvb, 0, 0, 0);
      PROTO_ITEM_SET_HIDDEN(hidden_item);
    }
    proto_tree_add_uint(fh_tree, hf_task, tvb, 0, 0, pseudo_header->ascend.task);
  }

  switch (pseudo_header->ascend.type) {
    case ASCEND_PFX_WDS_X:
    case ASCEND_PFX_WDS_R:
      call_dissector(ppp_hdlc_handle, tvb, pinfo, tree);
      break;
    case ASCEND_PFX_WDD:
      call_dissector(eth_withoutfcs_handle, tvb, pinfo, tree);
      break;
    default:
      break;
  }
}

void
proto_register_ascend(void)
{
  static hf_register_info hf[] = {
    { &hf_link_type,
      { "Link type",      "ascend.type",  FT_UINT32, BASE_DEC,    VALS(encaps_vals),      0x0,
        NULL, HFILL }},

    { &hf_session_id,
      { "Session ID",     "ascend.sess",  FT_UINT32, BASE_DEC,    NULL, 0x0,
        NULL, HFILL }},

    { &hf_called_number,
      { "Called number",  "ascend.number", FT_STRING, BASE_NONE,  NULL, 0x0,
        NULL, HFILL }},

    { &hf_chunk,
      { "WDD Chunk",      "ascend.chunk", FT_UINT32, BASE_HEX,    NULL, 0x0,
        NULL, HFILL }},

    { &hf_task,
      { "Task",           "ascend.task",  FT_UINT32, BASE_HEX,    NULL, 0x0,
        NULL, HFILL }},

    { &hf_user_name,
      { "User name",      "ascend.user",  FT_STRING, BASE_NONE,   NULL, 0x0,
        NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_raw,
  };

  proto_ascend = proto_register_protocol("Lucent/Ascend debug output",
                                         "Lucent/Ascend", "ascend");
  proto_register_field_array(proto_ascend, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ascend(void)
{
  dissector_handle_t ascend_handle;

  /*
   * Get handles for the Ethernet and PPP-in-HDLC-like-framing dissectors.
   */
  eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
  ppp_hdlc_handle = find_dissector("ppp_hdlc");

  ascend_handle = create_dissector_handle(dissect_ascend, proto_ascend);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_ASCEND, ascend_handle);
}
