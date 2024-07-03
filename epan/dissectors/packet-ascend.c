/* packet-ascend.c
 * Routines for decoding Lucent/Ascend packet traces
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

void proto_register_ascend(void);
void proto_reg_handoff_ascend(void);

static int proto_ascend;
static int hf_link_type;
static int hf_session_id;
static int hf_called_number;
static int hf_chunk;
static int hf_task;
static int hf_user_name;

static int ett_raw;

static const value_string encaps_vals[] = {
  {ASCEND_PFX_WDS_X,  "PPP Transmit"               },
  {ASCEND_PFX_WDS_R,  "PPP Receive"                },
  {ASCEND_PFX_WDD,    "Ethernet triggering dialout"},
  {ASCEND_PFX_ISDN_X, "ISDN Transmit"              },
  {ASCEND_PFX_ISDN_R, "ISDN Receive"               },
  {ASCEND_PFX_ETHER,  "Ethernet"                   },
  {0,                  NULL                        }
};

static dissector_handle_t ascend_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t ppp_hdlc_handle;
static dissector_handle_t lapd_phdr_handle;

static int
dissect_ascend(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree                    *fh_tree;
  proto_item                    *ti, *hidden_item;
  union wtap_pseudo_header      *pseudo_header = pinfo->pseudo_header;
  struct isdn_phdr              isdn;

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
    switch (pseudo_header->ascend.type) {

    case ASCEND_PFX_WDD:
      /* Ethernet packet forcing a call */
      proto_tree_add_string(fh_tree, hf_called_number, tvb, 0, 0,
                            pseudo_header->ascend.call_num);
      proto_tree_add_uint(fh_tree, hf_chunk, tvb, 0, 0,
                          pseudo_header->ascend.chunk);
      hidden_item = proto_tree_add_uint(fh_tree, hf_session_id, tvb, 0, 0, 0);
      proto_item_set_hidden(hidden_item);
      break;

    case ASCEND_PFX_WDS_X:
    case ASCEND_PFX_WDS_R:
      /* wandsession data */
      proto_tree_add_string(fh_tree, hf_user_name, tvb, 0, 0,
                            pseudo_header->ascend.user);
      proto_tree_add_uint(fh_tree, hf_session_id, tvb, 0, 0,
                          pseudo_header->ascend.sess);
      hidden_item = proto_tree_add_uint(fh_tree, hf_chunk, tvb, 0, 0, 0);
      proto_item_set_hidden(hidden_item);
      break;

    default:
      break;
    }
    proto_tree_add_uint(fh_tree, hf_task, tvb, 0, 0, pseudo_header->ascend.task);
  }

  switch (pseudo_header->ascend.type) {
    case ASCEND_PFX_WDS_X:
    case ASCEND_PFX_WDS_R:
      call_dissector(ppp_hdlc_handle, tvb, pinfo, tree);
      break;
    case ASCEND_PFX_WDD:
    case ASCEND_PFX_ETHER:
      call_dissector(eth_withoutfcs_handle, tvb, pinfo, tree);
      break;
    case ASCEND_PFX_ISDN_X:
      isdn.uton = true;
      isdn.channel = 0;
      call_dissector_with_data(lapd_phdr_handle, tvb, pinfo, tree, &isdn);
      break;
    case ASCEND_PFX_ISDN_R:
      isdn.uton = false;
      isdn.channel = 0;
      call_dissector_with_data(lapd_phdr_handle, tvb, pinfo, tree, &isdn);
      break;
    default:
      break;
  }
  return tvb_captured_length(tvb);
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
  static int *ett[] = {
    &ett_raw,
  };

  proto_ascend = proto_register_protocol("Lucent/Ascend debug output",
                                         "Lucent/Ascend", "ascend");
  proto_register_field_array(proto_ascend, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ascend_handle = register_dissector("ascend", dissect_ascend, proto_ascend);
}

void
proto_reg_handoff_ascend(void)
{
  /*
   * Get handles for the Ethernet, PPP-in-HDLC-like-framing, and
   * LAPD-with-pseudoheader dissectors.
   */
  eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_ascend);
  ppp_hdlc_handle = find_dissector_add_dependency("ppp_hdlc", proto_ascend);
  lapd_phdr_handle = find_dissector_add_dependency("lapd-phdr", proto_ascend);

  dissector_add_uint("wtap_encap", WTAP_ENCAP_ASCEND, ascend_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
