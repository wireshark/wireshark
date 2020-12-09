/* packet-git.c
 * Routines for git packet dissection
 * Copyright 2010, Jelmer Vernooij <jelmer@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

void proto_register_git(void);
void proto_reg_handoff_git(void);

static dissector_handle_t git_handle;

static int proto_git = -1;

static gint ett_git = -1;

static gint hf_git_packet_len = -1;
static gint hf_git_packet_data = -1;
static gint hf_git_packet_terminator = -1;
static gint hf_git_sideband_control_code = -1;

#define PNAME  "Git Smart Protocol"
#define PSNAME "Git"
#define PFNAME "git"

#define TCP_PORT_GIT    9418

#define SIDEBAND_PACKFILE_DATA 0x01
#define SIDEBAND_PROGRESS_INFO 0x02
#define SIDEBAND_ERROR_INFO 0x03
static const value_string sideband_vals[] = {
  { SIDEBAND_PACKFILE_DATA, "Git packfile data" },
  { SIDEBAND_PROGRESS_INFO, "Git progress data" },
  { SIDEBAND_ERROR_INFO, "Git error data" },
  { 0, NULL }
};

/* desegmentation of Git over TCP */
static gboolean git_desegment = TRUE;

static gboolean get_packet_length(tvbuff_t *tvb, int offset,
                                  guint16 *length)
{
  guint8 *lenstr;

  lenstr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, ENC_ASCII);

  return (sscanf(lenstr, "%hx", length) == 1);
}

static guint
get_git_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  guint16 plen;

  if (!get_packet_length(tvb, offset, &plen))
    return 0; /* No idea what this is */

  if (plen == 0) {
    /* Terminator packet */
    return 4;
  }

  return plen;
}

static int
dissect_git_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree             *git_tree;
  proto_item             *ti;
  int offset = 0;
  guint16 plen;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  col_set_str(pinfo->cinfo, COL_INFO, PNAME);

  ti = proto_tree_add_item(tree, proto_git, tvb, offset, -1, ENC_NA);
  git_tree = proto_item_add_subtree(ti, ett_git);

  if (!get_packet_length(tvb, 0, &plen))
    return 0;

  if (plen == 0) {
    proto_tree_add_uint(git_tree, hf_git_packet_terminator, tvb, offset,
                        4, plen);
    return 4;
  }

  proto_tree_add_uint(git_tree, hf_git_packet_len, tvb, offset, 4, plen);
  offset += 4;
  plen -= 4;

  /*
   * Parse out the sideband control code.
   *
   * Not all pkt-lines have a sideband control code. With more context from the rest of
   * the request or response, we would be able to tell whether sideband is expected here;
   * lacking that, let's assume for now that all pkt-lines starting with \1, \2, or \3
   * are using sideband.
   */
  int sideband_code = tvb_get_guint8(tvb, offset);

  if (1 <= sideband_code && sideband_code <= 3) {
    proto_tree_add_uint(git_tree, hf_git_sideband_control_code, tvb, offset, 1,
                        sideband_code);
    offset++;
    plen--;
  }

  proto_tree_add_item(git_tree, hf_git_packet_data, tvb, offset, plen, ENC_NA);

  return tvb_captured_length(tvb);
}

static int
dissect_git(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, git_desegment, 4, get_git_pdu_len,
                   dissect_git_pdu, data);
  return tvb_captured_length(tvb);
}

void
proto_register_git(void)
{
  static hf_register_info hf[] = {
    { &hf_git_packet_len,
      { "Packet length", "git.length", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
    },
    { &hf_git_packet_data,
      { "Packet data", "git.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
    },
    { &hf_git_packet_terminator,
      { "Terminator packet", "git.terminator", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
    },
    { &hf_git_sideband_control_code,
      { "Sideband control code", "git.sideband_control_code", FT_UINT8,
      BASE_HEX, VALS(sideband_vals), 0, NULL, HFILL },
    },
  };

  static gint *ett[] = {
    &ett_git,
  };

  module_t *git_module;

  proto_git = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_register_field_array(proto_git, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  git_handle = register_dissector(PFNAME, dissect_git, proto_git);

  git_module = prefs_register_protocol(proto_git, NULL);

  prefs_register_bool_preference(git_module, "desegment",
                                 "Reassemble GIT messages spanning multiple TCP segments",
                                 "Whether the GIT dissector should reassemble messages spanning multiple TCP segments."
                                 " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                 &git_desegment);
}

void
proto_reg_handoff_git(void)
{
  dissector_add_uint_with_preference("tcp.port", TCP_PORT_GIT, git_handle);
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
