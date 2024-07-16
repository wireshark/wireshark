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
 *
 * Current testing suite 'case_dissect_git' can be found at
 * test/suite_dissection.py
 */

#include "config.h"

#include <stdio.h>    /* for sscanf() */

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

void proto_register_git(void);
void proto_reg_handoff_git(void);

static dissector_handle_t git_handle;

static int proto_git;
static expert_field ei_git_bad_pkt_len;
static expert_field ei_git_malformed;

static int ett_git;

static int hf_git_protocol_version;
static int hf_git_packet_type;
static int hf_git_packet_len;
static int hf_git_packet_data;
static int hf_git_sideband_control_code;
static int hf_git_upload_pack_adv;
static int hf_git_upload_pack_req;
static int hf_git_upload_pack_res;

#define PNAME  "Git Smart Protocol"
#define PSNAME "Git"
#define PFNAME "git"

#define TCP_PORT_GIT    9418

static const value_string packet_type_vals[] = {
  { 0, "Flush" },
  { 1, "Delimiter" },
  { 2, "Response end" },
  { 0, NULL }
};

static const value_string version_vals[] = {
  { '1', "Git protocol version 1" },
  { '2', "Git protocol version 2" },
  { 0, NULL }
};

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
static bool git_desegment = true;

static bool get_packet_length(tvbuff_t *tvb, int offset,
                                  uint16_t *length)
{
  uint8_t *lenstr;

  lenstr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, ENC_ASCII);

  return (sscanf(lenstr, "%hx", length) == 1);
}

static unsigned
get_git_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  uint16_t plen;

  if (!get_packet_length(tvb, offset, &plen))
    return 0; /* No idea what this is */

  return plen < 4
      ? 4   // Special packet (e.g., flush-pkt)
      : plen;
}

/* Parse pkt-lines one-by-one
 *
 * @param  tvb       The buffer to dissect.
 * @param  pinfo     Packet info associated to this buffer.
 * @param  git_tree  The git protocol subtree.
 * @param  offset    The offset at which to start the dissection.
 * @return bool      After successful/unsuccessful parsing.
 *
 * This new helper takes the contents of the tvbuffer, updates the
 * offset, and returns to the caller for subsequent processing of the
 * remainder of the data.
*/
static bool
dissect_pkt_line(tvbuff_t *tvb, packet_info *pinfo, proto_tree *git_tree,
                 int *offset)
{
  uint16_t plen;

  // what type of pkt-line is it?
  if (!get_packet_length(tvb, *offset, &plen))
    return false;
  if (plen < 4) {   // a special packet (e.g., flush-pkt)
    proto_item *ti =
        proto_tree_add_uint(git_tree, hf_git_packet_type, tvb,
                            *offset, 4, plen);
    *offset += 4;

    if (!try_val_to_str(plen, packet_type_vals))
      expert_add_info(pinfo, ti, &ei_git_bad_pkt_len);
    return true;
  }

  proto_tree_add_uint(git_tree, hf_git_packet_len, tvb, *offset, 4, plen);
  *offset += 4;
  plen -= 4;

  /*
   * Parse out the version of the Git Protocol
   *
   * The initial server response contains the version of the Git Protocol in use;
   * 1 or 2. Parsing out this information helps identify the capabilities and
   * information that can be used with the protocol.
  */
  if (plen >= 9 && !tvb_strneql(tvb, *offset, "version ", 8)) {
    proto_tree_add_item(git_tree, hf_git_protocol_version, tvb, *offset + 8,
                        1, ENC_NA);
  }

  /*
   * Parse out the sideband control code.
   *
   * Not all pkt-lines have a sideband control code. With more context from the rest of
   * the request or response, we would be able to tell whether sideband is expected here;
   * lacking that, let's assume for now that all pkt-lines starting with \1, \2, or \3
   * are using sideband.
   */
  int sideband_code = tvb_get_guint8(tvb, *offset);

  if (1 <= sideband_code && sideband_code <= 3) {
    proto_tree_add_uint(git_tree, hf_git_sideband_control_code, tvb, *offset, 1,
                        sideband_code);
    (*offset)++;
    plen--;
  }

  proto_tree_add_item(git_tree, hf_git_packet_data, tvb, *offset, plen, ENC_NA);
  *offset += plen;
  return true;
}

static int
dissect_git_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree             *git_tree;
  proto_item             *ti;
  int offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  col_set_str(pinfo->cinfo, COL_INFO, PNAME);

  ti = proto_tree_add_item(tree, proto_git, tvb, offset, -1, ENC_NA);
  git_tree = proto_item_add_subtree(ti, ett_git);

  if (!dissect_pkt_line(tvb, pinfo, git_tree, &offset))
    return 0;

  return tvb_captured_length(tvb);
}

/* Parse http packs
 *
 * @param  tvb        The buffer to dissect.
 * @param  pinfo      The Packet Info.
 * @param  tree       The protocol tree.
 * @param  hfindex    The type of http pack.
 * @return tvb_length The amount of captured data in the buffer,
 *                    returns 0 if parsing failed.
 *
 * This new helper takes the contents of the tvbuffer sent by http
 * dissectors, adds the packs to the git subtree and returns the amount
 * of consumed bytes in the tvb buffer.
*/
static int
dissect_http_pkt_lines(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int hfindex)
{
  proto_tree             *git_tree;
  proto_item             *ti;
  int offset = 0;
  int total_len = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  col_set_str(pinfo->cinfo, COL_INFO, PNAME);

  ti = proto_tree_add_item(tree, proto_git, tvb, offset, -1, ENC_NA);
  git_tree = proto_item_add_subtree(ti, ett_git);

  proto_tree_add_item(git_tree, hfindex, tvb, offset,
                      tvb_captured_length(tvb), ENC_NA);

  total_len = tvb_reported_length(tvb);
  while (offset < total_len) {
    /* Add expert info if there is trouble parsing part-way through */
    if (!dissect_pkt_line(tvb, pinfo, git_tree, &offset)) {
      proto_tree_add_expert(git_tree, pinfo, &ei_git_malformed, tvb, offset, -1);
      break;
    }
  }

  return tvb_captured_length(tvb);
}

static int
dissect_git_upload_pack_adv(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void *data _U_)
{
  return dissect_http_pkt_lines(tvb, pinfo, tree, hf_git_upload_pack_adv);
}

static int
dissect_git_upload_pack_req(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void *data _U_)
{
  return dissect_http_pkt_lines(tvb, pinfo, tree, hf_git_upload_pack_req);
}

static int
dissect_git_upload_pack_res(tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, void *data _U_)
{
  return dissect_http_pkt_lines(tvb, pinfo, tree, hf_git_upload_pack_res);
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
    { &hf_git_protocol_version,
      { "Git Protocol Version", "git.version", FT_UINT8, BASE_NONE, VALS(version_vals),
      0, NULL, HFILL },
    },
    { &hf_git_packet_type,
      { "Git Packet Type", "git.packet_type", FT_UINT8, BASE_NONE, VALS(packet_type_vals),
      0, NULL, HFILL },
    },
    { &hf_git_packet_len,
      { "Packet length", "git.length", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
    },
    { &hf_git_packet_data,
      { "Packet data", "git.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
    },
    { &hf_git_sideband_control_code,
      { "Sideband control code", "git.sideband_control_code", FT_UINT8,
      BASE_HEX, VALS(sideband_vals), 0, NULL, HFILL },
    },
    { &hf_git_upload_pack_adv,
      { "Upload Pack Advertisement", "git.upload_pack_advertisement",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
    },
    { &hf_git_upload_pack_req,
      { "Upload Pack Request", "git.upload_pack_request",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
    },
    { &hf_git_upload_pack_res,
      { "Upload Pack Result", "git.upload_pack_result",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
    },
  };

  static int *ett[] = {
    &ett_git,
  };

  static ei_register_info ei[] = {
    { &ei_git_bad_pkt_len,
      { "git.bad_pkt_len", PI_PROTOCOL, PI_ERROR,
        "unrecognized special pkt-len value", EXPFILL }
    },
    { &ei_git_malformed,
      { "git.malformed", PI_MALFORMED, PI_ERROR,
        "malformed packet", EXPFILL }
    },
  };

  module_t *git_module;
  expert_module_t *expert_git;

  proto_git = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_register_field_array(proto_git, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_git = expert_register_protocol(proto_git);
  expert_register_field_array(expert_git, ei, array_length(ei));

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
  /*
   * Add the dissectors for GIT over HTTP
   *
   * Reference documentation at
   * https://www.kernel.org/pub/software/scm/git/docs//technical/http-protocol.txt
   */
  dissector_handle_t git_upload_pack_adv_handle;
  dissector_handle_t git_upload_pack_req_handle;
  dissector_handle_t git_upload_pack_res_handle;

  git_upload_pack_adv_handle = create_dissector_handle(dissect_git_upload_pack_adv,
                        proto_git);

  git_upload_pack_req_handle = create_dissector_handle(dissect_git_upload_pack_req,
                        proto_git);

  git_upload_pack_res_handle = create_dissector_handle(dissect_git_upload_pack_res,
                        proto_git);

  dissector_add_string("media_type",
                        "application/x-git-upload-pack-advertisement",
                        git_upload_pack_adv_handle);
  dissector_add_string("media_type",
                        "application/x-git-upload-pack-request",
                        git_upload_pack_req_handle);
  dissector_add_string("media_type",
                        "application/x-git-upload-pack-result",
                        git_upload_pack_res_handle);

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
