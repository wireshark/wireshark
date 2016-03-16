/* packet-clip.c
 * Routines for clip packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * This file created by Thierry Andry <Thierry.Andry@advalvas.be>
 * from nearly-the-same packet-raw.c created by Mike Hall <mlh@io.com>
 * Copyright 1999
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

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/expert.h>
#include <wiretap/wtap.h>

#include "packet-ip.h"

void proto_register_clip(void);
void proto_reg_handoff_clip(void);

static int proto_clip = -1;

static gint ett_clip = -1;

static expert_field ei_no_link_info = EI_INIT;

static dissector_handle_t ip_handle;

static int
dissect_clip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *fh_item;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
  col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CLIP");
  col_set_str(pinfo->cinfo, COL_INFO, "Classical IP frame");

  /* populate a tree in the second pane with the status of the link
     layer (ie none)

     XXX - the Linux Classical IP code supports both LLC Encapsulation,
     which puts an LLC header and possibly a SNAP header in front of
     the network-layer header, and VC Based Multiplexing, which puts
     no headers in front of the network-layer header.

     The ATM on Linux code includes a patch to "tcpdump"
     that compares the first few bytes of the packet with the
     LLC header that Classical IP frames may have and, if there's
     a SNAP LLC header at the beginning of the packet, it gets
     the packet type from that header and uses that, otherwise
     it treats the packet as being raw IP with no link-level
     header, in order to handle both of those.

     This code, however, won't handle LLC Encapsulation.  We've
     not yet seen a capture taken on a machine using LLC Encapsulation,
     however.  If we see one, we can modify the code.

     A future version of libpcap, however, will probably use DLT_LINUX_SLL
     for both of those cases, to avoid the headache of having to
     generate capture-filter code to handle both of those cases. */
  fh_item = proto_tree_add_item(tree, proto_clip, tvb, 0, 0, ENC_NA);
  expert_add_info(pinfo, fh_item, &ei_no_link_info);

  call_dissector(ip_handle, tvb, pinfo, tree);
  return tvb_captured_length(tvb);
}

void
proto_register_clip(void)
{
  static gint *ett[] = {
    &ett_clip,
  };

  static ei_register_info ei[] = {
    { &ei_no_link_info, { "clip.no_link_info", PI_PROTOCOL, PI_NOTE, "No link information available", EXPFILL }},
  };

  expert_module_t* expert_clip;

  proto_clip = proto_register_protocol("Classical IP frame", "CLIP", "clip");

  proto_register_subtree_array(ett, array_length(ett));
  expert_clip = expert_register_protocol(proto_clip);
  expert_register_field_array(expert_clip, ei, array_length(ei));
}

void
proto_reg_handoff_clip(void)
{
  dissector_handle_t clip_handle;

  /*
   * Get a handle for the IP dissector.
   */
  ip_handle = find_dissector_add_dependency("ip", proto_clip);

  clip_handle = create_dissector_handle(dissect_clip, proto_clip);
      /* XXX - no protocol, can't be disabled */
  dissector_add_uint("wtap_encap", WTAP_ENCAP_LINUX_ATM_CLIP, clip_handle);

  register_capture_dissector("wtap_encap", WTAP_ENCAP_LINUX_ATM_CLIP, capture_ip, proto_clip);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
