/* packet-raw.c
 * Routines for raw packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * This file created and by Mike Hall <mlh@io.com>
 * Copyright 1998
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
#include <wiretap/wtap.h>
#include "packet-ip.h"
#include "packet-ppp.h"

void proto_register_raw(void);
void proto_reg_handoff_raw(void);

static int proto_raw = -1;
static gint ett_raw = -1;

static const char zeroes[10] = {0,0,0,0,0,0,0,0,0,0};

static dissector_handle_t raw_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t ppp_hdlc_handle;

static gboolean
capture_raw(const guchar *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
  /* So far, the only time we get raw connection types are with Linux and
   * Irix PPP connections.  We can't tell what type of data is coming down
   * the line, so our safest bet is IP. - GCC
   */

  /* Currently, the Linux 2.1.xxx PPP driver passes back some of the header
   * sometimes.  This check should be removed when 2.2 is out.
   */
  if (BYTES_ARE_IN_FRAME(0,len,2) && pd[0] == 0xff && pd[1] == 0x03) {
    return capture_ppp_hdlc(pd, 0, len, cpinfo, pseudo_header);
  }
  /* The Linux ISDN driver sends a fake MAC address before the PPP header
   * on its ippp interfaces... */
  else if (BYTES_ARE_IN_FRAME(0,len,8) && pd[6] == 0xff && pd[7] == 0x03) {
    return capture_ppp_hdlc(pd, 6, len, cpinfo, pseudo_header);
  }
  /* ...except when it just puts out one byte before the PPP header... */
  else if (BYTES_ARE_IN_FRAME(0,len,3) && pd[1] == 0xff && pd[2] == 0x03) {
    return capture_ppp_hdlc(pd, 1, len, cpinfo, pseudo_header);
  }
  /* ...and if the connection is currently down, it sends 10 bytes of zeroes
   * instead of a fake MAC address and PPP header. */
  else if (BYTES_ARE_IN_FRAME(0,len,10) && memcmp(pd, zeroes, 10) == 0) {
    return capture_ip(pd, 10, len, cpinfo, pseudo_header);
  }
  else {
    /*
     * OK, is this IPv4 or IPv6?
     */
    if (BYTES_ARE_IN_FRAME(0,len,1)) {
      switch (pd[0] & 0xF0) {

      case 0x40:
        /* IPv4 */
        return capture_ip(pd, 0, len, cpinfo, pseudo_header);

#if 0
      case 0x60:
        /* IPv6 */
        return capture_ipv6(pd, 0, len, cpinfo, pseudo_header);
#endif
      }
    }
  }

  return FALSE;
}

static int
dissect_raw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  tvbuff_t      *next_tvb;

  /* load the top pane info. This should be overwritten by
     the next protocol in the stack */
  col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "N/A");
  col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "N/A");
  col_set_str(pinfo->cinfo, COL_INFO, "Raw packet data");

  /* populate a tree in the second pane with the status of the link
     layer (ie none) */
  proto_tree_add_item(tree, proto_raw, tvb, 0, tvb_captured_length(tvb), ENC_NA);

  /* So far, the only time we get raw connection types are with Linux and
   * Irix PPP connections.  We can't tell what type of data is coming down
   * the line, so our safest bet is IP. - GCC
   */

  /* Currently, the Linux 2.1.xxx PPP driver passes back some of the header
   * sometimes.  This check should be removed when 2.2 is out.
   */
  if (tvb_get_ntohs(tvb, 0) == 0xff03) {
    call_dissector(ppp_hdlc_handle, tvb, pinfo, tree);
  }
  /* The Linux ISDN driver sends a fake MAC address before the PPP header
   * on its ippp interfaces... */
  else if (tvb_get_ntohs(tvb, 6) == 0xff03) {
    next_tvb = tvb_new_subset_remaining(tvb, 6);
    call_dissector(ppp_hdlc_handle, next_tvb, pinfo, tree);
  }
  /* ...except when it just puts out one byte before the PPP header... */
  else if (tvb_get_ntohs(tvb, 1) == 0xff03) {
    next_tvb = tvb_new_subset_remaining(tvb, 1);
    call_dissector(ppp_hdlc_handle, next_tvb, pinfo, tree);
  }
  /* ...and if the connection is currently down, it sends 10 bytes of zeroes
   * instead of a fake MAC address and PPP header. */
  else if (tvb_memeql(tvb, 0, zeroes,10) == 0) {
    next_tvb = tvb_new_subset_remaining(tvb, 10);
    call_dissector(ip_handle, next_tvb, pinfo, tree);
  }
  else {
    /*
     * OK, is this IPv4 or IPv6?
     */
    switch (tvb_get_guint8(tvb, 0) & 0xF0) {

    case 0x40:
      /* IPv4 */
      call_dissector(ip_handle, tvb, pinfo, tree);
      break;

    case 0x60:
      /* IPv6 */
      call_dissector(ipv6_handle, tvb, pinfo, tree);
      break;

    default:
      /* None of the above. */
      call_data_dissector(tvb, pinfo, tree);
      break;
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_register_raw(void)
{
  static gint *ett[] = {
    &ett_raw,
  };

  proto_raw = proto_register_protocol("Raw packet data", "Raw", "raw");
  proto_register_subtree_array(ett, array_length(ett));

  raw_handle = register_dissector("raw_ip", dissect_raw, proto_raw);
}

void
proto_reg_handoff_raw(void)
{
  /*
   * Get handles for the IP, IPv6, undissected-data, and
   * PPP-in-HDLC-like-framing dissectors.
   */
  ip_handle = find_dissector_add_dependency("ip", proto_raw);
  ipv6_handle = find_dissector_add_dependency("ipv6", proto_raw);
  ppp_hdlc_handle = find_dissector_add_dependency("ppp_hdlc", proto_raw);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_RAW_IP, raw_handle);
  register_capture_dissector("wtap_encap", WTAP_ENCAP_RAW_IP, capture_raw, proto_raw);
}

/*
 * Editor modelines
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
