/* packet-gmhdr.c
 * Routines for Gigamon header disassembly (modified from packet-vlan.c)
 *
 * Dissector for Gigamon Header and Trailer
 * Copyright Gigamon 2010
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/in_cksum.h>
#include <epan/crc32-tvb.h>
#include <wsutil/crc32.h>
#include <epan/expert.h>

#include "packet-ieee8023.h"

#define GMHDR_FTYPE_PKTSIZE             1
#define GMHDR_FTYPE_SRCPORT             2
#define GMHDR_FTYPE_TIMESTAMP_LOCAL     3
#define GMHDR_FTYPE_TIMESTAMP_NTP       4
#define GMHDR_FTYPE_TIMESTAMP_GPS       5
#define GMHDR_FTYPE_TIMESTAMP_1588      6

static const value_string gmhdr_ftype_timestamp[] = {
  { GMHDR_FTYPE_TIMESTAMP_LOCAL, "Local" },
  { GMHDR_FTYPE_TIMESTAMP_NTP,   "NTP" },
  { GMHDR_FTYPE_TIMESTAMP_GPS,   "GPS" },
  { GMHDR_FTYPE_TIMESTAMP_1588,  "1588" },
  { 0,                           NULL }
};

#define GMHDR_SRCPORT_PLFM_MASK         0x00f80000
#define GMHDR_SRCPORT_GID_MASK          0x00078000
#define GMHDR_SRCPORT_BID_MASK          0x00007c00
#define GMHDR_SRCPORT_PID_MASK          0x000003ff
#define GMHDR_SRCPORT_PLFM_SHFT         19
#define GMHDR_SRCPORT_GID_SHFT          15
#define GMHDR_SRCPORT_BID_SHFT          10
#define GMHDR_SRCPORT_PID_SHFT          0

static const value_string gmhdr_plfm_str[] = {
  { 0, "Reserved" },
  { 1, "GV-2404" },
  { 0, NULL }
};

static gboolean gmhdr_summary_in_tree = TRUE;
static gboolean gmtrailer_summary_in_tree = TRUE;
static gboolean gmhdr_decode_timestamp_trailer = TRUE;

static int proto_gmhdr = -1;
static int proto_gmtrailer = -1;
static int hf_gmhdr_srcport = -1;
static int hf_gmhdr_srcport_plfm = -1;
static int hf_gmhdr_srcport_gid = -1;
static int hf_gmhdr_srcport_bid = -1;
static int hf_gmhdr_srcport_pid = -1;
static int hf_gmhdr_pktsize = -1;
static int hf_gmhdr_timestamp = -1;
static int hf_gmhdr_generic = -1;
static int hf_gmhdr_etype = -1;
static int hf_gmhdr_len = -1;
static int hf_gmhdr_trailer = -1;

static int hf_gmtrailer_origcrc = -1;
static int hf_gmtrailer_portid = -1;
static int hf_gmtrailer_timestamp = -1;

static gint ett_gmhdr = -1;
static gint ett_srcport = -1;
static gint ett_gmtrailer = -1;



static void
dissect_gmtlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *gmhdr_tree, guint offset, guint16 length)
{
  proto_tree *ti;
  proto_tree *srcport_tree;
  guint16     fl;

  while (length > 1) {
    guint16 tl = tvb_get_ntohs(tvb, offset);
    offset += 2; /* type + len */
    length -= 2;

    fl = tl & 0xff;
    switch (tl >> 8) {
      case GMHDR_FTYPE_SRCPORT: {
        guint16 pid;
        guint32 tv = tvb_get_ntohl(tvb, offset) >> 8; /* Only 24-bit field */

        if (fl != 3) {
          expert_add_info_format(pinfo, gmhdr_tree, PI_MALFORMED, PI_ERROR, "Field length %u invalid", fl);
          break;
        }
        ti = proto_tree_add_item(gmhdr_tree, hf_gmhdr_srcport,      tvb, offset, fl, ENC_BIG_ENDIAN);
        srcport_tree = proto_item_add_subtree(ti, ett_srcport);
        proto_tree_add_item(srcport_tree, hf_gmhdr_srcport_plfm, tvb, offset, fl, ENC_BIG_ENDIAN);
        proto_tree_add_item(srcport_tree, hf_gmhdr_srcport_gid,  tvb, offset, fl, ENC_BIG_ENDIAN);
        proto_tree_add_item(srcport_tree, hf_gmhdr_srcport_bid,  tvb, offset, fl, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(srcport_tree, hf_gmhdr_srcport_pid,  tvb, offset, fl, ENC_BIG_ENDIAN);
        /* If not GV-2404, we need different formula here */
        pid = ((tv & GMHDR_SRCPORT_PID_MASK) >> GMHDR_SRCPORT_PID_SHFT) - 24;
        if (pid >= 1 && pid <= 4) {
          proto_item_append_text(ti, " (g%d)", pid);
        }
        break;
      }
      case GMHDR_FTYPE_PKTSIZE:
        if (fl != 2) {
          expert_add_info_format(pinfo, gmhdr_tree, PI_MALFORMED, PI_ERROR, "Field length %u invalid", fl);
          break;
        }
        proto_tree_add_item(gmhdr_tree, hf_gmhdr_pktsize, tvb, offset, fl, ENC_BIG_ENDIAN);
        break;
      case GMHDR_FTYPE_TIMESTAMP_LOCAL:
      case GMHDR_FTYPE_TIMESTAMP_NTP:
      case GMHDR_FTYPE_TIMESTAMP_GPS:
      case GMHDR_FTYPE_TIMESTAMP_1588:
        if (fl != 8) {
          expert_add_info_format(pinfo, gmhdr_tree, PI_MALFORMED, PI_ERROR, "Field length %u invalid", fl);
          break;
        }
        ti = proto_tree_add_item(gmhdr_tree, hf_gmhdr_timestamp, tvb, offset, fl, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "; Source: %s", val_to_str_const(tl>>8, gmhdr_ftype_timestamp, "Unknown"));
        break;
      default:
        ti = proto_tree_add_item(gmhdr_tree, hf_gmhdr_generic, tvb, offset, fl, ENC_NA);
        proto_item_append_text(ti, " [Id: %u, Length: %u]", tl >> 8, fl);
        break;
    }
    /* Adjust for the field length */
    offset += fl;
    length -= fl;
  }
}



static void
dissect_gmhdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree          *ti;
  gint16               length;
  volatile guint16     encap_proto;
  volatile gboolean    is_802_2;
  proto_tree *volatile gmhdr_tree = NULL;
  volatile guint       offset = 0;

  length = tvb_get_guint8(tvb, offset); /* Length of the Gigamon header */

  if (tree) {
    ti = proto_tree_add_item(tree, proto_gmhdr, tvb, offset, length, ENC_NA);

    if (gmhdr_summary_in_tree) {
      proto_item_append_text(ti, ", Length: %u", length);
    }

    gmhdr_tree = proto_item_add_subtree(ti, ett_gmhdr);
    dissect_gmtlv(tvb, pinfo, gmhdr_tree, offset+1, length-1);

  } /* if (tree) */

  offset += length;
  encap_proto = tvb_get_ntohs(tvb, offset);
  offset += 2;
  if (encap_proto <= IEEE_802_3_MAX_LEN) {
    /* Is there an 802.2 layer? I can tell by looking at the first 2
       bytes after the GMHDR header. If they are 0xffff, then what
       follows the GMHDR header is an IPX payload, meaning no 802.2.
       (IPX/SPX is they only thing that can be contained inside a
       straight 802.3 packet, so presumably the same applies for
       Ethernet GMHDR packets). A non-0xffff value means that there's an
       802.2 layer inside the GMHDR layer */
    is_802_2 = TRUE;

    /* Don't throw an exception for this check (even a BoundsError) */
    if (tvb_length_remaining(tvb, offset) >= 2) {
      if (tvb_get_ntohs(tvb, offset) == 0xffff) {
        is_802_2 = FALSE;
      }
    }

    dissect_802_3(encap_proto, is_802_2, tvb, offset, pinfo, tree, gmhdr_tree,
                  hf_gmhdr_len, hf_gmhdr_trailer, 0);
  } else {
    ethertype(encap_proto, tvb, offset, pinfo, tree, gmhdr_tree,
              hf_gmhdr_etype, hf_gmhdr_trailer, 0);
  }
}

static int
dissect_gmtimestamp_trailer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_tree *ti;
  guint tvblen, trailer_len = 18;
  proto_tree *gmtrailer_tree = NULL;
  guint offset = 0;
  guint32 orig_crc, new_crc, comp_crc;
  guint16 port_num;
  nstime_t gmtimev;

  struct tm *tm = NULL;

  if ( ! gmhdr_decode_timestamp_trailer)
    return 0;

  /* See if this packet has a Gigamon trailer, if yes, then decode it */
  /* (Don't throw any exceptions while checking for the trailer).     */
  tvblen = tvb_length(tvb); /* end+1 */
  if (tvblen < trailer_len)
    return 0;

  orig_crc = tvb_get_ntohl(tvb, offset);
  new_crc  = tvb_get_ntohl(tvb, tvblen - 4);

  /* Verify the checksum; if not valid, it means that the trailer is not valid */
  comp_crc = CRC32C_SWAP(crc32_ccitt_tvb_seed(tvb, 14, CRC32C_SWAP(~orig_crc)));
  if (comp_crc != new_crc)
    return 0;

  /* OK: We appear to have a Gigamon trailer */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_gmtrailer, tvb, offset, trailer_len - 4, ENC_NA);

    if (gmtrailer_summary_in_tree) {
      offset += 4;
      port_num = tvb_get_ntohs(tvb, offset);
      offset += 2;
      gmtimev.secs = tvb_get_ntohl(tvb, offset);
      offset += 4;
      gmtimev.nsecs = tvb_get_ntohl(tvb, offset);

      tm = localtime(&gmtimev.secs);
      proto_item_append_text(ti, ", Port: %d, Timestamp: %d:%d:%d.%d", port_num, tm->tm_hour, tm->tm_min, tm->tm_sec, gmtimev.nsecs);
    }

    offset = 0;
    gmtrailer_tree = proto_item_add_subtree(ti, ett_gmtrailer);
    proto_tree_add_item(gmtrailer_tree, hf_gmtrailer_origcrc, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(gmtrailer_tree, hf_gmtrailer_portid, tvb, offset+4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(gmtrailer_tree, hf_gmtrailer_timestamp, tvb, offset+6, 8, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
  }

  return 14;
}

static int
dissect_gmtrailer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_tree *ti;
  guint tvblen, length;
  proto_tree *gmhdr_tree = NULL;
  guint offset;
  guint16 cksum, comp_cksum;

  /* See if this packet has a Gigamon trailer, if yes, then decode it */
  /* (Don't throw any exceptions while checking for the trailer).     */
  tvblen = tvb_length(tvb); /* end+1 */
  if (tvblen < 5)
    return 0;
  if (tvb_get_ntohs(tvb, tvblen-4) != ETHERTYPE_GIGAMON)
    return 0;

  length  = tvb_get_guint8(tvb, tvblen-5); /* length of Gigamon header */
  if ((tvblen-5) != length)
    return 0;

  offset  = tvblen - 5 - length;

  cksum   = tvb_get_ntohs(tvb, tvblen-2);

  /* Verify the checksum; if not valid, it means that the trailer is not valid */
  {
    vec_t vec;
    vec.len = length + 3;
    vec.ptr = tvb_get_ptr(tvb, offset, vec.len);

    comp_cksum = in_cksum(&vec, 1);
    if (pntohs(&comp_cksum) != cksum) {
      return 0;
    }
  }

  /* OK: We appear to have a Gigamon trailer */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_gmhdr, tvb, offset, length + 5, ENC_NA);

    if (gmhdr_summary_in_tree) {
        proto_item_append_text(ti, ", Length: %u, Checksum: 0x%x", length, cksum);
    }

    gmhdr_tree = proto_item_add_subtree(ti, ett_gmhdr);

    dissect_gmtlv(tvb, pinfo, gmhdr_tree, offset, length);
  }
  return tvblen;
}

void
proto_register_gmhdr(void)
{
  static hf_register_info hf[] = {
    { &hf_gmhdr_srcport, {
        "Src Port", "gmhdr.srcport", FT_UINT24, BASE_HEX,
        NULL, 0, "Original Source Port", HFILL }},
    { &hf_gmhdr_srcport_plfm, {
        "Platform Id", "gmhdr.srcport_plfm", FT_UINT24, BASE_DEC,
        VALS(gmhdr_plfm_str), GMHDR_SRCPORT_PLFM_MASK, "Original Platform Id", HFILL }},
    { &hf_gmhdr_srcport_gid, {
        "Group Id", "gmhdr.srcport_gid", FT_UINT24, BASE_DEC,
        NULL, GMHDR_SRCPORT_GID_MASK, "Original Source Group Id", HFILL }},
    { &hf_gmhdr_srcport_bid, {
        "Box Id", "gmhdr.srcport_bid", FT_UINT24, BASE_DEC,
        NULL, GMHDR_SRCPORT_BID_MASK, "Original Source Box Id", HFILL }},
    { &hf_gmhdr_srcport_pid, {
        "Port Id", "gmhdr.srcport_pid", FT_UINT24, BASE_DEC,
        NULL, GMHDR_SRCPORT_PID_MASK, "Original Source Port Id", HFILL }},
    { &hf_gmhdr_pktsize, {
        "Original Packet Size", "gmhdr.pktsize", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL }},
    { &hf_gmhdr_timestamp, {
        "Time Stamp", "gmhdr.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0x0, NULL, HFILL }},
    { &hf_gmhdr_generic, {
        "Generic Field", "gmhdr.generic", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
    { &hf_gmhdr_etype, {
        "Type", "gmhdr.etype", FT_UINT16, BASE_HEX,
        VALS(etype_vals), 0x0, "Ethertype", HFILL }},
    { &hf_gmhdr_len, {
        "Length", "gmhdr.len", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_gmhdr_trailer, {
        "Trailer", "gmhdr.trailer", FT_BYTES, BASE_NONE,
        NULL, 0x0, "GMHDR Trailer", HFILL }},
  };
  static hf_register_info gmtrailer_hf[] = {
    { &hf_gmtrailer_origcrc, {
        "Original CRC", "gmtrailer.crc", FT_UINT32, BASE_HEX,
        NULL, 0x0, "Original Packet CRC", HFILL }},
    { &hf_gmtrailer_portid, {
        "Src Port", "gmtrailer.portid", FT_UINT16, BASE_HEX,
        NULL, 0x0, "Origin Source Port", HFILL }},
    { &hf_gmtrailer_timestamp, {
        "Time Stamp", "gmtrailer.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0x0, NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_gmhdr,
    &ett_srcport
  };
  static gint *gmtrailer_ett[] = {
    &ett_gmtrailer,
  };
  module_t *gmhdr_module;
  module_t *gmtrailer_module;

  proto_gmhdr = proto_register_protocol("Gigamon Header", "GMHDR", "gmhdr");
  proto_register_field_array(proto_gmhdr, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  proto_gmtrailer = proto_register_protocol("Gigamon Trailer", "GMTRAILER", "gmtrailer");
  proto_register_field_array(proto_gmtrailer, gmtrailer_hf, array_length(gmtrailer_hf));
  proto_register_subtree_array(gmtrailer_ett, array_length(gmtrailer_ett));

  gmhdr_module = prefs_register_protocol(proto_gmhdr, NULL);
  prefs_register_bool_preference(gmhdr_module, "summary_in_tree",
        "Show Gigamon header summary in protocol tree",
        "Whether the Gigamon header summary line should be shown in the protocol tree",
        &gmhdr_summary_in_tree);

  gmtrailer_module = prefs_register_protocol(proto_gmtrailer, NULL);
  prefs_register_bool_preference(gmtrailer_module, "summary_in_tree",
        "Show Gigamon Trailer summary in protocol tree",
        "Whether the Gigamon Trailer summary line should be shown in the protocol tree",
        &gmtrailer_summary_in_tree);
  prefs_register_bool_preference(gmtrailer_module, "decode_trailer_timestamp",
        "Decode Gigamon HW timestamp and source id in trailer",
        "Whether the Gigamon trailer containing HW timestamp, source id and original CRC should be decoded",
        &gmhdr_decode_timestamp_trailer);
}

void
proto_reg_handoff_gmhdr(void)
{
  dissector_handle_t gmhdr_handle;

  gmhdr_handle = create_dissector_handle(dissect_gmhdr, proto_gmhdr);
  dissector_add_uint("ethertype", ETHERTYPE_GIGAMON, gmhdr_handle);
  heur_dissector_add("eth.trailer", dissect_gmtrailer, proto_gmhdr);

  heur_dissector_add("eth.trailer", dissect_gmtimestamp_trailer, proto_gmtrailer);
}

