/* packet-metamako.c
 * Routines for dissection of Metamako trailers. Forked from
 * packet-vssmonitoring.c on 20th December, 2015.
 * See https://www.metamako.com for further details.
 *
 * Copyright VSS-Monitoring 2011
 * Copyright Metamako LP 2015
 *
 * 20111205 - First edition by Sake Blok (sake.blok@SYN-bit.nl)
 * 20151220 - Forked to become packet-metamako.c
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

void proto_register_metamako(void);
void proto_reg_handoff_metamako(void);

static int proto_metamako = -1;

static int hf_metamako_origfcs = -1;
static int hf_metamako_time = -1;
static int hf_metamako_flags = -1;
static int hf_metamako_srcport = -1;
static int hf_metamako_srcdevice = -1;
static int hf_metamako_tdiff = -1;

static int hf_metamako_flags_orig_fcs_vld = -1;
static int hf_metamako_reserved = -1;

static gint ett_metamako = -1;
static gint ett_metamako_timestamp = -1;
static gint ett_metamako_flags = -1;

static const int * flags[] = {
  &hf_metamako_flags_orig_fcs_vld,
  &hf_metamako_reserved,
  NULL
};

static int
dissect_metamako(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_tree    *ti, *item;
  proto_tree    *metamako_tree, *timestamp_tree;
  guint         offset = 0;

  guint         trailer_len;
  nstime_t      metamako_time, timediff;
  guint8        metamako_srcport;
  guint16       metamako_srcdevice;

  struct tm     *tmp;

  /* First get the length of the trailer */
  trailer_len = tvb_reported_length(tvb);

  /* The Metamako trailer is made up of:
     4 bytes -- original FCS
     4 bytes -- seconds
     4 bytes -- nanoseconds
     1 byte  -- flags
     2 bytes -- device ID
     1 byte  -- port ID
     4 bytes -- New (valid) FCS
  */

  /* The ethernet trailer may or may not have an FCS */
  if ( (trailer_len != 20) && (trailer_len != 16) )
    return 0;

  /* If we have less than 12 bytes captured, we can't
     read the timestamp to confirm the heuristic */
  if( tvb_captured_length(tvb) < 12)
    return 0;

  /* Further validity checks to ensure that this is a Metamako-style timestamp trailer */
  metamako_time.secs  = tvb_get_ntohl(tvb, offset + 4);
  metamako_time.nsecs = tvb_get_ntohl(tvb, offset + 8);

  nstime_delta(&timediff, &metamako_time, &pinfo->fd->abs_ts);

  /* The timestamp will be based on the uptime until the TAP is completely booted,
   * this takes about 60s, but use 1 hour to be sure
   */

  /* Probably just null data to fill up a short frame.
   * FIXME: Should be made even stricter.
   */
  if (metamako_time.secs == 0)
    return 0;
  if (metamako_time.secs > 3600) {

    /* Check whether the timestamp in the PCAP header and the timestamp trailer
     * differ less than 30 days, otherwise, this might not be a timestamp trailer
     * timestamp
     */
    if ( metamako_time.secs > pinfo->fd->abs_ts.secs ) {
      if ( metamako_time.secs - pinfo->fd->abs_ts.secs > 2592000 ) /* 30 days */
        return 0;
    } else {
      if ( pinfo->fd->abs_ts.secs - metamako_time.secs > 2592000 ) /* 30 days */
        return 0;
    }
  }

  /* The nanoseconds field should be less than 1000000000
   */
  if ( metamako_time.nsecs >= 1000000000 )
    return 0;

  /* All systems are go, lets dissect the trailer */
  ti = proto_tree_add_item(tree, proto_metamako, tvb, 0, (trailer_len & 0xb), ENC_NA);
  metamako_tree = proto_item_add_subtree(ti, ett_metamako);

  /* Original FCS */
  proto_tree_add_item(metamako_tree, hf_metamako_origfcs, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* Timestamp */
  item = proto_tree_add_time(metamako_tree, hf_metamako_time, tvb, offset, 8, &metamako_time);
  timestamp_tree = proto_item_add_subtree(item, ett_metamako_timestamp);

  tmp = localtime(&metamako_time.secs);
  if (tmp)
    proto_item_append_text(ti, ", Timestamp: %02d:%02d:%02d.%09ld",
                             tmp->tm_hour, tmp->tm_min, tmp->tm_sec,(long)metamako_time.nsecs);
  else
    proto_item_append_text(ti, ", Timestamp: <Not representable>");

  item = proto_tree_add_time(timestamp_tree, hf_metamako_tdiff, tvb, offset, 8, &timediff);
  PROTO_ITEM_SET_GENERATED(item);
  offset += 8;

  proto_tree_add_bitmask(metamako_tree, tvb, offset, hf_metamako_flags, ett_metamako_flags, flags, ENC_BIG_ENDIAN);
  offset++;

  /* Source device */
  metamako_srcdevice = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(metamako_tree, hf_metamako_srcdevice, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_item_append_text(ti, ", Source Device: %d", metamako_srcdevice);

  /* Source port */
  metamako_srcport = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(metamako_tree, hf_metamako_srcport, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  proto_item_append_text(ti, ", Source Port: %d", metamako_srcport);

  return offset;
}

void
proto_register_metamako(void)
{
  static hf_register_info hf[] = {
    { &hf_metamako_origfcs, {
        "Original FCS", "metamako.orig_fcs",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_time, {
        "Time Stamp", "metamako.time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }},

    {&hf_metamako_flags, {
        "Flags", "metamako.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},

    {&hf_metamako_flags_orig_fcs_vld, {
        "Original FCS Valid", "metamako.flags.orig_fcs_vld",
        FT_BOOLEAN, 8, TFS(&tfs_valid_invalid), 0x01,
        NULL, HFILL}},

    {&hf_metamako_reserved, {
        "Reserved", "metamako.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xFE,
        NULL, HFILL}},

    { &hf_metamako_srcdevice, {
        "Source Device ID", "metamako.srcdevice",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_srcport, {
        "Source Port", "metamako.srcport",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_tdiff, {
        "Time Difference", "metamako.tdiff",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "Difference from capture timestamp", HFILL }}
  };

  static gint *ett[] = {
    &ett_metamako,
    &ett_metamako_timestamp,
    &ett_metamako_flags
  };

  proto_metamako = proto_register_protocol("Metamako ethernet trailer", "Metamako", "metamako");
  proto_register_field_array(proto_metamako, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_metamako(void)
{
  heur_dissector_add("eth.trailer", dissect_metamako, "Metamako ethernet trailer", "metamako_eth", proto_metamako, HEURISTIC_ENABLE);
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
