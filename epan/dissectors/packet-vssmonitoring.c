/* packet-vssmonitoring.c
 * Routines for dissection of VSS-monitoring timestamp and portstamp
 *
 * Copyright VSS-Monitoring 2011
 *
 * 20111205 - First edition by Sake Blok (sake.blok@SYN-bit.nl)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <epan/packet.h>
#include <epan/prefs.h>


#define VSS_NS_MASK     0x3fffffff
#define CLKSRC_SHIFT    30

#define CLKSRC_LOCAL    0
#define CLKSRC_NTP      1
#define CLKSRC_GPS      2
#define CLKSRC_PTP      3

static const value_string clksrc_vals[] = {
  { CLKSRC_LOCAL,       "Not Synced" },
  { CLKSRC_NTP,         "NTP" },
  { CLKSRC_GPS,         "GPS" },
  { CLKSRC_PTP,         "PTP" },
  { 0,                  NULL }
};


static int proto_vssmonitoring = -1;

static int hf_vssmonitoring_time = -1;
static int hf_vssmonitoring_clksrc = -1;
static int hf_vssmonitoring_srcport = -1;

static gint ett_vssmonitoring = -1;

static gboolean vssmonitoring_use_heuristics = TRUE;

static int
dissect_vssmonitoring(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree    *ti = NULL, *item = NULL;
  proto_tree    *vssmonitoring_tree = NULL;
  guint         offset = 0;

  guint         trailer_len;
  nstime_t      vssmonitoring_time;
  guint8        vssmonitoring_clksrc = 0;
  guint8        vssmonitoring_srcport = 0;

  struct tm     *tmp;


  /* First get the length of the trailer */
  trailer_len = tvb_reported_length(tvb);

  /* The trailer length is a sum (of any combination) of:
   * timestamp (8 bytes)
   * port stamp (1 or 2 bytes)
   * fcs (4 bytes)
   * 
   * This means a trailer length must not be more than 14 bytes
   */
  if ( trailer_len > 14 )
    return 0;

  /* ... and also a 1-byte port stamp can not co-exist with a 2-byte
   * portstamp
   */
  if ( (trailer_len & 3) == 3 )
    return 0;

  if ( trailer_len & 8 ) {
    vssmonitoring_time.secs  = tvb_get_ntohl(tvb, offset);
    vssmonitoring_time.nsecs = tvb_get_ntohl(tvb, offset + 4);
    vssmonitoring_clksrc     = (guint8)(((guint32)vssmonitoring_time.nsecs) >> CLKSRC_SHIFT);
    vssmonitoring_time.nsecs &= VSS_NS_MASK;

    /* There are only heuristics for timestamps, the port stamp can be any value */
    if ( vssmonitoring_use_heuristics ) {

      /* The timestamp will be based on the uptime untill the TAP is completely booted, 
       * this takes about 60s, but use 1 hour to be sure
       */
      if (vssmonitoring_time.secs > 3600) {

        /* Check whether the timestamp in the PCAP header and the VSS-Monitoring 
         * differ less than 30 days, otherwise, this might not be a VSS-Monitoring
         * timestamp
         */
        if ( vssmonitoring_time.secs > pinfo->fd->abs_ts.secs ) {
          if ( vssmonitoring_time.secs - pinfo->fd->abs_ts.secs > 2592000 ) /* 30 days */
            return 0;
        } else {
          if ( pinfo->fd->abs_ts.secs - vssmonitoring_time.secs > 2592000 ) /* 30 days */
            return 0;
        }
      }

      /* The nanoseconds field should be less than 1000000000 
       */
      if ( vssmonitoring_time.nsecs >= 1000000000 ) 
        return 0;
    }
  }

  /* All systems are go, lets dissect the VSS-Monitoring trailer */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_vssmonitoring, 
             tvb, 0, (trailer_len & 0xb), ENC_NA);
    vssmonitoring_tree = proto_item_add_subtree(ti, ett_vssmonitoring);
  }

  /* Do we have a timestamp? */
  if ( trailer_len & 8 ) {
    if (tree) {
      item = proto_tree_add_time(vssmonitoring_tree, hf_vssmonitoring_time, tvb, offset, 8, &vssmonitoring_time);
      item = proto_tree_add_uint(vssmonitoring_tree, hf_vssmonitoring_clksrc, tvb, offset + 4, 1, vssmonitoring_clksrc);

      tmp = localtime(&vssmonitoring_time.secs);
      proto_item_append_text(ti, ", Timestamp: %02d:%02d:%02d.%09ld",
          tmp->tm_hour, tmp->tm_min, tmp->tm_sec,(long)vssmonitoring_time.nsecs);
    }
    offset += 8;
  }

  /* Do we have a portstamp? */
  if ( trailer_len & 3) {
    if ( trailer_len & 1) {
      vssmonitoring_srcport = tvb_get_guint8(tvb, offset);
      if (tree) 
        item = proto_tree_add_item(vssmonitoring_tree, hf_vssmonitoring_srcport, tvb, offset, 1, ENC_NA);
      offset++;
    } else if ( trailer_len & 2) {
      vssmonitoring_srcport = tvb_get_ntohs(tvb, offset);
      if (tree)
        item = proto_tree_add_item(vssmonitoring_tree, hf_vssmonitoring_srcport, tvb, offset, 2, ENC_NA);
      offset += 2;
    }
    if (tree)
      proto_item_append_text(ti, ", Source Port: %d", vssmonitoring_srcport);
  }

  return offset;
}

void
proto_register_vssmonitoring(void)
{
  static hf_register_info hf[] = {
    { &hf_vssmonitoring_time, {
        "Time Stamp", "vssmonitoring.time", 
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, 
        "VSS-Monitoring Time Stamp", HFILL }},

    { &hf_vssmonitoring_clksrc, {
        "Clock Source", "vssmonitoring.clksrc", 
        FT_UINT8, BASE_DEC, VALS(clksrc_vals), 0x0, 
        "VSS-Monitoring Clock Source", HFILL }},

    { &hf_vssmonitoring_srcport, {
        "Src Port", "vssmonitoring.srcport", 
        FT_UINT8, BASE_DEC, NULL, 0x0, 
        "VSS-Monitoring Source Port", HFILL }}
  };

  static gint *ett[] = {
    &ett_vssmonitoring
  };

  module_t *vssmonitoring_module;

  proto_vssmonitoring = proto_register_protocol("VSS-Monitoring ethernet trailer", "VSS-Monitoring", "vssmonitoring");
  proto_register_field_array(proto_vssmonitoring, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  vssmonitoring_module = prefs_register_protocol(proto_vssmonitoring, NULL);

  prefs_register_bool_preference(vssmonitoring_module, "use_heuristics",
      "Use heuristics to verify if trailer contains VSS-Monitoring data",
      "When enabled, Wireshark will do a check on the trailer data to verify"
      "whether it contains VSS-Monitoring time- and port-stamps.",
      &vssmonitoring_use_heuristics);
}

void
proto_reg_handoff_vssmonitoring(void)
{
  heur_dissector_add("eth.trailer", dissect_vssmonitoring, proto_vssmonitoring);
}
