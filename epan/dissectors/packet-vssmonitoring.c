/* packet-vssmonitoring.c
 * Routines for dissection of VSS Monitoring timestamp and portstamp
 *
 * Copyright VSS Monitoring 2011
 *
 * 20111205 - First edition by Sake Blok (sake.blok@SYN-bit.nl)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

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

void proto_register_vssmonitoring(void);
void proto_reg_handoff_vssmonitoring(void);

static int proto_vssmonitoring;

static int hf_vssmonitoring_time;
static int hf_vssmonitoring_clksrc;
static int hf_vssmonitoring_srcport;

static int ett_vssmonitoring;

static bool vss_dissect_portstamping_only;
static bool vss_two_byte_portstamps;

static bool
dissect_vssmonitoring(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_tree    *ti = NULL;
  proto_tree    *vssmonitoring_tree = NULL;
  unsigned      offset = 0;

  unsigned      trailer_len;
  unsigned      portstamp_len = (vss_two_byte_portstamps) ? 2 : 1;
  nstime_t      vssmonitoring_time;
  uint8_t       vssmonitoring_clksrc = 0;
  uint32_t      vssmonitoring_srcport = 0;

  struct tm     *tmp;


  /* First get the length of the trailer */
  trailer_len = tvb_reported_length(tvb);

  /* The trailer length is a sum (of any combination) of:
   * timestamp (8 bytes)
   * port stamp (1 or 2 bytes)
   * fcs (4 bytes)
   *
   * Our caller might pass in the trailer with FCS included, so we check for
   * a trailer with a length that includes one or more of a time stamp,
   * a 1-byte or 2-byte port stamp, and optionally an FCS.
   *
   * See
   *
   *    https://web.archive.org/web/20160402091604/http://www.vssmonitoring.com/resources/feature-brief/Port-and-Time-Stamping.pdf
   *
   * which speaks of 2-byte port stamps as being for a "future release".
   *
   * Iris Packet Broker user manuals when VSS Monitoring was owned by
   * Tektronix also mentioned only a 1-byte port stamp.
   *
   * VSS Monitoring has since been acquired by NetScout.
   * Products released in 2019:
   * https://www.netscout.com/sites/default/files/2019-01/PFSPDS_002_EN-1803-nGenius-4200-Series-Packet-Flow-Switch.pdf
   * https://www.netscout.com/sites/default/files/2019-12/PFSPDS_003_EN-1901%20-%20nGenius%206010%20Packet%20Flow%20Switch.pdf
   * mention both Port Stamping and VLAN tagging under "traffic port tagging,"
   * and also note separately that up to _256_ ports can be meshed together
   * across hardware to act as a single device.
   *
   * Products released in 2021:
   * https://www.netscout.com/sites/default/files/2021-07/PFSPDS_021_EN-2102%20-%20nGenius%207000%20Series%20Packet%20Flow%20Switches.pdf
   * https://www.netscout.com/sites/default/files/2021-07/PFSPDS_022_EN-2102%20-%20nGenius%205000%20Series%20Packet%20Flow%20Switches.pdf
   * mention only VLAN tagging, and not Port Stamping in the port tagging
   * feature section.
   *
   * VSS Monitoring has apparently never released a product with 2 byte
   * port stamps, and it seems going forward that port stamping is going
   * to be deprecrated in favor of VLAN tagging.
   *
   * So by default we'll assume port stamps are 1 byte, with 2 bytes
   * port stamps supported via preference (disabled by default.)
   *
   * This means a trailer length must not be more than 14 bytes,
   * and:
   *
   *    must not be 3 modulo 4 (as it can't have both a 1-byte
   *    and a 2-byte port stamp);
   *
   *    can only be either 1 or 2 module 4, depending on the size
   *    of port stamp we accept;
   *
   *    if it's less than 8 bytes, must not be 0 modulo 4 (as
   *    it must have a 1-byte or 2-byte port stamp, given that
   *    it has no timestamp).
   */
  if ( trailer_len > 12 + portstamp_len )
    return false;

  if ( (trailer_len & 3) != 0 && (trailer_len & 3) != portstamp_len )
    return false;

  /*
   * If we have a time stamp, check it for validity.
   */
  if ( trailer_len >= 8 ) {
    vssmonitoring_time.secs  = tvb_get_ntohl(tvb, offset);
    vssmonitoring_time.nsecs = tvb_get_ntohl(tvb, offset + 4);
    vssmonitoring_clksrc     = (uint8_t)(((uint32_t)vssmonitoring_time.nsecs) >> CLKSRC_SHIFT);
    vssmonitoring_time.nsecs &= VSS_NS_MASK;

      /* Probably padding passed to this dissector (e.g., a 802.1Q tagged
       * packet where the minimum frame length was increased to account
       * for the tag, see IEEE Std 802.1Q-2014 G.2.3 "Minimum PDU Size")
       * FIXME: Should be made even stricter.
       */
      if (vssmonitoring_time.secs == 0)
        return false;
      /* The timestamp will be based on the uptime until the TAP is completely
       * booted, this takes about 60s, but use 1 hour to be sure
       */
      if (vssmonitoring_time.secs > 3600) {

        /* Check whether the timestamp in the PCAP header and the VSS-Monitoring
         * differ less than 30 days, otherwise, this might not be a VSS-Monitoring
         * timestamp
         */
        if ( vssmonitoring_time.secs > pinfo->abs_ts.secs ) {
          if ( vssmonitoring_time.secs - pinfo->abs_ts.secs > 2592000 ) /* 30 days */
            return false;
        } else {
          if ( pinfo->abs_ts.secs - vssmonitoring_time.secs > 2592000 ) /* 30 days */
            return false;
        }
      }

      /* The nanoseconds field should be less than 1000000000
       */
      if ( vssmonitoring_time.nsecs >= 1000000000 )
        return false;
  } else if (!vss_dissect_portstamping_only || (trailer_len & 3) == 0) {
    /* No timestamp, so we need a port stamp and be willing to accept
     * packets with port stamping but not time stamping.
     *
     * Unfortunately, the port stamp can be zero or any other value, so
     * this means that a one-byte or two-byte all-zero trailer that's just
     * padding can be misinterpreted as a VSS monitoring trailer, among
     * other false positives, so we disable that by default.
     */
    return false;
  }

  /* All systems are go, lets dissect the VSS-Monitoring trailer */
  if (tree) {
    ti = proto_tree_add_item(tree, proto_vssmonitoring,
             tvb, 0, (trailer_len & 0xb), ENC_NA);
    vssmonitoring_tree = proto_item_add_subtree(ti, ett_vssmonitoring);
  }

  /* Do we have a timestamp? */
  if ( trailer_len >= 8 ) {
    if (tree) {
      proto_tree_add_time(vssmonitoring_tree, hf_vssmonitoring_time, tvb, offset, 8, &vssmonitoring_time);
      proto_tree_add_uint(vssmonitoring_tree, hf_vssmonitoring_clksrc, tvb, offset + 4, 1, vssmonitoring_clksrc);

      tmp = localtime(&vssmonitoring_time.secs);
      if (tmp)
        proto_item_append_text(ti, ", Timestamp: %02d:%02d:%02d.%09ld",
            tmp->tm_hour, tmp->tm_min, tmp->tm_sec,(long)vssmonitoring_time.nsecs);
      else
        proto_item_append_text(ti, ", Timestamp: <Not representable>");
    }
    offset += 8;
  }

  /* Do we have a port stamp? */
  if ( (trailer_len & 3) == portstamp_len) {
    if (tree) {
      proto_tree_add_item_ret_uint(vssmonitoring_tree, hf_vssmonitoring_srcport, tvb, offset, portstamp_len, ENC_BIG_ENDIAN, &vssmonitoring_srcport);
      proto_item_append_text(ti, ", Source Port: %d", vssmonitoring_srcport);
    }
    /*offset += portstamp_len;*/
  }

  return true;
}

void
proto_register_vssmonitoring(void)
{
  static hf_register_info hf[] = {
    { &hf_vssmonitoring_time, {
        "Time Stamp", "vssmonitoring.time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        "VSS Monitoring Time Stamp", HFILL }},

    { &hf_vssmonitoring_clksrc, {
        "Clock Source", "vssmonitoring.clksrc",
        FT_UINT8, BASE_DEC, VALS(clksrc_vals), 0x0,
        "VSS Monitoring Clock Source", HFILL }},

    { &hf_vssmonitoring_srcport, {
        "Src Port", "vssmonitoring.srcport",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "VSS Monitoring Source Port", HFILL }}
  };

  static int *ett[] = {
    &ett_vssmonitoring
  };

  module_t *vssmonitoring_module;

  proto_vssmonitoring = proto_register_protocol("VSS Monitoring Ethernet trailer", "VSS Monitoring", "vssmonitoring");
  proto_register_field_array(proto_vssmonitoring, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  vssmonitoring_module = prefs_register_protocol(proto_vssmonitoring, NULL);

  prefs_register_obsolete_preference(vssmonitoring_module, "use_heuristics");
  prefs_register_bool_preference(vssmonitoring_module, "dissect_portstamping_only",
      "Dissect trailers with only port stamping",
      "Whether the VSS Monitoring dissector should attempt to dissect trailers with no timestamp, only port stamping.  Note that this can result in a large number of false positives.",
      &vss_dissect_portstamping_only);
  prefs_register_bool_preference(vssmonitoring_module, "two_byte_portstamps",
      "Two byte port stamps",
      "Whether the VSS Monitoring dissector should assume that the port stamp is two bytes, instead of the standard one byte.",
      &vss_two_byte_portstamps);
}

void
proto_reg_handoff_vssmonitoring(void)
{
  heur_dissector_add("eth.trailer", dissect_vssmonitoring, "VSS Monitoring ethernet trailer", "vssmonitoring_eth", proto_vssmonitoring, HEURISTIC_ENABLE);
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
