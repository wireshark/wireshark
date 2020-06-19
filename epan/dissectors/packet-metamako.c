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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <glib/gprintf.h>

void proto_register_metamako(void);
void proto_reg_handoff_metamako(void);

static int proto_metamako = -1;

static int hf_metamako_origfcs = -1;
static int hf_metamako_trailerext = -1;
static int hf_metamako_unknownext = -1;
static int hf_metamako_seqnum = -1;
static int hf_metamako_tagstring = -1;
static int hf_metamako_fracns = -1;
static int hf_metamako_time = -1;
static int hf_metamako_flags = -1;
static int hf_metamako_srcport = -1;
static int hf_metamako_srcdevice = -1;
static int hf_metamako_tdiff = -1;

static int hf_metamako_flags_orig_fcs_vld = -1;
static int hf_metamako_flags_has_ext = -1;
static int hf_metamako_reserved = -1;

static gint ett_metamako = -1;
static gint ett_metamako_timestamp = -1;
static gint ett_metamako_extensions = -1;
static gint ett_metamako_flags = -1;

static int * const flags[] = {
  &hf_metamako_flags_orig_fcs_vld,
  &hf_metamako_flags_has_ext,
  &hf_metamako_reserved,
  NULL
};

static void
sub_nanos_base_custom(gchar *result, guint32 value)
{
  double temp_double;
  temp_double = ((double)value) / (1U << 24);
  g_snprintf(result, ITEM_LABEL_LENGTH, "%1.9fns", temp_double);
}

static int
validate_metamako_timestamp(nstime_t *metamako_time, packet_info *pinfo)
{
  if ( metamako_time->secs > 3600 && metamako_time->nsecs < 1000000000 ) {
    if ( metamako_time->secs > pinfo->abs_ts.secs ) {
      if ( metamako_time->secs - pinfo->abs_ts.secs > 2592000 ) /* 30 days */
        return 0;
    } else {
      if ( pinfo->abs_ts.secs - metamako_time->secs > 2592000 ) /* 30 days */
        return 0;
    }
  }
  else {
    return 0;
  }
  return 1;
}

static int
dissect_metamako(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  guint           i, j;

  proto_tree    *ti, *parent, *item;
  proto_tree    *metamako_tree, *timestamp_tree;
  proto_tree    *extensions_tree;

  guint         offset = 0;

  guint         captured_trailer_bytes;
  guint         metamako_trailer_bytes;
  guint         trailer_valid;

  nstime_t      metamako_time, timediff;
  guint         metamako_meta;
  guint         metamako_tlv_present;

  guint         metamako_tlv_count;
  guint         metamako_tlv_firstword;
  guint         metamako_tlv_len;
  guint         metamako_tlv_tag;
  guint         metamako_tlv_pos;
  guint         metamako_tlv_bytes;

  guint8        metamako_srcport;
  guint16       metamako_srcdevice;
  guint8        metamako_flags;

  struct tm     *tmp;

  /* The Metamako trailer is made up of:
     4 bytes -- original FCS
     N bytes -- trailer extensions
     4 bytes -- seconds
     4 bytes -- nanoseconds
     1 byte  -- flags
     2 bytes -- device ID
     1 byte  -- port ID
     4 bytes -- New (valid) FCS (may or may not have been captured)
  */

  /* First get the captured length of the trailer */
  captured_trailer_bytes = tvb_captured_length(tvb);

  /* If we have less than 12 bytes captured, we can't
     read the timestamp to confirm the heuristic */
  if ( captured_trailer_bytes < 12 )
    return 0;

  /* Init variables before loop */
  metamako_trailer_bytes = captured_trailer_bytes;
  metamako_tlv_count = 0;
  metamako_tlv_bytes = 0;
  metamako_tlv_present = 0;

  /* Default state is no valid trailer found */
  trailer_valid = 0;

  /* Loop through the trailer bytes, try to find a valid trailer.
   * Only try twice:
   *   - First try the case there there IS NO trailing FCS
   *   - Second try the case where where IS a trailing FCS
   */
  for ( i = 0; i < 2 && metamako_trailer_bytes >= 12 && !trailer_valid; i++ ) {
    /* Start at the tail of the trailer and work inwards */
    metamako_meta       = tvb_get_ntohl(tvb, metamako_trailer_bytes - 4);
    metamako_flags      = (metamako_meta >> 24) & 0xFF;
    metamako_trailer_bytes -= 4;
    metamako_time.nsecs = tvb_get_ntohl(tvb, metamako_trailer_bytes - 4);
    metamako_trailer_bytes -= 4;
    metamako_time.secs  = tvb_get_ntohl(tvb, metamako_trailer_bytes - 4);
    metamako_trailer_bytes -= 4;

    /* Check the validity of the candidate timestamp */
    if ( validate_metamako_timestamp(&metamako_time, pinfo) ) {
      /* Check if the trailer has tlv extensions */
      metamako_tlv_present = metamako_flags & 0x2;
      metamako_tlv_bytes = 0;
      metamako_tlv_count = 0;
      if ( metamako_tlv_present ) {
        /* Extensions are flagged as included, check if there is bytes
         * to support this, and try to decode.
         */
        while ( metamako_trailer_bytes >= 4 ) {
          /* Bytes are here, decode as TLVs */
          metamako_tlv_firstword = tvb_get_ntohl(tvb, metamako_trailer_bytes - 4);
          metamako_tlv_count++;
          metamako_tlv_bytes += 4;
          metamako_trailer_bytes -= 4;

          /* Extract length */
          metamako_tlv_len = (metamako_tlv_firstword >> 6) & 0x3;

          /* If its a secondary tag header, extract the extended length */
          if ( ( metamako_tlv_firstword & 0x1F ) == 0x1F )
            metamako_tlv_len = ( (metamako_tlv_firstword >> 6) & 0x3FF ) + 1;

          /* Skip over the data, find the next tag */
          while ( metamako_tlv_len > 0 ) {
            metamako_tlv_len--;
            metamako_tlv_bytes += 4;
            metamako_trailer_bytes -= 4;
          }

          /* If this is flagged as the last TLV, stop */
          if ( ( metamako_tlv_firstword >> 5 ) & 0x1 ) {
            break;
          }
        }
      }

      /* There should be at least enough bytes for the Orig FCS left
       * any bytes before this are padding
       */
      if ( metamako_trailer_bytes >= 4 ) {
        /* Decrement by the number of bytes in the Orig FCS field */
        metamako_trailer_bytes -= 4;

        /* This byte offset is the beginning of the Metamako trailer */
        offset = metamako_trailer_bytes;

        /* If we've made it this far, it appears we've got a valid trailer */
        trailer_valid = 1;
      }
    }

    /* If we didn't find a valid metamako trailer, try again using 4 bytes less */
    if ( !trailer_valid ) {
      captured_trailer_bytes -= 4;
      metamako_trailer_bytes = captured_trailer_bytes;
    }
  }

  /* Did we find a valid trailer? */
  if ( !trailer_valid )
    return 0;

  /* Everything looks good! Now dissect the trailer. */
  ti = proto_tree_add_item(tree, proto_metamako, tvb, offset, (captured_trailer_bytes - offset), ENC_NA);
  metamako_tree = proto_item_add_subtree(ti, ett_metamako);

  /* Original FCS */
  proto_tree_add_item(metamako_tree, hf_metamako_origfcs, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* TLV Extensions */
  if ( metamako_tlv_present ) {
    parent = proto_tree_add_item(metamako_tree, hf_metamako_trailerext, tvb, captured_trailer_bytes - 12 - metamako_tlv_bytes, metamako_tlv_bytes, ENC_NA);
    extensions_tree = proto_item_add_subtree(parent, ett_metamako_extensions);
    while ( metamako_tlv_count > 0 ) {
      metamako_tlv_pos = captured_trailer_bytes - 16;
      i = metamako_tlv_count;
      do {
        /* Read TLV word and decode */
        metamako_tlv_firstword = tvb_get_ntohl(tvb, metamako_tlv_pos);
        metamako_tlv_len       = ( metamako_tlv_firstword >> 6 ) & 0x3;
        metamako_tlv_bytes     = ( metamako_tlv_len * 4 ) + 3;
        metamako_tlv_tag       = ( metamako_tlv_firstword & 0x1F );

        /* If this is a Secondary Tag Header, decode the tag extensions */
        if ( ( metamako_tlv_firstword & 0x1F ) == 0x1F ) {
          metamako_tlv_len   =  ( ( metamako_tlv_firstword >> 6 ) & 0x3FF ) + 1;
          metamako_tlv_bytes =  ( metamako_tlv_len * 4 );
          metamako_tlv_tag   += ( ( metamako_tlv_firstword >> 16 ) & 0xFFFF );
        }

        /* Decrement TLV count */
        i--;

        /* Skip over the data if this is not our destination */
        if ( i != 0 )
          metamako_tlv_pos -= ( metamako_tlv_len + 1 ) * 4;
      }
      while ( i > 0 );

      /* We've skipped to the i-th TLV, decode it */
      switch ( metamako_tlv_tag ) {
        case 0:
          /* Sequence Number */
          metamako_tlv_pos -= ( metamako_tlv_len + 1 ) * 4;
          proto_tree_add_item(extensions_tree, hf_metamako_seqnum, tvb, metamako_tlv_pos + 5, 2, ENC_BIG_ENDIAN);
          proto_item_append_text(parent, ", Sequence No: %d", tvb_get_ntohs(tvb, metamako_tlv_pos + 5));
          /* Increment the offset by the Data + Tag size */
          offset += ( metamako_tlv_len + 1 ) * 4;
          break;

        case 1:
          /* Sub-nanoseconds */
          metamako_tlv_pos -= ( metamako_tlv_len + 1 ) * 4;
          proto_tree_add_item(extensions_tree, hf_metamako_fracns, tvb, metamako_tlv_pos + 4, 3, ENC_BIG_ENDIAN);
          proto_item_append_text(parent, ", Sub-nanoseconds: %1.9fns", ((double)(tvb_get_ntohl(tvb, metamako_tlv_pos + 3) & 0x00FFFFFF)) / (1U << 24));
          /* Increment the offset by the Data + Tag size */
          offset += ( metamako_tlv_len + 1 ) * 4;
          break;

        case 31:
          /* Tag String */
          metamako_tlv_pos -= ( metamako_tlv_len + 1 ) * 4;
          proto_tree_add_item(extensions_tree, hf_metamako_tagstring, tvb, metamako_tlv_pos + 4, metamako_tlv_len * 4, ENC_ASCII|ENC_NA);
          /* Increment the offset by the Data + Tag size */
          offset += ( metamako_tlv_len + 1 ) * 4;
          break;

        default:
          /* Unknown tag: just print it's ID and Data */
          metamako_tlv_pos -= ( metamako_tlv_len + 1 ) * 4;
          item = proto_tree_add_item(extensions_tree, hf_metamako_unknownext, tvb, metamako_tlv_pos + 4, metamako_tlv_bytes, ENC_NA);
          /* Start with the Tag */
          proto_item_set_text(item, "Unknown Tag [0x%05x]: ", metamako_tlv_tag);
          /* Iterate through the data appending as we go */
          for ( j = 0; j < metamako_tlv_bytes; j++ ) {
            proto_item_append_text(item, "%02x", tvb_get_guint8(tvb, metamako_tlv_pos + 4 + j));
            if ( (28 + j*2) >= ITEM_LABEL_LENGTH ) {
              proto_item_append_text(item, "...");
              break;
            }
          }
          /* Increment the offset by the Data + Tag size */
          offset += ( metamako_tlv_len + 1 ) * 4;
          break;
      }

      /* Decrement count as we've just decoded a TLV */
      metamako_tlv_count--;
    }
  }

  /* Timestamp */
  item = proto_tree_add_time(metamako_tree, hf_metamako_time, tvb, offset, 8, &metamako_time);
  timestamp_tree = proto_item_add_subtree(item, ett_metamako_timestamp);

  tmp = localtime(&metamako_time.secs);
  if (tmp)
    proto_item_append_text(ti, ", Timestamp: %02d:%02d:%02d.%09ld",
                             tmp->tm_hour, tmp->tm_min, tmp->tm_sec,(long)metamako_time.nsecs);
  else
    proto_item_append_text(ti, ", Timestamp: <Not representable>");

  /* [Timestamp difference from pcap time] */
  nstime_delta(&timediff, &metamako_time, &pinfo->abs_ts);
  item = proto_tree_add_time(timestamp_tree, hf_metamako_tdiff, tvb, offset, 8, &timediff);
  proto_item_set_generated(item);

  offset += 8;

  /* Flags */
  proto_tree_add_bitmask(metamako_tree, tvb, offset, hf_metamako_flags, ett_metamako_flags, flags, ENC_BIG_ENDIAN);
  offset++;

  /* Source device */
  metamako_srcdevice = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(metamako_tree, hf_metamako_srcdevice, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_item_append_text(ti, ", Source Device: %d", metamako_srcdevice);
  offset += 2;

  /* Source port */
  metamako_srcport = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(metamako_tree, hf_metamako_srcport, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(ti, ", Source Port: %d", metamako_srcport);
  offset++;

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

    { &hf_metamako_trailerext, {
        "Trailer Extensions", "metamako.ext",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_unknownext, {
        "Unknown Tag", "metamako.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_seqnum, {
        "Sequence Number", "metamako.seqnum",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_fracns, {
        "Sub-nanoseconds", "metamako.subns",
        FT_UINT24, BASE_CUSTOM, CF_FUNC(sub_nanos_base_custom), 0x0,
        NULL, HFILL }},

    { &hf_metamako_tagstring, {
        "Tag String", "metamako.tagstring",
        FT_STRING, BASE_NONE, NULL, 0x0,
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

    {&hf_metamako_flags_has_ext, {
        "Has Trailer Extensions", "metamako.flags.has_extensions",
        FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
        NULL, HFILL}},

    {&hf_metamako_reserved, {
        "Reserved", "metamako.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xFC,
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
    &ett_metamako_extensions,
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
