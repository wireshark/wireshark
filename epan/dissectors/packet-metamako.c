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
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>

#include <glib/gprintf.h>

#define TRAILER_MIN_LENGTH_NO_FCS 16
#define TRAILER_NS_UPPER_BOUND 1000000000
#define TRAILER_SECS_BOUNDS_DFLT "3600-"
#define TRAILER_DAYS_DIFF_LIMIT_DFLT 30
#define SECS_IN_ONE_DAY (60 * 60 * 24)

void proto_register_metamako(void);
void proto_reg_handoff_metamako(void);

/* FCS Options */
static bool metamako_check_fcs = true;
static int metamako_fcs_len = -1; /* By default, try to autodetect the FCS. */
/* Heuristic Options */
static int metamako_trailer_present = -1; /* By default, try to autodetect the trailer. */
static range_t* metamako_trailer_secs_bounds;
static unsigned metamako_trailer_days_diff_limit = TRAILER_DAYS_DIFF_LIMIT_DFLT;

/* Protocols and Header Fields */
static int proto_metamako;

/*
  Metamako trailer format
   0.............7...............15..............23..............31
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                          Original FCS                         |
  +---------------+---------------+---------------+---------------+
  |                              ...                              |
  +---------------+---------------+---------------+---------------+
  |                        TLV Extensions                         |
  +---------------+---------------+---------------+---------------+
  |                              ...                              |
  +---------------+---------------+---------------+---------------+
  |                            Seconds                            |
  +---------------+---------------+---------------+---------------+
  |                           Nanoseconds                         |
  +---------------+---------------+---------------+---------------+
  |     Flags     |           Device ID           |  Port ID      |
  +---------------+---------------+---------------+---------------+
*/

static int hf_metamako_origfcs;
static int hf_metamako_trailerext;
static int hf_metamako_unknownext;
static int hf_metamako_seqnum;
static int hf_metamako_tagstring;
static int hf_metamako_fracns;
static int hf_metamako_crchash;
static int hf_metamako_egress_seqnum;
static int hf_metamako_time_abs;
static int hf_metamako_time_rel;
static int hf_metamako_flags;
static int hf_metamako_src_port;
static int hf_metamako_src_device;
static int hf_metamako_time_diff;
static int hf_metamako_fcs;
static int hf_metamako_fcs_status;

static int hf_metamako_flags_orig_fcs_vld;
static int hf_metamako_flags_has_ext;
static int hf_metamako_flags_duplicate;
static int hf_metamako_flags_ts_degraded;
static int hf_metamako_flags_control_block_type;
static int hf_metamako_reserved;

static int ett_metamako;
static int ett_metamako_timestamp;
static int ett_metamako_extensions;
static int ett_metamako_flags;

static const enum_val_t metamako_fcs_vals[] = {
  {"heuristic", "According to heuristic", -1},
  {"never",     "Never",                   0},
  {"always",    "Always",                  4},
  {NULL, NULL, 0}
};

static const enum_val_t metamako_trailer_present_vals[] = {
  {"heuristic", "According to heuristic", -1},
  {"never",     "Never",                   0},
  {"always",    "Always",                  1},
  {NULL, NULL, 0}
};

static const value_string tfs_pcs49_btf_vals[] = {
  { 0x0, "0x33 or 0x66" },
  { 0x1, "0x78"},
  { 0, NULL }
};

static const value_string tfs_orig_fcs_status_vals[] = {
  { 0x0, "Bad" },
  { 0x1, "Good"},
  { 0, NULL }
};

static int* const flags[] = {
  &hf_metamako_flags_control_block_type,
  &hf_metamako_flags_ts_degraded,
  &hf_metamako_flags_duplicate,
  &hf_metamako_flags_has_ext,
  &hf_metamako_flags_orig_fcs_vld,
  &hf_metamako_reserved,
  NULL
};

static expert_field ei_metamako_fcs_bad;

static void
sub_nanos_base_custom(char* result, uint32_t value)
{
  double temp_double;
  temp_double = ((double)value) / (1ULL << 24);
  snprintf(result, ITEM_LABEL_LENGTH, "%1.9fns", temp_double);
}

static int
validate_metamako_timestamp(nstime_t* metamako_time, packet_info* pinfo)
{

  /* Check that we have a valid nanoseconds field. */
  if (metamako_time->nsecs >= TRAILER_NS_UPPER_BOUND)
    return 0;

  /* Check that the seconds in the trailer timestamp are in the user-specified bounds. */
  if (!value_is_in_range(metamako_trailer_secs_bounds, (uint32_t)metamako_time->secs))
    return 0;

  /* Check that the number of days between the trailer timestamp
     and the capture timestamp are within the user-specified bounds.
     Don't use the abs() function because it is not supported on all
     platforms and has type ambiguity. */
  if (metamako_time->secs > pinfo->abs_ts.secs) {
    if (metamako_time->secs - pinfo->abs_ts.secs > (time_t)metamako_trailer_days_diff_limit * SECS_IN_ONE_DAY)
      return 0;
  }
  else {
    if (pinfo->abs_ts.secs - metamako_time->secs > (time_t)metamako_trailer_days_diff_limit * SECS_IN_ONE_DAY)
      return 0;
  }

  return 1;
}

static int
dissect_metamako(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
  unsigned      i, i_start, i_end, j;

  proto_tree*   ti, * parent, * item;
  proto_tree*   metamako_tree, * timestamp_tree;
  proto_tree*   extensions_tree;

  unsigned      offset = 0;

  unsigned      captured_trailer_bytes;
  unsigned      metamako_trailer_bytes;
  unsigned      trailer_min_length;
  bool          trailer_valid;
  bool          has_fcs;

  nstime_t      metamako_time, time_diff, time_rel;
  unsigned      metamako_meta;

  unsigned      metamako_tlv_count;
  unsigned      metamako_tlv_firstword;
  unsigned      metamako_tlv_len;
  unsigned      metamako_tlv_tag;
  unsigned      metamako_tlv_pos;
  unsigned      metamako_tlv_bytes;

  uint8_t       metamako_srcport;
  uint16_t      metamako_srcdevice;
  uint8_t       metamako_flags;

  struct tm*    tmp;

  /* The Metamako trailer is made up of:
     4 bytes -- original FCS
     N bytes -- trailer extensions
     4 bytes -- seconds
     4 bytes -- nanoseconds
     1 byte  -- flags
     2 bytes -- device ID
     1 byte  -- port ID

     The new FCS is not a part of the trailer specification,
     but it may be passed to this dissector in the course of
     dissecting the Ethernet trailer.
     If `metamako_fcs_len` is  0, we know it's not present;
     if `metamako_fcs_len` is  4, we know it's present;
     if `metamako_fcs_len` is -1, we need some heuristics to
     determine whether it's present.

     4 bytes -- New (valid) FCS (may or may not have been captured)
  */

  /* If the user has told us that the Metamako trailer is not present,
     then exit immediately. */
  if (metamako_trailer_present == 0)
    return 0;

  /* First get the captured length of the trailer. */
  captured_trailer_bytes = tvb_captured_length(tvb);

  /* Determine the minimum trailer length required, based on the user's
     setting of the assumed FCS capture. */
  trailer_min_length = metamako_fcs_len == 4 ? TRAILER_MIN_LENGTH_NO_FCS + 4 : TRAILER_MIN_LENGTH_NO_FCS;

  /* If we have less than `trailer_min_length` bytes captured, we can't
     read the trailer. */
  if (captured_trailer_bytes < trailer_min_length)
    return 0;

  /* Adjust the state of the loop variables to account for the user options. */
  trailer_valid = false;
  i_start = metamako_fcs_len == 4 ? 1 : 0;
  i_end = metamako_fcs_len == 0 ? 1 : 2;

  /* Loop through the trailer bytes, trying to find a valid trailer.
   * When:
   *   i == 0, we assume there IS NO trailing FCS
   *   i == 1, we assume there IS a trailing FCS
   */
  for (i = i_start; i < i_end && !trailer_valid; i++) {
    has_fcs = i == 1;
    captured_trailer_bytes -= 4 * i;
    metamako_trailer_bytes = captured_trailer_bytes;
    /* Start at the tail of the trailer and work inwards. */
    metamako_meta = tvb_get_ntohl(tvb, metamako_trailer_bytes - 4);
    metamako_flags = (metamako_meta >> 24) & 0xFF;
    metamako_trailer_bytes -= 4;
    metamako_time.nsecs = tvb_get_ntohl(tvb, metamako_trailer_bytes - 4);
    metamako_trailer_bytes -= 4;
    metamako_time.secs = tvb_get_ntohl(tvb, metamako_trailer_bytes - 4);
    metamako_trailer_bytes -= 4;

    /* Check the validity of the candidate timestamp. */
    if ((metamako_trailer_present == 1) || validate_metamako_timestamp(&metamako_time, pinfo)) {
      metamako_tlv_bytes = 0;
      metamako_tlv_count = 0;
      /* If the trailer has TLV extensions, "walk" them backwards to the Orig FCS field. */
      if (metamako_flags & 0x2) {
        /* Extensions are flagged as included, check if there is bytes
         * to support this, and try to decode.
         */
        while (metamako_trailer_bytes >= 4) {
          /* Bytes are here, decode as TLVs. */
          metamako_tlv_firstword = tvb_get_ntohl(tvb, metamako_trailer_bytes - 4);
          metamako_tlv_count++;
          metamako_tlv_bytes += 4;
          metamako_trailer_bytes -= 4;

          /* Extract length */
          metamako_tlv_len = (metamako_tlv_firstword >> 6) & 0x3;

          /* If it's a secondary tag header, extract the extended length. */
          if ((metamako_tlv_firstword & 0x1F) == 0x1F)
            metamako_tlv_len = ((metamako_tlv_firstword >> 6) & 0x3FF) + 1;

          /* Skip over the data and find the next tag. We do this in a loop
             rather than subtracting `4 * metamako_tlv_len` in case the
             dissection has picked up an invalid TLV length in its
             heuristic search. This prevents the "walk" from going past the
             original length of the trailer. */
          while ((metamako_tlv_len > 0) && (metamako_trailer_bytes >= 4)) {
            metamako_tlv_len--;
            metamako_tlv_bytes += 4;
            metamako_trailer_bytes -= 4;
          }

          /* If this is flagged as the last TLV, stop. */
          if ((metamako_tlv_firstword >> 5) & 0x1) {
            break;
          }
        }
      }

      /* There should be at least enough bytes for the Orig FCS field.
       * Any bytes before this are padding. */
      if (metamako_trailer_bytes >= 4) {
        /* Decrement by the number of bytes in the Orig FCS field. */
        metamako_trailer_bytes -= 4;
        /* This byte offset is the beginning of the Metamako trailer. */
        offset = metamako_trailer_bytes;
        /* If we've made it this far, it appears we've got a valid trailer. */
        trailer_valid = true;
      }
    }
  }

  /* Did we find a valid trailer? */
  if (!trailer_valid)
    return 0;

  /* Everything looks good! Now dissect the trailer. */
  col_append_str(pinfo->cinfo, COL_INFO, " with Metamako trailer");
  ti = proto_tree_add_item(tree, proto_metamako, tvb, offset, (captured_trailer_bytes - offset), ENC_NA);
  metamako_tree = proto_item_add_subtree(ti, ett_metamako);

  /* Original FCS */
  proto_tree_add_item(metamako_tree, hf_metamako_origfcs, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* TLV Extensions */
  if (metamako_tlv_bytes > 0) {
    parent = proto_tree_add_item(metamako_tree, hf_metamako_trailerext, tvb, captured_trailer_bytes - 12 - metamako_tlv_bytes, metamako_tlv_bytes, ENC_NA);
    extensions_tree = proto_item_add_subtree(parent, ett_metamako_extensions);
    while (metamako_tlv_count > 0) {
      metamako_tlv_pos = captured_trailer_bytes - 16;
      i = metamako_tlv_count;
      do {
        /* Read TLV word and decode. */
        metamako_tlv_firstword = tvb_get_ntohl(tvb, metamako_tlv_pos);
        metamako_tlv_len = (metamako_tlv_firstword >> 6) & 0x3;
        metamako_tlv_bytes = (metamako_tlv_len * 4) + 3;
        metamako_tlv_tag = (metamako_tlv_firstword & 0x1F);

        /* If this is a Secondary Tag Header, decode the tag extensions. */
        if ((metamako_tlv_firstword & 0x1F) == 0x1F) {
          metamako_tlv_len = ((metamako_tlv_firstword >> 6) & 0x3FF) + 1;
          metamako_tlv_bytes = (metamako_tlv_len * 4);
          metamako_tlv_tag += ((metamako_tlv_firstword >> 16) & 0xFFFF);
        }

        /* Decrement TLV count. */
        i--;

        /* Skip over the data if this is not our destination. */
        if (i != 0)
          metamako_tlv_pos -= (metamako_tlv_len + 1) * 4;
      } while (i > 0);

      metamako_tlv_pos -= (metamako_tlv_len + 1) * 4;
      /* We've skipped to the i-th TLV, decode it. */
      switch (metamako_tlv_tag) {
      case 0x00:
        /* Ingress Sequence Number */
        proto_tree_add_item(extensions_tree, hf_metamako_seqnum, tvb, metamako_tlv_pos + 5, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(parent, ", Sequence No: %d", tvb_get_ntohs(tvb, metamako_tlv_pos + 5));
        break;

      case 0x01:
        /* Sub-nanoseconds */
        proto_tree_add_item(extensions_tree, hf_metamako_fracns, tvb, metamako_tlv_pos + 4, 3, ENC_BIG_ENDIAN);
        proto_item_append_text(parent, ", Sub-nanoseconds: %1.9fns", ((double)(tvb_get_ntohl(tvb, metamako_tlv_pos + 3) & 0x00FFFFFF)) / (1ULL << 24));
        break;

      case 0x02:
        /* Deduplication CRC64 Hash */
        proto_tree_add_item(extensions_tree, hf_metamako_crchash, tvb, metamako_tlv_pos + 4, 8, ENC_BIG_ENDIAN);
        proto_item_append_text(parent, ", CRC64 ECMA Hash: 0x%" PRIx64, tvb_get_ntoh64(tvb, metamako_tlv_pos + 4));
        break;

      case 0x03:
        /* Egress Sequence Number */
        proto_tree_add_item(extensions_tree, hf_metamako_egress_seqnum, tvb, metamako_tlv_pos + 4, 3, ENC_BIG_ENDIAN);
        proto_item_append_text(parent, ", Egress Sequence No: %d", tvb_get_ntohl(tvb, metamako_tlv_pos + 3) & 0x000FFFFF);
        break;

      case 0x1F:
        /* Tag String */
        proto_tree_add_item(extensions_tree, hf_metamako_tagstring, tvb, metamako_tlv_pos + 4, metamako_tlv_len * 4, ENC_ASCII);
        break;

      default:
        /* Unknown tag: just print it's ID and Data. */
        item = proto_tree_add_item(extensions_tree, hf_metamako_unknownext, tvb, metamako_tlv_pos + 4, metamako_tlv_bytes, ENC_NA);
        /* Start with the Tag */
        proto_item_set_text(item, "Unknown Tag [0x%05" PRIx32 "]: ", metamako_tlv_tag);
        /* Iterate through the data appending as we go */
        for (j = 0; j < metamako_tlv_bytes; j++) {
          proto_item_append_text(item, "%02" PRIx8, tvb_get_uint8(tvb, metamako_tlv_pos + 4 + j));
          if ((28 + j * 2) >= ITEM_LABEL_LENGTH) {
            proto_item_append_text(item, "...");
            break;
          }
        }
        break;
      }

      /* Increment the offset by the Data + Tag size */
      offset += (metamako_tlv_len + 1) * 4;
      /* Decrement count as we've just decoded a TLV */
      metamako_tlv_count--;
    }
  }

  /* Timestamp */
  item = proto_tree_add_time(metamako_tree, hf_metamako_time_abs, tvb, offset, 8, &metamako_time);
  timestamp_tree = proto_item_add_subtree(item, ett_metamako_timestamp);

  tmp = localtime(&metamako_time.secs);
  if (tmp)
    proto_item_append_text(ti, ", Timestamp: %02d:%02d:%02d.%09ld",
      tmp->tm_hour, tmp->tm_min, tmp->tm_sec, (long)metamako_time.nsecs);
  else
    proto_item_append_text(ti, ", Timestamp: <Not representable>");

  /* [Timestamp in seconds] */
  item = proto_tree_add_time_item(timestamp_tree, hf_metamako_time_rel, tvb, offset, 8,
    ENC_BIG_ENDIAN, &time_rel, NULL, NULL);
  proto_item_set_generated(item);

  /* [Timestamp difference - capture timestamp minus trailer timestamp] */
  nstime_delta(&time_diff, &pinfo->abs_ts, &metamako_time);
  item = proto_tree_add_time(timestamp_tree, hf_metamako_time_diff, tvb, offset, 8, &time_diff);
  proto_item_set_generated(item);
  offset += 8;

  /* Flags */
  proto_tree_add_bitmask(metamako_tree, tvb, offset, hf_metamako_flags, ett_metamako_flags, flags, ENC_BIG_ENDIAN);
  offset++;

  /* Source device */
  metamako_srcdevice = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(metamako_tree, hf_metamako_src_device, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_item_append_text(ti, ", Source Device: %d", metamako_srcdevice);
  offset += 2;

  /* Source port */
  metamako_srcport = tvb_get_uint8(tvb, offset);
  proto_tree_add_item(metamako_tree, hf_metamako_src_port, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(ti, ", Source Port: %d", metamako_srcport);
  offset++;

  if (has_fcs) {
    uint32_t sent_fcs = tvb_get_ntohl(tvb, offset);
    if (metamako_check_fcs) {
      tvbuff_t* parent_tvb = tvb_get_ds_tvb(tvb);
      uint32_t fcs = crc32_802_tvb(parent_tvb, tvb_captured_length(parent_tvb) - 4);
      proto_tree_add_checksum(tree, tvb, offset, hf_metamako_fcs, hf_metamako_fcs_status, &ei_metamako_fcs_bad, pinfo, fcs, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

      if (fcs != sent_fcs) {
        col_append_str(pinfo->cinfo, COL_INFO, " [ETHERNET FRAME CHECK SEQUENCE INCORRECT]");
      }
    }
    else {
      proto_tree_add_checksum(tree, tvb, offset, hf_metamako_fcs, hf_metamako_fcs_status, &ei_metamako_fcs_bad, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }
    offset += 4;
  }

  return offset;
}

static bool
dissect_metamako_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return dissect_metamako(tvb, pinfo, tree, data) > 0;
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

    { &hf_metamako_crchash, {
        "CRC64 ECMA Hash", "metamako.crchash",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_egress_seqnum, {
        "Egress Sequence Number", "metamako.egrseqnum",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_tagstring, {
        "Tag String", "metamako.tagstring",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_time_abs, {
        "Timestamp", "metamako.time.abs",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_time_rel, {
        "Timestamp", "metamako.time.rel",
        FT_RELATIVE_TIME, ENC_BIG_ENDIAN, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_time_diff, {
        "Time Difference", "metamako.time.diff",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "Capture timestamp minus trailer timestamp", HFILL }},

  {&hf_metamako_flags, {
        "Flags", "metamako.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},

    {&hf_metamako_reserved, {
        "Reserved", "metamako.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xC8,
        NULL, HFILL}},

    {&hf_metamako_flags_control_block_type, {
        "Clause 49 BTF", "metamako.flags.pcs49_btf",
        FT_UINT8, BASE_HEX, VALS(tfs_pcs49_btf_vals), 0x20,
        NULL, HFILL}},

    {&hf_metamako_flags_ts_degraded, {
        "Timestamp degraded", "metamako.flags.ts_degraded",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL}},

    {&hf_metamako_flags_duplicate, {
        "Duplicate Packet", "metamako.flags.is_duplicate",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL}},

    {&hf_metamako_flags_has_ext, {
        "Has Trailer Extensions", "metamako.flags.has_extensions",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL}},

    {&hf_metamako_flags_orig_fcs_vld, {
        "Original FCS Status", "metamako.flags.orig_fcs_status",
        FT_UINT8, BASE_HEX, VALS(tfs_orig_fcs_status_vals), 0x01,
        NULL, HFILL}},

    { &hf_metamako_src_device, {
        "Source Device ID", "metamako.src.device_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_src_port, {
        "Source Port", "metamako.src.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_metamako_fcs, {
        "Frame check sequence", "metamako.fcs",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "Ethernet checksum", HFILL }},

    { &hf_metamako_fcs_status, {
        "FCS Status", "metamako.fcs.status",
        FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
        NULL, HFILL }},
  };

  static int* ett[] = {
    &ett_metamako,
    &ett_metamako_extensions,
    &ett_metamako_timestamp,
    &ett_metamako_flags
  };

  static ei_register_info ei[] = {
    { &ei_metamako_fcs_bad, { "metamako.fcs_bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
  };

  module_t* metamako_module;

  /* Register the Metamako trailer. */
  proto_metamako = proto_register_protocol("Metamako ethernet trailer", "Metamako", "metamako");

  /* Register header fields. */
  proto_register_field_array(proto_metamako, hf, array_length(hf));

  /*  Register subtree types. */
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the expert module. */
  expert_register_field_array(expert_register_protocol(proto_metamako), ei, array_length(ei));

  /* Register configuration preferences */
  metamako_module = prefs_register_protocol(proto_metamako, NULL);

  range_convert_str(wmem_epan_scope(), &metamako_trailer_secs_bounds, TRAILER_SECS_BOUNDS_DFLT, 0xffffffff);
  prefs_register_range_preference(metamako_module, "secs_bounds",
    "Heuristic: Bounds of the seconds value in the trailer timestamp",
    "If the trailer is found using heuristics, then the trailer may or may not be added "
    "and the FCS may or may not be captured. One of the heuristics is the timestamp seconds "
    "value being within specified bounds. "
    "Set ranges of valid seconds to adjust this particular heuristic.",
    &metamako_trailer_secs_bounds, 0xffffffff);

  prefs_register_uint_preference(metamako_module, "days_diff_limit",
    "Heuristic: Max. number of days difference between capture and trailer timestamps",
    "If the trailer is found using heuristics, then the trailer may or may not be added "
    "and the FCS may or may not be captured. One of the heuristics is the number of days "
    "difference between the capture (PCAP) timestamp and the Ethernet trailer timestamp. "
    "Set an upper bound (in days) to adjust this particular heuristic.",
    10, &metamako_trailer_days_diff_limit);

  prefs_register_enum_preference(metamako_module, "trailer_present",
    "Assume packets have a Metamako trailer",
    "This option can override the trailer detection heuristic so that the Metamako "
    "trailer is either never or always present.",
    &metamako_trailer_present, metamako_trailer_present_vals, false);

  prefs_register_enum_preference(metamako_module, "fcs",
    "Assume packets have FCS",
    "Some Ethernet adapters and drivers include the FCS at the end of a packet, others do not.  "
    "Some capture file formats and protocols do not indicate whether or not the FCS is included. "
    "The Metamako dissector attempts to guess whether a captured packet has an FCS, "
    "but it cannot always guess correctly. This option can override that heuristic "
    "and assume that the FCS is either never or always present.",
    &metamako_fcs_len, metamako_fcs_vals, false);

  prefs_register_bool_preference(metamako_module, "check_fcs",
    "Validate the Ethernet checksum if possible",
    "Whether to validate the Frame Check Sequence",
    &metamako_check_fcs);
}

void
proto_reg_handoff_metamako(void)
{
  heur_dissector_add("eth.trailer", dissect_metamako_heur, "Metamako ethernet trailer", "metamako_eth", proto_metamako, HEURISTIC_DISABLE);
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
