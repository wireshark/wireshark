/* packet-ixiatrailer.c
 * Routines for Ixia trailer parsing
 *
 * Dissector for Ixia Network Visibility Solutions trailer
 * Copyright Ixia 2012
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
#include <wsutil/pint.h>
#include <epan/prefs.h>
#include <epan/in_cksum.h>
#include <epan/expert.h>

void proto_register_ixiatrailer(void);
void proto_reg_handoff_ixiatrailer(void);

/* Trailer "magic number". */
#define IXIA_PATTERN    0xAF12

/* Trailer TLV types.

   TODO: which of these typestamp types are currently supported?
   Should lose the rest!! */
#define IXIATRAILER_FTYPE_ORIGINAL_PACKET_SIZE 1
#define IXIATRAILER_FTYPE_TIMESTAMP_LOCAL      3
#define IXIATRAILER_FTYPE_TIMESTAMP_NTP        4
#define IXIATRAILER_FTYPE_TIMESTAMP_GPS        5
#define IXIATRAILER_FTYPE_TIMESTAMP_1588       6 /* PTP */
#define IXIATRAILER_FTYPE_TIMESTAMP_HOLDOVER   7

static const value_string ixiatrailer_ftype_timestamp[] = {
  { IXIATRAILER_FTYPE_TIMESTAMP_LOCAL,      "Local" },
  { IXIATRAILER_FTYPE_TIMESTAMP_NTP,        "NTP" },
  { IXIATRAILER_FTYPE_TIMESTAMP_GPS,        "GPS" },
  { IXIATRAILER_FTYPE_TIMESTAMP_1588,       "PTP" },
  { IXIATRAILER_FTYPE_TIMESTAMP_HOLDOVER,   "Holdover" },
  { 0,                                      NULL }
};

/* Preference settings */
static gboolean ixiatrailer_summary_in_tree = TRUE;

static int proto_ixiatrailer = -1;
static gint ett_ixiatrailer = -1;

static int hf_ixiatrailer_packetlen = -1;
static int hf_ixiatrailer_timestamp = -1;
static int hf_ixiatrailer_generic = -1;

static expert_field ei_ixiatrailer_field_length_invalid = EI_INIT;

/* The trailer begins with a sequence of TLVs, each of which has a
   1-byte type, a 1-byte value length (not TLV length, so the TLV
   length is the value length + 2), and a variable-length value.

   Following the sequence of TLVs is:

      a 1-byte field giving the length of the sequence of TLVs;
      a 2-byte big-endian signature field with the value 0xAF12;
      a 2-byte big-endian checksum field, covering the sequence
      of TLVs, the sequence length, and the signature.
*/
static int
dissect_ixiatrailer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_tree *ti;
  guint tvblen, trailer_length, field_length;
  gboolean matched_without_fcs, matched_with_fcs;
  proto_tree *ixiatrailer_tree = NULL;
  guint offset = 0;
  guint16 cksum, comp_cksum;
  vec_t vec;
  guint8 field_type;

  /* A trailer must, at minimum, include:

       a "original packet size" TLV, with 1 byte of type, 1 byte of
       value length, and 2 bytes of original packet ize;

       1 byte of trailer length;

       2 bytes of signature;

       2 bytes of trailer checksum;

     for a total of 9 bytes. */
  tvblen = tvb_reported_length(tvb);
  if (tvblen != tvb_captured_length(tvb)) {
    /* The heuristic check includes a checksum check, so we need the
       *entire* trailer to have been captured; if it wasn't, we don't
       try to check it. */
    return 0;
  }
  if (tvblen < 9) {
    /* This is too short, so it cannot be a valid Ixia trailer. */
    return 0;
  }

  /* Depending upon the ethernet preference "Assume packets have FCS", we
     may be given those 4 bytes too.

     Try checking two locations for our pattern. */

  if (tvblen == 23) {
    tvblen = 19;
  }

  /* 3rd & 4th bytes from the end must match our pattern.
     First, try under the assumption that the tvbuff doesn't include
     the FCS. */
  matched_without_fcs = (tvb_get_ntohs(tvb, tvblen-4) == IXIA_PATTERN);

  /* If that didn't match, is the tvbuff big enough to include an Ixia
     trailer *and* an FCS? If so, try under that assumption. */
  if (!matched_without_fcs && tvblen >= 13)
    matched_with_fcs = (tvb_get_ntohs(tvb, tvblen-(4+4)) == IXIA_PATTERN);
  else
    matched_with_fcs = FALSE;
  if (!matched_without_fcs) {
    if (!matched_with_fcs) {
      /* Neither matched, so no Ixia trailer. */
      return 0;
    }

    /* Matched under the assumption that we have an FCS, so let's
       act as if that's the case.  Remove the FCS length from the
       tvbuff. */
    tvblen -= 4;
  }

  /* Read Trailer-length field */
  trailer_length  = tvb_get_guint8(tvb, tvblen-5);
  /* Should match overall length of trailer */
  if ((tvblen-5) != trailer_length) {
    return 0;
  }

  /* Last 2 bytes are the checksum */
  cksum = tvb_get_ntohs(tvb, tvblen-2);

  /* Verify the checksum; if not valid, it means that the trailer is not valid */
  SET_CKSUM_VEC_TVB(vec, tvb, offset, trailer_length + 3);
  comp_cksum = in_cksum(&vec, 1);
  if (pntoh16(&comp_cksum) != cksum) {
    return 0;
  }

  /* OK: We have our trailer - create protocol root */
  ti = proto_tree_add_item(tree, proto_ixiatrailer, tvb, offset, trailer_length + 5, ENC_NA);

  /* Append summary to item, if configured to */
  if (ixiatrailer_summary_in_tree) {
    proto_item_append_text(ti, ", Length: %u, Checksum: 0x%x", trailer_length, cksum);
  }

  /* Create subtree */
  ixiatrailer_tree = proto_item_add_subtree(ti, ett_ixiatrailer);

  while (offset < trailer_length - 2)
  {
    field_type = tvb_get_guint8(tvb, offset++);
    field_length = tvb_get_guint8(tvb, offset++);
    switch (field_type) {
      case IXIATRAILER_FTYPE_ORIGINAL_PACKET_SIZE:
        if (field_length != 2){
          expert_add_info_format(pinfo, ti, &ei_ixiatrailer_field_length_invalid, "Field length %u invalid", field_length);
          break;
        }
        ti = proto_tree_add_item(ixiatrailer_tree, hf_ixiatrailer_packetlen, tvb, offset, field_length, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " bytes");
      break;
      case IXIATRAILER_FTYPE_TIMESTAMP_LOCAL:
      case IXIATRAILER_FTYPE_TIMESTAMP_NTP:
      case IXIATRAILER_FTYPE_TIMESTAMP_GPS:
      case IXIATRAILER_FTYPE_TIMESTAMP_1588:
      case IXIATRAILER_FTYPE_TIMESTAMP_HOLDOVER:
        if (field_length != 8) {
          expert_add_info_format(pinfo, ti, &ei_ixiatrailer_field_length_invalid, "Field length %u invalid", field_length);
          break;
        }
        /* Timestamp */
        ti = proto_tree_add_item(ixiatrailer_tree, hf_ixiatrailer_timestamp, tvb, offset, field_length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
        proto_item_append_text(ti, "; Source: %s", val_to_str_const(field_type, ixiatrailer_ftype_timestamp, "Unknown"));
      break;
      default:
        /* Not a recognized time format - just show as bytes */
        ti = proto_tree_add_item(ixiatrailer_tree, hf_ixiatrailer_generic, tvb, offset, field_length, ENC_NA);
        proto_item_append_text(ti, " [Id: %u, Length: %u bytes]", field_type, field_length);
      break;
    };
    offset += field_length;
  }
  /* We are claiming all of the bytes */
  return tvblen;
}

void
proto_register_ixiatrailer(void)
{

  static hf_register_info hf[] = {
    { &hf_ixiatrailer_packetlen, {
        "Original packet length", "ixiatrailer.packetlen", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},
    { &hf_ixiatrailer_timestamp, {
        "Time Stamp", "ixiatrailer.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0x0, NULL, HFILL }},
    { &hf_ixiatrailer_generic, {
        "Generic Field", "ixiatrailer.generic", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
  };

  static gint *ixiatrailer_ett[] = {
    &ett_ixiatrailer
  };

  static ei_register_info ei[] = {
     { &ei_ixiatrailer_field_length_invalid, { "ixiatrailer.field_length_invalid", PI_MALFORMED, PI_ERROR, "Field length invalid", EXPFILL }},
  };

  module_t *ixiatrailer_module;
  expert_module_t* expert_ixiatrailer;

  proto_ixiatrailer = proto_register_protocol("Ixia Trailer", "IXIATRAILER", "ixiatrailer");
  proto_register_field_array(proto_ixiatrailer, hf, array_length(hf));
  proto_register_subtree_array(ixiatrailer_ett, array_length(ixiatrailer_ett));
  expert_ixiatrailer = expert_register_protocol(proto_ixiatrailer);
  expert_register_field_array(expert_ixiatrailer, ei, array_length(ei));

  ixiatrailer_module = prefs_register_protocol(proto_ixiatrailer, NULL);
  prefs_register_bool_preference(ixiatrailer_module, "summary_in_tree",
        "Show trailer summary in protocol tree",
        "Whether the trailer summary line should be shown in the protocol tree",
        &ixiatrailer_summary_in_tree);
}


void
proto_reg_handoff_ixiatrailer(void)
{
  /* Check for Ixia format in the ethernet trailer */
  heur_dissector_add("eth.trailer", dissect_ixiatrailer, "Ixia Trailer", "ixiatrailer_eth", proto_ixiatrailer, HEURISTIC_ENABLE);
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
