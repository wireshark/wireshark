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

#define IXIA_PATTERN    0xAF12

/* TODO: which of these typestamp types are currently supported?
   Should lose the rest!! */
#define IXIATRAILER_FTYPE_TIMESTAMP_LOCAL     3
#define IXIATRAILER_FTYPE_TIMESTAMP_NTP       4
#define IXIATRAILER_FTYPE_TIMESTAMP_GPS       5
#define IXIATRAILER_FTYPE_TIMESTAMP_1588      6 /* PTP */
#define IXIATRAILER_FTYPE_TIMESTAMP_HOLDOVER  7

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

static int hf_ixiatrailer_timestamp = -1;
static int hf_ixiatrailer_generic = -1;

static expert_field ei_ixiatrailer_field_length_invalid = EI_INIT;

/* Format is as follows:
   - Time Sync source (1 byte)
   - Length of time (1 byte - value will always be 8)
   - Timestamp (8 bytes)
   - Trailer length -previous fields, always 10 (1 byte)
   - Ixia signature - AF12 (2 bytes)
   - FCS for IXIA timestamp - covers 13 bytes of all previous fields (2 bytes)
*/
static int
dissect_ixiatrailer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *ti;
    guint tvblen, trailer_length, time_length;
    proto_tree *ixiatrailer_tree = NULL;
    guint offset = 0;
    guint16 cksum, comp_cksum;
    vec_t vec;
    guint8 source;

    /* Need at least 5 bytes.  TODO: should be 15? */
    tvblen = tvb_length(tvb);
    if (tvblen < 5) {
        return 0;
    }

    /* Depending upon the ethernet preference "Assume packets have FCS", we
       may be given those 4 bytes too.  If we see 19 bytes, assume we are
       getting them and only look at first 15. */
    if (tvblen == 19) {
        tvblen = 15;
    }

    /* 3rd & 4th bytes from the end must match our pattern */
    if (tvb_get_ntohs(tvb, tvblen-4) != IXIA_PATTERN) {
        return 0;
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
    vec.len = trailer_length + 3;
    vec.ptr = tvb_get_ptr(tvb, offset, vec.len);
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

    source = tvb_get_guint8(tvb, offset++);
    time_length = tvb_get_guint8(tvb, offset++);

    switch (source) {
        case IXIATRAILER_FTYPE_TIMESTAMP_LOCAL:
        case IXIATRAILER_FTYPE_TIMESTAMP_NTP:
        case IXIATRAILER_FTYPE_TIMESTAMP_GPS:
        case IXIATRAILER_FTYPE_TIMESTAMP_1588:
        case IXIATRAILER_FTYPE_TIMESTAMP_HOLDOVER:
            if (time_length != 8) {
                expert_add_info_format(pinfo, ti, &ei_ixiatrailer_field_length_invalid, "Field length %u invalid", time_length);
                break;
            }
            /* Timestamp */
            ti = proto_tree_add_item(ixiatrailer_tree, hf_ixiatrailer_timestamp, tvb, offset, time_length, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
            proto_item_append_text(ti, "; Source: %s", val_to_str_const(source, ixiatrailer_ftype_timestamp, "Unknown"));
            break;

      default:
            /* Not a recognised time format - just show as bytes */
            ti = proto_tree_add_item(ixiatrailer_tree, hf_ixiatrailer_generic, tvb, offset, time_length, ENC_NA);
            proto_item_append_text(ti, " [Id: %u, Length: %u]", source, time_length);
            break;
    }

    /* We are claiming all of the bytes */
    return tvblen;
}

void
proto_register_ixiatrailer(void)
{

  static hf_register_info hf[] = {
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
  heur_dissector_add("eth.trailer", dissect_ixiatrailer, proto_ixiatrailer);
}
