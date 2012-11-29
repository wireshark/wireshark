/* packet-amr.c
 * Routines for AMR dissection
 * Copyright 2005-2008, Anders Broman <anders.broman[at]ericsson.com>
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
 *
 * References:
 * RFC 3267  http://www.ietf.org/rfc/rfc3267.txt?number=3267
 * 3GPP TS 26.101 for AMR-NB, 3GPP TS 26.201 for AMR-WB
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include <epan/prefs.h>

#define AMR_NB_SID 8
#define AMR_WB_SID 9
#define AMR_NO_TRANS 15

#define AMR_NB 0
#define AMR_WB 1

/* Initialize the protocol and registered fields */
static int proto_amr = -1;
static int hf_amr_nb_cmr = -1;
static int hf_amr_wb_cmr = -1;
static int hf_amr_reserved = -1;
static int hf_amr_toc_f = -1;
static int hf_amr_nb_toc_ft = -1;
static int hf_amr_wb_toc_ft = -1;
static int hf_amr_toc_q = -1;

static int hf_amr_nb_if1_ft = -1;
static int hf_amr_wb_if1_ft = -1;
static int hf_amr_if1_fqi = -1;
static int hf_amr_nb_if1_mode_req = -1;
static int hf_amr_wb_if1_mode_req = -1;
static int hf_amr_if1_sti = -1;
static int hf_amr_nb_if1_mode_ind = -1;
static int hf_amr_wb_if1_mode_ind = -1;
static int hf_amr_nb_if1_sti_mode_ind = -1;
static int hf_amr_wb_if1_sti_mode_ind = -1;
static int hf_amr_if2_sti = -1;
static int hf_amr_nb_if2_sti_mode_ind = -1;
static int hf_amr_wb_if2_sti_mode_ind = -1;

static int hf_amr_nb_if2_ft = -1;
static int hf_amr_wb_if2_ft = -1;


/* Initialize the subtree pointers */
static int ett_amr = -1;
static int ett_amr_toc = -1;

/* The dynamic payload type which will be dissected as AMR */

static guint temp_dynamic_payload_type = 0;
static gint  amr_encoding_type         = 0;
static gint  pref_amr_mode             = AMR_NB;


/* Currently only octet aligned works */
/* static gboolean octet_aligned = TRUE; */

static const value_string amr_encoding_type_value[] = {
    {0, "RFC 3267"},
    {1, "RFC 3267 bandwidth-efficient mode"},
    {2, "AMR IF 1"},
    {3, "AMR IF 2"},
    { 0,    NULL }
};


/* Table 1a of 3GPP TS 26.201*/
static const value_string amr_nb_codec_mode_vals[] = {
    {0,            "AMR 4,75 kbit/s"},
    {1,            "AMR 5,15 kbit/s"},
    {2,            "AMR 5,90 kbit/s"},
    {3,            "AMR 6,70 kbit/s (PDC-EFR)"},
    {4,            "AMR 7,40 kbit/s (TDMA-EFR)"},
    {5,            "AMR 7,95 kbit/s"},
    {6,            "AMR 10,2 kbit/s"},
    {7,            "AMR 12,2 kbit/s (GSM-EFR)"},
    {AMR_NB_SID,   "AMR SID (Comfort Noise Frame)"},
    {9,            "GSM-EFR SID"},
    {10,           "TDMA-EFR SID "},
    {11,           "PDC-EFR SID"},
    {12,           "Illegal Frametype - for future use"},
    {13,           "Illegal Frametype - for future use"},
    {14,           "Illegal Frametype - for future use"},
    {AMR_NO_TRANS, "No Data (No transmission/No reception)"},
    { 0,    NULL }
};
static value_string_ext amr_nb_codec_mode_vals_ext = VALUE_STRING_EXT_INIT(amr_nb_codec_mode_vals);

static const value_string amr_wb_codec_mode_vals[] = {
    {0,            "AMR-WB 6.60 kbit/s"},
    {1,            "AMR-WB 8.85 kbit/s"},
    {2,            "AMR-WB 12.65 kbit/s"},
    {3,            "AMR-WB 14.25 kbit/s"},
    {4,            "AMR-WB 15.85 kbit/s"},
    {5,            "AMR-WB 18.25 kbit/s"},
    {6,            "AMR-WB 19.85 kbit/s"},
    {7,            "AMR-WB 23.05 kbit/s"},
    {8,            "AMR-WB 23.85 kbit/s"},
    {AMR_WB_SID,   "AMR-WB SID (Comfort Noise Frame)"},
    {10,           "Illegal Frametype"},
    {11,           "Illegal Frametype"},
    {12,           "Illegal Frametype"},
    {13,           "Illegal Frametype"},
    {14,           "Speech lost"},
    {AMR_NO_TRANS, "No Data (No transmission/No reception)"},
    { 0,    NULL }
};

static value_string_ext amr_wb_codec_mode_vals_ext = VALUE_STRING_EXT_INIT(amr_wb_codec_mode_vals);

/* Ref 3GPP TS 26.101 table 1a for AMR-NB*/

/* From RFC3267 chapter 4.3.1
CMR (4 bits): Indicates a codec mode request sent to the speech
      encoder at the site of the receiver of this payload.  The value of
      the CMR field is set to the frame type index of the corresponding
      speech mode being requested.  The frame type index may be 0-7 for
      AMR, as defined in Table 1a in [2], or 0-8 for AMR-WB, as defined
      in Table 1a in [3GPP TS 26.201].  CMR value 15 indicates that no
      mode request is present, and other values are for future use.
*/
static const value_string amr_nb_codec_mode_request_vals[] = {
    {0,  "AMR 4,75 kbit/s"},
    {1,  "AMR 5,15 kbit/s"},
    {2,  "AMR 5,90 kbit/s"},
    {3,  "AMR 6,70 kbit/s (PDC-EFR)"},
    {4,  "AMR 7,40 kbit/s (TDMA-EFR)"},
    {5,  "AMR 7,95 kbit/s"},
    {6,  "AMR 10,2 kbit/s"},
    {7,  "AMR 12,2 kbit/s (GSM-EFR)"},
    {8,  "Illegal Frametype - For future use"},
    {9,  "Illegal Frametype - For future use"},
    {10, "Illegal Frametype - For future use"},
    {11, "Illegal Frametype - For future use"},
    {12, "Illegal Frametype - For future use"},
    {13, "Illegal Frametype - For future use"},
    {14, "Illegal Frametype - For future use"},
    {15, "No mode request"},
    { 0,    NULL }
};
static value_string_ext amr_nb_codec_mode_request_vals_ext = VALUE_STRING_EXT_INIT(amr_nb_codec_mode_request_vals);

/* Ref 3GPP TS 26.201 table 1a for AMR-WB*/
static const value_string amr_wb_codec_mode_request_vals[] = {
    {0,  "AMR-WB 6.60 kbit/s"},
    {1,  "AMR-WB 8.85 kbit/s"},
    {2,  "AMR-WB 12.65 kbit/s"},
    {3,  "AMR-WB 14.25 kbit/s"},
    {4,  "AMR-WB 15.85 kbit/s"},
    {5,  "AMR-WB 18.25 kbit/s"},
    {6,  "AMR-WB 19.85 kbit/s"},
    {7,  "AMR-WB 23.05 kbit/s"},
    {8,  "AMR-WB 23.85 kbit/s"},
    {9,  "Illegal Frametype - For future use"},
    {10, "Illegal Frametype - For future use"},
    {11, "Illegal Frametype - For future use"},
    {12, "Illegal Frametype - For future use"},
    {13, "Illegal Frametype - For future use"},
    {14, "Illegal Frametype - For future use"},
    {15, "No mode request"},
    { 0,    NULL }
};
static value_string_ext amr_wb_codec_mode_request_vals_ext = VALUE_STRING_EXT_INIT(amr_wb_codec_mode_request_vals);

static const true_false_string toc_f_bit_vals = {
    "Followed by another speech frame",
    "Last frame in this payload"
};

static const true_false_string toc_q_bit_vals = {
    "Ok",
    "Severely damaged frame"
};

static const true_false_string amr_sti_vals = {
    "SID_UPDATE",
    "SID_FIRST"
};

/* See 3GPP TS 26.101 chapter 4 for AMR-NB IF1 */
static void
dissect_amr_nb_if1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int         offset = 0;
    guint8      octet;
    proto_item *ti;

    proto_tree_add_item(tree, hf_amr_nb_if1_ft, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_amr_if1_fqi,   tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = (tvb_get_guint8(tvb,offset) & 0xf0) >> 4;
    if (octet == AMR_NB_SID) {
        ti = proto_tree_add_item(tree, hf_amr_nb_if1_mode_req, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        if (tvb_get_guint8(tvb,offset+1) & 0x1f)
            expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Error:Spare bits not 0");
        proto_tree_add_text(tree, tvb, offset+2, 5, "Speech data");
        proto_tree_add_item(tree, hf_amr_if1_sti, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_amr_nb_if1_sti_mode_ind, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        return;
    }

    proto_tree_add_item(tree, hf_amr_nb_if1_mode_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    ti = proto_tree_add_item(tree, hf_amr_nb_if1_mode_req, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (tvb_get_guint8(tvb,offset) & 0x1f)
        expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Error:Spare bits not 0");
    offset += 1;
    proto_tree_add_text(tree, tvb, offset, -1, "Speech data");
}

/* See 3GPP TS 26.201 for AMR-WB */
static void
dissect_amr_wb_if1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int         offset = 0;
    guint8      octet;
    proto_item *ti;

    proto_tree_add_item(tree, hf_amr_wb_if1_ft, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(tree, hf_amr_if1_fqi, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (tvb_get_guint8(tvb,offset) & 0x03)
        expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Error:Spare bits not 0");
    octet = (tvb_get_guint8(tvb,offset) & 0xf0) >> 4;
    if (octet == AMR_WB_SID) {
        proto_tree_add_item(tree, hf_amr_wb_if1_mode_req, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(tree, tvb, offset+2, 4, "Speech data");
        proto_tree_add_item(tree, hf_amr_if1_sti, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_amr_wb_if1_sti_mode_ind, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        return;
    }

    offset += 1;
    proto_tree_add_item(tree, hf_amr_wb_if1_mode_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_amr_wb_if1_mode_req, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_text(tree, tvb, offset, -1, "Speech data");
}

static void
dissect_amr_nb_if2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int    offset = 0;
    guint8 octet;

    proto_tree_add_item(tree, hf_amr_nb_if2_ft, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = tvb_get_guint8(tvb,offset) & 0x0f;

    if (octet == AMR_NB_SID) {
        proto_tree_add_text(tree, tvb, offset+1, 3, "Speech data");
        proto_tree_add_item(tree, hf_amr_if2_sti, tvb, offset+4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_amr_nb_if2_sti_mode_ind, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        return;
    }
    if (octet == AMR_NO_TRANS)
        return;
    proto_tree_add_text(tree, tvb, offset+1, -1, "Speech data");

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
            val_to_str_ext(octet, &amr_nb_codec_mode_request_vals_ext, "Unknown (%d)" ));
}

static void
dissect_amr_wb_if2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int    offset = 0;
    guint8 octet;

    proto_tree_add_item(tree, hf_amr_wb_if2_ft, tvb, offset, 1, ENC_BIG_ENDIAN);
    octet = (tvb_get_guint8(tvb,offset) & 0xf0) >> 4;

    if (octet == AMR_WB_SID) {
        proto_tree_add_text(tree, tvb, offset+1, 4, "Speech data");
        proto_tree_add_item(tree, hf_amr_if2_sti, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_amr_wb_if2_sti_mode_ind, tvb, offset+5, 1, ENC_BIG_ENDIAN);
        return;
    }
    if (octet == AMR_NO_TRANS)
        return;
    proto_tree_add_text(tree, tvb, offset+1, -1, "Speech data");

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
            val_to_str_ext(octet, &amr_wb_codec_mode_request_vals_ext, "Unknown (%d)" ));
}

static void
dissect_amr_be(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint amr_mode) {
    proto_item *item;
    int         ft;
    int         bit_offset = 0;
    int         bitcount;       /*bitcounter, MSB = bit 0, over bytes*/
    int         bits_used_for_frames = 0;
    int         bytes_needed_for_frames;
    guint8      f_bit, q_bit;

    /* Number of bits per frame for AMR-NB, see Table 1 RFC3267*/
    /* Values taken for GSM-EFR SID, TDMA-EFR SID and PDC-EFR SID from 3GPP 26.101 Table A.1b */

    /*               Frame type     0   1   2   3   4   5   6   7  8  9  10 11 12 13 14 15 */
    unsigned char Framebits_NB[] = {95,103,118,134,148,159,204,244,39,43,38,37, 0, 0, 0, 0};

    /* Number of bits per frame for AMR-WB, see 3GPP TS 26.201 Table 2*/
    /*               Frame type     0   1   2   3   4   5   6   7   8   9  10 11 12 13 14 15 */
    unsigned int Framebits_WB[] = {132,177,253,285,317,365,397,461,477, 40, 0, 0, 0, 0, 0, 0,};


    /* Chapter 4.3 */

    bitcount = 3;
    if (amr_mode == AMR_NB)
        proto_tree_add_bits_item(tree, hf_amr_nb_cmr, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    else
        proto_tree_add_bits_item(tree, hf_amr_wb_cmr, tvb, bit_offset, 4, ENC_BIG_ENDIAN);

    bit_offset += 4;
    /* In bandwidth-efficient mode, a ToC entry takes the following format:
     *
     *    0 1 2 3 4 5
     *   +-+-+-+-+-+-+
     *   |F|  FT   |Q|
     *   +-+-+-+-+-+-+
     *
     *   F (1 bit): If set to 1, indicates that this frame is followed by
     *      another speech frame in this payload; if set to 0, indicates that
     *      this frame is the last frame in this payload.
     *
     *   FT (4 bits): Frame type index, indicating either the AMR or AMR-WB
     *      speech coding mode or comfort noise (SID) mode of the
     *      corresponding frame carried in this payload.
     */
    do {
        /* Check F bit */
        bitcount += 1;
        f_bit = tvb_get_bits8(tvb, bit_offset, 1);
        proto_tree_add_bits_item(tree, hf_amr_toc_f, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        ft = tvb_get_bits8(tvb, bit_offset, 4);
        if (amr_mode == AMR_NB)
            item = proto_tree_add_bits_item(tree, hf_amr_nb_toc_ft, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        else
            item = proto_tree_add_bits_item(tree, hf_amr_wb_toc_ft, tvb, bit_offset, 4, ENC_BIG_ENDIAN);

        bit_offset += 4;
        bitcount   += 4;
        if (amr_mode == AMR_NB)
            bits_used_for_frames += Framebits_NB[ft];
        else
            bits_used_for_frames += Framebits_WB[ft];
        /* Check Q bit */
        q_bit = tvb_get_bits8(tvb, bit_offset, 1);
        proto_tree_add_bits_item(tree, hf_amr_toc_q, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        bitcount   += 1;
        if (q_bit == 1)
            proto_item_append_text(item, " / Frame OK");
        else
            proto_item_append_text(item, " / Frame damaged");
    } while ((f_bit == 1) && (tvb_reported_length_remaining(tvb, bitcount/8) > 2));

    if (bits_used_for_frames > 0)
        bytes_needed_for_frames = 1 + (bitcount+bits_used_for_frames)/8-bitcount/8;
    else
        bytes_needed_for_frames = 0;

    /* Check if we have enough data available for our frames */
    if (tvb_reported_length_remaining(tvb, bitcount/8) < bytes_needed_for_frames) {
        item = proto_tree_add_text(tree, tvb, bitcount/8, bytes_needed_for_frames, "Error:");
        proto_item_append_text(item, " %d Bytes available, %d would be needed!",
                       tvb_reported_length_remaining(tvb, bitcount/8),
                       bytes_needed_for_frames);
        expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Not enough data for the frames according to TOC");
    }
    else {
        item = proto_tree_add_text(tree, tvb, bitcount/8, bytes_needed_for_frames, "Frame Data");
        proto_item_append_text(item, " (%d Bytes)",bytes_needed_for_frames);
    }

    bitcount += bits_used_for_frames;

    if (tvb_reported_length_remaining(tvb, (bitcount+8)/8) > 0) {
        item = proto_tree_add_text(tree, tvb, bitcount/8, tvb_reported_length_remaining(tvb, bitcount/8), "Error:");
        proto_item_append_text(item, " %d Bytes remaining - should be 0!",tvb_reported_length_remaining(tvb, (bitcount+8)/8));
        expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Superfluous data remaining");

        /* Now check the paddings */
        if (bitcount%8 != 0) {
            if ( (1 << (8 -(bitcount%8)-1)) & tvb_get_guint8(tvb,bitcount/8) )
                proto_tree_add_text(tree, tvb, bitcount/8, 1, "Padding bits correct");
            else {
                item = proto_tree_add_text(tree, tvb, bitcount/8, 1, "Padding bits error");
                expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Padding bits error - MUST be 0");
            }
        }
    }
}

/* Code to actually dissect the packets */
static void
dissect_amr_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint amr_mode)
{
    int         offset     = 0;
    int         bit_offset = 0;
    guint8      octet;
    proto_item *item;
    gboolean    first_time;

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti,*toc_item;
    proto_tree *amr_tree, *toc_tree;

    ti = proto_tree_add_item(tree, proto_amr, tvb, 0, -1, ENC_NA);
    amr_tree = proto_item_add_subtree(ti, ett_amr);

    proto_tree_add_text(amr_tree, tvb, offset, -1, "Payload decoded as %s",
                val_to_str(amr_encoding_type, amr_encoding_type_value, "Unknown value - Error"));

    switch (amr_encoding_type) {
    case 0: /* RFC 3267 Byte aligned */
        break;
    case 1: /* RFC 3267 Bandwidth-efficient */
        dissect_amr_be(tvb, pinfo, amr_tree, amr_mode);
        return;
    case 2: /* AMR IF1 */
        if (amr_mode == AMR_NB)
            dissect_amr_nb_if1(tvb, pinfo, amr_tree);
        else
            dissect_amr_wb_if1(tvb, pinfo, amr_tree);
        return;
    case 3: /* AMR IF2 */
        if (amr_mode == AMR_NB)
            dissect_amr_nb_if2(tvb, pinfo, amr_tree);
        else
            dissect_amr_wb_if2(tvb, pinfo, amr_tree);
        return;
    default:
        break;
    }

    if (amr_mode == AMR_NB)
        proto_tree_add_bits_item(amr_tree, hf_amr_nb_cmr, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    else
        proto_tree_add_bits_item(amr_tree, hf_amr_wb_cmr, tvb, bit_offset, 4, ENC_BIG_ENDIAN);

    bit_offset += 4;
    octet = tvb_get_guint8(tvb,offset) & 0x0f;
    if ( octet != 0  ) {
        item = proto_tree_add_text(amr_tree, tvb, offset, -1,
                       "Reserved != 0, wrongly encoded or not octet aligned."
                       " Decoding as bandwidth-efficient mode");
        PROTO_ITEM_SET_GENERATED(item);
        return;

    }

    proto_tree_add_item(amr_tree, hf_amr_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset     += 1;
    bit_offset += 4;
    /*
     *  A ToC entry takes the following format in octet-aligned mode:
     *
     *    0 1 2 3 4 5 6 7
     *   +-+-+-+-+-+-+-+-+
     *   |F|  FT   |Q|P|P|
     *   +-+-+-+-+-+-+-+-+
     *
     *   F (1 bit): see definition in Section 4.3.2.
     *
     *   FT (4 bits unsigned integer): see definition in Section 4.3.2.
     *
     *   Q (1 bit): see definition in Section 4.3.2.
     *
     *   P bits: padding bits, MUST be set to zero.
     */
    octet = tvb_get_guint8(tvb,offset);
    toc_item = proto_tree_add_text(amr_tree, tvb, offset, -1, "Payload Table of Contents");
    toc_tree = proto_item_add_subtree(toc_item, ett_amr_toc);

    first_time = TRUE;
    while ((( octet& 0x80 ) == 0x80) || (first_time == TRUE)) {
        first_time = FALSE;
        octet = tvb_get_guint8(tvb,offset);

        proto_tree_add_bits_item(toc_tree, hf_amr_toc_f, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        if (amr_mode == AMR_NB)
            proto_tree_add_bits_item(toc_tree, hf_amr_nb_toc_ft, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        else
            proto_tree_add_bits_item(toc_tree, hf_amr_wb_toc_ft, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        proto_tree_add_bits_item(toc_tree, hf_amr_toc_q, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        /* 2 pading bits */
        bit_offset += 2;
        offset     += 1;
    }

}

/* Code to actually dissect the packets */
static void
dissect_amr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMR");

    dissect_amr_common(tvb, pinfo, tree, pref_amr_mode);
}

static void
dissect_amr_wb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMR-WB");
    dissect_amr_common(tvb, pinfo, tree, AMR_WB);
}


typedef struct _amr_capability_t {
    const gchar     *id;
    const gchar     *name;
    new_dissector_t  content_pdu;
} amr_capability_t;

static amr_capability_t amr_capability_tab[] = {
    /* ITU-T H.241 (05/2006), 8.3 H.264 capabilities */
    { "GenericCapability/0.0.8.245.1.1.1",              "H.245 - GSM AMR Capability Identifier", NULL },
    { "GenericCapability/0.0.8.245.1.1.1/collapsing/0", "maxAl-sduAudioFrames",                  NULL },
    { "GenericCapability/0.0.8.245.1.1.1/collapsing/1", "bitRate",                               NULL },
    { "GenericCapability/0.0.8.245.1.1.1/collapsing/2", "gsmAmrComfortNoise",                    NULL },
    { "GenericCapability/0.0.8.245.1.1.1/collapsing/3", "gsmEfrComfortNoise",                    NULL },
    { "GenericCapability/0.0.8.245.1.1.1/collapsing/4", "is-641ComfortNoise",                    NULL },
    { "GenericCapability/0.0.8.245.1.1.1/collapsing/5", "pdcEFRComfortNoise",                    NULL },
    /* ITU-T Rec. G.722.2/Annex F (11/2002) */
    { "GenericCapability/0.0.7.7222.1.0/collapsing/0",  "maxAl-sduFrames",                       NULL },
    { "GenericCapability/0.0.7.7222.1.0/collapsing/1",  "bitRate",                               NULL },
    { "GenericCapability/0.0.7.7222.1.0/collapsing/2",  "octetAlign",                            NULL },
    { "GenericCapability/0.0.7.7222.1.0/collapsing/3",  "modeSet",                               NULL },
    { "GenericCapability/0.0.7.7222.1.0/collapsing/4",  "modeChangePeriod",                      NULL },
    { "GenericCapability/0.0.7.7222.1.0/collapsing/5",  "modeChangeNeighbour",                   NULL },
    { "GenericCapability/0.0.7.7222.1.0/collapsing/6",  "crc",                                   NULL },
    { "GenericCapability/0.0.7.7222.1.0/collapsing/7",  "robustSorting",                         NULL },
    { "GenericCapability/0.0.7.7222.1.0/collapsing/8",  "interleaving",                          NULL },
    { NULL, NULL, NULL },
};

static amr_capability_t *find_cap(const gchar *id) {
    amr_capability_t *ftr = NULL;
    amr_capability_t *f;

    for (f=amr_capability_tab; f->id; f++) {
        if (!strcmp(id, f->id)) {
            ftr = f;
            break;
        }
    }
    return ftr;
}

static void
dissect_amr_name(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree)
{
    asn1_ctx_t       *actx;

    actx = get_asn1_ctx(pinfo->private_data);
    DISSECTOR_ASSERT(actx != NULL);
    if (tree && actx != NULL) {
        amr_capability_t *ftr;
        ftr = find_cap(pinfo->match_string);
        if (ftr) {
            proto_item_append_text(actx->created_item, " - %s", ftr->name);
            proto_item_append_text(proto_item_get_parent(proto_tree_get_parent(tree)), ": %s", ftr->name);
        } else {
            proto_item_append_text(actx->created_item, " - unknown(%s)", pinfo->match_string);
        }
    }
}

void proto_reg_handoff_amr(void);

void
proto_register_amr(void)
{
    module_t *amr_module;

    static hf_register_info hf[] = {
        { &hf_amr_nb_cmr,
            { "CMR",           "amr.nb.cmr",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_nb_codec_mode_request_vals_ext, 0x0,
            "codec mode request", HFILL }
        },
        { &hf_amr_wb_cmr,
            { "CMR",           "amr.wb.cmr",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_wb_codec_mode_request_vals_ext, 0x0,
            "codec mode request", HFILL }
        },
        { &hf_amr_reserved,
            { "Reserved",           "amr.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            "Reserved bits", HFILL }
        },
        { &hf_amr_toc_f,
            { "F bit",           "amr.toc.f",
            FT_BOOLEAN, BASE_NONE, TFS(&toc_f_bit_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_amr_nb_toc_ft,
            { "FT bits",           "amr.nb.toc.ft",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_nb_codec_mode_request_vals_ext, 0x0,
            "Frame type index", HFILL }
        },
        { &hf_amr_wb_toc_ft,
            { "FT bits",           "amr.wb.toc.ft",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_wb_codec_mode_request_vals_ext, 0x0,
            "Frame type index", HFILL }
        },
        { &hf_amr_toc_q,
            { "Q bit",           "amr.toc.q",
            FT_BOOLEAN, BASE_NONE, TFS(&toc_q_bit_vals), 0x0,
            "Frame quality indicator bit", HFILL }
        },
        { &hf_amr_nb_if1_ft,
            { "Frame Type",           "amr.nb.if1.ft",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_nb_codec_mode_vals_ext, 0xf0,
            NULL, HFILL }
        },
        { &hf_amr_wb_if1_ft,
            { "Frame Type",           "amr.wb.if1.ft",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_wb_codec_mode_vals_ext, 0xf0,
            NULL, HFILL }
        },
        { &hf_amr_nb_if1_mode_req,
            { "Mode Type request",           "amr.nb.if1.modereq",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_nb_codec_mode_request_vals_ext, 0xe0,
            NULL, HFILL }
        },
        { &hf_amr_wb_if1_mode_req,
            { "Mode Type request",           "amr.wb.if1.modereq",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_wb_codec_mode_request_vals_ext, 0x0f,
            NULL, HFILL }
        },
        { &hf_amr_if1_sti,
            { "SID Type Indicator",           "amr.if1.sti",
            FT_BOOLEAN, 8, TFS(&amr_sti_vals), 0x10,
            NULL, HFILL }
        },
        { &hf_amr_nb_if1_sti_mode_ind,
            { "Mode Type indication",           "amr.nb.if1.stimodeind",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_nb_codec_mode_vals_ext, 0x0e,
            NULL, HFILL }
        },
        { &hf_amr_wb_if1_sti_mode_ind,
            { "Mode Type indication",           "amr.wb.if1.stimodeind",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_wb_codec_mode_vals_ext, 0x0f,
            NULL, HFILL }
        },
        { &hf_amr_nb_if1_mode_ind,
            { "Mode Type indication",           "amr.nb.if1.modeind",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_nb_codec_mode_vals_ext, 0x07,
            NULL, HFILL }
        },
        { &hf_amr_wb_if1_mode_ind,
            { "Mode Type indication",           "amr.wb.if1.modeind",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_wb_codec_mode_vals_ext, 0xf0,
            NULL, HFILL }
        },
        { &hf_amr_nb_if2_ft,
            { "Frame Type",           "amr.nb.if2.ft",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_nb_codec_mode_vals_ext, 0x0f,
            NULL, HFILL }
        },
        { &hf_amr_wb_if2_ft,
            { "Frame Type",           "amr.wb.if2.ft",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_wb_codec_mode_vals_ext, 0xf0,
            NULL, HFILL }
        },
        { &hf_amr_if2_sti,
            { "SID Type Indicator",           "amr.if2.sti",
            FT_BOOLEAN, 8, TFS(&amr_sti_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_amr_nb_if2_sti_mode_ind,
            { "Mode Type indication",           "amr.nb.if2.stimodeind",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_nb_codec_mode_vals_ext, 0x07,
            NULL, HFILL }
        },
        { &hf_amr_wb_if2_sti_mode_ind,
            { "Mode Type indication",           "amr.wb.if2.stimodeind",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &amr_wb_codec_mode_vals_ext, 0x78,
            NULL, HFILL }
        },
        { &hf_amr_if1_fqi,
            { "FQI",           "amr.fqi",
            FT_BOOLEAN, 8, TFS(&toc_q_bit_vals), 0x08,
            "Frame quality indicator bit", HFILL }
        },
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_amr,
        &ett_amr_toc,
    };
    static const enum_val_t encoding_types[] = {
        {"RFC 3267 Byte aligned", "RFC 3267 octet aligned", 0},
        {"RFC 3267 Bandwidth-efficient", "RFC 3267 BW-efficient", 1},
        {"AMR IF1", "AMR IF1", 2},
        {"AMR IF2", "AMR IF2", 3},
        {NULL, NULL, -1}
    };

    static const enum_val_t modes[] = {
        {"AMR-NB", "Narrowband AMR", AMR_NB},
        {"AMR-WB", "Wideband AMR", AMR_WB},
        {NULL, NULL, -1}
    };

/* Register the protocol name and description */
    proto_amr = proto_register_protocol("Adaptive Multi-Rate","AMR", "amr");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_amr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    /* Register a configuration option for port */

    amr_module = prefs_register_protocol(proto_amr, proto_reg_handoff_amr);

    prefs_register_uint_preference(amr_module, "dynamic.payload.type",
                       "AMR dynamic payload type",
                       "The dynamic payload type which will be interpreted as AMR"
                       "; The value must be greater than 95",
                       10,
                       &temp_dynamic_payload_type);

    prefs_register_enum_preference(amr_module, "encoding.version",
                       "Type of AMR encoding of the payload",
                       "Type of AMR encoding of the payload",
                       &amr_encoding_type, encoding_types, FALSE);

    prefs_register_enum_preference(amr_module, "mode",
                       "The AMR mode",
                       "The AMR mode",
                       &pref_amr_mode, modes, AMR_NB);

    register_dissector("amr", dissect_amr, proto_amr);
    register_dissector("amr-wb", dissect_amr_wb, proto_amr);
    register_dissector("amr_if1_nb", dissect_amr_nb_if1, proto_amr);
    register_dissector("amr_if1_wb", dissect_amr_wb_if1, proto_amr);
    register_dissector("amr_if2_nb", dissect_amr_nb_if2, proto_amr);
    register_dissector("amr_if2_wb", dissect_amr_wb_if2, proto_amr);

    oid_add_from_string("G.722.2 (AMR-WB) audio capability","0.0.7.7222.1.0");
}

/* Register the protocol with Wireshark */
void
proto_reg_handoff_amr(void)
{
    static dissector_handle_t amr_handle;
    static guint              dynamic_payload_type;
    static gboolean           amr_prefs_initialized = FALSE;

    if (!amr_prefs_initialized) {
        dissector_handle_t  amr_name_handle;
        dissector_handle_t  amr_wb_handle;
        amr_capability_t   *ftr;

        amr_handle    = find_dissector("amr");
        amr_wb_handle = find_dissector("amr-wb");
        dissector_add_string("rtp_dyn_payload_type","AMR", amr_handle);
        dissector_add_string("rtp_dyn_payload_type","AMR-WB", amr_wb_handle);

        /*
         * Register H.245 Generic parameter name(s)
         */
        amr_name_handle = create_dissector_handle(dissect_amr_name, proto_amr);
        for (ftr=amr_capability_tab; ftr->id; ftr++) {
            if (ftr->name)
                dissector_add_string("h245.gef.name", ftr->id, amr_name_handle);
            if (ftr->content_pdu)
                dissector_add_string("h245.gef.content", ftr->id,
                             new_create_dissector_handle(ftr->content_pdu, proto_amr));
        }
        /*  Activate the next line for testing with the randpkt tool
            dissector_add_uint("udp.port", 55555, amr_handle);
        */
        amr_prefs_initialized = TRUE;
    } else {
        if ( dynamic_payload_type > 95 )
            dissector_delete_uint("rtp.pt", dynamic_payload_type, amr_handle);
    }

    dynamic_payload_type = temp_dynamic_payload_type;

    if ( dynamic_payload_type > 95 ) {
        dissector_add_uint("rtp.pt", dynamic_payload_type, amr_handle);
    }
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
