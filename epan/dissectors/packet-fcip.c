/* packet-fcip.c
 * Routines for FCIP dissection
 * RFC 3821, RFC 3643
 * Copyright 2001, Dinesh G Dutt (ddutt@cisco.com)
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
#include <epan/prefs.h>
#include <epan/to_str.h>
#include "packet-fc.h"

void proto_register_fcip(void);
void proto_reg_handoff_fcip(void);

#define FCIP_ENCAP_HEADER_LEN                    28
#define FCIP_MIN_HEADER_LEN                      16 /* upto frame len field */
#define FCIP_IS_SF(pflags)                       ((pflags & 0x1) == 0x1)
#define FCIP_IS_CH(pflags)                       ((pflags & 0x80) == 0x80)

typedef enum {
    FCIP_EOFn    = 0x41,
    FCIP_EOFt    = 0x42,
    FCIP_EOFrt   = 0x44,
    FCIP_EOFdt   = 0x46,
    FCIP_EOFni   = 0x49,
    FCIP_EOFdti  = 0x4E,
    FCIP_EOFrti  = 0x4F,
    FCIP_EOFa    = 0x50
} fcip_eof_t;

typedef enum {
    FCIP_SOFf    = 0x28,
    FCIP_SOFi4   = 0x29,
    FCIP_SOFi2   = 0x2D,
    FCIP_SOFi3   = 0x2E,
    FCIP_SOFn4   = 0x31,
    FCIP_SOFn2   = 0x35,
    FCIP_SOFn3   = 0x36,
    FCIP_SOFc4   = 0x39
} fcip_sof_t;

typedef enum {
    FCENCAP_PROTO_FCIP = 1,
    FCENCAP_PROTO_iFCP = 2
} fcencap_proto_t;

static const value_string fcip_eof_vals[] = {
    {FCIP_EOFn,   "EOFn"   },
    {FCIP_EOFt,   "EOFt"   },
    {FCIP_EOFrt,  "EOFrt"  },
    {FCIP_EOFdt,  "EOFdt"  },
    {FCIP_EOFni,  "EOFni"  },
    {FCIP_EOFdti, "EOFdti" },
    {FCIP_EOFrti, "EOFrti" },
    {FCIP_EOFa,   "EOFa"   },
    {0, NULL},
};

static const value_string fcip_sof_vals[] = {
    {FCIP_SOFf, "SOFf" },
    {FCIP_SOFi4, "SOFi4" },
    {FCIP_SOFi2, "SOFi2" },
    {FCIP_SOFi3, "SOFi3" },
    {FCIP_SOFn4, "SOFn4" },
    {FCIP_SOFn2, "SOFn2" },
    {FCIP_SOFn3, "SOFn3" },
    {FCIP_SOFc4, "SOFc4" },
    {0, NULL},
};

static const value_string fcencap_proto_vals[] = {
    {FCENCAP_PROTO_FCIP, "FCIP" },
    {FCENCAP_PROTO_iFCP, "iFCP" },
    {0, NULL},
};

static const guint8 fcip_header_8_bytes[8] = {
    0x01, 0x01, 0xFE, 0xFE,
    0x01, 0x01, 0xFE, 0xFE
};

static int proto_fcip          = -1;

static int hf_fcip_protocol       = -1;
static int hf_fcip_protocol_c     = -1;
static int hf_fcip_version        = -1;
static int hf_fcip_version_c      = -1;
static int hf_fcip_encap_word1    = -1;
static int hf_fcip_flags          = -1;
static int hf_fcip_flags_c        = -1;
static int hf_fcip_framelen       = -1;
static int hf_fcip_framelen_c     = -1;
static int hf_fcip_tsec           = -1;
static int hf_fcip_tusec          = -1;
static int hf_fcip_encap_crc      = -1;
static int hf_fcip_sof            = -1;
static int hf_fcip_sof_c          = -1;
static int hf_fcip_eof            = -1;
static int hf_fcip_eof_c          = -1;
static int hf_fcip_pflags_changed = -1;
static int hf_fcip_pflags_special = -1;
static int hf_fcip_pflags_c       = -1;
static int hf_fcip_src_wwn        = -1;
static int hf_fcip_dst_wwn        = -1;
static int hf_fcip_conn_code      = -1;
static int hf_fcip_katov          = -1;
static int hf_fcip_src_entity_id  = -1;
static int hf_fcip_conn_nonce     = -1;
static int hf_fcip_conn_flags     = -1;

static int ett_fcip            = -1;

static guint fcip_port         = 3225;
static gboolean fcip_desegment = TRUE;

static dissector_handle_t fc_handle;

/* This routine attempts to locate the position of the next header in the
 * provided segment
 */
static guint
get_next_fcip_header_offset (tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
    gint       bytes_remaining = tvb_reported_length_remaining (tvb, offset);
    gint       frame_len;
    guint16    flen, flen1;
    fcip_eof_t eof, eofc;

    /*
     * As per the FCIP standard, the following tests must PASS:
     * 1)  Frame Length field validation -- 15 < Frame Length < 545;
     * 2)  Comparison of Frame Length field to its ones complement; and
     * 3)  A valid EOF is found in the word preceding the start of the next
     *     FCIP header as indicated by the Frame Length field, to be tested
     *     as follows:
     *     1)  Bits 24-31 and 16-23 contain identical legal EOF values (the
     *         list of legal EOF values is in the FC Frame Encapsulation
     *         [21]); and
     *     2)  Bits 8-15 and 0-7 contain the ones complement of the EOF
     *         value found in bits 24-31.
     *
     * As per the FCIP standard, in addition, at least 3 of the following set
     * of tests must be performed to identify that we've located the start of
     * an FCIP frame.
     * a)  Protocol# ones complement field (1 test);
     * b)  Version ones complement field (1 test);
     * c)  Replication of encapsulation word 0 in word 1 (1 test);
     * d)  Reserved field and its ones complement (2 tests);
     * e)  Flags field and its ones complement (2 tests);
     *    f)  CRC field is equal to zero (1 test); (DON'T DO THIS TEST!)
     * g)  SOF fields and ones complement fields (4 tests);
     * h)  Format and values of FC header (1 test);
     * i)  CRC of FC Frame (2 tests);
     * j)  FC Frame Encapsulation header information in the next FCIP Frame
     *     (1 test).
     *
     * At least 3 of the 16 tests listed above SHALL be performed. Failure
     * of any of the above tests actually performed SHALL indicate an
     * encapsulation error and the FC Frame SHALL NOT be forwarded on to
     * the FC Entity.
     */

NXT_BYTE: while (bytes_remaining) {
        if (bytes_remaining < FCIP_ENCAP_HEADER_LEN) {
            if(fcip_desegment && pinfo->can_desegment) {
                /*
                 * This frame doesn't have all of the data for
                 * the message header, but we can do reassembly on it.
                 *
                 * Tell the TCP dissector where the data for this
                 * message starts in the data it handed us, and that we need
                 * "some more data."  Don't tell it exactly how many bytes
                 * we need because if/when we ask for even more (after the
                 * header) that will break reassembly.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return -2;
            }
        }

        /* I check that we have a valid header before checking for the frame
         * length and the other initial tests.
         */

        /*
         * Tests a, b and c
         */
        if (tvb_memeql(tvb, offset, fcip_header_8_bytes, 8) != 0) {
            offset++;
            bytes_remaining--;
            goto NXT_BYTE;
        }

        flen = (tvb_get_ntohs (tvb, offset+12)) & 0x03FF;
        frame_len = (tvb_get_ntohs (tvb, offset+12) & 0x03FF)*4;

        if ((flen < 15) || (flen > 545)) {
            /* Frame length check failed. Skip byte and try again */
            offset++;
            bytes_remaining--;
            goto NXT_BYTE;
        }

        flen1 = (tvb_get_ntohs (tvb, offset+14)) & 0x03FF;

        if ((flen & 0x03FF) != ((~flen1)&0x03FF)) {
            /* frame_len and its one's complement are not the same */
            offset++;
            bytes_remaining--;
            goto NXT_BYTE;
        }

        /* Valid EOF check */
        if (tvb_bytes_exist (tvb, offset+(frame_len-1)*4, 4)) {
            eof = (fcip_eof_t)tvb_get_guint8 (tvb, offset+(frame_len-1)*4);
            eofc = (fcip_eof_t)tvb_get_guint8 (tvb, offset+(frame_len-1)*4+2);

            if ((eof != FCIP_EOFn) && (eof != FCIP_EOFt) && (eof != FCIP_EOFrt)
                && (eof != FCIP_EOFdt) && (eof != FCIP_EOFni) &&
                (eof != FCIP_EOFdti) && (eof != FCIP_EOFrti) &&
                (eof != FCIP_EOFa)) {
                offset++;
                bytes_remaining--;
                goto NXT_BYTE;
            }

            if ((eof != ~eofc) ||
                (eof != tvb_get_guint8 (tvb, offset+(frame_len-1)*4+1)) ||
                (eofc != tvb_get_guint8 (tvb, offset+(frame_len-1)*4+3))) {
                offset++;
                bytes_remaining--;
                goto NXT_BYTE;
            }
        }

        /* Test d */
        if ((tvb_get_guint8 (tvb, offset+9) != 0) ||
            (tvb_get_guint8 (tvb, offset+11) != 0xFF)) {
            /* Failed */
            offset++;
            bytes_remaining--;
            goto NXT_BYTE;
        }

        /* Test e */


        /* Test f
         * We don't test this since some implementations actually provide
         * a CRC here.
         */

        if (bytes_remaining >= (frame_len)) {
            if (tvb_bytes_exist (tvb, offset+frame_len, 8)) {
                /* The start of the next header matches what we wish to see */
                if (tvb_memeql (tvb, offset+frame_len, fcip_header_8_bytes,
                                8) == 0) {
                    return (offset);
                }
                else {
                    offset++;
                    bytes_remaining--;
                    goto NXT_BYTE;
                }
            }
            else {
                return (offset);
            }
        }
        else {
            if(fcip_desegment && pinfo->can_desegment) {
                /*
                 * This frame doesn't have all of the data for
                 * this message, but we can do reassembly on it.
                 *
                 * Tell the TCP dissector where the data for this
                 * message starts in the data it handed us, and
                 * how many more bytes we need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = frame_len - bytes_remaining;
                return -2;
            }
            else {
                return (offset);
            }
        }
    }

    return (-1);                /* Unable to find FCIP header */
}

static void
dissect_fcencap_header (tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    guint8 protocol = tvb_get_guint8 (tvb, offset);

    if (tree) {
        proto_tree_add_uint (tree, hf_fcip_protocol, tvb, offset, 1, protocol);
        proto_tree_add_item (tree, hf_fcip_version, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcip_protocol_c, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcip_version_c, tvb, offset+3, 1, ENC_BIG_ENDIAN);

        if (protocol == FCENCAP_PROTO_FCIP) {
            proto_tree_add_item (tree, hf_fcip_encap_word1, tvb, offset+4,
                                 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_fcip_pflags_changed, tvb, offset+8,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_fcip_pflags_special, tvb, offset+8,
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_fcip_pflags_c, tvb, offset+10, 1, ENC_BIG_ENDIAN);
        }

        /* XXX - break out CRCV flag. */
        proto_tree_add_item (tree, hf_fcip_flags, tvb, offset+12, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcip_framelen, tvb, offset+12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcip_flags_c, tvb, offset+14, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcip_framelen_c, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcip_tsec, tvb, offset+16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcip_tusec, tvb, offset+20, 4, ENC_BIG_ENDIAN);
        /* XXX - check CRC if CRCV is set? */
        proto_tree_add_item (tree, hf_fcip_encap_crc, tvb, offset+24, 4, ENC_BIG_ENDIAN);
    }
}

static void
dissect_fcip_sf (tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    if (tree) {
        proto_tree_add_item (tree, hf_fcip_src_wwn, tvb, offset, 8, ENC_NA);
        proto_tree_add_item (tree, hf_fcip_src_entity_id, tvb, offset+8, 8,
                              ENC_NA);
        proto_tree_add_item (tree, hf_fcip_conn_nonce, tvb, offset+16, 8,
                              ENC_NA);
        /* XXX - break out these flags */
        proto_tree_add_item (tree, hf_fcip_conn_flags, tvb, offset+24, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcip_conn_code, tvb, offset+26, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_fcip_dst_wwn, tvb, offset+30, 8, ENC_NA);
        proto_tree_add_item (tree, hf_fcip_katov, tvb, offset+38, 4, ENC_BIG_ENDIAN);
    }
}

static gboolean
dissect_fcip (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              gboolean check_port)
{
    gint offset = 0,
         start  = 0,
         frame_len = 0;
    gint bytes_remaining = tvb_captured_length (tvb);
    guint8 pflags, sof = 0, eof = 0;
   /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *fcip_tree = NULL;
    tvbuff_t *next_tvb;
    fc_data_t fc_data;

    if (bytes_remaining < FCIP_ENCAP_HEADER_LEN) {
        return FALSE;
    }

    if (check_port &&
        ((pinfo->srcport != fcip_port) && (pinfo->destport != fcip_port))) {
        return FALSE;
    }

    while (bytes_remaining > FCIP_ENCAP_HEADER_LEN) {
        if ((offset = get_next_fcip_header_offset (tvb, pinfo, offset)) == -1) {
            return FALSE;
        }
        else if (offset == -2) {
            /* We need more data to desegment */
            return (TRUE);
        }

        start = offset;
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "FCIP");

        frame_len = (tvb_get_ntohs (tvb, offset+12) & 0x03FF)*4;

        if (bytes_remaining < frame_len) {
            if(fcip_desegment && pinfo->can_desegment) {
                /*
                 * This frame doesn't have all of the data for
                 * this message, but we can do reassembly on it.
                 *
                 * Tell the TCP dissector where the data for this
                 * message starts in the data it handed us, and
                 * how many more bytes we need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = frame_len - bytes_remaining;
                return (TRUE);
            }
        }

        pflags = tvb_get_guint8 (tvb, start+8);

        if (tree) {
            if (FCIP_IS_SF (pflags)) {
                ti = proto_tree_add_protocol_format (tree, proto_fcip, tvb, 0,
                                                     FCIP_ENCAP_HEADER_LEN,
                                                     "FCIP");
            }
            else if (tvb_bytes_exist (tvb, offset, offset+frame_len-4)) {
                sof = tvb_get_guint8 (tvb, offset+FCIP_ENCAP_HEADER_LEN);
                eof = tvb_get_guint8 (tvb, offset+frame_len - 4);

                ti = proto_tree_add_protocol_format (tree, proto_fcip, tvb, 0,
                                                     FCIP_ENCAP_HEADER_LEN,
                                                     "FCIP (%s/%s)",
                                                     val_to_str (sof, fcip_sof_vals,
                                                                 "0x%x"),
                                                     val_to_str (eof, fcip_eof_vals,
                                                                 "0x%x"));
            }
            else {
                sof = tvb_get_guint8 (tvb, offset+FCIP_ENCAP_HEADER_LEN);

                ti = proto_tree_add_protocol_format (tree, proto_fcip, tvb, 0,
                                                     FCIP_ENCAP_HEADER_LEN,
                                                     "FCIP (%s/%s)",
                                                     val_to_str (sof, fcip_sof_vals,
                                                                 "0x%x"),
                                                     "NA");
            }
            fcip_tree = proto_item_add_subtree (ti, ett_fcip);
            /* Dissect the Common FC Encap header */
            dissect_fcencap_header (tvb, fcip_tree, offset);

            offset += FCIP_ENCAP_HEADER_LEN;

            if (!FCIP_IS_SF (pflags)) {
                /* print SOF */
                proto_tree_add_item (fcip_tree, hf_fcip_sof, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (fcip_tree, hf_fcip_sof_c, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                /* print EOF */

                offset += (frame_len-FCIP_ENCAP_HEADER_LEN-4);
                if (tvb_bytes_exist (tvb, offset, 4)) {
                    proto_tree_add_item (fcip_tree, hf_fcip_eof, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item (fcip_tree, hf_fcip_eof_c, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                }
            }
        }

        /* Call the FC Dissector if this is carrying an FC frame */
        if (!FCIP_IS_SF(pflags)) {
            /* Set the SOF/EOF flags in the packet_info header */
            fc_data.sof_eof = 0;

            if (sof) {
                if ((sof == FCIP_SOFi3) || (sof == FCIP_SOFi2) || (sof == FCIP_SOFi4)) {
                    fc_data.sof_eof = FC_DATA_SOF_FIRST_FRAME;
                }
                else if (sof == FCIP_SOFf) {
                    fc_data.sof_eof = FC_DATA_SOF_SOFF;
                }

                if (eof != FCIP_EOFn) {
                    fc_data.sof_eof |= FC_DATA_EOF_LAST_FRAME;
                }
                else if (eof != FCIP_EOFt) {
                    fc_data.sof_eof |= FC_DATA_EOF_INVALID;
                }
            }

            /* Special frame bit is not set */
            next_tvb = tvb_new_subset_remaining (tvb, FCIP_ENCAP_HEADER_LEN+4);
            if (fc_handle) {
                fc_data.ethertype = 0;
                call_dissector_with_data(fc_handle, next_tvb, pinfo, tree, &fc_data);
            }
            else {
                call_data_dissector(next_tvb, pinfo, tree);
            }
        }
        else {
            col_set_str(pinfo->cinfo, COL_INFO, "Special Frame");
            if (FCIP_IS_CH (pflags)) {
                col_append_str(pinfo->cinfo, COL_INFO, "(Changed)");
            }

            dissect_fcip_sf (tvb, fcip_tree, offset+4);
        }

        bytes_remaining -= frame_len;
    }

    return (TRUE);
}

/* This is called for those sessions where we have explicitly said
   this to be FCIP using "Decode As..."
   In this case we will not check the port number for sanity and just
   do as the user said.
*/
static int
dissect_fcip_handle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_fcip (tvb, pinfo, tree, FALSE);
    return tvb_captured_length(tvb);
}

static gboolean
dissect_fcip_heur (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return (dissect_fcip (tvb, pinfo, tree, TRUE));
}

void
proto_register_fcip (void)
{

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_fcip_protocol,
          { "Protocol", "fcip.proto", FT_UINT8, BASE_DEC,
            VALS(fcencap_proto_vals), 0, NULL, HFILL }},
        { &hf_fcip_protocol_c,
          {"Protocol (1's Complement)", "fcip.protoc", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_fcip_version,
          {"Version", "fcip.version", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_fcip_version_c,
          {"Version (1's Complement)", "fcip.versionc", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_fcip_encap_word1,
          {"FCIP Encapsulation Word1", "fcip.encap_word1", FT_UINT32, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_fcip_flags,
          {"Flags", "fcip.flags", FT_UINT8, BASE_HEX,
           NULL, 0xFC, NULL, HFILL}},
        { &hf_fcip_flags_c,
          {"Flags (1's Complement)", "fcip.flagsc", FT_UINT8, BASE_HEX,
           NULL, 0xFC, NULL, HFILL}},
        { &hf_fcip_framelen,
          {"Frame Length (in Words)", "fcip.framelen", FT_UINT16, BASE_DEC,
           NULL, 0x03FF, NULL, HFILL}},
        { &hf_fcip_framelen_c,
          {"Frame Length (1's Complement)", "fcip.framelenc", FT_UINT16, BASE_DEC,
           NULL, 0x03FF, NULL, HFILL}},
        { &hf_fcip_tsec,
          {"Time (secs)", "fcip.tsec", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_fcip_tusec,
          {"Time (fraction)", "fcip.tusec", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_fcip_encap_crc,
          {"CRC", "fcip.encap_crc", FT_UINT32, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_fcip_sof,
          {"SOF", "fcip.sof", FT_UINT8, BASE_HEX,
           VALS (fcip_sof_vals), 0, NULL, HFILL}},
        { &hf_fcip_sof_c,
          {"SOF (1's Complement)", "fcip.sofc", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_fcip_eof,
          {"EOF", "fcip.eof", FT_UINT8, BASE_HEX,
           VALS (fcip_eof_vals), 0, NULL, HFILL}},
        { &hf_fcip_eof_c,
          {"EOF (1's Complement)", "fcip.eofc", FT_UINT8, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_fcip_pflags_changed,
          {"Changed Flag", "fcip.pflags.ch", FT_BOOLEAN, 8,
           NULL, 0x80, NULL, HFILL}},
        { &hf_fcip_pflags_special,
          {"Special Frame Flag", "fcip.pflags.sf", FT_BOOLEAN, 8,
           NULL, 0x1, NULL, HFILL}},
        { &hf_fcip_pflags_c,
          {"Pflags (1's Complement)", "fcip.pflagsc", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcip_src_wwn,
          {"Source Fabric WWN", "fcip.srcwwn", FT_FCWWN, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcip_dst_wwn,
          {"Destination Fabric WWN", "fcip.dstwwn", FT_FCWWN, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcip_src_entity_id,
          {"FC/FCIP Entity Id", "fcip.srcid", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcip_conn_flags,
          {"Connection Usage Flags", "fcip.connflags", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcip_conn_code,
          {"Connection Usage Code", "fcip.conncode", FT_UINT16, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcip_katov,
          {"K_A_TOV", "fcip.katov", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_fcip_conn_nonce,
          {"Connection Nonce", "fcip.nonce", FT_BYTES, BASE_NONE,
           NULL, 0x0, NULL, HFILL}},
    };

    static gint *ett[] = {
        &ett_fcip,
    };

    module_t *fcip_module;

    /* Register the protocol name and description */
    proto_fcip = proto_register_protocol("FCIP", "Fibre Channel over IP", "fcip");

    proto_register_field_array(proto_fcip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    fcip_module = prefs_register_protocol(proto_fcip, NULL);
    prefs_register_bool_preference(fcip_module,
                                   "desegment",
                                   "Reassemble FCIP messages spanning multiple TCP segments",
                                   "Whether the FCIP dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable"
                                   " \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &fcip_desegment);
    prefs_register_uint_preference(fcip_module,
                                   "target_port",
                                   "Target port",
                                   "Port number used for FCIP",
                                   10,
                                   &fcip_port);
}

void
proto_reg_handoff_fcip (void)
{
    dissector_handle_t fcip_handle;

    heur_dissector_add("tcp", dissect_fcip_heur, "FCIP over TCP", "fcip_tcp", proto_fcip, HEURISTIC_ENABLE);

    fcip_handle = create_dissector_handle(dissect_fcip_handle, proto_fcip);
    dissector_add_for_decode_as("tcp.port", fcip_handle);

    fc_handle   = find_dissector_add_dependency("fc", proto_fcip);
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
