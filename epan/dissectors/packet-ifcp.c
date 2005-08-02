/* packet-ifcp.c
 * Routines for iFCP dissection
 * RFC 3821, RFC 3643
 *
 * Copyright 2005   Aboo Valappil     (valappil_aboo@emc.com)
 *
 *
 * Significantly based on packet-fcip.c by
 *       Copyright 2001, Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#define iFCP_ENCAP_HEADER_LEN                    28
#define iFCP_MIN_HEADER_LEN                      16 /* upto frame len field */ 

typedef enum {
    iFCP_EOFn    = 0x41,
    iFCP_EOFt    = 0x42,
    iFCP_EOFrt   = 0x44,
    iFCP_EOFdt   = 0x46,
    iFCP_EOFni   = 0x49,
    iFCP_EOFdti  = 0x4E,
    iFCP_EOFrti  = 0x4F,
    iFCP_EOFa    = 0x50
} ifcp_eof_t;

typedef enum {
    iFCP_SOFf    = 0x28,
    iFCP_SOFi4   = 0x29,
    iFCP_SOFi2   = 0x2D,
    iFCP_SOFi3   = 0x2E,
    iFCP_SOFn4   = 0x31,
    iFCP_SOFn2   = 0x35,
    iFCP_SOFn3   = 0x36,
    iFCP_SOFc4   = 0x39
} ifcp_sof_t;

typedef enum {
    FCENCAP_PROTO_FCIP = 1,
    FCENCAP_PROTO_iFCP = 2
} fcencap_proto_t;

static const value_string ifcp_eof_vals[] = {
    {iFCP_EOFn, "EOFn" },
    {iFCP_EOFt, "EOFt" },
    {iFCP_EOFrt, "EOFrt" },
    {iFCP_EOFdt, "EOFdt" },
    {iFCP_EOFni, "EOFni" },
    {iFCP_EOFdti, "EOFdti" },
    {iFCP_EOFrti, "EOFrti" },
    {iFCP_EOFa, "EOFa" },
    {0, NULL},
};

static const value_string ifcp_sof_vals[] = {
    {iFCP_SOFf, "SOFf" },
    {iFCP_SOFi4, "SOFi4" },
    {iFCP_SOFi2, "SOFi2" },
    {iFCP_SOFi3, "SOFi3" },
    {iFCP_SOFn4, "SOFn4" },
    {iFCP_SOFn2, "SOFn2" },
    {iFCP_SOFn3, "SOFn3" },
    {iFCP_SOFc4, "SOFc4" },
    {0, NULL},
};

static const value_string fcencap_proto_vals[] = {
    {FCENCAP_PROTO_iFCP, "iFCP"},
    {FCENCAP_PROTO_iFCP, "iFCP"},
    {0, NULL},
};

static const guint8 ifcp_header_8_bytes[8] = {
    0x02, 0x01, 0xFD, 0xFE,
    0x00, 0x00, 0x00, 0x00
};

static int proto_ifcp          = -1;

static int hf_ifcp_protocol    = -1;
static int hf_ifcp_protocol_c  = -1;
static int hf_ifcp_version     = -1;
static int hf_ifcp_version_c   = -1;
static int hf_ifcp_encap_flags = -1;
static int hf_ifcp_encap_flags_c=-1;
static int hf_ifcp_framelen    = -1;
static int hf_ifcp_framelen_c  = -1;
static int hf_ifcp_tsec        = -1;
static int hf_ifcp_tusec       = -1;
static int hf_ifcp_encap_crc   = -1;
static int hf_ifcp_sof         = -1;
static int hf_ifcp_sof_c       = -1;
static int hf_ifcp_eof         = -1;
static int hf_ifcp_eof_c       = -1;
static int hf_ifcp_ls_command_acc = -1;
static int hf_ifcp_flags_ses = -1;
static int hf_ifcp_flags_trp = -1;
static int hf_ifcp_flags_spc = -1;

static int ett_ifcp            = -1;

static guint ifcp_port         = 3420;
static gboolean ifcp_desegment    = TRUE;

static dissector_handle_t data_handle;
static dissector_handle_t fc_handle;

/* This routine attempts to locate the position of the next header in the
 * provided segment
 */
static guint
get_next_ifcp_header_offset (tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
    gint bytes_remaining = tvb_length_remaining (tvb, offset);
    gint frame_len;
    guint16 flen, flen1;

    /*
     * As per the iFCP standard, the following tests must PASS:
     * 1)  Frame Length field validation -- 15 < Frame Length < 545;
     * 2)  Comparison of Frame Length field to its ones complement; and
     * 3)  A valid EOF is found in the word preceding the start of the next
     *     iFCP header as indicated by the Frame Length field, to be tested
     *     as follows:
     *     1)  Bits 24-31 and 16-23 contain identical legal EOF values (the
     *         list of legal EOF values is in the FC Frame Encapsulation
     *         [21]); and
     *     2)  Bits 8-15 and 0-7 contain the ones complement of the EOF
     *         value found in bits 24-31.
     *
     * As per the iFCP standard, in addition, at least 3 of the following set
     * of tests must be performed to identify that we've located the start of
     * an iFCP frame. 
     * a)  Protocol# ones complement field (1 test);
     * b)  Version ones complement field (1 test);
     * c)  Replication of encapsulation word 0 in word 1 (1 test);
     * d)  Reserved field and its ones complement (2 tests);
     * e)  Flags field and its ones complement (2 tests);
     *    f)  CRC field is equal to zero (1 test); (DONT DO THIS TEST!)
     * g)  SOF fields and ones complement fields (4 tests);
     * h)  Format and values of FC header (1 test);
     * i)  CRC of FC Frame (2 tests);
     * j)  FC Frame Encapsulation header information in the next iFCP Frame
     *     (1 test).
     *
     * At least 3 of the 16 tests listed above SHALL be performed. Failure
     * of any of the above tests actually performed SHALL indicate an
     * encapsulation error and the FC Frame SHALL NOT be forwarded on to
     * the FC Entity.
     */

NXT_BYTE: while (bytes_remaining) {
        if (bytes_remaining < iFCP_ENCAP_HEADER_LEN) {
            if(ifcp_desegment && pinfo->can_desegment) {
                /*
                 * This frame doesn't have all of the data for
                 * this message, but we can do reassembly on it.
                 *
                 * Tell the TCP dissector where the data for this
                 * message starts in the data it handed us, and
                 * how many more bytes we need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = iFCP_ENCAP_HEADER_LEN;
                return -2;
            }
        }

        /* I check that we have a valid header before checking for the frame
         * length and the other initial tests.
         */

        /*
         * Tests a, b and c
         */
        if (tvb_memeql(tvb, offset, ifcp_header_8_bytes, 8) != 0) {
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

        if (bytes_remaining >= (frame_len)) {
            if (tvb_bytes_exist (tvb, offset+frame_len, 8)) {
                /* The start of the next header matches what we wish to see */ 
                if (tvb_memeql (tvb, offset+frame_len, ifcp_header_8_bytes,
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
            if(ifcp_desegment && pinfo->can_desegment) {
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

    return (-1);                /* Unable to find iFCP header */
}

static void
dissect_fcencap_header (tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    guint8 protocol = tvb_get_guint8 (tvb, offset);
    
    if (tree) {
        proto_tree_add_uint (tree, hf_ifcp_protocol, tvb, offset, 1, protocol);
        proto_tree_add_item (tree, hf_ifcp_version, tvb, offset+1, 1, 0);
        proto_tree_add_item (tree, hf_ifcp_protocol_c, tvb, offset+2, 1, 0);
        proto_tree_add_item (tree, hf_ifcp_version_c, tvb, offset+3, 1, 0);

        if (protocol == FCENCAP_PROTO_iFCP) {
            proto_tree_add_item (tree, hf_ifcp_ls_command_acc, tvb, offset+8, 1, 0);
            proto_tree_add_item (tree, hf_ifcp_flags_ses, tvb, offset+9, 1, 0);
            proto_tree_add_item (tree, hf_ifcp_flags_trp, tvb, offset+9, 1, 0);
            proto_tree_add_item (tree, hf_ifcp_flags_spc, tvb, offset+9, 1, 0);
            proto_tree_add_item (tree, hf_ifcp_sof, tvb, offset+10, 1, 0);
            proto_tree_add_item (tree, hf_ifcp_eof, tvb, offset+11, 1, 0);
        }

        /* XXX - break out CRCV flag. */
        proto_tree_add_item (tree, hf_ifcp_encap_flags, tvb, offset+12, 1, 0);
        proto_tree_add_item (tree, hf_ifcp_framelen, tvb, offset+12, 2, 0);
        proto_tree_add_item (tree, hf_ifcp_encap_flags_c, tvb, offset+14, 1, 0);
        proto_tree_add_item (tree, hf_ifcp_framelen_c, tvb, offset+14, 2, 0);
        proto_tree_add_item (tree, hf_ifcp_tsec, tvb, offset+16, 4, 0);
        proto_tree_add_item (tree, hf_ifcp_tusec, tvb, offset+20, 4, 0);
        /* XXX - check CRC if CRCV is set? */
        proto_tree_add_item (tree, hf_ifcp_encap_crc, tvb, offset+24, 4, 0);
    }
}

static gboolean
dissect_ifcp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              gboolean check_port)
{
    gint offset = 0,
         frame_len = 0;
    gint bytes_remaining = tvb_length_remaining (tvb, offset);
    guint8 sof = 0, eof = 0;
   /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *ifcp_tree = NULL;
    tvbuff_t *next_tvb;
    
    if (bytes_remaining < iFCP_ENCAP_HEADER_LEN) {
        return FALSE;
    }

    if (check_port &&
        ((pinfo->srcport != ifcp_port) && (pinfo->destport != ifcp_port))) {
        return FALSE;
    }

    while (bytes_remaining > iFCP_ENCAP_HEADER_LEN) {
        if ((offset = get_next_ifcp_header_offset (tvb, pinfo, offset)) == -1) { 
            return FALSE;
        }
        else if (offset == -2) {
            /* We need more data to desegment */
            return (TRUE);
        }

        if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "iFCP");

        frame_len = (tvb_get_ntohs (tvb, offset+12) & 0x03FF)*4;

        if (bytes_remaining < frame_len) {
            if(ifcp_desegment && pinfo->can_desegment) {
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
        
        if (tree) {
            if (tvb_bytes_exist (tvb, offset, frame_len-4)) {
                sof = tvb_get_guint8 (tvb, offset+iFCP_ENCAP_HEADER_LEN);
                eof = tvb_get_guint8 (tvb, offset+frame_len - 4);

                ti = proto_tree_add_protocol_format (tree, proto_ifcp, tvb, offset,
                                                     iFCP_ENCAP_HEADER_LEN,
                                                     "iFCP (%s/%s)",
                                                     val_to_str (sof, ifcp_sof_vals,
                                                                 "0x%x"),
                                                     val_to_str (eof, ifcp_eof_vals,
                                                                 "0x%x"));
            }
            else {
                sof = tvb_get_guint8 (tvb, offset+iFCP_ENCAP_HEADER_LEN);
                
                ti = proto_tree_add_protocol_format (tree, proto_ifcp, tvb, offset,
                                                     iFCP_ENCAP_HEADER_LEN,
                                                     "iFCP (%s/%s)",
                                                     val_to_str (sof, ifcp_sof_vals,
                                                                 "0x%x"),
                                                     "NA");
            }
            ifcp_tree = proto_item_add_subtree (ti, ett_ifcp);
            /* Dissect the Common FC Encap header */
            dissect_fcencap_header (tvb, ifcp_tree, offset);


            /* print SOF */
            proto_tree_add_item (ifcp_tree, hf_ifcp_sof, tvb, offset+iFCP_ENCAP_HEADER_LEN, 1, 0);
            proto_tree_add_item (ifcp_tree, hf_ifcp_sof_c, tvb, offset+iFCP_ENCAP_HEADER_LEN+2, 1, 0);

           /* print EOF */
                
            if (tvb_bytes_exist (tvb, offset, 4)) {
                    proto_tree_add_item (ifcp_tree, hf_ifcp_eof, tvb, offset+frame_len-4, 1, 0);
                    proto_tree_add_item (ifcp_tree, hf_ifcp_eof_c, tvb, offset+frame_len-2, 1, 0);
            }
        }


        /* Call the FC Dissector if this is carrying an FC frame */
        /* Set the SOF/EOF flags in the packet_info header */
        pinfo->sof_eof = 0;

        if (sof) {
                if ((sof == iFCP_SOFi3) || (sof == iFCP_SOFi2) || (sof == iFCP_SOFi4)) {
                    pinfo->sof_eof = PINFO_SOF_FIRST_FRAME;
                }
                else if (sof == iFCP_SOFf) {
                    pinfo->sof_eof = PINFO_SOF_SOFF;
                }

                if (eof != iFCP_EOFn) {
                    pinfo->sof_eof |= PINFO_EOF_LAST_FRAME;
                }
                else if (eof != iFCP_EOFt) {
                    pinfo->sof_eof |= PINFO_EOF_INVALID;
                }
        }
            
        next_tvb = tvb_new_subset (tvb, offset+iFCP_ENCAP_HEADER_LEN+4, frame_len-iFCP_ENCAP_HEADER_LEN-8, frame_len-iFCP_ENCAP_HEADER_LEN-8);

        if (fc_handle) {
                call_dissector (fc_handle, next_tvb, pinfo, tree);
        }
        else if (data_handle) {
                call_dissector (data_handle, next_tvb, pinfo, tree);
        }

        offset += frame_len;
        bytes_remaining -= frame_len;
    }

    return (TRUE);
}

/* This is called for those sessions where we have explicitely said
   this to be iFCP using "Decode As..."
   In this case we will not check the port number for sanity and just
   do as the user said.
*/
static void
dissect_ifcp_handle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_ifcp (tvb, pinfo, tree, FALSE);
}

static gboolean
dissect_ifcp_heur (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    return (dissect_ifcp (tvb, pinfo, tree, TRUE));
}

void
proto_register_ifcp (void)
{

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_ifcp_protocol,
	  { "Protocol", "fcencap.proto", FT_UINT8, BASE_DEC,
	     VALS(fcencap_proto_vals), 0, "Protocol", HFILL }},
        { &hf_ifcp_protocol_c,
          {"Protocol (1's Complement)", "fcencap.protoc", FT_UINT8, BASE_DEC, NULL,
           0, "Protocol (1's Complement)", HFILL}},
        { &hf_ifcp_version,
          {"Version", "fcencap.version", FT_UINT8, BASE_DEC, NULL, 0, "",
           HFILL}},
        { &hf_ifcp_version_c,
          {"Version (1's Complement)", "fcencap.versionc", FT_UINT8, BASE_DEC,
           NULL, 0, "", HFILL}},
        { &hf_ifcp_encap_flags,
          {"iFCP Encapsulation Flags", "ifcp.encap_flags", FT_UINT8, BASE_HEX, NULL, 0xFC, "", HFILL}},
        { &hf_ifcp_encap_flags_c,
          {"iFCP Encapsulation Flags (1's Complement)", "ifcp.encap_flagsc", FT_UINT8, BASE_HEX,
           NULL, 0xFC, "", HFILL}},
        { &hf_ifcp_framelen,
          {"Frame Length (in Words)", "fcencap.framelen", FT_UINT16, BASE_DEC,
           NULL, 0x03FF, "", HFILL}},
        { &hf_ifcp_framelen_c,
          {"Frame Length (1's Complement)", "fcencap.framelenc", FT_UINT16,
           BASE_DEC, NULL, 0x03FF, "", HFILL}},
        { &hf_ifcp_tsec,
          {"Time (secs)", "fcencap.tsec", FT_UINT32, BASE_DEC, NULL, 0, "",
           HFILL}},
        { &hf_ifcp_tusec,
          {"Time (fraction)", "fcencap.tusec", FT_UINT32, BASE_DEC, NULL, 0,
           "", HFILL}},
        { &hf_ifcp_encap_crc,
          {"CRC", "fcencap.crc", FT_UINT32, BASE_HEX, NULL, 0, "", HFILL}},
        { &hf_ifcp_sof,
          {"SOF", "ifcp.sof", FT_UINT8, BASE_HEX, VALS (&ifcp_sof_vals), 0,
           "", HFILL}},
        { &hf_ifcp_eof,
          {"EOF", "ifcp.eof", FT_UINT8, BASE_HEX, VALS (&ifcp_eof_vals), 0,
           "", HFILL}},
        { &hf_ifcp_sof_c,
          {"SOF Compliment", "ifcp.sof_c", FT_UINT8, BASE_HEX, NULL , 0,
           "", HFILL}},
        { &hf_ifcp_eof_c,
          {"EOF Compliment", "ifcp.eof_c", FT_UINT8, BASE_HEX, NULL , 0,
           "", HFILL}},
        { &hf_ifcp_ls_command_acc,
          {"Ls Command Acc", "ifcp.ls_command_acc", FT_UINT8, BASE_HEX, NULL, 0,
           "", HFILL}},
        { &hf_ifcp_flags_ses, 
	  {"SES", "ifcp.flags.ses", FT_BOOLEAN, 8 , NULL, 0x04, "Is this a Session control frame", HFILL }},
        { &hf_ifcp_flags_trp, 
	  {"TRP", "ifcp.flags.trp", FT_BOOLEAN, 8 , NULL, 0x02, "Is address transparent mode enabled", HFILL }},
        { &hf_ifcp_flags_spc, 
	  {"SPC", "ifcp.flags.spc", FT_BOOLEAN, 8 , NULL, 0x01, "Is frame part of link service", HFILL }},
    };

    static gint *ett[] = {
        &ett_ifcp,
    };
    
    module_t *ifcp_module;

    /* Register the protocol name and description */
    proto_ifcp = proto_register_protocol("iFCP", "iFCP", "ifcp");

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_ifcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    ifcp_module = prefs_register_protocol(proto_ifcp, NULL);
    prefs_register_bool_preference(ifcp_module,
                                   "desegment",
                                   "Reassemble iFCP messages spanning multiple TCP segments",
                                   "Whether the iFCP dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &ifcp_desegment);
    prefs_register_uint_preference(ifcp_module,
                                   "target_port",
                                   "Target port",
                                   "Port number used for iFCP",
                                   10,
                                   &ifcp_port);
}


/*
 * If this dissector uses sub-dissector registration add a
 * registration routine.
 */

/*
 * This format is required because a script is used to find these
 * routines and create the code that calls these routines.
 */
void
proto_reg_handoff_ifcp (void)
{
    dissector_handle_t ifcp_handle;

    heur_dissector_add("tcp", dissect_ifcp_heur, proto_ifcp);

    ifcp_handle = create_dissector_handle(dissect_ifcp_handle, proto_ifcp);
    dissector_add_handle("tcp.port", ifcp_handle);

    data_handle = find_dissector("data");
    fc_handle = find_dissector("fc_ifcp");
}
