/* packet-brdwlk.c
 * Routines for decoding MDS Port Analyzer Adapter (FC in Eth) Header
 * Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/etypes.h>

#define BRDWLK_MAX_PACKET_CNT  0xFFFF
#define BRDWLK_TRUNCATED_BIT   0x8
#define BRDWLK_HAS_PLEN        0x1

#define FCM_DELIM_SOFC1         0x01
#define FCM_DELIM_SOFI1		0x02
#define FCM_DELIM_SOFI2		0x04
#define FCM_DELIM_SOFI3		0x06
#define FCM_DELIM_SOFN1		0x03
#define FCM_DELIM_SOFN2		0x05
#define FCM_DELIM_SOFN3		0x07
#define FCM_DELIM_SOFF		0x08
#define FCM_DELIM_SOFC4         0x09
#define FCM_DELIM_SOFI4         0x0A
#define FCM_DELIM_SOFN4         0x0B

#define FCM_DELIM_EOFT		0x01
#define FCM_DELIM_EOFDT		0x02
#define FCM_DELIM_EOFN		0x03
#define FCM_DELIM_EOFA		0x04
#define FCM_DELIM_EOFNI         0x07
#define FCM_DELIM_EOFDTI        0x06
#define FCM_DELIM_EOFRT         0x0A
#define FCM_DELIM_EOFRTI        0x0E
#define FCM_DELIM_NOEOF         0xF0
#define FCM_DELIM_EOFJUMBO      0xF1

static const value_string brdwlk_sof_vals[] = {
    {FCM_DELIM_SOFI1, "SOFi1"},
    {FCM_DELIM_SOFI2, "SOFi2"},
    {FCM_DELIM_SOFI3, "SOFi3"},
    {FCM_DELIM_SOFN1, "SOFn1"},
    {FCM_DELIM_SOFN2, "SOFn2"},
    {FCM_DELIM_SOFN3, "SOFn3"},
    {FCM_DELIM_SOFF,  "SOFf"},
    {0, NULL},
};

static const value_string brdwlk_eof_vals[] = {
    {FCM_DELIM_EOFDT, "EOFdt"},
    {FCM_DELIM_EOFA,  "EOFa"},
    {FCM_DELIM_EOFN,  "EOFn"},
    {FCM_DELIM_EOFT,  "EOFt"},
    {0, NULL},
};

static int hf_brdwlk_sof = -1;
static int hf_brdwlk_eof = -1;
static int hf_brdwlk_error = -1;
static int hf_brdwlk_vsan = -1;
static int hf_brdwlk_pktcnt = -1;
static int hf_brdwlk_drop = -1;
static int hf_brdwlk_plen = -1;

/* Initialize the subtree pointers */
static gint ett_brdwlk = -1;

static gint proto_brdwlk = -1;

static guint16 packet_count = 0;
static gboolean first_pkt = TRUE;                /* start of capture */

static dissector_handle_t data_handle;
static dissector_handle_t fc_dissector_handle;

static gchar *
brdwlk_err_to_str (guint8 error, char *str)
{
    if (str != NULL) {
        str[0] = '\0';

        if (error & 0x1) {
            strcat (str, "Packet Length Present");
        }
        
        if (error & 0x2) {
            strcat (str, "Empty Frame, ");
        }

        if (error & 0x4) {
            strcat (str, "No Data, ");
        }

        if (error & 0x8) {
            strcat (str, "Truncated, ");
        }

        if (error & 0x10) {
            strcat (str, "Bad FC CRC, ");
        }

        if (error & 0x20) {
            strcat (str, "Fifo Full, ");
        }

        if (error & 0x40) {
            strcat (str, "Jumbo FC Frame, ");
        }

        if (error & 0x80) {
            strcat (str, "Ctrl Char Inside Frame");
        }
    }

    return (str);
}

/* Code to actually dissect the packets */
static void
dissect_brdwlk (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *brdwlk_tree = NULL;
    tvbuff_t *next_tvb;
    guint8 error, eof, sof;
    int hdrlen = 2,
        offset = 0;
    gint len, reported_len, plen;
    guint16 pkt_cnt;
    gboolean dropped_packets;
    gchar errstr[512];

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Boardwalk");
    
    if (check_col(pinfo->cinfo, COL_INFO)) 
        col_clear(pinfo->cinfo, COL_INFO);

    pinfo->vsan = (tvb_get_ntohs (tvb, offset) & 0xFFF);
    sof = (tvb_get_guint8 (tvb, offset) & 0xF0) >> 4;

    if ((sof == FCM_DELIM_SOFI3) || (sof == FCM_DELIM_SOFI2) || (sof == FCM_DELIM_SOFI1)
        || (sof == FCM_DELIM_SOFI4)) {
        pinfo->sof_eof = PINFO_SOF_FIRST_FRAME;
    }
    else if (sof == FCM_DELIM_SOFF) {
        pinfo->sof_eof = PINFO_SOF_SOFF;
    }

    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_brdwlk, tvb, 0,
                                             hdrlen, "Boardwalk");

        brdwlk_tree = proto_item_add_subtree (ti, ett_brdwlk);

        proto_tree_add_item (brdwlk_tree, hf_brdwlk_sof, tvb, offset, 1, 0);
        proto_tree_add_item (brdwlk_tree, hf_brdwlk_vsan, tvb, offset, 2, 0);

    }

    /* Locate EOF which is the last 4 bytes of the frame */
    len = tvb_length_remaining(tvb, hdrlen);
    reported_len = tvb_reported_length_remaining(tvb, hdrlen);
    if (reported_len < 4) {
        /*
         * This packet is claimed not to even have enough data for
         * a 4-byte EOF.
         * Don't try to process the EOF.
         */
        ;
    }
    else if (len < reported_len) {
        /*
         * This packet is claimed to have enough data for a 4-byte EOF,
         * but we didn't capture all of the packet.
         * Slice off the 4-byte EOF from the reported length, and trim
         * the captured length so it's no more than the reported length;
         * that will slice off what of the EOF, if any, is in the
         * captured length.
         */
        reported_len -= 4;
        if (len > reported_len)
            len = reported_len;
    }
    else {
        /*
         * We have the entire packet, and it includes a 4-byte EOF.
         * Slice it off, and put it into the tree if we're building
         * a tree.
         */
        len -= 4;
        reported_len -= 4;
        offset = tvb_reported_length(tvb) - 4;
        pkt_cnt = tvb_get_ntohs (tvb, offset);
        if (tree) {
            proto_tree_add_uint (brdwlk_tree, hf_brdwlk_pktcnt, tvb, offset,
                                 2, pkt_cnt);
        }
        dropped_packets = FALSE;
        if (pinfo->fd->flags.visited) {
            /*
             * This isn't the first pass, so we can't use the global
             * "packet_count" variable to determine whether there were
             * any dropped frames or not.
             * We therefore attach a non-null pointer as frame data to
             * any frame preceded by dropped packets.
             */
            if (p_get_proto_data(pinfo->fd, proto_brdwlk) != NULL)
                dropped_packets = TRUE;
        } else {
            /*
             * This is the first pass, so we have to use the global
             * "packet_count" variable to determine whether there were
             * any dropped frames or not.
             *
             * XXX - can there be more than one stream of packets, so that
             * we can't just use a global variable?
             */
            if (pkt_cnt != packet_count + 1) {
                if (!first_pkt &&
                    (pkt_cnt != 0 || (packet_count != BRDWLK_MAX_PACKET_CNT))) {
                    dropped_packets = TRUE;

                    /*
                     * Mark this frame as having been preceded by dropped
                     * packets.  (The data we use as the frame data doesn't
                     * matter - it just matters that it's non-null.)
                     */
                    p_add_proto_data(pinfo->fd, proto_brdwlk, &packet_count);
                }
            }

            if (tree) {
                proto_tree_add_boolean_hidden (brdwlk_tree, hf_brdwlk_drop,
                                               tvb, offset, 0, dropped_packets);
            }
        }
        packet_count = pkt_cnt;
            
        error = tvb_get_guint8 (tvb, offset+2);
        if (tree) {
            proto_tree_add_uint_format (brdwlk_tree, hf_brdwlk_error, tvb,
                                        offset+2, 1, error, "Error: 0x%x (%s)",
                                        error,
                                        brdwlk_err_to_str (error, errstr));
        }

        eof = tvb_get_guint8 (tvb, offset+3);
        if (eof != FCM_DELIM_EOFN) {
            pinfo->sof_eof |= PINFO_EOF_LAST_FRAME;
        }
        else if (eof != FCM_DELIM_EOFT) {
            pinfo->sof_eof |= PINFO_EOF_INVALID;
        }
        
        if (tree) {
            proto_tree_add_item (brdwlk_tree, hf_brdwlk_eof, tvb, offset+3,
                                 1, 0);
        }

        if ((error & BRDWLK_HAS_PLEN) && tree) {
            /* In newer Boardwalks, if this bit is set, the actual frame length
             * is also provided. This length is the size between SOF & EOF
             * including FC CRC.
             */
            plen = tvb_get_ntohl (tvb, offset-4);
            plen *= 4;
            proto_tree_add_uint (brdwlk_tree, hf_brdwlk_plen, tvb, offset-4,
                                 4, plen);
            
#if 0
            /* XXX - this would throw an exception if it would increase
             * the reported length.
             */
            if (error & BRDWLK_TRUNCATED_BIT) {
                tvb_set_reported_length (tvb, plen);
            }
#endif
        }
    }
    
    next_tvb = tvb_new_subset (tvb, 2, len, reported_len);
    if (fc_dissector_handle) {
        call_dissector (fc_dissector_handle, next_tvb, pinfo, tree);
    }
}

static void
brdwlk_init(void)
{
    packet_count = 0;
    first_pkt = TRUE;
}

/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_brdwlk (void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_brdwlk_sof,
          {"SOF", "brdwlk.sof", FT_UINT8, BASE_HEX, VALS (brdwlk_sof_vals),
           0xF0, "SOF", HFILL}},
        { &hf_brdwlk_eof,
          {"EOF", "brdwlk.eof", FT_UINT8, BASE_HEX, VALS (brdwlk_eof_vals),
           0x0F, "EOF", HFILL}},
        { &hf_brdwlk_error,
          {"Error", "brdwlk.error", FT_UINT8, BASE_DEC, NULL, 0x0, "Error",
           HFILL}},
        { &hf_brdwlk_pktcnt,
          {"Packet Count", "brdwlk.pktcnt", FT_UINT16, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_brdwlk_drop,
          {"Packet Dropped", "brdwlk.drop", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_brdwlk_vsan,
          {"VSAN", "brdwlk.vsan", FT_UINT16, BASE_DEC, NULL, 0xFFF, "",
           HFILL}},
        { &hf_brdwlk_plen,
          {"Original Packet Length", "brdwlk.plen", FT_UINT32, BASE_DEC, NULL, 0x0, "",
           HFILL}},
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_brdwlk,
    };

/* Register the protocol name and description */
    proto_brdwlk = proto_register_protocol("Boardwalk",
                                           "Boardwalk", "brdwlk");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_brdwlk, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(&brdwlk_init);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_brdwlk(void)
{
    dissector_handle_t brdwlk_handle;

    brdwlk_handle = create_dissector_handle (dissect_brdwlk, proto_brdwlk);
    dissector_add("ethertype", ETHERTYPE_BRDWALK, brdwlk_handle);
    dissector_add("ethertype", 0xABCD, brdwlk_handle);
    data_handle = find_dissector("data");
    fc_dissector_handle = find_dissector ("fc");
}
