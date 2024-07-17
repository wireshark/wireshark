/* packet-nb_rtpmux.c
 * Routines for 3GPP RTP Multiplex dissection, 3GPP TS 29.414
 * Copyright 2009, ip.access ltd <amp@ipaccess.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_nb_rtpmux(void);
void proto_reg_handoff_nb_rtpmux(void);

/* Initialize the protocol and registered fields */
static int proto_nb_rtpmux;
static int hf_nb_rtpmux_compressed;
static int hf_nb_rtpmux_dstport;
static int hf_nb_rtpmux_length;
static int hf_nb_r_bit;
static int hf_nb_rtpmux_srcport;
static int hf_nb_rtpmux_data;
static int hf_nb_rtpmux_cmp_rtp_sequence_no;
static int hf_nb_rtpmux_cmp_rtp_timestamp;
static int hf_nb_rtpmux_cmp_rtp_data;

/* Initialize the subtree pointers */
static int ett_nb_rtpmux;
static int ett_nb_rtpmux_cmp_rtp_hdr;

static dissector_handle_t nb_rtpmux_handle;
static dissector_handle_t rtpdissector;

static int
dissect_nb_rtpmux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *nb_rtpmux_tree, *nb_rtpmux_cmp_rtp_tree;
    unsigned int offset = 0;
    bool first_rtp_payload_seen = false;

    /*  First, if at all possible, do some heuristics to check if the packet cannot
     *  possibly belong to your protocol.  This is especially important for
     *  protocols directly on top of TCP or UDP where port collisions are
     *  common place (e.g., even though your protocol uses a well known port,
     *  someone else may set up, for example, a web server on that port which,
     *  if someone analyzed that web server's traffic in Wireshark, would result
     *  in Wireshark handing an HTTP packet to your dissector).  For example:
     */

    /*
     * XXX - this is *FAR* too weak a heuristic; it could cause all sorts
     * of stuff to be incorrectly identified as Nb_RTPmux.  Either this
     * needs a stronger heuristic, or it needs to have a preference to
     * set the port on which to dissect it, or it needs to be a non-heuristic
     * dissector and *require* that a user use "Decode As..." to decode
     * traffic as Nb_RTPmux.
     *
     * Look for a payload that looks like an RTP packet, using the
     * same (weakish) heuristics as RTP uses?
     */

    /* Check that there's enough data */
    if (tvb_captured_length(tvb) < 6)
        return 0;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NB_RTPMUX");

    /* NOTE: The offset and length values in the call to
       "proto_tree_add_item()" define what data bytes to highlight in the hex
       display window when the line in the protocol tree display
       corresponding to that item is selected.

       Supplying a length of -1 is the way to highlight all data from the
       offset to the end of the packet. */

    /* create display subtree for the protocol */
    while (offset < tvb_reported_length(tvb)-5)
    {
        uint16_t dstport, srcport;
        unsigned int length;
        int captured_length;
        tvbuff_t *next_tvb;
        bool tbit;

        length = tvb_get_uint8(tvb, offset+2);
        ti = proto_tree_add_item(tree, proto_nb_rtpmux, tvb, offset, length+5, ENC_NA);
        nb_rtpmux_tree = proto_item_add_subtree(ti, ett_nb_rtpmux);

        /* T bit */
        proto_tree_add_item(nb_rtpmux_tree, hf_nb_rtpmux_compressed, tvb, offset, 2, ENC_BIG_ENDIAN);
        tbit = tvb_get_uint8(tvb,offset)>>7;
        if(tbit == 1){
            /* 6.4.2.4 Transport Format for multiplexing with RTP header compression */
            dstport = (tvb_get_ntohs(tvb, offset) & 0x7fff) << 1;
            proto_tree_add_uint(nb_rtpmux_tree, hf_nb_rtpmux_dstport, tvb, offset, 2, dstport );
            proto_tree_add_item(nb_rtpmux_tree, hf_nb_rtpmux_length, tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(nb_rtpmux_tree, hf_nb_r_bit, tvb, offset+3, 2, ENC_BIG_ENDIAN);
            srcport = (tvb_get_ntohs(tvb, offset+3) & 0x7fff) << 1;
            proto_tree_add_uint(nb_rtpmux_tree, hf_nb_rtpmux_srcport, tvb, offset+3, 2, srcport );
            nb_rtpmux_cmp_rtp_tree = proto_tree_add_subtree( nb_rtpmux_tree, tvb, offset+5, 3, ett_nb_rtpmux_cmp_rtp_hdr, NULL, "Compressed RTP header" );
            /* Sequence Number (SN) */
            proto_tree_add_item(nb_rtpmux_cmp_rtp_tree, hf_nb_rtpmux_cmp_rtp_sequence_no, tvb, offset+5, 1, ENC_BIG_ENDIAN);
            /* Timestamp (TS) */
            proto_tree_add_item(nb_rtpmux_cmp_rtp_tree, hf_nb_rtpmux_cmp_rtp_timestamp, tvb, offset+6, 2, ENC_BIG_ENDIAN);
            if (length != 0)
                proto_tree_add_item(nb_rtpmux_cmp_rtp_tree, hf_nb_rtpmux_cmp_rtp_data,tvb, offset+8, length-3, ENC_NA);

            /* Not trying to decompress... */

            /* Add summary to protocol root */
            proto_item_append_text(ti, ", Src Port: %u, Dst Port: %u Length: %u", srcport, dstport, length);

        }else{
            /* 6.4.2.3 Transport Format for multiplexing without RTP Header Compression */
            dstport = (tvb_get_ntohs(tvb, offset) & 0x7fff) << 1;
            proto_tree_add_uint(nb_rtpmux_tree, hf_nb_rtpmux_dstport, tvb, offset, 2, dstport );
            proto_tree_add_item(nb_rtpmux_tree,
                                hf_nb_rtpmux_length, tvb, offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(nb_rtpmux_tree, hf_nb_r_bit, tvb, offset+3, 1, ENC_BIG_ENDIAN);
            srcport = (tvb_get_ntohs(tvb, offset+3) & 0x7fff) << 1;
            proto_tree_add_uint(nb_rtpmux_tree, hf_nb_rtpmux_srcport, tvb, offset+3, 2, srcport );

            /* Add summary to protocol root */
            proto_item_append_text(ti, ", Src Port: %u, Dst Port: %u Length: %u", srcport, dstport, length);

            if (length != 0)
            {
                /* We have an RTP payload. */
                if (rtpdissector)
                {
                    captured_length = tvb_reported_length_remaining(tvb, offset + 5);
                    if (captured_length > (int)length)
                        captured_length = length;
                    next_tvb = tvb_new_subset_length_caplen(tvb, offset+5, captured_length,
                                              length);

                    if (first_rtp_payload_seen)
                    {
                        /* Don't want to clear the column, instead show where multiple
                           RTP frames are being carried */
                        col_append_str(pinfo->cinfo, COL_INFO, "  | ");
                        col_set_fence(pinfo->cinfo, COL_INFO);
                    }

                    call_dissector(rtpdissector, next_tvb, pinfo, nb_rtpmux_tree);

                    first_rtp_payload_seen = true;
                }
                else
                {
                    proto_tree_add_item(nb_rtpmux_tree,
                                        hf_nb_rtpmux_data, tvb, offset+5, length, ENC_NA);
                }
            }
        } /* if tbit */
        offset += 5+length;
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_reported_length(tvb);
}


/* Register the protocol with Wireshark */

void
proto_register_nb_rtpmux(void)
{

    static hf_register_info hf[] = {
        { &hf_nb_rtpmux_compressed,
          { "Compressed headers(T bit)", "nb_rtpmux.compressed",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_nb_rtpmux_dstport,
          { "Dst port", "nb_rtpmux.dstport",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nb_rtpmux_length,
          { "Length", "nb_rtpmux.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nb_r_bit,
          { "R bit", "nb_rtpmux.r_bit",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_nb_rtpmux_srcport,
          { "Src port", "nb_rtpmux.srcport",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nb_rtpmux_data,
          { "RTP Packet", "nb_rtpmux.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nb_rtpmux_cmp_rtp_sequence_no,
          { "Sequence Number", "nb_rtpmux.cmp_rtp.sequence_no",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nb_rtpmux_cmp_rtp_timestamp,
          { "Timestamp", "nb_rtpmux.cmp_rtp.timestamp",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_nb_rtpmux_cmp_rtp_data,
          { "RTP Data", "nb_rtpmux.cmp_rtp.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL,HFILL }
        }

    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_nb_rtpmux,
        &ett_nb_rtpmux_cmp_rtp_hdr
    };

    /* Register the protocol name and description */
    proto_nb_rtpmux = proto_register_protocol("3GPP Nb Interface RTP Multiplex", "NB_RTPMUX", "nb_rtpmux");
    nb_rtpmux_handle = register_dissector("nb_rtpmux", dissect_nb_rtpmux, proto_nb_rtpmux);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_nb_rtpmux, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nb_rtpmux(void)
{
    dissector_add_uint_range_with_preference("udp.port", "", nb_rtpmux_handle);

    rtpdissector = find_dissector_add_dependency("rtp", proto_nb_rtpmux);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
