/* packet-brdwlk.c
 * Routines for decoding MDS Port Analyzer Adapter (FC in Eth) Header
 * Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include "packet-fc.h"

#define BRDWLK_MAX_PACKET_CNT  0xFFFF
#define BRDWLK_TRUNCATED_BIT   0x8
#define BRDWLK_HAS_PLEN        0x1

#define FCM_DELIM_SOFC1         0x01
#define FCM_DELIM_SOFI1         0x02
#define FCM_DELIM_SOFI2         0x04
#define FCM_DELIM_SOFI3         0x06
#define FCM_DELIM_SOFN1         0x03
#define FCM_DELIM_SOFN2         0x05
#define FCM_DELIM_SOFN3         0x07
#define FCM_DELIM_SOFF          0x08
#define FCM_DELIM_SOFC4         0x09
#define FCM_DELIM_SOFI4         0x0A
#define FCM_DELIM_SOFN4         0x0B

#define FCM_DELIM_EOFT          0x01
#define FCM_DELIM_EOFDT         0x02
#define FCM_DELIM_EOFN          0x03
#define FCM_DELIM_EOFA          0x04
#define FCM_DELIM_EOFNI         0x07
#define FCM_DELIM_EOFDTI        0x06
#define FCM_DELIM_EOFRT         0x0A
#define FCM_DELIM_EOFRTI        0x0E
#define FCM_DELIM_NOEOF         0xF0
#define FCM_DELIM_EOFJUMBO      0xF1

void proto_register_brdwlk(void);
void proto_reg_handoff_brdwlk(void);

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

static int hf_brdwlk_sof;
static int hf_brdwlk_eof;
static int hf_brdwlk_error;
static int hf_brdwlk_vsan;
static int hf_brdwlk_pktcnt;
static int hf_brdwlk_drop;
static int hf_brdwlk_plen;
static int hf_brdwlk_error_plp;
static int hf_brdwlk_error_ef;
static int hf_brdwlk_error_nd;
static int hf_brdwlk_error_tr;
static int hf_brdwlk_error_badcrc;
static int hf_brdwlk_error_ff;
static int hf_brdwlk_error_jumbo;
static int hf_brdwlk_error_ctrl;

/* Initialize the subtree pointers */
static int ett_brdwlk;
static int ett_brdwlk_error;

static int proto_brdwlk;

static uint16_t packet_count;
static bool first_pkt = true;                /* start of capture */

static dissector_handle_t fc_dissector_handle;
static dissector_handle_t brdwlk_handle;


static const true_false_string tfs_error_plp = {
    "Packet Length is PRESENT",
    "Packet length is NOT present"
};
static const true_false_string tfs_error_ef = {
    "This is an Empty Frame",
    "Frame is NOT empty"
};
static const true_false_string tfs_error_nd = {
    "This Frame has NO Data",
    "This frame carries data"
};
static const true_false_string tfs_error_tr = {
    "This frame is TRUNCATED",
    "This frame is NOT truncated"
};
static const true_false_string tfs_error_crc = {
    "This Frame has a BAD FC CRC",
    "This frame has a valid crc"
};
static const true_false_string tfs_error_ff = {
    "Fifo is Full",
    "Fifo is NOT full"
};
static const true_false_string tfs_error_jumbo = {
    "This is a JUMBO FC Frame",
    "This is a NORMAL FC Frame"
};
static const true_false_string tfs_error_ctrl = {
    "Ctrl Characters inside the frame",
    "No ctrl chars inside the frame"
};

static void
dissect_brdwlk_err(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
    static int * const flags[] = {
        &hf_brdwlk_error_plp,
        &hf_brdwlk_error_ef,
        &hf_brdwlk_error_nd,
        &hf_brdwlk_error_tr,
        &hf_brdwlk_error_badcrc,
        &hf_brdwlk_error_ff,
        &hf_brdwlk_error_jumbo,
        &hf_brdwlk_error_ctrl,
        NULL
    };

    proto_tree_add_bitmask_with_flags(parent_tree, tvb, offset, hf_brdwlk_error, ett_brdwlk_error, flags, ENC_NA, BMT_NO_FALSE|BMT_NO_TFS);
}

/* Code to actually dissect the packets */
static int
dissect_brdwlk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti, *hidden_item;
    proto_tree *brdwlk_tree;
    tvbuff_t *next_tvb;
    uint8_t error, eof, sof;
    int hdrlen = 2,
        offset = 0;
    int len, reported_len, plen;
    uint16_t pkt_cnt;
    bool dropped_packets;
    fc_data_t fc_data;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Boardwalk");

    col_clear(pinfo->cinfo, COL_INFO);

    sof = (tvb_get_uint8(tvb, offset) & 0xF0) >> 4;

    fc_data.sof_eof = 0;
    if ((sof == FCM_DELIM_SOFI3) || (sof == FCM_DELIM_SOFI2) || (sof == FCM_DELIM_SOFI1)
        || (sof == FCM_DELIM_SOFI4)) {
        fc_data.sof_eof = FC_DATA_SOF_FIRST_FRAME;
    }
    else if (sof == FCM_DELIM_SOFF) {
        fc_data.sof_eof = FC_DATA_SOF_SOFF;
    }

    ti = proto_tree_add_protocol_format(tree, proto_brdwlk, tvb, 0,
            hdrlen, "Boardwalk");

    brdwlk_tree = proto_item_add_subtree(ti, ett_brdwlk);

    proto_tree_add_item(brdwlk_tree, hf_brdwlk_sof, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(brdwlk_tree, hf_brdwlk_vsan, tvb, offset, 2, ENC_BIG_ENDIAN);

    /* Locate EOF which is the last 4 bytes of the frame */
    len = tvb_captured_length_remaining(tvb, hdrlen);
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
        pkt_cnt = tvb_get_ntohs(tvb, offset);
        if (tree) {
            proto_tree_add_uint(brdwlk_tree, hf_brdwlk_pktcnt, tvb, offset,
                                2, pkt_cnt);
        }
        dropped_packets = false;
        if (pinfo->fd->visited) {
            /*
             * This isn't the first pass, so we can't use the global
             * "packet_count" variable to determine whether there were
             * any dropped frames or not.
             * We therefore attach a non-null pointer as frame data to
             * any frame preceded by dropped packets.
             */
            if (p_get_proto_data(wmem_file_scope(), pinfo, proto_brdwlk, 0) != NULL)
                dropped_packets = true;
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
                    dropped_packets = true;

                    /*
                     * Mark this frame as having been preceded by dropped
                     * packets.  (The data we use as the frame data doesn't
                     * matter - it just matters that it's non-null.)
                     */
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_brdwlk, 0, &packet_count);
                }
            }
        }

        hidden_item = proto_tree_add_boolean(brdwlk_tree, hf_brdwlk_drop,
                tvb, offset, 0, dropped_packets);
        proto_item_set_hidden(hidden_item);

        packet_count = pkt_cnt;

        error=tvb_get_uint8(tvb, offset+2);
        dissect_brdwlk_err(brdwlk_tree, tvb, offset+2);

        eof = tvb_get_uint8(tvb, offset+3);
        if (eof != FCM_DELIM_EOFN) {
            fc_data.sof_eof |= FC_DATA_EOF_LAST_FRAME;
        }
        else if (eof != FCM_DELIM_EOFT) {
            fc_data.sof_eof |= FC_DATA_EOF_INVALID;
        }

        proto_tree_add_item(brdwlk_tree, hf_brdwlk_eof, tvb, offset+3,
                1, ENC_BIG_ENDIAN);

        if ((error & BRDWLK_HAS_PLEN) && tree) {
            /* In newer Boardwalks, if this bit is set, the actual frame length
             * is also provided. This length is the size between SOF & EOF
             * including FC CRC.
             */
            plen = tvb_get_ntohl(tvb, offset-4);
            plen *= 4;
            proto_tree_add_uint(brdwlk_tree, hf_brdwlk_plen, tvb, offset-4,
                                4, plen);

#if 0
            /* XXX - this would throw an exception if it would increase
             * the reported length.
             */
            if (error & BRDWLK_TRUNCATED_BIT) {
                tvb_set_reported_length(tvb, plen);
            }
#endif
        }
    }

    fc_data.ethertype = ETHERTYPE_BRDWALK;
    next_tvb = tvb_new_subset_length_caplen(tvb, 2, len, reported_len);
    call_dissector_with_data(fc_dissector_handle, next_tvb, pinfo, tree, &fc_data);
    return tvb_captured_length(tvb);
}

static void
brdwlk_init(void)
{
    packet_count = 0;
    first_pkt = true;
}

/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_brdwlk(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_brdwlk_sof,
          {"SOF", "brdwlk.sof", FT_UINT8, BASE_HEX, VALS(brdwlk_sof_vals),
           0xF0, NULL, HFILL}},
        { &hf_brdwlk_eof,
          {"EOF", "brdwlk.eof", FT_UINT8, BASE_HEX, VALS(brdwlk_eof_vals),
           0x0F, NULL, HFILL}},
        { &hf_brdwlk_error,
          {"Error", "brdwlk.error", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_brdwlk_pktcnt,
          {"Packet Count", "brdwlk.pktcnt", FT_UINT16, BASE_DEC, NULL, 0x0,
           NULL, HFILL}},
        { &hf_brdwlk_drop,
          {"Packet Dropped", "brdwlk.drop", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           NULL, HFILL}},
        { &hf_brdwlk_vsan,
          {"VSAN", "brdwlk.vsan", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL,
           HFILL}},
        { &hf_brdwlk_plen,
          {"Original Packet Length", "brdwlk.plen", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
           HFILL}},
        { &hf_brdwlk_error_plp,
          {"Packet Length Present", "brdwlk.error.plp", FT_BOOLEAN, 8, TFS(&tfs_error_plp), 0x01, NULL,
           HFILL}},
        { &hf_brdwlk_error_ef,
          {"Empty Frame", "brdwlk.error.ef", FT_BOOLEAN, 8, TFS(&tfs_error_ef), 0x02, NULL,
           HFILL}},
        { &hf_brdwlk_error_nd,
          {"No Data", "brdwlk.error.nd", FT_BOOLEAN, 8, TFS(&tfs_error_nd), 0x04, NULL,
           HFILL}},
        { &hf_brdwlk_error_tr,
          {"Truncated", "brdwlk.error.tr", FT_BOOLEAN, 8, TFS(&tfs_error_tr), 0x08, NULL,
           HFILL}},
        { &hf_brdwlk_error_badcrc,
          {"CRC", "brdwlk.error.crc", FT_BOOLEAN, 8, TFS(&tfs_error_crc), 0x10, NULL,
           HFILL}},
        { &hf_brdwlk_error_ff,
          {"Fifo Full", "brdwlk.error.ff", FT_BOOLEAN, 8, TFS(&tfs_error_ff), 0x20, NULL,
           HFILL}},
        { &hf_brdwlk_error_jumbo,
          {"Jumbo FC Frame", "brdwlk.error.jumbo", FT_BOOLEAN, 8, TFS(&tfs_error_jumbo), 0x40, NULL,
           HFILL}},
        { &hf_brdwlk_error_ctrl,
          {"Ctrl Char Inside Frame", "brdwlk.error.ctrl", FT_BOOLEAN, 8, TFS(&tfs_error_ctrl), 0x80, NULL,
           HFILL}},
    };

/* Setup protocol subtree array */
    static int *ett[] = {
        &ett_brdwlk,
        &ett_brdwlk_error,
    };

/* Register the protocol name and description */
    proto_brdwlk = proto_register_protocol("Boardwalk", "Boardwalk", "brdwlk");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_brdwlk, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(&brdwlk_init);

/* Register the dissector */
    brdwlk_handle = register_dissector("brdwlk", dissect_brdwlk, proto_brdwlk);
}


void
proto_reg_handoff_brdwlk(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_BRDWALK, brdwlk_handle);
    dissector_add_uint("ethertype", 0xABCD, brdwlk_handle);
    fc_dissector_handle = find_dissector_add_dependency("fc", proto_brdwlk);
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
