/* TODO mix direction bit into the chandle tree lookup   so we can handle when fragments sent in both directions simultaneously on the same chandle */

/* packet-bthci_acl.c
 * Routines for the Bluetooth ACL dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *  From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
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
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-hci_h4.h"
#include "packet-bthci_acl.h"

/* Initialize the protocol and registered fields */
static int proto_bthci_acl = -1;
static int hf_bthci_acl_chandle = -1;
static int hf_bthci_acl_pb_flag = -1;
static int hf_bthci_acl_bc_flag = -1;
static int hf_bthci_acl_length = -1;
static int hf_bthci_acl_data = -1;
static int hf_bthci_acl_continuation_to = -1;
static int hf_bthci_acl_reassembled_in = -1;

/* Initialize the subtree pointers */
static gint ett_bthci_acl = -1;

static dissector_handle_t btl2cap_handle = NULL;

static gboolean acl_reassembly = TRUE;

typedef struct _multi_fragment_pdu_t {
    guint32  first_frame;
    guint32  last_frame;
    guint16  tot_len;
    char    *reassembled;
    int      cur_off;           /* counter used by reassembly */
} multi_fragment_pdu_t;

typedef struct _chandle_data_t {
    emem_tree_t *start_fragments;  /* indexed by pinfo->fd->num */
} chandle_data_t;

static emem_tree_t *chandle_tree = NULL;

static const value_string pb_flag_vals[] = {
    {0, "First Non-automatically Flushable Packet"},
    {1, "Continuing Fragment"},
    {2, "First Automatically Flushable Packet"},
    {0, NULL }
};

static const value_string bc_flag_vals[] = {
    {0, "Point-To-Point"},
    {1, "Active Broadcast"},
    {2, "Piconet Broadcast"},
    {0, NULL }
};



/* Code to actually dissect the packets */
static void
dissect_bthci_acl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item       *ti                        = NULL;
    proto_tree       *bthci_acl_tree            = NULL;
    guint16           flags, length;
    gboolean          fragmented;
    int               offset                = 0;
    guint16           pb_flag, l2cap_length = 0;
    tvbuff_t         *next_tvb;
    bthci_acl_data_t *acl_data;
    chandle_data_t   *chandle_data;
    void*             pd_save;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_ACL");

    if (tree) {
        ti = proto_tree_add_item(tree, proto_bthci_acl, tvb, offset, -1, ENC_NA);
        bthci_acl_tree = proto_item_add_subtree(ti, ett_bthci_acl);
    }

    flags   = tvb_get_letohs(tvb, offset);
    pb_flag = (flags & 0x3000) >> 12;
    proto_tree_add_item(bthci_acl_tree, hf_bthci_acl_chandle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_acl_tree, hf_bthci_acl_pb_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_acl_tree, hf_bthci_acl_bc_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    acl_data            = ep_alloc(sizeof(bthci_acl_data_t));
    acl_data->chandle   = flags&0x0fff;
    pd_save             = pinfo->private_data;
    pinfo->private_data = acl_data;

    /* find the chandle_data structure associated with this chandle */
    chandle_data = se_tree_lookup32(chandle_tree, acl_data->chandle);
    if (!chandle_data) {
        chandle_data = se_alloc(sizeof(chandle_data_t));
        chandle_data->start_fragments = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "bthci_acl fragment starts");
        se_tree_insert32(chandle_tree, acl_data->chandle, chandle_data);
    }

    length = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(bthci_acl_tree, hf_bthci_acl_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    /* determine if packet is fragmented */
    switch(pb_flag) {
    case 0x01:  /* Continuation fragment */
        fragmented = TRUE;
        break;
    case 0x00:  /* First fragment/packet, non-auto flushable */
    case 0x02:  /* First fragment/packet, auto flushable */
        l2cap_length = tvb_get_letohs(tvb, offset);
        fragmented   = ((l2cap_length+4)!=length);
        break;
    default:
        /* unknown pb_flag */
        fragmented = FALSE;
    }


    if ((!fragmented)
        || ((!acl_reassembly)&& !(pb_flag&0x01))) {
        /* call L2CAP dissector for PDUs that are not fragmented
         * also for the first fragment if reassembly is disabled
         */
        next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), length);
        if (btl2cap_handle) {
            call_dissector(btl2cap_handle, next_tvb, pinfo, tree);
        }
        pinfo->private_data = pd_save;
        return;
    }

    if (fragmented && acl_reassembly) {
        multi_fragment_pdu_t *mfp = NULL;
        gint                  len;

        if (!(pb_flag&0x01)) { /* first fragment */
            if (!pinfo->fd->flags.visited) {
                mfp = se_alloc(sizeof(multi_fragment_pdu_t));
                mfp->first_frame = pinfo->fd->num;
                mfp->last_frame  = 0;
                mfp->tot_len     = l2cap_length+4;
                mfp->reassembled = se_alloc(mfp->tot_len);
                len = tvb_length_remaining(tvb, offset);
                if (len <= mfp->tot_len) {
                    tvb_memcpy(tvb, (guint8*)mfp->reassembled, offset, len);
                    mfp->cur_off = len;
                    se_tree_insert32(chandle_data->start_fragments, pinfo->fd->num, mfp);
                }
            } else {
                mfp = se_tree_lookup32(chandle_data->start_fragments, pinfo->fd->num);
            }
            if (mfp != NULL && mfp->last_frame) {
                proto_item *item;
                item = proto_tree_add_uint(bthci_acl_tree, hf_bthci_acl_reassembled_in, tvb, 0, 0, mfp->last_frame);
                PROTO_ITEM_SET_GENERATED(item);
                col_append_fstr(pinfo->cinfo, COL_INFO, " [Reassembled in #%u]", mfp->last_frame);
            }
        }
        if (pb_flag == 0x01) { /* continuation fragment */
            mfp = se_tree_lookup32_le(chandle_data->start_fragments, pinfo->fd->num);
            if (!pinfo->fd->flags.visited) {
                len = tvb_length_remaining(tvb, offset);
                if (mfp != NULL && !mfp->last_frame && (mfp->tot_len>=mfp->cur_off+len)) {
                    tvb_memcpy(tvb, (guint8*)mfp->reassembled+mfp->cur_off, offset, len);
                    mfp->cur_off+=len;
                    if (mfp->cur_off == mfp->tot_len) {
                        mfp->last_frame = pinfo->fd->num;
                    }
                }
            }
            if (mfp) {
                proto_item *item;
                item = proto_tree_add_uint(bthci_acl_tree, hf_bthci_acl_continuation_to, tvb, 0, 0, mfp->first_frame);
                PROTO_ITEM_SET_GENERATED(item);
                col_append_fstr(pinfo->cinfo, COL_INFO, " [Continuation to #%u]", mfp->first_frame);
            }
            if (mfp != NULL && mfp->last_frame == pinfo->fd->num) {
                next_tvb = tvb_new_child_real_data(tvb, (guint8*)mfp->reassembled, mfp->tot_len, mfp->tot_len);
                add_new_data_source(pinfo, next_tvb, "Reassembled BTHCI ACL");

                /* call L2CAP dissector */
                if (btl2cap_handle) {
                    call_dissector(btl2cap_handle, next_tvb, pinfo, tree);
                }
            }
        }
    }
    pinfo->private_data = pd_save;
}


void
proto_register_bthci_acl(void)
{

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_bthci_acl_chandle,
          { "Connection Handle",                             "bthci_acl.chandle",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_bthci_acl_pb_flag,
          { "PB Flag",                                       "bthci_acl.pb_flag",
            FT_UINT16, BASE_DEC, VALS(pb_flag_vals), 0x3000,
            "Packet Boundary Flag", HFILL }
        },
        { &hf_bthci_acl_bc_flag,
          { "BC Flag",                                       "bthci_acl.bc_flag",
            FT_UINT16, BASE_DEC, VALS(bc_flag_vals), 0xC000,
            "Broadcast Flag", HFILL }
        },
        { &hf_bthci_acl_length,
          { "Data Total Length",                             "bthci_acl.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_acl_data,
          { "Data",                                          "bthci_acl.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_acl_continuation_to,
          { "This is a continuation to the PDU in frame",    "bthci_acl.continuation_to",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This is a continuation to the PDU in frame #", HFILL }
        },
        { &hf_bthci_acl_reassembled_in,
          { "This PDU is reassembled in frame",              "bthci_acl.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This PDU is reassembled in frame #", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bthci_acl,
    };
    module_t *bthci_acl_module;

    /* Register the protocol name and description */
    proto_bthci_acl = proto_register_protocol("Bluetooth HCI ACL Packet", "HCI_ACL", "bthci_acl");
    register_dissector("bthci_acl", dissect_bthci_acl, proto_bthci_acl);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bthci_acl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register configuration preferences */
    bthci_acl_module = prefs_register_protocol(proto_bthci_acl, NULL);
    prefs_register_bool_preference(bthci_acl_module, "hci_acl_reassembly",
        "Reassemble ACL Fragments",
        "Whether the ACL dissector should reassemble fragmented PDUs",
        &acl_reassembly);

    chandle_tree = se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "bthci_acl chandles");
}


void
proto_reg_handoff_bthci_acl(void)
{
    dissector_handle_t bthci_acl_handle;

    bthci_acl_handle = find_dissector("bthci_acl");
    dissector_add_uint("hci_h4.type", HCI_H4_TYPE_ACL, bthci_acl_handle);
    dissector_add_uint("hci_h1.type", BTHCI_CHANNEL_ACL, bthci_acl_handle);


    btl2cap_handle = find_dissector("btl2cap");
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
