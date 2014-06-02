/* packet-bthci_acl.c
 * Routines for the Bluetooth ACL dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *     - from: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 * Copyright 2006, Ronnie Sahlberg
 *     - refactored for Wireshark checkin
 * Copyright 2014, Michal Labedzki for Tieto Corporation
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
#include <epan/addr_resolv.h>
#include <epan/wmem/wmem.h>

#include "packet-bluetooth-hci.h"
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
static int hf_bthci_acl_connect_in = -1;
static int hf_bthci_acl_disconnect_in = -1;
static int hf_bthci_acl_src_bd_addr = -1;
static int hf_bthci_acl_src_name = -1;
static int hf_bthci_acl_dst_bd_addr = -1;
static int hf_bthci_acl_dst_name = -1;

/* Initialize the subtree pointers */
static gint ett_bthci_acl = -1;

static dissector_handle_t bthci_acl_handle;
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
    wmem_tree_t *start_fragments;  /* indexed by pinfo->fd->num */
} chandle_data_t;

static wmem_tree_t *chandle_tree = NULL;

static const value_string pb_flag_vals[] = {
    { 0, "First Non-automatically Flushable Packet" },
    { 1, "Continuing Fragment" },
    { 2, "First Automatically Flushable Packet" },
    { 0, NULL }
};

static const value_string bc_flag_vals[] = {
    { 0, "Point-To-Point" },
    { 1, "Active Broadcast" },
    { 2, "Piconet Broadcast" },
    { 0, NULL }
};

static guint32 max_disconnect_in_frame = G_MAXUINT32;


void proto_register_bthci_acl(void);
void proto_reg_handoff_bthci_acl(void);

/* Code to actually dissect the packets */
static gint
dissect_bthci_acl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item               *ti;
    proto_tree               *bthci_acl_tree;
    proto_item               *sub_item;
    guint16                   flags;
    guint16                   length;
    gboolean                  fragmented;
    gint                      offset                = 0;
    guint16                   pb_flag, l2cap_length = 0;
    tvbuff_t                 *next_tvb;
    bthci_acl_data_t         *acl_data;
    chandle_data_t           *chandle_data;
    hci_data_t               *hci_data;
    wmem_tree_t              *subtree;
    wmem_tree_key_t           key[6];
    guint32                   interface_id;
    guint32                   adapter_id;
    guint32                   connection_handle;
    guint32                   direction;
    guint32                   frame_number;
    remote_bdaddr_t          *remote_bdaddr;
    const gchar              *localhost_name;
    guint8                    localhost_bdaddr[6];
    const gchar              *localhost_ether_addr;
    gchar                    *localhost_addr_name;
    gint                      localhost_length;
    localhost_bdaddr_entry_t *localhost_bdaddr_entry;
    localhost_name_entry_t   *localhost_name_entry;
    const guint8              unknown_bd_addr[6] = {0, 0, 0, 0, 0, 0};
    const guint8             *src_bd_addr = &unknown_bd_addr[0];
    const gchar              *src_name = "";
    const gchar              *src_addr_name = "";
    const guint8             *dst_bd_addr = &unknown_bd_addr[0];
    const gchar              *dst_name = "";
    const gchar              *dst_addr_name = "";
    chandle_session_t        *chandle_session;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    hci_data = (hci_data_t *) data;

    ti = proto_tree_add_item(tree, proto_bthci_acl, tvb, offset, -1, ENC_NA);
    bthci_acl_tree = proto_item_add_subtree(ti, ett_bthci_acl);

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
                pinfo->p2p_dir);
            break;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_ACL");

    flags   = tvb_get_letohs(tvb, offset);
    pb_flag = (flags & 0x3000) >> 12;
    proto_tree_add_item(bthci_acl_tree, hf_bthci_acl_chandle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_acl_tree, hf_bthci_acl_pb_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_acl_tree, hf_bthci_acl_bc_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    interface_id      = hci_data->interface_id;
    adapter_id        = hci_data->adapter_id;
    connection_handle = flags & 0x0fff;
    direction         = pinfo->p2p_dir;
    frame_number      = pinfo->fd->num;

    acl_data = wmem_new(wmem_packet_scope(), bthci_acl_data_t);
    acl_data->interface_id                = interface_id;
    acl_data->adapter_id                  = adapter_id;
    acl_data->adapter_disconnect_in_frame = hci_data->adapter_disconnect_in_frame;
    acl_data->chandle                     = connection_handle;

    key[0].length = 1;
    key[0].key    = &interface_id;
    key[1].length = 1;
    key[1].key    = &adapter_id;
    key[2].length = 1;
    key[2].key    = &connection_handle;
    key[3].length = 0;
    key[3].key    = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(hci_data->chandle_sessions, key);
    chandle_session = (subtree) ? (chandle_session_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num) : NULL;
    if (chandle_session &&
            chandle_session->connect_in_frame < pinfo->fd->num &&
            chandle_session->disconnect_in_frame > pinfo->fd->num) {
        acl_data->disconnect_in_frame = &chandle_session->disconnect_in_frame;
    } else {
        acl_data->disconnect_in_frame = &max_disconnect_in_frame;
    }

    acl_data->remote_bd_addr_oui         = 0;
    acl_data->remote_bd_addr_id          = 0;

    /* remote bdaddr and name */
    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(hci_data->chandle_to_bdaddr_table, key);
    remote_bdaddr = (subtree) ? (remote_bdaddr_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num) : NULL;
    if (remote_bdaddr) {
        guint32         k_bd_addr_oui;
        guint32         k_bd_addr_id;
        guint32         bd_addr_oui;
        guint32         bd_addr_id;
        device_name_t  *device_name;
        const gchar    *remote_name;
        const gchar    *remote_ether_addr;
        gchar          *remote_addr_name;
        gint            remote_length;

        bd_addr_oui = remote_bdaddr->bd_addr[0] << 16 | remote_bdaddr->bd_addr[1] << 8 | remote_bdaddr->bd_addr[2];
        bd_addr_id  = remote_bdaddr->bd_addr[3] << 16 | remote_bdaddr->bd_addr[4] << 8 | remote_bdaddr->bd_addr[5];

        acl_data->remote_bd_addr_oui = bd_addr_oui;
        acl_data->remote_bd_addr_id  = bd_addr_id;

        k_bd_addr_oui  = bd_addr_oui;
        k_bd_addr_id   = bd_addr_id;

        key[0].length = 1;
        key[0].key    = &k_bd_addr_id;
        key[1].length = 1;
        key[1].key    = &k_bd_addr_oui;
        key[2].length = 0;
        key[2].key    = NULL;

        subtree = (wmem_tree_t *) wmem_tree_lookup32_array(hci_data->bdaddr_to_name_table, key);
        device_name = (subtree) ? (device_name_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num) : NULL;
        if (device_name)
            remote_name = device_name->name;
        else
            remote_name = "";

        remote_ether_addr = get_ether_name(remote_bdaddr->bd_addr);
        remote_length = (gint)(strlen(remote_ether_addr) + 3 + strlen(remote_name) + 1);
        remote_addr_name = (gchar *)wmem_alloc(pinfo->pool, remote_length);

        g_snprintf(remote_addr_name, remote_length, "%s (%s)", remote_ether_addr, remote_name);

        if (pinfo->p2p_dir == P2P_DIR_RECV) {
            src_bd_addr   = remote_bdaddr->bd_addr;
            src_name      = remote_name;
            src_addr_name = remote_addr_name;
        } else if (pinfo->p2p_dir == P2P_DIR_SENT) {
            dst_bd_addr   = remote_bdaddr->bd_addr;
            dst_name      = remote_name;
            dst_addr_name = remote_addr_name;
        }
    } else {
        if (pinfo->p2p_dir == P2P_DIR_RECV)
            src_addr_name = "remote ()";
        else if (pinfo->p2p_dir == P2P_DIR_SENT)
            dst_addr_name = "remote ()";
    }

    /* localhost bdaddr and name */
    key[0].length = 1;
    key[0].key    = &interface_id;
    key[1].length = 1;
    key[1].key    = &adapter_id;
    key[2].length = 0;
    key[2].key    = NULL;


    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(hci_data->localhost_bdaddr, key);
    localhost_bdaddr_entry = (subtree) ? (localhost_bdaddr_entry_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num) : NULL;
    if (localhost_bdaddr_entry) {
        localhost_ether_addr = get_ether_name(localhost_bdaddr_entry->bd_addr);
        memcpy(localhost_bdaddr, localhost_bdaddr_entry->bd_addr, 6);
    } else {
        localhost_ether_addr = "localhost";
        memcpy(localhost_bdaddr, unknown_bd_addr, 6);
    }


    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(hci_data->localhost_name, key);
    localhost_name_entry = (subtree) ? (localhost_name_entry_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num) : NULL;
    if (localhost_name_entry)
        localhost_name = localhost_name_entry->name;
    else
        localhost_name = "";

    localhost_length = (gint)(strlen(localhost_ether_addr) + 3 + strlen(localhost_name) + 1);
    localhost_addr_name = (gchar *)wmem_alloc(pinfo->pool, localhost_length);

    g_snprintf(localhost_addr_name, localhost_length, "%s (%s)", localhost_ether_addr, localhost_name);

    if (pinfo->p2p_dir == P2P_DIR_RECV) {
        dst_bd_addr   = localhost_bdaddr;
        dst_name      = localhost_name;
        dst_addr_name = localhost_addr_name;
    } else if (pinfo->p2p_dir == P2P_DIR_SENT) {
        src_bd_addr   = localhost_bdaddr;
        src_name      = localhost_name;
        src_addr_name = localhost_addr_name;
    }

    /* find the chandle_data structure associated with this chandle */
    key[0].length = 1;
    key[0].key = &interface_id;
    key[1].length = 1;
    key[1].key = &adapter_id;
    key[2].length = 1;
    key[2].key = &connection_handle;
    key[3].length = 1;
    key[3].key = &direction;
    key[4].length = 0;
    key[4].key = NULL;

    subtree = (wmem_tree_t *) wmem_tree_lookup32_array(chandle_tree, key);
    chandle_data = (subtree) ? (chandle_data_t *) wmem_tree_lookup32_le(subtree, pinfo->fd->num) : NULL;
    if (!pinfo->fd->flags.visited && !chandle_data) {
        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &connection_handle;
        key[3].length = 1;
        key[3].key = &direction;
        key[4].length = 1;
        key[4].key = &frame_number;
        key[5].length = 0;
        key[5].key = NULL;

        chandle_data = (chandle_data_t *)wmem_alloc(wmem_file_scope(), sizeof(chandle_data_t));
        chandle_data->start_fragments = wmem_tree_new(wmem_file_scope());

        wmem_tree_insert32_array(chandle_tree, key, chandle_data);
    }

    length = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(bthci_acl_tree, hf_bthci_acl_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* determine if packet is fragmented */
    switch(pb_flag) {
    case 0x01:  /* Continuation fragment */
        fragmented = TRUE;
        break;
    case 0x00:  /* First fragment/packet, non-auto flushable */
    case 0x02:  /* First fragment/packet, auto flushable */
        l2cap_length = tvb_get_letohs(tvb, offset);
        fragmented   = (l2cap_length + 4 != length);
        break;
    default:
        /* unknown pb_flag */
        fragmented = FALSE;
    }


    if (!fragmented || (!acl_reassembly && !(pb_flag & 0x01))) {
        /* call L2CAP dissector for PDUs that are not fragmented
         * also for the first fragment if reassembly is disabled
         */
        next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb, offset), length);
        offset += call_dissector_with_data(btl2cap_handle, next_tvb, pinfo, tree, acl_data);
    } else if (fragmented && acl_reassembly) {
        multi_fragment_pdu_t *mfp = NULL;
        gint                  len;

        if (!(pb_flag & 0x01)) { /* first fragment */
            if (!pinfo->fd->flags.visited) {
                mfp = (multi_fragment_pdu_t *) wmem_new(wmem_file_scope(), multi_fragment_pdu_t);
                mfp->first_frame = pinfo->fd->num;
                mfp->last_frame  = 0;
                mfp->tot_len     = l2cap_length + 4;
                mfp->reassembled = (char *) wmem_alloc(wmem_file_scope(), mfp->tot_len);
                len = tvb_captured_length_remaining(tvb, offset);
                if (len <= mfp->tot_len) {
                    tvb_memcpy(tvb, (guint8 *) mfp->reassembled, offset, len);
                    mfp->cur_off = len;
                    wmem_tree_insert32(chandle_data->start_fragments, pinfo->fd->num, mfp);
                }
            } else {
                mfp = (multi_fragment_pdu_t *)wmem_tree_lookup32(chandle_data->start_fragments, pinfo->fd->num);
            }
            if (mfp != NULL && mfp->last_frame) {
                proto_item *item;

                item = proto_tree_add_uint(bthci_acl_tree, hf_bthci_acl_reassembled_in, tvb, 0, 0, mfp->last_frame);
                PROTO_ITEM_SET_GENERATED(item);
                col_append_fstr(pinfo->cinfo, COL_INFO, " [Reassembled in #%u]", mfp->last_frame);
            }
        }
        if (pb_flag == 0x01) { /* continuation fragment */
            mfp = (multi_fragment_pdu_t *)wmem_tree_lookup32_le(chandle_data->start_fragments, pinfo->fd->num);
            if (!pinfo->fd->flags.visited) {
                len = tvb_captured_length_remaining(tvb, offset);
                if (mfp != NULL && !mfp->last_frame && (mfp->tot_len >= mfp->cur_off + len)) {
                    tvb_memcpy(tvb, (guint8 *) mfp->reassembled + mfp->cur_off, offset, len);
                    mfp->cur_off += len;
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
                next_tvb = tvb_new_child_real_data(tvb, (guint8 *) mfp->reassembled, mfp->tot_len, mfp->tot_len);
                add_new_data_source(pinfo, next_tvb, "Reassembled BTHCI ACL");

                offset += call_dissector_with_data(btl2cap_handle, next_tvb, pinfo, tree, acl_data);
            }
        }
    }

    if (tvb_captured_length_remaining(tvb, offset) > 0)
        proto_tree_add_item(bthci_acl_tree, hf_bthci_acl_data, tvb, offset, -1, ENC_NA);

    if (chandle_session) {
        sub_item = proto_tree_add_uint(bthci_acl_tree, hf_bthci_acl_connect_in, tvb, 0, 0, chandle_session->connect_in_frame);
        PROTO_ITEM_SET_GENERATED(sub_item);

        if (chandle_session->disconnect_in_frame < G_MAXUINT32) {
            sub_item = proto_tree_add_uint(bthci_acl_tree, hf_bthci_acl_disconnect_in, tvb, 0, 0, chandle_session->disconnect_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }

    SET_ADDRESS(&pinfo->net_src, AT_STRINGZ, (int)strlen(src_name) + 1, src_name);
    SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src_bd_addr);
    SET_ADDRESS(&pinfo->src, AT_STRINGZ, (int)strlen(src_addr_name) + 1, src_addr_name);

    SET_ADDRESS(&pinfo->net_dst, AT_STRINGZ, (int)strlen(dst_name) + 1, dst_name);
    SET_ADDRESS(&pinfo->dl_dst, AT_ETHER, 6, dst_bd_addr);
    SET_ADDRESS(&pinfo->dst, AT_STRINGZ, (int)strlen(dst_addr_name) + 1, dst_addr_name);

    sub_item = proto_tree_add_ether(bthci_acl_tree, hf_bthci_acl_src_bd_addr, tvb, 0, 0, src_bd_addr);
    PROTO_ITEM_SET_GENERATED(sub_item);

    sub_item = proto_tree_add_string(bthci_acl_tree, hf_bthci_acl_src_name, tvb, 0, 0, src_name);
    PROTO_ITEM_SET_GENERATED(sub_item);

    sub_item = proto_tree_add_ether(bthci_acl_tree, hf_bthci_acl_dst_bd_addr, tvb, 0, 0, dst_bd_addr);
    PROTO_ITEM_SET_GENERATED(sub_item);

    sub_item = proto_tree_add_string(bthci_acl_tree, hf_bthci_acl_dst_name, tvb, 0, 0, dst_name);
    PROTO_ITEM_SET_GENERATED(sub_item);

    return tvb_captured_length(tvb);
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
        { &hf_bthci_acl_connect_in,
            { "Connect in frame",                            "bthci_acl.connect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_acl_disconnect_in,
            { "Disconnect in frame",                         "bthci_acl.disconnect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_acl_src_bd_addr,
            { "Source BD_ADDR",                              "bthci_acl.src.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_acl_src_name,
            { "Source Device Name",                          "bthci_acl.src.name",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_acl_dst_bd_addr,
            { "Destination BD_ADDR",                         "bthci_acl.dst.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bthci_acl_dst_name,
            { "Destination Device Name",                     "bthci_acl.dst.name",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bthci_acl,
    };
    module_t *bthci_acl_module;

    /* Register the protocol name and description */
    proto_bthci_acl = proto_register_protocol("Bluetooth HCI ACL Packet", "HCI_ACL", "bthci_acl");
    bthci_acl_handle = new_register_dissector("bthci_acl", dissect_bthci_acl, proto_bthci_acl);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bthci_acl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register configuration preferences */
    bthci_acl_module = prefs_register_protocol(proto_bthci_acl, NULL);
    prefs_register_bool_preference(bthci_acl_module, "hci_acl_reassembly",
        "Reassemble ACL Fragments",
        "Whether the ACL dissector should reassemble fragmented PDUs",
        &acl_reassembly);

    chandle_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}


void
proto_reg_handoff_bthci_acl(void)
{
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
