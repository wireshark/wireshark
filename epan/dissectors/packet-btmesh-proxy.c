/* packet-btmesh-proxy.c
 * Routines for Bluetooth mesh Proxy PDU dissection
 *
 * Copyright 2019, Piotr Winiarczyk <wino45@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: Mesh Profile v1.0
 * https://www.bluetooth.com/specifications/mesh-specifications
 */

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/tvbuff-int.h>
#include <epan/expert.h>
#include <wsutil/wsgcrypt.h>

#include "packet-btmesh.h"

#define PROXY_COMPLETE_MESSAGE      0x00
#define PROXY_FIRST_SEGMENT         0x01
#define PROXY_CONTINUATION_SEGMENT  0x02
#define PROXY_LAST_SEGMENT          0x03

#define PROXY_PDU_NETWORK           0x00
#define PROXY_PDU_MESH_BEACON       0x01
#define PROXY_PDU_CONFIGURATION     0x02
#define PROXY_PDU_PROVISIONING      0x03

#define PROXY_SET_FILTER_TYPE               0x00
#define PROXY_ADD_ADDRESSES_TO_FILTER       0x01
#define PROXY_REMOVE_ADDRESSES_FROM_FILTER  0x02
#define PROXY_FILTER_STATUS                 0x03

#define UNICAST_ADDRESS_MASK        0x8000

void proto_register_btmesh_proxy(void);
void proto_reg_handoff_btmesh_proxy(void);

static int proto_btmesh_proxy = -1;

static int hf_btmesh_proxy_type = -1;
static int hf_btmesh_proxy_sar = -1;
static int hf_btmesh_proxy_data = -1;
static int hf_btmesh_proxy_data_fragment = -1;
static int hf_btmesh_proxy_fragments = -1;
static int hf_btmesh_proxy_fragment = -1;
static int hf_btmesh_proxy_fragment_overlap = -1;
static int hf_btmesh_proxy_fragment_overlap_conflict = -1;
static int hf_btmesh_proxy_fragment_multiple_tails = -1;
static int hf_btmesh_proxy_fragment_too_long_fragment = -1;
static int hf_btmesh_proxy_fragment_error = -1;
static int hf_btmesh_proxy_fragment_count = -1;
static int hf_btmesh_proxy_reassembled_length = -1;
static int hf_btmesh_proxy_ivi = -1;
static int hf_btmesh_proxy_nid = -1;
static int hf_btmesh_proxy_ctl = -1;
static int hf_btmesh_proxy_ttl = -1;
static int hf_btmesh_proxy_seq = -1;
static int hf_btmesh_proxy_src = -1;
static int hf_btmesh_proxy_dst = -1;
static int hf_btmesh_proxy_transport_pdu = -1;
static int hf_btmesh_proxy_netmic = -1;
static int hf_btmesh_proxy_control_opcode = -1;
static int hf_btmesh_proxy_control_parameters = -1;
static int hf_btmesh_proxy_control_filter_type = -1;
static int hf_btmesh_proxy_control_list_size = -1;
static int hf_btmesh_proxy_control_list_item = -1;

static int ett_btmesh_proxy = -1;
static int ett_btmesh_proxy_network_pdu = -1;
static int ett_btmesh_proxy_transport_pdu = -1;
static int ett_btmesh_proxy_fragments = -1;
static int ett_btmesh_proxy_fragment = -1;

static expert_field ei_btmesh_proxy_unknown_opcode = EI_INIT;
static expert_field ei_btmesh_proxy_unknown_payload = EI_INIT;
static expert_field ei_btmesh_proxy_wrong_ctl = EI_INIT;
static expert_field ei_btmesh_proxy_wrong_ttl = EI_INIT;
static expert_field ei_btmesh_proxy_wrong_dst = EI_INIT;
static expert_field ei_btmesh_proxy_unknown_filter_type = EI_INIT;
static expert_field ei_btmesh_proxy_wrong_address_type = EI_INIT;

static dissector_handle_t btmesh_handle;
static dissector_handle_t btmesh_provisioning_handle;
static dissector_handle_t btmesh_beacon_handle;

static wmem_tree_t *connection_info_tree;
static wmem_allocator_t *pool;

static const value_string btmesh_proxy_type[] = {
    { 0, "Network PDU" },
    { 1, "Mesh Beacon" },
    { 2, "Proxy Configuration" },
    { 3, "Provisioning PDU" },
    { 0, NULL }
};

static const value_string btmesh_proxy_sar[] = {
    { 0, "Data field contains a complete message" },
    { 1, "Data field contains the first segment of a message" },
    { 2, "Data field contains a continuation segment of a message" },
    { 3, "Data field contains the last segment of a message" },
    { 0, NULL }
};

static const value_string btmesh_proxy_ctl_vals[] = {
    { 0, "Unknown Message" },
    { 1, "Proxy Message" },
    { 0, NULL }
};

static const value_string btmesh_proxy_control_opcode[] = {
    { 0, "Set Filter Type" },
    { 1, "Add Addresses To Filter" },
    { 2, "Remove Addresses From Filter" },
    { 3, "Filter Status" },
    { 0, NULL }
};

static const value_string btmesh_proxy_control_filter_type[] = {
    { 0, "White list filter" },
    { 1, "Black list filter" },
    { 0, NULL }
};

static const fragment_items btmesh_proxy_frag_items = {
    &ett_btmesh_proxy_fragments,
    &ett_btmesh_proxy_fragment,

    &hf_btmesh_proxy_fragments,
    &hf_btmesh_proxy_fragment,
    &hf_btmesh_proxy_fragment_overlap,
    &hf_btmesh_proxy_fragment_overlap_conflict,
    &hf_btmesh_proxy_fragment_multiple_tails,
    &hf_btmesh_proxy_fragment_too_long_fragment,
    &hf_btmesh_proxy_fragment_error,
    &hf_btmesh_proxy_fragment_count,
    NULL,
    &hf_btmesh_proxy_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

static reassembly_table proxy_reassembly_table;
static guint32 sequence_counter[E_BTMESH_PROXY_SIDE_LAST];
static guint32 fragment_counter[E_BTMESH_PROXY_SIDE_LAST];
static gboolean first_pass;

#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */

static gint
dissect_btmesh_proxy_configuration_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint32 enc_data_len = 0;
    guint8 *decrypted_data = NULL;
    tvbuff_t *de_obf_tvb;
    tvbuff_t *de_cry_tvb;
    proto_tree *sub_tree, *cntrl_sub_tree;
    guint32 net_mic_size, seq, src, dst, opcode, ttl, bd_address;
    guint32 filter_type, list_size;
    guint32 offset = 0;
    guint32 decry_off = 0;
    network_decryption_ctx_t *dec_ctx;

    proto_tree_add_item(tree, hf_btmesh_proxy_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);

    dec_ctx = wmem_new(wmem_packet_scope(), network_decryption_ctx_t);
    dec_ctx->net_nonce_type = BTMESH_NONCE_TYPE_PROXY;

    de_obf_tvb = btmesh_network_find_key_and_decrypt(tvb, pinfo, &decrypted_data, &enc_data_len, dec_ctx);
    if (de_obf_tvb) {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_proxy_network_pdu, NULL, "Proxy Network PDU");

        proto_tree_add_item(sub_tree, hf_btmesh_proxy_ivi, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_proxy_nid, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        add_new_data_source(pinfo, de_obf_tvb, "Deobfuscated data");

        /* CTL 1 bit Network Control*/
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_proxy_ctl, de_obf_tvb, 0, 1, ENC_BIG_ENDIAN, &net_mic_size);
        if (net_mic_size != 1) {
            proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_proxy_wrong_ctl, de_obf_tvb, 0, 1);
        }
        net_mic_size = (net_mic_size + 1) * 4;
        /* The TTL field is a 7-bit field */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_proxy_ttl, de_obf_tvb, 0, 1, ENC_BIG_ENDIAN, &ttl);
        if (ttl != 0) {
            proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_proxy_wrong_ttl, de_obf_tvb, 0, 1);
        }
        /* SEQ field is a 24-bit integer */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_proxy_seq, de_obf_tvb, 1, 3, ENC_BIG_ENDIAN, &seq);

        /* SRC field is a 16-bit value */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_proxy_src, de_obf_tvb, 4, 2, ENC_BIG_ENDIAN, &src);
        if (src & UNICAST_ADDRESS_MASK ) {
            proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_proxy_wrong_address_type, de_obf_tvb, 4, 2);
        }
        offset += 6;

        de_cry_tvb = tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
        add_new_data_source(pinfo, de_cry_tvb, "Decrypted data");

        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_proxy_dst, de_cry_tvb, decry_off, 2, ENC_BIG_ENDIAN, &dst);
        if (dst != 0) {
            proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_proxy_wrong_dst, de_cry_tvb, decry_off, 2);
        }
        decry_off += 2;

        /* TransportPDU */
        proto_tree_add_item(sub_tree, hf_btmesh_proxy_transport_pdu, de_cry_tvb, decry_off, enc_data_len - 2, ENC_NA);
        offset += enc_data_len;

        proto_tree_add_item(sub_tree, hf_btmesh_proxy_netmic, tvb, offset, net_mic_size, ENC_BIG_ENDIAN);
        offset += net_mic_size;

        cntrl_sub_tree = proto_tree_add_subtree(tree, de_cry_tvb, decry_off, -1, ett_btmesh_proxy_transport_pdu, NULL, "Proxy Transport PDU");
        /* Opcode */
        proto_tree_add_item_ret_uint(cntrl_sub_tree, hf_btmesh_proxy_control_opcode, de_cry_tvb, decry_off, 1, ENC_BIG_ENDIAN, &opcode);
        decry_off += 1;

        /* Parameters */
        switch(opcode) {
          case PROXY_SET_FILTER_TYPE:
              proto_tree_add_item_ret_uint(cntrl_sub_tree, hf_btmesh_proxy_control_filter_type, de_cry_tvb, decry_off, 1, ENC_BIG_ENDIAN, &filter_type);
              if (filter_type > 1) {
                  proto_tree_add_expert(cntrl_sub_tree, pinfo, &ei_btmesh_proxy_unknown_filter_type, de_cry_tvb, decry_off, 1);
              }
              decry_off += 1;

          break;
          case PROXY_ADD_ADDRESSES_TO_FILTER:
              while (decry_off <= (guint32)enc_data_len - 1) {
                proto_tree_add_item_ret_uint(cntrl_sub_tree, hf_btmesh_proxy_control_list_item, de_cry_tvb, decry_off, 2, ENC_BIG_ENDIAN, &bd_address);
                  if (bd_address == 0 ) {
                      proto_tree_add_expert(cntrl_sub_tree, pinfo, &ei_btmesh_proxy_wrong_address_type, de_cry_tvb, decry_off, 2);
                  }
                  decry_off += 2;
              }

          break;
          case PROXY_REMOVE_ADDRESSES_FROM_FILTER:
              while (decry_off <= (guint32)enc_data_len - 1) {
                proto_tree_add_item_ret_uint(cntrl_sub_tree, hf_btmesh_proxy_control_list_item, de_cry_tvb, decry_off, 2, ENC_BIG_ENDIAN, &bd_address);
                if (bd_address == 0 ) {
                      proto_tree_add_expert(cntrl_sub_tree, pinfo, &ei_btmesh_proxy_wrong_address_type, de_cry_tvb, decry_off, 2);
                }
                decry_off += 2;
              }

          break;
          case PROXY_FILTER_STATUS:
              proto_tree_add_item_ret_uint(cntrl_sub_tree, hf_btmesh_proxy_control_filter_type, de_cry_tvb, decry_off, 1, ENC_BIG_ENDIAN, &filter_type);
              if (filter_type > 1) {
                  proto_tree_add_expert(cntrl_sub_tree, pinfo, &ei_btmesh_proxy_unknown_filter_type, de_cry_tvb, decry_off, 1);
              }
              decry_off += 1;

              proto_tree_add_item_ret_uint(cntrl_sub_tree, hf_btmesh_proxy_control_list_size, de_cry_tvb, decry_off, 2, ENC_BIG_ENDIAN, &list_size);
              decry_off += 2;
          break;
          default:
              proto_tree_add_expert(cntrl_sub_tree, pinfo, &ei_btmesh_proxy_unknown_opcode, de_cry_tvb, decry_off -1 , 1);
              proto_tree_add_item(cntrl_sub_tree, hf_btmesh_proxy_control_parameters, de_cry_tvb, decry_off, enc_data_len - 3, ENC_NA);
              decry_off += enc_data_len - 3;
        }
        /* Still some octets left */
        if (offset - net_mic_size != decry_off + 7) {
            proto_tree_add_expert(cntrl_sub_tree, pinfo, &ei_btmesh_proxy_unknown_payload, de_cry_tvb, decry_off, -1);
        }
    }
    return offset;
}

#else /* GCRYPT_VERSION_NUMBER >= 0x010600 */

static gint
dissect_btmesh_proxy_configuration_msg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_btmesh_proxy_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    return tvb_reported_length(tvb);
}

#endif/* GCRYPT_VERSION_NUMBER >= 0x010600 */

static gint
dissect_btmesh_proxy_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *proxy_data)
{
    proto_item *item;
    proto_tree *sub_tree;
    tvbuff_t *next_tvb = NULL;
    fragment_head *fd_head = NULL;
    guint32 *sequence_counter_ptr;
    void *storage;
    btle_mesh_transport_ctx_t tr_ctx;
    guint offset = 0;
    btle_mesh_proxy_ctx_t *proxy_ctx = NULL;

    DISSECTOR_ASSERT(proxy_data);
    proxy_ctx = (btle_mesh_proxy_ctx_t *)proxy_data;
    DISSECTOR_ASSERT(proxy_ctx->proxy_side < E_BTMESH_PROXY_SIDE_LAST);

    if (pinfo->fd->visited && first_pass) {
      first_pass=FALSE;
      sequence_counter[proxy_ctx->proxy_side] = 0;
      fragment_counter[proxy_ctx->proxy_side] = 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT Mesh Proxy");

    item = proto_tree_add_item(tree, proto_btmesh_proxy, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_btmesh_proxy);

    proto_tree_add_item(sub_tree, hf_btmesh_proxy_sar, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(sub_tree, hf_btmesh_proxy_type, tvb, offset, 1, ENC_NA);

    guint8 proxy_sar = (tvb_get_guint8(tvb, offset) & 0xC0 ) >> 6;
    guint8 proxy_type = tvb_get_guint8(tvb, offset) & 0x3F;
    offset += 1;
    guint32 length = tvb_reported_length(tvb) - offset;

    gboolean packetReassembledOrComplete = FALSE;
    gboolean packetComplete = FALSE;

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(proxy_type, btmesh_proxy_type, "Unknown Proxy PDU"));

    switch (proxy_sar){
        case PROXY_COMPLETE_MESSAGE:
            packetReassembledOrComplete = TRUE;
            packetComplete = TRUE;
            next_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, tvb_captured_length(tvb) - offset);
            col_append_str(pinfo->cinfo, COL_INFO," (Complete)");

        break;
        case PROXY_FIRST_SEGMENT:
            proto_tree_add_item(sub_tree, hf_btmesh_proxy_data_fragment, tvb, offset, length, ENC_NA);
            if (!pinfo->fd->visited) {
              sequence_counter[proxy_ctx->proxy_side]++;
              fragment_counter[proxy_ctx->proxy_side]=0;

              fd_head = fragment_add_seq(&proxy_reassembly_table,
                tvb, offset, pinfo,
                sequence_counter[proxy_ctx->proxy_side], NULL,
                fragment_counter[proxy_ctx->proxy_side],
                tvb_captured_length_remaining(tvb, offset),
                TRUE, 0);

              fragment_counter[proxy_ctx->proxy_side]++;
            } else {
              sequence_counter[proxy_ctx->proxy_side]++;
            }
            col_append_str(pinfo->cinfo, COL_INFO," (First Segment)");

        break;
        case PROXY_CONTINUATION_SEGMENT:
            proto_tree_add_item(sub_tree, hf_btmesh_proxy_data_fragment, tvb, offset, length, ENC_NA);
            if (!pinfo->fd->visited) {
              fd_head = fragment_add_seq(&proxy_reassembly_table,
                tvb, offset, pinfo,
                sequence_counter[proxy_ctx->proxy_side], NULL,
                fragment_counter[proxy_ctx->proxy_side],
                tvb_captured_length_remaining(tvb, offset),
                TRUE, 0);
              fragment_counter[proxy_ctx->proxy_side]++;
            }
            col_append_str(pinfo->cinfo, COL_INFO," (Continuation Segment)");

        break;
        case PROXY_LAST_SEGMENT:

            proto_tree_add_item(sub_tree, hf_btmesh_proxy_data_fragment, tvb, offset, length, ENC_NA);
            if (!pinfo->fd->visited) {
              fragment_add_seq(&proxy_reassembly_table,
                tvb, offset, pinfo,
                sequence_counter[proxy_ctx->proxy_side], NULL,
                fragment_counter[proxy_ctx->proxy_side],
                tvb_captured_length_remaining(tvb, offset),
                FALSE, 0);

              fragment_counter[proxy_ctx->proxy_side]++;

              //add mapping "pinfo->num" -> "sequence_counter"
              storage = wmem_alloc0(pool, sizeof(sequence_counter[proxy_ctx->proxy_side]));
              *((guint32 *)storage) = sequence_counter[proxy_ctx->proxy_side];
              wmem_tree_insert32(connection_info_tree, pinfo->num, storage);

              fd_head = fragment_get(&proxy_reassembly_table, pinfo, sequence_counter[proxy_ctx->proxy_side], NULL);

           }
           packetReassembledOrComplete = TRUE;
           col_append_str(pinfo->cinfo, COL_INFO," (Last Segment)");

        break;
        //No default since this is 2 bit value
    }

    if (packetReassembledOrComplete && pinfo->fd->visited) {
      if (next_tvb == NULL) {
          sequence_counter_ptr = (guint32 *)wmem_tree_lookup32(connection_info_tree, pinfo->num);

        if (sequence_counter_ptr != NULL) {
          fd_head = fragment_get(&proxy_reassembly_table, pinfo, *sequence_counter_ptr, NULL);
        }

        if (fd_head) {
            next_tvb = process_reassembled_data(tvb, offset, pinfo,
              "Reassembled Message", fd_head, &btmesh_proxy_frag_items,
              NULL, sub_tree);
            col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
        }
      }

    if (next_tvb){
        offset = 0;
        tr_ctx.transport = E_BTMESH_TR_PROXY;
        if (packetComplete) {
            tr_ctx.fragmented = FALSE;
        } else {
            tr_ctx.fragmented = TRUE;
        }
        tr_ctx.segment_index = 0;

        switch(proxy_type) {
          case PROXY_PDU_NETWORK:
              if (btmesh_handle) {
                  call_dissector(btmesh_handle, next_tvb, pinfo, proto_tree_get_root(tree));
              } else {
                  proto_tree_add_item(sub_tree, hf_btmesh_proxy_data, next_tvb, offset, length, ENC_NA);
              }

          break;
          case PROXY_PDU_MESH_BEACON:
              if (btmesh_beacon_handle) {
                  call_dissector_with_data(btmesh_beacon_handle, next_tvb, pinfo, proto_tree_get_root(tree), &tr_ctx);
              } else {
                  proto_tree_add_item(sub_tree, hf_btmesh_proxy_data, next_tvb, offset, length, ENC_NA);
              }

          break;
          case PROXY_PDU_CONFIGURATION:
              dissect_btmesh_proxy_configuration_msg(next_tvb, pinfo, sub_tree, NULL);

          break;
          case PROXY_PDU_PROVISIONING:
              if (btmesh_provisioning_handle) {
                  call_dissector_with_data(btmesh_provisioning_handle, next_tvb, pinfo, proto_tree_get_root(tree), &tr_ctx);
              } else {
                  proto_tree_add_item(sub_tree, hf_btmesh_proxy_data, next_tvb, offset, length, ENC_NA);
              }

          break;
          //Default is not needed
          }
      }
  }

  return tvb_reported_length(tvb);
}

static void
proxy_init_routine(void)
{
  reassembly_table_register(&proxy_reassembly_table, &addresses_reassembly_table_functions);
  for (int i=0; i< E_BTMESH_PROXY_SIDE_LAST; i++ ){
    sequence_counter[i] = 0;
    fragment_counter[i] = 0;
  }
  first_pass = TRUE;
  pool = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);
}

static void
proxy_cleanup_dissector(void)
{
  wmem_destroy_allocator(pool);
  pool = NULL;
}

void
proto_register_btmesh_proxy(void)
{
    static hf_register_info hf[] = {
        { &hf_btmesh_proxy_type,
            { "Type", "btmproxy.type",
                FT_UINT8, BASE_DEC, VALS(btmesh_proxy_type), 0x3F,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_sar,
            { "SAR", "btmproxy.sar",
                FT_UINT8, BASE_DEC, VALS(btmesh_proxy_sar), 0xC0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_data,
            { "Data", "btmproxy.data",
                FT_BYTES, BASE_NONE, NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_data_fragment,
            { "Data Fragment", "btmproxy.data_fragment",
                FT_BYTES, BASE_NONE, NULL, 0x00,
                NULL, HFILL }
        },
        //Proxy Payload Reassembly
        { &hf_btmesh_proxy_fragments,
            { "Reassembled Proxy Payload Fragments", "btmproxy.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Proxy Payload Fragments", HFILL }
        },
        { &hf_btmesh_proxy_fragment,
            { "Proxy Payload Fragment", "btmproxy.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_fragment_overlap,
            { "Fragment overlap", "btmproxy.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_btmesh_proxy_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "btmproxy.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_btmesh_proxy_fragment_multiple_tails,
            { "Multiple tail fragments found", "btmproxy.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_btmesh_proxy_fragment_too_long_fragment,
            { "Fragment too long", "btmproxy.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }
        },
        { &hf_btmesh_proxy_fragment_error,
            { "Defragmentation error", "btmproxy.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_btmesh_proxy_fragment_count,
            { "Fragment count", "btmproxy.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_reassembled_length,
            { "Reassembled Proxy Payload length", "btmproxy.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }
        },
        { &hf_btmesh_proxy_ivi,
            { "IVI", "btmproxy.ivi",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_nid,
            { "NID", "btmproxy.nid",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_ctl,
            { "CTL", "btmproxy.ctl",
                FT_UINT8, BASE_DEC, VALS(btmesh_proxy_ctl_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_ttl,
            { "TTL", "btmproxy.ttl",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_seq,
            { "SEQ", "btmproxy.seq",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_src,
            { "SRC", "btmproxy.src",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_dst,
            { "DST", "btmproxy.dst",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_transport_pdu,
            { "Proxy Transport PDU", "btmproxy.transport_pdu",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_netmic,
            { "ProxyNetMIC", "btmproxy.netmic",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_control_opcode,
            { "Opcode", "btmproxy.control.opcode",
                FT_UINT8, BASE_DEC, VALS(btmesh_proxy_control_opcode), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_control_parameters,
            { "Proxy Control Parameters", "btmproxy.control.parameters",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_control_filter_type,
            { "Filter Type", "btmproxy.control.filter_type",
                FT_UINT8, BASE_DEC, VALS(btmesh_proxy_control_filter_type), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_control_list_size,
            { "List Size", "btmproxy.control.list_size",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_proxy_control_list_item,
            { "List Item", "btmproxy.control.list_item",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_btmesh_proxy,
        &ett_btmesh_proxy_network_pdu,
        &ett_btmesh_proxy_transport_pdu,
        &ett_btmesh_proxy_fragments,
        &ett_btmesh_proxy_fragment,
    };

    static ei_register_info ei[] = {
        { &ei_btmesh_proxy_unknown_opcode,{ "btmproxy.unknown_opcode", PI_PROTOCOL, PI_ERROR, "Unknown Opcode", EXPFILL } },
        { &ei_btmesh_proxy_unknown_payload,{ "btmproxy.unknown_payload", PI_PROTOCOL, PI_ERROR, "Unknown Payload", EXPFILL } },
        { &ei_btmesh_proxy_wrong_ctl,{ "btmproxy.wrong_ctl", PI_PROTOCOL, PI_ERROR, "Wrong CTL value", EXPFILL } },
        { &ei_btmesh_proxy_wrong_ttl,{ "btmproxy.wrong_ttl", PI_PROTOCOL, PI_ERROR, "Wrong TTL value", EXPFILL } },
        { &ei_btmesh_proxy_wrong_dst,{ "btmproxy.wrong_dst", PI_PROTOCOL, PI_ERROR, "Wrong DST value", EXPFILL } },
        { &ei_btmesh_proxy_unknown_filter_type,{ "btmproxy.unknown_filter_type", PI_PROTOCOL, PI_ERROR, "Unknown Filter Type", EXPFILL } },
        { &ei_btmesh_proxy_wrong_address_type,{ "btmproxy.wrong_address_type", PI_PROTOCOL, PI_ERROR, "Wrong Address Type", EXPFILL } },
    };

    expert_module_t* expert_btmesh_proxy;

    proto_btmesh_proxy = proto_register_protocol("Bluetooth Mesh Proxy", "BT Mesh proxy", "btmproxy");

    proto_register_field_array(proto_btmesh_proxy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_btmesh_proxy = expert_register_protocol(proto_btmesh_proxy);
    expert_register_field_array(expert_btmesh_proxy, ei, array_length(ei));

    prefs_register_protocol_subtree("Bluetooth", proto_btmesh_proxy, NULL);
    register_dissector("btmesh.proxy", dissect_btmesh_proxy_msg, proto_btmesh_proxy);

    connection_info_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    register_init_routine(proxy_init_routine);
    register_cleanup_routine(proxy_cleanup_dissector);
}

void
proto_reg_handoff_btmesh_proxy(void)
{
    btmesh_handle = find_dissector("btmesh.msg");
    btmesh_provisioning_handle = find_dissector("btmesh.provisioning");
    btmesh_beacon_handle = find_dissector("btmesh.beacon");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
